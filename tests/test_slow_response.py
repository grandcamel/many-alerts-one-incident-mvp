"""Optional slow-response Fault at HTTP, SDK span, and configuration boundaries."""

import importlib.util
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parent.parent


@pytest.fixture
def app_module():
    spec = importlib.util.spec_from_file_location(
        "rolldice_slow_app", REPOSITORY / "docker" / "rolldice" / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("delay", ["-1", "751", "1.5", "slow", "", "NaN"])
def test_invalid_delay_is_a_bad_request(app_module, delay):
    with app_module.app.test_client() as client:
        assert client.get("/rolldice", query_string={"slow_ms": delay}).status_code == 400


@pytest.fixture
def traced_app(app_module, monkeypatch):
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(app_module, "tracer", provider.get_tracer("rolldice.test"), raising=False)
    instrumentor = FlaskInstrumentor()
    instrumentor.instrument_app(app_module.app, tracer_provider=provider)
    yield app_module, exporter
    instrumentor.uninstrument_app(app_module.app)
    provider.shutdown()


@pytest.mark.parametrize("delay", [500, 750])
def test_requested_wait_is_inside_a_child_of_the_http_span(traced_app, monkeypatch, delay):
    from opentelemetry import trace
    from opentelemetry.trace import SpanKind

    module, exporter = traced_app
    observed = []

    def observe_wait(seconds):
        span = trace.get_current_span()
        observed.append((seconds, span.get_span_context().span_id, span.name))

    monkeypatch.setattr(module, "sleep", observe_wait, raising=False)
    response = module.app.test_client().get("/rolldice", query_string={"slow_ms": delay})
    assert response.status_code == 200
    assert 1 <= int(response.data) <= 6
    spans = exporter.get_finished_spans()
    servers = [span for span in spans if span.kind == SpanKind.SERVER]
    children = [span for span in spans if span.name == "rolldice.wait"]
    assert len(servers) == len(children) == 1
    server, child = servers[0], children[0]
    assert child.kind == SpanKind.INTERNAL
    assert child.context.trace_id == server.context.trace_id
    assert child.parent.span_id == server.context.span_id
    assert observed == [(delay / 1000, child.context.span_id, "rolldice.wait")]
    assert server.start_time <= child.start_time <= child.end_time <= server.end_time


@pytest.mark.parametrize("query", ["", "?slow_ms=0"])
def test_default_and_zero_have_no_wait_or_child(traced_app, monkeypatch, query):
    module, exporter = traced_app

    def unexpected_wait(_seconds):
        pytest.fail("zero-delay request must not sleep")

    monkeypatch.setattr(module, "sleep", unexpected_wait, raising=False)
    response = module.app.test_client().get("/rolldice" + query)
    assert response.status_code == 200
    assert not any(span.name == "rolldice.wait" for span in exporter.get_finished_spans())


def test_small_real_wait_is_exported_and_same_app_recovers(traced_app):
    module, exporter = traced_app
    client = module.app.test_client()
    assert client.get("/rolldice?slow_ms=1").status_code == 200
    child = next(span for span in exporter.get_finished_spans() if span.name == "rolldice.wait")
    assert child.end_time > child.start_time
    exporter.clear()
    assert client.get("/rolldice?slow_ms=0&sides=6").status_code == 200
    assert not any(span.name == "rolldice.wait" for span in exporter.get_finished_spans())
    assert client.get("/rolldice?sides=six").status_code == 500


def _overlay():
    import yaml

    class OverlayLoader(yaml.SafeLoader):
        pass

    OverlayLoader.add_constructor("!override", lambda loader, node: loader.construct_sequence(node))
    return yaml.load(
        (REPOSITORY / "docker-compose.slow-response.yml").read_text(), Loader=OverlayLoader
    )["services"]


def test_optional_provisioning_replaces_directory_mount_and_has_explicit_removal():
    import yaml

    document = yaml.compose((REPOSITORY / "docker-compose.slow-response.yml").read_text())
    services_node = next(value for key, value in document.value if key.value == "services")
    lgtm_node = next(value for key, value in services_node.value if key.value == "lgtm")
    volumes_node = next(value for key, value in lgtm_node.value if key.value == "volumes")
    assert volumes_node.tag == "!override"
    overlay = _overlay()
    assert set(overlay) == {"lgtm", "traffic"}
    volumes = overlay["lgtm"]["volumes"]
    directory = "/otel-lgtm/grafana/conf/provisioning/alerting/"
    assert volumes == [
        f"./grafana/provisioning/alerting/{name}:{directory}{name}:ro"
        for name in ("alert-rule.yaml", "contact-point.yaml", "notification-policy.yaml")
    ] + [
        "${SLOW_RESPONSE_RULES_FILE:-./grafana/optional/slow-response.yaml}:"
        + directory + "slow-response.yaml:ro"
    ]
    rules = yaml.safe_load((REPOSITORY / "grafana/optional/slow-response.yaml").read_text())
    group = rules["groups"][0]
    assert (group["orgId"], group["folder"], group["name"], group["interval"]) == (
        1, "demo-latency", "rolldice-latency", "10s"
    )
    rule = group["rules"][0]
    assert len(group["rules"]) == 1
    assert rule["uid"] == "rolldice-response-slow"
    assert rule["labels"] == {
        "severity": "warning", "service": "rolldice", "incident_group": "slow-response"
    }
    assert rule["for"] == "30s"
    assert rule["noDataState"] == rule["execErrState"] == "OK"
    query, threshold = rule["data"]
    assert query["model"]["expr"] == (
        'sum by (instance) (rate(http_server_duration_milliseconds_sum'
        '{service_name="rolldice"}[20s])) / '
        'sum by (instance) (rate(http_server_duration_milliseconds_count'
        '{service_name="rolldice"}[20s]))'
    )
    assert query["datasourceUid"] == "prometheus"
    assert query["model"]["instant"] is True
    assert threshold["refId"] == rule["condition"] == "B"
    assert threshold["model"]["expression"] == "A"
    assert threshold["model"]["conditions"][0]["evaluator"] == {
        "type": "gt", "params": [250]
    }
    removal = yaml.safe_load(
        (REPOSITORY / "grafana/optional/slow-response-remove.yaml").read_text()
    )
    assert removal == {"apiVersion": 1, "deleteRules": [{"orgId": 1, "uid": rule["uid"]}]}


@pytest.mark.parametrize("delay", [None, "500", "0"])
def test_optional_traffic_forwards_default_injection_and_reset(tmp_path, delay):
    import os
    import subprocess

    traffic = _overlay()["traffic"]
    assert traffic["environment"] == {"ROLLDICE_SLOW_MS": "${ROLLDICE_SLOW_MS:-0}"}
    command = traffic["command"]
    assert command[:2] == ["sh", "-c"]
    wget = tmp_path / "wget"
    wget.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRAFFIC_CALLS"\nexit 8\n')
    sleep = tmp_path / "sleep"
    sleep.write_text(
        '#!/bin/sh\nprintf "tick\\n" >> "$TRAFFIC_TICKS"\n'
        'if [ "$(wc -l < "$TRAFFIC_TICKS")" -ge 3 ]; then kill -TERM "$PPID"; fi\n'
    )
    wget.chmod(0o755)
    sleep.chmod(0o755)
    calls, ticks = tmp_path / "calls", tmp_path / "ticks"
    environment = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ.get("PATH", ""),
        "ROLLDICE_SIDES": "6",
        "ROLLDICE_SLOW_MS": "0" if delay is None else delay,
        "TRAFFIC_CALLS": str(calls),
        "TRAFFIC_TICKS": str(ticks),
    }
    completed = subprocess.run(
        [*command[:2], command[2].replace("$$", "$")], env=environment,
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert completed.returncode == -15
    selected_delay = "0" if delay is None else delay
    assert calls.read_text().splitlines() == [
        f"-qO- http://rolldice:8082/rolldice?player=demo&sides=6&slow_ms={selected_delay}"
    ] * 3
