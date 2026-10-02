"""Loki queries through the CLI, real fake HTTP, stdout and raw evidence."""

from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

import pytest

from grafana_jsm_sandbox import grafana_query
from tests.grafana_upstream import FakeGrafana

TOKEN = "viewer-test-secret"
PRESENTER = "https://presenter.example.invalid/grafana"


@pytest.fixture
def grafana(monkeypatch, tmp_path):
    upstream = FakeGrafana()
    upstream.start()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEMO_GRAFANA_URL", upstream.url + "/grafana/")
    monkeypatch.setenv("DEMO_GRAFANA_PRESENTER_URL", PRESENTER + "/")
    monkeypatch.setenv("DEMO_GRAFANA_VIEWER_TOKEN", TOKEN)
    try:
        yield upstream
    finally:
        upstream.stop()


def answer(upstream, response, status=200):
    upstream.responses.append((status, json.dumps(response).encode(), 0))


def streams(result):
    return {"status": "success", "data": {"resultType": "streams", "result": result}}


def record(capsys, tmp_path):
    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 6
    assert all(len(line) <= 200 for line in lines[:5])
    assert TOKEN not in output.out
    assert "127.0.0.1" not in output.out
    assert (tmp_path / "grafana-evidence.jsonl").read_text().splitlines()[-1] == lines[5]
    return lines, json.loads(lines[5])


def test_logs_proxy_keeps_raw_evidence_and_matching_explore_window(grafana, capsys, tmp_path):
    expression = '{service_name="rolldice"} |= "it\'s $5 日本"'
    response = streams([{"stream": {"service_name": "rolldice"}, "values": [
        ["1000000000001", "rolled 5", {"trace_id": "abc"}],
    ]}])
    answer(grafana, response)
    assert grafana_query.main([
        "logs", "--query=" + expression, "--datasource=a/b 日本", "--start=1000.1239",
        "--end=1001.9999", "--limit=1", "--direction=forward",
    ]) == 0
    sent = grafana.received[0]
    assert sent.method == "GET" and sent.body == b""
    assert sent.headers["Authorization"] == "Bearer " + TOKEN
    assert urlsplit(sent.path).path == (
        "/grafana/api/datasources/proxy/uid/a%2Fb%20%E6%97%A5%E6%9C%AC/loki/api/v1/query_range"
    )
    expected_parameters = [
        ("query", expression), ("start", "1970-01-01T00:16:40.123Z"),
        ("end", "1970-01-01T00:16:41.999Z"), ("limit", "1"), ("direction", "forward"),
    ]
    assert parse_qsl(urlsplit(sent.path).query) == expected_parameters
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: ok"
    assert evidence["command"] == "logs" and evidence["response"] == response
    assert evidence["window"] == {
        "start": "1970-01-01T00:16:40.123Z", "end": "1970-01-01T00:16:41.999Z",
        "step_seconds": None,
    }
    assert evidence["parameters"] == [list(pair) for pair in expected_parameters]
    assert evidence["sample_summary"] == {
        "result_type": "streams", "series_count": 0, "sample_count": 0,
        "unmodelled_count": 0, "discovery_items": None, "series": [],
    }
    assert evidence["log_summary"] == {
        "stream_count": 1, "entry_count": 1, "limit_reached": True,
        "excerpts": [{"timestamp_ns": "1000000000001", "labels": {"service_name": "rolldice"},
                      "metadata": {"trace_id": "abc"}, "line": "rolled 5", "truncated": False}],
    }
    panes = json.loads(dict(parse_qsl(urlsplit(evidence["presenter_link"]).query))["panes"])
    assert panes == {"A": {"datasource": "a/b 日本", "queries": [{
        "refId": "A", "expr": expression, "instant": False, "range": True,
        "queryType": "range", "direction": "forward", "maxLines": 1,
    }], "range": {"from": "1000123", "to": "1001999"}}}
    assert "possibly incomplete" in lines[3]


def test_logs_excerpts_keep_nanosecond_order_and_shorten_only_presentation(
    grafana, capsys, tmp_path
):
    literal = '日本 "quoted"\nsecond line \' $() `shell` ' + "x" * 600
    response = streams([
        {"stream": {"service_name": "alpha"}, "values": [
            ["1790899200000000001", "first", {"trace_id": "a"}],
            ["1790899200000000003", literal],
        ]},
        {"stream": {"service_name": "beta"}, "values": [
            ["1790899200000000002", "second"],
            ["1790899200000000004", "fourth", {"severity": "warning"}],
        ]},
    ])
    answer(grafana, response)
    assert grafana_query.main([
        "logs", '--query={service_name=~".*"}', "--start=now-1d", "--limit=4",
    ]) == 0
    _, evidence = record(capsys, tmp_path)
    assert evidence["response"] == response
    assert evidence["response"]["data"]["result"][0]["values"][1][1] == literal
    assert evidence["log_summary"] == {
        "stream_count": 2, "entry_count": 4, "limit_reached": True, "excerpts": [
            {"timestamp_ns": "1790899200000000004", "labels": {"service_name": "beta"},
             "metadata": {"severity": "warning"}, "line": "fourth", "truncated": False},
            {"timestamp_ns": "1790899200000000003", "labels": {"service_name": "alpha"},
             "metadata": {}, "line": literal[:600], "truncated": True},
            {"timestamp_ns": "1790899200000000002", "labels": {"service_name": "beta"},
             "metadata": {}, "line": "second", "truncated": False},
        ],
    }


def test_default_logs_window_and_empty_result_are_evidence_not_health(grafana, capsys, tmp_path):
    answer(grafana, streams([]))
    assert grafana_query.main(["logs", '--query={service_name="missing"}']) == 0
    lines, evidence = record(capsys, tmp_path)
    parameters = dict(parse_qsl(urlsplit(grafana.received[0].path).query))
    assert evidence["datasource"] == "loki"
    assert parameters["start"] == evidence["window"]["start"]
    assert parameters["end"] == evidence["window"]["end"]
    assert (datetime.fromisoformat(parameters["end"]) -
            datetime.fromisoformat(parameters["start"])).total_seconds() == 600
    assert parameters["limit"] == "100" and parameters["direction"] == "backward"
    assert "step" not in parameters and evidence["window"]["step_seconds"] is None
    assert lines[0] == "grafana-query: no data" and evidence["status"] == "empty"
    assert evidence["log_summary"] == {
        "stream_count": 0, "entry_count": 0, "limit_reached": False, "excerpts": [],
    }


@pytest.mark.parametrize("response", [
    None,
    {"status": "unknown", "data": {"resultType": "streams", "result": []}},
    {"status": "success", "data": {"resultType": "matrix", "result": []}},
    {"status": "success", "data": {"resultType": "streams", "result": {}}},
    streams([{"stream": {"service": 1}, "values": []}]),
    streams([{"stream": {}, "values": [[1000, "numeric timestamp"]]}]),
    streams([{"stream": {}, "values": [["-1", "negative timestamp"]]}]),
    streams([{"stream": {}, "values": [["1.0", "fractional timestamp"]]}]),
    streams([{"stream": {}, "values": [["1e9", "exponential timestamp"]]}]),
    streams([{"stream": {}, "values": [["253402300800000000000", "year 10000"]]}]),
    streams([{"stream": {}, "values": [["1", None]]}]),
    streams([{"stream": {}, "values": [["1", "line", {"nested": {"key": "value"}}]]}]),
    streams([{"stream": {}, "values": [["1", "line", {"number": 1}]]}]),
    streams([{"stream": {}, "values": [["1", "line", None]]}]),
    streams([{"stream": {}, "values": [["1", "line", {}, "extra"]]}]),
    streams([{"stream": {}}]),
])
def test_logs_malformed_response_remains_raw_and_unavailable(grafana, capsys, tmp_path, response):
    answer(grafana, response)
    assert grafana_query.main(["logs", '--query={service_name="rolldice"}']) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: malformed response"
    assert evidence["status"] == "unavailable"
    assert evidence["response"] == response and evidence["log_summary"] is None
    assert evidence["sample_summary"]["result_type"] is None
    assert evidence["error"]["kind"] == "malformed_response"


@pytest.mark.parametrize("response,status,kind", [
    ({"status": "error", "error": "secret query body"}, 200, "query_error"),
    ({"secret": "token body"}, 401, "token_rejected"),
    ({"secret": "server body"}, 503, "http_error"),
])
def test_logs_query_errors_are_distinct_from_empty_data(
    grafana, capsys, tmp_path, response, status, kind
):
    answer(grafana, response, status)
    assert grafana_query.main(["logs", '--query={service_name="rolldice"}']) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0].startswith("grafana-query: unavailable:")
    assert evidence["error"]["kind"] == kind and evidence["log_summary"] is None
    assert evidence["response"] == (response if status == 200 else None)


@pytest.mark.parametrize("arguments", [
    [], ["--limit=0"], ["--limit=-1"], ["--limit=1.5"], ["--limit=true"],
    ["--direction=sideways"], ["--step=1s"], ["--start=2", "--end=1"],
])
def test_invalid_logs_arguments_do_not_request_or_write_evidence(
    grafana, capsys, tmp_path, arguments
):
    command = ["logs"] if not arguments else ["logs", '--query={service="x"}', *arguments]
    assert grafana_query.main(command) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err.startswith("grafana-query: error:")
    assert grafana.received == []
    assert not (tmp_path / "grafana-evidence.jsonl").exists()


def test_loki_discovery_get_uses_recorded_rfc3339_window(grafana, capsys, tmp_path):
    answer(grafana, {"status": "success", "data": ["service_name", "severity"]})
    assert grafana_query.main([
        "get", "--datasource=loki", "--path=/loki/api/v1/labels",
        "--param=start=1000.1239", "--param=end=1001.9999",
    ]) == 0
    _, evidence = record(capsys, tmp_path)
    assert parse_qsl(urlsplit(grafana.received[0].path).query) == [
        ("start", "1970-01-01T00:16:40.123Z"), ("end", "1970-01-01T00:16:41.999Z"),
    ]
    assert evidence["window"] == {
        "start": "1970-01-01T00:16:40.123Z", "end": "1970-01-01T00:16:41.999Z",
        "step_seconds": None,
    }
    assert evidence["sample_summary"]["result_type"] == "discovery"
    assert "log_summary" not in evidence


def test_prometheus_discovery_get_keeps_numeric_time_parameters(grafana, capsys, tmp_path):
    answer(grafana, {"status": "success", "data": ["service"]})
    assert grafana_query.main([
        "get", "--datasource=prometheus", "--path=/api/v1/labels",
        "--param=start=1000.1239", "--param=end=1001.9999",
    ]) == 0
    _, evidence = record(capsys, tmp_path)
    assert parse_qsl(urlsplit(grafana.received[0].path).query) == [
        ("start", "1000.1239"), ("end", "1001.9999"),
    ]
    assert "log_summary" not in evidence
