"""The query CLI's confirmed boundary: real HTTP, stdout and local evidence."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
import threading
import time
import tomllib
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import pytest

from grafana_jsm_sandbox import grafana_query, incident_payload
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
    monkeypatch.setenv("DEMO_INVESTIGATION_ENABLED", "false")
    try:
        yield upstream
    finally:
        upstream.stop()


def answer(upstream, data, status=200, delay=0):
    upstream.responses.append((status, json.dumps(data, ensure_ascii=False).encode(), delay))


def query_result(kind, result):
    return {"status": "success", "data": {"resultType": kind, "result": result}}


def record(capsys, tmp_path):
    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 6
    assert all(len(line) <= 200 for line in lines[:5])
    saved = (tmp_path / "grafana-evidence.jsonl").read_text(encoding="utf-8").splitlines()
    assert saved[-1] == lines[5]
    assert TOKEN not in output.out
    assert "127.0.0.1" not in output.out
    evidence = json.loads(lines[5])
    assert set(evidence) == {
        "schema_version", "command", "query", "datasource", "path", "parameters", "window",
        "retrieved_at", "status", "error", "sample_summary", "presenter_link", "response",
    }
    assert evidence["retrieved_at"].endswith("Z")
    assert len(evidence["retrieved_at"]) == 24
    return lines, evidence


def evidence_comment(tmp_path):
    [command] = incident_payload.investigate(
        "SANDBOX-7", "Returned data", "Needs checking", "Check telemetry",
        tmp_path / "grafana-evidence.jsonl",
    )
    arguments = shlex.split(command)
    body_file = tmp_path / arguments[arguments.index("--body-file") + 1]
    nodes = json.loads(body_file.read_text(encoding="utf-8"))["content"][0]["content"]
    return "".join(node["text"] for node in nodes), nodes


def test_instant_proxy_evidence_and_presenter_link(grafana, capsys, tmp_path):
    expression = 'sum(rate(requests{service="日本",note="it\'s $5"}[5m]))'
    response = query_result("vector", [{"metric": {"service": "日本"}, "value": [1000, "2"]}])
    answer(grafana, response)
    assert grafana_query.main([
        "instant", "--query", expression, "--datasource", "a/b 日本", "--time", "1000"
    ]) == 0
    sent = grafana.received[0]
    assert sent.method == "GET"
    assert sent.body == b""
    assert sent.headers["Authorization"] == "Bearer " + TOKEN
    assert sent.headers["Accept"] == "application/json"
    assert urlsplit(sent.path).path == "/grafana/api/datasources/proxy/uid/a%2Fb%20%E6%97%A5%E6%9C%AC/api/v1/query"
    assert parse_qsl(urlsplit(sent.path).query) == [("query", expression), ("time", "1000")]
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: ok"
    assert lines[1] == "query: " + expression
    assert lines[2] == "datasource: a/b 日本 | window: 1970-01-01T00:16:40.000Z..1970-01-01T00:16:40.000Z | step: none"
    assert evidence["schema_version"] == 1
    assert evidence["response"] == response
    assert evidence["query"] == expression
    assert evidence["sample_summary"]["series"] == [{
        "labels": {"service": "日本"}, "count": 1,
        "latest": {"timestamp": 1000, "value": "2"}, "min": "2", "max": "2",
    }]
    prefix = PRESENTER + "/explore?schemaVersion=1&panes="
    assert evidence["presenter_link"].startswith(prefix)
    assert json.loads(unquote(evidence["presenter_link"][len(prefix):])) == {
        "A": {"datasource": "a/b 日本", "queries": [{"refId": "A", "expr": expression,
        "instant": True, "range": False}], "range": {"from": "1000000", "to": "1000000"}}
    }


def test_range_resolves_one_clock_and_keeps_all_series(grafana, capsys, tmp_path):
    response = query_result("matrix", [
        {"metric": {"z": "last", "a": "first"},
         "values": [[10, "2.0"], [30, "NaN"], [20, "-1"], [30, "+Inf"]]},
        {"metric": {}, "values": []},
        {"metric": {"other": "series"}, "values": [[12, "0"]]},
    ])
    answer(grafana, response)
    assert grafana_query.main(["range", "--query", "requests"]) == 0
    lines, evidence = record(capsys, tmp_path)
    sent = dict(parse_qsl(urlsplit(grafana.received[0].path).query))
    assert float(sent["end"]) - float(sent["start"]) == 600
    assert sent["step"] == "10"
    assert evidence["window"]["step_seconds"] == 10
    assert evidence["sample_summary"] == {
        "result_type": "matrix", "series_count": 3, "sample_count": 5,
        "unmodelled_count": 0, "discovery_items": None, "series": [
            {"labels": {"z": "last", "a": "first"}, "count": 4,
             "latest": {"timestamp": 30, "value": "+Inf"}, "min": "-1", "max": "2.0"},
            {"labels": {}, "count": 0, "latest": None, "min": None, "max": None},
            {"labels": {"other": "series"}, "count": 1,
             "latest": {"timestamp": 12, "value": "0"}, "min": "0", "max": "0"},
        ],
    }
    assert lines[3] == (
        'samples: 3 series, 5 samples | labels={"a":"first","z":"last"}; '
        'latest=+Inf@30; min=-1; max=2.0; +2 more series'
    )
    panes = json.loads(parse_qsl(urlsplit(evidence["presenter_link"]).query)[1][1])
    assert panes["A"]["queries"] == [{
        "refId": "A", "expr": "requests", "instant": False, "range": True,
    }]


@pytest.mark.parametrize("kind,result,outcome,count,series", [
    ("vector", [], "no data", 0, 0),
    ("matrix", [{"metric": {}, "values": []}], "no data", 0, 1),
    ("scalar", [1000, "0"], "observed zero", 1, 1),
    ("vector", [{"metric": {}, "value": [1000, "-0.00"]}], "observed zero", 1, 1),
    ("matrix", [{"metric": {}, "values": [[1000, "0"], [1001, "0.0"]]}],
     "observed zero", 2, 1),
    ("string", [1000, "hello"], "ok", 1, 1),
    ("scalar", [1000, "NaN"], "ok", 1, 1),
    ("scalar", [1000, "-Inf"], "ok", 1, 1),
])
def test_zero_empty_and_nonfinite_are_distinct(
    grafana, capsys, tmp_path, kind, result, outcome, count, series
):
    answer(grafana, query_result(kind, result))
    assert grafana_query.main(["instant", "--query", "requests", "--time", "1000"]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: " + outcome
    assert evidence["status"] == ("empty" if outcome == "no data" else "ok")
    assert evidence["sample_summary"]["sample_count"] == count
    assert evidence["sample_summary"]["series_count"] == series
    if kind == "string" or (kind == "scalar" and result[1] in {"NaN", "-Inf"}):
        assert evidence["sample_summary"]["series"][0]["min"] is None
        assert evidence["sample_summary"]["series"][0]["max"] is None


@pytest.mark.parametrize("kind,entry", [
    ("vector", {"metric": {}, "histogram": [1000, {"count": "1", "sum": "0"}]}),
    ("matrix", {"metric": {}, "values": [[1000, "0"]],
                "histograms": [[1001, {"count": "2", "sum": "0"}]]}),
])
def test_native_histograms_are_retained_and_never_absent_or_zero(
    grafana, capsys, tmp_path, kind, entry
):
    response = query_result(kind, [entry])
    answer(grafana, response)
    assert grafana_query.main(["range", "--query", "requests"]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: ok"
    assert "unmodelled samples=1" in lines[3]
    assert evidence["sample_summary"]["unmodelled_count"] == 1
    assert evidence["sample_summary"]["sample_count"] == (1 if kind == "vector" else 2)
    assert evidence["response"] == response


@pytest.mark.parametrize("response,items,outcome", [
    ([], 0, "no data"), ({}, 0, "no data"), (["one", "two"], 2, "discovery data"),
    ({"a": [], "b": []}, 2, "discovery data"), (None, 1, "discovery data"),
    ("raw JSON", 1, "discovery data"),
    ({"status": "success"}, 1, "discovery data"),
    ({"status": "custom", "data": []}, 2, "discovery data"),
])
def test_raw_discovery_json_and_repeated_parameters(
    grafana, capsys, tmp_path, response, items, outcome
):
    answer(grafana, response)
    assert grafana_query.main([
        "get", "--path", "/api/v1/series", "--param", 'match[]=foo{a="a b"}',
        "--param", "match[]=日本", "--param", "custom=a=b&c",
    ]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: " + outcome
    assert "window: none | step: none" in lines[2]
    assert lines[3] == f"samples: 0 series, 0 samples | discovery items={items}"
    assert evidence["query"] is None
    assert evidence["response"] == response
    assert evidence["window"] == {"start": None, "end": None, "step_seconds": None}
    assert evidence["parameters"] == [
        ["match[]", 'foo{a="a b"}'], ["match[]", "日本"], ["custom", "a=b&c"],
    ]
    proxy = "/api/datasources/proxy/uid/prometheus/api/v1/series"
    assert evidence["presenter_link"] == PRESENTER + proxy + "?" + urlsplit(
        grafana.received[0].path
    ).query


@pytest.mark.parametrize("data,items,outcome", [
    ([], 0, "no data"), ({}, 0, "no data"),
    ([{"service": "one"}, {"service": "two"}, {"service": "three"}], 3, "discovery data"),
    ({"one": [], "two": [], "three": []}, 3, "discovery data"),
    (None, 1, "discovery data"), ("raw JSON", 1, "discovery data"),
])
def test_discovery_envelopes_count_data_and_retain_response(
    grafana, capsys, tmp_path, data, items, outcome
):
    response = {"status": "success", "data": data}
    answer(grafana, response)
    assert grafana_query.main(["get", "--path", "/api/v1/series"]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: " + outcome
    assert lines[3] == f"samples: 0 series, 0 samples | discovery items={items}"
    assert evidence["status"] == ("empty" if items == 0 else "ok")
    assert evidence["sample_summary"]["result_type"] == "discovery"
    assert evidence["sample_summary"]["discovery_items"] == items
    assert evidence["response"] == response


def test_get_resolves_only_supplied_times_and_step(grafana, capsys, tmp_path):
    answer(grafana, [])
    assert grafana_query.main([
        "get", "--path", "/api/v1/anything", "--param", "time=1970-01-01T01:16:40+01:00",
        "--param", "step=0.5m",
    ]) == 0
    _, evidence = record(capsys, tmp_path)
    assert evidence["parameters"] == [["time", "1000.0"], ["step", "30.0"]]
    assert evidence["window"] == {
        "start": "1970-01-01T00:16:40.000Z", "end": "1970-01-01T00:16:40.000Z",
        "step_seconds": 30,
    }


def test_get_can_summarize_query_data_and_accept_other_json(grafana, capsys, tmp_path):
    answer(grafana, query_result("scalar", [1000, "0"]))
    assert grafana_query.main(["get", "--path", "/api/v1/query", "--param", "query=foo"]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: observed zero"
    assert evidence["sample_summary"]["result_type"] == "scalar"
    assert evidence["query"] is None
    answer(grafana, {"status": "success", "data": {"resultType": "future", "result": {}}})
    assert grafana_query.main(["get", "--path", "/future"]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: discovery data"
    assert evidence["sample_summary"]["discovery_items"] == 2


@pytest.mark.parametrize("value,seconds", [
    ("now-1.5s", 1.5), ("now-1.5m", 90), ("now-1.5h", 5400), ("now-1.5d", 129600),
])
def test_relative_time_units_share_the_invocation_clock(grafana, capsys, tmp_path, value, seconds):
    assert grafana_query.main(["range", "--query", "foo", "--start", value]) == 0
    _, evidence = record(capsys, tmp_path)
    sent = dict(evidence["parameters"])
    assert float(sent["end"]) - float(sent["start"]) == seconds


@pytest.mark.parametrize("step", ["1e100", "1e400", "1" + "0" * 400 + ".5"])
@pytest.mark.parametrize("failed", [False, True])
def test_no_step_or_observation_window_cap(configured, monkeypatch, capsys, tmp_path, step, failed):
    monkeypatch.setattr(grafana_query, "_request", lambda *args: (
        200, json.dumps(query_result("scalar", [1000, "2"])).encode(),
    ))
    assert grafana_query.main(["instant", "--query=up"]) == 0
    record(capsys, tmp_path)
    response = {"status": "error", "error": "bad query"} if failed else query_result("vector", [])
    monkeypatch.setattr(grafana_query, "_request", lambda *args: (200, json.dumps(response).encode()))
    assert grafana_query.main([
        "range", "--query", "foo", "--start", "0", "--end", "1000000000", "--step", step
    ]) == (1 if failed else 0)
    lines, evidence = record(capsys, tmp_path)
    if step in ("1e100", "1e400"):
        exponent = int(step[2:])
        assert evidence["window"]["step_seconds"] == 10 ** exponent
        assert dict(evidence["parameters"])["step"] == "1" + "0" * exponent
    else:
        assert '"step_seconds":' + step in lines[5]
        assert dict(evidence["parameters"])["step"] == step
    body, _ = evidence_comment(tmp_path)
    assert "latest 2 at " in body
    assert ("unavailable: query error" if failed else "no data") in body
    displayed_step = re.search(r", step (\S+)s; retrieved", body)[1]
    assert Decimal(displayed_step) == Decimal(step)
    assert "evidence file unreadable" not in body


@pytest.mark.parametrize("status,response,kind,message,retained", [
    (401, {"secret": TOKEN}, "token_rejected", "token rejected", None),
    (403, {"secret": TOKEN}, "http_error", "HTTP 403", None),
    (500, {"secret": TOKEN}, "http_error", "HTTP 500", None),
    (302, {"secret": TOKEN}, "http_error", "HTTP 302", None),
    (200, {"status": "error", "error": "bad expression"}, "query_error", "query error",
     {"status": "error", "error": "bad expression"}),
])
def test_retrieval_errors_have_unavailable_evidence_without_error_body(
    grafana, capsys, tmp_path, status, response, kind, message, retained
):
    answer(grafana, response, status)
    assert grafana_query.main(["instant", "--query", "requests"]) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: " + message
    assert lines[3] == "samples: 0 series, 0 samples | unavailable"
    assert evidence["status"] == "unavailable"
    assert evidence["error"] == {
        "kind": kind, "message": message,
        "http_status": status if kind != "query_error" else None,
    }
    assert evidence["response"] == retained
    assert len(grafana.received) == 1


@pytest.mark.parametrize("body", [
    b"not JSON", b"{", b'{"value":NaN}',
    b'{"status":"success","data":{"resultType":"vector","result":{}}}',
    b'{"status":"success","data":{"resultType":"vector","result":[{}]}}',
    b'{"status":"success","data":{"resultType":"scalar","result":[1,2]}}',
    b'{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[[1]]}]}}',
])
def test_malformed_query_responses_are_unavailable(grafana, capsys, tmp_path, body):
    grafana.responses.append((200, body, 0))
    assert grafana_query.main(["instant", "--query", "requests"]) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: malformed response"
    assert evidence["sample_summary"]["result_type"] is None
    assert evidence["error"]["kind"] == "malformed_response"


def test_stopped_grafana_is_unreachable(grafana, capsys, tmp_path):
    grafana.stop()
    assert grafana_query.main(["get", "--path", "/api/v1/labels"]) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: unreachable"
    assert evidence["response"] is None


def test_timeout_is_ten_elapsed_seconds(grafana, capsys, tmp_path):
    answer(grafana, query_result("vector", []), delay=11)
    before = time.monotonic()
    assert grafana_query.main(["instant", "--query", "requests"]) == 1
    elapsed = time.monotonic() - before
    assert 9.8 <= elapsed < 11
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: timeout after 10s"
    assert evidence["error"] == {
        "kind": "timeout", "message": "timeout after 10s", "http_status": None,
    }


def test_timeout_includes_a_trickling_response_body(grafana, monkeypatch, capsys, tmp_path):
    """An upstream that keeps sending must not reset the elapsed deadline."""
    finished = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    if finished.wait(0.5):
                        break
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    worker.start()
    monkeypatch.setenv("DEMO_GRAFANA_URL", f"http://127.0.0.1:{server.server_address[1]}")
    before = time.monotonic()
    try:
        assert grafana_query.main(["instant", "--query", "requests"]) == 1
        assert 9.8 <= time.monotonic() - before < 11
        lines, evidence = record(capsys, tmp_path)
        assert lines[0] == "grafana-query: unavailable: timeout after 10s"
        assert evidence["response"] is None
    finally:
        finished.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_full_record_is_not_clipped_and_attempts_append(grafana, capsys, tmp_path):
    expression = 'requests{note="' + "x\n\t日本\u0085\u2028\u2029" * 300 + '"}'
    response = query_result("vector", [
        {"metric": {"label": "x\u0085\u2028\u2029" * 500}, "value": [1000, "1"]},
    ])
    answer(grafana, response)
    assert grafana_query.main(["instant", "--query", expression, "--time", "1000"]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert len(lines[1]) == 200
    assert lines[1].endswith("...")
    assert evidence["query"] == expression
    assert evidence["response"] == response
    assert len(lines[5]) > 2000
    assert grafana_query.main(["get", "--path", "/api/v1/labels"]) == 0
    record(capsys, tmp_path)
    attempts = (tmp_path / "grafana-evidence.jsonl").read_text().splitlines()
    assert len(attempts) == 2
    assert json.loads(attempts[0]) == evidence


def test_evidence_write_failure_has_five_lines_and_exit_three(grafana, capsys, tmp_path):
    (tmp_path / "grafana-evidence.jsonl").mkdir()
    assert grafana_query.main(["instant", "--query", "requests", "--time", "1000"]) == 3
    output = capsys.readouterr()
    lines = output.out.splitlines()
    assert output.err == ""
    assert len(lines) == 5
    assert lines[0] == "grafana-query: unavailable: evidence file could not be written"
    assert lines[4].startswith("evidence: unavailable | presenter: " + PRESENTER)


@pytest.mark.parametrize("body,arguments", [
    (b'{"status":"success","data":["secret\\ud800"]}', ["get", "--path", "/api/v1/labels"]),
    (b'{"status":"success","data":{"secret\\udfff":"value"}}', ["get", "--path", "/api/v1/series"]),
    (b'{"status":"success","data":{"nested":[{"value":"secret\\ud800"}]}}', ["get", "--path", "/future"]),
    (b'{"status":"success","data":{"resultType":"string","result":[1000,"secret\\udfff"]}}', ["instant", "--query", "up"]),
    (b'{"status":"error","error":"secret\\ud800"}', ["instant", "--query", "up"]),
    (b'{"status":"success","data":{"secret\\udfff":true}}', ["instant", "--query", "up"]),
    (b'{"status":"success","data":{"resultType":"streams","result":[{"stream":{},"values":[["1000000000000","secret\\ud800"]]}]}}', ["logs", "--query", "{}"]),
    (b'{"traces":[{"traceID":"abc","rootServiceName":"secret\\ud800"}]}', ["traces", "--query", "{}"]),
    (b'{"trace":{"resourceSpans":[]},"future":"secret\\ud800"}', ["trace", "--id", "abc"]),
    (b'{"status":"success","data":' + b'[' * 750 + b'"secret"' + b']' * 750 + b'}', ["get", "--path", "/future"]),
    (b'{"status":"success","data":' + b'[' * 10000 + b'"secret"' + b']' * 10000 + b'}', ["get", "--path", "/future"]),
    (b'{"status":"success","data":{"secret":1e999999999999999999999}}', ["get", "--path", "/future"]),
    (b'{"status":"success","data":{"secret":1e-999999999999999999999}}', ["get", "--path", "/future"]),
], ids=["high-surrogate", "low-surrogate-key", "nested-surrogate", "sample-surrogate",
        "error-body-surrogate", "malformed-surrogate", "log-surrogate", "search-surrogate",
        "trace-surrogate", "serializer-recursion", "decoder-recursion",
        "positive-exponent", "negative-exponent"])
@pytest.mark.parametrize("has_previous", [False, True], ids=["new-file", "append"])
def test_unrepresentable_response_is_bounded_cli_failure(
    grafana, monkeypatch, capsys, tmp_path, body, arguments, has_previous
):
    """Real HTTP and a fresh CLI process must not emit success or partial JSONL."""
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parent.parent))
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8:strict")
    if body.count(b"[") == 750:
        # Isolate a successful decode from the recursive serializer's failure.
        assert json.loads(body)["status"] == "success"
    if b"999999999999999999999" in body:
        # The syntax is valid JSON; Decimal cannot represent this exponent.
        assert json.loads(body, parse_float=str)["status"] == "success"
    evidence_path = tmp_path / "grafana-evidence.jsonl"
    # A retained earlier observation must survive a representation failure intact.
    previous = b""
    previous_record = None
    if has_previous:
        answer(grafana, query_result("vector", [{"metric": {}, "value": [1000, "2"]}]))
        assert grafana_query.main(["instant", "--query", "up", "--time", "1000"]) == 0
        _, previous_record = record(capsys, tmp_path)
        previous = evidence_path.read_bytes()
    grafana.responses.append((200, body, 0))
    result = subprocess.run(
        [sys.executable, "-m", "grafana_jsm_sandbox.grafana_query", *arguments],
        cwd=tmp_path, capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 1
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert len(lines) == 6
    assert all(len(line) <= 200 for line in lines[:5])
    assert lines[0] == "grafana-query: unavailable: response could not be represented"
    assert "secret" not in result.stdout
    assert TOKEN not in result.stdout
    assert "\\ud800" not in result.stdout and "\\udfff" not in result.stdout
    assert "\ufffd" not in result.stdout
    saved = evidence_path.read_bytes()
    assert saved == previous + (lines[5] + "\n").encode("utf-8")
    evidence = json.loads(lines[5])
    assert evidence["status"] == "unavailable"
    assert evidence["response"] is None
    assert evidence["error"] == {
        "kind": "malformed_response", "message": "response could not be represented",
        "http_status": None,
    }
    assert evidence["sample_summary"] == {
        "result_type": None, "series_count": 0, "sample_count": 0,
        "unmodelled_count": 0, "discovery_items": None, "series": [],
    }
    if arguments[0] == "logs":
        assert evidence["log_summary"] is None
    if arguments[0] in {"traces", "trace"}:
        assert evidence["trace_summary"] is None
    assert evidence["retrieved_at"].endswith("Z")
    assert evidence["presenter_link"].startswith(PRESENTER)
    retained, unreadable = incident_payload.read_evidence(evidence_path)
    assert unreadable is None
    assert retained == ([previous_record] if has_previous else []) + [evidence]
    comment, _ = evidence_comment(tmp_path)
    assert "response could not be represented" in comment
    assert "evidence file unreadable" not in comment
    if has_previous:
        assert "latest 2 at 1970-01-01T00:16:40.000Z" in comment


def test_serializable_discovery_preserves_unicode_and_decimal_values(grafana, capsys, tmp_path):
    body = (
        b'{"status":"success","data":{"unicode":"\\ud83d\\ude00\\u65e5",'
        b'"tiny":1e-400,"large":1e400,"nested":' + b'[' * 100 + b'42' + b']' * 100 + b'}}'
    )
    grafana.responses.append((200, body, 0))
    assert grafana_query.main(["get", "--path", "/future"]) == 0
    lines, evidence = record(capsys, tmp_path)
    saved_response = json.loads(lines[5], parse_float=Decimal)["response"]
    assert saved_response == json.loads(body, parse_float=Decimal)
    assert saved_response["data"]["unicode"] == "😀日"
    assert evidence["status"] == "ok"
    retained, unreadable = incident_payload.read_evidence(tmp_path / "grafana-evidence.jsonl")
    assert unreadable is None
    assert retained[0]["response"] == saved_response


@pytest.fixture
def configured(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEMO_GRAFANA_URL", "http://upstream.example.invalid")
    monkeypatch.setenv("DEMO_GRAFANA_PRESENTER_URL", PRESENTER)
    monkeypatch.setenv("DEMO_GRAFANA_VIEWER_TOKEN", TOKEN)


@pytest.mark.parametrize("value", ["1e-400", "0", "NaN", "+Inf", "not numeric"])
def test_cli_sample_values_reach_comment_without_float_underflow(
    configured, monkeypatch, capsys, tmp_path, value
):
    monkeypatch.setattr(grafana_query, "_request", lambda *args: (
        200, json.dumps(query_result("string", [1000.5, value])).encode(),
    ))
    assert grafana_query.main(["instant", "--query=up"]) == 0
    lines, _ = record(capsys, tmp_path)
    body, _ = evidence_comment(tmp_path)
    assert ("observed zero" in body) == (value == "0")
    assert lines[0] == "grafana-query: " + ("observed zero" if value == "0" else "ok")
    if value != "0":
        assert f"latest {value} at 1970-01-01T00:16:40.500Z" in body
    if value == "1e-400":
        assert "min 1e-400, max 1e-400" in body


def test_unrepresentable_metric_timestamp_is_unavailable_in_query_and_comment(
    grafana, capsys, tmp_path
):
    answer(grafana, query_result("scalar", [253402300800, "2"]))

    assert grafana_query.main(["instant", "--query=up", "--time=1000"]) == 1
    lines, evidence = record(capsys, tmp_path)
    body, _ = evidence_comment(tmp_path)

    assert lines[0] == "grafana-query: unavailable: malformed response"
    assert evidence["response"]["data"]["result"] == [253402300800, "2"]
    assert body.endswith("Evidence: unavailable: malformed response")


@pytest.mark.parametrize("kind,result,expected", [
    ("matrix", [{"metric": {}, "values": [[-62135596801, "2"], [1000, "3"]]}],
     "latest 3 at 1970-01-01T00:16:40.000Z; min 2, max 3"),
    ("vector", [{"metric": {}, "histogram": [253402300800, {"count": "1"}]}],
     "unmodelled samples=1"),
])
def test_undisplayed_metric_timestamps_keep_their_existing_finite_only_contract(
    grafana, capsys, tmp_path, kind, result, expected
):
    answer(grafana, query_result(kind, result))

    assert grafana_query.main(["range", "--query=up", "--start=1000", "--end=1001"]) == 0
    _, evidence = record(capsys, tmp_path)
    body, _ = evidence_comment(tmp_path)

    assert evidence["response"]["data"]["result"] == result
    assert expected in body and "Evidence unavailable" not in body


def test_extreme_step_query_error_reaches_unavailable_comment(
    configured, monkeypatch, capsys, tmp_path
):
    monkeypatch.setattr(grafana_query, "_request", lambda *args: (
        200, b'{"status":"error","error":"bad query"}',
    ))
    assert grafana_query.main(["range", "--query=up", "--step", "1e400"]) == 1
    record(capsys, tmp_path)
    body, _ = evidence_comment(tmp_path)
    assert "Observation: Evidence unavailable" in body
    assert body.endswith("Evidence: unavailable: query error")


def test_equals_path_with_leading_minus_reaches_path_validation(configured, capsys, tmp_path):
    assert grafana_query.main(["get", "--path=-up"]) == 2
    output = capsys.readouterr()
    assert output.err == "grafana-query: error: --path must be an absolute datasource-relative path\n"
    assert not (tmp_path / "grafana-evidence.jsonl").exists()


@pytest.mark.parametrize("arguments", [
    ["instant", "--query=up"], ["get", "--path=/api/v1/labels"],
])
def test_presenter_base_path_is_encoded_for_comment(
    configured, monkeypatch, capsys, tmp_path, arguments
):
    base = "http://localhost:3000/grafana(demo)/already%20encoded"
    monkeypatch.setenv("DEMO_GRAFANA_PRESENTER_URL", base)
    monkeypatch.setattr(grafana_query, "_request", lambda *args: (
        200, json.dumps(query_result("scalar", [1000, "2"])).encode(),
    ))
    assert grafana_query.main(arguments) == 0
    _, evidence = record(capsys, tmp_path)
    body, nodes = evidence_comment(tmp_path)
    [link] = [mark["attrs"]["href"] for node in nodes for mark in node.get("marks", [])
              if mark["type"] == "link"]
    assert link == evidence["presenter_link"]
    assert link.startswith("http://localhost:3000/grafana%28demo%29/already%20encoded/")
    assert unquote(urlsplit(link).path).startswith("/grafana(demo)/already encoded/")
    assert "evidence file unreadable" not in body


@pytest.mark.parametrize("arguments,parameters", [
    (["instant", "--query=-up"], [("query", "-up")]),
    (["range", "--query=-up"], [("query", "-up")]),
    (["get", "--path=/api/v1/query", "--param=query=-up", "--param=-name=-value"],
     [("query", "-up"), ("-name", "-value")]),
])
def test_equals_arguments_preserve_leading_minus_values(
    configured, monkeypatch, capsys, tmp_path, arguments, parameters
):
    monkeypatch.setattr(grafana_query, "_request", lambda *args: (
        200, json.dumps(query_result("scalar", [1000, "-1"])).encode(),
    ))
    assert grafana_query.main(arguments) == 0
    _, evidence = record(capsys, tmp_path)
    assert evidence["parameters"][:len(parameters)] == [list(pair) for pair in parameters]
    body, _ = evidence_comment(tmp_path)
    assert "-up" in body and "latest -1 at " in body


@pytest.mark.parametrize("arguments,flag", [
    ([], "command"), (["instant"], "--query"), (["range"], "--query"), (["get"], "--path"),
    (["--query", "x", "instant"], "command"),
    (["instant", "--query", "x", "--time", "NaN"], "--time"),
    (["instant", "--query", "x", "--time", "1970-01-01T00:00:00"], "--time"),
    (["instant", "--query", "x", "--time", "now-0m"], "--time"),
    (["instant", "--query", "x", "--datasource", ""], "--datasource"),
    (["instant", "--query", "x", "--url", "secret"], "--url"),
    (["instant", "--query", "x", "--token", "secret"], "--token"),
    (["range", "--query", "x", "--start", "2", "--end", "1"], "--start"),
    (["range", "--query", "x", "--step", "0"], "--step"),
    (["range", "--query", "x", "--step", "inf"], "--step"),
    (["get", "--path", "https://bad.example.invalid/api"], "--path"),
    (["get", "--path", "//bad.example.invalid/api"], "--path"),
    (["get", "--path", "/api?q=x"], "--path"),
    (["get", "--path", "/api#x"], "--path"),
    (["get", "--path", "api"], "--path"),
    (["get", "--path", "/api", "--param", "broken"], "--param"),
    (["get", "--path", "/api", "--param", "=x"], "--param"),
    (["get", "--path", "/api", "--param", "step=-1"], "--param"),
])
def test_invalid_arguments_write_no_evidence(configured, capsys, tmp_path, arguments, flag):
    assert grafana_query.main(arguments) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert len(output.err.splitlines()) == 1
    assert output.err.startswith("grafana-query: error: ")
    assert flag in output.err
    assert "secret" not in output.err
    assert not (tmp_path / "grafana-evidence.jsonl").exists()


@pytest.mark.parametrize("variable,value", [
    ("DEMO_GRAFANA_URL", ""),
    ("DEMO_GRAFANA_URL", "http://user:secret@upstream.example.invalid"),
    ("DEMO_GRAFANA_URL", "http://upstream.example.invalid:70000"),
    ("DEMO_GRAFANA_URL", "file:///tmp/secret"),
    ("DEMO_GRAFANA_URL", "http://upstream.example.invalid/?secret"),
    ("DEMO_GRAFANA_PRESENTER_URL", ""),
    ("DEMO_GRAFANA_PRESENTER_URL", "http://user:secret@presenter.example.invalid"),
    ("DEMO_GRAFANA_VIEWER_TOKEN", ""),
    ("DEMO_GRAFANA_VIEWER_TOKEN", "secret\n"),
    ("DEMO_GRAFANA_VIEWER_TOKEN", "secret\rvalue"),
])
def test_invalid_configuration_is_token_free_even_when_disabled(
    configured, monkeypatch, capsys, tmp_path, variable, value
):
    monkeypatch.setenv("DEMO_INVESTIGATION_ENABLED", "false")
    monkeypatch.setenv(variable, value)
    assert grafana_query.main(["instant", "--query", "x"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert len(output.err.splitlines()) == 1
    assert variable in output.err
    assert "secret" not in output.err
    assert not (tmp_path / "grafana-evidence.jsonl").exists()


def test_module_entrypoint_and_console_script(configured, tmp_path):
    repository = Path(__file__).resolve().parent.parent
    project = tomllib.loads((repository / "pyproject.toml").read_text())
    assert project["project"]["scripts"]["grafana-query"] == (
        "grafana_jsm_sandbox.grafana_query:main"
    )
    result = subprocess.run(
        [sys.executable, "-m", "grafana_jsm_sandbox.grafana_query", "instant"],
        cwd=repository, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "grafana-query: error: the following arguments are required: --query\n"


@pytest.mark.parametrize("port", ["", "0", "65536", "not-a-port"])
def test_invalid_default_presenter_port_is_named(configured, monkeypatch, capsys, port):
    monkeypatch.delenv("DEMO_GRAFANA_PRESENTER_URL")
    monkeypatch.setenv("GRAFANA_HOST_PORT", port)
    assert grafana_query.main(["instant", "--query", "foo"]) == 2
    output = capsys.readouterr()
    assert "GRAFANA_HOST_PORT" in output.err
    assert output.out == ""
