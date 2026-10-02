"""Tempo evidence through the CLI, real fake HTTP, stdout and JSONL."""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

import pytest

from grafana_jsm_sandbox import grafana_query
from tests.grafana_upstream import FakeGrafana

TOKEN = "viewer-test-secret"
PRESENTER = "https://presenter.example.invalid/grafana"
TRACE_ID = "0123456789abcdef0123456789abcdef"
ROOT_ID = "0123456789abcdef"
CHILD_ID = "123456789abcdef0"


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


def record(capsys, tmp_path):
    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 6
    assert all(len(line) <= 200 for line in lines[:5])
    assert TOKEN not in output.out and "127.0.0.1" not in output.out
    assert (tmp_path / "grafana-evidence.jsonl").read_text().splitlines()[-1] == lines[5]
    return lines, json.loads(lines[5])


def panes(evidence):
    return json.loads(dict(parse_qsl(urlsplit(evidence["presenter_link"]).query))["panes"])


def test_traceql_search_matches_request_evidence_and_explore(grafana, capsys, tmp_path):
    query = '{ resource.service.name = "日本" && span:name = "it\'s $5" }'
    response = {"traces": [
        {"traceID": "ABC", "durationMs": 5, "spanSets": [{"matched": 99}]},
        {"traceID": TRACE_ID, "rootServiceName": "rolldice", "rootTraceName": "GET /rolldice",
         "startTimeUnixNano": "1000000000001", "durationMs": 800},
    ], "metrics": {"completedJobs": 1, "totalJobs": 2, "unknown": 10}, "future": "preserved"}
    answer(grafana, response)
    assert grafana_query.main([
        "traces", "--query=" + query, "--datasource=a/b 日本", "--start=1000.999",
        "--end=1001.999", "--limit=2",
    ]) == 0
    sent = grafana.received[0]
    assert sent.method == "GET" and sent.body == b""
    assert sent.headers["Authorization"] == "Bearer " + TOKEN
    assert sent.headers["Accept"] == "application/json"
    assert urlsplit(sent.path).path == (
        "/grafana/api/datasources/proxy/uid/a%2Fb%20%E6%97%A5%E6%9C%AC/api/search"
    )
    expected = [("q", query), ("start", "1000"), ("end", "1001"), ("limit", "2")]
    assert parse_qsl(urlsplit(sent.path).query) == expected
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: ok"
    assert evidence["command"] == "traces" and evidence["query"] == query
    assert evidence["response"] == response and evidence["parameters"] == [list(p) for p in expected]
    assert evidence["sample_summary"] == {
        "result_type": "traces", "series_count": 0, "sample_count": 0,
        "unmodelled_count": 0, "discovery_items": None, "series": [],
    }
    assert evidence["window"] == {"start": "1970-01-01T00:16:40.000Z",
                                  "end": "1970-01-01T00:16:41.000Z", "step_seconds": None}
    assert evidence["trace_summary"] == {
        "kind": "search", "trace_count": 2, "limit_reached": True,
        "completed_jobs": 1, "total_jobs": 2, "excerpts": [
            {"trace_id": TRACE_ID, "root_service": "rolldice", "root_name": "GET /rolldice",
             "start_time_ns": "1000000000001", "duration_ms": 800},
            {"trace_id": "00000000000000000000000000000abc", "root_service": None,
             "root_name": None, "start_time_ns": None, "duration_ms": 5},
        ],
    }
    assert panes(evidence) == {"A": {"datasource": "a/b 日本", "queries": [{
        "refId": "A", "datasource": {"uid": "a/b 日本", "type": "tempo"},
        "queryType": "traceql", "query": query, "filters": [], "limit": 2,
    }], "range": {"from": "1000000", "to": "1001000"}}}
    assert "limit reached" in lines[3]


def encoded(identifier):
    return base64.b64encode(bytes.fromhex(identifier)).decode()


def fetched_trace():
    return {"trace": {"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "rolldice"}},
            {"key": "unmodelled", "value": {"arrayValue": {"values": [{"boolValue": True}]}}},
        ]}, "scopeSpans": [{"scope": {"name": "demo"}, "spans": [
            {"traceId": encoded(TRACE_ID), "spanId": encoded(ROOT_ID), "name": "GET /rolldice",
             "kind": "SPAN_KIND_SERVER", "startTimeUnixNano": "1000000000001",
             "endTimeUnixNano": "1000800000001", "status": {"code": "STATUS_CODE_OK"},
             "events": [{"name": "literal ' $() 日本"}]},
            {"traceId": encoded(TRACE_ID), "spanId": encoded(CHILD_ID),
             "parentSpanId": encoded(ROOT_ID), "name": "rolldice.wait", "kind": 1,
             "startTimeUnixNano": "1000100000001", "endTimeUnixNano": "1000600000001"},
        ]}],
    }]}, "metrics": {"inspectedBytes": "99"}, "unknown": [1, 2]}


def test_fetch_v2_has_unbounded_lookup_and_observed_span_envelope(grafana, capsys, tmp_path):
    response = fetched_trace()
    answer(grafana, response)
    assert grafana_query.main(["trace", "--id=" + TRACE_ID.upper()]) == 0
    sent = grafana.received[0]
    assert sent.method == "GET" and sent.body == b""
    assert sent.headers["Accept"] == "application/json"
    assert sent.path == "/grafana/api/datasources/proxy/uid/tempo/api/v2/traces/" + TRACE_ID
    lines, evidence = record(capsys, tmp_path)
    assert evidence["command"] == "trace" and evidence["query"] == TRACE_ID
    assert evidence["parameters"] == []
    assert evidence["window"] == {"start": None, "end": None, "step_seconds": None}
    assert evidence["response"] == response
    assert evidence["sample_summary"] == {
        "result_type": "trace", "series_count": 0, "sample_count": 0,
        "unmodelled_count": 0, "discovery_items": None, "series": [],
    }
    assert evidence["trace_summary"] == {
        "kind": "trace", "trace_id": TRACE_ID, "backend_status": "complete",
        "backend_message": None, "span_count": 2, "services": ["rolldice"],
        "root_span_count": 1, "missing_parent_count": 0,
        "start_time_ns": "1000000000001", "end_time_ns": "1000800000001", "duration_ns": "800000000",
        "spans": [
            {"span_id": ROOT_ID, "parent_span_id": None, "service": "rolldice",
             "name": "GET /rolldice", "kind": "SPAN_KIND_SERVER", "status": "STATUS_CODE_OK",
             "start_time_ns": "1000000000001", "end_time_ns": "1000800000001", "duration_ns": "800000000"},
            {"span_id": CHILD_ID, "parent_span_id": ROOT_ID, "service": "rolldice",
             "name": "rolldice.wait", "kind": "SPAN_KIND_INTERNAL", "status": "STATUS_CODE_UNSET",
             "start_time_ns": "1000100000001", "end_time_ns": "1000600000001", "duration_ns": "500000000"},
        ],
    }
    assert panes(evidence) == {"A": {"datasource": "tempo", "queries": [{
        "refId": "A", "datasource": {"uid": "tempo", "type": "tempo"},
        "queryType": "traceId", "query": TRACE_ID,
    }], "range": {"from": "1000000", "to": "1000801"}}}
    assert "lookup by ID" in lines[2]
    assert "2 observed spans" in lines[3]


@pytest.mark.parametrize("command,response,expected", [
    ("traces", {}, {"kind": "search", "trace_count": 0, "limit_reached": False,
                    "completed_jobs": None, "total_jobs": None, "excerpts": []}),
    ("traces", {"metrics": {"completedJobs": 0, "totalJobs": 0}},
     {"kind": "search", "trace_count": 0, "limit_reached": False,
      "completed_jobs": 0, "total_jobs": 0, "excerpts": []}),
    ("trace", {"trace": {}}, {"kind": "trace", "trace_id": TRACE_ID,
        "backend_status": "complete", "backend_message": None, "span_count": 0,
        "services": [], "root_span_count": 0, "missing_parent_count": 0,
        "start_time_ns": None, "end_time_ns": None, "duration_ns": None, "spans": []}),
])
def test_protocol_empty_fields_remain_no_returned_data(
    grafana, capsys, tmp_path, command, response, expected
):
    answer(grafana, response)
    flag = "--query={ true }" if command == "traces" else "--id=" + TRACE_ID
    assert grafana_query.main([command, flag]) == 0
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: no data" and evidence["status"] == "empty"
    assert evidence["trace_summary"] == expected
    assert evidence["sample_summary"]["sample_count"] == 0
    assert evidence["sample_summary"]["result_type"] == command
    assert "log_summary" not in evidence
    if command == "trace":
        assert panes(evidence)["A"]["range"] == {"from": "now-10m", "to": "now"}
    else:
        parameters = dict(evidence["parameters"])
        assert parameters["limit"] == "20" and evidence["datasource"] == "tempo"
        for key in ("start", "end"):
            timestamp = datetime.fromisoformat(evidence["window"][key].replace("Z", "+00:00"))
            assert timestamp.timestamp() == int(parameters[key])
        assert int(parameters["end"]) - int(parameters["start"]) == 600


def test_partial_backend_and_missing_parents_are_mechanical_caveats(grafana, capsys, tmp_path):
    response = fetched_trace()
    response["status"] = "PARTIAL"
    response["message"] = "trace exceeds limit ' $() 日本"
    spans = response["trace"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans[0]["parentSpanId"] = encoded("fedcba9876543210")
    for index in range(3, 9):
        extra = copy.deepcopy(spans[1])
        extra["spanId"] = f"{index:016x}"
        extra["parentSpanId"] = ROOT_ID
        extra["traceId"] = TRACE_ID
        extra["name"] = "equal-duration " + str(index)
        spans.append(extra)
    answer(grafana, response)
    assert grafana_query.main(["trace", "--id=" + TRACE_ID]) == 0
    lines, evidence = record(capsys, tmp_path)
    summary = evidence["trace_summary"]
    assert summary["backend_status"] == "partial" and summary["backend_message"] == response["message"]
    assert summary["span_count"] == 8 and summary["root_span_count"] == 0
    assert summary["missing_parent_count"] == 1
    assert [span["span_id"] for span in summary["spans"]] == [ROOT_ID,
        "0000000000000003", "0000000000000004", "0000000000000005", "0000000000000006"]
    assert summary["duration_ns"] == "800000000" and evidence["response"] == response
    assert "backend partial" in lines[3] and "1 missing parents" in lines[3]


def test_search_is_only_longest_returned_and_preserves_unmodelled_spans(grafana, capsys, tmp_path):
    response = {"traces": [
        {"traceID": "4", "durationMs": 2, "spanSets": [{"matched": 999, "spans": []}]},
        {"traceID": "3", "durationMs": 3}, {"traceID": "2", "durationMs": 3},
        {"traceID": "1"},
    ]}
    answer(grafana, response)
    assert grafana_query.main(["traces", "--query={ true }", "--limit=10"]) == 0
    _, evidence = record(capsys, tmp_path)
    summary = evidence["trace_summary"]
    assert summary["trace_count"] == 4 and summary["limit_reached"] is False
    assert [trace["trace_id"] for trace in summary["excerpts"]] == [
        "00000000000000000000000000000002", "00000000000000000000000000000003",
        "00000000000000000000000000000004",
    ]
    assert evidence["response"] == response


@pytest.mark.parametrize("command,arguments", [
    ("traces", []), ("trace", []),
    *[("traces", ["--query={ true }", flag]) for flag in (
        "--limit=0", "--limit=-1", "--limit=1.5", "--limit=true", "--step=1s",
        "--direction=forward", "--start=-0.1", "--end=4294967296", "--datasource=",
    )],
    ("traces", ["--query={ true }", "--start=2", "--end=1"]),
    *[("trace", ["--id=" + value]) for value in ("", "0", "0" * 32, "1" * 33, "xyz", "0x12")],
    ("trace", ["--id=" + TRACE_ID, "--start=1"]),
])
def test_invalid_tempo_invocations_request_nothing_and_write_nothing(
    grafana, capsys, tmp_path, command, arguments
):
    assert grafana_query.main([command, *arguments]) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err.startswith("grafana-query: error:")
    assert grafana.received == [] and not (tmp_path / "grafana-evidence.jsonl").exists()


@pytest.mark.parametrize("identifier,expected", [
    ("F", "0000000000000000000000000000000f"),
    ("bb3e48fec3f3dc12f35c1ea4d7796fd", "0bb3e48fec3f3dc12f35c1ea4d7796fd"),
])
def test_trimmed_input_ids_are_canonical_for_lookup_and_evidence(
    grafana, capsys, tmp_path, identifier, expected
):
    answer(grafana, {"trace": {}})
    assert grafana_query.main(["trace", "--id=" + identifier]) == 0
    _, evidence = record(capsys, tmp_path)
    assert evidence["query"] == expected and evidence["trace_summary"]["trace_id"] == expected
    assert grafana.received[0].path.endswith("/api/v2/traces/" + expected)


@pytest.mark.parametrize("response", [
    None, [], {"traces": None}, {"traces": {}}, {"metrics": None}, {"metrics": []},
    {"error": "backend query failed"}, {"message": "backend query failed"},
    {"traces": [{"traceID": "0"}]}, {"traces": [{"traceID": 123}]},
    {"traces": [{"traceID": "1", "durationMs": -1}]},
    {"traces": [{"traceID": "1", "durationMs": True}]},
    {"traces": [{"traceID": "1", "durationMs": "10"}]},
    {"traces": [{"traceID": "1", "durationMs": 4294967296}]},
    {"traces": [{"traceID": "1", "rootServiceName": None}]},
    {"traces": [{"traceID": "1", "rootTraceName": 1}]},
    {"traces": [{"traceID": "1", "startTimeUnixNano": "1.5"}]},
    {"traces": [{"traceID": "1", "startTimeUnixNano": "18446744073709551616"}]},
    {"metrics": {"completedJobs": True}}, {"metrics": {"totalJobs": -1}},
])
def test_malformed_search_keeps_raw_response_and_null_summary(grafana, capsys, tmp_path, response):
    answer(grafana, response)
    assert grafana_query.main(["traces", "--query={ true }"]) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: malformed response"
    assert evidence["status"] == "unavailable" and evidence["trace_summary"] is None
    assert evidence["error"]["kind"] == "malformed_response" and evidence["response"] == response


def malformed_traces():
    yield None
    yield {}
    yield {"trace": None}
    yield {"trace": []}
    yield {"trace": {"batches": []}}
    yield {"trace": {"resourceSpans": None}}
    yield {"trace": {}, "status": "UNKNOWN"}
    yield {"trace": {}, "status": True}
    yield {"trace": {}, "status": 2}
    yield {"trace": {}, "message": 5}
    for field, value in (
        ("traceId", encoded("1" * 32)), ("traceId", "01"),
        ("spanId", encoded("0" * 16)), ("spanId", encoded("1" * 32)),
        ("spanId", "not-base64"), ("parentSpanId", None),
        ("startTimeUnixNano", 1000), ("startTimeUnixNano", "1e9"),
        ("endTimeUnixNano", "1000000000000"), ("endTimeUnixNano", "-1"),
        ("endTimeUnixNano", "18446744073709551616"),
        ("kind", "SERVER"), ("kind", 6), ("status", None), ("status", {"code": 3}),
        ("name", 1),
    ):
        response = fetched_trace()
        response["trace"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0][field] = value
        yield response
    response = fetched_trace()
    spans = response["trace"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans.append(copy.deepcopy(spans[0]))
    yield response
    response = fetched_trace()
    response["trace"]["resourceSpans"][0]["scopeSpans"] = None
    yield response
    response = fetched_trace()
    response["trace"]["resourceSpans"][0]["resource"]["attributes"][0]["value"] = {"intValue": "1"}
    yield response


@pytest.mark.parametrize("response", list(malformed_traces()))
def test_malformed_fetch_keeps_raw_response_and_null_summary(grafana, capsys, tmp_path, response):
    answer(grafana, response)
    assert grafana_query.main(["trace", "--id=" + TRACE_ID]) == 1
    lines, evidence = record(capsys, tmp_path)
    assert lines[0] == "grafana-query: unavailable: malformed response"
    assert evidence["status"] == "unavailable" and evidence["trace_summary"] is None
    assert evidence["error"]["kind"] == "malformed_response" and evidence["response"] == response
    assert panes(evidence)["A"]["range"] == {"from": "now-10m", "to": "now"}


@pytest.mark.parametrize("command,status,expected", [
    ("trace", 404, "http_error"), ("trace", 401, "token_rejected"),
    ("traces", 500, "http_error"), ("traces", 200, "query_error"),
])
def test_tempo_http_and_query_failure_are_not_empty_data(
    grafana, capsys, tmp_path, command, status, expected
):
    response = {"status": "error", "error": "secret response body"}
    answer(grafana, response, status)
    flag = "--id=" + TRACE_ID if command == "trace" else "--query={ true }"
    assert grafana_query.main([command, flag]) == 1
    _, evidence = record(capsys, tmp_path)
    assert evidence["error"]["kind"] == expected
    assert evidence["trace_summary"] is None and evidence["status"] == "unavailable"
    assert evidence["response"] == (response if status == 200 else None)
