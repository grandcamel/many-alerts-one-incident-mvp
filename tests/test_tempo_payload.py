"""Tempo evidence through the public incident-payload investigation command."""

from __future__ import annotations

import copy
import json
import re
import shlex
from datetime import datetime

import pytest

from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME
from grafana_jsm_sandbox.tempo_evidence import summarize_search, summarize_trace
from tests.test_incident_payload import evidence_record
from tests.test_loki_payload import END, STAMP, START, investigation

TRACE_ID = "0123456789abcdef0123456789abcdef"
QUERY = '{ resource.service.name = "rolldice" && span:duration > 500ms }'


def tempo_record(command="traces"):
    record = evidence_record()
    record.update(command=command, query=QUERY, datasource="tempo", path="/api/search",
                  parameters=[["q", QUERY], ["start", str(int(datetime.fromisoformat(START).timestamp()))],
                              ["end", str(int(datetime.fromisoformat(END).timestamp()))], ["limit", "4"]],
                  window={"start": START, "end": END, "step_seconds": None},
                  sample_summary={"result_type": command, "series_count": 0, "sample_count": 0,
                                  "unmodelled_count": 0, "discovery_items": None, "series": []})
    record["response"] = {"traces": [
        {"traceID": f"{number:x}", "rootServiceName": "rolldice",
         "rootTraceName": "GET /rolldice", "startTimeUnixNano": STAMP,
         "durationMs": duration}
        for number, duration in [(1, 200), (2, 900), (3, 700), (4, 500)]
    ], "metrics": {"completedJobs": 1, "totalJobs": 2}, "retained_unknown": "raw"}
    record["trace_summary"] = summarize_search(record["response"], 4)
    if command == "trace":
        spans = [{"traceId": TRACE_ID, "spanId": f"{number:016x}",
                  "name": "GET /rolldice" if number == 1 else f"operation {number}",
                  "kind": "SPAN_KIND_SERVER" if number == 1 else "SPAN_KIND_INTERNAL",
                  "status": {"code": "STATUS_CODE_OK"},
                  "startTimeUnixNano": STAMP,
                  "endTimeUnixNano": str(int(STAMP) + duration),
                  **({} if number == 1 else {"parentSpanId": f"{1 if number < 7 else 99:016x}"})}
                 for number, duration in enumerate(
                     [800_000_000, 700_000_000, 600_000_000, 500_000_000,
                      400_000_000, 300_000_000, 200_000_000], 1)]
        record.update(query=TRACE_ID, path="/api/v2/traces/" + TRACE_ID, parameters=[],
                      window={"start": None, "end": None, "step_seconds": None},
                      response={"trace": {"resourceSpans": [{
                          "resource": {"attributes": [{"key": "service.name", "value": {
                              "stringValue": "rolldice"}}]}, "scopeSpans": [{"spans": spans}],
                      }]}, "status": "PARTIAL", "message": "backend size limit"})
        record["trace_summary"] = summarize_trace(record["response"], TRACE_ID)
    record["presenter_link"] = "http://localhost:3000/explore?schemaVersion=1&panes=%7B%7D"
    return record


def test_tempo_search_and_fetch_render_mechanical_evidence_at_public_payload(tmp_path):
    records = [tempo_record(), tempo_record("trace")]

    command, nodes, text = investigation(tmp_path, records)

    assert "evidence file unreadable" not in text
    assert command.endswith(" --format adf")
    assert "4 returned traces" in text and "limit reached: possibly incomplete" in text
    assert "jobs completed=1 total=2; telemetry completeness unknown" in text
    assert "trace_id=00000000000000000000000000000002" in text
    assert "duration_ms=900" in text
    assert f"trace_id={TRACE_ID}" in text
    assert "lookup by ID" in text and "backend partial" in text
    assert "7 observed spans" in text and "1 missing parents" in text
    assert "observed envelope_ns=800000000" in text
    assert "sum" not in text
    assert "span_id=0000000000000001 parent_span_id=root" in text
    assert "SPAN_KIND_SERVER" in text and "STATUS_CODE_OK" in text
    assert "span_id=0000000000000005" in text
    assert "span_id=0000000000000006" not in text
    assert [mark["attrs"]["href"] for node in nodes for mark in node.get("marks", [])
            if mark["type"] == "link"] == [record["presenter_link"] for record in records]
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == "".join(json.dumps(record) + "\n" for record in records).encode()


@pytest.mark.parametrize("command,change", [
    ("traces", "query"), ("traces", "path"), ("traces", "duplicate"),
    ("traces", "extra"), ("traces", "limit_zero"), ("traces", "limit_fraction"),
    ("traces", "start_negative"), ("traces", "start_overflow"),
    ("traces", "end_before_start"), ("traces", "window"), ("traces", "window_fraction"),
    ("traces", "null_window"), ("traces", "sample_tag"), ("traces", "step"),
    ("traces", "status"), ("traces", "summary_missing"), ("traces", "summary_fabricated"),
    ("traces", "boolean_job"), ("traces", "boolean_duration"),
    ("traces", "wrong_summary_kind"), ("traces", "unavailable_summary"),
    ("traces", "malformed_raw"),
    ("trace", "path"), ("trace", "query"), ("trace", "trimmed_id"),
    ("trace", "extra"), ("trace", "window"), ("trace", "sample_tag"),
    ("trace", "step"), ("trace", "status"), ("trace", "summary_missing"),
    ("trace", "summary_fabricated"), ("trace", "boolean_root"),
    ("trace", "wrong_summary_kind"), ("trace", "unavailable_summary"),
    ("trace", "malformed_raw"), ("trace", "mismatched_id"),
    ("trace", "unknown_enum"), ("trace", "duplicate_span"),
])
def test_tempo_payload_refuses_inconsistent_or_fabricated_evidence(tmp_path, command, change):
    record = tempo_record(command)
    summary = record["trace_summary"]
    if change == "query":
        record["query"] = QUERY + " changed" if command == "traces" else "f" * 32
    elif change == "path":
        record["path"] = "/unrelated"
    elif change == "duplicate":
        record["parameters"].append(["limit", "4"])
    elif change == "extra":
        record["parameters"].append(["start", "1"])
    elif change.startswith("limit_"):
        record["parameters"][3][1] = "0" if change == "limit_zero" else "1.5"
    elif change.startswith("start_"):
        record["parameters"][1][1] = "-1" if change == "start_negative" else str(2 ** 32)
    elif change == "end_before_start":
        record["parameters"][2][1] = "1"
    elif change == "window":
        record["window"]["start"] = END
    elif change == "window_fraction":
        record["window"]["start"] = START.replace(".000Z", ".001Z")
    elif change == "null_window":
        record["window"]["start"] = None
    elif change == "sample_tag":
        record["sample_summary"]["result_type"] = None
    elif change == "step":
        record["window"]["step_seconds"] = 1
    elif change == "status":
        record["status"] = "empty"
    elif change == "summary_missing":
        del record["trace_summary"]
    elif change == "summary_fabricated":
        if command == "traces":
            summary["excerpts"][0]["root_name"] = "invented diagnosis"
        else:
            summary["spans"][0]["duration_ns"] = "123"
    elif change == "boolean_job":
        summary["completed_jobs"] = True  # True == 1 must not validate a count.
    elif change == "boolean_duration":
        for trace in record["response"]["traces"]:
            trace["durationMs"] = 1
        record["trace_summary"] = summarize_search(record["response"], 4)
        record["trace_summary"]["excerpts"][0]["duration_ms"] = True
    elif change == "boolean_root":
        summary["root_span_count"] = True
    elif change == "wrong_summary_kind":
        summary["kind"] = "unknown"
    elif change == "unavailable_summary":
        record.update(status="unavailable", error={"kind": "timeout", "message": "timeout",
                                                   "http_status": None})
        record["sample_summary"]["result_type"] = None
    elif change == "malformed_raw":
        record["response"] = {"error": "failed"}
    elif change == "trimmed_id":
        record["query"] = "123"
        record["path"] = "/api/v2/traces/123"
    else:
        spans = record["response"]["trace"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
        if change == "mismatched_id":
            spans[0]["traceId"] = "f" * 32
        elif change == "unknown_enum":
            spans[0]["kind"] = "UNKNOWN"
        elif change == "duplicate_span":
            spans.append(copy.deepcopy(spans[0]))

    _, _, text = investigation(tmp_path, [evidence_record(), record])

    assert "Evidence: unavailable: evidence file unreadable" in text
    assert "Observation: Evidence unavailable" in text
    assert "invented diagnosis" not in text


@pytest.mark.parametrize("command", ["traces", "trace"])
@pytest.mark.parametrize("status", ["empty", "unavailable"])
def test_tempo_empty_and_unavailable_stay_distinct_and_keep_successful_metrics(tmp_path, command, status):
    record = tempo_record(command)
    record["status"] = status
    if status == "empty":
        record["response"] = {} if command == "traces" else {"trace": {}}
        record["trace_summary"] = (summarize_search(record["response"], 4) if command == "traces"
                                   else summarize_trace(record["response"], TRACE_ID))
    else:
        record.update(response=None, trace_summary=None,
                      error={"kind": "timeout", "message": "request timed out", "http_status": None})
        record["sample_summary"]["result_type"] = None

    _, _, text = investigation(tmp_path, [evidence_record(), record])

    assert "observed zero" in text and "Observation: returned log evidence" in text
    expected = ("no data returned" if command == "traces" else "no returned spans")
    assert (expected if status == "empty" else "unavailable: request timed out") in text
    assert "healthy" not in text


@pytest.mark.parametrize("command", ["traces", "trace"])
def test_tempo_text_and_queries_preserve_punctuation_controls_and_raw_data(tmp_path, command):
    literal = "worker's \"trace\"\nnext\\line $HOME `literal` café 🎲 👩‍💻\x1b\u2028\u2029"
    record = tempo_record(command)
    if command == "traces":
        record["query"] = literal
        record["parameters"][0][1] = literal
        for trace in record["response"]["traces"]:
            trace["rootServiceName"] = literal
            trace["rootTraceName"] = literal
        record["trace_summary"] = summarize_search(record["response"], 4)
    else:
        resource = record["response"]["trace"]["resourceSpans"][0]
        resource["resource"]["attributes"][0]["value"]["stringValue"] = literal
        resource["scopeSpans"][0]["spans"][0]["name"] = literal
        record["response"]["message"] = literal
        record["trace_summary"] = summarize_trace(record["response"], TRACE_ID)
    original_bytes = (json.dumps(record) + "\n").encode()

    command_line, _, text = investigation(tmp_path, [record])
    normalized = re.sub(r"\\u(001b|0027|0024|0060|2019|201d|2028|2029)",
                        lambda match: chr(int(match[1], 16)), command_line, flags=re.IGNORECASE)
    words, normalized_words = shlex.split(command_line), shlex.split(normalized)

    assert json.loads(words[words.index("-b") + 1]) == json.loads(
        normalized_words[normalized_words.index("-b") + 1])
    assert len(command_line.splitlines()) == 1 and "\x1b" not in text
    assert literal[:-3] + "[U+001B][U+2028][U+2029]" in text
    assert "[control characters shown as U+XXXX]" in text
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes


@pytest.mark.parametrize("command,location", [
    ("traces", "query"), ("traces", "name"), ("traces", "service"),
    ("trace", "name"), ("trace", "service"), ("trace", "backend_message"),
])
def test_tempo_literal_unicode_escape_notation_survives_conservative_replay(tmp_path, command, location):
    literal = r"\u001b \u0027 \u2028 \u005c" + "\nordinary\\path 👩‍💻"
    displayed = literal.replace("\\u", "[U+005C]u")
    record = tempo_record(command)
    if command == "traces":
        if location == "query":
            record["query"] = literal
            record["parameters"][0][1] = literal
        else:
            name = "rootTraceName" if location == "name" else "rootServiceName"
            record["response"]["traces"][1][name] = literal
        record["trace_summary"] = summarize_search(record["response"], 4)
    else:
        resource = record["response"]["trace"]["resourceSpans"][0]
        if location == "name":
            resource["scopeSpans"][0]["spans"][0]["name"] = literal
        elif location == "service":
            resource["resource"]["attributes"][0]["value"]["stringValue"] = literal
        else:
            record["response"]["message"] = literal
        record["trace_summary"] = summarize_trace(record["response"], TRACE_ID)
    original_bytes = (json.dumps(record) + "\n").encode()

    command_line, _, text = investigation(tmp_path, [record])
    normalized = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match[1], 16)), command_line)

    assert normalized == command_line, "literal Unicode notation still expands in the replay"
    words, normalized_words = shlex.split(command_line), shlex.split(normalized)
    assert json.loads(words[words.index("-b") + 1]) == json.loads(
        normalized_words[normalized_words.index("-b") + 1])
    assert len(command_line.splitlines()) == 1
    assert displayed in text
    assert "[Unicode escape notation shown with U+005C]" in text
    assert "[control characters shown as U+XXXX]" not in text
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes
