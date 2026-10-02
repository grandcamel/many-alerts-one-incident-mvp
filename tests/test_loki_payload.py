"""Literal Loki evidence through the Run's public payload command."""

from __future__ import annotations

import json
import shlex

import pytest

from grafana_jsm_sandbox.incident_payload import printed
from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME
from tests.test_incident_payload import FIRING, canned, evidence_record, run_directory

START = "2026-10-01T14:00:00.000Z"
END = "2026-10-01T14:10:00.000Z"
STAMP = "1790863799123456789"
LINE = "worker's message: \"warning\"\nnext\\line $HOME `literal` café 🎲"
LABELS = {"service_name": "rolldice", "severity": "WARN"}


def logs_record():
    return {
        "schema_version": 1, "command": "logs", "query": '{service_name="rolldice"}',
        "datasource": "loki", "path": "/loki/api/v1/query_range",
        "parameters": [["query", '{service_name="rolldice"}'], ["start", START],
                       ["end", END], ["limit", "100"], ["direction", "backward"]],
        "window": {"start": START, "end": END, "step_seconds": None},
        "retrieved_at": END, "status": "ok", "error": None,
        "sample_summary": {"result_type": "streams", "series_count": 0, "sample_count": 0,
                           "unmodelled_count": 0, "discovery_items": None, "series": []},
        "log_summary": {"stream_count": 1, "entry_count": 1, "limit_reached": False,
                        "excerpts": [{"timestamp_ns": STAMP, "labels": LABELS,
                                      "metadata": {"trace_id": "trace'one"}, "line": LINE,
                                      "truncated": False}]},
        "presenter_link": "http://localhost:3000/explore?schemaVersion=1&panes=%7B%7D",
        "response": {"status": "success", "data": {"resultType": "streams", "result": [
            {"stream": LABELS, "values": [[STAMP, LINE, {"trace_id": "trace'one"}]]}
        ]}},
    }


def investigation(tmp_path, records):
    working = run_directory(tmp_path, canned(FIRING))
    (working / EVIDENCE_FILENAME).write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    [command] = printed([
        "investigate", "--key", "SANDBOX-7", "--observation", "returned log evidence",
        "--interpretation", "uncertain", "--unknown", "check next",
    ], working)
    words = shlex.split(command)
    comment = json.loads(words[words.index("-b") + 1])
    nodes = comment["content"][0]["content"]
    return command, nodes, "".join(node.get("text", "") for node in nodes)


def test_investigation_renders_literal_log_excerpt_with_exact_timestamp_and_link(tmp_path):
    record = logs_record()
    command, nodes, text = investigation(tmp_path, [record])

    assert "\n" not in command and len(shlex.split(command)) == 9
    assert "1 returned log entries" in text
    assert STAMP in text and '"service_name":"rolldice"' in text
    assert LINE in [node.get("text") for node in nodes]
    assert '"trace_id":"trace\'one"' in text
    assert [mark["attrs"]["href"] for node in nodes for mark in node.get("marks", [])
            if mark["type"] == "link"] == [record["presenter_link"]]


@pytest.mark.parametrize("change", [
    "query", "start", "end", "limit_missing", "limit_zero", "limit_fraction",
    "direction", "duplicate", "extra", "path", "step", "reversed_window",
    "sample_summary", "result_type", "status", "boolean_count", "fabricated_line",
    "malformed_raw", "missing_summary",
])
def test_investigation_refuses_inconsistent_or_fabricated_log_evidence(tmp_path, change):
    record = logs_record()
    if change in ("query", "start", "end", "direction"):
        next(pair for pair in record["parameters"] if pair[0] == change)[1] = "inconsistent"
    elif change.startswith("limit_"):
        pair = next(pair for pair in record["parameters"] if pair[0] == "limit")
        if change == "limit_missing":
            record["parameters"].remove(pair)
        else:
            pair[1] = "0" if change == "limit_zero" else "1.5"
    elif change in ("duplicate", "extra"):
        record["parameters"].append(["limit" if change == "duplicate" else "step", "100"])
    elif change == "path":
        record["path"] = "/api/v1/query_range"
    elif change == "step":
        record["window"]["step_seconds"] = 10
    elif change == "reversed_window":
        record["window"]["start"], record["window"]["end"] = END, START
        for pair in record["parameters"]:
            if pair[0] in ("start", "end"):
                pair[1] = record["window"][pair[0]]
    elif change == "sample_summary":
        record["sample_summary"]["sample_count"] = 1
    elif change == "result_type":
        record["sample_summary"]["result_type"] = "vector"
    elif change == "status":
        record["status"] = "empty"
    elif change == "boolean_count":
        record["log_summary"]["entry_count"] = True
    elif change == "fabricated_line":
        record["log_summary"]["excerpts"][0]["line"] = "invented root cause"
    elif change == "malformed_raw":
        record["response"]["data"]["result"][0]["values"][0][0] = 1790863799123456789
    else:
        del record["log_summary"]

    _, _, text = investigation(tmp_path, [evidence_record(), record])

    assert "Evidence: unavailable: evidence file unreadable" in text
    assert "Observation: Evidence unavailable" in text


def test_investigation_includes_newest_three_logs_and_marks_shortening_and_limit(tmp_path):
    record = logs_record()
    latest = "1790863799123456790"
    other_labels = {"service_name": "another-service"}
    long_line = "x" * 600 + "original tail"
    record["parameters"][3][1] = "4"
    record["response"]["data"]["result"] = [
        {"stream": LABELS, "values": [["1790863700000000000", "oldest"],
                                     [STAMP, "middle"], [latest, long_line]]},
        {"stream": other_labels, "values": [["1790863799123456788", "third newest"]]},
    ]
    record["log_summary"] = {
        "stream_count": 2, "entry_count": 4, "limit_reached": True,
        "excerpts": [
            {"timestamp_ns": latest, "labels": LABELS, "metadata": {},
             "line": "x" * 600, "truncated": True},
            {"timestamp_ns": STAMP, "labels": LABELS, "metadata": {},
             "line": "middle", "truncated": False},
            {"timestamp_ns": "1790863799123456788", "labels": other_labels, "metadata": {},
             "line": "third newest", "truncated": False},
        ],
    }

    _, nodes, text = investigation(tmp_path, [record])

    assert [node["text"] for node in nodes if node.get("marks") == [{"type": "code"}]] == [
        record["query"], "x" * 600, "middle", "third newest"]
    assert "4 returned log entries in 2 streams; limit reached: possibly incomplete" in text
    assert "[truncated to 600 characters]" in text
    assert "original tail" not in text and "oldest" not in text
    saved = (tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME).read_text()
    assert "original tail" in saved


@pytest.mark.parametrize("status", ["empty", "unavailable"])
def test_investigation_distinguishes_empty_logs_from_failed_logs(tmp_path, status):
    record = logs_record()
    record["status"] = status
    if status == "empty":
        record["response"]["data"]["result"] = []
        record["log_summary"] = {"stream_count": 0, "entry_count": 0,
                                 "limit_reached": False, "excerpts": []}
    else:
        record["response"] = None
        record["log_summary"] = None
        record["sample_summary"]["result_type"] = None
        record["error"] = {"kind": "timeout", "message": "request timed out", "http_status": None}

    _, _, text = investigation(tmp_path, [evidence_record(), record])

    assert "observed zero" in text
    assert ("0 returned log entries in 0 streams; no data returned" if status == "empty"
            else "unavailable: request timed out") in text
    assert "Observation: returned log evidence" in text


def test_investigation_failure_only_overrides_judgments_without_a_lifecycle_error(tmp_path):
    record = logs_record()
    record.update(status="unavailable", response=None, log_summary=None,
                  error={"kind": "timeout", "message": "request timed out", "http_status": None})
    record["sample_summary"]["result_type"] = None

    command, _, text = investigation(tmp_path, [record])

    assert command.startswith("jira-as collaborate comment add SANDBOX-7 ")
    assert text == ("[grafana-investigation] Observation: Evidence unavailable | "
                    "Interpretation: No conclusion from Grafana | Unknown / next check: "
                    "check next | Evidence: unavailable: request timed out")


def test_empty_log_lines_keep_valid_adf_and_an_explicit_empty_line_display(tmp_path):
    record = logs_record()
    record["response"]["data"]["result"][0]["values"][0][1] = ""
    record["log_summary"]["excerpts"][0]["line"] = ""

    _, nodes, text = investigation(tmp_path, [record])

    assert all(node["text"] for node in nodes if node["type"] == "text")
    assert STAMP in text and "[empty log line]" in text
