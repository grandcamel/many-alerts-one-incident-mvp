"""Literal Loki evidence through the Run's public payload command."""

from __future__ import annotations

import json
import re
import shlex
import unicodedata

import pytest

from grafana_jsm_sandbox.incident_payload import printed
from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME
from grafana_jsm_sandbox.loki_evidence import summarize_logs
from tests.test_incident_payload import FIRING, canned, evidence_record, run_directory

START = "2026-10-01T14:00:00.000Z"
END = "2026-10-01T14:10:00.000Z"
STAMP = "1790863799123456789"
LINE = "worker's message: \"warning\"\nnext\\line $HOME `literal` café 🎲"
LABELS = {"service_name": "rolldice", "severity_text": "WARN"}


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


def delivered_adf(command, tmp_path):
    words = shlex.split(command)
    working = tmp_path / "runs" / "20261001T140210-abc123"
    return json.loads((working / words[words.index("--body-file") + 1]).read_text(encoding="utf-8"))


def investigation(tmp_path, records):
    working = run_directory(tmp_path, canned(FIRING))
    (working / EVIDENCE_FILENAME).write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    [command] = printed([
        "investigate", "--key", "SANDBOX-7", "--observation", "returned log evidence",
        "--interpretation", "uncertain", "--unknown", "check next",
    ], working)
    comment = delivered_adf(command, tmp_path)
    nodes = comment["content"][0]["content"]
    return command, nodes, "".join(node.get("text", "") for node in nodes)


def test_investigation_renders_literal_log_excerpt_with_utc_time_severity_and_link(tmp_path):
    record = logs_record()
    command, nodes, text = investigation(tmp_path, [record])

    assert "\n" not in command and len(shlex.split(command)) == 9
    assert "1 returned log entries" in text
    assert " | 2026-10-01T14:09:59.123Z WARN " + LINE in text
    assert {"type": "text", "text": LINE, "marks": [{"type": "code"}]} in nodes
    assert all(field not in text for field in ("timestamp_ns=", "labels=", "metadata=", STAMP))
    assert "[control characters shown as U+XXXX]" not in text
    assert "trace'one" not in text
    assert [mark["attrs"]["href"] for node in nodes for mark in node.get("marks", [])
            if mark["type"] == "link"] == [record["presenter_link"]]
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == (json.dumps(record) + "\n").encode()
    excerpt = json.loads(saved.read_text())["log_summary"]["excerpts"][0]
    assert excerpt["timestamp_ns"] == STAMP
    assert excerpt["labels"] == LABELS
    assert excerpt["metadata"] == {"trace_id": "trace'one"}


@pytest.mark.parametrize("timestamp,expected", [
    ("1790921976660267264", "2026-10-02T06:19:36.660Z"),
    ("1790921976999999999", "2026-10-02T06:19:36.999Z"),
    ("0", "1970-01-01T00:00:00.000Z"),
    ("999999", "1970-01-01T00:00:00.000Z"),
    ("1000000", "1970-01-01T00:00:00.001Z"),
    ("253402300799999999999", "9999-12-31T23:59:59.999Z"),
])
def test_log_timestamp_display_truncates_to_exact_utc_milliseconds(tmp_path, timestamp, expected):
    record = logs_record()
    record["response"]["data"]["result"][0]["values"][0][0] = timestamp
    record["log_summary"] = summarize_logs(record["response"], 100)

    command, _, text = investigation(tmp_path, [record])

    assert f" | {expected} WARN " + LINE in text
    pytest.importorskip("jira_as")
    from jira_as.compat.richtext import richtext

    body = delivered_adf(command, tmp_path)
    assert richtext(json.dumps(body), "adf") == body


@pytest.mark.parametrize("labels,severity", [
    ({"severity_text": "Warn", "detected_level": "error"}, "Warn"),
    ({"detected_level": "warning"}, "WARNING"),
    ({"severity": "ERROR"}, ""),
    ({}, ""),
    ({"severity_text": "", "detected_level": "error"}, ""),
    ({"severity_text": "WARN\x1b"}, "WARN[U+001B]"),
    ({"severity_text": r"WARN\u001b"}, "WARN[U+005C]u001b"),
])
def test_log_severity_precedes_code_marked_line_and_uses_only_known_labels(tmp_path, labels, severity):
    record = logs_record()
    record["response"]["data"]["result"][0]["stream"] = labels
    record["log_summary"] = summarize_logs(record["response"], 100)

    _, nodes, text = investigation(tmp_path, [record])

    prefix = " | 2026-10-01T14:09:59.123Z " + (severity + " " if severity else "")
    index = next(i for i, node in enumerate(nodes) if node.get("text") == LINE)
    assert nodes[index - 1] == {"type": "text", "text": prefix}
    assert nodes[index]["marks"] == [{"type": "code"}]
    assert prefix + LINE in text
    assert all(field not in text for field in ("timestamp_ns=", "labels=", "metadata="))


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
    assert " | 2026-10-01T14:09:59.123Z WARN [empty log line]" in text


def test_colored_werkzeug_excerpt_survives_observed_command_normalization(tmp_path):
    """Replay the observed ESC expansion, not Claude's unavailable validator.

    The captured wire command matched helper stdout. Between wire and parsed
    tool input its literal \\u001b sequences became ESC; validation rejected
    hidden command controls before Bash ran. This is the captured fragment.
    """
    line = ("\x1b[35m\x1b[1mGET /rolldice?player=demo&sides=six HTTP/1.1"
            "\x1b[0m")
    record = logs_record()
    record["response"]["data"]["result"][0]["values"][0][1] = line
    record["log_summary"] = summarize_logs(record["response"], 100)
    original_bytes = (json.dumps(record) + "\n").encode()

    command, nodes, text = investigation(tmp_path, [record])

    assert "\x1b" not in command
    normalized_command = command.replace("\\u001b", "\x1b")
    assert "\x1b" not in normalized_command, "observed normalization reintroduced hidden ESC"
    assert ("[U+001B][35m[U+001B][1mGET /rolldice?player=demo&sides=six HTTP/1.1"
            "[U+001B][0m") in [node.get("text") for node in nodes]
    assert "[control characters shown as U+XXXX]" in text
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes


@pytest.mark.parametrize("location", [
    "line", "query", "label_key", "label_value", "metadata_key", "metadata_value",
])
def test_loki_display_controls_are_printable_without_rewriting_raw_evidence(tmp_path, location):
    record = logs_record()
    controls = "\x00\x07\x1b\x7f\x85\t\r"
    value = LINE + controls
    stream = record["response"]["data"]["result"][0]
    if location == "line":
        stream["values"][0][1] = value
    elif location == "query":
        record["query"] += value
        record["parameters"][0][1] = record["query"]
    elif location.startswith("label_"):
        stream["stream"] = ({value: "rolldice"} if location == "label_key"
                            else {"service_name": value})
    else:
        stream["values"][0][2] = ({value: "trace"} if location == "metadata_key"
                                 else {"trace_id": value})
    record["log_summary"] = summarize_logs(record["response"], 100)
    original_bytes = (json.dumps(record) + "\n").encode()

    command, _, text = investigation(tmp_path, [record])

    # Replay only the Unicode-control expansion observed in captured tool input.
    normalized = command
    for control in controls:
        normalized = normalized.replace(f"\\u{ord(control):04x}", control)
    assert not any(unicodedata.category(character) == "Cc" for character in normalized)
    assert not any(unicodedata.category(character) == "Cc" and character != "\n"
                   for character in text)
    displayed = location in ("line", "query")
    assert ("[U+0000][U+0007][U+001B][U+007F][U+0085][U+0009][U+000D]" in text) == displayed
    assert ("[control characters shown as U+XXXX]" in text) == displayed
    assert "café 🎲" in text
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes


@pytest.mark.parametrize("location", ["labels", "metadata"])
def test_undisplayed_fields_preserve_entries_with_colliding_key_spellings(tmp_path, location):
    record = logs_record()
    fields = {"\x1b": "actual control", "[U+001B]": "literal notation"}
    stream = record["response"]["data"]["result"][0]
    if location == "labels":
        stream["stream"] = fields
    else:
        stream["values"][0][2] = fields
    record["log_summary"] = summarize_logs(record["response"], 100)
    original_bytes = (json.dumps(record) + "\n").encode()

    _, _, text = investigation(tmp_path, [record])

    assert "actual control" not in text and "literal notation" not in text
    assert "[control characters shown as U+XXXX]" not in text
    assert all(field not in text for field in ("timestamp_ns=", "labels=", "metadata="))
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes


def test_observed_unicode_normalization_preserves_decoded_adf_punctuation(tmp_path):
    """Captured normalization expands Unicode escapes, leaving LF escapes intact.

    Its apostrophe expansion made shell parsing silently remove log punctuation.
    Replay the observed character classes rather than claiming the real validator.
    """
    record = logs_record()
    line = "invalid literal for int() with base 10: 'six'\n" + LINE.replace("worker's", "worker")
    record["response"]["data"]["result"][0]["values"][0][1] = line
    record["response"]["data"]["result"][0]["values"][0][2] = {
        "exception_message": "invalid literal for int() with base 10: 'six'"}
    record["log_summary"] = summarize_logs(record["response"], 100)
    original_bytes = (json.dumps(record) + "\n").encode()

    command, nodes, _ = investigation(tmp_path, [record])
    normalized = re.sub(r"\\u(001b|0027|0024|0060|2019|201d)",
                        lambda match: chr(int(match[1], 16)), command, flags=re.IGNORECASE)
    wire_adf = delivered_adf(command, tmp_path)
    parsed_adf = delivered_adf(normalized, tmp_path)

    assert parsed_adf == wire_adf, "observed normalization changed decoded ADF punctuation"
    assert line in [node.get("text") for node in nodes]
    assert "\n" not in command and "\x1b" not in normalized
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes


def test_unicode_separator_display_keeps_the_public_command_one_line(tmp_path):
    record = logs_record()
    record["response"]["data"]["result"][0]["values"][0][1] = "before\u2028after\u2029end"
    record["log_summary"] = summarize_logs(record["response"], 100)
    original_bytes = (json.dumps(record) + "\n").encode()

    command, nodes, text = investigation(tmp_path, [record])

    assert len(command.splitlines()) == 1
    assert "before[U+2028]after[U+2029]end" in [node.get("text") for node in nodes]
    assert "[control characters shown as U+XXXX]" in text
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes


@pytest.mark.parametrize("location", [
    "line", "query", "label_key", "label_value", "metadata_key", "metadata_value",
])
def test_literal_unicode_escape_notation_is_disclosed_and_survives_normalization(tmp_path, location):
    """Conservative replay boundary; live decoding of double escapes is unconfirmed."""
    literal = r"\u001b \u0027 \u2028 \u005c" + "\nordinary\\path 👩‍💻"
    displayed = literal.replace("\\u", "[U+005C]u")
    record = logs_record()
    stream = record["response"]["data"]["result"][0]
    if location == "line":
        stream["values"][0][1] = literal
    elif location == "query":
        record["query"] = literal
        record["parameters"][0][1] = literal
    elif location.startswith("label_"):
        stream["stream"] = ({literal: "rolldice"} if location == "label_key"
                            else {"service_name": literal})
    else:
        stream["values"][0][2] = ({literal: "trace"} if location == "metadata_key"
                                 else {"trace_id": literal})
    record["log_summary"] = summarize_logs(record["response"], 100)
    original_bytes = (json.dumps(record) + "\n").encode()

    command, _, text = investigation(tmp_path, [record])
    normalized = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match[1], 16)), command)

    assert normalized == command, "literal Unicode notation still expands in the replay"
    assert delivered_adf(command, tmp_path) == delivered_adf(normalized, tmp_path)
    assert len(command.splitlines()) == 1
    visible = location in ("line", "query")
    assert (displayed in text) == visible
    assert ("[Unicode escape notation shown with U+005C]" in text) == visible
    assert "[control characters shown as U+XXXX]" not in text
    saved = tmp_path / "runs" / "20261001T140210-abc123" / EVIDENCE_FILENAME
    assert saved.read_bytes() == original_bytes
