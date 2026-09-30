"""Independent tests for the pinned, documented stream subset.

These fixtures exercise an offline normalizer only.  They do not qualify a native
launcher, installed client, authentication path, tool execution, or billing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from decimal import Decimal

import pytest

from prototype.run_timing.documented_stream import (
    SOURCE_PROFILE,
    DocumentedStream,
    ProcessObservation,
)

MODEL = "claude-haiku-4-5"
SESSION = "session-1"


def init(session: str = SESSION, model: str = MODEL) -> dict:
    return {"type": "system", "subtype": "init", "session_id": session, "model": model}


def assistant(model: str = MODEL, *, session: str = SESSION, content=None, **extra) -> dict:
    return {"type": "assistant", "session_id": session,
            "message": {"model": model, "content": content or [{"type": "text", "text": "ok"}]},
            **extra}


def tool_use(tool_id: str = "tool-1", *, session: str = SESSION) -> dict:
    return assistant(session=session, content=[{"type": "tool_use", "id": tool_id,
                                               "name": "lookup", "input": {"key": "value"}}])


def tool_result(tool_id: str = "tool-1", *, session: str = SESSION,
                is_error: bool = False) -> dict:
    return {"type": "user", "session_id": session,
            "message": {"content": [{"type": "tool_result", "tool_use_id": tool_id,
                                       "content": "done", "is_error": is_error}]}}


def result(session: str = SESSION, *, subtype: str = "success", is_error: bool = False,
           cost: str | None = None, **extra) -> dict:
    value = {"type": "result", "subtype": subtype, "duration_ms": 10,
             "duration_api_ms": 8, "num_turns": 1, "is_error": is_error,
             "session_id": session}
    if cost is not None:
        value["total_cost_usd"] = cost
    value.update(extra)
    return value


def raw(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def feed_all(stream: DocumentedStream, values: list[bytes], *, start: int = 1):
    return [stream.feed(value, sequence=start + offset, received_at=float(start + offset))
            for offset, value in enumerate(values)]


def complete_values(*, cost: str | None = None) -> list[bytes]:
    terminal = raw(result())
    if cost is not None:
        terminal = terminal[:-1] + b',"total_cost_usd":' + cost.encode() + b"}"
    return [raw(init()), raw(assistant()), raw(tool_use()), raw(tool_result()),
            raw(assistant(content=[{"type": "text", "text": "finished"}])),
            terminal]


def observation(**overrides) -> ProcessObservation:
    values = {"exit_code": 0, "capture_complete": True, "root_reaped": True,
              "group_gone": True, "pipes_closed": True, "timed_out": False,
              "cancelled": False, "spawn_failed": False}
    values.update(overrides)
    return ProcessObservation(**values)


def test_valid_text_and_tool_flow_preserves_receiver_metadata_and_correlations():
    stream = DocumentedStream("attempt-1", MODEL)
    records = feed_all(stream, complete_values())
    outcome = stream.outcome(observation())

    assert all(record.accepted for record in records)
    assert records[0].attempt_id == "attempt-1"
    assert records[0].sequence == 1 and records[-1].sequence == 6
    assert records[0].received_at == 1.0 and records[-1].received_at == 6.0
    assert records[1].raw_bytes == len(raw(assistant()))
    assert records[1].raw_sha256 == hashlib.sha256(raw(assistant())).hexdigest()
    assert records[2].proposed_tool_ids == ("tool-1",)
    assert records[3].returned_tool_ids == ("tool-1",)
    assert outcome.status == "stream_consistent"
    assert outcome.attempt_id == "attempt-1"
    assert outcome.reported_session_id == SESSION
    assert outcome.reported_models == (MODEL,)
    assert outcome.native_qualification == "NOT_ASSESSED"
    assert outcome.further_dispatch == "hold"


@pytest.mark.parametrize(
    ("observation_overrides", "status"),
    [
        ({"root_reaped": False}, "containment_failed"),
        ({"group_gone": False, "timed_out": True}, "containment_failed"),
        ({"spawn_failed": True}, "spawn_failed"),
        ({"timed_out": True, "cancelled": True}, "timed_out"),
        ({"cancelled": True}, "cancelled"),
    ],
)
def test_process_observations_have_conservative_precedence(observation_overrides, status):
    stream = DocumentedStream("attempt-1", MODEL)
    feed_all(stream, complete_values())
    outcome = stream.outcome(observation(**observation_overrides))
    assert outcome.status == status
    assert outcome.further_dispatch == "hold"


def test_nonzero_exit_and_reported_error_do_not_become_consistent():
    stream = DocumentedStream("attempt-1", MODEL)
    feed_all(stream, [raw(init()), raw(assistant()),
                      raw(result(subtype="error_during_execution", is_error=True))])
    outcome = stream.outcome(observation(exit_code=7))
    assert outcome.status == "failed"
    assert {"result_error", "nonzero_exit"} <= set(outcome.reasons)


def test_tool_error_and_api_error_terminal_reason_are_failed():
    tool_failure = DocumentedStream("attempt-1", MODEL)
    feed_all(tool_failure, [raw(init()), raw(tool_use()), raw(tool_result(is_error=True)),
                            raw(result())])
    outcome = tool_failure.outcome(observation())
    assert outcome.status == "failed"
    assert "tool_error" in outcome.reasons

    api_failure = DocumentedStream("attempt-2", MODEL)
    feed_all(api_failure, [raw(init()), raw(assistant()),
                           raw(result(terminal_reason="api_error"))])
    assert api_failure.outcome(observation()).status == "failed"


def test_nonnull_api_error_status_forces_result_error_even_on_success_shape():
    stream = DocumentedStream("attempt-api-status", MODEL)
    feed_all(stream, [raw(init()), raw(assistant()),
                      raw(result(api_error_status=500))])
    outcome = stream.outcome(observation())
    assert outcome.status == "failed"
    assert "result_error" in outcome.reasons


def test_aborted_terminal_reason_is_cancellation_and_missing_exit_is_incomplete():
    aborted = DocumentedStream("attempt-1", MODEL)
    feed_all(aborted, [raw(init()), raw(assistant()),
                       raw(result(terminal_reason="aborted_streaming"))])
    assert aborted.outcome(observation()).status == "cancelled"

    missing_exit = DocumentedStream("attempt-2", MODEL)
    feed_all(missing_exit, complete_values())
    outcome = missing_exit.outcome(observation(exit_code=None))
    assert outcome.status == "incomplete"
    assert "missing_exit" in outcome.reasons


@pytest.mark.parametrize("payload", [b"{", b"\xff", b"[1,2,3]"])
def test_malformed_or_nonobject_input_is_rejected_and_sticky(payload):
    stream = DocumentedStream("attempt-1", MODEL)
    record = stream.feed(payload, sequence=1, received_at=0.0)
    assert not record.accepted and "malformed_input" in record.reasons
    assert stream.outcome(observation(exit_code=0)).status == "incomplete"


def test_duplicate_keys_and_nonfinite_numbers_are_rejected():
    stream = DocumentedStream("attempt-1", MODEL)
    duplicate = b'{"type":"system","type":"assistant","subtype":"init"}'
    nonfinite = b'{"type":"system","subtype":"init","unused":1e999}'
    first = stream.feed(duplicate, sequence=1, received_at=0.0)
    second = stream.feed(nonfinite, sequence=2, received_at=1.0)
    assert not first.accepted and not second.accepted
    assert "malformed_input" in first.reasons and "malformed_input" in second.reasons


def test_exact_bool_and_integer_types_are_required():
    stream = DocumentedStream("attempt-1", MODEL)
    invalid = result(is_error=1, duration_ms=True, num_turns=1.0)
    record = stream.feed(raw(invalid), sequence=1, received_at=0.0)
    assert not record.accepted and "malformed_input" in record.reasons
    with pytest.raises(ValueError):
        stream.outcome(observation(capture_complete=1))

    repaired = DocumentedStream("attempt-2", MODEL)
    feed_all(repaired, complete_values())
    with pytest.raises(ValueError):
        repaired.outcome(observation(pipes_closed=1))
    assert repaired.outcome(observation()).status == "incomplete"


@pytest.mark.parametrize("field,value", [
    ("is_error", 1), ("duration_ms", True), ("duration_api_ms", 1.0),
    ("num_turns", -1),
])
def test_each_terminal_required_type_is_checked_independently(field, value):
    stream = DocumentedStream("attempt-1", MODEL)
    terminal = result()
    terminal[field] = value
    feed_all(stream, [raw(init()), raw(assistant())])
    record = stream.feed(raw(terminal), sequence=3, received_at=3.0)
    assert not record.accepted and "malformed_input" in record.reasons


def test_depth_line_total_and_event_bounds_hold_without_continuing_parse():
    deep = {"type": "system", "subtype": "init", "nested": "x"}
    for _ in range(10):
        deep = {"nested": deep}
    stream = DocumentedStream("attempt-1", MODEL, max_depth=4, max_line_bytes=80,
                              max_total_bytes=100, max_events=2)
    record = stream.feed(raw(deep), sequence=1, received_at=0.0)
    assert not record.accepted
    assert stream.feed(raw(init()), sequence=2, received_at=1.0).accepted is False
    assert stream.feed(raw(init()), sequence=3, received_at=2.0).accepted is False
    assert stream.outcome(observation()).status == "incomplete"

    depth_ok = DocumentedStream("depth-ok", MODEL, max_depth=4, max_line_bytes=4096,
                                max_total_bytes=4096)
    within = init()
    within["unused"] = {"a": {"b": "ok"}}
    assert depth_ok.feed(raw(within), sequence=1, received_at=0.0).accepted
    depth_bad = DocumentedStream("depth-bad", MODEL, max_depth=4, max_line_bytes=4096,
                                 max_total_bytes=4096)
    too_deep = init()
    too_deep["unused"] = {"a": {"b": {"c": {"d": "too-deep"}}}}
    assert not depth_bad.feed(raw(too_deep), sequence=1, received_at=0.0).accepted

    line_limited = DocumentedStream("attempt-2", MODEL, max_line_bytes=20)
    assert not line_limited.feed(raw(init()), sequence=1, received_at=0.0).accepted

    total_limited = DocumentedStream("attempt-3", MODEL, max_total_bytes=10)
    assert not total_limited.feed(raw(init()), sequence=1, received_at=0.0).accepted

    event_limited = DocumentedStream("attempt-4", MODEL, max_events=1)
    assert event_limited.feed(raw(init()), sequence=1, received_at=0.0).accepted
    assert not event_limited.feed(raw(assistant()), sequence=2, received_at=1.0).accepted


@pytest.mark.parametrize("kwargs", [
    {"sequence": 0, "received_at": 0.0},
    {"sequence": 2, "received_at": 0.0},
    {"sequence": 1, "received_at": -1.0},
    {"sequence": 1, "received_at": 10**400},
])
def test_receiver_metadata_misuse_raises_and_sticks(kwargs):
    stream = DocumentedStream("attempt-1", MODEL)
    with pytest.raises(ValueError):
        stream.feed(raw(init()), **kwargs)
    record = stream.feed(raw(init()), sequence=1, received_at=0.0)
    assert not record.accepted
    assert {"sequence_error", "time_error"} & set(record.reasons)


def test_out_of_order_time_and_post_terminal_records_are_held():
    stream = DocumentedStream("attempt-1", MODEL)
    assert stream.feed(raw(init()), sequence=1, received_at=2.0).accepted
    with pytest.raises(ValueError):
        stream.feed(raw(assistant()), sequence=2, received_at=1.0)
    assert not stream.feed(raw(result()), sequence=2, received_at=3.0).accepted
    assert stream.outcome(observation()).status == "incomplete"

    after = DocumentedStream("attempt-2", MODEL)
    feed_all(after, [raw(init()), raw(assistant()), raw(result()), raw(assistant())])
    assert "record_after_terminal" in after.outcome(observation()).reasons

    duplicate = DocumentedStream("attempt-3", MODEL)
    feed_all(duplicate, [raw(init()), raw(assistant()), raw(result()), raw(result())])
    assert "duplicate_terminal" in duplicate.outcome(observation()).reasons


def test_duplicate_and_unpaired_tool_results_hold_pairing():
    duplicate_use = DocumentedStream("attempt-1", MODEL)
    feed_all(duplicate_use, [raw(init()), raw(tool_use()), raw(tool_use()), raw(result())])
    assert "tool_pairing" in duplicate_use.outcome(observation()).reasons

    unpaired = DocumentedStream("attempt-2", MODEL)
    feed_all(unpaired, [raw(init()), raw(tool_result()), raw(result())])
    outcome = unpaired.outcome(observation())
    assert "tool_pairing" in outcome.reasons
    assert outcome.status == "incomplete"

    repropose = DocumentedStream("attempt-3", MODEL)
    feed_all(repropose, [raw(init()), raw(tool_use()), raw(tool_result()), raw(tool_use())])
    assert "tool_pairing" in repropose.outcome(observation()).reasons


def test_tool_result_content_list_requires_object_blocks():
    stream = DocumentedStream("attempt-content", MODEL)
    invalid = tool_result()
    invalid["message"]["content"][0]["content"] = [1]
    records = feed_all(stream, [raw(init()), raw(tool_use()), raw(invalid)])
    record = records[-1]
    assert not record.accepted
    assert "malformed_input" in record.reasons


def test_documented_nullable_tool_result_and_optional_fields_are_accepted():
    stream = DocumentedStream("attempt-1", MODEL)
    user = tool_result()
    block = user["message"]["content"][0]
    block["content"] = [{"type": "text", "text": "done"}]
    block["is_error"] = None
    terminal = result()
    terminal.update({"usage": None, "modelUsage": None, "permission_denials": None,
                     "deferred_tool_use": None, "errors": None, "origin": {"kind": "cli"}})
    records = feed_all(stream, [raw(init()), raw(tool_use()), raw(user), raw(terminal)])
    assert all(record.accepted for record in records)
    assert stream.outcome(observation()).status == "stream_consistent"


@pytest.mark.parametrize("payload", [
    {"type": "stream_event", "event": {"type": "message_start"}},
    {"type": "assistant", "parent_tool_use_id": "parent", "message":
     {"model": MODEL, "content": [{"type": "text", "text": "child"}]}},
    {"type": "fallback", "model": "other"},
])
def test_partial_subagent_and_fallback_families_are_unsupported(payload):
    stream = DocumentedStream("attempt-1", MODEL)
    record = stream.feed(raw(payload), sequence=1, received_at=0.0)
    assert not record.accepted
    assert ("unsupported_event" in record.reasons or "unsupported_content" in record.reasons or
            "malformed_input" in record.reasons)
    assert stream.outcome(observation()).status == "incomplete"


def test_session_and_reported_model_mismatches_cannot_be_repaired():
    session_stream = DocumentedStream("attempt-1", MODEL)
    feed_all(session_stream, [raw(init()), raw(assistant(session="other")), raw(result())])
    session_outcome = session_stream.outcome(observation())
    assert "session_mismatch" in session_outcome.reasons
    assert session_outcome.status == "incomplete"

    model_stream = DocumentedStream("attempt-2", MODEL)
    feed_all(model_stream, [raw(init()), raw(assistant(model="other")), raw(result())])
    outcome = model_stream.outcome(observation())
    assert outcome.status == "incomplete"
    assert "model_mismatch" in outcome.reasons
    assert outcome.reported_models == ("other",)


@pytest.mark.parametrize("field,value", [
    ("permission_denials", ["lookup"]),
    ("deferred_tool_use", {"id": "tool-1", "name": "lookup", "input": {}}),
    ("errors", ["diagnostic"]),
])
def test_each_diagnostic_field_holds_without_becoming_permission_or_success(field, value):
    stream = DocumentedStream("attempt-1", MODEL)
    values = [raw(init()), raw(assistant()), raw(result(**{field: value}))]
    feed_all(stream, values)
    outcome = stream.outcome(observation())
    assert outcome.status == "incomplete"
    assert "diagnostic_hold" in outcome.reasons
    assert outcome.further_dispatch == "hold"


def test_deferred_tool_use_requires_its_documented_object_shape():
    empty = DocumentedStream("attempt-empty", MODEL)
    records = feed_all(empty, [raw(init()), raw(assistant()), raw(result(deferred_tool_use={}))])
    record = records[-1]
    assert not record.accepted
    assert "malformed_input" in record.reasons
    assert empty.feed(raw(result()), sequence=4, received_at=4.0).accepted
    assert empty.outcome(observation()).status == "incomplete"

    valid = DocumentedStream("attempt-valid", MODEL)
    feed_all(valid, [raw(init()), raw(assistant()),
                     raw(result(deferred_tool_use={"id": "tool-1", "name": "lookup",
                                                   "input": {}}))])
    outcome = valid.outcome(observation())
    assert outcome.status == "incomplete"
    assert "diagnostic_hold" in outcome.reasons


def test_diagnostic_error_items_are_typed():
    stream = DocumentedStream("attempt-1", MODEL)
    records = feed_all(stream, [raw(init()), raw(assistant()), raw(result(errors=[123]))])
    record = records[-1]
    assert not record.accepted
    assert "malformed_input" in record.reasons
    assert stream.feed(raw(result()), sequence=4, received_at=4.0).accepted
    assert stream.outcome(observation()).status == "incomplete"


@pytest.mark.parametrize("token_value", [True, 1.0, -1])
def test_assistant_usage_token_counts_require_nonnegative_integers(token_value):
    stream = DocumentedStream("attempt-1", MODEL)
    event = assistant()
    event["message"]["usage"] = {"input_tokens": token_value, "output_tokens": 0}
    feed_all(stream, [raw(init())])
    record = stream.feed(raw(event), sequence=2, received_at=2.0)
    assert not record.accepted
    assert "malformed_input" in record.reasons


def test_frozen_metadata_and_repeated_semantic_holds_are_observable():
    stream = DocumentedStream("attempt-1", MODEL)
    first = stream.feed(raw(init()), sequence=1, received_at=0.0)
    with pytest.raises(FrozenInstanceError):
        first.sequence = 9
    process = observation()
    with pytest.raises(FrozenInstanceError):
        process.exit_code = 7
    mismatch = assistant(session="other")
    second = stream.feed(raw(mismatch), sequence=2, received_at=1.0)
    third = stream.feed(raw(mismatch), sequence=3, received_at=2.0)
    assert not second.accepted and not third.accepted
    assert "session_mismatch" in second.reasons
    assert "session_mismatch" in third.reasons
    outcome = stream.outcome(observation())
    with pytest.raises(FrozenInstanceError):
        outcome.status = "stream_consistent"


def test_assistant_error_is_a_diagnostic_hold():
    stream = DocumentedStream("attempt-2", MODEL)
    feed_all(stream, [raw(init()), raw(assistant(error="tool denied")), raw(result())])
    outcome = stream.outcome(observation())
    assert outcome.status == "incomplete"
    assert "diagnostic_hold" in outcome.reasons


def test_reported_estimate_is_exact_and_provider_actual_remains_unknown():
    stream = DocumentedStream("attempt-1", MODEL)
    estimate = "0.12345678901234567890123456789"
    feed_all(stream, complete_values(cost=estimate))
    outcome = stream.outcome(observation())
    assert outcome.status == "stream_consistent"
    assert outcome.reported_estimate_usd == Decimal(estimate)
    assert outcome.provider_actual_usd is None
    assert outcome.actual_model is None
    assert outcome.source_profile == SOURCE_PROFILE


def test_missing_terminal_or_unresolved_tool_cannot_be_promoted_by_clean_process():
    missing = DocumentedStream("attempt-1", MODEL)
    feed_all(missing, [raw(init()), raw(assistant())])
    outcome = missing.outcome(observation())
    assert outcome.status == "incomplete"
    assert "missing_terminal" in outcome.reasons
    assert outcome.further_dispatch == "hold"

    unresolved = DocumentedStream("attempt-2", MODEL)
    feed_all(unresolved, [raw(init()), raw(tool_use()), raw(result())])
    assert unresolved.outcome(observation()).status == "incomplete"
