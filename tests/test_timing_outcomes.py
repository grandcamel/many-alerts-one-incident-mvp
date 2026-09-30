"""Adversarial parser checks; synthetic stream shapes, not native-client qualification."""

import json
from decimal import Decimal

import pytest

from prototype.run_timing.outcomes import Transcript, money


def encoded(event):
    return json.dumps(event).encode()


def assistant(model="candidate"):
    return encoded({"type": "assistant", "message": {"model": model, "content": []}})


def terminal(**changes):
    return encoded({"type": "result", "subtype": "success", "is_error": False, **changes})


def parsed(*lines):
    stream = Transcript("candidate")
    for line in lines:
        stream.feed(line)
    return stream


def test_terminal_success_is_not_effects_or_billed_cost():
    result = parsed(assistant(), terminal(total_cost_usd="0.01")).outcome(0)
    assert result.execution == "completed"
    assert result.estimate_usd == Decimal("0.01")
    assert result.further_dispatch == "requires_budget_recheck"


@pytest.mark.parametrize("line", [terminal(is_error=True), terminal(subtype="error")])
def test_result_error_prevents_exit_zero_success(line):
    assert parsed(assistant(), line).outcome(0).execution == "failed"


@pytest.mark.parametrize("lines,reason", [
    ([], "missing_terminal"),
    ([terminal(), terminal()], "duplicate_terminal"),
    ([terminal(), terminal(is_error=True)], "duplicate_terminal"),
    ([b'{"type":"result","subtype":"success"}'], "malformed_evidence"),
    ([b'{"type":"result","subtype":"success","is_error":false,"is_error":true}'],
     "malformed_evidence"),
    ([b'not-json'], "malformed_evidence"),
    ([b'[]'], "malformed_evidence"),
    ([b'\xff'], "malformed_evidence"),
    ([terminal(is_error="false")], "malformed_evidence"),
    ([terminal(subtype="future_unknown_success")], "malformed_evidence"),
    ([terminal(total_cost_usd=float("nan"))], "malformed_evidence"),
    ([terminal(usage={"input_tokens": True, "output_tokens": 0})], "malformed_evidence"),
    ([terminal(), encoded({"type": "unknown"})], "malformed_evidence"),
])
def test_missing_duplicate_and_malformed_evidence_cannot_succeed(lines, reason):
    outcome = parsed(assistant(), *lines).outcome(0)
    assert outcome.execution == "incomplete"
    assert reason in outcome.reasons


def test_conflicting_terminals_retain_error_without_picking_last_cost():
    for lines in [(terminal(), terminal(is_error=True, total_cost_usd=4)),
                  (terminal(is_error=True, total_cost_usd=4), terminal())]:
        result = parsed(assistant(), *lines).outcome(0)
        assert {"duplicate_terminal", "result_error"} <= set(result.reasons)
        assert result.estimate_usd is None


@pytest.mark.parametrize("observed,expected", [
    ({"spawn_failure"}, "spawn_failed"), ({"timeout"}, "timed_out"),
    ({"cancelled"}, "cancelled"), ({"timeout", "containment_failure"}, "containment_failed"),
])
def test_observed_failure_overrides_success(observed, expected):
    assert parsed(assistant(), terminal()).outcome(0, observed).execution == expected


def test_init_model_is_not_identity_and_missing_cost_not_zero():
    result = parsed(encoded({"type": "system", "subtype": "init", "model": "candidate"}),
                    terminal()).outcome(0)
    assert result.comparison == "invalid"
    assert result.estimate_usd is None
    assert result.further_dispatch == "hold"


def test_actual_model_mismatch_cannot_be_erased_by_later_requested_model():
    stream = parsed(assistant("different"), assistant(), terminal())
    assert stream.stop_requested
    assert stream.outcome(0).comparison == "invalid"
    assert stream.outcome(0).actual_models == ("candidate", "different")


def test_parser_limits_stop_capture_and_bound_state():
    stream = Transcript("candidate", max_events=2, max_line_bytes=128)
    for _ in range(200):
        stream.feed(assistant())
    assert stream.count == 3
    assert stream.stop_requested
    assert stream.outcome(0).execution == "incomplete"
    stream = Transcript("candidate", max_line_bytes=4)
    stream.feed(assistant())
    assert "capture_limit" in stream.outcome(0).reasons


@pytest.mark.parametrize("value", [True, None, -1, "nan", "Infinity", "-0.1", {}, "oops"])
def test_money_rejects_ambiguous_or_nonfinite_values(value):
    with pytest.raises((TypeError, ValueError)):
        money(value)


def test_nonzero_and_missing_exit_are_not_success():
    stream = parsed(assistant(), terminal())
    assert stream.outcome(1).execution == "failed"
    assert stream.outcome(None).execution == "incomplete"
    assert stream.outcome(False).execution == "incomplete"
