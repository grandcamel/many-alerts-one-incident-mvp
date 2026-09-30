"""Independent checks for the bounded supervised synthetic stream join."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prototype.run_timing.fixture_evidence import EvidenceUnavailable
from prototype.run_timing.fixture_ledger import FixtureLedger, LedgerUnavailable
from prototype.run_timing.process_fixture import FixtureCloseoutError
from prototype.run_timing.streaming_rehearsal import (
    read_supervised_streaming_evidence,
    run_supervised_streaming,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=UTC)


def new_case(tmp_path: Path) -> tuple[FixtureLedger, Path]:
    output = tmp_path / "output"
    output.mkdir()
    return FixtureLedger.create(tmp_path / "fixture.db"), output


def run_case(tmp_path: Path, scenario: str, *, attempt_id: str = "attempt",
             **kwargs) -> tuple[FixtureLedger, Path, dict]:
    ledger, output = new_case(tmp_path)
    result = run_supervised_streaming(
        ledger, scenario, output, attempt_id, NOW, billing_current=True,
        time_scale=0.02, **kwargs,
    )
    return ledger, output, result


def test_real_child_ack_and_terminal_join_preserves_unresolved_reservation(tmp_path):
    ledger, output, result = run_case(tmp_path, "stream_complete")

    assert result["integration_outcome"] == "completed"
    assert result["billing_actual"] is None
    assert result["qualification"] == "NOT_ASSESSED"
    process = result["process"]
    assert process["scenario"] == "stream_complete"
    assert process["outcome"]["execution"] == "completed"
    assert all(process[field] is True for field in (
        "capture_complete", "root_reaped", "group_gone", "pipes_closed",
    ))
    assert result["stream"]
    assert result["child"]
    assert not result["gaps"]
    parent = result["stream"]["parent"]
    child_ack = result["child"]["acknowledgements"][0]
    child_receipt = result["child"]["receipts"][0]
    assert child_ack["lease_id"] == parent["stream_receipt"]["lease_id"]
    assert child_receipt["lease_id"] == child_ack["lease_id"]
    assert child_ack["sequence"] == child_receipt["sequence"] == 1
    assert child_ack["frame_sha256"]
    assert child_receipt["terminal_observed"] is True
    assert child_receipt["transport_eof"] is True
    control = result["stream"]["control"]
    assert control["released"] is True
    assert control["ack_observed_us"] <= control["released_us"]
    assert ledger.snapshot(NOW).unresolved == 1

    reread = read_supervised_streaming_evidence(
        output / "attempt", scenario="stream_complete"
    )
    assert reread == result


@pytest.mark.parametrize("scenario", [
    "stream_truncate", "stream_duplicate_terminal", "stream_child_failure",
    "stream_missing_receipt", "stream_bad_ack", "stream_duplicate_ack", "stream_bad_receipt",
])
def test_stream_faults_hold_without_promoting_child_or_transport_evidence(tmp_path, scenario):
    ledger, _output, result = run_case(tmp_path, scenario)

    assert result["integration_outcome"] == "held"
    assert result["gaps"]
    assert result["billing_actual"] is None
    assert result["qualification"] == "NOT_ASSESSED"
    assert ledger.snapshot(NOW).unresolved == 1
    assert result["process"]["scenario"] == scenario
    assert result["process"]["root_reaped"] is True
    assert result["process"]["group_gone"] is True
    assert result["process"]["pipes_closed"] is True


def test_waiting_child_is_cancelled_and_keeps_pending_evidence(tmp_path):
    cancel = threading.Event()
    cancel.set()
    ledger, _output = new_case(tmp_path)
    result = run_supervised_streaming(
        ledger, "stream_wait", _output, "attempt", NOW,
        billing_current=True, time_scale=0.02, cancel=cancel,
    )
    assert result["integration_outcome"] == "held"
    assert result["process"]["outcome"]["execution"] == "cancelled"
    assert result["process"]["root_reaped"] is True
    assert result["process"]["group_gone"] is True
    assert result["process"]["pipes_closed"] is True
    assert result["gaps"]
    assert ledger.snapshot(NOW).unresolved == 1


def test_waiting_child_deadline_is_bounded_and_remains_held(tmp_path):
    ledger, output = new_case(tmp_path)

    result = run_supervised_streaming(
        ledger, "stream_wait", output, "deadline", NOW,
        billing_current=True, time_scale=0.02,
    )

    assert result["integration_outcome"] == "held"
    assert result["process"]["outcome"]["execution"] == "timed_out"
    assert result["process"]["elapsed_seconds"] < result["process"]["cleanup_bound_seconds"]
    assert result["gaps"]
    assert ledger.snapshot(NOW).unresolved == 1


def test_cancel_after_ack_never_promotes_completion(tmp_path, monkeypatch):
    from prototype.run_timing import streaming_session

    ledger, output = new_case(tmp_path)
    cancel = threading.Event()
    original_observe = streaming_session.StreamSession.observe_stdout

    def observe_and_cancel(session, line, elapsed, allow_release):
        original_observe(session, line, elapsed, allow_release)
        if session._ack is not None:
            cancel.set()

    monkeypatch.setattr(streaming_session.StreamSession, "observe_stdout", observe_and_cancel)
    result = run_supervised_streaming(
        ledger, "stream_wait", output, "late-cancel", NOW,
        billing_current=True, time_scale=0.02, cancel=cancel,
    )

    assert result["integration_outcome"] == "held"
    assert result["process"]["outcome"]["execution"] == "cancelled"
    assert result["process"]["root_reaped"] is True
    assert result["process"]["group_gone"] is True
    assert result["gaps"]
    assert result["child"]["acknowledgements"]
    assert result["stream"]["control"]["released"] is False
    assert ledger.snapshot(NOW).unresolved == 1


def test_reported_child_terminal_success_does_not_hide_process_failure(tmp_path):
    ledger, _output, result = run_case(tmp_path, "stream_child_failure")

    assert result["integration_outcome"] == "held"
    assert result["process"]["outcome"]["execution"] == "failed"
    assert result["child"]["receipts"][0]["reason"] == "complete"
    assert result["child"]["receipts"][0]["terminal_observed"] is True
    assert "process_not_clean" in result["gaps"]
    assert ledger.snapshot(NOW).unresolved == 1


def test_capture_limit_preserves_process_result_and_does_not_complete(tmp_path):
    ledger, output = new_case(tmp_path)

    result = run_supervised_streaming(
        ledger, "stream_complete", output, "capture-limit", NOW,
        billing_current=True, time_scale=0.02, capture_limit=64,
    )
    assert result["integration_outcome"] == "held"
    assert result["gaps"]
    assert result["process"]["captured_bytes"] <= 64
    assert result["process"]["capture_complete"] is False
    assert ledger.snapshot(NOW).unresolved == 1


def test_sidecar_write_failure_retains_process_result_and_ledger_hold(tmp_path, monkeypatch):
    from prototype.run_timing import streaming_session

    original_write = streaming_session._write

    def fail_sidecar(path, data):
        if Path(path).name == "stream-supervisor.pending":
            raise OSError("injected sidecar write failure")
        return original_write(path, data)

    monkeypatch.setattr(streaming_session, "_write", fail_sidecar)
    ledger, output = new_case(tmp_path)
    with pytest.raises(FixtureCloseoutError) as caught:
        run_supervised_streaming(
            ledger, "stream_complete", output, "write-failure", NOW,
            billing_current=True, time_scale=0.02,
        )

    process = caught.value.process_result
    assert process.scenario == "stream_complete"
    assert process.root_reaped is True
    assert process.group_gone is True
    assert process.pipes_closed is True
    assert ledger.snapshot(NOW).unresolved == 1


def test_post_readback_failure_is_wrapped_with_process_result(tmp_path, monkeypatch):
    from prototype.run_timing import streaming_rehearsal

    def fail_readback(_directory, *, scenario):
        raise EvidenceUnavailable("injected readback failure")

    monkeypatch.setattr(streaming_rehearsal, "read_supervised_streaming_evidence", fail_readback)
    ledger, output = new_case(tmp_path)
    with pytest.raises(streaming_rehearsal.StreamEvidenceError) as caught:
        run_supervised_streaming(
            ledger, "stream_complete", output, "readback-failure", NOW,
            billing_current=True, time_scale=0.02,
        )

    process = caught.value.process_result
    assert process.scenario == "stream_complete"
    assert process.outcome.execution == "completed"
    assert ledger.snapshot(NOW).unresolved == 1


def _tamper_sidecar(directory: Path, mutate) -> None:
    path = directory / "stream-supervisor.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8")


@pytest.mark.parametrize("mutation", [
    pytest.param(lambda value: value.update(version=True), id="version-bool"),
    pytest.param(lambda value: value.update(version=1.0), id="version-float"),
    pytest.param(lambda value: value.update(scenario="stream_wait"), id="scenario"),
    pytest.param(lambda value: value.update(worker_sha256="0" * 64), id="worker-digest"),
    pytest.param(lambda value: value.update(lease_id="forged-lease"), id="lease"),
    pytest.param(lambda value: value["child"]["acknowledgements"].clear(), id="child-count"),
    pytest.param(
        lambda value: value["child"]["receipts"][0].update(stream_sha256="0" * 64),
        id="child-digest",
    ),
    pytest.param(
        lambda value: value["control"].update(closeout_finished_us=0),
        id="cleanup-chronology",
    ),
])
def test_stream_sidecar_tampering_cannot_be_read_as_success(tmp_path, mutation):
    _ledger, output, _result = run_case(tmp_path, "stream_complete")
    directory = output / "attempt"
    _tamper_sidecar(directory, mutation)

    with pytest.raises(EvidenceUnavailable):
        read_supervised_streaming_evidence(directory, scenario="stream_complete")


@pytest.mark.parametrize(("mutation", "expected_gap"), [
    pytest.param(
        lambda value: value["parent"]["stream_receipts"][0].update(upstream_attempted=False),
        "parent_stream_metadata_mismatch", id="upstream-not-attempted",
    ),
    pytest.param(
        lambda value: value["parent"]["stream_receipts"][0].update(forwarded_frame_count=1),
        "parent_stream_metadata_mismatch", id="partial-forward",
    ),
    pytest.param(
        lambda value: value["parent"]["upstream_receipts"][0].update(credential_replaced=False),
        "upstream_binding_mismatch", id="credential-not-replaced",
    ),
    pytest.param(
        lambda value: value["parent"]["upstream_receipts"][0].update(host_matches=False),
        "upstream_binding_mismatch", id="host-mismatch",
    ),
    pytest.param(
        lambda value: value["parent"]["upstream_receipts"][0].update(body_sha256="0" * 64),
        "upstream_binding_mismatch", id="body-digest-mismatch",
    ),
])
def test_parent_receipt_metadata_mismatch_is_held_with_explicit_gap(
    tmp_path, mutation, expected_gap,
):
    _ledger, output, _result = run_case(tmp_path, "stream_complete")
    directory = output / "attempt"

    _tamper_sidecar(directory, mutation)
    result = read_supervised_streaming_evidence(directory, scenario="stream_complete")

    assert result["integration_outcome"] == "held"
    assert result["gaps"] == [expected_gap]
    assert result["billing_actual"] is None


def test_readback_rederives_close_duration_overrun_when_sidecar_gaps_are_empty(tmp_path):
    _ledger, output, _result = run_case(tmp_path, "stream_complete")
    directory = output / "attempt"

    def mutate(value):
        control = value["control"]
        control["closeout_finished_us"] = 6_000_001
        control["closeout_duration_us"] = 5_000_001
        control["close_failures"] = []
        value["gaps"] = []

    _tamper_sidecar(directory, mutate)
    result = read_supervised_streaming_evidence(directory, scenario="stream_complete")

    assert result["integration_outcome"] == "held"
    assert result["gaps"] == ["close_duration_exceeded"]


def test_missing_closeout_base_artifact_cannot_be_read_back_as_success(tmp_path):
    _ledger, output, _result = run_case(tmp_path, "stream_complete")
    directory = output / "attempt"
    (directory / "closeout.json").unlink()

    with pytest.raises(EvidenceUnavailable):
        read_supervised_streaming_evidence(directory, scenario="stream_complete")


def test_same_attempt_cannot_retry_after_stream_closeout(tmp_path):
    ledger, output, _result = run_case(tmp_path, "stream_complete")

    with pytest.raises(LedgerUnavailable):
        run_supervised_streaming(
            ledger, "stream_complete", output, "attempt", NOW,
            billing_current=True, time_scale=0.02,
        )
    assert ledger.snapshot(NOW).unresolved == 1


@pytest.mark.parametrize("scenario", ["timing_rehearsal", "success", "unknown"])
def test_only_closed_stream_scenarios_are_admitted(tmp_path, scenario):
    ledger, output = new_case(tmp_path)

    with pytest.raises(ValueError):
        run_supervised_streaming(
            ledger, scenario, output, "invalid", NOW,
            billing_current=True, time_scale=0.02,
        )
    assert ledger.snapshot(NOW).attempts == 0


@pytest.mark.parametrize("kwargs", [
    {"attempt_id": "../escape"},
    {"attempt_id": "bad space"},
    {"capture_limit": True},
    {"capture_limit": 0},
    {"capture_limit": 1024 * 1024 + 1},
])
def test_stream_api_rejects_unbounded_or_arbitrary_inputs(tmp_path, kwargs):
    ledger, output = new_case(tmp_path)
    attempt_id = kwargs.pop("attempt_id", "attempt")

    with pytest.raises((TypeError, ValueError)):
        run_supervised_streaming(
            ledger, "stream_complete", output, attempt_id, NOW,
            billing_current=True, time_scale=0.02, **kwargs,
        )
    assert ledger.snapshot(NOW).attempts == 0
