"""End-to-end tests for the fixed child-process timing rehearsal."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prototype.run_timing import process_fixture, rehearsal_bundle, timing_rehearsal
from prototype.run_timing.fixture_evidence import EvidenceUnavailable
from prototype.run_timing.fixture_ledger import (
    FixtureLedger,
    LedgerUnavailable,
    run_budgeted_fixture,
)
from prototype.run_timing.timing_rehearsal import (
    RehearsalEvidenceError,
    read_rehearsal_evidence,
    run_timing_rehearsal,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=UTC)


def new_case(tmp_path: Path) -> tuple[FixtureLedger, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = tmp_path / "output"
    output.mkdir()
    return FixtureLedger.create(tmp_path / "fixture.db"), output


def run_case(tmp_path: Path, scenario: str, *, attempt_id: str = "attempt",
             **kwargs) -> tuple[FixtureLedger, Path, dict]:
    ledger, output = new_case(tmp_path)
    result = run_timing_rehearsal(
        ledger, scenario, output, attempt_id, NOW, billing_current=True,
        time_scale=0.02, **kwargs,
    )
    return ledger, output, result


def test_success_unknown_and_pending_flows_retain_distinct_outcomes(tmp_path):
    for scenario, expected in (
        ("timing_rehearsal", ("completed", ["confirmed", "confirmed"], 2, False)),
        ("timing_unknown", ("held", ["unknown"], 1, True)),
    ):
        ledger, output, result = run_case(tmp_path / scenario, scenario)
        outcome, effects, revisions, hold = expected
        assert result["integration_outcome"] == outcome
        assert result["effect_outcomes"] == effects
        assert result["retained_revisions"] == revisions
        assert result["effect_hold"] is hold
        assert ledger.snapshot(NOW).unresolved == 1
        assert (output / "attempt" / "timing-snapshot").is_dir()
        assert result["pending_dispatch_id"] is None
        assert result["receipt"]["capture_phase"] == "final"


def test_wait_scenario_times_out_without_promoting_pending_write(tmp_path):
    ledger, _output, result = run_case(tmp_path, "timing_wait")
    # run_case uses no cancellation, so the real supervisor reaches its scaled host deadline.
    assert result["process"]["outcome"]["execution"] == "timed_out"
    assert result["integration_outcome"] == "held"
    assert result["effect_outcomes"] == []
    assert result["pending_dispatch_id"]
    assert result["retained_revisions"] == 0
    assert result["process"]["root_reaped"]
    assert result["process"]["group_gone"]
    assert result["process"]["pipes_closed"]
    assert ledger.snapshot(NOW).unresolved == 1


def test_cancellation_after_receipt_reaps_child_and_preserves_before_wait_snapshot(
        tmp_path, monkeypatch):
    ledger, output = new_case(tmp_path)
    cancel = threading.Event()
    original_append = process_fixture.Capture.append

    def append_and_cancel(capture, data):
        accepted = original_append(capture, data)
        if accepted and b"timing_rehearsal_receipt" in capture.data:
            cancel.set()
        return accepted

    monkeypatch.setattr(process_fixture.Capture, "append", append_and_cancel)
    result = run_timing_rehearsal(
        ledger, "timing_wait", output, "cancelled", NOW, billing_current=True,
        time_scale=0.02, cancel=cancel,
    )
    assert result["process"]["outcome"]["execution"] == "cancelled"
    assert result["integration_outcome"] == "held"
    assert result["receipt"]["capture_phase"] == "before_wait"
    assert result["pending_dispatch_id"]
    assert result["retained_revisions"] == 0
    assert result["process"]["root_reaped"]
    assert result["process"]["group_gone"]
    assert result["process"]["pipes_closed"]
    assert ledger.snapshot(NOW).unresolved == 1


def test_reservation_is_claimed_and_same_attempt_cannot_auto_retry(tmp_path):
    ledger, output, result = run_case(tmp_path, "timing_rehearsal")
    assert result["process"]["outcome"]["execution"] == "completed"
    assert ledger.snapshot(NOW).unresolved == 1
    with pytest.raises(LedgerUnavailable, match="attempt_exists"):
        run_timing_rehearsal(
            ledger, "timing_rehearsal", output, "attempt", NOW, billing_current=True,
            time_scale=0.02,
        )
    assert ledger.snapshot(NOW).unresolved == 1


@pytest.mark.parametrize("scenario", ["timing_rehearsal", "timing_unknown"])
def test_independent_cases_use_new_ledgers_and_do_not_inherit_unknown_state(tmp_path, scenario):
    ledger, _, result = run_case(tmp_path, scenario, attempt_id="same-attempt")
    assert result["scenario"] == scenario
    assert ledger.snapshot(NOW).attempts == 1
    assert ledger.snapshot(NOW).unresolved == 1


def test_receipt_binds_actual_manifest_bytes_and_fixed_child_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "host-secret-must-not-cross-child-boundary")
    monkeypatch.setenv("JIRA_API_TOKEN", "host-token-must-not-cross-child-boundary")
    _ledger, output, result = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"
    assert read_rehearsal_evidence(directory, scenario="timing_rehearsal") == result
    manifest = (directory / "timing-snapshot" / "manifest.json").read_bytes()
    assert result["receipt"]["snapshot_manifest_bytes"] == len(manifest)
    assert result["receipt"]["snapshot_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
    worker = (directory / "fixture.py").read_bytes()
    assert worker == rehearsal_bundle.build_rehearsal_worker()
    assert len(worker) <= rehearsal_bundle.MAX_WORKER_BYTES
    assert "timing_rehearsal.py" not in rehearsal_bundle.FILES
    assert "TIMING_BINDING.md" not in rehearsal_bundle.FILES
    assert all("rubric" not in name.lower() and "ground_truth" not in name.lower()
               for name in rehearsal_bundle.FILES)
    assert not list(directory.rglob("__pycache__"))


def test_parent_runner_never_constructs_child_binding_or_query_objects(tmp_path, monkeypatch):
    from prototype.run_timing import timing_binding, timing_incidents, timing_queries

    def forbidden(*args, **kwargs):
        raise AssertionError("parent constructed a child timing object")

    monkeypatch.setattr(timing_binding, "TimingBinding", forbidden)
    monkeypatch.setattr(timing_queries, "TimingQueries", forbidden)
    monkeypatch.setattr(timing_incidents, "TimingIncidents", forbidden)
    _, output, result = run_case(tmp_path, "timing_rehearsal")
    assert result["integration_outcome"] == "completed"
    assert (output / "attempt" / "fixture.py").exists()


def test_captured_success_without_rehearsal_artifacts_cannot_be_complete(tmp_path):
    ledger, output = new_case(tmp_path)
    process = run_budgeted_fixture(
        ledger, "timing_rehearsal", output, "orphaned", NOW,
        billing_current=True, time_scale=0.02,
    )
    assert process.outcome.execution == "completed"
    (output / "orphaned" / "binding-audit.json").unlink()
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(output / "orphaned", scenario="timing_rehearsal")
    assert ledger.snapshot(NOW).unresolved == 1


def _rewrite_closeout(directory: Path) -> None:
    result_path = directory / "result.json"
    result = json.loads(result_path.read_text())
    result["attempt_directory"] = str(directory.absolute())
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    manifest_path = directory / "closeout.json"
    manifest = json.loads(manifest_path.read_text())
    for name in ("capture.bin", "stdout.bin", "stderr.bin", "result.json"):
        if not (directory / name).exists():
            continue
        raw = (directory / name).read_bytes()
        manifest["files"][name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def _rewrite_capture(directory: Path, mutate_event) -> None:
    stdout_before = (directory / "stdout.bin").read_bytes()
    lines = stdout_before.splitlines()
    changed = False
    rewritten = []
    for line in lines:
        event = json.loads(line)
        changed = mutate_event(event) or changed
        rewritten.append(json.dumps(event, sort_keys=True, separators=(",", ":")).encode())
    assert changed
    capture = b"\n".join(rewritten) + b"\n"
    (directory / "stdout.bin").write_bytes(capture)
    result_path = directory / "result.json"
    result = json.loads(result_path.read_text())
    result["stdout_bytes"] = len(capture)
    result["stdout_sha256"] = hashlib.sha256(capture).hexdigest()
    assert not (directory / "stderr.bin").read_bytes()
    diagnostic = capture
    (directory / "capture.bin").write_bytes(diagnostic)
    result["captured_bytes"] = len(diagnostic)
    result["capture_sha256"] = hashlib.sha256(diagnostic).hexdigest()
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    _rewrite_closeout(directory)


def _rewrite_capture_and_process_manifest(directory: Path, mutate_receipt) -> None:
    def mutate_event(event):
        message = event.get("message", {})
        content = message.get("content", [])
        changed = False
        for item in content:
            if isinstance(item, dict) and item.get("type") == "timing_rehearsal_receipt":
                mutate_receipt(item)
                changed = True
        return changed

    _rewrite_capture(directory, mutate_event)


def _rewrite_audit_and_receipt(directory: Path, mutate_audit) -> None:
    audit_path = directory / "binding-audit.json"
    audit = json.loads(audit_path.read_text())
    mutate_audit(audit)
    audit_path.write_text(json.dumps(audit, sort_keys=True, separators=(",", ":")))
    audit_sha = hashlib.sha256(audit_path.read_bytes()).hexdigest()
    audit_bytes = audit_path.stat().st_size
    _rewrite_capture_and_process_manifest(
        directory,
        lambda receipt: receipt.update(binding_audit_sha256=audit_sha,
                                       binding_audit_bytes=audit_bytes),
    )


def _tamper_audit_query_arguments(directory: Path) -> None:
    def mutate(audit):
        query = next(row for row in audit["history"]
                     if row["request"]["operation"] == "logs.query")
        query["request"]["arguments"]["limit"] = 2

    _rewrite_audit_and_receipt(directory, mutate)


@pytest.mark.parametrize("tamper", ["audit_digest", "missing_audit", "duplicate_receipt",
                                     "wrong_attempt", "manifest"])
def test_readback_rejects_tampered_or_incomplete_rehearsal_evidence(tmp_path, tamper):
    _, output, _ = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"
    if tamper == "audit_digest":
        raw = bytearray((directory / "binding-audit.json").read_bytes())
        raw[-2] = ord(" ")
        (directory / "binding-audit.json").write_bytes(bytes(raw))
    elif tamper == "missing_audit":
        (directory / "binding-audit.json").unlink()
    elif tamper == "duplicate_receipt":
        stdout_before = (directory / "stdout.bin").read_bytes()
        lines = stdout_before.splitlines()
        receipt_line = next(line for line in lines if b"timing_rehearsal_receipt" in line)
        stdout = b"\n".join(lines + [receipt_line]) + b"\n"
        (directory / "stdout.bin").write_bytes(stdout)
        result_path = directory / "result.json"
        result = json.loads(result_path.read_text())
        result["stdout_bytes"] = len(stdout)
        result["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        assert not (directory / "stderr.bin").read_bytes()
        diagnostic = stdout
        (directory / "capture.bin").write_bytes(diagnostic)
        result["captured_bytes"] = len(diagnostic)
        result["capture_sha256"] = hashlib.sha256(diagnostic).hexdigest()
        result_path.write_text(json.dumps(result, indent=2) + "\n")
        _rewrite_closeout(directory)
    elif tamper == "wrong_attempt":
        _rewrite_capture_and_process_manifest(
            directory, lambda receipt: receipt.update(attempt_id="other-attempt"))
    elif tamper == "manifest":
        manifest_path = directory / "timing-snapshot" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["bytes"] += 1
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(directory, scenario="timing_rehearsal")


def test_readback_rejects_query_request_argument_tampering_even_when_outer_hashes_are_updated(tmp_path):
    _, output, _ = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"
    _tamper_audit_query_arguments(directory)
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(directory, scenario="timing_rehearsal")


@pytest.mark.parametrize("shape", ["message_list", "content_dict"])
def test_readback_rejects_malformed_assistant_shapes_after_capture_hash_refresh(tmp_path, shape):
    _, output, _ = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"

    def mutate_event(event):
        message = event.get("message", {})
        content = message.get("content")
        if (event.get("type") == "assistant" and isinstance(content, list) and
                any(isinstance(item, dict) and item.get("type") == "timing_rehearsal_receipt"
                    for item in content)):
            if shape == "message_list":
                event["message"] = []
            else:
                message["content"] = {"malformed": "expected a list"}
            return True
        return False

    _rewrite_capture(directory, mutate_event)
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(directory, scenario="timing_rehearsal")


@pytest.mark.parametrize("shape", ["items_dict", "response_list"])
def test_readback_rejects_malformed_candidate_shapes_after_digest_refresh(tmp_path, shape):
    _, output, _ = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"

    def mutate(audit):
        row = next(row for row in audit["history"]
                   if row["request"]["operation"] == "incidents.candidates")
        if shape == "response_list":
            row["response"] = []
        else:
            response = row["response"]
            response["items"] = {"malformed": "expected a list"}
            body = {key: value for key, value in response.items() if key != "sha256"}
            response["sha256"] = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        row["response_sha256"] = hashlib.sha256(
            json.dumps(row["response"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    _rewrite_audit_and_receipt(directory, mutate)
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(directory, scenario="timing_rehearsal")


def test_readback_rejects_invalid_candidate_call_id_after_outer_hash_refresh(tmp_path):
    _, output, _ = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"

    def mutate(audit):
        row = next(row for row in audit["history"]
                   if row["request"]["operation"] == "incidents.candidates")
        row["call_id"] = "../escaped"
        row["request"]["call_id"] = "../escaped"

    _rewrite_audit_and_receipt(directory, mutate)
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(directory, scenario="timing_rehearsal")


def test_rehearsal_error_preserves_completed_process_result_when_readback_fails(
        tmp_path, monkeypatch):
    ledger, output = new_case(tmp_path)

    def unavailable(*args, **kwargs):
        raise EvidenceUnavailable("synthetic post-run readback loss")

    monkeypatch.setattr(timing_rehearsal, "read_rehearsal_evidence", unavailable)
    with pytest.raises(RehearsalEvidenceError) as caught:
        run_timing_rehearsal(
            ledger, "timing_rehearsal", output, "readback-loss", NOW,
            billing_current=True, time_scale=0.02,
        )
    assert caught.value.process_result.outcome.execution == "completed"
    assert caught.value.process_result.attempt_directory == str(output / "readback-loss")
    assert ledger.snapshot(NOW).unresolved == 1


def test_readback_rejects_rehashed_non_json_stderr_capture(tmp_path):
    _, output, _ = run_case(tmp_path, "timing_rehearsal")
    directory = output / "attempt"
    stderr_path = directory / "stderr.bin"
    stderr = stderr_path.read_bytes() + b"stderr-is-not-json\n"
    stderr_path.write_bytes(stderr)
    capture_path = directory / "capture.bin"
    capture = capture_path.read_bytes() + b"stderr-is-not-json\n"
    capture_path.write_bytes(capture)
    result_path = directory / "result.json"
    result = json.loads(result_path.read_text())
    result["captured_bytes"] = len(capture)
    result["capture_sha256"] = hashlib.sha256(capture).hexdigest()
    result["stderr_bytes"] = len(stderr)
    result["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    _rewrite_closeout(directory)
    with pytest.raises(EvidenceUnavailable):
        read_rehearsal_evidence(directory, scenario="timing_rehearsal")
