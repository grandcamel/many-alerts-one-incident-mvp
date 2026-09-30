"""Independent stream-attribution tests for the fixed-process evidence contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from prototype.run_timing import process_fixture, timing_rehearsal
from prototype.run_timing.fixture_evidence import (
    EvidenceUnavailable,
    read_fixture_evidence,
    write_fixture_evidence,
)


def _run(tmp_path: Path, scenario: str, *, capture_limit: int = 1024 * 1024):
    return process_fixture.run_fixture(
        scenario, tmp_path, "attempt", time_scale=0.01, capture_limit=capture_limit,
    )


def _manifest(directory: Path) -> dict:
    return json.loads((directory / "closeout.json").read_text())


def _refresh_manifest(directory: Path) -> None:
    manifest_path = directory / "closeout.json"
    manifest = _manifest(directory)
    manifest["files"] = {
        name: {"bytes": path.stat().st_size,
               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for name in manifest["files"]
        for path in [directory / name]
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def _refresh_result_stream(directory: Path, *, stdout: bytes | None = None,
                           stderr: bytes | None = None) -> None:
    result_path = directory / "result.json"
    result = json.loads(result_path.read_text())
    if stdout is not None:
        (directory / "stdout.bin").write_bytes(stdout)
        result["stdout_bytes"] = len(stdout)
        result["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
    if stderr is not None:
        (directory / "stderr.bin").write_bytes(stderr)
        result["stderr_bytes"] = len(stderr)
        result["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
    diagnostic = (directory / "capture.bin").read_bytes()
    current_stdout = (directory / "stdout.bin").read_bytes()
    current_stderr = (directory / "stderr.bin").read_bytes()
    if not current_stderr:
        diagnostic = current_stdout
    else:
        # This helper rewrites a synthetic mixed capture in a valid possible
        # stream concatenation order; no native cross-stream order is claimed.
        diagnostic = current_stdout + current_stderr
    (directory / "capture.bin").write_bytes(diagnostic)
    result["captured_bytes"] = len(diagnostic)
    result["capture_sha256"] = hashlib.sha256(diagnostic).hexdigest()
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    _refresh_manifest(directory)


def test_closed_fixture_retains_exact_independent_streams(tmp_path):
    result = _run(tmp_path, "stderr_noise")
    directory = Path(result.attempt_directory)
    stdout = (directory / "stdout.bin").read_bytes()
    stderr = (directory / "stderr.bin").read_bytes()
    evidence = read_fixture_evidence(directory)
    manifest = _manifest(directory)

    assert result.outcome.execution == "completed"
    assert stdout and stderr
    assert result.stdout_bytes == len(stdout)
    assert result.stdout_sha256 == hashlib.sha256(stdout).hexdigest()
    assert result.stderr_bytes == len(stderr)
    assert result.stderr_sha256 == hashlib.sha256(stderr).hexdigest()
    assert result.captured_bytes == len(stdout) + len(stderr)
    assert evidence.stdout == stdout and evidence.stderr == stderr
    assert manifest["version"] == 2
    assert set(manifest["files"]) == {
        "fixture.py", "capture.bin", "stdout.bin", "stderr.bin", "result.json",
    }
    assert b"stderr-is-not-json" in stderr and b"stderr-is-not-json" not in stdout


def test_stream_files_are_not_cross_substitutable(tmp_path):
    result = _run(tmp_path, "stderr_noise")
    directory = Path(result.attempt_directory)
    stdout = (directory / "stdout.bin").read_bytes()
    stderr = (directory / "stderr.bin").read_bytes()
    (directory / "stdout.bin").write_bytes(stderr)
    (directory / "stderr.bin").write_bytes(stdout)
    _refresh_manifest(directory)

    with pytest.raises(EvidenceUnavailable, match="linkage|digest"):
        read_fixture_evidence(directory)


def test_rehashed_stdout_tampering_cannot_replace_single_stream_capture(tmp_path):
    result = _run(tmp_path, "timing_rehearsal")
    directory = Path(result.attempt_directory)
    stdout = (directory / "stdout.bin").read_bytes().replace(
        b"timing_rehearsal_receipt", b"timing_rehearsal_receipX",
    )
    (directory / "stdout.bin").write_bytes(stdout)
    result_path = directory / "result.json"
    payload = json.loads(result_path.read_text())
    payload["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
    result_path.write_text(json.dumps(payload, indent=2) + "\n")
    _refresh_manifest(directory)

    with pytest.raises(EvidenceUnavailable, match="capture|stream"):
        read_fixture_evidence(directory)


def test_aggregate_cap_applies_to_both_streams_and_retains_only_accepted_bytes(tmp_path):
    result = _run(tmp_path, "flood", capture_limit=1024)
    directory = Path(result.attempt_directory)
    stdout = (directory / "stdout.bin").read_bytes()
    stderr = (directory / "stderr.bin").read_bytes()

    assert result.outcome.execution != "completed"
    assert "capture_limit" in result.outcome.reasons
    assert result.capture_complete is False
    assert result.captured_bytes <= 1024
    assert len(stdout) + len(stderr) == result.captured_bytes
    assert read_fixture_evidence(directory).result["capture_complete"] is False


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_rehashed_outer_manifest_does_not_hide_independent_stream_tampering(tmp_path, stream):
    result = _run(tmp_path, "timing_rehearsal")
    directory = Path(result.attempt_directory)
    original_stdout = (directory / "stdout.bin").read_bytes()
    original_stderr = (directory / "stderr.bin").read_bytes()
    if stream == "stdout":
        _refresh_result_stream(directory, stdout=original_stdout.replace(
            b"timing_rehearsal_receipt", b"timing_rehearsal_receipX"))
    else:
        _refresh_result_stream(directory, stderr=original_stderr + b'{"type":"assistant"}\n')

    # The outer manifest and per-stream result links have both been rehashed.
    # The integrated contract still has to inspect the retained stream semantics.
    with pytest.raises(EvidenceUnavailable):
        timing_rehearsal.read_rehearsal_evidence(directory, scenario="timing_rehearsal")
    assert read_fixture_evidence(directory).result["scenario"] == "timing_rehearsal"


def test_stderr_json_cannot_spoof_stdout_receipt(tmp_path):
    result = _run(tmp_path, "stderr_json")
    directory = Path(result.attempt_directory)
    assert b'"channel":"stderr"' in (directory / "stderr.bin").read_bytes()
    # Use a complete rehearsal bundle, then inject the same JSON-shaped bytes
    # into its retained stderr stream. The integrated parser must stay stdout-only.
    rehearsal = process_fixture.run_fixture(
        "timing_rehearsal", tmp_path, "rehearsal", time_scale=0.01,
    )
    rehearsal_dir = Path(rehearsal.attempt_directory)
    _refresh_result_stream(rehearsal_dir, stderr=b'{"type":"assistant"}\n')
    with pytest.raises(EvidenceUnavailable):
        timing_rehearsal.read_rehearsal_evidence(
            rehearsal_dir, scenario="timing_rehearsal",
        )


def test_v1_readback_is_explicitly_stream_unknown_and_not_integrated(tmp_path):
    directory = tmp_path / "legacy"
    directory.mkdir()
    worker = b"# legacy fixture\n"
    capture = b'{"type":"result"}\n'
    (directory / "fixture.py").write_bytes(worker)
    result = {
        "scope": "FIXED_HOST_FIXTURES_ONLY", "native_launch": "CLOSED",
        "attempt_directory": str(directory), "captured_bytes": len(capture),
        "capture_sha256": hashlib.sha256(capture).hexdigest(),
        "worker_sha256": hashlib.sha256(worker).hexdigest(),
        "scenario": "timing_rehearsal",
    }
    evidence = write_fixture_evidence(directory, capture, result)

    assert _manifest(directory)["version"] == 1
    assert evidence.stdout is None and evidence.stderr is None
    assert read_fixture_evidence(directory).stdout is None
    # A historical receipt with unknown stream provenance cannot satisfy the
    # integrated stdout-only contract.
    with pytest.raises(EvidenceUnavailable):
        timing_rehearsal.read_rehearsal_evidence(directory, scenario="timing_rehearsal")


def test_v2_to_v1_downgrade_with_stream_metadata_is_rejected(tmp_path):
    result = _run(tmp_path, "stderr_noise")
    directory = Path(result.attempt_directory)
    manifest_path = directory / "closeout.json"
    manifest = _manifest(directory)
    manifest["version"] = 1
    del manifest["files"]["stdout.bin"]
    del manifest["files"]["stderr.bin"]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    with pytest.raises(EvidenceUnavailable, match="downgrad|manifest"):
        read_fixture_evidence(directory)


def test_writer_rejects_partial_stream_arguments(tmp_path):
    directory = tmp_path / "partial"
    directory.mkdir()

    with pytest.raises(EvidenceUnavailable, match="both streams"):
        write_fixture_evidence(directory, b"", {}, stdout=b"stdout")
    assert list(directory.iterdir()) == []


def test_partial_stream_metadata_is_rejected(tmp_path):
    result = _run(tmp_path, "stderr_noise")
    directory = Path(result.attempt_directory)
    result_path = directory / "result.json"
    payload = json.loads(result_path.read_text())
    payload.pop("stderr_sha256")
    result_path.write_text(json.dumps(payload, indent=2) + "\n")
    _refresh_manifest(directory)

    with pytest.raises(EvidenceUnavailable, match="linkage|stream"):
        read_fixture_evidence(directory)


def test_failed_v2_closeout_preserves_process_result(tmp_path, monkeypatch):
    observed = {}

    def fail(directory, capture, result, **kwargs):
        observed.update(result=result, kwargs=kwargs)
        raise EvidenceUnavailable("synthetic v2 closeout failure")

    monkeypatch.setattr(process_fixture, "write_fixture_evidence", fail)
    with pytest.raises(process_fixture.FixtureCloseoutError) as caught:
        process_fixture.run_fixture("stderr_noise", tmp_path, "attempt", time_scale=0.01)

    held = caught.value.process_result
    assert held.outcome.execution == "completed"
    assert held.stdout_bytes and held.stdout_sha256
    assert held.stderr_bytes and held.stderr_sha256
    assert observed["kwargs"]["stdout"] and observed["kwargs"]["stderr"]
    assert asdict(held)["scenario"] == "stderr_noise"


@pytest.mark.parametrize("field", ["capture_complete", "root_reaped", "group_gone",
                                    "pipes_closed"])
@pytest.mark.parametrize("value", ["false", 1])
def test_integrated_completion_flags_require_exact_booleans(tmp_path, field, value):
    result = _run(tmp_path, "timing_rehearsal")
    directory = Path(result.attempt_directory)
    result_path = directory / "result.json"
    payload = json.loads(result_path.read_text())
    payload[field] = value
    result_path.write_text(json.dumps(payload, indent=2) + "\n")
    _refresh_manifest(directory)

    with pytest.raises(EvidenceUnavailable, match="completion flags"):
        timing_rehearsal.read_rehearsal_evidence(directory, scenario="timing_rehearsal")


def test_exact_false_completion_flag_keeps_integrated_result_held(tmp_path):
    result = _run(tmp_path, "timing_rehearsal")
    directory = Path(result.attempt_directory)
    result_path = directory / "result.json"
    payload = json.loads(result_path.read_text())
    payload["capture_complete"] = False
    result_path.write_text(json.dumps(payload, indent=2) + "\n")
    _refresh_manifest(directory)

    evidence = timing_rehearsal.read_rehearsal_evidence(
        directory, scenario="timing_rehearsal",
    )
    assert evidence["integration_outcome"] == "held"
