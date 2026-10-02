"""Investigation body artifacts at the public helper output/file boundary."""

from __future__ import annotations

import json
import os
import re
import shlex
import stat

import pytest

from grafana_jsm_sandbox.incident_payload import main
from tests.test_incident_payload import FIRING, canned, run_directory


def argv(unknown="check next"):
    return ["investigate", "--key", "SANDBOX-7", "--observation", "ignored without evidence",
            "--interpretation", "ignored without evidence", "--unknown", unknown]


def test_public_investigation_emits_short_command_and_exact_private_adf_artifact(tmp_path, capsys):
    working = run_directory(tmp_path, canned(FIRING))

    assert main(argv(), working) == 0
    output = capsys.readouterr()
    words = shlex.split(output.out)

    assert output.err == "" and len(output.out.splitlines()) == 1
    assert words[:5] == ["jira-as", "collaborate", "comment", "add", "SANDBOX-7"]
    assert words[5] == "--body-file" and words[7:] == ["--format", "adf"]
    assert re.fullmatch(r"grafana-investigation-[0-9a-f]{64}\.adf\.json", words[6])
    assert len(output.out.encode()) < 200
    artifact = working / words[6]
    body = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [
        {"type": "text", "text": "[grafana-investigation] "},
        {"type": "text", "text": "Observation:", "marks": [{"type": "strong"}]},
        {"type": "text", "text": " Evidence unavailable | "},
        {"type": "text", "text": "Interpretation:", "marks": [{"type": "strong"}]},
        {"type": "text", "text": " No conclusion from Grafana | "},
        {"type": "text", "text": "Unknown / next check:", "marks": [{"type": "strong"}]},
        {"type": "text", "text": " check next | "},
        {"type": "text", "text": "Evidence:", "marks": [{"type": "strong"}]},
        {"type": "text", "text": " "},
        {"type": "text", "text": "unavailable: no query evidence recorded"},
    ]}]}
    assert artifact.read_bytes() == json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    assert stat.S_ISREG(artifact.lstat().st_mode)
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert list(working.glob(".grafana-investigation-*")) == []


def test_identical_body_reuses_artifact_and_changed_body_preserves_old_command(tmp_path, capsys):
    working = run_directory(tmp_path, canned(FIRING))
    assert main(argv(), working) == 0
    original_command = capsys.readouterr().out
    original = working / shlex.split(original_command)[6]
    original_bytes, original_stat = original.read_bytes(), original.stat()

    assert main(argv(), working) == 0
    assert capsys.readouterr().out == original_command
    assert original.read_bytes() == original_bytes
    assert original.stat().st_ino == original_stat.st_ino
    assert original.stat().st_mtime_ns == original_stat.st_mtime_ns

    assert main(argv("a different next check"), working) == 0
    changed_command = capsys.readouterr().out
    changed = working / shlex.split(changed_command)[6]
    assert changed != original and changed.read_bytes() != original_bytes
    assert original.read_bytes() == original_bytes
    assert len(list(working.glob("grafana-investigation-*.adf.json"))) == 2
    assert list(working.glob(".grafana-investigation-*")) == []


def test_artifact_bound_accepts_256kib_and_refuses_larger_body_without_truncating(tmp_path, capsys):
    working = run_directory(tmp_path, canned(FIRING))
    assert main(argv("x"), working) == 0
    baseline = working / shlex.split(capsys.readouterr().out)[6]
    exact_unknown = "x" * (256 * 1024 - len(baseline.read_bytes()) + 1)

    assert main(argv(exact_unknown), working) == 0
    accepted = working / shlex.split(capsys.readouterr().out)[6]
    accepted_bytes = accepted.read_bytes()
    assert len(accepted_bytes) == 256 * 1024
    assert exact_unknown in json.loads(accepted_bytes)["content"][0]["content"][6]["text"]

    assert main(argv(exact_unknown + "x"), working) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "256 KiB local artifact limit" in output.err
    assert accepted.read_bytes() == accepted_bytes
    assert len(list(working.glob("grafana-investigation-*.adf.json"))) == 2
    assert list(working.glob(".grafana-investigation-*")) == []


@pytest.mark.parametrize("shape", ["conflict", "symlink", "directory", "fifo", "public_mode"])
def test_unsafe_or_conflicting_existing_destination_is_refused_without_changes(tmp_path, capsys, shape):
    working = run_directory(tmp_path, canned(FIRING))
    assert main(argv(), working) == 0
    target = working / shlex.split(capsys.readouterr().out)[6]
    original_bytes = target.read_bytes()
    target.unlink()
    outside = tmp_path / "outside.json"
    outside.write_bytes(original_bytes)
    if shape == "conflict":
        target.write_bytes(b"conflicting contents")
        target.chmod(0o600)
    elif shape == "symlink":
        target.symlink_to(outside)
    elif shape == "directory":
        target.mkdir()
    elif shape == "fifo":
        os.mkfifo(target, 0o600)
    else:
        target.write_bytes(original_bytes)
        target.chmod(0o644)
    before = target.lstat()

    assert main(argv(), working) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err.startswith("incident-payload: error:")
    assert target.lstat().st_ino == before.st_ino and target.lstat().st_mode == before.st_mode
    assert outside.read_bytes() == original_bytes
    if shape == "conflict":
        assert target.read_bytes() == b"conflicting contents"
    assert list(working.glob(".grafana-investigation-*")) == []


@pytest.mark.parametrize("operation", ["temporary", "flush", "publish"])
def test_filesystem_failure_removes_temporary_file_and_emits_no_post_command(
    tmp_path, capsys, monkeypatch, operation
):
    working = run_directory(tmp_path, canned(FIRING))

    def unavailable(*args, **kwargs):
        raise OSError("synthetic filesystem refusal")

    if operation == "temporary":
        import tempfile
        monkeypatch.setattr(tempfile, "mkstemp", unavailable)
    else:
        monkeypatch.setattr(os, "fsync" if operation == "flush" else "link", unavailable)

    assert main(argv(), working) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err.startswith("incident-payload: error:")
    assert list(working.glob("grafana-investigation-*.adf.json")) == []
    assert list(working.glob(".grafana-investigation-*")) == []


def test_cleanup_failure_is_a_payload_error_without_claiming_cleanup_succeeded(tmp_path, capsys, monkeypatch):
    working = run_directory(tmp_path, canned(FIRING))

    def unavailable(*args, **kwargs):
        raise OSError("synthetic cleanup refusal")

    with monkeypatch.context() as boundary:
        boundary.setattr(os, "unlink", unavailable)
        assert main(argv(), working) == 2
        output = capsys.readouterr()
    assert output.out == "" and "temporary artifact cleanup failed" in output.err
    leftovers = list(working.glob(".grafana-investigation-*"))
    assert len(leftovers) == 1  # The filesystem refused cleanup; do not claim it succeeded.
    for path in leftovers:
        path.unlink()


@pytest.mark.parametrize("change", ["key", "output_path"])
def test_invalid_key_or_output_path_option_is_refused_before_any_artifact_write(tmp_path, capsys, change):
    working = run_directory(tmp_path, canned(FIRING))
    arguments = argv()
    if change == "key":
        arguments[2] = "OTHER-7"
    else:
        arguments.extend(["--output", str(tmp_path / "elsewhere.json")])

    assert main(arguments, working) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err.startswith("incident-payload: error:")
    assert list(working.glob("grafana-investigation-*")) == []
    assert list(working.glob(".grafana-investigation-*")) == []
    assert not (tmp_path / "elsewhere.json").exists()
