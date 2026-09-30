"""Bounded byte-integrity receipts for trusted fixed fixtures, not native audit evidence."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

SCOPE = "FIXED_FIXTURE_BYTE_INTEGRITY_ONLY"
LIMITS = {"fixture.py": 64 * 1024, "capture.bin": 1024 * 1024, "result.json": 64 * 1024}
V2_LIMITS = {**LIMITS, "stdout.bin": 1024 * 1024, "stderr.bin": 1024 * 1024}
MANIFEST_LIMIT = 4096
_STREAM_FIELDS = ("stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256")


class EvidenceUnavailable(RuntimeError):
    """No verified fixed-fixture receipt is available; retain accounting uncertainty."""


def _read(path: Path, limit: int) -> bytes:
    # O_NONBLOCK prevents a substituted FIFO from hanging before fstat can reject it.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise EvidenceUnavailable("nonregular or oversized fixture evidence")
        data = handle.read(limit + 1)
        if len(data) > limit or len(data) != info.st_size:
            raise EvidenceUnavailable("fixture evidence changed size during read")
        return data


def _json(data: bytes) -> dict:
    def nonfinite(_):
        raise EvidenceUnavailable("nonfinite evidence number")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise EvidenceUnavailable("duplicate evidence key")
            value[key] = item
        return value

    value = json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)
    if not isinstance(value, dict):
        raise EvidenceUnavailable("fixture evidence must be a JSON object")
    return value


def _encoded(value: dict, limit: int) -> bytes:
    data = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
    if len(data) > limit:
        raise EvidenceUnavailable("fixture evidence exceeds file bound")
    return data


def _record(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class FixtureEvidence:
    result: dict
    manifest_sha256: str
    scope: str = SCOPE
    native_launch: str = "CLOSED"
    stdout: bytes | None = None
    stderr: bytes | None = None


def _linked_result(directory: Path, contents: dict[str, bytes], *, version: int) -> dict:
    result = _json(contents["result.json"])
    if (result.get("scope") != "FIXED_HOST_FIXTURES_ONLY" or
            result.get("native_launch") != "CLOSED" or
            result.get("attempt_directory") != str(directory) or
            type(result.get("captured_bytes")) is not int or
            result["captured_bytes"] != len(contents["capture.bin"]) or
            result.get("capture_sha256") != _record(contents["capture.bin"])["sha256"] or
            result.get("worker_sha256") != _record(contents["fixture.py"])["sha256"]):
        raise EvidenceUnavailable("fixture result linkage mismatch")
    if version == 1:
        if any(result.get(field) is not None for field in _STREAM_FIELDS):
            raise EvidenceUnavailable("stream metadata cannot be downgraded to version 1")
    elif version == 2:
        stdout, stderr = contents["stdout.bin"], contents["stderr.bin"]
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            if (type(result.get(name + "_bytes")) is not int or
                    result[name + "_bytes"] != len(data) or
                    result.get(name + "_sha256") != _record(data)["sha256"]):
                raise EvidenceUnavailable("fixture stream linkage mismatch")
        if result["stdout_bytes"] + result["stderr_bytes"] != result["captured_bytes"]:
            raise EvidenceUnavailable("fixture stream lengths do not match diagnostic capture")
        if not stderr and contents["capture.bin"] != stdout:
            raise EvidenceUnavailable("stdout does not match single-stream diagnostic capture")
        if not stdout and contents["capture.bin"] != stderr:
            raise EvidenceUnavailable("stderr does not match single-stream diagnostic capture")
    else:
        raise EvidenceUnavailable("unsupported fixture manifest")
    return result


def write_fixture_evidence(directory: Path, capture: bytes, result: dict, *,
                           stdout: bytes | None = None, stderr: bytes | None = None) -> FixtureEvidence:
    """Publish once after supervision; failures leave partial files and never release cost."""
    directory = Path(directory).absolute()
    try:
        if type(capture) is not bytes or len(capture) > LIMITS["capture.bin"]:
            raise EvidenceUnavailable("invalid fixed fixture capture")
        if (stdout is None) != (stderr is None):
            raise EvidenceUnavailable("fixture stream evidence must include both streams")
        if stdout is not None and (type(stdout) is not bytes or type(stderr) is not bytes):
            raise EvidenceUnavailable("invalid fixed fixture stream evidence")
        version = 2 if stdout is not None else 1
        contents = {"fixture.py": _read(directory / "fixture.py", LIMITS["fixture.py"]),
                    "capture.bin": capture,
                    "result.json": _encoded(result, LIMITS["result.json"])}
        if version == 2:
            if len(stdout) > V2_LIMITS["stdout.bin"] or len(stderr) > V2_LIMITS["stderr.bin"]:
                raise EvidenceUnavailable("fixture stream evidence exceeds file bound")
            contents["stdout.bin"] = stdout
            contents["stderr.bin"] = stderr
        _linked_result(directory, contents, version=version)
        for name in ("capture.bin", "result.json", "stdout.bin", "stderr.bin"):
            if name in contents:
                _write(directory / name, contents[name])
        # The worker snapshot was created before launch. Flush it before publishing linkage.
        fd = os.open(directory / "fixture.py", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise EvidenceUnavailable("nonregular fixture snapshot")
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync_directory(directory)
        _sync_directory(directory.parent)
        manifest = {"version": version, "scope": SCOPE, "native_launch": "CLOSED",
                    "files": {name: _record(data) for name, data in contents.items()}}
        pending = directory / "closeout.pending"
        _write(pending, _encoded(manifest, MANIFEST_LIMIT))
        # Hard-link publication is atomic and refuses an existing target. Never overwrite.
        os.link(pending, directory / "closeout.json")
        pending.unlink()
        _sync_directory(directory)
        return read_fixture_evidence(directory)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise EvidenceUnavailable("fixture closeout failed; preserve partial evidence") from exc


def read_fixture_evidence(directory: Path) -> FixtureEvidence:
    """Verify retained bytes, not semantic success, provenance, billing or durable deadlines."""
    directory = Path(directory).absolute()
    try:
        raw = _read(directory / "closeout.json", MANIFEST_LIMIT)
        manifest = _json(raw)
        if (set(manifest) != {"version", "scope", "native_launch", "files"} or
                type(manifest["version"]) is not int or manifest["version"] not in (1, 2) or
                manifest["scope"] != SCOPE or manifest["native_launch"] != "CLOSED" or
                not isinstance(manifest["files"], dict)):
            raise EvidenceUnavailable("unsupported fixture manifest")
        version = manifest["version"]
        limits = LIMITS if version == 1 else V2_LIMITS
        if set(manifest["files"]) != set(limits):
            raise EvidenceUnavailable("unsupported fixture manifest")
        contents = {}
        for name, limit in limits.items():
            data = _read(directory / name, limit)
            entry = manifest["files"][name]
            if (not isinstance(entry, dict) or type(entry.get("bytes")) is not int or
                    entry != _record(data)):
                raise EvidenceUnavailable("fixture evidence digest/size mismatch")
            contents[name] = data
        result = _linked_result(directory, contents, version=version)
        return FixtureEvidence(result, hashlib.sha256(raw).hexdigest(),
                               stdout=contents.get("stdout.bin"), stderr=contents.get("stderr.bin"))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise EvidenceUnavailable("fixture evidence unavailable or malformed") from exc
