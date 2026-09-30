"""Closed stdlib child for the supervised synthetic TLS streaming fixture.

It accepts only a fixed scenario and a parent-created private bootstrap file in
its current directory. It is not a native client or general HTTP launcher.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import signal
import ssl
import stat
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

STREAM_SCENARIOS = frozenset({
    "stream_complete",
    "stream_truncate",
    "stream_duplicate_terminal",
    "stream_wait",
    "stream_child_failure",
    "stream_missing_receipt",
    "stream_bad_ack",
    "stream_duplicate_ack",
    "stream_bad_receipt",
})

_REQUEST = b'{"fixture":"mediated-client-v1"}'
_DELTA = b'data: {"sequence":1,"text":"h\xc3\xa9llo","type":"fixture_delta"}\n\n'
_TERMINAL = b'data: {"sequence":2,"stop_reason":"fixture_complete","type":"fixture_terminal"}\n\n'
_BOOTSTRAP = "stream-bootstrap.json"
_MAX_BOOTSTRAP = 12 * 1024
_MAX_WORKER = 64 * 1024
_MAX_RESPONSE = 16 * 1024
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _emit(value: dict[str, object]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)


def _assistant(content: dict[str, object]) -> None:
    _emit({"type": "assistant", "message": {"model": "fixture-only", "content": [content]}})


def _result(error: bool) -> None:
    _emit({"type": "result", "subtype": "error" if error else "success", "is_error": error})


def _bootstrap(directory: Path) -> tuple[dict[str, object], bytes]:
    path = directory / _BOOTSTRAP
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BOOTSTRAP:
            raise ValueError("invalid bootstrap file")
        raw = os.read(fd, _MAX_BOOTSTRAP + 1)
        if len(raw) != info.st_size or len(raw) > _MAX_BOOTSTRAP:
            raise ValueError("oversized bootstrap")
    finally:
        os.close(fd)
    value = json.loads(raw, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if not isinstance(value, dict) or set(value) != {
        "attempt_id", "ca_pem", "endpoint", "lease_id", "scenario", "token", "version", "worker_sha256",
    }:
        raise ValueError("unsupported bootstrap")
    if type(value["version"]) is not int or value["version"] != 1 or not all(
            isinstance(value[key], str) for key in value if key != "version"):
        raise ValueError("invalid bootstrap values")
    if not _SAFE.fullmatch(value["attempt_id"]) or not _TOKEN.fullmatch(value["lease_id"]):
        raise ValueError("invalid bootstrap identity")
    if not _TOKEN.fullmatch(value["token"]) or not _HEX.fullmatch(value["worker_sha256"]):
        raise ValueError("invalid bootstrap secret or digest")
    if value["scenario"] not in STREAM_SCENARIOS or len(value["ca_pem"].encode("utf-8")) > 8192:
        raise ValueError("invalid bootstrap scope")
    target = urlsplit(value["endpoint"])
    if (target.scheme != "https" or target.hostname != "127.0.0.1" or target.port is None or
            not 1 <= target.port <= 65535 or target.path != "/v1/messages" or target.query or
            target.fragment or target.username is not None or target.password is not None):
        raise ValueError("invalid bootstrap endpoint")
    return value, raw


def _worker_bytes() -> bytes:
    fd = os.open(Path(__file__), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_WORKER:
            raise ValueError("invalid worker snapshot")
        data = os.read(fd, _MAX_WORKER + 1)
        if len(data) != info.st_size or len(data) > _MAX_WORKER:
            raise ValueError("worker snapshot changed")
        return data
    finally:
        os.close(fd)


def _decode_delta(data: bytes) -> None:
    if data != _DELTA:
        raise ValueError("first fixture frame mismatch")
    record = json.loads(data[6:-2].decode("utf-8"), object_pairs_hook=_unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if record != {"sequence": 1, "text": "héllo", "type": "fixture_delta"}:
        raise ValueError("first fixture frame schema mismatch")


def _decode_terminal(data: bytes) -> None:
    if data != _TERMINAL:
        raise ValueError("fixture terminal mismatch")
    record = json.loads(data[6:-2].decode("utf-8"), object_pairs_hook=_unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if record != {"sequence": 2, "stop_reason": "fixture_complete", "type": "fixture_terminal"}:
        raise ValueError("fixture terminal schema mismatch")


def _ack(config: dict[str, object], bootstrap: bytes) -> dict[str, object]:
    return {
        "type": "fixture_stream_ack",
        "version": 1,
        "attempt_id": config["attempt_id"],
        "lease_id": config["lease_id"],
        "sequence": 1,
        "frame_bytes": len(_DELTA),
        "frame_sha256": hashlib.sha256(_DELTA).hexdigest(),
        "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
    }


def _receipt(config: dict[str, object], bootstrap: bytes, *, terminal: bool, eof: bool,
             response: bytes, reason: str) -> dict[str, object]:
    return {
        "type": "fixture_stream_receipt",
        "version": 1,
        "attempt_id": config["attempt_id"],
        "lease_id": config["lease_id"],
        "sequence": 1,
        "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
        "stream_bytes": len(response),
        "stream_sha256": hashlib.sha256(response).hexdigest(),
        "validated_frames": 2 if terminal else 1,
        "terminal_observed": terminal,
        "transport_eof": eof,
        "reason": reason,
    }


def main(scenario: str, directory: Path) -> int:
    # The parent supplies a fixed, deliberately small environment.  A caller
    # cannot use this child as an environment/configuration carrier.
    allowed_environment = {"HOME", "TMPDIR", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    if set(os.environ) - allowed_environment:
        return 91
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    _assistant({"type": "fixture_stream_init", "version": 1})
    try:
        if scenario not in STREAM_SCENARIOS:
            raise ValueError("unsupported stream scenario")
        config, bootstrap = _bootstrap(directory)
        if config["scenario"] != scenario or config["attempt_id"] != directory.name:
            raise ValueError("bootstrap scenario mismatch")
        if hashlib.sha256(_worker_bytes()).hexdigest() != config["worker_sha256"]:
            raise ValueError("worker snapshot mismatch")
        context = ssl.create_default_context(cadata=config["ca_pem"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        target = urlsplit(config["endpoint"])
        connection = http.client.HTTPSConnection(target.hostname, target.port, context=context, timeout=2)
        try:
            connection.request("POST", target.path, body=_REQUEST, headers={
                "Authorization": "Bearer " + config["token"],
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            headers = response.getheaders()
            types = [value for name, value in headers if name.lower() == "content-type"]
            lengths = [value for name, value in headers if name.lower() == "content-length"]
            transfer = [value for name, value in headers if name.lower() == "transfer-encoding"]
            connections = [value for name, value in headers if name.lower() == "connection"]
            if (response.status != 200 or types != ["text/event-stream"] or len(lengths) != 1 or
                    transfer or connections != ["close"] or not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]) or
                    len(lengths[0]) > len(str(_MAX_RESPONSE))):
                raise ValueError("fixture response framing")
            declared = int(lengths[0])
            if declared > _MAX_RESPONSE:
                raise ValueError("fixture response oversize")
            source = response.fp
            if source is None:
                raise ValueError("fixture response missing")
            first = source.read(len(_DELTA))
            _decode_delta(first)
            ack = _ack(config, bootstrap)
            if scenario == "stream_bad_ack":
                ack["frame_sha256"] = "0" * 64
            _assistant(ack)
            if scenario == "stream_duplicate_ack":
                _assistant(ack)
            if scenario == "stream_wait":
                while True:
                    time.sleep(0.05)
            if scenario == "stream_bad_ack":
                _result(True)
                return 1
            full_parts = [first]
            terminal = eof = False
            try:
                remaining = declared - len(first)
                if remaining < 0:
                    raise ValueError("fixture declared length")
                while remaining:
                    part = source.read(min(512, remaining))
                    if not part:
                        raise ValueError("fixture truncated")
                    remaining -= len(part)
                    full_parts.append(part)
                tail = b"".join(full_parts[1:])
                _decode_terminal(tail)
                terminal = True
                extra = source.read(1)
                if extra:
                    full_parts.append(extra)
                    raise ValueError("fixture trailing bytes")
                eof = True
                reason = "complete"
            except (http.client.HTTPException, OSError, ValueError, UnicodeError):
                reason = "stream_invalid"
            full = b"".join(full_parts)
            receipt = _receipt(config, bootstrap, terminal=terminal, eof=eof, response=full, reason=reason)
            if scenario == "stream_bad_receipt":
                receipt["stream_sha256"] = "0" * 64
            if scenario != "stream_missing_receipt":
                _assistant(receipt)
            failed = not terminal or not eof or scenario == "stream_bad_receipt"
            # This deliberate non-zero exit follows a syntactically successful
            # child result, so parent process evidence remains authoritative.
            _result(False if scenario == "stream_child_failure" else failed)
            return 7 if scenario == "stream_child_failure" else int(failed)
        finally:
            connection.close()
    except Exception:  # noqa: BLE001 - one fixture terminal is retained for every worker failure.
        _result(True)
        return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(92)
    raise SystemExit(main(sys.argv[1], Path(__file__).absolute().parent))
