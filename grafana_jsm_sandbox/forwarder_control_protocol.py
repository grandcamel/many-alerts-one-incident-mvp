"""Bounded JSON frames for the authenticated Forwarder control socket.

The control session owns authentication and command semantics.  This module only
serializes one deliberately small, self-contained frame at a time.  Exactly one
opaque attachment kind, a Receiver scope manifest, may follow a schema-valid gated
registration header, and its length is declared twice and must match.
"""

from __future__ import annotations

import json
import math
import socket
import struct
import time
from collections.abc import Mapping
from typing import Any

MAX_FRAME_BYTES = 8192
FRAME_TIMEOUT_SECONDS = 10.0
MAX_ATTACHMENT_BYTES = 16_384

_MAX_OBJECT_DEPTH = 4
_MAX_KEY_BYTES = 64
_MAX_STRING_BYTES = 512
_MIN_SIGNED_64 = -(2**63)
_MAX_SIGNED_64 = 2**63 - 1


class ControlProtocolError(ValueError):
    """A fixed, non-diagnostic protocol rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _ParseFailure(Exception):
    def __init__(self, code: str):
        self.code = code


def recv_frame(sock: socket.socket, *, timeout: float = FRAME_TIMEOUT_SECONDS) -> dict:
    """Receive and validate exactly one length-prefixed JSON object."""
    deadline = _deadline(timeout)
    previous_timeout = _socket_timeout(sock)
    try:
        header = _recv_exact(sock, 4, deadline, allow_clean_eof=True)
        if header is None:
            raise ControlProtocolError("eof")
        length = struct.unpack("!I", header)[0]
        if length == 0:
            raise ControlProtocolError("invalid_length")
        if length > MAX_FRAME_BYTES:
            raise ControlProtocolError("oversize_frame")
        body = _recv_exact(sock, length, deadline, allow_clean_eof=False)
        _check_deadline(deadline)
        payload = _decode_payload(body)
        _check_deadline(deadline)
        return payload
    finally:
        _restore_timeout(sock, previous_timeout)


def send_frame(sock: socket.socket, payload: dict, *, timeout: float = FRAME_TIMEOUT_SECONDS) -> None:
    """Validate and send one length-prefixed JSON object before the deadline."""
    _validate_payload(payload)
    try:
        body = json.dumps(
            payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeEncodeError):
        raise ControlProtocolError("invalid_payload") from None
    if len(body) > MAX_FRAME_BYTES:
        raise ControlProtocolError("oversize_frame")

    deadline = _deadline(timeout)
    previous_timeout = _socket_timeout(sock)
    try:
        _send_exact(sock, struct.pack("!I", len(body)) + body, deadline)
        _check_deadline(deadline)
    finally:
        _restore_timeout(sock, previous_timeout)


def send_attachment(
    sock: socket.socket, data: bytes, *, timeout: float = FRAME_TIMEOUT_SECONDS
) -> None:
    """Send one length-prefixed opaque attachment before the deadline."""
    if type(data) is not bytes or len(data) == 0:
        raise ControlProtocolError("invalid_payload")
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise ControlProtocolError("oversize_frame")

    deadline = _deadline(timeout)
    previous_timeout = _socket_timeout(sock)
    try:
        _send_exact(sock, struct.pack("!I", len(data)) + data, deadline)
        _check_deadline(deadline)
    finally:
        _restore_timeout(sock, previous_timeout)


def recv_attachment(
    sock: socket.socket, *, length: int, timeout: float = FRAME_TIMEOUT_SECONDS
) -> bytes:
    """Receive exactly one length-prefixed opaque attachment before the deadline."""
    if type(length) is not int or not 1 <= length <= MAX_ATTACHMENT_BYTES:
        raise ControlProtocolError("invalid_attachment_length")

    deadline = _deadline(timeout)
    previous_timeout = _socket_timeout(sock)
    try:
        header = _recv_exact(sock, 4, deadline, allow_clean_eof=False)
        declared = struct.unpack("!I", header)[0]
        if declared == 0:
            raise ControlProtocolError("invalid_length")
        if declared > MAX_ATTACHMENT_BYTES:
            raise ControlProtocolError("oversize_frame")
        if declared != length:
            raise ControlProtocolError("attachment_mismatch")
        body = _recv_exact(sock, length, deadline, allow_clean_eof=False)
        _check_deadline(deadline)
        return body
    finally:
        _restore_timeout(sock, previous_timeout)


def _deadline(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ControlProtocolError("invalid_timeout")
    try:
        seconds = float(timeout)
    except OverflowError:
        raise ControlProtocolError("invalid_timeout") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise ControlProtocolError("invalid_timeout")
    deadline = time.monotonic() + seconds
    if not math.isfinite(deadline):
        raise ControlProtocolError("invalid_timeout")
    return deadline


def _socket_timeout(sock: socket.socket) -> float | None:
    try:
        return sock.gettimeout()
    except (AttributeError, OSError):
        raise ControlProtocolError("socket_failure") from None


def _restore_timeout(sock: socket.socket, previous_timeout: float | None) -> None:
    try:
        sock.settimeout(previous_timeout)
    except (AttributeError, OSError):
        # A completed operation remains completed even if an already-closed peer
        # prevents restoring its local timeout setting.
        pass


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ControlProtocolError("timeout")
    return remaining


def _check_deadline(deadline: float) -> None:
    _remaining(deadline)


def _recv_exact(
    sock: socket.socket, size: int, deadline: float, *, allow_clean_eof: bool
) -> bytes | None:
    chunks: list[bytes] = []
    received = 0
    while received < size:
        try:
            sock.settimeout(_remaining(deadline))
            chunk = sock.recv(size - received)
        except TimeoutError:
            raise ControlProtocolError("timeout") from None
        except (AttributeError, OSError):
            raise ControlProtocolError("read_failure") from None
        if not chunk:
            if received == 0 and allow_clean_eof:
                return None
            raise ControlProtocolError("truncated_frame")
        chunks.append(chunk)
        received += len(chunk)
    _check_deadline(deadline)
    return b"".join(chunks)


def _send_exact(sock: socket.socket, data: bytes, deadline: float) -> None:
    sent = 0
    while sent < len(data):
        try:
            sock.settimeout(_remaining(deadline))
            count = sock.send(data[sent:])
        except TimeoutError:
            raise ControlProtocolError("timeout") from None
        except (AttributeError, OSError):
            raise ControlProtocolError("write_failure") from None
        if not isinstance(count, int) or count <= 0:
            raise ControlProtocolError("write_failure")
        sent += count
    _check_deadline(deadline)


def _decode_payload(body: bytes) -> dict:
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ControlProtocolError("invalid_utf8") from None
    try:
        payload = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_int=_parse_signed_64,
            parse_constant=_reject_nonfinite,
        )
    except _ParseFailure as error:
        raise ControlProtocolError(error.code) from None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError, MemoryError):
        raise ControlProtocolError("invalid_json") from None
    _validate_payload(payload)
    return payload


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ParseFailure("duplicate_key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise _ParseFailure("nonfinite_number")


def _parse_signed_64(value: str) -> int:
    negative = value.startswith("-")
    digits = value[1:] if negative else value
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > len(limit) or (len(digits) == len(limit) and digits > limit):
        raise _ParseFailure("integer_out_of_range")
    return int(value)


def _validate_payload(payload: Any) -> None:
    try:
        if not isinstance(payload, Mapping):
            raise ControlProtocolError("invalid_root")
        _validate_object(payload, 1)
    except RecursionError:
        raise ControlProtocolError("invalid_payload") from None


def _validate_object(payload: Mapping[Any, Any], depth: int) -> None:
    if depth > _MAX_OBJECT_DEPTH:
        raise ControlProtocolError("nesting_limit")
    for key, value in payload.items():
        if not isinstance(key, str):
            raise ControlProtocolError("invalid_key")
        try:
            key_bytes = key.encode("ascii")
        except UnicodeEncodeError:
            raise ControlProtocolError("invalid_key") from None
        if len(key_bytes) > _MAX_KEY_BYTES:
            raise ControlProtocolError("invalid_key")
        _validate_value(value, depth)


def _validate_value(value: Any, depth: int) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value_bytes = value.encode("utf-8")
        except UnicodeEncodeError:
            raise ControlProtocolError("invalid_value") from None
        if len(value_bytes) > _MAX_STRING_BYTES:
            raise ControlProtocolError("string_too_long")
        return
    if isinstance(value, int):
        if value < _MIN_SIGNED_64 or value > _MAX_SIGNED_64:
            raise ControlProtocolError("integer_out_of_range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ControlProtocolError("nonfinite_number")
        return
    if isinstance(value, Mapping):
        _validate_object(value, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        raise ControlProtocolError("arrays_not_allowed")
    raise ControlProtocolError("invalid_value")
