"""Bounded one-request TLS collection for Forwarder's narrow HTTP profile."""

from __future__ import annotations

import math
import ssl
import threading
import time

from .forwarder_http import (
    MAX_HEADER_BYTES,
    MAX_REQUEST_LINE_BYTES,
    ParsedRequest,
    parse_request,
    parse_request_head,
)

_SOCKET_MARKER = "_maoi_forwarder_http_receive_claimed"
_SOCKET_CLAIM_LOCK = threading.Lock()
_HEADER_CHUNK = 4_096
_BODY_CHUNK = 65_536


class HTTPReceiveError(ValueError):
    """A fixed, non-diagnostic HTTP collection rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise HTTPReceiveError(code) from None


def _finite(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _clock(previous: float | None = None) -> float:
    try:
        observed = _finite(time.monotonic())
    except Exception:  # noqa: BLE001 - a deadline needs a working monotonic clock.
        _fail("clock_fault")
    if observed is None or (previous is not None and observed < previous):
        _fail("clock_fault")
    return observed


def _remaining(deadline: float, previous: float) -> tuple[float, float]:
    observed = _clock(previous)
    remaining = deadline - observed
    if not math.isfinite(remaining) or remaining <= 0:
        _fail("deadline_expired")
    return remaining, observed


def _claim_and_validate(connection: object) -> ssl.SSLSocket:
    if type(connection) is not ssl.SSLSocket:
        _fail("invalid_connection")
    with _SOCKET_CLAIM_LOCK:
        if getattr(connection, _SOCKET_MARKER, False):
            _fail("connection_claimed")
        setattr(connection, _SOCKET_MARKER, True)
    try:
        if (
            connection.fileno() < 0
            or connection.context.protocol != ssl.PROTOCOL_TLS_SERVER
            or connection.server_side is not True
            or connection.version() not in {"TLSv1.2", "TLSv1.3"}
        ):
            _fail("invalid_connection")
    except HTTPReceiveError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        _fail("invalid_connection")
    return connection


def _read(connection: ssl.SSLSocket, amount: int, deadline: float,
          previous: float) -> tuple[bytes, float]:
    remaining, observed = _remaining(deadline, previous)
    connection.settimeout(remaining)
    try:
        received = connection.recv(amount)
    except (OSError, ssl.SSLError, ValueError, TypeError):
        _fail("receive_failed")
    _unused, observed = _remaining(deadline, observed)
    if type(received) is not bytes or not received or len(received) > amount:
        _fail("receive_failed")
    return received, observed


def _collect_head(connection: ssl.SSLSocket, deadline: float,
                  previous: float) -> tuple[bytes, bytes, float]:
    captured = bytearray()
    line_end = -1
    while line_end < 0:
        remaining_line = MAX_REQUEST_LINE_BYTES - len(captured)
        if remaining_line < 0:
            _fail("receive_failed")
        chunk, previous = _read(
            connection,
            min(_HEADER_CHUNK, remaining_line + 1),
            deadline,
            previous,
        )
        captured.extend(chunk)
        line_end = captured.find(b"\r\n")
        if line_end < 0 and len(captured) > MAX_REQUEST_LINE_BYTES:
            _fail("receive_failed")
    if line_end + 2 > MAX_REQUEST_LINE_BYTES:
        _fail("receive_failed")
    head_end = captured.find(b"\r\n\r\n", line_end + 2)
    while head_end < 0:
        header_length = len(captured) - (line_end + 2)
        remaining_header = MAX_HEADER_BYTES - header_length
        if remaining_header < 0:
            _fail("receive_failed")
        chunk, previous = _read(
            connection,
            min(_HEADER_CHUNK, remaining_header + 1),
            deadline,
            previous,
        )
        captured.extend(chunk)
        head_end = captured.find(b"\r\n\r\n", line_end + 2)
        if head_end < 0 and len(captured) - (line_end + 2) > MAX_HEADER_BYTES:
            _fail("receive_failed")
    end = head_end + 4
    if end - (line_end + 2) > MAX_HEADER_BYTES:
        _fail("receive_failed")
    return bytes(captured[:end]), bytes(captured[end:]), previous


def _receive(connection: ssl.SSLSocket, service: str, *, deadline: float,
            allowed_query_keys: frozenset[str] = frozenset(),
            accept: str = "application/json") -> tuple[ParsedRequest, int]:
    """Collect one bounded request under the caller's absolute handler deadline."""
    secured = _claim_and_validate(connection)
    now = _clock()
    absolute_deadline = _finite(deadline)
    if (
        absolute_deadline is None
        or absolute_deadline <= now
        or absolute_deadline - now > 40
    ):
        _fail("invalid_deadline")
    previous_timeout: float | None = None
    timeout_saved = False
    succeeded = False
    primary_failure = False
    result: ParsedRequest | None = None
    byte_count = 0
    observed = now
    try:
        previous_timeout = secured.gettimeout()
        timeout_saved = True
        head_bytes, body_prefix, observed = _collect_head(secured, absolute_deadline, now)
        head = parse_request_head(
            head_bytes,
            service,
            allowed_query_keys=allowed_query_keys,
            accept=accept,
        )
        if len(body_prefix) > head.body_length:
            _fail("receive_failed")
        captured = bytearray(head_bytes)
        captured.extend(body_prefix)
        body_received = len(body_prefix)
        while body_received < head.body_length:
            remaining_body = head.body_length - body_received
            chunk, observed = _read(
                secured,
                min(_BODY_CHUNK, remaining_body + 1),
                absolute_deadline,
                observed,
            )
            captured.extend(chunk)
            body_received += len(chunk)
            if body_received > head.body_length:
                _fail("receive_failed")
        result = parse_request(
            bytes(captured),
            service,
            allowed_query_keys=allowed_query_keys,
            accept=accept,
        )
        byte_count = len(captured)
        _unused, observed = _remaining(absolute_deadline, observed)
        succeeded = True
    except HTTPReceiveError:
        primary_failure = True
        raise
    except (OSError, ssl.SSLError, ValueError, TypeError):
        primary_failure = True
        _fail("receive_failed")
    except BaseException:
        primary_failure = True
        raise
    finally:
        if timeout_saved:
            try:
                secured.settimeout(previous_timeout)
            except BaseException:  # noqa: BLE001 - never report success after a restore failure.
                if not primary_failure and succeeded:
                    _fail("timeout_restore_failed")
    if result is None:
        _fail("receive_failed")
    _remaining(absolute_deadline, observed)
    return result, byte_count


def receive_request(connection: ssl.SSLSocket, service: str, *, deadline: float,
                    allowed_query_keys: frozenset[str] = frozenset(),
                    accept: str = "application/json") -> ParsedRequest:
    """Collect one bounded request under the caller's absolute handler deadline."""
    return _receive(
        connection,
        service,
        deadline=deadline,
        allowed_query_keys=allowed_query_keys,
        accept=accept,
    )[0]


def receive_request_sized(connection: ssl.SSLSocket, service: str, *, deadline: float,
                          allowed_query_keys: frozenset[str] = frozenset(),
                          accept: str = "application/json") -> tuple[ParsedRequest, int]:
    """Collect one bounded request and also report its exact inbound wire byte count."""
    return _receive(
        connection,
        service,
        deadline=deadline,
        allowed_query_keys=allowed_query_keys,
        accept=accept,
    )
