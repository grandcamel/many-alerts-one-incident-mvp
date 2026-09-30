"""Bounded one-response collection from an established client TLS socket."""

from __future__ import annotations

import math
import ssl
import threading
import time

from .forwarder_http_response import (
    MAX_HEADER_BYTES,
    MAX_STATUS_LINE_BYTES,
    ParsedResponse,
    parse_response,
    parse_response_head,
)

_MARKER = "_maoi_forwarder_response_receive_claimed"
_CLAIM_LOCK = threading.Lock()
_HEADER_CHUNK = 4_096
_BODY_CHUNK = 65_536
_INACTIVITY_LIMIT = 20.0


class ResponseReceiveError(ValueError):
    """Fixed non-diagnostic response collection rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ResponseReceiveError(code) from None


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
    except Exception:  # noqa: BLE001
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
    with _CLAIM_LOCK:
        if getattr(connection, _MARKER, False):
            _fail("connection_claimed")
        setattr(connection, _MARKER, True)
    try:
        if (
            connection.fileno() < 0
            or connection.server_side is not False
            or connection.context.protocol != ssl.PROTOCOL_TLS_CLIENT
            or connection.context.verify_mode != ssl.CERT_REQUIRED
            or connection.context.check_hostname is not True
            or connection.version() not in {"TLSv1.2", "TLSv1.3"}
            or connection.selected_alpn_protocol() not in {None, "http/1.1"}
        ):
            _fail("invalid_connection")
    except ResponseReceiveError:
        raise
    except (OSError, ssl.SSLError, ValueError, TypeError, AttributeError):
        _fail("invalid_connection")
    return connection


def _read(connection: ssl.SSLSocket, amount: int, deadline: float,
          previous: float) -> tuple[bytes, float]:
    remaining, observed = _remaining(deadline, previous)
    read_started = observed
    connection.settimeout(min(_INACTIVITY_LIMIT, remaining))
    try:
        received = connection.recv(amount)
    except (OSError, ssl.SSLError, ValueError, TypeError):
        _fail("receive_failed")
    _unused, observed = _remaining(deadline, observed)
    if observed - read_started >= _INACTIVITY_LIMIT:
        _fail("receive_failed")
    if type(received) is not bytes or not received or len(received) > amount:
        _fail("receive_failed")
    return received, observed


def _collect_head(connection: ssl.SSLSocket, deadline: float,
                  previous: float) -> tuple[bytes, bytes, float]:
    captured = bytearray()
    line_end = -1
    while line_end < 0:
        remaining_line = MAX_STATUS_LINE_BYTES - len(captured)
        if remaining_line < 0:
            _fail("receive_failed")
        chunk, previous = _read(connection, min(_HEADER_CHUNK, remaining_line + 1), deadline, previous)
        captured.extend(chunk)
        line_end = captured.find(b"\r\n")
        if line_end < 0 and len(captured) > MAX_STATUS_LINE_BYTES:
            _fail("receive_failed")
    if line_end + 2 > MAX_STATUS_LINE_BYTES:
        _fail("receive_failed")
    if captured[line_end + 2:line_end + 4] == b"\r\n":
        end = line_end + 4
        return bytes(captured[:end]), bytes(captured[end:]), previous
    head_end = captured.find(b"\r\n\r\n", line_end + 2)
    while head_end < 0:
        used = len(captured) - (line_end + 2)
        remaining_header = MAX_HEADER_BYTES - used
        if remaining_header < 0:
            _fail("receive_failed")
        chunk, previous = _read(
            connection, min(_HEADER_CHUNK, remaining_header + 1), deadline, previous
        )
        captured.extend(chunk)
        if captured[line_end + 2:line_end + 4] == b"\r\n":
            end = line_end + 4
            return bytes(captured[:end]), bytes(captured[end:]), previous
        head_end = captured.find(b"\r\n\r\n", line_end + 2)
        if head_end < 0 and len(captured) - (line_end + 2) > MAX_HEADER_BYTES:
            _fail("receive_failed")
    end = head_end + 4
    if end - (line_end + 2) > MAX_HEADER_BYTES:
        _fail("receive_failed")
    return bytes(captured[:end]), bytes(captured[end:]), previous


def receive_response(connection: ssl.SSLSocket, *, deadline: float) -> ParsedResponse:
    """Collect one bounded response under the caller's absolute deadline."""
    secured = _claim_and_validate(connection)
    now = _clock()
    absolute_deadline = _finite(deadline)
    if absolute_deadline is None or absolute_deadline <= now or absolute_deadline - now > 40:
        _fail("invalid_deadline")
    previous_timeout: float | None = None
    timeout_saved = False
    succeeded = False
    primary_failure = False
    result: ParsedResponse | None = None
    observed = now
    try:
        previous_timeout = secured.gettimeout()
        timeout_saved = True
        head_bytes, body_prefix, observed = _collect_head(secured, absolute_deadline, now)
        head = parse_response_head(head_bytes)
        if len(body_prefix) > head.body_length:
            _fail("receive_failed")
        captured = bytearray(head_bytes)
        captured.extend(body_prefix)
        body_received = len(body_prefix)
        while body_received < head.body_length:
            remaining_body = head.body_length - body_received
            chunk, observed = _read(
                secured, min(_BODY_CHUNK, remaining_body + 1), absolute_deadline, observed
            )
            captured.extend(chunk)
            body_received += len(chunk)
            if body_received > head.body_length:
                _fail("receive_failed")
        result = parse_response(bytes(captured))
        _unused, observed = _remaining(absolute_deadline, observed)
        succeeded = True
    except ResponseReceiveError:
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
            except BaseException:  # noqa: BLE001
                if not primary_failure and succeeded:
                    _fail("timeout_restore_failed")
    if result is None:
        _fail("receive_failed")
    _remaining(absolute_deadline, observed)
    return result
