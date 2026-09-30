"""Fixed, synthetic incremental TLS stream fixture.

The buffered :mod:`prototype.mediated_client.harness` contract remains separate.
This subclass uses its fixed route, lease, TLS, nonce, deadline, and loopback
upstream seams but only accepts finite built-in fixture stream scripts.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from typing import Any

from .certificates import FixtureCertificates
from .harness import (
    FIXTURE_REQUEST,
    MediatedClientHarness,
    RequestReceipt,
    _ConnectionDeadline,
    _Inbound,
    _Lease,
)

STREAM_FIXTURE_DELTA = b'data: {"sequence":1,"text":"h\xc3\xa9llo","type":"fixture_delta"}\n\n'
"""The first fixed synthetic data frame; its UTF-8 ``é`` is split in one mode."""

STREAM_FIXTURE_TERMINAL = (
    b'data: {"sequence":2,"stop_reason":"fixture_complete","type":"fixture_terminal"}\n\n'
)
"""The one fixed successful terminal frame."""

STREAM_FIXTURE_RESPONSE = STREAM_FIXTURE_DELTA + STREAM_FIXTURE_TERMINAL
"""The exact successful stream body, framed with finite Content-Length."""

_STREAM_MODES = frozenset({
    "complete",
    "split_utf8",
    "malformed_utf8",
    "duplicate_key",
    "unknown_kind",
    "nonfinite",
    "oversize",
    "deep",
    "event_limit",
    "missing_terminal",
    "duplicate_terminal",
    "conflicting_terminal",
    "trailing",
    "trailing_after_length",
    "truncate",
    "disconnect",
    "timeout",
    "surrogate",
    "out_of_order",
    "total_oversize",
})
_MAX_STREAM_EVENTS = 8
_MAX_STREAM_FRAME_BYTES = 2048
_MAX_STREAM_BYTES = 16384
_MAX_STREAM_NESTING = 8
_MAX_STREAM_HISTORY = 128
_READ_BYTES = 512


@dataclass(frozen=True)
class StreamReceipt:
    """Metadata-only local delivery record for one synthetic stream attempt."""

    sequence: int
    lease_id: str | None
    disposition: str
    reason: str
    upstream_attempted: bool
    validated_frame_count: int
    validated_bytes: int
    forwarded_frame_count: int
    forwarded_bytes: int
    stream_sha256: str
    bytes_may_have_crossed: bool
    terminal_observed: bool
    transport_complete: bool


@dataclass
class _Evidence:
    sequence: int
    lease_id: str | None
    upstream_attempted: bool = False
    validated_frame_count: int = 0
    validated_bytes: int = 0
    forwarded_frame_count: int = 0
    forwarded_bytes: int = 0
    bytes_may_have_crossed: bool = False
    terminal_observed: bool = False
    transport_complete: bool = False
    headers_started: bool = False
    _digest: Any = None

    def __post_init__(self) -> None:
        self._digest = hashlib.sha256()

    def observe(self, value: bytes) -> None:
        self._digest.update(value)

    def receipt(self, disposition: str, reason: str) -> StreamReceipt:
        return StreamReceipt(
            self.sequence,
            self.lease_id,
            disposition,
            reason,
            self.upstream_attempted,
            self.validated_frame_count,
            self.validated_bytes,
            self.forwarded_frame_count,
            self.forwarded_bytes,
            self._digest.hexdigest(),
            self.bytes_may_have_crossed,
            self.terminal_observed,
            self.transport_complete,
        )


@dataclass(frozen=True)
class _Frame:
    raw: bytes
    kind: str
    terminal_reason: str | None = None
    sequence: int = 0


class _StreamError(ValueError):
    pass


class IncrementalStreamHarness(MediatedClientHarness):
    """Two-hop fixed stream fixture with a controller-held final terminal frame.

    ``wait_for_first_frame_forwarded`` only observes the mediator's bounded local
    write. A separate client must decode the frame before the controller releases
    the terminal; this fixture does not pretend to receive a production client ACK.
    """

    def __init__(
        self,
        certificates: FixtureCertificates,
        *,
        stream_mode: str = "complete",
        server_certificate: str = "valid",
        upstream_certificate: str = "valid",
        max_request_bytes: int = 4096,
        max_response_bytes: int = 8192,
        timeout_seconds: float = 0.5,
    ):
        if stream_mode not in _STREAM_MODES:
            raise ValueError("unsupported synthetic stream mode")
        super().__init__(
            certificates,
            upstream_mode="ok",
            server_certificate=server_certificate,
            upstream_certificate=upstream_certificate,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
            timeout_seconds=timeout_seconds,
        )
        self._stream_mode = stream_mode
        self._stream_receipts: list[StreamReceipt] = []
        self._first_frame_forwarded = threading.Event()
        self._release_final_frame = threading.Event()
        self._stream_abort = threading.Event()

    @property
    def stream_receipts(self) -> tuple[StreamReceipt, ...]:
        with self._lock:
            return tuple(self._stream_receipts)

    def wait_for_first_frame_forwarded(self, timeout_seconds: float = 1.0) -> bool:
        """Wait for the mediator's first-frame write, never a client acknowledgement."""
        timeout = self._validated_wait(timeout_seconds)
        return self._first_frame_forwarded.wait(timeout)

    def release_final_frame(self) -> None:
        """Permit the fixed upstream to produce its final portion once."""
        if self._stream_abort.is_set():
            raise RuntimeError("stream fixture is stopping or downstream disconnected")
        self._release_final_frame.set()

    def stop(self) -> None:
        self._stream_abort.set()
        self._release_final_frame.set()
        super().stop()

    @staticmethod
    def _validated_wait(value: float) -> float:
        try:
            parsed = float(value)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError("barrier timeout must be finite, positive, and no greater than 2 seconds") from exc
        if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                not math.isfinite(parsed) or not 0 < parsed <= 2):
            raise ValueError("barrier timeout must be finite, positive, and no greater than 2 seconds")
        return parsed

    def _mediator_handler(self) -> type[BaseHTTPRequestHandler]:
        fixture = self

        class StreamingMediatorHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                deadline = self.server.connection_deadline(self.connection)
                fixture._receive_stream(self, deadline)

            def do_GET(self) -> None:
                deadline = self.server.connection_deadline(self.connection)
                fixture._receive_stream(self, deadline)

            do_PUT = do_DELETE = do_PATCH = do_GET
            do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = do_GET

            def log_message(self, format: str, *args: object) -> None:
                pass

        return StreamingMediatorHandler

    def _upstream_handler(self) -> type[BaseHTTPRequestHandler]:
        fixture = self

        class StreamingUpstreamHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                lengths = self.headers.get_all("Content-Length") or []
                if (self.path != "/v1/messages" or len(lengths) != 1 or
                        not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]) or
                        len(lengths[0]) > len(str(fixture._max_request_bytes))):
                    fixture._respond(self, 400, b"")
                    return
                size = int(lengths[0])
                if size > fixture._max_request_bytes:
                    fixture._respond(self, 413, b"")
                    return
                try:
                    body = self.rfile.read(size)
                except (OSError, TimeoutError):
                    fixture._respond(self, 400, b"")
                    return
                if (len(body) != size or body != FIXTURE_REQUEST or
                        self.headers.get_all("Content-Type") != ["application/json"]):
                    fixture._respond(self, 400, b"")
                    return
                assert fixture._upstream_server is not None
                expected_host = f"127.0.0.1:{fixture._upstream_server.server_address[1]}"
                if (self.headers.get_all("Host") != [expected_host] or
                        self.headers.get_all("X-Api-Key") != ["fixture-upstream-key"] or
                        self.headers.get_all("Authorization")):
                    fixture._respond(self, 401, b"")
                    return
                if not fixture._capture_upstream(self.headers, body):
                    fixture._respond(self, 401, b"")
                    return
                deadline = self.server.connection_deadline(self.connection)
                fixture._serve_stream_script(self, deadline)

            do_GET = do_PUT = do_DELETE = do_PATCH = do_POST

            def log_message(self, format: str, *args: object) -> None:
                pass

        return StreamingUpstreamHandler

    def _receive_stream(self, handler: BaseHTTPRequestHandler,
                        deadline: _ConnectionDeadline | None) -> None:
        with self._lock:
            sequence = self._next_sequence()
            if sequence is None:
                self._respond(handler, 429, b"fixture request limit")
                return
            checked = self._validate_request(handler, sequence)
            if isinstance(checked, _Inbound):
                self._append_receipt(sequence, checked)
                self._record_stream(_Evidence(sequence, checked.lease_id), checked.disposition, checked.reason)
                self._respond(handler, checked.status, checked.body)
                return
            lease, body = checked
            if self._stream_abort.is_set():
                aborted = self._deny("stream_aborted", lease.grant.lease_id, len(body))
                self._append_receipt(sequence, aborted)
                self._record_stream(_Evidence(sequence, aborted.lease_id), aborted.disposition, aborted.reason)
                self._respond(handler, aborted.status, aborted.body)
                return
        evidence = _Evidence(sequence, lease.grant.lease_id)
        if deadline is None or self._deadline_expired(deadline):
            self._finish_preheader(handler, lease, body, evidence, 504, "connection_deadline", False)
            return
        outcome = self._stream_upstream(handler, lease, body, deadline, evidence)
        if outcome is not None:
            status, reason, upstream_attempted = outcome
            self._finish_preheader(handler, lease, body, evidence, status, reason, upstream_attempted)

    def _finish_preheader(self, handler: BaseHTTPRequestHandler, lease: _Lease,
                          body: bytes, evidence: _Evidence, status: int, reason: str,
                          upstream_attempted: bool) -> None:
        disposition = "upstream_unknown" if upstream_attempted else "denied"
        if disposition == "upstream_unknown":
            with self._lock:
                lease.state = "REVOKED"
        inbound = _Inbound(status, b"", lease.grant.lease_id, disposition, reason, len(body),
                           upstream_attempted)
        with self._lock:
            self._append_receipt(evidence.sequence, inbound)
        self._record_stream(evidence, disposition, reason)
        self._respond(handler, status, b"")

    def _record_stream(self, evidence: _Evidence, disposition: str, reason: str) -> None:
        with self._lock:
            if len(self._stream_receipts) >= _MAX_STREAM_HISTORY:
                raise RuntimeError("stream receipt history exceeded fixture request bound")
            self._stream_receipts.append(evidence.receipt(disposition, reason))

    def _serve_stream_script(self, handler: BaseHTTPRequestHandler,
                             deadline: _ConnectionDeadline | None) -> None:
        if self._stream_mode == "disconnect":
            handler.close_connection = True
            return
        if self._stream_mode == "timeout":
            time.sleep(self._timeout_seconds + 0.05)
            handler.close_connection = True
            return
        declared, first_parts, final_parts, extra = self._stream_script()
        try:
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Content-Length", str(len(declared)))
            handler.send_header("Connection", "close")
            handler.end_headers()
            for part in first_parts:
                handler.wfile.write(part)
                handler.wfile.flush()
            if final_parts:
                if not self._wait_for_final_release(deadline):
                    handler.close_connection = True
                    return
                for part in final_parts:
                    handler.wfile.write(part)
                    handler.wfile.flush()
            if extra:
                handler.wfile.write(extra)
                handler.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError, TimeoutError):
            self._stream_abort.set()
        finally:
            handler.close_connection = True

    def _wait_for_final_release(self, deadline: _ConnectionDeadline | None) -> bool:
        while not self._release_final_frame.is_set():
            if self._stream_abort.is_set() or deadline is None or self._deadline_expired(deadline):
                return False
            remaining = deadline.expires_at - time.monotonic()
            if remaining <= 0:
                return False
            self._release_final_frame.wait(min(0.02, remaining))
        return not self._stream_abort.is_set()

    def _stream_script(self) -> tuple[bytes, tuple[bytes, ...], tuple[bytes, ...], bytes]:
        delta = STREAM_FIXTURE_DELTA
        terminal = STREAM_FIXTURE_TERMINAL
        mode = self._stream_mode
        if mode == "split_utf8":
            split = delta.index(b"\xc3") + 1
            return delta + terminal, (delta[:split], delta[split:]), (terminal,), b""
        if mode == "malformed_utf8":
            invalid = b'data: {"sequence":2,"stop_reason":"\xff","type":"fixture_terminal"}\n\n'
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "duplicate_key":
            invalid = b'data: {"sequence":2,"stop_reason":"fixture_complete","type":"fixture_terminal","type":"fixture_terminal"}\n\n'
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "unknown_kind":
            invalid = b'data: {"sequence":2,"type":"fixture_unknown"}\n\n'
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "nonfinite":
            invalid = b'data: {"sequence":2,"stop_reason":NaN,"type":"fixture_terminal"}\n\n'
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "oversize":
            invalid = b"data: " + b"x" * (_MAX_STREAM_FRAME_BYTES + 1) + b"\n\n"
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "deep":
            nested = b"[" * (_MAX_STREAM_NESTING + 1) + b"0" + b"]" * (_MAX_STREAM_NESTING + 1)
            invalid = b'data: {"meta":' + nested + b',"sequence":2,"stop_reason":"fixture_complete","type":"fixture_terminal"}\n\n'
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "event_limit":
            deltas = tuple(
                b'data: {"sequence":' + str(index).encode("ascii") +
                b',"text":"more","type":"fixture_delta"}\n\n'
                for index in range(2, _MAX_STREAM_EVENTS + 2)
            )
            declared = delta + b"".join(deltas) + terminal
            return declared, (delta,), deltas + (terminal,), b""
        if mode == "missing_terminal":
            return delta, (delta,), (b"",), b""
        if mode == "duplicate_terminal":
            duplicate = b'data: {"sequence":3,"stop_reason":"fixture_complete","type":"fixture_terminal"}\n\n'
            return delta + terminal + duplicate, (delta,), (terminal, duplicate), b""
        if mode == "conflicting_terminal":
            conflicting = b'data: {"sequence":3,"stop_reason":"fixture_abort","type":"fixture_terminal"}\n\n'
            return delta + terminal + conflicting, (delta,), (terminal, conflicting), b""
        if mode == "trailing":
            return delta + terminal + b"x", (delta,), (terminal + b"x",), b""
        if mode == "trailing_after_length":
            return delta + terminal, (delta,), (terminal,), b"x"
        if mode == "truncate":
            partial = terminal[:-5]
            return delta + terminal, (delta,), (partial,), b""
        if mode == "surrogate":
            invalid = b'data: {"sequence":2,"text":"\\ud800","type":"fixture_delta"}\n\n'
            return delta + invalid, (delta,), (invalid,), b""
        if mode == "out_of_order":
            invalid = b'data: {"sequence":3,"text":"late","type":"fixture_delta"}\n\n'
            return delta + invalid + terminal, (delta,), (invalid + terminal,), b""
        if mode == "total_oversize":
            tail = b"x" * (_MAX_STREAM_BYTES + 1)
            return delta + tail, (delta,), (tail,), b""
        return delta + terminal, (delta,), (terminal,), b""

    def _stream_upstream(self, handler: BaseHTTPRequestHandler, lease: _Lease, body: bytes,
                         deadline: _ConnectionDeadline, evidence: _Evidence) -> tuple[int, str, bool] | None:
        assert self._upstream_server is not None
        with self._upstream_receipt_lock:
            dispatch = self._fresh_secret(self._pending_dispatches)
            self._pending_dispatches[dispatch] = evidence.sequence
        socket_lock = threading.Lock()
        socket_state: dict[str, socket.socket | None] = {"socket": None}

        def close_outbound() -> None:
            with socket_lock:
                target = socket_state["socket"]
            if target is not None:
                try:
                    target.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    target.close()
                except OSError:
                    pass

        upstream_socket: socket.socket | None = None
        response: http.client.HTTPResponse | None = None
        timer: threading.Timer | None = None
        try:
            remaining = deadline.expires_at - time.monotonic()
            if deadline.expired.is_set() or remaining <= 0:
                return 504, "connection_deadline", False
            timer = threading.Timer(remaining, close_outbound)
            timer.daemon = True
            timer.start()
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with socket_lock:
                socket_state["socket"] = upstream_socket
            self._set_outbound_timeout(upstream_socket, deadline)
            upstream_socket.connect(("127.0.0.1", self._upstream_server.server_address[1]))
            upstream_socket = self._client_context().wrap_socket(upstream_socket, server_hostname="127.0.0.1")
            with socket_lock:
                socket_state["socket"] = upstream_socket
            self._set_outbound_timeout(upstream_socket, deadline)
            request = self._upstream_request(body, evidence.sequence, dispatch)
            with self._lock:
                self._ensure_deadline(deadline)
                if self._expired(lease):
                    lease.state = "EXPIRED"
                    return 401, "expired", False
                if lease.state != "ACTIVE":
                    return 401, "revoked", False
                evidence.upstream_attempted = True
                upstream_socket.sendall(request)
            response = http.client.HTTPResponse(upstream_socket)
            response.begin()
            declared = self._validate_stream_headers(response)
            if declared > min(self._max_response_bytes, _MAX_STREAM_BYTES):
                return 502, "response_oversize", True
            return self._consume_stream_body(
                handler, response, declared, lease, body, deadline, evidence
            )
        except _StreamError as exc:
            if evidence.headers_started:
                self._close_partial(handler, lease, body, evidence, str(exc))
                return None
            return 502, str(exc), evidence.upstream_attempted
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            if evidence.headers_started:
                self._close_partial(handler, lease, body, evidence, "upstream_failure")
                return None
            return 502, "upstream_failure", evidence.upstream_attempted
        finally:
            if timer is not None:
                timer.cancel()
            if response is not None:
                try:
                    response.close()
                except OSError:
                    pass
            if upstream_socket is not None:
                try:
                    upstream_socket.close()
                except OSError:
                    pass
            with self._upstream_receipt_lock:
                self._pending_dispatches.pop(dispatch, None)

    def _set_outbound_timeout(self, sock: socket.socket, deadline: _ConnectionDeadline) -> None:
        remaining = deadline.expires_at - time.monotonic()
        if deadline.expired.is_set() or remaining <= 0:
            raise TimeoutError("connection deadline")
        sock.settimeout(min(self._timeout_seconds, remaining))

    def _upstream_request(self, body: bytes, sequence: int, dispatch: str) -> bytes:
        assert self._upstream_server is not None
        return (
            f"POST /v1/messages HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self._upstream_server.server_address[1]}\r\n"
            "Content-Type: application/json\r\n"
            "X-Api-Key: fixture-upstream-key\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Fixture-Sequence: {sequence}\r\n"
            f"X-Fixture-Dispatch: {dispatch}\r\n\r\n"
        ).encode("ascii") + body

    def _validate_stream_headers(self, response: http.client.HTTPResponse) -> int:
        headers = response.getheaders()
        content_types = [value for name, value in headers if name.lower() == "content-type"]
        lengths = [value for name, value in headers if name.lower() == "content-length"]
        transfer_encodings = [value for name, value in headers if name.lower() == "transfer-encoding"]
        connections = [value for name, value in headers if name.lower() == "connection"]
        if (response.status != 200 or len(content_types) != 1 or
                content_types[0] != "text/event-stream" or len(lengths) != 1 or
                transfer_encodings or connections != ["close"] or
                not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]) or
                len(lengths[0]) > len(str(min(self._max_response_bytes, _MAX_STREAM_BYTES)))):
            raise _StreamError("response_framing")
        return int(lengths[0])

    def _consume_stream_body(self, handler: BaseHTTPRequestHandler, response: http.client.HTTPResponse,
                             declared: int, lease: _Lease, request_body: bytes,
                             deadline: _ConnectionDeadline, evidence: _Evidence) -> tuple[int, str, bool] | None:
        source = response.fp
        if source is None:
            raise _StreamError("response_missing")
        pending = bytearray()
        terminal: _Frame | None = None
        remaining = declared
        while remaining:
            self._ensure_deadline(deadline)
            read1 = getattr(source, "read1", None)
            part = read1(min(_READ_BYTES, remaining)) if read1 is not None else source.read(1)
            if not part:
                raise _StreamError("truncated")
            remaining -= len(part)
            evidence.observe(part)
            pending.extend(part)
            if len(pending) > _MAX_STREAM_FRAME_BYTES + 2:
                raise _StreamError("frame_oversize")
            while True:
                separator = pending.find(b"\n\n")
                if separator < 0:
                    break
                raw = bytes(pending[:separator + 2])
                del pending[:separator + 2]
                frame = self._decode_frame(raw)
                if frame.sequence != evidence.validated_frame_count + 1:
                    raise _StreamError("out_of_order")
                evidence.validated_frame_count += 1
                evidence.validated_bytes += len(raw)
                if evidence.validated_frame_count > _MAX_STREAM_EVENTS:
                    raise _StreamError("event_limit")
                if frame.kind == "fixture_terminal":
                    if terminal is not None:
                        if terminal.terminal_reason != frame.terminal_reason:
                            raise _StreamError("conflicting_terminal")
                        raise _StreamError("duplicate_terminal")
                    terminal = frame
                    evidence.terminal_observed = True
                    continue
                if terminal is not None:
                    raise _StreamError("trailing")
                self._forward_delta(handler, frame, declared, lease, deadline, evidence)
        if pending:
            raise _StreamError("trailing" if terminal is not None else "truncated")
        self._ensure_deadline(deadline)
        extra = source.read(1)
        if extra:
            evidence.observe(extra)
            raise _StreamError("trailing_after_length")
        if terminal is None:
            raise _StreamError("missing_terminal")
        if terminal.terminal_reason != "fixture_complete":
            raise _StreamError("conflicting_terminal")
        if evidence.forwarded_frame_count == 0:
            raise _StreamError("missing_delta")
        with self._lock:
            self._ensure_deadline(deadline)
            if self._expired(lease):
                lease.state = "EXPIRED"
                self._close_partial(handler, lease, request_body, evidence, "expired")
                return None
            if lease.state != "ACTIVE":
                self._close_partial(handler, lease, request_body, evidence, "revoked")
                return None
            try:
                evidence.bytes_may_have_crossed = True
                handler.wfile.write(terminal.raw)
                handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError, TimeoutError):
                self._stream_abort.set()
                self._close_partial(handler, lease, request_body, evidence, "downstream_disconnect")
                return None
            evidence.forwarded_frame_count += 1
            evidence.forwarded_bytes += len(terminal.raw)
            self._ensure_deadline(deadline)
            evidence.transport_complete = True
        handler.close_connection = True
        self._append_stream_request_receipt(
            evidence, lease.grant.lease_id, "response_complete", "stream_complete",
            len(request_body), True,
        )
        self._record_stream(evidence, "stream_complete", "complete")
        return None

    def _forward_delta(self, handler: BaseHTTPRequestHandler, frame: _Frame, declared: int,
                       lease: _Lease, deadline: _ConnectionDeadline, evidence: _Evidence) -> None:
        self._ensure_deadline(deadline)
        with self._lock:
            self._ensure_deadline(deadline)
            if self._expired(lease):
                lease.state = "EXPIRED"
                raise _StreamError("expired")
            if lease.state != "ACTIVE":
                raise _StreamError("revoked")
            try:
                if evidence.forwarded_frame_count == 0:
                    evidence.headers_started = True
                    handler.send_response(200)
                    handler.send_header("Content-Type", "text/event-stream")
                    handler.send_header("Content-Length", str(declared))
                    handler.send_header("Connection", "close")
                    handler.end_headers()
                evidence.bytes_may_have_crossed = True
                handler.wfile.write(frame.raw)
                handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError, TimeoutError) as exc:
                self._stream_abort.set()
                raise _StreamError("downstream_disconnect") from exc
            evidence.forwarded_frame_count += 1
            evidence.forwarded_bytes += len(frame.raw)
            if evidence.forwarded_frame_count == 1:
                self._first_frame_forwarded.set()

    def _close_partial(self, handler: BaseHTTPRequestHandler, lease: _Lease, body: bytes,
                       evidence: _Evidence, reason: str) -> None:
        self._stream_abort.set()
        handler.close_connection = True
        with self._lock:
            lease.state = "REVOKED"
            self._append_stream_request_receipt(
                evidence, lease.grant.lease_id, "upstream_unknown", reason, len(body),
                evidence.upstream_attempted,
            )
        self._record_stream(evidence, "stream_partial", reason)

    def _append_stream_request_receipt(self, evidence: _Evidence, lease_id: str,
                                       disposition: str, reason: str, request_bytes: int,
                                       upstream_attempted: bool) -> None:
        """Append base-compatible metadata without retaining streamed response bytes."""
        with self._lock:
            self._receipts.append(
                RequestReceipt(
                    evidence.sequence,
                    lease_id,
                    disposition,
                    reason,
                    upstream_attempted,
                    request_bytes,
                    evidence.forwarded_bytes,
                )
            )

    @staticmethod
    def _ensure_deadline(deadline: _ConnectionDeadline) -> None:
        if deadline.expired.is_set() or time.monotonic() >= deadline.expires_at:
            raise _StreamError("connection_deadline")

    def _decode_frame(self, raw: bytes) -> _Frame:
        if len(raw) > _MAX_STREAM_FRAME_BYTES or not raw.startswith(b"data: ") or not raw.endswith(b"\n\n"):
            raise _StreamError("frame_framing")
        payload = raw[6:-2]
        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=self._unique_object,
                parse_constant=self._reject_constant,
                parse_float=self._parse_float,
                parse_int=self._parse_int,
            )
        except UnicodeDecodeError as exc:
            raise _StreamError("malformed_utf8") from exc
        except _StreamError:
            raise
        except (json.JSONDecodeError, RecursionError, ValueError, TypeError) as exc:
            raise _StreamError("malformed_json") from exc
        try:
            depth = self._nesting(value)
        except RecursionError as exc:
            raise _StreamError("deep") from exc
        if depth > _MAX_STREAM_NESTING:
            raise _StreamError("deep")
        if not isinstance(value, dict):
            raise _StreamError("event_shape")
        kind = value.get("type")
        sequence = value.get("sequence")
        if type(sequence) is not int or sequence < 1 or not isinstance(kind, str):
            raise _StreamError("event_shape")
        if kind == "fixture_delta":
            if set(value) != {"type", "sequence", "text"} or type(value.get("text")) is not str:
                raise _StreamError("event_shape")
            try:
                text_bytes = value["text"].encode("utf-8")
            except UnicodeEncodeError as exc:
                raise _StreamError("malformed_utf8") from exc
            if len(text_bytes) > 128:
                raise _StreamError("event_shape")
            return _Frame(raw, kind, sequence=sequence)
        if kind == "fixture_terminal":
            if set(value) != {"type", "sequence", "stop_reason"} or type(value.get("stop_reason")) is not str:
                raise _StreamError("event_shape")
            if value["stop_reason"] not in {"fixture_complete", "fixture_abort"}:
                raise _StreamError("event_shape")
            return _Frame(raw, kind, value["stop_reason"], sequence)
        raise _StreamError("unknown_kind")

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _StreamError("duplicate_key")
            result[key] = value
        return result

    @staticmethod
    def _reject_constant(value: str) -> Any:
        raise _StreamError("nonfinite")

    @staticmethod
    def _parse_int(value: str) -> int:
        parsed = int(value)
        if not -(2**31) <= parsed <= 2**31 - 1:
            raise _StreamError("number_range")
        return parsed

    @staticmethod
    def _parse_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise _StreamError("nonfinite")
        return parsed

    @staticmethod
    def _nesting(value: Any) -> int:
        if isinstance(value, dict):
            return 1 + max((_ for _ in (IncrementalStreamHarness._nesting(item) for item in value.values())), default=0)
        if isinstance(value, list):
            return 1 + max((_ for _ in (IncrementalStreamHarness._nesting(item) for item in value)), default=0)
        return 0
