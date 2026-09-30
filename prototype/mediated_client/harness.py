"""Bounded, two-hop TLS transport fixture for mediated-client experiments.

This is an isolated synthetic harness.  It does not start a Claude client, use a
provider credential, select an external destination, or model a production
Forwarder control plane.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import math
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Self

from .certificates import FixtureCertificates

FIXTURE_REQUEST = b'{"fixture":"mediated-client-v1"}'
"""The only body admitted by this fixture; it is not a Messages API schema."""

FIXTURE_RESPONSE = b'data: {"type":"fixture_reply"}\n\n'
"""The complete buffered synthetic response; it is not streaming qualification."""

_ROUTE = "/v1/messages"
_SERVICE_NAMES = frozenset({"jira", "confluence", "grafana", "kubernetes", "anthropic"})
_CERTIFICATE_VARIANTS = frozenset({"valid", "expired", "wrong_hostname"})
_UPSTREAM_MODES = frozenset({"ok", "redirect", "oversize", "truncate", "disconnect", "timeout"})
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_MAX_HEADER_BYTES = 8192
_MAX_REQUESTS = 128
_MAX_DROPPED = 2**31 - 1
_SYNTHETIC_API_KEY = "fixture-upstream-key"
_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


@dataclass(frozen=True)
class Grant:
    lease_id: str
    run_id: str
    service: str
    expires_at: float
    token: str = field(repr=False)


@dataclass(frozen=True)
class RequestReceipt:
    sequence: int
    lease_id: str | None
    disposition: str
    reason: str
    upstream_attempted: bool
    request_bytes: int
    response_bytes: int


@dataclass(frozen=True)
class UpstreamReceipt:
    sequence: int
    request_bytes: int
    body_sha256: str
    credential_replaced: bool
    host_matches: bool
    header_names: tuple[str, ...]


@dataclass
class _Lease:
    grant: Grant
    state: str = "REGISTERED"


@dataclass(frozen=True)
class _Inbound:
    status: int
    body: bytes
    lease_id: str | None
    disposition: str
    reason: str
    request_bytes: int
    upstream_attempted: bool = False


@dataclass(frozen=True)
class _SendResult:
    status: int
    body: bytes
    disposition: str
    reason: str
    upstream_attempted: bool


@dataclass(frozen=True)
class _ConnectionDeadline:
    expires_at: float
    expired: threading.Event


class _BoundedHTTPServer(HTTPServer):
    """A sequential TLS server with one absolute deadline per accepted socket."""

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler],
                 connection_budget: float, handshake_timeout: float, context: ssl.SSLContext):
        self._connection_budget = connection_budget
        self._handshake_timeout = handshake_timeout
        self._context = context
        self._timers: dict[int, threading.Timer] = {}
        self._deadlines: dict[int, _ConnectionDeadline] = {}
        self._timers_lock = threading.Lock()
        super().__init__(address, handler)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        raw, address = super().get_request()
        deadline = time.monotonic() + self._connection_budget
        expired = threading.Event()
        state: dict[str, socket.socket | bool] = {"socket": raw, "expired": False}
        state_lock = threading.Lock()

        def expire() -> None:
            expired.set()
            with state_lock:
                state["expired"] = True
                target = state["socket"]
            if isinstance(target, socket.socket):
                try:
                    target.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    target.close()
                except OSError:
                    pass

        timer = threading.Timer(self._connection_budget, expire)
        timer.daemon = True
        timer.start()
        try:
            raw.settimeout(min(self._handshake_timeout, max(0.001, deadline - time.monotonic())))
            request = self._context.wrap_socket(raw, server_side=True)
            with state_lock:
                if state["expired"]:
                    raise TimeoutError("TLS handshake exceeded fixture deadline")
                state["socket"] = request
            request.settimeout(max(0.001, deadline - time.monotonic()))
            with self._timers_lock:
                self._timers[id(request)] = timer
                self._deadlines[id(request)] = _ConnectionDeadline(deadline, expired)
            return request, address
        except (OSError, ssl.SSLError, TimeoutError):
            timer.cancel()
            try:
                raw.close()
            except OSError:
                pass
            raise

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request(request, client_address)
        finally:
            with self._timers_lock:
                timer = self._timers.pop(id(request), None)
                self._deadlines.pop(id(request), None)
            if timer is not None:
                timer.cancel()

    def server_close(self) -> None:
        with self._timers_lock:
            timers = tuple(self._timers.values())
            self._timers.clear()
            self._deadlines.clear()
        for timer in timers:
            timer.cancel()
        super().server_close()

    def connection_deadline(self, request: socket.socket) -> _ConnectionDeadline | None:
        with self._timers_lock:
            return self._deadlines.get(id(request))

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        # Deadline-driven peer closure is an expected fixture rejection, not an
        # unbounded server traceback. Preserve unexpected programming failures.
        error = sys.exception()
        if isinstance(error, (BrokenPipeError, ConnectionResetError, OSError)):
            return
        super().handle_error(request, client_address)


class MediatedClientHarness:
    """Context-managed local TLS mediator with a fixed synthetic upstream.

    Registration and revocation are direct trusted-test methods only.  They do
    not demonstrate a Receiver-only authenticated control channel or OS boundary.
    """

    def __init__(
        self,
        certificates: FixtureCertificates,
        *,
        upstream_mode: str = "ok",
        server_certificate: str = "valid",
        upstream_certificate: str = "valid",
        max_request_bytes: int = 4096,
        max_response_bytes: int = 8192,
        timeout_seconds: float = 0.5,
    ):
        if upstream_mode not in _UPSTREAM_MODES:
            raise ValueError("unsupported synthetic upstream mode")
        if server_certificate not in _CERTIFICATE_VARIANTS:
            raise ValueError("unsupported mediator certificate variant")
        if upstream_certificate not in _CERTIFICATE_VARIANTS:
            raise ValueError("unsupported upstream certificate variant")
        for value in (max_request_bytes, max_response_bytes):
            if type(value) is not int or not 1 <= value <= 1024 * 1024:
                raise ValueError("transport byte limits must be positive ints no larger than 1 MiB")
        try:
            timeout = float(timeout_seconds)
        except (OverflowError, TypeError, ValueError):
            timeout = float("nan")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or
                not math.isfinite(timeout) or not 0 < timeout <= 2):
            raise ValueError("transport timeout must be finite, positive, and no greater than 2 seconds")
        if not isinstance(certificates, FixtureCertificates):
            raise TypeError("fixture certificates are required")
        self._certificates = certificates
        self._upstream_mode = upstream_mode
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._timeout_seconds = timeout
        # One hop gets the configured timeout; the accepted connection gets
        # bounded extra time to return its local gateway response.
        self._connection_budget = 2 * timeout + 0.2
        self._clock: Callable[[], float] = time.monotonic
        self._lock = threading.RLock()
        self._upstream_receipt_lock = threading.Lock()
        self._leases: dict[str, _Lease] = {}
        self._tokens: set[str] = set()
        self._receipts: list[RequestReceipt] = []
        self._upstream_receipts: list[UpstreamReceipt] = []
        self._pending_dispatches: dict[str, int] = {}
        self._dropped_count = 0
        self._request_count = 0
        self._started = False
        self._stopped = False

        self._upstream_server: _BoundedHTTPServer | None = None
        self._mediator_server: _BoundedHTTPServer | None = None
        try:
            upstream_context = self._server_context(self._certificate_path(upstream_certificate))
            mediator_context = self._server_context(self._certificate_path(server_certificate))
            self._upstream_server = _BoundedHTTPServer(
                ("127.0.0.1", 0), self._upstream_handler(), self._connection_budget,
                self._timeout_seconds, upstream_context,
            )
            self._mediator_server = _BoundedHTTPServer(
                ("127.0.0.1", 0), self._mediator_handler(), self._connection_budget,
                self._timeout_seconds, mediator_context,
            )
        except BaseException:
            for server in (self._mediator_server, self._upstream_server):
                if server is not None:
                    server.server_close()
            raise
        self._upstream_thread: threading.Thread | None = None
        self._mediator_thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self._mediator_server.server_address[1]}"

    @property
    def receipts(self) -> tuple[RequestReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    @property
    def upstream_receipts(self) -> tuple[UpstreamReceipt, ...]:
        with self._upstream_receipt_lock:
            return tuple(self._upstream_receipts)

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped_count

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()

    def start(self) -> None:
        if self._stopped:
            raise RuntimeError("a stopped harness cannot restart")
        if self._started:
            return
        self._upstream_thread = self._serve(self._upstream_server, "mediated-fixture-upstream")
        self._mediator_thread = self._serve(self._mediator_server, "mediated-fixture-mediator")
        self._started = True

    def stop(self) -> None:
        if self._stopped:
            return
        deadline = time.monotonic() + 5
        shutdown_threads = []
        for server in (self._mediator_server, self._upstream_server):
            assert server is not None
            if self._started:
                thread = threading.Thread(target=server.shutdown, name="mediated-fixture-stop")
                thread.start()
                shutdown_threads.append(thread)
        for thread in shutdown_threads:
            thread.join(max(0, deadline - time.monotonic()))
            if thread.is_alive():
                raise RuntimeError("bounded fixture server did not acknowledge shutdown")
        for server in (self._mediator_server, self._upstream_server):
            assert server is not None
            server.server_close()
        for thread in (self._mediator_thread, self._upstream_thread):
            if thread is not None:
                thread.join(max(0, deadline - time.monotonic()))
                if thread.is_alive():
                    raise RuntimeError("bounded fixture server did not stop")
        if time.monotonic() > deadline:
            raise RuntimeError("fixture shutdown exceeded five seconds")
        self._stopped = True

    def register(self, run_id: str, service: str = "anthropic", ttl_seconds: float = 270) -> Grant:
        """Create one synthetic registered lease; its token never enters receipts."""
        if type(run_id) is not str or not _SAFE_ID.fullmatch(run_id):
            raise ValueError("run ID must be a nonempty safe ASCII string no longer than 64 chars")
        if service not in _SERVICE_NAMES:
            raise ValueError("unsupported service")
        try:
            ttl = float(ttl_seconds)
        except (OverflowError, TypeError, ValueError):
            ttl = float("nan")
        if (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or
                not math.isfinite(ttl) or not 0 < ttl <= 270):
            raise ValueError("lease TTL must be finite, positive, and no greater than 270 seconds")
        with self._lock:
            if len(self._leases) >= 32:
                raise RuntimeError("fixture registration limit reached")
            lease_id = self._fresh_secret(self._leases)
            token = self._fresh_secret(self._tokens)
            grant = Grant(lease_id, run_id, service, self._clock() + ttl, token)
            self._leases[lease_id] = _Lease(grant)
            self._tokens.add(token)
            return grant

    def activate(self, lease_id: str) -> None:
        with self._lock:
            lease = self._lookup_lease(lease_id)
            if lease.state in {"REVOKED", "EXPIRED"}:
                raise ValueError("revoked or expired leases cannot be activated")
            if self._expired(lease):
                lease.state = "EXPIRED"
                raise ValueError("expired leases cannot be activated")
            if lease.state != "REGISTERED":
                raise ValueError("lease is not registered")
            lease.state = "ACTIVE"

    def revoke(self, lease_id: str) -> None:
        """Permanently stop later dispatch; an in-flight bounded send may finish first."""
        with self._lock:
            lease = self._lookup_lease(lease_id)
            lease.state = "REVOKED"

    def _lookup_lease(self, lease_id: str) -> _Lease:
        if type(lease_id) is not str:
            raise ValueError("lease ID is required")
        try:
            return self._leases[lease_id]
        except KeyError as exc:
            raise ValueError("unknown lease") from exc

    def _fresh_secret(self, existing: object) -> str:
        for _ in range(8):
            value = secrets.token_urlsafe(24)
            if value not in existing:
                return value
        raise RuntimeError("fixture random source repeatedly produced a duplicate")

    def _certificate_path(self, variant: str) -> Path:
        if variant == "valid":
            return self._certificates.server_cert
        if variant == "expired":
            return self._certificates.expired_cert
        return self._certificates.wrong_hostname_cert

    def _server_context(self, certificate: Path) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(certificate), keyfile=str(self._certificates.server_key)
        )
        return context

    def _client_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self._certificates.ca_cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _serve(self, server: HTTPServer, name: str) -> threading.Thread:
        thread = threading.Thread(
            target=server.serve_forever,
            args=(0.02,),
            name=name,
            daemon=True,
        )
        thread.start()
        return thread

    def _mediator_handler(self) -> type[BaseHTTPRequestHandler]:
        fixture = self

        class MediatorHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                deadline = self.server.connection_deadline(self.connection)
                result = fixture._receive(self, deadline)
                headers = {"Content-Type": "text/event-stream"} if result.status == 200 else None
                fixture._respond(self, result.status, result.body, headers)

            def do_GET(self) -> None:
                deadline = self.server.connection_deadline(self.connection)
                result = fixture._receive(self, deadline)
                fixture._respond(self, result.status, result.body)

            do_PUT = do_DELETE = do_PATCH = do_GET
            do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = do_GET

            def log_message(self, format: str, *args: object) -> None:
                pass

        return MediatorHandler

    def _upstream_handler(self) -> type[BaseHTTPRequestHandler]:
        fixture = self

        class UpstreamHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                lengths = self.headers.get_all("Content-Length") or []
                if (self.path != _ROUTE or len(lengths) != 1 or
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
                if not fixture._capture_upstream(self.headers, body):
                    fixture._respond(self, 401, b"")
                    return
                if fixture._upstream_mode == "disconnect":
                    self.close_connection = True
                    return
                if fixture._upstream_mode == "timeout":
                    time.sleep(fixture._timeout_seconds + 0.05)
                    return
                if fixture._upstream_mode == "redirect":
                    fixture._respond(
                        self, 302, b"", {"Location": "https://fixture.invalid/redirect"}
                    )
                    return
                if fixture._upstream_mode == "truncate":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", "32")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"event: partial\n\n")
                    self.close_connection = True
                    return
                if fixture._upstream_mode == "oversize":
                    fixture._respond(self, 200, b"x" * (fixture._max_response_bytes + 1))
                    return
                fixture._respond(self, 200, FIXTURE_RESPONSE, {"Content-Type": "text/event-stream"})

            do_GET = do_PUT = do_DELETE = do_PATCH = do_POST

            def log_message(self, format: str, *args: object) -> None:
                pass

        return UpstreamHandler

    def _receive(self, handler: BaseHTTPRequestHandler,
                 deadline: _ConnectionDeadline | None) -> _Inbound:
        with self._lock:
            sequence = self._next_sequence()
            if sequence is None:
                return _Inbound(429, b"fixture request limit", None, "denied", "request_limit", 0)
            checked = self._validate_request(handler, sequence)
            if isinstance(checked, _Inbound):
                self._append_receipt(sequence, checked)
                return checked
            lease, body = checked
            if deadline is None or self._deadline_expired(deadline):
                inbound = self._deny("connection_deadline", lease.grant.lease_id, len(body))
                self._append_receipt(sequence, inbound)
                return inbound
            result = self._send_upstream(lease, body, sequence, deadline)
            inbound = _Inbound(result.status, result.body, lease.grant.lease_id,
                               result.disposition, result.reason, len(body),
                               result.upstream_attempted)
            if result.disposition == "upstream_unknown":
                lease.state = "REVOKED"
            self._append_receipt(sequence, inbound)
            return inbound

    def _next_sequence(self) -> int | None:
        if self._request_count >= _MAX_REQUESTS:
            self._dropped_count = min(_MAX_DROPPED, self._dropped_count + 1)
            return None
        self._request_count += 1
        return self._request_count

    def _validate_request(self, handler: BaseHTTPRequestHandler,
                          sequence: int) -> _Inbound | tuple[_Lease, bytes]:
        if handler.command != "POST":
            return self._deny("method", None, 0)
        if handler.path != _ROUTE:
            return self._deny("route", None, 0)
        if self._header_size(handler) > _MAX_HEADER_BYTES:
            return self._deny("headers", None, 0)
        lengths = handler.headers.get_all("Content-Length") or []
        if (len(lengths) != 1 or not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]) or
                len(lengths[0]) > len(str(self._max_request_bytes))):
            return self._deny("content_length", None, 0)
        declared = int(lengths[0])
        if declared > self._max_request_bytes:
            return self._deny("request_oversize", None, 0)
        if (handler.headers.get("Transfer-Encoding") is not None or
                handler.headers.get("Expect") is not None):
            return self._deny("framing", None, 0)
        hosts = handler.headers.get_all("Host") or []
        if len(hosts) != 1:
            return self._deny("host", None, 0)
        content_types = handler.headers.get_all("Content-Type") or []
        if len(content_types) != 1 or content_types[0] != "application/json":
            return self._deny("content_type", None, 0)
        lease = self._authorize(handler.headers.get_all("Authorization") or [])
        if isinstance(lease, _Inbound):
            return lease
        try:
            body = handler.rfile.read(declared)
        except (OSError, TimeoutError):
            return self._deny("request_timeout", lease.grant.lease_id, 0)
        if len(body) != declared:
            return self._deny("short_body", lease.grant.lease_id, len(body))
        if body != FIXTURE_REQUEST:
            return self._deny("body", lease.grant.lease_id, len(body))
        return lease, body

    def _authorize(self, values: list[str]) -> _Lease | _Inbound:
        if len(values) != 1:
            return self._deny("authorization", None, 0)
        scheme, separator, token = values[0].partition(" ")
        if scheme != "Bearer" or not separator or not _TOKEN.fullmatch(token):
            return self._deny("authorization", None, 0)
        found: _Lease | None = None
        for lease in self._leases.values():
            if hmac.compare_digest(lease.grant.token, token):
                found = lease
        if found is None:
            return self._deny("unknown_token", None, 0)
        if found.grant.service != "anthropic":
            return self._deny("wrong_service", found.grant.lease_id, 0)
        if self._expired(found):
            found.state = "EXPIRED"
            return self._deny("expired", found.grant.lease_id, 0)
        if found.state != "ACTIVE":
            return self._deny("not_active", found.grant.lease_id, 0)
        return found

    def _expired(self, lease: _Lease) -> bool:
        return self._clock() >= lease.grant.expires_at

    @staticmethod
    def _deadline_expired(deadline: _ConnectionDeadline) -> bool:
        return deadline.expired.is_set() or time.monotonic() >= deadline.expires_at

    def _send_upstream(self, lease: _Lease, body: bytes, sequence: int,
                       deadline: _ConnectionDeadline) -> _SendResult:
        assert self._upstream_server is not None
        with self._upstream_receipt_lock:
            dispatch = self._fresh_secret(self._pending_dispatches)
            self._pending_dispatches[dispatch] = sequence
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

        remaining = deadline.expires_at - time.monotonic()
        if deadline.expired.is_set() or remaining <= 0:
            with self._upstream_receipt_lock:
                self._pending_dispatches.pop(dispatch, None)
            return _SendResult(504, b"", "denied", "connection_deadline", False)
        timer = threading.Timer(remaining, close_outbound)
        timer.daemon = True
        timer.start()
        upstream_socket: socket.socket | None = None
        response: http.client.HTTPResponse | None = None
        try:
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with socket_lock:
                socket_state["socket"] = upstream_socket
            remaining = deadline.expires_at - time.monotonic()
            if deadline.expired.is_set() or remaining <= 0:
                return _SendResult(504, b"", "denied", "connection_deadline", False)
            upstream_socket.settimeout(min(self._timeout_seconds, remaining))
            upstream_socket.connect(("127.0.0.1", self._upstream_server.server_address[1]))
            upstream_socket = self._client_context().wrap_socket(
                upstream_socket, server_hostname="127.0.0.1"
            )
            with socket_lock:
                socket_state["socket"] = upstream_socket
            remaining = deadline.expires_at - time.monotonic()
            if deadline.expired.is_set() or remaining <= 0:
                return _SendResult(504, b"", "denied", "connection_deadline", False)
            upstream_socket.settimeout(min(self._timeout_seconds, remaining))
            if self._expired(lease) or lease.state != "ACTIVE":
                if self._expired(lease):
                    lease.state = "EXPIRED"
                    reason = "expired"
                else:
                    reason = "revoked"
                return _SendResult(401, b"fixture lease denied", "denied", reason, False)
            request = (
                f"POST {_ROUTE} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self._upstream_server.server_address[1]}\r\n"
                "Content-Type: application/json\r\n"
                f"X-Api-Key: {_SYNTHETIC_API_KEY}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"X-Fixture-Sequence: {sequence}\r\n"
                f"X-Fixture-Dispatch: {dispatch}\r\n\r\n"
            ).encode("ascii") + body
            upstream_socket.sendall(request)
            response = http.client.HTTPResponse(upstream_socket)
            response.begin()
            if 300 <= response.status < 400:
                response.close()
                return _SendResult(502, b"", "upstream_unknown",
                                   "redirect", True)
            response_headers = response.getheaders()
            content_types = [
                value for name, value in response_headers if name.lower() == "content-type"
            ]
            lengths = [value for name, value in response_headers if name.lower() == "content-length"]
            transfer_encodings = [value for name, value in response_headers
                                  if name.lower() == "transfer-encoding"]
            if (response.status != 200 or len(content_types) != 1 or
                    content_types[0] != "text/event-stream" or len(lengths) != 1 or
                    lengths[0] != str(len(FIXTURE_RESPONSE)) or transfer_encodings):
                response.close()
                return _SendResult(502, b"", "upstream_unknown", "response_framing", True)
            if response.length is not None and response.length > self._max_response_bytes:
                response.close()
                return _SendResult(502, b"", "upstream_unknown",
                                   "response_oversize", True)
            try:
                response_body = response.read(self._max_response_bytes + 1)
            except http.client.IncompleteRead:
                return _SendResult(502, b"", "upstream_unknown",
                                   "truncated", True)
            if len(response_body) > self._max_response_bytes:
                return _SendResult(502, b"", "upstream_unknown", "response_oversize", True)
            if response_body != FIXTURE_RESPONSE:
                return _SendResult(502, b"", "upstream_unknown", "response_body", True)
            if self._deadline_expired(deadline):
                return _SendResult(502, b"", "upstream_unknown", "connection_deadline", True)
            return _SendResult(
                response.status, response_body, "response_complete", "complete", True
            )
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            return _SendResult(502, b"", "upstream_unknown",
                               "upstream_failure", True)
        finally:
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

    def _capture_upstream(self, headers: object, body: bytes) -> bool:
        sequence_values = headers.get_all("X-Fixture-Sequence")  # type: ignore[union-attr]
        dispatch_values = headers.get_all("X-Fixture-Dispatch")  # type: ignore[union-attr]
        if (sequence_values is None or len(sequence_values) != 1 or
                not re.fullmatch(r"[1-9][0-9]{0,2}", sequence_values[0]) or
                dispatch_values is None or len(dispatch_values) != 1 or
                not _TOKEN.fullmatch(dispatch_values[0])):
            return False
        sequence = int(sequence_values[0])
        header_items = headers.items()  # type: ignore[union-attr]
        names = tuple(sorted({
            name.lower() for name, _ in header_items if not name.lower().startswith("x-fixture-")
        }))
        authorization = headers.get("Authorization")  # type: ignore[union-attr]
        api_key = headers.get("X-Api-Key")  # type: ignore[union-attr]
        assert self._upstream_server is not None
        expected_host = f"127.0.0.1:{self._upstream_server.server_address[1]}"
        host = headers.get("Host")  # type: ignore[union-attr]
        receipt = UpstreamReceipt(
            sequence,
            len(body),
            hashlib.sha256(body).hexdigest(),
            authorization is None and hmac.compare_digest(api_key or "", _SYNTHETIC_API_KEY),
            hmac.compare_digest(host or "", expected_host),
            names,
        )
        with self._upstream_receipt_lock:
            if self._pending_dispatches.get(dispatch_values[0]) != sequence:
                return False
            del self._pending_dispatches[dispatch_values[0]]
            self._upstream_receipts.append(receipt)
        return True

    def _header_size(self, handler: BaseHTTPRequestHandler) -> int:
        return sum(len(name) + len(value) + 4 for name, value in handler.headers.items())

    def _deny(self, reason: str, lease_id: str | None, request_bytes: int) -> _Inbound:
        return _Inbound(401, b"fixture request denied", lease_id, "denied", reason, request_bytes)

    def _append_receipt(self, sequence: int, result: _Inbound) -> None:
        self._receipts.append(
            RequestReceipt(sequence, result.lease_id, result.disposition, result.reason,
                           result.upstream_attempted, result.request_bytes, len(result.body))
        )

    def _respond(self, handler: BaseHTTPRequestHandler, status: int, body: bytes,
                 headers: dict[str, str] | None = None) -> None:
        try:
            handler.send_response(status)
            for name, value in (headers or {}).items():
                handler.send_header(name, value)
            handler.send_header("Content-Length", str(len(body)))
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass
        handler.close_connection = True
