"""A fixed, single-service TLS listener with explicit descriptor ownership.

The listener establishes transport only.  It reads and writes no application
bytes, makes no request-policy decision, and starts no worker.
"""

from __future__ import annotations

import math
import select
import socket
import ssl
import threading
import time

from .forwarder_services import SERVICE_PROFILES

_CONTEXT_MARKER = "_maoi_fixed_tls_listener_claimed"
_CONTEXT_CLAIM_LOCK = threading.Lock()
_ACCEPT_POLL_INTERVAL = 0.1
_HANDSHAKE_POLL_INTERVAL = 0.1


class TLSListenerError(ValueError):
    """A fixed, non-diagnostic listener rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise TLSListenerError(code) from None


def _finite_number(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _timeout(value: object) -> float:
    seconds = _finite_number(value)
    if seconds is None or seconds <= 0 or seconds > 10:
        _fail("invalid_timeout")
    return seconds


def _monotonic(previous: float | None = None) -> float:
    try:
        observed = _finite_number(time.monotonic())
    except Exception:  # noqa: BLE001 - a failed clock cannot establish a deadline.
        _fail("clock_fault")
    if observed is None or (previous is not None and observed < previous):
        _fail("clock_fault")
    return observed


def _remaining(deadline: float, previous: float) -> tuple[float, float]:
    observed = _monotonic(previous)
    seconds = deadline - observed
    if not math.isfinite(seconds) or seconds <= 0:
        _fail("deadline_expired")
    return seconds, observed


class FixedTLSListener:
    """Own one fixed loopback TLS listener and one in-flight connection at most."""

    def __init__(self, service: str, *, context: ssl.SSLContext):
        if type(service) is not str or service not in SERVICE_PROFILES:
            _fail("unknown_service")
        if type(context) is not ssl.SSLContext:
            _fail("invalid_context")
        if context.protocol != ssl.PROTOCOL_TLS_SERVER:
            _fail("invalid_context")
        if context.keylog_filename is not None:
            _fail("invalid_context")
        with _CONTEXT_CLAIM_LOCK:
            if getattr(context, _CONTEXT_MARKER, False):
                _fail("context_claimed")
            setattr(context, _CONTEXT_MARKER, True)
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            expected_name = SERVICE_PROFILES[service].server_name

            def sni_callback(_socket: ssl.SSLSocket, server_name: str | None,
                             _initial_context: ssl.SSLContext) -> int | None:
                if server_name == expected_name:
                    return None
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

            context.set_servername_callback(sni_callback)
        except (OSError, ValueError, TypeError, AttributeError):
            _fail("invalid_context")

        self._service = service
        self._context = context
        self._listener: socket.socket | None = None
        self._inflight: socket.socket | ssl.SSLSocket | None = None
        self._opened = False
        self._closed = False
        self._accept_active = False
        self._unknown_latched = False
        self._state_lock = threading.RLock()
        self._accept_gate = threading.Lock()

    @property
    def service(self) -> str:
        """The bound service name; read-only."""
        return self._service

    def open(self) -> None:
        """Bind the sole fixed loopback socket.  Opening is one-shot."""
        with self._state_lock:
            if self._opened or self._closed:
                _fail("listener_closed")
            self._closed = True
            candidate: socket.socket | None = None
            try:
                profile = SERVICE_PROFILES[self._service]
                candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._listener = candidate
                candidate.set_inheritable(False)
                candidate.bind((profile.bind_host, profile.port))
                candidate.listen(4)
                self._opened = True
                self._closed = False
            except BaseException as error:
                if candidate is not None and not self._close_attribute("_listener", interrupt=True):
                    self._unknown_latched = True
                if isinstance(error, Exception):
                    _fail("open_failed")
                raise

    def _close_descriptor(self, connection: socket.socket | ssl.SSLSocket,
                          *, interrupt: bool = False) -> bool:
        if interrupt:
            self._shutdown_quietly(connection)
        try:
            connection.close()
        except BaseException:  # noqa: BLE001 - preserve safe retry handle.
            return False
        try:
            closed = connection.fileno() < 0
        except BaseException:  # noqa: BLE001 - preserve safe retry handle.
            return False
        return closed

    @staticmethod
    def _shutdown_quietly(connection: socket.socket | ssl.SSLSocket) -> None:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except BaseException:  # noqa: BLE001 - descriptor close still follows.
            return

    def _close_attribute(self, name: str, *, interrupt: bool) -> bool:
        connection = getattr(self, name)
        if connection is None:
            return True
        if not self._close_descriptor(connection, interrupt=interrupt):
            self._unknown_latched = True
            return False
        setattr(self, name, None)
        return True

    def close(self) -> str:
        """Make the instance terminal and interrupt only descriptors it owns."""
        with self._state_lock:
            self._closed = True
            listener_closed = self._close_attribute("_listener", interrupt=True)
            inflight_closed = self._close_attribute("_inflight", interrupt=True)
            if self._accept_active:
                return "unknown"
            if self._unknown_latched or not listener_closed or not inflight_closed:
                return "unknown"
            return "closed"

    def _nonblocking_handshake(self, secured: ssl.SSLSocket, deadline: float,
                               previous: float) -> float:
        """Advance exactly one handshake without blocking close on Darwin."""
        while True:
            remaining, previous = _remaining(deadline, previous)
            readable: list[ssl.SSLSocket] = []
            writable: list[ssl.SSLSocket] = []
            with self._state_lock:
                if self._closed or self._inflight is not secured:
                    _fail("listener_closed")
                secured.settimeout(0.0)
                try:
                    secured.do_handshake()
                except ssl.SSLWantReadError:
                    readable.append(secured)
                except ssl.SSLWantWriteError:
                    writable.append(secured)
                else:
                    remaining, previous = _remaining(deadline, previous)
                    if self._closed or self._inflight is not secured:
                        _fail("listener_closed")
                    secured.settimeout(remaining)
                    return previous
            remaining, previous = _remaining(deadline, previous)
            try:
                select.select(readable, writable, (), min(remaining, _HANDSHAKE_POLL_INTERVAL))
            except (OSError, ValueError, TypeError):
                with self._state_lock:
                    if self._closed:
                        _fail("listener_closed")
                _fail("handshake_failed")

    def accept(self, *, timeout: float = 1.0) -> ssl.SSLSocket:
        """Accept and explicitly handshake one TLS client under one deadline."""
        seconds = _timeout(timeout)
        if not self._accept_gate.acquire(blocking=False):
            _fail("accept_busy")
        raw: socket.socket | None = None
        secured: ssl.SSLSocket | None = None
        listener: socket.socket | None = None
        returned = False
        phase = "accept"
        previous_timeout: float | None = None
        timeout_changed = False
        started: float | None = None
        try:
            with self._state_lock:
                if not self._opened or self._closed or self._listener is None:
                    _fail("listener_closed")
                if self._unknown_latched:
                    _fail("listener_unknown")
                self._accept_active = True
                listener = self._listener
            started = _monotonic()
            deadline = started + seconds
            if not math.isfinite(deadline):
                _fail("clock_fault")
            previous_timeout = listener.gettimeout()
            timeout_changed = True
            observed = started
            while raw is None:
                remaining, observed = _remaining(deadline, observed)
                listener.settimeout(min(remaining, _ACCEPT_POLL_INTERVAL))
                try:
                    raw, _address = listener.accept()
                except TimeoutError:
                    pass
                with self._state_lock:
                    if self._closed or self._listener is not listener:
                        _fail("listener_closed")
                if raw is None:
                    # This is deadline-clipped waiting for one accept, rather
                    # than a retry or a new admission attempt.
                    continue
            raw.set_inheritable(False)
            with self._state_lock:
                if self._closed or self._listener is not listener:
                    _fail("listener_closed")
                self._inflight = raw
                phase = "tls"
                secured = self._context.wrap_socket(
                    raw,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                raw = None
                self._inflight = secured
            secured.set_inheritable(False)
            observed = self._nonblocking_handshake(secured, deadline, observed)
            with self._state_lock:
                if self._closed or self._inflight is not secured:
                    _fail("listener_closed")
                self._inflight = None
                returned = True
            return secured
        except TLSListenerError:
            raise
        except (OSError, ssl.SSLError, ValueError, TypeError):
            with self._state_lock:
                if self._closed:
                    _fail("listener_closed")
            _fail("handshake_failed" if phase == "tls" else "accept_failed")
        finally:
            try:
                with self._state_lock:
                    cleanup = secured if secured is not None and not returned else raw
                    if cleanup is not None:
                        if self._inflight is None:
                            self._inflight = cleanup
                        cleanup_ok = self._close_descriptor(cleanup, interrupt=True)
                        if cleanup_ok and self._inflight is cleanup:
                            self._inflight = None
                        if not cleanup_ok:
                            self._unknown_latched = True
                    self._accept_active = False
                    if timeout_changed and listener is not None and self._listener is listener:
                        try:
                            listener.settimeout(previous_timeout)
                        except OSError:
                            pass
                        except BaseException:  # noqa: BLE001 - release the gate below.
                            self._unknown_latched = True
            finally:
                self._accept_gate.release()
