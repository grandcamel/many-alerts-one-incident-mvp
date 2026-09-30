"""Deterministic lifecycle and ownership tests for fixed TLS listeners."""

from __future__ import annotations

import math
import ssl
import threading

import pytest

from grafana_jsm_sandbox import forwarder_server_tls
from grafana_jsm_sandbox.forwarder_server_tls import FixedTLSListener, TLSListenerError
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES


class _Socket:
    def __init__(self, *, accepted=None, bind_error=None):
        self.accepted = accepted
        self.bind_error = bind_error
        self.bind_address = None
        self.backlog = None
        self.inheritable = []
        self.timeout = None
        self.timeout_history = []
        self.closed = False

    def set_inheritable(self, value):
        self.inheritable.append(value)

    def bind(self, address):
        self.bind_address = address
        if self.bind_error:
            raise self.bind_error

    def listen(self, backlog):
        self.backlog = backlog

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout
        self.timeout_history.append(timeout)

    def accept(self):
        if isinstance(self.accepted, BaseException):
            raise self.accepted
        return self.accepted, ("127.0.0.1", 40000)

    def shutdown(self, _how):
        return None

    def close(self):
        self.closed = True

    def fileno(self):
        return -1 if self.closed else 81


class _Connection(_Socket):
    def __init__(self, *, handshake_error=None, close_error=None):
        super().__init__()
        self.handshake_error = handshake_error
        self.close_error = close_error

    def do_handshake(self):
        if self.handshake_error:
            raise self.handshake_error

    def close(self):
        if self.close_error:
            raise self.close_error
        super().close()


class _Context:
    def __init__(self, protocol):
        self.protocol = protocol
        self.keylog_filename = None
        self.minimum_version = None
        self.maximum_version = None
        self.verify_mode = None
        self.alpn = None
        self.callback = None
        self.wrapped = None

    def set_alpn_protocols(self, protocols):
        self.alpn = protocols

    def set_servername_callback(self, callback):
        self.callback = callback

    def wrap_socket(self, raw, *, server_side, do_handshake_on_connect):
        assert server_side and do_handshake_on_connect is False
        self.wrapped = raw
        return raw


def _error(call, code):
    with pytest.raises(TLSListenerError) as raised:
        call()
    assert raised.value.code == code
    assert str(raised.value) == code


def _fake_context(monkeypatch):
    monkeypatch.setattr(forwarder_server_tls.ssl, "SSLContext", _Context)
    return _Context(forwarder_server_tls.ssl.PROTOCOL_TLS_SERVER)


def test_constructor_requires_known_service_and_fresh_exact_server_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _error(lambda: FixedTLSListener("unknown", context=context), "unknown_service")
    _error(lambda: FixedTLSListener("jira", context=object()), "invalid_context")
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _error(lambda: FixedTLSListener("jira", context=client_context), "invalid_context")

    listener = FixedTLSListener("jira", context=context)
    assert listener.close() == "closed"
    _error(lambda: FixedTLSListener("grafana", context=context), "context_claimed")


def test_constructor_hardens_trusted_context_and_does_not_open_socket(monkeypatch):
    context = _fake_context(monkeypatch)
    calls = []
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: calls.append(args))

    FixedTLSListener("jira", context=context)

    assert calls == []
    assert context.minimum_version == forwarder_server_tls.ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == forwarder_server_tls.ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.verify_mode == forwarder_server_tls.ssl.CERT_NONE
    assert context.alpn == ["http/1.1"]
    assert context.callback(None, "forwarder-jira.maoi.local", context) is None
    assert context.callback(None, None, context) == forwarder_server_tls.ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME


def test_constructor_rejects_keylog_context_without_creating_a_file(monkeypatch):
    context = _fake_context(monkeypatch)
    context.keylog_filename = "/synthetic/keylog-never-created"
    _error(lambda: FixedTLSListener("jira", context=context), "invalid_context")


def test_same_context_can_be_claimed_by_only_one_concurrent_constructor():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    gate = threading.Barrier(3)
    outcomes = []

    def construct():
        gate.wait()
        try:
            outcomes.append(FixedTLSListener("jira", context=context))
        except TLSListenerError as error:
            outcomes.append(error.code)

    first = threading.Thread(target=construct)
    second = threading.Thread(target=construct)
    first.start()
    second.start()
    gate.wait()
    first.join(1)
    second.join(1)
    assert sum(isinstance(result, FixedTLSListener) for result in outcomes) == 1
    assert outcomes.count("context_claimed") == 1


def test_open_binds_only_fixed_loopback_port_is_noninheritable_and_single_use(monkeypatch):
    context = _fake_context(monkeypatch)
    socket = _Socket()
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: socket)
    listener = FixedTLSListener("kubernetes", context=context)

    assert listener.open() is None
    profile = SERVICE_PROFILES["kubernetes"]
    assert socket.bind_address == (profile.bind_host, profile.port)
    assert socket.backlog == 4
    assert socket.inheritable == [False]
    _error(listener.open, "listener_closed")
    assert listener.close() == "closed"
    _error(listener.open, "listener_closed")


def test_bind_failure_closes_candidate_without_a_fallback(monkeypatch):
    context = _fake_context(monkeypatch)
    socket = _Socket(bind_error=OSError("occupied"))
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: socket)
    listener = FixedTLSListener("jira", context=context)

    _error(listener.open, "open_failed")
    assert socket.bind_address == ("127.0.0.1", 17441)
    assert socket.closed
    _error(listener.open, "listener_closed")


def test_interrupted_open_cleans_candidate_and_leaves_lifecycle_terminal(monkeypatch):
    context = _fake_context(monkeypatch)
    socket = _Socket()
    socket.set_inheritable = lambda _value: (_ for _ in ()).throw(KeyboardInterrupt())
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: socket)
    listener = FixedTLSListener("jira", context=context)

    with pytest.raises(KeyboardInterrupt):
        listener.open()
    assert socket.closed
    _error(listener.open, "listener_closed")


@pytest.mark.parametrize("timeout", [True, 0, -1, 10.1, 2**2000, math.nan, math.inf, "1"])
def test_accept_rejects_nonfinite_or_invalid_timeout_before_waiting(monkeypatch, timeout):
    context = _fake_context(monkeypatch)
    listener = FixedTLSListener("jira", context=context)
    _error(lambda: listener.accept(timeout=timeout), "invalid_timeout")


def test_accept_timeout_is_bounded_and_listener_remains_open(monkeypatch):
    context = _fake_context(monkeypatch)
    listener_socket = _Socket(accepted=TimeoutError())
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    times = iter((10, 10.1, 10.2, 10.95, 11))
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: next(times))
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(lambda: listener.accept(timeout=1), "deadline_expired")
    assert listener_socket.timeout is None
    assert listener_socket.timeout_history == pytest.approx([0.1, 0.1, 0.05, None])
    assert listener.close() == "closed"


def test_second_accept_fails_busy_without_waiting_for_the_first(monkeypatch):
    context = _fake_context(monkeypatch)
    entered = threading.Event()
    release = threading.Event()

    class BlockingSocket(_Socket):
        def accept(self):
            entered.set()
            assert release.wait(1)
            return self.accepted, ("127.0.0.1", 40000)

    listener_socket = BlockingSocket(accepted=_Connection())
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()
    accepted = []
    worker = threading.Thread(target=lambda: accepted.append(listener.accept()), daemon=True)
    worker.start()
    assert entered.wait(1)
    try:
        _error(listener.accept, "accept_busy")
    finally:
        release.set()
    worker.join(1)
    assert not worker.is_alive()
    accepted[0].close()
    assert listener.close() == "closed"


@pytest.mark.parametrize("times,code", [((10, math.nan), "clock_fault"), ((10, 9), "clock_fault"), ((10, 11), "deadline_expired")])
def test_accept_denies_nonfinite_regressing_or_expired_deadline(monkeypatch, times, code):
    context = _fake_context(monkeypatch)
    listener_socket = _Socket(accepted=_Connection())
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    observed = iter(times)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: next(observed))
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(lambda: listener.accept(timeout=1), code)
    assert listener.close() == "closed"


def test_handshake_failure_closes_wrapped_connection_and_listener_can_close(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection(handshake_error=ssl.SSLError("bad handshake"))
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, "handshake_failed")
    assert raw.closed
    assert raw.inheritable == [False, False]
    assert listener.close() == "closed"


def test_want_read_and_write_handshake_steps_poll_outside_lock_and_keep_one_deadline(monkeypatch):
    context = _fake_context(monkeypatch)

    class SteppedConnection(_Connection):
        def __init__(self):
            super().__init__()
            self.steps = [ssl.SSLWantReadError(), ssl.SSLWantWriteError(), None]

        def do_handshake(self):
            step = self.steps.pop(0)
            if step:
                raise step

    raw = SteppedConnection()
    listener_socket = _Socket(accepted=raw)
    selections = []
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(
        forwarder_server_tls.select,
        "select",
        lambda readable, writable, errors, timeout: selections.append((readable, writable, errors, timeout)) or (readable, writable, errors),
    )
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    secured = listener.accept(timeout=1)

    assert selections == [([raw], [], (), 0.1), ([], [raw], (), 0.1)]
    assert raw.timeout_history == [0.0, 0.0, 0.0, 1.0]
    secured.close()
    assert listener.close() == "closed"


def test_fatal_handshake_error_is_not_retried_through_readiness_poll(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection(handshake_error=ssl.SSLError("fatal"))
    listener_socket = _Socket(accepted=raw)
    selections = []
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(forwarder_server_tls.select, "select", lambda *args: selections.append(args))
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, "handshake_failed")
    assert selections == []


def test_handshake_readiness_poll_is_clipped_to_the_original_deadline(monkeypatch):
    context = _fake_context(monkeypatch)

    class WantReadConnection(_Connection):
        def do_handshake(self):
            raise ssl.SSLWantReadError()

    raw = WantReadConnection()
    listener_socket = _Socket(accepted=raw)
    times = iter((10, 10, 10.1, 10.2, 10.95, 10.96, 11))
    selections = []
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(
        forwarder_server_tls.select,
        "select",
        lambda _readable, _writable, _errors, timeout: selections.append(timeout) or ([], [], []),
    )
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(lambda: listener.accept(timeout=1), "deadline_expired")
    assert selections == pytest.approx([0.1, 0.04])


def test_raw_failure_before_wrap_closes_raw_connection(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection()
    raw.set_inheritable = lambda _value: (_ for _ in ()).throw(OSError("raw setup"))
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, "accept_failed")
    assert raw.closed
    assert listener.close() == "closed"


def test_distinct_wrapped_socket_owns_raw_cleanup_after_handshake_failure(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection()

    class Wrapped(_Connection):
        def __init__(self):
            super().__init__(handshake_error=ssl.SSLError("bad handshake"))

        def close(self):
            super().close()
            raw.close()

    wrapped = Wrapped()
    context.wrap_socket = lambda *_args, **_kwargs: wrapped
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, "handshake_failed")
    assert raw.inheritable == [False]
    assert wrapped.inheritable == [False]
    assert wrapped.closed and raw.closed


def test_failed_wrapped_close_retains_handle_for_retry_but_unknown_stays_sticky(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection()

    class Wrapped(_Connection):
        def __init__(self):
            super().__init__(handshake_error=ssl.SSLError("bad handshake"), close_error=OSError("close"))

        def close(self):
            super().close()
            raw.close()

    wrapped = Wrapped()
    context.wrap_socket = lambda *_args, **_kwargs: wrapped
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, "handshake_failed")
    wrapped.close_error = None
    assert listener.close() == "unknown"
    assert wrapped.closed and raw.closed
    assert listener.close() == "unknown"


def test_listener_close_never_touches_a_successfully_returned_connection(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection()
    wrapped = _Connection()
    context.wrap_socket = lambda *_args, **_kwargs: wrapped
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    returned = listener.accept()
    assert returned is wrapped
    assert listener.close() == "closed"
    assert not returned.closed
    returned.close()


def test_wrapped_connection_close_fault_after_failed_handshake_latches_unknown(monkeypatch):
    context = _fake_context(monkeypatch)
    raw = _Connection(
        handshake_error=ssl.SSLError("bad handshake"),
        close_error=KeyboardInterrupt(),
    )
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, "handshake_failed")
    _error(listener.accept, "listener_unknown")
    assert listener.close() == "unknown"


def test_close_during_handshake_returns_unknown_then_allows_cleanup_to_finish(monkeypatch):
    context = _fake_context(monkeypatch)
    entered = threading.Event()
    release = threading.Event()

    class WantReadHandshake(_Connection):
        def do_handshake(self):
            raise ssl.SSLWantReadError()

    raw = WantReadHandshake()
    listener_socket = _Socket(accepted=raw)
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)

    def block_for_readiness(*_args):
        entered.set()
        assert release.wait(1)
        return [], [], []

    monkeypatch.setattr(
        forwarder_server_tls.select,
        "select",
        block_for_readiness,
    )
    listener = FixedTLSListener("jira", context=context)
    listener.open()
    errors = []

    def accept_in_worker():
        try:
            listener.accept()
        except TLSListenerError as error:
            errors.append(error.code)

    worker = threading.Thread(target=accept_in_worker, daemon=True)
    worker.start()
    assert entered.wait(1)
    assert listener.close() == "unknown"
    release.set()
    worker.join(1)
    assert not worker.is_alive()
    assert errors == ["listener_closed"]
    assert listener.close() == "closed"


def test_close_fault_latches_unknown_without_hiding_ownership_failure(monkeypatch):
    context = _fake_context(monkeypatch)
    socket = _Socket()
    socket.close = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: socket)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    assert listener.close() == "unknown"
    assert listener.close() == "unknown"


@pytest.mark.parametrize("failure,expected", [("handshake", "handshake_failed"), ("raw", "accept_failed")])
def test_unexpected_timeout_restore_failure_latches_unknown_without_masking_setup_failure(
    monkeypatch, failure, expected
):
    context = _fake_context(monkeypatch)
    raw = _Connection(handshake_error=ssl.SSLError("bad handshake") if failure == "handshake" else None)
    if failure == "raw":
        raw.set_inheritable = lambda _value: (_ for _ in ()).throw(OSError("raw setup"))
    listener_socket = _Socket(accepted=raw)
    original_settimeout = listener_socket.settimeout

    def settimeout(value):
        if value is None:
            raise RuntimeError("restore failed")
        original_settimeout(value)

    listener_socket.settimeout = settimeout
    monkeypatch.setattr(forwarder_server_tls.socket, "socket", lambda *args: listener_socket)
    monkeypatch.setattr(forwarder_server_tls.time, "monotonic", lambda: 10.0)
    listener = FixedTLSListener("jira", context=context)
    listener.open()

    _error(listener.accept, expected)
    _error(listener.accept, "listener_unknown")
    assert listener.close() == "unknown"
