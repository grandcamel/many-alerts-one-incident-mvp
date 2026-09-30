"""Lifecycle and failure tests for bounded private-control supervision.

These use only same-UID temporary Unix sockets and synthetic controllers.  They
exercise descriptor and thread ownership; authentication integration lives in
the separate control-service integration tests.
"""

from __future__ import annotations

import os
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_supervisor as supervisor
from grafana_jsm_sandbox.forwarder_control import ForwarderControl
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_listener import (
    ListenerCloseout,
    ListenerError,
    PrivateControlListener,
)
from grafana_jsm_sandbox.forwarder_supervisor import ControlService, ServiceError


@pytest.fixture
def runtime_parent():
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="maoi-") as temporary:
        parent = Path(temporary).resolve()
        os.chown(parent, -1, os.getegid())
        parent.chmod(0o710)
        yield parent


@pytest.fixture(autouse=True)
def cleanup_created_services() -> Iterator[None]:
    """Ensure an assertion cannot leave a service thread in this test process."""
    initial = len(_CREATED_SERVICES)
    yield
    for service in _CREATED_SERVICES[initial:]:
        try:
            service.stop(timeout=2)
        except ServiceError:
            pass


_CREATED_SERVICES = []


def _service(parent):
    listener = PrivateControlListener(parent, owner_uid=os.geteuid(), control_gid=os.getegid())
    control = ForwarderControl(
        LeaseRegistry(clock=lambda: 1000.0), receiver_uid=os.geteuid(),
        control_secret=b"s" * 32, timeout=1.0,
    )
    service = ControlService(listener, control)
    _CREATED_SERVICES.append(service)
    return service, listener, control


def _service_error(call, code):
    with pytest.raises(ServiceError) as raised:
        call()
    assert raised.value.code == code
    assert str(raised.value) == code


def _connect(service):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    client.connect(service.endpoint)
    return client


@pytest.mark.parametrize(
    "timeout", [0, -1, True, float("nan"), float("inf"), 10.01, 2**1000, "bad"],
)
def test_stop_rejects_invalid_timeout_before_terminal_shutdown(runtime_parent, timeout):
    service, _listener, _control = _service(runtime_parent)
    _service_error(lambda: service.stop(timeout=timeout), "invalid_timeout")
    assert service.start() is service
    assert service.stop().state == "stopped"


def test_terminal_lifecycle_and_endpoint_are_fixed(runtime_parent):
    service, _listener, _control = _service(runtime_parent)
    _service_error(lambda: service.endpoint, "not_running")

    closeout = service.stop()
    assert closeout.state == "stopped"
    assert closeout.listener_state == "not_open"
    assert closeout.threads_alive == 0
    _service_error(service.start, "invalid_lifecycle")
    _service_error(lambda: service.endpoint, "not_running")


def test_constructor_rejects_unowned_or_reused_dependencies(runtime_parent):
    service, listener, control = _service(runtime_parent)
    _service_error(lambda: ControlService(object(), control), "invalid_listener")
    _service_error(lambda: ControlService(listener, object()), "invalid_control")

    listener.open()
    try:
        _service_error(lambda: ControlService(listener, control), "listener_not_fresh")
    finally:
        listener.close()
    assert service.stop().state == "stopped"


def test_accept_failure_holds_authority_and_reports_only_fixed_diagnostics(runtime_parent, monkeypatch):
    service, listener, control = _service(runtime_parent)
    attempted = threading.Event()

    def fail_accept(*, timeout):
        attempted.set()
        raise ListenerError("injected detail must never escape")

    monkeypatch.setattr(listener, "accept", fail_accept)
    service.start()
    assert attempted.wait(1)
    closeout = service.stop()
    assert closeout.state == "unknown"
    assert closeout.reason == "fatal_failure"
    assert "injected" not in repr(closeout)
    assert control._closed is True


def test_worker_baseexception_causes_fatal_shutdown_and_closes_client(runtime_parent, monkeypatch):
    service, _listener, control = _service(runtime_parent)
    entered = threading.Event()

    def explode(_sock):
        entered.set()
        raise KeyboardInterrupt("injected nonstandard failure")

    monkeypatch.setattr(control, "serve_connection", explode)
    service.start()
    client = _connect(service)
    try:
        assert entered.wait(1)
        assert client.recv(1) == b""
        closeout = service.stop()
        assert closeout.state == "unknown"
        assert closeout.reason == "fatal_failure"
        assert "nonstandard" not in repr(closeout)
    finally:
        client.close()


def test_four_occupied_handlers_reject_an_excess_client_without_a_fifth_worker(runtime_parent, monkeypatch):
    service, _listener, control = _service(runtime_parent)
    entered = threading.Barrier(supervisor.MAX_HANDLERS + 1, timeout=2)
    release = threading.Event()

    def occupy(_sock):
        entered.wait()
        assert release.wait(2)

    monkeypatch.setattr(control, "serve_connection", occupy)
    service.start()
    clients = [_connect(service) for _ in range(supervisor.MAX_HANDLERS)]
    excess = None
    try:
        entered.wait()
        excess = _connect(service)
        assert excess.recv(1) == b""
        with service._lock:
            assert len(service._workers) == supervisor.MAX_HANDLERS
        release.set()
        assert service.stop(timeout=2).state == "stopped"
    finally:
        release.set()
        if excess is not None:
            excess.close()
        for client in clients:
            client.close()


def test_worker_start_failure_closes_accepted_socket_and_enters_fatal_shutdown(runtime_parent, monkeypatch):
    service, _listener, _control = _service(runtime_parent)
    real_thread = threading.Thread
    creations = 0

    class FailingStart:
        def start(self):
            raise RuntimeError("thread-start detail")

        def is_alive(self):
            return False

        def join(self, _timeout):
            raise AssertionError("unstarted worker must not be joined")

    def thread_factory(*args, **kwargs):
        nonlocal creations
        creations += 1
        if creations == 1:
            return real_thread(*args, **kwargs)
        return FailingStart()

    monkeypatch.setattr(supervisor.threading, "Thread", thread_factory)
    service.start()
    client = _connect(service)
    try:
        assert client.recv(1) == b""
        closeout = service.stop()
        assert closeout.state == "unknown"
        assert closeout.reason == "fatal_failure"
        assert "thread-start" not in repr(closeout)
    finally:
        client.close()


def test_accept_thread_start_failure_is_terminal_and_cleans_the_endpoint(runtime_parent, monkeypatch):
    service, _listener, control = _service(runtime_parent)

    class FailingStart:
        def start(self):
            raise RuntimeError("accept-start detail")

        def is_alive(self):
            return False

        def join(self, _timeout):
            raise AssertionError("unstarted accept thread must not be joined")

    monkeypatch.setattr(supervisor.threading, "Thread", lambda *_args, **_kwargs: FailingStart())
    _service_error(service.start, "start_failed")
    closeout = service.stop()
    assert closeout.state == "stopped"
    assert closeout.reason == "start_failed"
    assert closeout.listener_state == "removed"
    assert control._closed is True


def test_stop_during_accept_handoff_closes_the_returned_descriptor(runtime_parent, monkeypatch):
    service, listener, _control = _service(runtime_parent)
    original_accept = listener.accept
    accepted = threading.Event()
    release_accept = threading.Event()
    result = []

    def delayed_accept(*, timeout):
        connection = original_accept(timeout=timeout)
        if connection is not None:
            accepted.set()
            assert release_accept.wait(2)
        return connection

    monkeypatch.setattr(listener, "accept", delayed_accept)
    service.start()
    client = _connect(service)

    def stop():
        result.append(service.stop(timeout=2))

    stopper = threading.Thread(target=stop)
    try:
        assert accepted.wait(1)
        stopper.start()
        release_accept.set()
        stopper.join(3)
        assert not stopper.is_alive()
        assert result[0].state == "stopped"
        assert client.recv(1) == b""
    finally:
        release_accept.set()
        stopper.join(3)
        client.close()


def test_stop_during_open_never_claims_an_unopened_listener_clean(runtime_parent, monkeypatch):
    service, listener, _control = _service(runtime_parent)
    real_open = listener.open
    opened = threading.Event()
    release_open = threading.Event()
    start_errors = []

    def delayed_open():
        opened.set()
        assert release_open.wait(2)
        return real_open()

    monkeypatch.setattr(listener, "open", delayed_open)

    def start():
        try:
            service.start()
        except ServiceError as error:
            start_errors.append(error.code)

    starter = threading.Thread(target=start)
    starter.start()
    assert opened.wait(1)
    first = service.stop(timeout=0.01)
    assert first.state == "unknown"
    assert first.listener_state == "unknown"
    release_open.set()
    starter.join(2)
    assert not starter.is_alive()
    assert start_errors == ["start_failed"]
    second = service.stop(timeout=2)
    assert second.state == "stopped"
    assert second.listener_state == "removed"


def test_stop_during_handler_thread_start_keeps_completion_unknown_until_start_returns(
    runtime_parent, monkeypatch,
):
    service, _listener, _control = _service(runtime_parent)
    real_thread = threading.Thread
    creations = 0
    start_entered = threading.Event()
    release_start = threading.Event()

    class DelayedStart:
        def start(self):
            start_entered.set()
            assert release_start.wait(2)

        def is_alive(self):
            return False

        def join(self, _timeout):
            return None

    def thread_factory(*args, **kwargs):
        nonlocal creations
        creations += 1
        if creations == 1:
            return real_thread(*args, **kwargs)
        return DelayedStart()

    monkeypatch.setattr(supervisor.threading, "Thread", thread_factory)
    service.start()
    client = _connect(service)
    try:
        assert start_entered.wait(1)
        first = service.stop(timeout=0.01)
        assert first.state == "unknown"
        release_start.set()
        second = service.stop(timeout=2)
        assert second.state == "stopped"
        assert second.threads_alive == 0
    finally:
        release_start.set()
        client.close()


def test_unknown_listener_closeout_is_never_upgraded_by_later_thread_completion(runtime_parent, monkeypatch):
    service, listener, control = _service(runtime_parent)
    entered = threading.Event()
    release = threading.Event()

    def occupy(_sock):
        entered.set()
        assert release.wait(2)

    monkeypatch.setattr(control, "serve_connection", occupy)
    original_close = listener.close
    monkeypatch.setattr(listener, "close", lambda: ListenerCloseout("unknown", "cleanup_failed"))
    service.start()
    client = _connect(service)
    try:
        assert entered.wait(1)
        first = service.stop(timeout=0.01)
        assert first.state == "unknown"
        assert first.listener_state == "unknown"
        assert first.threads_alive >= 1
        release.set()
        second = service.stop(timeout=2)
        assert second.state == "unknown"
        assert second.listener_state == "unknown"
        assert second.threads_alive == 0
    finally:
        release.set()
        client.close()
        monkeypatch.setattr(listener, "close", original_close)
        original_close()


def test_concurrent_stops_share_terminal_cleanup_and_observe_late_worker_completion(runtime_parent, monkeypatch):
    service, _listener, control = _service(runtime_parent)
    entered = threading.Event()
    release = threading.Event()
    shutdown_entered = threading.Event()
    shutdown_release = threading.Event()
    shutdown_calls = 0
    shutdown_lock = threading.Lock()
    results = []

    def occupy(_sock):
        entered.set()
        assert release.wait(2)

    original_shutdown = control.shutdown

    def observed_shutdown():
        nonlocal shutdown_calls
        with shutdown_lock:
            shutdown_calls += 1
        shutdown_entered.set()
        assert shutdown_release.wait(2)
        original_shutdown()

    monkeypatch.setattr(control, "serve_connection", occupy)
    monkeypatch.setattr(control, "shutdown", observed_shutdown)
    service.start()
    client = _connect(service)
    assert entered.wait(1)

    def stop():
        results.append(service.stop(timeout=2))

    first = threading.Thread(target=stop)
    second = threading.Thread(target=stop)
    first.start()
    assert shutdown_entered.wait(1)
    second.start()
    shutdown_release.set()
    release.set()
    first.join(3)
    second.join(3)
    try:
        assert not first.is_alive()
        assert not second.is_alive()
        assert len(results) == 2
        assert all(result.state in {"stopped", "unknown"} for result in results)
        assert shutdown_calls >= 1
        final = service.stop(timeout=2)
        assert final.state == "stopped"
        assert final.threads_alive == 0
    finally:
        release.set()
        client.close()
