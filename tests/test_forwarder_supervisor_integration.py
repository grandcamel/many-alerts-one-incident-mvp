"""Real local control-service sockets; synthetic secrets and same-UID identity."""

import hashlib
import os
import queue
import socket
import tempfile
import threading
from itertools import pairwise
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_supervisor as supervisor
from grafana_jsm_sandbox.forwarder_control import ForwarderControl, authenticate_receiver
from grafana_jsm_sandbox.forwarder_control_protocol import recv_frame, send_frame
from grafana_jsm_sandbox.forwarder_leases import LeaseError, LeaseRegistry
from grafana_jsm_sandbox.forwarder_listener import PrivateControlListener
from grafana_jsm_sandbox.forwarder_supervisor import ControlService, ServiceError

SECRET = b"s" * 32
SCOPE = hashlib.sha256(b"supervisor-integration-scope").hexdigest()


@pytest.fixture
def environment():
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="maoi-") as directory:
        parent = Path(directory).resolve()
        os.chown(parent, -1, os.getegid())
        parent.chmod(0o710)
        registry = LeaseRegistry(clock=lambda: 1000.0)
        controller = ForwarderControl(registry, receiver_uid=os.geteuid(),
                                      control_secret=SECRET, timeout=2.0)
        listener = PrivateControlListener(parent, owner_uid=os.geteuid(),
                                          control_gid=os.getegid())
        service = ControlService(listener, controller)
        yield registry, controller, listener, service
        service.stop(timeout=3.0)


def connect(service):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2.0)
    try:
        client.connect(service.endpoint)
        return client
    except BaseException:
        client.close()
        raise


def authenticate(client):
    return authenticate_receiver(client, control_secret=SECRET, forwarder_uid=os.geteuid(),
                                 receiver_boot_id="supervisor-receiver", timeout=2.0)


def register_and_activate(client):
    send_frame(client, {"op": "register", "seq": 1, "params": {
        "run_id": "supervisor-run", "attempt_id": "attempt-1", "service": "jira",
        "scope_digest": SCOPE, "expires_at": 1100.0,
    }}, timeout=2.0)
    reply = recv_frame(client, timeout=2.0)
    assert reply["ok"] is True
    grant = reply["result"]
    send_frame(client, {"op": "activate", "seq": 2, "params": {
        "lease_id": grant["lease_id"], "launch_at": 1000.0,
    }}, timeout=2.0)
    assert recv_frame(client, timeout=2.0)["ok"] is True
    return grant


def test_managed_service_authenticates_holds_and_observes_all_threads(environment):
    registry, _controller, _listener, service = environment
    assert service.start() is service
    endpoint = Path(service.endpoint)
    with connect(service) as client:
        authentication = authenticate(client)
        assert authentication.generation == registry.generation
        grant = register_and_activate(client)
        assert registry.check(service="jira", sentinel=grant["sentinel"],
                              generation=registry.generation, scope_digest=SCOPE).authorized
        closeout = service.stop(timeout=3.0)
        assert closeout.state == "stopped"
        assert closeout.listener_state == "removed"
        assert closeout.threads_alive == 0
        with pytest.raises(LeaseError, match="registry_held"):
            registry.check(service="jira", sentinel=grant["sentinel"],
                           generation=registry.generation, scope_digest=SCOPE)
        assert client.recv(1) == b""
    assert not endpoint.parent.exists()
    assert service.stop(timeout=3.0) == closeout
    with pytest.raises(ServiceError):
        service.start()
    with pytest.raises(ServiceError):
        _ = service.endpoint


def test_rejected_peer_does_not_poison_service_for_an_authenticated_peer(environment):
    registry, _controller, _listener, service = environment
    service.start()
    with connect(service) as client:
        assert recv_frame(client, timeout=2.0)["op"] == "challenge"
        send_frame(client, {"op": "hello", "receiver_boot_id": "untrusted-peer",
                            "proof": "0" * 64}, timeout=2.0)
        assert recv_frame(client, timeout=2.0)["error"] == "authentication_failed"
        assert client.recv(1) == b""
    with connect(service) as client:
        authenticate(client)
        grant = register_and_activate(client)
        assert registry.check(service="jira", sentinel=grant["sentinel"],
                              generation=registry.generation, scope_digest=SCOPE).authorized
        closeout = service.stop(timeout=3.0)
        assert closeout.state == "stopped"
        assert closeout.threads_alive == 0


def test_service_holds_active_authority_before_listener_removal(environment, monkeypatch):
    registry, _controller, listener, service = environment
    service.start()
    observed = []
    original_close = listener.close

    def close_after_hold():
        observed.append(registry.snapshot()["registry_state"])
        return original_close()

    monkeypatch.setattr(listener, "close", close_after_hold)
    with connect(service) as client:
        authenticate(client)
        register_and_activate(client)
        assert service.stop(timeout=3.0).state == "stopped"
    assert observed == ["held"]


def test_owned_handler_stop_never_claims_its_own_thread_has_exited(environment, monkeypatch):
    _registry, controller, _listener, service = environment
    outcomes = queue.Queue()

    def stop_from_handler(_sock):
        outcomes.put(service.stop(timeout=0.2))

    monkeypatch.setattr(controller, "serve_connection", stop_from_handler)
    service.start()
    with connect(service):
        observed = outcomes.get(timeout=3.0)
    assert observed.state == "unknown"
    assert observed.threads_alive >= 1
    assert service.stop(timeout=3.0).state == "stopped"


def test_handler_joins_share_one_decreasing_deadline(environment, monkeypatch):
    _registry, controller, _listener, service = environment
    entered = threading.Barrier(supervisor.MAX_HANDLERS + 1, timeout=3.0)
    release = threading.Event()

    def occupy(_sock):
        entered.wait()
        assert release.wait(timeout=3.0)

    monkeypatch.setattr(controller, "serve_connection", occupy)
    service.start()
    clients = []
    try:
        for _ in range(supervisor.MAX_HANDLERS):
            clients.append(connect(service))
        entered.wait()
        original_join = threading.Thread.join
        budgets = []
        ticks = 0

        def clock():
            nonlocal ticks
            ticks += 1
            return 1000.0 + ticks * 0.01

        def observe_join(thread, timeout=None):
            if thread.name == "forwarder-control-handler":
                budgets.append(timeout)
                return  # Keep the real blocked thread alive for the next observation.
            return original_join(thread, timeout)

        with monkeypatch.context() as scoped:
            scoped.setattr(supervisor.time, "monotonic", clock)
            scoped.setattr(threading.Thread, "join", observe_join)
            observed = service.stop(timeout=0.2)
        assert observed.state == "unknown"
        assert observed.threads_alive >= supervisor.MAX_HANDLERS
        assert len(budgets) == supervisor.MAX_HANDLERS
        assert all(0 < remaining <= 0.2 for remaining in budgets)
        assert all(later < earlier for earlier, later in pairwise(budgets))
    finally:
        release.set()
        for client in clients:
            client.close()
        assert service.stop(timeout=3.0).threads_alive == 0
