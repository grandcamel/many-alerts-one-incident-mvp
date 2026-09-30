"""Private pathname listener integration with synthetic control authentication."""

import hashlib
import hmac
import os
import queue
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_control as control_module
from grafana_jsm_sandbox.forwarder_control import ForwarderControl, authenticate_receiver
from grafana_jsm_sandbox.forwarder_control_protocol import recv_frame, send_frame
from grafana_jsm_sandbox.forwarder_leases import LeaseError, LeaseRegistry

SECRET = b"t" * 32
SCOPE = hashlib.sha256(b"synthetic-listener-scope").hexdigest()


@pytest.fixture
def control_environment():
    registry = LeaseRegistry(clock=lambda: 1000.0)
    control = ForwarderControl(registry, receiver_uid=os.geteuid(),
                               control_secret=SECRET, timeout=1.0)
    yield registry, control
    control.shutdown()


@pytest.fixture
def handlers():
    running = []

    def start(control, accepted=None):
        if accepted is None:
            client, accepted = socket.socketpair()
        else:
            client = None
        outcomes = queue.Queue()
        thread = threading.Thread(name="listener-control-test",
                                  target=lambda: outcomes.put(control.serve_connection(accepted)))
        thread.start()
        running.append((client, accepted, thread))
        return client, outcomes

    yield start
    for client, accepted, thread in running:
        if client is not None:
            client.close()
        try:
            accepted.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        accepted.close()
        thread.join(timeout=3)
        assert not thread.is_alive(), "accepted control handler did not finish"


def authenticate(client):
    return authenticate_receiver(client, control_secret=SECRET, forwarder_uid=os.geteuid(),
                                 receiver_boot_id="receiver-listener", timeout=1.0)


def active_grant(client):
    send_frame(client, {"op": "register", "seq": 1, "params": {
        "run_id": "listener-run", "attempt_id": "attempt-1", "service": "jira",
        "scope_digest": SCOPE, "expires_at": 1100.0,
    }}, timeout=1.0)
    reply = recv_frame(client, timeout=1.0)
    assert reply["ok"] is True, reply
    grant = reply["result"]
    send_frame(client, {"op": "activate", "seq": 2, "params": {
        "lease_id": grant["lease_id"], "launch_at": 1000.0,
    }}, timeout=1.0)
    assert recv_frame(client, timeout=1.0)["ok"] is True
    return grant


def test_pathname_control_shutdown_then_listener_cleanup(control_environment, handlers):
    from grafana_jsm_sandbox.forwarder_listener import PrivateControlListener

    registry, control = control_environment
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="maoi-") as temporary:
        parent = Path(temporary).resolve()
        os.chown(parent, -1, os.getegid())
        parent.chmod(0o710)
        listener = PrivateControlListener(parent, owner_uid=os.geteuid(),
                                          control_gid=os.getegid()).open()
        endpoint = Path(listener.endpoint)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(endpoint))
            accepted = listener.accept(timeout=0.5)
            assert accepted is not None
            _unused, outcomes = handlers(control, accepted)
            authenticate(client)
            grant = active_grant(client)
            assert registry.check(service="jira", sentinel=grant["sentinel"],
                                  generation=registry.generation, scope_digest=SCOPE).authorized
            control.shutdown()
            with pytest.raises(LeaseError, match="registry_held"):
                registry.check(service="jira", sentinel=grant["sentinel"],
                               generation=registry.generation, scope_digest=SCOPE)
            outcome = outcomes.get(timeout=3)
            assert outcome.authenticated is True
            assert outcome.closeout == "unknown"  # Held is not fabricated revoke success.
            assert listener.close().state == "removed"
            assert not endpoint.parent.exists()
            assert parent.stat().st_mode & 0o7777 == 0o710
        finally:
            client.close()
            control.shutdown()
            listener.close()


def test_shutdown_interrupts_all_slots_and_permanently_rejects_new_work(
    control_environment, handlers,
):
    registry, control = control_environment
    clients = []
    for _ in range(control_module.MAX_CONNECTIONS):
        client, outcomes = handlers(control)
        assert recv_frame(client, timeout=1.0)["op"] == "challenge"
        clients.append((client, outcomes))
    control.shutdown()
    # Test the permanent gate before waiting for old slots to finish/release.
    _late, rejected = handlers(control)
    result = rejected.get(timeout=2)
    assert result.reason == "control_closed"
    assert result.authenticated is False
    for _client, outcomes in clients:
        assert outcomes.get(timeout=3).authenticated is False
    control.shutdown()
    assert registry.snapshot()["registry_state"] == "held"
    with pytest.raises(LeaseError, match="registry_held"):
        registry.handshake(receiver_boot_id="new-boot", generation=registry.generation)


def test_shutdown_between_valid_proof_and_owner_install_prevents_handshake(
    control_environment, handlers, monkeypatch,
):
    registry, control = control_environment
    proof_entered, release_proof = threading.Event(), threading.Event()
    original_proof = control_module._proof

    def delayed_proof(secret, role, generation, nonce, boot):
        result = original_proof(secret, role, generation, nonce, boot)
        if role == "receiver" and threading.current_thread().name == "listener-control-test":
            proof_entered.set()
            assert release_proof.wait(timeout=3)
        return result

    monkeypatch.setattr(control_module, "_proof", delayed_proof)
    client, outcomes = handlers(control)
    challenge = recv_frame(client, timeout=1.0)
    body = f"receiver\0{challenge['generation']}\0{challenge['challenge']}\0receiver-race"
    send_frame(client, {"op": "hello", "receiver_boot_id": "receiver-race",
                        "proof": hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()})
    try:
        assert proof_entered.wait(timeout=2)
        control.shutdown()
        assert registry.snapshot()["registry_state"] == "held"
    finally:
        release_proof.set()
    outcome = outcomes.get(timeout=3)
    assert outcome.reason == "control_closed"
    assert outcome.authenticated is False
    assert outcome.commands == 0
    assert registry.snapshot()["receiver_boot_id"] is None


def test_shutdown_holds_before_socket_io_without_holding_owner_lock(
    control_environment, handlers, monkeypatch,
):
    registry, control = control_environment
    client, outcome = handlers(control)
    recv_frame(client, timeout=1.0)
    closing_entered, release_close = threading.Event(), threading.Event()
    original_close = control_module._close

    def delayed_close(sock):
        if threading.current_thread().name == "control-shutdown-test":
            closing_entered.set()
            assert release_close.wait(timeout=3)
        return original_close(sock)

    monkeypatch.setattr(control_module, "_close", delayed_close)
    stop = threading.Thread(name="control-shutdown-test", target=control.shutdown)
    stop.start()
    try:
        assert closing_entered.wait(timeout=2)
        assert registry.snapshot()["registry_state"] == "held"
        _new, rejection = handlers(control)
        # Admission can take the owner lock while the old close is paused.
        assert rejection.get(timeout=1).reason == "control_closed"
    finally:
        release_close.set()
        stop.join(timeout=3)
    assert not stop.is_alive()
    assert outcome.get(timeout=3).authenticated is False
