"""Control authentication and lease lifecycle over actual local Unix sockets.

Secrets are synthetic, and peer UID observation is not deployment isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import queue
import socket
import struct
import threading

import pytest

from grafana_jsm_sandbox import forwarder_control as module
from grafana_jsm_sandbox.forwarder_control import (
    ForwarderControl,
    authenticate_receiver,
    peer_uid,
)
from grafana_jsm_sandbox.forwarder_control_protocol import (
    ControlProtocolError,
    recv_frame,
    send_frame,
)
from grafana_jsm_sandbox.forwarder_leases import LeaseError, LeaseRegistry

SECRET = b"s" * 32
SCOPE = hashlib.sha256(b"synthetic-scope").hexdigest()
TEST_TIMEOUT = 2.0


class Clock:
    value = 1000.0

    def __call__(self):
        return self.value


@pytest.fixture
def environment():
    clock = Clock()
    registry = LeaseRegistry(clock)
    control = ForwarderControl(registry, receiver_uid=os.geteuid(),
                               control_secret=SECRET, timeout=TEST_TIMEOUT)
    return clock, registry, control


@pytest.fixture
def start():
    running = []

    def launch(control):
        client, server = socket.socketpair()
        outcomes = queue.Queue()
        worker = threading.Thread(target=lambda: outcomes.put(control.serve_connection(server)))
        worker.start()
        running.append((client, worker))
        return client, outcomes

    yield launch
    for client, worker in running:
        client.close()
        worker.join(timeout=3)
        assert not worker.is_alive(), "control connection failed to terminate"


def hello(client, boot="receiver-a", secret=SECRET):
    return authenticate_receiver(client, control_secret=secret, forwarder_uid=os.geteuid(),
                                 receiver_boot_id=boot, timeout=TEST_TIMEOUT)


def command(client, op, seq, params):
    send_frame(client, {"op": op, "seq": seq, "params": params}, timeout=TEST_TIMEOUT)
    return recv_frame(client, timeout=TEST_TIMEOUT)


def registration(client, seq=1, run="run-a"):
    result = command(client, "register", seq, {
        "run_id": run, "attempt_id": "attempt-a", "service": "jira",
        "scope_digest": SCOPE, "expires_at": 1100.0,
    })
    assert result["ok"] is True
    return result["result"]


def allowed(registry, grant):
    return registry.check(service="jira", sentinel=grant["sentinel"],
                          generation=registry.generation, scope_digest=SCOPE).authorized


def test_actual_unix_peer_uid_and_non_unix_rejection():
    left, right = socket.socketpair()
    try:
        assert peer_uid(left) == os.geteuid()
        assert peer_uid(right) == os.geteuid()
    finally:
        left.close()
        right.close()
    with socket.socket() as internet_socket, pytest.raises(
        ControlProtocolError, match="peer_identity_unavailable"
    ):
        peer_uid(internet_socket)


def test_mutual_authentication_registration_activation_heartbeat_and_eof(environment, start):
    _clock, registry, control = environment
    client, outcomes = start(control)
    authenticated = hello(client)
    assert authenticated.generation == registry.generation
    grant = registration(client)
    assert grant["receiver_boot_id"] == "receiver-a"
    assert allowed(registry, grant) is False
    receipt = command(client, "activate", 2, {"lease_id": grant["lease_id"], "launch_at": 1000.0})
    assert receipt["result"]["state"] == "active"
    assert allowed(registry, grant) is True
    assert command(client, "heartbeat", 3, {})["ok"] is True
    client.close()
    outcome = outcomes.get(timeout=2)
    assert (outcome.reason, outcome.authenticated, outcome.commands, outcome.closeout) == (
        "eof", True, 3, "revoked")
    assert allowed(registry, grant) is False
    assert SECRET.hex() not in repr(outcome)
    assert grant["sentinel"] not in repr(outcome)
    assert grant["sentinel"] not in repr(registry.snapshot())


def test_revoke_command_and_replayed_sequence_terminate_authority(environment, start):
    _clock, registry, control = environment
    client, outcomes = start(control)
    hello(client)
    grant = registration(client)
    assert command(client, "revoke", 2, {
        "lease_id": grant["lease_id"], "reason": "cancelled",
    })["result"]["state"] == "revoked"
    error = command(client, "heartbeat", 2, {})
    assert error["error"] == "invalid_sequence"
    assert outcomes.get(timeout=2).closeout == "revoked"
    assert allowed(registry, grant) is False


def test_bad_secret_cannot_displace_existing_owner(environment, start):
    _clock, registry, control = environment
    owner, owner_outcomes = start(control)
    hello(owner)
    grant = registration(owner)
    command(owner, "activate", 2, {"lease_id": grant["lease_id"], "launch_at": 1000.0})
    intruder, rejected = start(control)
    with pytest.raises(ControlProtocolError):
        hello(intruder, boot="intruder", secret=b"z" * 32)
    outcome = rejected.get(timeout=2)
    assert outcome.reason == "authentication_failed"
    assert outcome.authenticated is False
    assert outcome.closeout == "not_owner"
    assert allowed(registry, grant) is True
    assert command(owner, "heartbeat", 3, {})["ok"] is True
    owner.close()
    assert owner_outcomes.get(timeout=2).closeout == "revoked"


@pytest.mark.parametrize("replacement_boot", ["receiver-a", "receiver-b"])
def test_authenticated_replacement_revokes_old_but_old_finalizer_spares_new(
    environment, start, replacement_boot, monkeypatch,
):
    _clock, registry, control = environment
    old, old_outcomes = start(control)
    hello(old)
    old_grant = registration(old)
    command(old, "activate", 2, {"lease_id": old_grant["lease_id"], "launch_at": 1000.0})
    old_owner = control._owner
    finalizer_entered, release_finalizer = threading.Event(), threading.Event()
    original_release = control._release_owner

    def delayed_finalizer(owner):
        if owner is old_owner:
            finalizer_entered.set()
            assert release_finalizer.wait(timeout=3), "finalizer barrier was not released"
        return original_release(owner)

    monkeypatch.setattr(control, "_release_owner", delayed_finalizer)
    old.close()
    try:
        # Pause old cleanup before its owner-identity check. No replacement
        # session exists yet, so this coordination cannot consume its idle limit.
        assert finalizer_entered.wait(timeout=2)
        replacement, new_outcomes = start(control)
        hello(replacement, replacement_boot)
        fresh = registration(replacement, run="run-b")
        command(replacement, "activate", 2, {"lease_id": fresh["lease_id"], "launch_at": 1000.0})
    finally:
        release_finalizer.set()
    old_result = old_outcomes.get(timeout=2)
    assert old_result.closeout == "not_owner"
    assert allowed(registry, old_grant) is False
    assert allowed(registry, fresh) is True
    heartbeat = command(replacement, "heartbeat", 3, {})
    assert heartbeat["ok"] is True, heartbeat
    replacement.close()
    assert new_outcomes.get(timeout=2).closeout == "revoked"


def test_hello_proof_cannot_replay_on_fresh_challenge(environment, start):
    _clock, registry, control = environment
    first, first_outcomes = start(control)
    challenge = recv_frame(first, timeout=0.5)
    message = f"receiver\0{registry.generation}\0{challenge['challenge']}\0receiver-a"
    request = {"op": "hello", "receiver_boot_id": "receiver-a",
               "proof": hmac.new(SECRET, message.encode(), hashlib.sha256).hexdigest()}
    send_frame(first, request)
    assert recv_frame(first)["ok"] is True
    first.close()
    first_outcomes.get(timeout=2)
    second, second_outcomes = start(control)
    fresh = recv_frame(second)
    assert fresh["challenge"] != challenge["challenge"]
    send_frame(second, request)
    assert recv_frame(second)["error"] == "authentication_failed"
    assert second_outcomes.get(timeout=2).authenticated is False
    assert registry.snapshot()["live_leases"] == 0


@pytest.mark.parametrize("op,seq,params,code", [
    ("heartbeat", True, {}, "invalid_sequence"),
    ("heartbeat", 2, {}, "invalid_sequence"),
    ("check", 1, {}, "unknown_operation"),
    ("heartbeat", 1, {"generation": "forged"}, "invalid_schema"),
    ("heartbeat", 1, {"receiver_boot_id": "forged"}, "invalid_schema"),
    ("register", 1, {}, "invalid_schema"),
    ("register", 1, {"run_id": "r", "attempt_id": "a", "service": "jira",
                      "scope_digest": SCOPE, "expires_at": True}, "invalid_expiry"),
])
def test_bad_commands_close_authenticated_session_without_grants(
    environment, start, op, seq, params, code,
):
    _clock, registry, control = environment
    client, outcomes = start(control)
    hello(client)
    assert command(client, op, seq, params)["error"] == code
    assert outcomes.get(timeout=2).closeout == "revoked"
    assert registry.snapshot()["retained_records"] == 0


def test_wrong_receiver_uid_denies_before_challenge_or_registry_mutation(environment, start):
    _clock, registry, _control = environment
    control = ForwarderControl(registry, receiver_uid=os.geteuid() + 1,
                               control_secret=SECRET, timeout=0.5)
    client, outcomes = start(control)
    assert recv_frame(client)["error"] == "peer_uid_mismatch"
    assert outcomes.get(timeout=2).authenticated is False
    assert registry.snapshot()["receiver_boot_id"] is None


def test_receiver_checks_forwarder_uid_before_sending_authentication(environment, start):
    _clock, registry, control = environment
    client, outcomes = start(control)
    with pytest.raises(ControlProtocolError, match="peer_uid_mismatch"):
        authenticate_receiver(client, control_secret=SECRET, forwarder_uid=os.geteuid() + 1,
                              receiver_boot_id="receiver-a")
    assert outcomes.get(timeout=2).authenticated is False
    assert registry.snapshot()["receiver_boot_id"] is None


def test_unsupported_peer_api_fails_closed(environment, start, monkeypatch):
    _clock, registry, control = environment
    monkeypatch.setattr(module.sys, "platform", "unsupported")
    client, outcomes = start(control)
    assert recv_frame(client)["error"] == "peer_identity_unavailable"
    assert outcomes.get(timeout=2).authenticated is False
    assert registry.snapshot()["receiver_boot_id"] is None


def test_authenticated_timeout_and_partial_frame_revoke_grants(environment, start):
    _clock, registry, _control = environment
    control = ForwarderControl(registry, receiver_uid=os.geteuid(),
                               control_secret=SECRET, timeout=0.05)
    client, outcomes = start(control)
    hello(client)
    grant = registration(client)
    command(client, "activate", 2, {"lease_id": grant["lease_id"], "launch_at": 1000.0})
    client.sendall(struct.pack("!I", 100) + b'{"op":')
    result = outcomes.get(timeout=2)
    assert result.reason == "timeout"
    assert result.closeout == "revoked"
    assert allowed(registry, grant) is False


def test_failed_closeout_holds_registry_without_clock_reconstruction(
    environment, start, monkeypatch,
):
    _clock, registry, control = environment
    client, outcomes = start(control)
    hello(client)
    grant = registration(client)
    command(client, "activate", 2, {"lease_id": grant["lease_id"], "launch_at": 1000.0})

    def failed_disconnect(**_kwargs):
        raise RuntimeError("private implementation failure")

    monkeypatch.setattr(registry, "disconnect", failed_disconnect)
    client.close()
    result = outcomes.get(timeout=2)
    assert result.closeout == "unknown"
    assert "private" not in repr(result)
    assert registry.snapshot()["registry_state"] == "held"
    with pytest.raises(LeaseError, match="registry_held"):
        allowed(registry, grant)


def test_response_write_failure_after_registration_revokes_new_grant(
    environment, start, monkeypatch,
):
    _clock, registry, control = environment
    client, outcomes = start(control)
    hello(client)
    original_send = module.send_frame

    def fail_register_reply(sock, payload, **kwargs):
        if payload.get("op") == "register" and payload.get("ok") is True:
            raise ControlProtocolError("write_failure")
        if payload.get("ok") is False:
            # A diagnostic write may block: authority must already be gone.
            assert registry.snapshot()["live_leases"] == 0
        return original_send(sock, payload, **kwargs)

    monkeypatch.setattr(module, "send_frame", fail_register_reply)
    reply = command(client, "register", 1, {
        "run_id": "r", "attempt_id": "a", "service": "jira",
        "scope_digest": SCOPE, "expires_at": 1100.0,
    })
    assert reply["error"] == "write_failure"
    assert outcomes.get(timeout=2).closeout == "revoked"
    snapshot = registry.snapshot()
    assert snapshot["retained_records"] == 1
    assert snapshot["live_leases"] == 0


def test_failed_replacement_closeout_holds_old_authority(environment, start, monkeypatch):
    _clock, registry, control = environment
    owner, old_outcomes = start(control)
    hello(owner)
    grant = registration(owner)
    command(owner, "activate", 2, {"lease_id": grant["lease_id"], "launch_at": 1000.0})

    def failed_disconnect(**_kwargs):
        raise RuntimeError("uncertain closeout")

    monkeypatch.setattr(registry, "disconnect", failed_disconnect)
    replacement, new_outcomes = start(control)
    with pytest.raises(ControlProtocolError):
        hello(replacement, "receiver-b")
    assert new_outcomes.get(timeout=2).authenticated is False
    with pytest.raises(LeaseError, match="registry_held"):
        allowed(registry, grant)
    owner.close()
    assert old_outcomes.get(timeout=2).closeout == "unknown"


def test_connection_capacity_is_bounded_and_released(environment, start):
    _clock, registry, control = environment
    parked = []
    for _ in range(module.MAX_CONNECTIONS):
        client, outcome = start(control)
        assert recv_frame(client, timeout=0.5)["op"] == "challenge"
        parked.append((client, outcome))
    _rejected, rejected_outcomes = start(control)
    result = rejected_outcomes.get(timeout=2)
    assert result.reason == "connection_capacity"
    assert result.authenticated is False
    assert registry.snapshot()["receiver_boot_id"] is None
    parked[0][0].close()
    parked[0][1].get(timeout=2)
    admitted, admitted_outcomes = start(control)
    assert hello(admitted).receiver_boot_id == "receiver-a"
    # Failures of the other unauthenticated connections cannot disconnect it.
    for client, outcomes in parked[1:]:
        client.close()
        assert outcomes.get(timeout=2).closeout == "not_owner"
    assert command(admitted, "heartbeat", 1, {})["ok"] is True
    admitted.close()
    assert admitted_outcomes.get(timeout=2).closeout == "revoked"


def test_receiver_rejects_wrong_forwarder_proof_and_closes_socket():
    client, server = socket.socketpair()
    finished = queue.Queue()

    def impostor():
        try:
            send_frame(server, {"op": "challenge", "generation": "generation-test",
                                "challenge": "a" * 64}, timeout=0.5)
            request = recv_frame(server, timeout=0.5)
            send_frame(server, {"op": "hello", "ok": True, "generation": "generation-test",
                                "receiver_boot_id": "receiver-a",
                                # Reflecting the Receiver proof cannot authenticate the server.
                                "proof": request["proof"]}, timeout=0.5)
            try:
                recv_frame(server, timeout=0.5)
            except ControlProtocolError as exc:
                finished.put(exc.code)
        finally:
            server.close()

    worker = threading.Thread(target=impostor)
    worker.start()
    try:
        with pytest.raises(ControlProtocolError, match="authentication_failed"):
            hello(client)
        assert finished.get(timeout=2) == "eof"
    finally:
        client.close()
        worker.join(timeout=2)
        assert not worker.is_alive()
