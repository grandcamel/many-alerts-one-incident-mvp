"""Deterministic tests for scope manifest delivery and lease closeout over the
gated Forwarder controller (Module 3), Tester D1 / Implementer C's file.

This file owns plan cases 2, 3, 7, 8, 9, 10, 11 (both variants), 12a-d, 13, 17
and 18. It imports the shared fixtures and helpers from
``test_forwarder_control_gate`` (``new_gated_system``, ``start_gated_control``,
``hello``, ``command``, ``scoped``, ``SECRET``, ``TEST_TIMEOUT``) rather than
redefining them, per the implementation plan's "Ownership and validation".
"""

from __future__ import annotations

import json
import queue
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from grafana_jsm_sandbox import forwarder_control as module
from grafana_jsm_sandbox import forwarder_control_scope as control_scope
from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox.forwarder_control_protocol import recv_frame, send_frame
from grafana_jsm_sandbox.forwarder_routes import JiraScope
from tests.test_forwarder_control_gate import (
    SECRET,
    TEST_TIMEOUT,
    command,
    hello,
    new_gated_system,
    scoped,
    start_gated_control,
)
from tests.test_forwarder_dispatch import make_routed, reserve_and_admit
from tests.test_forwarder_routes import golden_manifest

# --- local helpers -------------------------------------------------------------


def _large_manifest(*, pad: int, run_id: str, attempt_id: str):
    """A jira.search-only manifest with 256 unique, ascending search labels."""
    labels = tuple(f"label-{index:04d}" + "x" * pad for index in range(256))
    scope = JiraScope(issues=(), search_labels=labels)
    return golden_manifest(
        run_id=run_id, attempt_id=attempt_id, routes=("jira.search",), scope=scope,
    )


def _flipped_digest(digest: str) -> str:
    return ("1" if digest[0] != "1" else "2") + digest[1:]


def _connect(control) -> tuple[socket.socket, queue.Queue]:
    """Start one more connection against an existing ``ForwarderControl``."""
    client, server = socket.socketpair()
    outcomes: queue.Queue = queue.Queue()
    worker = threading.Thread(target=lambda: outcomes.put(control.serve_connection(server)))
    worker.start()
    return client, outcomes


def _attempt_reconnect(control, *, boot: str = "receiver-a", secret: bytes = SECRET):
    """Run the handshake by hand (not ``authenticate_receiver``) so a raw
    error frame -- e.g. ``registry_held`` -- can be inspected directly."""
    client, outcomes = _connect(control)
    challenge = recv_frame(client, timeout=TEST_TIMEOUT)
    proof = module._proof(
        secret, "receiver", challenge["generation"], challenge["challenge"], boot,
    )
    hello_frame = {"op": "hello", "receiver_boot_id": boot, "proof": proof}
    send_frame(client, hello_frame, timeout=TEST_TIMEOUT)
    reply = recv_frame(client, timeout=TEST_TIMEOUT)
    client.close()
    return reply, outcomes.get(timeout=2)


def _heartbeat_advance(
    client: socket.socket, clock, seq: int, target: float, *, step: float = 10.0,
) -> int:
    """Advance the shared ``FakeClock`` to ``target``, heartbeating over control
    at every step so no gap ever reaches ``HEARTBEAT_SECONDS``."""
    while clock.value < target:
        clock.value = min(clock.value + step, target)
        reply = command(client, "heartbeat", seq, {})
        assert reply["ok"] is True
        seq += 1
    return seq


# --- case 2: large manifests ----------------------------------------------------


def test_case2_large_manifests_install():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)

    over_8kib = _large_manifest(pad=20, run_id="run-big-a", attempt_id="attempt-big-a")
    data_a = over_8kib.canonical_bytes()
    assert len(data_a) > 8192
    header_a = {
        "op": "register_scoped", "seq": 1,
        "params": {
            "run_id": over_8kib.run_id, "attempt_id": over_8kib.attempt_id,
            "service": over_8kib.service, "scope_digest": over_8kib.digest,
            "expires_at": 1100.0, "manifest_bytes": len(data_a),
        },
    }
    assert len(json.dumps(header_a, separators=(",", ":")).encode()) <= 8192

    reply_a = scoped(client, 1, over_8kib)
    assert reply_a["ok"] is True
    assert reply_a["result"]["installed_at"] is not None

    over_15000 = _large_manifest(pad=45, run_id="run-big-b", attempt_id="attempt-big-b")
    data_b = over_15000.canonical_bytes()
    assert 15000 < len(data_b) <= 16384

    reply_b = scoped(client, 2, over_15000)
    assert reply_b["ok"] is True

    client.close()
    outcomes.get(timeout=2)


# --- case 3: exact replay --------------------------------------------------------


def test_case3_exact_replay_same_grant_and_installed_at():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply1 = scoped(client, 1, manifest)
    assert reply1["ok"] is True
    result1 = reply1["result"]

    reply2 = scoped(client, 2, manifest)
    assert reply2["ok"] is True
    result2 = reply2["result"]

    assert result2["lease_id"] == result1["lease_id"]
    assert result2["sentinel"] == result1["sentinel"]
    assert result2["installed_at"] == result1["installed_at"]
    assert len(gate.snapshot()["scope_entries"]) == 1

    client.close()
    outcomes.get(timeout=2)


# --- case 7: framing errors, no mutation -----------------------------------------


def test_case7_prefix_mismatch_gives_attachment_mismatch_no_mutation():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    data_len = len(manifest.canonical_bytes())

    reply = scoped(client, 1, manifest, manifest_bytes=data_len + 1)
    assert reply["error"] == "attachment_mismatch"
    assert registry.snapshot()["retained_records"] == 0
    assert gate.snapshot()["scope_entries"] == ()

    client.close()
    outcomes.get(timeout=2)


def test_case7_missing_attachment_gives_timeout_no_mutation():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate, timeout=0.3)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest, attachment=None)
    assert reply["error"] == "timeout"
    assert registry.snapshot()["retained_records"] == 0

    client.close()
    outcomes.get(timeout=2)


def test_case7_closing_mid_body_gives_truncated_frame_no_mutation():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    data = manifest.canonical_bytes()
    params = {
        "run_id": manifest.run_id, "attempt_id": manifest.attempt_id, "service": manifest.service,
        "scope_digest": manifest.digest, "expires_at": 1100.0, "manifest_bytes": len(data),
    }
    send_frame(client, {"op": "register_scoped", "seq": 1, "params": params}, timeout=TEST_TIMEOUT)
    client.sendall(struct.pack("!I", len(data)) + data[: len(data) // 2])
    client.close()

    outcome = outcomes.get(timeout=2)
    assert outcome.reason == "truncated_frame"
    assert registry.snapshot()["retained_records"] == 0
    assert gate.snapshot()["scope_entries"] == ()


def test_case7_budget_clip_uses_attachment_seconds_under_one_second(monkeypatch):
    monkeypatch.setattr(control_scope, "ATTACHMENT_SECONDS", 0.2)
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate, timeout=2.0)
    hello(client)
    manifest = golden_manifest()

    started = time.monotonic()
    reply = scoped(client, 1, manifest, attachment=None)
    elapsed = time.monotonic() - started
    assert reply["error"] == "timeout"
    assert elapsed < 1.0
    assert registry.snapshot()["retained_records"] == 0

    client.close()
    outcomes.get(timeout=2)


# --- case 8: manifest errors, no mutation, no marker leak ------------------------


def test_case8_noncanonical_bytes_give_manifest_invalid_no_marker():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    data_bad = manifest.canonical_bytes() + b"\n"

    reply = scoped(client, 1, manifest, attachment=data_bad, manifest_bytes=len(data_bad))
    assert reply["error"] == "manifest_invalid"
    assert "fp-0123456789abcdef" not in json.dumps(reply)
    assert registry.snapshot()["retained_records"] == 0
    assert gate.snapshot()["scope_entries"] == ()

    client.close()
    outcomes.get(timeout=2)


def test_case8_another_attempts_manifest_gives_manifest_binding_mismatch():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest, attempt_id="attempt-other")
    assert reply["error"] == "manifest_binding_mismatch"
    assert registry.snapshot()["retained_records"] == 0
    assert gate.snapshot()["scope_entries"] == ()

    client.close()
    outcomes.get(timeout=2)


def test_case8_digest_mismatch_gives_manifest_binding_mismatch():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    bad_digest = _flipped_digest(manifest.digest)

    reply = scoped(client, 1, manifest, scope_digest=bad_digest)
    assert reply["error"] == "manifest_binding_mismatch"
    assert registry.snapshot()["retained_records"] == 0
    assert gate.snapshot()["scope_entries"] == ()

    client.close()
    outcomes.get(timeout=2)


# --- case 9: install failure after register --------------------------------------


def _close_gate(gate, _monkeypatch):
    gate.shutdown()


def _zero_scope_capacity(_gate, monkeypatch):
    monkeypatch.setattr(fd, "MAX_SCOPE_ENTRIES", 0)


@pytest.mark.parametrize(
    "trigger,code",
    [(_close_gate, "scope_gate_closed"), (_zero_scope_capacity, "scope_capacity")],
    ids=["gate_closed", "scope_capacity"],
)
def test_case9_install_failure_after_register_revokes_session_leases(trigger, code, monkeypatch):
    events: list[str] = []
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    original_disconnect = registry.disconnect

    def wrapped_disconnect(**kwargs):
        events.append("disconnect")
        return original_disconnect(**kwargs)

    monkeypatch.setattr(registry, "disconnect", wrapped_disconnect)
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)

    manifest_a = golden_manifest()
    reply_a = scoped(client, 1, manifest_a)
    assert reply_a["ok"] is True
    lease_a = reply_a["result"]["lease_id"]

    trigger(gate, monkeypatch)

    manifest_b = golden_manifest(run_id="run-b", attempt_id="attempt-b")
    reply_b = scoped(client, 2, manifest_b)
    events.append("frame")
    assert reply_b["error"] == code
    assert "result" not in reply_b
    assert "sentinel" not in json.dumps(reply_b)
    assert events == ["disconnect", "frame"]

    outcome = outcomes.get(timeout=2)
    assert outcome.commands == 2
    assert outcome.closeout == "revoked"

    leases = registry.snapshot()["leases"]
    by_run = {item["run_id"]: item["state"] for item in leases}
    assert {item["lease_id"]: item["state"] for item in leases}[lease_a] == "revoked"
    assert by_run["run-b"] == "revoked"

    client.close()


# --- case 10: revoke reply shape --------------------------------------------------


def test_case10_revoke_reply_shape_quiescent():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]

    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True
    result = revoke_reply["result"]

    assert set(result) == set(module._RECEIPT_FIELDS) | {"revoked_at", "closeout_state", "closeout"}
    assert set(result["closeout"]) == set(control_scope.CLOSEOUT_FIELDS)
    assert result["revoked_at"] == result["observed_at"]
    assert result["closeout_state"] == result["closeout"]["closeout_state"] == "quiescent"
    assert result["closeout"]["lease_state"] == "revoked"
    for field in control_scope.CLOSEOUT_COUNT_FIELDS:
        assert result["closeout"][field] == 0
    assert result["closeout"]["generation"] == registry.generation

    encoded = json.dumps(revoke_reply, separators=(",", ":")).encode()
    assert len(encoded) < 2048

    entry = gate.resolve(service="jira", sentinel=sentinel)
    assert gate.precheck(entry, sentinel=sentinel) is False

    client.close()
    outcomes.get(timeout=2)


def test_case10_revoked_at_comes_from_the_registry_not_the_closeout_observation():
    # G4: revoked_at must be the registry's own retirement time (result.observed_at),
    # never the later closeout observation's own clock reading.
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id = reply["result"]["lease_id"]

    real_closeout = gate.closeout

    def wrapped(lease_id):
        clock.advance(1.0)
        return real_closeout(lease_id)

    gate.closeout = wrapped

    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True
    result = revoke_reply["result"]

    revoke_receipts = [
        item for item in registry.snapshot()["history"]
        if item["operation"] == "revoke" and item["lease_id"] == lease_id
    ]
    assert revoke_receipts
    registry_observed_at = revoke_receipts[-1]["observed_at"]

    assert result["revoked_at"] == result["observed_at"] == registry_observed_at
    assert result["revoked_at"] != result["closeout"]["observed_at"]

    client.close()
    outcomes.get(timeout=5)


# --- case 11: draining then quiescent ---------------------------------------------


def test_case11_draining_then_quiescent():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]
    activate_params = {"lease_id": lease_id, "launch_at": clock.value}
    activate_reply = command(client, "activate", 2, activate_params)
    assert activate_reply["ok"] is True

    entry = gate.resolve(service="jira", sentinel=sentinel)
    routed = make_routed(entry)
    grant_like = SimpleNamespace(sentinel=sentinel)
    admission = reserve_and_admit(gate, entry, grant_like, clock, routed=routed)

    revoke_reply = command(client, "revoke", 3, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True
    assert revoke_reply["result"]["closeout_state"] == "draining"
    assert revoke_reply["result"]["closeout"]["in_flight"] == 1
    assert revoke_reply["result"]["closeout"]["drain_deadline"] == admission.deadline

    write_outcome = gate.begin_write(admission, sentinel=sentinel)
    assert write_outcome.code == "lease_denied"

    closeout_reply = command(client, "closeout", 4, {"lease_id": lease_id})
    assert closeout_reply["ok"] is True
    assert closeout_reply["result"]["closeout_state"] == "quiescent"
    assert closeout_reply["result"]["uncertain"] == 0

    client.close()
    outcomes.get(timeout=2)


def test_case11_variant_fence_passed_before_revoke_gives_uncertain_1():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]
    activate_params = {"lease_id": lease_id, "launch_at": clock.value}
    activate_reply = command(client, "activate", 2, activate_params)
    assert activate_reply["ok"] is True

    entry = gate.resolve(service="jira", sentinel=sentinel)
    routed = make_routed(entry)
    grant_like = SimpleNamespace(sentinel=sentinel)
    admission = reserve_and_admit(gate, entry, grant_like, clock, routed=routed)

    write_outcome = gate.begin_write(admission, sentinel=sentinel)
    assert write_outcome.code == "write_admitted"
    gate.finish(admission, dispatch_state="DISPATCHED_UNKNOWN", reason="write_failed")

    revoke_reply = command(client, "revoke", 3, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True
    assert revoke_reply["result"]["closeout_state"] == "quiescent"
    assert revoke_reply["result"]["closeout"]["in_flight"] == 0
    assert revoke_reply["result"]["closeout"]["uncertain"] == 1

    client.close()
    outcomes.get(timeout=2)


# --- case 12: overdue holds --------------------------------------------------------


def test_case12a_overdue_after_draining_revoke_holds_and_refuses_reconnect():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]
    command(client, "activate", 2, {"lease_id": lease_id, "launch_at": clock.value})

    entry = gate.resolve(service="jira", sentinel=sentinel)
    routed = make_routed(entry)
    grant_like = SimpleNamespace(sentinel=sentinel)
    admission = reserve_and_admit(gate, entry, grant_like, clock, routed=routed)

    revoke_reply = command(client, "revoke", 3, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True
    assert revoke_reply["result"]["closeout_state"] == "draining"

    seq = _heartbeat_advance(client, clock, 4, admission.deadline + 1.0)

    closeout_reply = command(client, "closeout", seq, {"lease_id": lease_id})
    assert closeout_reply["error"] == "closeout_overdue"
    assert registry.snapshot()["registry_state"] == "held"

    outcome = outcomes.get(timeout=2)
    assert outcome.closeout == "unknown"

    reconnect_reply, reconnect_outcome = _attempt_reconnect(control)
    assert reconnect_reply["error"] == "registry_held"
    assert reconnect_outcome.reason == "registry_held"

    assert gate.release(admission) is True
    direct = gate.closeout(lease_id)
    assert direct.overdue == 0
    assert direct.uncertain == 1

    client.close()


def test_case12b_revoke_of_already_overdue_flight_gives_closeout_overdue():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]
    command(client, "activate", 2, {"lease_id": lease_id, "launch_at": clock.value})

    entry = gate.resolve(service="jira", sentinel=sentinel)
    routed = make_routed(entry)
    grant_like = SimpleNamespace(sentinel=sentinel)
    admission = reserve_and_admit(gate, entry, grant_like, clock, routed=routed)

    seq = _heartbeat_advance(client, clock, 3, admission.deadline + 1.0)

    revoke_reply = command(client, "revoke", seq, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["error"] == "closeout_overdue"
    assert registry.snapshot()["registry_state"] == "held"

    revokes = [
        item for item in registry.snapshot()["history"]
        if item["operation"] == "revoke" and item["lease_id"] == lease_id
    ]
    assert revokes, "the revoke receipt must still be recorded despite the hold"

    outcomes.get(timeout=2)
    client.close()


def test_case12c_open_lease_with_overdue_flight_gives_closeout_overdue():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]
    command(client, "activate", 2, {"lease_id": lease_id, "launch_at": clock.value})

    entry = gate.resolve(service="jira", sentinel=sentinel)
    routed = make_routed(entry)
    grant_like = SimpleNamespace(sentinel=sentinel)
    admission = reserve_and_admit(gate, entry, grant_like, clock, routed=routed)

    seq = _heartbeat_advance(client, clock, 3, admission.deadline + 1.0)

    direct_before = gate.closeout(lease_id)
    assert direct_before.lease_state in ("registered", "active")
    assert direct_before.closeout_state == "open"
    assert direct_before.overdue == 1

    closeout_reply = command(client, "closeout", seq, {"lease_id": lease_id})
    assert closeout_reply["error"] == "closeout_overdue"
    assert registry.snapshot()["registry_state"] == "held"

    outcomes.get(timeout=2)
    client.close()


def test_case12d_expiry_variant_gives_closeout_overdue_with_expired_lease_state():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id, sentinel = reply["result"]["lease_id"], reply["result"]["sentinel"]
    expires_at = reply["result"]["expires_at"]
    command(client, "activate", 2, {"lease_id": lease_id, "launch_at": clock.value})

    entry = gate.resolve(service="jira", sentinel=sentinel)
    routed = make_routed(entry)
    reserve_and_admit(gate, entry, SimpleNamespace(sentinel=sentinel), clock, routed=routed)

    seq = _heartbeat_advance(client, clock, 3, expires_at + 1.0)

    closeout_reply = command(client, "closeout", seq, {"lease_id": lease_id})
    assert closeout_reply["error"] == "closeout_overdue"
    assert registry.snapshot()["registry_state"] == "held"

    direct = gate.closeout(lease_id)
    assert direct.lease_state == "expired"

    outcomes.get(timeout=2)
    client.close()


# --- case 13: closeout command basics ----------------------------------------------


def test_case13_closeout_command_basics():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id = reply["result"]["lease_id"]
    activate_params = {"lease_id": lease_id, "launch_at": clock.value}
    activate_reply = command(client, "activate", 2, activate_params)
    assert activate_reply["ok"] is True

    open_reply = command(client, "closeout", 3, {"lease_id": lease_id})
    assert open_reply["ok"] is True
    assert open_reply["result"]["closeout_state"] == "open"
    assert open_reply["result"]["lease_state"] == "active"

    unknown_reply = command(client, "closeout", 4, {"lease_id": "lease-does-not-exist"})
    assert unknown_reply["ok"] is True
    assert unknown_reply["result"]["closeout_state"] == "unknown"
    assert unknown_reply["result"]["lease_state"] == "unknown"
    assert registry.snapshot()["registry_state"] != "held"

    heartbeat_reply = command(client, "heartbeat", 5, {})
    assert heartbeat_reply["ok"] is True

    bad_id_reply = command(client, "closeout", 6, {"lease_id": "bad id!"})
    assert bad_id_reply["error"] == "invalid_identity"

    client.close()
    outcomes.get(timeout=2)


def test_case13_commands_counts_exactly_the_fence_admitted_commands():
    # G5: commands counts every schema-valid command admitted past the owner
    # fence, including a gated closeout that makes no registry call. A closeout
    # refused with invalid_identity fails before the fence and is not counted.
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)  # 1: register_scoped
    lease_id = reply["result"]["lease_id"]
    activate_reply = command(client, "activate", 2, {"lease_id": lease_id, "launch_at": clock.value})
    assert activate_reply["ok"] is True  # 2: activate

    open_reply = command(client, "closeout", 3, {"lease_id": lease_id})
    assert open_reply["ok"] is True  # 3: closeout (open)

    unknown_reply = command(client, "closeout", 4, {"lease_id": "lease-does-not-exist"})
    assert unknown_reply["ok"] is True  # 4: closeout (unknown, no hold)

    heartbeat_reply = command(client, "heartbeat", 5, {})
    assert heartbeat_reply["ok"] is True  # 5: heartbeat

    bad_id_reply = command(client, "closeout", 6, {"lease_id": "bad id!"})
    assert bad_id_reply["error"] == "invalid_identity"  # before the fence: not counted

    client.close()
    outcome = outcomes.get(timeout=5)
    assert outcome.commands == 5


# --- case 17: registry held by the test, within one session -----------------------


def test_case17_registry_held_by_the_test_within_one_session():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    reply = scoped(client, 1, manifest)
    lease_id = reply["result"]["lease_id"]

    registry.hold()

    unknown_reply = command(client, "closeout", 2, {"lease_id": "lease-does-not-exist"})
    assert unknown_reply["ok"] is True
    assert unknown_reply["result"]["closeout_state"] == "unknown"
    assert unknown_reply["result"]["lease_state"] == "unknown"

    known_reply = command(client, "closeout", 3, {"lease_id": lease_id})
    assert known_reply["error"] == "closeout_unknown"

    client.close()
    outcomes.get(timeout=2)


# --- case 18: prior-boot leases -----------------------------------------------------


def test_case18_closeout_of_prior_boot_lease_from_new_session():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client_a, control, outcomes_a = start_gated_control(registry, gate)
    hello(client_a, boot="receiver-a")
    manifest = golden_manifest()

    reply_a = scoped(client_a, 1, manifest)
    lease_id = reply_a["result"]["lease_id"]

    client_b, outcomes_b = _connect(control)
    hello(client_b, boot="receiver-b")

    assert registry.snapshot()["registry_state"] != "held"
    leases = {item["lease_id"]: item["state"] for item in registry.snapshot()["leases"]}
    assert leases[lease_id] == "revoked"

    closeout_reply = command(client_b, "closeout", 1, {"lease_id": lease_id})
    assert closeout_reply["ok"] is True
    assert closeout_reply["result"]["lease_state"] == "revoked"
    assert closeout_reply["result"]["closeout_state"] == "quiescent"

    client_a.close()
    client_b.close()
    outcomes_b.get(timeout=5.0)
    # A's handler usually ends on its own 2.0 s read timeout once B's hello
    # closes A's socket, so a tight outer timeout is flaky; 5 s leaves margin.
    outcome_a = outcomes_a.get(timeout=5.0)
    assert outcome_a.closeout == "not_owner"
