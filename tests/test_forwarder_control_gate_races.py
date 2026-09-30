"""Race, fault-injection and custody tests for the gated Forwarder controller.

This file owns plan cases 14-16, 19-23, the case-24 thread-ownership checks
(the AST half lives in ``test_forwarder_control_gate.py``), 27 and 28. Every
race uses an instance-attribute wrapper on a real collaborator (never a mock)
with an ``Event``-based barrier, and asserts the wrapper actually fired before
drawing any conclusion from the barrier's timing.
"""

from __future__ import annotations

import ast
import math
import os
import queue
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_control as module
from grafana_jsm_sandbox import forwarder_control_scope as scope
from grafana_jsm_sandbox.forwarder_control import ForwarderControl
from grafana_jsm_sandbox.forwarder_control_protocol import (
    MAX_FRAME_BYTES,
    recv_frame,
    send_attachment,
    send_frame,
)
from grafana_jsm_sandbox.forwarder_dispatch import Closeout, DispatchGate
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_listener import PrivateControlListener
from grafana_jsm_sandbox.forwarder_receipts import ReceiptLedger
from grafana_jsm_sandbox.forwarder_routes import JiraScope, ScopeManifest
from grafana_jsm_sandbox.forwarder_supervisor import ControlService
from tests.test_forwarder_control_gate import (
    SECRET,
    TEST_TIMEOUT,
    command,
    hello,
    new_gated_system,
    scoped,
    start_gated_control,
)
from tests.test_forwarder_dispatch import FakeClock, make_routed
from tests.test_forwarder_routes import golden_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_MODULE_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_control.py"
CONTROL_PROTOCOL_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_control_protocol.py"
LEASES_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_leases.py"

LABEL_MARKER = "fp-0123456789abcdef"  # the search label baked into golden_manifest()


# --- code-union derivation (case 27) -------------------------------------------


def _string_codes(path: Path, class_name: str) -> frozenset[str]:
    """Every literal ``class_name("code")`` call argument found in ``path``'s source.

    This mechanically derives the committed/codec code vocabularies from the
    actual source text, rather than a hand-typed (and possibly stale) list.
    """
    tree = ast.parse(path.read_text())
    codes: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == class_name and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        ):
            codes.add(node.args[0].value)
    return frozenset(codes)


CODEC_CODES = _string_codes(CONTROL_PROTOCOL_PATH, "ControlProtocolError")
COMMITTED_CONTROL_CODES = _string_codes(CONTROL_MODULE_PATH, "ControlProtocolError")
COMMITTED_LEASE_CODES = _string_codes(LEASES_PATH, "LeaseError")
# eof/internal_failure/sequence_exhausted are assigned as plain strings in
# forwarder_control.py's exception handling, not raised via ControlProtocolError,
# so the AST scan above cannot see them; they are still committed reason values.
_NON_ERROR_REASONS = frozenset({"eof", "internal_failure", "sequence_exhausted"})
ALLOWED_CODES = (
    CODEC_CODES | COMMITTED_CONTROL_CODES | COMMITTED_LEASE_CODES
    | scope.SCOPE_CONTROL_CODES | _NON_ERROR_REASONS
)


# --- local helpers (not shared by any sibling file) ----------------------------


def _run_async(fn, *args, **kwargs) -> queue.Queue:
    """Run ``fn(*args, **kwargs)`` on a background thread; returns a result box.

    The box receives ``("ok", value)`` or ``("error", exc)``, so a race test can
    keep driving the foreground thread without the background call's own
    exception (e.g. a clean EOF read) crashing an unrelated thread silently.
    """
    box: queue.Queue = queue.Queue()

    def _runner() -> None:
        try:
            box.put(("ok", fn(*args, **kwargs)))
        except BaseException as exc:  # noqa: BLE001 - captured for the test thread
            box.put(("error", exc))

    threading.Thread(target=_runner, daemon=True).start()
    return box


def _serve_more(control: ForwarderControl) -> tuple[socket.socket, queue.Queue]:
    """Serve one more connection on an already-constructed, shared ``control``."""
    client, server = socket.socketpair()
    outcomes: queue.Queue = queue.Queue()
    worker = threading.Thread(
        target=lambda: outcomes.put(control.serve_connection(server)), daemon=True,
    )
    worker.start()
    return client, outcomes


def raw_hello_reply(client: socket.socket, *, boot: str = "receiver-b", secret: bytes = SECRET) -> dict:
    """Perform the handshake wire steps without validating the reply's shape.

    ``authenticate_receiver`` raises ``invalid_schema`` on a held-registry error
    frame, because its keys differ from a successful hello reply's. This reads
    the raw frame instead, so a ``registry_held`` refusal can be asserted directly.
    """
    challenge = recv_frame(client, timeout=TEST_TIMEOUT)
    generation, nonce = challenge["generation"], challenge["challenge"]
    send_frame(client, {
        "op": "hello", "receiver_boot_id": boot,
        "proof": module._proof(secret, "receiver", generation, nonce, boot),
    }, timeout=TEST_TIMEOUT)
    return recv_frame(client, timeout=TEST_TIMEOUT)


def _install_scope_barrier(gate: DispatchGate) -> tuple[threading.Event, threading.Event, dict]:
    """Wrap ``gate.install_scope`` to capture the grant and block before delegating.

    Returns ``(entered, resume, captured)``. ``entered`` is set the instant the
    wrapper fires (proof it fired); the wrapper then blocks on ``resume`` before
    calling the real method, opening the "before the check" race window.
    """
    real_install_scope = gate.install_scope
    entered = threading.Event()
    resume = threading.Event()
    captured: dict[str, str] = {}

    def wrapped(*, grant, manifest):
        captured["sentinel"] = grant.sentinel
        captured["lease_id"] = grant.lease_id
        entered.set()
        assert resume.wait(timeout=5.0), "the install_scope barrier was never released"
        return real_install_scope(grant=grant, manifest=manifest)

    gate.install_scope = wrapped
    return entered, resume, captured


def _capture_install_scope(gate: DispatchGate) -> dict:
    """Instance-attribute wrapper: captures the grant identity, no blocking."""
    real_install_scope = gate.install_scope
    captured: dict[str, str] = {}

    def wrapped(*, grant, manifest):
        captured["sentinel"] = grant.sentinel
        captured["lease_id"] = grant.lease_id
        return real_install_scope(grant=grant, manifest=manifest)

    gate.install_scope = wrapped
    return captured


def _snapshot_barrier(registry: LeaseRegistry) -> tuple[threading.Event, threading.Event]:
    """Wrap ``registry.snapshot`` to block once (its first call) after returning
    the real snapshot -- opens the "after the snapshot" install race window.

    Returns ``(fired, resume)``. Only the first call blocks; every later call
    (including the test's own later reads) delegates immediately.
    """
    real_snapshot = registry.snapshot
    fired = threading.Event()
    resume = threading.Event()

    def wrapped():
        if fired.is_set():
            return real_snapshot()
        result = real_snapshot()
        fired.set()
        assert resume.wait(timeout=5.0), "the snapshot barrier was never released"
        return result

    registry.snapshot = wrapped
    return fired, resume


def _capture_register_sentinels(registry: LeaseRegistry) -> dict[str, str]:
    """Instance-attribute wrapper: records every grant's sentinel as it is minted."""
    real_register = registry.register
    captured: dict[str, str] = {}

    def wrapped(**kwargs):
        grant = real_register(**kwargs)
        captured[grant.lease_id] = grant.sentinel
        return grant

    registry.register = wrapped
    return captured


def _assert_case27_custody(
    frame: object, outcome, control: ForwarderControl, registry: LeaseRegistry,
    gate: DispatchGate, sentinels: dict, label_marker: str,
) -> None:
    filtered_dict = {key: value for key, value in control.__dict__.items()
                     if key not in ("_registry", "_gate")}
    texts = (
        repr(frame), repr(outcome), repr(filtered_dict),
        repr(registry.snapshot()), repr(gate.snapshot()),
    )
    for text in texts:
        assert label_marker not in text
        for sentinel in sentinels.values():
            assert sentinel not in text
    assert outcome.reason in ALLOWED_CODES


def _oversized_manifest() -> ScopeManifest:
    """A canonical manifest whose bytes exceed the 8 KiB JSON frame limit."""
    labels = tuple(f"fp-{index:04d}-{'a' * 40}" for index in range(256))
    return golden_manifest(
        run_id="run-large", attempt_id="attempt-large",
        routes=("jira.search",), scope=JiraScope(issues=(), search_labels=labels),
    )


# --- case 14: pruned -------------------------------------------------------------


def test_case14_pruned_registry_record_then_pruned_scope_entry():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)

    calls = []
    real_install_scope = gate.install_scope

    def wrapped(*, grant, manifest):
        calls.append(1)
        clock.advance(10.0)
        return real_install_scope(grant=grant, manifest=manifest)

    gate.install_scope = wrapped

    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    assert calls == [1], "install_scope wrapper never fired"
    lease_id = reply["result"]["lease_id"]
    installed_at = reply["result"]["installed_at"]
    created_at = next(
        item for item in registry.snapshot()["leases"] if item["lease_id"] == lease_id
    )["created_at"]
    assert installed_at == pytest.approx(created_at + 10.0)

    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True
    assert revoke_reply["result"]["closeout_state"] == "quiescent"

    # Past the registry's 310 s retention but before the gate's own 310 s.
    clock.value = created_at + 315.0
    mid_reply = command(client, "closeout", 3, {"lease_id": lease_id})
    assert mid_reply["ok"] is True
    assert mid_reply["result"]["lease_state"] == "pruned"
    assert mid_reply["result"]["closeout_state"] == "quiescent"
    assert mid_reply["result"]["pending"] == 0
    assert mid_reply["result"]["in_flight"] == 0
    assert mid_reply["result"]["uncertain"] == 0
    assert registry.snapshot()["registry_state"] != "held"

    # Past the gate's own 310 s retention: no Forwarder record at all.
    clock.value = installed_at + 315.0
    late_reply = command(client, "closeout", 4, {"lease_id": lease_id})
    assert late_reply["ok"] is True
    assert late_reply["result"]["lease_state"] == "unknown"
    assert late_reply["result"]["closeout_state"] == "unknown"
    assert registry.snapshot()["registry_state"] != "held"

    client.close()
    outcomes.get(timeout=5)


# --- case 15: gate-only clock fault ----------------------------------------------


def test_case15_gate_only_clock_fault_on_revoke_holds_the_registry():
    registry, _ledger, gate, _clock, gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    gate_clock.fault = True
    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["error"] == "closeout_unknown"
    assert registry.snapshot()["registry_state"] == "held"
    outcome = outcomes.get(timeout=5)
    assert outcome.closeout == "unknown"
    client.close()

    client2, outcomes2 = _serve_more(control)
    refusal = raw_hello_reply(client2, boot="receiver-c")
    assert refusal.get("error") == "registry_held"
    client2.close()
    outcomes2.get(timeout=5)

    revokes = [
        item for item in registry.snapshot()["history"]
        if item["operation"] == "revoke" and item["lease_id"] == lease_id
    ]
    assert revokes and revokes[-1]["reason"] == "cancelled"
    assert revokes[-1]["state"] == "revoked"


# --- case 16: observation failures and incoherence -------------------------------


@pytest.mark.parametrize("trigger", ["revoke", "closeout"])
def test_case16_gate_closeout_raises_gives_closeout_unknown_and_holds(trigger):
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    def raising_closeout(_lease_id):
        raise RuntimeError("synthetic gate fault")

    gate.closeout = raising_closeout

    if trigger == "revoke":
        result = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    else:
        result = command(client, "closeout", 2, {"lease_id": lease_id})
    assert result["error"] == "closeout_unknown"
    assert registry.snapshot()["registry_state"] == "held"
    client.close()
    outcomes.get(timeout=5)


def test_case16_active_lease_state_after_revoke_gives_closeout_inconsistent():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    bad = Closeout(
        lease_id=lease_id, lease_state="active", closeout_state="open",
        pending=0, in_flight=0, overdue=0, drain_deadline=None,
        uncertain=0, observed_at=clock.value,
    )
    gate.closeout = lambda _lease_id: bad

    result = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert result["error"] == "closeout_inconsistent"
    assert registry.snapshot()["registry_state"] == "held"
    client.close()
    outcomes.get(timeout=5)


def test_case16_nonfinite_observed_at_gives_closeout_inconsistent_not_a_codec_error():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)

    bad = Closeout(
        lease_id="lease-x", lease_state="active", closeout_state="open",
        pending=0, in_flight=0, overdue=0, drain_deadline=None,
        uncertain=0, observed_at=float("nan"),
    )
    gate.closeout = lambda _lease_id: bad

    result = command(client, "closeout", 1, {"lease_id": "lease-x"})
    assert result["error"] == "closeout_inconsistent"
    assert registry.snapshot()["registry_state"] == "held"
    client.close()
    outcomes.get(timeout=5)


def test_case16_bool_count_gives_closeout_inconsistent():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)

    bad = Closeout(
        lease_id="lease-y", lease_state="active", closeout_state="open",
        pending=0, in_flight=True, overdue=0, drain_deadline=None,
        uncertain=0, observed_at=clock.value,
    )
    gate.closeout = lambda _lease_id: bad

    result = command(client, "closeout", 1, {"lease_id": "lease-y"})
    assert result["error"] == "closeout_inconsistent"
    assert registry.snapshot()["registry_state"] == "held"
    client.close()
    outcomes.get(timeout=5)


def test_case16_drain_deadline_infinite_after_revoke_gives_closeout_inconsistent():
    # G1: a control-level variant of the timestamp bound, over a real gated
    # controller. gate.closeout is stubbed only after a real revoke completed.
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True

    bad = Closeout(
        lease_id=lease_id, lease_state="revoked", closeout_state="draining",
        pending=0, in_flight=1, overdue=0, drain_deadline=math.inf,
        uncertain=0, observed_at=clock.value,
    )
    gate.closeout = lambda _lease_id: bad

    result = command(client, "closeout", 3, {"lease_id": lease_id})
    assert result["error"] == "closeout_inconsistent"
    assert registry.snapshot()["registry_state"] == "held"
    client.close()
    outcomes.get(timeout=5)


@pytest.mark.parametrize("observed_at", [2**64, 10**400], ids=["2_64", "10_400"])
def test_case16_observed_at_above_time_bound_after_revoke_gives_closeout_inconsistent(observed_at):
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["ok"] is True

    bad = Closeout(
        lease_id=lease_id, lease_state="revoked", closeout_state="quiescent",
        pending=0, in_flight=0, overdue=0, drain_deadline=None,
        uncertain=0, observed_at=observed_at,
    )
    gate.closeout = lambda _lease_id: bad

    result = command(client, "closeout", 3, {"lease_id": lease_id})
    assert result["error"] == "closeout_inconsistent"
    assert registry.snapshot()["registry_state"] == "held"
    client.close()
    outcomes.get(timeout=5)


# --- case 19: replacement race before the check ----------------------------------


def test_case19_replacement_race_before_the_check():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client_a, control, outcomes_a = start_gated_control(registry, gate)
    hello(client_a)
    manifest = golden_manifest()

    entered, resume, captured = _install_scope_barrier(gate)
    box = _run_async(scoped, client_a, 1, manifest)

    assert entered.wait(timeout=5.0), "install_scope wrapper never fired"
    client_b, outcomes_b = _serve_more(control)
    hello(client_b, boot="receiver-b")
    resume.set()

    outcome_a = outcomes_a.get(timeout=5.0)
    assert outcome_a.reason == "scope_lease_unverified"
    assert outcome_a.closeout == "not_owner"
    assert gate.resolve(service="jira", sentinel=captured["sentinel"]) is None

    manifest_b = golden_manifest(run_id="run-b", attempt_id="attempt-b")
    reply_b = scoped(client_b, 1, manifest_b)
    assert reply_b["ok"] is True

    client_a.close()
    client_b.close()
    outcomes_b.get(timeout=5.0)
    box.get(timeout=5.0)


# --- case 20: replacement race after the snapshot ---------------------------------


def test_case20_replacement_race_after_the_snapshot():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client_a, control, outcomes_a = start_gated_control(registry, gate)
    hello(client_a)
    manifest = golden_manifest()

    captured = _capture_install_scope(gate)
    fired, resume = _snapshot_barrier(registry)
    box = _run_async(scoped, client_a, 1, manifest)

    assert fired.wait(timeout=5.0), "registry.snapshot wrapper never fired"
    client_b, outcomes_b = _serve_more(control)
    hello(client_b, boot="receiver-b")
    resume.set()

    outcome_a = outcomes_a.get(timeout=5.0)
    assert outcome_a.reason == "session_replaced"
    assert outcome_a.closeout == "not_owner"

    kind, value = box.get(timeout=5.0)
    if kind == "ok":
        assert value.get("error") == "session_replaced"
        assert captured["sentinel"] not in repr(value)
    # Otherwise A's client saw a clean EOF, which is equally acceptable (I6).

    entry = gate.resolve(service="jira", sentinel=captured["sentinel"])
    if entry is not None:
        assert entry.lease_id == captured["lease_id"]
        assert gate.precheck(entry, sentinel=captured["sentinel"]) is False

    manifest_b = golden_manifest(run_id="run-b", attempt_id="attempt-b")
    reply_b = scoped(client_b, 1, manifest_b)
    assert reply_b["ok"] is True

    client_a.close()
    client_b.close()
    outcomes_b.get(timeout=5.0)


# --- case 21: shutdown race, both windows -----------------------------------------


def test_case21_shutdown_race_before_the_check():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    entered, resume, captured = _install_scope_barrier(gate)
    box = _run_async(scoped, client, 1, manifest)

    assert entered.wait(timeout=5.0), "install_scope wrapper never fired"
    control.shutdown()
    resume.set()

    outcome = outcomes.get(timeout=5.0)
    assert outcome.reason == "scope_lease_unverified"
    assert outcome.closeout == "unknown"
    assert registry.snapshot()["registry_state"] == "held"
    assert gate.resolve(service="jira", sentinel=captured["sentinel"]) is None

    kind, value = box.get(timeout=5.0)
    if kind == "ok":
        assert captured["sentinel"] not in repr(value)
    client.close()


def test_case21_shutdown_race_after_the_snapshot():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()

    captured = _capture_install_scope(gate)
    fired, resume = _snapshot_barrier(registry)
    box = _run_async(scoped, client, 1, manifest)

    assert fired.wait(timeout=5.0), "registry.snapshot wrapper never fired"
    control.shutdown()
    resume.set()

    outcome = outcomes.get(timeout=5.0)
    assert outcome.reason == "control_closed"
    assert outcome.closeout == "unknown"
    assert registry.snapshot()["registry_state"] == "held"

    entry = gate.resolve(service="jira", sentinel=captured["sentinel"])
    assert entry is not None
    assert entry.lease_id == captured["lease_id"]

    kind, value = box.get(timeout=5.0)
    if kind == "ok":
        assert captured["sentinel"] not in repr(value)
    client.close()


# --- case 22: cross-owner hold -----------------------------------------------------


def test_case22_cross_owner_hold():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client_a, control, outcomes_a = start_gated_control(registry, gate)
    hello(client_a)
    manifest = golden_manifest()
    reply = scoped(client_a, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    entered = threading.Event()
    resume = threading.Event()

    def blocking_closeout(_lease_id):
        entered.set()
        assert resume.wait(timeout=5.0), "B never replaced A"
        raise RuntimeError("synthetic cross-owner fault")

    gate.closeout = blocking_closeout

    box = _run_async(command, client_a, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})

    assert entered.wait(timeout=5.0), "gate.closeout wrapper never fired"
    client_b, outcomes_b = _serve_more(control)
    hello(client_b, boot="receiver-b")
    resume.set()

    outcome_a = outcomes_a.get(timeout=5.0)
    assert outcome_a.reason == "closeout_unknown"
    assert outcome_a.closeout == "not_owner"
    assert registry.snapshot()["registry_state"] == "held"

    heartbeat_reply = command(client_b, "heartbeat", 1, {})
    assert heartbeat_reply["error"] == "registry_held"
    outcome_b = outcomes_b.get(timeout=5.0)
    assert outcome_b.closeout == "unknown"

    box.get(timeout=5.0)
    client_a.close()
    client_b.close()


# --- case 23: heartbeat gap across the attachment -----------------------------------


def test_case23_heartbeat_gap_across_the_attachment_gives_heartbeat_late():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest1 = golden_manifest()
    reply1 = scoped(client, 1, manifest1)
    assert reply1["ok"] is True
    lease_id1 = reply1["result"]["lease_id"]

    manifest2 = golden_manifest(run_id="run-b", attempt_id="attempt-b")
    data2 = manifest2.canonical_bytes()
    params2 = {
        "run_id": manifest2.run_id, "attempt_id": manifest2.attempt_id,
        "service": manifest2.service, "scope_digest": manifest2.digest,
        "expires_at": 1100.0, "manifest_bytes": len(data2),
    }
    send_frame(client, {"op": "register_scoped", "seq": 2, "params": params2}, timeout=TEST_TIMEOUT)
    clock.advance(15.0)
    send_attachment(client, data2, timeout=TEST_TIMEOUT)
    reply2 = recv_frame(client, timeout=TEST_TIMEOUT)
    assert reply2["error"] == "heartbeat_late"

    outcome = outcomes.get(timeout=5)
    assert outcome.reason == "heartbeat_late"

    snap = registry.snapshot()
    assert snap["retained_records"] == 1
    assert not any(item["run_id"] == "run-b" for item in snap["leases"])
    record1 = next(item for item in snap["leases"] if item["lease_id"] == lease_id1)
    assert record1["state"] == "revoked"
    revokes = [
        item for item in snap["history"]
        if item["operation"] == "revoke" and item["lease_id"] == lease_id1
    ]
    assert revokes and revokes[-1]["reason"] == "heartbeat_late"
    client.close()


# --- case 24: lock order (thread-ownership checks) -----------------------------------


def test_case24_install_scope_and_closeout_run_without_the_control_lock():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)

    real_install_scope = gate.install_scope
    real_closeout = gate.closeout

    def wrapped_install_scope(*, grant, manifest):
        assert not control._lock.held_by_current_thread()
        return real_install_scope(grant=grant, manifest=manifest)

    def wrapped_closeout(lease_id):
        assert not control._lock.held_by_current_thread()
        return real_closeout(lease_id)

    gate.install_scope = wrapped_install_scope
    gate.closeout = wrapped_closeout

    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    closeout_reply = command(client, "closeout", 2, {"lease_id": lease_id})
    assert closeout_reply["ok"] is True

    client.close()
    outcomes.get(timeout=5)


def test_case24_overdue_abort_drained_by_closeout_observes_no_control_lock():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]
    sentinel = reply["result"]["sentinel"]
    activate_reply = command(client, "activate", 2, {"lease_id": lease_id, "launch_at": clock.value})
    assert activate_reply["ok"] is True

    entry = gate.resolve(service="jira", sentinel=sentinel)
    assert entry is not None
    routed = make_routed(entry)
    handle = gate.reserve(
        entry, routed, request_digest=routed.request_digest,
        request_bytes=100, deadline=clock.value + 5.0,
    )
    outcome = gate.admit(handle, sentinel=sentinel)
    assert outcome.code == "admitted"
    admission = outcome.admission

    abort_observed = []

    def abort():
        abort_observed.append(control._lock.held_by_current_thread())

    assert gate.attach_abort(admission, abort) is True

    clock.advance(10.0)  # past the flight deadline

    closeout_reply = command(client, "closeout", 3, {"lease_id": lease_id})
    assert closeout_reply["error"] == "closeout_overdue"
    assert abort_observed == [False]

    client.close()
    outcomes.get(timeout=5)


# --- case 27: custody scan after failed paths -----------------------------------------


def test_case27_custody_scan_install_failure():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    sentinels = _capture_register_sentinels(registry)
    gate.shutdown()
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["error"] == "scope_gate_closed"
    outcome = outcomes.get(timeout=5.0)
    client.close()
    assert sentinels, "no sentinel was minted for this scenario"
    _assert_case27_custody(reply, outcome, control, registry, gate, sentinels, LABEL_MARKER)


def test_case27_custody_scan_binding_mismatch():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest, scope_digest="0" * 64)
    assert reply["error"] == "manifest_binding_mismatch"
    outcome = outcomes.get(timeout=5.0)
    client.close()
    _assert_case27_custody(reply, outcome, control, registry, gate, {}, LABEL_MARKER)


def test_case27_custody_scan_closeout_hold():
    registry, _ledger, gate, _clock, gate_clock = new_gated_system()
    client, control, outcomes = start_gated_control(registry, gate)
    hello(client)
    sentinels = _capture_register_sentinels(registry)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]

    gate_clock.fault = True
    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert revoke_reply["error"] == "closeout_unknown"
    outcome = outcomes.get(timeout=5.0)
    client.close()
    _assert_case27_custody(revoke_reply, outcome, control, registry, gate, sentinels, LABEL_MARKER)


def test_case27_custody_scan_replacement_race_before_the_check():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client_a, control, outcomes_a = start_gated_control(registry, gate)
    hello(client_a)
    manifest = golden_manifest()

    entered, resume, captured = _install_scope_barrier(gate)
    box = _run_async(scoped, client_a, 1, manifest)

    assert entered.wait(timeout=5.0), "install_scope wrapper never fired"
    client_b, outcomes_b = _serve_more(control)
    hello(client_b, boot="receiver-b")
    resume.set()

    outcome_a = outcomes_a.get(timeout=5.0)
    assert outcome_a.reason == "scope_lease_unverified"
    kind, value = box.get(timeout=5.0)
    frame = value if kind == "ok" else {}
    sentinels = {captured["lease_id"]: captured["sentinel"]}
    _assert_case27_custody(frame, outcome_a, control, registry, gate, sentinels, LABEL_MARKER)

    client_a.close()
    client_b.close()
    outcomes_b.get(timeout=5.0)


def test_case27_custody_scan_replacement_race_after_the_snapshot():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client_a, control, outcomes_a = start_gated_control(registry, gate)
    hello(client_a)
    manifest = golden_manifest()

    captured = _capture_install_scope(gate)
    fired, resume = _snapshot_barrier(registry)
    box = _run_async(scoped, client_a, 1, manifest)

    assert fired.wait(timeout=5.0), "registry.snapshot wrapper never fired"
    client_b, outcomes_b = _serve_more(control)
    hello(client_b, boot="receiver-b")
    resume.set()

    outcome_a = outcomes_a.get(timeout=5.0)
    assert outcome_a.reason == "session_replaced"
    kind, value = box.get(timeout=5.0)
    frame = value if kind == "ok" else {}
    sentinels = {captured["lease_id"]: captured["sentinel"]}
    _assert_case27_custody(frame, outcome_a, control, registry, gate, sentinels, LABEL_MARKER)

    client_a.close()
    client_b.close()
    outcomes_b.get(timeout=5.0)


# --- case 28: pathname integration ------------------------------------------------------


def test_case28_pathname_integration_register_scoped_closeout_revoke_stop():
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="maoi-races-") as directory:
        parent = Path(directory).resolve()
        os.chown(parent, -1, os.getegid())
        parent.chmod(0o710)
        clock = FakeClock()
        registry = LeaseRegistry(clock=clock)
        ledger = ReceiptLedger(generation=registry.generation, clock=clock)
        gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
        control = ForwarderControl(
            registry, receiver_uid=os.geteuid(), control_secret=SECRET,
            timeout=TEST_TIMEOUT, gate=gate,
        )
        listener = PrivateControlListener(parent, owner_uid=os.geteuid(), control_gid=os.getegid())
        service = ControlService(listener, control)
        assert service.start() is service

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(TEST_TIMEOUT)
        client.connect(service.endpoint)
        try:
            hello(client)
            manifest = _oversized_manifest()
            assert len(manifest.canonical_bytes()) > MAX_FRAME_BYTES
            reply = scoped(client, 1, manifest)
            assert reply["ok"] is True
            lease_id = reply["result"]["lease_id"]

            closeout_reply = command(client, "closeout", 2, {"lease_id": lease_id})
            assert closeout_reply["ok"] is True

            revoke_reply = command(client, "revoke", 3, {"lease_id": lease_id, "reason": "cancelled"})
            assert revoke_reply["ok"] is True
        finally:
            client.close()

        closeout = service.stop(timeout=5.0)
        assert closeout.state == "stopped"
        gate.shutdown()
