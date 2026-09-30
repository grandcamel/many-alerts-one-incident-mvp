"""Deterministic tests for the gated Forwarder controller (Module 3), Implementer C.

This file owns the shared fixtures and cases 1, 4, 5, 6, 25, 26, and the static
(AST) half of case 24. Two sibling files (``test_forwarder_control_gate_closeout``
and ``test_forwarder_control_gate_races``, owned by other testers) import the
module-level helpers below rather than redefining them.
"""

from __future__ import annotations

import ast
import os
import queue
import socket
import threading
import time
from pathlib import Path
from typing import Self

import pytest

from grafana_jsm_sandbox import forwarder_control as module
from grafana_jsm_sandbox.forwarder_control import ForwarderControl, authenticate_receiver
from grafana_jsm_sandbox.forwarder_control_protocol import (
    ControlProtocolError,
    recv_frame,
    send_attachment,
    send_frame,
)
from grafana_jsm_sandbox.forwarder_dispatch import DispatchGate
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptLedger
from tests.test_forwarder_dispatch import FakeClock
from tests.test_forwarder_routes import SCOPE_DIGEST, golden_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_control.py"

SECRET = b"s" * 32
TEST_TIMEOUT = 2.0

_UNSET = object()


# --- fixtures and helpers (imported by the sibling case files) ----------------


class GateClock:
    """Wrap a shared clock for the gate alone; raises while ``fault`` is set (case 15)."""

    def __init__(self, clock):
        self._clock = clock
        self.fault = False

    def __call__(self) -> float:
        if self.fault:
            raise RuntimeError("gate_clock_fault")
        return self._clock()


def new_gated_system() -> tuple[LeaseRegistry, ReceiptLedger, DispatchGate, FakeClock, GateClock]:
    """One FakeClock shared by registry/ledger; the gate runs on a GateClock wrapper."""
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate_clock = GateClock(clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=gate_clock)
    return registry, ledger, gate, clock, gate_clock


class OwnedLock:
    """A ``threading.Lock`` substitute that records which thread currently holds it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner: threading.Thread | None = None

    def acquire(self, *args, **kwargs) -> bool:
        acquired = self._lock.acquire(*args, **kwargs)
        if acquired:
            self._owner = threading.current_thread()
        return acquired

    def release(self) -> None:
        self._owner = None
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

    def held_by_current_thread(self) -> bool:
        """True only on the thread that currently holds the lock (the lock-order predicate)."""
        return self._owner is threading.current_thread()


def start_gated_control(
    registry: LeaseRegistry, gate: DispatchGate | None, *,
    timeout: float = TEST_TIMEOUT, secret: bytes = SECRET,
) -> tuple[socket.socket, ForwarderControl, queue.Queue]:
    """Build a ``ForwarderControl`` with an ``OwnedLock`` and serve one socketpair connection."""
    control = ForwarderControl(
        registry, receiver_uid=os.geteuid(), control_secret=secret, timeout=timeout, gate=gate,
    )
    control._lock = OwnedLock()
    client, server = socket.socketpair()
    outcomes: queue.Queue = queue.Queue()
    worker = threading.Thread(target=lambda: outcomes.put(control.serve_connection(server)))
    worker.start()
    return client, control, outcomes


def hello(client: socket.socket, boot: str = "receiver-a", secret: bytes = SECRET):
    """``authenticate_receiver`` with this file's defaults."""
    return authenticate_receiver(
        client, control_secret=secret, forwarder_uid=os.geteuid(),
        receiver_boot_id=boot, timeout=TEST_TIMEOUT,
    )


def command(client: socket.socket, op: str, seq: int, params: dict) -> dict:
    """Send one JSON command frame and return its parsed reply."""
    send_frame(client, {"op": op, "seq": seq, "params": params}, timeout=TEST_TIMEOUT)
    return recv_frame(client, timeout=TEST_TIMEOUT)


def scoped(client: socket.socket, seq: int, manifest, *, attachment=_UNSET, **overrides) -> dict:
    """Send a ``register_scoped`` header plus its attachment; return the parsed reply.

    ``overrides`` replace header parameters. ``attachment=None`` withholds the
    attachment entirely (for a header-only failure); any other value replaces
    the manifest's own canonical bytes.
    """
    data = manifest.canonical_bytes()
    params = {
        "run_id": manifest.run_id, "attempt_id": manifest.attempt_id, "service": manifest.service,
        "scope_digest": manifest.digest, "expires_at": 1100.0, "manifest_bytes": len(data),
    }
    params.update(overrides)
    header = {"op": "register_scoped", "seq": seq, "params": params}
    send_frame(client, header, timeout=TEST_TIMEOUT)
    body = data if attachment is _UNSET else attachment
    if body is not None:
        send_attachment(client, body, timeout=TEST_TIMEOUT)
    return recv_frame(client, timeout=TEST_TIMEOUT)


def allowed(registry: LeaseRegistry, grant: dict, *, scope_digest: str = SCOPE_DIGEST) -> bool:
    """True when ``grant`` (a projected register reply) is currently authorized."""
    return registry.check(
        service=grant["service"], sentinel=grant["sentinel"],
        generation=registry.generation, scope_digest=scope_digest,
    ).authorized


def _register_params(service: str = "jira", *, run_id: str = "run-a",
                     attempt_id: str = "attempt-a") -> dict:
    """The 5-key gateless/gated ``register`` parameter set."""
    return {
        "run_id": run_id, "attempt_id": attempt_id, "service": service,
        "scope_digest": SCOPE_DIGEST, "expires_at": 1100.0,
    }


# --- case 1: happy path --------------------------------------------------------


def test_case1_happy_path_register_scoped():
    registry, _ledger, gate, clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    result = reply["result"]
    assert set(result) == set(module._GRANT_FIELDS) | {"installed_at"}
    sentinel = result["sentinel"]
    entry = gate.resolve(service="jira", sentinel=sentinel)
    assert entry is not None
    assert entry.scope_digest == result["scope_digest"] == manifest.digest
    assert entry.manifest.digest == manifest.digest
    assert entry.installed_at == result["installed_at"]
    assert gate.precheck(entry, sentinel=sentinel) is False
    activate_reply = command(client, "activate", 2, {
        "lease_id": result["lease_id"], "launch_at": clock.value,
    })
    assert activate_reply["ok"] is True
    assert gate.precheck(entry, sentinel=sentinel) is True
    client.close()
    outcome = outcomes.get(timeout=2)
    assert outcome.closeout == "revoked"
    assert sentinel not in repr(outcome)
    assert sentinel not in repr(registry.snapshot())
    assert sentinel not in repr(gate.snapshot())


# --- case 4: gated register is always refused ----------------------------------


def test_case4a_gated_register_refused_as_first_command():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    reply = command(client, "register", 1, _register_params())
    assert reply["error"] == "scope_required"
    outcome = outcomes.get(timeout=2)
    assert outcome.commands == 0
    assert outcome.closeout == "revoked"
    assert registry.snapshot()["retained_records"] == 0
    client.close()


def test_case4b_gated_register_refused_after_register_scoped():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest)
    assert reply["ok"] is True
    lease_id = reply["result"]["lease_id"]
    second_params = _register_params(run_id="run-b", attempt_id="attempt-b")
    refusal = command(client, "register", 2, second_params)
    assert refusal["error"] == "scope_required"
    outcome = outcomes.get(timeout=2)
    assert outcome.commands == 1
    assert outcome.closeout == "revoked"
    revokes = [
        item for item in registry.snapshot()["history"]
        if item["operation"] == "revoke" and item["lease_id"] == lease_id
    ]
    assert revokes and revokes[-1]["reason"] == "receiver_disconnected"
    client.close()


def test_case4c_gated_register_refused_before_the_parameter_schema():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    reply = command(client, "register", 1, {})
    assert reply["error"] == "scope_required"
    outcome = outcomes.get(timeout=2)
    assert outcome.commands == 0
    client.close()


# --- case 5: unscoped and unknown services under register_scoped ---------------


@pytest.mark.parametrize("service", ["confluence", "grafana", "kubernetes", "anthropic"])
def test_case5_unscoped_service_gives_scope_type_unavailable_before_attachment(service):
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    params = {
        "run_id": "run-a", "attempt_id": "attempt-a", "service": service,
        "scope_digest": SCOPE_DIGEST, "expires_at": 1100.0, "manifest_bytes": 16,
    }
    started = time.monotonic()
    send_frame(client, {"op": "register_scoped", "seq": 1, "params": params}, timeout=TEST_TIMEOUT)
    reply = recv_frame(client, timeout=TEST_TIMEOUT)
    elapsed = time.monotonic() - started
    assert reply["error"] == "scope_type_unavailable"
    assert elapsed < 1.0, "must not wait for a withheld attachment"
    assert registry.snapshot()["retained_records"] == 0
    client.close()
    outcomes.get(timeout=2)


@pytest.mark.parametrize("service", ["ghost", 7])
def test_case5_unknown_or_nonstr_service_gives_invalid_service(service):
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    params = {
        "run_id": "run-a", "attempt_id": "attempt-a", "service": service,
        "scope_digest": SCOPE_DIGEST, "expires_at": 1100.0, "manifest_bytes": 16,
    }
    reply = command(client, "register_scoped", 1, params)
    assert reply["error"] == "invalid_service"
    client.close()
    outcomes.get(timeout=2)


# --- case 6: bad manifest_bytes, no attachment ever sent ------------------------


@pytest.mark.parametrize("manifest_bytes,code", [
    (16_385, "manifest_too_large"),
    (0, "invalid_manifest_length"),
    (True, "invalid_manifest_length"),
    (1.5, "invalid_manifest_length"),
    ("12", "invalid_manifest_length"),
])
def test_case6_bad_manifest_bytes_no_attachment_sent(manifest_bytes, code):
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, gate)
    hello(client)
    manifest = golden_manifest()
    reply = scoped(client, 1, manifest, manifest_bytes=manifest_bytes, attachment=None)
    assert reply["error"] == code
    assert registry.snapshot()["retained_records"] == 0
    client.close()
    outcomes.get(timeout=2)


# --- case 24 (static half): no scope/gate/attachment call under the lock -------


def _context_is_self_attr(expr: ast.AST, name: str) -> bool:
    return (
        isinstance(expr, ast.Attribute) and expr.attr == name
        and isinstance(expr.value, ast.Name) and expr.value.id == "self"
    )


def _is_forbidden_call(func: ast.AST) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "recv_attachment"
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id == "scope":
            return True
        if _context_is_self_attr(func.value, "_gate"):
            return True
    return False


def test_case24_ast_no_scope_or_gate_calls_under_the_control_lock():
    """Static half of case 24: no ``scope.*``, ``self._gate.*`` or ``recv_attachment``
    call is lexically inside any ``with self._lock:`` body in forwarder_control.py."""
    tree = ast.parse(MODULE_PATH.read_text())
    violations = []
    for node in ast.walk(tree):
        is_lock_with = isinstance(node, ast.With) and any(
            _context_is_self_attr(item.context_expr, "_lock") for item in node.items
        )
        if not is_lock_with:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and _is_forbidden_call(inner.func):
                violations.append(ast.dump(inner))
    assert violations == []


# --- case 25: gateless (gate=None) legacy identity ------------------------------


def test_case25_register_scoped_is_unknown_operation_gateless():
    registry, *_rest = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, None)
    hello(client)
    assert command(client, "register_scoped", 1, {})["error"] == "unknown_operation"
    assert outcomes.get(timeout=2).closeout == "revoked"
    client.close()


def test_case25_closeout_is_unknown_operation_gateless():
    registry, *_rest = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, None)
    hello(client)
    assert command(client, "closeout", 1, {"lease_id": "lease-x"})["error"] == "unknown_operation"
    assert outcomes.get(timeout=2).closeout == "revoked"
    client.close()


@pytest.mark.parametrize("service", ["confluence", "grafana", "kubernetes", "anthropic"])
def test_case25_unscoped_register_adds_no_command_or_record_gateless(service):
    """The refusal itself adds no command/record; the session's earlier Jira
    lease still ends up revoked when the refusal ends the session."""
    registry, *_rest = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, None)
    hello(client)
    jira_reply = command(client, "register", 1, _register_params())
    assert jira_reply["ok"] is True
    grant = jira_reply["result"]
    refusal = command(
        client, "register", 2, _register_params(service, run_id="run-b", attempt_id="attempt-b"),
    )
    assert refusal["error"] == "scope_type_unavailable"
    outcome = outcomes.get(timeout=2)
    assert outcome.commands == 1
    assert outcome.closeout == "revoked"
    assert registry.snapshot()["retained_records"] == 1
    assert allowed(registry, grant) is False
    client.close()


@pytest.mark.parametrize("service", ["ghost", 7])
def test_case25_unknown_or_nonstr_service_still_invalid_service_gateless(service):
    registry, *_rest = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, None)
    hello(client)
    reply = command(client, "register", 1, _register_params(service))
    assert reply["error"] == "invalid_service"
    assert outcomes.get(timeout=2).commands == 1
    client.close()


def test_case25_jira_register_and_revoke_reply_keys_gateless():
    registry, *_rest = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, None)
    hello(client)
    reply = command(client, "register", 1, _register_params())
    assert set(reply["result"]) == set(module._GRANT_FIELDS)
    lease_id = reply["result"]["lease_id"]
    revoke_reply = command(client, "revoke", 2, {"lease_id": lease_id, "reason": "cancelled"})
    assert set(revoke_reply["result"]) == set(module._RECEIPT_FIELDS)
    client.close()
    outcomes.get(timeout=2)


def test_case25_gateless_jira_lease_is_inert_at_a_separate_gate():
    registry, _ledger, gate, _clock, _gate_clock = new_gated_system()
    client, _control, outcomes = start_gated_control(registry, None)
    hello(client)
    reply = command(client, "register", 1, _register_params())
    sentinel = reply["result"]["sentinel"]
    assert gate.resolve(service="jira", sentinel=sentinel) is None
    assert gate.snapshot()["scope_entries"] == ()
    client.close()
    outcomes.get(timeout=2)


# --- case 26: constructor --------------------------------------------------------


def test_case26_constructor_rejects_non_gate_or_mismatched_registry():
    registry, *_rest = new_gated_system()
    with pytest.raises(ControlProtocolError) as caught:
        ForwarderControl(registry, receiver_uid=os.geteuid(), control_secret=SECRET,
                         timeout=TEST_TIMEOUT, gate="not-a-gate")
    assert caught.value.code == "invalid_gate"

    _other_registry, _other_ledger, other_gate, _other_clock, _other_gate_clock = new_gated_system()
    with pytest.raises(ControlProtocolError) as caught2:
        ForwarderControl(registry, receiver_uid=os.geteuid(), control_secret=SECRET,
                         timeout=TEST_TIMEOUT, gate=other_gate)
    assert caught2.value.code == "invalid_gate"
