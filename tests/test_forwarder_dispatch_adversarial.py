"""Adversarial tests for the atomic dispatch gate (Module 1), Tester C1's third file.

Covers: an AST walk of ``forwarder_dispatch.py`` (no ``raise`` inside an
``except`` block, an exact import allowlist, forbidden stdlib modules);
forged/copied/cross-gate tokens; a walk of every ``DispatchError`` code for a
clean exception chain and no leaked marker; that no sentinel or index key
ever appears in the gate's exposed state; and that admission/fence outcome
codes map only to their documented reasons.

The AST checks below cover only ``forwarder_dispatch.py`` (plan Module 1):
this file's assignment is scoped to that module's own rules (forgeries,
exception chains, secret walk and closed codes are all Module-1 concepts --
``ScopeEntry``/``DispatchHandle``/``Admission``/``DispatchGate``). Module 2's
own AST allowlist and adversarial behavior (``forwarder_exchange.py``, built
concurrently by another implementer) belongs in
``tests/test_forwarder_exchange_adversarial.py``, a separate file this task
does not own.
"""

from __future__ import annotations

import ast
import copy
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox.forwarder_dispatch import (
    ADMISSION_CODES,
    DISPATCH_ERROR_CODES,
    WRITE_FENCE_CODES,
    Admission,
    DispatchError,
    DispatchGate,
    DispatchHandle,
    ScopeEntry,
)
from grafana_jsm_sandbox.forwarder_leases import LeaseError, LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptError, ReceiptLedger
from grafana_jsm_sandbox.forwarder_routes import RouteConfigError
from tests.test_forwarder_dispatch import (
    BOOT,
    assert_error,
    do_reserve,
    install,
    make_routed,
    new_system,
    register,
    reserve_and_admit,
)
from tests.test_forwarder_routes import golden_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
DISPATCH_MODULE_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_dispatch.py"

# --- Module 1's exact allowlist (plan: "Imports (AST-checked by exact name)") ----

DISPATCH_ALLOWED_STDLIB_PLAIN = {"hashlib", "hmac", "math", "secrets", "threading", "time"}
DISPATCH_ALLOWED_STDLIB_FROM = {
    "__future__": {"annotations"},
    "collections.abc": {"Callable"},
    "dataclasses": {"dataclass", "field"},
}
DISPATCH_ALLOWED_RELATIVE = {
    "forwarder_leases": {"LeaseError", "LeaseGrant", "LeaseRegistry"},
    "forwarder_receipts": {
        "MAX_HANDLER_SECONDS", "ForwarderReceipt", "ReceiptError", "ReceiptLedger",
        "ReceiptReservation",
    },
    "forwarder_routes": {
        "ROUTE_CATALOG", "RouteConfigError", "RoutedRequest", "ScopeManifest",
        "require_manifest_binding",
    },
    "forwarder_http_response": {"ParsedResponse"},
    "forwarder_services": {"SERVICE_PROFILES"},
}
FORBIDDEN_MODULE_ROOTS = {"socket", "ssl", "select", "os", "subprocess", "importlib"}


def _parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(), filename=str(path))


# --- AST: no raise inside an except handler ----------------------------------


def test_ast_no_raise_inside_except_handler():
    tree = _parse(DISPATCH_MODULE_PATH)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Raise):
                    offenders.append(inner.lineno)
    assert not offenders, (
        f"an except handler must only record a fixed code; a fresh DispatchError "
        f"is raised after the try statement ends (raise at line(s) {offenders})"
    )


# --- AST: exact import allowlist and forbidden modules -----------------------


def test_ast_import_allowlist_is_exact():
    tree = _parse(DISPATCH_MODULE_PATH)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in DISPATCH_ALLOWED_STDLIB_PLAIN, f"unlisted import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = {alias.name for alias in node.names}
            if node.level == 0:
                expected = DISPATCH_ALLOWED_STDLIB_FROM.get(module)
                assert expected is not None, f"unlisted stdlib import: from {module}"
                assert names <= expected, (
                    f"unlisted names from {module}: {names - expected}"
                )
            elif node.level == 1:
                expected = DISPATCH_ALLOWED_RELATIVE.get(module)
                assert expected is not None, f"unlisted relative import: from .{module}"
                assert names <= expected, (
                    f"unlisted names from .{module}: {names - expected}"
                )
            else:
                pytest.fail(f"unexpected relative import level {node.level} (from {module})")


def test_ast_forbidden_modules_are_absent_with_no_type_checking_exception():
    tree = _parse(DISPATCH_MODULE_PATH)
    for node in ast.walk(tree):
        # No TYPE_CHECKING exception: forbidden modules are checked over the
        # *whole* tree, including anything nested under an `if TYPE_CHECKING`
        # block, not only top-level statements.
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            root = (node.module or "").split(".")[0]
            assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {node.module}"
        elif isinstance(node, ast.Name) and node.id == "__import__":
            pytest.fail("__import__ must never be referenced")
    assert "TYPE_CHECKING" not in DISPATCH_MODULE_PATH.read_text()


# --- forgeries: identity-authenticated tokens ---------------------------------


def test_forged_and_copied_scope_entries_are_refused():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)

    forged_entry = replace(entry)
    copied_entry = copy.copy(entry)
    assert type(forged_entry) is ScopeEntry and forged_entry is not entry
    assert gate.precheck(forged_entry, sentinel=grant.sentinel) is False
    assert gate.precheck(copied_entry, sentinel=grant.sentinel) is False

    routed = make_routed(entry)
    assert_error(
        lambda: gate.reserve(forged_entry, routed, request_digest=routed.request_digest,
                              request_bytes=1, deadline=clock.value + 30.0),
        "scope_unknown",
    )
    digest = hashlib.sha256(b"forged-scope-entry").hexdigest()
    assert_error(
        lambda: gate.deny(forged_entry, route_id="unmatched", request_digest=digest,
                           reason="lease_denied", request_bytes=1, deadline=clock.value + 30.0),
        "scope_unknown",
    )

    # The real entry is unaffected by the refused forgeries above.
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"


def test_forged_and_copied_dispatch_handles_are_refused():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)

    forged_handle = replace(handle)
    copied_handle = copy.copy(handle)
    assert type(forged_handle) is DispatchHandle and forged_handle is not handle

    assert_error(lambda: gate.admit(forged_handle, sentinel=grant.sentinel), "handle_unknown")
    assert_error(lambda: gate.admit(copied_handle, sentinel=grant.sentinel), "handle_unknown")
    assert gate.release(forged_handle) is False
    assert gate.release(copied_handle) is False

    # The real handle still admits after the forgeries above were refused.
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"


def test_forged_and_copied_admissions_are_refused():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)

    forged_admission = replace(admission)
    copied_admission = copy.copy(admission)
    assert type(forged_admission) is Admission and forged_admission is not admission

    assert_error(lambda: gate.begin_write(forged_admission, sentinel=grant.sentinel),
                 "admission_unknown")
    assert_error(lambda: gate.begin_write(copied_admission, sentinel=grant.sentinel),
                 "admission_unknown")
    assert_error(lambda: gate.finish(forged_admission, dispatch_state="FAILED",
                                      reason="connect_failed"), "admission_unknown")
    assert_error(lambda: gate.attach_abort(forged_admission, lambda: None), "admission_unknown")
    assert gate.is_admitted(forged_admission) is False
    assert gate.is_admitted(copied_admission) is False
    assert gate.release(forged_admission) is False
    assert gate.release(copied_admission) is False

    # The real admission is unaffected: it still fences and finishes cleanly.
    write_outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert write_outcome.code == "write_admitted"
    # "dispatched" only legally finalizes into DISPATCHED_UNKNOWN/PARTIAL/
    # TRANSPORT_CONFIRMED (FAILED is only legal from "connecting").
    receipt = gate.finish(admission, dispatch_state="DISPATCHED_UNKNOWN", reason="write_failed")
    assert receipt.dispatch_state == "DISPATCHED_UNKNOWN"


def test_cross_gate_tokens_are_refused():
    gate1, registry1, _ledger1, clock1 = new_system()
    gate2, registry2, _ledger2, clock2 = new_system()
    grant1, entry1 = install(gate1, registry1, clock1, active=True, ttl=200.0)
    install(gate2, registry2, clock2, active=True, ttl=200.0)

    assert gate2.precheck(entry1, sentinel=grant1.sentinel) is False

    handle1 = do_reserve(gate1, entry1, clock1, ttl=30.0)
    assert_error(lambda: gate2.admit(handle1, sentinel=grant1.sentinel), "handle_unknown")
    assert gate2.release(handle1) is False

    admission1 = reserve_and_admit(gate1, entry1, grant1, clock1, ttl=30.0)
    assert_error(lambda: gate2.begin_write(admission1, sentinel=grant1.sentinel),
                 "admission_unknown")
    assert gate2.release(admission1) is False

    # The tokens still work correctly against their own gate.
    outcome = gate1.begin_write(admission1, sentinel=grant1.sentinel)
    assert outcome.code == "write_admitted"


def test_second_gate_over_claimed_pair_is_refused():
    _gate, registry, ledger, clock = new_system()
    assert_error(lambda: DispatchGate(registry=registry, ledger=ledger, clock=clock),
                 "authority_claimed")

    other_ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    assert_error(lambda: DispatchGate(registry=registry, ledger=other_ledger, clock=clock),
                 "authority_claimed")
    # A refused claim leaves the *other* object untouched (claims neither).
    assert not getattr(other_ledger, "_maoi_dispatch_gate_claimed", False)


def test_second_gate_over_a_copy_of_a_claimed_registry_is_refused():
    _gate, registry, _ledger, clock = new_system()
    copied_registry = copy.copy(registry)
    assert type(copied_registry) is LeaseRegistry
    fresh_ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    # The copy carries the copied claim marker: fail-closed, per the plan.
    assert_error(lambda: DispatchGate(registry=copied_registry, ledger=fresh_ledger, clock=clock),
                 "authority_claimed")


def test_second_gate_over_a_copy_of_a_claimed_ledger_is_refused():
    _gate, registry, ledger, clock = new_system()
    copied_ledger = copy.copy(ledger)
    assert type(copied_ledger) is ReceiptLedger
    assert copied_ledger.generation == registry.generation
    # LeaseRegistry's generation is auto-assigned and unsettable via the
    # public API, so a *fresh, unclaimed* registry with a matching
    # generation cannot be constructed; pairing the copy with the original
    # (already-claimed) registry still proves a copied ledger carries its
    # claim marker and is refused.
    assert_error(lambda: DispatchGate(registry=registry, ledger=copied_ledger, clock=clock),
                 "authority_claimed")
    assert getattr(copied_ledger, "_maoi_dispatch_gate_claimed", False) is True


# --- exception chains: every DispatchError code, no leaked marker ------------


def _assert_clean_chain(error: DispatchError, code: str) -> None:
    assert isinstance(error, DispatchError)
    assert error.code == code
    assert error.args == (code,)
    assert str(error) == code
    assert error.__cause__ is None
    assert error.__context__ is None
    assert set(vars(error)) == {"code"}, "a DispatchError must carry no attribute beyond .code"


def _assert_no_marker(error: DispatchError, marker: str) -> None:
    assert marker not in str(error)
    assert marker not in repr(error)
    assert all(marker not in str(value) for value in error.args)


def test_clock_fault_then_gate_held_chains_are_clean():
    gate, _registry, _ledger, _clock = new_system()
    marker = "MARK-CLOCK-9f2e11"

    def faulting():
        raise RuntimeError(marker)

    gate._clock = faulting
    fault_error = assert_error(lambda: gate.now(), "clock_fault")
    _assert_clean_chain(fault_error, "clock_fault")
    _assert_no_marker(fault_error, marker)

    held_error = assert_error(lambda: gate.now(), "gate_held")
    _assert_clean_chain(held_error, "gate_held")


def test_gate_closed_chain_is_clean():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    gate.shutdown()
    error = assert_error(lambda: do_reserve(gate, entry, clock), "gate_closed")
    _assert_clean_chain(error, "gate_closed")


def test_generation_mismatch_and_authority_claimed_chains_are_clean():
    gate, registry, _ledger, clock = new_system()
    other_ledger = ReceiptLedger(generation="a-different-generation", clock=clock)
    mismatch = assert_error(
        lambda: DispatchGate(registry=registry, ledger=other_ledger, clock=clock),
        "generation_mismatch",
    )
    _assert_clean_chain(mismatch, "generation_mismatch")

    claimed = assert_error(
        lambda: DispatchGate(registry=registry, ledger=gate.ledger, clock=clock),
        "authority_claimed",
    )
    _assert_clean_chain(claimed, "authority_claimed")


def test_manifest_binding_mismatch_chain_is_clean_with_planted_marker(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    marker = "MARK-MANIFEST-7ab1cd"

    def fake_binding(*_args, **_kwargs):
        raise RouteConfigError(marker)

    with monkeypatch.context() as patch:
        patch.setattr(fd, "require_manifest_binding", fake_binding)
        error = assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest),
                              "manifest_binding_mismatch")
    _assert_clean_chain(error, "manifest_binding_mismatch")
    _assert_no_marker(error, marker)


def test_grant_expired_chain_is_clean():
    # Only reachable by diverging the gate's own clock from the registry's
    # (see forwarder_dispatch._install_scope_locked step 6): the registry
    # must still consider the lease live while the gate's own later-read
    # "now" has already passed its expiry. tests.test_forwarder_dispatch
    # uses the same "offset clock" technique for clock_domain_mismatch.
    class FixedClock:
        def __init__(self, value):
            self.value = value

        def __call__(self):
            return self.value

    registry_clock = FixedClock(1_000.0)
    registry = LeaseRegistry(clock=registry_clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=registry_clock)
    manifest = golden_manifest()
    grant = registry.register(
        run_id="run-1", attempt_id="attempt-1", receiver_boot_id=BOOT, service="jira",
        scope_digest=manifest.digest, expires_at=registry_clock.value + 5.0,
        generation=registry.generation,
    )
    gate_clock = FixedClock(registry_clock.value + 5.0)  # already at the grant's expiry
    gate = DispatchGate(registry=registry, ledger=ledger, clock=gate_clock)

    error = assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest))
    assert error.code == "grant_expired"
    _assert_clean_chain(error, "grant_expired")


def test_lease_unverified_chain_is_clean_with_planted_marker(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    marker = "MARK-LEASE-4d3ce2"

    def fake_check(*_args, **_kwargs):
        raise LeaseError(marker)

    with monkeypatch.context() as patch:
        patch.setattr(registry, "check", fake_check)
        error = assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest),
                              "lease_unverified")
    _assert_clean_chain(error, "lease_unverified")
    _assert_no_marker(error, marker)


def test_scope_conflict_chain_is_clean():
    # White-box index collision: the only way to reach this branch without a
    # hash collision (same technique tests.test_forwarder_dispatch uses).
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    manifest2 = golden_manifest(run_id="run-x", attempt_id="attempt-x")
    grant2 = register(registry, clock, run_id="run-x", attempt_id="attempt-x",
                       scope_digest=manifest2.digest)
    foreign_index = gate._index_for(grant2.service, grant2.sentinel)
    with gate._G:
        gate._scope_by_index[foreign_index] = entry
        gate._scope_index_by_lease[grant2.lease_id] = foreign_index
    error = assert_error(lambda: gate.install_scope(grant=grant2, manifest=manifest2),
                          "scope_conflict")
    _assert_clean_chain(error, "scope_conflict")


def test_scope_capacity_chain_is_clean(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    with monkeypatch.context() as patch:
        patch.setattr(fd, "MAX_SCOPE_ENTRIES", 0)
        error = assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest),
                              "scope_capacity")
    _assert_clean_chain(error, "scope_capacity")


def test_scope_unknown_binding_mismatch_route_unavailable_and_lease_boundary_chains():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True, ttl=200.0)

    foreign_entry = replace(entry, lease_id="lease_" + "z" * 20)
    routed = make_routed(foreign_entry)
    error = assert_error(lambda: gate.reserve(
        foreign_entry, routed, request_digest=routed.request_digest,
        request_bytes=1, deadline=clock.value + 5.0,
    ), "scope_unknown")
    _assert_clean_chain(error, "scope_unknown")

    routed2 = make_routed(entry)
    forged_routed = replace(routed2, scope_digest=hashlib.sha256(b"other").hexdigest())
    error = assert_error(lambda: gate.reserve(
        entry, forged_routed, request_digest=forged_routed.request_digest,
        request_bytes=1, deadline=clock.value + 5.0,
    ), "binding_mismatch")
    _assert_clean_chain(error, "binding_mismatch")

    unavailable_routed = make_routed(entry, route_id="jira.issue.create")
    error = assert_error(lambda: gate.reserve(
        entry, unavailable_routed, request_digest=unavailable_routed.request_digest,
        request_bytes=1, deadline=clock.value + 5.0,
    ), "route_unavailable")
    _assert_clean_chain(error, "route_unavailable")

    _grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                               active=True, ttl=10.0)
    error = assert_error(lambda: do_reserve(gate, entry2, clock, ttl=20.0),
                          "deadline_exceeds_lease")
    _assert_clean_chain(error, "deadline_exceeds_lease")


def test_dispatch_capacity_chain_is_clean(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    with monkeypatch.context() as patch:
        patch.setattr(fd, "MAX_OPEN_DISPATCHES", 1)
        do_reserve(gate, entry, clock)
        error = assert_error(lambda: do_reserve(gate, entry, clock), "dispatch_capacity")
    _assert_clean_chain(error, "dispatch_capacity")


def test_receipt_unavailable_chain_is_clean_with_planted_marker(monkeypatch):
    gate, registry, ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    marker = "MARK-RECEIPT-1e8899"

    def fake_reserve(*_args, **_kwargs):
        raise ReceiptError(marker)

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "reserve", fake_reserve)
        error = assert_error(lambda: do_reserve(gate, entry, clock), "receipt_unavailable")
    _assert_clean_chain(error, "receipt_unavailable")
    _assert_no_marker(error, marker)


def test_invalid_reason_chain_is_clean():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    digest = hashlib.sha256(b"deny-digest").hexdigest()
    error = assert_error(lambda: gate.deny(
        entry, route_id="unmatched", request_digest=digest, reason="abandoned",
        request_bytes=1, deadline=clock.value + 5.0,
    ), "invalid_reason")
    _assert_clean_chain(error, "invalid_reason")


def test_handle_unknown_and_handle_consumed_chains_are_clean():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    forged = replace(handle, receipt_id="forged-" + handle.receipt_id)

    unknown_error = assert_error(lambda: gate.admit(forged, sentinel=grant.sentinel),
                                  "handle_unknown")
    _assert_clean_chain(unknown_error, "handle_unknown")

    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"
    consumed_error = assert_error(lambda: gate.admit(handle, sentinel=grant.sentinel),
                                   "handle_consumed")
    _assert_clean_chain(consumed_error, "handle_consumed")


def test_deadline_expired_at_admit_chain_is_clean():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=2.0)
    clock.advance(3.0)
    error = assert_error(lambda: gate.admit(handle, sentinel=grant.sentinel), "deadline_expired")
    _assert_clean_chain(error, "deadline_expired")


def test_admission_unknown_and_write_claimed_chains_are_clean():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    forged = replace(admission, receipt_id="forged-" + admission.receipt_id)

    unknown_error = assert_error(lambda: gate.begin_write(forged, sentinel=grant.sentinel),
                                  "admission_unknown")
    _assert_clean_chain(unknown_error, "admission_unknown")

    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "write_admitted"
    claimed_error = assert_error(lambda: gate.begin_write(admission, sentinel=grant.sentinel),
                                  "write_claimed")
    _assert_clean_chain(claimed_error, "write_claimed")


def test_invalid_outcome_chain_is_clean():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    # Still only "admitted" (connecting): NOT_DISPATCHED is not a legal
    # finalize from that ledger state, so this is the illegal transition.
    error = assert_error(
        lambda: gate.finish(admission, dispatch_state="NOT_DISPATCHED", reason="abandoned"),
        "invalid_outcome",
    )
    _assert_clean_chain(error, "invalid_outcome")
    # The flight is kept on invalid_outcome, so a legal retry still works.
    receipt = gate.finish(admission, dispatch_state="FAILED", reason="connect_failed")
    assert receipt.dispatch_state == "FAILED"


ALL_COVERED_CODES = frozenset({
    "clock_fault", "gate_held", "gate_closed", "generation_mismatch", "authority_claimed",
    "manifest_binding_mismatch", "grant_expired", "lease_unverified", "scope_conflict",
    "scope_capacity", "scope_unknown", "binding_mismatch", "route_unavailable",
    "deadline_exceeds_lease", "dispatch_capacity", "receipt_unavailable", "invalid_reason",
    "handle_unknown", "handle_consumed", "deadline_expired", "admission_unknown",
    "write_claimed", "invalid_outcome",
})


def test_every_dispatch_error_code_has_a_covering_scenario_above():
    # A static completeness guard: if the source enum ever grows or shrinks,
    # this fails loudly as a reminder to add/retire a chain-walk scenario,
    # rather than silently leaving a code unexercised by this file.
    assert ALL_COVERED_CODES == DISPATCH_ERROR_CODES


# --- secret walk: no sentinel, no index key -----------------------------------


def test_secret_walk_excludes_sentinel_and_index_key():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    sentinel = grant.sentinel
    index_key = gate._index_key
    index_key_repr = repr(index_key)

    gate_state_repr = repr({
        key: value for key, value in vars(gate).items() if key not in ("_registry", "_ledger")
    })
    surfaces = {
        "gate state (excluding registry/ledger)": gate_state_repr,
        "snapshot": repr(gate.snapshot()),
        "closeout": repr(gate.closeout(grant.lease_id)),
        "scope entry repr": repr(entry),
        "admission repr": repr(admission),
        "gate repr": repr(gate),
    }
    for label, text in surfaces.items():
        assert sentinel not in text, f"sentinel leaked via {label}"
        assert sentinel.encode("ascii") not in text.encode("utf-8", errors="ignore"), (
            f"sentinel leaked (bytes form) via {label}"
        )
    # The raw index key legitimately lives in the gate's own private state
    # (that surface is excluded above); it must never appear anywhere else.
    for label, text in surfaces.items():
        if label == "gate state (excluding registry/ledger)":
            continue
        assert index_key_repr not in text, f"index key leaked via {label}"
        assert index_key.hex() not in text, f"index key leaked (hex form) via {label}"


def test_flight_index_is_an_hmac_digest_not_the_raw_sentinel_or_key():
    # Defence in depth for the secret walk: the per-flight "index" bytes
    # (visible only white-box; never returned by a public method) must be an
    # HMAC digest, never the sentinel or the raw key reused verbatim.
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    with gate._G:
        flight = gate._flights[handle.receipt_id]
        index_bytes = flight.index
    assert isinstance(index_bytes, bytes) and len(index_bytes) == 32
    assert index_bytes != gate._index_key
    assert index_bytes != grant.sentinel.encode("ascii", errors="ignore")


# --- closed codes: admission and fence outcomes map only to legal reasons ----


def test_admission_denial_reasons_match_the_documented_mapping():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=1.999)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "insufficient_time"
    assert outcome.denial.reason == "deadline"
    assert outcome.denial.dispatch_state == "NOT_DISPATCHED"

    gate2, registry2, _ledger2, clock2 = new_system()
    grant2, entry2 = install(gate2, registry2, clock2, active=True, ttl=200.0)
    handle2 = do_reserve(gate2, entry2, clock2, ttl=30.0, requires_permit=True)
    outcome2 = gate2.admit(handle2, sentinel=grant2.sentinel)
    assert outcome2.code == "permit_unavailable"
    assert outcome2.denial.reason == "permit_denied"
    assert outcome2.denial.dispatch_state == "NOT_DISPATCHED"

    for cause in ("revoke", "disconnect", "boot_replace", "hold", "sentinel_mismatch",
                  "gate_closed"):
        gate3, registry3, _ledger3, clock3 = new_system()
        grant3, entry3 = install(gate3, registry3, clock3, active=True, ttl=200.0)
        handle3 = do_reserve(gate3, entry3, clock3, ttl=30.0)
        sentinel = grant3.sentinel
        if cause == "revoke":
            registry3.revoke(lease_id=grant3.lease_id, receiver_boot_id=BOOT,
                              generation=registry3.generation, reason="operator_cancel")
        elif cause == "disconnect":
            registry3.disconnect(receiver_boot_id=BOOT, generation=registry3.generation)
        elif cause == "boot_replace":
            registry3.handshake(receiver_boot_id="receiver-other", generation=registry3.generation)
        elif cause == "hold":
            registry3.hold()
        elif cause == "sentinel_mismatch":
            sentinel = "x" * 43
        elif cause == "gate_closed":
            gate3.shutdown()
        outcome3 = gate3.admit(handle3, sentinel=sentinel)
        expected_code = {
            "sentinel_mismatch": "sentinel_mismatch", "gate_closed": "gate_closed",
        }.get(cause, "lease_denied")
        assert outcome3.code == expected_code
        assert outcome3.code in ADMISSION_CODES
        assert outcome3.denial.reason == "lease_denied"
        assert outcome3.denial.dispatch_state == "NOT_DISPATCHED"


def test_fence_denials_always_map_to_failed_connect_failed():
    for cause in ("revoke", "disconnect", "boot_replace", "hold", "heartbeat",
                  "sentinel_mismatch", "gate_closed", "permit_white_box", "insufficient_time"):
        gate, registry, _ledger, clock = new_system()
        grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
        admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
        sentinel = grant.sentinel
        if cause == "revoke":
            registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                             generation=registry.generation, reason="operator_cancel")
        elif cause == "disconnect":
            registry.disconnect(receiver_boot_id=BOOT, generation=registry.generation)
        elif cause == "boot_replace":
            registry.handshake(receiver_boot_id="receiver-other", generation=registry.generation)
        elif cause == "hold":
            registry.hold()
        elif cause == "heartbeat":
            clock.advance(16.0)
        elif cause == "sentinel_mismatch":
            sentinel = "y" * 43
        elif cause == "gate_closed":
            gate.shutdown()
        elif cause == "permit_white_box":
            with gate._G:
                gate._flights[admission.receipt_id].requires_permit = True
        elif cause == "insufficient_time":
            clock.advance(admission.exchange_deadline - clock.value - 0.0001)

        outcome = gate.begin_write(admission, sentinel=sentinel)
        assert outcome.code != "write_admitted"
        assert outcome.code in WRITE_FENCE_CODES
        assert outcome.denial.dispatch_state == "FAILED"
        assert outcome.denial.reason == "connect_failed"


def test_release_of_a_wrong_type_raises_type_error_not_a_dispatch_error():
    gate, _registry, _ledger, _clock = new_system()
    with pytest.raises(TypeError):
        gate.release("not-a-token")
    with pytest.raises(TypeError):
        gate.release(object())
