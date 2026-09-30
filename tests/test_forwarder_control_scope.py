"""Deterministic tests for the scoped control policy (Module 2), Implementer B.

Cases B1-B6 exercise the pure functions against a real ``DispatchGate`` built
with ``tests.test_forwarder_dispatch`` helpers, plus stubbed ``Closeout``
values for ``observe_closeout``. B7 checks the error-chain discipline across
representative paths. B8 is an AST walk of ``forwarder_control_scope.py``.
"""

from __future__ import annotations

import ast
import math
import socket
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from grafana_jsm_sandbox import forwarder_control_scope as scope
from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox.forwarder_control_protocol import (
    ControlProtocolError,
    recv_frame,
    send_frame,
)
from grafana_jsm_sandbox.forwarder_dispatch import Closeout, DispatchGate
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptLedger
from grafana_jsm_sandbox.forwarder_routes import RouteConfigError
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from tests.test_forwarder_dispatch import (
    BOOT,
    FakeClock,
    activate,
    make_routed,  # noqa: F401 - exercised indirectly through reserve_and_admit
    new_system,
    register,
    reserve_and_admit,
)
from tests.test_forwarder_routes import golden_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_control_scope.py"

UNSCOPED_SERVICES = tuple(sorted(s for s in SERVICE_PROFILES if s not in scope.SCOPED_SERVICES))


def assert_scope_error(call, code: str | None = None) -> ControlProtocolError:
    with pytest.raises(ControlProtocolError) as caught:
        call()
    error = caught.value
    assert isinstance(error.code, str) and str(error) == error.code
    assert error.args == (error.code,)
    assert error.__cause__ is None and error.__context__ is None
    if code is not None:
        assert error.code == code
    return error


def make_closeout(**overrides) -> Closeout:
    """A fully coherent baseline observation; tests override only what they probe."""
    fields = {
        "lease_id": "lease-1", "lease_state": "revoked", "closeout_state": "quiescent",
        "pending": 0, "in_flight": 0, "overdue": 0, "drain_deadline": None, "uncertain": 0,
        "observed_at": 1_000.0,
    }
    fields.update(overrides)
    return Closeout(**fields)


def stub_gate(closeout_fn) -> DispatchGate:
    """A real gate (for ``.generation``) whose ``.closeout`` is instance-replaced."""
    gate, _registry, _ledger, _clock = new_system()
    gate.closeout = closeout_fn
    return gate


def new_system_with_gate_clock(gate_clock) -> tuple[DispatchGate, LeaseRegistry, FakeClock]:
    """A registry/ledger on a working clock, paired with a gate on ``gate_clock``."""
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=gate_clock)
    return gate, registry, clock


# --- B1: SCOPED_SERVICES, ATTACHMENT_SECONDS ----------------------------------


def test_b1_scoped_services_and_attachment_seconds():
    assert scope.SCOPED_SERVICES == frozenset({"jira"})
    assert scope.SCOPED_SERVICES <= frozenset(SERVICE_PROFILES)
    assert scope.ATTACHMENT_SECONDS == 2.0
    for service in UNSCOPED_SERVICES:
        with pytest.raises(RouteConfigError) as caught:
            golden_manifest(service=service)
        assert caught.value.code == "manifest_invalid"


# --- B2: refusal and length tables ---------------------------------------------


def test_b2_refuse_unscoped_table():
    for service in UNSCOPED_SERVICES:
        assert_scope_error(
            lambda service=service: scope.refuse_unscoped(service), "scope_type_unavailable",
        )
    for value in ("jira", "ghost", 7, None, {}):
        assert scope.refuse_unscoped(value) is None


def test_b2_manifest_length_table():
    for service in UNSCOPED_SERVICES:
        assert_scope_error(
            lambda service=service: scope.manifest_length(
                {"service": service, "manifest_bytes": 100},
            ),
            "scope_type_unavailable",
        )
    for value in ("ghost", 7, None, {}):
        assert_scope_error(
            lambda value=value: scope.manifest_length({"service": value, "manifest_bytes": 100}),
            "invalid_service",
        )
    for value in (True, 0, -1, 1.5, "10"):
        assert_scope_error(
            lambda value=value: scope.manifest_length({"service": "jira", "manifest_bytes": value}),
            "invalid_manifest_length",
        )
    assert_scope_error(
        lambda: scope.manifest_length({"service": "jira", "manifest_bytes": 16_385}),
        "manifest_too_large",
    )
    assert scope.manifest_length({"service": "jira", "manifest_bytes": 16_384}) == 16_384
    # Service is checked before length: a bad service still reports invalid_service.
    assert_scope_error(
        lambda: scope.manifest_length({"service": "ghost", "manifest_bytes": -1}), "invalid_service",
    )


# --- B3: bound_manifest ----------------------------------------------------------


def test_b3_bound_manifest_golden_bytes():
    manifest = golden_manifest()
    data = manifest.canonical_bytes()
    params = {
        "run_id": "run-1", "attempt_id": "attempt-1",
        "service": "jira", "scope_digest": manifest.digest,
    }
    bound = scope.bound_manifest(data, params)
    assert bound.digest == manifest.digest == params["scope_digest"]


def test_b3_bound_manifest_non_canonical_bytes_give_manifest_invalid():
    manifest = golden_manifest()
    data = manifest.canonical_bytes()
    params = {
        "run_id": "run-1", "attempt_id": "attempt-1",
        "service": "jira", "scope_digest": manifest.digest,
    }
    # Reordered keys: canonical order is alphabetical; move "service" to the front.
    reordered = b'{"service":"jira",' + data.split(b",", 1)[1]
    # Extra whitespace right after the opening brace.
    whitespace = data[:1] + b" " + data[1:]
    # A trailing newline after an otherwise-canonical document.
    trailing_newline = data + b"\n"
    # A non-ASCII byte inside the run_id string value.
    non_ascii = data.replace(b"run-1", b"run-1\xc3\xa9")
    for malformed in (reordered, whitespace, trailing_newline, non_ascii):
        assert_scope_error(
            lambda malformed=malformed: scope.bound_manifest(malformed, params), "manifest_invalid",
        )


def test_b3_bound_manifest_binding_mismatch():
    manifest = golden_manifest()
    data = manifest.canonical_bytes()
    base_params = {
        "run_id": "run-1", "attempt_id": "attempt-1",
        "service": "jira", "scope_digest": manifest.digest,
    }
    for key, bad_value in (
        ("run_id", "other-run"), ("attempt_id", "other-attempt"),
        ("service", "confluence"), ("scope_digest", "0" * 64),
    ):
        bad_params = {**base_params, key: bad_value}
        assert_scope_error(
            lambda p=bad_params: scope.bound_manifest(data, p), "manifest_binding_mismatch",
        )
    for key in ("run_id", "attempt_id", "service", "scope_digest"):
        bad_params = {**base_params, key: 7}
        assert_scope_error(
            lambda p=bad_params: scope.bound_manifest(data, p), "manifest_binding_mismatch",
        )


# --- B4: install against a real gate --------------------------------------------


def test_b4_install_gate_closed():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    gate.shutdown()
    assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_gate_closed")


def test_b4_install_clock_fault_holds_first_and_later_calls():
    def faulty_clock():
        raise RuntimeError("gate clock fault")

    gate, registry, clock = new_system_with_gate_clock(faulty_clock)
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_gate_held")
    assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_gate_held")


def test_b4_install_revoked_lease_gives_lease_unverified():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    registry.revoke(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, reason="operator_cancel",
    )
    assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_lease_unverified")


def test_b4_install_wrong_generation_gives_lease_unverified():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    other_generation_grant = replace(grant, generation="different-generation")
    assert_scope_error(
        lambda: scope.install(gate, other_generation_grant, manifest), "scope_lease_unverified",
    )


def test_b4_install_capacity_zero_gives_scope_capacity(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    monkeypatch.setattr(fd, "MAX_SCOPE_ENTRIES", 0)
    assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_capacity")


def test_b4_install_reinstall_returns_same_installed_at():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    first = scope.install(gate, grant, manifest)
    second = scope.install(gate, grant, manifest)
    assert first == second


def test_b4_install_identity_mismatch_gives_scope_install_failed():
    gate, registry, _ledger, clock = new_system()
    manifest_a = golden_manifest(run_id="run-1", attempt_id="attempt-1")
    grant_a = register(
        registry, clock, run_id="run-1", attempt_id="attempt-1", scope_digest=manifest_a.digest,
    )
    entry_a = gate.install_scope(grant=grant_a, manifest=manifest_a)

    manifest_b = golden_manifest(run_id="run-2", attempt_id="attempt-2")
    grant_b = register(
        registry, clock, run_id="run-2", attempt_id="attempt-2", scope_digest=manifest_b.digest,
    )

    gate.install_scope = lambda *, grant, manifest: entry_a  # another lease's entry
    assert_scope_error(lambda: scope.install(gate, grant_b, manifest_b), "scope_install_failed")


def test_b4_install_post_install_identity_clauses_each_give_scope_install_failed():
    # G2: each variant below violates exactly one clause of the post-install
    # identity check, against a real installed entry's own field values.
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)

    variants = (
        replace(entry, generation="other-generation"),
        replace(entry, scope_digest="0" * 64),
        replace(entry, lease_id="another-lease-id"),
        SimpleNamespace(**{field.name: getattr(entry, field.name) for field in fields(entry)}),
    )
    for variant in variants:
        gate.install_scope = lambda *, grant, manifest, variant=variant: variant
        assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_install_failed")


def test_b4_install_type_error_gives_scope_install_failed():
    # G3: a TypeError from install_scope maps to scope_install_failed, not through.
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)

    def raiser(*, grant, manifest):
        raise TypeError("x")

    gate.install_scope = raiser
    assert_scope_error(lambda: scope.install(gate, grant, manifest), "scope_install_failed")


@pytest.mark.parametrize(("dispatch_code", "control_code"), [
    ("gate_closed", "scope_gate_closed"),
    ("gate_held", "scope_gate_held"),
    ("clock_fault", "scope_gate_held"),
    ("lease_unverified", "scope_lease_unverified"),
    ("grant_expired", "scope_lease_unverified"),
    ("generation_mismatch", "scope_lease_unverified"),
    ("manifest_binding_mismatch", "manifest_binding_mismatch"),
    ("scope_capacity", "scope_capacity"),
    ("scope_conflict", "scope_conflict"),
    ("unlisted_code", "scope_install_failed"),
])
def test_b4_install_maps_each_dispatch_code(dispatch_code, control_code):
    # Some of these codes are unreachable through control; the table is pinned anyway.
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)

    def raiser(*, grant, manifest):
        raise fd.DispatchError(dispatch_code)

    gate.install_scope = raiser
    assert_scope_error(lambda: scope.install(gate, grant, manifest), control_code)


# --- B5: observe_closeout -------------------------------------------------------


def test_b5_call_failures_give_closeout_unknown():
    def raiser(lease_id):
        raise RuntimeError("boom")

    gate = stub_gate(raiser)
    assert_scope_error(
        lambda: scope.observe_closeout(gate, "lease-1", after_revoke=False), "closeout_unknown",
    )
    for bad_result in (None, {"lease_id": "lease-1"}, "closeout"):
        gate = stub_gate(lambda lease_id, bad_result=bad_result: bad_result)
        assert_scope_error(
            lambda g=gate: scope.observe_closeout(g, "lease-1", after_revoke=False),
            "closeout_unknown",
        )


def test_b5_type_and_range_failures_give_closeout_inconsistent():
    cases = (
        make_closeout(lease_id="other-lease"),
        make_closeout(lease_state="not-a-state"),
        make_closeout(closeout_state="not-a-state"),
        make_closeout(pending=True),
        make_closeout(in_flight=-1),
        make_closeout(overdue=1.5),
        make_closeout(uncertain=2**31),
        make_closeout(observed_at=math.nan),
        make_closeout(observed_at=math.inf),
        make_closeout(observed_at=-1),
        make_closeout(drain_deadline=math.nan),
        make_closeout(drain_deadline="x"),
    )
    for closeout in cases:
        gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
        assert_scope_error(
            lambda g=gate: scope.observe_closeout(g, "lease-1", after_revoke=False),
            "closeout_inconsistent",
        )


def test_b5_coherence_failures_give_closeout_inconsistent():
    cases = (
        make_closeout(lease_state="revoked", closeout_state="open"),
        make_closeout(lease_state="active", closeout_state="quiescent"),
        make_closeout(lease_state="unknown", closeout_state="quiescent"),
        make_closeout(closeout_state="draining", in_flight=0),
        make_closeout(closeout_state="draining", in_flight=1, overdue=1, drain_deadline=1_000.0),
        make_closeout(closeout_state="quiescent", overdue=1),
        make_closeout(closeout_state="quiescent", in_flight=1, drain_deadline=1_000.0),
        make_closeout(closeout_state="quiescent", drain_deadline=1_000.0),
        make_closeout(closeout_state="draining", in_flight=1, drain_deadline=None),
    )
    for closeout in cases:
        gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
        assert_scope_error(
            lambda g=gate: scope.observe_closeout(g, "lease-1", after_revoke=False),
            "closeout_inconsistent",
        )


def test_b5_after_revoke_requires_revoked_lease_states():
    for lease_state in ("registered", "active", "expired", "unknown"):
        closeout = make_closeout(lease_state=lease_state, closeout_state="quiescent")
        gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
        assert_scope_error(
            lambda g=gate: scope.observe_closeout(g, "lease-1", after_revoke=True),
            "closeout_inconsistent",
        )
    for lease_state in scope.REVOKED_LEASE_STATES:
        for closeout_state, extra in (
            ("draining", {"in_flight": 1, "drain_deadline": 1_000.0}),
            ("quiescent", {"in_flight": 0, "drain_deadline": None}),
        ):
            closeout = make_closeout(lease_state=lease_state, closeout_state=closeout_state, **extra)
            gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
            projection = scope.observe_closeout(gate, "lease-1", after_revoke=True)
            assert projection["closeout_state"] in ("draining", "quiescent")


def test_b5_holds_overdue_and_unknown():
    closeout = make_closeout(lease_state="revoked", closeout_state="overdue", overdue=1)
    gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
    assert_scope_error(
        lambda: scope.observe_closeout(gate, "lease-1", after_revoke=False), "closeout_overdue",
    )

    closeout = make_closeout(lease_state="active", closeout_state="open", overdue=1)
    gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
    assert_scope_error(
        lambda: scope.observe_closeout(gate, "lease-1", after_revoke=False), "closeout_overdue",
    )

    closeout = make_closeout(lease_state="revoked", closeout_state="unknown")
    gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
    assert_scope_error(
        lambda: scope.observe_closeout(gate, "lease-1", after_revoke=True), "closeout_unknown",
    )

    closeout = make_closeout(lease_state="active", closeout_state="unknown")
    gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
    assert_scope_error(
        lambda: scope.observe_closeout(gate, "lease-1", after_revoke=False), "closeout_unknown",
    )

    closeout = make_closeout(lease_state="unknown", closeout_state="unknown")
    gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
    projection = scope.observe_closeout(gate, "lease-1", after_revoke=False)
    assert projection["lease_state"] == "unknown" and projection["closeout_state"] == "unknown"


def test_b5_projection_fields_and_wire_transport():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    gate.install_scope(grant=grant, manifest=manifest)

    projection = scope.observe_closeout(gate, grant.lease_id, after_revoke=False)
    assert tuple(projection.keys()) == scope.CLOSEOUT_FIELDS
    assert projection["generation"] == gate.generation
    assert projection["closeout_state"] == "open"

    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        writer.settimeout(1.0)
        send_frame(writer, {"op": "closeout", "seq": 1, "ok": True, "result": projection})
        received = recv_frame(reader)
    finally:
        reader.close()
        writer.close()
    assert received["result"] == projection


def test_b5_real_draining_state_via_reserve_and_admit():
    # A live (registered/active) lease always reports "open" (forwarder_dispatch.py
    # L928-940); "draining" only appears once the lease itself has been retired.
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    activate(registry, clock, grant)

    admission = reserve_and_admit(gate, entry, grant, clock)
    registry.revoke(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, reason="operator_cancel",
    )
    projection = scope.observe_closeout(gate, grant.lease_id, after_revoke=True)
    assert projection["closeout_state"] == "draining"
    assert projection["in_flight"] == 1
    assert projection["drain_deadline"] is not None
    gate.release(admission)


def test_b5_timestamp_validation_bounds():
    # G1: a coherent draining shape isolates the _valid_time check itself.
    bad_drain_deadlines = (math.inf, math.nan, -1.0, "x", True, 2**63, 2**64, 10**400)
    for drain_deadline in bad_drain_deadlines:
        closeout = make_closeout(
            lease_state="revoked", closeout_state="draining", in_flight=1,
            drain_deadline=drain_deadline,
        )
        gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
        assert_scope_error(
            lambda g=gate: scope.observe_closeout(g, "lease-1", after_revoke=False),
            "closeout_inconsistent",
        )

    bad_observed_ats = (2**63, 2**64, 10**400)
    for observed_at in bad_observed_ats:
        closeout = make_closeout(
            lease_state="revoked", closeout_state="draining", in_flight=1,
            drain_deadline=1_000.0, observed_at=observed_at,
        )
        gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
        assert_scope_error(
            lambda g=gate: scope.observe_closeout(g, "lease-1", after_revoke=False),
            "closeout_inconsistent",
        )

    # The signed 64-bit bound itself is accepted for both fields.
    closeout = make_closeout(
        lease_state="revoked", closeout_state="draining", in_flight=1,
        drain_deadline=2**63 - 1, observed_at=2**63 - 1,
    )
    gate = stub_gate(lambda lease_id, closeout=closeout: closeout)
    projection = scope.observe_closeout(gate, "lease-1", after_revoke=False)
    assert projection["drain_deadline"] == 2**63 - 1
    assert projection["observed_at"] == 2**63 - 1


# --- B6: require_gate ------------------------------------------------------------


def test_b6_require_gate_invalid_combinations():
    gate, registry, _ledger, _clock = new_system()

    assert_scope_error(lambda: scope.require_gate("not-a-gate", registry), "invalid_gate")

    _other_gate, other_registry, _other_ledger, _other_clock = new_system()
    assert_scope_error(lambda: scope.require_gate(gate, other_registry), "invalid_gate")

    assert_scope_error(lambda: scope.require_gate(gate, "not-a-registry"), "invalid_gate")

    assert scope.require_gate(gate, registry) is gate


# --- B7: error-chain discipline ---------------------------------------------------


def test_b7_error_chain_is_always_suppressed():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    gate.shutdown()  # install() will fail through a caught DispatchError

    def raiser(lease_id):
        raise RuntimeError("boom")

    raising_gate = stub_gate(raiser)  # observe_closeout() will fail through a caught Exception

    calls = (
        lambda: scope.require_gate(None, None),
        lambda: scope.manifest_length({"service": "ghost"}),
        lambda: scope.bound_manifest(b"not json", {}),
        lambda: scope.install(gate, grant, manifest),
        lambda: scope.observe_closeout(raising_gate, "lease-1", after_revoke=False),
    )
    for call in calls:
        assert_scope_error(call)


# --- B8: AST checks ----------------------------------------------------------------

ALLOWED_STDLIB_PLAIN = {"math"}
ALLOWED_STDLIB_FROM = {
    "__future__": {"annotations"},
}
ALLOWED_RELATIVE = {
    "forwarder_control_protocol": {"ControlProtocolError"},
    "forwarder_dispatch": {
        "CLOSEOUT_STATES", "LEASE_STATES", "Closeout", "DispatchError", "DispatchGate", "ScopeEntry",
    },
    "forwarder_leases": {"LeaseGrant", "LeaseRegistry"},
    "forwarder_routes": {
        "MAX_MANIFEST_BYTES", "RouteConfigError", "ScopeManifest",
        "parse_scope_manifest", "require_manifest_binding",
    },
    "forwarder_services": {"SERVICE_PROFILES"},
}
FORBIDDEN_MODULE_ROOTS = {"socket", "os", "ssl", "time", "threading", "subprocess"}
FORBIDDEN_BUILTIN_NAMES = {"open", "print"}
FORBIDDEN_ATTRIBUTE_CALLS = {
    "register", "activate", "revoke", "heartbeat", "handshake", "disconnect", "hold", "check",
}


def _parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(), filename=str(path))


def test_ast_no_raise_inside_except_handler():
    tree = _parse(MODULE_PATH)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Raise):
                    offenders.append(inner.lineno)
    assert not offenders, (
        f"an except handler must only record a fixed code; a fresh ControlProtocolError "
        f"is raised after the try statement ends (raise at line(s) {offenders})"
    )


def test_ast_import_allowlist_is_exact():
    tree = _parse(MODULE_PATH)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in ALLOWED_STDLIB_PLAIN, f"unlisted import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = {alias.name for alias in node.names}
            if node.level == 0:
                expected = ALLOWED_STDLIB_FROM.get(module)
                assert expected is not None, f"unlisted stdlib import: from {module}"
                assert names <= expected, f"unlisted names from {module}: {names - expected}"
            elif node.level == 1:
                expected = ALLOWED_RELATIVE.get(module)
                assert expected is not None, f"unlisted relative import: from .{module}"
                assert names <= expected, f"unlisted names from .{module}: {names - expected}"
            else:
                pytest.fail(f"unexpected relative import level {node.level} (from {module})")


def test_ast_forbidden_modules_and_builtins_absent():
    tree = _parse(MODULE_PATH)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            root = (node.module or "").split(".")[0]
            assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {node.module}"
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_BUILTIN_NAMES:
            pytest.fail(f"forbidden builtin reference: {node.id}")


def test_ast_no_registry_attribute_calls():
    tree = _parse(MODULE_PATH)
    offenders = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in FORBIDDEN_ATTRIBUTE_CALLS
        ):
            offenders.append((node.func.attr, node.lineno))
    assert not offenders, f"no registry method may be called directly: {offenders}"
