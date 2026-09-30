"""Deterministic tests for the atomic dispatch gate (Module 1).

One ``FakeClock`` is shared by the registry, the ledger and the gate, so every
authorizing check and every ledger transition is observed on one monotonic
domain. Golden route/manifest fixtures come from ``tests.test_forwarder_routes``
(unit-12 policy-r1/scope-r1).
"""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import FrozenInstanceError, replace

import pytest

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox.forwarder_dispatch import (
    ADMISSION_CODES,
    CONNECT_SECONDS,
    DENIAL_REASONS,
    DISPATCH_ERROR_CODES,
    MAX_HANDLER_SECONDS,
    MIN_ADMISSION_SECONDS,
    MIN_WRITE_SECONDS,
    READ_INACTIVITY_SECONDS,
    RESPONSE_MARGIN_SECONDS,
    WRITE_FENCE_CODES,
    WRITE_SECONDS,
    Admission,
    AdmissionOutcome,
    Closeout,
    DispatchError,
    DispatchGate,
    DispatchHandle,
    ScopeEntry,
    ShutdownReport,
    WriteOutcome,
)
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_leases import LeaseGrant, LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptError, ReceiptLedger
from grafana_jsm_sandbox.forwarder_response_receive import _INACTIVITY_LIMIT
from grafana_jsm_sandbox.forwarder_routes import (
    ROUTE_CATALOG,
    RoutedRequest,
    RouteSelection,
    ScopeManifest,
    UpstreamRequest,
)
from tests.test_forwarder_routes import GOLDEN_SCOPE, POLICY_DIGEST, SCOPE_DIGEST, golden_manifest


class FakeClock:
    def __init__(self, value: float = 1_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


BOOT = "receiver-a"
SERVICE = "jira"


_System = tuple[DispatchGate, LeaseRegistry, ReceiptLedger, FakeClock]


def new_system(clock: FakeClock | None = None) -> _System:
    clock = clock or FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    return gate, registry, ledger, clock


def register(
    registry: LeaseRegistry, clock: FakeClock, *, run_id: str = "run-1",
    attempt_id: str = "attempt-1", service: str = SERVICE, scope_digest: str, ttl: float = 200.0,
) -> LeaseGrant:
    return registry.register(
        run_id=run_id, attempt_id=attempt_id, receiver_boot_id=BOOT, service=service,
        scope_digest=scope_digest, expires_at=clock.value + ttl, generation=registry.generation,
    )


def advance_with_heartbeats(
    registry: LeaseRegistry, clock: FakeClock, target: float, step: float = 10.0,
) -> None:
    """Move ``clock`` to ``target``, heartbeating at every step (including the
    last) so no gap ever reaches ``HEARTBEAT_SECONDS`` and the lease stays live.
    """
    while clock.value < target:
        clock.value = min(clock.value + step, target)
        registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)


def activate(registry: LeaseRegistry, clock: FakeClock, grant: LeaseGrant) -> None:
    registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, launch_at=clock.value,
    )


def install(
    gate: DispatchGate, registry: LeaseRegistry, clock: FakeClock, *, run_id: str = "run-1",
    attempt_id: str = "attempt-1", ttl: float = 200.0, active: bool = False,
    manifest: ScopeManifest | None = None,
) -> tuple[LeaseGrant, ScopeEntry]:
    manifest = manifest or golden_manifest(run_id=run_id, attempt_id=attempt_id)
    grant = register(
        registry, clock, run_id=run_id, attempt_id=attempt_id,
        scope_digest=manifest.digest, ttl=ttl,
    )
    if active:
        activate(registry, clock, grant)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    return grant, entry


def make_routed(
    entry: ScopeEntry, *, route_id: str = "jira.issue.get", request_digest: str | None = None,
    requires_permit: bool = False,
) -> RoutedRequest:
    if request_digest is None:
        label = f"digest:{route_id}:{id(entry)}".encode()
        request_digest = hashlib.sha256(label).hexdigest()
    return RoutedRequest(
        route_id=route_id, service=entry.service, scope_digest=entry.scope_digest,
        policy_digest=POLICY_DIGEST, request_digest=request_digest, requires_permit=requires_permit,
        upstream=UpstreamRequest(
            method="GET", target="/rest/api/3/issue/90101", accept="application/json",
            content_type=None, body=b"",
        ),
        selection=RouteSelection(
            issue_id="90101", issue_key="SYN-1", search_label=None, max_results=None,
        ),
    )


def do_reserve(
    gate: DispatchGate, entry: ScopeEntry, clock: FakeClock, *, route_id: str = "jira.issue.get",
    ttl: float = 30.0, requires_permit: bool = False, request_bytes: int = 100,
    routed: RoutedRequest | None = None,
) -> DispatchHandle:
    routed = routed or make_routed(entry, route_id=route_id, requires_permit=requires_permit)
    return gate.reserve(
        entry, routed, request_digest=routed.request_digest,
        request_bytes=request_bytes, deadline=clock.value + ttl,
    )


def reserve_and_admit(
    gate: DispatchGate, entry: ScopeEntry, grant: LeaseGrant, clock: FakeClock, **kwargs,
) -> Admission:
    handle = do_reserve(gate, entry, clock, **kwargs)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"
    return outcome.admission


def snapshot_from_worker(gate: DispatchGate, seen: list) -> None:
    """Read ``open_dispatches`` on a joined worker thread.

    ``G`` is an ``RLock``, so a snapshot on the calling thread would re-enter it
    even while held; only another thread can prove ``G`` is free.
    """
    worker = threading.Thread(target=lambda: seen.append(gate.snapshot()["open_dispatches"]))
    worker.start()
    worker.join(2.0)
    seen.append(("worker_alive", worker.is_alive()))


class ScriptedClock:
    """Delegates to ``base`` except on call number ``bad_call``, which raises or returns ``bad``."""

    def __init__(self, base, *, bad_call: int, bad):
        self.base = base
        self.bad_call = bad_call
        self.bad = bad
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls != self.bad_call:
            return self.base()
        if isinstance(self.bad, Exception):
            raise self.bad
        return self.bad


def assert_error(call, code: str | None = None) -> DispatchError:
    with pytest.raises(DispatchError) as caught:
        call()
    error = caught.value
    assert isinstance(error.code, str) and str(error) == error.code
    assert error.args == (error.code,)
    assert error.__cause__ is None and error.__context__ is None
    if code is not None:
        assert error.code == code
    return error


# --- construction ------------------------------------------------------------


def test_construction_exact_types_and_generation_mismatch():
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)

    with pytest.raises(TypeError):
        DispatchGate(registry="not-a-registry", ledger=ledger, clock=clock)
    with pytest.raises(TypeError):
        DispatchGate(registry=registry, ledger="not-a-ledger", clock=clock)
    with pytest.raises(TypeError):
        DispatchGate(registry=registry, ledger=ledger, clock="not-callable")

    other_ledger = ReceiptLedger(generation="different-generation", clock=clock)
    assert_error(lambda: DispatchGate(registry=registry, ledger=other_ledger, clock=clock),
                 "generation_mismatch")
    # A refused generation mismatch must claim neither object.
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    assert gate.generation == registry.generation


def test_system_clock_property():
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    fake_gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    assert fake_gate.system_clock is False

    real_registry = LeaseRegistry()
    real_registry.handshake(receiver_boot_id=BOOT, generation=real_registry.generation)
    real_ledger = ReceiptLedger(generation=real_registry.generation)
    real_gate = DispatchGate(registry=real_registry, ledger=real_ledger)
    assert real_gate.system_clock is True


def test_second_gate_over_claimed_objects_gives_authority_claimed():
    gate, registry, ledger, clock = new_system()
    assert gate.generation == registry.generation

    fresh_ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    assert_error(lambda: DispatchGate(registry=registry, ledger=fresh_ledger, clock=clock),
                 "authority_claimed")
    assert getattr(fresh_ledger, fd._CLAIM_MARKER, False) is False

    fresh_registry = LeaseRegistry(clock=clock)
    fresh_registry.handshake(receiver_boot_id=BOOT, generation=fresh_registry.generation)
    # White-box: align generations so this exercises the authority claim, not
    # the (already-covered) generation-mismatch check.
    fresh_registry._generation = registry.generation
    other_ledger = ReceiptLedger(generation=fresh_registry.generation, clock=clock)
    assert_error(lambda: DispatchGate(registry=fresh_registry, ledger=ledger, clock=clock),
                 "authority_claimed")
    assert getattr(fresh_registry, fd._CLAIM_MARKER, False) is False
    # The unclaimed pair can still form its own gate.
    DispatchGate(registry=fresh_registry, ledger=other_ledger, clock=clock)


def test_copy_of_claimed_registry_is_refused():
    _gate, registry, _ledger, clock = new_system()
    copied = copy.copy(registry)
    fresh_ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    assert_error(lambda: DispatchGate(registry=copied, ledger=fresh_ledger, clock=clock),
                 "authority_claimed")


# --- install_scope -------------------------------------------------------------


def test_install_scope_golden_binding_succeeds():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=SCOPE_DIGEST)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    assert entry.lease_id == grant.lease_id
    assert entry.run_id == grant.run_id == "run-1"
    assert entry.attempt_id == grant.attempt_id == "attempt-1"
    assert entry.service == grant.service == "jira"
    assert entry.generation == grant.generation == registry.generation
    assert entry.scope_digest == grant.scope_digest == SCOPE_DIGEST
    assert entry.expires_at == grant.expires_at
    assert entry.manifest is manifest
    assert entry.manifest.digest == SCOPE_DIGEST


@pytest.mark.parametrize("field_name,value", [
    ("run_id", "other-run"), ("attempt_id", "other-attempt"), ("service", "grafana"),
])
def test_install_scope_manifest_binding_field_mismatch(field_name, value):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    kwargs = {"run_id": "run-1", "attempt_id": "attempt-1", "service": "jira"}
    kwargs[field_name] = value
    grant = register(registry, clock, run_id=kwargs["run_id"], attempt_id=kwargs["attempt_id"],
                      service=kwargs["service"], scope_digest=SCOPE_DIGEST)
    assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest),
                 "manifest_binding_mismatch")


def test_install_scope_manifest_digest_mismatch():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    other_digest = hashlib.sha256(b"unrelated-scope").hexdigest()
    grant = register(registry, clock, scope_digest=other_digest)
    assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest),
                 "manifest_binding_mismatch")


@pytest.mark.parametrize("active_state", [False, True])
def test_install_scope_replace_expires_at_gives_lease_unverified(active_state):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    if active_state:
        activate(registry, clock, grant)
    forged = replace(grant, expires_at=grant.expires_at + 1.0)
    assert_error(lambda: gate.install_scope(grant=forged, manifest=manifest), "lease_unverified")


@pytest.mark.parametrize("active_state", [False, True])
def test_install_scope_replace_scope_digest_gives_lease_unverified(active_state):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    if active_state:
        activate(registry, clock, grant)
    other_scope = replace(GOLDEN_SCOPE, search_labels=("fp-other0000000",))
    manifest2 = golden_manifest(scope=other_scope)
    forged = replace(grant, scope_digest=manifest2.digest)
    assert_error(lambda: gate.install_scope(grant=forged, manifest=manifest2), "lease_unverified")


def test_install_scope_replace_receiver_boot_id_gives_lease_unverified():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    forged = replace(grant, receiver_boot_id="receiver-b")
    assert_error(lambda: gate.install_scope(grant=forged, manifest=manifest), "lease_unverified")


def test_install_scope_generation_mismatch():
    gate, _registry, _ledger, clock = new_system()
    other_registry = LeaseRegistry(clock=clock)
    other_registry.handshake(receiver_boot_id=BOOT, generation=other_registry.generation)
    manifest = golden_manifest()
    grant = register(other_registry, clock, scope_digest=manifest.digest)
    assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest), "generation_mismatch")


def test_install_scope_expired_lease_gives_grant_expired_or_lease_unverified():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=10.0)
    clock.advance(11.0)
    error = assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest))
    assert error.code in ("grant_expired", "lease_unverified")


def test_install_scope_revoked_lease_gives_lease_unverified():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest), "lease_unverified")


def test_install_scope_unknown_lease_gives_lease_unverified():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    forged = replace(grant, lease_id="lease_" + "x" * 20)
    assert_error(lambda: gate.install_scope(grant=forged, manifest=manifest), "lease_unverified")


def test_install_scope_both_lease_states_accepted():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    assert entry.lease_id == grant.lease_id

    manifest2 = golden_manifest(run_id="run-2", attempt_id="attempt-2")
    grant2 = register(registry, clock, run_id="run-2", attempt_id="attempt-2",
                       scope_digest=manifest2.digest)
    activate(registry, clock, grant2)
    entry2 = gate.install_scope(grant=grant2, manifest=manifest2)
    assert entry2.lease_id == grant2.lease_id


def test_install_scope_reinstall_is_idempotent_and_index_collision_is_conflict():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    again = gate.install_scope(grant=grant, manifest=manifest)
    assert again is entry

    # White-box: force an index collision with a foreign lease to prove the
    # "any other index or lease collision" branch of step 7.
    manifest2 = golden_manifest(run_id="run-3", attempt_id="attempt-3")
    grant2 = register(registry, clock, run_id="run-3", attempt_id="attempt-3",
                       scope_digest=manifest2.digest)
    foreign_index = gate._index_for(grant2.service, grant2.sentinel)
    with gate._G:
        gate._scope_by_index[foreign_index] = entry
        gate._scope_index_by_lease[grant2.lease_id] = foreign_index
    assert_error(lambda: gate.install_scope(grant=grant2, manifest=manifest2), "scope_conflict")


def test_install_scope_capacity_entries(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    monkeypatch.setattr(fd, "MAX_SCOPE_ENTRIES", 2)
    for index in range(2):
        manifest = golden_manifest(run_id=f"run-{index}", attempt_id=f"attempt-{index}")
        grant = register(registry, clock, run_id=f"run-{index}", attempt_id=f"attempt-{index}",
                          scope_digest=manifest.digest)
        gate.install_scope(grant=grant, manifest=manifest)
    manifest = golden_manifest(run_id="run-overflow", attempt_id="attempt-overflow")
    grant = register(registry, clock, run_id="run-overflow", attempt_id="attempt-overflow",
                      scope_digest=manifest.digest)
    assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest), "scope_capacity")


def test_install_scope_capacity_bytes_and_reconcile_frees_pruned_records(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    monkeypatch.setattr(fd, "SCOPE_ENTRY_OVERHEAD_BYTES", 0)
    manifest = golden_manifest()
    charge = len(manifest.canonical_bytes())
    monkeypatch.setattr(fd, "MAX_SCOPE_BYTES", charge)
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=5.0)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    assert gate.snapshot()["scope_bytes"] == charge

    manifest2 = golden_manifest(run_id="run-2", attempt_id="attempt-2")
    grant2 = register(registry, clock, run_id="run-2", attempt_id="attempt-2",
                       scope_digest=manifest2.digest)
    assert_error(lambda: gate.install_scope(grant=grant2, manifest=manifest2), "scope_capacity")

    # White-box: simulate the first lease's registry record having aged out.
    # A real 310s wait is not usable here: the registry's own retention prunes
    # every record by created_at, at most 270s (LEASE_SECONDS) after any lease
    # can still be registered, so grant2 could never itself outlive it.
    real_snapshot = registry.snapshot

    def snapshot_without_first_lease():
        result = real_snapshot()
        result["leases"] = tuple(
            item for item in result["leases"] if item["lease_id"] != grant.lease_id
        )
        return result

    monkeypatch.setattr(registry, "snapshot", snapshot_without_first_lease)
    entry2 = gate.install_scope(grant=grant2, manifest=manifest2)
    assert entry2.lease_id == grant2.lease_id
    assert entry.lease_id not in {row[0] for row in gate.snapshot()["scope_entries"]}


def test_install_scope_retention_pruning_releases_bytes():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=200.0)
    gate.install_scope(grant=grant, manifest=manifest)
    assert gate.snapshot()["scope_bytes"] > 0
    clock.advance(311.0)
    gate.now()
    assert gate.snapshot()["scope_bytes"] == 0
    assert gate.snapshot()["scope_entries"] == ()


def test_install_scope_gate_closed_and_held():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    gate.shutdown()
    assert_error(lambda: gate.install_scope(grant=grant, manifest=manifest), "gate_closed")

    gate2, registry2, _ledger2, clock2 = new_system()
    manifest2 = golden_manifest()
    grant2 = register(registry2, clock2, scope_digest=manifest2.digest)
    bad_clock = FakeClock(float("nan"))
    gate2._clock = bad_clock  # white-box: force the very next tick to fault.
    assert_error(lambda: gate2.install_scope(grant=grant2, manifest=manifest2), "clock_fault")
    assert_error(lambda: gate2.install_scope(grant=grant2, manifest=manifest2), "gate_held")


# --- resolve -------------------------------------------------------------------


def test_resolve_hit_cross_service_malformed_and_retained_past():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=200.0)
    entry = gate.install_scope(grant=grant, manifest=manifest)

    assert gate.resolve(service="jira", sentinel=grant.sentinel) is entry
    assert gate.resolve(service="confluence", sentinel=grant.sentinel) is None
    assert gate.resolve(service="jira", sentinel="too-short") is None
    assert gate.resolve(service="jira", sentinel="!" * 43) is None

    with pytest.raises(ValueError):
        gate.resolve(service="not-a-service", sentinel=grant.sentinel)

    clock.advance(311.0)
    gate.now()
    assert gate.resolve(service="jira", sentinel=grant.sentinel) is None


def test_resolve_past_retention_gives_none_without_a_prior_tick():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=200.0)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    clock.value = entry.installed_at + fd.STORE_RETENTION_SECONDS - 1.0
    assert gate.resolve(service="jira", sentinel=grant.sentinel) is entry

    clock.value = entry.installed_at + fd.STORE_RETENTION_SECONDS
    assert gate.resolve(service="jira", sentinel=grant.sentinel) is None
    # resolve does not tick: the entry is still stored until the next tick prunes it.
    assert [row[0] for row in gate.snapshot()["scope_entries"]] == [entry.lease_id]


# --- precheck --------------------------------------------------------------------


def test_precheck_true_only_when_authorized():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    assert gate.precheck(entry, sentinel=grant.sentinel) is False  # not yet active

    activate(registry, clock, grant)
    assert gate.precheck(entry, sentinel=grant.sentinel) is True

    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    assert gate.precheck(entry, sentinel=grant.sentinel) is False


def test_precheck_false_after_heartbeat_late_boot_replacement_and_holds():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=200.0)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    activate(registry, clock, grant)
    assert gate.precheck(entry, sentinel=grant.sentinel) is True

    clock.advance(16.0)
    assert gate.precheck(entry, sentinel=grant.sentinel) is False

    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    manifest2 = golden_manifest(run_id="run-2", attempt_id="attempt-2")
    grant2 = register(registry, clock, run_id="run-2", attempt_id="attempt-2",
                       scope_digest=manifest2.digest)
    entry2 = gate.install_scope(grant=grant2, manifest=manifest2)
    activate(registry, clock, grant2)
    registry.handshake(receiver_boot_id="receiver-b", generation=registry.generation)
    assert gate.precheck(entry2, sentinel=grant2.sentinel) is False

    registry.hold()
    assert gate.precheck(entry2, sentinel=grant2.sentinel) is False

    gate2, registry3, _ledger3, clock3 = new_system()
    manifest3 = golden_manifest()
    grant3 = register(registry3, clock3, scope_digest=manifest3.digest)
    entry3 = gate2.install_scope(grant=grant3, manifest=manifest3)
    activate(registry3, clock3, grant3)
    gate2.shutdown()
    assert gate2.precheck(entry3, sentinel=grant3.sentinel) is False


# --- deny --------------------------------------------------------------------------


@pytest.mark.parametrize("reason", sorted(DENIAL_REASONS))
def test_deny_each_reason_produces_a_receipt(reason):
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    digest = hashlib.sha256(b"deny-digest").hexdigest()
    receipt = gate.deny(entry, route_id="unmatched", request_digest=digest, reason=reason,
                        request_bytes=10, deadline=clock.value + 5.0)
    assert receipt.dispatch_state == "NOT_DISPATCHED"
    assert receipt.reason == reason


def test_deny_abandoned_gives_invalid_reason():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    digest = hashlib.sha256(b"deny-digest").hexdigest()
    deadline = clock.value + 5.0
    assert_error(
        lambda: gate.deny(entry, route_id="unmatched", request_digest=digest,
                           reason="abandoned", request_bytes=10, deadline=deadline),
        "invalid_reason",
    )


def test_deny_full_ledger_gives_receipt_unavailable(monkeypatch):
    gate, registry, ledger, clock = new_system()
    monkeypatch.setattr(ledger.__class__, "reserve", ledger.__class__.reserve)
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)

    def raise_capacity(*args, **kwargs):
        from grafana_jsm_sandbox.forwarder_receipts import ReceiptError
        raise ReceiptError("capacity_records")

    monkeypatch.setattr(ledger, "reserve", raise_capacity)
    digest = hashlib.sha256(b"deny-digest").hexdigest()
    assert_error(lambda: gate.deny(entry, route_id="unmatched", request_digest=digest,
                                    reason="lease_denied", request_bytes=10,
                                    deadline=clock.value + 5.0),
                 "receipt_unavailable")


def test_deny_passed_deadline_gives_deadline_expired():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    digest = hashlib.sha256(b"deny-digest").hexdigest()
    assert_error(lambda: gate.deny(entry, route_id="unmatched", request_digest=digest,
                                    reason="lease_denied", request_bytes=10, deadline=clock.value),
                 "deadline_expired")


def test_deny_foreign_entry_gives_scope_unknown():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    foreign = replace(entry, lease_id="lease_foreignxxxxxxxxxxxxxxxxxxxx")
    digest = hashlib.sha256(b"deny-digest").hexdigest()
    assert_error(lambda: gate.deny(foreign, route_id="unmatched", request_digest=digest,
                                    reason="lease_denied", request_bytes=10,
                                    deadline=clock.value + 5.0),
                 "scope_unknown")


# --- reserve -----------------------------------------------------------------------


def test_reserve_binding_mismatch():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock)
    routed = make_routed(entry)
    forged = replace(routed, scope_digest=hashlib.sha256(b"other").hexdigest())
    assert_error(lambda: gate.reserve(entry, forged, request_digest=forged.request_digest,
                                       request_bytes=10, deadline=clock.value + 5.0),
                 "binding_mismatch")


def test_reserve_route_unavailable_by_catalog_and_monkeypatch(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock)
    routed = make_routed(entry)
    unavailable = replace(routed, route_id="jira.issue.create")
    assert_error(lambda: gate.reserve(entry, unavailable, request_digest=unavailable.request_digest,
                                       request_bytes=10, deadline=clock.value + 5.0),
                 "route_unavailable")

    forced_off = replace(ROUTE_CATALOG["jira.issue.get"], state="unavailable")
    monkeypatch.setattr(fd, "ROUTE_CATALOG", {**ROUTE_CATALOG, "jira.issue.get": forced_off})
    assert_error(lambda: do_reserve(gate, entry, clock), "route_unavailable")


def test_reserve_deadline_exceeds_lease():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, ttl=10.0)
    assert_error(lambda: do_reserve(gate, entry, clock, ttl=20.0), "deadline_exceeds_lease")


def test_reserve_capacity_freed_by_finish_and_release(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 2)
    grant, entry = install(gate, registry, clock, active=True)
    handle1 = do_reserve(gate, entry, clock)
    handle2 = do_reserve(gate, entry, clock)
    assert_error(lambda: do_reserve(gate, entry, clock), "dispatch_capacity")

    assert gate.release(handle2) is True
    do_reserve(gate, entry, clock)
    assert_error(lambda: do_reserve(gate, entry, clock), "dispatch_capacity")

    admission = gate.admit(handle1, sentinel=grant.sentinel).admission
    gate.finish(admission, dispatch_state="FAILED", reason="connect_failed")
    do_reserve(gate, entry, clock)


def test_reserve_overdue_flight_still_counts(monkeypatch):
    gate, registry, _ledger, clock = new_system()
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 1)
    _grant, entry = install(gate, registry, clock)
    do_reserve(gate, entry, clock, ttl=2.0)
    clock.advance(3.0)
    assert_error(lambda: do_reserve(gate, entry, clock), "dispatch_capacity")


def test_reserve_gate_closed_and_scope_unknown():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock)
    gate.shutdown()
    assert_error(lambda: do_reserve(gate, entry, clock), "gate_closed")

    gate2, registry2, _ledger2, clock2 = new_system()
    _grant2, entry2 = install(gate2, registry2, clock2)
    clock2.advance(311.0)
    gate2.now()
    assert_error(lambda: do_reserve(gate2, entry2, clock2), "scope_unknown")


def test_reserve_first_clock_fault_gives_gate_held():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock)
    gate._clock = ScriptedClock(clock, bad_call=1, bad=RuntimeError("boom"))
    assert_error(lambda: do_reserve(gate, entry, clock), "gate_held")
    assert gate.snapshot()["hold_code"] == "clock_fault"
    assert_error(lambda: do_reserve(gate, entry, clock), "gate_held")


# --- admit ---------------------------------------------------------------------------


def test_admit_success_fields():
    gate, registry, ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    before_admit = clock.value
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"
    admission = outcome.admission
    assert admission.admitted_at == before_admit
    assert admission.deadline == handle.deadline
    assert admission.exchange_deadline == handle.deadline - RESPONSE_MARGIN_SECONDS
    assert admission.connect_deadline == min(
        admission.admitted_at + CONNECT_SECONDS, admission.exchange_deadline,
    )
    snap = ledger.snapshot()
    entries = [item for item in snap["entries"] if item["receipt_id"] == handle.receipt_id]
    assert entries[0]["entry_state"] == "connecting"


def test_admit_connect_deadline_clips_to_exchange_deadline():
    """F5-1: connect_deadline must clip to exchange_deadline, never hand out
    the raw CONNECT_SECONDS budget when the exchange window is shorter."""
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=2.5)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"
    admission = outcome.admission
    assert admission.exchange_deadline < admission.admitted_at + CONNECT_SECONDS
    assert admission.connect_deadline == admission.exchange_deadline


@pytest.mark.parametrize("retire", ["revoke", "disconnect", "boot_replace", "heartbeat", "hold"])
def test_admit_each_retirement_cause_gives_lease_denied(retire):
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)

    if retire == "revoke":
        registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                         generation=registry.generation, reason="operator_cancel")
    elif retire == "disconnect":
        registry.disconnect(receiver_boot_id=BOOT, generation=registry.generation)
    elif retire == "boot_replace":
        registry.handshake(receiver_boot_id="receiver-b", generation=registry.generation)
    elif retire == "heartbeat":
        clock.advance(16.0)
    elif retire == "hold":
        registry.hold()

    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "lease_denied"
    assert outcome.admission is None
    assert outcome.denial.dispatch_state == "NOT_DISPATCHED"
    assert outcome.denial.reason == "lease_denied"
    assert gate.snapshot()["open_dispatches"] == 0


def test_admit_another_leases_sentinel_gives_sentinel_mismatch():
    gate, registry, _ledger, clock = new_system()
    _grant1, entry1 = install(gate, registry, clock, active=True)
    grant2, _entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True)
    handle = do_reserve(gate, entry1, clock)
    outcome = gate.admit(handle, sentinel=grant2.sentinel)
    assert outcome.code == "sentinel_mismatch"


def test_admit_permit_route_gives_permit_denied():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True)
    handle = do_reserve(gate, entry, clock, requires_permit=True)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "permit_unavailable"
    assert outcome.denial.reason == "permit_denied"


@pytest.mark.parametrize("falsy_value", [None, 0, ""])
def test_admit_denies_permit_unavailable_for_falsy_non_false_requires_permit(falsy_value):
    """F4-1 (fixed): only ``requires_permit is False`` may admit. A falsy-but-
    not-``False`` value (``None``, ``0`` or ``""``) forged onto ``RoutedRequest``
    must still deny ``permit_unavailable``, proving the check is an identity
    comparison, not a truthiness check.
    """
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True)
    routed = make_routed(entry, requires_permit=falsy_value)
    handle = gate.reserve(entry, routed, request_digest=routed.request_digest,
                           request_bytes=100, deadline=clock.value + 30.0)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "permit_unavailable"
    assert outcome.denial.dispatch_state == "NOT_DISPATCHED"
    assert outcome.denial.reason == "permit_denied"


def test_admit_deadline_boundary():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=2.0)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "admitted"

    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    handle2 = do_reserve(gate, entry2, clock, ttl=1.999)
    outcome2 = gate.admit(handle2, sentinel=grant2.sentinel)
    assert outcome2.code == "insufficient_time"
    assert outcome2.denial.reason == "deadline"


def test_admit_handle_consumed_and_deadline_expired():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    gate.admit(handle, sentinel=grant.sentinel)
    assert_error(lambda: gate.admit(handle, sentinel=grant.sentinel), "handle_consumed")

    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    handle2 = do_reserve(gate, entry2, clock, ttl=2.0)
    clock.advance(3.0)
    assert_error(lambda: gate.admit(handle2, sentinel=grant2.sentinel), "deadline_expired")


def test_admit_forged_handle_with_faulting_clock_gives_handle_unknown():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True)
    handle = do_reserve(gate, entry, clock)
    forged = replace(handle, receipt_id="forged-" + handle.receipt_id)

    class FaultingClock:
        def __call__(self):
            raise RuntimeError("boom")

    gate._clock = FaultingClock()
    assert_error(lambda: gate.admit(forged, sentinel=grant.sentinel), "handle_unknown")
    # The lookup precedes the clock read, so the gate is untouched by the fault.
    assert gate.snapshot()["gate_state"] == "ready"


def test_admit_clock_domain_mismatch_holds_gate():
    shared = FakeClock()
    registry_clock = FakeClock(value=shared.value + 1000.0)
    registry = LeaseRegistry(clock=registry_clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=shared)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=shared)

    manifest = golden_manifest()
    grant = registry.register(
        run_id="run-1", attempt_id="attempt-1", receiver_boot_id=BOOT, service="jira",
        scope_digest=manifest.digest, expires_at=registry_clock.value + 200.0,
        generation=registry.generation,
    )
    registry.activate(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                       generation=registry.generation, launch_at=registry_clock.value)
    entry = gate.install_scope(grant=grant, manifest=manifest)
    handle = do_reserve(gate, entry, shared, ttl=30.0)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "gate_held"
    assert gate.snapshot()["hold_code"] == "clock_domain_mismatch"

    # The gate is now permanently held: even a reserve() against the entry
    # installed before the hold fails closed.
    assert_error(lambda: do_reserve(gate, entry, shared), "gate_held")


@pytest.mark.parametrize("step", ["admit", "begin_write"])
@pytest.mark.parametrize("bad_call,bad", [
    (2, RuntimeError("MARK-LEASE-CLOCK")), (2, 999.0), (3, float("nan")),
])
def test_clock_fault_around_lease_check_denies_and_holds_with_clock_fault(step, bad_call, bad):
    # Call 1 is the step's own tick; calls 2 and 3 bracket the registry check.
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    admission = gate.admit(handle, sentinel=grant.sentinel).admission if step != "admit" else None
    gate._clock = ScriptedClock(clock, bad_call=bad_call, bad=bad)
    if step == "admit":
        outcome = gate.admit(handle, sentinel=grant.sentinel)
    else:
        outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "gate_held"
    assert outcome.denial.dispatch_state == ("NOT_DISPATCHED" if step == "admit" else "FAILED")
    snap = gate.snapshot()
    assert (snap["gate_state"], snap["hold_code"]) == ("held", "clock_fault")
    assert snap["open_dispatches"] == 0


# --- begin_write ---------------------------------------------------------------------


def test_begin_write_success_fields():
    gate, registry, ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    before_fence = clock.value
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "write_admitted"
    assert outcome.write_deadline == min(before_fence + WRITE_SECONDS, admission.exchange_deadline)
    snap = ledger.snapshot()
    entries = [item for item in snap["entries"] if item["receipt_id"] == admission.receipt_id]
    assert entries[0]["entry_state"] == "dispatched"


def test_begin_write_write_deadline_clips_to_exchange_deadline():
    """F5-1: write_deadline must clip to exchange_deadline, never hand out the
    raw WRITE_SECONDS budget when the exchange window is shorter."""
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.5)
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "write_admitted"
    assert outcome.write_deadline == admission.exchange_deadline
    assert outcome.write_deadline < admission.admitted_at + WRITE_SECONDS


def test_begin_write_deadline_comes_from_the_fence_reading_not_admission():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    advance_with_heartbeats(registry, clock, clock.value + 4.0, step=2.0)
    fence_at = clock.value
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "write_admitted"
    assert outcome.write_deadline == fence_at + WRITE_SECONDS
    assert outcome.write_deadline != admission.admitted_at + WRITE_SECONDS


@pytest.mark.parametrize("retire", ["revoke", "disconnect", "boot_replace", "heartbeat", "hold"])
def test_begin_write_each_retirement_cause_gives_failed(retire):
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)

    if retire == "revoke":
        registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                         generation=registry.generation, reason="operator_cancel")
    elif retire == "disconnect":
        registry.disconnect(receiver_boot_id=BOOT, generation=registry.generation)
    elif retire == "boot_replace":
        registry.handshake(receiver_boot_id="receiver-b", generation=registry.generation)
    elif retire == "heartbeat":
        clock.advance(16.0)
    elif retire == "hold":
        registry.hold()

    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "lease_denied"
    assert outcome.denial.dispatch_state == "FAILED"
    assert outcome.denial.reason == "connect_failed"
    assert gate.snapshot()["open_dispatches"] == 0


def test_begin_write_sentinel_mismatch():
    gate, registry, _ledger, clock = new_system()
    grant1, entry1 = install(gate, registry, clock, active=True)
    grant2, _entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True)
    admission = reserve_and_admit(gate, entry1, grant1, clock)
    outcome = gate.begin_write(admission, sentinel=grant2.sentinel)
    assert outcome.code == "sentinel_mismatch"
    assert outcome.denial.dispatch_state == "FAILED"


def test_begin_write_boundary_at_exchange_deadline():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    # Move the clock so the fence observes exactly MIN_WRITE_SECONDS of budget,
    # heartbeating along the way so the lease itself does not go stale.
    advance_with_heartbeats(registry, clock, admission.exchange_deadline - MIN_WRITE_SECONDS)
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "write_admitted"

    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    admission2 = reserve_and_admit(gate, entry2, grant2, clock, ttl=30.0)
    target = admission2.exchange_deadline - MIN_WRITE_SECONDS + 0.0001
    advance_with_heartbeats(registry, clock, target)
    outcome2 = gate.begin_write(admission2, sentinel=grant2.sentinel)
    assert outcome2.code == "insufficient_time"


def test_begin_write_permit_unavailable_white_box():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    with gate._G:
        gate._flights[admission.receipt_id].requires_permit = True
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "permit_unavailable"
    assert outcome.denial.dispatch_state == "FAILED"


def test_begin_write_permit_unavailable_white_box_falsy_none():
    """F4-1 (fixed): a white-box flip to ``None`` (falsy, not ``False``) must
    still deny at the fence, proving the check is ``is not False``."""
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    with gate._G:
        gate._flights[admission.receipt_id].requires_permit = None
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "permit_unavailable"
    assert outcome.denial.dispatch_state == "FAILED"
    assert outcome.denial.reason == "connect_failed"


def test_begin_write_claimed_admission_unknown_and_deadline_expired():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.begin_write(admission, sentinel=grant.sentinel)
    assert_error(lambda: gate.begin_write(admission, sentinel=grant.sentinel), "write_claimed")

    forged = replace(admission, receipt_id="forged-" + admission.receipt_id)
    assert_error(lambda: gate.begin_write(forged, sentinel=grant.sentinel), "admission_unknown")

    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    admission2 = reserve_and_admit(gate, entry2, grant2, clock, ttl=2.0)
    clock.advance(3.0)
    assert_error(lambda: gate.begin_write(admission2, sentinel=grant2.sentinel), "deadline_expired")


def test_begin_write_gate_closed_after_shutdown():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.shutdown()
    outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert outcome.code == "gate_closed"
    assert outcome.denial.dispatch_state == "FAILED"


# --- finish ------------------------------------------------------------------------


def test_finish_legal_matrix_admitted_and_writing():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)

    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    receipt = gate.finish(admission, dispatch_state="FAILED", reason="connect_failed")
    assert receipt.dispatch_state == "FAILED"
    assert gate.snapshot()["open_dispatches"] == 0

    admission2 = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.begin_write(admission2, sentinel=grant.sentinel)
    ok_response = ParsedResponse(200, b'{"ok":true}')
    receipt2 = gate.finish(admission2, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                            upstream_response=ok_response)
    assert receipt2.dispatch_state == "TRANSPORT_CONFIRMED"


def test_finish_invalid_outcome_keeps_flight_then_retry_succeeds():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    # "dispatched" only legally finalizes into DISPATCHED_UNKNOWN/PARTIAL/TRANSPORT_CONFIRMED;
    # this transition is still only "admitted" (connecting), so FAILED here is legal, but
    # NOT_DISPATCHED is not -- that is the illegal transition under test.
    assert_error(
        lambda: gate.finish(admission, dispatch_state="NOT_DISPATCHED", reason="abandoned"),
        "invalid_outcome",
    )
    assert gate.snapshot()["open_dispatches"] == 1
    receipt = gate.finish(admission, dispatch_state="FAILED", reason="connect_failed")
    assert receipt.dispatch_state == "FAILED"


def test_finish_malformed_response_gives_invalid_outcome():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.begin_write(admission, sentinel=grant.sentinel)
    malformed = ParsedResponse(302, b"")
    assert_error(lambda: gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                                      upstream_response=malformed),
                 "invalid_outcome")
    assert gate.snapshot()["open_dispatches"] == 1
    receipt = gate.finish(
        admission, dispatch_state="DISPATCHED_UNKNOWN", reason="malformed_response",
    )
    assert receipt.reason == "malformed_response"


def test_finish_overdue_gives_deadline_expired():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    clock.advance(3.0)
    assert_error(lambda: gate.finish(admission, dispatch_state="FAILED", reason="connect_failed"),
                 "deadline_expired")
    assert gate.snapshot()["open_dispatches"] == 0


def test_finish_works_on_held_gate():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)

    class FaultingClock:
        def __call__(self):
            raise RuntimeError("boom")

    gate._clock = FaultingClock()
    assert_error(lambda: gate.now(), "clock_fault")
    receipt = gate.finish(admission, dispatch_state="FAILED", reason="connect_failed")
    assert receipt.dispatch_state == "FAILED"


def test_finish_unknown_admission():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    forged = replace(admission, receipt_id="forged-" + admission.receipt_id)
    assert_error(lambda: gate.finish(forged, dispatch_state="FAILED", reason="connect_failed"),
                 "admission_unknown")


def test_forged_token_with_unhashable_receipt_id_is_refused_not_typeerror():
    """F2-1 (fixed): a forged token built with ``dataclasses.replace`` and an
    unhashable ``receipt_id`` (a list or dict) must be treated as unknown/
    foreign by every identity-lookup method, never let a raw ``TypeError``
    escape from ``dict.get``.
    """
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)

    forged_handle = replace(handle, receipt_id=["not", "hashable"])
    assert_error(lambda: gate.admit(forged_handle, sentinel=grant.sentinel), "handle_unknown")

    admission = gate.admit(handle, sentinel=grant.sentinel).admission
    forged_admission = replace(admission, receipt_id={"unhashable": True})
    assert_error(lambda: gate.attach_abort(forged_admission, lambda: None), "admission_unknown")
    assert_error(lambda: gate.begin_write(forged_admission, sentinel=grant.sentinel),
                 "admission_unknown")
    assert_error(
        lambda: gate.finish(forged_admission, dispatch_state="FAILED", reason="connect_failed"),
        "admission_unknown",
    )
    assert gate.release(forged_admission) is False
    assert gate.is_admitted(forged_admission) is False

    forged_handle_for_release = replace(handle, receipt_id=[1, 2, 3])
    assert gate.release(forged_handle_for_release) is False


# --- overdue -----------------------------------------------------------------------


def test_overdue_marks_flight_and_fires_abort_once_with_g_free():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    calls = []

    def abort():
        snapshot_from_worker(gate, calls)

    assert gate.attach_abort(admission, abort) is True
    clock.advance(3.0)
    gate.now()  # an unrelated tick marks the flight overdue.
    assert calls == [1, ("worker_alive", False)]
    assert gate.is_admitted(admission) is False
    assert gate.attach_abort(admission, abort) is False

    receipt_id = admission.receipt_id
    flights = {row[0]: row for row in gate.snapshot()["flights"]}
    assert flights[receipt_id][5] is True  # overdue flag


def test_overdue_owner_finish_removes_it():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    clock.advance(3.0)
    gate.now()
    assert_error(lambda: gate.finish(admission, dispatch_state="FAILED", reason="connect_failed"),
                 "deadline_expired")
    assert gate.snapshot()["open_dispatches"] == 0


def test_admit_on_overdue_flight_removes_it_and_frees_the_slot(monkeypatch):
    """F7-1: the owner's admit on an overdue flight must remove it, freeing
    its MAX_OPEN_DISPATCHES slot for a later reserve."""
    gate, registry, _ledger, clock = new_system()
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 1)
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=2.0)
    clock.advance(3.0)
    assert_error(lambda: do_reserve(gate, entry, clock), "dispatch_capacity")

    assert_error(lambda: gate.admit(handle, sentinel=grant.sentinel), "deadline_expired")
    assert gate.snapshot()["open_dispatches"] == 0
    do_reserve(gate, entry, clock)  # the slot is free again


def test_begin_write_on_overdue_flight_removes_it_and_frees_the_slot(monkeypatch):
    """F7-1: the owner's begin_write on an overdue flight must remove it,
    freeing its MAX_OPEN_DISPATCHES slot for a later reserve."""
    gate, registry, _ledger, clock = new_system()
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 1)
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    clock.advance(3.0)
    assert_error(lambda: do_reserve(gate, entry, clock), "dispatch_capacity")

    assert_error(lambda: gate.begin_write(admission, sentinel=grant.sentinel), "deadline_expired")
    assert gate.snapshot()["open_dispatches"] == 0
    do_reserve(gate, entry, clock)  # the slot is free again


def test_release_is_idempotent_and_true_only_once():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True)
    handle = do_reserve(gate, entry, clock)
    assert gate.release(handle) is True
    assert gate.release(handle) is False

    with pytest.raises(TypeError):
        gate.release("not-a-token")


def test_release_foreign_token_returns_false():
    gate1, registry1, _ledger1, clock1 = new_system()
    gate2, registry2, _ledger2, clock2 = new_system()
    _grant1, entry1 = install(gate1, registry1, clock1, active=True)
    _grant2, entry2 = install(gate2, registry2, clock2, active=True)
    handle1 = do_reserve(gate1, entry1, clock1)
    handle2 = do_reserve(gate2, entry2, clock2)
    assert gate1.release(handle2) is False
    assert gate2.release(handle1) is False


def test_abort_exceptions_are_counted():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)

    def failing_abort():
        raise RuntimeError("boom")

    gate.attach_abort(admission, failing_abort)
    clock.advance(3.0)
    gate.now()
    assert gate.snapshot()["abort_failures"] == 1


def test_admit_drains_the_abort_queue():
    """F8-1: admit must drain the abort queue after releasing G, exactly like
    now()/reserve()/closeout(), even when admitting an unrelated flight."""
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    overdue_admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    fired = []
    gate.attach_abort(overdue_admission, lambda: fired.append(True))

    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    handle2 = do_reserve(gate, entry2, clock, ttl=30.0)
    clock.advance(3.0)  # only the first flight's deadline has passed

    gate.admit(handle2, sentinel=grant2.sentinel)  # ticks and must drain the queued abort
    assert fired == [True]


def test_begin_write_drains_the_abort_queue():
    """F8-1: begin_write must drain the abort queue after releasing G, even
    when fencing an unrelated flight."""
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    overdue_admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    fired = []
    gate.attach_abort(overdue_admission, lambda: fired.append(True))

    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    admission2 = reserve_and_admit(gate, entry2, grant2, clock, ttl=30.0)
    clock.advance(3.0)

    gate.begin_write(admission2, sentinel=grant2.sentinel)  # ticks and must drain the queue
    assert fired == [True]


# --- closeout ----------------------------------------------------------------------


def test_closeout_open_draining_and_quiescent():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    closeout = gate.closeout(grant.lease_id)
    assert closeout.closeout_state == "open"
    assert closeout.lease_state == "active"

    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.begin_write(admission, sentinel=grant.sentinel)
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    draining = gate.closeout(grant.lease_id)
    assert draining.closeout_state == "draining"
    assert draining.in_flight == 1
    assert draining.drain_deadline == admission.deadline

    gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                upstream_response=ParsedResponse(200, b"{}"))
    quiescent = gate.closeout(grant.lease_id)
    assert quiescent.closeout_state == "quiescent"
    assert quiescent.uncertain == 0


def test_closeout_overdue_while_owner_has_not_returned():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    # "open" (registered/active) takes precedence over "overdue" in the state
    # order, so the lease must first be retired to observe the overdue state.
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    clock.advance(3.0)
    result = gate.closeout(grant.lease_id)
    assert result.closeout_state == "overdue"
    assert result.overdue == 1


def test_closeout_overdue_takes_precedence_over_draining_with_both_flight_kinds():
    """F9-1: for one lease with both an overdue flight (already ledger-swept)
    and a genuinely in-flight one, closeout must report ``overdue``, not
    ``draining``."""
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)

    overdue_admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    assert gate.begin_write(overdue_admission, sentinel=grant.sentinel).code == "write_admitted"

    inflight_admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    assert gate.begin_write(inflight_admission, sentinel=grant.sentinel).code == "write_admitted"

    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    clock.advance(3.0)  # only overdue_admission's deadline has passed

    result = gate.closeout(grant.lease_id)
    assert result.overdue == 1
    assert result.in_flight == 1
    assert result.closeout_state == "overdue"


def test_closeout_pending_never_blocks_quiescent():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    do_reserve(gate, entry, clock, ttl=35.0)  # still pending: deadline far in the future
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    result = gate.closeout(grant.lease_id)
    assert result.pending == 1
    assert result.overdue == 0
    assert result.in_flight == 0
    assert result.closeout_state == "quiescent"


def test_closeout_expired_lease_never_draining():
    gate, registry, _ledger, clock = new_system()
    grant, _entry = install(gate, registry, clock, active=True, ttl=5.0)
    clock.advance(6.0)
    result = gate.closeout(grant.lease_id)
    assert result.lease_state == "expired"
    assert result.closeout_state == "quiescent"


def test_closeout_pruned_then_unknown_across_retention():
    gate, registry, _ledger, clock = new_system()
    manifest = golden_manifest()
    grant = register(registry, clock, scope_digest=manifest.digest, ttl=200.0)
    clock.advance(5.0)  # install happens a little after registration
    gate.install_scope(grant=grant, manifest=manifest)

    # The registry record ages out at created_at+310; the gate's own store
    # entry ages out at installed_at(+5s later)+310, so there is a real
    # window where the registry has forgotten the lease but the gate has not.
    clock.advance(306.0)
    pruned = gate.closeout(grant.lease_id)
    assert pruned.lease_state == "pruned"
    assert pruned.closeout_state == "quiescent"

    clock.advance(10.0)
    unknown = gate.closeout(grant.lease_id)
    assert unknown.lease_state == "unknown"
    assert unknown.closeout_state == "unknown"


def test_closeout_held_states_give_unknown():
    gate, registry, _ledger, clock = new_system()
    grant, _entry = install(gate, registry, clock, active=True, ttl=200.0)
    registry.hold()
    result = gate.closeout(grant.lease_id)
    assert result.closeout_state == "unknown"

    gate2, registry2, _ledger2, clock2 = new_system()
    grant2, _entry2 = install(gate2, registry2, clock2, active=True, ttl=200.0)

    class FaultingClock:
        def __call__(self):
            raise RuntimeError("boom")

    gate2._clock = FaultingClock()
    assert_error(lambda: gate2.now(), "clock_fault")
    held_result = gate2.closeout(grant2.lease_id)
    assert held_result.closeout_state == "unknown"
    assert held_result.lease_state == "active"  # observed from the record, not made up


def test_closeout_held_ledger_gives_unknown():
    """F6-1: a held ledger, independent of the registry and the gate, must
    also give closeout ``unknown``."""
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger_clock = ScriptedClock(clock, bad_call=1, bad=RuntimeError("boom"))
    ledger = ReceiptLedger(generation=registry.generation, clock=ledger_clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    grant, _entry = install(gate, registry, clock, active=True, ttl=200.0)

    with pytest.raises(ReceiptError):
        ledger.reserve(lease_id=grant.lease_id, attempt_id="attempt-1", service="jira",
                        route_id="jira.issue.get", request_digest="0" * 64, request_bytes=10,
                        deadline=clock.value + 5.0)
    assert ledger.snapshot()["ledger_state"] == "held"
    assert gate.snapshot()["gate_state"] == "ready"
    assert registry.snapshot()["registry_state"] == "ready"

    result = gate.closeout(grant.lease_id)
    assert result.closeout_state == "unknown"
    assert result.lease_state == "active"


def test_closeout_on_a_held_gate_still_reports_observed_counts():
    shared = FakeClock()
    registry_clock = FakeClock(value=shared.value)
    registry = LeaseRegistry(clock=registry_clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=shared)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=shared)
    grant, entry = install(gate, registry, shared, active=True, ttl=200.0)

    uncertain = reserve_and_admit(gate, entry, grant, shared, ttl=30.0)
    gate.begin_write(uncertain, sentinel=grant.sentinel)
    gate.finish(uncertain, dispatch_state="DISPATCHED_UNKNOWN", reason="write_failed")
    writing = reserve_and_admit(gate, entry, grant, shared, ttl=30.0)
    assert gate.begin_write(writing, sentinel=grant.sentinel).code == "write_admitted"

    registry_clock.advance(5.0)  # the registry drifts off the gate's clock domain
    held = gate.admit(do_reserve(gate, entry, shared, ttl=30.0), sentinel=grant.sentinel)
    assert held.code == "gate_held"
    assert gate.snapshot()["hold_code"] == "clock_domain_mismatch"

    result = gate.closeout(grant.lease_id)
    assert (result.lease_state, result.closeout_state) == ("active", "unknown")
    assert (result.pending, result.in_flight, result.uncertain) == (0, 1, 1)
    assert result.drain_deadline == writing.deadline
    assert result.observed_at == shared.value


def test_closeout_first_clock_fault_gives_unknown_not_an_error():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.begin_write(admission, sentinel=grant.sentinel)
    gate._clock = ScriptedClock(clock, bad_call=1, bad=RuntimeError("boom"))
    result = gate.closeout(grant.lease_id)
    assert (result.lease_state, result.closeout_state) == ("active", "unknown")
    assert (result.in_flight, result.drain_deadline) == (1, admission.deadline)
    assert gate.snapshot()["hold_code"] == "clock_fault"


class SteppingClock:
    """The ledger's view of ``base``: once ``step`` is set, the next read first moves
    ``base`` forward, as if time passed between the gate's and the ledger's reads."""

    def __init__(self, base: FakeClock):
        self.base = base
        self.step = 0.0

    def __call__(self) -> float:
        step, self.step = self.step, 0.0
        self.base.advance(step)
        return self.base()


def test_closeout_never_quiescent_while_a_swept_writing_flight_is_live():
    clock = FakeClock()
    ledger_clock = SteppingClock(clock)
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=ledger_clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    assert gate.begin_write(admission, sentinel=grant.sentinel).code == "write_admitted"
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")

    # The gate would still read just before the deadline; the ledger's snapshot
    # read lands just after it and sweeps the still-writing entry.
    clock.value = admission.deadline - 0.001
    ledger_clock.step = 0.002
    first = gate.closeout(grant.lease_id)
    assert (first.closeout_state, first.in_flight, first.overdue) == ("overdue", 0, 1)
    assert first.uncertain == 1
    assert gate.closeout(grant.lease_id).closeout_state == "overdue"

    assert_error(lambda: gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED",
                                     reason="ok", upstream_response=ParsedResponse(200, b"{}")),
                 "deadline_expired")
    assert gate.closeout(grant.lease_id).closeout_state == "quiescent"


def test_closeout_at_exactly_the_deadline_is_overdue_like_the_ledger_sweep():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    assert gate.begin_write(admission, sentinel=grant.sentinel).code == "write_admitted"
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")

    clock.value = admission.deadline  # the ledger sweeps at now >= deadline; so must the gate
    result = gate.closeout(grant.lease_id)
    assert (result.closeout_state, result.in_flight, result.overdue) == ("overdue", 0, 1)
    assert result.uncertain == 1
    assert gate.is_admitted(admission) is False


def test_closeout_unsafe_lease_id_gives_unknown():
    gate, _registry, _ledger, _clock = new_system()
    result = gate.closeout("not a safe id!")
    assert result.closeout_state == "unknown"


# --- shutdown ------------------------------------------------------------------------


def test_shutdown_closes_gate_without_holding_registry():
    gate, registry, _ledger, clock = new_system()
    _grant, _entry = install(gate, registry, clock, active=True, ttl=200.0)
    report = gate.shutdown()
    assert isinstance(report, ShutdownReport)
    assert gate.snapshot()["gate_state"] == "closed"
    assert registry.snapshot()["registry_state"] == "ready"


def test_shutdown_aborts_admitted_and_writing_flights_with_g_free():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission1 = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    admission2 = reserve_and_admit(gate, entry2, grant2, clock, ttl=30.0)
    gate.begin_write(admission2, sentinel=grant2.sentinel)

    calls = []

    def abort():
        snapshot_from_worker(gate, calls)

    gate.attach_abort(admission1, abort)
    gate.attach_abort(admission2, abort)
    report = gate.shutdown()
    assert report.in_flight == 2
    assert report.aborted == 2
    assert calls == [2, ("worker_alive", False)] * 2

    assert gate.attach_abort(admission1, abort) is False
    assert gate.precheck(entry, sentinel=grant.sentinel) is False


def test_shutdown_finish_still_records():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.shutdown()
    receipt = gate.finish(admission, dispatch_state="FAILED", reason="connect_failed")
    assert receipt.dispatch_state == "FAILED"


def test_shutdown_second_call_aborts_nothing_new():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    gate.attach_abort(admission, lambda: None)
    gate.shutdown()
    second = gate.shutdown()
    assert second.aborted == 0
    assert second.in_flight == 0


def test_shutdown_abort_exceptions_are_counted():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)

    def failing_abort():
        raise RuntimeError("boom")

    gate.attach_abort(admission, failing_abort)
    report = gate.shutdown()
    assert report.abort_failures == 1


def test_shutdown_ignores_a_pending_shared_abort_queue_item():
    """F3-1 (fixed): shutdown must report only the failures of the aborts it
    fired itself. An unrelated callable already queued by some other tick
    (e.g. now()/reserve()/admit()) must not be drained, executed or counted
    by shutdown, unlike the old before/after-drain implementation.
    """
    gate, _registry, _ledger, _clock = new_system()

    def unrelated_failing_abort():
        raise RuntimeError("unrelated")

    with gate._G:
        gate._abort_queue.append(unrelated_failing_abort)

    report = gate.shutdown()
    assert report.in_flight == 0
    assert report.aborted == 0
    assert report.abort_failures == 0  # shutdown fired none of its own

    assert gate.snapshot()["abort_failures"] == 0
    with gate._G:
        assert list(gate._abort_queue) == [unrelated_failing_abort]


def test_shutdown_reports_exact_own_failures_under_concurrent_queue_draining():
    """F3-1 (fixed): shutdown's report must count exactly its own fired
    aborts' failures even while another thread concurrently drains the
    shared overdue abort queue.
    """
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission1 = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    grant2, entry2 = install(gate, registry, clock, run_id="run-2", attempt_id="attempt-2",
                              active=True, ttl=200.0)
    admission2 = reserve_and_admit(gate, entry2, grant2, clock, ttl=30.0)
    gate.begin_write(admission2, sentinel=grant2.sentinel)

    def failing_abort():
        raise RuntimeError("shutdown-own-failure")

    gate.attach_abort(admission1, failing_abort)
    gate.attach_abort(admission2, lambda: None)

    stop = threading.Event()

    def unrelated_failure():
        raise RuntimeError("unrelated")

    def hammer():
        for _ in range(2000):
            if stop.is_set():
                return
            with gate._G:
                gate._abort_queue.append(unrelated_failure)
            gate._drain_aborts()

    worker = threading.Thread(target=hammer)
    worker.start()
    try:
        report = gate.shutdown()
    finally:
        stop.set()
        worker.join(2.0)

    assert report.in_flight == 2
    assert report.aborted == 2
    assert report.abort_failures == 1  # exactly its own failing_abort


def test_shutdown_keeps_an_existing_hold():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    fired = []
    gate.attach_abort(admission, lambda: fired.append(True))
    gate._clock = ScriptedClock(clock, bad_call=1, bad=RuntimeError("boom"))  # one transient fault
    assert_error(lambda: gate.now(), "clock_fault")

    report = gate.shutdown()
    assert (report.in_flight, report.aborted, fired) == (1, 1, [True])
    snap = gate.snapshot()
    assert (snap["gate_state"], snap["hold_code"]) == ("held", "clock_fault")
    assert_error(lambda: gate.now(), "gate_held")
    assert gate.closeout(grant.lease_id).closeout_state == "unknown"
    assert gate.shutdown().in_flight == 0


def test_hold_after_shutdown_does_not_make_the_next_shutdown_a_first_call():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    reserve_and_admit(gate, entry, grant, clock, ttl=30.0)
    assert gate.shutdown().in_flight == 1
    gate._clock = ScriptedClock(clock, bad_call=1, bad=RuntimeError("boom"))
    assert_error(lambda: gate.now(), "clock_fault")
    assert gate.snapshot()["gate_state"] == "held"
    assert gate.shutdown() == ShutdownReport(in_flight=0, overdue=0, aborted=0, abort_failures=0)
    assert gate.snapshot()["gate_state"] == "held"


# --- other -------------------------------------------------------------------------


def test_now_hold_behavior_permanently_holds_the_gate():
    gate, _registry, _ledger, _clock = new_system()

    class BadClock:
        def __init__(self):
            self.calls = 0

        def __call__(self):
            self.calls += 1
            raise RuntimeError("boom")

    bad = BadClock()
    gate._clock = bad
    assert_error(lambda: gate.now(), "clock_fault")
    assert bad.calls == 1
    assert_error(lambda: gate.now(), "gate_held")
    assert bad.calls == 1  # a held gate never re-reads the faulting clock.


def test_now_regression_holds_the_gate():
    gate, _registry, _ledger, clock = new_system()
    clock.advance(5.0)
    gate.now()
    clock.value -= 1.0
    assert_error(lambda: gate.now(), "clock_fault")
    assert gate.snapshot()["hold_code"] == "clock_fault"


def test_snapshot_and_repr_contain_no_sentinel_or_index():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock)
    snapshot = gate.snapshot()
    blob = repr(snapshot) + repr(entry) + repr(handle)
    assert grant.sentinel not in blob
    assert gate._index_key.hex() not in blob
    assert "sentinel" not in repr(entry)


def test_read_inactivity_matches_response_receive_module():
    assert READ_INACTIVITY_SECONDS == _INACTIVITY_LIMIT


def test_min_write_seconds_is_at_most_min_admission_seconds():
    assert MIN_WRITE_SECONDS <= MIN_ADMISSION_SECONDS


def test_max_handler_seconds_matches_receipts_module():
    from grafana_jsm_sandbox.forwarder_receipts import MAX_HANDLER_SECONDS as receipts_max
    assert MAX_HANDLER_SECONDS == receipts_max


def test_dispatch_error_codes_is_a_closed_set_of_23():
    assert len(DISPATCH_ERROR_CODES) == 23
    assert "insufficient_time" not in DISPATCH_ERROR_CODES
    assert "admitted" not in DISPATCH_ERROR_CODES
    outcome_only = {"admitted", "write_admitted", "insufficient_time",
                    "sentinel_mismatch", "permit_unavailable", "lease_denied"}
    assert set(ADMISSION_CODES) <= DISPATCH_ERROR_CODES | outcome_only
    assert set(WRITE_FENCE_CODES) <= DISPATCH_ERROR_CODES | outcome_only


def test_dataclasses_are_frozen_and_identity_authenticated():
    gate, registry, _ledger, clock = new_system()
    _grant, entry = install(gate, registry, clock, active=True)
    with pytest.raises(FrozenInstanceError):
        entry.lease_id = "other"  # type: ignore[misc]

    handle = do_reserve(gate, entry, clock)
    copied = copy.copy(handle)
    assert True  # eq=False: identity, not value, is what the gate checks
    assert gate.release(copied) is False
    assert gate.release(handle) is True


def test_admission_outcome_and_write_outcome_shape():
    gate, registry, _ledger, clock = new_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert isinstance(outcome, AdmissionOutcome)
    assert (outcome.admission is None) != (outcome.denial is None)

    outcome2 = gate.begin_write(outcome.admission, sentinel=grant.sentinel)
    assert isinstance(outcome2, WriteOutcome)
    assert (outcome2.write_deadline is None) == (outcome2.code != "write_admitted")
    assert (outcome2.denial is None) == (outcome2.code == "write_admitted")


def test_closeout_return_type():
    gate, registry, _ledger, clock = new_system()
    grant, _entry = install(gate, registry, clock, active=True, ttl=200.0)
    result = gate.closeout(grant.lease_id)
    assert isinstance(result, Closeout)


@pytest.mark.parametrize("active_state", [False, True])
def test_install_scope_grant_carrying_another_leases_sentinel_gives_lease_unverified(
    active_state,
):
    # Registry snapshots carry no sentinel, so only the check's lease_id binds it to the lease.
    gate, registry, _ledger, clock = new_system()
    manifest_a = golden_manifest(run_id="run-1", attempt_id="attempt-1")
    manifest_b = golden_manifest(run_id="run-2", attempt_id="attempt-2")
    grant_a = register(registry, clock, run_id="run-1", attempt_id="attempt-1",
                       scope_digest=manifest_a.digest, ttl=200.0)
    grant_b = register(registry, clock, run_id="run-2", attempt_id="attempt-2",
                       scope_digest=manifest_b.digest, ttl=200.0)
    if active_state:
        activate(registry, clock, grant_a)
        activate(registry, clock, grant_b)
    forged = replace(grant_a, sentinel=grant_b.sentinel)
    assert_error(lambda: gate.install_scope(grant=forged, manifest=manifest_a), "lease_unverified")
    assert gate.snapshot()["scope_entries"] == ()
