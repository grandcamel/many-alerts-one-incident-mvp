"""Independent policy tests for the in-process Forwarder lease registry.

The registry is a trusted application controller.  These tests do not treat a
snapshot or a successful check as an authenticated transport or OS dispatch
authorization.
"""

from __future__ import annotations

import json
import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from hashlib import sha256
from threading import Barrier

import pytest

from grafana_jsm_sandbox.forwarder_leases import (
    HEARTBEAT_SECONDS,
    LEASE_SECONDS,
    MAX_HISTORY,
    MAX_LIVE_LEASES,
    MAX_METADATA_BYTES,
    MAX_RECORDS,
    RETENTION_SECONDS,
    LeaseError,
    LeaseGrant,
    LeaseReceipt,
    LeaseRegistry,
)


class FakeClock:
    def __init__(self, value: float = 1_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


SCOPE = sha256(b"fixed-scope").hexdigest()
OTHER_SCOPE = sha256(b"other-scope").hexdigest()
SERVICE = "jira"
BOOT = "receiver-a"


def new_registry() -> tuple[LeaseRegistry, FakeClock]:
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    receipt = registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    assert isinstance(receipt, LeaseReceipt)
    assert receipt.authorized is None
    return registry, clock


def register_lease(
    registry: LeaseRegistry,
    clock: FakeClock,
    *,
    run_id: str = "run-1",
    attempt_id: str = "attempt-1",
    service: str = SERVICE,
    scope_digest: str = SCOPE,
    ttl: float = 100.0,
) -> LeaseGrant:
    return registry.register(
        run_id=run_id,
        attempt_id=attempt_id,
        receiver_boot_id=BOOT,
        service=service,
        scope_digest=scope_digest,
        expires_at=clock.value + ttl,
        generation=registry.generation,
    )


def activate(registry: LeaseRegistry, clock: FakeClock, grant: LeaseGrant) -> LeaseReceipt:
    return registry.activate(
        lease_id=grant.lease_id,
        receiver_boot_id=BOOT,
        generation=registry.generation,
        launch_at=clock.value,
    )


def assert_error(call, code: str | None = None) -> LeaseError:
    with pytest.raises(LeaseError) as caught:
        call()
    error = caught.value
    assert isinstance(error.code, str)
    if code is not None:
        assert error.code == code
    return error


def test_grant_binding_is_immutable_and_exact_replay_is_idempotent():
    registry, clock = new_registry()
    grant = register_lease(registry, clock, ttl=100)

    replay = register_lease(registry, clock, ttl=100)
    assert replay == grant
    assert replay.sentinel == grant.sentinel

    assert_error(lambda: register_lease(registry, clock, scope_digest=OTHER_SCOPE, ttl=100),
                 "binding_conflict")
    assert_error(lambda: register_lease(registry, clock, ttl=101), "binding_conflict")
    distinct_service = registry.register(
        run_id="run-1", attempt_id="attempt-1", receiver_boot_id="receiver-a",
        service="grafana", scope_digest=SCOPE, expires_at=clock.value + 100,
        generation=registry.generation,
    )
    assert distinct_service.lease_id != grant.lease_id

    with pytest.raises(FrozenInstanceError):
        grant.service = "grafana"  # type: ignore[misc]
    assert grant.sentinel not in repr(grant)


def test_pending_active_expiry_and_revocation_are_distinct_states():
    registry, clock = new_registry()
    grant = register_lease(registry, clock, ttl=10)

    pending = registry.check(service=SERVICE, sentinel=grant.sentinel,
                             generation=registry.generation, scope_digest=SCOPE)
    assert pending.authorized is False
    assert pending.state == "denied"
    assert pending.reason == "lease_registered"

    active = activate(registry, clock, grant)
    assert active.state == "active"
    allowed = registry.check(service=SERVICE, sentinel=grant.sentinel,
                             generation=registry.generation, scope_digest=SCOPE)
    assert allowed.authorized is True
    assert allowed.lease_id == grant.lease_id

    clock.advance(10)
    expired = registry.check(service=SERVICE, sentinel=grant.sentinel,
                             generation=registry.generation, scope_digest=SCOPE)
    assert expired.authorized is False
    assert expired.reason == "lease_expired"
    assert_error(lambda: registry.register(
        run_id=grant.run_id, attempt_id=grant.attempt_id, receiver_boot_id=BOOT,
        service=SERVICE, scope_digest=SCOPE, expires_at=clock.value + 10,
        generation=registry.generation,
    ))

    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)
    revoked = registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                              generation=registry.generation, reason="operator_cancel")
    assert revoked.state == "revoked"
    denied = registry.check(service=SERVICE, sentinel=grant.sentinel,
                            generation=registry.generation, scope_digest=SCOPE)
    assert denied.authorized is False
    assert denied.reason == "lease_revoked"
    assert_error(lambda: registry.register(
        run_id=grant.run_id, attempt_id=grant.attempt_id, receiver_boot_id=BOOT,
        service=SERVICE, scope_digest=SCOPE, expires_at=clock.value + 10,
        generation=registry.generation,
    ), "replay_not_live")


def test_check_is_instantaneous_and_does_not_serve_as_dispatch_authorization():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)
    observed = registry.check(service=SERVICE, sentinel=grant.sentinel,
                              generation=registry.generation, scope_digest=SCOPE)
    assert observed.authorized is True

    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                    generation=registry.generation, reason="cancelled")
    assert observed.authorized is True  # immutable historical observation
    current = registry.check(service=SERVICE, sentinel=grant.sentinel,
                             generation=registry.generation, scope_digest=SCOPE)
    assert current.authorized is False


def test_wrong_service_token_scope_and_generation_fail_closed_without_secrets():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)

    wrong_token = "A" * 32
    assert_error(lambda: registry.check(
        service="unknown", sentinel=grant.sentinel,
        generation=registry.generation, scope_digest=SCOPE,
    ), "invalid_service")
    for kwargs, reason in [
        ({"service": SERVICE, "sentinel": wrong_token}, "sentinel_unknown"),
        ({"service": SERVICE, "scope_digest": OTHER_SCOPE}, "scope_mismatch"),
        ({"service": SERVICE, "generation": "generation-forged"}, "generation_mismatch"),
    ]:
        args = {"service": SERVICE, "sentinel": grant.sentinel,
                "generation": registry.generation, "scope_digest": SCOPE}
        args.update(kwargs)
        receipt = registry.check(**args)
        assert receipt.authorized is False
        assert receipt.reason == reason
        assert grant.sentinel not in repr(receipt)

    assert_error(lambda: registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation="generation-forged", launch_at=clock.value,
    ), "generation_mismatch")
    assert grant.sentinel not in repr(registry.snapshot())


def test_ttl_270_expiry_is_inclusive_and_late_heartbeat_cannot_revive():
    registry, clock = new_registry()
    grant = register_lease(registry, clock, ttl=LEASE_SECONDS)
    activate(registry, clock, grant)
    for _ in range(19):
        clock.advance(13.5)
        registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)
    clock.advance(13.5)
    expired = registry.check(service=SERVICE, sentinel=grant.sentinel,
                             generation=registry.generation, scope_digest=SCOPE)
    assert expired.authorized is False
    assert expired.reason == "lease_expired"

    registry, clock = new_registry()
    grant = register_lease(registry, clock, ttl=100)
    activate(registry, clock, grant)
    clock.advance(HEARTBEAT_SECONDS - 0.1)
    heartbeat = registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)
    assert heartbeat.state == "connected"
    clock.advance(0.1)
    timely = registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)
    assert timely.reason == "ok"
    clock.advance(HEARTBEAT_SECONDS)
    late = registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)
    assert late.reason == "late_recovered"
    assert late.authorized is None
    assert registry.check(
        service=SERVICE, sentinel=grant.sentinel,
        generation=registry.generation, scope_digest=SCOPE,
    ).reason == "lease_revoked"


def test_late_heartbeat_retires_leases_and_does_not_extend_expiry():
    registry, clock = new_registry()
    grant = register_lease(registry, clock, ttl=200)
    activate(registry, clock, grant)
    clock.advance(HEARTBEAT_SECONDS)
    late = registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)
    assert late.reason == "late_recovered"
    assert late.authorized is None
    denied = registry.check(service=SERVICE, sentinel=grant.sentinel,
                            generation=registry.generation, scope_digest=SCOPE)
    assert denied.authorized is False
    assert denied.reason == "lease_revoked"


def test_expiry_and_launch_bounds_reject_future_or_overlong_values():
    registry, clock = new_registry()
    assert_error(lambda: register_lease(registry, clock, ttl=LEASE_SECONDS + 0.001),
                 "invalid_expiry")
    grant = register_lease(registry, clock)
    assert_error(lambda: registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, launch_at=clock.value - 0.001,
    ), "invalid_launch_time")
    assert_error(lambda: registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, launch_at=clock.value + 0.001,
    ), "invalid_launch_time")


def test_disconnect_and_new_receiver_boot_revoke_old_generation_bindings():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)
    disconnected = registry.disconnect(receiver_boot_id=BOOT, generation=registry.generation)
    assert disconnected.state == "disconnected"
    disconnected_check = registry.check(
        service=SERVICE, sentinel=grant.sentinel,
        generation=registry.generation, scope_digest=SCOPE)
    assert disconnected_check.authorized is False
    assert disconnected_check.reason == "receiver_disconnected"

    registry.handshake(receiver_boot_id="receiver-b", generation=registry.generation)
    old = registry.check(service=SERVICE, sentinel=grant.sentinel,
                         generation=registry.generation, scope_digest=SCOPE)
    assert old.authorized is False
    assert old.reason == "lease_revoked"
    assert_error(lambda: registry.activate(
        lease_id=grant.lease_id, receiver_boot_id="receiver-b",
        generation=registry.generation, launch_at=clock.value,
    ), "receiver_boot_mismatch")

    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)
    registry.handshake(receiver_boot_id="receiver-b", generation=registry.generation)
    replaced = registry.check(service=SERVICE, sentinel=grant.sentinel,
                              generation=registry.generation, scope_digest=SCOPE)
    assert replaced.authorized is False
    assert replaced.reason == "lease_revoked"


def test_same_boot_handshake_at_heartbeat_boundary_cannot_revive_leases():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)
    clock.advance(HEARTBEAT_SECONDS)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    denied = registry.check(service=SERVICE, sentinel=grant.sentinel,
                            generation=registry.generation, scope_digest=SCOPE)
    assert denied.authorized is False
    assert denied.reason == "lease_revoked"


def test_stale_receiver_cannot_register_until_new_handshake():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    activate(registry, clock, grant)
    clock.advance(HEARTBEAT_SECONDS)
    snapshot = registry.snapshot()
    assert snapshot["live_leases"] == 0
    assert snapshot["retained_records"] == 1
    assert_error(lambda: register_lease(
        registry, clock, run_id="stale", attempt_id="stale",
    ), "heartbeat_late")
    assert_error(lambda: activate(registry, clock, grant), "heartbeat_late")

    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    replacement = register_lease(registry, clock, run_id="fresh", attempt_id="fresh")
    activate(registry, clock, replacement)
    assert registry.check(
        service=SERVICE, sentinel=replacement.sentinel,
        generation=registry.generation, scope_digest=SCOPE,
    ).authorized is True


def test_short_expiry_frees_live_capacity_without_early_record_eviction():
    registry, clock = new_registry()
    for index in range(MAX_LIVE_LEASES):
        register_lease(
            registry, clock, run_id=f"short-run-{index}",
            attempt_id=f"short-attempt-{index}", ttl=1,
        )
    clock.advance(1)
    replacement = register_lease(registry, clock, run_id="after-expiry", attempt_id="after-expiry")
    assert replacement.lease_id
    snapshot = registry.snapshot()
    assert snapshot["live_leases"] == 1
    assert snapshot["retained_records"] == MAX_LIVE_LEASES + 1


@pytest.mark.parametrize("field,value", [
    ("run_id", 1), ("attempt_id", None), ("receiver_boot_id", True),
    ("service", 1), ("scope_digest", SCOPE.upper()),
    ("expires_at", True), ("generation", None),
])
def test_registration_inputs_are_strictly_typed(field, value):
    registry, clock = new_registry()
    values = {
        "run_id": "run-1", "attempt_id": "attempt-1", "receiver_boot_id": BOOT,
        "service": SERVICE, "scope_digest": SCOPE, "expires_at": clock.value + 100,
        "generation": registry.generation,
    }
    values[field] = value
    assert_error(lambda: registry.register(**values))


def test_identifier_and_sentinel_byte_bounds_are_exact():
    registry, clock = new_registry()
    grant = register_lease(registry, clock, run_id="r" * 128, attempt_id="a" * 128)
    assert len(grant.run_id) == len(grant.attempt_id) == 128
    assert_error(lambda: registry.register(
        run_id="r" * 129, attempt_id="other", receiver_boot_id=BOOT,
        service=SERVICE, scope_digest=SCOPE, expires_at=clock.value + 100,
        generation=registry.generation,
    ), "invalid_run_id")
    assert_error(lambda: registry.check(
        service=SERVICE, sentinel="x" * 129,
        generation=registry.generation, scope_digest=SCOPE,
    ), "invalid_sentinel")


@pytest.mark.parametrize("value", [None, True, 1, "", "é", "x" * 65])
def test_check_sentinel_types_are_rejected_without_echoing_input(value):
    registry, _clock = new_registry()
    error = assert_error(lambda: registry.check(
        service=SERVICE, sentinel=value, generation=registry.generation, scope_digest=SCOPE
    ))
    if value:
        assert str(value) not in str(error)


def test_reasons_are_bounded_and_strictly_typed():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    bad_reason = "é" * 2
    assert_error(lambda: registry.revoke(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, reason=bad_reason,
    ), "invalid_reason")
    assert_error(lambda: registry.revoke(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, reason=grant.sentinel,
    ), "invalid_reason")
    assert_error(lambda: registry.revoke(
        lease_id=grant.lease_id, receiver_boot_id=BOOT,
        generation=registry.generation, reason=True,
    ), "invalid_reason")


def test_clock_rollback_and_nonfinite_time_sticky_hold_registry():
    registry, clock = new_registry()
    register_lease(registry, clock)
    clock.value -= 1
    assert_error(lambda: registry.heartbeat(
        receiver_boot_id=BOOT, generation=registry.generation), "clock_regressed")
    clock.value += 2
    held = registry.snapshot()
    assert held["registry_state"] == "held"
    assert_error(lambda: registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation),
                 "registry_held")

    registry, clock = new_registry()
    clock.value = math.nan
    assert_error(lambda: registry.handshake(
        receiver_boot_id=BOOT, generation=registry.generation), "clock_invalid")
    clock.value = 1_001
    assert registry.snapshot()["registry_state"] == "held"

    class ExplodingClock:
        def __init__(self):
            self.fail = True
            self.value = 1_000.0

        def __call__(self):
            if self.fail:
                raise RuntimeError("clock unavailable")
            return self.value

    exploding = ExplodingClock()
    registry = LeaseRegistry(clock=exploding)
    assert_error(lambda: registry.handshake(
        receiver_boot_id=BOOT, generation=registry.generation), "clock_invalid")
    exploding.fail = False
    assert exploding.value == 1_000.0
    assert registry.snapshot()["registry_state"] == "held"

    huge = FakeClock(10**1000)
    registry = LeaseRegistry(clock=huge)
    assert_error(lambda: registry.handshake(
        receiver_boot_id=BOOT, generation=registry.generation), "clock_invalid")
    huge.value = 1_000.0
    assert registry.snapshot()["registry_state"] == "held"


def test_snapshot_shape_is_bounded_nonsecret_and_receipts_are_frozen():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    receipt = activate(registry, clock, grant)
    snapshot = registry.snapshot()
    assert set(snapshot) == {
        "generation", "registry_state", "receiver_boot_id", "last_heartbeat",
        "live_leases", "retained_records", "metadata_bytes", "leases", "history",
        "history_dropped",
    }
    assert snapshot["metadata_bytes"] <= MAX_METADATA_BYTES
    encoded_payload = dict(snapshot)
    metadata_bytes = encoded_payload["metadata_bytes"]
    canonical_size = len(json.dumps(
        encoded_payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8"))
    assert metadata_bytes == canonical_size
    assert len(snapshot["leases"]) == 1
    assert set(snapshot["leases"][0]) == {
        "generation", "lease_id", "run_id", "attempt_id", "receiver_boot_id", "service",
        "scope_digest", "expires_at", "created_at", "launch_at", "retired_at", "state",
    }
    assert grant.sentinel not in repr(snapshot["leases"])
    assert isinstance(snapshot["history"], tuple)
    assert len(snapshot["history"]) <= MAX_HISTORY
    assert all(grant.sentinel not in repr(item) for item in snapshot["history"])
    assert grant.sentinel not in repr(receipt)
    with pytest.raises(FrozenInstanceError):
        receipt.reason = "tampered"  # type: ignore[misc]


def test_concurrent_duplicate_registration_returns_one_exact_grant():
    registry, clock = new_registry()
    barrier = Barrier(8)

    def register_same() -> LeaseGrant:
        barrier.wait()
        return register_lease(registry, clock)

    with ThreadPoolExecutor(max_workers=8) as pool:
        grants = list(pool.map(lambda _: register_same(), range(8)))
    assert all(item == grants[0] for item in grants)
    snapshot = registry.snapshot()
    assert snapshot["live_leases"] == 1
    assert snapshot["retained_records"] == 1


def test_live_capacity_refuses_registration_without_eviction():
    registry, clock = new_registry()
    for index in range(MAX_LIVE_LEASES):
        register_lease(registry, clock, run_id=f"run-{index}", attempt_id=f"attempt-{index}")
    before = registry.snapshot()
    assert before["live_leases"] == MAX_LIVE_LEASES
    assert before["retained_records"] == MAX_LIVE_LEASES
    assert_error(lambda: register_lease(registry, clock, run_id="overflow", attempt_id="overflow"),
                 "capacity_live")
    after = registry.snapshot()
    assert after["live_leases"] == MAX_LIVE_LEASES
    assert after["retained_records"] == MAX_LIVE_LEASES


def test_total_capacity_refuses_before_eviction(monkeypatch):
    from grafana_jsm_sandbox import forwarder_leases

    registry, clock = new_registry()
    monkeypatch.setattr(forwarder_leases, "MAX_METADATA_BYTES", 10**9)
    for index in range(MAX_RECORDS):
        grant = register_lease(registry, clock, run_id=f"run-{index}", attempt_id=f"attempt-{index}")
        registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                        generation=registry.generation, reason="cancelled")
    before = registry.snapshot()
    assert before["retained_records"] == MAX_RECORDS
    assert before["live_leases"] == 0
    assert_error(lambda: register_lease(registry, clock, run_id="overflow", attempt_id="overflow"),
                 "capacity_total")
    after = registry.snapshot()
    assert after["retained_records"] == MAX_RECORDS
    assert after["live_leases"] == 0
    assert len(after["history"]) <= MAX_HISTORY


def test_default_metadata_capacity_refuses_without_eviction():
    registry, clock = new_registry()
    accepted = 0
    pending = []
    with pytest.raises(LeaseError) as caught:
        for index in range(MAX_RECORDS):
            grant = register_lease(registry, clock, run_id=f"bytes-run-{index}",
                                   attempt_id=f"bytes-attempt-{index}")
            if len(pending) < MAX_LIVE_LEASES // 2:
                pending.append(grant)
            else:
                registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                                generation=registry.generation, reason="cancelled")
            accepted += 1
    assert caught.value.code == "capacity_metadata"
    snapshot = registry.snapshot()
    assert snapshot["retained_records"] == accepted
    assert snapshot["live_leases"] == len(pending)
    assert snapshot["metadata_bytes"] <= MAX_METADATA_BYTES
    retained_ids = {item["lease_id"] for item in snapshot["leases"]}

    # Fill later timestamps without admitting a new record, then retire every
    # remaining lease at the heartbeat boundary. Both transitions need space.
    clock.advance(0.123456789)
    for grant in pending:
        activate(registry, clock, grant)
    clock.value = 1_000.0 + HEARTBEAT_SECONDS
    final = registry.snapshot()
    assert final["live_leases"] == 0
    assert {item["lease_id"] for item in final["leases"]} == retained_ids
    assert len(final["history"]) == MAX_HISTORY
    assert final["history_dropped"] > snapshot["history_dropped"]
    assert final["metadata_bytes"] == len(json.dumps(
        final, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8"))
    assert final["metadata_bytes"] <= MAX_METADATA_BYTES


def test_retention_prunes_only_after_310_seconds_and_allows_new_binding():
    registry, clock = new_registry()
    grant = register_lease(registry, clock)
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                    generation=registry.generation, reason="cancelled")
    assert registry.snapshot()["retained_records"] == 1
    clock.advance(RETENTION_SECONDS - 0.1)
    assert registry.snapshot()["retained_records"] == 1
    clock.advance(0.2)
    assert registry.snapshot()["retained_records"] == 0
    assert registry.snapshot()["history"] == ()

    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    replacement = register_lease(registry, clock, ttl=100)
    assert replacement.lease_id != grant.lease_id
    assert replacement.sentinel != grant.sentinel
