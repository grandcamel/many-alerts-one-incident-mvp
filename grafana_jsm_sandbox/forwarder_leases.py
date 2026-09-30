"""Receiver-controlled, in-memory scoped leases for fixed Forwarder services.

This module has no transport, credential, process-isolation, or dispatch authority.
A future authenticated Receiver control adapter owns every mutating call.  ``check``
is an instantaneous authorization observation, never a dispatch token.
"""

from __future__ import annotations

import hmac
import json
import math
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from .forwarder_services import SERVICE_PROFILES

MAX_LIVE_LEASES = 256
MAX_RECORDS = 1024
MAX_HISTORY = 128
MAX_METADATA_BYTES = 512 * 1024
HEARTBEAT_SECONDS = 15.0
LEASE_SECONDS = 270.0
RETENTION_SECONDS = 310.0
# One record may turn two ``None`` timestamps into finite values and change its
# state/separators; one receipt is capped at 512 bytes; 4 KiB covers fixed
# snapshot keys and counters.  Registration reserves all three before mutation.
STATE_TRANSITION_RESERVE_BYTES = 128
HISTORY_RECEIPT_RESERVE_BYTES = 512
TOP_LEVEL_RESERVE_BYTES = 4096
MAX_HISTORY_DROPPED = 2**31 - 1
REVOCATION_REASONS = frozenset({
    "cancelled", "deadline", "control_failure", "launch_failure", "operator_cancel", "receiver_shutdown",
})

_MAX_ID_BYTES = 128
_SAFE_ID = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)
_SAFE_TOKEN = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
_HEX = frozenset("0123456789abcdef")


class LeaseError(ValueError):
    """A bounded control failure that never embeds a sentinel or caller value."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LeaseGrant:
    """An immutable lease binding.  Its sentinel never appears in repr/receipts."""

    generation: str
    lease_id: str
    run_id: str
    attempt_id: str
    receiver_boot_id: str
    service: str
    scope_digest: str
    expires_at: float
    sentinel: str = field(repr=False)


@dataclass(frozen=True)
class LeaseReceipt:
    """Nonsecret observation of one control or authorization decision."""

    operation: str
    generation: str
    lease_id: str | None
    service: str | None
    state: str
    reason: str
    authorized: bool | None
    observed_at: float


@dataclass
class _Record:
    grant: LeaseGrant
    receiver_boot_id: str
    created_at: float
    state: str = "registered"
    launch_at: float | None = None
    retired_at: float | None = None


class LeaseRegistry:
    """Serialize short-lived fixed-service authority under one injected clock.

    It intentionally loses duplicate suppression after retention or restart.  The
    durable Receiver journal must cover those intervals before a real launcher is
    connected.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock
        self._lock = threading.RLock()
        self._generation = _new_id("generation")
        self._receiver_boot_id: str | None = None
        self._last_heartbeat: float | None = None
        self._records: dict[str, _Record] = {}
        self._bindings: dict[tuple[str, str, str], str] = {}
        self._history: deque[LeaseReceipt] = deque(maxlen=MAX_HISTORY)
        self._history_dropped = 0
        self._last_now: float | None = None
        self._held_code: str | None = None
        self._control_stale = False

    @property
    def generation(self) -> str:
        """The current opaque process generation for the trusted controller."""
        return self._generation

    def hold(self) -> None:
        """Permanently deny authority after an uncertain control closeout.

        The trusted adapter uses this latch without consulting a possibly broken
        clock. Only a fresh registry generation can recover from a hold.
        """
        with self._lock:
            self._held_code = "control_failure"

    def handshake(self, *, receiver_boot_id: str, generation: str) -> LeaseReceipt:
        with self._lock:
            now = self._now()
            self._require_generation(generation)
            _require_id(receiver_boot_id, "invalid_receiver_boot_id")
            if self._receiver_boot_id is not None and receiver_boot_id != self._receiver_boot_id:
                self._retire_connected("receiver_replaced", now)
            self._receiver_boot_id = receiver_boot_id
            self._last_heartbeat = now
            self._control_stale = False
            return self._record_receipt("handshake", None, None, "connected", "ok", None, now)

    def heartbeat(self, *, receiver_boot_id: str, generation: str) -> LeaseReceipt:
        with self._lock:
            now = self._now()
            self._require_generation(generation)
            self._require_receiver(receiver_boot_id, require_fresh=False)
            if self._control_stale:
                self._last_heartbeat = now
                self._control_stale = False
                return self._record_receipt("heartbeat", None, None, "connected", "late_recovered", None, now)
            self._last_heartbeat = now
            return self._record_receipt("heartbeat", None, None, "connected", "ok", None, now)

    def disconnect(self, *, receiver_boot_id: str, generation: str) -> LeaseReceipt:
        with self._lock:
            now = self._now()
            self._require_generation(generation)
            self._require_receiver(receiver_boot_id, require_fresh=False)
            self._retire_connected("receiver_disconnected", now)
            self._receiver_boot_id = None
            self._last_heartbeat = None
            self._control_stale = False
            return self._record_receipt("disconnect", None, None, "disconnected", "ok", None, now)

    def register(
        self,
        *,
        run_id: str,
        attempt_id: str,
        receiver_boot_id: str,
        service: str,
        scope_digest: str,
        expires_at: float,
        generation: str,
    ) -> LeaseGrant:
        with self._lock:
            now = self._now()
            self._require_generation(generation)
            self._require_receiver(receiver_boot_id)
            _require_id(run_id, "invalid_run_id")
            _require_id(attempt_id, "invalid_attempt_id")
            _require_service(service)
            _require_digest(scope_digest)
            expiry = _require_time(expires_at, "invalid_expiry")
            if not now < expiry <= now + LEASE_SECONDS:
                raise LeaseError("invalid_expiry")
            binding = (run_id, attempt_id, service)
            known_id = self._bindings.get(binding)
            if known_id is not None:
                record = self._records[known_id]
                grant = record.grant
                self._expire_record(record, now, "expired")
                if record.state not in {"registered", "active"}:
                    raise LeaseError("replay_not_live")
                if (record.receiver_boot_id != receiver_boot_id or grant.generation != generation or
                        grant.scope_digest != scope_digest or grant.expires_at != expiry):
                    raise LeaseError("binding_conflict")
                return grant
            self._ensure_registration_capacity()
            grant = LeaseGrant(
                generation=self._generation,
                lease_id=_new_id("lease"),
                run_id=run_id,
                attempt_id=attempt_id,
                receiver_boot_id=receiver_boot_id,
                service=service,
                scope_digest=scope_digest,
                expires_at=expiry,
                sentinel=_new_token(),
            )
            record = _Record(grant, receiver_boot_id, now)
            if self._admission_reserve_bytes(extra=record) > MAX_METADATA_BYTES:
                raise LeaseError("capacity_metadata")
            self._records[grant.lease_id] = record
            self._bindings[binding] = grant.lease_id
            self._record_receipt("register", grant.lease_id, service, "registered", "ok", None, now)
            return grant

    def activate(
        self,
        *,
        lease_id: str,
        receiver_boot_id: str,
        generation: str,
        launch_at: float,
    ) -> LeaseReceipt:
        with self._lock:
            now = self._now()
            self._require_generation(generation)
            self._require_receiver(receiver_boot_id)
            record = self._record_for_control(lease_id, receiver_boot_id)
            launch = _require_time(launch_at, "invalid_launch_time")
            if launch < record.created_at or launch > now:
                raise LeaseError("invalid_launch_time")
            self._expire_record(record, now, "expired")
            if record.state == "revoked":
                raise LeaseError("lease_revoked")
            if record.state == "expired":
                raise LeaseError("lease_expired")
            if record.state == "active":
                if record.launch_at != launch:
                    raise LeaseError("lease_active")
                return self._record_receipt("activate", record.grant.lease_id, record.grant.service,
                                            "active", "replay", None, now)
            if record.state != "registered":
                raise LeaseError("lease_not_registered")
            if now >= launch + LEASE_SECONDS:
                self._retire(record, "expired", now)
                raise LeaseError("lease_expired")
            record.launch_at = launch
            record.state = "active"
            return self._record_receipt("activate", record.grant.lease_id, record.grant.service,
                                        "active", "ok", None, now)

    def revoke(
        self,
        *,
        lease_id: str,
        receiver_boot_id: str,
        generation: str,
        reason: str,
    ) -> LeaseReceipt:
        with self._lock:
            now = self._now()
            self._require_generation(generation)
            self._require_receiver(receiver_boot_id, require_fresh=False)
            record = self._record_for_control(lease_id, receiver_boot_id)
            _require_reason(reason)
            self._expire_record(record, now, "expired")
            if record.state == "expired":
                raise LeaseError("lease_expired")
            if record.state == "revoked":
                raise LeaseError("lease_revoked")
            self._retire(record, "revoked", now)
            return self._record_receipt("revoke", record.grant.lease_id, record.grant.service,
                                        "revoked", reason, None, now)

    def check(
        self, *, service: str, sentinel: str, generation: str, scope_digest: str
    ) -> LeaseReceipt:
        """Return an instantaneous nonsecret authorization snapshot only."""
        with self._lock:
            now = self._now()
            _require_service(service)
            _require_token(sentinel)
            _require_digest(scope_digest)
            _require_id(generation, "invalid_generation")
            if generation != self._generation:
                return self._record_receipt("check", None, service, "denied", "generation_mismatch", False, now)
            if self._receiver_boot_id is None:
                return self._record_receipt("check", None, service, "denied", "receiver_disconnected", False, now)
            if self._last_heartbeat is None or now - self._last_heartbeat >= HEARTBEAT_SECONDS:
                self._retire_connected("heartbeat_late", now)
                return self._record_receipt("check", None, service, "denied", "heartbeat_late", False, now)
            for record in self._records.values():
                grant = record.grant
                if grant.service != service or not hmac.compare_digest(grant.sentinel, sentinel):
                    continue
                self._expire_record(record, now, "expired")
                if record.state != "active":
                    return self._record_receipt("check", grant.lease_id, service, "denied",
                                                "lease_" + record.state, False, now)
                if grant.scope_digest != scope_digest:
                    return self._record_receipt("check", grant.lease_id, service, "denied",
                                                "scope_mismatch", False, now)
                return self._record_receipt("check", grant.lease_id, service, "active", "ok", True, now)
            return self._record_receipt("check", None, service, "denied", "sentinel_unknown", False, now)

    def snapshot(self) -> dict[str, object]:
        """Return bounded nonsecret diagnostics; callers receive a fresh projection."""
        with self._lock:
            try:
                now = self._now()
            except LeaseError:
                # Diagnostics remain readable once a clock fault has held all
                # authority. This does not advance or reconstruct the clock.
                now = self._last_now if self._last_now is not None else 0.0
            self._prune(now)
            payload = self._snapshot_payload()
            payload["metadata_bytes"] = self._fixed_point_bytes(payload)
            payload["leases"] = tuple(payload["leases"])
            payload["history"] = tuple(payload["history"])
            return payload

    def _now(self) -> float:
        try:
            now = _require_time(self._clock(), "clock_invalid")
        except Exception:  # noqa: BLE001 - a controller-supplied clock must never escape unheld.
            self._held_code = "clock_invalid"
            raise LeaseError("clock_invalid") from None
        if self._last_now is not None and now < self._last_now:
            self._held_code = "clock_regressed"
            raise LeaseError("clock_regressed")
        if self._held_code is not None:
            raise LeaseError("registry_held")
        self._last_now = now
        self._prune(now)
        for record in self._records.values():
            self._expire_record(record, now, "expired")
        if (self._receiver_boot_id is not None and self._last_heartbeat is not None and
                now - self._last_heartbeat >= HEARTBEAT_SECONDS):
            self._retire_connected("heartbeat_late", now)
            self._control_stale = True
        return now

    def _prune(self, now: float) -> None:
        for lease_id, record in tuple(self._records.items()):
            if now - record.created_at >= RETENTION_SECONDS:
                self._records.pop(lease_id)
                self._bindings.pop((record.grant.run_id, record.grant.attempt_id, record.grant.service), None)
        while self._history and now - self._history[0].observed_at >= RETENTION_SECONDS:
            self._history.popleft()
            self._drop_history(1)

    def _require_generation(self, generation: str) -> None:
        _require_id(generation, "invalid_generation")
        if generation != self._generation:
            raise LeaseError("generation_mismatch")

    def _require_receiver(self, receiver_boot_id: str, *, require_fresh: bool = True) -> None:
        _require_id(receiver_boot_id, "invalid_receiver_boot_id")
        if self._receiver_boot_id is None:
            raise LeaseError("receiver_not_connected")
        if require_fresh and self._control_stale:
            raise LeaseError("heartbeat_late")
        if receiver_boot_id != self._receiver_boot_id:
            raise LeaseError("receiver_boot_mismatch")

    def _record_for_control(self, lease_id: str, receiver_boot_id: str) -> _Record:
        _require_id(lease_id, "invalid_lease_id")
        record = self._records.get(lease_id)
        if record is None:
            raise LeaseError("lease_unknown")
        if record.receiver_boot_id != receiver_boot_id:
            raise LeaseError("receiver_boot_mismatch")
        return record

    def _ensure_registration_capacity(self) -> None:
        live = sum(record.state in {"registered", "active"} for record in self._records.values())
        if live >= MAX_LIVE_LEASES:
            raise LeaseError("capacity_live")
        if len(self._records) >= MAX_RECORDS:
            raise LeaseError("capacity_total")

    def _expire_record(self, record: _Record, now: float, reason: str) -> None:
        limits = [record.grant.expires_at, record.created_at + LEASE_SECONDS]
        if record.launch_at is not None:
            limits.append(record.launch_at + LEASE_SECONDS)
        limit = min(limits)
        if record.state in {"registered", "active"} and now >= limit:
            self._retire(record, "expired", now)
            self._record_receipt("expire", record.grant.lease_id, record.grant.service,
                                 "expired", reason, None, now)

    def _retire_connected(self, reason: str, now: float) -> None:
        for record in self._records.values():
            if record.state in {"registered", "active"}:
                self._retire(record, "revoked", now)
                self._record_receipt("revoke", record.grant.lease_id, record.grant.service,
                                     "revoked", reason, None, now)

    @staticmethod
    def _retire(record: _Record, state: str, now: float) -> None:
        record.state = state
        record.retired_at = now

    def _record_receipt(
        self,
        operation: str,
        lease_id: str | None,
        service: str | None,
        state: str,
        reason: str,
        authorized: bool | None,
        now: float,
    ) -> LeaseReceipt:
        receipt = LeaseReceipt(operation, self._generation, lease_id, service, state, reason, authorized, now)
        if len(self._history) == MAX_HISTORY:
            self._history.popleft()
            self._drop_history(1)
        self._history.append(receipt)
        while self._snapshot_bytes() > MAX_METADATA_BYTES and self._history:
            self._history.popleft()
            self._drop_history(1)
        return receipt

    def _snapshot_payload(self, *, extra: _Record | None = None) -> dict[str, object]:
        records = list(self._records.values())
        if extra is not None:
            records.append(extra)
        history = [_receipt_metadata(item) for item in self._history]
        return {
            "generation": self._generation,
            "registry_state": "held" if self._held_code else ("stale" if self._control_stale else "ready"),
            "receiver_boot_id": self._receiver_boot_id,
            "last_heartbeat": self._last_heartbeat,
            "live_leases": sum(record.state in {"registered", "active"} for record in records),
            "retained_records": len(records),
            "leases": [_record_metadata(record) for record in records],
            "history": history,
            "history_dropped": self._history_dropped,
        }

    def _snapshot_bytes(self) -> int:
        return self._fixed_point_bytes(self._snapshot_payload())

    def _admission_reserve_bytes(self, *, extra: _Record) -> int:
        records = [*self._records.values(), extra]
        return (
            sum(self._canonical_bytes(_record_metadata(record)) + STATE_TRANSITION_RESERVE_BYTES
                for record in records)
            + MAX_HISTORY * HISTORY_RECEIPT_RESERVE_BYTES
            + TOP_LEVEL_RESERVE_BYTES
        )

    @staticmethod
    def _canonical_bytes(payload: dict[str, object]) -> int:
        return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8"))

    def _fixed_point_bytes(self, payload: dict[str, object]) -> int:
        current = self._canonical_bytes(payload)
        while True:
            probe = dict(payload)
            probe["metadata_bytes"] = current
            updated = self._canonical_bytes(probe)
            if updated == current:
                return updated
            current = updated

    def _drop_history(self, count: int) -> None:
        self._history_dropped = min(MAX_HISTORY_DROPPED, self._history_dropped + count)


def _new_id(prefix: str) -> str:
    return prefix + "_" + secrets.token_urlsafe(24)


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _require_id(value: object, code: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= _MAX_ID_BYTES or any(char not in _SAFE_ID for char in value):
        raise LeaseError(code)
    return value


def _require_token(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 64 or any(char not in _SAFE_TOKEN for char in value):
        raise LeaseError("invalid_sentinel")
    return value


def _require_digest(value: object) -> str:
    if type(value) is not str or len(value) != 64 or any(char not in _HEX for char in value):
        raise LeaseError("invalid_scope_digest")
    return value


def _require_service(value: object) -> str:
    if type(value) is not str or value not in SERVICE_PROFILES:
        raise LeaseError("invalid_service")
    return value


def _require_reason(value: object) -> str:
    if type(value) is not str or value not in REVOCATION_REASONS:
        raise LeaseError("invalid_reason")
    return value


def _require_time(value: object, code: str) -> float:
    if type(value) not in {int, float}:
        raise LeaseError(code)
    try:
        converted = float(value)
    except (OverflowError, TypeError, ValueError):
        raise LeaseError(code) from None
    if not math.isfinite(converted) or converted < 0:
        raise LeaseError(code)
    return converted


def _receipt_metadata(receipt: LeaseReceipt) -> dict[str, object]:
    return {
        "operation": receipt.operation,
        "generation": receipt.generation,
        "lease_id": receipt.lease_id,
        "service": receipt.service,
        "state": receipt.state,
        "reason": receipt.reason,
        "authorized": receipt.authorized,
        "observed_at": receipt.observed_at,
    }


def _record_metadata(record: _Record) -> dict[str, object]:
    grant = record.grant
    return {
        "generation": grant.generation,
        "lease_id": grant.lease_id,
        "run_id": grant.run_id,
        "attempt_id": grant.attempt_id,
        "receiver_boot_id": grant.receiver_boot_id,
        "service": grant.service,
        "scope_digest": grant.scope_digest,
        "expires_at": grant.expires_at,
        "created_at": record.created_at,
        "launch_at": record.launch_at,
        "retired_at": record.retired_at,
        "state": record.state,
    }


__all__ = [
    "HEARTBEAT_SECONDS",
    "LEASE_SECONDS",
    "MAX_HISTORY",
    "MAX_LIVE_LEASES",
    "MAX_METADATA_BYTES",
    "MAX_RECORDS",
    "RETENTION_SECONDS",
    "REVOCATION_REASONS",
    "STATE_TRANSITION_RESERVE_BYTES",
    "LeaseError",
    "LeaseGrant",
    "LeaseReceipt",
    "LeaseRegistry",
]
