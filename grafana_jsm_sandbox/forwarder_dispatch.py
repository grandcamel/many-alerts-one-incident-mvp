"""Atomic dispatch gate: admission, the write fence and closeout for one generation.

One ``DispatchGate`` is the dispatch authority for exactly one ``LeaseRegistry``
and one ``ReceiptLedger`` of equal generation. It performs no I/O and never
holds its lock ``G`` while calling injected code, except the three monotonic
clocks (its own, the registry's under ``R``, the ledger's under ``L``, all
called while ``G`` is held). It never mutates the registry and never retains
a ``RoutedRequest``, request, response or body.

Two moments are linearized under ``G``: dispatch initiation (``admit``, L1)
and the first possible upstream write (``begin_write``, L2). Between them and
after them, a flight is tracked until the owner releases it or its deadline
passes and it becomes ``overdue`` -- never silently deleted by another
thread's clock read.

The module-1 error discipline applies: an ``except`` block only records a
fixed code, and a fresh ``DispatchError`` is raised once the ``try``
statement has ended, with ``from None``; nothing is re-raised.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .forwarder_http_response import ParsedResponse
from .forwarder_leases import LeaseError, LeaseGrant, LeaseRegistry
from .forwarder_receipts import (
    MAX_HANDLER_SECONDS,
    ForwarderReceipt,
    ReceiptError,
    ReceiptLedger,
    ReceiptReservation,
)
from .forwarder_routes import (
    ROUTE_CATALOG,
    RouteConfigError,
    RoutedRequest,
    ScopeManifest,
    require_manifest_binding,
)
from .forwarder_services import SERVICE_PROFILES

# --- constants ---------------------------------------------------------------

MAX_SCOPE_ENTRIES = 1024
MAX_SCOPE_BYTES = 2 * 1024 * 1024
SCOPE_ENTRY_OVERHEAD_BYTES = 1024
STORE_RETENTION_SECONDS = 310.0
MAX_OPEN_DISPATCHES = 32
CONNECT_SECONDS = 5.0
WRITE_SECONDS = 10.0
READ_INACTIVITY_SECONDS = 20.0
RESPONSE_MARGIN_SECONDS = 1.0
MIN_ADMISSION_SECONDS = 1.0
MIN_WRITE_SECONDS = 0.5
# MAX_HANDLER_SECONDS is re-exported from forwarder_receipts (imported above).

# --- closed codes --------------------------------------------------------------

DENIAL_REASONS = frozenset({
    "request_rejected", "lease_denied", "route_denied", "permit_denied", "deadline",
})
ADMISSION_CODES = (
    "admitted", "lease_denied", "sentinel_mismatch", "permit_unavailable",
    "insufficient_time", "gate_closed", "gate_held",
)
WRITE_FENCE_CODES = (
    "write_admitted", "lease_denied", "sentinel_mismatch", "permit_unavailable",
    "insufficient_time", "gate_closed", "gate_held",
)
_UNCERTAIN_DISPATCH_STATES = ("DISPATCHED_UNKNOWN", "PARTIAL")
GATE_STATES = ("ready", "closed", "held")
HOLD_CODES = ("clock_fault", "clock_domain_mismatch")
FLIGHT_PHASES = ("reserved", "admitted", "writing")
CLOSEOUT_STATES = ("open", "draining", "overdue", "quiescent", "unknown")
LEASE_STATES = ("registered", "active", "revoked", "expired", "pruned", "unknown")

DISPATCH_ERROR_CODES = frozenset({
    "clock_fault", "gate_held", "gate_closed", "generation_mismatch", "authority_claimed",
    "manifest_binding_mismatch", "grant_expired", "lease_unverified", "scope_conflict",
    "scope_capacity", "scope_unknown",
    "binding_mismatch", "route_unavailable", "deadline_exceeds_lease", "dispatch_capacity",
    "receipt_unavailable", "invalid_reason",
    "handle_unknown", "handle_consumed", "deadline_expired", "admission_unknown",
    "write_claimed", "invalid_outcome",
})


class DispatchError(ValueError):
    """A fixed, non-diagnostic dispatch rejection; never embeds a caller value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _map_reserve_error(code: str) -> str:
    """``ledger.reserve``'s only mapped failure: an already-passed deadline."""
    return "deadline_expired" if code == "invalid_deadline" else "receipt_unavailable"


def _map_transition_error(code: str) -> str:
    """A ledger transition failure: swept (deadline_expired) or any other fault."""
    return "deadline_expired" if code == "deadline_expired" else "receipt_unavailable"


# --- validation helpers --------------------------------------------------------

_SENTINEL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_SAFE_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)


def _valid_sentinel_shape(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 43
        and all(character in _SENTINEL_CHARS for character in value)
    )


def _valid_lease_id_shape(value: str) -> bool:
    return 1 <= len(value) <= 128 and all(character in _SAFE_ID_CHARS for character in value)


# --- types -----------------------------------------------------------------


@dataclass(frozen=True, eq=False)
class ScopeEntry:
    """An installed lease binding. Authenticated by identity, never by value."""

    lease_id: str
    run_id: str
    attempt_id: str
    service: str
    generation: str
    scope_digest: str
    expires_at: float
    installed_at: float
    manifest: ScopeManifest = field(repr=False)


@dataclass(frozen=True, eq=False)
class DispatchHandle:
    """A reserved-flight token. Authenticated by identity, never by value."""

    receipt_id: str
    lease_id: str
    service: str
    route_id: str
    deadline: float


@dataclass(frozen=True, eq=False)
class Admission:
    """An admitted-flight token (L1 passed). Authenticated by identity."""

    receipt_id: str
    lease_id: str
    service: str
    route_id: str
    admitted_at: float
    deadline: float
    exchange_deadline: float
    connect_deadline: float


@dataclass(frozen=True)
class AdmissionOutcome:
    code: str
    admission: Admission | None
    denial: ForwarderReceipt | None


@dataclass(frozen=True)
class WriteOutcome:
    code: str
    write_deadline: float | None
    denial: ForwarderReceipt | None


@dataclass(frozen=True)
class Closeout:
    lease_id: str
    lease_state: str
    closeout_state: str
    pending: int
    in_flight: int
    overdue: int
    drain_deadline: float | None
    uncertain: int
    observed_at: float


@dataclass(frozen=True)
class ShutdownReport:
    in_flight: int
    overdue: int
    aborted: int
    abort_failures: int


@dataclass
class _Flight:
    """Private, mutable bookkeeping for one in-flight dispatch. Never exported."""

    handle: DispatchHandle
    reservation: ReceiptReservation
    lease_id: str
    service: str
    route_id: str
    generation: str
    scope_digest: str
    index: bytes
    requires_permit: bool
    deadline: float
    exchange_deadline: float
    phase: str = "reserved"
    overdue: bool = False
    admission: Admission | None = None
    abort: Callable[[], None] | None = None
    abort_fired: bool = False


_AUTHORITY_LOCK = threading.Lock()
_CLAIM_MARKER = "_maoi_dispatch_gate_claimed"
_SYSTEM_CLOCK = time.monotonic


class DispatchGate:
    """The dispatch authority for one ``LeaseRegistry``/``ReceiptLedger`` pair.

    The gate is the only caller of the registry's ``check``/``snapshot``
    besides ``ForwarderControl``, and it never calls a mutating registry
    method. The only writers of the ledger are the gate (``reserve``,
    ``begin_connect``, ``begin_dispatch``, ``finalize``) and
    ``send_response`` (``claim_delivery``, ``complete_delivery``).
    """

    def __init__(
        self, *, registry: LeaseRegistry, ledger: ReceiptLedger,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(registry) is not LeaseRegistry or type(ledger) is not ReceiptLedger:
            raise TypeError("DispatchGate requires an exact LeaseRegistry and ReceiptLedger")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if ledger.generation != registry.generation:
            raise DispatchError("generation_mismatch")
        with _AUTHORITY_LOCK:
            if getattr(registry, _CLAIM_MARKER, False) or getattr(ledger, _CLAIM_MARKER, False):
                raise DispatchError("authority_claimed")
            setattr(registry, _CLAIM_MARKER, True)
            setattr(ledger, _CLAIM_MARKER, True)
        self._registry = registry
        self._ledger = ledger
        self._clock = clock
        self._generation = registry.generation
        self._system_clock = clock is _SYSTEM_CLOCK
        self._G = threading.RLock()
        self._index_key = secrets.token_bytes(32)
        self._scope_by_index: dict[bytes, ScopeEntry] = {}
        self._scope_by_lease: dict[str, ScopeEntry] = {}
        self._scope_index_by_lease: dict[str, bytes] = {}
        self._scope_charge: dict[str, int] = {}
        self._scope_bytes = 0
        self._flights: dict[str, _Flight] = {}
        self._gate_state = "ready"
        self._hold_code: str | None = None
        self._closed = False
        self._last_now: float | None = None
        self._abort_queue: list[Callable[[], None]] = []
        self._abort_failures = 0

    # -- properties ---------------------------------------------------------

    @property
    def generation(self) -> str:
        return self._generation

    @property
    def ledger(self) -> ReceiptLedger:
        return self._ledger

    @property
    def system_clock(self) -> bool:
        return self._system_clock

    # -- index and clock plumbing --------------------------------------------

    def _index_for(self, service: str, sentinel: str) -> bytes | None:
        try:
            payload = service.encode("ascii") + b"\x00" + sentinel.encode("ascii")
        except UnicodeEncodeError:
            return None
        return hmac.new(self._index_key, payload, hashlib.sha256).digest()

    def _sweep_overdue(self, now: float) -> None:
        for flight in self._flights.values():
            if not flight.overdue and now >= flight.deadline:
                flight.overdue = True
                if flight.abort is not None and not flight.abort_fired:
                    self._abort_queue.append(flight.abort)
                    flight.abort_fired = True

    def _remove_scope_entry(self, lease_id: str) -> None:
        index = self._scope_index_by_lease.pop(lease_id, None)
        if index is not None:
            self._scope_by_index.pop(index, None)
        self._scope_by_lease.pop(lease_id, None)
        self._scope_bytes -= self._scope_charge.pop(lease_id, 0)

    def _prune_scope(self, now: float) -> None:
        for lease_id, entry in list(self._scope_by_lease.items()):
            if now - entry.installed_at >= STORE_RETENTION_SECONDS:
                self._remove_scope_entry(lease_id)

    def _over_scope_capacity(self, charge: int) -> bool:
        return (
            len(self._scope_by_lease) >= MAX_SCOPE_ENTRIES
            or self._scope_bytes + charge > MAX_SCOPE_BYTES
        )

    def _read_clock(self) -> float | None:
        """One validated gate-clock read under ``G``; any fault holds the gate (None)."""
        value: float | None = None
        try:
            reading = self._clock()
            if type(reading) in (int, float) and math.isfinite(reading) and reading >= 0:
                value = float(reading)
        except Exception:  # noqa: BLE001 - an injected clock must never escape unheld.
            value = None
        if value is None or (self._last_now is not None and value < self._last_now):
            self._gate_state = "held"
            self._hold_code = "clock_fault"
            return None
        self._last_now = value
        return value

    def _advance(self) -> tuple[bool, float, str]:
        """Advance the clock under ``G``. Never raises; (ok, now, code)."""
        if self._hold_code is not None:
            return False, 0.0, "gate_held"
        value = self._read_clock()
        if value is None:
            return False, 0.0, "clock_fault"
        self._sweep_overdue(value)
        self._prune_scope(value)
        return True, value, ""

    def _tick(self) -> float:
        ok, value, code = self._advance()
        if not ok:
            raise DispatchError(code) from None
        return value

    def _drain_aborts(self) -> None:
        while True:
            with self._G:
                if not self._abort_queue:
                    return
                callback = self._abort_queue.pop(0)
            failed = False
            try:
                callback()
            except Exception:  # noqa: BLE001 - an injected abort callable must never escape.
                failed = True
            if failed:
                with self._G:
                    self._abort_failures += 1

    def _flight_for(self, receipt_id: object) -> _Flight | None:
        # A forged token may carry an unhashable receipt_id; it is simply unknown.
        return self._flights.get(receipt_id) if type(receipt_id) is str else None

    def now(self) -> float:
        try:
            with self._G:
                return self._tick()
        finally:
            self._drain_aborts()

    # -- scope store ----------------------------------------------------------

    def install_scope(self, *, grant: LeaseGrant, manifest: ScopeManifest) -> ScopeEntry:
        if type(grant) is not LeaseGrant or type(manifest) is not ScopeManifest:
            raise TypeError("install_scope requires an exact LeaseGrant and ScopeManifest")
        try:
            with self._G:
                return self._install_scope_locked(grant, manifest)
        finally:
            self._drain_aborts()

    def _install_scope_locked(self, grant: LeaseGrant, manifest: ScopeManifest) -> ScopeEntry:
        if self._gate_state == "closed":
            raise DispatchError("gate_closed")
        now = self._tick()
        binding_code: str | None = None
        try:
            require_manifest_binding(
                manifest, service=grant.service, run_id=grant.run_id,
                attempt_id=grant.attempt_id, scope_digest=grant.scope_digest,
            )
        except RouteConfigError:
            binding_code = "manifest_binding_mismatch"
        if binding_code is not None:
            raise DispatchError(binding_code) from None
        if grant.generation != self._generation:
            raise DispatchError("generation_mismatch")
        check_code: str | None = None
        receipt = None
        try:
            receipt = self._registry.check(
                service=grant.service, sentinel=grant.sentinel,
                generation=grant.generation, scope_digest=grant.scope_digest,
            )
        except LeaseError:
            check_code = "lease_unverified"
        if check_code is None and (
            type(receipt.lease_id) is not str
            or not hmac.compare_digest(receipt.lease_id, grant.lease_id)
            or not (receipt.authorized is True or receipt.reason == "lease_registered")
        ):
            check_code = "lease_unverified"
        if check_code is not None:
            raise DispatchError(check_code) from None
        registry_snapshot = self._registry.snapshot()
        record = next(
            (item for item in registry_snapshot["leases"] if item["lease_id"] == grant.lease_id),
            None,
        )
        if (
            record is None
            or record["service"] != grant.service
            or record["run_id"] != grant.run_id
            or record["attempt_id"] != grant.attempt_id
            or record["receiver_boot_id"] != grant.receiver_boot_id
            or record["scope_digest"] != grant.scope_digest
            or record["expires_at"] != grant.expires_at
            or record["generation"] != grant.generation
            or record["state"] not in ("registered", "active")
        ):
            raise DispatchError("lease_unverified")
        if now >= record["expires_at"]:
            raise DispatchError("grant_expired")
        index = self._index_for(grant.service, grant.sentinel)
        if index is None:
            raise DispatchError("lease_unverified")
        existing = self._scope_by_lease.get(grant.lease_id)
        if existing is not None:
            if (
                self._scope_index_by_lease.get(grant.lease_id) == index
                and existing.manifest.digest == manifest.digest
            ):
                return existing
            raise DispatchError("scope_conflict")
        if index in self._scope_by_index:
            raise DispatchError("scope_conflict")
        charge = len(manifest.canonical_bytes()) + SCOPE_ENTRY_OVERHEAD_BYTES
        if self._over_scope_capacity(charge):
            self._prune_scope(now)
            live_leases = {item["lease_id"] for item in registry_snapshot["leases"]}
            for stale_lease in list(self._scope_by_lease):
                if stale_lease not in live_leases:
                    self._remove_scope_entry(stale_lease)
            if self._over_scope_capacity(charge):
                raise DispatchError("scope_capacity")
        entry = ScopeEntry(
            lease_id=grant.lease_id, run_id=grant.run_id, attempt_id=grant.attempt_id,
            service=grant.service, generation=grant.generation, scope_digest=grant.scope_digest,
            expires_at=grant.expires_at, installed_at=now, manifest=manifest,
        )
        self._scope_by_index[index] = entry
        self._scope_by_lease[grant.lease_id] = entry
        self._scope_index_by_lease[grant.lease_id] = index
        self._scope_charge[grant.lease_id] = charge
        self._scope_bytes += charge
        return entry

    def resolve(self, *, service: str, sentinel: str) -> ScopeEntry | None:
        if type(service) is not str:
            raise TypeError("resolve requires an exact str service")
        if service not in SERVICE_PROFILES:
            raise ValueError("unknown service")
        if not _valid_sentinel_shape(sentinel):
            return None
        with self._G:
            index = self._index_for(service, sentinel)
            entry = self._scope_by_index.get(index) if index is not None else None
            if entry is None:
                return None
            # Retention is checked on a fresh reading without a tick; a held gate
            # never re-reads its clock.
            now = self._last_now if self._hold_code is not None else self._read_clock()
            if now is None or now - entry.installed_at >= STORE_RETENTION_SECONDS:
                return None
            return entry

    def precheck(self, entry: ScopeEntry, *, sentinel: str) -> bool:
        if type(entry) is not ScopeEntry:
            raise TypeError("precheck requires an exact ScopeEntry")
        if type(sentinel) is not str:
            raise TypeError("precheck requires an exact str sentinel")
        with self._G:
            if self._gate_state != "ready":
                return False
            if self._scope_by_lease.get(entry.lease_id) is not entry:
                return False
            try:
                receipt = self._registry.check(
                    service=entry.service, sentinel=sentinel,
                    generation=entry.generation, scope_digest=entry.scope_digest,
                )
            except LeaseError:
                return False
            if receipt.authorized is not True or type(receipt.lease_id) is not str:
                return False
            return hmac.compare_digest(receipt.lease_id, entry.lease_id)

    def deny(
        self, entry: ScopeEntry, *, route_id: str, request_digest: str, reason: str,
        request_bytes: int, deadline: float,
    ) -> ForwarderReceipt:
        if type(entry) is not ScopeEntry:
            raise TypeError("deny requires an exact ScopeEntry")
        if (
            type(route_id) is not str or type(request_digest) is not str
            or type(reason) is not str or type(request_bytes) is not int
            or type(deadline) not in (int, float)
        ):
            raise TypeError("deny requires exact argument types")
        with self._G:
            if self._scope_by_lease.get(entry.lease_id) is not entry:
                raise DispatchError("scope_unknown")
            if reason not in DENIAL_REASONS:
                raise DispatchError("invalid_reason")
            code: str | None = None
            receipt: ForwarderReceipt | None = None
            try:
                reservation = self._ledger.reserve(
                    lease_id=entry.lease_id, attempt_id=entry.attempt_id, service=entry.service,
                    route_id=route_id, request_digest=request_digest,
                    request_bytes=request_bytes, deadline=deadline,
                )
            except ReceiptError as caught:
                code = _map_reserve_error(caught.code)
            if code is None:
                try:
                    receipt = self._ledger.finalize(
                        reservation, dispatch_state="NOT_DISPATCHED", reason=reason,
                    )
                except ReceiptError:
                    code = "receipt_unavailable"
            if code is not None:
                raise DispatchError(code) from None
            return receipt

    # -- dispatch flights -------------------------------------------------------

    def reserve(
        self, entry: ScopeEntry, routed: RoutedRequest, *, request_digest: str,
        request_bytes: int, deadline: float,
    ) -> DispatchHandle:
        if type(entry) is not ScopeEntry or type(routed) is not RoutedRequest:
            raise TypeError("reserve requires an exact ScopeEntry and RoutedRequest")
        if (
            type(request_digest) is not str or type(request_bytes) is not int
            or type(deadline) not in (int, float)
        ):
            raise TypeError("reserve requires exact argument types")
        try:
            with self._G:
                return self._reserve_locked(entry, routed, request_digest, request_bytes, deadline)
        finally:
            self._drain_aborts()

    def _reserve_locked(
        self, entry: ScopeEntry, routed: RoutedRequest, request_digest: str,
        request_bytes: int, deadline: float,
    ) -> DispatchHandle:
        if self._gate_state == "closed":
            raise DispatchError("gate_closed")
        if not self._advance()[0]:
            raise DispatchError("gate_held")
        if self._scope_by_lease.get(entry.lease_id) is not entry:
            raise DispatchError("scope_unknown")
        if routed.service != entry.service or not hmac.compare_digest(
            routed.scope_digest, entry.scope_digest,
        ):
            raise DispatchError("binding_mismatch")
        status = ROUTE_CATALOG.get(routed.route_id)
        if status is None or status.state not in ("enabled", "partial"):
            raise DispatchError("route_unavailable")
        if deadline > entry.expires_at:
            raise DispatchError("deadline_exceeds_lease")
        if len(self._flights) >= MAX_OPEN_DISPATCHES:
            raise DispatchError("dispatch_capacity")
        code: str | None = None
        reservation = None
        try:
            reservation = self._ledger.reserve(
                lease_id=entry.lease_id, attempt_id=entry.attempt_id, service=entry.service,
                route_id=routed.route_id, request_digest=request_digest,
                request_bytes=request_bytes, deadline=deadline,
            )
        except ReceiptError as caught:
            code = _map_reserve_error(caught.code)
        if code is not None:
            raise DispatchError(code) from None
        index = self._scope_index_by_lease.get(entry.lease_id)
        handle = DispatchHandle(
            receipt_id=reservation.receipt_id, lease_id=entry.lease_id,
            service=entry.service, route_id=routed.route_id, deadline=deadline,
        )
        self._flights[handle.receipt_id] = _Flight(
            handle=handle, reservation=reservation, lease_id=entry.lease_id,
            service=entry.service, route_id=routed.route_id, generation=entry.generation,
            scope_digest=entry.scope_digest, index=index, requires_permit=routed.requires_permit,
            deadline=deadline, exchange_deadline=deadline - RESPONSE_MARGIN_SECONDS,
        )
        return handle

    def _finalize_and_drop(
        self, flight: _Flight, *, dispatch_state: str, reason: str,
    ) -> ForwarderReceipt:
        """Finalize ``flight``'s reservation and always remove the flight.

        Raises ``deadline_expired`` if the ledger had already swept the
        entry, or ``receipt_unavailable`` for any other ledger fault.
        """
        code: str | None = None
        receipt: ForwarderReceipt | None = None
        try:
            receipt = self._ledger.finalize(
                flight.reservation, dispatch_state=dispatch_state, reason=reason,
            )
        except ReceiptError as caught:
            code = _map_transition_error(caught.code)
        del self._flights[flight.handle.receipt_id]
        if code is not None:
            raise DispatchError(code) from None
        return receipt

    def _checked_lease(self, flight: _Flight, sentinel: str) -> tuple[str | None, object]:
        """Run the L1/L2 lease check; returns (denial_code_or_None, receipt)."""
        code: str | None = None
        receipt = None
        before = self._read_clock()
        if before is None:
            return "gate_held", None
        try:
            receipt = self._registry.check(
                service=flight.service, sentinel=sentinel,
                generation=flight.generation, scope_digest=flight.scope_digest,
            )
        except LeaseError:
            code = "lease_denied"
        after = self._read_clock()
        if after is None:
            return "gate_held", receipt
        if code is None and (
            receipt.authorized is not True
            or type(receipt.lease_id) is not str
            or not hmac.compare_digest(receipt.lease_id, flight.lease_id)
        ):
            code = "lease_denied"
        if code is None and not before <= receipt.observed_at <= after:
            self._gate_state = "held"
            self._hold_code = "clock_domain_mismatch"
            code = "gate_held"
        return code, receipt

    def admit(self, handle: DispatchHandle, *, sentinel: str) -> AdmissionOutcome:
        if type(handle) is not DispatchHandle:
            raise TypeError("admit requires an exact DispatchHandle")
        if type(sentinel) is not str:
            raise TypeError("admit requires an exact str sentinel")
        try:
            with self._G:
                return self._admit_locked(handle, sentinel)
        finally:
            self._drain_aborts()

    def _admit_locked(self, handle: DispatchHandle, sentinel: str) -> AdmissionOutcome:
        flight = self._flight_for(handle.receipt_id)
        if flight is None or flight.handle is not handle:
            raise DispatchError("handle_unknown")
        if flight.phase != "reserved":
            raise DispatchError("handle_consumed")
        ok, _now, _code = self._advance()
        if not ok:
            return self._deny_admission(flight, "gate_held")
        if flight.overdue:
            del self._flights[handle.receipt_id]
            raise DispatchError("deadline_expired")
        if self._gate_state == "closed":
            return self._deny_admission(flight, "gate_closed")
        candidate = self._index_for(flight.service, sentinel)
        if candidate is None or not hmac.compare_digest(candidate, flight.index):
            return self._deny_admission(flight, "sentinel_mismatch")
        if flight.requires_permit is not False:
            return self._deny_admission(flight, "permit_unavailable")
        check_code, receipt = self._checked_lease(flight, sentinel)
        if check_code is not None:
            return self._deny_admission(flight, check_code)
        if receipt.observed_at + RESPONSE_MARGIN_SECONDS + MIN_ADMISSION_SECONDS > flight.deadline:
            return self._deny_admission(flight, "insufficient_time")
        begin_code: str | None = None
        try:
            self._ledger.begin_connect(flight.reservation)
        except ReceiptError as caught:
            begin_code = _map_transition_error(caught.code)
        if begin_code is not None:
            del self._flights[handle.receipt_id]
            raise DispatchError(begin_code) from None
        flight.phase = "admitted"
        admitted_at = receipt.observed_at
        connect_deadline = min(admitted_at + CONNECT_SECONDS, flight.exchange_deadline)
        admission = Admission(
            receipt_id=handle.receipt_id, lease_id=flight.lease_id, service=flight.service,
            route_id=flight.route_id, admitted_at=admitted_at, deadline=flight.deadline,
            exchange_deadline=flight.exchange_deadline, connect_deadline=connect_deadline,
        )
        flight.admission = admission
        return AdmissionOutcome(code="admitted", admission=admission, denial=None)

    def _deny_admission(self, flight: _Flight, code: str) -> AdmissionOutcome:
        if code == "insufficient_time":
            reason = "deadline"
        elif code == "permit_unavailable":
            reason = "permit_denied"
        else:
            reason = "lease_denied"
        receipt = self._finalize_and_drop(flight, dispatch_state="NOT_DISPATCHED", reason=reason)
        return AdmissionOutcome(code=code, admission=None, denial=receipt)

    def attach_abort(self, admission: Admission, abort: Callable[[], None]) -> bool:
        if type(admission) is not Admission:
            raise TypeError("attach_abort requires an exact Admission")
        if not callable(abort):
            raise TypeError("attach_abort requires a callable abort")
        with self._G:
            flight = self._flight_for(admission.receipt_id)
            if flight is None or flight.admission is not admission:
                raise DispatchError("admission_unknown")
            if self._gate_state != "ready" or flight.overdue:
                return False
            flight.abort = abort
            return True

    def begin_write(self, admission: Admission, *, sentinel: str) -> WriteOutcome:
        if type(admission) is not Admission:
            raise TypeError("begin_write requires an exact Admission")
        if type(sentinel) is not str:
            raise TypeError("begin_write requires an exact str sentinel")
        try:
            with self._G:
                return self._begin_write_locked(admission, sentinel)
        finally:
            self._drain_aborts()

    def _begin_write_locked(self, admission: Admission, sentinel: str) -> WriteOutcome:
        flight = self._flight_for(admission.receipt_id)
        if flight is None or flight.admission is not admission:
            raise DispatchError("admission_unknown")
        if flight.phase == "writing":
            raise DispatchError("write_claimed")
        ok, _now, _code = self._advance()
        if not ok:
            return self._deny_write(flight, "gate_held")
        if flight.overdue:
            del self._flights[admission.receipt_id]
            raise DispatchError("deadline_expired")
        if self._gate_state == "closed":
            return self._deny_write(flight, "gate_closed")
        candidate = self._index_for(flight.service, sentinel)
        if candidate is None or not hmac.compare_digest(candidate, flight.index):
            return self._deny_write(flight, "sentinel_mismatch")
        check_code, receipt = self._checked_lease(flight, sentinel)
        if check_code is not None:
            return self._deny_write(flight, check_code)
        if flight.requires_permit is not False:
            return self._deny_write(flight, "permit_unavailable")
        if receipt.observed_at + MIN_WRITE_SECONDS > flight.exchange_deadline:
            return self._deny_write(flight, "insufficient_time")
        begin_code: str | None = None
        try:
            self._ledger.begin_dispatch(flight.reservation)
        except ReceiptError as caught:
            begin_code = _map_transition_error(caught.code)
        if begin_code is not None:
            del self._flights[admission.receipt_id]
            raise DispatchError(begin_code) from None
        flight.phase = "writing"
        write_deadline = min(receipt.observed_at + WRITE_SECONDS, flight.exchange_deadline)
        return WriteOutcome(code="write_admitted", write_deadline=write_deadline, denial=None)

    def _deny_write(self, flight: _Flight, code: str) -> WriteOutcome:
        receipt = self._finalize_and_drop(flight, dispatch_state="FAILED", reason="connect_failed")
        return WriteOutcome(code=code, write_deadline=None, denial=receipt)

    def finish(
        self, admission: Admission, *, dispatch_state: str, reason: str,
        upstream_response: ParsedResponse | None = None,
    ) -> ForwarderReceipt:
        if type(admission) is not Admission:
            raise TypeError("finish requires an exact Admission")
        if type(dispatch_state) is not str or type(reason) is not str:
            raise TypeError("finish requires exact str dispatch_state and reason")
        if upstream_response is not None and type(upstream_response) is not ParsedResponse:
            raise TypeError("finish requires an exact ParsedResponse or None")
        with self._G:
            flight = self._flight_for(admission.receipt_id)
            if flight is None or flight.admission is not admission:
                raise DispatchError("admission_unknown")
            if flight.overdue:
                del self._flights[admission.receipt_id]
                raise DispatchError("deadline_expired")
            code: str | None = None
            receipt: ForwarderReceipt | None = None
            try:
                receipt = self._ledger.finalize(
                    flight.reservation, dispatch_state=dispatch_state, reason=reason,
                    upstream_response=upstream_response,
                )
            except ReceiptError as caught:
                if caught.code in (
                    "invalid_transition", "invalid_reason", "invalid_dispatch_state",
                    "invalid_upstream_response", "invalid_response",
                ):
                    code = "invalid_outcome"
                elif caught.code == "deadline_expired":
                    code = "deadline_expired"
                else:
                    code = "receipt_unavailable"
            if code == "invalid_outcome":
                raise DispatchError(code) from None
            if code is not None:
                del self._flights[admission.receipt_id]
                raise DispatchError(code) from None
            del self._flights[admission.receipt_id]
            return receipt

    def release(self, token: DispatchHandle | Admission) -> bool:
        if type(token) is DispatchHandle or type(token) is Admission:
            receipt_id = token.receipt_id
        else:
            raise TypeError("release requires an exact DispatchHandle or Admission")
        with self._G:
            flight = self._flight_for(receipt_id)
            if flight is None or (flight.handle is not token and flight.admission is not token):
                return False
            del self._flights[receipt_id]
            return True

    def is_admitted(self, admission: Admission) -> bool:
        if type(admission) is not Admission:
            raise TypeError("is_admitted requires an exact Admission")
        with self._G:
            flight = self._flight_for(admission.receipt_id)
            return (
                flight is not None and flight.admission is admission
                and flight.phase in ("admitted", "writing") and not flight.overdue
            )

    # -- closeout and shutdown ---------------------------------------------------

    def closeout(self, lease_id: str) -> Closeout:
        if type(lease_id) is not str:
            raise TypeError("closeout requires an exact str lease_id")
        try:
            with self._G:
                return self._closeout_locked(lease_id)
        finally:
            self._drain_aborts()

    def _closeout_locked(self, lease_id: str) -> Closeout:
        safe_id = _valid_lease_id_shape(lease_id)
        registry_snapshot = self._registry.snapshot()
        ledger_snapshot = self._ledger.snapshot()
        # Tick after the ledger's sweep so every flight it swept is already overdue here.
        # A held (or newly faulted) gate skips the tick but still reports what it observed.
        gate_ok, observed_at, _code = self._advance()
        if not gate_ok:
            observed_at = self._last_now if self._last_now is not None else 0.0
        registry_state = registry_snapshot["registry_state"]
        record = next(
            (item for item in registry_snapshot["leases"] if item["lease_id"] == lease_id), None,
        )
        if record is not None:
            lease_state = record["state"]
        elif lease_id in self._scope_by_lease:
            lease_state = "pruned"
        else:
            lease_state = "unknown"
        ledger_state = ledger_snapshot["ledger_state"]
        pending = 0
        in_flight = 0
        uncertain = 0
        drain_deadline: float | None = None
        for item in ledger_snapshot["entries"]:
            if item["lease_id"] != lease_id:
                continue
            state = item["entry_state"]
            if state == "reserved":
                pending += 1
            elif state in ("connecting", "dispatched"):
                in_flight += 1
                entry_deadline = item["deadline"]
                if drain_deadline is None or entry_deadline > drain_deadline:
                    drain_deadline = entry_deadline
            elif state == "finalized" and item["dispatch_state"] in _UNCERTAIN_DISPATCH_STATES:
                uncertain += 1
        overdue = sum(
            1 for flight in self._flights.values() if flight.lease_id == lease_id and flight.overdue
        )
        if (
            not gate_ok or registry_state == "held" or ledger_state == "held"
            or not safe_id or lease_state == "unknown"
        ):
            closeout_state = "unknown"
        elif lease_state in ("registered", "active"):
            closeout_state = "open"
        elif overdue > 0:
            closeout_state = "overdue"
        elif in_flight > 0:
            closeout_state = "draining"
        else:
            closeout_state = "quiescent"
        return Closeout(
            lease_id=lease_id, lease_state=lease_state, closeout_state=closeout_state,
            pending=pending, in_flight=in_flight, overdue=overdue,
            drain_deadline=drain_deadline, uncertain=uncertain, observed_at=observed_at,
        )

    def shutdown(self) -> ShutdownReport:
        with self._G:
            first_call = not self._closed
            self._closed = True
            if self._gate_state == "ready":
                self._gate_state = "closed"  # a held gate stays held
            in_flight = 0
            overdue = 0
            aborted = 0
            callbacks: list[Callable[[], None]] = []
            if first_call:
                for flight in self._flights.values():
                    touched = flight.phase in ("admitted", "writing") or flight.overdue
                    if not touched:
                        continue
                    if flight.phase in ("admitted", "writing"):
                        in_flight += 1
                    if flight.overdue:
                        overdue += 1
                    if flight.abort is not None and not flight.abort_fired:
                        callbacks.append(flight.abort)
                        flight.abort_fired = True
                        aborted += 1
        # Run this call's own aborts outside G so its failure count is its own.
        failures = 0
        for callback in callbacks:
            try:
                callback()
            except Exception:  # noqa: BLE001 - an injected abort callable must never escape.
                failures += 1
        if failures:
            with self._G:
                self._abort_failures += failures
        return ShutdownReport(
            in_flight=in_flight, overdue=overdue, aborted=aborted, abort_failures=failures,
        )

    def snapshot(self) -> dict[str, object]:
        with self._G:
            scope_entries = tuple(
                (entry.lease_id, entry.service, entry.scope_digest, entry.expires_at,
                 entry.installed_at)
                for entry in self._scope_by_lease.values()
            )
            flights = tuple(
                (
                    flight.handle.receipt_id, flight.lease_id, flight.service, flight.route_id,
                    flight.phase, flight.overdue, flight.deadline,
                    flight.abort is not None, flight.abort_fired,
                )
                for flight in self._flights.values()
            )
            return {
                "generation": self._generation,
                "gate_state": self._gate_state,
                "hold_code": self._hold_code,
                "open_dispatches": len(self._flights),
                "scope_bytes": self._scope_bytes,
                "abort_failures": self._abort_failures,
                "scope_entries": scope_entries,
                "flights": flights,
            }


__all__ = [
    "ADMISSION_CODES",
    "CLOSEOUT_STATES",
    "CONNECT_SECONDS",
    "DENIAL_REASONS",
    "DISPATCH_ERROR_CODES",
    "FLIGHT_PHASES",
    "GATE_STATES",
    "HOLD_CODES",
    "LEASE_STATES",
    "MAX_HANDLER_SECONDS",
    "MAX_OPEN_DISPATCHES",
    "MAX_SCOPE_BYTES",
    "MAX_SCOPE_ENTRIES",
    "MIN_ADMISSION_SECONDS",
    "MIN_WRITE_SECONDS",
    "READ_INACTIVITY_SECONDS",
    "RESPONSE_MARGIN_SECONDS",
    "SCOPE_ENTRY_OVERHEAD_BYTES",
    "STORE_RETENTION_SECONDS",
    "WRITE_FENCE_CODES",
    "WRITE_SECONDS",
    "Admission",
    "AdmissionOutcome",
    "Closeout",
    "DispatchError",
    "DispatchGate",
    "DispatchHandle",
    "ScopeEntry",
    "ShutdownReport",
    "WriteOutcome",
]
