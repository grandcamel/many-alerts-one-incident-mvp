"""Sanitized dispatch receipts and a bounded, identity-authenticated ledger.

This module has no transport, upstream-connection, route-selection, lease, or
dispatch-permit authority. It never opens an upstream connection or writes a
durable journal. It makes one thing enforceable: a client response is written
only when its exact canonical bytes are named by a receipt already recorded
here, and capacity failure rejects new dispatch before any bytes are sent.

A handler follows exactly this order: ``reserve`` before opening any upstream
connection, ``begin_connect`` immediately before opening it, ``begin_dispatch``
immediately before the first possible upstream request write, ``finalize``
once the outcome is known (before any client send), then
``forwarder_response_send.send_response`` writes the receipt-named bytes. The
ledger's explicit transition calls are the seam later units call.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType

from .forwarder_http_response import HTTPResponseError, ParsedResponse, serialize_response
from .forwarder_services import SERVICE_PROFILES

MAX_RECEIPTS = 2048
MAX_RECEIPT_BYTES = 8192
MAX_LEDGER_BYTES = 2 * 1024 * 1024
RETENTION_SECONDS = 310.0
MAX_HANDLER_SECONDS = 40.0
MAX_REQUEST_BYTES = 2048 + 16384 + 262144

DISPATCH_STATES = (
    "NOT_DISPATCHED", "FAILED", "DISPATCHED_UNKNOWN", "PARTIAL", "TRANSPORT_CONFIRMED",
)
DELIVERY_OUTCOMES = ("pending", "sending", "sent", "not_sent", "send_unknown")

_MAX_ID_BYTES = 128
_SAFE_ID = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)
_HEX = frozenset("0123456789abcdef")


class ReceiptError(ValueError):
    """A fixed, non-diagnostic ledger rejection; never embeds a caller value."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ReceiptError(code) from None


# --- Reason -> local client-response kind, per legal dispatch state --------

_REASON_LOCAL_RESPONSE: Mapping[str, Mapping[str, str | None]] = MappingProxyType({
    "NOT_DISPATCHED": MappingProxyType({
        "request_rejected": "invalid_request",
        "lease_denied": "denied",
        "route_denied": "denied",
        "permit_denied": "denied",
        "deadline": "deadline",
        "abandoned": "unavailable",
    }),
    "FAILED": MappingProxyType({
        "connect_failed": "upstream_failed",
        "upstream_tls_failed": "upstream_failed",
    }),
    "DISPATCHED_UNKNOWN": MappingProxyType({
        "write_failed": "upstream_unknown",
        "receive_failed": "upstream_unknown",
        "malformed_response": "upstream_unknown",
        "abandoned": "upstream_unknown",
        "deadline": "deadline",
    }),
    "PARTIAL": MappingProxyType({
        "response_incomplete": "upstream_unknown",
        "response_overflow": "upstream_unknown",
    }),
    "TRANSPORT_CONFIRMED": MappingProxyType({
        "ok": None,  # the complete upstream response itself
        "response_policy_rejected": "response_rejected",
    }),
})

# Entry state (reserved -> connecting -> dispatched) -> legal finalize states.
_LEGAL_FINALIZE_STATES: Mapping[str, frozenset[str]] = MappingProxyType({
    "reserved": frozenset({"NOT_DISPATCHED"}),
    "connecting": frozenset({"FAILED", "DISPATCHED_UNKNOWN"}),
    "dispatched": frozenset({"DISPATCHED_UNKNOWN", "PARTIAL", "TRANSPORT_CONFIRMED"}),
})

LOCAL_RESPONSES: Mapping[str, ParsedResponse] = MappingProxyType({
    "invalid_request": ParsedResponse(400, b'{"error":"forwarder_invalid_request"}'),
    "denied": ParsedResponse(403, b'{"error":"forwarder_denied"}'),
    "unavailable": ParsedResponse(503, b'{"error":"forwarder_unavailable"}'),
    "upstream_failed": ParsedResponse(502, b'{"error":"forwarder_upstream_failed"}'),
    "upstream_unknown": ParsedResponse(502, b'{"error":"forwarder_dispatch_unknown"}'),
    "deadline": ParsedResponse(504, b'{"error":"forwarder_deadline"}'),
    "response_rejected": ParsedResponse(502, b'{"error":"forwarder_response_rejected"}'),
})


def _digest_and_length(response: ParsedResponse) -> tuple[str, int]:
    wire = serialize_response(response)
    return hashlib.sha256(wire).hexdigest(), len(wire)


_LOCAL_RESPONSE_DIGESTS: Mapping[str, tuple[str, int]] = MappingProxyType({
    kind: _digest_and_length(response) for kind, response in LOCAL_RESPONSES.items()
})

# Worst-case (maximum-length) placeholders for fields unknown at reservation.
_WORST_DISPATCH_STATE = max(DISPATCH_STATES, key=len)
_WORST_REASON = max(
    (reason for table in _REASON_LOCAL_RESPONSE.values() for reason in table), key=len
)
_WORST_STATUS_CLASS = "5xx"
_WORST_DIGEST = "f" * 64
_WORST_BODY_BYTES = 99_999_999
_WORST_FLOAT = sys.float_info.max
_WORST_DELIVERY_OUTCOME = max(DELIVERY_OUTCOMES, key=len)
# entry_state/charge are also part of every snapshot()-returned per-entry
# record (see _entry_metadata), so they must be charged too, or a real
# record could exceed its own reservation-time charge. entry_state's legal
# values are the four internal lifecycle states (not DISPATCH_STATES);
# charge is bounded by MAX_RECEIPT_BYTES, whose own fixed decimal width
# bounds every real charge value's width in turn.
_WORST_ENTRY_STATE = max(("reserved", "connecting", "dispatched", "finalized"), key=len)
_WORST_CHARGE = 10 ** len(str(MAX_RECEIPT_BYTES)) - 1


def _require_id(value: object, code: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_ID_BYTES
        or any(character not in _SAFE_ID for character in value)
    ):
        _fail(code)
    return value


def _require_optional_id(value: object, code: str) -> str | None:
    if value is None:
        return None
    return _require_id(value, code)


def _require_digest(value: object, code: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        _fail(code)
    return value


def _require_service(value: object) -> str:
    if type(value) is not str or value not in SERVICE_PROFILES:
        _fail("invalid_service")
    return value


def _require_count(value: object, maximum: int, code: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(code)
    return value


def _finite(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _require_deadline(value: object, now: float) -> float:
    deadline = _finite(value)
    if deadline is None or not now < deadline <= now + MAX_HANDLER_SECONDS:
        _fail("invalid_deadline")
    return deadline


def _new_receipt_id() -> str:
    return "receipt_" + secrets.token_urlsafe(24)


def _status_class(status: int) -> str:
    if 200 <= status <= 299:
        return "2xx"
    if 400 <= status <= 499:
        return "4xx"
    return "5xx"


def _serialize_or_fail(response: object) -> bytes:
    if type(response) is not ParsedResponse:
        _fail("invalid_response")
    try:
        return serialize_response(response)
    except HTTPResponseError:
        _fail("invalid_response")


def response_digest(response: ParsedResponse) -> str:
    """Return the lowercase SHA-256 hex digest of one canonical response."""
    wire = _serialize_or_fail(response)
    return hashlib.sha256(wire).hexdigest()


def local_response(kind: object) -> ParsedResponse:
    """Return the fixed, nonsecret local client response for one known kind."""
    if type(kind) is not str or kind not in LOCAL_RESPONSES:
        _fail("unknown_local_response")
    return LOCAL_RESPONSES[kind]


@dataclass(frozen=True)
class ReceiptReservation:
    """An opaque in-flight dispatch reservation, authenticated by identity.

    The ledger recognizes only the exact instance it issued; an equal-valued
    forged or copied instance (``dataclasses.replace``, ``copy.copy``) is
    rejected as ``reservation_unknown``.
    """

    receipt_id: str


@dataclass(frozen=True)
class DeliveryClaim:
    """The one-use right to write one receipt's client bytes, authenticated by identity.

    Only the exact instance returned by ``claim_delivery`` can record that
    delivery's outcome; an equal-valued copy is rejected as ``claim_unknown``.
    """

    receipt_id: str


@dataclass(frozen=True)
class ForwarderReceipt:
    """A sanitized, nonsecret dispatch-correlation record.

    Dispatch correlation only: not external-effect confirmation, not billing
    evidence and not a durable journal record. Excludes URLs/paths/queries,
    headers, sentinels, credentials and bodies.
    """

    receipt_id: str
    generation: str
    lease_id: str
    attempt_id: str
    operation_id: str | None
    service: str
    route_id: str
    request_digest: str
    dispatch_state: str
    reason: str
    http_status_class: str | None
    response_digest: str | None
    client_response_digest: str
    request_bytes: int
    upstream_body_bytes: int | None
    client_response_bytes: int
    started_monotonic: float
    completed_monotonic: float


def local_response_for(receipt: ForwarderReceipt) -> ParsedResponse:
    """Return the fixed local client response for a non-``ok`` receipt."""
    if (
        type(receipt) is not ForwarderReceipt
        or type(receipt.dispatch_state) is not str
        or type(receipt.reason) is not str
    ):
        # The exact-type checks above also guard against a forged, unhashable
        # dispatch_state/reason (e.g. a list) reaching the dict lookups below.
        _fail("invalid_receipt")
    reason_table = _REASON_LOCAL_RESPONSE.get(receipt.dispatch_state)
    kind = reason_table.get(receipt.reason) if reason_table is not None else None
    if kind is None:
        _fail("upstream_response_required")
    return local_response(kind)


def _worst_case_charge(
    *, receipt_id: str, generation: str, lease_id: str, attempt_id: str,
    operation_id: str | None, service: str, route_id: str, request_digest: str,
    request_bytes: int, deadline: float, started_monotonic: float,
) -> int:
    """Canonical JSON size of this entry's worst-case finalized record.

    Fields already fixed at reservation (including ``deadline``, which never
    changes after reserve()) use their exact value, since they cannot grow
    later; fields unknown until finalize/delivery use maximum-length
    placeholders, so later finalization/delivery can never exceed this charge.
    This must cover exactly the field set ``_entry_metadata`` returns in
    ``snapshot()`` -- every one of those fields is retained footprint that
    counts against the charge, not only the ``ForwarderReceipt`` fields.
    """
    document = {
        "receipt_id": receipt_id,
        "generation": generation,
        "lease_id": lease_id,
        "attempt_id": attempt_id,
        "operation_id": operation_id,
        "service": service,
        "route_id": route_id,
        "request_digest": request_digest,
        "request_bytes": request_bytes,
        "deadline": deadline,
        # entry_state and charge are snapshot()-only (not ForwarderReceipt)
        # fields that _entry_metadata also returns per entry; entry_state
        # varies over the entry's life and charge is circular (it bounds
        # itself), so both use worst-case placeholders rather than exact
        # values.
        "entry_state": _WORST_ENTRY_STATE,
        "charge": _WORST_CHARGE,
        "dispatch_state": _WORST_DISPATCH_STATE,
        "reason": _WORST_REASON,
        "http_status_class": _WORST_STATUS_CLASS,
        "response_digest": _WORST_DIGEST,
        "client_response_digest": _WORST_DIGEST,
        "upstream_body_bytes": _WORST_BODY_BYTES,
        "client_response_bytes": _WORST_BODY_BYTES,
        "started_monotonic": started_monotonic,
        "completed_monotonic": _WORST_FLOAT,
        "delivery_outcome": _WORST_DELIVERY_OUTCOME,
        # complete_delivery() also stores this on the entry, and snapshot()
        # returns it per-entry: it must be charged like any other retained
        # field, or a real delivery could exceed this entry's own charge.
        "delivery_bytes_sent": _WORST_BODY_BYTES,
    }
    return len(
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )


@dataclass
class _Entry:
    reservation: ReceiptReservation
    # Ledger-private copy; retained and reported IDs never read the caller's handle.
    receipt_id: str
    generation: str
    lease_id: str
    attempt_id: str
    operation_id: str | None
    service: str
    route_id: str
    request_digest: str
    request_bytes: int
    deadline: float
    started_monotonic: float
    charge: int
    state: str = "reserved"  # reserved -> connecting -> dispatched -> finalized
    # ``receipt`` is the instance handed to the caller and is used only for
    # identity. ``record`` is an equal ledger-private copy that is never handed
    # out; retention, snapshots and delivery checks read only ``record``, so an
    # in-place mutation of the caller's frozen instance cannot alter them.
    receipt: ForwarderReceipt | None = None
    record: ForwarderReceipt | None = None
    delivery_outcome: str | None = None
    delivery_bytes_sent: int | None = None
    claim: DeliveryClaim | None = None
    # True only when the deadline sweep (not a caller's own finalize() call,
    # even with reason="abandoned") finalized this entry; _require_active
    # uses this -- not the receipt's reason string -- to decide whether a
    # later late call means "the deadline passed" or "already finalized".
    swept: bool = False


def _entry_metadata(entry: _Entry) -> dict[str, object]:
    receipt = entry.record
    return {
        "receipt_id": entry.receipt_id,
        "generation": entry.generation,
        "lease_id": entry.lease_id,
        "attempt_id": entry.attempt_id,
        "operation_id": entry.operation_id,
        "service": entry.service,
        "route_id": entry.route_id,
        "request_digest": entry.request_digest,
        "request_bytes": entry.request_bytes,
        "entry_state": entry.state,
        "charge": entry.charge,
        "deadline": entry.deadline,
        "started_monotonic": entry.started_monotonic,
        "dispatch_state": receipt.dispatch_state if receipt else None,
        "reason": receipt.reason if receipt else None,
        "http_status_class": receipt.http_status_class if receipt else None,
        "response_digest": receipt.response_digest if receipt else None,
        "client_response_digest": receipt.client_response_digest if receipt else None,
        "client_response_bytes": receipt.client_response_bytes if receipt else None,
        "upstream_body_bytes": receipt.upstream_body_bytes if receipt else None,
        "completed_monotonic": receipt.completed_monotonic if receipt else None,
        "delivery_outcome": entry.delivery_outcome,
        "delivery_bytes_sent": entry.delivery_bytes_sent,
    }


class ReceiptLedger:
    """A bounded, sanitized dispatch-receipt ledger under one process lock.

    It deliberately does not open an upstream connection, select routes,
    check leases, consume dispatch permits or write a durable journal; it
    only makes receipt ordering and capacity explicit and enforceable.
    """

    def __init__(self, *, generation: str, clock: Callable[[], float] = time.monotonic):
        if not callable(clock):
            raise TypeError("clock must be callable")
        _require_id(generation, "invalid_generation")
        self._generation = generation
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: dict[str, _Entry] = {}
        self._charged_bytes = 0
        self._last_now: float | None = None
        self._held_code: str | None = None

    @property
    def generation(self) -> str:
        """The fixed opaque generation this ledger was constructed with."""
        return self._generation

    # -- clock, abandonment sweep and retention ---------------------------

    def _now(self) -> float:
        # Checked before the clock is read at all: once the ledger is held,
        # every later call must report "ledger_held", never re-derive and
        # re-raise the original fault code from a clock that keeps failing
        # (or keeps regressing) the same way on every subsequent read.
        if self._held_code is not None:
            raise ReceiptError("ledger_held")
        try:
            observed = _finite(self._clock())
            if observed is None or observed < 0:
                raise ValueError("clock did not return a finite non-negative number")
        except Exception:  # noqa: BLE001 - any clock fault permanently holds the ledger.
            self._held_code = "clock_invalid"
            raise ReceiptError("clock_invalid") from None
        if self._last_now is not None and observed < self._last_now:
            self._held_code = "clock_regressed"
            raise ReceiptError("clock_regressed")
        self._last_now = observed
        self._sweep_abandoned(observed)
        self._prune_retention(observed)
        return observed

    def _sweep_abandoned(self, now: float) -> None:
        for entry in self._entries.values():
            if entry.state == "finalized" or now < entry.deadline:
                continue
            if entry.state == "reserved":
                dispatch_state = "NOT_DISPATCHED"
            else:  # connecting or dispatched
                dispatch_state = "DISPATCHED_UNKNOWN"
            # Stamp completion at the deadline itself (the actual point of
            # abandonment), not at whenever this lazy sweep happens to run:
            # retention is measured from completed_monotonic, so using the
            # (possibly much later) detection time would hold capacity for
            # far longer than RETENTION_SECONDS past the real deadline.
            self._do_finalize(entry, dispatch_state, "abandoned", None, entry.deadline, swept=True)

    def _prune_retention(self, now: float) -> None:
        # Retention is an unconditional, hard bound (the specification's "at
        # most 310 seconds", not "310 seconds unless a delivery is still
        # sending"): an entry whose delivery was claimed and never completed
        # (an interrupted or otherwise abandoned send) is pruned like any
        # other once its time is up, freeing its slot and charge. A caller
        # that later calls complete_delivery for a since-pruned entry gets
        # claim_unknown, which forwarder_response_send.send_response reports
        # as an unrecorded delivery, not a crash.
        for receipt_id, entry in list(self._entries.items()):
            if entry.state != "finalized" or entry.record is None:
                continue
            if now - entry.record.completed_monotonic >= RETENTION_SECONDS:
                del self._entries[receipt_id]
                self._charged_bytes -= entry.charge

    # -- identity-authenticated lookups ------------------------------------

    def _lookup_reservation(self, reservation: object) -> _Entry:
        # The receipt_id type check also guards the dict lookup below against
        # a forged, unhashable receipt_id (e.g. a list) raising a raw TypeError.
        if type(reservation) is not ReceiptReservation or type(reservation.receipt_id) is not str:
            _fail("reservation_unknown")
        entry = self._entries.get(reservation.receipt_id)
        if entry is None or entry.reservation is not reservation:
            _fail("reservation_unknown")
        return entry

    def _lookup_receipt(self, receipt: object) -> _Entry:
        if type(receipt) is not ForwarderReceipt or type(receipt.receipt_id) is not str:
            _fail("receipt_unknown")
        entry = self._entries.get(receipt.receipt_id)
        if entry is None or entry.receipt is not receipt:
            _fail("receipt_unknown")
        return entry

    def _require_active(self, entry: _Entry) -> None:
        if entry.state != "finalized":
            return
        # Distinguished by which code path finalized the entry, not by its
        # reason string: "abandoned" is also a legal reason for a caller's
        # own finalize() call (see the reason table), and that entry is
        # simply already finalized, not deadline_expired, if the deadline
        # genuinely has not passed.
        if entry.swept:
            _fail("deadline_expired")
        _fail("reservation_finalized")

    # -- the dispatch seam --------------------------------------------------

    def reserve(
        self, *, lease_id: str, attempt_id: str, service: str, route_id: str,
        request_digest: str, request_bytes: int, deadline: float,
        operation_id: str | None = None,
    ) -> ReceiptReservation:
        """Reserve one receipt slot before any upstream connection opens."""
        with self._lock:
            now = self._now()
            _require_id(lease_id, "invalid_lease_id")
            _require_id(attempt_id, "invalid_attempt_id")
            _require_service(service)
            _require_id(route_id, "invalid_route_id")
            _require_digest(request_digest, "invalid_request_digest")
            checked_bytes = _require_count(
                request_bytes, MAX_REQUEST_BYTES, "invalid_request_bytes"
            )
            checked_deadline = _require_deadline(deadline, now)
            checked_operation_id = _require_optional_id(operation_id, "invalid_operation_id")
            if len(self._entries) >= MAX_RECEIPTS:
                _fail("capacity_records")
            receipt_id = _new_receipt_id()
            charge = _worst_case_charge(
                receipt_id=receipt_id, generation=self._generation, lease_id=lease_id,
                attempt_id=attempt_id, operation_id=checked_operation_id, service=service,
                route_id=route_id, request_digest=request_digest,
                request_bytes=checked_bytes, deadline=checked_deadline, started_monotonic=now,
            )
            if charge > MAX_RECEIPT_BYTES:
                _fail("receipt_too_large")
            if self._charged_bytes + charge > MAX_LEDGER_BYTES:
                _fail("capacity_bytes")
            reservation = ReceiptReservation(receipt_id=receipt_id)
            entry = _Entry(
                reservation=reservation, receipt_id=receipt_id, generation=self._generation,
                lease_id=lease_id, attempt_id=attempt_id, operation_id=checked_operation_id,
                service=service, route_id=route_id, request_digest=request_digest,
                request_bytes=checked_bytes, deadline=checked_deadline, started_monotonic=now,
                charge=charge,
            )
            self._entries[receipt_id] = entry
            self._charged_bytes += charge
            return reservation

    def begin_connect(self, reservation: ReceiptReservation) -> None:
        """Mark the point where a future dispatch permit would be consumed."""
        with self._lock:
            self._now()
            entry = self._lookup_reservation(reservation)
            self._require_active(entry)
            if entry.state != "reserved":
                _fail("invalid_transition")
            entry.state = "connecting"

    def begin_dispatch(self, reservation: ReceiptReservation) -> None:
        """Mark the point immediately before the first upstream write."""
        with self._lock:
            self._now()
            entry = self._lookup_reservation(reservation)
            self._require_active(entry)
            if entry.state != "connecting":
                _fail("invalid_transition")
            entry.state = "dispatched"

    def finalize(
        self, reservation: ReceiptReservation, *, dispatch_state: str, reason: str,
        upstream_response: ParsedResponse | None = None,
    ) -> ForwarderReceipt:
        """Close out one reservation once its outcome is known."""
        with self._lock:
            now = self._now()
            entry = self._lookup_reservation(reservation)
            self._require_active(entry)
            if type(dispatch_state) is not str or dispatch_state not in DISPATCH_STATES:
                _fail("invalid_dispatch_state")
            allowed = _LEGAL_FINALIZE_STATES.get(entry.state, frozenset())
            if dispatch_state not in allowed:
                _fail("invalid_transition")
            reason_table = _REASON_LOCAL_RESPONSE[dispatch_state]
            if type(reason) is not str or reason not in reason_table:
                _fail("invalid_reason")
            if dispatch_state == "TRANSPORT_CONFIRMED":
                if type(upstream_response) is not ParsedResponse:
                    _fail("invalid_upstream_response")
            elif upstream_response is not None:
                _fail("invalid_upstream_response")
            return self._do_finalize(entry, dispatch_state, reason, upstream_response, now)

    def _do_finalize(
        self, entry: _Entry, dispatch_state: str, reason: str,
        upstream_response: ParsedResponse | None, now: float, *, swept: bool = False,
    ) -> ForwarderReceipt:
        status_class: str | None = None
        upstream_digest: str | None = None
        body_bytes: int | None = None
        if dispatch_state == "TRANSPORT_CONFIRMED":
            wire = _serialize_or_fail(upstream_response)
            upstream_digest = hashlib.sha256(wire).hexdigest()
            body_bytes = len(upstream_response.body)  # type: ignore[union-attr]
            status_class = _status_class(upstream_response.status)  # type: ignore[union-attr]
            if reason == "ok":
                client_digest, client_bytes = upstream_digest, len(wire)
            else:  # response_policy_rejected: transport succeeded, policy refuses forwarding
                kind = _REASON_LOCAL_RESPONSE[dispatch_state][reason]
                client_digest, client_bytes = _LOCAL_RESPONSE_DIGESTS[kind]  # type: ignore[index]
        else:
            kind = _REASON_LOCAL_RESPONSE[dispatch_state][reason]
            client_digest, client_bytes = _LOCAL_RESPONSE_DIGESTS[kind]  # type: ignore[index]
        record = ForwarderReceipt(
            receipt_id=entry.receipt_id,
            generation=entry.generation,
            lease_id=entry.lease_id,
            attempt_id=entry.attempt_id,
            operation_id=entry.operation_id,
            service=entry.service,
            route_id=entry.route_id,
            request_digest=entry.request_digest,
            dispatch_state=dispatch_state,
            reason=reason,
            http_status_class=status_class,
            response_digest=upstream_digest,
            client_response_digest=client_digest,
            request_bytes=entry.request_bytes,
            upstream_body_bytes=body_bytes,
            client_response_bytes=client_bytes,
            started_monotonic=entry.started_monotonic,
            completed_monotonic=now,
        )
        receipt = replace(record)
        entry.record = record
        entry.receipt = receipt
        entry.state = "finalized"
        entry.delivery_outcome = "pending"
        entry.swept = swept
        return receipt

    # -- delivery tracking ----------------------------------------------------

    def claim_delivery(
        self, receipt: ForwarderReceipt, *, client_response_digest: str,
    ) -> DeliveryClaim:
        """Claim the one-use right to write this receipt's exact client bytes.

        ``client_response_digest`` is the SHA-256 hex digest of the canonical
        bytes the caller is about to write. It is compared in constant time
        with the ledger's private record, never with fields of the caller's
        receipt instance, so the check and the claim form one locked step. A
        mismatch (``receipt_mismatch``) or an already claimed delivery
        (``delivery_claimed``) leaves the entry unchanged.
        """
        with self._lock:
            self._now()
            entry = self._lookup_receipt(receipt)
            record = entry.record
            if (
                type(client_response_digest) is not str
                or len(client_response_digest) != 64
                or any(character not in _HEX for character in client_response_digest)
                or record is None
                or not hmac.compare_digest(client_response_digest, record.client_response_digest)
            ):
                _fail("receipt_mismatch")
            if entry.delivery_outcome != "pending":
                _fail("delivery_claimed")
            claim = DeliveryClaim(receipt_id=record.receipt_id)
            entry.claim = claim
            entry.delivery_outcome = "sending"
            return claim

    def complete_delivery(self, claim: DeliveryClaim, *, outcome: str, bytes_sent: int) -> None:
        """Record the outcome of the delivery ``claim`` authorized.

        Only the exact claim instance issued by ``claim_delivery`` is accepted.
        """
        with self._lock:
            self._now()
            if type(claim) is not DeliveryClaim or type(claim.receipt_id) is not str:
                _fail("claim_unknown")
            entry = self._entries.get(claim.receipt_id)
            if entry is None or entry.claim is not claim or entry.record is None:
                _fail("claim_unknown")
            if entry.delivery_outcome != "sending":
                _fail("delivery_completed")
            if type(outcome) is not str or outcome not in {"sent", "not_sent", "send_unknown"}:
                _fail("invalid_delivery_outcome")
            maximum = entry.record.client_response_bytes
            if type(bytes_sent) is not int or not 0 <= bytes_sent <= maximum:
                _fail("invalid_bytes_sent")
            if outcome == "sent" and bytes_sent != maximum:
                _fail("invalid_bytes_sent")
            if outcome == "not_sent" and bytes_sent != 0:
                _fail("invalid_bytes_sent")
            entry.delivery_outcome = outcome
            entry.delivery_bytes_sent = bytes_sent

    def contains(self, receipt: ForwarderReceipt) -> bool:
        """Return whether ``receipt`` is the exact instance this ledger holds.

        Freshens the ledger first (the same sweep/retention pass every other
        public operation runs), tolerating a held or faulted clock the way
        ``snapshot`` does, so this never reports a stale ``True`` for a
        receipt that has already been abandoned/retention-pruned, and never
        answers from an untrustworthy held ledger.
        """
        with self._lock:
            if type(receipt) is not ForwarderReceipt or type(receipt.receipt_id) is not str:
                return False
            try:
                now = self._now()
            except ReceiptError:
                now = self._last_now if self._last_now is not None else 0.0
            self._sweep_abandoned(now)
            self._prune_retention(now)
            if self._held_code is not None:
                return False
            entry = self._entries.get(receipt.receipt_id)
            return entry is not None and entry.receipt is receipt

    def snapshot(self) -> dict[str, object]:
        """Return a fresh, nonsecret projection; readable even while held."""
        with self._lock:
            try:
                now = self._now()
            except ReceiptError:
                now = self._last_now if self._last_now is not None else 0.0
            self._sweep_abandoned(now)
            self._prune_retention(now)
            counts = {"reserved": 0, "connecting": 0, "dispatched": 0, "finalized": 0}
            for entry in self._entries.values():
                counts[entry.state] += 1
            return {
                "generation": self._generation,
                "ledger_state": "held" if self._held_code else "ready",
                "counts_by_state": counts,
                "charged_bytes": self._charged_bytes,
                "entries": tuple(_entry_metadata(entry) for entry in self._entries.values()),
            }


__all__ = [
    "DELIVERY_OUTCOMES",
    "DISPATCH_STATES",
    "LOCAL_RESPONSES",
    "MAX_HANDLER_SECONDS",
    "MAX_LEDGER_BYTES",
    "MAX_RECEIPTS",
    "MAX_RECEIPT_BYTES",
    "MAX_REQUEST_BYTES",
    "RETENTION_SECONDS",
    "DeliveryClaim",
    "ForwarderReceipt",
    "ReceiptError",
    "ReceiptLedger",
    "ReceiptReservation",
    "local_response",
    "local_response_for",
    "response_digest",
]
