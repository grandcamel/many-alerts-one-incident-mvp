"""Adversarial tests for the sanitized dispatch-receipt ledger (Tester C1).

These tests are derived from the unit implementation plan (in the unpublished working notes)
and the ticket-36 forwarder specification's "Common HTTP boundary" and
"Readiness, effects, and retention" sections -- not from
``forwarder_receipts.py``'s own implementation. They try to break the ledger:
forge reservations/receipts, walk the complete dispatch-state x entry-state x
reason matrix (legal and illegal), probe capacity ordering before dispatch,
hammer the abandonment/retention boundaries exactly, break the clock
contract, confirm no caller value or response byte ever leaks into an error
or a snapshot, and race concurrent finalize calls against each other and
against the abandonment sweep.

Everything here uses an injected fake clock; nothing opens a socket.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import math
import pickle
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, serialize_response
from grafana_jsm_sandbox.forwarder_receipts import (
    DISPATCH_STATES,
    MAX_HANDLER_SECONDS,
    MAX_REQUEST_BYTES,
    RETENTION_SECONDS,
    DeliveryClaim,
    ForwarderReceipt,
    ReceiptError,
    ReceiptLedger,
    ReceiptReservation,
    local_response_for,
)

DIGEST = hashlib.sha256(b"adversarial-fixed-request").hexdigest()
GENERATION = "adversarial-generation"

_POISON = "POISON-MARKER-should-never-leak-9182"


class FakeClock:
    """A deterministic, manually-advanced monotonic clock stand-in."""

    def __init__(self, value: float = 10_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def new_ledger(*, generation: str = GENERATION, clock: object | None = None):
    clock = clock if clock is not None else FakeClock()
    return ReceiptLedger(generation=generation, clock=clock), clock


def reserve(
    ledger: ReceiptLedger, clock: FakeClock, *, lease_id: str = "lease-1",
    attempt_id: str = "attempt-1", service: str = "jira", route_id: str = "jira.issue.get",
    request_digest: str = DIGEST, request_bytes: int = 100, ttl: float = 30.0,
    operation_id: str | None = None,
) -> ReceiptReservation:
    return ledger.reserve(
        lease_id=lease_id, attempt_id=attempt_id, service=service, route_id=route_id,
        request_digest=request_digest, request_bytes=request_bytes,
        deadline=clock.value + ttl, operation_id=operation_id,
    )


def advance_to(ledger: ReceiptLedger, reservation: ReceiptReservation, state: str) -> None:
    if state in ("connecting", "dispatched"):
        ledger.begin_connect(reservation)
    if state == "dispatched":
        ledger.begin_dispatch(reservation)


def upstream(status: int = 200, body: bytes = b'{"ok":true}') -> ParsedResponse:
    return ParsedResponse(status, body)


def error_code(call) -> str:
    with pytest.raises(ReceiptError) as caught:
        call()
    return caught.value.code


# --- forged/copied reservations and receipts --------------------------------


def test_reservation_synthesized_from_a_leaked_receipt_id_is_rejected():
    # snapshot()/receipt fields expose receipt_id -- it is not secret -- so an
    # attacker who only observes it and builds their own ReceiptReservation
    # must still be rejected: authentication is by object identity, not value.
    ledger, clock = new_ledger()
    genuine = reserve(ledger, clock)
    forged = ReceiptReservation(receipt_id=genuine.receipt_id)
    assert forged == genuine and forged is not genuine
    assert error_code(lambda: ledger.begin_connect(forged)) == "reservation_unknown"
    assert error_code(lambda: ledger.finalize(
        forged, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )) == "reservation_unknown"
    ledger.begin_connect(genuine)  # the real instance still works


def test_reservation_confusable_with_a_different_real_entry_is_rejected():
    # The forged id here is not a stranger's id -- it genuinely exists in the
    # ledger, just bound to a different ReceiptReservation instance.
    ledger, clock = new_ledger()
    reservation_a = reserve(ledger, clock, lease_id="a", attempt_id="a")
    reservation_b = reserve(ledger, clock, lease_id="b", attempt_id="b")
    confusable = ReceiptReservation(receipt_id=reservation_b.receipt_id)
    assert confusable == reservation_b and confusable is not reservation_b
    assert error_code(lambda: ledger.begin_connect(confusable)) == "reservation_unknown"
    ledger.begin_connect(reservation_b)
    ledger.begin_connect(reservation_a)


def test_receipt_synthesized_from_a_finalized_receipts_own_fields_is_rejected():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    forged = ForwarderReceipt(**dataclasses.asdict(receipt))
    assert forged == receipt and forged is not receipt
    assert ledger.contains(receipt) is True
    assert ledger.contains(forged) is False
    # Identity fails at lookup before the digest is ever compared, so even the
    # genuine digest does not help a forged receipt.
    assert error_code(lambda: ledger.claim_delivery(
        forged, client_response_digest=receipt.client_response_digest,
    )) == "receipt_unknown"
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )  # the real instance still works
    # A copied/forged DeliveryClaim (equal value, different instance) must be
    # rejected the same way a forged ForwarderReceipt or ReceiptReservation is.
    forged_claim = DeliveryClaim(receipt_id=claim.receipt_id)
    assert forged_claim == claim and forged_claim is not claim
    assert error_code(lambda: ledger.complete_delivery(
        forged_claim, outcome="sent", bytes_sent=0,
    )) == "claim_unknown"
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=receipt.client_response_bytes)


def test_pickled_reservation_and_receipt_round_trips_are_rejected_as_forgeries():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    pickled_reservation = pickle.loads(pickle.dumps(reservation))
    assert pickled_reservation == reservation and pickled_reservation is not reservation
    assert error_code(lambda: ledger.begin_connect(pickled_reservation)) == "reservation_unknown"

    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    pickled_receipt = pickle.loads(pickle.dumps(receipt))
    assert pickled_receipt == receipt and pickled_receipt is not receipt
    assert ledger.contains(pickled_receipt) is False
    assert error_code(lambda: ledger.claim_delivery(
        pickled_receipt, client_response_digest=receipt.client_response_digest,
    )) == "receipt_unknown"

    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    pickled_claim = pickle.loads(pickle.dumps(claim))
    assert pickled_claim == claim and pickled_claim is not claim
    assert error_code(lambda: ledger.complete_delivery(
        pickled_claim, outcome="sent", bytes_sent=receipt.client_response_bytes,
    )) == "claim_unknown"
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=receipt.client_response_bytes)


def test_in_place_mutation_of_the_callers_receipt_cannot_redirect_what_a_claim_authorizes():
    # F3-6 (root-revised): claim_delivery no longer trusts ANY field on the
    # caller's receipt instance -- it compares the caller-supplied wire
    # digest against the ledger's own PRIVATE record under the lock. So
    # object.__setattr__ (which bypasses a frozen dataclass's own generated
    # __setattr__) mutating the EXACT SAME, ledger-recorded ForwarderReceipt
    # instance in place must not be able to redirect which bytes a claim
    # authorizes: a claim attempted with the mutated (attacker-controlled)
    # digest is rejected, and the ORIGINAL, genuine digest -- which the
    # mutation cannot touch on the ledger's private copy -- still succeeds.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")
    rejected_upstream = upstream(200, b'{"secret":"do-not-forward"}')
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=rejected_upstream,
    )
    genuine_digest = receipt.client_response_digest
    genuine_bytes = receipt.client_response_bytes
    # Smuggle the rejected upstream's own digest/length past what the ledger
    # actually approved for delivery -- the exact technique this defense
    # exists for.
    smuggled_digest = hashlib.sha256(serialize_response(rejected_upstream)).hexdigest()
    assert smuggled_digest != genuine_digest
    object.__setattr__(receipt, "client_response_digest", smuggled_digest)
    object.__setattr__(receipt, "client_response_bytes", len(serialize_response(rejected_upstream)))

    assert ledger.contains(receipt) is True  # identity still matches -- only the fields changed
    # A claim attempted with the mutated, attacker-controlled digest is refused...
    assert error_code(lambda: ledger.claim_delivery(
        receipt, client_response_digest=smuggled_digest,
    )) == "receipt_mismatch"
    # ...the rejection leaves the entry unchanged, so the original, genuine
    # digest still claims delivery of the one true response.
    claim = ledger.claim_delivery(receipt, client_response_digest=genuine_digest)
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=genuine_bytes)


def test_complete_delivery_byte_bound_uses_the_ledgers_own_copy_not_a_mutated_receipt():
    # Even after a genuine claim succeeds, mutating client_response_bytes
    # afterward (again via object.__setattr__) must not let complete_delivery
    # accept an out-of-bound bytes_sent that the ledger's own recorded value
    # would reject -- the bound is enforced against the claim's entry, never
    # against the (mutable, caller-owned) receipt instance.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    genuine_bytes = receipt.client_response_bytes
    object.__setattr__(receipt, "client_response_bytes", genuine_bytes + 1000)

    assert error_code(lambda: ledger.complete_delivery(
        claim, outcome="sent", bytes_sent=genuine_bytes + 1000,
    )) == "invalid_bytes_sent"
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=genuine_bytes)


def test_in_place_mutation_of_the_receipt_cannot_change_retention_timing_or_snapshot_contents():
    # Same F3-6 defense, from the retention/snapshot side: retention and
    # snapshot() both read only entry.record (the ledger's private copy), so
    # mutating the caller's receipt -- including completed_monotonic itself,
    # which retention is measured from -- must be invisible to both.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    genuine_completed = receipt.completed_monotonic
    genuine_digest = receipt.client_response_digest
    genuine_bytes = receipt.client_response_bytes
    # Try to push retention far into the future and smuggle different bytes,
    # all via mutation of the one instance the caller holds.
    object.__setattr__(receipt, "completed_monotonic", clock.value + 100_000.0)
    object.__setattr__(receipt, "client_response_digest", "0" * 64)
    object.__setattr__(receipt, "client_response_bytes", 999_999)

    entry_meta = next(
        entry for entry in ledger.snapshot()["entries"] if entry["receipt_id"] == receipt.receipt_id
    )
    assert entry_meta["completed_monotonic"] == genuine_completed
    assert entry_meta["client_response_digest"] == genuine_digest
    assert entry_meta["client_response_bytes"] == genuine_bytes

    # Retention is still measured from the ledger's own, unmutated
    # completed_monotonic -- not the caller's forged far-future value.
    clock.advance(RETENTION_SECONDS - 1e-6)
    assert len(ledger.snapshot()["entries"]) == 1

    clock.advance(1e-6)
    snapshot = ledger.snapshot()
    assert snapshot["entries"] == ()
    assert snapshot["charged_bytes"] == 0


def test_in_place_mutation_of_the_reservation_cannot_forge_the_snapshot_receipt_id():
    # F2-4: the private record is documented as authoritative for
    # snapshots, but ``_entry_metadata`` built ``receipt_id`` from
    # ``entry.reservation.receipt_id`` -- the exact ``ReceiptReservation``
    # instance the caller still holds -- rather than from a ledger-private
    # copy. ``object.__setattr__`` (the same bypass already exercised above
    # against ``ForwarderReceipt``) on that reservation, after finalize, can
    # smuggle an arbitrarily long ``receipt_id`` into ``snapshot()`` output,
    # blowing past the per-record byte charge the entry was admitted under.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    genuine_id = reservation.receipt_id
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    charge = ledger.snapshot()["entries"][0]["charge"]

    object.__setattr__(reservation, "receipt_id", "X" * 20_000)

    entry = ledger.snapshot()["entries"][0]
    assert entry["receipt_id"] == genuine_id
    assert entry["charge"] == charge
    serialized_size = len(
        json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    assert serialized_size <= charge
    # Identity lookups and delivery are keyed on the dict key/object identity,
    # not the mutated field, so a genuine claim still works after the mutation.
    assert ledger.contains(receipt) is True
    claim = ledger.claim_delivery(receipt, client_response_digest=receipt.client_response_digest)
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=receipt.client_response_bytes)


def test_receipt_from_a_sibling_ledger_of_the_same_generation_is_unknown_here():
    # Same generation string on two independent ledgers must not confuse
    # cross-ledger identity checks.
    ledger_a, clock_a = new_ledger(generation="shared-gen")
    ledger_b, _clock_b = new_ledger(generation="shared-gen")
    reservation_a = reserve(ledger_a, clock_a)
    receipt_a = ledger_a.finalize(
        reservation_a, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    assert ledger_b.contains(receipt_a) is False
    assert error_code(lambda: ledger_b.claim_delivery(
        receipt_a, client_response_digest=receipt_a.client_response_digest,
    )) == "receipt_unknown"


# --- the complete dispatch-state x entry-state x reason matrix --------------

_ENTRY_STATES = ("reserved", "connecting", "dispatched")

_ALL_REASONS = (
    "request_rejected", "lease_denied", "route_denied", "permit_denied", "deadline",
    "abandoned", "connect_failed", "upstream_tls_failed", "write_failed", "receive_failed",
    "malformed_response", "response_incomplete", "response_overflow", "ok",
    "response_policy_rejected",
)

# Hard-coded straight from the plan's "Legal finalizations" table -- not read
# back out of the implementation's own private tables.
_LEGAL_TRANSITIONS = {
    "reserved": {"NOT_DISPATCHED"},
    "connecting": {"FAILED", "DISPATCHED_UNKNOWN"},
    "dispatched": {"DISPATCHED_UNKNOWN", "PARTIAL", "TRANSPORT_CONFIRMED"},
}

# Hard-coded straight from the plan's "Closed reason codes" table.
_LEGAL_REASONS = {
    "NOT_DISPATCHED": {
        "request_rejected", "lease_denied", "route_denied", "permit_denied",
        "deadline", "abandoned",
    },
    "FAILED": {"connect_failed", "upstream_tls_failed"},
    "DISPATCHED_UNKNOWN": {
        "write_failed", "receive_failed", "malformed_response", "abandoned", "deadline",
    },
    "PARTIAL": {"response_incomplete", "response_overflow"},
    "TRANSPORT_CONFIRMED": {"ok", "response_policy_rejected"},
}


@pytest.mark.parametrize(
    "from_state,dispatch_state,reason",
    list(itertools.product(_ENTRY_STATES, DISPATCH_STATES, _ALL_REASONS)),
)
def test_full_transition_by_reason_matrix(from_state, dispatch_state, reason):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=MAX_HANDLER_SECONDS)
    advance_to(ledger, reservation, from_state)

    if dispatch_state not in _LEGAL_TRANSITIONS[from_state]:
        assert error_code(lambda: ledger.finalize(
            reservation, dispatch_state=dispatch_state, reason=reason,
        )) == "invalid_transition"
        return

    if reason not in _LEGAL_REASONS[dispatch_state]:
        assert error_code(lambda: ledger.finalize(
            reservation, dispatch_state=dispatch_state, reason=reason,
        )) == "invalid_reason"
        return

    if dispatch_state == "TRANSPORT_CONFIRMED":
        receipt = ledger.finalize(
            reservation, dispatch_state=dispatch_state, reason=reason,
            upstream_response=upstream(),
        )
    else:
        receipt = ledger.finalize(reservation, dispatch_state=dispatch_state, reason=reason)
    assert receipt.dispatch_state == dispatch_state
    assert receipt.reason == reason


def test_transport_confirmed_requires_upstream_response_even_with_a_legal_reason():
    # TRANSPORT_CONFIRMED/ok and TRANSPORT_CONFIRMED/response_policy_rejected
    # are both legal reasons for a legal transition, but neither is complete
    # without an exact ParsedResponse.
    for reason in ("ok", "response_policy_rejected"):
        ledger, clock = new_ledger()
        reservation = reserve(ledger, clock)
        advance_to(ledger, reservation, "dispatched")
        assert error_code(lambda ledger=ledger, reservation=reservation, reason=reason: ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason=reason,
        )) == "invalid_upstream_response"


# --- reason -> local-response kind matches the plan's own table exactly ----
#
# test_forwarder_receipts.py's own coverage of this mapping reads the
# expected kind out of the implementation's private _REASON_LOCAL_RESPONSE
# table, so it stays internally consistent even if that table itself were
# wrong (e.g. a copy/paste error mapping route_denied -> invalid_request
# instead of denied). These cases are hard-coded straight from the plan's
# "Closed reason codes" table instead, and additionally pin the resulting
# HTTP status code, so a wrong client-facing status ships with a failing test.

_PLAN_REASON_TO_KIND_AND_ENTRY_STATE = {
    ("NOT_DISPATCHED", "request_rejected"): ("invalid_request", "reserved"),
    ("NOT_DISPATCHED", "lease_denied"): ("denied", "reserved"),
    ("NOT_DISPATCHED", "route_denied"): ("denied", "reserved"),
    ("NOT_DISPATCHED", "permit_denied"): ("denied", "reserved"),
    ("NOT_DISPATCHED", "deadline"): ("deadline", "reserved"),
    ("NOT_DISPATCHED", "abandoned"): ("unavailable", "reserved"),
    ("FAILED", "connect_failed"): ("upstream_failed", "connecting"),
    ("FAILED", "upstream_tls_failed"): ("upstream_failed", "connecting"),
    ("DISPATCHED_UNKNOWN", "write_failed"): ("upstream_unknown", "connecting"),
    ("DISPATCHED_UNKNOWN", "receive_failed"): ("upstream_unknown", "connecting"),
    ("DISPATCHED_UNKNOWN", "malformed_response"): ("upstream_unknown", "connecting"),
    ("DISPATCHED_UNKNOWN", "abandoned"): ("upstream_unknown", "connecting"),
    ("DISPATCHED_UNKNOWN", "deadline"): ("deadline", "connecting"),
    ("PARTIAL", "response_incomplete"): ("upstream_unknown", "dispatched"),
    ("PARTIAL", "response_overflow"): ("upstream_unknown", "dispatched"),
    ("TRANSPORT_CONFIRMED", "response_policy_rejected"): ("response_rejected", "dispatched"),
}

_PLAN_KIND_STATUS = {
    "invalid_request": 400,
    "denied": 403,
    "unavailable": 503,
    "upstream_failed": 502,
    "upstream_unknown": 502,
    "deadline": 504,
    "response_rejected": 502,
}


@pytest.mark.parametrize(
    "dispatch_state,reason,kind,from_state",
    [
        (state, reason, kind, from_state)
        for (state, reason), (kind, from_state) in _PLAN_REASON_TO_KIND_AND_ENTRY_STATE.items()
    ],
)
def test_reason_to_local_response_kind_matches_the_plan_exactly(
    dispatch_state, reason, kind, from_state,
):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, from_state)
    if dispatch_state == "TRANSPORT_CONFIRMED":
        receipt = ledger.finalize(
            reservation, dispatch_state=dispatch_state, reason=reason,
            upstream_response=upstream(200, b'{"never":"forwarded-to-the-client"}'),
        )
    else:
        receipt = ledger.finalize(reservation, dispatch_state=dispatch_state, reason=reason)
    expected_response = LOCAL_RESPONSES[kind]
    assert local_response_for(receipt) is expected_response
    assert receipt.client_response_digest == hashlib.sha256(
        serialize_response(expected_response)
    ).hexdigest()
    assert expected_response.status == _PLAN_KIND_STATUS[kind]


# --- TRANSPORT_CONFIRMED digest invariants ----------------------------------


def test_transport_confirmed_ok_client_digest_equals_response_digest():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")
    response = upstream(201, b'{"x":1}')
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok", upstream_response=response,
    )
    expected = hashlib.sha256(serialize_response(response)).hexdigest()
    assert receipt.client_response_digest == receipt.response_digest == expected


def test_transport_confirmed_rejected_client_digest_is_the_fixed_local_digest_only():
    # The client digest for response_policy_rejected must be the ONE fixed
    # local response's digest regardless of what the (never-forwarded)
    # upstream body actually was -- an attacker cannot smuggle upstream
    # content through client_response_digest by varying the rejected body.
    ledger, clock = new_ledger()
    bodies = (b'{"secret":"one"}', b'{"totally":"different-shape-and-length-body"}')
    digests = set()
    for index, body in enumerate(bodies):
        reservation = reserve(ledger, clock, lease_id=f"l{index}", attempt_id=f"a{index}")
        advance_to(ledger, reservation, "dispatched")
        receipt = ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
            upstream_response=upstream(200, body),
        )
        assert receipt.client_response_digest != receipt.response_digest
        local = local_response_for(receipt)
        assert receipt.client_response_digest == hashlib.sha256(serialize_response(local)).hexdigest()
        digests.add(receipt.client_response_digest)
    assert len(digests) == 1  # identical fixed digest no matter the rejected body


# --- non-TRANSPORT states carry no upstream metadata ------------------------


@pytest.mark.parametrize("from_state,dispatch_state,reason", [
    ("reserved", "NOT_DISPATCHED", "request_rejected"),
    ("reserved", "NOT_DISPATCHED", "deadline"),
    ("connecting", "FAILED", "connect_failed"),
    ("connecting", "DISPATCHED_UNKNOWN", "write_failed"),
    ("dispatched", "DISPATCHED_UNKNOWN", "write_failed"),
    ("dispatched", "PARTIAL", "response_incomplete"),
    ("dispatched", "PARTIAL", "response_overflow"),
])
def test_non_transport_states_carry_no_upstream_metadata(from_state, dispatch_state, reason):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, from_state)
    receipt = ledger.finalize(reservation, dispatch_state=dispatch_state, reason=reason)
    assert receipt.http_status_class is None
    assert receipt.response_digest is None
    assert receipt.upstream_body_bytes is None


# --- capacity is checked at reserve, before any upstream connection --------


def test_capacity_records_denies_before_any_reservation_object_exists(monkeypatch):
    import grafana_jsm_sandbox.forwarder_receipts as fr

    monkeypatch.setattr(fr, "MAX_RECEIPTS", 3)
    ledger, clock = new_ledger()
    for index in range(3):
        reserve(ledger, clock, lease_id=f"l{index}", attempt_id=f"a{index}")
    before = ledger.snapshot()
    assert error_code(
        lambda: reserve(ledger, clock, lease_id="overflow", attempt_id="overflow")
    ) == "capacity_records"
    after = ledger.snapshot()
    # reserve() raised instead of returning: the caller never held a
    # reservation object, so begin_connect could never be reached for it,
    # and nothing partial was recorded either.
    assert after == before


def test_capacity_bytes_denies_before_any_reservation_object_exists(monkeypatch):
    import grafana_jsm_sandbox.forwarder_receipts as fr

    monkeypatch.setattr(fr, "MAX_LEDGER_BYTES", 1)  # any single entry already exceeds this
    ledger, clock = new_ledger()
    before = ledger.snapshot()
    assert error_code(lambda: reserve(ledger, clock)) == "capacity_bytes"
    after = ledger.snapshot()
    assert after == before


def test_full_ledger_never_admits_one_more_reservation_under_load(monkeypatch):
    import grafana_jsm_sandbox.forwarder_receipts as fr

    monkeypatch.setattr(fr, "MAX_RECEIPTS", 8)
    ledger, clock = new_ledger()
    for index in range(8):
        reserve(ledger, clock, lease_id=f"l{index}", attempt_id=f"a{index}")
    barrier = Barrier(10)

    def attempt(index: int) -> str:
        barrier.wait()
        try:
            reserve(ledger, clock, lease_id=f"extra-{index}", attempt_id=f"extra-{index}")
            return "admitted"
        except ReceiptError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(attempt, range(10)))
    assert results == ["capacity_records"] * 10
    assert len(ledger.snapshot()["entries"]) == 8


# --- worst-case byte charge is never exceeded -------------------------------


def _canonical_size(document: dict) -> int:
    return len(json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
               .encode("utf-8"))


def test_worst_case_charge_bounds_a_transport_confirmed_delivery_with_max_length_ids():
    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "m" * 128
    body = b"1" * 4096  # comfortably large, still far under the 1 MiB response cap
    reservation = ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="anthropic", route_id=long_id,
        operation_id=long_id, request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + MAX_HANDLER_SECONDS,
    )
    charge = ledger.snapshot()["entries"][0]["charge"]
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
        upstream_response=ParsedResponse(200, body),
    )
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=receipt.client_response_bytes)

    actual = {
        "receipt_id": receipt.receipt_id, "generation": receipt.generation,
        "lease_id": receipt.lease_id, "attempt_id": receipt.attempt_id,
        "operation_id": receipt.operation_id, "service": receipt.service,
        "route_id": receipt.route_id, "request_digest": receipt.request_digest,
        "dispatch_state": receipt.dispatch_state, "reason": receipt.reason,
        "http_status_class": receipt.http_status_class,
        "response_digest": receipt.response_digest,
        "client_response_digest": receipt.client_response_digest,
        "request_bytes": receipt.request_bytes,
        "upstream_body_bytes": receipt.upstream_body_bytes,
        "client_response_bytes": receipt.client_response_bytes,
        "started_monotonic": receipt.started_monotonic,
        "completed_monotonic": receipt.completed_monotonic,
        "delivery_outcome": "sent",
    }
    assert charge <= 8192  # MAX_RECEIPT_BYTES, spelled out to avoid re-importing it twice
    assert _canonical_size(actual) <= charge


def test_worst_case_charge_bounds_an_abandoned_receipt_with_max_length_ids():
    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "n" * 128
    ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="confluence", route_id=long_id,
        operation_id=long_id, request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + 5.0,
    )
    charge = ledger.snapshot()["entries"][0]["charge"]
    clock.advance(5.0)  # cross the deadline: the sweep abandons it
    entry = ledger.snapshot()["entries"][0]
    assert entry["dispatch_state"] == "NOT_DISPATCHED" and entry["reason"] == "abandoned"
    actual = {
        "receipt_id": entry["receipt_id"], "generation": "g" * 128,
        "lease_id": long_id, "attempt_id": long_id, "operation_id": long_id,
        "service": "confluence", "route_id": long_id, "request_digest": DIGEST,
        "dispatch_state": entry["dispatch_state"], "reason": entry["reason"],
        "http_status_class": entry["http_status_class"],
        "response_digest": entry["response_digest"],
        "client_response_digest": entry["client_response_digest"],
        "request_bytes": MAX_REQUEST_BYTES,
        "upstream_body_bytes": entry["upstream_body_bytes"],
        "client_response_bytes": entry["client_response_bytes"],
        "started_monotonic": entry["started_monotonic"],
        "completed_monotonic": entry["completed_monotonic"],
        "delivery_outcome": "send_unknown",  # worst-case-length placeholder outcome
    }
    assert _canonical_size(actual) <= charge


def test_worst_case_charge_bounds_the_largest_realizable_record():
    # The two tests above use a small fixed clock (10_000.0) and a 4 KiB
    # body, which leaves enough slack from the sys.float_info.max placeholder
    # that a dropped charge field or an undersized WORST_* placeholder would
    # go unnoticed (see the module docstring's own worst-case rationale).
    # This uses the actual worst-case reason/state, the full 1 MiB response
    # cap, a realistically long monotonic clock repr, and a delivered
    # send_unknown outcome with delivery_bytes_sent at its maximum -- the
    # largest record the ledger can really produce -- and checks it against
    # both its own charge and the field-width of the placeholders themselves.
    import grafana_jsm_sandbox.forwarder_receipts as fr

    assert len(str(fr._WORST_BODY_BYTES)) >= len(str(2**20))  # covers the 1 MiB body cap
    # The placeholder's own field width must cover a legal maximum-length
    # clock repr, not just whatever value this test happens to pick below --
    # otherwise a too-narrow _WORST_FLOAT could slip past this test's own
    # (comfortably short) fixed clock value while still under-charging a
    # ledger driven by a real, wider monotonic clock reading. This anchor is
    # a genuinely 23-character repr (unlike a same-width-by-coincidence
    # pick), matching _WORST_FLOAT's own true maximum width.
    _widest_possible_repr_anchor = 2.2250738585072014e-308
    assert len(repr(fr._WORST_FLOAT)) >= len(repr(_widest_possible_repr_anchor))

    _widest_legal_clock_value = 1.2345678901234567e16

    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "w" * 128
    clock.value = _widest_legal_clock_value  # a maximum-width monotonic repr
    reservation = ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="anthropic", route_id=long_id,
        operation_id=long_id, request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + MAX_HANDLER_SECONDS,
    )
    charge = ledger.snapshot()["entries"][0]["charge"]
    clock.advance(38.0)  # completed_monotonic also gets a maximum-width repr
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    upstream_body = b"1" * (1024 * 1024)  # the full 1 MiB response cap
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=ParsedResponse(200, upstream_body),
    )
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    ledger.complete_delivery(
        claim, outcome="send_unknown", bytes_sent=receipt.client_response_bytes,
    )
    actual = {
        "receipt_id": receipt.receipt_id, "generation": receipt.generation,
        "lease_id": receipt.lease_id, "attempt_id": receipt.attempt_id,
        "operation_id": receipt.operation_id, "service": receipt.service,
        "route_id": receipt.route_id, "request_digest": receipt.request_digest,
        "dispatch_state": receipt.dispatch_state, "reason": receipt.reason,
        "http_status_class": receipt.http_status_class,
        "response_digest": receipt.response_digest,
        "client_response_digest": receipt.client_response_digest,
        "request_bytes": receipt.request_bytes,
        "upstream_body_bytes": receipt.upstream_body_bytes,
        "client_response_bytes": receipt.client_response_bytes,
        "started_monotonic": receipt.started_monotonic,
        "completed_monotonic": receipt.completed_monotonic,
        "delivery_outcome": "send_unknown",
        "delivery_bytes_sent": receipt.client_response_bytes,
    }
    assert _canonical_size(actual) <= charge


def test_worst_case_charge_bounds_a_record_whose_completion_time_reprs_wider_than_its_start_time():
    # F3-5: every "worst-case charge" test above finalizes at a clock value
    # whose repr width equals the reservation-time value's own repr width, so
    # a mutant charging completed_monotonic using started_monotonic's exact
    # value instead of the _WORST_FLOAT placeholder would still pass every
    # one of them. This starts the clock at a short-repr value and advances
    # to a far wider-repr one purely between reservation and completion, and
    # compares the *actual* snapshot()-returned entry (every field
    # _entry_metadata emits, not a hand-picked subset) against its own
    # charge -- also covering the entry_state/charge/deadline fields the
    # charge must account for (see the F3-3 fix in forwarder_receipts.py).
    ledger, clock = new_ledger(generation="g" * 128, clock=FakeClock(0.0))
    long_id = "u" * 128
    reservation = ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="anthropic", route_id=long_id,
        operation_id=long_id, request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + MAX_HANDLER_SECONDS,
    )
    charge = ledger.snapshot()["entries"][0]["charge"]
    clock.value = 1.2345678901234567e-300  # far wider repr than the 0.0 reservation time
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    upstream_body = b"1" * (1024 * 1024)  # the full 1 MiB response cap
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=ParsedResponse(200, upstream_body),
    )
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    ledger.complete_delivery(
        claim, outcome="send_unknown", bytes_sent=receipt.client_response_bytes,
    )
    entry = next(
        e for e in ledger.snapshot()["entries"] if e["receipt_id"] == receipt.receipt_id
    )
    assert _canonical_size(entry) <= charge


# --- abandonment sweep: exact deadline boundary, per originating state ------


@pytest.mark.parametrize("from_state,expected_dispatch_state", [
    ("reserved", "NOT_DISPATCHED"),
    ("connecting", "DISPATCHED_UNKNOWN"),
    ("dispatched", "DISPATCHED_UNKNOWN"),
])
def test_abandonment_converts_each_state_correctly_exactly_at_the_deadline(
    from_state, expected_dispatch_state,
):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10.0)
    advance_to(ledger, reservation, from_state)
    clock.advance(10.0 - 1e-6)
    assert ledger.snapshot()["entries"][0]["entry_state"] == from_state  # one tick early: alive
    clock.advance(1e-6)  # now exactly at the deadline
    entry = ledger.snapshot()["entries"][0]
    assert entry["entry_state"] == "finalized"
    assert entry["dispatch_state"] == expected_dispatch_state
    assert entry["reason"] == "abandoned"


def test_deadline_boundary_call_at_exact_deadline_fails():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10.0)
    clock.advance(10.0)  # exactly at the deadline: "at/after" is expired
    assert error_code(lambda: ledger.begin_connect(reservation)) == "deadline_expired"


def test_call_one_tick_before_the_deadline_still_succeeds():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10.0)
    clock.advance(10.0 - 1e-9)
    ledger.begin_connect(reservation)  # must not raise


# --- late finalize/transition after abandonment always fails ---------------


def test_every_late_operation_after_abandonment_fails_with_deadline_expired():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=5.0)
    ledger.begin_connect(reservation)
    clock.advance(5.0)  # abandon from connecting -> DISPATCHED_UNKNOWN
    late_attempts = (
        lambda: ledger.begin_connect(reservation),
        lambda: ledger.begin_dispatch(reservation),
        lambda: ledger.finalize(reservation, dispatch_state="FAILED", reason="connect_failed"),
        lambda: ledger.finalize(
            reservation, dispatch_state="DISPATCHED_UNKNOWN", reason="write_failed",
        ),
        lambda: ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
            upstream_response=upstream(),
        ),
    )
    for attempt in late_attempts:
        assert error_code(attempt) == "deadline_expired"
    entry = ledger.snapshot()["entries"][0]
    assert entry["dispatch_state"] == "DISPATCHED_UNKNOWN" and entry["reason"] == "abandoned"


# --- retention boundary is exact at 310 seconds -----------------------------


def test_retention_boundary_is_exact_at_310_seconds():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    clock.advance(RETENTION_SECONDS - 1e-6)
    assert len(ledger.snapshot()["entries"]) == 1
    assert ledger.contains(receipt) is True
    clock.advance(1e-6)  # now exactly RETENTION_SECONDS since completion
    snapshot = ledger.snapshot()
    assert snapshot["entries"] == ()
    assert snapshot["charged_bytes"] == 0
    assert ledger.contains(receipt) is False


def test_contains_itself_prunes_a_retention_expired_receipt_without_a_prior_snapshot():
    # Every retention-boundary test above calls snapshot() (which sweeps and
    # prunes) immediately before its post-retention contains() assertion, so
    # contains() itself is never required to freshen the ledger to pass. This
    # calls contains() as the very first operation after the clock crosses
    # the retention boundary, with no prior snapshot()/other call.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    clock.advance(RETENTION_SECONDS)
    assert ledger.contains(receipt) is False
    snapshot = ledger.snapshot()
    assert snapshot["entries"] == ()
    assert snapshot["charged_bytes"] == 0


def test_contains_never_reports_true_from_a_held_ledger_for_a_genuine_receipt():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    clock.value = math.nan  # hold the ledger via a clock fault
    assert error_code(lambda: ledger.begin_connect(reservation)) == "clock_invalid"
    # The receipt is genuine and not expired, but a held ledger cannot be
    # trusted to answer a presence check either.
    assert ledger.contains(receipt) is False


def test_retention_prunes_before_a_late_delivery_call_can_find_the_receipt():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    clock.advance(RETENTION_SECONDS)
    assert error_code(lambda: ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )) == "receipt_unknown"


# --- the clock contract: exception, non-finite, bool, regression, negative -


def test_clock_exception_then_healthy_reading_still_holds_every_operation():
    class ExplodingClock:
        def __init__(self) -> None:
            self.fail = False

        def __call__(self) -> float:
            if self.fail:
                raise RuntimeError("clock unavailable")
            return 2_000.0

    clock = ExplodingClock()
    ledger = ReceiptLedger(generation=GENERATION, clock=clock)
    reservation = ledger.reserve(
        lease_id="a", attempt_id="a", service="jira", route_id="jira.issue.get",
        request_digest=DIGEST, request_bytes=10, deadline=2_030.0,
    )
    clock.fail = True  # the clock now faults on every subsequent read
    assert error_code(lambda: ledger.begin_connect(reservation)) == "clock_invalid"
    clock.fail = False  # a perfectly healthy, later reading cannot lift the hold
    assert error_code(lambda: ledger.begin_connect(reservation)) == "ledger_held"
    assert error_code(lambda: ledger.begin_dispatch(reservation)) == "ledger_held"
    assert error_code(lambda: ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )) == "ledger_held"
    assert ledger.snapshot()["ledger_state"] == "held"


def test_all_mutating_operation_kinds_are_held_after_a_clock_fault():
    ledger, clock = new_ledger()
    reservation_a = reserve(ledger, clock, lease_id="a", attempt_id="a")
    receipt = ledger.finalize(
        reservation_a, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    reservation_b = reserve(ledger, clock, lease_id="b", attempt_id="b")

    clock.value = math.nan
    assert error_code(lambda: ledger.begin_connect(reservation_b)) == "clock_invalid"

    clock.value = 999_999.0  # much later, perfectly valid: must not lift the hold
    assert error_code(
        lambda: reserve(ledger, clock, lease_id="c", attempt_id="c")
    ) == "ledger_held"
    assert error_code(lambda: ledger.begin_connect(reservation_b)) == "ledger_held"
    assert error_code(lambda: ledger.begin_dispatch(reservation_b)) == "ledger_held"
    assert error_code(lambda: ledger.finalize(
        reservation_b, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )) == "ledger_held"
    assert error_code(lambda: ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )) == "ledger_held"
    # complete_delivery's own held-check runs before it even inspects the
    # type of its first argument, so a receipt (not a genuine claim -- none
    # could ever be obtained from an already-held ledger) still surfaces the
    # hold rather than a type-confusion error.
    assert error_code(
        lambda: ledger.complete_delivery(receipt, outcome="sent", bytes_sent=0)
    ) == "ledger_held"
    assert ledger.snapshot()["ledger_state"] == "held"


def test_persisting_clock_fault_reports_ledger_held_not_the_original_fault_again():
    # A clock that keeps failing (rather than recovering after one bad read)
    # must report "ledger_held" on every call after the first, not keep
    # re-deriving and re-raising the original fault code -- the held check
    # must run before the clock is read at all, once already held.
    class PersistentlyExplodingClock:
        def __call__(self) -> float:
            raise RuntimeError("clock unavailable")

    ledger = ReceiptLedger(generation=GENERATION, clock=PersistentlyExplodingClock())
    reservation_kwargs = {
        "lease_id": "a", "attempt_id": "a", "service": "jira", "route_id": "jira.issue.get",
        "request_digest": DIGEST, "request_bytes": 10, "deadline": 2_030.0,
    }
    assert error_code(lambda: ledger.reserve(**reservation_kwargs)) == "clock_invalid"
    assert error_code(lambda: ledger.reserve(**reservation_kwargs)) == "ledger_held"
    assert error_code(lambda: ledger.reserve(**reservation_kwargs)) == "ledger_held"
    assert ledger.snapshot()["ledger_state"] == "held"


def test_persisting_clock_regression_reports_ledger_held_not_clock_regressed_again():
    ledger, clock = new_ledger()
    reserve(ledger, clock)
    clock.value -= 1  # first regression: sets the hold
    assert error_code(
        lambda: reserve(ledger, clock, lease_id="l2", attempt_id="a2")
    ) == "clock_regressed"
    clock.value -= 1  # a second, still-regressed reading must not re-report clock_regressed
    assert error_code(
        lambda: reserve(ledger, clock, lease_id="l3", attempt_id="a3")
    ) == "ledger_held"
    assert ledger.snapshot()["ledger_state"] == "held"


def test_clock_regression_by_one_ulp_holds_permanently():
    ledger, clock = new_ledger()
    reserve(ledger, clock)
    clock.value = math.nextafter(clock.value, -math.inf)  # smallest possible regression
    assert error_code(
        lambda: reserve(ledger, clock, lease_id="l2", attempt_id="a2")
    ) == "clock_regressed"
    clock.value += 1_000.0  # a much later, valid value cannot lift the hold
    assert error_code(
        lambda: reserve(ledger, clock, lease_id="l3", attempt_id="a3")
    ) == "ledger_held"
    assert ledger.snapshot()["ledger_state"] == "held"


@pytest.mark.parametrize("bad_clock_value", [True, False])
def test_clock_returning_a_bool_is_rejected_not_coerced_to_zero_or_one(bad_clock_value):
    ledger = ReceiptLedger(generation=GENERATION, clock=lambda: bad_clock_value)
    assert error_code(lambda: reserve(ledger, FakeClock())) == "clock_invalid"
    assert ledger.snapshot()["ledger_state"] == "held"


def test_negative_clock_value_is_rejected_per_the_documented_clock_contract():
    """The plan's clock contract (Module 1, ``ReceiptLedger``) is: 'Clock:
    exact finite non-negative int/float, non-regressing. A clock exception,
    invalid value or regression permanently holds the ledger.'

    A negative reading violates that exact type contract exactly as clearly
    as a non-finite one, and the sibling ledger this unit is modeled on
    (``forwarder_leases._require_time``) explicitly rejects ``converted < 0``
    for the same reason. This ledger's ``_finite`` helper checks only type
    and finiteness, so a negative clock value is silently accepted as a
    valid ``now`` instead of holding the ledger -- a genuine deviation from
    the documented contract.
    """
    ledger = ReceiptLedger(generation=GENERATION, clock=lambda: -1.0)
    with pytest.raises(ReceiptError):
        ledger.reserve(
            lease_id="lease-1", attempt_id="attempt-1", service="jira",
            route_id="jira.issue.get", request_digest=DIGEST, request_bytes=10,
            deadline=29.0,
        )
    assert ledger.snapshot()["ledger_state"] == "held"


# --- error messages never contain a caller-supplied value -------------------


def test_error_messages_never_contain_caller_supplied_values():
    ledger, clock = new_ledger()
    base_kwargs = {
        "lease_id": "l", "attempt_id": "a", "service": "jira", "route_id": "jira.issue.get",
        "request_digest": DIGEST, "request_bytes": 10, "deadline": clock.value + 10,
    }
    # _POISON alone is (deliberately) a syntactically valid safe-ID value, so an
    # ID-shaped field would silently accept it instead of failing; append a
    # character outside the safe-ID grammar so id-shaped fields still reject
    # it, while every check below still searches for the bare _POISON substring.
    poisoned_id_value = _POISON + "!"
    poisoned_fields = {
        "lease_id": poisoned_id_value, "attempt_id": poisoned_id_value,
        "service": _POISON, "route_id": poisoned_id_value,
        "request_digest": _POISON, "request_bytes": _POISON, "deadline": _POISON,
        "operation_id": poisoned_id_value,
    }
    for field, poison_value in poisoned_fields.items():
        kwargs = dict(base_kwargs)
        kwargs[field] = poison_value
        with pytest.raises(ReceiptError) as caught:
            ledger.reserve(**kwargs)
        assert _POISON not in str(caught.value)
        assert _POISON not in repr(caught.value)
        assert _POISON not in caught.value.code

    for bad_reservation in (_POISON, ReceiptReservation(receipt_id=_POISON)):
        with pytest.raises(ReceiptError) as caught:
            ledger.begin_connect(bad_reservation)
        assert _POISON not in str(caught.value)

    reservation = reserve(ledger, clock, lease_id="clean", attempt_id="clean")
    for bad_dispatch_state, bad_reason in ((_POISON, "ok"), ("NOT_DISPATCHED", _POISON)):
        with pytest.raises(ReceiptError) as caught:
            ledger.finalize(reservation, dispatch_state=bad_dispatch_state, reason=bad_reason)
        assert _POISON not in str(caught.value)

    with pytest.raises(ReceiptError) as caught:
        ledger.claim_delivery(_POISON, client_response_digest="a" * 64)
    assert _POISON not in str(caught.value)

    # The loop above never let ``reservation`` reach finalize() (every
    # attempt was rejected before completing it), so a fresh, genuinely
    # finalized receipt is needed to poison-check the digest argument itself.
    genuine_receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    with pytest.raises(ReceiptError) as caught:
        ledger.claim_delivery(genuine_receipt, client_response_digest=poisoned_id_value)
    assert _POISON not in str(caught.value)

    with pytest.raises(ReceiptError) as caught:
        ReceiptLedger(generation=_POISON + "!")  # "!" keeps this an invalid safe id
    assert _POISON not in str(caught.value)


# --- snapshot never contains response body bytes ----------------------------


def test_snapshot_never_contains_a_rejected_response_body():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")
    secret = "TOTALLY-SECRET-BODY-CONTENT-42"
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=ParsedResponse(200, f'{{"leak":"{secret}"}}'.encode()),
    )
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    ledger.complete_delivery(claim, outcome="sent", bytes_sent=receipt.client_response_bytes)
    serialized = repr(ledger.snapshot())
    assert secret not in serialized
    assert "leak" not in serialized


def test_snapshot_never_contains_an_ok_response_body_either():
    # Even when the upstream body IS the approved client response, the
    # ledger's own sanitized snapshot must describe it only by digest/count.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")
    marker = "MARKER-VALUE-77-forwarded-to-client-not-to-the-ledger"
    ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
        upstream_response=ParsedResponse(200, f'{{"v":"{marker}"}}'.encode()),
    )
    assert marker not in repr(ledger.snapshot())


# --- concurrency: finalize races, and finalize races the sweep -------------


def test_concurrent_finalize_attempts_on_one_reservation_yield_exactly_one_receipt():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=30.0)
    advance_to(ledger, reservation, "dispatched")
    workers = 20
    barrier = Barrier(workers)
    outcomes: list[tuple[str, object]] = []
    outcomes_lock = threading.Lock()

    def attempt(index: int) -> None:
        barrier.wait()
        try:
            if index % 2 == 0:
                receipt = ledger.finalize(
                    reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                    upstream_response=upstream(),
                )
            else:
                receipt = ledger.finalize(
                    reservation, dispatch_state="DISPATCHED_UNKNOWN", reason="write_failed",
                )
            with outcomes_lock:
                outcomes.append(("ok", receipt))
        except ReceiptError as error:
            with outcomes_lock:
                outcomes.append(("error", error.code))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(attempt, range(workers)))

    successes = [item for item in outcomes if item[0] == "ok"]
    failures = [item for item in outcomes if item[0] == "error"]
    assert len(successes) == 1, "exactly one concurrent finalize must win the race"
    assert len(failures) == workers - 1
    assert all(code == "reservation_finalized" for _, code in failures)
    winning_receipt = successes[0][1]
    assert ledger.contains(winning_receipt) is True

    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["receipt_id"] == reservation.receipt_id
    assert snapshot["counts_by_state"]["finalized"] == 1


def _finalize_racer(
    ledger: ReceiptLedger, reservation: ReceiptReservation,
    barrier: Barrier, outcomes: list, outcomes_lock: threading.Lock,
) -> None:
    barrier.wait()
    try:
        receipt = ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
            upstream_response=upstream(),
        )
        with outcomes_lock:
            outcomes.append(("ok", receipt))
    except ReceiptError as error:
        with outcomes_lock:
            outcomes.append(("error", error.code))


def _deadline_advancer(clock: FakeClock, barrier: Barrier) -> None:
    barrier.wait()
    clock.advance(5.0)  # crosses the deadline mid-race, outside the ledger's lock


def _run_one_finalize_vs_sweep_race(iteration: int) -> None:
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=5.0)
    advance_to(ledger, reservation, "dispatched")
    workers = 16
    barrier = Barrier(workers)
    outcomes: list[tuple[str, object]] = []
    outcomes_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_finalize_racer, ledger, reservation, barrier, outcomes, outcomes_lock)
            for _ in range(workers - 1)
        ]
        futures.append(pool.submit(_deadline_advancer, clock, barrier))
        for future in futures:
            future.result()

    successes = [item for item in outcomes if item[0] == "ok"]
    failures = [item for item in outcomes if item[0] == "error"]
    assert len(successes) + len(failures) == workers - 1, iteration
    assert len(successes) <= 1, (
        f"iteration {iteration}: the lock must serialize finalize against the sweep"
    )
    assert all(
        code in ("deadline_expired", "reservation_finalized") for _, code in failures
    ), iteration

    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == 1, f"iteration {iteration}: lost/duplicated entry"
    entry = snapshot["entries"][0]
    assert entry["entry_state"] == "finalized"
    assert snapshot["counts_by_state"]["finalized"] == 1
    if successes:
        # A finalizer won the race before the clock crossed the deadline.
        assert entry["dispatch_state"] == "TRANSPORT_CONFIRMED" and entry["reason"] == "ok"
        winning_receipt = successes[0][1]
        assert ledger.contains(winning_receipt) is True
    else:
        # The abandonment sweep won: every finalizer lost to it.
        assert entry["dispatch_state"] == "DISPATCHED_UNKNOWN"
        assert entry["reason"] == "abandoned"


def test_concurrent_finalize_races_the_abandonment_sweep_under_the_lock():
    # Unlike advancing the clock to the deadline BEFORE any thread starts
    # (which decides the winner before the race even begins, regardless of
    # locking), this crosses the deadline from inside the barrier-released
    # race itself: one worker calls clock.advance() -- outside the ledger's
    # lock, standing in for real time elapsing -- concurrently with the rest
    # racing a legitimate finalize(). Depending purely on scheduling, either
    # a finalizer can win before the clock crosses the deadline, or the
    # abandonment sweep (triggered from inside ANY thread's own locked
    # _now() call once the clock has crossed it) wins first; both are
    # legal outcomes. What the lock must guarantee regardless of which wins
    # is the invariant checked on every iteration: never more than one
    # success, and the entry ends up finalized exactly once, never lost or
    # duplicated. Run many iterations so a lock that only "usually"
    # serializes correctly cannot pass by luck.
    for iteration in range(40):
        _run_one_finalize_vs_sweep_race(iteration)


def test_concurrent_finalize_widens_window_never_double_finalizes_one_reservation(monkeypatch):
    # F2-1: with 20 threads released off one barrier, CPython's GIL makes
    # _do_finalize's critical section (a handful of attribute sets plus one
    # dataclass construction, with no forced yield point) essentially never
    # get preempted, so test_concurrent_finalize_attempts_on_one_reservation_
    # yield_exactly_one_receipt above still passes 15/15 even with the
    # ledger's lock entirely removed from finalize(). Widen the window the
    # same way test_concurrent_claim_delivery_never_double_claims_one_receipt
    # does for claim_delivery: monkeypatch fr.ForwarderReceipt with a
    # subclass that sleeps in __init__. _do_finalize constructs exactly one
    # ForwarderReceipt strictly after finalize()'s own _require_active check
    # has already accepted the entry as still active, and strictly before it
    # mutates entry.state to "finalized" -- exactly the documented race
    # window. Two threads finalizing one dispatched reservation must now
    # reliably interleave inside that window if (and only if) the lock does
    # not actually serialize them.
    import grafana_jsm_sandbox.forwarder_receipts as fr

    class _SlowForwarderReceipt(fr.ForwarderReceipt):
        def __init__(self, *args, **kwargs) -> None:
            time.sleep(0.05)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(fr, "ForwarderReceipt", _SlowForwarderReceipt)

    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=30.0)
    advance_to(ledger, reservation, "dispatched")
    barrier = Barrier(2)
    outcomes: list[tuple[str, object]] = []
    outcomes_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            receipt = ledger.finalize(
                reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                upstream_response=upstream(),
            )
            with outcomes_lock:
                outcomes.append(("ok", receipt))
        except ReceiptError as error:
            with outcomes_lock:
                outcomes.append(("error", error.code))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(kind for kind, _ in outcomes) == ["error", "ok"]
    failure_codes = [code for kind, code in outcomes if kind == "error"]
    assert failure_codes == ["reservation_finalized"]
    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == 1
    assert snapshot["counts_by_state"]["finalized"] == 1


def test_concurrent_finalize_races_the_abandonment_sweep_with_widened_window(monkeypatch):
    # F2-1 (sweep half): likewise, _run_one_finalize_vs_sweep_race's 40
    # iterations above pass even with the lock removed, because the sweep's
    # own call into _do_finalize is just as fast and just as unlikely to be
    # preempted under the GIL, and because it is scheduling-dependent which
    # thread (a finalizer or the clock advancer) even wins the initial "is
    # the deadline already past" read. Make that ordering deterministic
    # instead of statistical: pause one explicit finalize() call, via
    # monkeypatched fr.ForwarderReceipt (constructed by _do_finalize strictly
    # after _require_active accepted the entry, strictly before the state
    # mutation -- the same window used above), *after* it has already been
    # admitted as active but *before* it commits. While it is paused, advance
    # the clock past the deadline and run a concurrent snapshot() -- which
    # runs the same abandonment sweep under its own lock acquisition -- on
    # the very same entry. With the lock genuinely serializing finalize()'s
    # entire check-then-commit span, snapshot() cannot even start its sweep
    # until finalize() releases the lock, by which point the entry is already
    # finalized (TRANSPORT_CONFIRMED) and the sweep skips it. Without that
    # serialization, snapshot() runs concurrently, sees the entry as still
    # "dispatched" past its deadline, and abandons it there and then --
    # finalizing it a second time once the paused finalize() call resumes and
    # overwrites that with "ok", silently erasing the abandonment a caller
    # may have already observed and acted on.
    import grafana_jsm_sandbox.forwarder_receipts as fr

    sleeping_started = threading.Event()
    proceed = threading.Event()

    class _SlowForwarderReceipt(fr.ForwarderReceipt):
        def __init__(self, *args, **kwargs) -> None:
            sleeping_started.set()
            proceed.wait(timeout=2.0)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(fr, "ForwarderReceipt", _SlowForwarderReceipt)

    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=5.0)
    advance_to(ledger, reservation, "dispatched")
    outcomes: list[tuple[str, object]] = []

    def finalizer() -> None:
        try:
            receipt = ledger.finalize(
                reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                upstream_response=upstream(),
            )
            outcomes.append(("ok", receipt))
        except ReceiptError as error:
            outcomes.append(("error", error.code))

    finalize_thread = threading.Thread(target=finalizer)
    finalize_thread.start()
    assert sleeping_started.wait(timeout=2.0), "finalize() never reached the widened window"

    clock.advance(10.0)  # crosses the deadline while finalize() is paused mid-commit

    snapshot_ready = threading.Event()
    mid_snapshot: dict[str, object] = {}

    def snapshotter() -> None:
        mid_snapshot["value"] = ledger.snapshot()
        snapshot_ready.set()

    snapshot_thread = threading.Thread(target=snapshotter)
    snapshot_thread.start()
    # A real lock held by the paused finalize() call must block snapshot()
    # from even starting its own sweep for this brief window.
    blocked_before_release = not snapshot_ready.wait(timeout=0.2)

    proceed.set()
    finalize_thread.join(timeout=2.0)
    snapshot_thread.join(timeout=2.0)

    assert blocked_before_release, (
        "snapshot() observed/finalized the entry before finalize() released its lock"
    )
    assert len(outcomes) == 1 and outcomes[0][0] == "ok"
    winning_receipt = outcomes[0][1]
    # The sweep must never be able to see, let alone abandon, this entry
    # while a legitimate finalize() call is genuinely already in flight for
    # it: what snapshot() (however long it took to finally return) observed
    # must be the winning finalize() call's own committed state, never a
    # transient sweep-induced "abandoned" one.
    mid_entry = mid_snapshot["value"]["entries"][0]
    assert mid_entry["entry_state"] == "finalized"
    assert mid_entry["dispatch_state"] == "TRANSPORT_CONFIRMED"
    assert mid_entry["reason"] == "ok"
    # And the ledger must still recognize the exact receipt instance the
    # winning finalize() call returned to its caller -- never silently swap
    # it out for a different (e.g. sweep-constructed) instance afterward.
    assert ledger.contains(winning_receipt) is True


def test_concurrent_mixed_lifecycle_never_loses_or_duplicates_an_entry():
    ledger, clock = new_ledger()
    count = 60
    reservations = [
        reserve(ledger, clock, lease_id=f"l{i}", attempt_id=f"a{i}", ttl=30.0)
        for i in range(count)
    ]
    barrier = Barrier(count)

    def worker(index: int) -> None:
        reservation = reservations[index]
        barrier.wait()
        try:
            ledger.begin_connect(reservation)
            ledger.begin_dispatch(reservation)
            ledger.finalize(
                reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                upstream_response=upstream(),
            )
        except ReceiptError:
            pass  # any legitimate rejection is fine; silent corruption is not

    with ThreadPoolExecutor(max_workers=count) as pool:
        list(pool.map(worker, range(count)))

    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == count
    receipt_ids = {entry["receipt_id"] for entry in snapshot["entries"]}
    assert len(receipt_ids) == count  # no id collision, no lost/duplicated entry
    assert all(entry["entry_state"] == "finalized" for entry in snapshot["entries"])
    assert snapshot["counts_by_state"]["finalized"] == count


# --- concurrency: claim_delivery itself must be race-free -------------------


def test_concurrent_claim_delivery_never_double_claims_one_receipt(monkeypatch):
    # F1-5: the "concurrent handler threads" threat model applies to
    # claim_delivery/complete_delivery too, not only reserve/finalize/the
    # sweep -- but nothing above ever races claim_delivery. Widen the gap
    # between claim_delivery's "pending" check and its "sending" mutation
    # with a real time.sleep in a DeliveryClaim subclass's __init__, so two
    # threads racing the same receipt reliably interleave inside that
    # window if (and only if) the ledger's lock does not actually serialize
    # them. Exactly one thread must win ("claimed"); the other must see
    # "delivery_claimed", never a second successful claim -- a lock removed
    # from claim_delivery would let both win, i.e. double-deliver one receipt.
    import grafana_jsm_sandbox.forwarder_receipts as fr

    class _SlowDeliveryClaim(fr.DeliveryClaim):
        def __init__(self, *args, **kwargs) -> None:
            time.sleep(0.05)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(fr, "DeliveryClaim", _SlowDeliveryClaim)

    ledger, clock = new_ledger()
    receipt = _finalize(ledger, clock)
    barrier = Barrier(2)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            ledger.claim_delivery(
                receipt, client_response_digest=receipt.client_response_digest,
            )
            with outcomes_lock:
                outcomes.append("claimed")
        except ReceiptError as error:
            with outcomes_lock:
                outcomes.append(error.code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(outcomes) == ["claimed", "delivery_claimed"]
    snapshot = ledger.snapshot()
    assert snapshot["entries"][0]["delivery_outcome"] == "sending"


def _finalize(ledger: ReceiptLedger, clock: FakeClock) -> ForwarderReceipt:
    reservation = reserve(ledger, clock)
    return ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )


# --- concurrency: complete_delivery itself must also be race-free ----------


def _patch_slow_client_response_bytes(monkeypatch) -> None:
    # F2-2: complete_delivery reads entry.record.client_response_bytes
    # strictly between checking delivery_outcome == "sending" and writing
    # the new outcome/bytes_sent. Widen exactly that gap, but only when it
    # is read from a thread whose name starts with "race" -- the setup
    # calls (reserve/finalize/claim_delivery, all on the main thread) must
    # stay fast.
    import grafana_jsm_sandbox.forwarder_receipts as fr

    class _SlowAttributeForwarderReceipt(fr.ForwarderReceipt):
        def __getattribute__(self, name):
            if name == "client_response_bytes" and threading.current_thread().name.startswith(
                "race",
            ):
                time.sleep(0.05)
            return object.__getattribute__(self, name)

    monkeypatch.setattr(fr, "ForwarderReceipt", _SlowAttributeForwarderReceipt)


def test_concurrent_complete_delivery_never_double_completes_one_claim(monkeypatch):
    # F2-2: no test above ever races complete_delivery itself -- only
    # reserve (test_concurrent_reserves_never_exceed_max_receipts) and
    # claim_delivery (above) have race tests that fail when their lock is
    # removed. Two threads racing to complete the same claim with different
    # outcomes must not both succeed; the loser must see delivery_completed,
    # and the ledger's own recorded delivery_outcome must match whichever
    # outcome actually won, never a mix of the two.
    _patch_slow_client_response_bytes(monkeypatch)

    ledger, clock = new_ledger()
    receipt = _finalize(ledger, clock)
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    genuine_bytes = receipt.client_response_bytes

    barrier = Barrier(2)
    outcomes: list[tuple[str, object]] = []
    outcomes_lock = threading.Lock()

    def complete(outcome: str, bytes_sent: int) -> None:
        barrier.wait()
        try:
            ledger.complete_delivery(claim, outcome=outcome, bytes_sent=bytes_sent)
            with outcomes_lock:
                outcomes.append(("ok", outcome))
        except ReceiptError as error:
            with outcomes_lock:
                outcomes.append(("error", error.code))

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="race") as pool:
        futures = [
            pool.submit(complete, "sent", genuine_bytes),
            pool.submit(complete, "send_unknown", 0),
        ]
        for future in futures:
            future.result()

    assert sorted(kind for kind, _ in outcomes) == ["error", "ok"]
    failure_codes = [code for kind, code in outcomes if kind == "error"]
    assert failure_codes == ["delivery_completed"]
    winning_outcome = next(value for kind, value in outcomes if kind == "ok")
    snapshot = ledger.snapshot()
    assert snapshot["entries"][0]["delivery_outcome"] == winning_outcome


class _RaceSensitiveClock:
    """A clock whose reading is captured early but returned late for one
    designated ("slow"-named) thread, while any other thread's reading is
    always freshly incremented and registered immediately.

    Reproduces the specific interleaving an unlocked ``complete_delivery``
    is vulnerable to (F2-2): one thread's own clock reading is genuinely
    valid at the moment it is taken, but by the time that thread's own
    ``_now()`` gets to compare it against ``self._last_now``, a different,
    concurrently-running call (here modelling ``snapshot()``) has already
    registered a strictly later reading -- so the first call's own,
    perfectly valid reading looks like a clock regression. ``gate`` is only
    armed once the race actually starts, so setup calls (reserve/finalize/
    claim_delivery, all on the main thread) are never blocked by it.
    """

    def __init__(self, value: float = 10_000.0) -> None:
        self.value = value
        self.gated = False
        self._slow_read_started = threading.Event()

    def __call__(self) -> float:
        if threading.current_thread().name.startswith("slow"):
            current = self.value
            self._slow_read_started.set()
            time.sleep(0.05)
            return current
        if self.gated:
            self._slow_read_started.wait(timeout=2.0)
        self.value += 0.01
        return self.value


def test_concurrent_complete_delivery_races_snapshot_without_a_false_clock_regression():
    # F2-2 (second race): complete_delivery calls the ledger's own _now()
    # exactly like every other public method. If it does not hold the lock
    # for its own reading-then-comparing span, a concurrent snapshot() can
    # register a later _last_now first, making complete_delivery's own
    # (earlier, perfectly valid) reading look like a clock regression --
    # permanently holding the ledger and leaving the send unrecorded even
    # though nothing was ever actually wrong with the clock.
    clock = _RaceSensitiveClock()
    ledger, _ = new_ledger(clock=clock)
    receipt = _finalize(ledger, clock)
    claim = ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    )
    genuine_bytes = receipt.client_response_bytes
    clock.gated = True

    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def completer() -> None:
        try:
            ledger.complete_delivery(claim, outcome="sent", bytes_sent=genuine_bytes)
        except BaseException as error:  # noqa: BLE001 - recorded, never swallowed
            with errors_lock:
                errors.append(error)

    def snapshotter() -> None:
        try:
            ledger.snapshot()
        except BaseException as error:  # noqa: BLE001 - recorded, never swallowed
            with errors_lock:
                errors.append(error)

    completer_thread = threading.Thread(target=completer, name="slow-completer")
    snapshot_thread = threading.Thread(target=snapshotter, name="fast-snapshotter")
    completer_thread.start()
    snapshot_thread.start()
    completer_thread.join(timeout=2.0)
    snapshot_thread.join(timeout=2.0)

    assert errors == []
    final_snapshot = ledger.snapshot()
    assert final_snapshot["ledger_state"] == "ready"
    assert final_snapshot["entries"][0]["delivery_outcome"] == "sent"


# --- root-added: deterministic lock-acquisition probe for every public operation


def _lock_probe_operations(ledger: ReceiptLedger, clock: FakeClock):
    finalized = reserve(ledger, clock, lease_id="lease-final")
    receipt = ledger.finalize(finalized, dispatch_state="NOT_DISPATCHED", reason="lease_denied")
    claimed_receipt = ledger.finalize(
        reserve(ledger, clock, lease_id="lease-claimed"),
        dispatch_state="NOT_DISPATCHED", reason="lease_denied",
    )
    claim = ledger.claim_delivery(
        claimed_receipt, client_response_digest=claimed_receipt.client_response_digest,
    )
    connecting = reserve(ledger, clock, lease_id="lease-connecting")
    dispatching = reserve(ledger, clock, lease_id="lease-dispatching")
    ledger.begin_connect(dispatching)
    pending = reserve(ledger, clock, lease_id="lease-pending")
    return {
        "reserve": lambda: reserve(ledger, clock, lease_id="lease-new"),
        "begin_connect": lambda: ledger.begin_connect(connecting),
        "begin_dispatch": lambda: ledger.begin_dispatch(dispatching),
        "finalize": lambda: ledger.finalize(
            pending, dispatch_state="NOT_DISPATCHED", reason="lease_denied"),
        "claim_delivery": lambda: ledger.claim_delivery(
            receipt, client_response_digest=receipt.client_response_digest),
        "complete_delivery": lambda: ledger.complete_delivery(
            claim, outcome="not_sent", bytes_sent=0),
        "contains": lambda: ledger.contains(receipt),
        "snapshot": ledger.snapshot,
    }


@pytest.mark.parametrize("operation", [
    "reserve", "begin_connect", "begin_dispatch", "finalize", "claim_delivery",
    "complete_delivery", "contains", "snapshot",
])
def test_every_public_operation_waits_for_the_ledger_lock(operation):
    ledger, clock = new_ledger()
    call = _lock_probe_operations(ledger, clock)[operation]
    finished = threading.Event()
    failures = []

    def worker():
        try:
            call()
        except BaseException as error:  # noqa: BLE001 - surfaced by the assertion below
            failures.append(error)
        finally:
            finished.set()

    with ledger._lock:
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert not finished.wait(0.2), f"{operation} ran without acquiring the ledger lock"
    assert finished.wait(2.0)
    thread.join(2.0)
    assert not failures
