"""Deterministic tests for the sanitized dispatch-receipt ledger (Module 1).

These tests treat the ledger as a trusted in-process controller: a receipt is
dispatch correlation, never an external-effect confirmation. All timing uses
an injected fake clock; nothing here opens a socket or a real connection.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier

import pytest

from grafana_jsm_sandbox import forwarder_receipts as fr
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, serialize_response
from grafana_jsm_sandbox.forwarder_receipts import (
    DELIVERY_OUTCOMES,
    DISPATCH_STATES,
    LOCAL_RESPONSES,
    MAX_HANDLER_SECONDS,
    MAX_LEDGER_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_RECEIPTS,
    MAX_REQUEST_BYTES,
    RETENTION_SECONDS,
    DeliveryClaim,
    ReceiptError,
    ReceiptLedger,
    ReceiptReservation,
    local_response,
    local_response_for,
    response_digest,
)


class FakeClock:
    def __init__(self, value: float = 1_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


DIGEST = hashlib.sha256(b"fixed-request").hexdigest()
GENERATION = "generation-a"


def new_ledger(*, generation: str = GENERATION) -> tuple[ReceiptLedger, FakeClock]:
    clock = FakeClock()
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


def assert_error(call, code: str | None = None) -> ReceiptError:
    with pytest.raises(ReceiptError) as caught:
        call()
    error = caught.value
    assert isinstance(error.code, str) and str(error) == error.code
    if code is not None:
        assert error.code == code
    return error


# --- constants -------------------------------------------------------------


def test_fixed_constants_and_tables():
    assert DISPATCH_STATES == (
        "NOT_DISPATCHED", "FAILED", "DISPATCHED_UNKNOWN", "PARTIAL", "TRANSPORT_CONFIRMED",
    )
    assert DELIVERY_OUTCOMES == ("pending", "sending", "sent", "not_sent", "send_unknown")
    assert MAX_RECEIPTS == 2048
    assert MAX_RECEIPT_BYTES == 8192
    assert MAX_LEDGER_BYTES == 2 * 1024 * 1024
    assert RETENTION_SECONDS == 310.0
    assert MAX_HANDLER_SECONDS == 40.0
    assert MAX_REQUEST_BYTES == 2048 + 16384 + 262144
    assert set(LOCAL_RESPONSES) == {
        "invalid_request", "denied", "unavailable", "upstream_failed",
        "upstream_unknown", "deadline", "response_rejected",
    }


@pytest.mark.parametrize("kind,status,body", [
    ("invalid_request", 400, b'{"error":"forwarder_invalid_request"}'),
    ("denied", 403, b'{"error":"forwarder_denied"}'),
    ("unavailable", 503, b'{"error":"forwarder_unavailable"}'),
    ("upstream_failed", 502, b'{"error":"forwarder_upstream_failed"}'),
    ("upstream_unknown", 502, b'{"error":"forwarder_dispatch_unknown"}'),
    ("deadline", 504, b'{"error":"forwarder_deadline"}'),
    ("response_rejected", 502, b'{"error":"forwarder_response_rejected"}'),
])
def test_local_responses_are_fixed_and_looked_up_by_kind(kind, status, body):
    assert LOCAL_RESPONSES[kind] == ParsedResponse(status, body)
    assert local_response(kind) is LOCAL_RESPONSES[kind]


@pytest.mark.parametrize("bad", [None, 1, True, "", "unknown_kind", "Denied"])
def test_local_response_rejects_unknown_or_untyped_kind(bad):
    assert_error(lambda: local_response(bad), "unknown_local_response")


# --- response_digest ---------------------------------------------------------


def test_response_digest_matches_serialized_bytes():
    response = upstream(200, b'{"a":1}')
    expected = hashlib.sha256(serialize_response(response)).hexdigest()
    assert response_digest(response) == expected
    assert len(expected) == 64 and expected == expected.lower()


@pytest.mark.parametrize("bad", [None, "not-a-response", 1, upstream.__class__])
def test_response_digest_rejects_non_response_types(bad):
    assert_error(lambda: response_digest(bad), "invalid_response")


def test_response_digest_rejects_invalid_response_shape():
    assert_error(lambda: response_digest(ParsedResponse(200, b"")), "invalid_response")
    assert_error(lambda: response_digest(ParsedResponse(300, b"x")), "invalid_response")


# --- reservation input validation ------------------------------------------


@pytest.mark.parametrize("field,value", [
    ("lease_id", 1), ("lease_id", None), ("lease_id", True), ("lease_id", ""),
    ("lease_id", "é"), ("lease_id", "x" * 129),
    ("attempt_id", 1), ("attempt_id", None),
    ("service", 1), ("service", "unknown-service"), ("service", None),
    ("route_id", ""), ("route_id", "x" * 129), ("route_id", 5),
    ("request_digest", "A" * 64), ("request_digest", "a" * 63), ("request_digest", "g" * 64),
    ("request_digest", b"a" * 64), ("request_digest", None),
    ("request_bytes", True), ("request_bytes", False), ("request_bytes", -1),
    ("request_bytes", MAX_REQUEST_BYTES + 1), ("request_bytes", 1.0), ("request_bytes", "10"),
    ("operation_id", 1), ("operation_id", ""), ("operation_id", "x" * 129), ("operation_id", True),
])
def test_reserve_input_types_are_strictly_validated(field, value):
    ledger, clock = new_ledger()
    kwargs = {
        "lease_id": "lease-1", "attempt_id": "attempt-1", "service": "jira",
        "route_id": "jira.issue.get", "request_digest": DIGEST, "request_bytes": 100,
        "deadline": clock.value + 30, "operation_id": None,
    }
    kwargs[field] = value
    assert_error(lambda: ledger.reserve(**kwargs))


@pytest.mark.parametrize("deadline", [
    True, False, 0, -1, math.nan, math.inf, -math.inf, 2**2000, "30", None,
])
def test_reserve_deadline_type_and_finiteness_is_exact(deadline):
    ledger, _clock = new_ledger()
    assert_error(lambda: ledger.reserve(
        lease_id="lease-1", attempt_id="attempt-1", service="jira", route_id="jira.issue.get",
        request_digest=DIGEST, request_bytes=10, deadline=deadline,
    ), "invalid_deadline")


def test_reserve_deadline_window_is_exclusive_now_inclusive_max():
    ledger, clock = new_ledger()
    assert_error(lambda: reserve(ledger, clock, ttl=0), "invalid_deadline")
    assert_error(
        lambda: reserve(ledger, clock, ttl=MAX_HANDLER_SECONDS + 0.001), "invalid_deadline",
    )
    ok = reserve(ledger, clock, ttl=MAX_HANDLER_SECONDS)
    assert ok.receipt_id


def test_reserve_accepts_request_bytes_of_exactly_zero():
    # A bodyless GET route legitimately reserves with request_bytes=0 (the
    # forwarder specification: "bodyless GET permits absent length or
    # exactly zero"); the accept side of this boundary had no direct test.
    ledger, clock = new_ledger()
    reservation = ledger.reserve(
        lease_id="lease-1", attempt_id="attempt-1", service="jira", route_id="jira.issue.get",
        request_digest=DIGEST, request_bytes=0, deadline=clock.value + 30,
    )
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    assert receipt.request_bytes == 0


def test_reserve_accepts_realistic_generated_id_shapes_with_underscore_and_uppercase():
    # Real lease/attempt IDs from forwarder_leases._new_id look like
    # "<prefix>_<url-safe-base64>", which always contains "_" and usually
    # uppercase letters; every accept-side test elsewhere in this file uses
    # only hand-typed lowercase/hyphen IDs.
    ledger, clock = new_ledger()
    realistic_id = "lease_AbC-9_XyZ.7"
    reservation = ledger.reserve(
        lease_id=realistic_id, attempt_id=realistic_id, service="jira",
        route_id="jira.issue.get", request_digest=DIGEST, request_bytes=10,
        deadline=clock.value + 30, operation_id=realistic_id,
    )
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    assert receipt.lease_id == realistic_id
    assert receipt.attempt_id == realistic_id
    assert receipt.operation_id == realistic_id


def test_reserve_accepts_max_length_ids_and_charges_within_bound():
    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "x" * 128
    reservation = ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="kubernetes", route_id=long_id,
        request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + MAX_HANDLER_SECONDS, operation_id=long_id,
    )
    entry = ledger.snapshot()["entries"][0]
    assert entry["receipt_id"] == reservation.receipt_id
    assert 0 < entry["charge"] <= MAX_RECEIPT_BYTES


def test_finalized_receipt_correlation_and_timing_fields_match_the_reservation():
    # snapshot() renders most of these fields from the internal _Entry, not
    # from the returned ForwarderReceipt, so this checks the receipt object
    # itself: a swapped lease_id/attempt_id, a dropped operation_id, or a
    # started_monotonic/completed_monotonic mix-up would all be invisible to
    # a snapshot()-only assertion.
    ledger, clock = new_ledger()
    reservation = ledger.reserve(
        lease_id="lease-distinct", attempt_id="attempt-distinct", service="jira",
        route_id="jira.issue.get", request_digest=DIGEST, request_bytes=42,
        deadline=clock.value + 30.0, operation_id="operation-distinct",
    )
    clock.advance(7.0)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    assert receipt.generation == GENERATION
    assert receipt.lease_id == "lease-distinct"
    assert receipt.attempt_id == "attempt-distinct"
    assert receipt.operation_id == "operation-distinct"
    assert receipt.service == "jira"
    assert receipt.route_id == "jira.issue.get"
    assert receipt.request_digest == DIGEST
    assert receipt.request_bytes == 42
    assert receipt.started_monotonic == 1_000.0
    assert receipt.completed_monotonic == 1_007.0

    # Retention is measured from the true completion instant, not the start:
    # a completed_monotonic wrongly pinned to started_monotonic would prune
    # this entry seven seconds early.
    clock.advance(RETENTION_SECONDS - 0.001)
    assert len(ledger.snapshot()["entries"]) == 1
    clock.advance(0.001)
    assert ledger.snapshot()["entries"] == ()


def test_reservation_and_receipt_are_frozen_dataclasses():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    with pytest.raises(FrozenInstanceError):
        reservation.receipt_id = "other"  # type: ignore[misc]
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    with pytest.raises(FrozenInstanceError):
        receipt.reason = "tampered"  # type: ignore[misc]


# --- legal and illegal transitions ------------------------------------------


def test_full_dispatched_path_is_legal():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
        upstream_response=upstream(),
    )
    assert receipt.dispatch_state == "TRANSPORT_CONFIRMED"


def test_short_not_dispatched_path_skips_connect_and_dispatch():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="lease_denied")
    assert receipt.dispatch_state == "NOT_DISPATCHED"


def test_failed_path_requires_connecting_state():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    ledger.begin_connect(reservation)
    receipt = ledger.finalize(reservation, dispatch_state="FAILED", reason="connect_failed")
    assert receipt.dispatch_state == "FAILED"


@pytest.mark.parametrize("skip", ["begin_connect", "begin_dispatch_only"])
def test_out_of_order_transitions_are_rejected(skip):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    if skip == "begin_connect":
        assert_error(lambda: ledger.begin_dispatch(reservation), "invalid_transition")
    else:
        ledger.begin_connect(reservation)
        ledger.begin_dispatch(reservation)
        assert_error(lambda: ledger.begin_dispatch(reservation), "invalid_transition")
        assert_error(lambda: ledger.begin_connect(reservation), "invalid_transition")


def test_double_begin_connect_is_rejected():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    ledger.begin_connect(reservation)
    assert_error(lambda: ledger.begin_connect(reservation), "invalid_transition")


@pytest.mark.parametrize("from_state,bad_dispatch_state", [
    ("reserved", "FAILED"), ("reserved", "DISPATCHED_UNKNOWN"),
    ("reserved", "PARTIAL"), ("reserved", "TRANSPORT_CONFIRMED"),
    ("connecting", "NOT_DISPATCHED"), ("connecting", "PARTIAL"),
    ("connecting", "TRANSPORT_CONFIRMED"),
    ("dispatched", "NOT_DISPATCHED"), ("dispatched", "FAILED"),
])
def test_illegal_finalize_transitions_are_rejected(from_state, bad_dispatch_state):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, from_state)
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state=bad_dispatch_state, reason="deadline",
    ), "invalid_transition")


def test_finalize_after_finalize_is_rejected_as_already_finalized():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected")
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    ), "reservation_finalized")
    assert_error(lambda: ledger.begin_connect(reservation), "reservation_finalized")


@pytest.mark.parametrize("bad", [None, 1, "not-a-state", True])
def test_finalize_rejects_untyped_dispatch_state(bad):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    assert_error(lambda: ledger.finalize(reservation, dispatch_state=bad, reason="ok"),
                 "invalid_dispatch_state")


# --- every legal (state, reason) pair ---------------------------------------

_LEGAL_REASON_CASES = [
    ("reserved", "NOT_DISPATCHED", "request_rejected"),
    ("reserved", "NOT_DISPATCHED", "lease_denied"),
    ("reserved", "NOT_DISPATCHED", "route_denied"),
    ("reserved", "NOT_DISPATCHED", "permit_denied"),
    ("reserved", "NOT_DISPATCHED", "deadline"),
    ("connecting", "FAILED", "connect_failed"),
    ("connecting", "FAILED", "upstream_tls_failed"),
    ("connecting", "DISPATCHED_UNKNOWN", "write_failed"),
    ("connecting", "DISPATCHED_UNKNOWN", "receive_failed"),
    ("connecting", "DISPATCHED_UNKNOWN", "malformed_response"),
    ("connecting", "DISPATCHED_UNKNOWN", "deadline"),
    ("dispatched", "DISPATCHED_UNKNOWN", "write_failed"),
    ("dispatched", "PARTIAL", "response_incomplete"),
    ("dispatched", "PARTIAL", "response_overflow"),
]


@pytest.mark.parametrize("from_state,dispatch_state,reason", _LEGAL_REASON_CASES)
def test_every_legal_non_transport_state_reason_pair_finalizes(from_state, dispatch_state, reason):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, from_state)
    receipt = ledger.finalize(reservation, dispatch_state=dispatch_state, reason=reason)
    assert receipt.dispatch_state == dispatch_state and receipt.reason == reason
    assert receipt.http_status_class is None
    assert receipt.response_digest is None
    assert receipt.upstream_body_bytes is None
    kind = fr._REASON_LOCAL_RESPONSE[dispatch_state][reason]
    expected_digest, expected_bytes = fr._LOCAL_RESPONSE_DIGESTS[kind]
    assert receipt.client_response_digest == expected_digest
    assert receipt.client_response_bytes == expected_bytes
    assert local_response_for(receipt) is LOCAL_RESPONSES[kind]


@pytest.mark.parametrize("status", [200, 201, 299, 400, 404, 499, 500, 502, 599])
def test_transport_confirmed_ok_uses_the_upstream_response_itself(status):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")
    response = upstream(status, b'{"payload":true}')
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok", upstream_response=response,
    )
    wire = serialize_response(response)
    expected_class = "2xx" if status <= 299 else ("4xx" if status <= 499 else "5xx")
    assert receipt.http_status_class == expected_class
    assert receipt.response_digest == hashlib.sha256(wire).hexdigest()
    assert receipt.upstream_body_bytes == len(response.body)
    assert receipt.client_response_digest == receipt.response_digest
    assert receipt.client_response_bytes == len(wire)
    assert_error(lambda: local_response_for(receipt), "upstream_response_required")


def test_transport_confirmed_response_policy_rejected_does_not_leak_upstream_bytes():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")
    response = upstream(200, b'{"secret":"do-not-forward"}')
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=response,
    )
    # Correlation metadata still describes the real upstream response...
    assert receipt.http_status_class == "2xx"
    assert receipt.response_digest == hashlib.sha256(serialize_response(response)).hexdigest()
    assert receipt.upstream_body_bytes == len(response.body)
    # ...but the bytes approved for the client are the fixed local response.
    expected_digest, expected_bytes = fr._LOCAL_RESPONSE_DIGESTS["response_rejected"]
    assert receipt.client_response_digest == expected_digest
    assert receipt.client_response_bytes == expected_bytes
    assert receipt.client_response_digest != receipt.response_digest
    assert local_response_for(receipt) is LOCAL_RESPONSES["response_rejected"]


@pytest.mark.parametrize("from_state,dispatch_state,reason,upstream_response", [
    ("reserved", "NOT_DISPATCHED", "unknown_reason", None),
    ("reserved", "NOT_DISPATCHED", "ok", None),
    ("connecting", "DISPATCHED_UNKNOWN", "response_incomplete", None),
    ("dispatched", "PARTIAL", "malformed_response", None),
    ("dispatched", "TRANSPORT_CONFIRMED", "response_policy_rejected", None),
    ("dispatched", "TRANSPORT_CONFIRMED", "ok", "not-a-response"),
    ("connecting", "FAILED", "ok", None),
])
def test_reason_not_listed_or_missing_response_is_rejected(
    from_state, dispatch_state, reason, upstream_response,
):
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, from_state)
    if reason not in fr._REASON_LOCAL_RESPONSE.get(dispatch_state, {}):
        assert_error(lambda: ledger.finalize(
            reservation, dispatch_state=dispatch_state, reason=reason,
            upstream_response=upstream_response,
        ), "invalid_reason")
    else:
        assert_error(lambda: ledger.finalize(
            reservation, dispatch_state=dispatch_state, reason=reason,
            upstream_response=upstream_response,
        ), "invalid_upstream_response")


def test_abandoned_reason_is_a_legal_manual_finalize_too():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="abandoned")
    assert receipt.reason == "abandoned"
    assert local_response_for(receipt) is LOCAL_RESPONSES["unavailable"]


def test_non_transport_confirmed_finalize_rejects_a_supplied_upstream_response():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
        upstream_response=upstream(),
    ), "invalid_upstream_response")


def test_transport_confirmed_requires_an_exact_parsed_response_type():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    advance_to(ledger, reservation, "dispatched")

    class _FakeResponse(ParsedResponse):
        pass

    for bad in (None, "response", 200, _FakeResponse(200, b"x")):
        assert_error(lambda bad=bad: ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok", upstream_response=bad,
        ), "invalid_upstream_response")
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
        upstream_response=ParsedResponse(200, b""),
    ), "invalid_response")


# --- identity forgery --------------------------------------------------------


def test_forged_reservation_via_replace_or_copy_is_rejected():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    forged_replace = dataclasses.replace(reservation)
    forged_copy = copy.copy(reservation)
    forged_deepcopy = copy.deepcopy(reservation)
    for forged in (forged_replace, forged_copy, forged_deepcopy):
        assert forged == reservation and forged is not reservation
        assert_error(lambda forged=forged: ledger.begin_connect(forged), "reservation_unknown")
        assert_error(lambda forged=forged: ledger.finalize(
            forged, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
        ), "reservation_unknown")
    # The genuine instance still works.
    ledger.begin_connect(reservation)


def test_unknown_reservation_is_rejected():
    ledger, clock = new_ledger()
    reserve(ledger, clock)
    stranger = ReceiptReservation(receipt_id="receipt_does-not-exist")
    assert_error(lambda: ledger.begin_connect(stranger), "reservation_unknown")
    assert_error(lambda: ledger.finalize(
        stranger, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    ), "reservation_unknown")


@pytest.mark.parametrize("bad", [None, "reservation", 1, object()])
def test_non_reservation_types_are_rejected(bad):
    ledger, _clock = new_ledger()
    assert_error(lambda: ledger.begin_connect(bad), "reservation_unknown")


def test_forged_receipt_via_replace_or_copy_is_rejected():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    receipt = ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    forged = dataclasses.replace(receipt)
    assert forged == receipt and forged is not receipt
    assert ledger.contains(receipt) is True
    assert ledger.contains(forged) is False
    assert_error(lambda: ledger.claim_delivery(
        forged, client_response_digest=receipt.client_response_digest,
    ), "receipt_unknown")
    assert_error(
        lambda: ledger.complete_delivery(forged, outcome="sent", bytes_sent=0), "claim_unknown",
    )
    claim(ledger, receipt)  # the genuine instance still works


@pytest.mark.parametrize("bad", [None, "receipt", 1, object()])
def test_non_receipt_types_are_rejected(bad):
    ledger, _clock = new_ledger()
    assert_error(lambda: ledger.claim_delivery(bad, client_response_digest=DIGEST), "receipt_unknown")
    assert ledger.contains(bad) is False


def test_forged_reservation_with_an_unhashable_receipt_id_is_rejected_not_raised():
    # A dict lookup on an unhashable receipt_id (e.g. a list) would otherwise
    # raise a raw TypeError instead of the module's fixed, non-diagnostic code.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    forged_reservation = ReceiptReservation(receipt_id=["not-hashable"])  # type: ignore[arg-type]
    assert_error(lambda: ledger.begin_connect(forged_reservation), "reservation_unknown")
    assert_error(lambda: ledger.finalize(
        forged_reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    ), "reservation_unknown")
    ledger.begin_connect(reservation)  # the real instance still works


def test_forged_receipt_with_an_unhashable_receipt_id_is_rejected_not_raised():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    bad_id: list[str] = ["not-hashable"]
    forged_receipt = dataclasses.replace(receipt, receipt_id=bad_id)  # type: ignore[arg-type]
    assert ledger.contains(forged_receipt) is False
    assert_error(lambda: ledger.claim_delivery(
        forged_receipt, client_response_digest=receipt.client_response_digest,
    ), "receipt_unknown")
    assert_error(
        lambda: ledger.complete_delivery(forged_receipt, outcome="sent", bytes_sent=0),
        "claim_unknown",
    )
    claim(ledger, receipt)  # the real instance still works


def test_local_response_for_with_unhashable_dispatch_state_or_reason_is_rejected():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    bad_value: list[str] = ["not-hashable"]
    forged_state = dataclasses.replace(receipt, dispatch_state=bad_value)  # type: ignore[arg-type]
    assert_error(lambda: local_response_for(forged_state), "invalid_receipt")
    forged_reason = dataclasses.replace(receipt, reason=bad_value)  # type: ignore[arg-type]
    assert_error(lambda: local_response_for(forged_reason), "invalid_receipt")


def test_receipt_from_a_different_ledger_is_unknown_here():
    ledger_a, clock_a = new_ledger()
    ledger_b, _clock_b = new_ledger()
    reservation_a = reserve(ledger_a, clock_a)
    receipt_a = ledger_a.finalize(
        reservation_a, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    )
    assert ledger_b.contains(receipt_a) is False
    assert_error(lambda: ledger_b.claim_delivery(
        receipt_a, client_response_digest=receipt_a.client_response_digest,
    ), "receipt_unknown")


# --- delivery claim rules ----------------------------------------------------


def _finalized(ledger, clock, **reserve_kwargs):
    reservation = reserve(ledger, clock, **reserve_kwargs)
    return ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected")


def claim(ledger: ReceiptLedger, receipt) -> DeliveryClaim:
    """Claim delivery for ``receipt`` using its own (correct) wire digest."""
    return ledger.claim_delivery(receipt, client_response_digest=receipt.client_response_digest)


def test_claim_delivery_requires_pending_and_is_one_use():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    assert isinstance(delivery_claim, DeliveryClaim)
    assert delivery_claim.receipt_id == receipt.receipt_id
    assert_error(lambda: claim(ledger, receipt), "delivery_claimed")


@pytest.mark.parametrize("bad_digest", [
    "f" * 64,  # well-formed hex but the wrong value
    "F" * 64,  # uppercase hex is not the lowercase wire digest
    "g" * 64,  # not a hex character
    "a" * 63,  # too short
    "a" * 65,  # too long
    b"a" * 64,  # bytes, not str
    "",
    None,
    1,
    True,
    # F2-6: non-ASCII strings pass the length check but must still be
    # rejected as receipt_mismatch by the hex-membership guard, never reach
    # hmac.compare_digest (which raises TypeError on non-ASCII str input).
    "é" * 64,
    "0" * 63 + "é",
    "０" * 64,  # full-width digit "0", not an ASCII hex character
])
def test_claim_delivery_rejects_wrong_or_malformed_digest_leaving_entry_pending(bad_digest):
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    assert_error(
        lambda: ledger.claim_delivery(receipt, client_response_digest=bad_digest),
        "receipt_mismatch",
    )
    # The rejection left the entry unchanged: delivery is still pending...
    entry = ledger.snapshot()["entries"][0]
    assert entry["delivery_outcome"] == "pending"
    # ...so a later, correct claim succeeds.
    delivery_claim = claim(ledger, receipt)
    assert isinstance(delivery_claim, DeliveryClaim)


def test_rejected_claim_attempt_on_a_sending_entry_leaves_the_issued_claim_usable():
    # F1-4: a rejection must leave the entry unchanged even when it already
    # has a live claim (not just when it is still "pending" -- every other
    # rejection test above only covers the pending case). Simulates a buggy
    # caller or a second handler thread racing send_response for the same
    # receipt on another connection: the ledger must refuse the second
    # attempt without breaking the first, still-outstanding claim.
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)  # first caller's claim: entry is "sending"

    assert_error(lambda: ledger.claim_delivery(
        receipt, client_response_digest="f" * 64,
    ), "receipt_mismatch")
    assert_error(lambda: claim(ledger, receipt), "delivery_claimed")
    assert ledger.snapshot()["entries"][0]["delivery_outcome"] == "sending"

    # The original claim -- issued before either rejected attempt -- still
    # completes normally.
    ledger.complete_delivery(
        delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes,
    )
    assert ledger.snapshot()["entries"][0]["delivery_outcome"] == "sent"


def test_forged_delivery_claim_via_replace_or_copy_is_rejected():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    forged_replace = dataclasses.replace(delivery_claim)
    forged_copy = copy.copy(delivery_claim)
    forged_deepcopy = copy.deepcopy(delivery_claim)
    for forged in (forged_replace, forged_copy, forged_deepcopy):
        assert forged == delivery_claim and forged is not delivery_claim
        assert_error(lambda forged=forged: ledger.complete_delivery(
            forged, outcome="sent", bytes_sent=receipt.client_response_bytes,
        ), "claim_unknown")
    # The genuine instance still works.
    ledger.complete_delivery(delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes)


def test_complete_delivery_without_a_prior_claim_is_claim_unknown():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    # No claim was ever issued for this entry: a freshly constructed
    # DeliveryClaim naming its receipt_id is a well-typed but never-issued
    # (foreign) claim, not the exact instance the ledger would hand out.
    never_issued = DeliveryClaim(receipt_id=receipt.receipt_id)
    assert_error(lambda: ledger.complete_delivery(never_issued, outcome="sent", bytes_sent=0),
                 "claim_unknown")


def test_complete_delivery_after_retention_prune_is_claim_unknown():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    clock.advance(RETENTION_SECONDS + 1.0)
    assert ledger.snapshot()["entries"] == ()  # pruned while still "sending"
    assert_error(lambda: ledger.complete_delivery(
        delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes,
    ), "claim_unknown")


def test_complete_delivery_sent_requires_exact_full_byte_count():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    assert_error(lambda: ledger.complete_delivery(
        delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes - 1,
    ), "invalid_bytes_sent")
    ledger.complete_delivery(delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes)
    assert ledger.snapshot()["entries"][0]["delivery_outcome"] == "sent"


def test_complete_delivery_not_sent_requires_exactly_zero():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    assert_error(lambda: ledger.complete_delivery(delivery_claim, outcome="not_sent", bytes_sent=1),
                 "invalid_bytes_sent")
    ledger.complete_delivery(delivery_claim, outcome="not_sent", bytes_sent=0)


@pytest.mark.parametrize("bytes_sent", [0, 1])
def test_complete_delivery_send_unknown_allows_any_in_range_count(bytes_sent):
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    ledger.complete_delivery(delivery_claim, outcome="send_unknown", bytes_sent=bytes_sent)


@pytest.mark.parametrize("bytes_sent", [-1, True, False, 1.0, "0", None])
def test_complete_delivery_bytes_sent_is_strictly_typed(bytes_sent):
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    assert_error(lambda: ledger.complete_delivery(
        delivery_claim, outcome="send_unknown", bytes_sent=bytes_sent,
    ), "invalid_bytes_sent")


def test_complete_delivery_bytes_sent_cannot_exceed_client_response_bytes():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    assert_error(lambda: ledger.complete_delivery(
        delivery_claim, outcome="send_unknown", bytes_sent=receipt.client_response_bytes + 1,
    ), "invalid_bytes_sent")


@pytest.mark.parametrize("outcome", ["pending", "sending", "bogus", None, 1, True])
def test_complete_delivery_outcome_is_strictly_validated(outcome):
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    assert_error(lambda: ledger.complete_delivery(delivery_claim, outcome=outcome, bytes_sent=0),
                 "invalid_delivery_outcome")


def test_complete_delivery_is_terminal():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    ledger.complete_delivery(delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes)
    assert_error(lambda: ledger.complete_delivery(delivery_claim, outcome="sent",
                                                  bytes_sent=receipt.client_response_bytes),
                 "delivery_completed")
    assert_error(lambda: claim(ledger, receipt), "delivery_claimed")


def test_receipt_error_is_a_value_error_subclass():
    assert issubclass(ReceiptError, ValueError)
    error = ReceiptError("some_code")
    assert isinstance(error, ValueError)
    assert error.code == "some_code"
    assert str(error) == "some_code"


def test_snapshot_and_retention_read_the_private_copy_not_the_callers_receipt():
    # The ledger hands the caller a ForwarderReceipt used only for identity
    # and keeps an equal private copy; in-place mutation of the caller's
    # frozen instance (via object.__setattr__, bypassing dataclass immutability)
    # must not alter what snapshot() reports, what claim_delivery compares
    # against, or when retention prunes the entry.
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    original_completed = receipt.completed_monotonic
    original_digest = receipt.client_response_digest
    object.__setattr__(receipt, "completed_monotonic", original_completed - 1000.0)
    object.__setattr__(receipt, "client_response_digest", "f" * 64)

    entry = ledger.snapshot()["entries"][0]
    assert entry["completed_monotonic"] == original_completed
    assert entry["client_response_digest"] == original_digest

    # A claim using the mutated (now-wrong) digest value still fails: the
    # ledger compares against its private record, never re-derives the
    # expected digest from the caller's own (tamperable) receipt fields.
    assert_error(lambda: ledger.claim_delivery(
        receipt, client_response_digest=receipt.client_response_digest,
    ), "receipt_mismatch")
    # The real (unmutated) digest value still succeeds.
    delivery_claim = ledger.claim_delivery(receipt, client_response_digest=original_digest)
    ledger.complete_delivery(delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes)

    # Retention timing uses the private record's real completed_monotonic,
    # not the mutated (1000s-earlier) value on the caller's instance: the
    # entry survives up to the real boundary...
    clock.advance(RETENTION_SECONDS - 0.1)
    assert len(ledger.snapshot()["entries"]) == 1
    # ...and is pruned only once the real completed_monotonic's window elapses.
    clock.advance(0.2)
    assert ledger.snapshot()["entries"] == ()


# --- abandonment sweep -------------------------------------------------------


def test_abandonment_from_reserved_is_not_dispatched():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10)
    clock.advance(10)
    assert_error(lambda: ledger.begin_connect(reservation), "deadline_expired")
    entry = ledger.snapshot()["entries"][0]
    assert entry["dispatch_state"] == "NOT_DISPATCHED" and entry["reason"] == "abandoned"
    assert entry["entry_state"] == "finalized"


def test_abandonment_from_connecting_is_dispatched_unknown():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10)
    ledger.begin_connect(reservation)
    clock.advance(10)
    assert_error(lambda: ledger.begin_dispatch(reservation), "deadline_expired")
    entry = ledger.snapshot()["entries"][0]
    assert entry["dispatch_state"] == "DISPATCHED_UNKNOWN" and entry["reason"] == "abandoned"


def test_abandonment_from_dispatched_is_dispatched_unknown():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10)
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    clock.advance(10)
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
        upstream_response=upstream(),
    ), "deadline_expired")
    entry = ledger.snapshot()["entries"][0]
    assert entry["dispatch_state"] == "DISPATCHED_UNKNOWN" and entry["reason"] == "abandoned"


def test_abandoned_receipt_is_recorded_but_the_late_handler_cannot_finalize_or_deliver_it():
    # No public API ever hands the late caller a usable ForwarderReceipt for
    # the entry the sweep abandoned: finalize() (the only way to obtain one)
    # fails deadline_expired, so "delivery still works" for it is never true.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10)
    clock.advance(10)
    # Any public call triggers the sweep; use snapshot to observe it directly.
    snapshot = ledger.snapshot()
    receipt_meta = snapshot["entries"][0]
    assert receipt_meta["delivery_outcome"] == "pending"
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    ), "deadline_expired")
    matching = [
        entry for entry in ledger.snapshot()["entries"]
        if entry["receipt_id"] == reservation.receipt_id
    ]
    assert matching


def test_deadline_boundary_is_inclusive_of_abandonment():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10)
    clock.advance(10 - 0.001)
    ledger.begin_connect(reservation)  # not yet expired
    clock.advance(0.001)
    assert_error(lambda: ledger.begin_dispatch(reservation), "deadline_expired")


def test_abandoned_entry_is_stamped_at_its_deadline_not_at_lazy_sweep_time():
    # The sweep only runs at the start of the next public operation, which
    # can be long after the deadline actually passed. completed_monotonic
    # must still be pinned to the deadline itself: retention is measured
    # from it, so stamping the (later) detection time instead would hold
    # capacity for far longer than RETENTION_SECONDS past the real deadline.
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=10)
    deadline = clock.value + 10
    clock.advance(200)  # the first sweep runs well after the deadline passed
    snapshot = ledger.snapshot()
    entry = snapshot["entries"][0]
    assert entry["receipt_id"] == reservation.receipt_id
    assert entry["completed_monotonic"] == deadline
    clock.value = deadline + RETENTION_SECONDS - 0.001
    assert len(ledger.snapshot()["entries"]) == 1
    clock.value = deadline + RETENTION_SECONDS
    final_snapshot = ledger.snapshot()
    assert final_snapshot["entries"] == ()
    assert final_snapshot["charged_bytes"] == 0


def test_explicit_abandoned_finalize_is_not_misreported_as_deadline_expired():
    # "abandoned" is also a legal reason for a caller's own finalize() call,
    # not only for the internal deadline sweep (see the reason table and
    # test_abandoned_reason_is_a_legal_manual_finalize_too above). A later
    # call on that already-finalized entry must report reservation_finalized
    # when the deadline genuinely has not passed, never deadline_expired just
    # because the reason string happens to be "abandoned".
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock, ttl=30.0)
    ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="abandoned")
    clock.advance(5.0)  # still well inside the original deadline
    assert_error(lambda: ledger.begin_connect(reservation), "reservation_finalized")
    assert_error(lambda: ledger.finalize(
        reservation, dispatch_state="NOT_DISPATCHED", reason="request_rejected",
    ), "reservation_finalized")


# --- retention ---------------------------------------------------------------


def test_retention_prunes_only_after_310_seconds_and_frees_charge():
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    charge = ledger.snapshot()["entries"][0]["charge"]
    assert ledger.snapshot()["charged_bytes"] == charge
    clock.advance(RETENTION_SECONDS - 0.1)
    assert len(ledger.snapshot()["entries"]) == 1
    clock.advance(0.2)
    snapshot = ledger.snapshot()
    assert snapshot["entries"] == ()
    assert snapshot["charged_bytes"] == 0
    assert ledger.contains(receipt) is False


def test_an_uncompleted_sending_entry_is_still_pruned_at_the_retention_boundary():
    # Retention is a hard, unconditional bound ("at most 310 seconds" in the
    # specification; the plan states no exception for delivery_outcome): a
    # delivery that was claimed and never completed -- a genuine bug or an
    # unrecoverable crash elsewhere -- must not be able to hold its slot and
    # byte charge forever just because it is still nominally "sending".
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    claim(ledger, receipt)
    clock.advance(RETENTION_SECONDS + 100)
    snapshot = ledger.snapshot()
    assert snapshot["entries"] == ()
    assert snapshot["charged_bytes"] == 0
    assert ledger.contains(receipt) is False


def test_sending_entry_survives_until_retention_actually_elapses():
    # The unconditional prune above must still respect the 310-second bound
    # itself, not prune a "sending" entry early just because it is claimed.
    ledger, clock = new_ledger()
    receipt = _finalized(ledger, clock)
    delivery_claim = claim(ledger, receipt)
    clock.advance(RETENTION_SECONDS - 0.1)
    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["delivery_outcome"] == "sending"
    # The outcome can still be recorded before retention elapses.
    ledger.complete_delivery(delivery_claim, outcome="sent", bytes_sent=receipt.client_response_bytes)


def test_sweep_runs_before_prune_within_a_single_now_call(monkeypatch):
    # _now() must sweep (finalize any now-abandoned entry) before pruning
    # (drop any long-finalized entry) in the SAME call: an entry that is
    # still "reserved" when the clock jumps straight past
    # deadline + RETENTION_SECONDS must be finalized then immediately
    # pruned in that one call, not left occupying capacity because prune ran
    # first (while it was still unfinalized, so prune skipped it) and sweep
    # only finalized it afterward with no second prune pass to catch it. No
    # intervening snapshot()/contains() call is used here (that would sweep
    # and prune a second time, masking a wrong ordering).
    monkeypatch.setattr(fr, "MAX_RECEIPTS", 4)
    ledger, clock = new_ledger()
    for index in range(4):
        reserve(ledger, clock, lease_id=f"lease-{index}", attempt_id=f"attempt-{index}", ttl=10.0)
    clock.value += 10.0 + RETENTION_SECONDS  # straight past deadline + retention, in one jump
    reservation = reserve(ledger, clock, lease_id="after", attempt_id="after")
    assert reservation.receipt_id
    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["receipt_id"] == reservation.receipt_id


def test_retention_pruning_frees_capacity_for_a_new_reservation():
    ledger, clock = new_ledger()
    for index in range(MAX_RECEIPTS):
        _finalized(ledger, clock, lease_id=f"lease-{index}", attempt_id=f"attempt-{index}")
    assert_error(lambda: reserve(ledger, clock, lease_id="overflow", attempt_id="overflow"),
                 "capacity_records")
    clock.advance(RETENTION_SECONDS)
    reservation = reserve(ledger, clock, lease_id="after-retention", attempt_id="after-retention")
    assert reservation.receipt_id


# --- count and byte capacity, without eviction -------------------------------


def test_count_capacity_refuses_without_eviction():
    ledger, clock = new_ledger()
    for index in range(MAX_RECEIPTS):
        reserve(ledger, clock, lease_id=f"lease-{index}", attempt_id=f"attempt-{index}")
    before = ledger.snapshot()
    assert len(before["entries"]) == MAX_RECEIPTS
    assert_error(lambda: reserve(ledger, clock, lease_id="overflow", attempt_id="overflow"),
                 "capacity_records")
    after = ledger.snapshot()
    assert len(after["entries"]) == MAX_RECEIPTS
    assert before["charged_bytes"] == after["charged_bytes"]


def test_byte_capacity_triggers_before_count_capacity_with_long_ids():
    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "r" * 128
    accepted = 0
    with pytest.raises(ReceiptError) as caught:
        for index in range(MAX_RECEIPTS):
            reserve(
                ledger, clock, lease_id=long_id, attempt_id=long_id, service="kubernetes",
                route_id=long_id, operation_id=long_id, request_bytes=MAX_REQUEST_BYTES,
            )
            accepted += 1
    assert caught.value.code == "capacity_bytes"
    assert accepted < MAX_RECEIPTS  # the byte cap won, not the count cap
    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == accepted  # no eviction happened
    assert snapshot["charged_bytes"] <= MAX_LEDGER_BYTES


def test_charge_never_exceeds_max_receipt_bytes_at_maximum_field_lengths():
    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "z" * 128
    reservation = ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="anthropic", route_id=long_id,
        operation_id=long_id, request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + MAX_HANDLER_SECONDS,
    )
    charge = ledger.snapshot()["entries"][0]["charge"]
    assert charge <= MAX_RECEIPT_BYTES
    assert reservation.receipt_id


def test_capacity_bytes_boundary_allows_an_exact_fit(monkeypatch):
    # The plan's capacity check is "exceeds MAX_LEDGER_BYTES" (strict `>`):
    # a reservation whose charge exactly fills the remaining budget must
    # still be admitted, not rejected as if it overflowed by one byte.
    probe_ledger, probe_clock = new_ledger()
    reserve(probe_ledger, probe_clock)
    charge = probe_ledger.snapshot()["entries"][0]["charge"]
    monkeypatch.setattr(fr, "MAX_LEDGER_BYTES", charge)
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    assert reservation.receipt_id
    assert ledger.snapshot()["charged_bytes"] == charge


def test_charge_bounds_the_full_entry_including_delivery_bytes_sent():
    # snapshot() also returns delivery_bytes_sent per entry, so the charge
    # must cover it too, or a fully-realized delivered record could exceed
    # its own charge even though MAX_LEDGER_BYTES accounting stays compliant.
    ledger, clock = new_ledger(generation="g" * 128)
    long_id = "q" * 128
    reservation = ledger.reserve(
        lease_id=long_id, attempt_id=long_id, service="anthropic", route_id=long_id,
        operation_id=long_id, request_digest=DIGEST, request_bytes=MAX_REQUEST_BYTES,
        deadline=clock.value + MAX_HANDLER_SECONDS,
    )
    charge = ledger.snapshot()["entries"][0]["charge"]
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    body = b"1" * 4096
    receipt = ledger.finalize(
        reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=ParsedResponse(200, body),
    )
    delivery_claim = claim(ledger, receipt)
    ledger.complete_delivery(
        delivery_claim, outcome="send_unknown", bytes_sent=receipt.client_response_bytes,
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
    size = len(
        json.dumps(actual, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )
    assert size <= charge


# --- clock faults ------------------------------------------------------------


def test_clock_exception_permanently_holds_the_ledger():
    class ExplodingClock:
        def __init__(self):
            self.fail = True

        def __call__(self):
            if self.fail:
                raise RuntimeError("clock unavailable")
            return 2_000.0

    clock = ExplodingClock()
    ledger = ReceiptLedger(generation=GENERATION, clock=clock)
    assert_error(lambda: reserve(ledger, FakeClock()), "clock_invalid")
    clock.fail = False
    assert_error(lambda: reserve(ledger, FakeClock()), "ledger_held")
    assert ledger.snapshot()["ledger_state"] == "held"


@pytest.mark.parametrize("bad_value", [math.nan, math.inf, -math.inf, 10**1000])
def test_clock_non_finite_or_huge_value_holds_the_ledger(bad_value):
    ledger = ReceiptLedger(generation=GENERATION, clock=lambda: bad_value)
    assert_error(lambda: reserve(ledger, FakeClock()), "clock_invalid")
    assert ledger.snapshot()["ledger_state"] == "held"


def test_clock_regression_permanently_holds_the_ledger():
    ledger, clock = new_ledger()
    reserve(ledger, clock)
    clock.value -= 1
    assert_error(lambda: reserve(ledger, clock, lease_id="l2", attempt_id="a2"), "clock_regressed")
    clock.value += 5  # even a later, non-regressed value cannot lift the hold
    assert_error(lambda: reserve(ledger, clock, lease_id="l3", attempt_id="a3"), "ledger_held")
    assert ledger.snapshot()["ledger_state"] == "held"


def test_snapshot_remains_readable_while_held_without_advancing_clock():
    ledger, clock = new_ledger()
    reservation = reserve(ledger, clock)
    clock.value = math.nan
    snapshot = ledger.snapshot()
    assert snapshot["ledger_state"] == "held"
    assert len(snapshot["entries"]) == 1
    assert snapshot["entries"][0]["receipt_id"] == reservation.receipt_id


def test_held_snapshot_does_not_use_a_later_valid_clock_reading():
    # Unlike the NaN-clock case above, this forces the hold via regression:
    # the clock keeps returning perfectly valid (if bogus) later readings.
    # snapshot() must still sweep/prune using the last *good* reading from
    # before the hold, never a later reading observed while held -- or it
    # would abandon/prune entries using an untrustworthy "now".
    ledger, clock = new_ledger()
    first = reserve(ledger, clock, lease_id="first", attempt_id="first", ttl=30.0)
    second = reserve(ledger, clock, lease_id="second", attempt_id="second", ttl=30.0)
    ledger.finalize(second, dispatch_state="NOT_DISPATCHED", reason="request_rejected")
    clock.value -= 1  # force a hold via clock regression
    assert_error(lambda: reserve(ledger, clock, lease_id="third", attempt_id="third"),
                 "clock_regressed")
    clock.value += 10_000  # a much later, perfectly valid reading must not be used
    snapshot = ledger.snapshot()
    assert snapshot["ledger_state"] == "held"
    assert len(snapshot["entries"]) == 2
    first_entry = next(e for e in snapshot["entries"] if e["receipt_id"] == first.receipt_id)
    assert first_entry["entry_state"] == "reserved"  # not abandoned by the later reading


def test_clock_reading_of_exactly_zero_is_accepted_as_a_valid_now():
    # The clock contract is "exact finite non-negative int/float": zero is a
    # legal boundary value, not a fault, so a ledger whose injected clock
    # starts at 0 must reserve normally and stay ready.
    ledger = ReceiptLedger(generation=GENERATION, clock=lambda: 0)
    reservation = ledger.reserve(
        lease_id="lease-1", attempt_id="attempt-1", service="jira", route_id="jira.issue.get",
        request_digest=DIGEST, request_bytes=10, deadline=10,
    )
    assert reservation.receipt_id
    assert ledger.snapshot()["ledger_state"] == "ready"


def test_reserve_accepts_an_exact_int_deadline():
    # Every other test in this suite derives its deadline from a float clock
    # value; an exact int now/deadline pair must be accepted too.
    ledger = ReceiptLedger(generation=GENERATION, clock=lambda: 1000)
    reservation = ledger.reserve(
        lease_id="lease-1", attempt_id="attempt-1", service="jira", route_id="jira.issue.get",
        request_digest=DIGEST, request_bytes=10, deadline=1030,
    )
    assert reservation.receipt_id


def test_reserve_rejects_a_charge_exceeding_max_receipt_bytes(monkeypatch):
    ledger, clock = new_ledger()
    monkeypatch.setattr(fr, "MAX_RECEIPT_BYTES", 100)
    before = ledger.snapshot()
    assert_error(lambda: reserve(ledger, clock), "receipt_too_large")
    after = ledger.snapshot()
    assert after == before  # the rejected reservation left no trace


def test_clock_must_be_callable():
    with pytest.raises(TypeError):
        ReceiptLedger(generation=GENERATION, clock="not-callable")  # type: ignore[arg-type]


@pytest.mark.parametrize("generation", [None, "", "x" * 129, "bad space", 1, True])
def test_generation_is_validated_as_a_safe_id(generation):
    with pytest.raises(ReceiptError):
        ReceiptLedger(generation=generation)


# --- snapshot shape ------------------------------------------------------------


def test_snapshot_shape_and_counts_by_state():
    ledger, clock = new_ledger()
    reserved = reserve(ledger, clock, lease_id="r", attempt_id="r")
    connecting = reserve(ledger, clock, lease_id="c", attempt_id="c")
    ledger.begin_connect(connecting)
    dispatched = reserve(ledger, clock, lease_id="d", attempt_id="d")
    ledger.begin_connect(dispatched)
    ledger.begin_dispatch(dispatched)
    finalized = reserve(ledger, clock, lease_id="f", attempt_id="f")
    ledger.finalize(finalized, dispatch_state="NOT_DISPATCHED", reason="request_rejected")

    snapshot = ledger.snapshot()
    assert set(snapshot) == {
        "generation", "ledger_state", "counts_by_state", "charged_bytes", "entries",
    }
    assert snapshot["generation"] == GENERATION
    assert snapshot["ledger_state"] == "ready"
    assert snapshot["counts_by_state"] == {
        "reserved": 1, "connecting": 1, "dispatched": 1, "finalized": 1,
    }
    assert len(snapshot["entries"]) == 4
    assert snapshot["charged_bytes"] == sum(entry["charge"] for entry in snapshot["entries"])
    receipt_ids = {entry["receipt_id"] for entry in snapshot["entries"]}
    assert receipt_ids == {reserved.receipt_id, connecting.receipt_id,
                          dispatched.receipt_id, finalized.receipt_id}
    assert reserved.receipt_id  # no secrets/sentinels exist to assert absent


# --- concurrency smoke test ---------------------------------------------------


def test_concurrent_reserves_never_exceed_max_receipts(monkeypatch):
    monkeypatch.setattr(fr, "MAX_RECEIPTS", 16)
    ledger, clock = new_ledger()
    barrier = Barrier(40)

    def attempt(index: int) -> bool:
        barrier.wait()
        try:
            reserve(ledger, clock, lease_id=f"lease-{index}", attempt_id=f"attempt-{index}")
            return True
        except ReceiptError as error:
            assert error.code == "capacity_records"
            return False

    with ThreadPoolExecutor(max_workers=40) as pool:
        results = list(pool.map(attempt, range(40)))

    assert sum(results) == 16
    snapshot = ledger.snapshot()
    assert len(snapshot["entries"]) == 16
