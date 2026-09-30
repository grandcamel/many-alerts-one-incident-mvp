"""Deterministic fake-socket tests for receipt-gated client-response delivery.

Nothing here opens a real socket or a real connection: a fake ``_Socket``
stands in for ``ssl.SSLSocket`` (monkeypatched into the module under test,
mirroring ``tests/test_forwarder_response_receive.py``), and both the send
module's own ``time.monotonic`` and the ledger's injected clock are fake and
independently controlled.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import ssl
import threading
import time

import pytest

from grafana_jsm_sandbox import forwarder_response_send
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, serialize_response
from grafana_jsm_sandbox.forwarder_receipts import ForwarderReceipt, ReceiptError, ReceiptLedger
from grafana_jsm_sandbox.forwarder_response_send import (
    DeliveryResult,
    ResponseSendError,
    send_response,
)

DIGEST = hashlib.sha256(b"fixed-request").hexdigest()


class FakeLedgerClock:
    """The ledger's own injected clock; independent of the send module's clock."""

    def __init__(self, value: float = 1_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def new_ledger(generation: str = "generation-a") -> tuple[ReceiptLedger, FakeLedgerClock]:
    clock = FakeLedgerClock()
    return ReceiptLedger(generation=generation, clock=clock), clock


def make_receipt(
    ledger: ReceiptLedger,
    clock: FakeLedgerClock,
    *,
    dispatch_state: str = "NOT_DISPATCHED",
    reason: str = "request_rejected",
    upstream_response: ParsedResponse | None = None,
    lease_id: str = "lease-1",
    attempt_id: str = "attempt-1",
    service: str = "jira",
    route_id: str = "jira.issue.get",
    ttl: float = 30.0,
) -> ForwarderReceipt:
    """Build one genuine, finalized receipt via the real Module-1 ledger."""
    reservation = ledger.reserve(
        lease_id=lease_id, attempt_id=attempt_id, service=service, route_id=route_id,
        request_digest=DIGEST, request_bytes=10, deadline=clock.value + ttl,
    )
    if dispatch_state == "FAILED":
        ledger.begin_connect(reservation)
    elif dispatch_state in ("DISPATCHED_UNKNOWN", "PARTIAL", "TRANSPORT_CONFIRMED"):
        ledger.begin_connect(reservation)
        ledger.begin_dispatch(reservation)
    return ledger.finalize(
        reservation, dispatch_state=dispatch_state, reason=reason,
        upstream_response=upstream_response,
    )


def confirmed_receipt(ledger, clock, response: ParsedResponse, **kwargs) -> ForwarderReceipt:
    return make_receipt(
        ledger, clock, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
        upstream_response=response, **kwargs,
    )


class _Context:
    def __init__(self, protocol=ssl.PROTOCOL_TLS_SERVER):
        self.protocol = protocol


class _Socket:
    """A fake server-side ``ssl.SSLSocket`` whose ``send`` follows a fixed plan.

    ``send_plan`` is a list consumed one entry per ``send()`` call: an int is
    returned as the byte count actually accepted (a short entry simulates a
    partial write); a ``BaseException`` instance is raised instead. Once the
    plan is exhausted, ``send`` returns the full chunk length.
    """

    def __init__(
        self, send_plan=None, *, version="TLSv1.3", server_side=True,
        fileno=7, protocol=ssl.PROTOCOL_TLS_SERVER, restore_error=None,
    ):
        self.context = _Context(protocol)
        self.server_side = server_side
        self._version = version
        self._fileno = fileno
        self.timeout = 2.0
        self.restore_error = restore_error
        self.send_plan = list(send_plan) if send_plan is not None else None
        self.offered: list[bytes] = []  # every chunk passed to send(), regardless of outcome
        self.accepted: list[bytes] = []  # the prefix of each chunk actually "sent"
        self.timeout_history: list[float] = []
        self.closed = self.shutdowns = 0

    def fileno(self):
        return self._fileno

    def version(self):
        return self._version

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        if value == 2.0 and self.restore_error:
            raise self.restore_error
        self.timeout = value
        self.timeout_history.append(value)

    def send(self, data):
        chunk = bytes(data)
        self.offered.append(chunk)
        if self.send_plan is not None and self.send_plan:
            action = self.send_plan.pop(0)
            if isinstance(action, BaseException):
                raise action
            if type(action) is int and not isinstance(action, bool) and action > 0:
                self.accepted.append(chunk[:action])
            return action
        self.accepted.append(chunk)
        return len(chunk)

    def close(self):
        self.closed += 1

    def shutdown(self, _how):
        self.shutdowns += 1


def _install(monkeypatch, socket, clock=lambda: 10.0):
    monkeypatch.setattr(forwarder_response_send.ssl, "SSLSocket", type(socket))
    monkeypatch.setattr(forwarder_response_send.time, "monotonic", clock)


def _error(call, code: str | None = None) -> ResponseSendError:
    with pytest.raises(ResponseSendError) as raised:
        call()
    assert raised.value.code and str(raised.value) == raised.value.code
    if code:
        assert raised.value.code == code
    return raised.value


def _entry_for(ledger: ReceiptLedger, receipt: ForwarderReceipt) -> dict:
    for entry in ledger.snapshot()["entries"]:
        if entry["receipt_id"] == receipt.receipt_id:
            return entry
    raise AssertionError("receipt not found in ledger snapshot")


def _unclaimed_delivery_outcome(ledger: ReceiptLedger, receipt: ForwarderReceipt) -> str:
    return _entry_for(ledger, receipt)["delivery_outcome"]


# --- happy path: exact chunk sizes and full delivery ------------------------


def test_full_send_records_sent_and_returns_delivery_result(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    receipt = make_receipt(ledger, lclock)
    response = LOCAL_RESPONSES["invalid_request"]
    wire = serialize_response(response)
    socket = _Socket()
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, response, deadline=40)

    assert result == DeliveryResult(receipt.receipt_id, "sent", len(wire))
    assert b"".join(socket.accepted) == wire
    assert _unclaimed_delivery_outcome(ledger, receipt) == "sent"
    assert not (socket.closed or socket.shutdowns)


def test_large_body_is_sent_in_16384_byte_chunks(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"x" * 40_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    wire = serialize_response(response)
    socket = _Socket()
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, response, deadline=40)

    assert result.outcome == "sent"
    assert result.bytes_sent == len(wire)
    assert b"".join(socket.accepted) == wire
    assert all(len(chunk) <= 16384 for chunk in socket.offered)
    # 40000-byte body plus a short header: five full 16384-byte chunks would
    # overshoot, so this must take more than two chunks.
    assert len(socket.offered) >= 3


def test_partial_writes_continue_with_the_unsent_remainder(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"y" * 20_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    wire = serialize_response(response)
    # Force short writes: 100 bytes, then 1 byte, then whatever remains each time.
    socket = _Socket(send_plan=[100, 1])
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, response, deadline=40)

    assert result.outcome == "sent"
    assert result.bytes_sent == len(wire)
    assert b"".join(socket.accepted) == wire
    assert len(socket.offered) > 2  # more calls than a single-shot send


# --- digest mismatch: sends nothing, never claims delivery -------------------


def test_digest_mismatch_sends_nothing_and_never_claims_delivery(monkeypatch):
    ledger, lclock = new_ledger()
    original = ParsedResponse(200, b'{"a":1}')
    receipt = confirmed_receipt(ledger, lclock, original)
    tampered = ParsedResponse(200, b'{"a":2}')
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, tampered, deadline=40), "receipt_mismatch")

    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"
    # The genuine digest still claims delivery normally afterward.
    ledger.claim_delivery(receipt, client_response_digest=receipt.client_response_digest)


@pytest.mark.parametrize("bad_response", [None, "not-a-response", 1, ParsedResponse(200, b"")])
def test_invalid_response_is_rejected_before_claiming_delivery(monkeypatch, bad_response):
    ledger, lclock = new_ledger()
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, bad_response, deadline=40), "invalid_response")

    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"


# --- unrecorded / forged receipt ---------------------------------------------


def test_forged_receipt_is_rejected_as_receipt_unknown(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    forged = dataclasses.replace(receipt)
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, forged, response, deadline=40), "receipt_unknown")
    assert socket.offered == []


def test_receipt_from_a_different_ledger_is_unknown_here(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger_a, clock_a = new_ledger()
    ledger_b, _clock_b = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt_a = make_receipt(ledger_a, clock_a)
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger_b, receipt_a, response, deadline=40), "receipt_unknown")
    assert socket.offered == []


@pytest.mark.parametrize("bad", [None, "receipt", 1, object()])
def test_non_receipt_types_are_rejected_as_invalid_receipt(monkeypatch, bad):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, _clock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, bad, response, deadline=40), "invalid_receipt")


@pytest.mark.parametrize("bad", [None, "ledger", 1, object()])
def test_non_ledger_types_are_rejected_as_invalid_ledger(monkeypatch, bad):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, bad, receipt, response, deadline=40), "invalid_ledger")


# --- double delivery ----------------------------------------------------------


def test_double_delivery_is_rejected_as_delivery_claimed(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    first = _Socket()
    _install(monkeypatch, first)
    send_response(first, ledger, receipt, response, deadline=40)

    second = _Socket()
    _install(monkeypatch, second)
    _error(lambda: send_response(second, ledger, receipt, response, deadline=40), "delivery_claimed")
    assert second.offered == []


# --- interruption inside the ledger's own claim_delivery call --------------


def test_interruption_inside_ledger_claim_delivery_after_mutation_leaves_entry_sending(monkeypatch):
    # Root redesign: the claim (and its digest comparison) now happens inside
    # ledger.claim_delivery itself, called *before* send_response's own
    # try/finally begins. So an interruption that strikes after the ledger's
    # real mutation commits ("pending" -> "sending") but before that call
    # returns to send_response is never seen by send_response's cleanup at
    # all: there is no complete_delivery offer for it, and the entry is left
    # "sending" (unknown) -- exactly the documented, accepted asynchronous
    # gap between the ledger's claim and its return. Retention prunes it like
    # any other finalized entry once its time is up.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES, RETENTION_SECONDS

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    real_claim_delivery = ledger.claim_delivery

    def interrupted_after_mutation(*args, **kwargs):
        real_claim_delivery(*args, **kwargs)  # the real mutation commits ("sending")...
        raise KeyboardInterrupt()  # ...then the interruption strikes before returning

    monkeypatch.setattr(ledger, "claim_delivery", interrupted_after_mutation)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)

    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "sending"

    # Retention prunes the stuck entry once RETENTION_SECONDS has elapsed.
    lclock.advance(RETENTION_SECONDS)
    snapshot = ledger.snapshot()
    assert all(entry["receipt_id"] != receipt.receipt_id for entry in snapshot["entries"])


def test_interrupt_before_claim_mutation_leaves_the_entry_pending(monkeypatch):
    # The companion case: the interruption strikes before the ledger ever
    # touches the entry, so it must stay "pending", not be misreported as
    # "not_sent" for a claim that never actually happened.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def interrupted_before_mutation(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(ledger, "claim_delivery", interrupted_before_mutation)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)

    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"


def test_setup_before_the_claim_call_is_outside_the_ledger_claim_window(monkeypatch):
    # F1-2 regression: the plain local initializations (total, sent_bytes,
    # began_sending, ...) must run BEFORE ``ledger.claim_delivery`` is even
    # called, not merely before send_response's own try/finally. A CALL
    # instruction -- such as the ``len(wire)`` used to compute ``total`` -- is
    # a CPython eval-breaker point where a real KeyboardInterrupt or async
    # exception can land. If that call sat after the claim (as it once did),
    # an interruption landing there would strike *after* the ledger had
    # already moved the entry to "sending", with no complete_delivery offer
    # ever made for it. This shadows the module's own ``len`` lookup to raise
    # KeyboardInterrupt on its first call, which is exactly that statement,
    # and asserts the ledger was never touched: the entry stays "pending".
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def interrupting_len(_value):
        raise KeyboardInterrupt()

    monkeypatch.setattr(forwarder_response_send, "len", interrupting_len, raising=False)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)

    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"


def test_ledger_clock_fault_maps_to_ledger_held(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    lclock.value = math.nan  # corrupt the ledger's own clock
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "ledger_held")
    assert socket.offered == []


# --- invalid connection states and claimed-connection reuse ------------------


@pytest.mark.parametrize(
    "attribute,value",
    [("server_side", False), ("_version", "TLSv1.1"), ("_fileno", -1)],
)
def test_tls_state_matrix_rejects_non_server_tls_transport(monkeypatch, attribute, value):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    setattr(socket, attribute, value)
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "invalid_connection")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"


def test_wrong_context_protocol_rejects_the_connection(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(protocol=ssl.PROTOCOL_TLS_CLIENT)
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "invalid_connection")


@pytest.mark.parametrize("bad", [None, "socket", 1, object()])
def test_non_socket_types_are_rejected_as_invalid_connection(monkeypatch, bad):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(bad, ledger, receipt, response, deadline=40), "invalid_connection")


def test_claimed_connection_is_permanently_consumed_even_after_a_later_failure(monkeypatch):
    """A failed first attempt still consumes the socket for any later attempt."""
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    bad_receipt = dataclasses.replace(receipt)  # forces the first attempt to fail
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, bad_receipt, response, deadline=40), "receipt_unknown")
    # The genuine receipt would otherwise succeed, but the socket is spent.
    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "connection_claimed")


def test_concurrent_reuse_of_the_same_connection_is_rejected(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt_one = make_receipt(ledger, lclock, lease_id="l1", attempt_id="a1")
    receipt_two = make_receipt(ledger, lclock, lease_id="l2", attempt_id="a2")
    socket = _Socket()
    _install(monkeypatch, socket)

    send_response(socket, ledger, receipt_one, response, deadline=40)
    _error(lambda: send_response(socket, ledger, receipt_two, response, deadline=40), "connection_claimed")


# --- deadline validation -------------------------------------------------------


@pytest.mark.parametrize("deadline", [True, 0, -1, math.nan, math.inf, 2**2000, 10, 51])
def test_deadline_is_exact_finite_future_and_handler_clipped(monkeypatch, deadline):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=deadline), "invalid_deadline")
    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"


def test_deadline_already_elapsed_before_the_first_send_is_not_sent(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    # now=10 passes the initial <=40s check against deadline=15; by the time the
    # loop's first _remaining() call runs, the clock has jumped past it.
    times = iter((10.0, 50.0))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=15), "deadline_expired")
    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "not_sent"


# --- clock regression ----------------------------------------------------------


def test_send_module_clock_regression_is_rejected_as_clock_fault(monkeypatch):
    # A post-send clock fault after every byte was already accepted by TLS:
    # the accepted count must still be recorded (send_unknown), not discarded.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    wire = serialize_response(response)
    socket = _Socket()
    times = iter((10.0, 10.1, 10.0))  # regresses after the first successful send
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "clock_fault")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == len(wire)
    assert socket.timeout == 2.0  # the original timeout was restored despite the failure


def test_deadline_is_rechecked_before_every_chunk_not_only_the_first(monkeypatch):
    # The only other deadline_expired test fires before the first send, where
    # the outcome is not_sent; this drives a multi-chunk body and lets the
    # deadline elapse strictly between chunks, so a regression that only
    # rechecks the deadline once (before the loop) would keep sending.
    ledger, lclock = new_ledger()
    body = b"z" * 40_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    # Calls: initial `now`, pre-send remaining check, post-send stall check
    # (all 10.0 -- chunk 1 is accepted well within the stall bound), then the
    # pre-send remaining check for chunk 2 jumps past the deadline.
    times = iter((10.0, 10.0, 10.0, 50.0))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "deadline_expired")
    assert len(socket.offered) == 1
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == 16384


# --- exceptions on first vs. later send; KeyboardInterrupt --------------------


def test_exception_on_the_first_send_is_recorded_as_send_unknown(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[OSError("reset")])
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == 0
    assert not (socket.closed or socket.shutdowns)
    assert socket.timeout == 2.0  # the original timeout was restored despite the failure


def test_exception_on_a_later_send_is_recorded_as_send_unknown(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 30_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[8_000, OSError("reset")])
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert len(socket.offered) == 2
    result_entry = _unclaimed_delivery_outcome(ledger, receipt)
    assert result_entry == "send_unknown"
    # The first chunk's bytes were genuinely accepted by TLS before the
    # second chunk failed: that partial count must survive into the ledger.
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == 8_000
    assert socket.timeout_history  # settimeout ran on the send path...
    assert socket.timeout == 2.0  # ...but the original timeout was restored anyway


def test_keyboard_interrupt_during_send_is_recorded_as_send_unknown(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 30_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    # The first chunk is fully accepted by TLS before the interrupt strikes on
    # the second: those already-accepted bytes must survive into the ledger.
    socket = _Socket(send_plan=[16_384, KeyboardInterrupt()])
    _install(monkeypatch, socket)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == 16_384
    assert socket.timeout == 2.0  # the original timeout was restored despite the interruption


def test_send_unknown_preserves_bytes_accepted_before_a_stalled_post_send_check(monkeypatch):
    # The send() call itself fully succeeds; only the *post-send* stall check
    # trips. Those accepted bytes must not be discarded from the recorded
    # partial count just because an unrelated later check then fails.
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    times = iter((10.0, 10.0, 20.0))  # post-send check sees a 10s stall
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    wire = serialize_response(response)
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == len(wire)


@pytest.mark.parametrize("bad_count", [0, -1, 1.0, "10", None, True])
def test_invalid_send_count_is_rejected(monkeypatch, bad_count):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[bad_count])
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"


def test_oversized_send_count_is_rejected(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    wire_len = len(serialize_response(response))
    socket = _Socket(send_plan=[wire_len + 1])
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")


# --- slow send (>= 10s) --------------------------------------------------------


def test_send_taking_ten_seconds_or_more_is_rejected(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    # 1st call: initial `now`. 2nd: pre-send remaining check (send_started).
    # 3rd: post-send clock check, 10.0s after send_started -> stalled send.
    times = iter((10.0, 10.0, 20.0))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"


def test_send_timeout_is_clipped_to_ten_seconds(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    _install(monkeypatch, socket, lambda: 10.0)

    send_response(socket, ledger, receipt, response, deadline=40)  # remaining=30, clipped to 10
    assert socket.timeout_history[0] == 10.0


def test_send_timeout_uses_remaining_when_below_ten_seconds(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    _install(monkeypatch, socket, lambda: 10.0)

    send_response(socket, ledger, receipt, response, deadline=15)  # remaining=5 < 10
    assert socket.timeout_history[0] == 5.0


def test_send_timeout_is_recomputed_from_remaining_time_for_each_chunk(monkeypatch):
    # F2-3: only a single-chunk body was ever exercised for timeout_history,
    # so a mutation that reuses the FIRST chunk's remaining time for every
    # later chunk (instead of recomputing it from the current clock reading
    # before each send) went undetected. A multi-chunk body plus a clock
    # that advances between chunks must show a distinct, decreasing timeout
    # per chunk, not the same value repeated.
    ledger, lclock = new_ledger()
    body = b"z" * 40_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    # 1 initial `now` read, then 2 reads per chunk (the pre-send remaining
    # calc, then the post-send stall check) for 3 chunks: 7 reads total.
    times = iter((0.0, 0.0, 0.0, 5.0, 5.0, 8.0, 8.0))
    _install(monkeypatch, socket, lambda: next(times))

    result = send_response(socket, ledger, receipt, response, deadline=9.0)

    assert result.outcome == "sent"
    assert len(socket.offered) == 3
    # The last entry is the final timeout restore, not a send timeout.
    assert socket.timeout_history[:3] == [9.0, 4.0, 1.0]


def test_ten_second_stall_bound_applies_per_chunk_not_cumulatively(monkeypatch):
    # F2-3: a mutation that anchors the stall check to the send loop's
    # initial time (instead of resetting it at the start of each chunk)
    # makes the 10-second bound cumulative across the whole send instead of
    # per chunk. Three chunks that each take 6 seconds (18 seconds total,
    # comfortably under a 40-second deadline) must still succeed, because no
    # single chunk ever stalls for a full 10 seconds.
    ledger, lclock = new_ledger()
    body = b"z" * 40_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    times = iter((0.0, 0.0, 6.0, 6.0, 12.0, 12.0, 18.0))
    _install(monkeypatch, socket, lambda: next(times))

    result = send_response(socket, ledger, receipt, response, deadline=40)

    assert result.outcome == "sent"
    assert result.bytes_sent == len(serialize_response(response))
    assert len(socket.offered) == 3


# --- restore-failure precedence ------------------------------------------------


def test_restore_failure_after_success_raises_timeout_restore_failed_but_keeps_sent(monkeypatch):
    ledger, lclock = new_ledger()
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "timeout_restore_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "sent"


def test_restore_failure_never_masks_a_primary_send_failure(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[OSError("reset")], restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    # The primary send_failed error must win, not timeout_restore_failed.
    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"


def test_restore_failure_never_masks_an_interruption(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[KeyboardInterrupt()], restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"


def test_restore_failure_is_not_hidden_by_callers_handled_exception(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    def invoke():
        try:
            raise ValueError("ambient, unrelated to delivery")
        except ValueError:
            return send_response(socket, ledger, receipt, response, deadline=40)

    _error(invoke, "timeout_restore_failed")


# --- complete_delivery failure in the finally must never mask an outcome ----


@pytest.mark.parametrize("complete_delivery_error", [
    ReceiptError("clock_invalid"),
    # F2-5: every complete_delivery-failure test used to raise only
    # ReceiptError, so a regression narrowing _record's `except Exception:`
    # to `except ReceiptError:` (an easy mistake, given the surrounding code
    # otherwise models ledger errors as ReceiptError) went undetected. A
    # bookkeeping failure of any kind must still be swallowed into
    # "recorded=False", never escape raw or mask a primary outcome.
    RuntimeError("boom"),
    MemoryError(),
], ids=["ReceiptError", "RuntimeError", "MemoryError"])
def test_complete_delivery_failure_after_a_full_send_is_reported_not_masked(
    monkeypatch, complete_delivery_error,
):
    # A ledger fault (or a retention race) landing inside the finally, after
    # every byte was already accepted, must not: (a) escape as a raw
    # exception instead of the module's own fixed code, (b) be reported
    # as a successful DeliveryResult, or (c) skip the timeout restore.
    ledger, lclock = new_ledger()
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def failing_complete_delivery(*_args, **_kwargs):
        raise complete_delivery_error

    monkeypatch.setattr(ledger, "complete_delivery", failing_complete_delivery)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "delivery_unrecorded")

    # All bytes were still fully accepted by the local TLS layer...
    assert b"".join(socket.accepted) == serialize_response(response)
    # ...and the timeout was still restored despite the bookkeeping failure.
    assert socket.timeout == 2.0


@pytest.mark.parametrize("complete_delivery_error", [
    ReceiptError("clock_invalid"),
    RuntimeError("boom"),
    MemoryError(),
], ids=["ReceiptError", "RuntimeError", "MemoryError"])
def test_complete_delivery_failure_never_masks_a_primary_send_failure(
    monkeypatch, complete_delivery_error,
):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[OSError("reset")])
    _install(monkeypatch, socket)

    def failing_complete_delivery(*_args, **_kwargs):
        raise complete_delivery_error

    monkeypatch.setattr(ledger, "complete_delivery", failing_complete_delivery)

    # The primary send_failed error must still win over the bookkeeping failure.
    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert socket.timeout == 2.0  # the restore still ran despite both failures


def test_complete_delivery_failure_never_masks_an_interruption(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[KeyboardInterrupt()])
    _install(monkeypatch, socket)

    def failing_complete_delivery(*_args, **_kwargs):
        raise ReceiptError("clock_invalid")

    monkeypatch.setattr(ledger, "complete_delivery", failing_complete_delivery)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)
    assert socket.timeout == 2.0


# --- a genuine BaseException interruption inside cleanup itself is never ----
# --- replaced by a fixed ResponseSendError code -----------------------------


def test_keyboard_interrupt_from_complete_delivery_propagates_not_replaced(monkeypatch):
    # complete_delivery itself (not a caller's send loop) is where the
    # interruption strikes this time, on the pure-success path (no primary
    # failure already in flight): it must still propagate as KeyboardInterrupt,
    # never be swallowed into the fixed "delivery_unrecorded" code.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def interrupting_complete_delivery(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(ledger, "complete_delivery", interrupting_complete_delivery)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)
    # The timeout restore still ran despite the interruption in complete_delivery.
    assert socket.timeout == 2.0


def test_system_exit_from_complete_delivery_propagates_not_replaced(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def exiting_complete_delivery(*_args, **_kwargs):
        raise SystemExit(1)

    monkeypatch.setattr(ledger, "complete_delivery", exiting_complete_delivery)

    with pytest.raises(SystemExit):
        send_response(socket, ledger, receipt, response, deadline=40)
    assert socket.timeout == 2.0


def test_keyboard_interrupt_from_complete_delivery_overrides_a_primary_send_failure(monkeypatch):
    # Even when an ordinary primary failure (send_failed) is already in
    # flight, a BaseException interruption striking during the complete_delivery
    # cleanup must still win: it is not an "earlier interruption already
    # propagating", so it takes over rather than being swallowed.
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[OSError("reset")])
    _install(monkeypatch, socket)

    def interrupting_complete_delivery(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(ledger, "complete_delivery", interrupting_complete_delivery)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)
    assert socket.timeout == 2.0  # the restore still ran


def test_keyboard_interrupt_during_timeout_restore_propagates_not_replaced(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(restore_error=KeyboardInterrupt())
    _install(monkeypatch, socket)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)
    # complete_delivery had already succeeded before the restore was attempted.
    assert _unclaimed_delivery_outcome(ledger, receipt) == "sent"


def test_system_exit_during_timeout_restore_propagates_not_replaced(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(restore_error=SystemExit(1))
    _install(monkeypatch, socket)

    with pytest.raises(SystemExit):
        send_response(socket, ledger, receipt, response, deadline=40)
    assert _unclaimed_delivery_outcome(ledger, receipt) == "sent"


# --- F3-1: a restore failure combined with a complete_delivery fault -------
# must never invert the delivery_unrecorded/timeout_restore_failed precedence
# and must never replace an interruption from complete_delivery itself.


def test_restore_failure_never_replaces_a_keyboard_interrupt_from_complete_delivery(monkeypatch):
    # Two independent faults at once: complete_delivery is interrupted (not
    # merely failing with an ordinary exception), AND the timeout restore
    # separately fails with an ordinary exception. The interruption must
    # still win and propagate as KeyboardInterrupt, never be replaced by the
    # fixed timeout_restore_failed code raised from within the restore's own
    # cleanup while that interruption is in flight.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    def interrupting_complete_delivery(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(ledger, "complete_delivery", interrupting_complete_delivery)

    with pytest.raises(KeyboardInterrupt):
        send_response(socket, ledger, receipt, response, deadline=40)


def test_restore_failure_after_an_ordinary_complete_delivery_failure_is_delivery_unrecorded(
    monkeypatch,
):
    # F3-1 case B: complete_delivery fails with an ordinary exception (the
    # delivery is genuinely never recorded), and the timeout restore also
    # fails. The caller must learn delivery_unrecorded (accurate: the ledger
    # entry is really still "sending"), not timeout_restore_failed (which
    # would misreport the entry as "sent").
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    def failing_complete_delivery(*_args, **_kwargs):
        raise ReceiptError("clock_invalid")

    monkeypatch.setattr(ledger, "complete_delivery", failing_complete_delivery)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "delivery_unrecorded")


# --- the connection is claimed before any TLS-state validation runs --------


def test_connection_is_claimed_before_tls_state_validation_runs(monkeypatch):
    # A failed validation attempt must still permanently consume the socket:
    # fixing the TLS version afterward must not un-claim it.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(version="TLSv1.1")
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "invalid_connection")

    socket._version = "TLSv1.3"
    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "connection_claimed")
    assert socket.offered == []


def test_claim_lock_serializes_concurrent_claim_attempts_on_one_socket(monkeypatch):
    # test_concurrent_reuse_of_the_same_connection_is_rejected (above) makes
    # two purely sequential calls despite its name; it cannot exercise
    # _CLAIM_LOCK at all. This widens the check-then-set window by sleeping
    # *after* reading the marker's current value (not before): a missing or
    # broken lock then lets both threads' reads land in the same window,
    # before either thread's write, so both see "unclaimed" and both
    # proceed. A barrier releases both threads together immediately before
    # the claim so their reads are as close to simultaneous as possible.
    class SlowMarkerSocket(_Socket):
        def __getattribute__(self, name):
            if name == forwarder_response_send._MARKER:
                try:
                    value = super().__getattribute__(name)
                except AttributeError:
                    time.sleep(0.05)
                    raise
                time.sleep(0.05)
                return value
            return super().__getattribute__(name)

    socket = SlowMarkerSocket()
    _install(monkeypatch, socket)
    start_barrier = threading.Barrier(2)
    results: list[str] = []
    results_lock = threading.Lock()

    def attempt() -> None:
        start_barrier.wait(timeout=2)
        try:
            forwarder_response_send._claim_and_validate(socket)
            outcome = "claimed"
        except ResponseSendError as error:
            outcome = error.code
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert sorted(results) == ["claimed", "connection_claimed"]


# --- forged receipt_id never raises a raw TypeError -------------------------
#
# Root redesign note: send_response no longer pre-checks the wire digest
# against any field of the caller's receipt instance -- claim_delivery's
# digest comparison runs entirely inside the ledger, against its private
# record, and only after the ledger has confirmed the receipt argument is the
# *identical* recorded instance (see the receipt_unknown/receipt_from-a-
# different-ledger tests above). A receipt built via ``dataclasses.replace``
# with a forged ``client_response_digest`` field is therefore rejected as
# ``receipt_unknown`` (identity), never as a field-level ``receipt_mismatch``;
# there is no longer a send-side path that would even inspect that field.


def test_unhashable_receipt_id_is_rejected_as_receipt_unknown_not_raised(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    forged = dataclasses.replace(receipt, receipt_id=["not-hashable"])
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, forged, response, deadline=40), "receipt_unknown")
    assert socket.offered == []


# --- exact-type checks and inclusive boundaries, not isinstance/off-by-one --


def test_ledger_and_receipt_subclasses_are_rejected_not_isinstance_matched(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES, ReceiptLedger

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)

    class EvilLedger(ReceiptLedger):
        def claim_delivery(self, receipt):  # pragma: no cover - must never run
            raise AssertionError("claim_delivery must not be reachable via a ledger subclass")

    class EvilReceipt(ForwarderReceipt):
        pass

    socket = _Socket()
    _install(monkeypatch, socket)
    evil_ledger = EvilLedger(generation="evil")
    _error(lambda: send_response(socket, evil_ledger, receipt, response, deadline=40),
           "invalid_ledger")
    assert socket.offered == []

    evil_receipt = EvilReceipt(**dataclasses.asdict(receipt))
    socket2 = _Socket()
    _install(monkeypatch, socket2)
    _error(lambda: send_response(socket2, ledger, evil_receipt, response, deadline=40),
           "invalid_receipt")
    assert socket2.offered == []


def test_deadline_exactly_at_the_forty_second_boundary_is_accepted(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket, lambda: 10.0)

    result = send_response(socket, ledger, receipt, response, deadline=50.0)  # 40.0 remaining
    assert result.outcome == "sent"


# --- the socket is never closed, shut down or retried after a failure --------


def test_socket_is_never_closed_or_shutdown_on_any_path(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]

    ok_receipt = make_receipt(ledger, lclock, lease_id="l1", attempt_id="a1")
    ok_socket = _Socket()
    _install(monkeypatch, ok_socket)
    send_response(ok_socket, ledger, ok_receipt, response, deadline=40)
    assert not (ok_socket.closed or ok_socket.shutdowns)

    failing_receipt = make_receipt(ledger, lclock, lease_id="l2", attempt_id="a2")
    failing_socket = _Socket(send_plan=[OSError("reset")])
    _install(monkeypatch, failing_socket)
    _error(lambda: send_response(failing_socket, ledger, failing_receipt, response, deadline=40))
    assert not (failing_socket.closed or failing_socket.shutdowns)


def test_no_retry_after_a_send_exception_only_one_send_call_made(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[OSError("reset")])
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40))
    assert len(socket.offered) == 1  # the failed attempt was not retried


# --- TRANSPORT_CONFIRMED / non-2xx local responses still deliver correctly ---


@pytest.mark.parametrize("dispatch_state,reason", [
    ("NOT_DISPATCHED", "lease_denied"),
    ("FAILED", "connect_failed"),
    ("DISPATCHED_UNKNOWN", "write_failed"),
    ("PARTIAL", "response_incomplete"),
])
def test_every_non_transport_confirmed_local_response_is_deliverable(monkeypatch, dispatch_state, reason):
    from grafana_jsm_sandbox.forwarder_receipts import local_response_for

    ledger, lclock = new_ledger()
    receipt = make_receipt(ledger, lclock, dispatch_state=dispatch_state, reason=reason)
    response = local_response_for(receipt)
    wire = serialize_response(response)
    socket = _Socket()
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, response, deadline=40)
    assert result.outcome == "sent" and result.bytes_sent == len(wire)


def test_transport_confirmed_ok_delivers_the_upstream_response_itself(monkeypatch):
    ledger, lclock = new_ledger()
    upstream = ParsedResponse(404, b'{"missing":true}')
    receipt = confirmed_receipt(ledger, lclock, upstream)
    wire = serialize_response(upstream)
    socket = _Socket()
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, upstream, deadline=40)
    assert result.outcome == "sent"
    assert b"".join(socket.accepted) == wire


def test_transport_confirmed_response_policy_rejected_never_sends_the_rejected_upstream_body(
    monkeypatch,
):
    # The receipt's client_response_digest for response_policy_rejected names
    # the fixed local "response_rejected" body, not the (never-forwarded)
    # upstream one: passing the real upstream response must be rejected as a
    # digest mismatch, and only the fixed local response is deliverable.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES, local_response_for

    ledger, lclock = new_ledger()
    rejected_upstream = ParsedResponse(200, b'{"secret":1}')
    receipt = make_receipt(
        ledger, lclock, dispatch_state="TRANSPORT_CONFIRMED", reason="response_policy_rejected",
        upstream_response=rejected_upstream,
    )
    first_socket = _Socket()
    _install(monkeypatch, first_socket)

    _error(
        lambda: send_response(first_socket, ledger, receipt, rejected_upstream, deadline=40),
        "receipt_mismatch",
    )
    assert first_socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "pending"

    second_socket = _Socket()
    _install(monkeypatch, second_socket)
    fixed_response = local_response_for(receipt)
    assert fixed_response is LOCAL_RESPONSES["response_rejected"]
    result = send_response(second_socket, ledger, receipt, fixed_response, deadline=40)
    assert result.outcome == "sent"
    assert b"".join(second_socket.accepted) == serialize_response(fixed_response)


# --- exact TLS-version, exact-type, and boundary checks are each pinned -----


def test_tls_v1_2_connection_is_accepted(monkeypatch):
    # The plan's accepted set is "TLSv1.2/1.3": a version-check regression
    # that only accepted TLSv1.3 would still pass every other test here.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket(version="TLSv1.2")
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, response, deadline=40)
    assert result.outcome == "sent"


def test_subclass_of_the_registered_socket_type_is_rejected_not_isinstance_matched(monkeypatch):
    # The plan requires "type(connection) is ssl.SSLSocket" exactly, not an
    # isinstance check: a regression to isinstance would still accept every
    # other test's plain _Socket instance, so this specifically passes a
    # *subclass* of the type registered as ssl.SSLSocket.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    base_socket = _Socket()
    _install(monkeypatch, base_socket)  # registers type(base_socket) as ssl.SSLSocket

    class Sub(_Socket):
        pass

    subclass_socket = Sub()
    _error(lambda: send_response(subclass_socket, ledger, receipt, response, deadline=40),
           "invalid_connection")


def test_deadline_reached_with_exactly_zero_remaining_is_rejected(monkeypatch):
    # The plan checks "remaining <= 0", not "remaining < 0": a send whose
    # clock reading lands exactly on the deadline (zero time left) must
    # still be rejected before ever calling settimeout(0.0)/send().
    ledger, lclock = new_ledger()
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    times = iter((10.0, 40.0))  # initial `now`, then the loop's remaining check
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "deadline_expired")
    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "not_sent"


def test_oversized_per_chunk_count_is_rejected_even_when_within_total_body_size(monkeypatch):
    # The plan rejects a count exceeding *this chunk's* length, not the total
    # body length: a regression comparing against the total would accept an
    # oversized count on any chunk of a multi-chunk body as long as it still
    # fit under the overall response size.
    ledger, lclock = new_ledger()
    body = b"z" * 40_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[16385])  # exceeds this 16384-byte chunk, not the 40000-byte total
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"


# --- an OSError from the per-chunk settimeout never escapes raw ------------


def test_settimeout_oserror_mid_loop_is_rejected_not_raised_raw(monkeypatch):
    # Only secured.send() was wrapped; a closed socket (e.g. another thread
    # closing it during shutdown) can also raise from settimeout() on a
    # later chunk, which must be mapped to the same fixed send_failed code
    # instead of escaping as a raw OSError.
    ledger, lclock = new_ledger()
    body = b"z" * 40_000
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket()
    _install(monkeypatch, socket)
    real_settimeout = socket.settimeout
    calls = {"count": 0}

    def flaky_settimeout(value):
        calls["count"] += 1
        if calls["count"] == 2:  # let the first chunk's settimeout succeed
            raise OSError("Bad file descriptor")
        return real_settimeout(value)

    socket.settimeout = flaky_settimeout

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert _unclaimed_delivery_outcome(ledger, receipt) == "send_unknown"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == 16384


# --- F3-10: not_sent classification and pre-send failure mapping ------------


def test_settimeout_oserror_on_the_very_first_chunk_is_not_sent_not_send_unknown(monkeypatch):
    # began_sending must be set only *after* the per-chunk settimeout call
    # succeeds: an OSError here, on a body small enough to need only one
    # chunk, means send() was never even attempted, so the outcome must be
    # not_sent, not send_unknown.
    ledger, lclock = new_ledger()
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    response = LOCAL_RESPONSES["invalid_request"]  # small, single-chunk body
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def failing_settimeout(_value):
        raise OSError("Bad file descriptor")

    socket.settimeout = failing_settimeout

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "not_sent"
    assert _entry_for(ledger, receipt)["delivery_bytes_sent"] == 0


def test_gettimeout_oserror_before_the_send_loop_is_rejected_not_raised_raw(monkeypatch):
    # secured.gettimeout() (reading the *prior* timeout, before the send loop
    # starts) is wrapped the same way secured.settimeout() is; this pins that
    # an OSError from it is mapped to the fixed send_failed code instead of
    # escaping raw.
    ledger, lclock = new_ledger()
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)

    def failing_gettimeout():
        raise OSError("Bad file descriptor")

    socket.gettimeout = failing_gettimeout

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert socket.offered == []
    assert _unclaimed_delivery_outcome(ledger, receipt) == "not_sent"


def test_fileno_raising_during_validation_is_mapped_to_invalid_connection(monkeypatch):
    # The wrapper around the TLS-state checks in _claim_and_validate is only
    # ever exercised with bad *values* elsewhere; this makes an accessor
    # itself raise, pinning that it is mapped to the fixed invalid_connection
    # code (with the connection still permanently claimed), not raised raw.
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()

    def failing_fileno():
        raise OSError("Bad file descriptor")

    socket.fileno = failing_fileno
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "invalid_connection")
    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "connection_claimed")


# --- F3-11: restoring a blocking (None) prior socket timeout ----------------


def test_a_blocking_prior_timeout_of_none_is_correctly_restored(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    response = LOCAL_RESPONSES["invalid_request"]
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    socket.timeout = None  # simulate a caller's socket that was blocking
    _install(monkeypatch, socket)

    result = send_response(socket, ledger, receipt, response, deadline=40)

    assert result.outcome == "sent"
    assert socket.timeout is None
    assert socket.timeout_history[-1] is None


def test_a_blocking_prior_timeout_of_none_is_restored_even_after_a_send_failure(monkeypatch):
    ledger, lclock = new_ledger()
    body = b"z" * 100
    response = ParsedResponse(200, body)
    receipt = confirmed_receipt(ledger, lclock, response)
    socket = _Socket(send_plan=[OSError("reset")])
    socket.timeout = None
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40), "send_failed")
    assert socket.timeout is None
    assert socket.timeout_history[-1] is None


# --- basic type contracts: frozen result, ValueError-derived error ----------


def test_delivery_result_is_frozen():
    result = DeliveryResult(receipt_id="receipt-1", outcome="sent", bytes_sent=3)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.outcome = "not_sent"
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.bytes_sent = 0


def test_response_send_error_is_a_value_error():
    assert issubclass(ResponseSendError, ValueError)
    error = ResponseSendError("some_fixed_code")
    assert isinstance(error, ValueError)
    assert error.code == "some_fixed_code"
    assert str(error) == "some_fixed_code"


# --- root-added: consumption before every validation and record-then-restore order


@pytest.mark.parametrize("fault", ["ledger", "receipt", "deadline", "response"])
def test_every_pre_claim_validation_failure_still_consumes_the_socket(monkeypatch, fault):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    receipt = make_receipt(ledger, lclock)
    response = LOCAL_RESPONSES["invalid_request"]
    arguments = {"ledger": ledger, "receipt": receipt, "response": response, "deadline": 40}
    arguments[fault] = {"ledger": object(), "receipt": object(), "deadline": 99.0,
                        "response": ParsedResponse(200, b"")}[fault]
    socket = _Socket()
    _install(monkeypatch, socket)

    _error(lambda: send_response(socket, arguments["ledger"], arguments["receipt"],
                                 arguments["response"], deadline=arguments["deadline"]))
    _error(lambda: send_response(socket, ledger, receipt, response, deadline=40),
           "connection_claimed")
    assert socket.offered == [] and _unclaimed_delivery_outcome(ledger, receipt) == "pending"


def test_outcome_is_recorded_before_the_prior_timeout_is_restored(monkeypatch):
    from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES

    ledger, lclock = new_ledger()
    receipt = make_receipt(ledger, lclock)
    socket = _Socket()
    _install(monkeypatch, socket)
    observed = []
    real_complete = ledger.complete_delivery

    def recording_complete(claim, **kwargs):
        observed.append(socket.timeout)
        return real_complete(claim, **kwargs)

    monkeypatch.setattr(ledger, "complete_delivery", recording_complete)
    send_response(socket, ledger, receipt, LOCAL_RESPONSES["invalid_request"], deadline=40)

    assert observed and observed[0] != 2.0  # still the per-send timeout when recorded
    assert socket.timeout == 2.0 and socket.timeout_history[-1] == 2.0
