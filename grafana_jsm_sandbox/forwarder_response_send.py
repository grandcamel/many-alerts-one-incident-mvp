"""Receipt-gated, bounded client-response delivery over a claimed TLS socket.

This module has no route, lease, dispatch-permit or upstream-connection
authority. It writes bytes to the client only when they are the exact
canonical bytes already named by a ``ForwarderReceipt`` recorded in the
caller's ``ReceiptLedger``: ``send_response`` serializes the supplied response
and asks the ledger to claim delivery for that digest. The ledger compares the
digest with its own private record under its lock, so a mismatch sends nothing
and claims nothing. The ledger's ``claim_delivery``/``complete_delivery`` calls
make this ordering and its outcome bookkeeping explicit; this module has no
other durable state.

The caller owns the socket. This function never closes, shuts down or
unwraps it, and never retries a send after a failure -- the caller decides
what happens to the connection next. ``sent`` means the local TLS layer
accepted every byte; it is not proof the client read them, and it cannot
attest which upstream produced the response or which service the caller's
listener represents.
"""

from __future__ import annotations

import hashlib
import math
import ssl
import threading
import time
from dataclasses import dataclass

from .forwarder_http_response import HTTPResponseError, ParsedResponse, serialize_response
from .forwarder_receipts import DeliveryClaim, ForwarderReceipt, ReceiptError, ReceiptLedger

_MARKER = "_maoi_forwarder_response_send_claimed"
_CLAIM_LOCK = threading.Lock()
_MAX_CHUNK_BYTES = 16_384
_SEND_TIMEOUT_SECONDS = 10.0
_MAX_DEADLINE_SECONDS = 40.0
_CLAIM_ERRORS = frozenset({"receipt_unknown", "receipt_mismatch", "delivery_claimed"})


class ResponseSendError(ValueError):
    """A fixed, non-diagnostic client-response delivery rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ResponseSendError(code) from None


@dataclass(frozen=True)
class DeliveryResult:
    """The recorded outcome of one receipt-named client delivery attempt."""

    receipt_id: str
    outcome: str
    bytes_sent: int


def _finite(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _clock(previous: float | None = None) -> float:
    try:
        observed = _finite(time.monotonic())
    except Exception:  # noqa: BLE001 - a deadline needs a working monotonic clock.
        _fail("clock_fault")
    if observed is None or (previous is not None and observed < previous):
        _fail("clock_fault")
    return observed


def _remaining(deadline: float, previous: float) -> tuple[float, float]:
    observed = _clock(previous)
    remaining = deadline - observed
    if not math.isfinite(remaining) or remaining <= 0:
        _fail("deadline_expired")
    return remaining, observed


def _claim_and_validate(connection: object) -> ssl.SSLSocket:
    """Permanently claim the socket, then validate it is a live server TLS 1.2+ peer.

    The claim happens before any validation: a failed attempt still consumes
    the socket, so a caller cannot retry delivery on the same connection.
    """
    if type(connection) is not ssl.SSLSocket:
        _fail("invalid_connection")
    with _CLAIM_LOCK:
        if getattr(connection, _MARKER, False):
            _fail("connection_claimed")
        setattr(connection, _MARKER, True)
    try:
        if (
            connection.fileno() < 0
            or connection.server_side is not True
            or connection.context.protocol != ssl.PROTOCOL_TLS_SERVER
            or connection.version() not in {"TLSv1.2", "TLSv1.3"}
        ):
            _fail("invalid_connection")
    except ResponseSendError:
        raise
    except (OSError, ssl.SSLError, ValueError, TypeError, AttributeError):
        _fail("invalid_connection")
    return connection


def _serialize_or_fail(response: object) -> bytes:
    if type(response) is not ParsedResponse:
        _fail("invalid_response")
    try:
        return serialize_response(response)
    except HTTPResponseError:
        _fail("invalid_response")


def _claim_delivery(ledger: ReceiptLedger, receipt: ForwarderReceipt,
                    wire: bytes) -> DeliveryClaim:
    code: str | None = None
    try:
        claim = ledger.claim_delivery(
            receipt, client_response_digest=hashlib.sha256(wire).hexdigest(),
        )
    except ReceiptError as error:
        # Any other ledger rejection (a clock fault or an existing hold) means
        # the ledger cannot be trusted to record this delivery either.
        code = error.code if error.code in _CLAIM_ERRORS else "ledger_held"
    if code is not None:
        _fail(code)
    return claim


def _record(ledger: ReceiptLedger, claim: DeliveryClaim, outcome: str, bytes_sent: int) -> bool:
    try:
        ledger.complete_delivery(claim, outcome=outcome, bytes_sent=bytes_sent)
    except Exception:  # noqa: BLE001 - bookkeeping failure never masks the primary outcome.
        return False
    return True


def _restore(connection: ssl.SSLSocket, timeout: float | None) -> bool:
    try:
        connection.settimeout(timeout)
    except Exception:  # noqa: BLE001 - reported only after otherwise complete success.
        return False
    return True


def send_response(
    connection: object,
    ledger: ReceiptLedger,
    receipt: ForwarderReceipt,
    response: ParsedResponse,
    *,
    deadline: float,
) -> DeliveryResult:
    """Write one receipt-named response to a claimed client TLS connection.

    The connection is claimed first (see ``_claim_and_validate``), then
    ``ledger``/``receipt``/``deadline`` are validated and the caller's
    ``response`` is serialized. ``ledger.claim_delivery`` then compares the
    serialized digest with the recorded receipt and claims the one-use
    delivery right in one locked step; a mismatch sends nothing.

    After the claim, the outcome is always offered to
    ``ledger.complete_delivery`` and the prior socket timeout is restored:
    ``sent`` once every byte was accepted by the local TLS layer, ``not_sent``
    if no ``connection.send`` call began, otherwise ``send_unknown`` (a send
    may have already emitted bytes). A primary failure or interruption always
    propagates unchanged. Only after an otherwise complete send does an
    unrecorded outcome raise ``delivery_unrecorded`` and a failed restore
    raise ``timeout_restore_failed``, in that order. An asynchronous
    interruption between the ledger's claim and its return leaves that
    delivery ``sending`` (unknown) until retention prunes it.

    ``sent`` means the local TLS layer accepted every byte; it is not proof
    the client read them. The caller owns the socket and must close it after
    this one response. The caller also binds ``receipt.service`` to its
    listener; this function cannot attest service identity from the socket.
    ``deadline`` is validated only against the moment this call runs (finite,
    future, at most 40 seconds away); the caller derives it from the original
    handler deadline so the inbound 40-second bound holds end to end.
    """
    secured = _claim_and_validate(connection)
    if type(ledger) is not ReceiptLedger:
        _fail("invalid_ledger")
    if type(receipt) is not ForwarderReceipt:
        _fail("invalid_receipt")
    now = _clock()
    absolute_deadline = _finite(deadline)
    if (
        absolute_deadline is None
        or absolute_deadline <= now
        or absolute_deadline - now > _MAX_DEADLINE_SECONDS
    ):
        _fail("invalid_deadline")
    wire = _serialize_or_fail(response)

    # Initialize before the claim so the claim is the last statement before the
    # try/finally; only the documented gap inside the ledger call remains.
    total = len(wire)
    sent_bytes = 0
    began_sending = False
    succeeded = False
    previous_timeout: float | None = None
    timeout_saved = False
    recorded = False
    restored = True
    claim = _claim_delivery(ledger, receipt, wire)
    try:
        try:
            previous_timeout = secured.gettimeout()
        except (OSError, ssl.SSLError, ValueError, TypeError):
            _fail("send_failed")
        timeout_saved = True
        observed = now
        while sent_bytes < total:
            remaining, observed = _remaining(absolute_deadline, observed)
            chunk = wire[sent_bytes:sent_bytes + _MAX_CHUNK_BYTES]
            try:
                secured.settimeout(min(_SEND_TIMEOUT_SECONDS, remaining))
            except (OSError, ssl.SSLError, ValueError, TypeError):
                _fail("send_failed")
            send_started = observed
            # Any failure from here on may already have emitted bytes over TLS.
            began_sending = True
            try:
                count = secured.send(chunk)
            except (OSError, ssl.SSLError, ValueError, TypeError):
                _fail("send_failed")
            # Account for accepted bytes before a later stall or clock check fails.
            if type(count) is not int or count <= 0 or count > len(chunk):
                _fail("send_failed")
            sent_bytes += count  # a partial count continues with the remainder
            observed = _clock(observed)
            if observed - send_started >= _SEND_TIMEOUT_SECONDS:
                _fail("send_failed")
        succeeded = True
    finally:
        if succeeded:
            outcome, bytes_sent = "sent", total
        elif began_sending:
            outcome, bytes_sent = "send_unknown", sent_bytes
        else:
            outcome, bytes_sent = "not_sent", 0
        try:
            recorded = _record(ledger, claim, outcome, bytes_sent)
        finally:
            if timeout_saved:
                restored = _restore(secured, previous_timeout)
    # Reached only after a complete send: a propagating failure skips these.
    if not recorded:
        _fail("delivery_unrecorded")
    if not restored:
        _fail("timeout_restore_failed")
    return DeliveryResult(receipt_id=claim.receipt_id, outcome=outcome, bytes_sent=bytes_sent)


__all__ = [
    "DeliveryResult",
    "ResponseSendError",
    "send_response",
]
