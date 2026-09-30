"""One receipt-gated exchange over one already-handshaken inbound TLS socket.

``serve_request`` composes the dispatch gate (module 1), the route policy and
an injected trusted ``UpstreamConnector`` around exactly one accepted
connection. It performs no upstream network I/O of its own, never closes the
socket, never retries, and never sends bytes that are not named by a ledger
receipt already recorded in ``gate.ledger``.

``receive_request_sized`` and ``send_response`` are called through this
module's own globals (not through their owning modules), so a deterministic
test can monkeypatch ``forwarder_exchange.receive_request_sized`` and
``forwarder_exchange.send_response`` without touching a real socket.

The module-1 error discipline applies: an ``except`` block only records a
fixed code, and a fresh outcome is built (or a fresh error raised) once the
``try`` statement has ended; nothing caught here is ever re-raised.
"""

from __future__ import annotations

import hmac
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .forwarder_dispatch import (
    MAX_HANDLER_SECONDS,
    MIN_ADMISSION_SECONDS,
    RESPONSE_MARGIN_SECONDS,
    Admission,
    DispatchError,
    DispatchGate,
)
from .forwarder_http_receive import HTTPReceiveError, receive_request_sized
from .forwarder_http_response import ParsedResponse
from .forwarder_receipts import ForwarderReceipt, ReceiptError, local_response_for, response_digest
from .forwarder_response_send import ResponseSendError, send_response
from .forwarder_routes import (
    UNMATCHED_ROUTE_ID,
    RoutedRequest,
    RoutePolicy,
    RoutePolicyError,
    denied_request_digest,
)
from .forwarder_server_tls import FixedTLSListener, TLSListenerError
from .forwarder_services import SERVICE_PROFILES

# --- constants ---------------------------------------------------------------

UPSTREAM_ERROR_CODES = frozenset({
    "connect_failed", "upstream_tls_failed", "write_failed", "receive_failed", "deadline",
})
SERVE_RESULTS = ("responded", "closed_without_response", "delivery_failed")
CLOSE_REASONS = frozenset({
    "accept_failed", "request_unreadable", "sentinel_unknown", "receipt_unavailable",
    "dispatch_capacity", "deadline_expired", "gate_failure", "internal_failure",
})

_HEX_CHARS = frozenset("0123456789abcdef")


class UpstreamError(ValueError):
    """A fixed, non-diagnostic upstream-connector rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class UpstreamConnector(Protocol):
    """The 13b trusted upstream connector's shape. Source ships no implementation."""

    def prepare(self, routed: RoutedRequest) -> str: ...

    def connect(
        self, admission: Admission, routed: RoutedRequest, *, request_digest: str,
        deadline: float,
    ) -> UpstreamChannel: ...


class UpstreamChannel(Protocol):
    """One connector-owned upstream transport, used for exactly one request."""

    def send(self, *, deadline: float) -> None: ...

    def receive(self, *, deadline: float) -> ParsedResponse: ...

    def abort(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class ServeOutcome:
    """The closed, non-diagnostic result of one ``serve_request`` call."""

    result: str
    reason: str
    receipt_id: str | None
    dispatch_state: str | None
    delivery: str | None


# --- small result and safety helpers ------------------------------------------


def _outcome(
    result: str, reason: str, receipt: ForwarderReceipt | None = None,
    delivery: str | None = None,
) -> ServeOutcome:
    return ServeOutcome(
        result=result, reason=reason,
        receipt_id=receipt.receipt_id if receipt is not None else None,
        dispatch_state=receipt.dispatch_state if receipt is not None else None,
        delivery=delivery,
    )


def _closed(reason: str) -> ServeOutcome:
    return _outcome("closed_without_response", reason)


def _closed_for(code: str) -> ServeOutcome:
    """Close on a gate error: the deadline and receipt codes keep their name; others are bugs."""
    known = code in ("deadline_expired", "receipt_unavailable")
    return _closed(code if known else "internal_failure")


def _safe_call(fn: Callable[[], object]) -> None:
    try:
        fn()
    except Exception:  # noqa: BLE001, S110 - an injected connector callback must never escape.
        pass


def _safe_close(closeable: object) -> None:
    def close() -> None:
        method = getattr(closeable, "close", None)
        if callable(method):
            method()
    _safe_call(close)


def _safe_abort(channel: object) -> None:
    _safe_call(lambda: channel.abort())


def _has_callables(target: object, names: tuple[str, ...]) -> bool:
    try:
        return all(callable(getattr(target, name, None)) for name in names)
    except Exception:  # noqa: BLE001 - a raising attribute lookup counts as missing.
        return False


def _valid_channel(channel: object) -> bool:
    return _has_callables(channel, ("send", "receive", "abort", "close"))


def _deliver(
    connection: object, gate: DispatchGate, receipt: ForwarderReceipt, deadline: float, *,
    upstream_response: ParsedResponse | None = None,
) -> ServeOutcome:
    """E18: send the receipt-named body, never bytes the ledger does not already own."""
    try:
        if receipt.dispatch_state == "TRANSPORT_CONFIRMED" and receipt.reason == "ok":
            body = upstream_response
        else:
            body = local_response_for(receipt)
        send_response(connection, gate.ledger, receipt, body, deadline=deadline)
    except ResponseSendError as error:
        return _outcome("delivery_failed", error.code, receipt)
    except Exception:  # noqa: BLE001 - never leak exception text into the outcome.
        return _outcome("delivery_failed", "internal_failure", receipt)
    return _outcome("responded", receipt.reason, receipt, "sent")


def _try_finish(
    gate: DispatchGate, admission: Admission, dispatch_state: str, reason: str,
    upstream_response: ParsedResponse | None = None,
) -> tuple[ForwarderReceipt | None, str | None]:
    try:
        receipt = gate.finish(
            admission, dispatch_state=dispatch_state, reason=reason,
            upstream_response=upstream_response,
        )
    except DispatchError as error:
        return None, error.code
    return receipt, None


def _finish_and_deliver(
    connection: object, gate: DispatchGate, admission: Admission, dispatch_state: str,
    reason: str, deadline: float, *, fence_passed: bool,
    upstream_response: ParsedResponse | None = None,
) -> ServeOutcome:
    """E17: finalize one flight and deliver its receipt, with the one-shot fallback rule."""
    receipt, code = _try_finish(gate, admission, dispatch_state, reason, upstream_response)
    if code is None:
        return _deliver(connection, gate, receipt, deadline, upstream_response=upstream_response)
    if code != "invalid_outcome":
        return _closed_for(code)
    receipt, code = _try_finish(gate, admission, *_unmapped_outcome(fence_passed))
    if code is None:
        return _deliver(connection, gate, receipt, deadline)
    return _closed("internal_failure")


def _unmapped_outcome(fence_passed: bool) -> tuple[str, str]:
    """E16: FAILED/connect_failed before the fence, DISPATCHED_UNKNOWN/abandoned after it."""
    return ("DISPATCHED_UNKNOWN", "abandoned") if fence_passed else ("FAILED", "connect_failed")


def _deny(
    connection: object, gate: DispatchGate, entry: object, *, route_id: str,
    request_digest: str, reason: str, request_bytes: int, deadline: float,
) -> ServeOutcome:
    """The single denial procedure: reserve and deliver one pre-dispatch receipt."""
    try:
        now = gate.now()
    except DispatchError:
        return _closed("gate_failure")
    if deadline <= now:
        return _closed("deadline_expired")
    try:
        receipt = gate.deny(
            entry, route_id=route_id, request_digest=request_digest, reason=reason,
            request_bytes=request_bytes, deadline=deadline,
        )
    except DispatchError as error:
        return _closed_for(error.code)  # scope_unknown, invalid_reason: internal_failure
    return _deliver(connection, gate, receipt, deadline)


# --- argument validation (E1) --------------------------------------------------


def _check_gate_and_policy(gate: object, policy: object) -> None:
    if type(gate) is not DispatchGate:
        raise TypeError("an exact DispatchGate is required")
    if type(policy) is not RoutePolicy:
        raise TypeError("an exact RoutePolicy is required")


def _check_service_and_upstream(service: object, upstream: object) -> None:
    if type(service) is not str:
        raise TypeError("service must be an exact str")
    if service not in SERVICE_PROFILES:
        raise ValueError("unknown service")
    if upstream is not None and not _has_callables(upstream, ("prepare", "connect")):
        raise TypeError("upstream must be None or expose callable prepare and connect")


def _check_clock_domain(gate: DispatchGate) -> None:
    if gate.system_clock is not True:
        raise ValueError("clock_domain_mismatch")


# --- the one-request exchange (E1-E19) -----------------------------------------


def serve_request(
    connection: object, *, service: str, gate: DispatchGate, policy: RoutePolicy,
    upstream: UpstreamConnector | None, started: float,
) -> ServeOutcome:
    """Serve exactly one request on ``connection``. Never closes it, never retries."""
    _check_gate_and_policy(gate, policy)
    if type(started) not in (int, float) or not math.isfinite(started):
        raise TypeError("started must be an exact finite int or float")
    _check_service_and_upstream(service, upstream)
    _check_clock_domain(gate)

    try:
        now = gate.now()
    except DispatchError:
        return _closed("gate_failure")
    if not (now - MAX_HANDLER_SECONDS < started <= now):
        return _closed("deadline_expired")
    handler_deadline = started + MAX_HANDLER_SECONDS

    opts = policy.parser_options(service)
    try:
        request, request_bytes = receive_request_sized(
            connection, service, deadline=handler_deadline,
            allowed_query_keys=opts.allowed_query_keys, accept=opts.accept,
        )
    except HTTPReceiveError:
        return _closed("request_unreadable")

    entry = gate.resolve(service=service, sentinel=request.sentinel)
    if entry is None:
        return _closed("sentinel_unknown")

    def deny(route_id: str, digest: str, reason: str, deadline: float) -> ServeOutcome:
        return _deny(
            connection, gate, entry, route_id=route_id, request_digest=digest, reason=reason,
            request_bytes=request_bytes, deadline=deadline,
        )

    if not gate.precheck(entry, sentinel=request.sentinel):
        return deny(
            UNMATCHED_ROUTE_ID, denied_request_digest(service, UNMATCHED_ROUTE_ID),
            "lease_denied", handler_deadline,
        )
    dispatch_deadline = min(handler_deadline, entry.expires_at)

    route_denial: tuple[str, str, str] | None = None
    try:
        routed = policy.route(request, entry.manifest)
    except RoutePolicyError as error:
        route_denial = (error.route_id, error.request_digest, error.receipt_reason)
    except (TypeError, ValueError):
        return _closed("internal_failure")
    if route_denial is not None:
        return deny(*route_denial, dispatch_deadline)

    denial_digest = denied_request_digest(service, routed.route_id)
    if routed.requires_permit is not False:  # unreachable in 13a: route() never sets it
        return deny(routed.route_id, denial_digest, "permit_denied", dispatch_deadline)
    if upstream is None:
        return deny(routed.route_id, denial_digest, "route_denied", dispatch_deadline)
    try:
        digest = upstream.prepare(routed)
    except Exception:  # noqa: BLE001 - an injected connector must never escape here.
        digest = None
    if (
        type(digest) is not str
        or len(digest) != 64
        or any(character not in _HEX_CHARS for character in digest)
        or hmac.compare_digest(digest, routed.request_digest)
    ):
        return deny(routed.route_id, denial_digest, "route_denied", dispatch_deadline)
    try:
        now = gate.now()
    except DispatchError:
        return _closed("gate_failure")
    if dispatch_deadline - now < RESPONSE_MARGIN_SECONDS + MIN_ADMISSION_SECONDS:
        return deny(routed.route_id, digest, "deadline", dispatch_deadline)

    reserve_code: str | None = None
    try:
        handle = gate.reserve(
            entry, routed, request_digest=digest, request_bytes=request_bytes,
            deadline=dispatch_deadline,
        )
    except DispatchError as error:
        reserve_code = error.code
    if reserve_code == "gate_closed":
        return deny(routed.route_id, digest, "lease_denied", dispatch_deadline)
    if reserve_code == "route_unavailable":
        return deny(routed.route_id, digest, "route_denied", dispatch_deadline)
    if reserve_code == "gate_held":
        return _closed("gate_failure")
    if reserve_code == "dispatch_capacity":
        return _closed(reserve_code)  # capacity (or a full ledger, below) before any bytes
    if reserve_code is not None:
        return _closed_for(reserve_code)

    try:
        return _serve_admitted(
            connection, gate, policy, handle, routed, request.sentinel, digest,
            dispatch_deadline, upstream,
        )
    finally:
        gate.release(handle)  # E19: the backstop; a no-op on every normal path


def _serve_admitted(
    connection: object, gate: DispatchGate, policy: RoutePolicy, handle: object,
    routed: RoutedRequest, sentinel: str, digest: str, dispatch_deadline: float,
    upstream: UpstreamConnector,
) -> ServeOutcome:
    try:
        outcome = gate.admit(handle, sentinel=sentinel)
    except DispatchError as error:
        return _closed_for(error.code)  # handle_unknown or handle_consumed: a bug
    if outcome.code != "admitted":
        return _deliver(connection, gate, outcome.denial, dispatch_deadline)
    admission = outcome.admission

    # Every handler below records only a code; finish and delivery run after the try, so
    # nothing raised there can carry a connector exception as its __context__.
    connect_failure: str | None = None
    try:
        channel = upstream.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline,
        )
    except Exception as error:  # noqa: BLE001 - a connect failure is finalized, not raised.
        connect_failure = _upstream_reason(error, "connect_failed", "upstream_tls_failed")
    if connect_failure is not None:
        return _finish_and_deliver(
            connection, gate, admission, "FAILED", connect_failure, dispatch_deadline,
            fence_passed=False,
        )

    if not _valid_channel(channel):
        _safe_close(channel)
        return _finish_and_deliver(
            connection, gate, admission, "FAILED", "connect_failed", dispatch_deadline,
            fence_passed=False,
        )

    try:
        return _run_channel(
            connection, gate, policy, admission, routed, sentinel, channel, dispatch_deadline,
        )
    finally:
        _safe_close(channel)  # exactly once, whichever branch below returned


def _run_channel(
    connection: object, gate: DispatchGate, policy: RoutePolicy, admission: Admission,
    routed: RoutedRequest, sentinel: str, channel: UpstreamChannel, dispatch_deadline: float,
) -> ServeOutcome:
    fence_passed = False
    unmapped = False
    failure: str | None = None
    response: ParsedResponse | None = None
    verdict_reason = ""
    try:
        # E11: attach the abort so shutdown/overdue can unblock a stuck connector.
        if not gate.attach_abort(admission, channel.abort):
            _safe_abort(channel)

        fence_code: str | None = None
        try:
            fence = gate.begin_write(admission, sentinel=sentinel)  # E12
        except DispatchError as error:
            fence_code = error.code
        if fence_code is not None:
            _safe_abort(channel)
            return _closed_for(fence_code)  # admission_unknown or write_claimed: a bug
        if fence.code != "write_admitted":
            _safe_abort(channel)
            return _deliver(connection, gate, fence.denial, dispatch_deadline)
        fence_passed = True

        failure, response = _send_and_receive(
            channel, fence.write_deadline, admission.exchange_deadline,
        )
        if failure is None:
            verdict_reason = policy.check_response(routed, response).receipt_reason  # E15
    except Exception:  # noqa: BLE001 - E16: any unmapped exception after admission.
        unmapped = True
    if unmapped:
        state, reason = _unmapped_outcome(fence_passed)
        return _finish_and_deliver(
            connection, gate, admission, state, reason, dispatch_deadline,
            fence_passed=fence_passed,
        )
    if failure is not None:
        return _finish_and_deliver(
            connection, gate, admission, "DISPATCHED_UNKNOWN", failure, dispatch_deadline,
            fence_passed=True,
        )
    return _finish_and_deliver(
        connection, gate, admission, "TRANSPORT_CONFIRMED", verdict_reason, dispatch_deadline,
        fence_passed=True, upstream_response=response,
    )


def _upstream_reason(error: Exception, default: str, mapped: str = "deadline") -> str:
    """The one ``UpstreamError`` code a phase keeps; any other exception gives ``default``."""
    return mapped if type(error) is UpstreamError and error.code == mapped else default


def _send_and_receive(
    channel: UpstreamChannel, write_deadline: float, exchange_deadline: float,
) -> tuple[str | None, ParsedResponse | None]:
    """E13-E14: one send, then one receive. A failure is its DISPATCHED_UNKNOWN reason."""
    failure: str | None = None
    try:
        channel.send(deadline=write_deadline)  # E13: the first possible upstream write
    except Exception as error:  # noqa: BLE001 - mapped to a finalized receipt by the caller.
        failure = _upstream_reason(error, "write_failed")
    if failure is not None:
        return failure, None
    try:
        response = channel.receive(deadline=exchange_deadline)  # E14
    except Exception as error:  # noqa: BLE001 - mapped to a finalized receipt by the caller.
        failure = _upstream_reason(error, "receive_failed")
    if failure is not None:
        return failure, None
    if type(response) is not ParsedResponse:
        return "receive_failed", None
    try:
        response_digest(response)
    except ReceiptError:
        failure = "malformed_response"
    return failure, (response if failure is None else None)


def serve_one(
    listener: FixedTLSListener, *, gate: DispatchGate, policy: RoutePolicy,
    upstream: UpstreamConnector | None, accept_timeout: float = 1.0,
) -> ServeOutcome:
    """Accept exactly one connection on ``listener`` and serve it, then close it."""
    if type(listener) is not FixedTLSListener:
        raise TypeError("an exact FixedTLSListener is required")
    _check_gate_and_policy(gate, policy)
    _check_service_and_upstream(listener.service, upstream)
    _check_clock_domain(gate)

    try:
        connection = listener.accept(timeout=accept_timeout)
    except TLSListenerError:
        return _closed("accept_failed")
    try:
        try:
            started = gate.now()
        except DispatchError:
            return _closed("gate_failure")
        return serve_request(
            connection, service=listener.service, gate=gate, policy=policy,
            upstream=upstream, started=started,
        )
    finally:
        _safe_close(connection)


__all__ = [
    "CLOSE_REASONS",
    "SERVE_RESULTS",
    "UPSTREAM_ERROR_CODES",
    "ServeOutcome",
    "UpstreamChannel",
    "UpstreamConnector",
    "UpstreamError",
    "serve_one",
    "serve_request",
]
