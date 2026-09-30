"""Real local TLS integration tests for receipt-gated client response delivery.

These tests exercise ``forwarder_receipts.ReceiptLedger`` and
``forwarder_response_send.send_response`` together over an actual local TLS
connection built from the existing ``FixedTLSListener``/``connect_service_tls``
fixtures (imported from ``test_forwarder_server_tls_integration`` as
``tls_fixtures``, the same pattern ``test_forwarder_http_receive_integration``
uses). Every scenario plays the server side of exactly the documented
transition protocol -- ``reserve`` before any upstream connection,
``begin_connect``/``begin_dispatch`` around the (here: synthetic, in-test)
upstream call, ``finalize`` once the outcome is known, then
``send_response`` -- and verifies what the client actually receives with
``forwarder_response_receive.receive_response`` or a raw ``recv``.

No real upstream connection is ever opened: ``TRANSPORT_CONFIRMED`` receipts
are finalized against an in-test synthetic ``ParsedResponse`` the test
constructs itself. This module owns no source file; it only observes the
already-implemented ``forwarder_receipts``/``forwarder_response_send`` seam.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import time
from contextlib import contextmanager

import pytest

from grafana_jsm_sandbox.forwarder_http_receive import receive_request
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, serialize_response
from grafana_jsm_sandbox.forwarder_receipts import (
    LOCAL_RESPONSES,
    ReceiptLedger,
    local_response_for,
)
from grafana_jsm_sandbox.forwarder_response_receive import (
    ResponseReceiveError,
    receive_response,
)
from grafana_jsm_sandbox.forwarder_response_send import ResponseSendError, send_response
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_server_tls_integration as tls_fixtures

service_tls_material = tls_fixtures.service_tls_material

_LEASE_ID = "lease-c2"
_ATTEMPT_ID = "attempt-c2"
_ROUTE_ID = "c2.synthetic.dispatch"
# Exactly MAX_BODY_BYTES (1_048_576): the largest response body the codec allows.
_ONE_MEBIBYTE_BODY = bytes(range(256)) * 4096


def _digest(wire: bytes) -> str:
    return hashlib.sha256(wire).hexdigest()


def _reserve(ledger: ReceiptLedger, wire: bytes, *, service: str, ttl: float = 5.0):
    """Reserve one receipt slot for a synthetic lease/attempt/route."""
    return ledger.reserve(
        lease_id=_LEASE_ID, attempt_id=_ATTEMPT_ID, service=service, route_id=_ROUTE_ID,
        request_digest=_digest(wire), request_bytes=len(wire),
        deadline=time.monotonic() + ttl,
    )


@contextmanager
def dispatch_peer(monkeypatch, material, handler, *, service="jira", timeout=2.0):
    """Run one real local-TLS connection against ``handler`` and yield the client.

    Mirrors ``test_forwarder_http_receive_integration.receiving_peer``: the
    server thread runs ``handler(connection)`` to completion (any expected
    rejection must be caught inside ``handler`` itself, or it surfaces as an
    unexpected worker failure), then the fixture asserts it was reached.
    """
    with tls_fixtures.ephemeral_listener(monkeypatch, material, service) as (listener, _address):
        with tls_fixtures.serve_once(listener, handler, timeout=timeout) as (outcomes, completed):
            base, _paths = material
            client = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=timeout)
            try:
                yield client
            finally:
                client.close()
                assert completed.wait(timeout + 3), "server handler did not finish"
        assert outcomes == ["accepted"]


# --- (1) NOT_DISPATCHED / lease_denied -> fixed local 403 -------------------


def test_not_dispatched_lease_denied_sends_fixed_403(service_tls_material, monkeypatch):
    service = "jira"
    wire = tls_fixtures.wire_request(service)
    ledger = ReceiptLedger(generation="c2-not-dispatched")
    filenos: list[int] = []

    def handle(connection):
        receive_request(connection, service, deadline=time.monotonic() + 2)
        reservation = _reserve(ledger, wire, service=service)
        receipt = ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="lease_denied")
        response = local_response_for(receipt)
        result = send_response(connection, ledger, receipt, response, deadline=time.monotonic() + 2)
        assert result.outcome == "sent"
        filenos.append(connection.fileno())

    with dispatch_peer(monkeypatch, service_tls_material, handle, service=service) as client:
        client.sendall(wire)
        parsed = receive_response(client, deadline=time.monotonic() + 2)
        assert parsed == LOCAL_RESPONSES["denied"]
        assert parsed.status == 403
        assert parsed.body == b'{"error":"forwarder_denied"}'

    assert filenos and filenos[0] >= 0  # send_response never closed the socket
    entries = ledger.snapshot()["entries"]
    assert len(entries) == 1
    assert entries[0]["dispatch_state"] == "NOT_DISPATCHED"
    assert entries[0]["reason"] == "lease_denied"
    assert entries[0]["delivery_outcome"] == "sent"


# --- (2) TRANSPORT_CONFIRMED / ok -> byte-exact forwarding, all services ----


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_transport_confirmed_ok_forwards_synthetic_upstream_byte_exact(
    service_tls_material, monkeypatch, service,
):
    wire = tls_fixtures.wire_request(service)
    ledger = ReceiptLedger(generation="c2-confirmed")
    # A synthetic in-test upstream response; no real upstream connection exists.
    upstream = ParsedResponse(200, f'{{"service":"{service}","synthetic":true}}'.encode())
    filenos: list[int] = []

    def handle(connection):
        receive_request(connection, service, deadline=time.monotonic() + 2)
        reservation = _reserve(ledger, wire, service=service)
        ledger.begin_connect(reservation)
        ledger.begin_dispatch(reservation)
        receipt = ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
            upstream_response=upstream,
        )
        result = send_response(connection, ledger, receipt, upstream, deadline=time.monotonic() + 2)
        assert result.outcome == "sent"
        assert result.bytes_sent == len(serialize_response(upstream))
        filenos.append(connection.fileno())

    with dispatch_peer(monkeypatch, service_tls_material, handle, service=service) as client:
        client.sendall(wire)
        parsed = receive_response(client, deadline=time.monotonic() + 2)
        assert parsed == upstream

    assert filenos and filenos[0] >= 0
    entries = ledger.snapshot()["entries"]
    assert len(entries) == 1
    assert entries[0]["dispatch_state"] == "TRANSPORT_CONFIRMED"
    assert entries[0]["reason"] == "ok"
    assert entries[0]["delivery_outcome"] == "sent"
    assert entries[0]["http_status_class"] == "2xx"


# --- (3) a ~1 MiB body is chunked on send and received intact ---------------


def test_one_mebibyte_body_is_chunked_on_send_and_received_intact(service_tls_material, monkeypatch):
    service = "jira"
    wire = tls_fixtures.wire_request(service)
    ledger = ReceiptLedger(generation="c2-large-body")
    upstream = ParsedResponse(200, _ONE_MEBIBYTE_BODY)
    wire_response = serialize_response(upstream)

    def handle(connection):
        receive_request(connection, service, deadline=time.monotonic() + 5)
        reservation = _reserve(ledger, wire, service=service, ttl=10)
        ledger.begin_connect(reservation)
        ledger.begin_dispatch(reservation)
        receipt = ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
            upstream_response=upstream,
        )
        result = send_response(connection, ledger, receipt, upstream, deadline=time.monotonic() + 10)
        assert result.outcome == "sent"
        assert result.bytes_sent == len(wire_response)

    with dispatch_peer(
        monkeypatch, service_tls_material, handle, service=service, timeout=6,
    ) as client:
        client.sendall(wire)
        parsed = receive_response(client, deadline=time.monotonic() + 10)
        assert parsed.status == 200
        assert len(parsed.body) == len(_ONE_MEBIBYTE_BODY)
        assert parsed.body == _ONE_MEBIBYTE_BODY  # every byte, in order, intact

    entries = ledger.snapshot()["entries"]
    assert entries[0]["delivery_outcome"] == "sent"
    assert entries[0]["client_response_bytes"] == len(wire_response)


# --- (4) digest mismatch -> sends nothing; client observes EOF, no bytes ----


def test_digest_mismatch_sends_nothing_client_sees_eof(service_tls_material, monkeypatch):
    service = "jira"
    wire = tls_fixtures.wire_request(service)
    ledger = ReceiptLedger(generation="c2-mismatch")
    upstream = ParsedResponse(200, b'{"ok":true}')
    tampered = ParsedResponse(200, b'{"ok":false}')
    mismatch_codes: list[str] = []
    filenos: list[int] = []

    def handle(connection):
        receive_request(connection, service, deadline=time.monotonic() + 2)
        reservation = _reserve(ledger, wire, service=service)
        ledger.begin_connect(reservation)
        ledger.begin_dispatch(reservation)
        receipt = ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
            upstream_response=upstream,
        )
        try:
            send_response(connection, ledger, receipt, tampered, deadline=time.monotonic() + 2)
        except ResponseSendError as error:
            mismatch_codes.append(error.code)
        filenos.append(connection.fileno())

    with dispatch_peer(monkeypatch, service_tls_material, handle, service=service) as client:
        client.sendall(wire)
        # No bytes were ever offered to the transport: whether the peer close
        # is graceful (b"") or abrupt (raises), either way nothing arrives.
        try:
            observed = client.recv(4096)
        except (OSError, ssl.SSLError):
            observed = b""
        assert observed == b""
        with pytest.raises(ResponseReceiveError):
            receive_response(client, deadline=time.monotonic() + 1)

    assert mismatch_codes == ["receipt_mismatch"]
    assert filenos and filenos[0] >= 0  # the failed attempt still never closed the socket
    entries = ledger.snapshot()["entries"]
    assert len(entries) == 1
    # A mismatch never claims delivery: the receipt is finalized but undelivered.
    assert entries[0]["delivery_outcome"] == "pending"


# --- (5) a stalled, non-reading client reaches send_unknown within deadline -


def test_stalled_client_reaches_send_unknown_within_short_deadline(
    service_tls_material, monkeypatch,
):
    service = "jira"
    wire = tls_fixtures.wire_request(service)
    ledger = ReceiptLedger(generation="c2-stalled")
    upstream = ParsedResponse(200, _ONE_MEBIBYTE_BODY)
    send_codes: list[str] = []
    filenos: list[int] = []

    def handle(connection):
        receive_request(connection, service, deadline=time.monotonic() + 3)
        # Shrink the server's send buffer so a non-reading peer backpressures fast.
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        reservation = _reserve(ledger, wire, service=service, ttl=10)
        ledger.begin_connect(reservation)
        ledger.begin_dispatch(reservation)
        receipt = ledger.finalize(
            reservation, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
            upstream_response=upstream,
        )
        # The outer 6s wait below is only a hang guard; the *real* bound this
        # test pins is the deadline actually handed to send_response
        # (`_SEND_DEADLINE_BUDGET`), not that much looser guard. Both the
        # deadline argument and the elapsed-time assertion are derived from
        # the one shared budget below so they can never drift apart. A
        # regression that derived each per-chunk socket timeout from a fixed
        # constant instead of the real, deadline-derived remaining time would
        # still finish well under 6s and slip past a hang-guard-only check
        # unnoticed; it would not slip past this tighter, deadline-tracking one.
        _SEND_DEADLINE_BUDGET = 2.0
        _SLACK_SECONDS = 1.0
        send_started = time.monotonic()
        try:
            send_response(
                connection, ledger, receipt, upstream,
                deadline=send_started + _SEND_DEADLINE_BUDGET,
            )
        except ResponseSendError as error:
            send_codes.append(error.code)
        send_elapsed = time.monotonic() - send_started
        max_elapsed = _SEND_DEADLINE_BUDGET + _SLACK_SECONDS
        assert send_elapsed < max_elapsed, (
            f"send_response took {send_elapsed:.3f}s, not <= {max_elapsed:.1f}s "
            f"(deadline budget was {_SEND_DEADLINE_BUDGET:.1f}s)"
        )
        filenos.append(connection.fileno())

    with tls_fixtures.ephemeral_listener(monkeypatch, service_tls_material, service) as (
        listener, _address,
    ):
        with tls_fixtures.serve_once(listener, handle, timeout=4) as (outcomes, completed):
            base, _paths = service_tls_material
            client = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=4)
            try:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                started = time.monotonic()
                client.sendall(wire)
                # Deliberately never read the response: force the server's
                # send() to block on a full send buffer and time out.
                assert completed.wait(6), "stalled-send handler did not finish in time"
                assert time.monotonic() - started < 6, "stalled send took unexpectedly long"
            finally:
                client.close()
        assert outcomes == ["accepted"]

    assert send_codes and send_codes[0] in ("send_failed", "deadline_expired")
    assert filenos and filenos[0] >= 0  # never closed by send_response, even on failure
    entries = ledger.snapshot()["entries"]
    assert len(entries) == 1
    assert entries[0]["delivery_outcome"] == "send_unknown"


# --- (6) a second send on the same connection is rejected -------------------


def test_second_send_on_same_connection_is_rejected(service_tls_material, monkeypatch):
    service = "jira"
    wire = tls_fixtures.wire_request(service)
    ledger = ReceiptLedger(generation="c2-double-send")
    second_codes: list[str] = []
    filenos: list[int] = []

    def handle(connection):
        receive_request(connection, service, deadline=time.monotonic() + 2)
        first_reservation = _reserve(ledger, wire, service=service)
        first_receipt = ledger.finalize(
            first_reservation, dispatch_state="NOT_DISPATCHED", reason="lease_denied",
        )
        first_response = local_response_for(first_receipt)
        first_result = send_response(
            connection, ledger, first_receipt, first_response, deadline=time.monotonic() + 2,
        )
        assert first_result.outcome == "sent"
        filenos.append(connection.fileno())

        second_reservation = _reserve(ledger, wire, service=service)
        second_receipt = ledger.finalize(
            second_reservation, dispatch_state="NOT_DISPATCHED", reason="lease_denied",
        )
        second_response = local_response_for(second_receipt)
        try:
            send_response(
                connection, ledger, second_receipt, second_response, deadline=time.monotonic() + 2,
            )
        except ResponseSendError as error:
            second_codes.append(error.code)
        filenos.append(connection.fileno())

    with dispatch_peer(monkeypatch, service_tls_material, handle, service=service) as client:
        client.sendall(wire)
        parsed = receive_response(client, deadline=time.monotonic() + 2)
        assert parsed == LOCAL_RESPONSES["denied"]

    assert second_codes == ["connection_claimed"]
    assert filenos == [filenos[0], filenos[0]]  # send_response never closed the socket, either call
    assert filenos[0] >= 0
    entries = ledger.snapshot()["entries"]
    assert len(entries) == 2
    # Ledger entries preserve reservation order: the first send delivered, the
    # rejected second attempt never even reached ledger.claim_delivery.
    assert entries[0]["delivery_outcome"] == "sent"
    assert entries[1]["delivery_outcome"] == "pending"
