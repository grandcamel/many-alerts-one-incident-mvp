"""Real local TLS response collection, without upstream or client forwarding."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager

import pytest

from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, serialize_response
from grafana_jsm_sandbox.forwarder_response_receive import ResponseReceiveError, receive_response
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_server_tls_integration as tls_fixtures

service_tls_material = tls_fixtures.service_tls_material


@contextmanager
def responding_peer(monkeypatch, material, wire, *, service="jira", fragment=None, eof=False):
    release = threading.Event()
    with tls_fixtures.ephemeral_listener(monkeypatch, material, service) as (listener, _address):
        def handle(connection):
            if wire:
                size = fragment or len(wire)
                for offset in range(0, len(wire), size):
                    connection.sendall(wire[offset:offset + size])
            if not eof:
                assert release.wait(3), "response fixture was not released"

        with tls_fixtures.serve_once(listener, handle, timeout=2) as (outcomes, finished):
            base, _paths = material
            client = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=2)
            try:
                yield client
            finally:
                release.set()
                client.close()
                assert finished.wait(2), "response fixture did not finish"
            assert outcomes == ["accepted"]


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_fragmented_response_uses_strict_local_tls_and_is_collected_once(
    service_tls_material, monkeypatch, service,
):
    body = b'{"message":"fragmented fixture"}'
    expected = ParsedResponse(status=200, body=body)
    with responding_peer(monkeypatch, service_tls_material, serialize_response(expected),
                         service=service, fragment=7) as client:
        original_timeout = client.gettimeout()
        parsed = receive_response(client, deadline=time.monotonic() + 2)
        assert parsed == expected
        assert client.gettimeout() == original_timeout
        assert client.fileno() >= 0  # Collector preserves caller ownership.
        assert "fragmented fixture" not in repr(parsed)
        with pytest.raises(ResponseReceiveError):
            receive_response(client, deadline=time.monotonic() + 2)


@pytest.mark.parametrize("status", [204, 205])
def test_no_body_response_finishes_without_waiting_for_eof(service_tls_material, monkeypatch, status):
    response = ParsedResponse(status=status, body=b"")
    with responding_peer(monkeypatch, service_tls_material, serialize_response(response),
                         fragment=1) as client:
        assert receive_response(client, deadline=time.monotonic() + 2) == response


def test_opaque_response_bytes_remain_unchanged(service_tls_material, monkeypatch):
    response = ParsedResponse(status=500, body=bytes(range(256)) * 32)
    with responding_peer(monkeypatch, service_tls_material, serialize_response(response),
                         fragment=1024) as client:
        assert receive_response(client, deadline=time.monotonic() + 2) == response


@pytest.mark.parametrize("wire", [
    b"HTTP/1.1 302 Redirect\r\nLocation: private-upstream\r\nContent-Length: 9000\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 200 " + b"x" * 2049,
])
def test_invalid_head_rejects_while_peer_remains_open(service_tls_material, monkeypatch, wire):
    with responding_peer(monkeypatch, service_tls_material, wire) as client:
        started = time.monotonic()
        with pytest.raises(ResponseReceiveError) as caught:
            receive_response(client, deadline=started + 2)
        assert time.monotonic() - started < 1
        assert "private-upstream" not in str(caught.value)
        assert client.fileno() >= 0


def test_captured_second_response_is_rejected(service_tls_material, monkeypatch):
    wire = serialize_response(ParsedResponse(status=200, body=b"{}"))
    with (
        responding_peer(monkeypatch, service_tls_material, wire + wire) as client,
        pytest.raises(ResponseReceiveError),
    ):
        receive_response(client, deadline=time.monotonic() + 2)


@pytest.mark.parametrize("prefix", [b"", b"HTTP/1.1 200 OK\r\nContent-Type: "])
def test_stalled_response_uses_original_deadline(service_tls_material, monkeypatch, prefix):
    with responding_peer(monkeypatch, service_tls_material, prefix) as client:
        started = time.monotonic()
        with pytest.raises(ResponseReceiveError):
            receive_response(client, deadline=started + 0.15)
        assert time.monotonic() - started < 1


def test_truncated_response_eof_cannot_report_success(service_tls_material, monkeypatch):
    wire = serialize_response(ParsedResponse(status=200, body=b"abcdef"))[:-3]
    with (
        responding_peer(monkeypatch, service_tls_material, wire, eof=True) as client,
        pytest.raises(ResponseReceiveError),
    ):
        receive_response(client, deadline=time.monotonic() + 2)
