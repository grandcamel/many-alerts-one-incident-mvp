"""Real local TLS collection; production routing and responses remain separate."""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager

import pytest

from grafana_jsm_sandbox.forwarder_http_receive import HTTPReceiveError, receive_request
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_server_tls_integration as tls_fixtures

service_tls_material = tls_fixtures.service_tls_material


@contextmanager
def receiving_peer(monkeypatch, material, *, service="jira", timeout=1.0):
    outcomes = []
    arrived = threading.Event()
    finished = threading.Event()
    with tls_fixtures.ephemeral_listener(monkeypatch, material, service) as (listener, _address):
        def handle(connection):
            arrived.set()
            try:
                parsed = receive_request(connection, service, deadline=time.monotonic() + timeout)
                outcomes.append(parsed)
                # Only the fixture sends this acknowledgement, not the collector.
                connection.sendall(b"ok")
                with pytest.raises(HTTPReceiveError):
                    receive_request(connection, service, deadline=time.monotonic() + 1)
                assert connection.recv(1) == b""
                connection.unwrap().close()
            except HTTPReceiveError as error:
                outcomes.append(error.code)
            finally:
                finished.set()

        with tls_fixtures.serve_once(listener, handle, timeout=2) as (_listener_outcomes, done):
            base, _paths = material
            client = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=2)
            try:
                assert arrived.wait(1)
                yield client, outcomes, finished
            finally:
                client.close()
                assert done.wait(2), "collector fixture did not finish"


def body_request(service, body):
    head = tls_fixtures.wire_request(service).replace(b"GET ", b"POST ", 1)
    return head[:-2] + (f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
                      .encode()) + body


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_fragmented_tls_request_is_collected_once(service_tls_material, monkeypatch, service):
    body = b'{\n  "message": "hello"\n}\n'
    wire = body_request(service, body)
    with receiving_peer(monkeypatch, service_tls_material, service=service) as (client, results, done):
        for offset in range(0, len(wire), 7):
            client.sendall(wire[offset:offset + 7])
        assert client.recv(2) == b"ok"
        client.unwrap().close()
        assert done.wait(1)
    assert len(results) == 1
    assert results[0].service == service
    assert results[0].body == body
    assert "hello" not in repr(results[0])


def test_binary_body_is_preserved_over_real_tls(service_tls_material, monkeypatch):
    body = bytes(range(256)) * 32 + b"\r\nGET /in-body HTTP/1.1\r\n\r\n"
    with receiving_peer(monkeypatch, service_tls_material) as (client, results, done):
        client.sendall(body_request("jira", body))
        assert client.recv(2) == b"ok"
        client.unwrap().close()
        assert done.wait(1)
    assert results[0].body == body  # Route-specific JSON validation is still required.


@pytest.mark.parametrize("malformed", [
    b"GET / HTTP/1.1\r\nHost: wrong\r\n\r\n",
    b"GET /" + b"x" * 2049 + b" HTTP/1.1\r\n\r\n",
])
def test_invalid_heads_fail_without_waiting_for_a_body(service_tls_material, monkeypatch, malformed):
    with receiving_peer(monkeypatch, service_tls_material) as (client, results, done):
        client.sendall(malformed)
        assert done.wait(1)
    assert len(results) == 1 and isinstance(results[0], str)


def test_captured_pipelining_is_rejected(service_tls_material, monkeypatch):
    wire = tls_fixtures.wire_request("jira")
    with receiving_peer(monkeypatch, service_tls_material) as (client, results, done):
        # Both short requests fit the first collector read and one TLS record.
        client.sendall(wire + wire)
        assert done.wait(1)
    assert len(results) == 1 and isinstance(results[0], str)


@pytest.mark.parametrize("prefix", [b"", b"GET / HTTP/1.1\r\nHost: "])
def test_stalled_tls_input_obeys_absolute_deadline(service_tls_material, monkeypatch, prefix):
    with receiving_peer(monkeypatch, service_tls_material, timeout=0.15) as (client, results, done):
        if prefix:
            client.sendall(prefix)
        assert done.wait(1)
    assert len(results) == 1 and isinstance(results[0], str)


def test_transport_eof_before_body_completion_is_not_success(service_tls_material, monkeypatch):
    wire = body_request("jira", b"abcdef")
    with receiving_peer(monkeypatch, service_tls_material) as (client, results, done):
        client.sendall(wire[:-3])
        # Abrupt client EOF is a failure case; no successful-TLS shutdown claim.
        client.shutdown(socket.SHUT_RDWR)
        client.close()
        assert done.wait(1)
    assert len(results) == 1 and isinstance(results[0], str)
