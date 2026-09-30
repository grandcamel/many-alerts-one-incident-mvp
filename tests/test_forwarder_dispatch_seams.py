"""Additive-seam tests for unit 13a: byte-counted receive, listener service binding.

These prove `receive_request_sized`/private `_receive` preserve `receive_request`'s
exact behavior while additionally reporting the exact inbound wire byte count, and
that `FixedTLSListener.service` exposes the bound service, read-only, for every
listener. No dispatch gate or exchange behavior is exercised here.

Each real-TLS peer gets its own `pytest.MonkeyPatch` scope: `ephemeral_listener`
wraps `socket.socket` for the duration of one listener, and nesting two such
scopes under one shared `monkeypatch` fixture would double-wrap the socket class.
"""

from __future__ import annotations

import ssl
import threading
import time
from contextlib import contextmanager

import pytest

from grafana_jsm_sandbox.forwarder_http import MAX_BODY_BYTES
from grafana_jsm_sandbox.forwarder_http_receive import (
    HTTPReceiveError,
    receive_request,
    receive_request_sized,
)
from grafana_jsm_sandbox.forwarder_server_tls import FixedTLSListener
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_server_tls_integration as tls_fixtures

service_tls_material = tls_fixtures.service_tls_material


def body_request(service, body):
    head = tls_fixtures.wire_request(service).replace(b"GET ", b"POST ", 1)
    return head[:-2] + (f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
                       .encode()) + body


@contextmanager
def _sized_peer(material, *, service="jira", timeout=1.0, reader=receive_request_sized):
    """Serve exactly one real-TLS connection, running `reader` on the server side."""
    outcomes = []
    arrived = threading.Event()
    with (
        pytest.MonkeyPatch.context() as mp,
        tls_fixtures.ephemeral_listener(mp, material, service) as (listener, _addr),
    ):
        def handle(connection):
            arrived.set()
            try:
                deadline = time.monotonic() + timeout
                outcomes.append(reader(connection, service, deadline=deadline))
                connection.sendall(b"ok")
                assert connection.recv(1) == b""
                connection.unwrap().close()
            except HTTPReceiveError as error:
                outcomes.append(error.code)

        with tls_fixtures.serve_once(listener, handle, timeout=2) as (_outcomes, done):
            base, _paths = material
            client = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=2)
            try:
                assert arrived.wait(1)
                yield client, outcomes
            finally:
                client.close()
                assert done.wait(2), "sized collector fixture did not finish"


def _send_whole(client, wire):
    client.sendall(wire)


def _send_fragmented(client, wire):
    for offset in range(0, len(wire), 7):
        client.sendall(wire[offset:offset + 7])


@pytest.mark.parametrize("shape,sender", [
    ("fragmented", _send_fragmented),
    ("coalesced", _send_whole),
    ("zero_body", _send_whole),
    ("max_body", _send_whole),
])
def test_receive_request_sized_counts_equal_wire_bytes(service_tls_material, shape, sender):
    if shape == "zero_body":
        wire = tls_fixtures.wire_request("jira")
    elif shape == "max_body":
        wire = body_request("jira", b"x" * MAX_BODY_BYTES)
    else:
        wire = body_request("jira", b'{"a": 1}')

    with _sized_peer(service_tls_material) as (client, outcomes):
        sender(client, wire)
        assert client.recv(2) == b"ok"
        client.unwrap().close()

    assert len(outcomes) == 1
    request, count = outcomes[0]
    assert not isinstance(request, str)
    assert count == len(wire)


def test_receive_request_sized_error_codes_match_receive_request(service_tls_material):
    malformed = [
        b"GET / HTTP/1.1\r\nHost: wrong\r\n\r\n",
        b"GET /" + b"x" * 2049 + b" HTTP/1.1\r\n\r\n",
    ]
    for wire in malformed:
        with _sized_peer(service_tls_material, reader=receive_request) as (client, plain):
            client.sendall(wire)
        with _sized_peer(service_tls_material, reader=receive_request_sized) as (client, sized):
            client.sendall(wire)

        assert len(plain) == 1 and isinstance(plain[0], str)
        assert sized == plain


def test_receive_request_sized_result_matches_receive_request_result(service_tls_material):
    wire = body_request("jira", b'{"ok": true}')

    with _sized_peer(service_tls_material, reader=receive_request) as (client, plain):
        client.sendall(wire)
        assert client.recv(2) == b"ok"
        client.unwrap().close()

    with _sized_peer(service_tls_material, reader=receive_request_sized) as (client, sized):
        client.sendall(wire)
        assert client.recv(2) == b"ok"
        client.unwrap().close()

    assert len(plain) == 1 and len(sized) == 1
    sized_request, sized_count = sized[0]
    assert sized_request == plain[0]
    assert sized_count == len(wire)


# Non-default reader options the existing parser already accepts: a Jira query key,
# and the one non-JSON Accept value (anthropic's event stream).
@pytest.mark.parametrize("service,edit,options,field,expected", [
    ("jira", (b"/local-fixture ", b"/local-fixture?fields=summary "),
     {"allowed_query_keys": frozenset({"fields"})}, "query", (("fields", "summary"),)),
    ("anthropic", (b"Accept: application/json", b"Accept: text/event-stream"),
     {"accept": "text/event-stream"}, "accept", "text/event-stream"),
])
def test_receive_request_forwards_non_default_options_like_sized(
    service_tls_material, service, edit, options, field, expected,
):
    wire = tls_fixtures.wire_request(service).replace(*edit, 1)

    def plain_reader(connection, name, *, deadline):
        return receive_request(connection, name, deadline=deadline, **options)

    def sized_reader(connection, name, *, deadline):
        return receive_request_sized(connection, name, deadline=deadline, **options)

    results = []
    for reader in (plain_reader, sized_reader):
        with _sized_peer(service_tls_material, service=service, reader=reader) as (client, out):
            client.sendall(wire)
            assert client.recv(2) == b"ok"
            client.unwrap().close()
        results.append(out)

    (plain,), (sized,) = results
    sized_request, sized_count = sized
    assert getattr(plain, field) == expected
    assert sized_request == plain
    assert sized_count == len(wire)


@pytest.mark.parametrize("first,second", [
    (receive_request, receive_request_sized),
    (receive_request_sized, receive_request),
])
def test_receive_request_and_sized_share_one_socket_claim_marker(
    service_tls_material, first, second,
):
    wire = tls_fixtures.wire_request("jira")
    outcomes = []
    arrived = threading.Event()
    with (
        pytest.MonkeyPatch.context() as mp,
        tls_fixtures.ephemeral_listener(mp, service_tls_material, "jira") as (listener, _addr),
    ):
        def handle(connection):
            arrived.set()
            outcomes.append(first(connection, "jira", deadline=time.monotonic() + 1))
            with pytest.raises(HTTPReceiveError) as raised:
                second(connection, "jira", deadline=time.monotonic() + 1)
            outcomes.append(raised.value.code)
            connection.sendall(b"ok")
            assert connection.recv(1) == b""
            connection.unwrap().close()

        with tls_fixtures.serve_once(listener, handle, timeout=2) as (_outcomes, done):
            base, _paths = service_tls_material
            client = connect_service_tls("jira", ca_pem=base.ca_cert.read_text(), timeout=2)
            try:
                assert arrived.wait(1)
                client.sendall(wire)
                assert client.recv(2) == b"ok"
                client.unwrap().close()
            finally:
                client.close()
            assert done.wait(2), "marker collector fixture did not finish"

    assert len(outcomes) == 2
    assert outcomes[1] == "connection_claimed"


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_fixed_tls_listener_service_property_returns_bound_service(service):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    listener = FixedTLSListener(service, context=context)
    try:
        assert listener.service == service
        with pytest.raises(AttributeError):
            listener.service = "other"
    finally:
        assert listener.close() == "closed"
