"""Local TLS listener tests; no upstream, native client or deployment qualification."""

from __future__ import annotations

import base64
import socket
import ssl
import threading
from contextlib import contextmanager

import pytest

from grafana_jsm_sandbox.forwarder_http import parse_request
from grafana_jsm_sandbox.forwarder_server_tls import FixedTLSListener, TLSListenerError
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_tls_integration as material_fixtures

service_tls_material = material_fixtures.tls_material

def server_context(material, service):
    base, paths = material
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(paths[service], base.server_key)
    return context


@contextmanager
def ephemeral_listener(monkeypatch, material, service="jira"):
    """Assert the fixed bind/connect choices, redirect only for ephemeral fixtures."""
    original = socket.socket
    profile = SERVICE_PROFILES[service]
    addresses = []
    attempts = []

    class FixtureSocket(original):
        def bind(self, address):
            assert address == (profile.bind_host, profile.port)
            attempts.append(address)
            result = super().bind(("127.0.0.1", 0))
            addresses.append(self.getsockname())
            return result

        def connect(self, address):
            if address == (profile.bind_host, profile.port):
                address = addresses[0]
            return super().connect(address)

    monkeypatch.setattr(socket, "socket", FixtureSocket)
    listener = FixedTLSListener(service, context=server_context(material, service))
    listener.open()
    try:
        assert attempts == [(profile.bind_host, profile.port)]
        yield listener, addresses[0]
    finally:
        listener.close()


@contextmanager
def serve_once(listener, handler, *, timeout=1.0):
    outcomes = []
    unexpected = []
    completed = threading.Event()

    def serve():
        connection = None
        try:
            connection = listener.accept(timeout=timeout)
            handler(connection)
            outcomes.append("accepted")
        except TLSListenerError as error:
            outcomes.append(error.code)
        except BaseException as error:  # noqa: BLE001 - expose thread test failures
            unexpected.append(error)
        finally:
            if connection is not None:
                connection.close()
            completed.set()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield outcomes, completed
    finally:
        listener.close()
        worker.join(3.0)
        assert not worker.is_alive(), "listener test worker did not exit"
        assert not unexpected, [type(error).__name__ for error in unexpected]
        assert listener.close() == "closed"


def client_context(material):
    base, _paths = material
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=base.ca_cert.read_text())
    context.set_alpn_protocols(["http/1.1"])
    return context


def wire_request(service):
    profile = SERVICE_PROFILES[service]
    token = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    authorization = ("Basic " + base64.b64encode(f"run:{token}".encode()).decode()
                     if profile.sentinel_scheme == "Basic" else "Bearer " + token)
    return (f"GET /local-fixture HTTP/1.1\r\nHost: {profile.server_name}:{profile.port}\r\n"
            f"Authorization: {authorization}\r\nAccept: application/json\r\n\r\n").encode()


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_strict_client_listener_and_http_parser_compose_locally(service_tls_material, monkeypatch, service):
    base, _paths = service_tls_material
    wire = wire_request(service)
    received = []

    def handle(connection):
        assert connection.get_inheritable() is False
        assert connection.version() in {"TLSv1.2", "TLSv1.3"}
        captured = bytearray()
        # Known-length fixture collection only, not the future production reader.
        while len(captured) < len(wire):
            chunk = connection.recv(len(wire) - len(captured))
            assert chunk
            captured.extend(chunk)
        received.append(parse_request(bytes(captured), service))
        connection.sendall(b"ok")
        assert connection.recv(1) == b""
        connection.unwrap().close()

    with (
        ephemeral_listener(monkeypatch, service_tls_material, service) as (listener, _address),
        serve_once(listener, handle) as (outcomes, completed),
    ):
        connection = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=2)
        try:
            connection.sendall(wire)
            assert connection.recv(2) == b"ok"
            connection.unwrap().close()
        finally:
            connection.close()
        assert completed.wait(2)
        assert outcomes == ["accepted"]
    assert received[0].path == "/local-fixture"
    assert received[0].service == service


@pytest.mark.parametrize("name", [None, "wrong.invalid", "forwarder-grafana.maoi.local"])
def test_missing_or_cross_service_sni_never_reaches_application(service_tls_material, monkeypatch, name):
    reached = []
    context = client_context(service_tls_material)
    if name is None:
        context.check_hostname = False  # CA verification stays enabled; exercise absent SNI.
    with (
        ephemeral_listener(monkeypatch, service_tls_material) as (listener, address),
        serve_once(listener, lambda conn: reached.append(conn)) as (outcomes, completed),
    ):
        raw = socket.create_connection(address, timeout=2)
        try:
            with pytest.raises(ssl.SSLError):
                context.wrap_socket(raw, server_hostname=name)
        finally:
            raw.close()
        assert completed.wait(2)
        assert outcomes and outcomes != ["accepted"]
    assert reached == []


def test_exact_sni_negotiates_only_http11_alpn(service_tls_material, monkeypatch):
    selected = []

    def handle(connection):
        selected.append(connection.selected_alpn_protocol())
        connection.sendall(b"ok")
        assert connection.recv(1) == b""
        connection.unwrap().close()

    with (
        ephemeral_listener(monkeypatch, service_tls_material) as (listener, address),
        serve_once(listener, handle) as (outcomes, completed),
    ):
        context = client_context(service_tls_material)
        context.set_alpn_protocols(["h2", "http/1.1"])
        with context.wrap_socket(socket.create_connection(address, timeout=2),
                                 server_hostname=SERVICE_PROFILES["jira"].server_name) as client:
            assert client.selected_alpn_protocol() == "http/1.1"
            assert client.recv(2) == b"ok"
            client.unwrap().close()
        assert completed.wait(2)
        assert outcomes == ["accepted"]
    assert selected == ["http/1.1"]


@pytest.mark.parametrize("mode", ["plaintext", "stalled"])
def test_plaintext_or_stalled_handshake_is_bounded(service_tls_material, monkeypatch, mode):
    reached = []
    with (
        ephemeral_listener(monkeypatch, service_tls_material) as (listener, address),
        serve_once(listener, lambda conn: reached.append(conn), timeout=0.15) as (outcomes, done),
        socket.create_connection(address, timeout=1) as client,
    ):
        if mode == "plaintext":
            client.sendall(b"GET / HTTP/1.1\r\n\r\n")
        assert done.wait(1.5)
        assert outcomes and outcomes != ["accepted"]
    assert reached == []


def test_close_interrupts_idle_accept_and_later_calls_are_terminal(service_tls_material, monkeypatch):
    entered = threading.Event()
    with ephemeral_listener(monkeypatch, service_tls_material) as (listener, _address):
        original = socket.socket.accept

        def observed_accept(connection):
            entered.set()
            return original(connection)

        monkeypatch.setattr(socket.socket, "accept", observed_accept)
        with serve_once(listener, lambda _conn: pytest.fail("unexpected connection"), timeout=5) as (_, done):
            assert entered.wait(1)
            assert listener.close() == "unknown"
            assert done.wait(1.5)
            assert listener.close() == "closed"
            with pytest.raises(TLSListenerError):
                listener.open()
            with pytest.raises(TLSListenerError):
                listener.accept()


def test_close_interrupts_stalled_tls_handshake(service_tls_material, monkeypatch):
    entered = threading.Event()
    original = ssl.SSLSocket.do_handshake

    def observed_handshake(connection, *args, **kwargs):
        entered.set()
        return original(connection, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLSocket, "do_handshake", observed_handshake)
    with (
        ephemeral_listener(monkeypatch, service_tls_material) as (listener, address),
        serve_once(listener, lambda _conn: pytest.fail('unexpected handshake'), timeout=5) as (_, done),
    ):
        with socket.create_connection(address, timeout=1):
            assert entered.wait(1)
            assert listener.close() == "unknown"
            assert done.wait(1.5)
        assert listener.close() == "closed"


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_actual_fixed_port_bind_is_exclusive_without_fallback(service_tls_material, service):
    # Actual prescribed ports. An existing occupant is a visible failure, not killed/skipped.
    profile = SERVICE_PROFILES[service]
    listener = FixedTLSListener(service, context=server_context(service_tls_material, service))
    listener.open()
    try:
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as contender,
            pytest.raises(OSError),
        ):
            contender.bind((profile.bind_host, profile.port))
        duplicate = FixedTLSListener(service, context=server_context(service_tls_material, service))
        try:
            with pytest.raises(TLSListenerError):
                duplicate.open()
            with pytest.raises(TLSListenerError):
                duplicate.open()
        finally:
            assert duplicate.close() == "closed"
    finally:
        assert listener.close() == "closed"


def test_returned_connection_survives_listener_close(service_tls_material, monkeypatch):
    base, _paths = service_tls_material
    with ephemeral_listener(monkeypatch, service_tls_material) as (listener, _address):
        def handle(connection):
            assert listener.close() == "closed"
            connection.sendall(b"ok")
            assert connection.recv(1) == b""
            connection.unwrap().close()

        with serve_once(listener, handle) as (outcomes, completed):
            connection = connect_service_tls("jira", ca_pem=base.ca_cert.read_text(), timeout=2)
            try:
                assert connection.recv(2) == b"ok"
                connection.unwrap().close()
            finally:
                connection.close()
            assert completed.wait(2)
            assert outcomes == ["accepted"]
