"""Real TLS on ephemeral loopback sockets; fixed target selection is asserted."""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import TLSBoundaryError, connect_service_tls
from prototype.mediated_client.certificates import create_certificates


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    directory = tmp_path_factory.mktemp("service-tls")
    base = create_certificates(directory)
    executable = shutil.which("openssl")
    assert executable is not None

    def run(*arguments):
        completed = subprocess.run(
            [executable, *arguments], cwd=directory, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10,
            check=False, umask=0o077,
            env={"PATH": os.defpath, "LC_ALL": "C", "OPENSSL_CONF": os.devnull},
        )
        assert completed.returncode == 0, "synthetic certificate generation failed"

    run("req", "-new", "-key", "server.key", "-out", "service.csr",
        "-subj", "/CN=forwarder-jira.maoi.local")
    now = datetime.now(UTC).replace(microsecond=0)
    start = now - timedelta(minutes=5)
    end = now + timedelta(hours=23)
    variants = {
        name: (start, end, f"DNS:{profile.server_name},IP:127.0.0.1")
        for name, profile in SERVICE_PROFILES.items()
    }
    jira_san = variants["jira"][2]
    variants.update({
        "wrong-name": (start, end, "DNS:wrong.invalid,IP:127.0.0.1"),
        "wildcard": (start, end, "DNS:*.maoi.local,IP:127.0.0.1"),
        "missing-ip": (start, end, "DNS:forwarder-jira.maoi.local"),
        "extra-name": (start, end, jira_san + ",DNS:forwarder-grafana.maoi.local"),
        "cn-only": (start, end, None),
        "expired": (now - timedelta(days=2), now - timedelta(days=1), jira_san),
        "future": (now + timedelta(hours=1), now + timedelta(hours=2), jira_san),
        "near-expiry": (start, now + timedelta(minutes=5), jira_san),
        "overlong": (start, now + timedelta(days=2), jira_san),
    })
    with (directory / "ca.cnf").open("a") as config:
        for name, (_begin, _finish, san) in variants.items():
            config.write(f"\n[service_{name}]\nbasicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=serverAuth\n")
            if san is not None:
                config.write(f"subjectAltName={san}\n")
    paths = {}
    for name, (begin, finish, _san) in variants.items():
        path = directory / f"service-{name}.pem"
        run("ca", "-batch", "-notext", "-config", "ca.cnf", "-in", "service.csr",
            "-out", path.name, "-startdate", begin.strftime("%Y%m%d%H%M%SZ"),
            "-enddate", finish.strftime("%Y%m%d%H%M%SZ"), "-extensions", f"service_{name}")
        paths[name] = path
    return base, paths


@contextmanager
def local_peer(tls_material, variant, *, mode="tls"):
    base, paths = tls_material
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3.0)
    stop = threading.Event()
    received = []
    errors = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(paths[variant], base.server_key)

    def serve():
        accepted = None
        try:
            accepted, _ = listener.accept()
            accepted.settimeout(3.0)
            if mode == "stall":
                stop.wait(3.0)
            elif mode == "plaintext":
                accepted.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            else:
                accepted = context.wrap_socket(accepted, server_side=True)
                received.append(accepted.recv(1))
                if received[-1] == b"":
                    accepted = accepted.unwrap()
        except (ssl.SSLError, ConnectionError):
            # Expected when a client rejects the fixture certificate.
            pass
        except BaseException as error:  # noqa: BLE001 - surface fixture-thread failures.
            errors.append(type(error).__name__)
        finally:
            if accepted is not None:
                accepted.close()

    worker = threading.Thread(target=serve, name="service-tls-fixture", daemon=True)
    worker.start()
    try:
        yield listener.getsockname(), received
    finally:
        stop.set()
        listener.close()
        worker.join(4.0)
        assert not worker.is_alive(), "TLS fixture worker did not exit"
        assert not errors, errors


def redirect_fixed_target(monkeypatch, address, service):
    original_socket = socket.socket
    attempted = []

    class FixtureSocket(original_socket):
        def connect(self, destination):
            profile = SERVICE_PROFILES[service]
            assert destination == (profile.bind_host, profile.port)
            attempted.append(destination)
            return super().connect(address)

    monkeypatch.setattr(socket, "socket", FixtureSocket)
    return attempted


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_real_tls_verifies_each_fixed_service_and_sends_no_application_bytes(
    tls_material, monkeypatch, service,
):
    base, _paths = tls_material
    with local_peer(tls_material, service) as (address, received):
        attempted = redirect_fixed_target(monkeypatch, address, service)
        connection = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=2.0)
        try:
            assert connection.get_inheritable() is False
            assert connection.version() in {"TLSv1.2", "TLSv1.3"}
        finally:
            try:
                # Complete TLS close_notify on both peers so unread TLS 1.3
                # session tickets cannot turn close() into a TCP reset.
                connection.unwrap().close()
            finally:
                connection.close()
    assert len(attempted) == 1
    assert received == [b""]


@pytest.mark.parametrize("variant", [
    "wrong-name", "wildcard", "missing-ip", "extra-name", "cn-only", "expired",
    "future", "near-expiry", "overlong",
])
def test_real_tls_rejects_invalid_identity_or_lifetime(tls_material, monkeypatch, variant):
    base, _paths = tls_material
    with local_peer(tls_material, variant) as (address, received):
        attempted = redirect_fixed_target(monkeypatch, address, "jira")
        with pytest.raises(TLSBoundaryError) as rejected:
            connect_service_tls("jira", ca_pem=base.ca_cert.read_text(), timeout=2.0)
        assert "CERTIFICATE" not in str(rejected.value)
    assert len(attempted) == 1
    assert all(chunk == b"" for chunk in received)


def test_real_tls_rejects_untrusted_ca(tls_material, monkeypatch):
    base, _paths = tls_material
    with local_peer(tls_material, "jira") as (address, _received):
        attempted = redirect_fixed_target(monkeypatch, address, "jira")
        with pytest.raises(TLSBoundaryError):
            connect_service_tls("jira", ca_pem=base.wrong_ca_cert.read_text(), timeout=2.0)
    assert len(attempted) == 1


def test_real_non_ca_trust_is_rejected_before_connect(tls_material, monkeypatch):
    _base, paths = tls_material

    def unexpected_socket(*_args, **_kwargs):
        raise AssertionError("non-CA trust must be rejected before opening a socket")

    monkeypatch.setattr(socket, "socket", unexpected_socket)
    with pytest.raises(TLSBoundaryError, match="invalid_ca_pem"):
        connect_service_tls("jira", ca_pem=paths["jira"].read_text())


@pytest.mark.parametrize("mode", ["plaintext", "stall"])
def test_real_tls_rejects_non_tls_and_stalled_peer(tls_material, monkeypatch, mode):
    base, _paths = tls_material
    with local_peer(tls_material, "jira", mode=mode) as (address, _received):
        attempted = redirect_fixed_target(monkeypatch, address, "jira")
        with pytest.raises(TLSBoundaryError):
            connect_service_tls("jira", ca_pem=base.ca_cert.read_text(), timeout=0.2)
    assert len(attempted) == 1
