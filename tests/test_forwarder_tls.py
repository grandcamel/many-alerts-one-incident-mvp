"""Deterministic unit coverage for the fixed Forwarder TLS client boundary."""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from grafana_jsm_sandbox import forwarder_tls
from grafana_jsm_sandbox.forwarder_tls import TLSBoundaryError, connect_service_tls

PEM = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
NOT_BEFORE = "Sep 21 00:00:00 2026 GMT"
NOT_AFTER = "Sep 21 12:00:00 2026 GMT"
WALL_NOW = 1_789_960_000.0


class _RawSocket:
    def __init__(self):
        self.closed = False
        self.inheritable = []
        self.timeouts = []
        self.address = None

    def set_inheritable(self, value):
        self.inheritable.append(value)

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.address = address

    def close(self):
        self.closed = True


class _SecureSocket:
    def __init__(self, raw, certificate, *, close_raw=True):
        self.raw = raw
        self.certificate = certificate
        self.close_raw = close_raw
        self.closed = False
        self.inheritable = []
        self.timeouts = []

    def set_inheritable(self, value):
        self.inheritable.append(value)

    def settimeout(self, value):
        self.timeouts.append(value)

    def do_handshake(self):
        return None

    def getpeercert(self):
        return self.certificate

    def close(self):
        self.closed = True
        if self.close_raw:
            self.raw.close()


class _Context:
    def __init__(self, protocol, certificate, *, wrap_error=None):
        self.protocol = protocol
        self.certificate = certificate
        self.wrap_error = wrap_error
        self.loaded = None
        self.server_name = None
        self.secure = None

    def load_verify_locations(self, *, cadata):
        self.loaded = cadata

    def cert_store_stats(self):
        return {"x509": 1, "x509_ca": 1}

    def wrap_socket(self, raw, *, server_hostname, do_handshake_on_connect):
        self.server_name = server_hostname
        assert do_handshake_on_connect is False
        if self.wrap_error:
            raise self.wrap_error
        self.secure = _SecureSocket(raw, self.certificate)
        return self.secure


def _certificate(service="jira", **overrides):
    profile = forwarder_tls.SERVICE_PROFILES[service]
    certificate = {
        "subjectAltName": (("DNS", profile.server_name), ("IP Address", "127.0.0.1")),
        "notBefore": NOT_BEFORE,
        "notAfter": NOT_AFTER,
    }
    certificate.update(overrides)
    return certificate


def _certificate_time(seconds):
    return datetime.fromtimestamp(seconds, UTC).strftime("%b %d %H:%M:%S %Y GMT")


def _install_fake_transport(monkeypatch, *, certificate=None,
                            monotonic=(10, 10.1, 10.2, 10.3, 10.4)):
    raw = _RawSocket()
    context = _Context(None, certificate or _certificate())
    values = iter(monotonic)
    monkeypatch.setattr(forwarder_tls.time, "monotonic", lambda: next(values))
    monkeypatch.setattr(forwarder_tls.time, "time", lambda: WALL_NOW)
    monkeypatch.setattr(forwarder_tls.socket, "socket", lambda family, kind: raw)
    monkeypatch.setattr(forwarder_tls.ssl, "SSLContext", lambda protocol: context)
    return raw, context


def _error(call, code):
    with pytest.raises(TLSBoundaryError) as raised:
        call()
    assert raised.value.code == code
    assert str(raised.value) == code


@pytest.mark.parametrize("service", [None, 1, "JIRA", "other", "jira:17441"])
def test_rejects_unknown_or_non_string_service(service):
    _error(lambda: connect_service_tls(service, ca_pem=PEM), "unknown_service")


@pytest.mark.parametrize(
    "timeout", [True, False, 0, -1, 10.01, 2**2000, math.nan, math.inf, -math.inf, "1"]
)
def test_rejects_invalid_timeout_before_creating_a_socket(timeout):
    _error(lambda: connect_service_tls("jira", ca_pem=PEM, timeout=timeout), "invalid_timeout")


@pytest.mark.parametrize(
    "ca_pem",
    [
        None,
        b"pem",
        "",
        "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n",
        "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
        "x" * (128 * 1024 + 1),
    ],
)
def test_rejects_malformed_private_or_non_text_ca_material(ca_pem):
    _error(lambda: connect_service_tls("jira", ca_pem=ca_pem), "invalid_ca_pem")


def test_rejects_non_ca_store_and_never_opens_tcp(monkeypatch):
    raw = _RawSocket()

    class NonCaContext(_Context):
        def cert_store_stats(self):
            return {"x509": 1, "x509_ca": 0}

    monkeypatch.setattr(forwarder_tls.ssl, "SSLContext", lambda protocol: NonCaContext(protocol, {}))
    monkeypatch.setattr(forwarder_tls.socket, "socket", lambda *args: raw)
    _error(lambda: connect_service_tls("jira", ca_pem=PEM), "invalid_ca_pem")
    assert raw.address is None


def test_connect_uses_fixed_loopback_sni_noninheritable_descriptors_and_one_deadline(monkeypatch):
    raw, context = _install_fake_transport(monkeypatch)

    secured = connect_service_tls("jira", ca_pem=PEM, timeout=1.0)

    assert secured is context.secure
    assert raw.address == ("127.0.0.1", 17441)
    assert context.server_name == "forwarder-jira.maoi.local"
    assert raw.inheritable == [False]
    assert secured.inheritable == [False]
    assert raw.timeouts == pytest.approx([0.9, 0.8])
    assert secured.timeouts == pytest.approx([0.7])
    assert all(value < 1.0 for value in raw.timeouts)
    assert not raw.closed and not secured.closed
    secured.close()


@pytest.mark.parametrize("clock", [(10, math.nan), (10, 9)])
def test_nonfinite_or_regressing_monotonic_clock_closes_raw_socket(monkeypatch, clock):
    raw, _ = _install_fake_transport(monkeypatch, monotonic=clock)
    _error(lambda: connect_service_tls("jira", ca_pem=PEM), "clock_fault")
    assert raw.closed


def test_regressing_wall_clock_closes_wrapped_socket(monkeypatch):
    raw, context = _install_fake_transport(monkeypatch)
    walls = iter((WALL_NOW, WALL_NOW - 1))
    monkeypatch.setattr(forwarder_tls.time, "time", lambda: next(walls))
    _error(lambda: connect_service_tls("jira", ca_pem=PEM), "clock_fault")
    assert context.secure.closed and raw.closed


def test_expired_deadline_after_certificate_policy_closes_wrapped_socket(monkeypatch):
    raw, context = _install_fake_transport(monkeypatch, monotonic=(10, 10.1, 10.2, 10.3, 11))
    _error(lambda: connect_service_tls("jira", ca_pem=PEM, timeout=0.5), "deadline_expired")
    assert context.secure.closed and raw.closed


def test_base_exception_during_tls_setup_closes_the_raw_socket(monkeypatch):
    raw, context = _install_fake_transport(monkeypatch)
    context.wrap_error = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        connect_service_tls("jira", ca_pem=PEM)
    assert raw.closed


def test_certificate_policy_failure_closes_wrapped_socket(monkeypatch):
    raw, context = _install_fake_transport(
        monkeypatch,
        certificate=_certificate(subjectAltName=(("DNS", "unexpected.local"), ("IP Address", "127.0.0.1"))),
    )
    _error(lambda: connect_service_tls("jira", ca_pem=PEM), "certificate_policy_failed")
    assert context.secure.closed and raw.closed


@pytest.mark.parametrize(
    ("validity", "remaining", "expected"),
    [
        pytest.param(86_400, 600, None, id="inclusive-validity-and-remaining-boundaries-pass"),
        pytest.param(86_400, 599, "certificate_policy_failed", id="remaining-one-second-short-rejects"),
        pytest.param(86_401, 600, "certificate_policy_failed", id="validity-one-second-long-rejects"),
    ],
)
def test_certificate_validity_policy_has_exact_inclusive_boundaries(
    monkeypatch, validity, remaining, expected
):
    after = WALL_NOW + remaining
    certificate = _certificate(
        notBefore=_certificate_time(after - validity),
        notAfter=_certificate_time(after),
    )
    raw, context = _install_fake_transport(monkeypatch, certificate=certificate)

    if expected is not None:
        _error(lambda: connect_service_tls("jira", ca_pem=PEM), expected)
        assert context.secure.closed and raw.closed
        return

    secured = connect_service_tls("jira", ca_pem=PEM)
    assert secured is context.secure
    secured.close()


def test_cleanup_does_not_close_a_still_owned_descriptor_when_detach_fails(monkeypatch):
    raw = _RawSocket()

    class OwnedSocketContext(_Context):
        def wrap_socket(self, *args, **kwargs):
            secured = super().wrap_socket(*args, **kwargs)
            secured.close = lambda: (_ for _ in ()).throw(OSError("close failed"))
            secured.detach = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
            secured.fileno = lambda: (_ for _ in ()).throw(AssertionError("must not inspect owned fd"))
            return secured

    context = OwnedSocketContext(None, _certificate(subjectAltName=()))
    closed_descriptors = []
    monkeypatch.setattr(forwarder_tls.socket, "socket", lambda *args: raw)
    monkeypatch.setattr(forwarder_tls.ssl, "SSLContext", lambda protocol: context)
    monkeypatch.setattr(forwarder_tls.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(forwarder_tls.time, "time", lambda: WALL_NOW)
    monkeypatch.setattr(forwarder_tls.socket, "close", closed_descriptors.append)

    _error(lambda: connect_service_tls("jira", ca_pem=PEM), "certificate_policy_failed")

    assert closed_descriptors == []


def test_cleanup_detaches_before_close_and_preserves_original_failure_when_raw_close_raises(monkeypatch):
    raw = _RawSocket()

    class DetachedSocketContext(_Context):
        def wrap_socket(self, *args, **kwargs):
            secured = super().wrap_socket(*args, **kwargs)
            secured.close = lambda: (_ for _ in ()).throw(OSError("close failed"))
            secured.detach = lambda: 417
            return secured

    context = DetachedSocketContext(None, _certificate(subjectAltName=()))
    monkeypatch.setattr(forwarder_tls.socket, "socket", lambda *args: raw)
    monkeypatch.setattr(forwarder_tls.ssl, "SSLContext", lambda protocol: context)
    monkeypatch.setattr(forwarder_tls.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(forwarder_tls.time, "time", lambda: WALL_NOW)
    monkeypatch.setattr(
        forwarder_tls.socket,
        "close",
        lambda descriptor: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    _error(lambda: connect_service_tls("jira", ca_pem=PEM), "certificate_policy_failed")
