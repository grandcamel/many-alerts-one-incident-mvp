"""Strict, fixed-destination TLS client connections for Forwarder services.

This module establishes a verified TLS transport only.  It neither sends
application bytes nor grants authority for a request or a Run.
"""

from __future__ import annotations

import math
import re
import socket
import ssl
import time
from datetime import UTC, datetime

from .forwarder_services import SERVICE_PROFILES, ServiceProfile

_MAX_CA_PEM_BYTES = 128 * 1024
_MAX_CA_CERTIFICATES = 16
_MAX_LEAF_VALIDITY_SECONDS = 86_400
_MIN_LEAF_REMAINING_SECONDS = 600
_PEM_BUNDLE = re.compile(
    r"(?:-----BEGIN CERTIFICATE-----\r?\n"
    r"(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+"
    r"-----END CERTIFICATE-----\r?\n?)+\Z"
)
_PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----")


class TLSBoundaryError(ValueError):
    """A deliberately non-diagnostic error from the TLS transport boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise TLSBoundaryError(code) from None


def _finite_number(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _validate_timeout(timeout: object) -> float:
    seconds = _finite_number(timeout)
    if seconds is None or seconds <= 0 or seconds > 10:
        _fail("invalid_timeout")
    return seconds


def _monotonic(previous: float | None = None) -> float:
    try:
        current = _finite_number(time.monotonic())
    except Exception:  # noqa: BLE001 - a failed clock cannot establish a deadline.
        _fail("clock_fault")
    if current is None or (previous is not None and current < previous):
        _fail("clock_fault")
    return current


def _wall_time(previous: float | None = None) -> float:
    try:
        current = _finite_number(time.time())
    except Exception:  # noqa: BLE001 - a failed clock cannot establish a deadline.
        _fail("clock_fault")
    if current is None or (previous is not None and current < previous):
        _fail("clock_fault")
    return current


def _remaining_timeout(deadline: float, previous: float) -> tuple[float, float]:
    current = _monotonic(previous)
    remaining = deadline - current
    if not math.isfinite(remaining) or remaining <= 0:
        _fail("deadline_expired")
    return remaining, current


def _validate_ca_pem(ca_pem: object) -> str:
    if type(ca_pem) is not str:
        _fail("invalid_ca_pem")
    if not ca_pem or len(ca_pem) > _MAX_CA_PEM_BYTES:
        _fail("invalid_ca_pem")
    try:
        encoded = ca_pem.encode("ascii")
    except UnicodeEncodeError:
        _fail("invalid_ca_pem")
    if len(encoded) > _MAX_CA_PEM_BYTES:
        _fail("invalid_ca_pem")
    if not _PEM_BUNDLE.fullmatch(ca_pem):
        _fail("invalid_ca_pem")
    if len(_PEM_CERTIFICATE.findall(ca_pem)) > _MAX_CA_CERTIFICATES:
        _fail("invalid_ca_pem")
    return ca_pem


def _strict_context(ca_pem: str) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.hostname_checks_common_name = False
        context.load_verify_locations(cadata=ca_pem)
        store = context.cert_store_stats()
        certificates = store.get("x509")
        ca_certificates = store.get("x509_ca")
        if (
            type(certificates) is not int
            or type(ca_certificates) is not int
            or certificates < 1
            or certificates != ca_certificates
        ):
            _fail("invalid_ca_pem")
        return context
    except TLSBoundaryError:
        raise
    except (ssl.SSLError, ValueError, TypeError, AttributeError):
        _fail("invalid_ca_pem")


def _certificate_times(certificate: dict[str, object]) -> tuple[float, float]:
    before = certificate.get("notBefore")
    after = certificate.get("notAfter")
    if type(before) is not str or type(after) is not str:
        _fail("certificate_policy_failed")
    try:
        before_seconds = _finite_number(ssl.cert_time_to_seconds(before))
        after_seconds = _finite_number(ssl.cert_time_to_seconds(after))
    except (ValueError, OverflowError, TypeError):
        _fail("certificate_policy_failed")
    if before_seconds is None or after_seconds is None:
        _fail("certificate_policy_failed")
    try:
        # Force UTC conversion as an additional guard against invalid epochs.
        datetime.fromtimestamp(before_seconds, UTC)
        datetime.fromtimestamp(after_seconds, UTC)
    except (OverflowError, OSError, ValueError):
        _fail("certificate_policy_failed")
    return before_seconds, after_seconds


def _validate_peer_certificate(certificate: object, profile: ServiceProfile,
                               wall_now: float) -> None:
    if type(certificate) is not dict:
        _fail("certificate_policy_failed")
    names = certificate.get("subjectAltName")
    if type(names) is not tuple or len(names) != 2:
        _fail("certificate_policy_failed")
    expected = {("DNS", profile.server_name), ("IP Address", profile.bind_host)}
    if any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not str
        or type(item[1]) is not str
        for item in names
    ):
        _fail("certificate_policy_failed")
    if set(names) != expected:
        _fail("certificate_policy_failed")
    before, after = _certificate_times(certificate)
    if (
        before > wall_now
        or after <= before
        or after - before > _MAX_LEAF_VALIDITY_SECONDS
        or after - wall_now < _MIN_LEAF_REMAINING_SECONDS
    ):
        _fail("certificate_policy_failed")


def _close_quietly(connection: socket.socket | ssl.SSLSocket) -> None:
    try:
        connection.close()
        return
    except BaseException:  # noqa: BLE001 - cleanup must not mask setup failure.
        try:
            descriptor = connection.detach()
        except BaseException:  # noqa: BLE001 - retain the original setup failure.
            return
    if type(descriptor) is int and descriptor >= 0:
        try:
            socket.close(descriptor)
        except BaseException:  # noqa: BLE001 - retain the original setup failure.
            return


def connect_service_tls(service: str, *, ca_pem: str,
                        timeout: float = 1.0) -> ssl.SSLSocket:
    """Connect to one fixed service and return its verified TLS socket.

    The caller exclusively owns and must close the returned socket.
    """
    if type(service) is not str or service not in SERVICE_PROFILES:
        _fail("unknown_service")
    profile = SERVICE_PROFILES[service]
    seconds = _validate_timeout(timeout)
    trust = _validate_ca_pem(ca_pem)
    context = _strict_context(trust)

    started = _monotonic()
    deadline = started + seconds
    if not math.isfinite(deadline):
        _fail("clock_fault")
    initial_wall = _wall_time()
    raw: socket.socket | None = None
    secured: ssl.SSLSocket | None = None
    returned = False
    phase = "tcp"
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.set_inheritable(False)
        remaining, observed = _remaining_timeout(deadline, started)
        raw.settimeout(remaining)
        raw.connect((profile.bind_host, profile.port))

        remaining, observed = _remaining_timeout(deadline, observed)
        raw.settimeout(remaining)
        phase = "tls"
        secured = context.wrap_socket(
            raw,
            server_hostname=profile.server_name,
            do_handshake_on_connect=False,
        )
        raw = None
        secured.set_inheritable(False)
        remaining, observed = _remaining_timeout(deadline, observed)
        secured.settimeout(remaining)
        secured.do_handshake()
        wall_now = _wall_time(initial_wall)
        _validate_peer_certificate(secured.getpeercert(), profile, wall_now)
        _remaining_timeout(deadline, observed)
        returned = True
        return secured
    except TLSBoundaryError:
        raise
    except (OSError, ssl.SSLError, ValueError, TypeError):
        # These exceptions deliberately do not expose endpoint, certificate, or
        # implementation details beyond the boundary.
        _fail("tls_handshake_failed" if phase == "tls" else "tcp_connect_failed")
    finally:
        if secured is not None and not returned:
            _close_quietly(secured)
        elif raw is not None:
            _close_quietly(raw)
