"""Independent local TLS acceptance tests for the mediated-client fixture harness."""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit

import pytest

from prototype.mediated_client import FIXTURE_REQUEST, FIXTURE_RESPONSE, MediatedClientHarness
from prototype.mediated_client.certificates import FixtureCertificates, create_certificates


@pytest.fixture(scope="session")
def certificates(tmp_path_factory) -> FixtureCertificates:
    return create_certificates(tmp_path_factory.mktemp("mediated-client-certs"))


def strict_context(certificates: FixtureCertificates, ca: str = "ca_cert") -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(getattr(certificates, ca)))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def test_certificate_factory_requires_fresh_directory_and_restricts_keys(tmp_path):
    certificates = create_certificates(tmp_path)
    assert isinstance(certificates, FixtureCertificates)
    for key in (certificates.server_key, certificates.ca_cert.parent / "ca.key",
                certificates.ca_cert.parent / "wrong-ca.key"):
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    with pytest.raises(ValueError):
        create_certificates(tmp_path)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_request_bytes": True},
        {"max_response_bytes": 0},
        {"max_request_bytes": 2**100},
        {"max_response_bytes": 2**100},
        {"timeout_seconds": True},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": 10**100},
    ],
)
def test_constructor_rejects_malformed_and_huge_transport_limits(certificates, kwargs):
    with pytest.raises((TypeError, ValueError, OverflowError)):
        MediatedClientHarness(certificates, **kwargs)


def test_plaintext_connection_cannot_hold_a_serving_thread_during_shutdown(certificates):
    harness = MediatedClientHarness(certificates, timeout_seconds=0.1)
    harness.start()
    site = urlsplit(harness.url)
    plain = socket.create_connection((site.hostname, site.port), timeout=1)
    stop_done = threading.Event()
    stop_errors = []

    def stop_harness():
        try:
            harness.stop()
        except RuntimeError as exc:  # surface the error in the test thread
            stop_errors.append(exc)
        finally:
            stop_done.set()

    stopper = threading.Thread(target=stop_harness, daemon=True)
    started = time.monotonic()
    stopper.start()
    try:
        assert stop_done.wait(4.5), "shutdown remained blocked on a plaintext handshake"
        stopper.join(1)
        assert not stop_errors
        assert time.monotonic() - started < 5
        assert not any(
            thread.name.startswith("mediated-fixture-")
            for thread in threading.enumerate()
        )
    finally:
        plain.close()
        if stopper.is_alive():
            stopper.join(1)


def test_slow_drip_tls_request_has_a_total_connection_deadline(certificates):
    timeout_seconds = 0.1
    harness = MediatedClientHarness(certificates, timeout_seconds=timeout_seconds)
    harness.start()
    site = urlsplit(harness.url)
    grant = active(harness)
    wire = (
        b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        + f"Authorization: Bearer {grant.token}\r\n".encode()
        + b"Content-Type: application/json\r\nContent-Length: "
        + str(len(FIXTURE_REQUEST)).encode()
        + b"\r\n\r\n"
        + FIXTURE_REQUEST
    )
    plain = socket.create_connection((site.hostname, site.port), timeout=1)
    secure = strict_context(certificates).wrap_socket(plain, server_hostname=site.hostname)
    secure.settimeout(2)
    drip_interval = timeout_seconds * 0.4
    incoming_budget = min(4.2, 2 * timeout_seconds + 0.2)
    assert len(wire) * drip_interval > incoming_budget
    started = time.monotonic()
    peer_closed = False
    try:
        # Keep TLS operations on one client thread. Concurrent send/recv on this
        # SSL object previously produced a record-MAC error in the test client.
        # Repeated writes still keep arriving below the inactivity timeout, so
        # only the total connection deadline should terminate this incomplete request.
        for byte in wire:
            if time.monotonic() - started >= 2:
                break
            try:
                if secure.send(bytes((byte,))) == 0:
                    peer_closed = True
                    break
            except TimeoutError:
                break
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                    ssl.SSLEOFError, ssl.SSLZeroReturnError):
                peer_closed = True
                break
            time.sleep(drip_interval)
        elapsed = time.monotonic() - started
        assert peer_closed, "server did not terminate the incomplete slow-drip request"
        assert elapsed < incoming_budget + 0.5, "slow drip extended the connection deadline"
        assert not harness.upstream_receipts
    finally:
        secure.close()
        plain.close()
        stop_bounded(harness)


def test_late_body_cannot_extend_accepted_deadline_through_upstream_timeout(certificates):
    timeout_seconds = 0.2
    incoming_budget = min(4.2, 2 * timeout_seconds + 0.2)
    harness = MediatedClientHarness(
        certificates, upstream_mode="timeout", timeout_seconds=timeout_seconds,
    )
    harness.start()
    site = urlsplit(harness.url)
    grant = active(harness)
    wire = (
        b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        + f"Authorization: Bearer {grant.token}\r\n".encode()
        + b"Content-Type: application/json\r\nContent-Length: "
        + str(len(FIXTURE_REQUEST)).encode()
        + b"\r\n\r\n"
        + FIXTURE_REQUEST
    )
    secure = None
    plain = None
    accepted_started = time.monotonic()
    try:
        plain = socket.create_connection((site.hostname, site.port), timeout=1)
        secure = strict_context(certificates).wrap_socket(plain, server_hostname=site.hostname)
        secure.sendall(wire[:-1])
        # The body remains incomplete while this is below the accepted budget.
        time.sleep(0.55)
        try:
            secure.sendall(wire[-1:])
        except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
            pass
        receipt_wait_deadline = accepted_started + incoming_budget + 0.1
        while not harness.receipts and time.monotonic() < receipt_wait_deadline:
            time.sleep(0.01)
        assert harness.receipts, "mediator receipt was delayed beyond its accepted deadline"
        assert harness.receipts[-1].disposition in {"denied", "upstream_unknown"}
        assert len(harness.upstream_receipts) <= 1
    finally:
        if secure is not None:
            secure.close()
        elif plain is not None:
            plain.close()
        stop_bounded(harness)
    assert not any(
        thread.name.startswith("mediated-fixture-")
        for thread in threading.enumerate()
    )
    assert len(harness.upstream_receipts) <= 1


def active(harness: MediatedClientHarness, run_id: str = "run-1", *, service: str = "anthropic",
          ttl_seconds: float = 270):
    grant = harness.register(run_id, service=service, ttl_seconds=ttl_seconds)
    harness.activate(grant.lease_id)
    return grant


def stop_bounded(harness: MediatedClientHarness, timeout: float = 5) -> None:
    done = threading.Event()
    errors = []

    def stop():
        try:
            harness.stop()
        except RuntimeError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=stop, daemon=True)
    thread.start()
    assert done.wait(timeout), "fixture shutdown exceeded its bounded deadline"
    thread.join(1)
    assert not errors


def request(harness: MediatedClientHarness, certificates: FixtureCertificates, token: str,
            *, method: str = "POST", target: str = "/v1/messages",
            body: bytes = FIXTURE_REQUEST, headers: dict[str, str] | None = None,
            ca: str = "ca_cert"):
    site = urlsplit(harness.url)
    sent = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if headers:
        sent.update(headers)
    connection = http.client.HTTPSConnection(
        site.hostname, site.port, context=strict_context(certificates, ca), timeout=2,
    )
    try:
        connection.request(method, target, body=body, headers=sent)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def raw_request(harness: MediatedClientHarness, certificates: FixtureCertificates,
                wire: bytes) -> bytes:
    site = urlsplit(harness.url)
    context = strict_context(certificates)
    with socket.create_connection((site.hostname, site.port), timeout=2) as plain, \
            context.wrap_socket(plain, server_hostname=site.hostname) as secure:
        secure.sendall(wire)
        secure.settimeout(2)
        chunks = []
        while True:
            try:
                chunk = secure.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                header, _, body = b"".join(chunks).partition(b"\r\n\r\n")
                match = re.search(br"\r\nContent-Length:\s*(\d+)\r\n", b"\r\n" + header,
                                  re.IGNORECASE)
                if match and len(body) >= int(match.group(1)):
                    break
        return b"".join(chunks)


def raw_tls_endpoint(certificates: FixtureCertificates, host: str, port: int,
                     wire: bytes, *, timeout: float = 2) -> bytes:
    context = strict_context(certificates)
    with socket.create_connection((host, port), timeout=timeout) as plain, \
            context.wrap_socket(plain, server_hostname=host) as secure:
        secure.sendall(wire)
        secure.settimeout(timeout)
        chunks = []
        while True:
            try:
                chunk = secure.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def test_valid_two_hop_tls_and_fixed_request_reach_upstream(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        status, headers, body = request(harness, certificates, grant.token)

        assert status == 200
        assert body == FIXTURE_RESPONSE
        assert headers.get("Content-Type") == "text/event-stream"
        assert headers.get("Content-Length") == str(len(FIXTURE_RESPONSE))
        assert "transfer-encoding" not in {key.lower() for key in headers}
        assert len(harness.upstream_receipts) == 1
        upstream = harness.upstream_receipts[0]
        assert upstream.credential_replaced and upstream.host_matches
        assert upstream.request_bytes == len(FIXTURE_REQUEST)
        assert upstream.body_sha256 == hashlib.sha256(FIXTURE_REQUEST).hexdigest()


@pytest.mark.parametrize(
    "server_certificate,upstream_certificate",
    [("wrong_hostname", "valid"), ("expired", "valid"), ("valid", "wrong_hostname"),
     ("valid", "expired")],
)
def test_hostname_and_expiry_failures_are_strict_tls_failures(
    certificates, server_certificate, upstream_certificate
):
    with MediatedClientHarness(
        certificates, server_certificate=server_certificate,
        upstream_certificate=upstream_certificate,
    ) as harness:
        grant = active(harness)
        if server_certificate != "valid":
            with pytest.raises(ssl.SSLCertVerificationError):
                request(harness, certificates, grant.token)
            assert not harness.upstream_receipts
        else:
            status, _headers, _body = request(harness, certificates, grant.token)
            assert 500 <= status < 600
            assert harness.receipts[-1].disposition == "upstream_unknown"
            # A TLS failure can happen before the upstream HTTP handler receives
            # request bytes; it remains conservatively unknown either way.
            assert not harness.upstream_receipts


def test_wrong_ca_is_rejected_before_http(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        with pytest.raises(ssl.SSLCertVerificationError):
            request(harness, certificates, grant.token, ca="wrong_ca_cert")
        assert not harness.receipts
        assert not harness.upstream_receipts


def test_lease_requires_activation_scope_and_fresh_instance(certificates):
    with MediatedClientHarness(certificates) as harness:
        pending = harness.register("pending")
        assert request(harness, certificates, pending.token)[0] in (401, 403)
        service_mismatch = active(harness, "jira-run", service="jira")
        assert request(harness, certificates, service_mismatch.token)[0] in (401, 403)
        valid = active(harness, "valid-run")
        harness.revoke(valid.lease_id)
        assert request(harness, certificates, valid.token)[0] in (401, 403)

    with MediatedClientHarness(certificates) as fresh:
        assert request(fresh, certificates, valid.token)[0] in (401, 403)


def test_expired_lease_is_denied_without_upstream_dispatch(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness, ttl_seconds=0.01)
        time.sleep(0.05)
        assert request(harness, certificates, grant.token)[0] in (401, 403)
        assert not harness.upstream_receipts


def test_revoked_or_expired_lease_cannot_be_reactivated(certificates):
    with MediatedClientHarness(certificates) as harness:
        revoked = harness.register("revoked")
        harness.revoke(revoked.lease_id)
        with pytest.raises(ValueError):
            harness.activate(revoked.lease_id)

        expired = harness.register("expired", ttl_seconds=0.01)
        time.sleep(0.05)
        with pytest.raises(ValueError):
            harness.activate(expired.lease_id)


def test_lease_expiry_boundary_is_strict_now_before_expiry_unit_predicate(
    certificates, monkeypatch
):
    with MediatedClientHarness(certificates) as harness:
        grant = harness.register("boundary")
        monkeypatch.setattr(harness, "_clock", lambda: grant.expires_at)
        with pytest.raises(ValueError):
            harness.activate(grant.lease_id)


@pytest.mark.parametrize("method,target", [
    ("POST", "/v1/messages?origin=https://evil.invalid"),
    ("POST", "/v1/%6dessages"),
    ("POST", "/v1/messages/%2e%2e/secret"),
    ("POST", "https://evil.invalid/v1/messages"),
    ("GET", "/v1/messages"),
    ("PUT", "/v1/messages"),
])
def test_fixed_target_rejects_queries_encoded_paths_and_methods(certificates, method, target):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        status, _headers, _body = request(
            harness, certificates, grant.token, method=method, target=target,
        )
        assert 400 <= status < 500
        assert not harness.upstream_receipts


def test_headers_are_rebuilt_and_caller_authority_is_not_forwarded(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        status, _headers, _body = request(
            harness, certificates, grant.token,
            headers={"Host": "evil.invalid", "X-Api-Key": "caller-key",
                     "Proxy-Authorization": "Basic caller"},
        )
        assert status == 200
        upstream = harness.upstream_receipts[-1]
        lowered = {name.lower() for name in upstream.header_names}
        assert "authorization" not in lowered
        assert "proxy-authorization" not in lowered
        # The caller's X-Api-Key is replaced by the harness-owned synthetic key.
        assert "x-api-key" in lowered
        assert "host" in lowered
        assert upstream.credential_replaced and upstream.host_matches


def test_request_body_and_framing_limits_reject_before_upstream(certificates):
    with MediatedClientHarness(certificates, max_request_bytes=len(FIXTURE_REQUEST) - 1) as harness:
        grant = active(harness)
        assert 400 <= request(harness, certificates, grant.token)[0] < 500
        assert not harness.upstream_receipts


def test_aggregate_headers_over_cap_are_rejected_before_upstream(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        wire = (
            b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            + f"Authorization: Bearer {grant.token}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: "
            + str(len(FIXTURE_REQUEST)).encode()
            + b"\r\nX-Fill: "
            + (b"x" * 8200)
            + b"\r\n\r\n"
            + FIXTURE_REQUEST
        )
        response = raw_request(harness, certificates, wire)
        assert re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts

    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        wire = (
            b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            + f"Authorization: Bearer {grant.token}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: 1\r\n"
              b"Content-Length: 1\r\n\r\n{"
        )
        response = raw_request(harness, certificates, wire)
        assert re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts


@pytest.mark.parametrize(
    "extra_headers",
    [
        b"Host: 127.0.0.1\r\nHost: 127.0.0.1\r\n",
        b"Authorization: Bearer duplicate\r\n",
        b"Content-Type: application/json\r\nContent-Type: application/json\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Expect: 100-continue\r\n",
    ],
)
def test_duplicate_authority_or_ambiguous_framing_is_denied_before_dispatch(
    certificates, extra_headers
):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        authorization = f"Authorization: Bearer {grant.token}\r\n".encode()
        headers = b"Host: 127.0.0.1\r\n" + authorization + extra_headers
        wire = (
            b"POST /v1/messages HTTP/1.1\r\n"
            + headers
            + b"Content-Type: application/json\r\nContent-Length: "
            + str(len(FIXTURE_REQUEST)).encode()
            + b"\r\n\r\n"
            + FIXTURE_REQUEST
        )
        response = raw_request(harness, certificates, wire)
        assert re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts


def test_noncanonical_content_length_and_content_type_are_denied(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        for content_length, content_type in ((b"032", b"application/json"),
                                              (b"32 ", b"application/json"),
                                              (b"32", b"application/json; charset=utf-8")):
            wire = (
                b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                + f"Authorization: Bearer {grant.token}\r\n".encode()
                + b"Content-Type: " + content_type + b"\r\nContent-Length: "
                + content_length + b"\r\n\r\n" + FIXTURE_REQUEST
            )
            response = raw_request(harness, certificates, wire)
            assert re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts


def test_non_ascii_bearer_value_is_denied_with_a_receipt_and_server_survives(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        wire = (
            b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            + b"Authorization: Bearer \xff\r\n"
            + b"Content-Type: application/json\r\nContent-Length: "
            + str(len(FIXTURE_REQUEST)).encode()
            + b"\r\n\r\n"
            + FIXTURE_REQUEST
        )
        response = raw_request(harness, certificates, wire)
        assert re.search(br"HTTP/1\.[01] 4", response)
        assert harness.receipts[-1].disposition == "denied"
        assert harness.receipts[-1].reason == "authorization"
        assert request(harness, certificates, grant.token)[0] == 200


def test_huge_content_length_is_rejected_before_integer_conversion(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        wire = (
            b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            + f"Authorization: Bearer {grant.token}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: "
            + (b"9" * 5000)
            + b"\r\n\r\n"
        )
        response = raw_request(harness, certificates, wire,)
        assert re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts


def test_direct_fixture_upstream_oversize_request_is_bounded_and_not_receipted(certificates):
    with MediatedClientHarness(certificates, max_request_bytes=32, timeout_seconds=0.1) as harness:
        host, port = harness._upstream_server.server_address
        wire = (
            b"POST /v1/messages HTTP/1.1\r\nHost: "
            + f"{host}:{port}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: 33\r\n\r\n"
            + b"x"
        )
        started = time.monotonic()
        response = raw_tls_endpoint(certificates, host, port, wire, timeout=1)
        assert time.monotonic() - started < 1.5
        assert not response or re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts


def test_direct_upstream_forged_dispatch_cannot_create_receipt(certificates):
    with MediatedClientHarness(certificates) as harness:
        host, port = harness._upstream_server.server_address
        forged = (
            b"POST /v1/messages HTTP/1.1\r\nHost: "
            + f"{host}:{port}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: "
            + str(len(FIXTURE_REQUEST)).encode()
            + b"\r\nX-Fixture-Sequence: 1\r\n"
              b"X-Fixture-Dispatch: fake-dispatch\r\nX-Api-Key: fake-key\r\n\r\n"
            + FIXTURE_REQUEST
        )
        response = raw_tls_endpoint(certificates, host, port, forged)
        assert not response or re.search(br"HTTP/1\.[01] 4", response)
        assert not harness.upstream_receipts

        grant = active(harness)
        assert request(harness, certificates, grant.token)[0] == 200
        assert len(harness.upstream_receipts) == 1


@pytest.mark.parametrize("mode", ["redirect", "oversize", "truncate", "disconnect", "timeout"])
def test_upstream_failures_are_unknown_bounded_and_never_retried(certificates, mode):
    with MediatedClientHarness(certificates, upstream_mode=mode, timeout_seconds=0.1) as harness:
        grant = active(harness)
        status, headers, body = request(harness, certificates, grant.token)
        assert 500 <= status < 600
        assert "location" not in {key.lower() for key in headers}
        assert body == b""
        assert len(harness.upstream_receipts) == 1
        receipt = harness.receipts[-1]
        assert receipt.disposition == "upstream_unknown"
        assert receipt.upstream_attempted
        assert request(harness, certificates, grant.token)[0] in (401, 403)
        assert len(harness.upstream_receipts) == 1


def test_response_cap_rejects_complete_body_as_unknown_without_retry(certificates):
    with MediatedClientHarness(certificates, max_response_bytes=1) as harness:
        grant = active(harness)
        status, _headers, _body = request(harness, certificates, grant.token)
        assert 500 <= status < 600
        assert harness.receipts[-1].disposition == "upstream_unknown"
        assert len(harness.upstream_receipts) == 1


def test_revocation_after_unknown_cannot_reactivate_lease(certificates):
    with MediatedClientHarness(certificates, upstream_mode="disconnect") as harness:
        grant = active(harness)
        assert request(harness, certificates, grant.token)[0] >= 500
        harness.revoke(grant.lease_id)
        assert request(harness, certificates, grant.token)[0] in (401, 403)
        assert len(harness.upstream_receipts) == 1


def test_receipts_are_frozen_bounded_and_contain_no_tokens_or_bodies(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        assert request(harness, certificates, grant.token)[0] == 200
        assert grant.token not in repr(harness.receipts)
        assert grant.token not in repr(harness.upstream_receipts)
        assert repr(FIXTURE_REQUEST) not in repr(harness.receipts)
        assert repr(FIXTURE_REQUEST) not in repr(harness.upstream_receipts)
        assert len(harness.receipts) == 1
        assert len(harness.upstream_receipts) == 1
        with pytest.raises(AttributeError):
            harness.receipts.append(None)


def test_request_and_receipt_processing_has_a_saturating_bound(certificates):
    with MediatedClientHarness(certificates) as harness:
        grant = active(harness)
        for _ in range(130):
            request(harness, certificates, grant.token)
        assert len(harness.receipts) == 128
        assert len(harness.upstream_receipts) == 128
        assert harness.dropped_count == 2


def test_shutdown_context_closes_both_local_listeners(certificates):
    with MediatedClientHarness(certificates) as harness:
        url = harness.url
    site = urlsplit(url)
    with pytest.raises((ConnectionRefusedError, OSError, ssl.SSLError)):
        connection = http.client.HTTPSConnection(
            site.hostname, site.port, context=strict_context(certificates), timeout=0.5,
        )
        try:
            connection.request("POST", "/v1/messages", body=FIXTURE_REQUEST)
            connection.getresponse()
        finally:
            connection.close()
