"""Independent client checks of the fixed synthetic incremental TLS fixture."""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import threading
import time
from dataclasses import asdict
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from prototype.mediated_client import (
    FIXTURE_REQUEST,
    STREAM_FIXTURE_DELTA,
    STREAM_FIXTURE_RESPONSE,
    STREAM_FIXTURE_TERMINAL,
    IncrementalStreamHarness,
)
from prototype.mediated_client import streaming as stream_module
from prototype.mediated_client.certificates import create_certificates


@pytest.fixture(scope="session")
def streaming_certificates(tmp_path_factory):
    return create_certificates(tmp_path_factory.mktemp("incremental-tls-certs"))


def active(harness, *, service="anthropic", ttl=30):
    grant = harness.register("stream-test", service=service, ttl_seconds=ttl)
    harness.activate(grant.lease_id)
    return grant


def open_client(harness, certificates, token, *, path="/v1/messages", method="POST",
                extra_headers="", api_key="incoming-secret-must-not-pass", omit_auth=False):
    site = urlsplit(harness.url)
    context = ssl.create_default_context(cafile=str(certificates.ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection((site.hostname, site.port), timeout=3)
    secure = context.wrap_socket(raw, server_hostname=site.hostname)
    secure.settimeout(3)
    auth_header = "" if omit_auth else f"Authorization: Bearer {token}\r\n"
    wire = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {site.hostname}:{site.port}\r\n"
        f"{auth_header}"
        "Content-Type: application/json\r\n"
        f"X-Api-Key: {api_key}\r\n"
        f"{extra_headers}"
        f"Content-Length: {len(FIXTURE_REQUEST)}\r\n\r\n"
    ).encode("ascii") + FIXTURE_REQUEST
    try:
        secure.sendall(wire)
        response = http.client.HTTPResponse(secure)
        response.begin()
        return secure, response
    except BaseException:
        secure.close()
        raise


def read_remaining(response):
    try:
        return response.read(), False
    except http.client.IncompleteRead as exc:
        return exc.partial, True


def final_receipt(harness):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        receipts = harness.stream_receipts
        if receipts:
            return receipts[-1]
        time.sleep(0.01)
    pytest.fail("stream receipt not retained within bounded cleanup interval")


def decode_ack(frame):
    """Return a local decode acknowledgement to the test controller, not the mediator.

    No network ACK protocol or production client acknowledgement is claimed.
    """
    assert frame.startswith(b"data: ") and frame.endswith(b"\n\n")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result

    record = json.loads(frame[6:-2].decode("utf-8"), object_pairs_hook=unique)
    assert isinstance(record, dict)
    return record


@pytest.mark.parametrize("mode", ["complete", "split_utf8"])
def test_client_ack_precedes_final_release_and_terminal(streaming_certificates, mode, monkeypatch):
    if mode == "split_utf8":
        # Force byte-sized body reads: separate upstream writes alone can coalesce.
        monkeypatch.setattr(stream_module, "_READ_BYTES", 1)
    with IncrementalStreamHarness(
        streaming_certificates, stream_mode=mode, timeout_seconds=1.5
    ) as harness:
        grant = active(harness)
        secure, response = open_client(harness, streaming_certificates, grant.token)
        order = []
        try:
            assert response.status == 200
            assert response.headers.get_all("Content-Type") == ["text/event-stream"]
            assert response.headers.get_all("Content-Length") == [str(len(STREAM_FIXTURE_RESPONSE))]
            assert response.headers.get_all("Transfer-Encoding") is None
            assert response.headers.get_all("Connection") == ["close"]
            first = response.read(len(STREAM_FIXTURE_DELTA))
            assert first == STREAM_FIXTURE_DELTA
            assert decode_ack(first)
            order.append("client_first_frame_ack")
            assert harness.wait_for_first_frame_forwarded(timeout_seconds=0.5)
            # Completion before release would falsify the actual streaming claim.
            assert not harness.stream_receipts
            order.append("controller_final_release")
            harness.release_final_frame()
            remainder, incomplete = read_remaining(response)
            assert not incomplete
            assert remainder == STREAM_FIXTURE_TERMINAL
            assert decode_ack(remainder)
            order.append("client_terminal_ack")
            assert secure.recv(1) == b""
            order.append("transport_close")
        finally:
            response.close()
            secure.close()
        assert order == ["client_first_frame_ack", "controller_final_release",
                         "client_terminal_ack", "transport_close"]
        receipt = final_receipt(harness)
        assert receipt.transport_complete
        assert receipt.terminal_observed
        assert receipt.validated_frame_count == receipt.forwarded_frame_count == 2
        assert receipt.forwarded_bytes == len(STREAM_FIXTURE_RESPONSE)
        assert receipt.stream_sha256 == hashlib.sha256(STREAM_FIXTURE_RESPONSE).hexdigest()
        assert receipt.upstream_attempted and receipt.bytes_may_have_crossed
        assert len(harness.upstream_receipts) == 1
        retained = json.dumps([asdict(receipt), *map(asdict, harness.upstream_receipts)])
        for forbidden in (grant.token, "fixture-upstream-key", "incoming-secret-must-not-pass",
                          FIXTURE_REQUEST.decode(), STREAM_FIXTURE_RESPONSE.decode()):
            assert forbidden not in retained
        upstream = harness.upstream_receipts[0]
        assert upstream.credential_replaced and upstream.host_matches
        assert "authorization" not in upstream.header_names


@pytest.mark.parametrize("mode", [
    "malformed_utf8", "duplicate_key", "unknown_kind", "nonfinite", "oversize",
    "deep", "event_limit", "missing_terminal", "duplicate_terminal",
    "conflicting_terminal", "trailing", "trailing_after_length", "truncate",
    "disconnect", "timeout", "surrogate", "out_of_order", "total_oversize",
])
def test_faults_never_deliver_a_terminal_or_retry(streaming_certificates, mode):
    with IncrementalStreamHarness(
        streaming_certificates, stream_mode=mode, timeout_seconds=0.3
    ) as harness:
        grant = active(harness)
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            body, incomplete = read_remaining(response)
            assert response.status in (200, 502, 504)
            assert STREAM_FIXTURE_TERMINAL not in body
            if mode in {"truncate", "duplicate_terminal", "conflicting_terminal",
                        "trailing", "trailing_after_length"}:
                assert response.status == 200 and incomplete
        finally:
            response.close()
            secure.close()
        receipt = final_receipt(harness)
        assert not receipt.transport_complete
        assert receipt.reason and receipt.reason != "complete"
        if body:
            assert receipt.disposition == "stream_partial"
            assert receipt.bytes_may_have_crossed
        if mode in {"duplicate_terminal", "conflicting_terminal", "trailing_after_length"}:
            assert receipt.terminal_observed
        assert receipt.forwarded_bytes < len(STREAM_FIXTURE_RESPONSE) or mode == "event_limit"
        assert receipt.upstream_attempted
        assert len(harness.upstream_receipts) == 1


@pytest.mark.parametrize("limit_delta", [-1, 0])
def test_declared_total_response_byte_limit_edge(streaming_certificates, limit_delta):
    with IncrementalStreamHarness(
        streaming_certificates, max_response_bytes=len(STREAM_FIXTURE_RESPONSE) + limit_delta
    ) as harness:
        grant = active(harness)
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.status == (502 if limit_delta < 0 else 200)
            body = response.read()
            assert body == (b"" if limit_delta < 0 else STREAM_FIXTURE_RESPONSE)
        finally:
            response.close()
            secure.close()
        receipt = final_receipt(harness)
        assert receipt.transport_complete is (limit_delta == 0)
        if limit_delta < 0:
            assert not receipt.bytes_may_have_crossed
            assert receipt.forwarded_bytes == 0


@pytest.mark.parametrize("action", ["revoke", "expire"])
def test_revocation_or_expiry_between_frames_prevents_terminal(streaming_certificates, action):
    with IncrementalStreamHarness(streaming_certificates, timeout_seconds=1.5) as harness:
        grant = active(harness)
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.read(len(STREAM_FIXTURE_DELTA)) == STREAM_FIXTURE_DELTA
            done = threading.Event()
            errors = []

            def change_lease():
                try:
                    if action == "revoke":
                        harness.revoke(grant.lease_id)
                    else:
                        harness._clock = lambda: grant.expires_at
                except (ValueError, RuntimeError) as exc:
                    errors.append(exc)
                finally:
                    done.set()

            worker = threading.Thread(target=change_lease, daemon=True)
            worker.start()
            # A lock held across the upstream barrier cannot satisfy this.
            assert done.wait(harness._timeout_seconds / 2), "lease control blocked on upstream frame"
            worker.join(0.5)
            assert not errors
            harness.release_final_frame()
            body, _ = read_remaining(response)
            assert STREAM_FIXTURE_TERMINAL not in body
        finally:
            response.close()
            secure.close()
        receipt = final_receipt(harness)
        assert not receipt.transport_complete
        assert receipt.disposition == "stream_partial"
        assert receipt.reason == ("revoked" if action == "revoke" else "expired")
        assert receipt.forwarded_frame_count == 1
        assert receipt.forwarded_bytes == len(STREAM_FIXTURE_DELTA)
        assert len(harness.upstream_receipts) == 1


@pytest.mark.parametrize("denial", ["revoke", "inactive", "wrong_service", "wrong_route", "method"])
def test_denials_cannot_reach_upstream(streaming_certificates, denial):
    with IncrementalStreamHarness(streaming_certificates) as harness:
        service = "jira" if denial == "wrong_service" else "anthropic"
        grant = harness.register("denied", service=service, ttl_seconds=30)
        if denial != "inactive":
            harness.activate(grant.lease_id)
        if denial == "revoke":
            harness.revoke(grant.lease_id)
        secure, response = open_client(
            harness, streaming_certificates, grant.token,
            path="/arbitrary" if denial == "wrong_route" else "/v1/messages",
            method="GET" if denial == "method" else "POST",
        )
        try:
            assert response.status == 401
            response.read()
        finally:
            response.close()
            secure.close()
        assert not harness.upstream_receipts


def test_unreleased_barrier_and_disconnected_client_have_bounded_cleanup(streaming_certificates):
    harness = IncrementalStreamHarness(streaming_certificates, timeout_seconds=0.25)
    started = time.monotonic()
    with harness:
        grant = active(harness)
        secure, response = open_client(harness, streaming_certificates, grant.token)
        assert response.read(len(STREAM_FIXTURE_DELTA)) == STREAM_FIXTURE_DELTA
        secure.shutdown(socket.SHUT_RDWR)
        response.close()
        secure.close()
        # No final release: upstream wait and all connection timers must remain bounded.
        receipt = final_receipt(harness)
        assert not receipt.transport_complete
        assert receipt.forwarded_frame_count == 1
    assert time.monotonic() - started < 4
    assert not any(thread.name.startswith("mediated-fixture-")
                   for thread in threading.enumerate())


def test_streaming_rejects_untrusted_upstream_tls(streaming_certificates):
    with IncrementalStreamHarness(
        streaming_certificates, upstream_certificate="wrong_hostname"
    ) as harness:
        grant = active(harness)
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.status == 502
            assert STREAM_FIXTURE_TERMINAL not in response.read()
        finally:
            response.close()
            secure.close()
        assert not final_receipt(harness).transport_complete
        assert not harness.upstream_receipts


def test_streaming_client_rejects_untrusted_mediator_tls(streaming_certificates):
    with IncrementalStreamHarness(
        streaming_certificates, server_certificate="wrong_hostname"
    ) as harness:
        grant = active(harness)
        with pytest.raises(ssl.SSLCertVerificationError):
            open_client(harness, streaming_certificates, grant.token)
        assert not harness.stream_receipts
        assert not harness.upstream_receipts


def test_direct_synthetic_upstream_call_cannot_forge_correlation(streaming_certificates):
    with IncrementalStreamHarness(streaming_certificates) as harness:
        grant = active(harness)
        host, port = harness._upstream_server.server_address
        target = SimpleNamespace(url=f"https://{host}:{port}")
        secure, response = open_client(
            target, streaming_certificates, grant.token,
            extra_headers="X-Fixture-Sequence: 1\r\nX-Fixture-Dispatch: forged-nonce\r\n",
            api_key="fixture-upstream-key", omit_auth=True,
        )
        try:
            assert response.status == 401
            response.read()
        finally:
            response.close()
            secure.close()
        assert not harness.stream_receipts
        assert not harness.upstream_receipts
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.status == 200
            assert response.read() == STREAM_FIXTURE_RESPONSE
        finally:
            response.close()
            secure.close()
        assert final_receipt(harness).transport_complete
        assert len(harness.upstream_receipts) == 1


def test_partial_first_write_does_not_emit_a_second_http_response(streaming_certificates, monkeypatch):
    original = IncrementalStreamHarness._forward_delta

    class FailDuringFirstFrame:
        def __init__(self, writer):
            self.writer = writer

        def write(self, data):
            if data == STREAM_FIXTURE_DELTA:
                self.writer.write(data[:5])
                self.writer.flush()
                raise BrokenPipeError("synthetic partial downstream write")
            return self.writer.write(data)

        def __getattr__(self, name):
            return getattr(self.writer, name)

    def fail_at_writer(self, handler, *args, **kwargs):
        handler.wfile = FailDuringFirstFrame(handler.wfile)
        return original(self, handler, *args, **kwargs)

    monkeypatch.setattr(IncrementalStreamHarness, "_forward_delta", fail_at_writer)
    with IncrementalStreamHarness(streaming_certificates) as harness:
        grant = active(harness)
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.status == 200
            body, incomplete = read_remaining(response)
            assert incomplete
            assert body == STREAM_FIXTURE_DELTA[:5]
            assert b"HTTP/" not in body
        finally:
            response.close()
            secure.close()
        receipt = final_receipt(harness)
        assert receipt.bytes_may_have_crossed
        assert not receipt.transport_complete
        assert receipt.forwarded_frame_count == 0
        assert receipt.forwarded_bytes == 0  # full successful writes only


def test_stream_receipt_history_and_dispatch_remain_bounded(streaming_certificates):
    with IncrementalStreamHarness(streaming_certificates) as harness:
        grant = active(harness, ttl=270)
        harness.release_final_frame()
        for index in range(129):
            secure, response = open_client(harness, streaming_certificates, grant.token)
            try:
                assert response.status == (200 if index < 128 else 429)
                body = response.read()
                if index < 128:
                    assert body == STREAM_FIXTURE_RESPONSE
            finally:
                response.close()
                secure.close()
        assert len(harness.stream_receipts) == len(harness.upstream_receipts) == 128
        assert [r.sequence for r in harness.stream_receipts] == list(range(1, 129))
        assert harness.dropped_count == 1


def test_partial_upstream_send_retains_unknown_and_prevents_lease_reuse(streaming_certificates, monkeypatch):
    original = ssl.SSLSocket.sendall
    sends = []

    def partial_send(sock, data, *args, **kwargs):
        if data.startswith(b"POST /v1/messages") and b"X-Fixture-Dispatch:" in data:
            sends.append(1)
            original(sock, data[:16], *args, **kwargs)
            raise ConnectionResetError("synthetic partial upstream request")
        return original(sock, data, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLSocket, "sendall", partial_send)
    with IncrementalStreamHarness(streaming_certificates) as harness:
        grant = active(harness)
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.status == 502
            assert response.read() == b""
        finally:
            response.close()
            secure.close()
        receipt = final_receipt(harness)
        assert receipt.upstream_attempted
        assert receipt.disposition == "upstream_unknown"
        assert not receipt.transport_complete
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            assert response.status == 401
            response.read()
        finally:
            response.close()
            secure.close()
        assert sends == [1]


def test_partial_stream_holds_new_grants_before_another_dispatch(streaming_certificates):
    with IncrementalStreamHarness(streaming_certificates, stream_mode="missing_terminal") as harness:
        grant = active(harness)
        harness.release_final_frame()
        secure, response = open_client(harness, streaming_certificates, grant.token)
        try:
            read_remaining(response)
        finally:
            response.close()
            secure.close()
        assert not final_receipt(harness).transport_complete
        new_grant = active(harness)
        secure, response = open_client(harness, streaming_certificates, new_grant.token)
        try:
            assert response.status == 401
            response.read()
        finally:
            response.close()
            secure.close()
        assert len(harness.upstream_receipts) == 1
        assert harness.stream_receipts[-1].reason == "stream_aborted"


@pytest.mark.parametrize("kwargs", [
    {"stream_mode": "arbitrary"}, {"max_response_bytes": True},
    {"timeout_seconds": float("nan")}, {"timeout_seconds": 10**100},
])
def test_stream_constructor_retains_finite_boundary(streaming_certificates, kwargs):
    with pytest.raises((TypeError, ValueError, OverflowError)):
        IncrementalStreamHarness(streaming_certificates, **kwargs)
