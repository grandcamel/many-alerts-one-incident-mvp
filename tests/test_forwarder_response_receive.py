"""Controlled TLS response-collection and shared-head contract tests."""

from __future__ import annotations

import math
import ssl
import threading

import pytest

from grafana_jsm_sandbox import forwarder_response_receive
from grafana_jsm_sandbox.forwarder_http_response import (
    MAX_BODY_BYTES,
    HTTPResponseError,
    ParsedResponseHead,
    parse_response_head,
)
from grafana_jsm_sandbox.forwarder_response_receive import ResponseReceiveError, receive_response


class _Context:
    protocol = ssl.PROTOCOL_TLS_CLIENT
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True


class _Socket:
    def __init__(self, chunks, *, version="TLSv1.3", alpn="http/1.1", restore_error=None):
        self.chunks = list(chunks)
        self.context = _Context()
        self.server_side = False
        self._version = version
        self.alpn = alpn
        self.timeout = 2.0
        self.restore_error = restore_error
        self.recv_sizes = []
        self.timeout_history = []
        self.sent = self.closed = self.shutdowns = 0

    def fileno(self):
        return 42

    def version(self):
        return self._version

    def selected_alpn_protocol(self):
        return self.alpn

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        if value == 2.0 and self.restore_error:
            raise self.restore_error
        self.timeout = value
        self.timeout_history.append(value)

    def recv(self, amount):
        self.recv_sizes.append(amount)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        assert len(chunk) <= amount
        return chunk

    def send(self, _data):
        self.sent += 1

    def close(self):
        self.closed += 1

    def shutdown(self, _how):
        self.shutdowns += 1


def _response(status=200, body=b'{"ok":true}'):
    if status == 204:
        return b"HTTP/1.1 204 No Content\r\n\r\n"
    if status == 205:
        return b"HTTP/1.1 205 Reset\r\nContent-Length: 0\r\n\r\n"
    return (
        f"HTTP/1.1 {status} Upstream\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        + body
    )


def _install(monkeypatch, socket, clock=lambda: 10.0):
    monkeypatch.setattr(forwarder_response_receive.ssl, "SSLSocket", type(socket))
    monkeypatch.setattr(forwarder_response_receive.time, "monotonic", clock)


def _error(call, code=None):
    with pytest.raises(ResponseReceiveError) as raised:
        call()
    assert raised.value.code and str(raised.value) == raised.value.code
    if code:
        assert raised.value.code == code


@pytest.mark.parametrize("status,length", [(200, 11), (204, 0), (205, 0)])
def test_response_head_matches_framing_without_allocating_a_body(status, length):
    raw = _response(status)
    head = raw[: raw.index(b"\r\n\r\n") + 4]
    assert parse_response_head(head) == ParsedResponseHead(status, length)
    with pytest.raises(HTTPResponseError):
        parse_response_head(head + b"body")


@pytest.mark.parametrize(
    "head", [b"HTTP/1.1 200 Ok\r\n", b"HTTP/1.1 200 Ok\r\n\r\nbody", bytearray(b"x")]
)
def test_response_head_requires_exact_complete_header_bytes(head):
    with pytest.raises(HTTPResponseError):
        parse_response_head(head)


def test_coalesced_and_fragmented_collection_preserve_opaque_body_and_socket_ownership(monkeypatch):
    body = b"\x00opaque\xff"
    raw = _response(200, body)
    coalesced = _Socket([raw])
    _install(monkeypatch, coalesced)
    assert receive_response(coalesced, deadline=20).body == body
    assert coalesced.timeout_history[-1] == 2.0
    assert not (coalesced.sent or coalesced.closed or coalesced.shutdowns)

    end = raw.index(b"\r\n\r\n") + 4
    fragmented = _Socket([raw[:20], raw[20:end], body[:2], body[2:]])
    _install(monkeypatch, fragmented)
    assert receive_response(fragmented, deadline=20).body == body
    assert max(fragmented.recv_sizes) <= 4096


def test_headerless_204_is_collected_at_every_fragment_boundary_and_rejects_captured_extra(
    monkeypatch,
):
    raw = _response(204)
    for split in range(1, len(raw)):
        socket = _Socket([raw[:split], raw[split:]])
        _install(monkeypatch, socket)
        assert receive_response(socket, deadline=20).status == 204
    extra = _Socket([raw + b"x"])
    _install(monkeypatch, extra)
    _error(lambda: receive_response(extra, deadline=20), "receive_failed")


@pytest.mark.parametrize("deadline", [True, 0, -1, math.nan, math.inf, 2**2000, 10, 51])
def test_deadline_is_exact_finite_future_and_lease_clipped(monkeypatch, deadline):
    socket = _Socket([])
    _install(monkeypatch, socket)
    _error(lambda: receive_response(socket, deadline=deadline), "invalid_deadline")


@pytest.mark.parametrize(
    "attribute,value", [("server_side", True), ("_version", "TLSv1.1"), ("alpn", "h2")]
)
def test_tls_state_matrix_rejects_non_client_tls_transport(monkeypatch, attribute, value):
    socket = _Socket([])
    setattr(socket, attribute, value)
    _install(monkeypatch, socket)
    _error(lambda: receive_response(socket, deadline=20), "invalid_connection")


def test_completed_read_past_inactivity_limit_but_inside_original_deadline_rejects(monkeypatch):
    socket = _Socket([_response()])
    times = iter((10, 10.1, 30.2))
    _install(monkeypatch, socket, lambda: next(times))
    _error(lambda: receive_response(socket, deadline=40), "receive_failed")
    assert socket.timeout_history[0] == 20


def test_tls_validation_eof_extra_and_invalid_head_fail_without_socket_cleanup(monkeypatch):
    invalid = _Socket([_response(302)])
    _install(monkeypatch, invalid)
    _error(lambda: receive_response(invalid, deadline=20), "receive_failed")
    assert len(invalid.recv_sizes) == 1

    eof = _Socket([b"HTTP/1.1 200 Ok\r\n", b""])
    _install(monkeypatch, eof)
    _error(lambda: receive_response(eof, deadline=20), "receive_failed")

    extra = _Socket([_response(200, b"x") + b"x"])
    _install(monkeypatch, extra)
    _error(lambda: receive_response(extra, deadline=20), "receive_failed")
    assert not (extra.sent or extra.closed or extra.shutdowns)


def test_max_body_and_body_eof_are_bounded(monkeypatch):
    body = b"x" * MAX_BODY_BYTES
    raw = _response(200, body)
    end = raw.index(b"\r\n\r\n") + 4
    socket = _Socket(
        [raw[:end], *(body[index : index + 65536] for index in range(0, len(body), 65536))]
    )
    _install(monkeypatch, socket)
    assert receive_response(socket, deadline=20).body == body
    assert max(socket.recv_sizes) <= 65536

    short = _Socket([raw[:end], body[:2], b""])
    _install(monkeypatch, short)
    _error(lambda: receive_response(short, deadline=20), "receive_failed")


def test_clock_deadline_and_timeout_restore_failures_preserve_primary_outcome(monkeypatch):
    slow = _Socket([_response()])
    times = iter((10, 10.1, 10.2, 10.4, 10.5))
    _install(monkeypatch, slow, lambda: next(times))
    _error(lambda: receive_response(slow, deadline=10.45), "deadline_expired")

    restore = _Socket([_response()], restore_error=RuntimeError("restore"))
    _install(monkeypatch, restore)
    _error(lambda: receive_response(restore, deadline=20), "timeout_restore_failed")

    primary = _Socket([OSError("read")], restore_error=RuntimeError("restore"))
    _install(monkeypatch, primary)
    _error(lambda: receive_response(primary, deadline=20), "receive_failed")

    interrupted = _Socket([KeyboardInterrupt()], restore_error=RuntimeError("restore"))
    _install(monkeypatch, interrupted)
    with pytest.raises(KeyboardInterrupt):
        receive_response(interrupted, deadline=20)


def test_regressing_clock_after_read_is_rejected_and_timeout_is_restored(monkeypatch):
    socket = _Socket([_response()])
    times = iter((10, 10.1, 10.0))
    _install(monkeypatch, socket, lambda: next(times))
    _error(lambda: receive_response(socket, deadline=20), "clock_fault")
    assert socket.timeout_history[-1] == 2.0


def test_restore_failure_is_not_hidden_by_callers_handled_exception(monkeypatch):
    socket = _Socket([_response()], restore_error=RuntimeError("restore"))
    _install(monkeypatch, socket)

    def invoke():
        try:
            raise ValueError("ambient")
        except ValueError:
            return receive_response(socket, deadline=20)

    _error(invoke, "timeout_restore_failed")


def test_permanent_and_concurrent_claim_prevents_second_reader(monkeypatch):
    socket = _Socket([b"bad\r\n\r\n"])
    _install(monkeypatch, socket)
    _error(lambda: receive_response(socket, deadline=20))
    _error(lambda: receive_response(socket, deadline=20), "connection_claimed")

    entered, release = threading.Event(), threading.Event()

    class BlockingSocket(_Socket):
        def recv(self, amount):
            entered.set()
            assert release.wait(1)
            return super().recv(amount)

    blocking = BlockingSocket([_response()])
    _install(monkeypatch, blocking)
    result = []
    worker = threading.Thread(target=lambda: result.append(receive_response(blocking, deadline=20)))
    worker.start()
    assert entered.wait(1)
    _error(lambda: receive_response(blocking, deadline=20), "connection_claimed")
    release.set()
    worker.join(1)
    assert not worker.is_alive() and result


def test_oversized_fake_recv_is_rejected_before_buffering(monkeypatch):
    class OversizedSocket(_Socket):
        def recv(self, amount):
            self.recv_sizes.append(amount)
            return b"x" * (amount + 1)

    socket = OversizedSocket([])
    _install(monkeypatch, socket)
    _error(lambda: receive_response(socket, deadline=20), "receive_failed")
