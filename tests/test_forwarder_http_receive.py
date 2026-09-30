"""Synthetic bounded receive tests for the one-request Forwarder TLS boundary."""

from __future__ import annotations

import base64
import math
import ssl
import threading

import pytest

from grafana_jsm_sandbox import forwarder_http_receive
from grafana_jsm_sandbox.forwarder_http import (
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    MAX_REQUEST_LINE_BYTES,
)
from grafana_jsm_sandbox.forwarder_http_receive import HTTPReceiveError, receive_request
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES

TOKEN = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")


class _Context:
    protocol = ssl.PROTOCOL_TLS_SERVER


class _Socket:
    def __init__(self, chunks, *, version="TLSv1.3", timeout=3.0, restore_error=None):
        self.chunks = list(chunks)
        self.context = _Context()
        self.server_side = True
        self._version = version
        self._timeout = timeout
        self.restore_error = restore_error
        self.recv_sizes = []
        self.timeout_history = []
        self.sends = 0
        self.closes = 0
        self.shutdowns = 0

    def fileno(self):
        return 47

    def version(self):
        return self._version

    def gettimeout(self):
        return self._timeout

    def settimeout(self, timeout):
        if timeout == 3.0 and self.restore_error:
            raise self.restore_error
        self._timeout = timeout
        self.timeout_history.append(timeout)

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
        self.sends += 1

    def close(self):
        self.closes += 1

    def shutdown(self, _how):
        self.shutdowns += 1


class _StreamSocket(_Socket):
    """A recv stream that returns no more bytes than the collector requested."""

    def __init__(self, data):
        super().__init__([])
        self.remaining = data

    def recv(self, amount):
        self.recv_sizes.append(amount)
        chunk, self.remaining = self.remaining[:amount], self.remaining[amount:]
        return chunk


def _authorization(service):
    if service in {"jira", "confluence"}:
        return "Basic " + base64.b64encode(f"run:{TOKEN}".encode()).decode()
    return f"Bearer {TOKEN}"


def _request(service="jira", *, method="GET", target="/items", body=b""):
    profile = SERVICE_PROFILES[service]
    headers = [
        f"Host: {profile.server_name}:{profile.port}",
        f"Authorization: {_authorization(service)}",
        "Accept: application/json",
    ]
    if method != "GET":
        headers.extend(("Content-Type: application/json", f"Content-Length: {len(body)}"))
    return (f"{method} {target} HTTP/1.1\r\n".encode()
            + "\r\n".join(headers).encode() + b"\r\n\r\n" + body)


def _install(monkeypatch, socket, clock=lambda: 10.0):
    monkeypatch.setattr(forwarder_http_receive.ssl, "SSLSocket", type(socket))
    monkeypatch.setattr(forwarder_http_receive.time, "monotonic", clock)
    return socket


def _error(call, code=None):
    with pytest.raises(HTTPReceiveError) as raised:
        call()
    assert raised.value.code
    assert str(raised.value) == raised.value.code
    if code:
        assert raised.value.code == code


def test_coalesced_request_preserves_body_and_never_mutates_caller_socket(monkeypatch):
    body = b'{"opaque":true}'
    socket = _install(monkeypatch, _Socket([_request("grafana", method="POST", body=body)]))

    parsed = receive_request(socket, "grafana", deadline=20)

    assert parsed.body == body
    assert parsed.sentinel == TOKEN
    assert socket.recv_sizes == [2049]
    assert socket.timeout_history[-1] == 3.0
    assert not (socket.sends or socket.closes or socket.shutdowns)


def test_fragmented_header_and_body_are_collected_under_bounded_reads(monkeypatch):
    body = b'{"a":1}'
    request = _request("jira", method="POST", body=body)
    first = request.index(b"\r\n") + 2
    head_end = request.index(b"\r\n\r\n") + 4
    chunks = [request[:first], request[first:head_end], body[:2], body[2:]]
    socket = _install(monkeypatch, _Socket(chunks))

    parsed = receive_request(socket, "jira", deadline=20)

    assert parsed.body == body
    assert all(amount <= 4096 for amount in socket.recv_sizes[:2])
    assert all(amount <= 65536 for amount in socket.recv_sizes)


@pytest.mark.parametrize("connection", [object(), _Socket([], version="TLSv1.1")])
def test_requires_exact_open_tls12_or_tls13_server_socket(monkeypatch, connection):
    _install(monkeypatch, _Socket([]))
    _error(lambda: receive_request(connection, "jira", deadline=20), "invalid_connection")


def test_requires_exact_server_side_socket(monkeypatch):
    socket = _Socket([])
    socket.server_side = False
    _install(monkeypatch, socket)
    _error(lambda: receive_request(socket, "jira", deadline=20), "invalid_connection")


@pytest.mark.parametrize("deadline", [True, 0, -1, 2**2000, math.nan, math.inf, 10, 51])
def test_rejects_invalid_or_nonfuture_absolute_deadline(monkeypatch, deadline):
    socket = _install(monkeypatch, _Socket([]))
    _error(lambda: receive_request(socket, "jira", deadline=deadline), "invalid_deadline")


def test_head_eof_or_extra_coalesced_body_rejects_without_further_read_or_close(monkeypatch):
    incomplete = _install(monkeypatch, _Socket([b"GET /items HTTP/1.1\r\n", b""]))
    _error(lambda: receive_request(incomplete, "jira", deadline=20), "receive_failed")
    assert incomplete.recv_sizes == [2049, 4096]
    assert not incomplete.closes

    extra = _install(monkeypatch, _Socket([_request("jira", method="POST", body=b"x") + b"x"]))
    _error(lambda: receive_request(extra, "jira", deadline=20), "receive_failed")
    assert extra.recv_sizes == [2049]
    assert not extra.closes


def test_body_reads_are_chunked_and_exact_body_completion_does_not_probe(monkeypatch):
    body = b"x" * 70_000
    request = _request("jira", method="POST", body=body)
    head_end = request.index(b"\r\n\r\n") + 4
    socket = _install(monkeypatch, _Socket([request[:head_end], body[:65536], body[65536:]]))

    parsed = receive_request(socket, "jira", deadline=20)

    assert parsed.body == body
    assert socket.recv_sizes == [2049, 65536, len(body) - 65536 + 1]
    assert socket.chunks == []


def test_exact_request_line_and_header_limits_accept_with_one_byte_overflows_rejected(monkeypatch):
    target = "/" + "a" * (MAX_REQUEST_LINE_BYTES - len(b"GET  HTTP/1.1\r\n") - 1)
    exact_line = _request(target=target)
    assert len(exact_line.split(b"\r\n", 1)[0]) + 2 == MAX_REQUEST_LINE_BYTES
    assert receive_request(_install(monkeypatch, _StreamSocket(exact_line)), "jira", deadline=20).path == target
    _error(
        lambda: receive_request(_install(monkeypatch, _StreamSocket(_request(target=target + "a"))), "jira", deadline=20),
        "receive_failed",
    )

    normal = _request()
    header_section = normal.split(b"\r\n", 1)[1]
    padding = MAX_HEADER_BYTES - len(header_section) - len(b"User-Agent: \r\n")
    exact_headers = normal[:-2] + b"User-Agent: " + b"x" * padding + b"\r\n\r\n"
    assert len(exact_headers.split(b"\r\n", 1)[1]) == MAX_HEADER_BYTES
    assert receive_request(_install(monkeypatch, _StreamSocket(exact_headers)), "jira", deadline=20).method == "GET"
    _error(
        lambda: receive_request(_install(monkeypatch, _StreamSocket(exact_headers[:-2] + b"x\r\n\r\n")), "jira", deadline=20),
        "receive_failed",
    )


def test_invalid_complete_heads_reject_before_any_body_receive(monkeypatch):
    oversized = _request("jira", method="POST", body=b"").replace(b"Content-Length: 0", b"Content-Length: 262145")
    duplicate = _request("jira", method="POST", body=b"")[:-2] + b"Content-Length: 0\r\n\r\n"
    for request in (oversized, duplicate):
        socket = _install(monkeypatch, _StreamSocket(request + b"later-body"))
        _error(lambda socket=socket: receive_request(socket, "jira", deadline=20))
        assert max(socket.recv_sizes) <= 4096
        assert len(socket.recv_sizes) == 1


def test_maximum_body_stream_accepts_but_a_captured_extra_byte_rejects(monkeypatch):
    body = b"x" * MAX_BODY_BYTES
    request = _request("jira", method="POST", body=body)
    accepted = _install(monkeypatch, _StreamSocket(request))
    assert receive_request(accepted, "jira", deadline=20).body == body
    assert max(accepted.recv_sizes) <= 65536

    head_end = request.index(b"\r\n\r\n") + 4
    chunks = [request[:head_end], body[:65536], body[65536:131072], body[131072:196608], body[196608:-1], b"xx"]
    extra = _install(monkeypatch, _Socket(chunks))
    _error(lambda: receive_request(extra, "jira", deadline=20), "receive_failed")
    assert extra.recv_sizes[-1] == 2


def test_eof_inside_declared_body_rejects(monkeypatch):
    body = b"abcdef"
    request = _request("jira", method="POST", body=body)
    head_end = request.index(b"\r\n\r\n") + 4
    socket = _install(monkeypatch, _Socket([request[:head_end], body[:3], b""]))
    _error(lambda: receive_request(socket, "jira", deadline=20), "receive_failed")


def test_absolute_deadline_is_not_reset_between_slow_fragments(monkeypatch):
    request = _request()
    line_end = request.index(b"\r\n") + 2
    socket = _Socket([request[:line_end], request[line_end:]])
    times = iter((10, 10.1, 10.2, 10.9, 11.0))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: receive_request(socket, "jira", deadline=11), "deadline_expired")
    assert socket.timeout_history[0] == pytest.approx(0.9)
    assert socket.timeout_history[1] == pytest.approx(0.1)
    assert socket.timeout_history[-1] == 3.0


def test_regressing_clock_after_a_read_rejects_and_preserves_socket(monkeypatch):
    socket = _Socket([_request()])
    times = iter((10, 10.1, 10.0))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: receive_request(socket, "jira", deadline=20), "clock_fault")
    assert socket.timeout_history[-1] == 3.0
    assert not socket.closes


def test_connection_is_permanently_claimed_even_after_failure(monkeypatch):
    socket = _install(monkeypatch, _Socket([b"bad\r\n\r\n"]))
    _error(lambda: receive_request(socket, "jira", deadline=20))
    reads = list(socket.recv_sizes)
    _error(lambda: receive_request(socket, "jira", deadline=20), "connection_claimed")
    assert socket.recv_sizes == reads


def test_oversized_recv_result_is_rejected_before_buffering(monkeypatch):
    class OversizedSocket(_Socket):
        def recv(self, amount):
            self.recv_sizes.append(amount)
            return b"x" * (amount + 1)

    socket = _install(monkeypatch, OversizedSocket([]))
    _error(lambda: receive_request(socket, "jira", deadline=20), "receive_failed")
    assert socket.recv_sizes == [2049]


def test_concurrent_claim_fails_before_second_reader_can_consume_bytes(monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    class BlockingSocket(_Socket):
        def recv(self, amount):
            entered.set()
            assert release.wait(1)
            return super().recv(amount)

    socket = _install(monkeypatch, BlockingSocket([_request()]))
    outcomes = []
    worker = threading.Thread(target=lambda: outcomes.append(receive_request(socket, "jira", deadline=20)))
    worker.start()
    assert entered.wait(1)
    _error(lambda: receive_request(socket, "jira", deadline=20), "connection_claimed")
    release.set()
    worker.join(1)
    assert not worker.is_alive() and len(outcomes) == 1


def test_restore_failure_rejects_success_and_does_not_mask_prior_receive_failure(monkeypatch):
    successful = _install(monkeypatch, _Socket([_request()], restore_error=RuntimeError("restore")))
    _error(lambda: receive_request(successful, "jira", deadline=20), "timeout_restore_failed")
    _error(lambda: receive_request(successful, "jira", deadline=20), "connection_claimed")

    failed = _install(monkeypatch, _Socket([OSError("read"),], restore_error=RuntimeError("restore")))
    _error(lambda: receive_request(failed, "jira", deadline=20), "receive_failed")


def test_restore_failure_after_success_is_not_hidden_by_callers_handled_exception(monkeypatch):
    socket = _install(monkeypatch, _Socket([_request()], restore_error=RuntimeError("restore")))

    def called_while_handling_another_error():
        try:
            raise ValueError("ambient")
        except ValueError:
            return receive_request(socket, "jira", deadline=20)

    _error(called_while_handling_another_error, "timeout_restore_failed")


def test_restore_failure_does_not_mask_interrupted_receive(monkeypatch):
    socket = _install(monkeypatch, _Socket([KeyboardInterrupt()], restore_error=RuntimeError("restore")))
    with pytest.raises(KeyboardInterrupt):
        receive_request(socket, "jira", deadline=20)


def test_final_deadline_check_runs_after_timeout_restoration(monkeypatch):
    socket = _Socket([_request()])
    times = iter((10, 10.1, 10.2, 10.3, 10.4))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: receive_request(socket, "jira", deadline=10.35), "deadline_expired")
    assert socket.timeout_history[-1] == 3.0


def test_post_restore_clock_cannot_regress_from_the_final_pre_restore_sample(monkeypatch):
    socket = _Socket([_request()])
    times = iter((10, 10.1, 10.2, 10.4, 10.3))
    _install(monkeypatch, socket, lambda: next(times))

    _error(lambda: receive_request(socket, "jira", deadline=20), "clock_fault")
    assert socket.timeout_history[-1] == 3.0
