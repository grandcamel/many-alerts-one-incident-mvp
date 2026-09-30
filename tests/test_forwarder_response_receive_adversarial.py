"""Independent transport caps, trust-state and deadline regression tests."""

import math
import ssl
from itertools import pairwise

import pytest

from grafana_jsm_sandbox.forwarder_http_response import (
    HTTPResponseError,
    parse_response_head,
)
from grafana_jsm_sandbox.forwarder_response_receive import ResponseReceiveError, receive_response
from tests.test_forwarder_response_receive import _install, _response, _Socket


class StreamSocket(_Socket):
    def __init__(self, data):
        super().__init__([])
        self.remaining = data

    def recv(self, amount):
        self.recv_sizes.append(amount)
        part, self.remaining = self.remaining[:amount], self.remaining[amount:]
        return part


@pytest.mark.parametrize("field,value", [
    ("protocol", ssl.PROTOCOL_TLS_SERVER),
    ("verify_mode", ssl.CERT_NONE),
    ("check_hostname", False),
])
def test_unverified_client_configuration_is_rejected_before_reads(monkeypatch, field, value):
    connection = _Socket([_response()])
    setattr(connection.context, field, value)
    _install(monkeypatch, connection)
    with pytest.raises(ResponseReceiveError) as caught:
        receive_response(connection, deadline=20)
    assert caught.value.code == "invalid_connection"
    assert not connection.recv_sizes


def test_closed_descriptor_is_rejected_and_absent_alpn_is_allowed(monkeypatch):
    connection = _Socket([_response()])
    connection.fileno = lambda: -1
    _install(monkeypatch, connection)
    with pytest.raises(ResponseReceiveError):
        receive_response(connection, deadline=20)
    assert not connection.recv_sizes
    connected = _Socket([_response()], alpn=None)
    _install(monkeypatch, connected)
    assert receive_response(connected, deadline=20).status == 200


@pytest.mark.parametrize("post_restore,code", [
    (math.nan, "clock_fault"), (math.inf, "clock_fault"),
    (10.1, "clock_fault"), (20, "deadline_expired"),
])
def test_post_restore_clock_must_remain_valid_forward_and_inside_deadline(
    monkeypatch, post_restore, code,
):
    connection = _Socket([_response()])
    times = iter((10, 10.1, 10.2, 10.3, post_restore))
    _install(monkeypatch, connection, lambda: next(times))
    with pytest.raises(ResponseReceiveError) as caught:
        receive_response(connection, deadline=20)
    assert caught.value.code == code
    assert connection.timeout_history[-1] == 2.0


def test_fragment_progress_never_renews_handler_deadline(monkeypatch):
    connection = _Socket([bytes([byte]) for byte in _response()])
    current = [9.4]

    def clock():
        current[0] += 0.6
        return current[0]

    _install(monkeypatch, connection, clock)
    with pytest.raises(ResponseReceiveError) as caught:
        receive_response(connection, deadline=13)
    assert caught.value.code == "deadline_expired"
    assert 1 <= len(connection.recv_sizes) < len(_response())
    active_timeouts = connection.timeout_history[:-1]
    assert all(later < earlier for earlier, later in pairwise(active_timeouts))


def test_socket_timeout_clips_to_inactivity_and_remaining_handler_budget(monkeypatch):
    for deadline, expected in ((40, 20), (15, 5)):
        connection = _Socket([_response()])
        _install(monkeypatch, connection)
        receive_response(connection, deadline=deadline)
        assert connection.timeout_history == [expected, 2.0]


def test_complete_head_rejects_oversized_declaration_before_more_body_reads(monkeypatch):
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 1048577\r\n\r\n")
    connection = _Socket([head, b"should never read this"])
    _install(monkeypatch, connection)
    with pytest.raises(ResponseReceiveError):
        receive_response(connection, deadline=20)
    assert len(connection.recv_sizes) == 1
    assert connection.chunks == [b"should never read this"]
    maximum = head.replace(b"1048577", b"1048576")
    parsed = parse_response_head(maximum)
    assert parsed.body_length == 1048576
    assert not hasattr(parsed, "body")


def test_status_and_header_caps_are_independently_enforced_during_collection(monkeypatch):
    line = b"HTTP/1.1 200 " + b"x" * (2048 - len(b"HTTP/1.1 200 \r\n")) + b"\r\n"
    fields = b"Content-Type: application/json\r\nContent-Length: 1\r\nX-Pad: "
    head = line + fields + b"p" * (16384 - len(fields) - 4) + b"\r\n\r\n"
    assert len(head) == 2048 + 16384
    assert parse_response_head(head).body_length == 1
    connection = StreamSocket(head + b"x")
    _install(monkeypatch, connection)
    assert receive_response(connection, deadline=20).body == b"x"
    assert max(connection.recv_sizes) <= 4096

    for oversized in (head.replace(b"HTTP/1.1 200 ", b"HTTP/1.1 200 x", 1),
                      head.replace(b"X-Pad: ", b"X-Pad: p", 1)):
        with pytest.raises(HTTPResponseError):
            parse_response_head(oversized)
        connection = StreamSocket(oversized + b"x")
        _install(monkeypatch, connection)
        with pytest.raises(ResponseReceiveError):
            receive_response(connection, deadline=20)
        assert max(connection.recv_sizes) <= 4096
