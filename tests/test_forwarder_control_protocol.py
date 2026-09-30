"""Behavioral tests for the bounded Forwarder control-frame codec.

These tests use only connected local Unix stream sockets.  They exercise the
wire boundary independently of the controller-session implementation.
"""

from __future__ import annotations

import json
import socket
import struct
import time
from types import SimpleNamespace

import pytest

import grafana_jsm_sandbox.forwarder_control_protocol as protocol
from grafana_jsm_sandbox.forwarder_control_protocol import (
    MAX_FRAME_BYTES,
    ControlProtocolError,
    recv_frame,
    send_frame,
)


def wire(payload: object) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return struct.pack("!I", len(body)) + body


def socket_pair() -> tuple[socket.socket, socket.socket]:
    reader, writer = socket.socketpair()
    reader.settimeout(1.0)
    writer.settimeout(1.0)
    return reader, writer


def assert_protocol_error(call, marker: str | None = None) -> ControlProtocolError:
    with pytest.raises(ControlProtocolError) as caught:
        call()
    error = caught.value
    assert isinstance(error.code, str)
    assert str(error) == error.code
    if marker is not None:
        assert marker not in error.code
        assert marker not in str(error)
        assert marker not in repr(error)
    return error


def test_recv_frame_accepts_fragmented_frame_and_restores_socket_timeout():
    reader, writer = socket_pair()
    try:
        reader.settimeout(0.73)
        frame = wire({"op": "heartbeat", "seq": 1})
        writer.sendall(frame[:1])
        writer.sendall(frame[1:4])
        writer.sendall(frame[4:9])
        writer.sendall(frame[9:])

        assert recv_frame(reader, timeout=0.2) == {"op": "heartbeat", "seq": 1}
        assert reader.gettimeout() == 0.73
    finally:
        reader.close()
        writer.close()


def test_recv_frame_consumes_exactly_one_coalesced_frame():
    reader, writer = socket_pair()
    try:
        first = {"op": "register", "seq": 1}
        second = {"op": "activate", "seq": 2}
        writer.sendall(wire(first) + wire(second))

        assert recv_frame(reader, timeout=0.2) == first
        assert recv_frame(reader, timeout=0.2) == second
    finally:
        reader.close()
        writer.close()


def test_send_frame_writes_a_decodable_frame_and_restores_socket_timeout():
    reader, writer = socket_pair()
    try:
        writer.settimeout(0.61)
        payload = {"op": "heartbeat", "seq": 7, "params": {}}
        send_frame(writer, payload, timeout=0.2)

        assert recv_frame(reader, timeout=0.2) == payload
        assert writer.gettimeout() == 0.61
    finally:
        reader.close()
        writer.close()


def test_recv_frame_uses_a_bounded_deadline_and_restores_timeout():
    reader, writer = socket_pair()
    try:
        reader.settimeout(0.88)
        started = time.monotonic()
        error = assert_protocol_error(lambda: recv_frame(reader, timeout=0.04))
        elapsed = time.monotonic() - started

        assert error.code == "timeout"
        assert elapsed < 0.5
        assert reader.gettimeout() == 0.88
    finally:
        reader.close()
        writer.close()


def test_clean_eof_and_partial_eof_have_distinct_fixed_errors():
    reader, writer = socket_pair()
    writer.close()
    try:
        assert assert_protocol_error(lambda: recv_frame(reader, timeout=0.2)).code == "eof"
    finally:
        reader.close()

    reader, writer = socket_pair()
    try:
        writer.sendall(b"\x00\x00")
        writer.close()
        assert assert_protocol_error(lambda: recv_frame(reader, timeout=0.2)).code == "truncated_frame"
    finally:
        reader.close()

    reader, writer = socket_pair()
    try:
        writer.sendall(struct.pack("!I", 3) + b"{")
        writer.close()
        assert assert_protocol_error(lambda: recv_frame(reader, timeout=0.2)).code == "truncated_frame"
    finally:
        reader.close()


@pytest.mark.parametrize("length", [0, MAX_FRAME_BYTES + 1])
def test_rejected_length_prefix_does_not_read_a_body(length: int):
    reader, writer = socket_pair()
    try:
        marker = b"body-remains-unread"
        writer.sendall(struct.pack("!I", length) + marker)

        error = assert_protocol_error(lambda: recv_frame(reader, timeout=0.2))
        assert error.code in {"invalid_length", "oversize_frame"}
        assert reader.recv(len(marker)) == marker
    finally:
        reader.close()
        writer.close()


@pytest.mark.parametrize(
    ("body", "marker"),
    [
        (b"not-json-PRIVATE-MARKER", "PRIVATE-MARKER"),
        (b'{"field":"bad-UTF8-PRIVATE-\xff"}', "PRIVATE"),
        (b'{"dup":1,"dup":2,"PRIVATE-DUP":3}', "PRIVATE-DUP"),
        (b"[\"PRIVATE-ARRAY\"]", "PRIVATE-ARRAY"),
        (b'"PRIVATE-SCALAR"', "PRIVATE-SCALAR"),
        (b'{"number":NaN,"marker":"PRIVATE-NAN"}', "PRIVATE-NAN"),
        (b'{"number":Infinity,"marker":"PRIVATE-INF"}', "PRIVATE-INF"),
        (b'{"number":-Infinity,"marker":"PRIVATE-NEG-INF"}', "PRIVATE-NEG-INF"),
        (b'{"number":9223372036854775808,"marker":"PRIVATE-INT"}', "PRIVATE-INT"),
        (
            b'{"one":{"two":{"three":{"four":{"five":{"six":"PRIVATE-DEEP"}}}}}}',
            "PRIVATE-DEEP",
        ),
    ],
)
def test_recv_frame_rejects_invalid_parser_forms_without_echoing_input(body: bytes, marker: str):
    reader, writer = socket_pair()
    try:
        writer.sendall(struct.pack("!I", len(body)) + body)
        assert_protocol_error(lambda: recv_frame(reader, timeout=0.2), marker)
    finally:
        reader.close()
        writer.close()


def test_recv_frame_rejects_oversized_keys_and_string_values_without_echoing_input():
    cases = [
        ({"k" * 65: "PRIVATE-KEY"}, "PRIVATE-KEY"),
        ({"field": "PRIVATE-VALUE-" + "x" * 600}, "PRIVATE-VALUE-"),
    ]
    for payload, marker in cases:
        reader, writer = socket_pair()
        try:
            writer.sendall(wire(payload))
            assert_protocol_error(lambda reader=reader: recv_frame(reader, timeout=0.2), marker)
        finally:
            reader.close()
            writer.close()


def test_recv_frame_accepts_boundary_values_and_allowed_leaf_types():
    payload = {
        "k" * 64: "é" * 256,
        "minimum": -(2 ** 63),
        "maximum": 2 ** 63 - 1,
        "float": 1.25,
        "true": True,
        "false": False,
        "nothing": None,
        "one": {"two": {"three": {}}},
    }
    reader, writer = socket_pair()
    try:
        writer.sendall(wire(payload))
        assert recv_frame(reader, timeout=0.2) == payload
    finally:
        reader.close()
        writer.close()


def test_recv_frame_wraps_a_5000_digit_json_integer_without_echoing_input():
    body = b'{"number":' + b"9" * 5000 + b',"marker":"PRIVATE-HUGE-INTEGER"}'
    assert len(body) < MAX_FRAME_BYTES
    reader, writer = socket_pair()
    try:
        writer.sendall(struct.pack("!I", len(body)) + body)
        assert_protocol_error(lambda: recv_frame(reader, timeout=0.2), "PRIVATE-HUGE-INTEGER")
    finally:
        reader.close()
        writer.close()


@pytest.mark.parametrize(
    "call",
    [
        lambda reader, writer: recv_frame(reader, timeout=10**1000),
        lambda reader, writer: send_frame(writer, {"op": "heartbeat"}, timeout=10**1000),
    ],
)
def test_unrepresentable_timeout_is_a_fixed_protocol_error(call):
    reader, writer = socket_pair()
    try:
        assert assert_protocol_error(lambda: call(reader, writer)).code == "invalid_timeout"
    finally:
        reader.close()
        writer.close()


class DribbleSocket:
    def __init__(self, chunks: list[bytes]):
        self.chunks = list(chunks)
        self.timeout = 0.91
        self.timeouts: list[float | None] = []
        self.recv_calls = 0

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout
        self.timeouts.append(timeout)

    def recv(self, maximum: int) -> bytes:
        self.recv_calls += 1
        chunk = self.chunks.pop(0)
        assert len(chunk) <= maximum
        return chunk


class MutableClock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_recv_frame_dribble_uses_one_absolute_deadline(monkeypatch):
    frame = wire({"op": "heartbeat"})
    clock_values = iter([100.0, 100.0, 100.0, 104.0, 108.0, 111.0])
    sock = DribbleSocket([frame[:4], frame[4:7], frame[7:10], frame[10:]])
    monkeypatch.setattr(protocol, "time", SimpleNamespace(monotonic=lambda: next(clock_values)))

    assert assert_protocol_error(lambda: recv_frame(sock, timeout=10.0)).code == "timeout"
    assert sock.recv_calls == 3
    assert sock.timeouts[:3] == [10.0, 6.0, 2.0]
    assert sock.timeout == 0.91
    assert sock.chunks == [frame[10:]]


def test_recv_frame_checks_its_deadline_after_the_final_body_read(monkeypatch):
    class FinalReadSocket(DribbleSocket):
        def recv(self, maximum: int) -> bytes:
            chunk = super().recv(maximum)
            if not self.chunks:
                clock.value = 111.0
            return chunk

    frame = wire({"op": "heartbeat"})
    clock = MutableClock(100.0)
    sock = FinalReadSocket([frame[:4], frame[4:]])
    monkeypatch.setattr(protocol, "time", SimpleNamespace(monotonic=clock))

    assert assert_protocol_error(lambda: recv_frame(sock, timeout=10.0)).code == "timeout"
    assert sock.timeout == 0.91


def test_recv_frame_checks_its_deadline_after_decoding(monkeypatch):
    frame = wire({"op": "heartbeat"})
    clock = MutableClock(100.0)
    sock = DribbleSocket([frame[:4], frame[4:]])
    decode = protocol._decode_payload

    def late_decode(body: bytes) -> dict:
        result = decode(body)
        clock.value = 111.0
        return result

    monkeypatch.setattr(protocol, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(protocol, "_decode_payload", late_decode)

    assert assert_protocol_error(lambda: recv_frame(sock, timeout=10.0)).code == "timeout"
    assert sock.timeout == 0.91


def test_send_frame_checks_its_deadline_after_the_final_write(monkeypatch):
    class FinalWriteSocket:
        def __init__(self):
            self.timeout = 0.91
            self.sent = b""

        def gettimeout(self) -> float:
            return self.timeout

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

        def send(self, data: bytes) -> int:
            self.sent += data
            clock.value = 111.0
            return len(data)

    clock = MutableClock(100.0)
    sock = FinalWriteSocket()
    monkeypatch.setattr(protocol, "time", SimpleNamespace(monotonic=clock))

    assert assert_protocol_error(
        lambda: send_frame(sock, {"op": "heartbeat"}, timeout=10.0)
    ).code == "timeout"
    assert sock.timeout == 0.91
    assert sock.sent


@pytest.mark.parametrize(
    "payload",
    [
        {"bad": ["PRIVATE-OUTPUT-ARRAY"]},
        {"bad": "PRIVATE-OUTPUT-STRING-" + "x" * 600},
        {"marker": "PRIVATE-OUTPUT-NAN", "bad": float("nan")},
        {"bad": "PRIVATE-OUTPUT-OVERSIZE-" + "x" * (MAX_FRAME_BYTES + 1)},
    ],
)
def test_send_frame_validation_failure_writes_no_bytes(payload: dict[str, object]):
    reader, writer = socket_pair()
    try:
        assert_protocol_error(lambda: send_frame(writer, payload, timeout=0.2), "PRIVATE-OUTPUT")
        reader.settimeout(0.05)
        with pytest.raises(socket.timeout):
            reader.recv(1)
    finally:
        reader.close()
        writer.close()
