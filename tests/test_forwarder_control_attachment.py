"""Behavioral tests for the additive attachment codec on the Forwarder control socket.

These tests use only connected local Unix stream sockets, plus fake sockets and a
monkeypatched clock for deadline and reassembly edge cases, mirroring
tests/test_forwarder_control_protocol.py.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

import grafana_jsm_sandbox.forwarder_control_protocol as protocol
from grafana_jsm_sandbox.forwarder_control_protocol import (
    MAX_ATTACHMENT_BYTES,
    MAX_FRAME_BYTES,
    ControlProtocolError,
    recv_attachment,
    recv_frame,
    send_attachment,
)


def wire(payload: object) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return struct.pack("!I", len(body)) + body


def socket_pair() -> tuple[socket.socket, socket.socket]:
    reader, writer = socket.socketpair()
    reader.settimeout(1.0)
    writer.settimeout(1.0)
    return reader, writer


def attachment_bytes(size: int) -> bytes:
    pattern = bytes([0xFF, 0xFE, 0xFD, 0x00, 0x80, 0xC0, 0xC1, 0x41])
    return (pattern * (size // len(pattern) + 1))[:size]


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


class DripSocket:
    """Serves one byte per `recv` call, regardless of the requested maximum."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self.timeout = 5.0

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def recv(self, maximum: int) -> bytes:
        if self._pos >= len(self._data):
            return b""
        chunk = self._data[self._pos : self._pos + 1]
        self._pos += 1
        return chunk


class NoCallSocket:
    def gettimeout(self) -> float | None:
        raise AssertionError("socket touched")

    def settimeout(self, timeout: float | None) -> None:
        raise AssertionError("socket touched")

    def recv(self, maximum: int) -> bytes:
        raise AssertionError("socket touched")

    def send(self, data: bytes) -> int:
        raise AssertionError("socket touched")


# A1


@pytest.mark.parametrize("size", [1, MAX_FRAME_BYTES + 1, MAX_ATTACHMENT_BYTES])
def test_attachment_round_trip_returns_exact_bytes_and_restores_timeout(size: int):
    # A larger-than-buffer send blocks until read, so send concurrently.
    reader, writer = socket_pair()
    try:
        reader.settimeout(0.83)
        writer.settimeout(0.77)
        data = attachment_bytes(size)
        sender_errors: list[Exception] = []

        def send() -> None:
            try:
                send_attachment(writer, data, timeout=2.0)
            except Exception as error:  # noqa: BLE001 - surfaced via the assertion below
                sender_errors.append(error)

        thread = threading.Thread(target=send)
        thread.start()
        received = recv_attachment(reader, length=size, timeout=2.0)
        thread.join(timeout=5.0)

        assert not thread.is_alive()
        assert sender_errors == []
        assert received == data
        assert reader.gettimeout() == 0.83
        assert writer.gettimeout() == 0.77
    finally:
        reader.close()
        writer.close()


def test_recv_attachment_restores_timeout_after_a_wire_failure():
    reader, writer = socket_pair()
    try:
        reader.settimeout(0.55)
        writer.sendall(struct.pack("!I", 999))
        error = assert_protocol_error(lambda: recv_attachment(reader, length=100, timeout=0.2))
        assert error.code == "attachment_mismatch"
        assert reader.gettimeout() == 0.55
    finally:
        reader.close()
        writer.close()


def test_send_attachment_restores_timeout_after_a_write_failure():
    class FailingSendSocket:
        def __init__(self):
            self.timeout = 0.44

        def gettimeout(self) -> float | None:
            return self.timeout

        def settimeout(self, timeout: float | None) -> None:
            self.timeout = timeout

        def send(self, data: bytes) -> int:
            raise OSError("boom")

    sock = FailingSendSocket()
    error = assert_protocol_error(lambda: send_attachment(sock, b"x", timeout=0.2))
    assert error.code == "write_failure"
    assert sock.gettimeout() == 0.44


# A2


def test_recv_attachment_reassembles_a_one_byte_drip_and_recv_frame_reads_the_coalesced_frame():
    body = attachment_bytes(37)
    header = struct.pack("!I", len(body))
    frame_payload = {"op": "heartbeat", "seq": 3}
    sock = DripSocket(header + body + wire(frame_payload))

    received = recv_attachment(sock, length=len(body), timeout=1.0)
    assert received == body

    assert recv_frame(sock, timeout=1.0) == frame_payload


# A3


@pytest.mark.parametrize(
    ("declared", "length", "code"),
    [
        (0, 10, "invalid_length"),
        (MAX_ATTACHMENT_BYTES + 1, 10, "oversize_frame"),
        (5, 10, "attachment_mismatch"),
    ],
)
def test_recv_attachment_rejects_bad_declared_length_without_reading_the_body(
    declared: int, length: int, code: str
):
    reader, writer = socket_pair()
    try:
        marker = b"attachment-body-remains-unread"
        writer.sendall(struct.pack("!I", declared) + marker)

        error = assert_protocol_error(lambda: recv_attachment(reader, length=length, timeout=0.2))
        assert error.code == code
        assert reader.recv(len(marker)) == marker
    finally:
        reader.close()
        writer.close()


# A4


@pytest.mark.parametrize("length", [0, -1, True, 1.0, MAX_ATTACHMENT_BYTES + 1])
def test_recv_attachment_rejects_invalid_length_argument_without_any_socket_call(length: object):
    sock = NoCallSocket()
    error = assert_protocol_error(lambda: recv_attachment(sock, length=length, timeout=0.2))
    assert error.code == "invalid_attachment_length"


# A5


def test_recv_attachment_eof_before_the_header_gives_truncated_frame():
    reader, writer = socket_pair()
    writer.close()
    try:
        error = assert_protocol_error(lambda: recv_attachment(reader, length=10, timeout=0.2))
        assert error.code == "truncated_frame"
    finally:
        reader.close()


def test_recv_attachment_eof_inside_the_header_gives_truncated_frame():
    reader, writer = socket_pair()
    try:
        writer.sendall(b"\x00\x00")
        writer.close()
        error = assert_protocol_error(lambda: recv_attachment(reader, length=10, timeout=0.2))
        assert error.code == "truncated_frame"
    finally:
        reader.close()


def test_recv_attachment_eof_mid_body_gives_truncated_frame():
    reader, writer = socket_pair()
    try:
        writer.sendall(struct.pack("!I", 10) + b"abc")
        writer.close()
        error = assert_protocol_error(lambda: recv_attachment(reader, length=10, timeout=0.2))
        assert error.code == "truncated_frame"
    finally:
        reader.close()


# A6


def test_recv_attachment_dribble_past_the_deadline_gives_timeout(monkeypatch):
    body = b"abcdef"
    header = struct.pack("!I", len(body))
    clock_values = iter([100.0, 100.0, 101.0, 102.0, 103.0, 111.0])
    sock = DribbleSocket([header[:2], header[2:], body[:3], body[3:]])
    monkeypatch.setattr(protocol, "time", SimpleNamespace(monotonic=lambda: next(clock_values)))

    error = assert_protocol_error(
        lambda: recv_attachment(sock, length=len(body), timeout=10.0)
    )
    assert error.code == "timeout"
    assert sock.recv_calls == 3
    assert sock.chunks == [body[3:]]
    assert sock.timeout == 0.91


def test_recv_attachment_checks_the_deadline_after_the_final_body_read(monkeypatch):
    class FinalReadSocket(DribbleSocket):
        def recv(self, maximum: int) -> bytes:
            chunk = super().recv(maximum)
            if not self.chunks:
                clock.value = 111.0
            return chunk

    body = b"manifest-tail"
    header = struct.pack("!I", len(body))
    clock = MutableClock(100.0)
    sock = FinalReadSocket([header, body])
    monkeypatch.setattr(protocol, "time", SimpleNamespace(monotonic=clock))

    error = assert_protocol_error(
        lambda: recv_attachment(sock, length=len(body), timeout=10.0)
    )
    assert error.code == "timeout"
    assert sock.timeout == 0.91


def test_send_attachment_checks_the_deadline_after_the_final_write(monkeypatch):
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

    error = assert_protocol_error(lambda: send_attachment(sock, b"x", timeout=10.0))
    assert error.code == "timeout"
    assert sock.timeout == 0.91
    assert sock.sent


# A7


@pytest.mark.parametrize("data", [bytearray(b"x"), "x", memoryview(b"x"), b""])
def test_send_attachment_rejects_non_bytes_or_empty_payload_without_writing(data: object):
    reader, writer = socket_pair()
    try:
        error = assert_protocol_error(lambda: send_attachment(writer, data, timeout=0.2))
        assert error.code == "invalid_payload"
        reader.settimeout(0.05)
        with pytest.raises(socket.timeout):
            reader.recv(1)
    finally:
        reader.close()
        writer.close()


def test_send_attachment_rejects_oversize_payload_without_writing():
    reader, writer = socket_pair()
    try:
        data = b"x" * (MAX_ATTACHMENT_BYTES + 1)
        error = assert_protocol_error(lambda: send_attachment(writer, data, timeout=0.2))
        assert error.code == "oversize_frame"
        reader.settimeout(0.05)
        with pytest.raises(socket.timeout):
            reader.recv(1)
    finally:
        reader.close()
        writer.close()


# A8


def test_send_attachment_string_rejection_does_not_echo_the_payload():
    marker = "PRIVATE-STR-ATTACHMENT"
    reader, writer = socket_pair()
    try:
        assert_protocol_error(lambda: send_attachment(writer, marker, timeout=0.2), marker)
    finally:
        reader.close()
        writer.close()


def test_recv_attachment_mismatch_error_does_not_echo_the_body_marker():
    reader, writer = socket_pair()
    try:
        marker = "PRIVATE-MISMATCH-BODY"
        writer.sendall(struct.pack("!I", 5) + marker.encode("ascii"))
        assert_protocol_error(lambda: recv_attachment(reader, length=999, timeout=0.2), marker)
    finally:
        reader.close()
        writer.close()


def test_recv_attachment_truncated_body_does_not_echo_the_partial_marker():
    reader, writer = socket_pair()
    try:
        marker = "PRIVATE-PARTIAL-BODY"
        writer.sendall(struct.pack("!I", 40) + marker.encode("ascii"))
        writer.close()
        assert_protocol_error(lambda: recv_attachment(reader, length=40, timeout=0.2), marker)
    finally:
        reader.close()


# A9


def test_max_attachment_bytes_equals_the_manifest_limit_and_exceeds_the_frame_limit():
    from grafana_jsm_sandbox import forwarder_routes

    assert MAX_ATTACHMENT_BYTES == forwarder_routes.MAX_MANIFEST_BYTES
    assert MAX_ATTACHMENT_BYTES > MAX_FRAME_BYTES == 8192
