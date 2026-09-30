"""Pure contract coverage for the bounded Forwarder HTTP response codec."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from grafana_jsm_sandbox.forwarder_http_response import (
    HTTPResponseError,
    ParsedResponse,
    parse_response,
    serialize_response,
)

MAX_BODY = 1_048_576
MAX_STATUS_LINE = 2_048
MAX_HEADERS = 16_384


def _response(status=200, *, reason="Upstream detail", body=b'{"ok":true}', headers=()):
    fields = list(headers)
    if status == 204:
        return f"HTTP/1.1 {status} {reason}\r\n\r\n".encode() + body
    if status == 205:
        fields.append(("Content-Length", "0"))
    else:
        fields.extend((("Content-Type", "application/json"), ("Content-Length", str(len(body)))))
    lines = [f"HTTP/1.1 {status} {reason}".encode()]
    lines.extend(f"{name}: {value}".encode() for name, value in fields)
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _reject(call):
    with pytest.raises(HTTPResponseError) as raised:
        call()
    assert raised.value.code == "invalid_response"
    assert str(raised.value) == "invalid response"


@pytest.mark.parametrize("status", [200, 201, 299, 400, 404, 599])
def test_accepted_body_statuses_parse_opaque_body_and_serialize_deterministically(status):
    body = b"\x00opaque\xff"
    parsed = parse_response(_response(status, reason="Secret upstream reason", body=body))

    assert parsed == ParsedResponse(status=status, body=body)
    assert "opaque" not in repr(parsed)
    serialized = serialize_response(parsed)
    assert serialized == (
        f"HTTP/1.1 {status} Response\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    assert b"Secret upstream reason" not in serialized


def test_private_and_upstream_headers_are_discarded_from_the_result_and_output():
    raw = _response(
        200,
        reason="Internal routing result",
        headers=(("Location", "https://elsewhere.invalid"), ("Set-Cookie", "secret=1"), ("X-Upstream", "trace")),
    )
    parsed = parse_response(raw)
    serialized = serialize_response(parsed)

    assert "Location" not in repr(parsed)
    assert b"Location" not in serialized
    assert b"Set-Cookie" not in serialized
    assert b"X-Upstream" not in serialized
    assert b"Internal routing result" not in serialized


def test_204_and_205_have_distinct_no_body_framing_and_roundtrip():
    no_content = parse_response(_response(204, reason="ignored", body=b""))
    reset = parse_response(_response(205, reason="ignored", body=b""))

    assert serialize_response(no_content) == b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    assert serialize_response(reset) == (
        b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )


def test_header_ows_and_connection_option_ows_are_normalized_before_validation():
    raw = (
        b"HTTP/1.1 200 Upstream\r\n"
        b"Content-Type:\t application/json \t\r\n"
        b"Content-Length: \t11\t\r\n"
        b"Connection: \tkeep-alive \t\r\n\r\n"
        b'{"ok":true}'
    )
    assert parse_response(raw) == ParsedResponse(200, b'{"ok":true}')


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.0 200 Nope\r\n\r\n",
        b"HTTP/1.1 200\r\n\r\n",
        b"HTTP/1.1 200  Double separator\r\n\r\n",
        b"HTTP/1.1 302 Redirect\r\n\r\n",
        b"HTTP/1.1 101 Upgrade\r\n\r\n",
        _response(200, headers=(("Transfer-Encoding", "chunked"),)),
        _response(200, headers=(("Connection", "Content-Length"),)),
        _response(200, headers=(("content-length", "1"),)),
        _response(200, headers=(("Content-Type", "text/plain"),)),
        _response(204, body=b"x"),
        _response(205, body=b"x"),
    ],
)
def test_rejects_unsupported_statuses_framing_and_duplicate_case_insensitive_headers(raw):
    _reject(lambda: parse_response(raw))


def test_exact_status_header_and_body_caps_accept_then_one_byte_overflows_reject():
    reason = "r" * (MAX_STATUS_LINE - len(b"HTTP/1.1 200 \r\n"))
    exact_status = _response(reason=reason)
    assert len(exact_status.split(b"\r\n", 1)[0]) + 2 == MAX_STATUS_LINE
    assert parse_response(exact_status).status == 200
    _reject(lambda: parse_response(_response(reason=reason + "r")))

    normal = _response()
    status_line, remainder = normal.split(b"\r\n", 1)
    original_headers, body = remainder.split(b"\r\n\r\n", 1)
    padding = MAX_HEADERS - len(original_headers) - len(b"\r\nX-Pad: \r\n\r\n")
    exact_headers = (
        status_line + b"\r\n" + original_headers + b"\r\nX-Pad: " + b"x" * padding
        + b"\r\n\r\n" + body
    )
    assert len(exact_headers.split(b"\r\n", 1)[1].split(body, 1)[0]) == MAX_HEADERS
    assert parse_response(exact_headers).status == 200
    _reject(lambda: parse_response(exact_headers.replace(b"X-Pad: ", b"X-Pad: x", 1)))

    body = b"x" * MAX_BODY
    maximum = _response(body=body)
    assert parse_response(maximum).body == body
    _reject(lambda: parse_response(_response(body=body + b"x")))


@pytest.mark.parametrize("value", [None, b"not a response", "text", 1])
def test_parser_requires_exact_bytes(value):
    _reject(lambda: parse_response(value))


def test_result_is_frozen_and_serializer_revalidates_hostile_constructor_bypass():
    parsed = ParsedResponse(200, b"x")
    with pytest.raises(FrozenInstanceError):
        parsed.status = 500
    for response in (
        object(),
        ParsedResponse(302, b"x"),
        ParsedResponse(200, b""),
        ParsedResponse(204, b"x"),
        ParsedResponse(205, b"x"),
    ):
        _reject(lambda response=response: serialize_response(response))

    hostile = object.__new__(ParsedResponse)
    object.__setattr__(hostile, "status", 200)
    object.__setattr__(hostile, "body", bytearray(b"x"))
    _reject(lambda: serialize_response(hostile))


@pytest.mark.parametrize("length", ["", "-1", "+1", "1,1", "01", "1048577", "999999999999"])
def test_content_length_requires_one_canonical_bounded_decimal(length):
    raw = _response().replace(b"Content-Length: 11", f"Content-Length: {length}".encode())
    _reject(lambda: parse_response(raw))


def test_field_count_boundary_accepts_64_and_rejects_65():
    accepted = _response(headers=tuple((f"X-{index}", "v") for index in range(62)))
    rejected = _response(headers=tuple((f"X-{index}", "v") for index in range(63)))
    assert parse_response(accepted).status == 200
    _reject(lambda: parse_response(rejected))


@pytest.mark.parametrize(
    "raw",
    [
        _response().replace(b"\r\n", b"\n", 1),
        _response().replace(b"Content-Type:", b"\tContent-Type:", 1),
        _response().replace(b"Content-Type", b"Cont\x80ent-Type", 1),
        _response().replace(b"Content-Type:", b"Content Type:", 1),
    ],
)
def test_rejects_bare_newlines_folding_nonascii_and_malformed_header_names(raw):
    _reject(lambda: parse_response(raw))


@pytest.mark.parametrize("header", ["Transfer-Encoding", "Trailer", "Content-Encoding", "Upgrade"])
def test_rejects_every_forbidden_streaming_or_upgrade_header(header):
    _reject(lambda: parse_response(_response(headers=((header, "value"),))))


def test_requires_exact_body_length_and_special_no_body_status_framing():
    raw = _response()
    _reject(lambda: parse_response(raw[:-1]))
    _reject(lambda: parse_response(raw + b"x"))
    _reject(lambda: parse_response(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
    _reject(lambda: parse_response(b"HTTP/1.1 205 Reset Content\r\n\r\n"))
    _reject(
        lambda: parse_response(
            b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\nContent-Type: application/json\r\n\r\n"
        )
    )


def test_parser_requires_exact_builtin_bytes_not_buffer_or_subclass():
    class BytesSubclass(bytes):
        pass

    raw = _response()
    for value in (bytearray(raw), memoryview(raw), BytesSubclass(raw)):
        _reject(lambda value=value: parse_response(value))
