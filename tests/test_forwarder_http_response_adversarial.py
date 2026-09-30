"""Independent response privacy and hostile-constructor regressions."""

from dataclasses import FrozenInstanceError

import pytest

from grafana_jsm_sandbox.forwarder_http_response import (
    HTTPResponseError,
    ParsedResponse,
    parse_response,
    serialize_response,
)

PRIVATE = b"private-upstream-value-should-not-survive"


def _response(*headers, reason=b"OK", status=b"200", body=b"{}"):
    return (b"HTTP/1.1 " + status + b" " + reason + b"\r\n"
            + b"\r\n".join(headers) + b"\r\n\r\n" + body)


def _json(*headers, **kwargs):
    body = kwargs.get("body", b"{}")
    return _response(b"Content-Type: application/json",
                     b"Content-Length: " + str(len(body)).encode(),
                     *headers, **kwargs)


@pytest.mark.parametrize("name", [
    b"Location", b"Set-Cookie", b"Authorization", b"Proxy-Authorization",
    b"X-Provider-Secret", b"Server", b"WWW-Authenticate",
])
def test_private_headers_and_reason_never_survive_projection(name):
    parsed = parse_response(_json(name + b": " + PRIVATE, reason=PRIVATE))
    serialized = serialize_response(parsed)
    assert PRIVATE not in serialized
    assert PRIVATE.decode() not in repr(parsed)
    assert name.lower() + b":" not in serialized.lower()
    assert parsed.body == b"{}"
    assert parse_response(serialized) == parsed


@pytest.mark.parametrize("value", [
    b"Content-Length", b"content-type", b"keep-alive, CONTENT-LENGTH",
    b"\tContent-Type\t", b'"content-length"', b"keep-alive,", b",close",
    b"close,,keep-alive", b"close;extension", b"",
])
def test_connection_cannot_hide_framing_or_malformed_options(value):
    with pytest.raises(HTTPResponseError):
        parse_response(_json(b"Connection: " + value))


@pytest.mark.parametrize("status,body", [
    (True, b"{}"), (200.0, b"{}"), ("200", b"{}"), (302, b"{}"),
    (199, b"{}"), (600, b"{}"), (204, b"body"), (205, b"body"),
    (200, b""), (200, bytearray(b"{}")), (200, memoryview(b"{}")),
    (200, b"x" * (1_048_576 + 1)),
])
def test_serializer_revalidates_public_value_instead_of_trusting_constructor(status, body):
    with pytest.raises(HTTPResponseError):
        # The validation may occur on construction or serialization.
        serialize_response(ParsedResponse(status=status, body=body))


def test_serializer_rejects_subclass_and_frozen_field_corruption():
    class Derived(ParsedResponse):
        pass

    with pytest.raises(HTTPResponseError):
        serialize_response(Derived(status=200, body=b"{}"))
    parsed = parse_response(_json())
    with pytest.raises(FrozenInstanceError):
        parsed.status = 302
    object.__setattr__(parsed, "status", 302)
    with pytest.raises(HTTPResponseError):
        serialize_response(parsed)


@pytest.mark.parametrize("operation", [
    lambda: parse_response(_json(b"Content-Length: " + PRIVATE)),
    lambda: parse_response(_json(b"Bad\x00Name: " + PRIVATE)),
    lambda: parse_response(_json(reason=PRIVATE + b"\x00")),
    lambda: parse_response(_json(status=b"302", reason=PRIVATE)),
])
def test_rejections_do_not_expose_upstream_details(operation):
    with pytest.raises(HTTPResponseError) as caught:
        operation()
    assert caught.value.code == "invalid_response"
    assert PRIVATE.decode() not in str(caught.value)
    assert PRIVATE.decode() not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


def test_opaque_body_is_preserved_without_claiming_json_semantics():
    opaque = b"\xff\x00not-json\r\n\r\nHTTP/1.1 302 Fake\r\n"
    parsed = parse_response(_json(body=opaque))
    assert parsed.body == opaque
    assert parse_response(serialize_response(parsed)).body == opaque
    assert "not-json" not in repr(parsed)


@pytest.mark.parametrize("fields", [{}, {"status": 200}, {"body": b"{}"}])
def test_serializer_rejects_incomplete_constructor_bypassed_values(fields):
    response = object.__new__(ParsedResponse)
    for name, value in fields.items():
        object.__setattr__(response, name, value)
    with pytest.raises(HTTPResponseError) as caught:
        serialize_response(response)
    assert caught.value.code == "invalid_response"


def test_connection_option_whitespace_is_validated_per_token_and_stripped():
    parsed = parse_response(_json(b"Connection: \tclose,\t keep-alive \t"))
    assert b"keep-alive" not in serialize_response(parsed)
    with pytest.raises(HTTPResponseError):
        parse_response(_json(b"Connection: clo\tse"))
