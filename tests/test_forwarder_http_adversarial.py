"""Independent complete-buffer attacks and local lease composition, without transport."""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
from hashlib import sha256

import pytest

from grafana_jsm_sandbox.forwarder_http import HTTPBoundaryError, parse_request
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES

TOKEN = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def request(service="jira", token=TOKEN, *, target="/rest/api/3/issue", body=b"{}"):
    profile = SERVICE_PROFILES[service]
    credential = ("Basic " + base64.b64encode(f"run:{token}".encode()).decode()
                  if profile.sentinel_scheme == "Basic" else f"Bearer {token}")
    return (f"POST {target} HTTP/1.1\r\nHost: {profile.server_name}:{profile.port}\r\n"
            f"Authorization: {credential}\r\nAccept: application/json\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "\r\n").encode() + body


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_every_truncated_prefix_is_rejected(service):
    complete = request(service)
    for length in range(len(complete)):
        with pytest.raises(HTTPBoundaryError):
            parse_request(complete[:length], service)
    assert parse_request(complete, service).body == b"{}"


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_base64url_pad_bits_have_one_canonical_spelling(service):
    for index, final in enumerate(ALPHABET):
        token = TOKEN[:-1] + final
        raw = request(service, token)
        if index % 4:
            with pytest.raises(HTTPBoundaryError):
                parse_request(raw, service)
        else:
            assert parse_request(raw, service).sentinel == token


@pytest.mark.parametrize("octet", [0, 9, 10, 11, 12, 13, 31, 127, 128, 255])
def test_controls_and_non_ascii_cannot_enter_structural_fields(octet):
    raw = request()
    for marker in (b"POST", b"/rest", b"Host", b"application/json"):
        malicious = raw.replace(marker, marker + bytes([octet]), 1)
        with pytest.raises(HTTPBoundaryError):
            parse_request(malicious, "jira")


@pytest.mark.parametrize("suffix", [b"\x00", b"\r\n", b"GET / HTTP/1.1\r\n\r\n"])
def test_trailing_bytes_never_form_a_second_request(suffix):
    with pytest.raises(HTTPBoundaryError):
        parse_request(request() + suffix, "jira")


def test_binary_body_is_preserved_and_not_parsed_as_headers():
    body = bytes(range(256)) + b"\r\n\r\nHost: evil\r\nGET / HTTP/1.1\r\n"
    parsed = parse_request(request(body=body), "jira")
    assert parsed.body == body  # JSON route validation is a separate step.
    assert not hasattr(parsed, "headers")
    assert TOKEN not in repr(parsed)
    assert "/rest/api/3/issue" not in repr(parsed)
    assert "Host: evil" not in repr(parsed)
    with pytest.raises(FrozenInstanceError):
        parsed.sentinel = "changed"


def test_decoded_query_delimiters_remain_inside_a_value():
    parsed = parse_request(
        request(target="/search?q=a%26admin%3Dtrue%2Bextra+text"), "jira",
        allowed_query_keys=frozenset({"q"}),
    )
    assert parsed.query == (("q", "a&admin=true+extra text"),)
    assert "admin=true" not in repr(parsed)


def test_newlines_inside_json_and_slashes_in_query_values_are_data():
    body = b'{\n  "message": "hello"\n}\n'
    parsed = parse_request(
        request(target="/search?q=https://example.invalid/path", body=body), "jira",
        allowed_query_keys=frozenset({"q"}),
    )
    assert parsed.body == body
    assert parsed.query == (("q", "https://example.invalid/path"),)


def test_very_long_decimal_length_fails_with_the_fixed_error():
    raw = request().replace(b"Content-Length: 2", b"Content-Length: " + b"9" * 8000)
    with pytest.raises(HTTPBoundaryError) as caught:
        parse_request(raw, "jira")
    assert caught.value.code == "invalid_request"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("target", [
    "/a%252fb", "/a%2fb", "/a%2Fb", "/a%5Cb", "/%2e%2e", "/a/../b",
    "/a/./b", "/a//b", "//evil/path", "/%61dmin", "/a%00b", "/a%C0%AFb",
    "/?q=a%0db", "/?q=a%0ab", "/?q=a%7fb", "/?q=%ff", "/?%71=a",
    "/?q=a&q=b", "/?q=a;admin=b", "/?q=a&&q=b", "/?q=a#fragment",
])
def test_path_and_query_alias_attacks(target):
    with pytest.raises(HTTPBoundaryError):
        parse_request(request(target=target), "jira", allowed_query_keys=frozenset({"q"}))


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_parsing_does_not_grant_or_restore_a_lease(service):
    registry = LeaseRegistry(clock=lambda: 1000.0)
    scope = sha256(b"local-test-scope").hexdigest()
    generation = registry.generation
    registry.handshake(receiver_boot_id="receiver", generation=generation)
    grant = registry.register(run_id="run", attempt_id="attempt", receiver_boot_id="receiver",
                              service=service, scope_digest=scope, expires_at=1010.0,
                              generation=generation)
    parsed = parse_request(request(service, grant.sentinel), service)

    def check(current=registry, selected=service, gen=generation, digest=scope):
        return current.check(service=selected, sentinel=parsed.sentinel,
                             generation=gen, scope_digest=digest).authorized

    assert check() is False
    registry.activate(lease_id=grant.lease_id, receiver_boot_id="receiver",
                      generation=generation, launch_at=1000.0)
    assert check() is True
    assert check(digest=sha256(b"wrong").hexdigest()) is False
    for other in SERVICE_PROFILES:
        if other != service:
            assert check(selected=other) is False
    restarted = LeaseRegistry(clock=lambda: 1000.0)
    assert check(current=restarted) is False
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id="receiver",
                    generation=generation, reason="cancelled")
    assert parse_request(request(service, grant.sentinel), service).sentinel == grant.sentinel
    assert check() is False


def test_error_surface_never_reports_caller_material():
    private = "private-synthetic-canary"
    raw = request(target="/" + private).replace(b"Authorization: Basic ",
                                               b"Authorization: " + private.encode())
    with pytest.raises(HTTPBoundaryError) as caught:
        parse_request(raw, "jira")
    assert private not in str(caught.value)
    assert private not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


@pytest.mark.parametrize("header", [
    b"Transfer-Encoding: chunked", b"Connection: close", b"Proxy-Authorization: secret",
    b"X-Forwarded-Host: evil", b"Forwarded: host=evil", b"Expect: 100-continue",
    b"TE: trailers", b"Trailer: digest", b"Upgrade: websocket", b"X-Api-Key: secret",
])
def test_forbidden_transport_and_credential_headers_are_rejected(header):
    raw = request().replace(b"\r\n\r\n", b"\r\n" + header + b"\r\n\r\n", 1)
    with pytest.raises(HTTPBoundaryError):
        parse_request(raw, "jira")


@pytest.mark.parametrize("length", [b"+2", b"02", b"-1", b"2, 2", b"2 2", b"2.0", b"0x2"])
def test_noncanonical_lengths_are_rejected(length):
    with pytest.raises(HTTPBoundaryError):
        parse_request(request().replace(b"Content-Length: 2", b"Content-Length: " + length),
                      "jira")


@pytest.mark.parametrize("method", [b"POST", b"PUT", b"PATCH", b"DELETE"])
def test_each_body_method_requires_length_and_media_type(method):
    raw = request().replace(b"POST ", method + b" ", 1)
    assert parse_request(raw, "jira").method == method.decode()
    for required in (b"Content-Length: 2\r\n", b"Content-Type: application/json\r\n"):
        with pytest.raises(HTTPBoundaryError):
            parse_request(raw.replace(required, b"", 1), "jira")


def test_get_can_explicitly_declare_zero_and_query_count_limit_is_exact():
    pairs = "&".join(f"q{i}=" for i in range(32))
    keys = frozenset(f"q{i}" for i in range(32))
    raw = request(target="/search?" + pairs, body=b"")
    raw = raw.replace(b"POST ", b"GET ", 1).replace(b"Content-Type: application/json\r\n", b"")
    parsed = parse_request(raw, "jira", allowed_query_keys=keys)
    assert len(parsed.query) == 32
    assert parsed.body == b""
    with pytest.raises(HTTPBoundaryError):
        parse_request(raw, "jira", allowed_query_keys=keys | {"q32"})
