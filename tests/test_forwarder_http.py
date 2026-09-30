"""Pure complete-buffer Forwarder HTTP boundary contract tests."""

from __future__ import annotations

import base64

import pytest

from grafana_jsm_sandbox.forwarder_http import HTTPBoundaryError, parse_request
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES

TOKEN = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
MAX_REQUEST_LINE = 2_048
MAX_HEADERS = 16_384
MAX_BODY = 262_144


def _authorization(service, token=TOKEN):
    if service in {"jira", "confluence"}:
        credentials = base64.b64encode(f"run:{token}".encode("ascii")).decode("ascii")
        return f"Basic {credentials}"
    return f"Bearer {token}"


def _request(service="jira", *, method="GET", target="/v1/items", body=b"", headers=()):
    profile = SERVICE_PROFILES[service]
    fields = [
        ("Host", f"{profile.server_name}:{profile.port}"),
        ("Authorization", _authorization(service)),
        ("Accept", "application/json"),
    ]
    if method != "GET":
        fields.extend((("Content-Type", "application/json"), ("Content-Length", str(len(body)))))
    fields.extend(headers)
    encoded = [f"{method} {target} HTTP/1.1".encode("ascii")]
    encoded.extend(f"{name}: {value}".encode("ascii") for name, value in fields)
    return b"\r\n".join(encoded) + b"\r\n\r\n" + body


def _replace_header(request, name, value):
    prefix = name.encode("ascii") + b": "
    lines, body = request.split(b"\r\n\r\n", 1)
    replaced = [prefix + value.encode("ascii") if line.startswith(prefix) else line
                for line in lines.split(b"\r\n")]
    return b"\r\n".join(replaced) + b"\r\n\r\n" + body


def _reject(data, service="jira", **kwargs):
    with pytest.raises(HTTPBoundaryError) as raised:
        parse_request(data, service, **kwargs)
    assert raised.value.code
    assert str(raised.value) == "invalid request"


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_each_service_parses_its_fixed_profile_with_redacted_result(service):
    parsed = parse_request(_request(service), service)

    assert (parsed.service, parsed.method, parsed.path, parsed.query, parsed.accept) == (
        service, "GET", "/v1/items", (), "application/json"
    )
    assert parsed.body == b""
    assert parsed.sentinel == TOKEN
    representation = repr(parsed)
    for secret in (TOKEN, "/v1/items", "body"):
        assert secret not in representation


@pytest.mark.parametrize("service", ["jira", "confluence"])
def test_basic_sentinel_requires_canonical_run_credentials(service):
    canonical = _request(service)
    assert parse_request(canonical, service).sentinel == TOKEN
    for replacement in (
        "Basic " + base64.b64encode(f"other:{TOKEN}".encode()).decode(),
        "Basic " + base64.b64encode(f"run:{TOKEN}".encode()).decode() + "=",
        "Basic not!base64",
    ):
        _reject(_replace_header(_request(service), "Authorization", replacement), service)


@pytest.mark.parametrize("service", ["grafana", "kubernetes", "anthropic"])
def test_bearer_sentinel_requires_exact_canonical_base64url_token(service):
    assert parse_request(_request(service), service).sentinel == TOKEN
    for replacement in (f"Bearer {TOKEN}=", f"Bearer {TOKEN[:-1]}+", f"bearer {TOKEN}"):
        _reject(_replace_header(_request(service), "Authorization", replacement), service)


def test_complete_bodyless_and_json_body_framing():
    assert parse_request(_request("jira", target="/ready"), "jira").body == b""
    body = b'{"state":"open"}'
    parsed = parse_request(_request("grafana", method="POST", body=body), "grafana")
    assert parsed.body == body
    _reject(_request("jira", target="/ready", body=b"x"))
    _reject(_request("jira", method="POST", body=body) + b"pipelined")


@pytest.mark.parametrize(
    "mutator",
    [
        lambda request: request.replace(b"Host:", b"Host :", 1),
        lambda request: request.replace(b"Accept: application/json", b"Accept:  application/json", 1),
        lambda request: request.replace(b"\r\nAccept:", b"\nAccept:", 1),
        lambda request: request.replace(b"\r\n\r\n", b"\r\nX-Smuggled: yes\r\n\r\n", 1),
        lambda request: request.replace(b"\r\nAccept:", b"\r\nhOsT: wrong\r\nAccept:", 1),
    ],
)
def test_rejects_header_smuggling_and_duplicate_case_insensitive_headers(mutator):
    _reject(mutator(_request()))


@pytest.mark.parametrize("target", ["//double", "/one/../two", "/a%2Fb", "/a%2eb", "/a%7E", "/a\\b", "/a#x"])
def test_rejects_ambiguous_or_unsafe_targets(target):
    _reject(_request(target=target))


def test_query_requires_exact_trusted_configuration_and_preserves_decoded_values():
    parsed = parse_request(
        _request(target="/search?limit=10&owner=Jane+Doe"),
        "jira",
        allowed_query_keys=frozenset({"limit", "owner"}),
    )
    assert parsed.query == (("limit", "10"), ("owner", "Jane Doe"))
    for target in ("/search?limit=1&limit=2", "/search?unknown=1", "/search?limit", "/search?limit=1;other=2"):
        _reject(_request(target=target), allowed_query_keys=frozenset({"limit"}))
    for config in (set(), frozenset({"bad key"}), frozenset({"x" * 129}), frozenset(range(1))):
        _reject(_request(), allowed_query_keys=config)


def test_profile_and_accept_are_fixed_and_anthropic_streaming_requires_explicit_expectation():
    wrong_host = _replace_header(_request(), "Host", "forwarder-other.maoi.local:1")
    _reject(wrong_host)
    _reject(_request(), accept="text/event-stream")
    streaming = _replace_header(_request("anthropic"), "Accept", "text/event-stream")
    parsed = parse_request(streaming, "anthropic", accept="text/event-stream")
    assert parsed.accept == "text/event-stream"
    _reject(streaming, "anthropic")


def test_request_line_header_and_body_limits_are_inclusive_then_fail_closed():
    exact_target = "/" + "a" * (MAX_REQUEST_LINE - len(b"GET  HTTP/1.1\r\n") - 1)
    assert len(_request(target=exact_target).split(b"\r\n", 1)[0]) + 2 == MAX_REQUEST_LINE
    assert parse_request(_request(target=exact_target), "jira").path == exact_target
    _reject(_request(target=exact_target + "a"))

    normal = _request()
    header_section = normal.split(b"\r\n", 1)[1]
    padding = MAX_HEADERS - len(header_section) - len(b"User-Agent: \r\n")
    exact_headers = normal[:-2] + b"User-Agent: " + b"x" * padding + b"\r\n\r\n"
    assert len(exact_headers.split(b"\r\n", 1)[1]) == MAX_HEADERS
    assert parse_request(exact_headers, "jira").method == "GET"
    _reject(exact_headers[:-2] + b"x\r\n\r\n")

    body = b"x" * MAX_BODY
    assert parse_request(_request("jira", method="POST", body=body), "jira").body == body
    _reject(_request("jira", method="POST", body=body + b"x"))


@pytest.mark.parametrize("data,service", [("GET / HTTP/1.1\r\n", "jira"), (b"GET / HTTP/1.1\r\n", None)])
def test_requires_exact_bytes_and_known_service(data, service):
    _reject(data, service)
