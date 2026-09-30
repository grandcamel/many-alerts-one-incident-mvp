"""Public complete-head contract and equivalence to existing full request parsing."""

from dataclasses import FrozenInstanceError

import pytest

from grafana_jsm_sandbox.forwarder_http import (
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    MAX_REQUEST_LINE_BYTES,
    HTTPBoundaryError,
    parse_request,
    parse_request_head,
)
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from tests.test_forwarder_http_receive import TOKEN, _request


@pytest.mark.parametrize("service", tuple(SERVICE_PROFILES))
def test_head_and_complete_parser_share_structural_results(service):
    body = b'{\n "value": "opaque"\n}'
    wire = _request(service, method="POST", body=body)
    head_bytes = wire[:wire.index(b"\r\n\r\n") + 4]
    head = parse_request_head(head_bytes, service)
    complete = parse_request(wire, service)
    for field in ("service", "method", "path", "query", "accept", "sentinel"):
        assert getattr(head, field) == getattr(complete, field)
    assert head.body_length == len(body)
    assert not hasattr(head, "body")
    assert TOKEN not in repr(head) and "/items" not in repr(head)
    with pytest.raises(FrozenInstanceError):
        head.body_length = 0
    with pytest.raises(HTTPBoundaryError):
        parse_request_head(wire, service)


def test_maximum_body_declaration_needs_no_dummy_body():
    head = _request(method="POST").replace(b"Content-Length: 0", b"Content-Length: 262144")
    result = parse_request_head(head, "jira")
    assert result.body_length == MAX_BODY_BYTES
    with pytest.raises(HTTPBoundaryError):
        parse_request(head, "jira")
    with pytest.raises(HTTPBoundaryError):
        parse_request_head(head.replace(b"262144", b"262145"), "jira")


def test_head_line_and_header_byte_limits_are_independent():
    target = "/" + "a" * (MAX_REQUEST_LINE_BYTES - len(b"GET  HTTP/1.1\r\n") - 1)
    wire = _request(target=target)
    assert parse_request_head(wire, "jira").path == target
    with pytest.raises(HTTPBoundaryError):
        parse_request_head(_request(target=target + "a"), "jira")

    header_length = len(wire.split(b"\r\n", 1)[1])
    padding = MAX_HEADER_BYTES - header_length - len(b"User-Agent: \r\n")
    boundary = wire[:-2] + b"User-Agent: " + b"x" * padding + b"\r\n\r\n"
    assert len(boundary) == MAX_REQUEST_LINE_BYTES + MAX_HEADER_BYTES
    assert parse_request_head(boundary, "jira").body_length == 0
    with pytest.raises(HTTPBoundaryError):
        parse_request_head(boundary[:-4] + b"x\r\n\r\n", "jira")


def test_head_rejects_every_truncated_prefix_and_extra_bytes():
    head = _request()
    for length in range(len(head)):
        with pytest.raises(HTTPBoundaryError):
            parse_request_head(head[:length], "jira")
    for extra in (b"\x00", b"\r\n", head):
        with pytest.raises(HTTPBoundaryError):
            parse_request_head(head + extra, "jira")


@pytest.mark.parametrize("data", ["", None, bytearray(b"GET"), memoryview(b"GET")])
def test_head_requires_exact_bytes(data):
    with pytest.raises(HTTPBoundaryError):
        parse_request_head(data, "jira")
