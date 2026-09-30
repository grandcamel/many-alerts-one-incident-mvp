"""Deliberately narrow complete-buffer HTTP/1.1 request validation.

This is not a general RFC HTTP parser and does not authorize a route, lease, or
dispatch.  Its small accepted profile is intentional: a future transport must
close after one complete request and apply route policy separately.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from .forwarder_services import SERVICE_PROFILES

MAX_REQUEST_LINE_BYTES = 2_048
MAX_HEADER_BYTES = 16_384
MAX_BODY_BYTES = 262_144
_MAX_REQUEST_LINE = MAX_REQUEST_LINE_BYTES
_MAX_HEADERS = MAX_HEADER_BYTES
_MAX_BODY = MAX_BODY_BYTES
_MAX_INPUT = _MAX_REQUEST_LINE + _MAX_HEADERS + _MAX_BODY
_MAX_HEADER_FIELDS = 64
_MAX_QUERY_PAIRS = 32
_MAX_QUERY_KEYS = 32
_MAX_QUERY_KEY_LENGTH = 128
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_ALLOWED_HEADERS = frozenset({
    "host", "authorization", "content-length", "content-type", "accept",
    "user-agent",
})
_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789"
                   b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_UNRESERVED = frozenset(b"-._~0123456789"
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_PCHAR = _UNRESERVED | frozenset(b"!$&'()*+,;=:@%")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_CANONICAL_LENGTH = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_HEX = frozenset(b"0123456789ABCDEFabcdef")


class HTTPBoundaryError(ValueError):
    """The HTTP boundary's deliberately non-diagnostic rejection."""

    def __init__(self) -> None:
        self.code = "invalid_request"
        super().__init__("invalid request")


@dataclass(frozen=True)
class ParsedRequest:
    """Validated request structure; it is not a route-authorization result."""

    service: str
    method: str
    path: str = field(repr=False)
    query: tuple[tuple[str, str], ...] = field(repr=False)
    accept: str
    body: bytes = field(repr=False)
    sentinel: str = field(repr=False)


@dataclass(frozen=True)
class ParsedRequestHead:
    """Validated complete HTTP head with a declared body length only."""

    service: str
    method: str
    path: str = field(repr=False)
    query: tuple[tuple[str, str], ...] = field(repr=False)
    accept: str
    sentinel: str = field(repr=False)
    body_length: int


def _fail() -> None:
    raise HTTPBoundaryError() from None


def _ascii(value: bytes) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        _fail()


def _is_unreserved_name(value: str) -> bool:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return bool(encoded) and all(character in _UNRESERVED for character in encoded)


def _validate_configuration(service: object, allowed_query_keys: object,
                            accept: object) -> tuple[str, frozenset[str], str]:
    if type(service) is not str or service not in SERVICE_PROFILES:
        _fail()
    if type(allowed_query_keys) is not frozenset or len(allowed_query_keys) > _MAX_QUERY_KEYS:
        _fail()
    if any(
        type(key) is not str
        or len(key) > _MAX_QUERY_KEY_LENGTH
        or not _is_unreserved_name(key)
        for key in allowed_query_keys
    ):
        _fail()
    if type(accept) is not str:
        _fail()
    if accept != "application/json" and not (
        service == "anthropic" and accept == "text/event-stream"
    ):
        _fail()
    return service, allowed_query_keys, accept


def _reject_bad_newlines(data: bytes) -> None:
    remainder = data.replace(b"\r\n", b"")
    if b"\r" in remainder or b"\n" in remainder:
        _fail()


def _parse_request_line(data: bytes) -> tuple[str, bytes, int]:
    end = data.find(b"\r\n")
    if end < 0 or end + 2 > _MAX_REQUEST_LINE:
        _fail()
    parts = data[:end].split(b" ")
    if len(parts) != 3 or any(not part for part in parts):
        _fail()
    method_bytes, target, version = parts
    if version != b"HTTP/1.1":
        _fail()
    method = _ascii(method_bytes)
    if method not in _METHODS:
        _fail()
    return method, target, end + 2


def _parse_headers(data: bytes, start: int) -> tuple[dict[str, str], int]:
    end = data.find(b"\r\n\r\n", start)
    if end < 0 or end + 4 - start > _MAX_HEADERS:
        _fail()
    block = data[start:end]
    lines = () if not block else tuple(block.split(b"\r\n"))
    if len(lines) > _MAX_HEADER_FIELDS:
        _fail()
    headers: dict[str, str] = {}
    for line in lines:
        colon = line.find(b":")
        if colon <= 0 or line[:colon][-1:] in (b" ", b"\t"):
            _fail()
        name = line[:colon]
        value = line[colon + 1:]
        if (
            any(character not in _TOKEN for character in name)
            or not value.startswith(b" ")
            or value.startswith((b"  ", b" \t"))
            or value.endswith((b" ", b"\t"))
        ):
            _fail()
        value = value[1:]
        if any(character < 0x20 or character == 0x7f or character > 0x7e
               for character in value):
            _fail()
        lowered = _ascii(name).lower()
        if lowered in headers or lowered not in _ALLOWED_HEADERS:
            _fail()
        headers[lowered] = _ascii(value)
    return headers, end + 4


def _validate_sentinel(service: str, authorization: str) -> str:
    if service in {"jira", "confluence"}:
        if not authorization.startswith("Basic "):
            _fail()
        encoded = authorization[6:]
        if not encoded:
            _fail()
        try:
            decoded = base64.b64decode(encoded, validate=True)
            canonical = base64.b64encode(decoded).decode("ascii")
            text = decoded.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            _fail()
        if canonical != encoded or not text.startswith("run:"):
            _fail()
        sentinel = text[4:]
    else:
        if not authorization.startswith("Bearer "):
            _fail()
        sentinel = authorization[7:]
    if not _BASE64URL.fullmatch(sentinel):
        _fail()
    try:
        decoded_sentinel = base64.urlsafe_b64decode(sentinel + "=")
        canonical_sentinel = base64.urlsafe_b64encode(decoded_sentinel).decode("ascii")
    except ValueError:
        _fail()
    if len(decoded_sentinel) != 32 or canonical_sentinel.rstrip("=") != sentinel:
        _fail()
    return sentinel


def _decode_percent(value: bytes) -> str:
    decoded = bytearray()
    index = 0
    while index < len(value):
        character = value[index]
        if character == ord("%"):
            if index + 2 >= len(value):
                _fail()
            escaped = value[index + 1:index + 3]
            if any(digit not in _HEX for digit in escaped):
                _fail()
            byte = int(escaped, 16)
            decoded.append(byte)
            index += 3
        else:
            decoded.append(character)
            index += 1
    if any(character > 0x7e or character < 0x20 or character == 0x7f
           for character in decoded):
        _fail()
    return _ascii(bytes(decoded))


def _parse_path(target: bytes) -> tuple[str, bytes | None]:
    path, separator, query = target.partition(b"?")
    if (
        not path.startswith(b"/")
        or b"//" in path
        or any(character < 0x20 or character == 0x7f or character > 0x7e
               for character in target)
        or b"#" in target
        or b"\\" in target
    ):
        _fail()
    if separator and not query:
        _fail()
    if b"?" in query:
        _fail()
    if any(character not in _PCHAR and character != ord("/") for character in path):
        _fail()
    index = 0
    while index < len(path):
        if path[index] != ord("%"):
            index += 1
            continue
        if index + 2 >= len(path):
            _fail()
        escaped = path[index + 1:index + 3]
        if any(digit not in _HEX for digit in escaped):
            _fail()
        byte = int(escaped, 16)
        if (
            byte in _UNRESERVED
            or byte in {ord("/"), ord("\\"), ord("."), ord("%")}
            or byte < 0x20
            or byte == 0x7f
            or byte > 0x7e
        ):
            _fail()
        index += 3
    if any(segment in (b".", b"..") for segment in path.split(b"/")):
        _fail()
    return _ascii(path), query if separator else None


def _parse_query(query: bytes | None,
                 allowed_query_keys: frozenset[str]) -> tuple[tuple[str, str], ...]:
    if query is None:
        return ()
    if b";" in query:
        _fail()
    parts = query.split(b"&")
    if len(parts) > _MAX_QUERY_PAIRS or any(not part for part in parts):
        _fail()
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for part in parts:
        key, equals, raw_value = part.partition(b"=")
        if not equals or not key or any(character not in _UNRESERVED for character in key):
            _fail()
        text_key = _ascii(key)
        if text_key not in allowed_query_keys or text_key in seen:
            _fail()
        seen.add(text_key)
        result.append((text_key, _decode_percent(raw_value.replace(b"+", b" "))))
    return tuple(result)


def _validate_head_framing(method: str, headers: dict[str, str], service: str,
                           accept: str) -> tuple[str, int]:
    required = {"host", "authorization", "accept"}
    if not required.issubset(headers):
        _fail()
    profile = SERVICE_PROFILES[service]
    if headers["host"] != f"{profile.server_name}:{profile.port}" or headers["accept"] != accept:
        _fail()
    if method == "GET":
        if "content-type" in headers:
            _fail()
        length = headers.get("content-length")
        if length is not None and length != "0":
            _fail()
        body_length = 0
    else:
        if headers.get("content-type") != "application/json":
            _fail()
        length = headers.get("content-length")
        if (
            length is None
            or len(length) > len(str(_MAX_BODY))
            or not _CANONICAL_LENGTH.fullmatch(length)
        ):
            _fail()
        try:
            declared_length = int(length)
        except ValueError:
            _fail()
        if declared_length > _MAX_BODY:
            _fail()
        body_length = declared_length
    return _validate_sentinel(service, headers["authorization"]), body_length


def parse_request_head(data: bytes, service: str, *,
                       allowed_query_keys: frozenset[str] = frozenset(),
                       accept: str = "application/json") -> ParsedRequestHead:
    """Validate exactly one complete request line and header section, no body."""
    if type(data) is not bytes or len(data) > _MAX_REQUEST_LINE + _MAX_HEADERS:
        _fail()
    service, keys, expected_accept = _validate_configuration(service, allowed_query_keys, accept)
    method, target, header_start = _parse_request_line(data)
    headers, body_start = _parse_headers(data, header_start)
    if body_start != len(data):
        _fail()
    _reject_bad_newlines(data)
    sentinel, body_length = _validate_head_framing(method, headers, service, expected_accept)
    path, query = _parse_path(target)
    return ParsedRequestHead(
        service=service,
        method=method,
        path=path,
        query=_parse_query(query, keys),
        accept=expected_accept,
        sentinel=sentinel,
        body_length=body_length,
    )


def parse_request(data: bytes, service: str, *,
                  allowed_query_keys: frozenset[str] = frozenset(),
                  accept: str = "application/json") -> ParsedRequest:
    """Validate one complete request in the Forwarder's intentionally narrow profile."""
    if type(data) is not bytes or len(data) > _MAX_INPUT:
        _fail()
    line_end = data.find(b"\r\n")
    if line_end < 0:
        _fail()
    header_end = data.find(b"\r\n\r\n", line_end + 2)
    if header_end < 0:
        _fail()
    body_start = header_end + 4
    head = parse_request_head(
        data[:body_start],
        service,
        allowed_query_keys=allowed_query_keys,
        accept=accept,
    )
    body = data[body_start:]
    if len(body) > _MAX_BODY or len(body) != head.body_length:
        _fail()
    return ParsedRequest(
        service=head.service,
        method=head.method,
        path=head.path,
        query=head.query,
        accept=head.accept,
        body=body,
        sentinel=head.sentinel,
    )
