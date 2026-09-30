"""Narrow, complete-buffer HTTP/1.1 response parsing and serialization."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_STATUS_LINE_BYTES = 2_048
MAX_HEADER_BYTES = 16_384
MAX_BODY_BYTES = 1_048_576
_MAX_STATUS_LINE = MAX_STATUS_LINE_BYTES
_MAX_HEADERS = MAX_HEADER_BYTES
_MAX_BODY = MAX_BODY_BYTES
_MAX_INPUT = _MAX_STATUS_LINE + _MAX_HEADERS + _MAX_BODY
_MAX_FIELDS = 64
_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789"
                   b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_CANONICAL_LENGTH = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_FORBIDDEN_HEADERS = frozenset({"transfer-encoding", "trailer", "content-encoding", "upgrade"})


class HTTPResponseError(ValueError):
    """The response codec's fixed, non-diagnostic rejection."""

    def __init__(self) -> None:
        self.code = "invalid_response"
        super().__init__("invalid response")


@dataclass(frozen=True)
class ParsedResponse:
    """A bounded response structure, not an upstream-success attestation."""

    status: int
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class ParsedResponseHead:
    """Validated complete response head with a declared body length only."""

    status: int
    body_length: int


def _fail() -> None:
    raise HTTPResponseError() from None


def _ascii(value: bytes) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        _fail()


def _valid_status(status: object) -> bool:
    return type(status) is int and (200 <= status <= 299 or 400 <= status <= 599)


def _parse_status_line(data: bytes) -> tuple[int, int]:
    end = data.find(b"\r\n")
    if end < 0 or end + 2 > _MAX_STATUS_LINE:
        _fail()
    pieces = data[:end].split(b" ", 2)
    if len(pieces) != 3 or pieces[0] != b"HTTP/1.1" or len(pieces[1]) != 3:
        _fail()
    if not pieces[1].isdigit() or not pieces[2] or pieces[2].startswith(b" "):
        _fail()
    if any(character < 0x20 or character > 0x7e for character in pieces[2]):
        _fail()
    status = int(pieces[1])
    if not _valid_status(status):
        _fail()
    return status, end + 2


def _parse_headers(data: bytes, start: int) -> tuple[dict[str, str], int]:
    if data[start:start + 2] == b"\r\n":
        return {}, start + 2
    end = data.find(b"\r\n\r\n", start)
    if end < 0 or end + 4 - start > _MAX_HEADERS:
        _fail()
    lines = () if end == start else tuple(data[start:end].split(b"\r\n"))
    if len(lines) > _MAX_FIELDS:
        _fail()
    headers: dict[str, str] = {}
    for line in lines:
        colon = line.find(b":")
        if colon <= 0 or line[:colon][-1:] in (b" ", b"\t"):
            _fail()
        name = line[:colon]
        value = line[colon + 1:]
        if any(character not in _TOKEN for character in name):
            _fail()
        if any((character < 0x20 and character != ord("\t"))
               or character == 0x7f or character > 0x7e
               for character in value):
            _fail()
        lowered = _ascii(name).lower()
        if lowered in headers or lowered in _FORBIDDEN_HEADERS:
            _fail()
        normalized = _ascii(value).strip(" \t")
        if "\t" in normalized and lowered != "connection":
            _fail()
        headers[lowered] = normalized
    connection = headers.get("connection")
    if connection is not None:
        tokens = tuple(token.strip(" \t") for token in connection.split(","))
        if any(
            not token
            or any(character not in _TOKEN for character in token.encode("ascii"))
            for token in tokens
        ):
            _fail()
        if {token.lower() for token in tokens} & {"content-length", "content-type"}:
            _fail()
    return headers, end + 4


def _body_length(status: int, headers: dict[str, str]) -> int:
    if status == 204:
        if "content-length" in headers or "content-type" in headers:
            _fail()
        return 0
    if status == 205:
        if headers.get("content-length") != "0" or "content-type" in headers:
            _fail()
        return 0
    length = headers.get("content-length")
    if (
        length is None
        or len(length) > len(str(_MAX_BODY))
        or not _CANONICAL_LENGTH.fullmatch(length)
        or headers.get("content-type") != "application/json"
    ):
        _fail()
    try:
        declared = int(length)
    except ValueError:
        _fail()
    if declared > _MAX_BODY or not declared:
        _fail()
    return declared


def parse_response_head(data: bytes) -> ParsedResponseHead:
    """Validate exactly one complete status and header region without a body."""
    if type(data) is not bytes or len(data) > _MAX_STATUS_LINE + _MAX_HEADERS:
        _fail()
    status, header_start = _parse_status_line(data)
    headers, body_start = _parse_headers(data, header_start)
    if body_start != len(data):
        _fail()
    remainder = data.replace(b"\r\n", b"")
    if b"\r" in remainder or b"\n" in remainder:
        _fail()
    return ParsedResponseHead(status=status, body_length=_body_length(status, headers))


def parse_response(data: bytes) -> ParsedResponse:
    """Parse one complete bounded response, discarding all upstream metadata."""
    if type(data) is not bytes or len(data) > _MAX_INPUT:
        _fail()
    status_end = data.find(b"\r\n")
    if status_end < 0:
        _fail()
    if data[status_end + 2:status_end + 4] == b"\r\n":
        body_start = status_end + 4
    else:
        header_end = data.find(b"\r\n\r\n", status_end + 2)
        if header_end < 0:
            _fail()
        body_start = header_end + 4
    head = parse_response_head(data[:body_start])
    body = data[body_start:]
    if len(body) > _MAX_BODY or len(body) != head.body_length:
        _fail()
    return ParsedResponse(status=head.status, body=body)


def serialize_response(response: ParsedResponse) -> bytes:
    """Serialize only deterministic, sanitized response metadata."""
    if type(response) is not ParsedResponse:
        _fail()
    try:
        status = response.status
        body = response.body
    except AttributeError:
        _fail()
    if not _valid_status(status) or type(body) is not bytes or len(body) > _MAX_BODY:
        _fail()
    if status == 204:
        if body:
            _fail()
        return b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    if status == 205:
        if body:
            _fail()
        return b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    if not body:
        _fail()
    prefix = (
        f"HTTP/1.1 {status} Response\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return prefix + body
