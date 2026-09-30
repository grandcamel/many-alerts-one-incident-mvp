"""Strict, bounded JSON parsing and one pinned canonical encoding.

No I/O, clock or authority: this module only transforms bytes a caller
already holds. It has no notion of a route, lease, manifest or credential.

Error discipline (load-bearing). ``raise X from None`` clears ``__cause__``
but not ``__context__``: Python still attaches whatever exception was active
in a handler, and that chained exception (a ``JSONDecodeError``'s ``.doc``, a
``UnicodeDecodeError``'s ``.object``) can carry the full caller input. So
every ``except`` block here only assigns a local ``code`` variable; once the
``try`` statement ends, a fresh ``JSONPolicyError`` is raised with
``from None``, never an exception object created inside a handler. No
exception this module raises has a non-``None`` ``__cause__``/``__context__``,
or an attribute other than ``.code`` holding caller data.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re

MAX_JSON_DEPTH = 16
MAX_JSON_ARRAY_ITEMS = 256
MAX_JSON_STRING_BYTES = 16_384
MAX_SAFE_INTEGER = 2**53 - 1
# A local lexeme bound, so int()/float() never see a huge caller-chosen token.
MAX_JSON_NUMBER_CHARS = 32
MAX_JSON_DOCUMENT_BYTES = 1_048_576

JSON_ERROR_CODES = frozenset({
    "json_argument", "json_too_large", "json_encoding", "json_syntax",
    "json_unicode", "json_duplicate_key", "json_depth", "json_array_too_long",
    "json_string_too_long", "json_number", "json_type",
})

_BOM = b"\xef\xbb\xbf"
_STRUCTURAL = re.compile(r'["\\\[\]{}]')
_BAD_CHARACTERS = re.compile("[\x00\ud800-\udfff]")
_TAG_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")


class JSONPolicyError(ValueError):
    """A fixed, non-diagnostic JSON policy rejection; never embeds caller data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise JSONPolicyError(code) from None


@dataclasses.dataclass(frozen=True)
class JSONDecimal:
    """A validated RFC 8259 non-integer lexeme, held as text (finite mode only).

    Never converted to ``float``, so a lexeme with no exact float
    representation is preserved exactly as received.
    """

    text: str


def _check_string(value: str, *, ascii_only: bool, too_long_code: str) -> None:
    if _BAD_CHARACTERS.search(value):
        _fail("json_unicode")
    if ascii_only and any(character < "\x20" or character > "\x7e" for character in value):
        _fail("json_unicode")
    if len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
        _fail(too_long_code)


def _encode_string(value: str) -> bytes:
    # json.dumps(ensure_ascii=False) is pinned by known-answer tests to match
    # the required escaping exactly, leaving '/', U+007F and U+2028 literal.
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def _prescan_depth(text: str) -> None:
    """Bound nesting depth before ``json.loads`` runs, so a pathological depth
    never reaches Python's recursion limit; the post-walk re-checks depth
    authoritatively. An escape-aware scan over structural characters only;
    malformed input is left for ``json.loads`` to reject.
    """
    depth = 0
    in_string = False
    pos = 0
    length = len(text)
    while pos < length:
        match = _STRUCTURAL.search(text, pos)
        if match is None:
            return
        character = match.group()
        pos = match.end()
        if in_string:
            if character == "\\":
                pos += 1  # the escaped character is consumed, whatever it is
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail("json_depth")
        elif character in "]}":
            depth -= 1


def _postwalk(root: object, *, ascii_only: bool) -> object:
    """Rebuild the parsed document, authoritatively checking depth (root
    container is depth 1), array length, key/string content and
    ``ascii_only``. An iterative walk with an explicit stack, so this also
    catches any prescan bug directly rather than trusting the linear pass.
    """
    work: list = [("value", root, 1)]
    results: list = []
    while work:
        item = work.pop()
        if item[0] == "value":
            _, value, depth = item
            kind = type(value)
            if kind is dict:
                if depth > MAX_JSON_DEPTH:
                    _fail("json_depth")
                keys = list(value.keys())
                for key in keys:
                    _check_string(key, ascii_only=ascii_only, too_long_code="json_string_too_long")
                work.append(("dict", keys))
                for key in reversed(keys):
                    work.append(("value", value[key], depth + 1))
            elif kind is list:
                if depth > MAX_JSON_DEPTH:
                    _fail("json_depth")
                if len(value) > MAX_JSON_ARRAY_ITEMS:
                    _fail("json_array_too_long")
                work.append(("list", len(value)))
                for element in reversed(value):
                    work.append(("value", element, depth + 1))
            elif kind is str:
                _check_string(value, ascii_only=ascii_only, too_long_code="json_string_too_long")
                results.append(value)
            elif value is None:
                results.append(None)
            elif kind is bool or kind is int or kind is JSONDecimal:
                results.append(value)
            else:
                _fail("json_type")
        elif item[0] == "dict":
            _, keys = item
            count = len(keys)
            values = results[len(results) - count:] if count else []
            if count:
                del results[len(results) - count:]
            results.append(dict(zip(keys, values)))
        else:  # "list"
            _, count = item
            values = results[len(results) - count:] if count else []
            if count:
                del results[len(results) - count:]
            results.append(tuple(values))
    return results[0]


def parse_json(
    data: object, *, max_bytes: object, numbers: str = "integer", ascii_only: bool = False,
) -> object:
    """Parse one bounded, strict JSON document into safe Python values.

    Returns ``dict``/``tuple``/``str``/``int``/``bool``/``None`` (plus
    ``JSONDecimal`` in ``numbers="finite"`` mode); a top-level scalar is
    accepted. Consumers must use ``type(x) is ...``, never ``isinstance`` or
    ``==`` (``True == 1 == 1.0``). Every rejection raises ``JSONPolicyError``.
    """
    if (
        type(data) is not bytes
        or type(max_bytes) is not int
        or not 1 <= max_bytes <= MAX_JSON_DOCUMENT_BYTES
        or numbers not in ("integer", "finite")
        or type(ascii_only) is not bool
    ):
        _fail("json_argument")
    if len(data) > max_bytes:
        _fail("json_too_large")

    if data[:3] == _BOM:
        _fail("json_encoding")
    code: str | None = None
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        code = "json_encoding"
    if code is not None:
        raise JSONPolicyError(code) from None
    if ascii_only and any(byte < 0x20 or byte > 0x7E for byte in data):
        _fail("json_unicode")

    _prescan_depth(text)

    def object_pairs_hook(pairs: list) -> dict:
        # Keys arrive already unescaped by json's tokenizer, so this compares
        # "a" against "a" and "/" against "\/" as the same key, per spec.
        merged = dict(pairs)
        if len(merged) != len(pairs):
            raise JSONPolicyError("json_duplicate_key")
        return merged

    def parse_int(lexeme: str) -> int:
        if len(lexeme) > MAX_JSON_NUMBER_CHARS:
            raise JSONPolicyError("json_number")
        value = int(lexeme)  # "-0" becomes 0
        if abs(value) > MAX_SAFE_INTEGER:
            raise JSONPolicyError("json_number")
        return value

    def parse_float(lexeme: str) -> JSONDecimal:
        if numbers == "integer" or len(lexeme) > MAX_JSON_NUMBER_CHARS:
            raise JSONPolicyError("json_number")
        if not math.isfinite(float(lexeme)):
            raise JSONPolicyError("json_number")
        return JSONDecimal(lexeme)

    def parse_constant(_name: str) -> object:
        raise JSONPolicyError("json_number")

    code = None
    try:
        # Handler order is load-bearing: JSONPolicyError (a ValueError) must
        # be caught first, or every hook code below is masked as json_syntax.
        parsed = json.loads(
            text,
            object_pairs_hook=object_pairs_hook,
            parse_int=parse_int,
            parse_float=parse_float,
            parse_constant=parse_constant,
            strict=True,
        )
    except JSONPolicyError as error:
        code = error.code
    except (json.JSONDecodeError, ValueError, RecursionError, OverflowError):
        code = "json_syntax"
    if code is not None:
        raise JSONPolicyError(code) from None

    return _postwalk(parsed, ascii_only=ascii_only)


def _canonicalize(value: object, *, depth: int, ascii_only: bool) -> bytes:
    kind = type(value)
    if kind is bool:
        return b"true" if value else b"false"
    if kind is int:
        if abs(value) > MAX_SAFE_INTEGER:
            _fail("json_number")
        return str(value).encode("ascii")
    if value is None:
        return b"null"
    if kind is str:
        _check_string(value, ascii_only=ascii_only, too_long_code="json_string_too_long")
        return _encode_string(value)
    if kind is dict:
        if depth > MAX_JSON_DEPTH:
            _fail("json_depth")
        members = []
        for key, member in value.items():
            if type(key) is not str:
                _fail("json_type")
            _check_string(key, ascii_only=ascii_only, too_long_code="json_string_too_long")
            members.append((key.encode("utf-16-be"), _encode_string(key), member))
        members.sort(key=lambda entry: entry[0])
        parts = [
            name + b":" + _canonicalize(member, depth=depth + 1, ascii_only=ascii_only)
            for _, name, member in members
        ]
        return b"{" + b",".join(parts) + b"}"
    if kind is list or kind is tuple:
        if depth > MAX_JSON_DEPTH:
            _fail("json_depth")
        if len(value) > MAX_JSON_ARRAY_ITEMS:
            _fail("json_array_too_long")
        parts = [_canonicalize(item, depth=depth + 1, ascii_only=ascii_only) for item in value]
        return b"[" + b",".join(parts) + b"]"
    _fail("json_type")


def canonical_json(value: object, *, ascii_only: bool = False) -> bytes:
    """Encode ``value`` as RFC 8785 (JCS) subset canonical JSON, integers only.

    A cycle fails as ``json_depth``: depth strictly increases on each
    recursive step regardless of object identity, so it can never loop.
    """
    return _canonicalize(value, depth=1, ascii_only=ascii_only)


def tagged_digest(tag: object, value: object) -> str:
    """Return ``sha256(tag + b"\\x00" + canonical_json(value, ascii_only=True))``."""
    if type(tag) is not str or not _TAG_PATTERN.fullmatch(tag):
        _fail("json_argument")
    body = canonical_json(value, ascii_only=True)
    return hashlib.sha256(tag.encode("ascii") + b"\x00" + body).hexdigest()


__all__ = [
    "JSON_ERROR_CODES",
    "MAX_JSON_ARRAY_ITEMS",
    "MAX_JSON_DEPTH",
    "MAX_JSON_DOCUMENT_BYTES",
    "MAX_JSON_NUMBER_CHARS",
    "MAX_JSON_STRING_BYTES",
    "MAX_SAFE_INTEGER",
    "JSONDecimal",
    "JSONPolicyError",
    "canonical_json",
    "parse_json",
    "tagged_digest",
]
