"""Deterministic tests for strict bounded JSON parsing and canonical encoding.

Golden vectors are recomputed independently in the implementation plan; the
known-answer tests below pin them literally. Nothing here opens a socket,
clock or file; every input is a Python literal or a small generated corpus.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import random

import pytest

from grafana_jsm_sandbox import forwarder_json
from grafana_jsm_sandbox.forwarder_json import (
    JSON_ERROR_CODES,
    MAX_JSON_ARRAY_ITEMS,
    MAX_JSON_DEPTH,
    MAX_JSON_DOCUMENT_BYTES,
    MAX_JSON_NUMBER_CHARS,
    MAX_JSON_STRING_BYTES,
    MAX_SAFE_INTEGER,
    JSONDecimal,
    JSONPolicyError,
    canonical_json,
    parse_json,
    tagged_digest,
)

# --- helpers -----------------------------------------------------------


def parse(data: bytes, *, max_bytes: int = MAX_JSON_DOCUMENT_BYTES, **kwargs) -> object:
    return parse_json(data, max_bytes=max_bytes, **kwargs)


def assert_json_error(call, code: str | None = None) -> JSONPolicyError:
    with pytest.raises(JSONPolicyError) as caught:
        call()
    error = caught.value
    assert str(error) == error.code
    assert error.args == (error.code,)
    assert vars(error) == {"code": error.code}
    assert error.code in JSON_ERROR_CODES
    if code is not None:
        assert error.code == code
    return error


def nested(depth: int, *, kind: str = "array") -> bytes:
    """Build a JSON document nested ``depth`` containers deep around a leaf ``1``."""
    opens: list[str] = []
    closes: list[str] = []
    for i in range(depth):
        use_object = kind == "object" or (kind == "mixed" and i % 2 == 1)
        if use_object:
            opens.append('{"a":')
            closes.append("}")
        else:
            opens.append("[")
            closes.append("]")
    return ("".join(opens) + "1" + "".join(reversed(closes))).encode("ascii")


def normalize(value: object) -> object:
    """Collapse list/tuple to a common shape for structural comparison."""
    if type(value) is dict:
        return {key: normalize(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return tuple(normalize(item) for item in value)
    return value


# === constants and error type ==========================================


def test_constants():
    assert MAX_JSON_DEPTH == 16
    assert MAX_JSON_ARRAY_ITEMS == 256
    assert MAX_JSON_STRING_BYTES == 16_384
    assert MAX_SAFE_INTEGER == 2**53 - 1
    assert MAX_JSON_NUMBER_CHARS == 32
    assert MAX_JSON_DOCUMENT_BYTES == 1_048_576
    assert JSON_ERROR_CODES == frozenset({
        "json_argument", "json_too_large", "json_encoding", "json_syntax",
        "json_unicode", "json_duplicate_key", "json_depth", "json_array_too_long",
        "json_string_too_long", "json_number", "json_type",
    })


def test_json_policy_error_shape():
    error = assert_json_error(lambda: parse(b"", numbers="bogus"), "json_argument")
    assert isinstance(error, ValueError)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_json_decimal_is_frozen_text_holder():
    value = JSONDecimal("1.50")
    assert value.text == "1.50"
    assert dataclasses.is_dataclass(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.text = "2"  # type: ignore[misc]
    assert value == JSONDecimal("1.50")
    assert value != JSONDecimal("1.5")


# === known-answer canonical encoding ====================================


def test_known_answer_72_bytes():
    value = {
        "b": 1, "a": [True, False, None],
        "c": 'é\n\x01"\\/\x7f ',
        "\U0001F600": 0, "～": 1,
    }
    encoded = canonical_json(value)
    assert len(encoded) == 72
    assert encoded.hex() == (
        "7b2261223a5b747275652c66616c73652c6e756c6c5d2c2262223a312c2263223a22c3a9"
        "5c6e5c75303030315c225c5c2f7fe280a8222c22f09f9880223a302c22efbd9e223a317d"
    )


def test_tagged_digest_known_answer():
    assert tagged_digest("maoi.test.v1", {}) == (
        "55789aa27a10eff073ef2f86fceea079909d9ee9957238c063aa0e7d1dde3195"[:64]
    )
    assert len(tagged_digest("maoi.test.v1", {})) == 64


def test_escape_table_and_literal_passthrough():
    escapes = {
        "\x08": "\\b", "\x09": "\\t", "\x0a": "\\n", "\x0c": "\\f", "\x0d": "\\r",
        '"': '\\"', "\\": "\\\\",
    }
    for raw, escaped in escapes.items():
        assert canonical_json(raw) == ('"' + escaped + '"').encode("ascii")
    for code_point in range(0x01, 0x20):
        char = chr(code_point)
        if char in escapes:
            continue
        assert canonical_json(char) == f'"\\u{code_point:04x}"'.encode("ascii")
    # literal, unescaped: '/', DEL and U+2028
    assert canonical_json("/") == b'"/"'
    assert canonical_json("\x7f") == b'"\x7f"'
    assert canonical_json(" ") == "\" \"".encode()


# === U+0000 and lone-surrogate rejection ================================


def test_u0000_raw_control_char_is_syntax_error():
    assert_json_error(lambda: parse(b'"\x00"'), "json_syntax")  # raw control char: syntax


def test_u0000_rejected_via_escape_on_decode():
    assert_json_error(lambda: parse(b'"a\\u0000b"'), "json_unicode")


def test_u0000_rejected_on_encode():
    assert_json_error(lambda: canonical_json("a\x00b"), "json_unicode")
    assert_json_error(lambda: canonical_json({"a\x00b": 1}), "json_unicode")


def test_lone_and_reversed_surrogate_rejected():
    assert_json_error(lambda: parse(b'"\\ud800"'), "json_unicode")
    assert_json_error(lambda: parse(b'"\\ude00\\ud83d"'), "json_unicode")  # reversed order
    assert_json_error(lambda: canonical_json("\ud800"), "json_unicode")


def test_valid_surrogate_pair_combines_to_one_codepoint():
    result = parse(b'"\\ud83d\\ude00"')
    assert result == "\U0001F600"
    assert result.encode("utf-8") == bytes.fromhex("f09f9880")


# === UTF-16BE key order ==================================================


def test_utf16_key_order():
    encoded = canonical_json({"a": 1, "B": 2})
    assert encoded == b'{"B":2,"a":1}'  # "B" (0x0042) sorts before "a" (0x0061)
    # U+1F600 is the UTF-16BE surrogate pair D83D DE00, which sorts before the
    # BMP code point U+FF5E (FF5E): the digest key precedes the tilde key.
    encoded = canonical_json({"～": 1, "\U0001F600": 2})
    expected = (
        b'{"' + "\U0001F600".encode("utf-8") + b'":2,"'
        + "～".encode() + b'":1}'
    )
    assert encoded == expected


# === integers =============================================================


@pytest.mark.parametrize("value", [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER, 0])
def test_integer_boundary_accepted(value):
    result = parse(str(value).encode("ascii"))
    assert result == value
    assert type(result) is int


@pytest.mark.parametrize("value", [MAX_SAFE_INTEGER + 1, -(MAX_SAFE_INTEGER + 1)])
def test_integer_boundary_rejected(value):
    assert_json_error(lambda: parse(str(value).encode("ascii")), "json_number")


def test_seventeen_digit_lexeme_rejected():
    assert_json_error(lambda: parse(b"9" * 17), "json_number")


def test_thirtythree_character_lexeme_rejected():
    assert_json_error(lambda: parse(b"1" * 33), "json_number")


def test_thirtytwo_character_fraction_lexeme_boundary_in_finite_mode():
    # The 33-char lexeme above is integer-shaped (parse_int); this boundary
    # is fraction-shaped, so it is the only vector that exercises the length
    # check inside parse_float rather than parse_int.
    assert_json_error(lambda: parse(b"1." + b"0" * 31, numbers="finite"), "json_number")
    result = parse(b"1." + b"0" * 30, numbers="finite")
    assert result == JSONDecimal("1." + "0" * 30)


def test_negative_zero_becomes_zero():
    result = parse(b"-0")
    assert result == 0
    assert type(result) is int
    assert not str(result).startswith("-")


@pytest.mark.parametrize("literal", [b"1.0", b"1e2", b"1E-2", b"-0.0"])
def test_integer_mode_rejects_non_integer_lexemes(literal):
    assert_json_error(lambda: parse(literal, numbers="integer"), "json_number")


# === finite mode ===========================================================


@pytest.mark.parametrize("literal,text", [(b"1.5", "1.5"), (b"1e2", "1e2")])
def test_finite_mode_produces_json_decimal(literal, text):
    result = parse(literal, numbers="finite")
    assert result == JSONDecimal(text)


@pytest.mark.parametrize("literal", [b"1e400", b"-1e400"])
def test_finite_mode_rejects_non_finite(literal):
    assert_json_error(lambda: parse(literal, numbers="finite"), "json_number")


def test_finite_mode_still_bounds_integers():
    lexeme = str(2**53).encode("ascii")
    assert_json_error(lambda: parse(lexeme, numbers="finite"), "json_number")


@pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity"])
@pytest.mark.parametrize("mode", ["integer", "finite"])
def test_non_finite_constants_rejected_both_modes(literal, mode):
    assert_json_error(lambda: parse(literal, numbers=mode), "json_number")


# === duplicate keys ========================================================


def test_duplicate_key_plain():
    assert_json_error(lambda: parse(b'{"a":1,"a":2}'), "json_duplicate_key")


def test_duplicate_key_escaped_slash():
    assert_json_error(lambda: parse(b'{"/":1,"\\/":2}'), "json_duplicate_key")


def test_duplicate_key_nested():
    assert_json_error(lambda: parse(b'{"outer":{"a":1,"a":2}}'), "json_duplicate_key")


# === depth ==================================================================


@pytest.mark.parametrize("kind", ["array", "object", "mixed"])
def test_depth_sixteen_accepted_seventeen_rejected(kind):
    parse(nested(16, kind=kind))  # does not raise
    assert_json_error(lambda: parse(nested(17, kind=kind)), "json_depth")


def test_depth_escaped_backslash_prescan_vector():
    # A string holding one escaped backslash, at the exact depth boundary:
    # a buggy escape-consumption in the prescan could mis-toggle in_string
    # here and miscount the closing brackets that follow.
    ok = ("[" * 16 + '"\\\\"' + "]" * 16).encode("ascii")
    parse(ok)
    bad = ("[" * 17 + '"\\\\"' + "]" * 17).encode("ascii")
    assert_json_error(lambda: parse(bad), "json_depth")


def test_depth_escaped_quote_prescan_vector():
    # An escaped quote inside a string, followed by literal '[' characters: not
    # consuming the escape would mistake it for the string's closing quote and
    # miscount the following brackets as real nesting.
    value = '"' + "[" * 20
    document = json.dumps([value]).encode("ascii")
    assert parse(document) == (value,)


def test_one_mebibyte_of_open_brackets_gives_depth_not_recursion_error():
    data = b"[" * MAX_JSON_DOCUMENT_BYTES
    assert_json_error(lambda: parse(data), "json_depth")


@pytest.mark.parametrize("kind", ["array", "object", "mixed"])
def test_postwalk_depth_check_is_authoritative_without_the_prescan(monkeypatch, kind):
    # The post-walk depth check is documented as catching "any prescan bug
    # directly"; disable the prescan to prove it independently enforces the
    # same bound, rather than only ever running after the prescan already
    # rejected the input.
    monkeypatch.setattr(forwarder_json, "_prescan_depth", lambda _text: None)
    parse(nested(16, kind=kind))  # still accepted
    assert_json_error(lambda: parse(nested(17, kind=kind)), "json_depth")


# === arrays =================================================================


def test_array_two_hundred_fifty_six_accepted_two_fifty_seven_rejected():
    ok = ("[" + ",".join(["1"] * MAX_JSON_ARRAY_ITEMS) + "]").encode("ascii")
    result = parse(ok)
    assert len(result) == MAX_JSON_ARRAY_ITEMS
    bad = ("[" + ",".join(["1"] * (MAX_JSON_ARRAY_ITEMS + 1)) + "]").encode("ascii")
    assert_json_error(lambda: parse(bad), "json_array_too_long")


# === strings: byte-length boundary =========================================


def _euro_string(extra_a: int) -> str:
    return "€" * 5_461 + "a" * extra_a


def test_string_16384_bytes_accepted_16385_rejected_value():
    ok = _euro_string(1)
    assert len(ok.encode("utf-8")) == MAX_JSON_STRING_BYTES
    document = json.dumps({"k": ok}).encode("utf-8")
    result = parse(document)
    assert result == {"k": ok}
    bad = _euro_string(2)
    assert len(bad.encode("utf-8")) == MAX_JSON_STRING_BYTES + 1
    bad_document = json.dumps({"k": bad}).encode("utf-8")
    assert_json_error(lambda: parse(bad_document), "json_string_too_long")


def test_string_16384_bytes_accepted_16385_rejected_key():
    ok = _euro_string(1)
    document = json.dumps({ok: 1}).encode("utf-8")
    parse(document)
    bad = _euro_string(2)
    bad_document = json.dumps({bad: 1}).encode("utf-8")
    assert_json_error(lambda: parse(bad_document), "json_string_too_long")


def test_e_acute_counts_as_two_canonical_bytes():
    at_limit = "é" * 8_192
    assert len(at_limit.encode("utf-8")) == MAX_JSON_STRING_BYTES
    canonical_json(at_limit)  # accepted
    over_limit = "é" * 8_193
    assert_json_error(lambda: canonical_json(over_limit), "json_string_too_long")


# === invalid UTF-8 and BOM =================================================


@pytest.mark.parametrize("data", [
    b'"' + b"\xc0\xaf" + b'"',           # overlong encoding of '/'
    b'"' + b"\xed\xa0\x80" + b'"',       # UTF-8-encoded surrogate
    b'"' + b"\xf4\x90\x80\x80" + b'"',   # above U+10FFFF
    b'"' + b"\xe2\x82" + b'"',           # truncated 3-byte sequence
])
def test_invalid_utf8_rejected(data):
    assert_json_error(lambda: parse(data), "json_encoding")


def test_leading_bom_rejected():
    assert_json_error(lambda: parse(b"\xef\xbb\xbf" + b"1"), "json_encoding")


def test_interior_feff_is_syntax_not_encoding():
    # Only a *leading* BOM is json_encoding; FEFF used as whitespace elsewhere
    # is simply not legal JSON whitespace, so it is json_syntax.
    assert_json_error(lambda: parse(b"[\xef\xbb\xbf1]"), "json_syntax")


# === syntax and whitespace rejections ======================================


@pytest.mark.parametrize("data", [
    b'{"a":1} trailing',
    b'{"a":1,}',
    b"{'a':1}",
    b'{"a": 1 /* c */}',
    b'"\x01"',
    b"\x0c" + b"1",       # \f
    b"\x0b" + b"1",       # \v
    b"\xc2\xa0" + b"1",   # NBSP
    b"\xe2\x80\xa8" + b"1",  # U+2028
    b"",
    b"   ",
])
def test_syntax_and_whitespace_rejections(data):
    assert_json_error(lambda: parse(data), "json_syntax")


# === arguments ==============================================================


def test_max_bytes_boundary():
    data = b"1" * 10
    parse(data, max_bytes=10)  # exact fit accepted
    assert_json_error(lambda: parse_json(data, max_bytes=9), "json_too_large")


@pytest.mark.parametrize("kwargs", [
    {"max_bytes": 0},
    {"max_bytes": MAX_JSON_DOCUMENT_BYTES + 1},
    {"max_bytes": True},
    {"max_bytes": 10.0},
    {"max_bytes": 10, "numbers": "float"},
    {"max_bytes": 10, "ascii_only": 1},
    {"max_bytes": 10, "ascii_only": "yes"},
])
def test_argument_rejections(kwargs):
    assert_json_error(lambda: parse_json(b"1", **kwargs), "json_argument")


def test_data_must_be_exact_bytes():
    assert_json_error(lambda: parse_json("1", max_bytes=10), "json_argument")


# === ascii_only =============================================================


def test_ascii_only_rejects_raw_non_ascii_bytes():
    assert_json_error(lambda: parse('"é"'.encode(), ascii_only=True), "json_unicode")


def test_ascii_only_rejects_escaped_non_ascii_character():
    assert_json_error(lambda: parse(b'"\\u00e9"', ascii_only=True), "json_unicode")


def test_ascii_only_accepts_printable_ascii():
    assert parse(b'"hello"', ascii_only=True) == "hello"


# === ascii_only U+007F boundary =============================================
#
# ascii_only admits 0x20..0x7E; DEL (U+007F) is one past the top of that
# range even though it is otherwise an ASCII code point, so it must be the
# first byte/character rejected on every ascii_only path: the raw-byte
# prescan, the post-decode string check, and canonical/digest encoding.


def test_ascii_only_boundary_raw_bytes_0x7e_accepted_0x7f_rejected():
    assert parse(b'"\x7e"', ascii_only=True) == "\x7e"
    assert_json_error(lambda: parse(b'"\x7f"', ascii_only=True), "json_unicode")


def test_ascii_only_boundary_escaped_u007e_accepted_u007f_rejected():
    # The raw bytes of the escape sequence ("\", "u", "0", "0", "7", "e"/"f")
    # are themselves plain ASCII, so this exercises the post-decode
    # _check_string character check, distinct from the raw-byte prescan above.
    assert parse(b'"\\u007e"', ascii_only=True) == "\x7e"
    assert_json_error(lambda: parse(b'"\\u007f"', ascii_only=True), "json_unicode")


def test_canonical_json_ascii_only_boundary_0x7e_accepted_0x7f_rejected():
    assert canonical_json("\x7e", ascii_only=True) == b'"\x7e"'
    assert_json_error(lambda: canonical_json("\x7f", ascii_only=True), "json_unicode")


def test_tagged_digest_ascii_only_boundary_0x7e_accepted_0x7f_rejected():
    # tagged_digest always canonicalizes with ascii_only=True internally.
    tagged_digest("maoi.test.v1", "\x7e")
    assert_json_error(lambda: tagged_digest("maoi.test.v1", "\x7f"), "json_unicode")


# === canonical_json type rejections and structure ==========================


class _StrSub(str):
    pass


@pytest.mark.parametrize("value", [
    1.5, JSONDecimal("1.5"), b"bytes", {1, 2}, _StrSub("a"),
])
def test_canonical_json_rejects_disallowed_types(value):
    assert_json_error(lambda: canonical_json(value), "json_type")


def test_canonical_json_rejects_non_str_key():
    assert_json_error(lambda: canonical_json({1: "a"}), "json_type")


def test_canonical_json_rejects_out_of_range_int():
    assert_json_error(lambda: canonical_json(MAX_SAFE_INTEGER + 1), "json_number")
    assert_json_error(lambda: canonical_json(-(MAX_SAFE_INTEGER + 1)), "json_number")


def test_canonical_json_tuple_and_list_equivalent():
    assert canonical_json([1, "a", None]) == canonical_json((1, "a", None))


def test_canonical_json_depth_and_array_limits():
    ok = 1
    for _ in range(MAX_JSON_DEPTH):
        ok = [ok]
    canonical_json(ok)  # exactly MAX_JSON_DEPTH: accepted
    bad = [ok]
    assert_json_error(lambda: canonical_json(bad), "json_depth")
    too_long = [0] * (MAX_JSON_ARRAY_ITEMS + 1)
    assert_json_error(lambda: canonical_json(too_long), "json_array_too_long")


def test_canonical_json_cycle_gives_depth_error():
    cyclic: list = []
    cyclic.append(cyclic)
    assert_json_error(lambda: canonical_json(cyclic), "json_depth")


def test_canonical_json_dict_only_depth_limit():
    # The list branch has its own depth check; nest only through dicts so
    # this exercises the dict branch's check in isolation.
    ok: object = 1
    for _ in range(MAX_JSON_DEPTH):
        ok = {"a": ok}
    canonical_json(ok)  # exactly MAX_JSON_DEPTH: accepted
    assert_json_error(lambda: canonical_json({"a": ok}), "json_depth")


def test_canonical_json_dict_only_cycle_gives_depth_error():
    cyclic: dict = {}
    cyclic["x"] = cyclic
    assert_json_error(lambda: canonical_json(cyclic), "json_depth")


def test_canonical_json_ascii_only():
    assert_json_error(lambda: canonical_json("é", ascii_only=True), "json_unicode")
    assert canonical_json("a", ascii_only=True) == b'"a"'


def test_canonical_json_bool_before_int():
    assert canonical_json(True) == b"true"
    assert canonical_json(False) == b"false"
    assert canonical_json(1) == b"1"


def test_canonical_json_none():
    assert canonical_json(None) == b"null"


def test_canonical_json_no_whitespace_or_trailing_separators():
    encoded = canonical_json({"a": [1, 2], "b": {}})
    assert b" " not in encoded
    assert encoded == b'{"a":[1,2],"b":{}}'


# === tag grammar =============================================================


@pytest.mark.parametrize("tag", ["a", "a.b-c", "9z", "a" * 64])
def test_tag_grammar_accepted(tag):
    tagged_digest(tag, 1)


@pytest.mark.parametrize("tag", ["", "A", "-a", "a" * 65, "a b", "a_b"])
def test_tag_grammar_rejected(tag):
    assert_json_error(lambda: tagged_digest(tag, 1), "json_argument")


def test_tagged_digest_matches_manual_formula():
    value = {"x": 1}
    expected = hashlib.sha256(
        b"maoi.test.v1" + b"\x00" + canonical_json(value, ascii_only=True)
    ).hexdigest()
    assert tagged_digest("maoi.test.v1", value) == expected


def test_tagged_digest_non_str_tag():
    assert_json_error(lambda: tagged_digest(1, {}), "json_argument")


def test_tagged_digest_enforces_ascii_only():
    # tagged_digest always canonicalizes with ascii_only=True; a non-ASCII
    # value must be rejected, not silently digested.
    assert_json_error(lambda: tagged_digest("maoi.test.v1", "café"), "json_unicode")


# === seeded fixed-point corpus ==============================================


def _random_value(rng: random.Random, depth_left: int) -> object:
    choices = ["int", "str", "bool", "none"]
    if depth_left > 0:
        choices += ["list", "dict"]
    kind = rng.choice(choices)
    if kind == "int":
        return rng.randint(-1_000_000, 1_000_000)
    if kind == "str":
        alphabet = "abcxyz012 é"
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "none":
        return None
    if kind == "list":
        return [_random_value(rng, depth_left - 1) for _ in range(rng.randint(0, 4))]
    keys = rng.sample(
        ["k1", "k2", "k3", "k4", "k5", "k6"], rng.randint(0, 4),
    )
    return {key: _random_value(rng, depth_left - 1) for key in keys}


def test_seeded_fixed_point_corpus():
    rng = random.Random(20260922)
    for _ in range(50):
        original = _random_value(rng, depth_left=4)
        encoded = canonical_json(original)
        round_tripped = parse(encoded)
        assert normalize(round_tripped) == normalize(original)
        # canonical_json is a pure function of value: re-encoding matches.
        assert canonical_json(round_tripped) == encoded


# === error discipline spot checks ===========================================


def test_str_and_args_hold_only_the_code():
    for code in JSON_ERROR_CODES:
        error = JSONPolicyError(code)
        assert str(error) == code
        assert error.args == (code,)
        assert vars(error) == {"code": code}
