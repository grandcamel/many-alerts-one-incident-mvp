"""Hostile inputs and the exception-chain leak walk for ``forwarder_json``.

Complements ``test_forwarder_json.py``'s known-answer coverage with inputs
chosen to break the depth prescan, the number lexeme guards and the
Unicode/duplicate-key checks, plus the module's central claim: every raised
``JSONPolicyError`` carries only its fixed code, never a fragment of the
input that triggered it, however that input reached the failing check.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Iterator

import pytest

from grafana_jsm_sandbox.forwarder_json import (
    JSON_ERROR_CODES,
    MAX_JSON_ARRAY_ITEMS,
    MAX_JSON_DEPTH,
    MAX_JSON_DOCUMENT_BYTES,
    MAX_JSON_STRING_BYTES,
    JSONPolicyError,
    canonical_json,
    parse_json,
)

# --- helpers -------------------------------------------------------------


def parse(data: bytes, *, max_bytes: int = MAX_JSON_DOCUMENT_BYTES, **kwargs) -> object:
    return parse_json(data, max_bytes=max_bytes, **kwargs)


def expect_code(call, code: str) -> JSONPolicyError:
    with pytest.raises(JSONPolicyError) as caught:
        call()
    assert caught.value.code == code
    return caught.value


def unwrap(value: object, times: int) -> object:
    """Descend ``times`` single-element containers to reach a leaf."""
    for _ in range(times):
        assert len(value) == 1
        value = value[0]
    return value


# === hostile nesting =======================================================


def test_prescan_survives_long_backslash_run_at_max_depth():
    # 500 escaped-backslash pairs (1000 raw backslashes) right at the depth
    # boundary: a state-machine off-by-one here would misalign and miscount
    # the closing brackets that follow.
    leaf = '"' + ("\\\\" * 500) + '"'
    ok = ("[" * MAX_JSON_DEPTH + leaf + "]" * MAX_JSON_DEPTH).encode("ascii")
    assert unwrap(parse(ok), MAX_JSON_DEPTH) == "\\" * 500


def test_prescan_long_backslash_run_still_rejected_one_level_deeper():
    leaf = '"' + ("\\\\" * 500) + '"'
    bad = ("[" * (MAX_JSON_DEPTH + 1) + leaf + "]" * (MAX_JSON_DEPTH + 1)).encode("ascii")
    expect_code(lambda: parse(bad), "json_depth")


def test_brackets_inside_strings_do_not_count_toward_depth():
    noisy = "[{}]" * 20  # 80 structural-looking characters, but inside a string
    ok = ("[" * MAX_JSON_DEPTH + '"' + noisy + '"' + "]" * MAX_JSON_DEPTH).encode("ascii")
    assert unwrap(parse(ok), MAX_JSON_DEPTH) == noisy


def test_max_depth_and_max_array_width_compose_independently():
    at_width = "[" + ",".join(["0"] * MAX_JSON_ARRAY_ITEMS) + "]"
    # 15 wrapping arrays + 1 leaf array = depth 16 (the limit), width at cap.
    ok = ("[" * (MAX_JSON_DEPTH - 1) + at_width + "]" * (MAX_JSON_DEPTH - 1)).encode("ascii")
    leaf = unwrap(parse(ok), MAX_JSON_DEPTH - 1)
    assert len(leaf) == MAX_JSON_ARRAY_ITEMS

    over_width = "[" + ",".join(["0"] * (MAX_JSON_ARRAY_ITEMS + 1)) + "]"
    bad_width = (
        "[" * (MAX_JSON_DEPTH - 1) + over_width + "]" * (MAX_JSON_DEPTH - 1)
    ).encode("ascii")
    expect_code(lambda: parse(bad_width), "json_array_too_long")

    over_depth = ("[" * MAX_JSON_DEPTH + at_width + "]" * MAX_JSON_DEPTH).encode("ascii")
    expect_code(lambda: parse(over_depth), "json_depth")  # depth wins even though width is legal


def test_duplicate_key_check_only_reached_within_the_depth_limit():
    leaf = '{"a":1,"a":2}'
    at_limit = ("[" * (MAX_JSON_DEPTH - 1) + leaf + "]" * (MAX_JSON_DEPTH - 1)).encode("ascii")
    expect_code(lambda: parse(at_limit), "json_duplicate_key")
    one_deeper = ("[" * MAX_JSON_DEPTH + leaf + "]" * MAX_JSON_DEPTH).encode("ascii")
    expect_code(lambda: parse(one_deeper), "json_depth")  # prescan intercepts before the hook runs


def test_canonical_json_indirect_cycle_via_two_containers_is_depth_error():
    a: dict = {}
    b: list = [a]
    a["x"] = b  # a -> b -> a, not a self-reference
    expect_code(lambda: canonical_json(a), "json_depth")


def test_canonical_json_shared_non_cyclic_reference_is_encoded_twice():
    shared = {"v": 1}
    encoded = canonical_json({"p": shared, "q": shared})
    assert encoded == b'{"p":{"v":1},"q":{"v":1}}'


def test_many_unique_object_keys_have_no_artificial_cap():
    # The spec caps string bytes, not member count; this stays under the
    # 1 MiB document limit while exercising far more keys than any route
    # payload would ever carry.
    count = 20_000
    document = ("{" + ",".join(f'"k{i}":1' for i in range(count)) + "}").encode("ascii")
    result = parse(document)
    assert len(result) == count
    assert result["k0"] == 1 and result[f"k{count - 1}"] == 1


# === hostile numbers ========================================================


def test_long_pure_digit_lexeme_rejected_without_big_int_conversion():
    # Length is checked before int() ever runs, so this must reject promptly
    # regardless of digit count.
    expect_code(lambda: parse(b"9" * 5_000), "json_number")


@pytest.mark.parametrize("literal", [b"1e" + b"9" * 40, b"-1e" + b"9" * 40])
def test_overlong_exponent_lexeme_rejected_in_both_modes(literal):
    expect_code(lambda: parse(literal, numbers="integer"), "json_number")
    expect_code(lambda: parse(literal, numbers="finite"), "json_number")


def test_finite_underflow_to_zero_is_still_finite_and_keeps_exact_text():
    result = parse(b"1e-400", numbers="finite")
    assert result.text == "1e-400"  # never rounded to "0" or converted to float


@pytest.mark.parametrize("digits", ["١٢٣", "１２３"])  # Arabic-indic, fullwidth
def test_non_ascii_digit_lookalikes_are_not_tokenized_as_numbers(digits):
    # Python's int() accepts these; the JSON tokenizer must not, or a
    # locale-aware bypass of the safe-integer range would be possible.
    expect_code(lambda: parse(digits.encode("utf-8")), "json_syntax")


def test_array_of_boundary_and_over_boundary_integers():
    literals = ["9007199254740991", "-9007199254740991", "-0"]  # +-(2**53-1), and -0
    ok = ("[" + ",".join(literals) + "]").encode("ascii")
    assert parse(ok) == (2**53 - 1, -(2**53 - 1), 0)
    bad = ("[" + ",".join(literals) + ",9007199254740992]").encode("ascii")  # one past the max
    expect_code(lambda: parse(bad), "json_number")


# === hostile Unicode ========================================================


@pytest.mark.parametrize("codepoint", [0xD7FF, 0xE000])  # just outside the surrogate range
def test_characters_adjacent_to_surrogate_range_are_accepted(codepoint):
    result = parse(f'"\\u{codepoint:04x}"'.encode("ascii"))
    assert result == chr(codepoint)


@pytest.mark.parametrize("codepoint", [0xD800, 0xDFFF])  # the surrogate range's own edges
def test_lone_surrogate_at_either_edge_of_the_range_is_rejected(codepoint):
    expect_code(lambda: parse(f'"\\u{codepoint:04x}"'.encode("ascii")), "json_unicode")


def test_two_unpaired_high_surrogates_in_a_row_rejected():
    expect_code(lambda: parse(b'"\\ud800\\ud800"'), "json_unicode")


def test_extreme_valid_surrogate_pairs_combine_correctly():
    assert parse(b'"\\ud800\\udc00"') == "\U00010000"  # minimum astral code point
    assert parse(b'"\\udbff\\udfff"') == "\U0010ffff"  # maximum code point


def test_overlong_encoding_of_nul_is_an_encoding_error_not_unicode():
    # A canonical-looking (but strict-UTF-8-invalid) two-byte encoding of
    # U+0000 must never reach the string content as a literal NUL.
    expect_code(lambda: parse(b'"' + b"\xc0\x80" + b'"'), "json_encoding")


def test_cesu8_encoded_surrogate_pair_is_an_encoding_error():
    # CESU-8 encodes an astral character as two surrogate-half UTF-8
    # sequences; strict UTF-8 must reject each half rather than combine them.
    expect_code(lambda: parse(b'"' + b"\xed\xa0\x80\xed\xb0\x80" + b'"'), "json_encoding")


@pytest.mark.parametrize("value,text", [("é", "é")])
def test_nfc_and_nfd_keys_are_distinct_not_normalized(value, text):
    result = parse(f'{{"{value}":1,"{text}":2}}'.encode())
    assert result == {value: 1, text: 2}


def test_escaped_and_literal_forms_of_the_same_key_still_collide():
    expect_code(lambda: parse(b'{"\\u0041":1,"A":2}'), "json_duplicate_key")


@pytest.mark.parametrize("codepoint", [0x20, 0x7E])
def test_ascii_only_boundary_bytes_accepted(codepoint):
    assert parse(f'"{chr(codepoint)}"'.encode("ascii"), ascii_only=True) == chr(codepoint)


def test_ascii_only_raw_control_byte_is_unicode_not_syntax():
    # Without ascii_only the same raw control byte is a syntax error (it is
    # never legal unescaped inside a JSON string); the ascii_only raw-byte
    # sweep runs before json.loads and intercepts it first.
    expect_code(lambda: parse(b'"\x1f"'), "json_syntax")
    expect_code(lambda: parse(b'"\x1f"', ascii_only=True), "json_unicode")


# === exception-chain leak walk =============================================

_MARKER = "ADV3RSARIAL-JSON-MARKER-3f1c"


def _leak_surface(node: object, seen: set) -> Iterator[object]:
    """Yield every str/bytes reachable from ``node``.

    Walks ``str``/``repr``/``args``/every instance attribute of an
    exception, plus ``__cause__``/``__context__`` and ``.doc``/``.object``/
    ``.msg`` on any chained exception, recursively.
    """
    if id(node) in seen:
        return
    seen.add(id(node))
    if isinstance(node, (str, bytes, bytearray)):
        yield node
        return
    if isinstance(node, BaseException):
        yield str(node)
        yield repr(node)
        yield from _leak_surface(node.args, seen)
        for value in vars(node).values():
            yield from _leak_surface(value, seen)
        yield from _leak_surface(node.__cause__, seen)
        yield from _leak_surface(node.__context__, seen)
        for attribute in ("doc", "object", "msg"):
            if hasattr(node, attribute):
                yield from _leak_surface(getattr(node, attribute), seen)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _leak_surface(key, seen)
            yield from _leak_surface(value, seen)
        return
    if isinstance(node, (list, tuple, set, frozenset)):
        for item in node:
            yield from _leak_surface(item, seen)
        return


def assert_no_leak(error: JSONPolicyError, marker: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    marker_bytes = marker.encode("utf-8")
    for value in _leak_surface(error, set()):
        if isinstance(value, str):
            assert marker not in value, f"marker leaked as str: {value!r}"
        else:
            assert marker_bytes not in bytes(value), f"marker leaked as bytes: {value!r}"


def _cases_by_code(marker: str) -> dict:
    """One marker-bearing trigger per code in ``JSON_ERROR_CODES``.

    Each case plants ``marker`` somewhere in the input that is *not* the
    direct cause of the rejection, so a leak would only show up through the
    chain the module promises to sever (a chained stdlib exception's own
    ``.doc``/``.object``), not through an obviously-related value.
    """
    huge_int = "9" * 20  # > MAX_SAFE_INTEGER, well under the 32-char lexeme cap
    padding = "a" * (MAX_JSON_STRING_BYTES + 1 - len(marker))
    return {
        "json_argument": (
            lambda: parse_json(f'{{"m":"{marker}"}}'.encode(), max_bytes=0)
        ),
        "json_too_large": (
            lambda: parse_json(f'{{"m":"{marker}"}}'.encode(), max_bytes=5)
        ),
        "json_encoding": (
            lambda: parse(
                f'{{"m":"{marker}","bad":"'.encode() + b"\xff\xfe" + b'"}', max_bytes=10_000,
            )
        ),
        "json_syntax": (
            lambda: parse(f'{{"m":"{marker}"}} trailing'.encode(), max_bytes=10_000)
        ),
        "json_unicode": (
            lambda: parse(f'{{"m":"{marker}","bad":"\\u0000"}}'.encode(), max_bytes=10_000)
        ),
        "json_duplicate_key": (
            lambda: parse(f'{{"{marker}":1,"{marker}":2}}'.encode(), max_bytes=10_000)
        ),
        "json_depth": (
            lambda: parse(
                ("[" * 20 + f'"{marker}"' + "]" * 20).encode(), max_bytes=10_000,
            )
        ),
        "json_array_too_long": (
            lambda: parse(
                ("[" + ",".join([f'"{marker}"'] + ["1"] * MAX_JSON_ARRAY_ITEMS) + "]").encode(),
                max_bytes=100_000,
            )
        ),
        "json_string_too_long": (
            lambda: parse(f'{{"k":"{marker}{padding}"}}'.encode(), max_bytes=100_000)
        ),
        "json_number": (
            lambda: parse(f'{{"m":"{marker}","n":{huge_int}}}'.encode(), max_bytes=10_000)
        ),
        "json_type": (
            # unreachable from parse_json: its hooks only ever produce
            # allowed types, so json_type is exercised through canonical_json.
            lambda: canonical_json({"m": marker, "bad": {1, 2, 3}})
        ),
    }


def test_every_json_error_code_has_a_marker_case():
    assert set(_cases_by_code(_MARKER)) == set(JSON_ERROR_CODES)


@pytest.mark.parametrize("code", sorted(JSON_ERROR_CODES))
def test_exception_chain_carries_no_marker_for_every_code(code):
    trigger = _cases_by_code(_MARKER)[code]
    error = expect_code(trigger, code)
    assert_no_leak(error, _MARKER)


def test_marker_case_invoked_outside_any_handler_of_this_test_itself():
    # Guards against a future refactor of _cases_by_code wrapping the call
    # in its own try/except, which would reintroduce exactly the __context__
    # risk this file exists to rule out.
    import sys

    assert sys.exc_info() == (None, None, None)
    for code in JSON_ERROR_CODES:
        trigger = _cases_by_code(_MARKER)[code]
        error = expect_code(trigger, code)
        assert sys.exc_info() == (None, None, None)
        assert_no_leak(error, _MARKER)


# === AST checks =============================================================

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "grafana_jsm_sandbox" / "forwarder_json.py"
)
_ALLOWED_IMPORTS = frozenset({"__future__", "dataclasses", "hashlib", "json", "math", "re"})


def _module_ast() -> ast.Module:
    source = _MODULE_PATH.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(_MODULE_PATH))


def test_no_raise_inside_any_except_handler():
    tree = _module_ast()
    handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]
    assert len(handlers) >= 2  # sanity: the module does have handlers to check
    for handler in handlers:
        for inner in ast.walk(handler):
            assert not isinstance(inner, ast.Raise), (
                f"raise statement inside except handler at line {inner.lineno}"
            )


def test_imports_are_exactly_the_allowlist_with_no_dynamic_import():
    tree = _module_ast()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "forwarder_json.py must have no relative imports"
            assert node.module is not None
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            target = node.func
            is_dunder_import = isinstance(target, ast.Name) and target.id == "__import__"
            is_importlib = isinstance(target, ast.Attribute) and target.attr == "import_module"
            assert not is_dunder_import and not is_importlib, "dynamic import call found"
    assert names == _ALLOWED_IMPORTS
