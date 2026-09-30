"""Adversarial tests for the Jira route policy (Tester C, routes part).

Derived from the forwarder-routes implementation plan and the ticket-36
specification's "Route policies", "Common HTTP boundary" and "Trusted
dispatch permit" sections -- not from ``forwarder_routes.py``'s own
implementation. These tests try to break the route policy: walk every
error's exception chain for a leaked marker, check the module's import and
raise-in-except discipline by AST, prove the sentinel never reaches the
upstream or the digest, run the native-request matrix per listener,
smuggle malformed selectors/bodies/JQL, fuzz a seeded request property,
compose with a real ``LeaseRegistry`` and ``ReceiptLedger`` under one fake
clock, and confirm no socket or wall-clock access.
"""

from __future__ import annotations

import ast
import base64
import dataclasses
import json
import pathlib
import random
import re
import socket
import sys
import time
from hashlib import sha256

import pytest

from grafana_jsm_sandbox import forwarder_routes as fr
from grafana_jsm_sandbox.forwarder_http import HTTPBoundaryError, ParsedRequest, parse_request
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_json import canonical_json
from grafana_jsm_sandbox.forwarder_leases import LEASE_SECONDS, LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import (
    MAX_HANDLER_SECONDS,
    ReceiptLedger,
    local_response_for,
    response_digest,
)
from grafana_jsm_sandbox.forwarder_routes import (
    MAX_TEMPLATE_BYTES,
    ROUTE_CATALOG,
    ROUTE_ERROR_REASONS,
    UNMATCHED_ROUTE_ID,
    JiraScope,
    JiraVenuePolicy,
    RouteConfigError,
    RoutePolicy,
    RoutePolicyError,
    ScopedIssue,
    ScopeManifest,
    denied_request_digest,
    encode_query_value,
    parse_scope_manifest,
    require_manifest_binding,
)
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES

MARKER = "RouteAdvMarker7f2c9d3b1e4a"

# --- golden fixtures (recomputed from the plan; independent of Implementer B) --

GOLDEN_POLICY_KWARGS = {
    "revision": "policy-r1",
    "project_id": "90001",
    "project_key": "SYN",
    "issue_type_id": "90002",
    "issue_fields": ("issuetype", "labels", "project", "status", "summary"),
    "search_fields": ("issuetype", "labels", "project", "status", "summary"),
    "search_templates": (
        (
            'project = 90001 AND issuetype = 90002 AND labels = "{label}" '
            "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
        ),
    ),
    "search_max_results": 50,
    "open_status_category_keys": ("syn-new", "syn-progress"),
}
POLICY_DIGEST = "3013f6a10469469651028a5ea422849591fae5a8bb4a7e15b92e2b0caf99a156"

GOLDEN_SCOPE = JiraScope(
    issues=(ScopedIssue(issue_id="90101", issue_key="SYN-1"),),
    search_labels=("fp-0123456789abcdef",),
)
SCOPE_DIGEST = "849028ca20f4b87db84ad25974dadd560b5d06177e17afad6b6a65fb902de47c"
MANIFEST_CANONICAL_BYTES = (
    b'{"attempt_id":"attempt-1","policy_digest":'
    b'"3013f6a10469469651028a5ea422849591fae5a8bb4a7e15b92e2b0caf99a156",'
    b'"rehearsal_id":"rehearsal-1","revision":"scope-r1",'
    b'"routes":["jira.issue.get","jira.search"],"run_id":"run-1",'
    b'"schema":"maoi.forwarder.scope.v1","scope":{"issues":'
    b'[{"id":"90101","key":"SYN-1"}],"search_labels":["fp-0123456789abcdef"]},'
    b'"service":"jira"}'
)
ISSUE_GET_TARGET = "/rest/api/3/issue/90101?fields=issuetype%2Clabels%2Cproject%2Cstatus%2Csummary"
GOLDEN_LABEL = "fp-0123456789abcdef"
GOLDEN_JQL = (
    'project = 90001 AND issuetype = 90002 AND labels = "' + GOLDEN_LABEL + '" '
    "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
)


def golden_policy(**overrides) -> JiraVenuePolicy:
    kwargs = {**GOLDEN_POLICY_KWARGS, **overrides}
    return JiraVenuePolicy(**kwargs)


def golden_manifest(**overrides) -> ScopeManifest:
    kwargs = {
        "service": "jira", "run_id": "run-1", "attempt_id": "attempt-1",
        "rehearsal_id": "rehearsal-1", "revision": "scope-r1",
        "routes": ("jira.issue.get", "jira.search"),
        "policy_digest": POLICY_DIGEST, "scope": GOLDEN_SCOPE,
    }
    kwargs.update(overrides)
    return ScopeManifest(**kwargs)


def policy_with_golden() -> RoutePolicy:
    return RoutePolicy(jira=golden_policy())


def make_request(
    *, service="jira", method="GET", path="/", query=(), accept="application/json",
    body=b"", sentinel="s" * 43,
) -> ParsedRequest:
    return ParsedRequest(
        service=service, method=method, path=path, query=query, accept=accept, body=body,
        sentinel=sentinel,
    )


def ambiguous_policy_and_manifest(*, run_id: str = "run-amb"):
    """Two templates whose renderings collide on a single jql (plan L494-496)."""
    templates = ('x = "a" y = "{label}"', 'x = "{label}" y = "z"')
    policy = JiraVenuePolicy(
        revision="policy-amb", project_id="1", project_key="AA", issue_type_id="1",
        issue_fields=("issuetype", "project"),
        search_fields=("issuetype", "labels", "project", "status"),
        search_templates=templates, search_max_results=10,
        open_status_category_keys=("new",),
    )
    manifest = ScopeManifest(
        service="jira", run_id=run_id, attempt_id="attempt-1", rehearsal_id="rehearsal-1",
        revision="scope-amb", routes=("jira.search",), policy_digest=policy.digest,
        scope=JiraScope(issues=(), search_labels=("a", "z")),
    )
    return policy, manifest


def assert_denied(call, *, code: str, route_id: str, service: str = "jira") -> RoutePolicyError:
    with pytest.raises(RoutePolicyError) as caught:
        call()
    error = caught.value
    assert error.code == code
    assert error.args == (code,)
    assert error.route_id == route_id
    assert error.receipt_reason == ROUTE_ERROR_REASONS[code]
    assert error.request_digest == denied_request_digest(service, route_id)
    return error


# --- raw HTTP composition (real forwarder_http.parse_request, no shortcuts) ---

DEFAULT_SENTINEL = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def raw_request(
    service: str, method: str, path: str, *, query: str = "", body: bytes = b"",
    accept: str = "application/json", sentinel: str = "",
) -> bytes:
    profile = SERVICE_PROFILES[service]
    token = sentinel or DEFAULT_SENTINEL
    credential = (
        "Basic " + base64.b64encode(f"run:{token}".encode()).decode()
        if profile.sentinel_scheme == "Basic" else f"Bearer {token}"
    )
    lines = [
        f"{method} {path}{query} HTTP/1.1",
        f"Host: {profile.server_name}:{profile.port}",
        f"Authorization: {credential}",
        f"Accept: {accept}",
    ]
    if method != "GET":
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def raw_jira_get(sentinel: str, target: str) -> bytes:
    path, _, query = target.partition("?")
    return raw_request("jira", "GET", path, query=("?" + query if query else ""),
                       sentinel=sentinel)


def native_parsed(
    policy: RoutePolicy, service: str, method: str, path: str, *, query: str = "",
    body: bytes = b"", header_accept: str | None = None,
) -> ParsedRequest:
    opts = policy.parser_options(service)
    accept_sent = header_accept if header_accept is not None else opts.accept
    raw = raw_request(service, method, path, query=query, body=body, accept=accept_sent)
    return parse_request(raw, service, allowed_query_keys=opts.allowed_query_keys,
                         accept=opts.accept)


# --- exception-chain leak walk (same discipline as forwarder_json's own) -----


def _leak_surface(node: object, seen: set):
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


def assert_no_leak(error: BaseException, marker: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    marker_bytes = marker.encode("utf-8")
    for value in _leak_surface(error, set()):
        if isinstance(value, str):
            assert marker not in value, f"marker leaked as str: {value!r}"
        else:
            assert marker_bytes not in bytes(value), f"marker leaked as bytes: {value!r}"


# === RoutePolicyError exception-chain walk ===================================


def _rpe_request_invalid() -> None:
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101", body=f'{{"m":"{MARKER}"}}'.encode())
    policy.route(request, golden_manifest())


def _rpe_selector_invalid() -> None:
    policy = policy_with_golden()
    request = make_request(path=f"/rest/api/3/issue/{MARKER}")
    policy.route(request, golden_manifest())


def _rpe_query_rejected() -> None:
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101", query=(("fields", MARKER),))
    policy.route(request, golden_manifest())


def _rpe_body_rejected_syntax() -> None:
    policy = policy_with_golden()
    body = f'{{"jql":"{MARKER}"}} trailing'.encode()
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    policy.route(request, golden_manifest())


def _rpe_body_rejected_encoding() -> None:
    policy = policy_with_golden()
    body = b'{"jql":"' + MARKER.encode() + b"\xff\xfe" + b'"}'
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    policy.route(request, golden_manifest())


def _rpe_body_rejected_shape() -> None:
    policy = policy_with_golden()
    body = canonical_json({"jql": "x", "extra": MARKER})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    policy.route(request, golden_manifest())


def _rpe_service_unavailable() -> None:
    policy = policy_with_golden()
    request = ParsedRequest(
        service="grafana", method="GET", path="/api/search", query=(), accept="application/json",
        body=f'{{"m":"{MARKER}"}}'.encode(), sentinel="s" * 43,
    )
    policy.route(request, golden_manifest())


def _rpe_manifest_mismatch() -> None:
    policy = policy_with_golden()
    manifest = golden_manifest(run_id=MARKER, policy_digest="0" * 64)
    request = make_request(path="/rest/api/3/issue/90101")
    policy.route(request, manifest)


def _rpe_route_unknown() -> None:
    policy = policy_with_golden()
    request = make_request(path=f"/{MARKER}/x")
    policy.route(request, golden_manifest())


def _rpe_route_not_in_scope() -> None:
    policy = policy_with_golden()
    manifest = golden_manifest(
        routes=("jira.search",),
        scope=JiraScope(issues=(), search_labels=("fp-0123456789abcdef",)),
    )
    request = make_request(path=f"/rest/api/3/issue/{MARKER}")
    policy.route(request, manifest)


def _rpe_selector_out_of_scope() -> None:
    policy = policy_with_golden()
    manifest = golden_manifest(run_id=MARKER)
    request = make_request(path="/rest/api/3/issue/999999999999999999")
    policy.route(request, manifest)


def _rpe_selector_ambiguous() -> None:
    policy_obj, manifest = ambiguous_policy_and_manifest(run_id=MARKER)
    policy = RoutePolicy(jira=policy_obj)
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": 'x = "a" y = "z"'}),
    )
    policy.route(request, manifest)


_POLICY_MARKER_CASES = [
    ("request_invalid", "jira", "jira.issue.get", _rpe_request_invalid),
    ("selector_invalid", "jira", "jira.issue.get", _rpe_selector_invalid),
    ("query_rejected", "jira", "jira.issue.get", _rpe_query_rejected),
    ("body_rejected", "jira", "jira.search", _rpe_body_rejected_syntax),
    ("body_rejected", "jira", "jira.search", _rpe_body_rejected_encoding),
    ("body_rejected", "jira", "jira.search", _rpe_body_rejected_shape),
    ("service_unavailable", "grafana", UNMATCHED_ROUTE_ID, _rpe_service_unavailable),
    ("manifest_mismatch", "jira", UNMATCHED_ROUTE_ID, _rpe_manifest_mismatch),
    ("route_unknown", "jira", UNMATCHED_ROUTE_ID, _rpe_route_unknown),
    ("route_not_in_scope", "jira", "jira.issue.get", _rpe_route_not_in_scope),
    ("selector_out_of_scope", "jira", "jira.issue.get", _rpe_selector_out_of_scope),
    ("selector_ambiguous", "jira", "jira.search", _rpe_selector_ambiguous),
]


@pytest.mark.parametrize(
    "code,service,route_id,case", _POLICY_MARKER_CASES,
    ids=[f"{c}-{i}" for i, (c, *_rest) in enumerate(_POLICY_MARKER_CASES)],
)
def test_route_policy_error_chain_carries_no_marker(code, service, route_id, case):
    with pytest.raises(RoutePolicyError) as caught:
        case()
    error = caught.value
    assert error.code == code
    assert error.route_id == route_id
    assert error.request_digest == denied_request_digest(service, route_id)
    assert_no_leak(error, MARKER)


def test_route_policy_error_upstream_unbuildable_chain_carries_no_marker(monkeypatch):
    policy = policy_with_golden()

    def _raiser(_value):
        raise RouteConfigError(MARKER)

    monkeypatch.setattr(fr, "encode_query_value", _raiser)
    request = make_request(path="/rest/api/3/issue/90101")
    with pytest.raises(RoutePolicyError) as caught:
        policy.route(request, golden_manifest())
    error = caught.value
    assert error.code == "upstream_unbuildable"
    assert error.route_id == "jira.issue.get"
    assert error.request_digest == denied_request_digest("jira", "jira.issue.get")
    assert_no_leak(error, MARKER)


def test_every_route_policy_error_code_has_a_marker_case():
    covered = {code for code, *_rest in _POLICY_MARKER_CASES} | {"upstream_unbuildable"}
    assert covered == set(ROUTE_ERROR_REASONS)


# === RouteConfigError exception-chain walk ====================================

ROUTE_CONFIG_ERROR_CODES = frozenset({
    "policy_invalid", "policy_too_large", "manifest_invalid",
    "manifest_too_large", "manifest_binding_mismatch", "digest_input_invalid",
})


def _rce_policy_invalid() -> None:
    golden_policy(revision=MARKER, search_max_results=0)


def _rce_policy_too_large() -> None:
    def padded(suffix: str) -> str:
        prefix = f'{MARKER}-{suffix} "{{label}}"'
        return prefix + "x" * (MAX_TEMPLATE_BYTES - len(prefix))

    templates = tuple(padded(str(i)) for i in range(8))
    golden_policy(search_templates=templates)


def _rce_manifest_invalid_dataclass() -> None:
    ScopeManifest(
        service="confluence", run_id=MARKER, attempt_id="attempt-1", rehearsal_id="rehearsal-1",
        revision="scope-r1", routes=("jira.issue.get",), policy_digest=POLICY_DIGEST,
        scope=GOLDEN_SCOPE,
    )


def _rce_manifest_invalid_parse() -> None:
    data = f'{{"m":"{MARKER}"}} trailing'.encode()
    parse_scope_manifest(data)


def _rce_manifest_too_large() -> None:
    data = b'{"m":"' + MARKER.encode() + b'","pad":"' + b"a" * 20_000 + b'"}'
    parse_scope_manifest(data)


def _rce_manifest_binding_mismatch() -> None:
    require_manifest_binding(
        golden_manifest(), service="jira", run_id=MARKER, attempt_id="attempt-1",
        scope_digest=SCOPE_DIGEST,
    )


def _rce_digest_input_invalid() -> None:
    denied_request_digest("jira", MARKER)


_CONFIG_MARKER_CASES = [
    ("policy_invalid", _rce_policy_invalid),
    ("policy_too_large", _rce_policy_too_large),
    ("manifest_invalid", _rce_manifest_invalid_dataclass),
    ("manifest_invalid", _rce_manifest_invalid_parse),
    ("manifest_too_large", _rce_manifest_too_large),
    ("manifest_binding_mismatch", _rce_manifest_binding_mismatch),
    ("digest_input_invalid", _rce_digest_input_invalid),
]


@pytest.mark.parametrize(
    "code,case", _CONFIG_MARKER_CASES,
    ids=[f"{c}-{i}" for i, (c, _case) in enumerate(_CONFIG_MARKER_CASES)],
)
def test_route_config_error_chain_carries_no_marker(code, case):
    with pytest.raises(RouteConfigError) as caught:
        case()
    error = caught.value
    assert error.code == code
    assert error.args == (code,)
    assert_no_leak(error, MARKER)


def test_every_route_config_error_code_has_a_marker_case():
    assert {code for code, _case in _CONFIG_MARKER_CASES} == ROUTE_CONFIG_ERROR_CODES


def test_marker_cases_run_outside_any_active_exception_handler(monkeypatch):
    assert sys.exc_info() == (None, None, None)
    for _code, _service, _route_id, case in _POLICY_MARKER_CASES:
        with pytest.raises(RoutePolicyError):
            case()
        assert sys.exc_info() == (None, None, None)
    for _code, case in _CONFIG_MARKER_CASES:
        with pytest.raises(RouteConfigError):
            case()
        assert sys.exc_info() == (None, None, None)

    def _raiser(_value):
        raise RouteConfigError(MARKER)

    monkeypatch.setattr(fr, "encode_query_value", _raiser)
    with pytest.raises(RoutePolicyError):
        policy_with_golden().route(make_request(path="/rest/api/3/issue/90101"), golden_manifest())
    assert sys.exc_info() == (None, None, None)


# === AST checks ===============================================================

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ROUTES_MODULE_PATH = _REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_routes.py"
_JSON_MODULE_PATH = _REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_json.py"

_ROUTES_ABSOLUTE_ALLOWED = frozenset({
    "__future__", "collections.abc", "dataclasses", "hashlib", "hmac", "re",
    "threading", "types", "weakref",
})
_ROUTES_RELATIVE_ALLOWED = frozenset({
    "forwarder_json", "forwarder_http", "forwarder_http_response", "forwarder_services",
})
_ROUTES_RELATIVE_SYMBOLS = {
    "forwarder_http": frozenset({"ParsedRequest"}),
    "forwarder_http_response": frozenset({"ParsedResponse", "serialize_response", "HTTPResponseError"}),
    "forwarder_json": frozenset({"JSONPolicyError", "canonical_json", "parse_json", "tagged_digest"}),
    "forwarder_services": frozenset({"SERVICE_PROFILES"}),
}
_JSON_ABSOLUTE_ALLOWED = frozenset({"__future__", "dataclasses", "hashlib", "json", "math", "re"})


def _module_ast(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _collect_imports(tree: ast.Module):
    absolute_modules: set[str] = set()
    relative_symbols: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                absolute_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                assert node.module is not None
                absolute_modules.add(node.module)
            elif node.level == 1:
                assert node.module is not None
                relative_symbols.setdefault(node.module, set()).update(
                    alias.name for alias in node.names
                )
            else:
                raise AssertionError(f"unexpected import level {node.level}")
        elif isinstance(node, ast.Call):
            target = node.func
            is_dunder_import = isinstance(target, ast.Name) and target.id == "__import__"
            is_importlib = isinstance(target, ast.Attribute) and target.attr == "import_module"
            assert not is_dunder_import and not is_importlib, "dynamic import call found"
    return absolute_modules, relative_symbols


@pytest.mark.parametrize("path", [_ROUTES_MODULE_PATH, _JSON_MODULE_PATH], ids=["routes", "json"])
def test_no_raise_inside_any_except_handler(path):
    tree = _module_ast(path)
    handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]
    assert handlers, "sanity: module has handlers to check"
    for handler in handlers:
        for inner in ast.walk(handler):
            assert not isinstance(inner, ast.Raise), (
                f"raise inside except handler at {path.name}:{inner.lineno}"
            )


def test_routes_import_allowlist_is_exact():
    absolute_modules, relative_symbols = _collect_imports(_module_ast(_ROUTES_MODULE_PATH))
    assert absolute_modules == _ROUTES_ABSOLUTE_ALLOWED
    assert set(relative_symbols) == _ROUTES_RELATIVE_ALLOWED
    for module, expected in _ROUTES_RELATIVE_SYMBOLS.items():
        assert relative_symbols[module] == expected


def test_routes_does_not_import_leases_or_receipts():
    _absolute, relative_symbols = _collect_imports(_module_ast(_ROUTES_MODULE_PATH))
    assert "forwarder_leases" not in relative_symbols
    assert "forwarder_receipts" not in relative_symbols


def test_json_import_allowlist_is_exact_and_has_no_relative_imports():
    absolute_modules, relative_symbols = _collect_imports(_module_ast(_JSON_MODULE_PATH))
    assert absolute_modules == _JSON_ABSOLUTE_ALLOWED
    assert relative_symbols == {}


# === sentinel isolation ========================================================

SENTINEL_A = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
SENTINEL_B = base64.urlsafe_b64encode(bytes(range(32))[::-1]).decode().rstrip("=")


def test_sentinel_never_reaches_the_upstream_target_body_or_digest():
    policy = policy_with_golden()
    manifest = golden_manifest()
    parsed_a = parse_request(raw_jira_get(SENTINEL_A, ISSUE_GET_TARGET), "jira",
                             allowed_query_keys=frozenset({"fields"}))
    parsed_b = parse_request(raw_jira_get(SENTINEL_B, ISSUE_GET_TARGET), "jira",
                             allowed_query_keys=frozenset({"fields"}))
    assert parsed_a.sentinel == SENTINEL_A
    assert parsed_b.sentinel == SENTINEL_B
    assert parsed_a.sentinel != parsed_b.sentinel

    routed_a = policy.route(parsed_a, manifest)
    routed_b = policy.route(parsed_b, manifest)
    assert routed_a.request_digest == routed_b.request_digest

    for sentinel in (SENTINEL_A, SENTINEL_B):
        assert sentinel not in routed_a.upstream.target
        assert sentinel.encode() not in routed_a.upstream.body
        assert sentinel not in routed_a.request_digest


def test_sentinel_never_reaches_a_search_upstream_body_or_digest():
    policy = policy_with_golden()
    manifest = golden_manifest()
    body = canonical_json({"jql": GOLDEN_JQL})
    raw_a = raw_request("jira", "POST", "/rest/api/3/search/jql", body=body, sentinel=SENTINEL_A)
    raw_b = raw_request("jira", "POST", "/rest/api/3/search/jql", body=body, sentinel=SENTINEL_B)
    parsed_a = parse_request(raw_a, "jira", allowed_query_keys=frozenset({"fields"}))
    parsed_b = parse_request(raw_b, "jira", allowed_query_keys=frozenset({"fields"}))
    routed_a = policy.route(parsed_a, manifest)
    routed_b = policy.route(parsed_b, manifest)
    assert routed_a.request_digest == routed_b.request_digest
    for sentinel in (SENTINEL_A, SENTINEL_B):
        assert sentinel.encode() not in routed_a.upstream.body


# === native-form matrix, split by listener ====================================

_JIRA_UNAVAILABLE_NATIVE_FORMS = [
    ("POST", "/rest/api/3/issue", b'{"fields":{}}'),
    ("PUT", "/rest/api/3/issue/SYN-1", b'{"fields":{}}'),
    ("DELETE", "/rest/api/3/issue/SYN-1", b"{}"),
    ("GET", "/rest/api/3/issue/SYN-1/comment", b""),
    ("POST", "/rest/api/3/issue/SYN-1/comment", b'{"body":{}}'),
    ("GET", "/rest/api/3/comment/10001", b""),
    ("POST", "/rest/api/3/issue/SYN-1/transitions", b'{"transition":{"id":"1"}}'),
    ("GET", "/rest/api/3/search/jql", b""),
    ("POST", "/rest/api/3/search", b'{"jql":"x"}'),
    # POST-only: a non-GET/non-POST verb at the exact search path (F3-16).
    ("PUT", "/rest/api/3/search/jql", b'{"jql":"x"}'),
    ("DELETE", "/rest/api/3/search/jql", b""),
    # Case-sensitive, exact path matching for the search route (F3-26).
    ("POST", "/rest/api/3/search/JQL", b'{"jql":"x"}'),
    ("POST", "/rest/api/3/Search/jql", b'{"jql":"x"}'),
]


@pytest.mark.parametrize("method,path,body", _JIRA_UNAVAILABLE_NATIVE_FORMS)
def test_jira_native_unavailable_forms_give_route_unknown(method, path, body):
    policy = policy_with_golden()
    parsed = native_parsed(policy, "jira", method, path, body=body)
    assert_denied(lambda: policy.route(parsed, golden_manifest()),
                 code="route_unknown", route_id=UNMATCHED_ROUTE_ID, service="jira")


def test_jira_native_form_with_jira_none_gives_service_unavailable():
    policy = RoutePolicy(jira=None)
    parsed = native_parsed(policy, "jira", "GET", "/rest/api/3/issue/SYN-1")
    assert_denied(lambda: policy.route(parsed, golden_manifest()),
                 code="service_unavailable", route_id=UNMATCHED_ROUTE_ID, service="jira")


_NON_JIRA_NATIVE_FORMS = [
    ("confluence", "GET", "/wiki/api/v2/pages/123", b""),
    ("kubernetes", "GET", "/api/v1/namespaces/ns/pods", b""),
    ("kubernetes", "GET", "/api/v1/namespaces/ns/events", b""),
    ("kubernetes", "GET", "/apis/discovery.k8s.io/v1/namespaces/ns/endpointslices", b""),
    ("grafana", "GET", "/api/datasources/proxy/uid/x/api/v1/query", b""),
    ("grafana", "GET", "/loki/api/v1/query_range", b""),
    ("grafana", "GET", "/api/search", b""),
    ("anthropic", "POST", "/v1/messages", b'{"model":"x"}'),
]


@pytest.mark.parametrize("service,method,path,body", _NON_JIRA_NATIVE_FORMS)
def test_non_jira_native_forms_give_service_unavailable(service, method, path, body):
    policy = policy_with_golden()
    parsed = native_parsed(policy, service, method, path, body=body)
    assert_denied(lambda: policy.route(parsed, golden_manifest()),
                 code="service_unavailable", route_id=UNMATCHED_ROUTE_ID, service=service)


# (service, method, path, query_key, query_value) -- one disallowed key per form.
_QUERY_SMUGGLE_FORMS = [
    ("confluence", "GET", "/wiki/api/v2/pages/123", "expand", "body"),
    ("kubernetes", "GET", "/api/v1/namespaces/ns/pods", "labelSelector", "app-web"),
    ("kubernetes", "GET", "/api/v1/namespaces/ns/events", "fieldSelector", "reason-Failed"),
    ("kubernetes", "GET", "/apis/discovery.k8s.io/v1/namespaces/ns/endpointslices", "limit", "5"),
    ("grafana", "GET", "/api/datasources/proxy/uid/x/api/v1/query", "query", "up"),
    ("grafana", "GET", "/loki/api/v1/query_range", "start", "0"),
    ("grafana", "GET", "/api/search", "q", "incident"),
    ("anthropic", "POST", "/v1/messages", "startAt", "0"),
]


@pytest.mark.parametrize("service,method,path,key,value", _QUERY_SMUGGLE_FORMS)
def test_undeclared_query_key_fails_at_parse_not_route(service, method, path, key, value):
    policy = policy_with_golden()
    opts = policy.parser_options(service)
    body = b'{"model":"x"}' if method == "POST" else b""
    raw = raw_request(service, method, path, query=f"?{key}={value}", body=body,
                      accept=opts.accept)
    with pytest.raises(HTTPBoundaryError):
        parse_request(raw, service, allowed_query_keys=opts.allowed_query_keys, accept=opts.accept)


def test_anthropic_event_stream_accept_fails_at_parse_not_route():
    policy = policy_with_golden()
    opts = policy.parser_options("anthropic")
    raw = raw_request("anthropic", "POST", "/v1/messages", body=b'{"model":"x"}',
                      accept="text/event-stream")
    with pytest.raises(HTTPBoundaryError):
        parse_request(raw, "anthropic", allowed_query_keys=opts.allowed_query_keys,
                      accept=opts.accept)


# === smuggling: selectors and paths ============================================


@pytest.mark.parametrize("selector", ["SYN-1%3B", "syn-1", "SYN-01", "SYN-1;x"])
def test_selector_smuggling_attempts_are_rejected(selector):
    policy = policy_with_golden()
    request = make_request(path=f"/rest/api/3/issue/{selector}")
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="selector_invalid", route_id="jira.issue.get")


def test_trailing_slash_selector_does_not_match_the_route():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/SYN-1/")
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="route_unknown", route_id=UNMATCHED_ROUTE_ID)


def test_capitalized_issue_segment_does_not_match_the_route():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/Issue/SYN-1")
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="route_unknown", route_id=UNMATCHED_ROUTE_ID)


def test_capitalized_search_path_does_not_match_the_route():
    # The search path is matched by exact, case-sensitive equality (plan:
    # "Matching uses exact, case-sensitive ASCII"), the same rule as the
    # issue.get path segments checked just above.
    policy = policy_with_golden()
    request = make_request(
        method="POST", path="/rest/api/3/Search/jql", body=canonical_json({"jql": GOLDEN_JQL}),
    )
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="route_unknown", route_id=UNMATCHED_ROUTE_ID)


def test_raw_semicolon_selector_is_rejected_through_real_http_parsing():
    policy = policy_with_golden()
    raw = raw_jira_get(SENTINEL_A, "/rest/api/3/issue/SYN-1;x")
    parsed = parse_request(raw, "jira", allowed_query_keys=frozenset({"fields"}))
    assert parsed.path == "/rest/api/3/issue/SYN-1;x"
    assert_denied(lambda: policy.route(parsed, golden_manifest()),
                 code="selector_invalid", route_id="jira.issue.get")


# === smuggling: fields =========================================================


@pytest.mark.parametrize("fields_value", [
    "issuetype,labels",
    "issuetype,labels,project,status,summary,resolution",
    "",
    "issuetype labels,project,status,summary",  # '+' decodes to a space at the HTTP layer
])
def test_issue_get_fields_smuggling_is_rejected(fields_value):
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101", query=(("fields", fields_value),))
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="query_rejected", route_id="jira.issue.get")


def test_fields_sent_to_search_query_is_rejected():
    policy = policy_with_golden()
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", query=(("fields", "issuetype"),),
        body=canonical_json({"jql": "x"}),
    )
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="query_rejected", route_id="jira.search")


# === smuggling: search bodies ==================================================


@pytest.mark.parametrize("body", [
    b'{"jql":"a","jql":"b"}',
    b'{"jql":"a","j\\u0071l":"b"}',
    b'{"jql":"a","nextPageToken":"x"}',
    b'{"jql":"a","expand":"names"}',
    b'{"jql":"a","properties":["p"]}',
    b'{"jql":"a","reconcileIssues":[1]}',
    b'["a"]',
    b'null',
    b'{"jql":\x0c"a"}',
    b'{"jql":\x0b"a"}',
    '{"jql": "a"}'.encode(),
])
def test_search_body_smuggling_is_rejected(body):
    policy = policy_with_golden()
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="body_rejected", route_id="jira.search")


# === smuggling: maxResults =====================================================


def _search_body_with_raw_max_results(literal: str) -> bytes:
    prefix = canonical_json({"jql": GOLDEN_JQL})[:-1]
    return prefix + b',"maxResults":' + literal.encode() + b'}'


@pytest.mark.parametrize("literal", ["true", "1.0", "1e1", '"50"', "0", "101", "-1"])
def test_max_results_smuggling_is_rejected(literal):
    policy = policy_with_golden()
    request = make_request(method="POST", path="/rest/api/3/search/jql",
                           body=_search_body_with_raw_max_results(literal))
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="body_rejected", route_id="jira.search")


# === smuggling: JQL =============================================================


def test_jql_with_appended_clause_breaks_the_template_match():
    policy = policy_with_golden()
    body = canonical_json({"jql": GOLDEN_JQL + ' OR project != SYN'})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="selector_out_of_scope", route_id="jira.search")


def test_jql_with_trailing_space_breaks_the_template_match():
    policy = policy_with_golden()
    body = canonical_json({"jql": GOLDEN_JQL + " "})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="selector_out_of_scope", route_id="jira.search")


@pytest.mark.parametrize("candidate_label", [
    GOLDEN_LABEL.replace("0", "０"),  # fullwidth digit lookalike
    GOLDEN_LABEL.upper(),                 # case variant
])
def test_jql_label_lookalikes_do_not_match_the_manifest_label(candidate_label):
    policy = policy_with_golden()
    prefix, suffix = golden_policy().search_templates[0].split("{label}")
    body = canonical_json({"jql": prefix + candidate_label + suffix})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="selector_out_of_scope", route_id="jira.search")


def test_jql_template_collision_gives_ambiguous_not_a_silent_pick():
    policy_obj, manifest = ambiguous_policy_and_manifest()
    policy = RoutePolicy(jira=policy_obj)
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": 'x = "a" y = "z"'}),
    )
    assert_denied(lambda: policy.route(request, manifest),
                 code="selector_ambiguous", route_id="jira.search")


def test_jql_exact_length_forged_suffix_is_rejected():
    """A forged suffix of exactly the golden suffix's length must not slip
    through on the strength of a length-preserving candidate slice alone;
    the ``endswith`` half of the boundary check must still be enforced."""
    policy = policy_with_golden()
    prefix, suffix = golden_policy().search_templates[0].split("{label}")
    evil_suffix = '" OR project != 90001'.ljust(len(suffix))
    body = canonical_json({"jql": prefix + GOLDEN_LABEL + evil_suffix})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="selector_out_of_scope", route_id="jira.search")


def test_jql_exact_length_forged_prefix_is_rejected():
    """The symmetric case: a forged prefix of exactly the golden prefix's
    length must not slip through; the ``startswith`` half must be enforced."""
    policy = policy_with_golden()
    prefix, suffix = golden_policy().search_templates[0].split("{label}")
    evil_prefix = 'project = 90009 OR labels = "'.rjust(len(prefix))
    body = canonical_json({"jql": evil_prefix + GOLDEN_LABEL + suffix})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(lambda: policy.route(request, golden_manifest()),
                 code="selector_out_of_scope", route_id="jira.search")


def test_search_upstream_body_is_rendered_from_the_template_not_the_caller_jql():
    """The rebuilt body's ``jql`` is always ``template.replace(label)``, never
    a copy of the caller's own jql string, so a matcher regression can never
    let caller bytes reach the upstream request."""
    policy = policy_with_golden()
    template = golden_policy().search_templates[0]
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": GOLDEN_JQL}),
    )
    routed = policy.route(request, golden_manifest())
    body = json.loads(routed.upstream.body)
    assert body["jql"] == template.replace("{label}", GOLDEN_LABEL)


def test_search_upstream_body_uses_the_matched_label_not_the_raw_caller_jql(monkeypatch):
    """A genuine template match forces ``jql == template.replace(label)``
    byte-for-byte (the candidate slice IS the label, by construction of
    ``_match_templates``), so the assertion above alone cannot distinguish
    "rendered from the template" from "copied the caller's jql verbatim" --
    both produce the identical string whenever the real matcher is used.

    Monkeypatch the matcher to report a label that is not in the caller's
    jql at all, simulating a matcher regression, and confirm the rebuilt
    body still follows the (template, label) pair returned by the matcher --
    never the caller's own jql -- which only ``template.replace(placeholder,
    label)`` can produce here.
    """
    policy = policy_with_golden()
    template = golden_policy().search_templates[0]
    forged_label = "fp-forgedforgedforg"

    def _forged_match(_templates, _labels, _jql):
        return [(template, forged_label)]

    monkeypatch.setattr(fr, "_match_templates", _forged_match)
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": GOLDEN_JQL}),
    )
    routed = policy.route(request, golden_manifest())
    body = json.loads(routed.upstream.body)
    assert body["jql"] == template.replace("{label}", forged_label)
    assert body["jql"] != GOLDEN_JQL


# === seeded request property ===================================================


def _random_selector(rng: random.Random) -> str:
    return rng.choice([
        "90101", "999999999999999999", "SYN-1", "SYN-999", "syn-1", "SYN-1x", "SYN-1;x",
        rng.randbytes(4).hex(),
    ])


def _random_search_body(rng: random.Random, policy: JiraVenuePolicy) -> bytes:
    label = rng.choice([GOLDEN_LABEL, "not-a-label", "fp-fedcba9876543210"])
    prefix, suffix = policy.search_templates[0].split("{label}")
    payload: dict[str, object] = {"jql": prefix + label + suffix}
    if rng.random() < 0.5:
        payload["maxResults"] = rng.choice([1, 10, 50, 101, 0])
    if rng.random() < 0.3:
        payload["fields"] = list(policy.search_fields)
    return canonical_json(payload)


def _random_request(rng: random.Random, policy: JiraVenuePolicy) -> ParsedRequest:
    kind = rng.choice(["issue_get", "search", "garbage_path", "wrong_method"])
    if kind == "issue_get":
        selector = _random_selector(rng)
        query = rng.choice([(), (("fields", ",".join(policy.issue_fields)),)])
        return make_request(path=f"/rest/api/3/issue/{selector}", query=query)
    if kind == "search":
        return make_request(method="POST", path="/rest/api/3/search/jql",
                            body=_random_search_body(rng, policy))
    if kind == "garbage_path":
        segment = rng.choice(["issue", "search"])
        return make_request(path=f"/rest/api/3/{segment}/{rng.randbytes(4).hex()}")
    return make_request(method=rng.choice(["PUT", "DELETE"]), path="/rest/api/3/issue/90101")


def _rebuild_from_upstream(policy: RoutePolicy, upstream: fr.UpstreamRequest) -> ParsedRequest:
    """Round-trip the upstream through raw bytes and the real HTTP codec (plan:
    "rebuilt into raw bytes, re-parses"), not an ad hoc reconstruction."""
    path, _, query = upstream.target.partition("?")
    opts = policy.parser_options("jira")
    raw = raw_request(
        "jira", upstream.method, path, query=("?" + query if query else ""),
        body=upstream.body, accept=upstream.accept,
    )
    return parse_request(raw, "jira", allowed_query_keys=opts.allowed_query_keys, accept=opts.accept)


def test_seeded_property_route_is_idempotent_or_closes_with_a_closed_reason():
    policy = policy_with_golden()
    manifest = golden_manifest()
    rng = random.Random(20260922)
    for _ in range(200):
        request = _random_request(rng, golden_policy())
        try:
            routed = policy.route(request, manifest)
        except RoutePolicyError as error:
            assert error.code in ROUTE_ERROR_REASONS
            assert error.route_id in (*ROUTE_CATALOG, UNMATCHED_ROUTE_ID)
            assert re.fullmatch(r"[0-9a-f]{64}", error.request_digest)
            continue
        rebuilt = _rebuild_from_upstream(policy, routed.upstream)
        again = policy.route(rebuilt, manifest)
        assert again.request_digest == routed.request_digest


# === LeaseRegistry composition (one shared fake clock) =========================


class FakeClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


BOOT = "receiver-adv"


def new_registry():
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    return registry, clock


def register_and_activate(registry, clock, manifest, *, service="jira", run_id="run-1",
                          attempt_id="attempt-1", ttl=200.0):
    grant = registry.register(
        run_id=run_id, attempt_id=attempt_id, receiver_boot_id=BOOT, service=service,
        scope_digest=manifest.digest, expires_at=clock.value + ttl, generation=registry.generation,
    )
    registry.activate(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                      generation=registry.generation, launch_at=clock.value)
    return grant


def test_lease_composition_binds_manifest_and_authorizes_the_matching_check():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)

    require_manifest_binding(manifest, service=grant.service, run_id=grant.run_id,
                             attempt_id=grant.attempt_id, scope_digest=grant.scope_digest)
    store_entry = {
        "lease_id": grant.lease_id, "attempt_id": grant.attempt_id,
        "generation": grant.generation, "manifest": manifest,
    }
    lease = registry.check(service="jira", sentinel=grant.sentinel,
                           generation=store_entry["generation"],
                           scope_digest=store_entry["manifest"].digest)
    assert lease.authorized is True
    assert lease.lease_id == store_entry["lease_id"]


@pytest.mark.parametrize("field,overrides", [
    ("revision", {"revision": "scope-r2"}),
    ("routes", {"routes": ("jira.issue.get",),
               "scope": JiraScope(issues=GOLDEN_SCOPE.issues, search_labels=())}),
    ("attempt_id", {"attempt_id": "attempt-2"}),
    ("policy_digest", {"policy_digest": "0" * 64}),
    ("label", {"scope": JiraScope(issues=GOLDEN_SCOPE.issues,
                                  search_labels=("fp-fedcba9876543210",))}),
])
def test_lease_check_denies_a_manifest_that_differs_in_one_field(field, overrides):
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)
    mutated = golden_manifest(**overrides)
    assert mutated.digest != manifest.digest

    lease = registry.check(service="jira", sentinel=grant.sentinel,
                           generation=registry.generation, scope_digest=mutated.digest)
    assert lease.authorized is False
    assert lease.reason == "scope_mismatch"


def test_store_installation_refuses_mismatched_or_non_jira_grants():
    registry, clock = new_registry()
    manifest = golden_manifest()
    jira_grant = register_and_activate(registry, clock, manifest, service="jira")

    with pytest.raises(RouteConfigError) as caught:
        require_manifest_binding(manifest, service="jira", run_id="wrong-run",
                                 attempt_id=jira_grant.attempt_id,
                                 scope_digest=jira_grant.scope_digest)
    assert caught.value.code == "manifest_binding_mismatch"

    grafana_grant = registry.register(
        run_id="run-g", attempt_id="attempt-g", receiver_boot_id=BOOT, service="grafana",
        scope_digest=sha256(b"grafana-scope").hexdigest(), expires_at=clock.value + 100.0,
        generation=registry.generation,
    )
    with pytest.raises(RouteConfigError) as caught:
        require_manifest_binding(manifest, service=grafana_grant.service,
                                 run_id=grafana_grant.run_id, attempt_id=grafana_grant.attempt_id,
                                 scope_digest=grafana_grant.scope_digest)
    assert caught.value.code == "manifest_binding_mismatch"


def test_stale_stored_generation_denies_the_lease_check():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)

    restarted = LeaseRegistry(clock=clock)
    restarted.handshake(receiver_boot_id=BOOT, generation=restarted.generation)
    lease = restarted.check(service="jira", sentinel=grant.sentinel,
                            generation=grant.generation, scope_digest=manifest.digest)
    assert lease.authorized is False
    assert lease.reason == "generation_mismatch"


def test_changed_policy_with_old_manifest_gives_manifest_mismatch():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)
    lease = registry.check(service="jira", sentinel=grant.sentinel,
                           generation=registry.generation, scope_digest=manifest.digest)
    assert lease.authorized is True

    policy = RoutePolicy(jira=golden_policy(revision="policy-r2"))
    request = make_request(path="/rest/api/3/issue/90101")
    assert_denied(lambda: policy.route(request, manifest), code="manifest_mismatch",
                 route_id=UNMATCHED_ROUTE_ID)


def test_revoked_lease_denies_even_though_routing_succeeds():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                    generation=registry.generation, reason="operator_cancel")

    policy = policy_with_golden()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    assert routed.route_id == "jira.issue.get"

    lease = registry.check(service="jira", sentinel=grant.sentinel,
                           generation=registry.generation, scope_digest=manifest.digest)
    assert lease.authorized is False
    assert lease.reason == "lease_revoked"


def test_expired_lease_denies_even_though_routing_succeeds():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest, ttl=10.0)
    clock.advance(11.0)

    policy = policy_with_golden()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    assert routed.route_id == "jira.issue.get"

    lease = registry.check(service="jira", sentinel=grant.sentinel,
                           generation=registry.generation, scope_digest=manifest.digest)
    assert lease.authorized is False


# === ReceiptLedger composition (same shared fake clock) ========================

_OK_ISSUE_BODY = canonical_json({
    "id": "90101", "key": "SYN-1",
    "fields": {"project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"}},
})


def test_receipt_ledger_composition_ok_and_rejected_upstream():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    policy = policy_with_golden()

    raw = raw_jira_get(grant.sentinel, ISSUE_GET_TARGET)
    parsed = parse_request(raw, "jira", allowed_query_keys=frozenset({"fields"}))
    routed = policy.route(parsed, manifest)
    deadline = min(clock.value + MAX_HANDLER_SECONDS, grant.expires_at)

    reservation = ledger.reserve(lease_id=grant.lease_id, attempt_id=grant.attempt_id,
                                 service="jira", route_id=routed.route_id,
                                 request_digest=routed.request_digest, request_bytes=len(raw),
                                 deadline=deadline)
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    ok_response = ParsedResponse(status=200, body=_OK_ISSUE_BODY)
    verdict = policy.check_response(routed, ok_response)
    assert verdict.receipt_reason == "ok"
    receipt = ledger.finalize(reservation, dispatch_state="TRANSPORT_CONFIRMED",
                              reason=verdict.receipt_reason, upstream_response=ok_response)
    assert receipt.client_response_digest == response_digest(ok_response)
    assert receipt.generation == registry.generation

    reservation2 = ledger.reserve(lease_id=grant.lease_id, attempt_id=grant.attempt_id,
                                  service="jira", route_id=routed.route_id,
                                  request_digest=routed.request_digest, request_bytes=len(raw),
                                  deadline=deadline)
    ledger.begin_connect(reservation2)
    ledger.begin_dispatch(reservation2)
    bad_response = ParsedResponse(status=404, body=b'{"errorMessages":["nope"]}')
    verdict2 = policy.check_response(routed, bad_response)
    assert verdict2.receipt_reason == "response_policy_rejected"
    receipt2 = ledger.finalize(reservation2, dispatch_state="TRANSPORT_CONFIRMED",
                               reason=verdict2.receipt_reason, upstream_response=bad_response)
    assert receipt2.http_status_class == "4xx"
    assert local_response_for(receipt2).status == 502


def test_full_dispatch_seam_runs_parse_bind_check_route_reserve_in_documented_order():
    """Plan's dispatch seam, all five steps in order: parse -> require_manifest_binding
    -> registry.check (stored generation, lease_id match) -> policy.route -> ledger.reserve,
    with the deadline clipped by all three of the plan's terms."""
    registry, clock = new_registry()
    manifest = golden_manifest()
    policy = policy_with_golden()
    launch_at = clock.value
    grant = register_and_activate(registry, clock, manifest, ttl=200.0)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)

    raw = raw_jira_get(grant.sentinel, ISSUE_GET_TARGET)
    parsed = parse_request(raw, "jira", allowed_query_keys=frozenset({"fields"}))

    store_entry = {
        "lease_id": grant.lease_id, "generation": grant.generation, "manifest": manifest,
    }
    require_manifest_binding(store_entry["manifest"], service=grant.service, run_id=grant.run_id,
                             attempt_id=grant.attempt_id, scope_digest=grant.scope_digest)
    lease = registry.check(service="jira", sentinel=grant.sentinel,
                           generation=store_entry["generation"],
                           scope_digest=store_entry["manifest"].digest)
    assert lease.authorized is True
    assert lease.lease_id == store_entry["lease_id"]

    routed = policy.route(parsed, store_entry["manifest"])

    deadline = min(
        clock.value + MAX_HANDLER_SECONDS, grant.expires_at, launch_at + LEASE_SECONDS,
    )
    reservation = ledger.reserve(lease_id=lease.lease_id, attempt_id=grant.attempt_id,
                                 service="jira", route_id=routed.route_id,
                                 request_digest=routed.request_digest, request_bytes=len(raw),
                                 deadline=deadline)
    ledger.begin_connect(reservation)
    ledger.begin_dispatch(reservation)
    response = ParsedResponse(status=200, body=_OK_ISSUE_BODY)
    verdict = policy.check_response(routed, response)
    assert verdict.receipt_reason == "ok"
    receipt = ledger.finalize(reservation, dispatch_state="TRANSPORT_CONFIRMED",
                              reason=verdict.receipt_reason, upstream_response=response)
    assert receipt.generation == grant.generation


def test_lease_denial_seam_reserves_with_unmatched_digest_and_gives_403():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)

    restarted = LeaseRegistry(clock=clock)
    restarted.handshake(receiver_boot_id=BOOT, generation=restarted.generation)
    lease = restarted.check(service="jira", sentinel=grant.sentinel,
                            generation=grant.generation, scope_digest=manifest.digest)
    assert lease.authorized is False

    route_id = UNMATCHED_ROUTE_ID
    digest = denied_request_digest("jira", route_id)
    reservation = ledger.reserve(lease_id=grant.lease_id, attempt_id=grant.attempt_id,
                                 service="jira", route_id=route_id, request_digest=digest,
                                 request_bytes=256, deadline=clock.value + 30.0)
    receipt = ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED", reason="lease_denied")
    assert local_response_for(receipt).status == 403


def test_denial_reserve_and_finalize_gives_400_or_403():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = register_and_activate(registry, clock, manifest)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    policy = policy_with_golden()

    bad_request = make_request(path="/rest/api/3/issue/90101", body=b'{"not":"empty"}')
    with pytest.raises(RoutePolicyError) as caught:
        policy.route(bad_request, manifest)
    error = caught.value
    reservation = ledger.reserve(lease_id=grant.lease_id, attempt_id=grant.attempt_id,
                                 service="jira", route_id=error.route_id,
                                 request_digest=error.request_digest, request_bytes=64,
                                 deadline=clock.value + 30.0)
    receipt = ledger.finalize(reservation, dispatch_state="NOT_DISPATCHED",
                              reason=error.receipt_reason)
    assert local_response_for(receipt).status == 400

    denied_request = make_request(path="/rest/api/3/issue/999999999999999999")
    with pytest.raises(RoutePolicyError) as caught:
        policy.route(denied_request, manifest)
    error2 = caught.value
    reservation2 = ledger.reserve(lease_id=grant.lease_id, attempt_id=grant.attempt_id,
                                  service="jira", route_id=error2.route_id,
                                  request_digest=error2.request_digest, request_bytes=64,
                                  deadline=clock.value + 30.0)
    receipt2 = ledger.finalize(reservation2, dispatch_state="NOT_DISPATCHED",
                               reason=error2.receipt_reason)
    assert local_response_for(receipt2).status == 403


# === identity ====================================================================


def test_check_response_identity_rejects_forged_replaced_and_foreign_routed_requests():
    policy = policy_with_golden()
    manifest = golden_manifest()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    response = ParsedResponse(status=200, body=_OK_ISSUE_BODY)

    forged = fr.RoutedRequest(
        route_id=routed.route_id, service=routed.service, scope_digest=routed.scope_digest,
        policy_digest=routed.policy_digest, request_digest=routed.request_digest,
        requires_permit=routed.requires_permit, upstream=routed.upstream,
        selection=routed.selection,
    )
    replaced = dataclasses.replace(routed)
    foreign = policy_with_golden().route(make_request(path="/rest/api/3/issue/90101"), manifest)

    for candidate in (forged, replaced, foreign):
        verdict = policy.check_response(candidate, response)
        assert verdict.receipt_reason == "response_policy_rejected"
        assert verdict.detail == "routed_unknown"

    assert policy.check_response(routed, response).receipt_reason == "ok"


# === purity ========================================================================


def test_route_policy_never_touches_socket_or_the_wall_clock(monkeypatch):
    def _raiser(*_args, **_kwargs):
        raise AssertionError("forwarder_routes must never touch this")

    monkeypatch.setattr(socket, "socket", _raiser)
    monkeypatch.setattr(time, "monotonic", _raiser)
    monkeypatch.setattr(time, "time", _raiser)

    policy = policy_with_golden()
    manifest = golden_manifest()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=_OK_ISSUE_BODY))
    assert verdict.receipt_reason == "ok"
    assert parse_scope_manifest(MANIFEST_CANONICAL_BYTES).digest == SCOPE_DIGEST
    assert encode_query_value("a b") == "a%20b"
    denied_request_digest("jira", "unmatched")


# === grammar compatibility =========================================================


def test_route_ids_are_accepted_by_the_receipts_safe_id_grammar():
    clock = FakeClock()
    ledger = ReceiptLedger(generation="adv-generation", clock=clock)
    dummy_digest = "f" * 64
    for route_id in (*ROUTE_CATALOG, UNMATCHED_ROUTE_ID):
        reservation = ledger.reserve(
            lease_id="lease-1", attempt_id="attempt-1", service="jira", route_id=route_id,
            request_digest=dummy_digest, request_bytes=10, deadline=clock.value + 5.0,
        )
        assert reservation is not None


def test_manifest_safe_ids_are_accepted_by_the_lease_registry_grammar():
    registry, clock = new_registry()
    manifest = golden_manifest()
    grant = registry.register(
        run_id=manifest.run_id, attempt_id=manifest.attempt_id, receiver_boot_id=BOOT,
        service="jira", scope_digest=manifest.digest, expires_at=clock.value + 50.0,
        generation=registry.generation,
    )
    assert grant.run_id == manifest.run_id
    assert grant.attempt_id == manifest.attempt_id
