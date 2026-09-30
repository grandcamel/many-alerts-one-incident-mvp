"""Adversarial tests for the synthetic fixed-origin Jira upstream connector
(Tester C, forwarder-upstream part).

Derived from the forwarder-upstream implementation plan's "Tester C" section,
not from ``forwarder_upstream.py``'s own implementation. These tests try to
break the connector: an exact AST import allowlist and forbidden-name/store
walk, the handler-body and call-site-count rules, the no-production-caller
repository walk, a generic marker walk over ``gc.get_referents``/traceback
frame locals for the credential secret, an exception-chain cleanliness walk
over every closed code, a real-TLS fixture-captured property, the address and
host attack lists, and deadline widening.

Fixtures are reused by module import, following the existing ``tls_fixtures``
pattern: Tester A's deterministic helpers from ``tests.test_forwarder_upstream``
and Tester B's real-TLS fixtures from ``tests.test_forwarder_upstream_integration``.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import dataclasses
import gc
import logging
import random
import socket
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_response_receive as frr
from grafana_jsm_sandbox import forwarder_upstream as fu
from grafana_jsm_sandbox.forwarder_dispatch import CONNECT_SECONDS
from grafana_jsm_sandbox.forwarder_exchange import UPSTREAM_ERROR_CODES, UpstreamError
from grafana_jsm_sandbox.forwarder_routes import (
    ROUTE_CATALOG,
    RoutedRequest,
    UpstreamRequest,
    policy_readiness_facts,
)
from grafana_jsm_sandbox.forwarder_routes import request_digest as v1_request_digest
from tests import test_forwarder_server_tls_integration as tls_fixtures
from tests import test_forwarder_upstream_integration as upstream_fixtures
from tests.test_forwarder_exchange import (
    SERVICE,
    install_lease,
    new_real_system,
    ok_issue_get_body,
    policy_with_golden,
)
from tests.test_forwarder_exchange_integration import raw_get, roundtrip, serve_one_exchange
from tests.test_forwarder_upstream import (
    POLICY_DIGEST,
    SCOPE_DIGEST,
    SYNTHETIC_AUTH_VALUE,
    FakeTLSSocket,
    _admission,
    assert_config_error,
    assert_upstream_error,
    blocked_socket,  # noqa: F401 - reused pytest fixture
    connector,  # noqa: F401 - reused pytest fixture
    golden_credential,
    golden_issue_get_routed,
    make_channel,
    make_endpoint,
    real_ca_pem,  # noqa: F401 - reused pytest fixture
)

# Reuse Tester B's real-TLS fixtures by module import (the existing pattern:
# compare ``service_tls_material = material_fixtures.tls_material`` in
# test_forwarder_upstream_integration.py itself).
upstream_tls_material = upstream_fixtures.upstream_tls_material
service_tls_material = upstream_fixtures.service_tls_material

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_upstream.py"

MARKER = "UpAdvMarker9f1c7e2b4d"


def _parse() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(), filename=str(MODULE_PATH))


def _attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node


def _all_functions(tree: ast.AST, name: str) -> list[ast.FunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]


def _the_function(tree: ast.AST, name: str) -> ast.FunctionDef:
    matches = _all_functions(tree, name)
    assert len(matches) == 1, f"expected exactly one def {name}, found {len(matches)}"
    return matches[0]


def _the_class(tree: ast.AST, name: str) -> ast.ClassDef:
    matches = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
    assert len(matches) == 1, f"expected exactly one class {name}"
    return matches[0]


def _the_method(tree: ast.AST, class_name: str, method_name: str) -> ast.FunctionDef:
    cls = _the_class(tree, class_name)
    matches = [
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method_name
    ]
    assert len(matches) == 1, f"expected exactly one {class_name}.{method_name}"
    return matches[0]


def _calls_with_attr(tree: ast.AST, attr: str) -> list[ast.Call]:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == attr
    ]


# =============================================================================
# AST: exact import allowlist
# =============================================================================

ALLOWED_STDLIB_PLAIN = {
    "base64", "hashlib", "hmac", "ipaddress", "math", "re", "socket", "ssl", "threading",
    "time", "weakref",
}
ALLOWED_STDLIB_FROM = {
    "__future__": {"annotations"},
    "dataclasses": {"dataclass", "field"},
    "types": {"MappingProxyType"},
}
ALLOWED_RELATIVE = {
    "forwarder_dispatch": {"Admission", "CONNECT_SECONDS", "WRITE_SECONDS"},
    "forwarder_exchange": {"UpstreamError"},
    "forwarder_http_response": {"ParsedResponse"},
    "forwarder_json": {"tagged_digest"},
    "forwarder_response_receive": {"ResponseReceiveError", "receive_response"},
    "forwarder_routes": {
        "JIRA_READABLE_SYSTEM_FIELDS", "MAX_REQUEST_JSON_BYTES", "ROUTE_CATALOG",
        "RouteConfigError", "RoutedRequest", "UpstreamRequest", "request_digest",
    },
}


def test_ast_import_allowlist_is_exact():
    tree = _parse()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in ALLOWED_STDLIB_PLAIN, f"unlisted import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            names = {alias.name for alias in node.names}
            if node.level == 0:
                expected = ALLOWED_STDLIB_FROM.get(node.module or "")
                assert expected is not None, f"unlisted stdlib import: from {node.module}"
                assert names <= expected, f"unlisted names from {node.module}: {names - expected}"
            elif node.level == 1:
                expected = ALLOWED_RELATIVE.get(node.module or "")
                assert expected is not None, f"unlisted relative import: from .{node.module}"
                assert names <= expected, f"unlisted names from .{node.module}: {names - expected}"
            else:
                pytest.fail(f"unexpected import level {node.level} (from {node.module})")


# =============================================================================
# AST: forbidden names, attributes and stores
# =============================================================================

FORBIDDEN_MODULE_ROOTS = {
    "os", "pathlib", "subprocess", "importlib", "logging", "pickle", "copyreg", "json",
    "urllib", "http", "select",
}
FORBIDDEN_BARE_NAMES = {
    "__import__", "open", "environ", "getenv", "eval", "exec", "print", "forwarder_tls",
}
FORBIDDEN_ATTRS = {
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getfqdn",
    "getnameinfo", "create_connection",
    "create_default_context", "_create_unverified_context", "load_default_certs",
    "set_default_verify_paths", "load_cert_chain", "sni_callback", "set_servername_callback",
    "cafile", "capath", "CERT_NONE", "CERT_OPTIONAL", "VERIFY_X509_PARTIAL_CHAIN",
}
# These two are allowed only inside the one read-back assertion function.
SCOPED_TLS_ATTRS = {"OP_IGNORE_UNEXPECTED_EOF", "OP_LEGACY_SERVER_CONNECT"}

CONTEXT_STORE_ATTRS = {
    "check_hostname", "verify_mode", "hostname_checks_common_name", "minimum_version",
    "verify_flags", "options",
}


def test_ast_forbidden_module_roots_are_absent():
    tree = _parse()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {node.module}"
            if node.level == 1:
                assert node.module != "forwarder_tls", "forwarder_tls must never be imported"
    assert "TYPE_CHECKING" not in MODULE_PATH.read_text()


def test_ast_forbidden_bare_names_are_absent():
    tree = _parse()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_BARE_NAMES:
            pytest.fail(f"forbidden name {node.id!r} referenced at line {node.lineno}")


def test_ast_forbidden_attrs_are_absent():
    tree = _parse()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRS:
            pytest.fail(f"forbidden attribute {node.attr!r} referenced at line {node.lineno}")


def test_ast_scoped_tls_attrs_appear_only_in_the_readback_assertion():
    tree = _parse()
    readback = _the_function(tree, "_verify_context_readback")
    span = range(readback.lineno, readback.end_lineno + 1)
    seen = {name: 0 for name in SCOPED_TLS_ATTRS}
    for node in ast.walk(tree):
        # `ssl.OP_...`, or the name as a string: Python 3.11's ssl lacks
        # OP_LEGACY_SERVER_CONNECT, so the module reads it with getattr and a fallback.
        if isinstance(node, ast.Attribute) and node.attr in SCOPED_TLS_ATTRS:
            name = node.attr
        elif isinstance(node, ast.Constant) and node.value in SCOPED_TLS_ATTRS:
            name = node.value
        else:
            continue
        assert node.lineno in span, (
            f"{name} used outside _verify_context_readback at line {node.lineno}"
        )
        seen[name] += 1
    assert all(count == 1 for count in seen.values()), seen


def test_ast_no_store_to_keylog_filename_anywhere():
    tree = _parse()
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        for target in targets:
            assert not (isinstance(target, ast.Attribute) and target.attr == "keylog_filename")


def test_ast_context_attribute_stores_are_confined_to_build_context():
    tree = _parse()
    build_context = _the_function(tree, "_build_context")
    span = range(build_context.lineno, build_context.end_lineno + 1)
    found = set()
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Attribute) and target.attr in CONTEXT_STORE_ATTRS:
                assert node.lineno in span, (
                    f"store to {target.attr} outside _build_context at line {node.lineno}"
                )
                found.add(target.attr)
    assert found == CONTEXT_STORE_ATTRS, f"missing expected stores: {CONTEXT_STORE_ATTRS - found}"


def test_ast_no_store_to_channel_socket_type_outside_its_definition():
    tree = _parse()
    stores = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "_CHANNEL_SOCKET_TYPE" for t in node.targets
        )
    ]
    assert len(stores) == 1, "_CHANNEL_SOCKET_TYPE must be assigned exactly once, at definition"
    augs = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Name) and node.target.id == "_CHANNEL_SOCKET_TYPE"
    ]
    assert not augs


# =============================================================================
# AST: except-handler body rule (Assign/AnnAssign/Pass/Return only)
# =============================================================================

_ALLOWED_HANDLER_STATEMENTS = (ast.Assign, ast.AnnAssign, ast.Pass, ast.Return)


def test_ast_every_except_handler_body_is_assign_annassign_pass_or_return():
    tree = _parse()
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for stmt in node.body:
                if not isinstance(stmt, _ALLOWED_HANDLER_STATEMENTS):
                    offenders.append((stmt.lineno, type(stmt).__name__))
    assert not offenders, f"except handler bodies must be assign/annassign/pass/return: {offenders}"


def test_ast_no_bare_except_and_close_quietly_catches_only_exception():
    tree = _parse()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            assert node.type is not None, f"bare except at line {node.lineno}"
            elements = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
            names = [
                e.id if isinstance(e, ast.Name)
                else e.attr if isinstance(e, ast.Attribute) else None
                for e in elements
            ]
            assert "BaseException" not in names, f"except BaseException at line {node.lineno}"
    close_quietly = _the_function(tree, "_close_quietly")
    shutdown_fd = _the_function(tree, "_shutdown_fd")
    for func in (close_quietly, shutdown_fd):
        for node in ast.walk(func):
            if isinstance(node, ast.ExceptHandler):
                assert isinstance(node.type, ast.Name) and node.type.id == "Exception", (
                    f"{func.name} must catch Exception, not {ast.dump(node.type)}"
                )


# =============================================================================
# AST: exactly-one call-site counts
# =============================================================================

def test_ast_exactly_one_sslcontext_call_site():
    tree = _parse()
    calls = [
        n for n in ast.walk(tree) if isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Attribute) and n.func.attr == "SSLContext")
            or (isinstance(n.func, ast.Name) and n.func.id == "SSLContext")
        )
    ]
    assert len(calls) == 1
    build_context = _the_function(tree, "_build_context")
    assert calls[0].lineno in range(build_context.lineno, build_context.end_lineno + 1)


def test_ast_exactly_one_wrap_socket_call_site_with_no_handshake_on_connect_false():
    tree = _parse()
    calls = _calls_with_attr(tree, "wrap_socket")
    assert len(calls) == 1
    keywords = {kw.arg: kw.value for kw in calls[0].keywords}
    assert "do_handshake_on_connect" in keywords
    value = keywords["do_handshake_on_connect"]
    assert isinstance(value, ast.Constant) and value.value is False


def test_ast_exactly_one_do_handshake_call_site():
    assert len(_calls_with_attr(_parse(), "do_handshake")) == 1


def test_ast_exactly_one_dot_connect_call_site():
    assert len(_calls_with_attr(_parse(), "connect")) == 1


def test_ast_exactly_one_dot_send_call_site():
    assert len(_calls_with_attr(_parse(), "send")) == 1


def test_ast_exactly_one_load_verify_locations_call_site_with_only_cadata():
    tree = _parse()
    calls = _calls_with_attr(tree, "load_verify_locations")
    assert len(calls) == 1
    call = calls[0]
    assert not call.args
    assert [kw.arg for kw in call.keywords] == ["cadata"]


def test_ast_no_recv_read_sendall_write_makefile_unwrap_call():
    tree = _parse()
    forbidden = {"recv", "recv_into", "read", "sendall", "write", "makefile", "unwrap"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden, (
                f"forbidden call .{node.func.attr}( at line {node.lineno}"
            )


def test_ast_shutdown_appears_only_in_shutdown_fd_via_super_call():
    tree = _parse()
    calls = _calls_with_attr(tree, "shutdown")
    assert len(calls) == 1
    call = calls[0]
    shutdown_fd = _the_function(tree, "_shutdown_fd")
    assert call.lineno in range(shutdown_fd.lineno, shutdown_fd.end_lineno + 1)
    # ``super(ssl.SSLSocket, sock).shutdown(...)``
    assert isinstance(call.func.value, ast.Call)
    assert isinstance(call.func.value.func, ast.Name) and call.func.value.func.id == "super"


# =============================================================================
# AST: _authorization is loaded exactly twice, both in _UpstreamChannel.send
# =============================================================================

def _enclosing_scope(node: ast.AST) -> str:
    names = []
    current = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(current.name)
        current = getattr(current, "parent", None)
    return ".".join(reversed(names)) or "<module>"


def _authorization_sites(tree: ast.AST) -> list[str]:
    """The enclosing scope of every ``_authorization`` attribute or string constant."""
    return sorted(
        _enclosing_scope(n) for n in ast.walk(tree)
        if (isinstance(n, ast.Attribute) and n.attr == "_authorization")
        or (isinstance(n, ast.Constant) and n.value == "_authorization")
    )


def test_authorization_site_rule_is_live():
    source = (
        "class _UpstreamChannel:\n"
        "    def send(self):\n"
        "        n = len(credential._authorization)\n"
        "        buffer[0:n] = credential._authorization\n"
        "class JiraUpstreamConnector:\n"
        "    def connect(self):\n"
        "        header_value = self._credential._authorization\n"
        "        leaked = getattr(self._credential, '_authorization')\n"
    )
    tree = ast.parse(source)
    _attach_parents(tree)
    assert _authorization_sites(tree) == [
        "JiraUpstreamConnector.connect", "JiraUpstreamConnector.connect",
        "_UpstreamChannel.send", "_UpstreamChannel.send",
    ]


def test_ast_authorization_slot_is_loaded_exactly_twice_in_send():
    tree = _parse()
    _attach_parents(tree)
    # Module-wide: two loads in send, plus the slot name and the one setattr in __init__.
    assert _authorization_sites(tree) == [
        "BasicCredential", "BasicCredential.__init__",
        "_UpstreamChannel.send", "_UpstreamChannel.send",
    ]
    slots = next(
        stmt.value for stmt in _the_class(tree, "BasicCredential").body
        if isinstance(stmt, ast.Assign) and ast.unparse(stmt.targets[0]) == "__slots__"
    )
    assert "_authorization" in ast.literal_eval(slots)
    send_method = _the_method(tree, "_UpstreamChannel", "send")
    occurrences = [
        n for n in ast.walk(send_method)
        if isinstance(n, ast.Attribute) and n.attr == "_authorization"
    ]
    assert len(occurrences) == 2, f"expected exactly 2 uses, found {len(occurrences)}"

    as_len_arg = 0
    as_slice_rhs = 0
    for node in occurrences:
        parent = node.parent
        if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and (
            parent.func.id == "len" and parent.args and parent.args[0] is node
        ):
            as_len_arg += 1
        elif isinstance(parent, ast.Assign) and parent.value is node:
            assert isinstance(parent.targets[0], ast.Subscript), (
                "the other _authorization use must be the value of a slice assignment"
            )
            as_slice_rhs += 1
        else:
            pytest.fail(f"unexpected _authorization use at line {node.lineno}: {ast.dump(parent)}")
    assert as_len_arg == 1 and as_slice_rhs == 1


# =============================================================================
# AST: BasicCredential.__init__ rules
# =============================================================================

def _statement_list_containing(node: ast.AST) -> list | None:
    parent = getattr(node, "parent", None)
    if parent is None:
        return None
    for field_name in ("body", "orelse", "finalbody"):
        candidate = getattr(parent, field_name, None)
        if isinstance(candidate, list) and node in candidate:
            return candidate
    return None


_SECRET_NAMES = {"user", "token"}


def _is_reducing_call(call: ast.AST, name: ast.Name) -> bool:
    """``type(x)``, ``len(x)`` or ``<pattern>.fullmatch(x)``, with ``x`` its sole argument."""
    if not isinstance(call, ast.Call) or call.keywords or len(call.args) != 1:
        return False
    func = call.func
    return call.args[0] is name and (
        (isinstance(func, ast.Name) and func.id in ("type", "len"))
        or (isinstance(func, ast.Attribute) and func.attr == "fullmatch")
    )


def _is_reduced_to_bool(name: ast.Name, root: ast.AST) -> bool:
    """The reference is a reducing call's argument, compared, then only and/or/not."""
    call = name.parent
    if not _is_reducing_call(call, name):
        return False
    node = call
    if isinstance(call.func, ast.Name) and call.func.id == "len":
        while node is not root and isinstance(node.parent, ast.BinOp):
            node = node.parent
    if node is root or not isinstance(node.parent, ast.Compare):
        return False
    node = node.parent
    while node is not root:
        parent = node.parent
        if not isinstance(parent, ast.BoolOp) and not (
            isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not)
        ):
            return False
        node = parent
    return True


def _secret_bindings(tree: ast.AST) -> list[int]:
    """Lines where a name is bound from ``user``/``token`` other than as a bool."""
    offenders: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            root, reducible = node.value, True
        elif isinstance(node, (ast.For, ast.comprehension)):
            root, reducible = node.iter, False
        else:
            continue
        if root is None:
            continue
        for ref in ast.walk(root):
            if isinstance(ref, ast.Name) and ref.id in _SECRET_NAMES and not (
                reducible and _is_reduced_to_bool(ref, root)
            ):
                offenders.append(ref.lineno)
    return offenders


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ('joined = (user + ":" + token).encode("ascii")', True),
        ("lowered = user.lower()", True),
        ('value = base64.b64encode((user + ":" + token).encode())', True),
        ("alias = user", True),
        ("pair = user + token", True),
        ("match = _USER_GRAMMAR.fullmatch(user)", True),
        ("size = len(user) + 1", True),
        ("encoded: bytes = token.encode()", True),
        ("size += len(token)", True),
        ("for character in user:\n    pass", True),
        ("ok = all(character.isalnum() for character in token)", True),
        ("ok = (alias := user) is not None", True),
        ("types_ok = type(user) is str and type(token) is str", False),
        ("user_ok = types_ok and _USER_GRAMMAR.fullmatch(user) is not None", False),
        ("bound_ok = ok and 6 + 4 * ((len(user) + 1 + len(token) + 2) // 3) <= LIMIT", False),
        ("token_ok = not _TOKEN_GRAMMAR.fullmatch(token) is None", False),
    ],
)
def test_secret_binding_rule_is_live(source, flagged):
    tree = ast.parse(source)
    _attach_parents(tree)
    assert bool(_secret_bindings(tree)) is flagged


def test_ast_credential_init_raises_are_preceded_by_del_user_and_token():
    tree = _parse()
    _attach_parents(tree)
    init_method = _the_method(tree, "BasicCredential", "__init__")
    raises = [n for n in ast.walk(init_method) if isinstance(n, ast.Raise)]
    assert raises, "BasicCredential.__init__ must raise on an invalid credential"
    for raise_node in raises:
        block = _statement_list_containing(raise_node)
        assert block is not None
        index = block.index(raise_node)
        deleted = {
            target.id for stmt in block[:index] if isinstance(stmt, ast.Delete)
            for target in stmt.targets if isinstance(target, ast.Name)
        }
        assert {"user", "token"} <= deleted, (
            f"raise at line {raise_node.lineno} is not preceded by 'del user, token'"
        )


def test_ast_credential_init_never_binds_a_bare_re_match_to_a_name():
    tree = _parse()
    init_method = _the_method(tree, "BasicCredential", "__init__")
    for node in ast.walk(init_method):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            value = node.value
            if (
                isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and value.func.attr in ("match", "fullmatch", "search")
            ):
                pytest.fail(f"a bare re.Match object is bound to a name at line {node.lineno}")


def test_ast_credential_init_binds_no_name_from_user_or_token():
    tree = _parse()
    _attach_parents(tree)
    init_method = _the_method(tree, "BasicCredential", "__init__")
    offenders = _secret_bindings(init_method)
    assert not offenders, f"a name is bound from user/token at lines {offenders}"
    # The one legitimate combination is inside the ``object.__setattr__`` call, which is
    # an Expr(Call(...)), never an Assign -- confirm it exists and is not an Assign.
    setattr_calls = [
        n for n in ast.walk(init_method)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "__setattr__"
        and any(isinstance(a, ast.Constant) and a.value == "_authorization" for a in n.args)
    ]
    assert len(setattr_calls) == 1
    assert isinstance(setattr_calls[0].parent, ast.Expr)
    secret_setattr_calls = [
        n for n in ast.walk(init_method)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "__setattr__"
        and any(isinstance(ref, ast.Name) and ref.id in _SECRET_NAMES for ref in ast.walk(n))
    ]
    assert secret_setattr_calls == setattr_calls


# =============================================================================
# AST: pure functions touch no credential, clock, socket or TLS names
# =============================================================================

@pytest.mark.parametrize(
    ("finder", "name"),
    [
        (lambda t: _the_function(t, "request_descriptor"), "request_descriptor"),
        (lambda t: _the_function(t, "render_parts"), "render_parts"),
        (lambda t: _the_function(t, "_wire_lengths"), "_wire_lengths"),
        (
            lambda t: _the_method(t, "JiraUpstreamConnector", "prepare"),
            "JiraUpstreamConnector.prepare",
        ),
    ],
)
def test_ast_pure_functions_reference_no_credential_clock_or_transport_names(finder, name):
    tree = _parse()
    func = finder(tree)
    forbidden = {"_credential", "_authorization", "time", "socket", "ssl"}
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id in forbidden:
            pytest.fail(f"{name} references forbidden name {node.id!r} at line {node.lineno}")
        if isinstance(node, ast.Attribute) and node.attr in {"_credential", "_authorization"}:
            pytest.fail(
                f"{name} references forbidden attribute {node.attr!r} at line {node.lineno}"
            )


def test_ast_connect_and_its_helpers_contain_no_send_or_write_call():
    tree = _parse()
    helpers = [
        _the_method(tree, "JiraUpstreamConnector", "connect"),
        _the_function(tree, "_build_context"),
        _the_function(tree, "_verify_context_readback"),
        _the_function(tree, "_verify_post_handshake"),
        _the_function(tree, "_close_quietly"),
    ]
    forbidden = {"send", "sendall", "write"}
    for func in helpers:
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, (
                    f"{func.name} calls .{node.func.attr}( at line {node.lineno}"
                )


# =============================================================================
# No production caller (lock 1)
# =============================================================================

_FORBIDDEN_NAMES = frozenset({"JiraUpstreamConnector", "UpstreamEndpoint", "BasicCredential"})
_FORBIDDEN_STRINGS = _FORBIDDEN_NAMES | {"forwarder_upstream"}


def _is_venv_dir(path: Path) -> bool:
    return (path / "pyvenv.cfg").is_file()


def _iter_repo_python_files() -> list[Path]:
    files: list[Path] = []
    skip_dirs = {".git", "__pycache__", "tests"}
    for path in REPO_ROOT.rglob("*.py"):
        relative_parts = path.relative_to(REPO_ROOT).parts
        if any(part in skip_dirs for part in relative_parts[:-1]):
            continue
        if any(_is_venv_dir(parent) for parent in path.parents):
            continue
        if path == MODULE_PATH:
            continue
        files.append(path)
    return files


def test_no_production_python_file_imports_or_names_the_connector():
    offenders = []
    for path in _iter_repo_python_files():
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "forwarder_upstream" in alias.name:
                        offenders.append((path, node.lineno, "import"))
            elif isinstance(node, ast.ImportFrom):
                if node.module and "forwarder_upstream" in node.module:
                    offenders.append((path, node.lineno, "import from"))
            elif isinstance(node, (ast.Name, ast.Attribute)):
                identifier = node.id if isinstance(node, ast.Name) else node.attr
                if identifier in _FORBIDDEN_NAMES:
                    offenders.append((path, node.lineno, identifier))
            elif (
                isinstance(node, ast.Constant) and isinstance(node.value, str)
                and any(marker in node.value for marker in _FORBIDDEN_STRINGS)
            ):
                offenders.append((path, node.lineno, "string constant"))
    assert not offenders, f"a production caller was wired: {offenders}"


def test_no_production_config_or_launch_file_names_the_module():
    skip_dirs = {"tests", "docs", ".scratch", ".git"}
    suffixes = {".toml", ".cfg", ".ini", ".sh", ".yaml", ".yml"}
    offenders = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(REPO_ROOT).parts
        if any(part in skip_dirs for part in relative_parts[:-1]):
            continue
        is_dockerfile = path.name.startswith("Dockerfile")
        if path.suffix not in suffixes and not is_dockerfile:
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        if "forwarder_upstream" in text:
            offenders.append(path)
    assert not offenders, f"a launch/config file names forwarder_upstream: {offenders}"


def test_catalog_states_and_readiness_facts_are_unchanged():
    assert ROUTE_CATALOG["jira.issue.get"].state == "partial"
    assert ROUTE_CATALOG["jira.search"].state == "partial"
    assert all(value is False for value in policy_readiness_facts().values())


# =============================================================================
# Generic marker walk (gc.get_referents + frame f_locals), for the secret walk
# =============================================================================

def _frame_in_package(frame: types.FrameType) -> bool:
    filename = frame.f_code.co_filename.replace("\\", "/")
    return "/grafana_jsm_sandbox/" in f"/{filename}"


def _referents_for(obj: object) -> list:
    if isinstance(obj, types.FrameType):
        return [obj.f_locals]
    if isinstance(obj, (types.ModuleType, type, types.CodeType, types.FunctionType)):
        return []
    try:
        return gc.get_referents(obj)
    except TypeError:
        return []


def _marker_hits(roots: list, marker: str, *, exclude_ids: frozenset[int] = frozenset()) -> list:
    """Iterative walk over gc.get_referents and frame f_locals for a planted marker.

    Skips modules, classes, code objects and function ``__globals__``. Frames
    outside ``grafana_jsm_sandbox/`` are not descended into (they legitimately
    hold the planted input). ``exclude_ids`` names object identities that hold
    the marker legitimately (the one BasicCredential instance).
    """
    raw = marker.encode("ascii")
    b64 = base64.b64encode(raw)
    seen = set(exclude_ids)
    stack = list(roots)
    hits = []
    while stack:
        obj = stack.pop()
        oid = id(obj)
        if oid in seen:
            continue
        seen.add(oid)
        if isinstance(obj, types.FrameType):
            if not _frame_in_package(obj):
                continue
            stack.append(dict(obj.f_locals))
            continue
        if isinstance(obj, str):
            if marker in obj:
                hits.append(obj)
            continue
        if isinstance(obj, (bytes, bytearray)):
            data = bytes(obj)
            if raw in data or b64 in data:
                hits.append(obj)
            continue
        stack.extend(_referents_for(obj))
    return hits


# =============================================================================
# Secret walk
# =============================================================================

def _marker_credential(**overrides) -> fu.BasicCredential:
    kwargs = {
        "service": "jira", "profile": "basic", "credential_id": "jira-basic-synthetic-1",
        "user": f"probe-{MARKER}@example.invalid", "token": f"tok-{MARKER}-0001",
    }
    kwargs.update(overrides)
    return fu.BasicCredential(**kwargs)


def test_secret_walk_credential_invalid_never_leaks_the_planted_marker(caplog):
    with pytest.raises(fu.UpstreamConfigError) as raised:
        fu.BasicCredential(
            service="jira", profile="basic", credential_id="jira-basic-synthetic-1",
            user=f"bad:user-{MARKER}", token=f"tok-{MARKER}",
        )
    error = raised.value
    assert error.args == ("credential_invalid",)
    assert error.__cause__ is None and error.__context__ is None
    assert MARKER not in repr(error) and MARKER not in str(error)
    hits = _marker_hits([error, error.__traceback__], MARKER)
    assert not hits, f"marker leaked via: {hits}"
    assert MARKER not in caplog.text


def test_secret_walk_repr_str_of_credential_connector_endpoint_are_clean(real_ca_pem):  # noqa: F811
    endpoint = make_endpoint(real_ca_pem)
    credential = _marker_credential()
    connector_ = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    routed = golden_issue_get_routed()
    descriptor = fu.request_descriptor(
        routed, endpoint_digest=endpoint.digest, authority=endpoint.authority,
    )
    parts = fu.render_parts(descriptor)
    surfaces = {
        "credential repr": repr(credential),
        "credential str": str(credential),
        "credential format": format(credential),
        "connector repr": repr(connector_),
        "endpoint repr": repr(endpoint),
        "descriptor repr": repr(descriptor),
        "descriptor document": repr(descriptor.document()),
        "parts repr": repr(parts),
    }
    for label, text in surfaces.items():
        assert MARKER not in text, f"marker leaked via {label}"
    hits = _marker_hits(
        [credential, connector_, endpoint, descriptor, parts], MARKER,
        exclude_ids=frozenset({id(credential)}),
    )
    assert not hits, f"marker reachable outside the credential's own slot: {hits}"
    assert sorted(fu.BasicCredential.__slots__) == [
        "_authorization", "_claimed", "_credential_id", "_profile", "_service",
    ]
    other_slots = [
        getattr(credential, name) for name in fu.BasicCredential.__slots__
        if name != "_authorization"
    ]
    assert not _marker_hits(other_slots, MARKER)


def test_secret_walk_over_a_real_tls_round_trip(monkeypatch, upstream_tls_material):
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    credential = _marker_credential()
    connector_ = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    routed = upstream_fixtures.routed_issue_get()
    body = b'{"fields":{},"id":"90101","key":"SYN-1"}'

    with upstream_fixtures.synthetic_upstream(
        upstream_tls_material, respond=upstream_fixtures._ok_response_bytes(body),
    ) as (_record, address), upstream_fixtures.asserting_upstream_adapter(
        monkeypatch, endpoint, address,
    ):
        admission, digest, channel = upstream_fixtures.connect_real(connector_, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        assert channel._credential is None, "the channel must drop the credential after send"
        channel.close()

    assert response.status == 200
    # The marker legitimately appears on the wire (it is the Authorization value) and in
    # the credential's own slot; everywhere else it must be absent.
    hits = _marker_hits(
        [connector_, endpoint, channel, admission, digest, response], MARKER,
        exclude_ids=frozenset({id(credential)}),
    )
    assert not hits, f"marker reachable outside the wire and the credential slot: {hits}"


class _NonRecordingFakeSocket:
    """A minimal fake with no plaintext bookkeeping of its own, unlike ``FakeTLSSocket``:

    the marker walk below must find the secret nowhere in the channel's own state, so
    the fake must not carry a side-channel record of what it was asked to send (that
    would be the fixture leaking, not the module under test).
    """

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def settimeout(self, value: float) -> None:
        pass

    def send(self, chunk) -> int:
        raise self._exc

    def close(self) -> None:
        pass


def test_secret_walk_send_failure_traceback_frame_locals_are_clean(monkeypatch):
    credential = _marker_credential()
    sock = _NonRecordingFakeSocket(OSError("boom"))
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", _NonRecordingFakeSocket)
    parts = fu.RequestParts(prefix=b"GET / HTTP/1.1\r\nHost: h\r\n", suffix=b"Accept: a\r\n\r\n")
    channel = fu._UpstreamChannel(
        fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential=credential,
        exchange_deadline=time.monotonic() + 100.0,
    )
    with pytest.raises(UpstreamError) as raised:
        channel.send(deadline=time.monotonic() + 5.0)
    error = raised.value
    assert error.args == ("write_failed",)
    assert error.__cause__ is None and error.__context__ is None
    hits = _marker_hits(
        [error, error.__traceback__], MARKER, exclude_ids=frozenset({id(credential)}),
    )
    assert not hits, f"marker leaked via the failed-send exception chain: {hits}"
    assert channel._credential is None


def test_secret_walk_connect_failure_tracebacks_are_clean(monkeypatch, upstream_tls_material):
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    credential = _marker_credential()
    connector_ = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    routed = upstream_fixtures.routed_issue_get()
    digest = connector_.prepare(routed)
    errors = []

    def attempt(*, request_digest=digest, deadline=None):
        admission = upstream_fixtures.build_admission(routed)
        with pytest.raises(UpstreamError) as raised:
            connector_.connect(
                admission, routed, request_digest=request_digest,
                deadline=admission.connect_deadline if deadline is None else deadline,
            )
        errors.append(raised.value)

    with upstream_fixtures.asserting_upstream_adapter(
        monkeypatch, endpoint, upstream_fixtures.refused_tcp_address(),
    ):
        attempt(request_digest=routed.request_digest)
        attempt(deadline=time.monotonic() - 1.0)
        attempt()
    with upstream_fixtures.synthetic_upstream(upstream_tls_material, leaf="wrong-name") as (
        _record, address,
    ), upstream_fixtures.asserting_upstream_adapter(monkeypatch, endpoint, address):
        attempt()

    assert [error.code for error in errors] == [
        "connect_failed", "deadline", "connect_failed", "upstream_tls_failed",
    ]
    for error in errors:
        hits = _marker_hits(
            [error, error.__traceback__], MARKER, exclude_ids=frozenset({id(credential)}),
        )
        assert not hits, f"marker leaked via the {error.code} traceback: {hits}"


class _RecordingChannel:
    def __init__(self, real, errors: list) -> None:
        self._real = real
        self._errors = errors

    def send(self, *, deadline):
        try:
            return self._real.send(deadline=deadline)
        except UpstreamError as error:
            self._errors.append(error)
            raise

    def receive(self, *, deadline):
        try:
            return self._real.receive(deadline=deadline)
        except UpstreamError as error:
            self._errors.append(error)
            raise

    def abort(self):
        self._real.abort()

    def close(self):
        self._real.close()


class _RecordingConnector:
    """Passes through to the real connector and keeps every UpstreamError it raises."""

    def __init__(self, real) -> None:
        self._real = real
        self.errors: list[UpstreamError] = []

    def prepare(self, routed):
        return self._real.prepare(routed)

    def connect(self, admission, routed, *, request_digest, deadline):
        try:
            channel = self._real.connect(
                admission, routed, request_digest=request_digest, deadline=deadline,
            )
        except UpstreamError as error:
            self.errors.append(error)
            raise
        return _RecordingChannel(channel, self.errors)


_REDIRECT = (
    b"HTTP/1.1 302 Found\r\nLocation: https://attacker.invalid/x\r\nContent-Length: 0\r\n\r\n"
)
_COMPOSITION_CASES = {
    "success": ("TRANSPORT_CONFIRMED", "ok", []),
    "wrong-name": ("FAILED", "upstream_tls_failed", ["upstream_tls_failed"]),
    "refused-tcp": ("FAILED", "connect_failed", ["connect_failed"]),
    "redirect": ("DISPATCHED_UNKNOWN", "receive_failed", ["receive_failed"]),
    "stall": ("DISPATCHED_UNKNOWN", "receive_failed", ["receive_failed"]),
}


def _traceback_files(error: BaseException) -> list[str]:
    files, tb = [], error.__traceback__
    while tb is not None:
        files.append(Path(tb.tb_frame.f_code.co_filename).name)
        tb = tb.tb_next
    return files


@pytest.mark.parametrize("case", sorted(_COMPOSITION_CASES))
def test_secret_walk_over_serve_one_with_the_real_connector(
    monkeypatch, caplog, upstream_tls_material, service_tls_material, case,
):
    caplog.set_level(logging.DEBUG)
    base, _paths = service_tls_material
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    credential = _marker_credential()
    connector_ = _RecordingConnector(
        fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential),
    )
    gate, registry, ledger = new_real_system()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    upstream_kwargs = {
        "success": {"respond": upstream_fixtures._ok_response_bytes(ok_issue_get_body())},
        "wrong-name": {"leaf": "wrong-name"},
        "refused-tcp": None,
        "redirect": {"respond": _REDIRECT, "allow_reset": True},
        "stall": {"head_then_stall": True},
    }[case]
    if case == "stall":
        monkeypatch.setattr(frr, "_INACTIVITY_LIMIT", 0.5)

    try:
        with contextlib.ExitStack() as stack:
            listener, _addr = stack.enter_context(
                tls_fixtures.ephemeral_listener(monkeypatch, service_tls_material, SERVICE),
            )
            if upstream_kwargs is None:
                address = upstream_fixtures.refused_tcp_address()
            else:
                _record, address = stack.enter_context(
                    upstream_fixtures.synthetic_upstream(upstream_tls_material, **upstream_kwargs),
                )
            stack.enter_context(
                upstream_fixtures.asserting_upstream_adapter(monkeypatch, endpoint, address),
            )
            outcomes, completed = stack.enter_context(serve_one_exchange(
                listener, gate=gate, policy=policy_with_golden(), upstream=connector_,
            ))
            data = roundtrip(base, wire, timeout=6.0)
            assert completed.wait(6.0)
    finally:
        socket.socket = upstream_fixtures._ORIGINAL_SOCKET

    dispatch_state, reason, codes = _COMPOSITION_CASES[case]
    outcome = outcomes[0]
    assert (outcome.dispatch_state, outcome.reason) == (dispatch_state, reason)
    assert [error.code for error in connector_.errors] == codes
    for error in connector_.errors:
        files = _traceback_files(error)
        assert "forwarder_exchange.py" in files and "forwarder_upstream.py" in files, files
    roots = [
        outcome, data, ledger.snapshot(), gate.snapshot(), registry.snapshot(),
        ledger, gate, registry, connector_.errors,
        *[error.__traceback__ for error in connector_.errors],
    ]
    hits = _marker_hits(roots, MARKER, exclude_ids=frozenset({id(credential)}))
    assert not hits, f"marker reachable from the {case} composition: {hits}"
    assert MARKER not in caplog.text


# =============================================================================
# Exception-chain walk over every closed code
# =============================================================================

def _assert_clean(error: Exception, expected_type: type, code: str) -> None:
    assert isinstance(error, expected_type)
    assert error.args == (code,)
    if expected_type is not UpstreamError:
        assert str(error) == code
    assert error.__cause__ is None
    assert error.__context__ is None


def test_exception_chain_endpoint_invalid_is_clean():
    with pytest.raises(fu.UpstreamConfigError) as raised:
        fu.UpstreamEndpoint(
            service="jira", revision="r1", host="jira-upstream.synthetic.invalid",
            address="192.0.2.10", port=0, ca_pem="garbage", credential_id="id-1",
        )
    _assert_clean(raised.value, fu.UpstreamConfigError, "endpoint_invalid")


def test_exception_chain_trust_invalid_is_clean():
    with pytest.raises(fu.UpstreamConfigError) as raised:
        make_endpoint("not a pem")
    _assert_clean(raised.value, fu.UpstreamConfigError, "trust_invalid")


def test_exception_chain_endpoint_unqualified_is_clean(real_ca_pem):  # noqa: F811
    with pytest.raises(fu.UpstreamConfigError) as raised:
        make_endpoint(real_ca_pem, host="jira.example.com")
    _assert_clean(raised.value, fu.UpstreamConfigError, "endpoint_unqualified")


def test_exception_chain_credential_invalid_is_clean():
    with pytest.raises(fu.UpstreamConfigError) as raised:
        fu.BasicCredential(
            service="jira", profile="basic", credential_id="id-1", user="bad:user", token="tok",
        )
    _assert_clean(raised.value, fu.UpstreamConfigError, "credential_invalid")


def test_exception_chain_credential_mismatch_is_clean(real_ca_pem):  # noqa: F811
    credential = golden_credential(credential_id="jira-basic-synthetic-1", service="jira")
    other_endpoint = make_endpoint(real_ca_pem, credential_id="a-different-id")
    with pytest.raises(fu.UpstreamConfigError) as raised:
        fu.JiraUpstreamConnector(endpoint=other_endpoint, credential=credential)
    _assert_clean(raised.value, fu.UpstreamConfigError, "credential_mismatch")


def test_exception_chain_credential_claimed_is_clean(real_ca_pem):  # noqa: F811
    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    with pytest.raises(fu.UpstreamConfigError) as raised:
        fu.JiraUpstreamConnector(endpoint=make_endpoint(real_ca_pem), credential=credential)
    _assert_clean(raised.value, fu.UpstreamConfigError, "credential_claimed")


def test_exception_chain_shape_unavailable_is_clean():
    routed = dataclasses.replace(golden_issue_get_routed(), route_id="jira.issue.create")
    with pytest.raises(fu.UpstreamPrepareError) as raised:
        fu.request_descriptor(
            routed, endpoint_digest="0" * 64, authority="jira-upstream.synthetic.invalid",
        )
    _assert_clean(raised.value, fu.UpstreamPrepareError, "shape_unavailable")


def test_exception_chain_request_inconsistent_is_clean():
    routed = dataclasses.replace(golden_issue_get_routed(), request_digest="0" * 64)
    with pytest.raises(fu.UpstreamPrepareError) as raised:
        fu.request_descriptor(
            routed, endpoint_digest="0" * 64, authority="jira-upstream.synthetic.invalid",
        )
    _assert_clean(raised.value, fu.UpstreamPrepareError, "request_inconsistent")


def test_exception_chain_request_unbuildable_is_clean():
    with pytest.raises(fu.UpstreamPrepareError) as raised:
        fu.request_descriptor(
            golden_issue_get_routed(), endpoint_digest="not-hex",
            authority="jira-upstream.synthetic.invalid",
        )
    _assert_clean(raised.value, fu.UpstreamPrepareError, "request_unbuildable")


def test_exception_chain_connect_failed_for_a_wrong_type_is_clean(
    blocked_socket, connector,  # noqa: F811
):
    conn, _endpoint = connector
    with pytest.raises(UpstreamError) as raised:
        conn.connect(
            "not an admission", golden_issue_get_routed(),
            request_digest="0" * 64, deadline=time.monotonic() + 1.0,
        )
    _assert_clean(raised.value, UpstreamError, "connect_failed")


def test_exception_chain_deadline_for_connect_is_clean(blocked_socket, connector):  # noqa: F811
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    past = time.monotonic() - 1.0
    admission = _admission(deadline=past + 100, exchange_deadline=past + 99, connect_deadline=past)
    with pytest.raises(UpstreamError) as raised:
        conn.connect(admission, routed, request_digest=digest, deadline=past)
    _assert_clean(raised.value, UpstreamError, "deadline")


def test_exception_chain_upstream_tls_failed_is_clean(monkeypatch, upstream_tls_material):
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    conn = fu.JiraUpstreamConnector(
        endpoint=endpoint, credential=upstream_fixtures.synthetic_credential(),
    )
    routed = upstream_fixtures.routed_issue_get()
    with upstream_fixtures.synthetic_upstream(
        upstream_tls_material, leaf="wrong-name", allow_reset=True,
    ) as (_record, address), upstream_fixtures.asserting_upstream_adapter(
        monkeypatch, endpoint, address,
    ):
        admission = upstream_fixtures.build_admission(routed)
        digest = conn.prepare(routed)
        with pytest.raises(UpstreamError) as raised:
            conn.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )
    _assert_clean(raised.value, UpstreamError, "upstream_tls_failed")


def test_exception_chain_write_failed_is_clean(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.send(deadline=time.monotonic() + 5.0)
    with pytest.raises(UpstreamError) as raised:
        channel.send(deadline=time.monotonic() + 5.0)
    _assert_clean(raised.value, UpstreamError, "write_failed")


def test_exception_chain_receive_failed_before_send_is_clean(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    with pytest.raises(UpstreamError) as raised:
        channel.receive(deadline=time.monotonic() + 5.0)
    _assert_clean(raised.value, UpstreamError, "receive_failed")


ALL_CONFIG_CODES_COVERED = {
    "endpoint_invalid", "trust_invalid", "endpoint_unqualified", "credential_invalid",
    "credential_mismatch", "credential_claimed",
}
ALL_PREPARE_CODES_COVERED = {"shape_unavailable", "request_inconsistent", "request_unbuildable"}
ALL_TRANSPORT_CODES_COVERED = {
    "connect_failed", "upstream_tls_failed", "write_failed", "receive_failed", "deadline",
}


def test_every_closed_code_has_a_covering_exception_chain_scenario_above():
    assert ALL_CONFIG_CODES_COVERED == fu.UPSTREAM_CONFIG_CODES
    assert ALL_PREPARE_CODES_COVERED == fu.UPSTREAM_PREPARE_CODES
    assert ALL_TRANSPORT_CODES_COVERED == UPSTREAM_ERROR_CODES


# =============================================================================
# Fixture-captured property (24 seeded cases over real TLS)
# =============================================================================

def _reference_render(document: dict, body: bytes, auth_value: bytes) -> bytes:
    prefix = f"{document['method']} {document['target']} HTTP/1.1\r\n".encode("ascii")
    prefix += f"Host: {document['authority']}\r\n".encode("ascii")
    suffix = f"Accept: {document['accept']}\r\nAccept-Encoding: identity\r\n".encode("ascii")
    if document["body_bytes"] > 0:
        suffix += (
            f"Content-Type: {document['content_type']}\r\n"
            f"Content-Length: {document['body_bytes']}\r\n"
        ).encode("ascii")
    suffix += b"Connection: close\r\n\r\n" + body
    return prefix + b"Authorization: " + auth_value + b"\r\n" + suffix


def _seeded_search_routed(rng):
    max_results = rng.randint(1, 100)
    body = (
        b'{"fields":["issuetype","labels","project","status","summary"],'
        b'"jql":"project = 90001 AND issuetype = 90002 AND labels = '
        b'\\"fp-0123456789abcdef\\" AND statusCategory != Done AND created >= '
        b'-30m ORDER BY created ASC","maxResults":' + str(max_results).encode() + b"}"
    )
    upstream = UpstreamRequest(
        "POST", "/rest/api/3/search/jql", "application/json", "application/json", body,
    )
    digest = v1_request_digest(
        service="jira", route_id="jira.search", policy_digest=POLICY_DIGEST,
        scope_digest=SCOPE_DIGEST, upstream=upstream,
    )
    return RoutedRequest(
        route_id="jira.search", service="jira", scope_digest=SCOPE_DIGEST,
        policy_digest=POLICY_DIGEST, request_digest=digest, requires_permit=False,
        upstream=upstream, selection=None,
    )


def _capture_one_request(monkeypatch, material, endpoint, routed):
    connector_ = fu.JiraUpstreamConnector(
        endpoint=endpoint, credential=upstream_fixtures.synthetic_credential(),
    )
    with upstream_fixtures.synthetic_upstream(material) as (
        record, address,
    ), upstream_fixtures.asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, digest, channel = upstream_fixtures.connect_real(connector_, routed)
        channel.send(deadline=admission.exchange_deadline)
        channel.close()
    return record.raw_in, record.captured, digest


@pytest.mark.parametrize("seed_index", range(24))
def test_fixture_captured_property_over_real_tls(monkeypatch, upstream_tls_material, seed_index):
    rng = random.Random(20260923 + seed_index)
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    routed = _seeded_search_routed(rng)

    raw_in_1, captured_1, digest_1 = _capture_one_request(
        monkeypatch, upstream_tls_material, endpoint, routed,
    )
    raw_in_2, captured_2, digest_2 = _capture_one_request(
        monkeypatch, upstream_tls_material, endpoint, routed,
    )

    upstream_fixtures.assert_tls_records(raw_in_1)
    upstream_fixtures.assert_tls_records(raw_in_2)

    lines = captured_1.split(b"\r\n")
    assert lines[2].startswith(b"Authorization: ")
    assert sum(1 for line in lines if line.startswith(b"Authorization:")) == 1

    descriptor = fu.request_descriptor(
        routed, endpoint_digest=endpoint.digest, authority=endpoint.authority,
    )
    reference = _reference_render(
        descriptor.document(), routed.upstream.body, SYNTHETIC_AUTH_VALUE,
    )
    redacted_capture = (
        captured_1[:captured_1.index(b"Authorization: ")]
        + b"<redacted>\r\n"
        + captured_1[captured_1.index(b"\r\n", captured_1.index(b"Authorization: ")) + 2:]
    )
    redacted_reference = (
        reference[:reference.index(b"Authorization: ")]
        + b"<redacted>\r\n"
        + reference[reference.index(b"\r\n", reference.index(b"Authorization: ")) + 2:]
    )
    assert redacted_capture == redacted_reference

    assert captured_1 == captured_2, "identical routed requests must capture identical bytes"
    assert digest_1 == digest_2
    if digest_1 == digest_2:
        assert captured_1 == captured_2, "equal v2 digests must give identical redacted bytes"


# =============================================================================
# Attack lists: addresses and hosts
# =============================================================================

_ATTACK_ADDRESSES = [
    "192.0.2.010", " 192.0.2.10", "192.0.2.10:443", "[192.0.2.10]", "::ffff:192.0.2.10",
    "2001:db8::1", "::1", "127.1", "0x7f.0.0.1", "2130706433", "127.0.0.1", "0.0.0.0",
    "0.1.2.3", "169.254.169.254", "224.0.0.1", "239.255.255.250", "240.0.0.1",
    "255.255.255.255",
]


@pytest.mark.parametrize("address", _ATTACK_ADDRESSES)
def test_attack_addresses_give_endpoint_invalid(blocked_socket, real_ca_pem, address):  # noqa: F811
    assert_config_error(lambda: make_endpoint(real_ca_pem, address=address), "endpoint_invalid")


_ATTACK_HOSTS = [
    "JIRA-UPSTREAM.SYNTHETIC.INVALID", "jira..invalid", "-a.invalid", "a-.invalid",
    "jira.invalid.", ("a" * 64) + ".invalid", ("a" * 250) + ".invalid", "invalidhost",
    "ji_ra.invalid", "localhost", "x.localhost", "x.local", "forwarder-jira.maoi.local",
    "192.0.2.10", "jíra.invalid",
]


@pytest.mark.parametrize("host", _ATTACK_HOSTS)
def test_attack_hosts_give_endpoint_invalid(blocked_socket, real_ca_pem, host):  # noqa: F811
    assert_config_error(lambda: make_endpoint(real_ca_pem, host=host), "endpoint_invalid")


# =============================================================================
# Deadline widening
# =============================================================================

def test_connect_refuses_a_deadline_beyond_admission_connect_deadline_before_any_socket(
    blocked_socket, connector,  # noqa: F811
):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission()
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=digest,
            deadline=admission.connect_deadline + 1.0,
        ),
        "connect_failed",
    )


def test_settimeout_spy_never_exceeds_the_clipped_remaining_connect_deadline(
    monkeypatch, upstream_tls_material,
):
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    conn = fu.JiraUpstreamConnector(
        endpoint=endpoint, credential=upstream_fixtures.synthetic_credential(),
    )
    routed = upstream_fixtures.routed_issue_get()
    calls: list[tuple[float, float]] = []
    original = socket.socket.settimeout

    def spy(self, value):
        # Only the connector's own calls: the fixture's sockets and ``ssl.py``'s
        # internal re-application of the raw timeout have other callers.
        if sys._getframe(1).f_globals.get("__name__") == fu.__name__:
            calls.append((time.monotonic(), value))
        return original(self, value)

    monkeypatch.setattr(socket.socket, "settimeout", spy)
    with upstream_fixtures.synthetic_upstream(upstream_tls_material) as (
        _record, address,
    ), upstream_fixtures.asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission = upstream_fixtures.build_admission(routed, deadline_from_now=1.5)
        digest = conn.prepare(routed)
        channel = conn.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline,
        )
        channel.close()

    assert len(calls) == 2, "expected the raw and the secured settimeout calls"
    for call_time, value in calls:
        assert value <= CONNECT_SECONDS
        assert value <= (admission.connect_deadline - call_time) + 0.01, (
            f"settimeout({value}) at t={call_time} exceeds the clipped remaining deadline"
        )


def test_settimeout_spy_never_exceeds_the_clipped_remaining_write_deadline(monkeypatch):
    class TimedFakeSocket(FakeTLSSocket):
        def settimeout(self, value: float) -> None:
            self.settimeout_calls.append((time.monotonic(), value))

    sock = TimedFakeSocket()
    exchange_deadline = time.monotonic() + 3.0
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", TimedFakeSocket)
    channel = fu._UpstreamChannel(
        fu._CHANNEL_TOKEN, sock=sock, parts=fu.RequestParts(prefix=b"", suffix=b"H" * 40_000),
        credential=golden_credential(), exchange_deadline=exchange_deadline,
    )
    channel.send(deadline=exchange_deadline)
    assert len(sock.settimeout_calls) == 3, "expected one settimeout call per chunk"
    for call_time, value in sock.settimeout_calls:
        assert value <= 10.0, f"settimeout({value}) exceeds WRITE_SECONDS"
        assert value <= (exchange_deadline - call_time) + 0.01


def test_receive_honors_its_deadline_and_never_blocks_past_it(monkeypatch, upstream_tls_material):
    endpoint = upstream_fixtures.synthetic_endpoint(upstream_tls_material)
    conn = fu.JiraUpstreamConnector(
        endpoint=endpoint, credential=upstream_fixtures.synthetic_credential(),
    )
    routed = upstream_fixtures.routed_issue_get()
    stall_event = threading.Event()

    with upstream_fixtures.synthetic_upstream(
        upstream_tls_material, stall_until=stall_event, allow_reset=True,
    ) as (_record, address), upstream_fixtures.asserting_upstream_adapter(
        monkeypatch, endpoint, address,
    ):
        admission, _digest, channel = upstream_fixtures.connect_real(
            conn, routed, deadline_from_now=3.0,
        )
        channel.send(deadline=admission.exchange_deadline)
        short_deadline = time.monotonic() + 0.4
        started = time.monotonic()
        with pytest.raises(UpstreamError) as raised:
            channel.receive(deadline=short_deadline)
        elapsed = time.monotonic() - started
        channel.close()
        stall_event.set()
    assert raised.value.args == ("receive_failed",)
    assert elapsed < 1.2, f"receive did not honor its short deadline: {elapsed}s"


# =============================================================================
# T1: forbidden names as attribute chains, not just bare names or imports
# =============================================================================

FORBIDDEN_NAME_OR_ATTR = {
    "os", "environ", "getenv", "open", "sys", "builtins", "subprocess", "importlib",
    "json", "pickle", "logging", "urllib", "http", "select", "print", "eval", "exec",
    "__import__",
}


def test_ast_forbidden_names_and_attrs_together_catch_attribute_chains():
    """``test_ast_forbidden_module_roots_are_absent`` only walks ``ast.Import``/
    ``ast.ImportFrom``, and ``test_ast_forbidden_bare_names_are_absent`` only
    walks bare ``ast.Name`` nodes. Neither sees an attribute chain, so
    ``ssl.os.environ.get("SSLKEYLOGFILE")`` -- ``os``/``environ``/``getenv``
    reached as ``ast.Attribute.attr``, never imported or bound as a name --
    would pass both. This walks ``ast.Attribute`` and ``ast.Name`` together.
    """
    tree = _parse()
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_NAME_OR_ATTR:
            hits.append((node.attr, node.lineno))
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAME_OR_ATTR:
            hits.append((node.id, node.lineno))
    assert hits == []
