"""Adversarial tests for the one-request exchange (Module 2), Tester C2's file.

Covers: an AST walk of ``forwarder_exchange.py`` (no ``raise`` inside an
``except`` block, an exact import allowlist, forbidden stdlib modules);
argument-type rejections and the ``clock_domain_mismatch`` ``ValueError``; a
manifest bound to a different policy; a Jira sentinel replayed on the
Confluence listener; a planted exception marker from an injected connector
that must never reach the outcome, a receipt or any snapshot; the closed
``ServeOutcome`` code catalogs; an event-order proof that ``connect`` only
follows the ledger's ``connecting`` state and ``send`` only follows
``dispatched``; and ledger capacity during ``reserve``. Every scenario that
serves a real request runs over an actual local TLS connection built from the
existing ``FixedTLSListener``/``connect_service_tls`` fixtures (imported from
``test_forwarder_server_tls_integration`` as ``tls_fixtures``, the same
pattern the other Forwarder integration test files use); only the injected
``UpstreamConnector``/``UpstreamChannel`` are fakes, per the plan.

This file owns no source module: it only observes ``forwarder_exchange.py``,
built concurrently by another implementer.
"""

from __future__ import annotations

import ast
import base64
import ssl
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_exchange as fx
from grafana_jsm_sandbox import forwarder_receipts as fr
from grafana_jsm_sandbox.forwarder_dispatch import DispatchGate
from grafana_jsm_sandbox.forwarder_exchange import (
    CLOSE_REASONS,
    SERVE_RESULTS,
    UPSTREAM_ERROR_CODES,
    ServeOutcome,
)
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptLedger
from grafana_jsm_sandbox.forwarder_response_receive import receive_response
from grafana_jsm_sandbox.forwarder_routes import UNMATCHED_ROUTE_ID, RoutePolicy
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_server_tls_integration as tls_fixtures
from tests.test_forwarder_exchange import (
    BOOT,
    FakeChannel,
    FakeConnector,
    install_lease,
    new_real_system,
    ok_issue_get_body,
    policy_with_golden,
)
from tests.test_forwarder_routes import DENIAL_DIGESTS, ISSUE_GET_TARGET, golden_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
EXCHANGE_MODULE_PATH = REPO_ROOT / "grafana_jsm_sandbox" / "forwarder_exchange.py"

service_tls_material = tls_fixtures.service_tls_material

# --- Module 2's exact allowlist (plan: "Imports (AST-checked by exact name)") ----

EXCHANGE_ALLOWED_STDLIB_PLAIN = {"hmac", "math"}
EXCHANGE_ALLOWED_STDLIB_FROM = {
    "__future__": {"annotations"},
    "collections.abc": {"Callable"},
    "dataclasses": {"dataclass"},
    "typing": {"Protocol"},
}
EXCHANGE_ALLOWED_RELATIVE = {
    "forwarder_dispatch": {
        "MAX_HANDLER_SECONDS", "MIN_ADMISSION_SECONDS", "RESPONSE_MARGIN_SECONDS",
        "Admission", "DispatchError", "DispatchGate",
    },
    "forwarder_http_receive": {"HTTPReceiveError", "receive_request_sized"},
    "forwarder_http_response": {"ParsedResponse"},
    "forwarder_receipts": {
        "ForwarderReceipt", "ReceiptError", "local_response_for", "response_digest",
    },
    "forwarder_response_send": {"ResponseSendError", "send_response"},
    "forwarder_routes": {
        "UNMATCHED_ROUTE_ID", "RoutedRequest", "RoutePolicy", "RoutePolicyError",
        "denied_request_digest",
    },
    "forwarder_server_tls": {"FixedTLSListener", "TLSListenerError"},
    "forwarder_services": {"SERVICE_PROFILES"},
}
FORBIDDEN_MODULE_ROOTS = {"socket", "ssl", "select", "os", "subprocess"}


def _parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(), filename=str(path))


# --- AST: no raise inside an except handler ------------------------------------


def test_ast_no_raise_inside_except_handler():
    tree = _parse(EXCHANGE_MODULE_PATH)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Raise):
                    offenders.append(inner.lineno)
    assert not offenders, (
        f"an except handler must only record a fixed code; a fresh outcome is built "
        f"after the try statement ends (raise at line(s) {offenders})"
    )


# --- AST: exact import allowlist and forbidden modules -------------------------


def test_ast_import_allowlist_is_exact():
    tree = _parse(EXCHANGE_MODULE_PATH)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in EXCHANGE_ALLOWED_STDLIB_PLAIN, f"unlisted import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = {alias.name for alias in node.names}
            if node.level == 0:
                expected = EXCHANGE_ALLOWED_STDLIB_FROM.get(module)
                assert expected is not None, f"unlisted stdlib import: from {module}"
                assert names <= expected, f"unlisted names from {module}: {names - expected}"
            elif node.level == 1:
                expected = EXCHANGE_ALLOWED_RELATIVE.get(module)
                assert expected is not None, f"unlisted relative import: from .{module}"
                assert names <= expected, f"unlisted names from .{module}: {names - expected}"
            else:
                pytest.fail(f"unexpected relative import level {node.level} (from {module})")


def test_ast_forbidden_modules_are_absent_with_no_type_checking_exception():
    tree = _parse(EXCHANGE_MODULE_PATH)
    for node in ast.walk(tree):
        # No TYPE_CHECKING exception: the whole tree is checked, including
        # anything nested under an `if TYPE_CHECKING` block.
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            root = (node.module or "").split(".")[0]
            assert root not in FORBIDDEN_MODULE_ROOTS, f"forbidden import: {node.module}"
        elif isinstance(node, ast.Name) and node.id == "__import__":
            pytest.fail("__import__ must never be referenced")
    assert "TYPE_CHECKING" not in EXCHANGE_MODULE_PATH.read_text()


# --- argument types and the clock-domain guard (no socket needed: E1 runs ------
# --- before any I/O, so a plain `object()` connection is legitimate here) -----


def _fast_system():
    return new_real_system()


@pytest.mark.parametrize("overrides,expected", [
    ({"gate": object()}, TypeError),
    ({"policy": object()}, TypeError),
    ({"service": 123}, TypeError),
    ({"service": "not-a-real-service"}, ValueError),
    ({"started": "now"}, TypeError),
    ({"started": True}, TypeError),  # bool is not an exact int/float
    ({"started": float("nan")}, TypeError),
    ({"started": float("inf")}, TypeError),
    ({"upstream": object()}, TypeError),
])
def test_serve_request_rejects_bad_arguments(overrides, expected):
    gate, _registry, _ledger = _fast_system()
    policy = policy_with_golden()
    kwargs = {
        "service": "jira", "gate": gate, "policy": policy, "upstream": None,
        "started": time.monotonic(),
    }
    kwargs.update(overrides)
    with pytest.raises(expected):
        fx.serve_request(object(), **kwargs)


def test_serve_one_rejects_a_non_listener_type():
    gate, _registry, _ledger = _fast_system()
    policy = policy_with_golden()
    with pytest.raises(TypeError):
        fx.serve_one(object(), gate=gate, policy=policy, upstream=None)


def test_serve_request_with_a_non_system_clock_gate_gives_clock_domain_mismatch():
    registry = LeaseRegistry()
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=lambda: 0.0)
    assert gate.system_clock is False
    policy = policy_with_golden()
    with pytest.raises(ValueError, match="clock_domain_mismatch"):
        fx.serve_request(
            object(), service="jira", gate=gate, policy=policy, upstream=None, started=0.0,
        )


# --- ServeOutcome's closed code catalogs ---------------------------------------


def test_serve_outcome_code_catalogs_match_the_plan():
    assert SERVE_RESULTS == ("responded", "closed_without_response", "delivery_failed")
    assert CLOSE_REASONS == frozenset({
        "accept_failed", "request_unreadable", "sentinel_unknown", "receipt_unavailable",
        "dispatch_capacity", "deadline_expired", "gate_failure", "internal_failure",
    })
    assert UPSTREAM_ERROR_CODES == frozenset({
        "connect_failed", "upstream_tls_failed", "write_failed", "receive_failed", "deadline",
    })


def _assert_closed_outcome_shape(outcome: ServeOutcome) -> None:
    assert outcome.result in SERVE_RESULTS
    if outcome.result == "closed_without_response":
        assert outcome.reason in CLOSE_REASONS
        assert outcome.receipt_id is None
        assert outcome.dispatch_state is None
        assert outcome.delivery is None
    else:
        assert outcome.dispatch_state in fr.DISPATCH_STATES
        if outcome.result == "responded":
            assert outcome.delivery == "sent"


# --- real local TLS: shared helpers ---------------------------------------------


def _wire(service: str, sentinel: str, *, method: str = "GET",
         path: str = "/local-fixture", body: bytes = b"") -> bytes:
    profile = SERVICE_PROFILES[service]
    if profile.sentinel_scheme == "Basic":
        authorization = "Basic " + base64.b64encode(f"run:{sentinel}".encode()).decode()
    else:
        authorization = "Bearer " + sentinel
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {profile.server_name}:{profile.port}",
        f"Authorization: {authorization}",
        "Accept: application/json",
    ]
    if body:
        lines += [f"Content-Length: {len(body)}", "Content-Type: application/json"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _drain(client: ssl.SSLSocket, *, timeout: float = 1.5) -> bytes:
    """Read whatever the server sent, treating an abrupt close as no bytes too."""
    client.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except (OSError, ssl.SSLError):
        pass
    return b"".join(chunks)


def _entry_state(gate: DispatchGate, receipt_id: str) -> str | None:
    for entry in gate.ledger.snapshot()["entries"]:
        if entry["receipt_id"] == receipt_id:
            return entry["entry_state"]
    return None


@contextmanager
def _served_client(material, handler, *, service: str = "jira", timeout: float = 2.0):
    """Serve exactly one real-TLS connection with ``handler`` and yield the client.

    Each peer gets its own ``pytest.MonkeyPatch`` scope, matching the other
    Forwarder integration test files: nesting two such scopes under one
    shared ``monkeypatch`` fixture would double-wrap ``socket.socket``.
    """
    with (
        pytest.MonkeyPatch.context() as mp,
        tls_fixtures.ephemeral_listener(mp, material, service) as (listener, _address),
    ):
        with tls_fixtures.serve_once(listener, handler, timeout=timeout) as (outcomes, completed):
            base, _paths = material
            client = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=timeout)
            try:
                yield client
            finally:
                client.close()
                assert completed.wait(timeout + 3), "server handler did not finish"
        assert outcomes == ["accepted"]


# --- a manifest from another policy: 403 route_denied ---------------------------


def test_manifest_from_another_policy_gives_403_route_denied(service_tls_material):
    gate, registry, ledger = new_real_system()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    other_policy = RoutePolicy(jira=golden_policy(revision="policy-r9-other"))

    results = []

    def handle(connection):
        results.append(fx.serve_request(
            connection, service="jira", gate=gate, policy=other_policy, upstream=None,
            started=gate.now(),
        ))

    with _served_client(service_tls_material, handle) as client:
        client.sendall(_wire("jira", grant.sentinel, path=ISSUE_GET_TARGET))
        parsed = receive_response(client, deadline=time.monotonic() + 2.0)

    outcome = results[0]
    _assert_closed_outcome_shape(outcome)
    assert outcome.result == "responded"
    assert outcome.reason == "route_denied"
    assert outcome.dispatch_state == "NOT_DISPATCHED"
    assert parsed.status == 403

    entry_meta = next(
        entry for entry in ledger.snapshot()["entries"] if entry["receipt_id"] == outcome.receipt_id
    )
    assert entry_meta["route_id"] == UNMATCHED_ROUTE_ID
    assert entry_meta["request_digest"] == DENIAL_DIGESTS[("jira", "unmatched")]


# --- a Jira sentinel replayed on the Confluence listener: EOF -------------------


def test_jira_sentinel_replayed_on_confluence_listener_gives_eof(service_tls_material):
    gate, registry, ledger = new_real_system()
    grant, _entry = install_lease(gate, registry, ttl=10.0)  # bound to the "jira" service only
    policy = policy_with_golden()

    results = []

    def handle(connection):
        results.append(fx.serve_request(
            connection, service="confluence", gate=gate, policy=policy, upstream=None,
            started=gate.now(),
        ))

    with _served_client(service_tls_material, handle, service="confluence") as client:
        client.sendall(_wire("confluence", grant.sentinel))
        raw = _drain(client)

    assert raw == b""
    outcome = results[0]
    _assert_closed_outcome_shape(outcome)
    assert outcome == ServeOutcome("closed_without_response", "sentinel_unknown", None, None, None)
    assert ledger.snapshot()["entries"] == ()  # no lease was ever known: no receipt exists


# --- a planted connector-exception marker never leaks ---------------------------


@pytest.mark.parametrize("inject", ["connect", "send", "receive"])
def test_connector_exception_marker_never_leaks(service_tls_material, inject):
    marker = f"MARK-LEAK-{inject}-9f2c31a0"

    def boom(*_args, **_kwargs):
        raise RuntimeError(marker)

    gate, registry, ledger = new_real_system()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    policy = policy_with_golden()

    if inject == "connect":
        connector = FakeConnector(connect=boom)
    elif inject == "send":
        channel = FakeChannel(send_error=RuntimeError(marker))
        connector = FakeConnector(connect=lambda *a, **k: channel)
    else:
        channel = FakeChannel(receive_error=RuntimeError(marker))
        connector = FakeConnector(connect=lambda *a, **k: channel)

    results = []

    def handle(connection):
        results.append(fx.serve_request(
            connection, service="jira", gate=gate, policy=policy, upstream=connector,
            started=gate.now(),
        ))

    with _served_client(service_tls_material, handle) as client:
        client.sendall(_wire("jira", grant.sentinel, path=ISSUE_GET_TARGET))
        raw = _drain(client)

    outcome = results[0]
    _assert_closed_outcome_shape(outcome)
    assert outcome.result == "responded"  # every injection site here still finalizes a receipt
    assert raw, "the marker check is meaningless if nothing was actually delivered"
    assert marker not in raw.decode("latin-1")
    assert marker not in repr(outcome)
    assert marker not in repr(ledger.snapshot())
    assert marker not in repr(gate.snapshot())
    assert marker not in repr(registry.snapshot())


# --- event-order proof: connect after "connecting", send after "dispatched" ----


def test_connect_follows_connecting_and_send_follows_dispatched(service_tls_material):
    gate, registry, _ledger = new_real_system()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    policy = policy_with_golden()
    events = []
    channels = []

    class OrderedChannel:
        def __init__(self, admission):
            self._admission = admission
            self.send_calls = 0
            self.receive_calls = 0

        def send(self, *, deadline):
            self.send_calls += 1
            events.append(("send", _entry_state(gate, self._admission.receipt_id)))

        def receive(self, *, deadline):
            self.receive_calls += 1
            return ParsedResponse(200, ok_issue_get_body())

        def abort(self):
            pass

        def close(self):
            pass

    def connect(admission, routed, *, request_digest, deadline):
        events.append(("connect", _entry_state(gate, admission.receipt_id)))
        channel = OrderedChannel(admission)
        channels.append(channel)
        return channel

    connector = FakeConnector(connect=connect)
    results = []

    def handle(connection):
        results.append(fx.serve_request(
            connection, service="jira", gate=gate, policy=policy, upstream=connector,
            started=gate.now(),
        ))

    with _served_client(service_tls_material, handle) as client:
        client.sendall(_wire("jira", grant.sentinel, path=ISSUE_GET_TARGET))
        parsed = receive_response(client, deadline=time.monotonic() + 2.0)

    assert parsed.status == 200
    outcome = results[0]
    _assert_closed_outcome_shape(outcome)
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert connector.connect_calls == 1
    assert len(channels) == 1
    assert channels[0].send_calls == 1
    assert channels[0].receive_calls == 1
    # The proof itself: each event observed the ledger entry already in the
    # state that authorized it, and each happened exactly once.
    assert events == [("connect", "connecting"), ("send", "dispatched")]


# --- ledger capacity during reserve, over real TLS: EOF, zero connects ---------


def test_ledger_capacity_during_reserve_over_real_tls_gives_eof(
    service_tls_material, monkeypatch,
):
    gate, registry, ledger = new_real_system()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    policy = policy_with_golden()
    connector = FakeConnector()

    monkeypatch.setattr(fr, "MAX_RECEIPTS", 1)
    ledger.reserve(
        lease_id="filler-lease", attempt_id="attempt-1", service="jira",
        route_id="jira.issue.get", request_digest="0" * 64, request_bytes=10,
        deadline=time.monotonic() + 30.0,
    )

    results = []

    def handle(connection):
        results.append(fx.serve_request(
            connection, service="jira", gate=gate, policy=policy, upstream=connector,
            started=gate.now(),
        ))

    with _served_client(service_tls_material, handle) as client:
        client.sendall(_wire("jira", grant.sentinel, path=ISSUE_GET_TARGET))
        raw = _drain(client)

    assert raw == b""
    outcome = results[0]
    _assert_closed_outcome_shape(outcome)
    assert outcome == ServeOutcome(
        "closed_without_response", "receipt_unavailable", None, None, None,
    )
    assert connector.connect_calls == 0
    assert len(ledger.snapshot()["entries"]) == 1  # only the filler; nothing new was reserved
