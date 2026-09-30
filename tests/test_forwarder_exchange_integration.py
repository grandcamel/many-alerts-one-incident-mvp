"""Real local TLS integration tests for the one-request exchange (module 2).

Inbound TLS is real: ``tls_fixtures.ephemeral_listener`` binds a real
``FixedTLSListener`` on an ephemeral loopback port, and a real client connects
with ``connect_service_tls``. ``receive_request_sized`` and ``send_response``
run unmocked. Only the upstream connector is fake -- source ships none. Every
request is raw ``Basic run:<sentinel>``/``Bearer <sentinel>`` bytes built by
hand, matching the wire a real client would send.
"""

from __future__ import annotations

import base64
import hashlib
import ssl
import threading
import time
from contextlib import contextmanager

import pytest

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox import forwarder_exchange as fx
from grafana_jsm_sandbox.forwarder_exchange import UpstreamError
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, parse_response
from grafana_jsm_sandbox.forwarder_json import canonical_json
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import LOCAL_RESPONSES, ReceiptLedger
from grafana_jsm_sandbox.forwarder_server_tls import TLSListenerError
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
from grafana_jsm_sandbox.forwarder_tls import connect_service_tls
from tests import test_forwarder_server_tls_integration as tls_fixtures
from tests.test_forwarder_exchange import (
    BOOT,
    ISSUE_GET_DENIAL_DIGEST,
    PREPARED_ISSUE_GET_DIGEST,
    SERVICE,
    UNMATCHED_DIGEST,
    FakeChannel,
    FakeConnector,
    install_lease,
    new_real_system,
    ok_issue_get_body,
    policy_with_golden,
)
from tests.test_forwarder_routes import SEARCH_DIGEST_50

service_tls_material = tls_fixtures.service_tls_material

SEARCH_LABEL = "fp-0123456789abcdef"
SEARCH_JQL = (
    'project = 90001 AND issuetype = 90002 AND labels = "' + SEARCH_LABEL + '" '
    "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
)
PREPARED_SEARCH_DIGEST = hashlib.sha256(b"fake-v2|" + SEARCH_DIGEST_50.encode()).hexdigest()


# --- raw wire construction (a real client, not ParsedRequest) ------------------


def _authorization(profile, sentinel: str) -> str:
    if profile.sentinel_scheme == "Basic":
        return "Basic " + base64.b64encode(f"run:{sentinel}".encode()).decode()
    return "Bearer " + sentinel


def raw_get(service: str, sentinel: str, path: str, *, accept: str = "application/json",
            duplicate_host: bool = False) -> bytes:
    profile = SERVICE_PROFILES[service]
    host_line = f"{profile.server_name}:{profile.port}"
    lines = [f"GET {path} HTTP/1.1", f"Host: {host_line}"]
    if duplicate_host:
        lines.append(f"Host: {host_line}")
    lines += [f"Authorization: {_authorization(profile, sentinel)}", f"Accept: {accept}", "", ""]
    return "\r\n".join(lines).encode()


def raw_post(service: str, sentinel: str, path: str, body: bytes, *,
             accept: str = "application/json") -> bytes:
    profile = SERVICE_PROFILES[service]
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {profile.server_name}:{profile.port}\r\n"
        f"Authorization: {_authorization(profile, sentinel)}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Accept: {accept}\r\n\r\n"
    ).encode()
    return head + body


def roundtrip(base, wire: bytes, *, service: str = "jira", timeout: float = 3.0) -> bytes:
    """Connect, send one raw request, and read until the server closes."""
    connection = connect_service_tls(service, ca_pem=base.ca_cert.read_text(), timeout=timeout)
    try:
        connection.sendall(wire)
        connection.settimeout(timeout)
        chunks = []
        try:
            while True:
                chunk = connection.recv(65_536)
                if not chunk:
                    break
                chunks.append(chunk)
        except (OSError, ssl.SSLError):
            pass
        return b"".join(chunks)
    finally:
        connection.close()


# --- server-side harnesses (real accept, on server threads) -------------------


def _serve_connection(connection, *, service, gate, policy, upstream):
    """Mirror ``serve_one``'s own started-timestamp/gate-failure handling."""
    try:
        started = gate.now()
    except fd.DispatchError:
        return fx.ServeOutcome("closed_without_response", "gate_failure", None, None, None)
    return fx.serve_request(
        connection, service=service, gate=gate, policy=policy, upstream=upstream,
        started=started,
    )


@contextmanager
def serve_once_exchange(listener, *, gate, policy, upstream, accept_timeout: float = 3.0):
    """Accept exactly one connection and run ``serve_request`` for it."""
    outcomes = []
    unexpected = []
    completed = threading.Event()

    def serve():
        connection = None
        try:
            connection = listener.accept(timeout=accept_timeout)
            outcomes.append(_serve_connection(
                connection, service=listener.service, gate=gate, policy=policy,
                upstream=upstream,
            ))
        except TLSListenerError as error:
            outcomes.append(error)
        except BaseException as error:  # noqa: BLE001 - expose thread failures to the test
            unexpected.append(error)
        finally:
            if connection is not None:
                connection.close()
            completed.set()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield outcomes, completed
    finally:
        worker.join(6.0)
        assert not worker.is_alive(), "exchange server thread did not exit"
        assert not unexpected, [repr(error) for error in unexpected]


@contextmanager
def serve_one_exchange(listener, *, gate, policy, upstream, accept_timeout: float = 3.0):
    outcomes = []
    unexpected = []
    completed = threading.Event()

    def serve():
        try:
            outcomes.append(fx.serve_one(
                listener, gate=gate, policy=policy, upstream=upstream,
                accept_timeout=accept_timeout,
            ))
        except BaseException as error:  # noqa: BLE001 - expose thread failures to the test
            unexpected.append(error)
        finally:
            completed.set()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield outcomes, completed
    finally:
        worker.join(6.0)
        assert not worker.is_alive(), "serve_one worker did not exit"
        assert not unexpected, [repr(error) for error in unexpected]


@contextmanager
def accept_loop_exchange(listener, *, gate, policy, upstream, poll_timeout: float = 0.2):
    """Repeatedly accept connections, running one ``serve_request`` per connection."""
    outcomes = []
    lock = threading.Lock()
    unexpected = []
    stop = threading.Event()
    handlers = []

    def handle(connection):
        try:
            outcome = _serve_connection(
                connection, service=listener.service, gate=gate, policy=policy,
                upstream=upstream,
            )
            with lock:
                outcomes.append(outcome)
        except BaseException as error:  # noqa: BLE001 - expose thread failures to the test
            unexpected.append(error)
        finally:
            connection.close()

    def accept_forever():
        while not stop.is_set():
            try:
                connection = listener.accept(timeout=poll_timeout)
            except TLSListenerError as error:
                if error.code == "listener_closed":
                    return
                continue
            handler = threading.Thread(target=handle, args=(connection,), daemon=True)
            handler.start()
            handlers.append(handler)

    acceptor = threading.Thread(target=accept_forever, daemon=True)
    acceptor.start()
    try:
        yield outcomes, lock
    finally:
        stop.set()
        acceptor.join(6.0)
        for handler in handlers:
            handler.join(6.0)
        assert not unexpected, [repr(error) for error in unexpected]


# --- scripted fake upstream channels for blocking/racing scenarios ------------


class GatedChannel:
    """A fake channel whose ``receive`` blocks until released.

    ``honors_abort`` makes the connector's own ``abort`` do the releasing, so
    a shutdown or overdue abort can unblock a stuck connector the way a real
    one must (spec: ``abort`` is safe and effective at any time).
    """

    def __init__(self, *, response=None, receive_error=None, honors_abort=False):
        self.response = response
        self.receive_error = receive_error
        self.honors_abort = honors_abort
        self.release_event = threading.Event()
        self.send_calls = 0
        self.receive_calls = 0
        self.abort_calls = 0
        self.close_calls = 0

    def release(self) -> None:
        self.release_event.set()

    def send(self, *, deadline):
        self.send_calls += 1

    def receive(self, *, deadline):
        self.receive_calls += 1
        self.release_event.wait(10.0)
        if self.receive_error is not None:
            raise self.receive_error
        return self.response

    def abort(self):
        self.abort_calls += 1
        if self.honors_abort:
            self.release_event.set()

    def close(self):
        self.close_calls += 1


class DeadlineBlockingChannel:
    """Blocks past its ``receive`` deadline, then raises -- mirrors unit 10's stall."""

    def __init__(self, error):
        self.error = error
        self.send_calls = 0
        self.receive_calls = 0
        self.abort_calls = 0
        self.close_calls = 0

    def send(self, *, deadline):
        self.send_calls += 1

    def receive(self, *, deadline):
        self.receive_calls += 1
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining + 0.05)
        raise self.error

    def abort(self):
        self.abort_calls += 1

    def close(self):
        self.close_calls += 1


# --- small assertion helpers ---------------------------------------------------


def ledger_entry(ledger, receipt_id):
    for entry in ledger.snapshot()["entries"]:
        if entry["receipt_id"] == receipt_id:
            return entry
    raise AssertionError(f"no ledger entry for {receipt_id}")


def lease_state(registry, lease_id):
    for record in registry.snapshot()["leases"]:
        if record["lease_id"] == lease_id:
            return record["state"]
    return None


def flight_phase(gate, lease_id):
    for flight in gate.snapshot()["flights"]:
        if flight[1] == lease_id:
            return flight[4]
    return None


def wait_until(predicate, *, timeout=3.0, interval=0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def assert_local(data: bytes, kind: str) -> None:
    assert parse_response(data) == LOCAL_RESPONSES[kind]


def ok_search_body() -> bytes:
    issue = {
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": [SEARCH_LABEL], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    return canonical_json({"issues": [issue]})


def search_wire(sentinel: str) -> bytes:
    body = canonical_json({"jql": SEARCH_JQL})
    return raw_post(SERVICE, sentinel, "/rest/api/3/search/jql", body)


# === case 1: success (byte-exact 200, prepared digest, each fake call once) ===


def test_case1_success_issue_get(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.result == "responded"
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    assert outcome.delivery == "sent"
    parsed = parse_response(data)
    assert parsed == ParsedResponse(status=200, body=ok_issue_get_body())

    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["request_digest"] == PREPARED_ISSUE_GET_DIGEST
    assert entry["generation"] == grant.generation
    assert entry["request_bytes"] == len(wire)
    assert entry["delivery_outcome"] == "sent"

    assert connector.prepare_calls == 1
    assert connector.connect_calls == 1
    assert channel.send_calls == 1
    assert channel.receive_calls == 1
    assert channel.close_calls == 1
    assert channel.abort_calls == 0
    assert gate.snapshot()["open_dispatches"] == 0


def test_case1_success_search(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_search_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = search_wire(grant.sentinel)

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    parsed = parse_response(data)
    assert parsed == ParsedResponse(status=200, body=ok_search_body())

    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["request_digest"] == PREPARED_SEARCH_DIGEST
    assert entry["generation"] == grant.generation
    assert entry["request_bytes"] == len(wire)
    assert connector.prepare_calls == 1
    assert connector.connect_calls == 1
    assert channel.send_calls == 1
    assert channel.receive_calls == 1
    assert channel.close_calls == 1
    assert channel.abort_calls == 0


# === case 2: upstream 404 =========================================================


def test_case2_upstream_404_gives_response_rejected(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=404, body=b'{"errorMessages":[]}'))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "response_policy_rejected"
    assert_local(data, "response_rejected")
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["http_status_class"] == "4xx"


# === case 3: malformed upstream responses =========================================


@pytest.mark.parametrize("response", [
    ParsedResponse(status=302, body=b""),
    ParsedResponse(status=200, body=b""),
    ParsedResponse(status=200, body=b"a" * 1_048_577),
], ids=["redirect", "empty-200", "over-1mib"])
def test_case3_malformed_upstream_response_gives_malformed_response(
    monkeypatch, service_tls_material, response,
):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=response)
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "malformed_response"
    assert_local(data, "upstream_unknown")
    assert gate.snapshot()["open_dispatches"] == 0
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["entry_state"] == "finalized"


# === case 4: no bytes at all ======================================================


def test_case4_unknown_sentinel_gives_no_bytes(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, _registry, ledger = new_real_system()
    policy = policy_with_golden()
    connector = FakeConnector()
    wire = raw_get(SERVICE, "s" * 43, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    assert data == b""
    outcome = outcomes[0]
    assert outcome.result == "closed_without_response"
    assert outcome.reason == "sentinel_unknown"
    assert connector.prepare_calls == 0
    assert connector.connect_calls == 0
    assert ledger.snapshot()["entries"] == ()


def test_case4_grafana_listener_never_resolves_a_lease(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant = registry.register(
        run_id="run-grafana", attempt_id="attempt-1", receiver_boot_id=BOOT, service="grafana",
        scope_digest="0" * 64, expires_at=time.monotonic() + 30.0, generation=registry.generation,
    )
    registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
        launch_at=time.monotonic(),
    )
    # Every ScopeManifest is service="jira" (__post_init__), so this lease can
    # never be installed -- confirming it is genuinely unresolvable, not just
    # untried.
    from tests.test_forwarder_exchange import golden_manifest
    with pytest.raises(fd.DispatchError) as caught:
        gate.install_scope(grant=grant, manifest=golden_manifest(run_id="run-grafana"))
    assert caught.value.code == "manifest_binding_mismatch"

    connector = FakeConnector()
    wire = raw_get("grafana", grant.sentinel, "/")

    with tls_fixtures.ephemeral_listener(monkeypatch, service_tls_material, "grafana") as (
        listener, _addr,
    ), serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
        outcomes, completed,
    ):
        data = roundtrip(base, wire, service="grafana")
        assert completed.wait(3)

    assert data == b""
    assert outcomes[0].reason == "sentinel_unknown"
    assert connector.connect_calls == 0
    assert ledger.snapshot()["entries"] == ()


def test_case4_duplicate_host_gives_no_bytes(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = FakeConnector()
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1", duplicate_host=True)

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    assert data == b""
    assert outcomes[0].reason == "request_unreadable"
    assert connector.connect_calls == 0
    assert ledger.snapshot()["entries"] == ()


# === case 5: denials with zero connects ===========================================


def test_case5_revoked_before_request_gives_unmatched_denial(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    registry.revoke(
        lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
        reason="operator_cancel",
    )
    connector = FakeConnector()
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.result == "responded"
    assert outcome.reason == "lease_denied"
    assert_local(data, "denied")
    entry = ledger_entry(ledger, outcome.receipt_id)
    literal = "4d70175f274bcfc9b1ac634035192fb5f3152f9aa2cd5a8c1baefc06f7db0703"
    assert entry["request_digest"] == UNMATCHED_DIGEST == literal
    assert entry["route_id"] == "unmatched"
    assert entry["request_bytes"] == len(wire)
    assert connector.prepare_calls == 0
    assert connector.connect_calls == 0


def test_case5_selector_out_of_scope_gives_route_denied(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = FakeConnector()
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-2")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.reason == "route_denied"
    assert_local(data, "denied")
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["request_digest"] == ISSUE_GET_DENIAL_DIGEST
    assert connector.connect_calls == 0


def test_case5_fields_subset_gives_400(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = FakeConnector()
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1?fields=issuetype,labels")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.reason == "request_rejected"
    assert_local(data, "invalid_request")
    assert connector.connect_calls == 0


def test_case5_no_upstream_gives_route_denied(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=None) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.reason == "route_denied"
    assert_local(data, "denied")
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["request_digest"] == ISSUE_GET_DENIAL_DIGEST


def test_case5_prepare_raising_gives_route_denied(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)

    def boom(routed):
        raise RuntimeError("prepare exploded")
    connector = FakeConnector(prepare=boom)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.reason == "route_denied"
    assert_local(data, "denied")
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["request_digest"] == ISSUE_GET_DENIAL_DIGEST
    assert connector.connect_calls == 0


def test_case5_short_lease_gives_deadline_before_reserve(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=1.5)
    connector = FakeConnector()
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(1.4)  # delivered comfortably before expires_at

    outcome = outcomes[0]
    assert outcome.reason == "deadline"
    assert_local(data, "deadline")
    receipt = ledger_entry(ledger, outcome.receipt_id)
    assert receipt["request_digest"] == PREPARED_ISSUE_GET_DIGEST
    assert receipt["request_bytes"] == len(wire)
    assert connector.connect_calls == 0
    assert time.monotonic() < entry.expires_at


# === case 6: upstream failures, each with exactly one connect ====================


def test_case6_upstream_tls_failed(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)

    def boom(*a, **k):
        raise UpstreamError("upstream_tls_failed")
    connector = FakeConnector(connect=boom)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "upstream_tls_failed"
    assert_local(data, "upstream_failed")
    assert connector.connect_calls == 1


def test_case6_connect_oserror(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)

    def boom(*a, **k):
        raise OSError("connection refused")
    connector = FakeConnector(connect=boom)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "connect_failed"
    assert_local(data, "upstream_failed")
    assert connector.connect_calls == 1


def test_case6_send_raises_gives_write_failed(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(send_error=OSError("broken pipe"))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "write_failed"
    assert_local(data, "upstream_unknown")
    assert connector.connect_calls == 1


def test_case6_receive_blocks_past_deadline_then_fails(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=4.0)
    channel = DeadlineBlockingChannel(UpstreamError("receive_failed"))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    dispatch_deadline = time.monotonic() + 4.0

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire, timeout=6.0)
        assert completed.wait(6.0)

    assert time.monotonic() < dispatch_deadline
    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "receive_failed"
    assert_local(data, "upstream_unknown")
    assert connector.connect_calls == 1


def test_case6_receive_deadline_error_gives_504(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(receive_error=UpstreamError("deadline"))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "deadline"
    assert_local(data, "deadline")
    assert connector.connect_calls == 1


def test_case6_receive_returns_non_response_gives_receive_failed(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=b"not-a-parsed-response")
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "receive_failed"
    assert_local(data, "upstream_unknown")
    assert connector.connect_calls == 1


# === case 7: fence race -- connect revokes before returning =======================


def test_case7_connect_revokes_lease_gives_failed_at_fence(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))

    def connect_and_revoke(*a, **k):
        registry.revoke(
            lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
            reason="operator_cancel",
        )
        return channel
    connector = FakeConnector(connect=connect_and_revoke)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "connect_failed"
    assert_local(data, "upstream_failed")
    assert channel.send_calls == 0
    assert channel.abort_calls == 1
    assert gate.closeout(grant.lease_id).closeout_state == "quiescent"


# === case 8: revocation after write still delivers TRANSPORT_CONFIRMED ===========


def test_case8_revoke_after_write_still_delivers_ok(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))

    def send_and_revoke(*, deadline):
        channel.send_calls += 1
        registry.revoke(
            lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
            reason="operator_cancel",
        )
    channel.send = send_and_revoke
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    assert parse_response(data) == ParsedResponse(status=200, body=ok_issue_get_body())
    assert lease_state(registry, grant.lease_id) == "revoked"


# === case 9: revocation while receive blocks ======================================


def test_case9_revoke_while_receive_blocks(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=20.0)
    channel = GatedChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with tls_fixtures.ephemeral_listener(
        monkeypatch, service_tls_material, SERVICE,
    ) as (listener, _addr):
        with accept_loop_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, lock,
        ):
            first = {}

            def run_first():
                first["data"] = roundtrip(base, wire, timeout=6.0)
            first_thread = threading.Thread(target=run_first, daemon=True)
            first_thread.start()

            assert wait_until(lambda: flight_phase(gate, grant.lease_id) == "writing")
            registry.revoke(
                lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
                reason="operator_cancel",
            )
            closeout = gate.closeout(grant.lease_id)
            assert closeout.closeout_state == "draining"
            assert closeout.in_flight == 1

            second_data = roundtrip(base, wire)
            assert second_data != b""
            assert parse_response(second_data).status == 403
            assert connector.connect_calls == 1

            channel.release()
            first_thread.join(6.0)
            assert not first_thread.is_alive()

        with lock:
            second_outcome = next(o for o in outcomes if o.reason == "lease_denied")
            first_outcome = next(o for o in outcomes if o.reason == "ok")
        assert second_outcome.result == "responded"
        assert first_outcome.dispatch_state == "TRANSPORT_CONFIRMED"

    assert parse_response(first["data"]) == ParsedResponse(status=200, body=ok_issue_get_body())
    assert gate.closeout(grant.lease_id).closeout_state == "quiescent"


# === case 10: shutdown ============================================================


def test_case10_shutdown_unblocks_receive_via_abort(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=20.0)
    channel = GatedChannel(receive_error=UpstreamError("receive_failed"), honors_abort=True)
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with tls_fixtures.ephemeral_listener(
        monkeypatch, service_tls_material, SERVICE,
    ) as (listener, _addr):
        with serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ):
            def run_first():
                nonlocal data
                data = roundtrip(base, wire, timeout=6.0)
            data = None
            first_thread = threading.Thread(target=run_first, daemon=True)
            first_thread.start()

            assert wait_until(lambda: flight_phase(gate, grant.lease_id) == "writing")
            report = gate.shutdown()
            first_thread.join(6.0)
            assert not first_thread.is_alive()
            assert completed.wait(1.0)

        assert report.aborted == 1
        outcome = outcomes[0]
        assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
        assert outcome.reason == "receive_failed"
        assert_local(data, "upstream_unknown")
        assert registry.snapshot()["registry_state"] != "held"

        # A later request on the same (now-closed) gate gets a receipt-backed 403.
        with serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes2, completed2,
        ):
            second_wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
            second_data = roundtrip(base, second_wire)
            assert completed2.wait(3)
        assert outcomes2[0].reason == "lease_denied"
        assert parse_response(second_data).status == 403


def test_case10_shutdown_from_inside_connect_denies_at_fence(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))

    def connect_and_shutdown(*a, **k):
        gate.shutdown()
        return channel
    connector = FakeConnector(connect=connect_and_shutdown)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "connect_failed"
    assert_local(data, "upstream_failed")
    assert channel.send_calls == 0
    # Two calls, per plan E11/E12: attach_abort refuses (gate already closed),
    # then the fence denies with gate_closed -- each site aborts independently.
    assert channel.abort_calls == 2


# === case 11: flight capacity ======================================================


def test_case11_flight_capacity_gives_eof_with_zero_connects(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 2)

    grant_a, _entry_a = install_lease(gate, registry, ttl=20.0, run_id="run-a")
    grant_b, _entry_b = install_lease(gate, registry, ttl=20.0, run_id="run-b")
    grant_c, _entry_c = install_lease(gate, registry, ttl=20.0, run_id="run-c")

    channel_a = GatedChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    channel_b = GatedChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    channels = iter([channel_a, channel_b])
    connector = FakeConnector(connect=lambda *a, **k: next(channels))

    with tls_fixtures.ephemeral_listener(
        monkeypatch, service_tls_material, SERVICE,
    ) as (listener, _addr):
        with accept_loop_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, lock,
        ):
            def blocked(grant):
                return threading.Thread(
                    target=lambda: roundtrip(
                        base, raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1"),
                        timeout=6.0,
                    ),
                    daemon=True,
                )
            thread_a = blocked(grant_a)
            thread_b = blocked(grant_b)
            thread_a.start()
            thread_b.start()
            assert wait_until(lambda: gate.snapshot()["open_dispatches"] == 2)

            third_wire = raw_get(SERVICE, grant_c.sentinel, "/rest/api/3/issue/SYN-1")
            third_data = roundtrip(base, third_wire)
            assert third_data == b""

            channel_a.release()
            channel_b.release()
            thread_a.join(6.0)
            thread_b.join(6.0)
            assert not thread_a.is_alive()
            assert not thread_b.is_alive()

        with lock:
            third_outcome = next(
                o for o in outcomes if o.result == "closed_without_response"
            )
    assert third_outcome.reason == "dispatch_capacity"
    assert connector.connect_calls == 2


# === case 12: misbehaving connectors ==============================================


def test_case12a_overdue_honors_abort_then_quiescent(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=3.0)
    channel = GatedChannel(
        response=ParsedResponse(status=200, body=ok_issue_get_body()), honors_abort=True,
    )
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = None

        def run_client():
            nonlocal data
            data = roundtrip(base, wire, timeout=6.0)
        client_thread = threading.Thread(target=run_client, daemon=True)
        client_thread.start()

        assert wait_until(lambda: flight_phase(gate, grant.lease_id) == "writing")
        time.sleep(3.2)  # past the lease's 3s deadline
        closeout = gate.closeout(grant.lease_id)
        assert closeout.closeout_state == "overdue"

        client_thread.join(6.0)
        assert not client_thread.is_alive()
        assert completed.wait(1.0)

    assert data == b""
    outcome = outcomes[0]
    assert outcome.result == "closed_without_response"
    assert outcome.reason == "deadline_expired"
    assert channel.abort_calls == 1
    assert wait_until(
        lambda: gate.closeout(grant.lease_id).closeout_state == "quiescent", timeout=2.0,
    )
    entry = ledger_entry(ledger, outcome.receipt_id) if outcome.receipt_id else None
    if entry is None:
        entry = next(iter(ledger.snapshot()["entries"]))
    assert entry["dispatch_state"] == "DISPATCHED_UNKNOWN"
    assert entry["reason"] == "abandoned"


def test_case12b_overdue_ignoring_abort_holds_capacity(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 1)
    grant_a, _entry_a = install_lease(gate, registry, ttl=3.0, run_id="run-a")
    grant_b, _entry_b = install_lease(gate, registry, ttl=20.0, run_id="run-b")

    stuck = GatedChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: stuck)
    wire_a = raw_get(SERVICE, grant_a.sentinel, "/rest/api/3/issue/SYN-1")
    wire_b = raw_get(SERVICE, grant_b.sentinel, "/rest/api/3/issue/SYN-1")

    with tls_fixtures.ephemeral_listener(
        monkeypatch, service_tls_material, SERVICE,
    ) as (listener, _addr):
        with accept_loop_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, lock,
        ):
            first_thread = threading.Thread(
                target=lambda: roundtrip(base, wire_a, timeout=8.0), daemon=True,
            )
            first_thread.start()
            assert wait_until(lambda: flight_phase(gate, grant_a.lease_id) == "writing")
            time.sleep(3.3)  # past lease A's 3s deadline; A never returns

            closeout = gate.closeout(grant_a.lease_id)
            assert closeout.closeout_state == "overdue"

            second_data = roundtrip(base, wire_b)
            assert second_data == b""

            stuck.release()
            first_thread.join(6.0)
            assert not first_thread.is_alive()

        with lock:
            second_outcome = next(o for o in outcomes if o.reason == "dispatch_capacity")
    assert second_outcome.result == "closed_without_response"
    assert connector.connect_calls == 1


# === case 13: held gate (registry/gate clock domains diverge) ====================


def test_case13_held_gate_gives_gate_failure(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    offset = 5_000.0

    def offset_clock() -> float:
        return time.monotonic() + offset

    registry = LeaseRegistry(clock=offset_clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation)
    gate = fd.DispatchGate(registry=registry, ledger=ledger)  # gate keeps the real system clock
    policy = policy_with_golden()

    from tests.test_forwarder_exchange import golden_manifest
    manifest = golden_manifest()
    now = offset_clock()
    grant = registry.register(
        run_id="run-1", attempt_id="attempt-1", receiver_boot_id=BOOT, service=SERVICE,
        scope_digest=manifest.digest, expires_at=now + 30.0, generation=registry.generation,
    )
    registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
        launch_at=offset_clock(),
    )
    gate.install_scope(grant=grant, manifest=manifest)

    connector = FakeConnector()
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with tls_fixtures.ephemeral_listener(
        monkeypatch, service_tls_material, SERVICE,
    ) as (listener, _addr):
        with serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ):
            first_data = roundtrip(base, wire)
            assert completed.wait(3)
        assert outcomes[0].reason == "lease_denied"
        assert parse_response(first_data).status == 403
        assert gate.snapshot()["gate_state"] == "held"

        with serve_once_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes2, completed2,
        ):
            second_data = roundtrip(base, wire)
            assert completed2.wait(3)

    assert second_data == b""
    assert outcomes2[0].result == "closed_without_response"
    assert outcomes2[0].reason == "gate_failure"
    assert connector.connect_calls == 0
    entries_before = 1  # only the first (denial) receipt should ever exist
    assert len(ledger.snapshot()["entries"]) == entries_before


# === case 14: serve_one binds the listener's own service =========================


def test_case14_serve_one_binds_listener_service(monkeypatch, service_tls_material):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with tls_fixtures.ephemeral_listener(
        monkeypatch, service_tls_material, SERVICE,
    ) as (listener, _addr):
        assert listener.service == SERVICE
        # Holding the accepted socket defeats refcount cleanup, so only serve_one's own
        # close can leave it closed.
        accepted = []
        real_accept = listener.accept

        def recording_accept(*, timeout):
            connection = real_accept(timeout=timeout)
            accepted.append(connection)
            return connection
        monkeypatch.setattr(listener, "accept", recording_accept)
        with serve_one_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ):
            data = roundtrip(base, wire)
            assert completed.wait(3)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["service"] == SERVICE
    parsed = parse_response(data)
    assert parsed == ParsedResponse(status=200, body=ok_issue_get_body())
    assert len(accepted) == 1
    assert accepted[0].fileno() == -1  # closed after the one response


def test_case14_serve_one_on_the_confluence_listener_never_serves_jira(
    monkeypatch, service_tls_material,
):
    base, _paths = service_tls_material
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")  # Jira-shaped bytes

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, "confluence",
        ) as (listener, _addr),
        serve_one_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire, service="confluence")
        assert completed.wait(3)

    assert data == b""
    assert outcomes[0] == fx.ServeOutcome(
        "closed_without_response", "request_unreadable", None, None, None,
    )
    assert connector.prepare_calls == connector.connect_calls == 0
    assert ledger.snapshot()["entries"] == ()
