"""Deterministic tests for the one-request exchange (module 2).

``receive_request_sized`` and ``send_response`` are monkeypatched at
``forwarder_exchange``'s own module globals; the registry, the ledger and the
gate all share the real ``time.monotonic`` clock, since ``serve_request``
requires ``gate.system_clock is True``. Every sleep is at most 0.1 s.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ssl
import time

import pytest

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox import forwarder_exchange as fx
from grafana_jsm_sandbox import forwarder_receipts as fr
from grafana_jsm_sandbox.forwarder_dispatch import DispatchGate
from grafana_jsm_sandbox.forwarder_exchange import ServeOutcome, UpstreamError
from grafana_jsm_sandbox.forwarder_http_receive import HTTPReceiveError
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_json import canonical_json
from grafana_jsm_sandbox.forwarder_leases import LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptLedger
from grafana_jsm_sandbox.forwarder_response_send import ResponseSendError
from grafana_jsm_sandbox.forwarder_routes import JiraScope, RoutePolicy
from grafana_jsm_sandbox.forwarder_server_tls import FixedTLSListener
from tests.test_forwarder_routes import (
    DENIAL_DIGESTS,
    GOLDEN_SCOPE,
    ISSUE_GET_DIGEST,
    golden_manifest,
    golden_policy,
    make_request,
)

BOOT = "receiver-exchange"
SERVICE = "jira"

UNMATCHED_DIGEST = DENIAL_DIGESTS[("jira", "unmatched")]
ISSUE_GET_DENIAL_DIGEST = DENIAL_DIGESTS[("jira", "jira.issue.get")]
# The fake v2 digest formula from the plan, pinned against the golden v1 digest.
PREPARED_ISSUE_GET_DIGEST = "3bf1e11b2d062dd9d37a9b959c9ca290a0821153da52361cbc8cd74df7124acf"


# --- system setup (a real shared monotonic clock) -----------------------------


def new_real_system() -> tuple[DispatchGate, LeaseRegistry, ReceiptLedger]:
    registry = LeaseRegistry()
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation)
    gate = DispatchGate(registry=registry, ledger=ledger)
    return gate, registry, ledger


def install_lease(gate, registry, *, ttl=30.0, run_id="run-1", attempt_id="attempt-1",
                  manifest=None):
    manifest = manifest or golden_manifest(run_id=run_id, attempt_id=attempt_id)
    now = time.monotonic()
    grant = registry.register(
        run_id=run_id, attempt_id=attempt_id, receiver_boot_id=BOOT, service=SERVICE,
        scope_digest=manifest.digest, expires_at=now + ttl, generation=registry.generation,
    )
    registry.activate(
        lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
        launch_at=time.monotonic(),  # freshly read: >= record.created_at from register() above
    )
    entry = gate.install_scope(grant=grant, manifest=manifest)
    return grant, entry


def register_only(registry, *, ttl=30.0, run_id="run-2", attempt_id="attempt-1", manifest=None):
    """A registered-but-never-activated lease: installable, but always fails precheck."""
    manifest = manifest or golden_manifest(run_id=run_id, attempt_id=attempt_id)
    now = time.monotonic()
    return registry.register(
        run_id=run_id, attempt_id=attempt_id, receiver_boot_id=BOOT, service=SERVICE,
        scope_digest=manifest.digest, expires_at=now + ttl, generation=registry.generation,
    ), manifest


def policy_with_golden() -> RoutePolicy:
    return RoutePolicy(jira=golden_policy())


def issue_get_request(sentinel: str, **overrides):
    kwargs = {"path": "/rest/api/3/issue/90101", "sentinel": sentinel}
    kwargs.update(overrides)
    return make_request(**kwargs)


def ok_issue_get_body() -> bytes:
    return canonical_json({
        "id": "90101", "key": "SYN-1",
        "fields": {"project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"}},
    })


# --- receive/send fakes --------------------------------------------------------


def patch_receive(monkeypatch, request, request_bytes=100, *, sleep=0.0, error=None):
    def fake(connection, service, *, deadline, allowed_query_keys=frozenset(),
            accept="application/json"):
        if sleep:
            time.sleep(sleep)
        if error is not None:
            raise error
        return request, request_bytes
    monkeypatch.setattr(fx, "receive_request_sized", fake)


def patch_send(monkeypatch, *, error=None, sink=None):
    def fake(connection, ledger, receipt, response, *, deadline):
        if sink is not None:
            sink.append({"receipt": receipt, "response": response, "deadline": deadline})
        if error is not None:
            raise error
    monkeypatch.setattr(fx, "send_response", fake)


# --- fake upstream connector and channel ---------------------------------------


def fake_prepare_v2(routed):
    return hashlib.sha256(b"fake-v2|" + routed.request_digest.encode()).hexdigest()


class FakeConnector:
    def __init__(self, *, prepare=fake_prepare_v2, connect=None):
        self._prepare = prepare
        self._connect = connect
        self.prepare_calls = 0
        self.connect_calls = 0

    def prepare(self, routed):
        self.prepare_calls += 1
        return self._prepare(routed)

    def connect(self, admission, routed, *, request_digest, deadline):
        self.connect_calls += 1
        if self._connect is None:
            raise AssertionError("connect not expected in this test")
        return self._connect(admission, routed, request_digest=request_digest, deadline=deadline)


class FakeChannel:
    def __init__(self, *, response=None, send_error=None, receive_error=None):
        self.response = response
        self.send_error = send_error
        self.receive_error = receive_error
        self.send_calls = 0
        self.receive_calls = 0
        self.abort_calls = 0
        self.close_calls = 0

    def send(self, *, deadline):
        self.send_calls += 1
        if self.send_error is not None:
            raise self.send_error

    def receive(self, *, deadline):
        self.receive_calls += 1
        if self.receive_error is not None:
            raise self.receive_error
        return self.response

    def abort(self):
        self.abort_calls += 1

    def close(self):
        self.close_calls += 1


def delivered_row(ledger, sink):
    receipt = sink[0]["receipt"]
    return next(item for item in ledger.snapshot()["entries"]
                if item["receipt_id"] == receipt.receipt_id)


def assert_receipt_deadline(ledger, sink, expected):
    """The delivered receipt's ledger deadline and its delivery deadline both equal ``expected``."""
    assert delivered_row(ledger, sink)["deadline"] == expected
    assert sink[0]["deadline"] == expected


def assert_request_bytes(ledger, sink, expected):
    """The delivered receipt and its ledger row both carry the exact inbound byte count."""
    assert sink[0]["receipt"].request_bytes == expected
    assert delivered_row(ledger, sink)["request_bytes"] == expected


def dispatch_deadline(started, entry):
    return min(started + fd.MAX_HANDLER_SECONDS, entry.expires_at)


def run_serve_request(monkeypatch, gate, policy, *, request, upstream, sink=None,
                      started=None, request_bytes=100):
    patch_receive(monkeypatch, request, request_bytes)
    patch_send(monkeypatch, sink=sink if sink is not None else [])
    return fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=upstream,
        started=started if started is not None else time.monotonic(),
    )


# === E2: the absolute handler deadline =========================================


def test_e2_started_too_old_gives_deadline_expired(monkeypatch):
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()

    def never_called(*args, **kwargs):
        raise AssertionError("receive must not run once E2 has already closed")
    monkeypatch.setattr(fx, "receive_request_sized", never_called)

    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None,
        started=time.monotonic() - fd.MAX_HANDLER_SECONDS - 1.0,
    )
    assert outcome == ServeOutcome("closed_without_response", "deadline_expired", None, None, None)


def test_e2_started_in_the_future_gives_deadline_expired(monkeypatch):
    """F11-1: E2's bound is two-sided (``now - 40 < started <= now``); a
    ``started`` in the future must also close ``deadline_expired``."""
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()

    def never_called(*args, **kwargs):
        raise AssertionError("receive must not run once E2 has already closed")
    monkeypatch.setattr(fx, "receive_request_sized", never_called)

    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None,
        started=time.monotonic() + 5.0,
    )
    assert outcome == ServeOutcome("closed_without_response", "deadline_expired", None, None, None)


def test_e2_deny_deadline_expired_when_receive_overruns_handler_deadline(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, manifest = register_only(registry)  # registered but not active: precheck fails
    gate.install_scope(grant=grant, manifest=manifest)
    request = issue_get_request(grant.sentinel)

    # Barely inside the 40s handler window; a 0.12s receive stall then exceeds it.
    started = time.monotonic() - fd.MAX_HANDLER_SECONDS + 0.05
    sink = []
    patch_receive(monkeypatch, request, sleep=0.12)
    patch_send(monkeypatch, sink=sink)

    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None, started=started,
    )
    assert outcome == ServeOutcome("closed_without_response", "deadline_expired", None, None, None)
    assert sink == []
    assert ledger.snapshot()["entries"] == ()


def test_held_gate_gives_gate_failure(monkeypatch):
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()

    class FaultingClock:
        def __call__(self):
            raise RuntimeError("boom")
    gate._clock = FaultingClock()
    assert gate.system_clock is True  # fixed at construction; unaffected by this swap

    def never_called(*args, **kwargs):
        raise AssertionError("receive must not run once the gate is held")
    monkeypatch.setattr(fx, "receive_request_sized", never_called)

    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None,
        started=time.monotonic(),
    )
    assert outcome == ServeOutcome("closed_without_response", "gate_failure", None, None, None)


def test_shutdown_after_a_transient_clock_fault_keeps_gate_failure(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry)

    def faulting():
        raise RuntimeError("boom")
    gate._clock = faulting
    with pytest.raises(fd.DispatchError):
        gate.now()
    gate._clock = time.monotonic  # the fault was transient; the hold must not lift
    gate.shutdown()

    sink = []
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink)
    assert outcome == ServeOutcome("closed_without_response", "gate_failure", None, None, None)
    assert sink == []
    assert ledger.snapshot()["entries"] == ()


# === E3-E4: receive and resolve =================================================


def test_e3_unreadable_request_closes(monkeypatch):
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()
    patch_receive(monkeypatch, None, error=HTTPReceiveError("receive_failed"))
    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None,
        started=time.monotonic(),
    )
    assert outcome == ServeOutcome(
        "closed_without_response", "request_unreadable", None, None, None,
    )


def test_e4_unknown_sentinel_closes(monkeypatch):
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()
    request = issue_get_request("s" * 43)  # a shape-valid sentinel bound to no lease
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None)
    assert outcome == ServeOutcome("closed_without_response", "sentinel_unknown", None, None, None)


# === E5: precheck denial (the deliberate unclipped-deadline deviation) =========


def test_e5_precheck_denial_has_unmatched_digest(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, manifest = register_only(registry)
    gate.install_scope(grant=grant, manifest=manifest)
    request = issue_get_request(grant.sentinel)
    sink = []
    started = time.monotonic()
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink, started=started, request_bytes=137)
    assert outcome.result == "responded"
    assert outcome.reason == "lease_denied"
    assert outcome.dispatch_state == "NOT_DISPATCHED"
    receipt = sink[0]["receipt"]
    assert receipt.request_digest == UNMATCHED_DIGEST
    assert receipt.route_id == "unmatched"
    assert ledger.snapshot()["counts_by_state"]["finalized"] == 1
    assert_receipt_deadline(ledger, sink, started + fd.MAX_HANDLER_SECONDS)
    assert_request_bytes(ledger, sink, 137)


def test_e5_expired_lease_gets_its_403_on_the_unclipped_deadline(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=0.05)
    time.sleep(0.1)
    sink = []
    started = time.monotonic()
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink, started=started)
    assert (outcome.result, outcome.reason) == ("responded", "lease_denied")
    assert sink[0]["receipt"].request_digest == UNMATCHED_DIGEST
    assert_receipt_deadline(ledger, sink, started + fd.MAX_HANDLER_SECONDS)


# === E6: route policy denials ====================================================


def test_e6_route_unknown_denial_has_unmatched_digest(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel, path="/not/a/known/route")
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink)
    assert outcome.reason == "route_denied"
    assert sink[0]["receipt"].request_digest == UNMATCHED_DIGEST
    assert_receipt_deadline(ledger, sink, entry.expires_at)


def test_e6_route_not_in_scope_denial_has_route_digest(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    # Scoped for jira.issue.get only; a search request matches a real route ID
    # that is simply absent from this manifest's declared routes.
    manifest = golden_manifest(
        routes=("jira.issue.get",),
        scope=JiraScope(issues=GOLDEN_SCOPE.issues, search_labels=()),
    )
    grant, entry = install_lease(gate, registry, manifest=manifest)
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", sentinel=grant.sentinel,
        body=canonical_json({"jql": "anything"}),
    )
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink, request_bytes=137)
    assert outcome.reason == "route_denied"
    assert sink[0]["receipt"].request_digest == DENIAL_DIGESTS[("jira", "jira.search")]
    assert_receipt_deadline(ledger, sink, entry.expires_at)
    assert_request_bytes(ledger, sink, 137)


# === E7: pre-reserve denials =====================================================


def test_e7a_permit_required_denies_permit_denied(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)

    real_route = policy.route

    def route_requiring_permit(req, manifest):
        return dataclasses.replace(real_route(req, manifest), requires_permit=True)
    monkeypatch.setattr(policy, "route", route_requiring_permit)

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink)
    assert outcome.reason == "permit_denied"
    assert sink[0]["receipt"].request_digest == ISSUE_GET_DENIAL_DIGEST
    assert_receipt_deadline(ledger, sink, entry.expires_at)


def test_e7b_no_upstream_denies_route_denied(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink)
    assert outcome.reason == "route_denied"
    assert sink[0]["receipt"].request_digest == ISSUE_GET_DENIAL_DIGEST
    assert_receipt_deadline(ledger, sink, entry.expires_at)


def test_e7c_v1_digest_leak_denies_route_denied(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)

    leaky = FakeConnector(prepare=lambda routed: routed.request_digest)
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=leaky,
                                sink=sink, request_bytes=137)
    assert outcome.reason == "route_denied"
    receipt = sink[0]["receipt"]
    literal = "d25b40c66fc9a150a6337bf0aeb2f8bf783b8b2196511a76577a23a2aa0c14ae"
    assert receipt.request_digest == ISSUE_GET_DENIAL_DIGEST == literal
    assert leaky.connect_calls == 0
    assert_receipt_deadline(ledger, sink, entry.expires_at)
    assert_request_bytes(ledger, sink, 137)


def test_e7c_malformed_prepare_result_denies_route_denied(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)

    bad = FakeConnector(prepare=lambda routed: "not-hex")
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=bad,
                                sink=sink)
    assert outcome.reason == "route_denied"
    assert sink[0]["receipt"].request_digest == ISSUE_GET_DENIAL_DIGEST


def test_e7c_prepare_raising_denies_route_denied(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)

    def boom(routed):
        raise RuntimeError("prepare exploded")
    bad = FakeConnector(prepare=boom)
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=bad,
                                sink=sink)
    assert outcome.reason == "route_denied"
    assert sink[0]["receipt"].request_digest == ISSUE_GET_DENIAL_DIGEST


def test_e7d_insufficient_dispatch_time_denies_deadline(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=1.5)
    request = issue_get_request(grant.sentinel)
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 0)  # E7d must deny before reserve
    connector = FakeConnector()
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome.reason == "deadline"
    assert sink[0]["receipt"].request_digest == PREPARED_ISSUE_GET_DIGEST
    assert connector.connect_calls == 0
    assert_receipt_deadline(ledger, sink, entry.expires_at)


def test_e7d_reads_a_fresh_clock_after_a_slow_receive(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    # Just over the 2.0 s budget at E2; the 0.1 s receive pushes it under before reserve.
    grant, entry = install_lease(gate, registry, ttl=2.08)
    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 0)
    patch_receive(monkeypatch, issue_get_request(grant.sentinel), sleep=0.1)
    sink = []
    patch_send(monkeypatch, sink=sink)
    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=FakeConnector(),
        started=time.monotonic(),
    )
    assert (outcome.result, outcome.reason) == ("responded", "deadline")
    assert sink[0]["receipt"].request_digest == PREPARED_ISSUE_GET_DIGEST
    assert_receipt_deadline(ledger, sink, entry.expires_at)


# === E8: reserve denials =========================================================


def test_e8_full_ledger_during_reserve_closes_receipt_unavailable(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)
    connector = FakeConnector()

    monkeypatch.setattr(fr, "MAX_RECEIPTS", 1)
    ledger.reserve(
        lease_id="filler-lease", attempt_id="attempt-1", service="jira",
        route_id="jira.issue.get", request_digest="0" * 64, request_bytes=10,
        deadline=time.monotonic() + 30.0,
    )

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome == ServeOutcome("closed_without_response", "receipt_unavailable", None, None,
                                   None)
    assert connector.connect_calls == 0
    assert len(ledger.snapshot()["entries"]) == 1
    assert sink == []


def test_e8_full_ledger_during_route_denial_closes_receipt_unavailable(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel, path="/not/a/known/route")

    monkeypatch.setattr(fr, "MAX_RECEIPTS", 1)
    ledger.reserve(
        lease_id="filler-lease", attempt_id="attempt-1", service="jira",
        route_id="jira.issue.get", request_digest="0" * 64, request_bytes=10,
        deadline=time.monotonic() + 30.0,
    )

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=None,
                                sink=sink)
    assert outcome == ServeOutcome("closed_without_response", "receipt_unavailable", None, None,
                                   None)
    assert len(ledger.snapshot()["entries"]) == 1
    assert sink == []


def test_e8_flight_capacity_gives_dispatch_capacity(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)
    routed = policy.route(issue_get_request(grant.sentinel), entry.manifest)

    monkeypatch.setattr(fd, "MAX_OPEN_DISPATCHES", 1)
    gate.reserve(
        entry, routed, request_digest=fake_prepare_v2(routed), request_bytes=10,
        deadline=time.monotonic() + 5.0,
    )

    connector = FakeConnector()
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector)
    assert outcome == ServeOutcome("closed_without_response", "dispatch_capacity", None, None,
                                   None)
    assert connector.connect_calls == 0


def test_e8_gate_closed_race_denies_lease_denied(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)

    def shutdown_right_after_precheck(checked_entry, *, sentinel):
        assert checked_entry is entry
        gate.shutdown()
        return True
    monkeypatch.setattr(gate, "precheck", shutdown_right_after_precheck)

    connector = FakeConnector()
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome.reason == "lease_denied"
    assert sink[0]["receipt"].request_digest == PREPARED_ISSUE_GET_DIGEST
    assert connector.connect_calls == 0
    assert_receipt_deadline(ledger, sink, entry.expires_at)


def test_e8_route_unavailable_gives_route_denied_with_prepared_digest(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry)
    request = issue_get_request(grant.sentinel)

    from grafana_jsm_sandbox.forwarder_routes import ROUTE_CATALOG
    unavailable = dict(ROUTE_CATALOG)
    unavailable["jira.issue.get"] = dataclasses.replace(
        unavailable["jira.issue.get"], state="unavailable",
    )
    monkeypatch.setattr(fd, "ROUTE_CATALOG", unavailable)

    connector = FakeConnector()
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink, request_bytes=137)
    assert outcome.reason == "route_denied"
    receipt = sink[0]["receipt"]
    assert receipt.request_digest == PREPARED_ISSUE_GET_DIGEST
    assert_request_bytes(ledger, sink, 137)
    assert PREPARED_ISSUE_GET_DIGEST == hashlib.sha256(
        b"fake-v2|" + ISSUE_GET_DIGEST.encode(),
    ).hexdigest()
    assert connector.connect_calls == 0
    assert_receipt_deadline(ledger, sink, entry.expires_at)


# === delivery failures (E18) ======================================================


def test_delivery_failed_maps_response_send_error_and_other_exceptions(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, manifest = register_only(registry)
    gate.install_scope(grant=grant, manifest=manifest)
    request = issue_get_request(grant.sentinel)

    patch_receive(monkeypatch, request)
    patch_send(monkeypatch, error=ResponseSendError("send_failed"))
    outcome = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None,
        started=time.monotonic(),
    )
    assert outcome.result == "delivery_failed"
    assert outcome.reason == "send_failed"
    assert outcome.dispatch_state == "NOT_DISPATCHED"

    grant2, manifest2 = register_only(registry, run_id="run-3")
    gate.install_scope(grant=grant2, manifest=manifest2)
    request2 = issue_get_request(grant2.sentinel)
    patch_receive(monkeypatch, request2)
    patch_send(monkeypatch, error=RuntimeError("boom"))
    outcome2 = fx.serve_request(
        object(), service=SERVICE, gate=gate, policy=policy, upstream=None,
        started=time.monotonic(),
    )
    assert outcome2.result == "delivery_failed"
    assert outcome2.reason == "internal_failure"


# === serve_one ====================================================================


def test_serve_one_unopened_listener_gives_accept_failed():
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    listener = FixedTLSListener("jira", context=context)
    outcome = fx.serve_one(listener, gate=gate, policy=policy, upstream=None)
    assert outcome == ServeOutcome("closed_without_response", "accept_failed", None, None, None)


def test_serve_one_gate_failure_when_started_time_read_raises(monkeypatch):
    """F10-1: when the post-accept ``started = gate.now()`` read raises, serve_one
    must return ``gate_failure`` and still close the accepted connection."""
    gate, _registry, _ledger = new_real_system()
    policy = policy_with_golden()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    listener = FixedTLSListener("jira", context=context)

    class DummyConnection:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    dummy = DummyConnection()
    monkeypatch.setattr(listener, "accept", lambda timeout: dummy)

    class FaultingClock:
        def __call__(self):
            raise RuntimeError("boom")
    gate._clock = FaultingClock()
    assert gate.system_clock is True  # fixed at construction; unaffected by this swap

    outcome = fx.serve_one(listener, gate=gate, policy=policy, upstream=None)
    assert outcome == ServeOutcome("closed_without_response", "gate_failure", None, None, None)
    assert dummy.closed is True


# === the full admitted path: success, connect/send/receive mapping, E16, E17 =====


def test_full_success_delivers_transport_confirmed_with_prepared_digest(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    sink = []
    started = time.monotonic()
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink, started=started)

    assert outcome.result == "responded"
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    assert outcome.delivery == "sent"
    receipt = sink[0]["receipt"]
    assert receipt.request_digest == PREPARED_ISSUE_GET_DIGEST
    assert_receipt_deadline(ledger, sink, dispatch_deadline(started, entry))
    assert connector.prepare_calls == 1
    assert connector.connect_calls == 1
    assert channel.send_calls == 1
    assert channel.receive_calls == 1
    assert channel.close_calls == 1
    assert channel.abort_calls == 0
    assert gate.snapshot()["open_dispatches"] == 0
    assert ledger.snapshot()["counts_by_state"]["finalized"] == 1


class RecordingChannel(FakeChannel):
    def __init__(self, seen, **kwargs):
        super().__init__(**kwargs)
        self.seen = seen

    def send(self, *, deadline):
        self.seen["send"] = deadline
        super().send(deadline=deadline)

    def receive(self, *, deadline):
        self.seen["receive"] = deadline
        return super().receive(deadline=deadline)


def test_phase_deadlines_passed_to_connect_send_and_receive(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=30.0)  # long enough that no clip applies
    seen = {}
    channel = RecordingChannel(seen, response=ParsedResponse(status=200, body=ok_issue_get_body()))

    def connect(admission, routed, *, request_digest, deadline):
        seen["admission"] = admission
        seen["connect"] = deadline
        return channel
    connector = FakeConnector(connect=connect)
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector)
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    admission = seen["admission"]
    assert seen["connect"] == admission.connect_deadline
    assert admission.connect_deadline == admission.admitted_at + fd.CONNECT_SECONDS
    assert admission.admitted_at + fd.WRITE_SECONDS <= seen["send"] < admission.exchange_deadline
    assert seen["receive"] == admission.exchange_deadline


def test_connect_failure_maps_to_failed_connect_failed(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    def boom(*a, **k):
        raise OSError("connection refused")
    connector = FakeConnector(connect=boom)
    sink = []
    started = time.monotonic()
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink, started=started)
    assert outcome.result == "responded"
    assert outcome.dispatch_state == "FAILED"
    assert sink[0]["receipt"].reason == "connect_failed"
    assert_receipt_deadline(ledger, sink, dispatch_deadline(started, entry))


def test_admit_denial_is_delivered_on_the_dispatch_deadline(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=10.0)
    real_precheck = gate.precheck

    def revoke_right_after_precheck(checked_entry, *, sentinel):
        passed = real_precheck(checked_entry, sentinel=sentinel)
        registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                        generation=registry.generation, reason="operator_cancel")
        return passed
    monkeypatch.setattr(gate, "precheck", revoke_right_after_precheck)

    connector = FakeConnector()
    sink = []
    started = time.monotonic()
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink, started=started)
    assert (outcome.result, outcome.reason) == ("responded", "lease_denied")
    assert outcome.dispatch_state == "NOT_DISPATCHED"
    assert sink[0]["receipt"].request_digest == PREPARED_ISSUE_GET_DIGEST
    assert connector.connect_calls == 0
    assert_receipt_deadline(ledger, sink, dispatch_deadline(started, entry))


def test_connect_failure_upstream_tls_failed_maps_correctly(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    def boom(*a, **k):
        raise UpstreamError("upstream_tls_failed")
    connector = FakeConnector(connect=boom)
    sink = []
    run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector, sink=sink)
    assert sink[0]["receipt"].reason == "upstream_tls_failed"
    assert sink[0]["receipt"].dispatch_state == "FAILED"


def test_send_failure_maps_to_dispatched_unknown_write_failed(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(send_error=OSError("broken pipe"))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert sink[0]["receipt"].dispatch_state == "DISPATCHED_UNKNOWN"
    assert sink[0]["receipt"].reason == "write_failed"
    assert outcome.result == "responded"


def test_receive_deadline_error_maps_to_deadline(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(receive_error=UpstreamError("deadline"))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    sink = []
    run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector, sink=sink)
    assert sink[0]["receipt"].dispatch_state == "DISPATCHED_UNKNOWN"
    assert sink[0]["receipt"].reason == "deadline"


def test_malformed_upstream_response_gives_malformed_response(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(response=ParsedResponse(status=302, body=b""))
    connector = FakeConnector(connect=lambda *a, **k: channel)
    sink = []
    run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector, sink=sink)
    assert sink[0]["receipt"].dispatch_state == "DISPATCHED_UNKNOWN"
    assert sink[0]["receipt"].reason == "malformed_response"


def test_malformed_channel_has_close_called_once(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    class MalformedChannel:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    malformed = MalformedChannel()
    connector = FakeConnector(connect=lambda *a, **k: malformed)
    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert malformed.close_calls == 1
    assert sink[0]["receipt"].dispatch_state == "FAILED"
    assert sink[0]["receipt"].reason == "connect_failed"
    assert outcome.result == "responded"


def test_channel_whose_attribute_lookup_raises_is_a_malformed_channel(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)

    class RaisingChannel:
        def __getattr__(self, name):
            raise KeyError("MARK-CHANNEL-ATTR")

    connector = FakeConnector(connect=lambda *a, **k: RaisingChannel())
    sink = []
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert (outcome.result, outcome.dispatch_state) == ("responded", "FAILED")
    assert sink[0]["receipt"].reason == "connect_failed"
    assert "MARK" not in repr(outcome)
    assert gate.snapshot()["open_dispatches"] == 0
    assert ledger.snapshot()["counts_by_state"]["finalized"] == 1


class FlakyAttributeChannel(FakeChannel):
    """Passes validation, then raises once each named attribute's lookups run out."""

    def __init__(self, *, lookups, **kwargs):
        self._lookups = lookups
        super().__init__(**kwargs)

    def __getattribute__(self, name):
        lookups = object.__getattribute__(self, "_lookups")
        if name in lookups:
            if lookups[name] == 0:
                raise RuntimeError("MARK-FLAKY-" + name)
            lookups[name] -= 1
        return object.__getattribute__(self, name)


def test_raising_abort_and_close_lookups_never_lose_the_fence_denial(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=10.0)
    # abort: validation and attach succeed, the fence-denial abort raises;
    # close: validation succeeds, the final close raises.
    channel = FlakyAttributeChannel(lookups={"abort": 2, "close": 1})

    def connect_then_revoke(*a, **k):
        registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                        generation=registry.generation, reason="operator_cancel")
        return channel
    connector = FakeConnector(connect=connect_then_revoke)
    sink = []
    started = time.monotonic()
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink, started=started)
    assert (outcome.result, outcome.dispatch_state) == ("responded", "FAILED")
    assert sink[0]["receipt"].reason == "connect_failed"
    assert channel.send_calls == 0
    assert gate.snapshot()["open_dispatches"] == 0
    assert_receipt_deadline(ledger, sink, dispatch_deadline(started, entry))


def test_upstream_whose_attribute_lookup_raises_is_a_type_error():
    gate, _registry, _ledger = new_real_system()

    class RaisingUpstream:
        def __getattr__(self, name):
            raise KeyError(name)

    with pytest.raises(TypeError):
        fx.serve_request(
            object(), service=SERVICE, gate=gate, policy=policy_with_golden(),
            upstream=RaisingUpstream(), started=time.monotonic(),
        )


def test_e16_attach_abort_raise_gives_failed_connect_failed(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)

    def bad_attach(admission, abort):
        raise RuntimeError("boom")
    monkeypatch.setattr(gate, "attach_abort", bad_attach)

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome.result == "responded"
    assert sink[0]["receipt"].dispatch_state == "FAILED"
    assert sink[0]["receipt"].reason == "connect_failed"
    assert channel.send_calls == 0
    assert channel.receive_calls == 0
    assert channel.close_calls == 1


def test_e16_check_response_raise_gives_dispatched_unknown_abandoned(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)

    def bad_check_response(routed, response):
        raise RuntimeError("boom")
    monkeypatch.setattr(policy, "check_response", bad_check_response)

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome.result == "responded"
    assert sink[0]["receipt"].dispatch_state == "DISPATCHED_UNKNOWN"
    assert sink[0]["receipt"].reason == "abandoned"
    assert channel.send_calls == 1
    assert channel.receive_calls == 1


def test_e17_invalid_outcome_fallback_delivers(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)

    real_finish = gate.finish
    calls = {"n": 0}

    def patched_finish(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise fd.DispatchError("invalid_outcome")
        return real_finish(*args, **kwargs)
    monkeypatch.setattr(gate, "finish", patched_finish)

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome.result == "responded"
    assert calls["n"] == 2
    receipt = sink[0]["receipt"]
    assert receipt.dispatch_state == "DISPATCHED_UNKNOWN"
    assert receipt.reason == "abandoned"


@pytest.mark.parametrize("site", ["connect", "attach_abort"])
def test_e17_fallback_before_the_fence_is_failed_connect_failed(monkeypatch, site):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, entry = install_lease(gate, registry, ttl=10.0)
    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))

    def connect(*a, **k):
        if site == "connect":
            raise OSError("connection refused")
        return channel
    connector = FakeConnector(connect=connect)

    def bad_attach(admission, abort):
        raise RuntimeError("boom")
    if site == "attach_abort":
        monkeypatch.setattr(gate, "attach_abort", bad_attach)

    real_finish = gate.finish
    finishes = []

    def patched_finish(admission, **kwargs):
        finishes.append((kwargs["dispatch_state"], kwargs["reason"]))
        if len(finishes) == 1:
            raise fd.DispatchError("invalid_outcome")
        return real_finish(admission, **kwargs)
    monkeypatch.setattr(gate, "finish", patched_finish)

    sink = []
    started = time.monotonic()
    request = issue_get_request(grant.sentinel)
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink, started=started)
    # Zero application bytes were written, so the fallback must not claim a dispatch.
    assert finishes == [("FAILED", "connect_failed")] * 2
    assert (outcome.result, outcome.dispatch_state, outcome.reason) == (
        "responded", "FAILED", "connect_failed",
    )
    assert connector.connect_calls == 1
    assert channel.send_calls == 0
    assert_receipt_deadline(ledger, sink, dispatch_deadline(started, entry))


def test_e17_receipt_unavailable_closes(monkeypatch):
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    channel = FakeChannel(response=ParsedResponse(status=200, body=ok_issue_get_body()))
    connector = FakeConnector(connect=lambda *a, **k: channel)

    def always_fails(*args, **kwargs):
        raise fd.DispatchError("receipt_unavailable")
    monkeypatch.setattr(gate, "finish", always_fails)

    sink = []
    outcome = run_serve_request(monkeypatch, gate, policy, request=request, upstream=connector,
                                sink=sink)
    assert outcome == ServeOutcome("closed_without_response", "receipt_unavailable", None, None,
                                   None)
    assert sink == []


def test_base_exception_from_send_propagates_and_cleans_up(monkeypatch):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    request = issue_get_request(grant.sentinel)

    class Marker(BaseException):
        pass

    class RaisingChannel:
        def __init__(self):
            self.close_calls = 0

        def send(self, *, deadline):
            raise Marker("boom")

        def receive(self, *, deadline):
            raise AssertionError("must not be reached")

        def abort(self):
            pass

        def close(self):
            self.close_calls += 1

    channel = RaisingChannel()
    connector = FakeConnector(connect=lambda *a, **k: channel)
    patch_receive(monkeypatch, request)
    patch_send(monkeypatch, sink=[])

    with pytest.raises(Marker):
        fx.serve_request(
            object(), service=SERVICE, gate=gate, policy=policy, upstream=connector,
            started=time.monotonic(),
        )

    assert channel.close_calls == 1
    assert gate.snapshot()["open_dispatches"] == 0
    # finish() was never called: the ledger entry is still open (in flight),
    # not finalized -- confirming exchange.py did not swallow the BaseException.
    entries = ledger.snapshot()["entries"]
    assert len(entries) == 1
    assert entries[0]["entry_state"] == "dispatched"


class Interrupt(BaseException):
    """Stands in for a supervisor's cancellation raised from the client socket."""


@pytest.mark.parametrize("site", ["connect", "send", "receive", "check_response"])
def test_base_exception_during_delivery_never_chains_connector_text(monkeypatch, site):
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    marker = OSError("MARK-CONNECTOR-SECRET")
    channel = FakeChannel(
        response=ParsedResponse(status=200, body=ok_issue_get_body()),
        send_error=marker if site == "send" else None,
        receive_error=marker if site == "receive" else None,
    )

    def connect(*a, **k):
        if site == "connect":
            raise marker
        return channel

    def bad_check_response(routed, response):
        raise marker
    if site == "check_response":
        monkeypatch.setattr(policy, "check_response", bad_check_response)

    patch_receive(monkeypatch, issue_get_request(grant.sentinel))
    patch_send(monkeypatch, error=Interrupt("stop"))
    with pytest.raises(Interrupt) as caught:
        fx.serve_request(
            object(), service=SERVICE, gate=gate, policy=policy,
            upstream=FakeConnector(connect=connect), started=time.monotonic(),
        )
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert "MARK" not in repr(caught.value)
    assert gate.snapshot()["open_dispatches"] == 0
    assert ledger.snapshot()["counts_by_state"]["finalized"] == 1  # recorded before delivery
