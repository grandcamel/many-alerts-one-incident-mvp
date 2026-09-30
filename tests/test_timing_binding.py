"""Focused contract tests for the model-facing synthetic timing binding.

These tests exercise the public dispatcher protocol.  They deliberately use the
controller-only completion and snapshot methods only to arrange/read fixture state;
those methods must never be admitted as model operations.
"""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from prototype.run_timing.executor import Lifecycle
from prototype.run_timing.timing_binding import (
    MAX_CALLS,
    MAX_HISTORY_BYTES,
    MAX_REQUEST_BYTES,
    SCOPE,
    TimingBinding,
)
from prototype.run_timing.timing_incidents import SECTIONS


@pytest.fixture
def binding() -> TimingBinding:
    return TimingBinding("binding-test", Lifecycle())


def request(call_id: str, operation: str, arguments: dict | None = None) -> dict:
    return {"call_id": call_id, "operation": operation, "arguments": arguments or {}}


def rejected(result: dict, *, code: str | None = None) -> dict:
    assert result["kind"] == "rejected"
    assert result["effect"] == "none"
    assert result["retry"] == "not_implicit"
    assert result["scope"] == SCOPE
    assert result["native_launch"] == "CLOSED"
    if code is not None:
        assert result["code"] == code
    return result


def notification(binding: TimingBinding, call_id: str = "notification") -> dict:
    response = binding.call(request(call_id, "notification.get"))
    assert response["operation"] == "notification.get"
    assert response["request_id"] == call_id
    assert response["status"] == "ok"
    assert response["items"]
    return response


def report_for(response: dict, members: list[str]) -> dict:
    fingerprints = [alert["fingerprint"] for alert in response["items"][0]["value"]["alerts"]]
    return {
        "sections": {section: "Synthetic binding evidence" for section in SECTIONS},
        "references": [{"response_id": response["response_id"], "item_index": 0}],
        "explanations": [
            {"fingerprint": fingerprint,
             "relation": "direct" if fingerprint in members else "unexplained"}
            for fingerprint in fingerprints
        ],
        "correction_of": None,
    }


def create_payload(response: dict) -> dict:
    member = response["items"][0]["value"]["alerts"][0]["fingerprint"]
    return {
        "summary": "Synthetic binding incident",
        "members": [member],
        "report": report_for(response, [member]),
    }


def test_describe_is_detached_and_excludes_controller_operations(binding):
    description = binding.describe()
    assert description["scope"] == SCOPE
    assert description["native_launch"] == "CLOSED"
    assert set(description["operations"]) >= {
        "notification.get", "metrics.list", "metrics.query", "logs.query",
        "traces.list", "traces.get", "changes.list", "incidents.candidates",
        "incidents.create", "incidents.append",
    }
    assert "complete" not in description["operations"]
    assert "audit_snapshot" not in description["operations"]
    description["operations"]["metrics.list"]["arguments"].append("path")
    description["operations"]["incidents.create"]["required"].clear()
    assert "path" not in binding.describe()["operations"]["metrics.list"]["arguments"]
    assert binding.describe()["operations"]["incidents.create"]["required"]


def test_constructor_does_not_bootstrap_notification_or_incident_store():
    lifecycle = Lifecycle()
    lifecycle.advance(270)
    bound = TimingBinding("expired-binding", lifecycle)
    snapshot = bound.audit_snapshot()
    assert snapshot["history"] == []
    assert snapshot["queries"]["responses"] == []
    assert snapshot["incident"] is None
    rejected(bound.call(request("late", "notification.get")), code="work_revoked_or_finished")


def test_queries_exist_but_initial_incident_operations_reject_without_empty_success(binding):
    catalog = binding.call(request("catalog", "metrics.list"))
    assert catalog["operation"] == "metrics.list"
    assert catalog["items"]
    for call_id, operation in (("candidate-before-notification", "incidents.candidates"),
                               ("create-before-notification", "incidents.create"),
                               ("append-before-notification", "incidents.append")):
        result = binding.call(request(call_id, operation))
        rejected(result, code="backend_rejected")
    assert binding.audit_snapshot()["incident"] is None


def test_notification_calls_are_fresh_correlated_responses_and_enable_incidents(binding):
    first = notification(binding, "notification-one")
    second = notification(binding, "notification-two")
    assert first["response_id"] != second["response_id"]
    assert first["request_id"] == "notification-one"
    assert second["request_id"] == "notification-two"
    assert first["response_sha256"] != second["response_sha256"]

    dispatch = binding.call(request("create", "incidents.create", create_payload(first)))
    assert dispatch["kind"] == "dispatch"
    assert dispatch["effect_outcome"] == "pending"
    assert "history" not in dispatch


def test_report_reference_uses_returned_notification_and_success_envelopes_are_unchanged(binding):
    response = notification(binding)
    payload = create_payload(response)
    result = binding.call(request("create", "incidents.create", payload))
    assert result["kind"] == "dispatch"
    assert result["operation"] == "create"
    assert result["request_id"] == "create"
    assert result["payload_sha256"]
    assert set(result) == {
        "version", "scope", "native_launch", "kind", "dispatch_id", "request_id",
        "operation", "at_virtual_seconds", "payload_sha256", "effect_outcome", "sha256",
    }
    dispatch_id = result["dispatch_id"]
    effect = binding.complete(dispatch_id)
    assert effect["effect_outcome"] == "confirmed"
    candidate = binding.call(request("candidate", "incidents.candidates"))
    assert candidate["kind"] == "candidates"
    assert candidate["items"][0]["report"]["report"]["references"] == payload["report"]["references"]


def test_pending_and_unknown_effects_hold_model_work(binding):
    response = notification(binding)
    dispatch = binding.call(request("create", "incidents.create", create_payload(response)))
    pending_candidates = binding.call(request("candidate-pending", "incidents.candidates"))
    assert pending_candidates["kind"] == "candidates"
    assert pending_candidates["items"] == []

    binding.complete(dispatch["dispatch_id"], disposition="unknown_before_apply")
    blocked_after_unknown = binding.call(request("candidate-unknown", "incidents.candidates"))
    rejected(blocked_after_unknown, code="backend_rejected")
    blocked_append = binding.call(request("append-unknown", "incidents.append"))
    rejected(blocked_append, code="backend_rejected")


@pytest.mark.parametrize("bad_request", [
    {"call_id": "extra-field", "operation": "metrics.list", "arguments": {}, "extra": 1},
    {"call_id": "bad-args", "operation": "metrics.list", "arguments": []},
    {"call_id": "unknown-op", "operation": "complete", "arguments": {}},
    {"call_id": "unknown-op-2", "operation": "audit_snapshot", "arguments": {}},
    {"call_id": "unknown-path", "operation": "shell", "arguments": {"path": "/tmp"}},
])
def test_malformed_unrecognized_and_controller_requests_are_structured_rejections(
    binding, bad_request
):
    rejected(binding.call(bad_request))


def test_valid_call_ids_are_consumed_by_rejections(binding):
    bad = request("consumed", "metrics.list", {"path": "/tmp"})
    rejected(binding.call(bad), code="backend_rejected")
    rejected(binding.call(request("consumed", "metrics.list")), code="duplicate_call_id")


def test_schema_rejection_consumes_call_id(binding):
    malformed = {"call_id": "schema-consumed", "operation": "metrics.list",
                 "arguments": {}, "extra": "rejected"}
    rejected(binding.call(malformed), code="invalid_request_schema")
    rejected(binding.call(request("schema-consumed", "metrics.list")),
             code="duplicate_call_id")


@pytest.mark.parametrize("call_id", [None, "", "Uppercase", "../path", "x" * 65])
def test_invalid_call_ids_are_rejected_without_empty_success(binding, call_id):
    rejected(binding.call(request(call_id, "metrics.list")), code="invalid_call_id")


def test_returned_outputs_and_history_are_detached_and_snapshots_are_read_only(binding):
    result = notification(binding)
    original = deepcopy(result)
    result["items"][0]["value"]["alerts"].clear()
    result["arguments"]["tampered"] = True
    result["response_sha256"] = "forged"
    snapshot = binding.audit_snapshot()
    retained = snapshot["history"][0]["response"]
    assert retained == original
    before_count = len(snapshot["history"])
    binding.audit_snapshot()
    assert len(binding.audit_snapshot()["history"]) == before_count


def test_oversized_input_is_rejected_without_retaining_unbounded_bytes(binding):
    oversized = request("oversized", "logs.query", {"contains": "x" * MAX_REQUEST_BYTES})
    result = rejected(binding.call(oversized), code="request_too_large")
    assert result["call_id"] == "oversized"
    record = binding.audit_snapshot()["history"][0]
    assert record["request"]["retention"] == "oversized_not_retained"
    assert record["request"]["bytes"] > MAX_REQUEST_BYTES
    assert record["request"]["sha256"]
    rejected(binding.call(request("oversized", "metrics.list")), code="duplicate_call_id")


def test_call_count_and_history_byte_bounds_are_explicit(binding):
    for index in range(MAX_CALLS):
        result = binding.call(request(f"fill-{index}", "metrics.list"))
        assert result["operation"] == "metrics.list"
    overflow = rejected(binding.call(request("overflow", "metrics.list")),
                        code="call_capacity_exhausted")
    assert overflow["retained"] is False
    snapshot = binding.audit_snapshot()
    assert len(snapshot["history"]) == MAX_CALLS
    assert snapshot["history_status"]["retained_calls"] == MAX_CALLS
    assert snapshot["history_status"]["dropped_observations"] == 1
    encoded_history = sum(len(json.dumps(item, sort_keys=True, separators=(",", ":")).encode())
                         for item in snapshot["history"])
    assert encoded_history <= MAX_HISTORY_BYTES


def test_revocation_is_never_an_empty_success_and_prior_history_remains(binding):
    first = binding.call(request("before-revoke", "metrics.list"))
    assert first["items"]
    binding.lifecycle.advance(270)
    result = rejected(binding.call(request("after-revoke", "changes.list")),
                      code="work_revoked_or_finished")
    assert "items" not in result
    snapshot = binding.audit_snapshot()
    assert snapshot["history"][-1]["response"] == result
