"""Fixed local dispatcher for the ticket 23 synthetic timing rehearsal.

It is a trusted, single-threaded Python object, not a security boundary, native tool server,
or model client.  The caller is responsible for keeping this object and its controller-only
methods out of model code.  The fixed dispatcher itself admits no paths, callbacks, executables,
schema extensions, or completion controls.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy

from .executor import Lifecycle
from .timing_incidents import IncidentRejected, TimingIncidents
from .timing_queries import MAX_RESPONSE_BYTES, OPERATIONS, QueryRejected, TimingQueries
from .timing_snapshot import capture_timing_snapshot

SCOPE = "OFFLINE_SYNTHETIC_TIMING_BINDING_ONLY"
MAX_REQUEST_BYTES = 16 * 1024
MAX_CALLS = 64
# Derived ceiling for these fixed bounded backends, not an independent storage quota.
MAX_HISTORY_BYTES = MAX_CALLS * (MAX_REQUEST_BYTES + MAX_RESPONSE_BYTES + 2048)
MAX_DROPPED_OBSERVATIONS = 2**31 - 1
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_INCIDENT_OPERATIONS = ("incidents.candidates", "incidents.create", "incidents.append")
_MODEL_OPERATIONS = tuple(OPERATIONS) + _INCIDENT_OPERATIONS


def _encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identifier(value: object) -> str | None:
    return value if isinstance(value, str) and _IDENTIFIER.fullmatch(value) else None


class TimingBinding:
    """Bind pinned queries and one synthetic Incident store behind a finite JSON protocol."""

    def __init__(self, attempt_id: str, lifecycle: Lifecycle):
        if type(lifecycle) is not Lifecycle:
            raise TypeError("shared Lifecycle required")
        self.attempt_id = attempt_id
        self.lifecycle = lifecycle
        self._queries = TimingQueries(attempt_id, lifecycle)
        self._notification_response_id: str | None = None
        self._incidents: TimingIncidents | None = None
        self._call_ids: set[str] = set()
        self._history: list[bytes] = []
        self._dropped_observations = 0

    def describe(self) -> dict:
        """Return only model-callable operations; controller methods are intentionally absent."""
        queries = self._queries.describe()
        operations = {
            name: {"kind": "query", "arguments": queries["operations"][name]["arguments"],
                   "required": queries["operations"][name]["required"]}
            for name in OPERATIONS
        }
        operations["notification.get"]["delivery"] = "initializes_incident_store_once_on_success"
        operations.update({
            "incidents.candidates": {"kind": "candidate_read", "arguments": [], "required": []},
            "incidents.create": {"kind": "write_intent", "arguments": ["summary", "members", "report"],
                                 "required": ["summary", "members", "report"]},
            "incidents.append": {"kind": "write_intent",
                                 "arguments": ["incident_id", "expected_revision", "members", "report"],
                                 "required": ["incident_id", "expected_revision", "members", "report"]},
        })
        return {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                "trust_boundary": "trusted_same_process_not_security_boundary",
                "request": {"exact_fields": ["call_id", "operation", "arguments"],
                            "call_id": "lowercase alphanumeric plus hyphen/underscore, 1..64",
                            "canonical_json_max_bytes": MAX_REQUEST_BYTES},
                "operations": operations,
                "limits": {"model_calls": MAX_CALLS, "history_max_bytes": MAX_HISTORY_BYTES},
                "rejections": "structured; distinct from backend empty or not_found success",
                "initialization": ("first successful notification.get initializes the one Incident store; "
                                   "Incident operations reject before then"),
                "completion": "controller_only_separate_api; write dispatches remain pending"}

    def call(self, request: dict) -> dict:
        """Dispatch exactly one bounded model request and retain its detached outcome when possible."""
        # Lifecycle closure wins before parsing or routing every model request.
        if not self.lifecycle.work_allowed:
            call_id, _ = self._claim_call_id(request) if len(self._history) < MAX_CALLS else (None, False)
            return self._reject(request, "work_revoked_or_finished", call_id=call_id)
        if len(self._history) >= MAX_CALLS:
            self._dropped_observations = min(MAX_DROPPED_OBSERVATIONS,
                                             self._dropped_observations + 1)
            return self._capacity_rejection(request)

        call_id, duplicate = self._claim_call_id(request)
        raw = self._request_bytes(request)
        if raw is None:
            return self._reject(request, "invalid_request_json", call_id=call_id)
        if len(raw) > MAX_REQUEST_BYTES:
            return self._reject(request, "request_too_large", request_bytes=raw, call_id=call_id,
                                retain_raw=False)
        if duplicate:
            return self._reject(request, "duplicate_call_id", request_bytes=raw, call_id=call_id)
        if type(request) is not dict or set(request) != {"call_id", "operation", "arguments"}:
            return self._reject(request, "invalid_request_schema", request_bytes=raw, call_id=call_id)
        if call_id is None:
            return self._reject(request, "invalid_call_id", request_bytes=raw)

        operation = request["operation"]
        if type(operation) is not str or operation not in _MODEL_OPERATIONS:
            return self._reject(request, "unsupported_operation", request_bytes=raw, call_id=call_id)
        if type(request["arguments"]) is not dict:
            return self._reject(request, "invalid_arguments", request_bytes=raw, call_id=call_id)

        try:
            if operation == "notification.get":
                response = self._queries.query(call_id, operation, request["arguments"])
                if self._incidents is None:
                    self._notification_response_id = response["response_id"]
                    self._incidents = TimingIncidents(self._queries, self._notification_response_id)
            elif operation in OPERATIONS:
                response = self._queries.query(call_id, operation, request["arguments"])
            elif operation == "incidents.candidates":
                if request["arguments"]:
                    raise IncidentRejected("candidate reads take no arguments")
                response = self._incident_store().candidates()
            else:
                response = self._incident_store().dispatch(
                    call_id, operation.removeprefix("incidents."), request["arguments"])
        except (QueryRejected, IncidentRejected) as exc:
            return self._reject(request, "backend_rejected", request_bytes=raw, call_id=call_id,
                                detail=str(exc))
        return self._record(request, response, request_bytes=raw, call_id=call_id,
                            outcome="accepted")

    def complete(self, dispatch_id: str, disposition: str = "confirmed") -> dict:
        """Controller-only simulated effect observation; never reachable from ``call``."""
        return self._incident_store().complete(dispatch_id, disposition=disposition)

    @property
    def incident_store(self) -> TimingIncidents | None:
        """Trusted controller read-only access for the existing snapshot writer; never model-exposed."""
        return self._incidents

    def capture_incident_snapshot(self) -> dict:
        """Controller-only validated timing snapshot after Notification initialization."""
        return capture_timing_snapshot(self._incident_store())

    def audit_snapshot(self) -> dict:
        """Controller-only detached inventory; it neither admits work nor completes a dispatch."""
        return {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                "trust_boundary": "trusted_same_process_not_security_boundary",
                "attempt_id": self.attempt_id,
                "initial_notification_response_id": self._notification_response_id,
                "history": [json.loads(record) for record in self._history],
                "history_status": {
                    "retained_calls": len(self._history), "call_limit": MAX_CALLS,
                    "dropped_observations": self._dropped_observations,
                    "dropped_observations_saturates_at": MAX_DROPPED_OBSERVATIONS,
                    "coverage": ("complete_for_retained_calls_only" if not self._dropped_observations else
                                 "incomplete_after_call_capacity")},
                "queries": self._queries.audit_snapshot(),
                "incident": (self._incidents.audit_snapshot() if self._incidents is not None else None)}

    @staticmethod
    def _request_bytes(request: object) -> bytes | None:
        try:
            return _encode(request)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return None

    def _reject(self, request: object, code: str, *, request_bytes: bytes | None = None,
                call_id: str | None = None, detail: str | None = None,
                retain_raw: bool = True) -> dict:
        raw = self._request_bytes(request) if request_bytes is None else request_bytes
        if raw is not None and len(raw) > MAX_REQUEST_BYTES:
            retain_raw = False
        identity = call_id if call_id is not None else (
            _identifier(request.get("call_id")) if type(request) is dict else None)
        response = {"version": 1, "scope": SCOPE, "native_launch": "CLOSED", "kind": "rejected",
                    "call_id": identity, "code": code, "effect": "none", "retry": "not_implicit"}
        if detail:
            response["detail"] = detail
        if len(self._history) >= MAX_CALLS:
            self._dropped_observations = min(MAX_DROPPED_OBSERVATIONS,
                                             self._dropped_observations + 1)
            return {**response, "retained": False,
                    "dropped_observations": self._dropped_observations}
        return self._record(request, response, request_bytes=raw, call_id=identity, outcome="rejected",
                            retain_raw=retain_raw)

    def _capacity_rejection(self, request: object) -> dict:
        """Return a bounded response after history capacity, without falsely claiming retention."""
        identity = _identifier(request.get("call_id")) if type(request) is dict else None
        return {"version": 1, "scope": SCOPE, "native_launch": "CLOSED", "kind": "rejected",
                "call_id": identity, "code": "call_capacity_exhausted", "effect": "none",
                "retry": "not_implicit", "retained": False,
                "dropped_observations": self._dropped_observations}

    def _incident_store(self) -> TimingIncidents:
        if self._incidents is None:
            raise IncidentRejected("Notification initialization required before Incident operations")
        return self._incidents

    def _claim_call_id(self, request: object) -> tuple[str | None, bool]:
        """Consume a valid ID before any non-capacity rejection; malformed IDs never enter the set."""
        call_id = _identifier(request.get("call_id")) if type(request) is dict else None
        if call_id is None:
            return None, False
        duplicate = call_id in self._call_ids
        if not duplicate:
            self._call_ids.add(call_id)
        return call_id, duplicate

    def _record(self, request: object, response: dict, *, request_bytes: bytes | None,
                call_id: str | None, outcome: str, retain_raw: bool = True) -> dict:
        if len(self._history) >= MAX_CALLS:
            # Single-threaded callers preflight capacity; this is a defensive terminal marker.
            self._dropped_observations = min(MAX_DROPPED_OBSERVATIONS,
                                             self._dropped_observations + 1)
            return self._capacity_rejection(request)
        if type(response) is not dict:
            raise TypeError("fixed backend response must be a JSON object")
        response_bytes = _encode(response)
        if request_bytes is None:
            retained_request = {"retention": "unserializable_not_retained"}
        elif retain_raw:
            retained_request = json.loads(request_bytes)
        else:
            retained_request = {"retention": "oversized_not_retained", "bytes": len(request_bytes),
                                "sha256": hashlib.sha256(request_bytes).hexdigest()}
        history = {"sequence": len(self._history) + 1, "call_id": call_id, "outcome": outcome,
                   "request": retained_request, "response": json.loads(response_bytes),
                   "response_sha256": hashlib.sha256(response_bytes).hexdigest()}
        self._history.append(_encode(history))
        return deepcopy(response)
