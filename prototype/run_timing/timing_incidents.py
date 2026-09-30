"""One synthetic Incident, immutable Report revisions and simulated effect receipts.

Trusted single-threaded fixture state only. No Jira, transport, durable recovery or grades.
"""

from __future__ import annotations

import hashlib
import json
import re
from uuid import uuid4

from .outcomes import seconds
from .timing_queries import QueryRejected, TimingQueries

SCOPE = "OFFLINE_SYNTHETIC_INCIDENT_ONLY"
INCIDENT_ID = "SYNTHETIC-INCIDENT-1"
MAX_WRITES = 32
MAX_REPORT_BYTES = 16384
SECTIONS = ("summary", "blast_radius", "timeline", "evidence", "suggested_root_cause",
            "suggested_remediation", "fingerprints_explained")
DISPOSITIONS = ("confirmed", "failed", "unknown_before_apply", "unknown_after_apply")


class IncidentRejected(ValueError):
    """Request rejected without a new dispatch or effect; not a write receipt."""


def _encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise IncidentRejected("invalid fixture request identity")
    return value


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise IncidentRejected("unexpected fixture payload fields")


def _text(value, limit):
    if type(value) is not str or not value.strip() or len(value) > limit:
        raise IncidentRejected("invalid or oversized fixture text")


def _envelope(body):
    result = {"version": 1, "scope": SCOPE, "native_launch": "CLOSED", **body}
    result["sha256"] = hashlib.sha256(_encode(result)).hexdigest()
    return _encode(result)


class TimingIncidents:
    def __init__(self, queries: TimingQueries, notification_response_id: str):
        if not isinstance(queries, TimingQueries):
            raise TypeError("pinned TimingQueries adapter required")
        try:
            response = queries.read_response(notification_response_id)
        except QueryRejected as exc:
            raise IncidentRejected("retained Notification response required") from exc
        if response["operation"] != "notification.get" or response["status"] != "ok":
            raise IncidentRejected("retained Notification response required")
        self._queries = queries
        self.lifecycle = queries.lifecycle
        self._alerts = {a["fingerprint"]: a for a in response["items"][0]["value"]["alerts"]}
        self._notification_ref = response["response_id"]
        self._session = uuid4().hex
        self._incident: dict | None = None
        self._revisions: dict[str, bytes] = {}
        self._dispatches: dict[str, bytes] = {}
        self._effects: dict[str, bytes] = {}
        self._requests: set[str] = set()
        self._pending: tuple | None = None
        self._hold = False

    def _work(self):
        if not self.lifecycle.work_allowed or self._hold:
            raise IncidentRejected("fixture work closed or held")

    def candidates(self) -> dict:
        """Model-side candidate query; only this fixture's open Incident can appear."""
        self._work()
        now = seconds(self.lifecycle.now)
        candidates = []
        if self._incident and now - self._incident["created_at_virtual_seconds"] <= 1800:
            candidates.append({**self._incident, "report": json.loads(
                self._revisions[self._incident["report_revision_id"]])})
        return json.loads(_envelope({"kind": "candidates", "session_id": self._session,
            "observed_at_virtual_seconds": now, "candidate_window_seconds": 1800,
            "notification_response_id": self._notification_ref, "items": candidates}))

    def _report(self, report, members):
        _keys(report, ("sections", "references", "explanations", "correction_of"))
        _keys(report["sections"], SECTIONS)
        for text in report["sections"].values():
            _text(text, 2048)
        refs = report["references"]
        if type(refs) is not list or len(refs) > 32:
            raise IncidentRejected("invalid fixture reference list")
        for ref in refs:
            _keys(ref, ("response_id", "item_index"))
            _text(ref["response_id"], 200)
            try:
                response = self._queries.read_response(ref["response_id"])
            except QueryRejected as exc:
                raise IncidentRejected("unrecognized fixture response reference") from exc
            index = ref["item_index"]
            if index is not None and (type(index) is not int or not 0 <= index < len(response["items"])):
                raise IncidentRejected("unrecognized fixture response item")
        explanations = report["explanations"]
        if type(explanations) is not list or len(explanations) != len(self._alerts):
            raise IncidentRejected("every Notification Alert needs an explanation")
        explained, seen = set(), set()
        for row in explanations:
            _keys(row, ("fingerprint", "relation"))
            fp = row["fingerprint"]
            if type(fp) is not str or fp not in self._alerts or fp in seen:
                raise IncidentRejected("unknown or repeated fingerprint")
            if row["relation"] not in ("direct", "downstream", "unexplained"):
                raise IncidentRejected("invalid Alert relation")
            seen.add(fp)
            if row["relation"] != "unexplained":
                explained.add(fp)
        if explained != members:
            raise IncidentRejected("explained members must match accumulated membership")
        correction = report["correction_of"]
        if correction is not None and (type(correction) is not str or correction not in self._revisions):
            raise IncidentRejected("correction must name a retained Report revision")
        encoded = _encode(report)
        if len(encoded) > MAX_REPORT_BYTES:
            raise IncidentRejected("Report exceeds fixture byte cap")
        return json.loads(encoded)

    def dispatch(self, request_id: str, operation: str, payload: dict) -> dict:
        """Admit a write intent only; completion is a separate trusted fixture action."""
        self._work()
        request_id = _identifier(request_id)
        if self._pending is not None:
            raise IncidentRejected("one fixture write is already pending")
        if request_id in self._requests or len(self._dispatches) >= MAX_WRITES:
            raise IncidentRejected("duplicate request or fixture write capacity exhausted")
        if operation not in ("create", "append"):
            raise IncidentRejected("unknown fixed write operation")
        fields = ("summary", "members", "report") if operation == "create" else (
            "incident_id", "expected_revision", "members", "report")
        _keys(payload, fields)
        if operation == "create":
            if self._incident is not None:
                raise IncidentRejected("single fixture Incident already exists")
            _text(payload["summary"], 200)
            previous_members = set()
        else:
            if (self._incident is None or payload["incident_id"] != INCIDENT_ID or
                    type(payload["expected_revision"]) is not int or
                    payload["expected_revision"] != self._incident["revision"]):
                raise IncidentRejected("Incident identity or expected revision mismatch")
            previous_members = set(self._incident["members"])
        supplied = payload["members"]
        if (type(supplied) is not list or len(supplied) > len(self._alerts) or
                any(type(fp) is not str or fp not in self._alerts for fp in supplied) or
                len(set(supplied)) != len(supplied)):
            raise IncidentRejected("invalid fixture member list")
        members = previous_members | set(supplied)
        if not members:
            raise IncidentRejected("an Incident needs an explained member")
        report = self._report(payload["report"], members)
        now = seconds(self.lifecycle.now)
        revision = len(self._revisions) + 1
        revision_id = f"{self._session}/report/{revision:02d}"
        previous_id = self._incident["report_revision_id"] if self._incident else None
        level = min({"critical": 1, "warning": 2}.get(
            self._alerts[fp]["labels"]["severity"], 3) for fp in members)
        incident = {"incident_id": INCIDENT_ID, "status": "open", "revision": revision,
                    "report_revision_id": revision_id, "members": sorted(members),
                    "labels": sorted({"synthetic-timing"} | {"fp-" + fp for fp in members}),
                    "severity": f"Sev-{level}", "urgency": {1: "Critical", 2: "High", 3: "Medium"}[level],
                    "source": "Monitoring systems",
                    "summary": payload["summary"] if self._incident is None else self._incident["summary"],
                    "created_at_virtual_seconds": now if self._incident is None else
                                                  self._incident["created_at_virtual_seconds"]}
        dispatch_id = f"{self._session}/dispatch/{len(self._dispatches) + 1:02d}"
        revision_bytes = _envelope({"kind": "report_revision", "revision_id": revision_id,
            "previous_revision_id": previous_id, "dispatch_id": dispatch_id,
            "prepared_at_virtual_seconds": now, "report": report})
        dispatch_bytes = _envelope({"kind": "dispatch", "dispatch_id": dispatch_id,
            "request_id": request_id, "operation": operation, "at_virtual_seconds": now,
            "payload_sha256": hashlib.sha256(_encode(payload)).hexdigest(),
            "effect_outcome": "pending"})
        self._dispatches[dispatch_id] = dispatch_bytes
        self._requests.add(request_id)
        self._pending = (dispatch_id, incident, revision_id, revision_bytes)
        return json.loads(dispatch_bytes)

    def complete(self, dispatch_id: str, *, disposition: str = "confirmed") -> dict:
        """Controller-only simulation of a previously dispatched effect, including lost replies."""
        if self._pending is None or dispatch_id != self._pending[0] or disposition not in DISPOSITIONS:
            raise IncidentRejected("no matching pending fixture completion")
        _, incident, revision_id, revision_bytes = self._pending
        outcome = "confirmed" if disposition == "confirmed" else (
            "failed" if disposition == "failed" else "unknown")
        effect = _envelope({"kind": "effect", "dispatch_id": dispatch_id,
            "observed_at_virtual_seconds": seconds(self.lifecycle.now), "effect_outcome": outcome,
            "incident_id": INCIDENT_ID if outcome == "confirmed" else None,
            "report_revision_id": revision_id if outcome == "confirmed" else None})
        if disposition in ("confirmed", "unknown_after_apply"):
            self._incident = incident
            self._revisions[revision_id] = revision_bytes
        self._effects[dispatch_id] = effect
        self._pending = None
        self._hold = outcome != "confirmed"
        return json.loads(effect)

    def inspect(self) -> dict:
        """Operator read-back, available while held; never clears a hold or confirms an effect."""
        return json.loads(_envelope({"kind": "operator_snapshot", "session_id": self._session,
            "hold": self._hold, "incident": self._incident,
            "pending_dispatch_id": self._pending[0] if self._pending else None,
            "revision_ids": list(self._revisions), "dispatch_ids": list(self._dispatches)}))

    def audit_snapshot(self) -> dict:
        """Operator-only coherent inventory in this trusted single-threaded process."""
        return {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                "notification_response_id": self._notification_ref,
                "queries": self._queries.audit_snapshot(), "state": self.inspect(),
                "lifecycle": {"now": seconds(self.lifecycle.now),
                              "work_allowed": self.lifecycle.work_allowed,
                              "revoked": self.lifecycle.revoked, "finished": self.lifecycle.finished},
                "dispatches": [json.loads(raw) for raw in self._dispatches.values()],
                "effects": [json.loads(raw) for raw in self._effects.values()],
                "revisions": [json.loads(raw) for raw in self._revisions.values()]}

    def read_record(self, kind: str, identity: str) -> dict:
        """Retained operator-side byte read-back only; no call or receipt re-import."""
        records = {"dispatch": self._dispatches, "effect": self._effects, "revision": self._revisions}
        if type(kind) is not str or kind not in records or type(identity) is not str or identity not in records[kind]:
            raise IncidentRejected("unknown retained fixture record")
        return json.loads(records[kind][identity])
