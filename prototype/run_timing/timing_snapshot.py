"""Operator-only byte/linkage snapshots of trusted synthetic timing observations."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from .fixture_evidence import EvidenceUnavailable, _json, _read, _sync_directory, _write
from .outcomes import seconds
from .timing_incidents import MAX_WRITES, TimingIncidents
from .timing_incidents import SCOPE as INCIDENT_SCOPE
from .timing_queries import (
    HISTORICAL_COMMIT,
    MAX_RESPONSE_BYTES,
    MAX_RESPONSES,
    OPERATIONS,
    PINNED_INPUTS,
)
from .timing_queries import SCOPE as QUERY_SCOPE

SCOPE = "SYNTHETIC_TIMING_SNAPSHOT_ONLY"
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
COVERAGE_GAPS = (
    "rejected_requests_not_retained", "candidate_read_observations_not_retained",
    "unapplied_proposal_bodies_not_retained", "native_provenance_not_established",
    "human_claim_support_not_assessed", "model_billing_execution_not_established",
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _require(condition, message):
    if not condition:
        raise EvidenceUnavailable(message)


def _scope(record, expected):
    _require(type(record) is dict and type(record.get("version")) is int and
             record["version"] == 1 and record.get("scope") == expected and
             record.get("native_launch") == "CLOSED", "invalid timing snapshot scope")


def _record(record, scope, digest_key, byte_limit):
    _scope(record, scope)
    body = {key: value for key, value in record.items() if key != digest_key}
    _require(len(_canonical(record)) <= byte_limit and
             record.get(digest_key) == hashlib.sha256(_canonical(body)).hexdigest(),
             "timing record digest or size mismatch")


def _index(records, identity, limit, scope, digest_key="sha256", byte_limit=20480):
    _require(type(records) is list and len(records) <= limit, "timing record count exceeded")
    indexed = {}
    for row in records:
        _record(row, scope, digest_key, byte_limit)
        key = row.get(identity)
        _require(type(key) is str and key not in indexed, "duplicate or invalid record identity")
        indexed[key] = row
    return indexed


def _query_links(query):
    _scope(query, QUERY_SCOPE)
    attempt, session = query["attempt_id"], query["session_id"]
    _require(type(attempt) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", attempt) and
             type(session) is str and re.fullmatch(r"[a-f0-9]{32}", session), "invalid query namespace")
    responses = _index(query["responses"], "response_id", MAX_RESPONSES, QUERY_SCOPE,
                       "response_sha256", MAX_RESPONSE_BYTES)
    requests = set()
    for number, (identity, response) in enumerate(responses.items(), 1):
        _require(identity == f"{attempt}/{session}/response/{number:04d}", "query sequence mismatch")
        request = response["request_id"]
        _require(type(request) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", request) and
                 request not in requests, "invalid or duplicate query request")
        requests.add(request)
        operation = response["operation"]
        _require(type(operation) is str and operation in OPERATIONS, "unknown query operation")
        source = OPERATIONS[operation][0]
        _require(response["source"] == {"file": source, "sha256": PINNED_INPUTS[source],
                 "historical_commit": HISTORICAL_COMMIT}, "query source linkage mismatch")
        returned, matched = response["returned_count"], response["matched_count"]
        _require(type(response["items"]) is list and type(returned) is int and type(matched) is int and
                 len(response["items"]) == returned and 0 <= returned <= matched and
                 type(response["truncated"]) is bool and response["truncated"] == (matched > returned),
                 "query count linkage mismatch")
    return responses


def _incident_links(store, responses):
    state = store["state"]
    _record(state, INCIDENT_SCOPE, "sha256", 32768)
    _require(state.get("kind") == "operator_snapshot", "wrong snapshot state kind")
    session = state["session_id"]
    _require(type(session) is str and re.fullmatch(r"[a-f0-9]{32}", session), "invalid store namespace")
    dispatches = _index(store["dispatches"], "dispatch_id", MAX_WRITES, INCIDENT_SCOPE, byte_limit=4096)
    effects = _index(store["effects"], "dispatch_id", MAX_WRITES, INCIDENT_SCOPE, byte_limit=4096)
    revisions = _index(store["revisions"], "revision_id", MAX_WRITES, INCIDENT_SCOPE)
    _require(state["dispatch_ids"] == list(dispatches) and state["revision_ids"] == list(revisions),
             "state record inventory mismatch")
    requests = set()
    for number, (identity, dispatch) in enumerate(dispatches.items(), 1):
        _require(identity == f"{session}/dispatch/{number:02d}" and dispatch.get("kind") == "dispatch"
                 and dispatch.get("effect_outcome") == "pending" and dispatch.get("operation") in
                 ("create", "append"), "dispatch identity or intent mismatch")
        request = dispatch["request_id"]
        _require(type(request) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", request) and
                 request not in requests, "invalid or duplicate dispatch request")
        requests.add(request)
    for identity, effect in effects.items():
        outcome = effect.get("effect_outcome")
        _require(identity in dispatches and effect.get("kind") == "effect" and
                 outcome in ("confirmed", "failed", "unknown"), "orphan or invalid effect")
        if outcome == "confirmed":
            revision = revisions.get(effect["report_revision_id"])
            _require(revision is not None and revision["dispatch_id"] == identity and
                     effect.get("incident_id") == "SYNTHETIC-INCIDENT-1", "confirmed effect lacks revision")
        else:
            _require(effect.get("incident_id") is None and effect.get("report_revision_id") is None,
                     "uncertain or failed effect claimed confirmation")
    previous = None
    previous_dispatch = None
    revision_dispatches = set()
    for number, (identity, revision) in enumerate(revisions.items(), 1):
        _require(identity == f"{session}/report/{number:02d}" and revision.get("kind") == "report_revision"
                 and revision.get("previous_revision_id") == previous, "revision chain mismatch")
        _require(revision["dispatch_id"] not in revision_dispatches, "duplicate revision dispatch")
        _require(previous_dispatch is None or revision["dispatch_id"] > previous_dispatch,
                 "revision dispatch order mismatch")
        previous_dispatch = revision["dispatch_id"]
        revision_dispatches.add(revision["dispatch_id"])
        effect = effects.get(revision["dispatch_id"])
        _require(effect is not None and effect["effect_outcome"] in ("confirmed", "unknown"),
                 "revision has no applied or uncertain effect")
        correction = revision["report"]["correction_of"]
        _require(correction is None or correction in list(revisions)[:number - 1], "invalid correction link")
        references = revision["report"]["references"]
        _require(type(references) is list and len(references) <= 32, "invalid reference inventory")
        for ref in references:
            response = responses.get(ref["response_id"])
            _require(response is not None, "Report response is missing")
            index = ref["item_index"]
            _require(index is None or type(index) is int and 0 <= index < len(response["items"]),
                     "Report response item is missing")
        previous = identity
    pending = state["pending_dispatch_id"]
    unsettled = [key for key in dispatches if key not in effects]
    _require(unsettled == ([] if pending is None else [pending]) and
             (pending is None or pending == next(reversed(dispatches))), "pending dispatch mismatch")
    _require(type(state["hold"]) is bool and state["hold"] ==
             any(effect["effect_outcome"] != "confirmed" for effect in effects.values()), "effect hold mismatch")
    if state["hold"]:
        _require(pending is None and bool(effects) and
                 next(reversed(effects)) == next(reversed(dispatches)) and
                 list(effects.values())[-1]["effect_outcome"] != "confirmed" and
                 all(e["effect_outcome"] == "confirmed" for e in list(effects.values())[:-1]),
                 "dispatch continued after held effect")
    incident = state["incident"]
    _require((incident is None and not revisions) or (type(incident) is dict and bool(revisions) and
             incident.get("report_revision_id") == previous and type(incident.get("revision")) is int and
             incident["revision"] == len(revisions) and incident.get("incident_id") == "SYNTHETIC-INCIDENT-1"),
             "current Incident revision mismatch")


def validate_timing_snapshot(snapshot: dict) -> None:
    """Structural byte/link checks only; supplied hashes do not authenticate observations."""
    try:
        _require(len(_canonical(snapshot)) <= MAX_SNAPSHOT_BYTES, "timing snapshot too large")
        _scope(snapshot, SCOPE)
        _require(snapshot.get("audit_completeness") == "NOT_ASSESSED" and
                 snapshot.get("coverage_gaps") == list(COVERAGE_GAPS), "snapshot coverage overstated")
        store = snapshot["store"]
        _scope(store, INCIDENT_SCOPE)
        lifecycle = store["lifecycle"]
        now = seconds(lifecycle["now"])
        _require(all(type(lifecycle[key]) is bool for key in ("work_allowed", "revoked", "finished")) and
                 lifecycle["work_allowed"] == (not lifecycle["revoked"] and not lifecycle["finished"]
                                                and now < 270), "invalid lifecycle snapshot")
        responses = _query_links(store["queries"])
        notification = responses.get(store["notification_response_id"])
        _require(notification is not None and notification.get("operation") == "notification.get" and
                 notification.get("status") == "ok" and len(notification["items"]) == 1,
                 "Notification response linkage missing")
        _incident_links(store, responses)
    except (KeyError, ValueError, TypeError, OverflowError, RecursionError, StopIteration) as exc:
        raise EvidenceUnavailable("malformed timing snapshot") from exc


def capture_timing_snapshot(store: TimingIncidents) -> dict:
    """Capture retained state without admitting work, completing writes or clearing holds."""
    if type(store) is not TimingIncidents:
        raise TypeError("trusted TimingIncidents instance required")
    snapshot = {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                "audit_completeness": "NOT_ASSESSED", "coverage_gaps": list(COVERAGE_GAPS),
                "store": store.audit_snapshot()}
    validate_timing_snapshot(snapshot)
    return snapshot


def write_timing_snapshot(directory: Path, store: TimingIncidents) -> dict:
    """Publish once to a new private directory; failure preserves any partial evidence."""
    snapshot = capture_timing_snapshot(store)
    directory = Path(directory).absolute()
    try:
        directory.mkdir(mode=0o700)
        raw = _canonical(snapshot)
        _write(directory / "snapshot.json", raw)
        _sync_directory(directory)
        _sync_directory(directory.parent)
        manifest = {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        pending = directory / "manifest.pending"
        _write(pending, _canonical(manifest))
        os.link(pending, directory / "manifest.json")
        pending.unlink()
        _sync_directory(directory)
        return read_timing_snapshot(directory)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise EvidenceUnavailable("timing snapshot publication failed; preserve partial evidence") from exc


def read_timing_snapshot(directory: Path) -> dict:
    """Verify a retained snapshot; no reconstruction of a writable adapter or model context."""
    directory = Path(directory).absolute()
    try:
        manifest = _json(_read(directory / "manifest.json", 4096))
        _scope(manifest, SCOPE)
        _require(set(manifest) == {"version", "scope", "native_launch", "bytes", "sha256"} and
                 type(manifest["bytes"]) is int, "invalid timing manifest")
        raw = _read(directory / "snapshot.json", MAX_SNAPSHOT_BYTES)
        _require(len(raw) == manifest["bytes"] and hashlib.sha256(raw).hexdigest() == manifest["sha256"],
                 "timing snapshot bytes differ")
        snapshot = _json(raw)
        validate_timing_snapshot(snapshot)
        return snapshot
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise EvidenceUnavailable("timing snapshot unavailable or malformed") from exc
