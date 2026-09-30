"""Closed fixed-client worker for the synthetic timing rehearsal.

This module is copied into the parent-owned fixture bundle and called in-process by
its wrapper.  It accepts no paths, commands, credentials, model content, or live
tool configuration.  Its outputs are limited to the fixed snapshot, binding audit,
and fixture transcript envelopes.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import time
from pathlib import Path

from .executor import Lifecycle
from .fixture_evidence import EvidenceUnavailable, _json, _read, _sync_directory, _write
from .timing_binding import TimingBinding
from .timing_snapshot import write_timing_snapshot

_ALLOWED_ENVIRONMENT = {"HOME", "TMPDIR", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
_SCENARIOS = {"timing_rehearsal", "timing_unknown", "timing_wait"}
_AUDIT_LIMIT = 16 * 1024 * 1024
_SECTIONS = {
    "summary": "Synthetic storage exercise only. No human-truth claim is made.",
    "blast_radius": "Synthetic storage exercise only; no real blast-radius claim is made.",
    "timeline": "Synthetic fixture observations only; no wall-time claim is made.",
    "evidence": "References identify retained synthetic fixture responses only.",
    "suggested_root_cause": "No root-cause claim is made in this synthetic storage exercise.",
    "suggested_remediation": "No remediation claim or action is made in this synthetic storage exercise.",
    "fingerprints_explained": "Relations are synthetic storage entries, not human-truth findings.",
}
_SUMMARY = "Synthetic timing rehearsal storage exercise"


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _report(notification: dict, reference: dict, direct_members: set[str],
            correction_of: str | None) -> dict:
    alerts = notification["items"][0]["value"]["alerts"]
    return {
        "sections": dict(_SECTIONS),
        "references": [{"response_id": reference["response_id"], "item_index": 0}],
        "explanations": [
            {"fingerprint": alert["fingerprint"],
             "relation": "direct" if alert["fingerprint"] in direct_members else "unexplained"}
            for alert in alerts
        ],
        "correction_of": correction_of,
    }


def _accepted(binding: TimingBinding, call_id: str, operation: str, arguments: dict) -> dict:
    response = binding.call({"call_id": call_id, "operation": operation, "arguments": arguments})
    if response.get("kind") == "rejected":
        raise EvidenceUnavailable(f"fixed timing call rejected: {operation}")
    return response


def _write_audit(directory: Path, binding: TimingBinding) -> tuple[str, int]:
    raw = _canonical(binding.audit_snapshot())
    if len(raw) > _AUDIT_LIMIT:
        raise EvidenceUnavailable("binding audit exceeds fixed byte limit")
    _write(directory / "binding-audit.json", raw)
    _sync_directory(directory)
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _receipt(snapshot: dict, *, scenario: str, attempt_id: str,
             manifest_sha256: str, manifest_bytes: int, audit_sha256: str,
             audit_bytes: int, capture_phase: str) -> dict:
    queries = snapshot["store"]["queries"]
    state = snapshot["store"]["state"]
    if (type(manifest_sha256) is not str or len(manifest_sha256) != 64 or
            type(manifest_bytes) is not int or manifest_bytes < 0):
        raise EvidenceUnavailable("invalid retained timing manifest receipt")
    return {
        "type": "timing_rehearsal_receipt",
        "version": 1,
        "scope": "FIXED_TIMING_REHEARSAL_ONLY",
        "native_launch": "CLOSED",
        "scenario": scenario,
        "attempt_id": attempt_id,
        "query_session_id": queries["session_id"],
        "incident_session_id": state["session_id"],
        "snapshot_manifest_sha256": manifest_sha256,
        "snapshot_manifest_bytes": manifest_bytes,
        "binding_audit_sha256": audit_sha256,
        "binding_audit_bytes": audit_bytes,
        "capture_phase": capture_phase,
    }


def main(scenario: str, directory: Path) -> int:
    """Run one allowlisted fixed synthetic timing scenario in ``directory``."""
    if set(os.environ) - _ALLOWED_ENVIRONMENT:
        return 91
    signal.signal(signal.SIGINT, signal.default_int_handler)
    _emit({"type": "assistant", "message": {"model": "fixture-only", "content": []}})
    try:
        if scenario not in _SCENARIOS:
            raise ValueError("unsupported fixed timing scenario")
        directory = Path(directory)
        attempt_id = directory.name
        lifecycle = Lifecycle()
        binding = TimingBinding(attempt_id, lifecycle)

        notification = _accepted(binding, "notification", "notification.get", {})
        candidates = _accepted(binding, "candidates", "incidents.candidates", {})
        if candidates.get("items") != []:
            raise EvidenceUnavailable("fixed timing candidate baseline is not empty")
        logs = _accepted(binding, "logs", "logs.query", {"contains": "cache", "limit": 1})
        if logs.get("returned_count") != 1 or len(logs.get("items", [])) != 1:
            raise EvidenceUnavailable("fixed timing log reference is unavailable")

        alerts = notification["items"][0]["value"]["alerts"]
        if not alerts:
            raise EvidenceUnavailable("fixed timing notification has no Alert inventory")
        first_member = alerts[0]["fingerprint"]
        lifecycle.advance(1)
        created = _accepted(binding, "create", "incidents.create", {
            "summary": _SUMMARY,
            "members": [first_member],
            "report": _report(notification, logs, {first_member}, None),
        })
        lifecycle.advance(2)

        if scenario == "timing_unknown":
            binding.complete(created["dispatch_id"], disposition="unknown_after_apply")
            lifecycle.advance(3)
            capture_phase = "final"
        elif scenario == "timing_wait":
            lifecycle.advance(3)
            capture_phase = "before_wait"
        else:
            first_effect = binding.complete(created["dispatch_id"], disposition="confirmed")
            lifecycle.advance(3)
            if len(alerts) < 2:
                raise EvidenceUnavailable("fixed timing correction member is unavailable")
            added_member = alerts[1]["fingerprint"]
            current = binding.incident_store
            if current is None:
                raise EvidenceUnavailable("fixed timing Incident store is unavailable")
            appended = _accepted(binding, "append", "incidents.append", {
                "incident_id": first_effect["incident_id"],
                "expected_revision": current.inspect()["incident"]["revision"],
                "members": [added_member],
                "report": _report(notification, logs, {first_member, added_member},
                                  first_effect["report_revision_id"]),
            })
            binding.complete(appended["dispatch_id"], disposition="confirmed")
            capture_phase = "final"

        store = binding.incident_store
        if store is None:
            raise EvidenceUnavailable("fixed timing Incident store was not initialized")
        snapshot = write_timing_snapshot(directory / "timing-snapshot", store)
        manifest_raw = _read(directory / "timing-snapshot" / "manifest.json", 4096)
        _json(manifest_raw)
        audit_sha256, audit_bytes = _write_audit(directory, binding)
        _emit({"type": "assistant", "message": {"model": "fixture-only", "content": [
            _receipt(snapshot, scenario=scenario, attempt_id=attempt_id,
                     manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
                     manifest_bytes=len(manifest_raw),
                     audit_sha256=audit_sha256, audit_bytes=audit_bytes,
                     capture_phase=capture_phase)
        ]}})
        if scenario == "timing_wait":
            while True:
                time.sleep(1)
        _emit({"type": "result", "subtype": "success", "is_error": False})
        return 0
    except KeyboardInterrupt:
        _emit({"type": "result", "subtype": "error", "is_error": True})
        return 130
    except Exception:  # noqa: BLE001 - transcript contract requires one terminal error envelope.
        _emit({"type": "result", "subtype": "error", "is_error": True})
        return 1
