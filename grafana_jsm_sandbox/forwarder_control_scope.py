"""Scoped control policy for a gated Forwarder control session.

Pure functions only: no I/O, no clock read, no lock taken and no state kept
after returning. A grant, sentinel, manifest or raw attachment byte is never
retained past the call that receives it.

An ``except`` block only records a fixed code, and a fresh
``ControlProtocolError`` is raised once the ``try`` statement has ended, with
``from None``; nothing is re-raised.

No registry mutation happens here, and no registry method is ever called.
Registry mutation and ``hold()`` stay inside ``ForwarderControl``; every
refusal below is a hold decision the caller carries out.
"""

from __future__ import annotations

import math

from .forwarder_control_protocol import ControlProtocolError
from .forwarder_dispatch import (
    CLOSEOUT_STATES,
    LEASE_STATES,
    Closeout,
    DispatchError,
    DispatchGate,
    ScopeEntry,
)
from .forwarder_leases import LeaseGrant, LeaseRegistry
from .forwarder_routes import (
    MAX_MANIFEST_BYTES,
    RouteConfigError,
    ScopeManifest,
    parse_scope_manifest,
    require_manifest_binding,
)
from .forwarder_services import SERVICE_PROFILES

# --- constants ---------------------------------------------------------------

SCOPED_SERVICES = frozenset({"jira"})
ATTACHMENT_SECONDS = 2.0  # read at call time by callers, so a test can monkeypatch it
REGISTER_SCOPED_PARAMETERS = frozenset({
    "run_id", "attempt_id", "service", "scope_digest", "expires_at", "manifest_bytes",
})
CLOSEOUT_PARAMETERS = frozenset({"lease_id"})
CLOSEOUT_FIELDS = (
    "generation", "lease_id", "lease_state", "closeout_state", "pending",
    "in_flight", "overdue", "uncertain", "drain_deadline", "observed_at",
)
CLOSEOUT_COUNT_FIELDS = ("pending", "in_flight", "overdue", "uncertain")
MAX_CLOSEOUT_COUNT = 2**31 - 1
MAX_TIME_INT = 2**63 - 1  # the control codec's signed 64-bit integer bound
REVOKED_LEASE_STATES = ("revoked", "pruned")

# A DispatchError code from install_scope, mapped to its wire code. Any other
# DispatchError code (none is currently reachable) maps to scope_install_failed.
INSTALL_ERROR_CODES = {
    "gate_closed": "scope_gate_closed",
    "gate_held": "scope_gate_held",
    "clock_fault": "scope_gate_held",
    "lease_unverified": "scope_lease_unverified",
    "grant_expired": "scope_lease_unverified",
    "generation_mismatch": "scope_lease_unverified",
    "manifest_binding_mismatch": "manifest_binding_mismatch",
    "scope_capacity": "scope_capacity",
    "scope_conflict": "scope_conflict",
}

# Every code the committed controller never emits that this unit can put on
# the wire, apart from the attachment codec's own attachment_mismatch.
SCOPE_CONTROL_CODES = frozenset({
    "scope_required", "scope_type_unavailable", "invalid_manifest_length",
    "manifest_too_large", "manifest_invalid", "manifest_binding_mismatch",
    "scope_gate_closed", "scope_gate_held", "scope_lease_unverified",
    "scope_capacity", "scope_conflict", "scope_install_failed",
    "closeout_unknown", "closeout_inconsistent", "closeout_overdue",
})

# invalid_gate is raised only by require_gate, at construction; never on the wire.


# --- gate pairing --------------------------------------------------------------


def require_gate(gate: object, registry: object) -> DispatchGate:
    """Return ``gate`` if it is paired with ``registry`` by generation.

    Exclusive ownership of both objects stays a trusted-caller precondition;
    this only proves pairing by equality of the 192-bit random generation.
    """
    if (
        type(gate) is not DispatchGate
        or type(registry) is not LeaseRegistry
        or gate.generation != registry.generation
    ):
        raise ControlProtocolError("invalid_gate")
    return gate


# --- registration refusal and manifest validation -----------------------------


def refuse_unscoped(service: object) -> None:
    """Refuse a profiled service that has no scope type; unknown values pass through."""
    if type(service) is str and service in SERVICE_PROFILES and service not in SCOPED_SERVICES:
        raise ControlProtocolError("scope_type_unavailable")


def manifest_length(params: dict) -> int:
    """Validate ``service`` and ``manifest_bytes`` before any attachment byte is read."""
    service = params.get("service")
    if type(service) is not str or service not in SERVICE_PROFILES:
        raise ControlProtocolError("invalid_service")
    refuse_unscoped(service)
    manifest_bytes = params.get("manifest_bytes")
    if type(manifest_bytes) is not int or manifest_bytes < 1:
        raise ControlProtocolError("invalid_manifest_length")
    if manifest_bytes > MAX_MANIFEST_BYTES:
        raise ControlProtocolError("manifest_too_large")
    return manifest_bytes


def bound_manifest(data: bytes, params: dict) -> ScopeManifest:
    """Parse canonical manifest ``data`` and bind it to the registration ``params``."""
    code: str | None = None
    manifest: ScopeManifest | None = None
    try:
        manifest = parse_scope_manifest(data)
    except RouteConfigError as caught:
        code = caught.code
    if code is not None:
        raise ControlProtocolError(code) from None
    service = params.get("service")
    run_id = params.get("run_id")
    attempt_id = params.get("attempt_id")
    scope_digest = params.get("scope_digest")
    if (
        type(service) is not str or type(run_id) is not str
        or type(attempt_id) is not str or type(scope_digest) is not str
    ):
        raise ControlProtocolError("manifest_binding_mismatch")
    try:
        require_manifest_binding(
            manifest, service=service, run_id=run_id,
            attempt_id=attempt_id, scope_digest=scope_digest,
        )
    except RouteConfigError:
        code = "manifest_binding_mismatch"
    if code is not None:
        raise ControlProtocolError(code) from None
    return manifest


def registry_parameters(params: dict) -> dict:
    """Project the registry-bound subset of a ``register_scoped`` parameter set."""
    return {
        "run_id": params["run_id"],
        "attempt_id": params["attempt_id"],
        "service": params["service"],
        "scope_digest": params["scope_digest"],
        "expires_at": params["expires_at"],
    }


# --- install -------------------------------------------------------------------


def install(gate: DispatchGate, grant: LeaseGrant, manifest: ScopeManifest) -> float:
    """Install ``manifest`` for ``grant`` and return the entry's ``installed_at``."""
    code: str | None = None
    entry: ScopeEntry | None = None
    try:
        entry = gate.install_scope(grant=grant, manifest=manifest)
    except DispatchError as caught:
        code = INSTALL_ERROR_CODES.get(caught.code, "scope_install_failed")
    except TypeError:
        code = "scope_install_failed"
    if code is not None:
        raise ControlProtocolError(code) from None
    # The entry must be the one this grant and manifest describe, never another
    # lease's or another digest's.
    if not (
        type(entry) is ScopeEntry
        and entry.lease_id == grant.lease_id
        and entry.scope_digest == grant.scope_digest == manifest.digest
        and entry.generation == grant.generation
    ):
        raise ControlProtocolError("scope_install_failed")
    return entry.installed_at


# --- closeout observation -------------------------------------------------------


def _valid_time(value: object) -> bool:
    # Only values the control codec can encode; a bigger int would fail at send_frame.
    if type(value) is float:
        return math.isfinite(value) and value >= 0
    return type(value) is int and 0 <= value <= MAX_TIME_INT


def observe_closeout(gate: DispatchGate, lease_id: str, *, after_revoke: bool) -> dict:
    """Observe one lease's closeout. Every refusal here means "hold the registry"."""
    code: str | None = None
    result: Closeout | None = None
    try:
        result = gate.closeout(lease_id)
    except Exception:  # noqa: BLE001 - an injected gate/clock must never escape unheld.
        code = "closeout_unknown"
    if code is None and type(result) is not Closeout:
        code = "closeout_unknown"
    if code is not None:
        raise ControlProtocolError(code) from None

    lease_state = result.lease_state
    closeout_state = result.closeout_state
    counts = tuple(getattr(result, name) for name in CLOSEOUT_COUNT_FIELDS)
    observed_at = result.observed_at
    drain_deadline = result.drain_deadline

    typed = (
        type(result.lease_id) is str and result.lease_id == lease_id
        and lease_state in LEASE_STATES and closeout_state in CLOSEOUT_STATES
        and all(type(value) is int and 0 <= value <= MAX_CLOSEOUT_COUNT for value in counts)
        and _valid_time(observed_at)
        and (drain_deadline is None or _valid_time(drain_deadline))
    )
    if not typed:
        raise ControlProtocolError("closeout_inconsistent")

    pending, in_flight, overdue, uncertain = counts
    # Coherence mirrors the gate's own decision order in _closeout_locked.
    coherent = (
        (closeout_state != "open" or lease_state in ("registered", "active"))
        and (lease_state not in ("registered", "active") or closeout_state in ("open", "unknown"))
        and (lease_state != "unknown" or closeout_state == "unknown")
        and (closeout_state != "overdue" or overdue >= 1)
        and (closeout_state != "draining" or (in_flight >= 1 and overdue == 0))
        and (closeout_state != "quiescent" or (in_flight == 0 and overdue == 0))
        and (drain_deadline is None) == (in_flight == 0)
        and (not after_revoke or lease_state in REVOKED_LEASE_STATES)
    )
    if not coherent:
        raise ControlProtocolError("closeout_inconsistent")

    if overdue > 0:
        raise ControlProtocolError("closeout_overdue")
    if closeout_state == "unknown" and (after_revoke or lease_state != "unknown"):
        raise ControlProtocolError("closeout_unknown")

    return {
        "generation": gate.generation,
        "lease_id": result.lease_id,
        "lease_state": lease_state,
        "closeout_state": closeout_state,
        "pending": pending,
        "in_flight": in_flight,
        "overdue": overdue,
        "uncertain": uncertain,
        "drain_deadline": drain_deadline,
        "observed_at": observed_at,
    }


__all__ = [
    "ATTACHMENT_SECONDS",
    "CLOSEOUT_COUNT_FIELDS",
    "CLOSEOUT_FIELDS",
    "CLOSEOUT_PARAMETERS",
    "INSTALL_ERROR_CODES",
    "MAX_CLOSEOUT_COUNT",
    "MAX_TIME_INT",
    "REGISTER_SCOPED_PARAMETERS",
    "REVOKED_LEASE_STATES",
    "SCOPED_SERVICES",
    "SCOPE_CONTROL_CODES",
    "bound_manifest",
    "install",
    "manifest_length",
    "observe_closeout",
    "refuse_unscoped",
    "registry_parameters",
    "require_gate",
]
