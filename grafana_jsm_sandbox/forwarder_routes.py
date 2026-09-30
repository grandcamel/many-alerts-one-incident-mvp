"""Route policy: strict scope-bound Jira routing and response validation.

No socket, clock, file, environment or credential access. The only state is
each ``RoutePolicy`` instance's lock-guarded registry of issued
``RoutedRequest`` objects. Never reads ``ParsedRequest.sentinel`` and never
imports ``forwarder_leases``/``forwarder_receipts``: a trusted store
(deferred) maps a sentinel to a lease and manifest before any of this runs.

``route()`` rebuilds the upstream request from manifest and operator-policy
values only; caller bytes never reach it. Every rejection is a closed code
mapped to a fixed receipt reason. The module-1 error discipline applies
unchanged: an ``except`` block only records a code, and a fresh error is
raised once the ``try`` statement has ended, never an exception object
created inside a handler.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import weakref
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .forwarder_http import ParsedRequest
from .forwarder_http_response import HTTPResponseError, ParsedResponse, serialize_response
from .forwarder_json import JSONPolicyError, canonical_json, parse_json, tagged_digest
from .forwarder_services import SERVICE_PROFILES

# --- route IDs, schema/tag strings, and size bounds -------------------------

ROUTE_ID_PATTERN = r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*"
_ROUTE_ID_RE = re.compile(ROUTE_ID_PATTERN)
_MAX_ROUTE_ID_LENGTH = 64
UNMATCHED_ROUTE_ID = "unmatched"  # reserved; never a catalog ID

JIRA_POLICY_SCHEMA = "maoi.forwarder.jira-policy.v1"
JIRA_ROUTES_CODE_REVISION = "maoi.forwarder.jira-routes.v1"
SCOPE_SCHEMA = "maoi.forwarder.scope.v1"
POLICY_DIGEST_TAG = "maoi.forwarder.policy.v1"
SCOPE_DIGEST_TAG = "maoi.forwarder.scope.v1"
REQUEST_DIGEST_TAG = "maoi.forwarder.request.v1"
DENIED_DIGEST_TAG = "maoi.forwarder.request-denied.v1"

MAX_POLICY_BYTES = 65_536
MAX_MANIFEST_BYTES = 16_384
MAX_REQUEST_JSON_BYTES = 262_144
MAX_RESPONSE_BYTES = 1_048_576
MAX_SCOPED_ISSUES = 256
MAX_SEARCH_LABELS = 256
MAX_FIELDS = 32
MAX_SEARCH_TEMPLATES = 8
MAX_TEMPLATE_BYTES = 8_192
MAX_SEARCH_RESULTS = 100

JIRA_READABLE_SYSTEM_FIELDS = frozenset({
    "created", "issuetype", "labels", "project", "resolution",
    "resolutiondate", "status", "summary", "updated",
})

ROUTE_ERROR_REASONS: Mapping[str, str] = MappingProxyType({
    "request_invalid": "request_rejected",
    "selector_invalid": "request_rejected",
    "query_rejected": "request_rejected",
    "body_rejected": "request_rejected",
    "service_unavailable": "route_denied",
    "manifest_mismatch": "route_denied",
    "route_unknown": "route_denied",
    "route_not_in_scope": "route_denied",
    "selector_out_of_scope": "route_denied",
    "selector_ambiguous": "route_denied",
    "upstream_unbuildable": "route_denied",
})

RESPONSE_DETAILS = frozenset({
    "ok", "routed_unknown", "response_invalid", "status_not_allowed",
    "json_invalid", "schema_invalid", "scope_mismatch", "count_exceeded",
})

class RouteConfigError(ValueError):
    """A fixed, non-diagnostic operator/config rejection; never embeds caller data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

class RoutePolicyError(ValueError):
    """A fixed dispatch-denial; ``route_id``/``request_digest`` never carry caller data."""

    def __init__(self, code: str, *, route_id: str, request_digest: str) -> None:
        self.code = code
        self.route_id = route_id
        self.receipt_reason = ROUTE_ERROR_REASONS[code]
        self.request_digest = request_digest
        super().__init__(code)

# --- shared grammar helpers --------------------------------------------------

_SAFE_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_NUMERIC_ID_RE = re.compile(r"[1-9][0-9]{0,17}")
_PROJECT_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{1,9}")
_ISSUE_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,17}")
_STATUS_CATEGORY_KEY_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_SEARCH_LABEL_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_TEMPLATE_PLACEHOLDER = "{label}"

def _printable_ascii(text: str) -> bool:
    return all(0x20 <= ord(character) <= 0x7E for character in text)

def _valid_tuple(value: object, *, min_len: int, max_len: int, item_ok) -> bool:
    """A tuple of ``min_len..max_len`` strictly ascending, unique, valid strings."""
    if type(value) is not tuple or not min_len <= len(value) <= max_len:
        return False
    if any(type(item) is not str or not item_ok(item) for item in value):
        return False
    return all(value[index] < value[index + 1] for index in range(len(value) - 1))

def _valid_hex64(value: object) -> bool:
    return type(value) is str and _HEX64_RE.fullmatch(value) is not None

# --- route catalog ------------------------------------------------------------

MISSING_INPUT_CODES: frozenset[str] = frozenset({
    "adf_profile", "client_profile", "continuation_tracking", "datasource_mapping",
    "delivery_receipt_seam", "dispatch_permit", "draft_mapping", "effect_identity_binding",
    "event_selector_support", "exposure_reservation", "eyes_schemas", "handle_binding",
    "health_route", "membership_state", "operation_counters", "query_templates",
    "readback_seam", "rehearsal_window", "report_attempt_budget", "report_history_scope",
    "request_envelope", "response_projection", "sse_qualification", "tenant_field_ids",
    "tenant_semantics", "tenant_space_ids", "tenant_workflow_ids",
})

@dataclass(frozen=True)
class RouteStatus:
    route_id: str
    service: str
    state: str  # "enabled" | "partial" | "unavailable"
    optional: bool
    spec_named: bool
    missing_inputs: tuple[str, ...]

# (route_id, service, state, optional, spec_named, missing_inputs); 24 spec IDs
# plus the local "anthropic.messages" (spec_named=False) for POST /v1/messages.
_ROUTE_DEFINITIONS: tuple[tuple[str, str, str, bool, bool, tuple[str, ...]], ...] = (
    ("jira.issue.get", "jira", "partial", False, True,
     ("effect_identity_binding", "tenant_field_ids")),
    ("jira.search", "jira", "partial", False, True,
     ("continuation_tracking", "tenant_field_ids")),
    ("jira.issue.create", "jira", "unavailable", False, True,
     ("adf_profile", "dispatch_permit", "effect_identity_binding", "report_attempt_budget",
      "tenant_field_ids")),
    ("jira.issue.update", "jira", "unavailable", False, True,
     ("dispatch_permit", "membership_state", "readback_seam", "tenant_field_ids")),
    ("jira.comment.add", "jira", "unavailable", False, True,
     ("adf_profile", "dispatch_permit", "readback_seam", "report_attempt_budget")),
    ("jira.comments.list", "jira", "unavailable", False, True,
     ("continuation_tracking", "report_history_scope", "response_projection")),
    ("jira.comment.get", "jira", "unavailable", False, True,
     ("effect_identity_binding", "readback_seam", "response_projection")),
    ("jira.transition", "jira", "unavailable", False, True,
     ("dispatch_permit", "readback_seam", "tenant_workflow_ids")),
    ("reference.read", "confluence", "unavailable", False, True,
     ("delivery_receipt_seam", "response_projection", "tenant_space_ids")),
    ("draft.create", "confluence", "unavailable", False, True,
     ("dispatch_permit", "draft_mapping", "tenant_semantics", "tenant_space_ids")),
    ("draft.read", "confluence", "unavailable", False, True,
     ("delivery_receipt_seam", "draft_mapping", "response_projection", "tenant_semantics")),
    ("draft.update", "confluence", "unavailable", False, True,
     ("delivery_receipt_seam", "dispatch_permit", "draft_mapping", "tenant_semantics")),
    ("pod_list", "kubernetes", "unavailable", False, True,
     ("continuation_tracking", "eyes_schemas", "response_projection")),
    ("pod_status", "kubernetes", "unavailable", False, True,
     ("eyes_schemas", "handle_binding", "response_projection")),
    ("pod_events", "kubernetes", "unavailable", False, True,
     ("event_selector_support", "eyes_schemas", "response_projection")),
    ("service_endpoints", "kubernetes", "unavailable", False, True,
     ("continuation_tracking", "eyes_schemas", "response_projection")),
    ("metrics_instant", "grafana", "unavailable", False, True,
     ("datasource_mapping", "eyes_schemas", "query_templates", "rehearsal_window")),
    ("metrics_range", "grafana", "unavailable", False, True,
     ("datasource_mapping", "eyes_schemas", "query_templates", "rehearsal_window")),
    ("logs_range", "grafana", "unavailable", False, True,
     ("datasource_mapping", "eyes_schemas", "query_templates", "rehearsal_window",
      "response_projection")),
    ("traces_search", "grafana", "unavailable", True, True,
     ("datasource_mapping", "eyes_schemas", "query_templates", "rehearsal_window")),
    ("trace_get", "grafana", "unavailable", True, True,
     ("datasource_mapping", "eyes_schemas", "handle_binding")),
    ("eyes.run_telemetry_query", "grafana", "unavailable", False, True,
     ("eyes_schemas", "operation_counters", "query_templates", "rehearsal_window")),
    ("eyes.change_query", "grafana", "unavailable", False, True,
     ("eyes_schemas", "query_templates", "rehearsal_window")),
    ("grafana_health", "grafana", "unavailable", False, True, ("health_route",)),
    ("anthropic.messages", "anthropic", "unavailable", False, False,
     ("client_profile", "dispatch_permit", "exposure_reservation", "request_envelope",
      "sse_qualification")),
)

ROUTE_CATALOG: Mapping[str, RouteStatus] = MappingProxyType({
    route_id: RouteStatus(
        route_id=route_id, service=service, state=state, optional=optional,
        spec_named=spec_named, missing_inputs=tuple(sorted(missing_inputs)),
    )
    for route_id, service, state, optional, spec_named, missing_inputs in _ROUTE_DEFINITIONS
})

SPEC_ROUTE_IDS: frozenset[str] = frozenset(
    route_id for route_id, status in ROUTE_CATALOG.items() if status.spec_named
)
LOCAL_ROUTE_IDS: frozenset[str] = frozenset(
    route_id for route_id, status in ROUTE_CATALOG.items() if not status.spec_named
)
OPTIONAL_ROUTE_IDS: frozenset[str] = frozenset(
    route_id for route_id, status in ROUTE_CATALOG.items() if status.optional
)
MATCHABLE_ROUTE_IDS: frozenset[str] = frozenset({"jira.issue.get", "jira.search"})

def policy_readiness_facts() -> dict[str, bool]:
    """A service is ``True`` only when every non-optional route is ``enabled``."""
    facts = dict.fromkeys(SERVICE_PROFILES, True)
    for status in ROUTE_CATALOG.values():
        if not status.optional and status.state != "enabled":
            facts[status.service] = False
    return facts

# --- operator venue policy: JiraVenuePolicy ----------------------------------

def _valid_template(text: str) -> bool:
    if not _printable_ascii(text) or len(text) > MAX_TEMPLATE_BYTES:
        return False
    if text.count("{") != 1 or text.count("}") != 1:
        return False
    return f'"{_TEMPLATE_PLACEHOLDER}"' in text

def _valid_field_tuple(value: object, *, required: frozenset[str]) -> bool:
    if not _valid_tuple(
        value, min_len=1, max_len=len(JIRA_READABLE_SYSTEM_FIELDS),
        item_ok=lambda item: item in JIRA_READABLE_SYSTEM_FIELDS,
    ):
        return False
    return required <= set(value)

@dataclass(frozen=True)
class JiraVenuePolicy:
    """A trusted operator venue policy; digest-pinned, never caller-controlled."""

    revision: str
    project_id: str
    project_key: str
    issue_type_id: str
    issue_fields: tuple[str, ...]
    search_fields: tuple[str, ...]
    search_templates: tuple[str, ...]
    search_max_results: int
    open_status_category_keys: tuple[str, ...]
    _canonical: bytes = field(init=False, repr=False, compare=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        valid = (
            type(self.revision) is str and _SAFE_ID_RE.fullmatch(self.revision) is not None
            and type(self.project_id) is str and _NUMERIC_ID_RE.fullmatch(self.project_id)
            and type(self.issue_type_id) is str and _NUMERIC_ID_RE.fullmatch(self.issue_type_id)
            and type(self.project_key) is str and _PROJECT_KEY_RE.fullmatch(self.project_key)
            and _valid_field_tuple(self.issue_fields, required=frozenset({"issuetype", "project"}))
            and _valid_field_tuple(
                self.search_fields,
                required=frozenset({"issuetype", "labels", "project", "status"}),
            )
            and _valid_tuple(
                self.search_templates, min_len=1, max_len=MAX_SEARCH_TEMPLATES,
                item_ok=_valid_template,
            )
            and type(self.search_max_results) is int
            and 1 <= self.search_max_results <= MAX_SEARCH_RESULTS
            and _valid_tuple(
                self.open_status_category_keys, min_len=1, max_len=4,
                item_ok=lambda item: _STATUS_CATEGORY_KEY_RE.fullmatch(item) is not None,
            )
        )
        if not valid:
            raise RouteConfigError("policy_invalid")
        document = {
            "code_revision": JIRA_ROUTES_CODE_REVISION,
            "issue_fields": list(self.issue_fields),
            "issue_type_id": self.issue_type_id,
            "open_status_category_keys": list(self.open_status_category_keys),
            "project_id": self.project_id,
            "project_key": self.project_key,
            "revision": self.revision,
            "schema": JIRA_POLICY_SCHEMA,
            "search_fields": list(self.search_fields),
            "search_max_results": self.search_max_results,
            "search_templates": list(self.search_templates),
        }
        canonical = canonical_json(document, ascii_only=True)
        if len(canonical) > MAX_POLICY_BYTES:
            raise RouteConfigError("policy_too_large")
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_digest", tagged_digest(POLICY_DIGEST_TAG, document))

    def canonical_bytes(self) -> bytes:
        return self._canonical

    @property
    def digest(self) -> str:
        return self._digest

# --- Receiver scope manifest --------------------------------------------------

@dataclass(frozen=True)
class ScopedIssue:
    issue_id: str
    issue_key: str

    def __post_init__(self) -> None:
        if (
            type(self.issue_id) is not str or _NUMERIC_ID_RE.fullmatch(self.issue_id) is None
            or type(self.issue_key) is not str or _ISSUE_KEY_RE.fullmatch(self.issue_key) is None
        ):
            raise RouteConfigError("manifest_invalid")

@dataclass(frozen=True)
class JiraScope:
    issues: tuple[ScopedIssue, ...]
    search_labels: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.issues) is not tuple
            or len(self.issues) > MAX_SCOPED_ISSUES
            or any(type(item) is not ScopedIssue for item in self.issues)
        ):
            raise RouteConfigError("manifest_invalid")
        ids = [item.issue_id for item in self.issues]
        keys = [item.issue_key for item in self.issues]
        if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise RouteConfigError("manifest_invalid")
        if any(int(ids[index]) >= int(ids[index + 1]) for index in range(len(ids) - 1)):
            raise RouteConfigError("manifest_invalid")
        if not _valid_tuple(
            self.search_labels, min_len=0, max_len=MAX_SEARCH_LABELS,
            item_ok=lambda item: _SEARCH_LABEL_RE.fullmatch(item) is not None,
        ):
            raise RouteConfigError("manifest_invalid")

@dataclass(frozen=True)
class ScopeManifest:
    """One scope-manifest digest binds allowed IDs, rehearsal, routes and revision."""

    service: str
    run_id: str
    attempt_id: str
    rehearsal_id: str
    revision: str
    routes: tuple[str, ...]
    policy_digest: str
    scope: JiraScope
    _canonical: bytes = field(init=False, repr=False, compare=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.service) is not str or self.service != "jira":
            raise RouteConfigError("manifest_invalid")
        for value in (self.run_id, self.attempt_id, self.rehearsal_id, self.revision):
            if type(value) is not str or _SAFE_ID_RE.fullmatch(value) is None:
                raise RouteConfigError("manifest_invalid")
        if not _valid_tuple(
            self.routes, min_len=1, max_len=2, item_ok=lambda item: item in MATCHABLE_ROUTE_IDS,
        ):
            raise RouteConfigError("manifest_invalid")
        if not _valid_hex64(self.policy_digest):
            raise RouteConfigError("manifest_invalid")
        if type(self.scope) is not JiraScope:
            raise RouteConfigError("manifest_invalid")
        if bool(self.scope.issues) != ("jira.issue.get" in self.routes):
            raise RouteConfigError("manifest_invalid")
        if bool(self.scope.search_labels) != ("jira.search" in self.routes):
            raise RouteConfigError("manifest_invalid")
        document = {
            "attempt_id": self.attempt_id,
            "policy_digest": self.policy_digest,
            "rehearsal_id": self.rehearsal_id,
            "revision": self.revision,
            "routes": list(self.routes),
            "run_id": self.run_id,
            "schema": SCOPE_SCHEMA,
            "scope": {
                "issues": [
                    {"id": item.issue_id, "key": item.issue_key} for item in self.scope.issues
                ],
                "search_labels": list(self.scope.search_labels),
            },
            "service": self.service,
        }
        canonical = canonical_json(document, ascii_only=True)
        if len(canonical) > MAX_MANIFEST_BYTES:
            raise RouteConfigError("manifest_too_large")
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_digest", tagged_digest(SCOPE_DIGEST_TAG, document))

    def canonical_bytes(self) -> bytes:
        return self._canonical

    @property
    def digest(self) -> str:
        return self._digest

_MANIFEST_TOP_KEYS = frozenset({
    "attempt_id", "policy_digest", "rehearsal_id", "revision",
    "routes", "run_id", "schema", "scope", "service",
})
_SCOPE_KEYS = frozenset({"issues", "search_labels"})
_ISSUE_DOC_KEYS = frozenset({"id", "key"})

def _manifest_from_document(parsed: object) -> ScopeManifest:
    if type(parsed) is not dict or set(parsed.keys()) != _MANIFEST_TOP_KEYS:
        raise RouteConfigError("manifest_invalid")
    if parsed["schema"] != SCOPE_SCHEMA:
        raise RouteConfigError("manifest_invalid")
    scope_document = parsed["scope"]
    if type(scope_document) is not dict or set(scope_document.keys()) != _SCOPE_KEYS:
        raise RouteConfigError("manifest_invalid")
    issues_document = scope_document["issues"]
    if type(issues_document) is not tuple:
        raise RouteConfigError("manifest_invalid")
    issues = []
    for entry in issues_document:
        if type(entry) is not dict or set(entry.keys()) != _ISSUE_DOC_KEYS:
            raise RouteConfigError("manifest_invalid")
        issue_id, issue_key = entry["id"], entry["key"]
        if type(issue_id) is not str or type(issue_key) is not str:
            raise RouteConfigError("manifest_invalid")
        issues.append(ScopedIssue(issue_id=issue_id, issue_key=issue_key))
    search_labels = scope_document["search_labels"]
    if type(search_labels) is not tuple or any(type(item) is not str for item in search_labels):
        raise RouteConfigError("manifest_invalid")
    scope = JiraScope(issues=tuple(issues), search_labels=search_labels)
    routes = parsed["routes"]
    if type(routes) is not tuple or any(type(item) is not str for item in routes):
        raise RouteConfigError("manifest_invalid")
    top_strings = (
        parsed["service"], parsed["run_id"], parsed["attempt_id"],
        parsed["rehearsal_id"], parsed["revision"], parsed["policy_digest"],
    )
    if any(type(value) is not str for value in top_strings):
        raise RouteConfigError("manifest_invalid")
    service, run_id, attempt_id, rehearsal_id, revision, policy_digest = top_strings
    return ScopeManifest(
        service=service, run_id=run_id, attempt_id=attempt_id, rehearsal_id=rehearsal_id,
        revision=revision, routes=routes, policy_digest=policy_digest, scope=scope,
    )

def parse_scope_manifest(data: bytes) -> ScopeManifest:
    """Parse canonical scope-manifest bytes only; a non-canonical encoding is rejected."""
    if type(data) is not bytes:
        raise RouteConfigError("manifest_invalid")
    if len(data) > MAX_MANIFEST_BYTES:
        raise RouteConfigError("manifest_too_large")
    code: str | None = None
    parsed: object = None
    try:
        parsed = parse_json(data, max_bytes=MAX_MANIFEST_BYTES, numbers="integer", ascii_only=True)
    except JSONPolicyError:
        code = "manifest_invalid"
    if code is not None:
        raise RouteConfigError(code) from None
    manifest = _manifest_from_document(parsed)
    if manifest.canonical_bytes() != data:
        raise RouteConfigError("manifest_invalid")
    return manifest

def require_manifest_binding(
    manifest: object, *, service: str, run_id: str, attempt_id: str, scope_digest: str,
) -> None:
    """The check a trusted store runs before installing a manifest for a grant."""
    if (
        type(manifest) is not ScopeManifest
        or type(service) is not str
        or type(run_id) is not str
        or type(attempt_id) is not str
        or type(scope_digest) is not str
    ):
        raise TypeError("require_manifest_binding requires exact str/ScopeManifest types")
    if (
        manifest.service != service
        or manifest.run_id != run_id
        or manifest.attempt_id != attempt_id
        or not _valid_hex64(scope_digest)
        or not hmac.compare_digest(manifest.digest, scope_digest)
    ):
        raise RouteConfigError("manifest_binding_mismatch")

# --- result types --------------------------------------------------------------

@dataclass(frozen=True)
class UpstreamRequest:
    method: str
    target: str = field(repr=False)
    accept: str
    content_type: str | None
    body: bytes = field(repr=False)

@dataclass(frozen=True)
class RouteSelection:
    issue_id: str | None
    issue_key: str | None
    search_label: str | None
    max_results: int | None

@dataclass(frozen=True, eq=False)
class RoutedRequest:
    """Issued only by ``RoutePolicy.route``; identity (not value) is what matters."""

    route_id: str
    service: str
    scope_digest: str
    policy_digest: str
    request_digest: str
    requires_permit: bool
    upstream: UpstreamRequest = field(repr=False)
    selection: RouteSelection = field(repr=False)

@dataclass(frozen=True)
class ResponseVerdict:
    route_id: str
    receipt_reason: str
    detail: str

# --- request digest ------------------------------------------------------------

_DIGEST_METHODS = frozenset({"GET", "POST", "PUT"})

def _valid_route_id(route_id: object) -> bool:
    return (
        type(route_id) is str
        and len(route_id) <= _MAX_ROUTE_ID_LENGTH
        and _ROUTE_ID_RE.fullmatch(route_id) is not None
    )

def _valid_target(target: object) -> bool:
    return (
        type(target) is str
        and _printable_ascii(target)
        and " " not in target
        and target.startswith("/")
        and "#" not in target
        and len(target) <= 2_048
    )

_MAX_MEDIA_TYPE_CHARS = 256

def _valid_media_type(value: object) -> bool:
    return (
        type(value) is str and _printable_ascii(value)
        and 1 <= len(value) <= _MAX_MEDIA_TYPE_CHARS
    )

_QUERY_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

def encode_query_value(value: str) -> str:
    """Percent-encode ``value`` (``A-Za-z0-9-._~`` literal; upper-case ``%XX`` else)."""
    if type(value) is not str or not _printable_ascii(value):
        raise RouteConfigError("digest_input_invalid")
    return "".join(
        character if character in _QUERY_UNRESERVED else f"%{ord(character):02X}"
        for character in value
    )

def request_digest(
    *, service: str, route_id: str, policy_digest: str, scope_digest: str,
    upstream: UpstreamRequest,
) -> str:
    """A tagged digest over the reconstructed upstream request only (v1: no origin)."""
    if (
        type(service) is not str or service not in SERVICE_PROFILES
        or not _valid_route_id(route_id)
        or not _valid_hex64(policy_digest)
        or not _valid_hex64(scope_digest)
        or type(upstream) is not UpstreamRequest
    ):
        raise RouteConfigError("digest_input_invalid")
    method, target, accept, content_type, body = (
        upstream.method, upstream.target, upstream.accept, upstream.content_type, upstream.body,
    )
    if (
        type(method) is not str
        or method not in _DIGEST_METHODS
        or not _valid_target(target)
        or not _valid_media_type(accept)
        or type(body) is not bytes or len(body) > MAX_REQUEST_JSON_BYTES
        or (content_type is not None and not _valid_media_type(content_type))
        or (content_type is None) != (body == b"")
        or (method == "GET" and body != b"")
    ):
        raise RouteConfigError("digest_input_invalid")
    body_sha256 = hashlib.sha256(body).hexdigest() if body else None
    descriptor = {
        "v": 1,
        "service": service,
        "route_id": route_id,
        "policy_digest": policy_digest,
        "scope_digest": scope_digest,
        "method": method,
        "target": target,
        "accept": accept,
        "content_type": content_type,
        "body_bytes": len(body),
        "body_sha256": body_sha256,
    }
    return tagged_digest(REQUEST_DIGEST_TAG, descriptor)

def denied_request_digest(service: str, route_id: str) -> str:
    """A constant digest per ``(service, route_id)``; no caller input is hashed."""
    if type(service) is not str or service not in SERVICE_PROFILES:
        raise RouteConfigError("digest_input_invalid")
    valid_route_ids = {UNMATCHED_ROUTE_ID} | {
        rid for rid, status in ROUTE_CATALOG.items() if status.service == service
    }
    if type(route_id) is not str or route_id not in valid_route_ids:
        raise RouteConfigError("digest_input_invalid")
    return tagged_digest(DENIED_DIGEST_TAG, {"v": 1, "service": service, "route_id": route_id})

# --- matching and per-route validation helpers ----------------------------------

def _match_route(request: ParsedRequest) -> tuple[str | None, str | None]:
    if request.method == "GET":
        parts = request.path.split("/")
        if len(parts) == 6 and parts[:5] == ["", "rest", "api", "3", "issue"] and parts[5]:
            return "jira.issue.get", parts[5]
    elif request.method == "POST" and request.path == "/rest/api/3/search/jql":
        return "jira.search", None
    return None, None

def _lookup_issue(manifest: ScopeManifest, selector: str) -> ScopedIssue | None:
    for entry in manifest.scope.issues:
        if selector == entry.issue_id or selector == entry.issue_key:
            return entry
    return None

def _match_templates(
    templates: tuple[str, ...], labels: tuple[str, ...], jql: str,
) -> list[tuple[str, str]]:
    """One ``(template, label)`` entry per match; see the ambiguity example.

    The template, not the caller's ``jql``, is what later renders the
    upstream body, so a matcher regression here can misroute but can never
    smuggle caller bytes into the request.
    """
    label_set = set(labels)
    matches: list[tuple[str, str]] = []
    for template in templates:
        prefix, suffix = template.split(_TEMPLATE_PLACEHOLDER)
        if len(jql) < len(prefix) + len(suffix):
            continue
        if not (jql.startswith(prefix) and jql.endswith(suffix)):
            continue
        candidate = jql[len(prefix):len(jql) - len(suffix)]
        if candidate in label_set:
            matches.append((template, candidate))
    return matches

def _issue_key_matches(project_key: str, candidate: object) -> bool:
    if type(candidate) is not str:
        return False
    prefix = project_key + "-"
    if not candidate.startswith(prefix):
        return False
    return _NUMERIC_ID_RE.fullmatch(candidate[len(prefix):]) is not None

def _nested_str(document: object, *keys: str) -> str | None:
    """Walk nested dict ``keys``; the string at the end, or ``None`` if any step misses."""
    for key in keys[:-1]:
        document = document.get(key) if type(document) is dict else None
    value = document.get(keys[-1]) if type(document) is dict else None
    return value if type(value) is str else None


def _identity_matches(project: dict, issuetype: dict, policy: JiraVenuePolicy) -> bool:
    return (
        project.get("id") == policy.project_id
        and project.get("key") == policy.project_key
        and issuetype.get("id") == policy.issue_type_id
    )


def _common_issue_shape(
    document: object, allowed_fields: frozenset[str],
) -> tuple[dict, dict, dict] | None:
    """Return ``(fields, project, issuetype)`` for a valid IssueBean shape, else ``None``."""
    if type(document) is not dict:
        return None
    keys = set(document.keys())
    if not ({"id", "key", "fields"} <= keys <= {"expand", "id", "key", "self", "fields"}):
        return None
    if type(document["id"]) is not str or type(document["key"]) is not str:
        return None
    for optional_key in ("self", "expand"):
        if optional_key in document and type(document[optional_key]) is not str:
            return None
    fields = document["fields"]
    if type(fields) is not dict or not set(fields.keys()) <= allowed_fields:
        return None
    project = fields.get("project")
    issuetype = fields.get("issuetype")
    if type(project) is not dict or type(issuetype) is not dict:
        return None
    return fields, project, issuetype

# --- ParserOptions and RoutePolicy ----------------------------------------------

@dataclass(frozen=True)
class ParserOptions:
    allowed_query_keys: frozenset[str]
    accept: str

class RoutePolicy:
    """Validate, scope-check and digest one bounded HTTP request per service."""

    def __init__(self, *, jira: JiraVenuePolicy | None = None) -> None:
        if jira is not None and type(jira) is not JiraVenuePolicy:
            raise TypeError("jira must be a JiraVenuePolicy or None")
        configured_bytes = len(jira.canonical_bytes()) if jira is not None else 0
        if configured_bytes > MAX_POLICY_BYTES:
            raise RouteConfigError("policy_too_large")
        self._jira = jira
        self._lock = threading.Lock()
        self._issued: weakref.WeakSet[RoutedRequest] = weakref.WeakSet()

    @staticmethod
    def _check_service(service: object) -> None:
        if type(service) is not str:
            raise TypeError("service must be a str")
        if service not in SERVICE_PROFILES:
            raise ValueError("unknown service")

    def policy_digest(self, service: str) -> str | None:
        self._check_service(service)
        if service == "jira" and self._jira is not None:
            return self._jira.digest
        return None

    def parser_options(self, service: str) -> ParserOptions:
        self._check_service(service)
        if service == "jira" and self._jira is not None:
            return ParserOptions(frozenset({"fields"}), "application/json")
        return ParserOptions(frozenset(), "application/json")

    def _deny(self, code: str, *, service: str, route_id: str) -> None:
        raise RoutePolicyError(
            code, route_id=route_id, request_digest=denied_request_digest(service, route_id),
        ) from None

    @staticmethod
    def _check_request_shape(request: object) -> None:
        if type(request) is not ParsedRequest:
            raise TypeError("request must be an exact ParsedRequest")
        if (
            type(request.service) is not str
            or type(request.method) is not str
            or type(request.path) is not str
            or type(request.accept) is not str
            or type(request.body) is not bytes
            or type(request.query) is not tuple
            or any(
                type(pair) is not tuple or len(pair) != 2
                or type(pair[0]) is not str or type(pair[1]) is not str
                for pair in request.query
            )
        ):
            raise TypeError("request has an invalid field type")

    def _select_issue_get(
        self, request: ParsedRequest, manifest: ScopeManifest, selector: str, service: str,
    ) -> RouteSelection:
        route_id = "jira.issue.get"
        policy = self._jira
        if request.body != b"":
            self._deny("request_invalid", service=service, route_id=route_id)
        csv = ",".join(policy.issue_fields)
        if request.query not in ((), (("fields", csv),)):
            self._deny("query_rejected", service=service, route_id=route_id)
        if _NUMERIC_ID_RE.fullmatch(selector) is None and _ISSUE_KEY_RE.fullmatch(selector) is None:
            self._deny("selector_invalid", service=service, route_id=route_id)
        entry = _lookup_issue(manifest, selector)
        if entry is None:
            self._deny("selector_out_of_scope", service=service, route_id=route_id)
        return RouteSelection(
            issue_id=entry.issue_id, issue_key=entry.issue_key, search_label=None, max_results=None,
        )

    def _select_search(
        self, request: ParsedRequest, manifest: ScopeManifest, service: str,
    ) -> tuple[RouteSelection, str, int]:
        route_id = "jira.search"
        policy = self._jira
        if request.query != ():
            self._deny("query_rejected", service=service, route_id=route_id)
        code: str | None = None
        parsed: object = None
        try:
            parsed = parse_json(request.body, max_bytes=MAX_REQUEST_JSON_BYTES, numbers="integer")
        except JSONPolicyError:
            code = "body_rejected"
        if code is not None:
            self._deny(code, service=service, route_id=route_id)
        if (
            type(parsed) is not dict
            or "jql" not in parsed
            or not set(parsed) <= {"jql", "maxResults", "fields"}
        ):
            self._deny("body_rejected", service=service, route_id=route_id)
        jql = parsed["jql"]
        if type(jql) is not str:
            self._deny("body_rejected", service=service, route_id=route_id)

        matches = _match_templates(policy.search_templates, manifest.scope.search_labels, jql)
        if len(matches) == 0:
            self._deny("selector_out_of_scope", service=service, route_id=route_id)
        if len(matches) > 1:
            self._deny("selector_ambiguous", service=service, route_id=route_id)
        template, label = matches[0]

        max_results = parsed.get("maxResults", policy.search_max_results)
        if type(max_results) is not int or not 1 <= max_results <= policy.search_max_results:
            self._deny("body_rejected", service=service, route_id=route_id)

        if "fields" in parsed:
            fields = parsed["fields"]
            if (
                type(fields) is not tuple
                or any(type(item) is not str for item in fields)
                or len(set(fields)) != len(fields)
                or set(fields) != set(policy.search_fields)
            ):
                self._deny("body_rejected", service=service, route_id=route_id)

        selection = RouteSelection(
            issue_id=None, issue_key=None, search_label=label, max_results=max_results,
        )
        # Render from the matched template, never the caller's jql string, so
        # caller bytes can never reach the upstream body even if the matcher
        # above ever regressed (plan: "caller bytes never reach it").
        rendered = template.replace(_TEMPLATE_PLACEHOLDER, label)
        return selection, rendered, max_results

    def route(self, request: object, manifest: object) -> RoutedRequest:
        self._check_request_shape(request)
        if type(manifest) is not ScopeManifest:
            raise TypeError("manifest must be an exact ScopeManifest")
        if request.service not in SERVICE_PROFILES:
            raise ValueError("unknown service")

        service = request.service
        if service != "jira" or self._jira is None:
            self._deny("service_unavailable", service=service, route_id=UNMATCHED_ROUTE_ID)
        policy = self._jira

        if (
            manifest.service != service
            or not hmac.compare_digest(manifest.policy_digest, policy.digest)
            or any(
                not issue.issue_key.startswith(policy.project_key + "-")
                for issue in manifest.scope.issues
            )
        ):
            self._deny("manifest_mismatch", service=service, route_id=UNMATCHED_ROUTE_ID)

        if request.accept != "application/json":
            self._deny("request_invalid", service=service, route_id=UNMATCHED_ROUTE_ID)

        route_id, selector = _match_route(request)
        if route_id is None:
            self._deny("route_unknown", service=service, route_id=UNMATCHED_ROUTE_ID)

        if route_id not in manifest.routes:
            self._deny("route_not_in_scope", service=service, route_id=route_id)

        rendered_jql: str | None = None
        max_results: int | None = None
        if route_id == "jira.issue.get":
            selection = self._select_issue_get(request, manifest, selector, service)
        else:
            selection, rendered_jql, max_results = self._select_search(request, manifest, service)

        # Step 8: build the upstream request and its digest from manifest/policy
        # values only. Inputs are already validated, so this cannot fail; if a
        # helper ever did raise, the denial is upstream_unbuildable (route_denied).
        code: str | None = None
        digest: str | None = None
        upstream: UpstreamRequest | None = None
        try:
            if route_id == "jira.issue.get":
                csv = ",".join(policy.issue_fields)
                target = (
                    "/rest/api/3/issue/" + selection.issue_id
                    + "?fields=" + encode_query_value(csv)
                )
                upstream = UpstreamRequest("GET", target, "application/json", None, b"")
            else:
                body = canonical_json({
                    "fields": list(policy.search_fields),
                    "jql": rendered_jql,
                    "maxResults": max_results,
                })
                upstream = UpstreamRequest(
                    "POST", "/rest/api/3/search/jql", "application/json",
                    "application/json", body,
                )
            digest = request_digest(
                service=service, route_id=route_id, policy_digest=policy.digest,
                scope_digest=manifest.digest, upstream=upstream,
            )
        except (RouteConfigError, JSONPolicyError):
            code = "upstream_unbuildable"
        if code is not None:
            self._deny(code, service=service, route_id=route_id)

        routed = RoutedRequest(
            route_id=route_id, service=service, scope_digest=manifest.digest,
            policy_digest=policy.digest, request_digest=digest, requires_permit=False,
            upstream=upstream, selection=selection,
        )
        with self._lock:
            self._issued.add(routed)
        return routed

    def _check_issue_get_response(self, routed: RoutedRequest, document: object) -> str:
        policy = self._jira
        shape = _common_issue_shape(document, set(policy.issue_fields))
        if shape is None:
            return "schema_invalid"
        _fields, project, issuetype = shape
        selection = routed.selection
        if document["id"] != selection.issue_id or document["key"] != selection.issue_key:
            return "scope_mismatch"
        if not _identity_matches(project, issuetype, policy):
            return "scope_mismatch"
        return "ok"

    def _check_search_issue(
        self, issue: object, policy: JiraVenuePolicy, selection: RouteSelection,
        seen_ids: set[str],
    ) -> str:
        shape = _common_issue_shape(issue, set(policy.search_fields))
        if shape is None:
            return "schema_invalid"
        fields, project, issuetype = shape
        issue_id, issue_key = issue["id"], issue["key"]
        if _NUMERIC_ID_RE.fullmatch(issue_id) is None or issue_id in seen_ids:
            return "schema_invalid"
        seen_ids.add(issue_id)
        if not _issue_key_matches(policy.project_key, issue_key):
            return "schema_invalid"
        if not _identity_matches(project, issuetype, policy):
            return "scope_mismatch"
        labels = fields.get("labels")
        if type(labels) is not tuple or any(type(item) is not str for item in labels):
            return "schema_invalid"
        if selection.search_label not in labels:
            return "scope_mismatch"
        category_key = _nested_str(fields, "status", "statusCategory", "key")
        if category_key is None:
            return "schema_invalid"
        if category_key not in policy.open_status_category_keys:
            return "scope_mismatch"
        return "ok"

    def _check_search_response(self, routed: RoutedRequest, document: object) -> str:
        policy = self._jira
        if type(document) is not dict:
            return "schema_invalid"
        keys = set(document.keys())
        if not ({"issues"} <= keys <= {"issues", "isLast", "nextPageToken", "warnings"}):
            return "schema_invalid"
        if "warnings" in document and type(document["warnings"]) is not tuple:
            return "schema_invalid"
        if "isLast" in document and type(document["isLast"]) is not bool:
            return "schema_invalid"
        if "nextPageToken" in document and type(document["nextPageToken"]) is not str:
            return "schema_invalid"
        issues = document["issues"]
        if type(issues) is not tuple:
            return "schema_invalid"
        selection = routed.selection
        if len(issues) > selection.max_results:
            return "count_exceeded"
        seen_ids: set[str] = set()
        for issue in issues:
            detail = self._check_search_issue(issue, policy, selection, seen_ids)
            if detail != "ok":
                return detail
        return "ok"

    def check_response(self, routed: object, response: object) -> ResponseVerdict:
        if type(routed) is not RoutedRequest:
            raise TypeError("routed must be an exact RoutedRequest")
        if type(response) is not ParsedResponse:
            raise TypeError("response must be an exact ParsedResponse")
        with self._lock:
            issued = routed in self._issued
        if not issued:
            return ResponseVerdict(routed.route_id, "response_policy_rejected", "routed_unknown")
        try:
            serialize_response(response)
        except HTTPResponseError:
            return ResponseVerdict(routed.route_id, "response_policy_rejected", "response_invalid")
        if response.status != 200:
            return ResponseVerdict(
                routed.route_id, "response_policy_rejected", "status_not_allowed",
            )
        try:
            parsed = parse_json(response.body, max_bytes=MAX_RESPONSE_BYTES, numbers="finite")
        except JSONPolicyError:
            return ResponseVerdict(routed.route_id, "response_policy_rejected", "json_invalid")
        if routed.route_id == "jira.issue.get":
            detail = self._check_issue_get_response(routed, parsed)
        else:
            detail = self._check_search_response(routed, parsed)
        if detail != "ok":
            return ResponseVerdict(routed.route_id, "response_policy_rejected", detail)
        return ResponseVerdict(routed.route_id, "ok", "ok")

__all__ = [
    "DENIED_DIGEST_TAG", "JIRA_POLICY_SCHEMA", "JIRA_READABLE_SYSTEM_FIELDS",
    "JIRA_ROUTES_CODE_REVISION", "LOCAL_ROUTE_IDS", "MATCHABLE_ROUTE_IDS", "MAX_FIELDS",
    "MAX_MANIFEST_BYTES", "MAX_POLICY_BYTES", "MAX_REQUEST_JSON_BYTES", "MAX_RESPONSE_BYTES",
    "MAX_SCOPED_ISSUES", "MAX_SEARCH_LABELS", "MAX_SEARCH_RESULTS", "MAX_SEARCH_TEMPLATES",
    "MAX_TEMPLATE_BYTES", "MISSING_INPUT_CODES", "OPTIONAL_ROUTE_IDS", "POLICY_DIGEST_TAG",
    "REQUEST_DIGEST_TAG", "RESPONSE_DETAILS", "ROUTE_CATALOG", "ROUTE_ERROR_REASONS",
    "ROUTE_ID_PATTERN", "SCOPE_DIGEST_TAG", "SCOPE_SCHEMA", "SPEC_ROUTE_IDS",
    "UNMATCHED_ROUTE_ID",
    "JiraScope", "JiraVenuePolicy", "ParserOptions", "ResponseVerdict", "RouteConfigError",
    "RoutePolicy", "RoutePolicyError", "RouteSelection", "RouteStatus", "RoutedRequest",
    "ScopeManifest", "ScopedIssue", "UpstreamRequest",
    "denied_request_digest", "encode_query_value", "parse_scope_manifest",
    "policy_readiness_facts", "request_digest", "require_manifest_binding",
]
