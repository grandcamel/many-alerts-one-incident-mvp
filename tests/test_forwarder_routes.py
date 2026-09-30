"""Deterministic tests for the Jira route policy: catalog, digests and routing.

Golden vectors are recomputed independently in the implementation plan; the
known-answer tests below pin them literally. Every ``ParsedRequest`` here is
built directly (not through ``forwarder_http``), which is legitimate for
exercising ``RoutePolicy`` in isolation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from grafana_jsm_sandbox import forwarder_routes as fr
from grafana_jsm_sandbox.forwarder_http import ParsedRequest
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_json import JSONPolicyError, canonical_json
from grafana_jsm_sandbox.forwarder_routes import (
    MATCHABLE_ROUTE_IDS,
    MAX_REQUEST_JSON_BYTES,
    MAX_TEMPLATE_BYTES,
    MISSING_INPUT_CODES,
    ROUTE_CATALOG,
    ROUTE_ERROR_REASONS,
    ROUTE_ID_PATTERN,
    JiraScope,
    JiraVenuePolicy,
    ParserOptions,
    ResponseVerdict,
    RouteConfigError,
    RoutedRequest,
    RoutePolicy,
    RoutePolicyError,
    RouteSelection,
    ScopedIssue,
    ScopeManifest,
    UpstreamRequest,
    denied_request_digest,
    encode_query_value,
    parse_scope_manifest,
    policy_readiness_facts,
    request_digest,
    require_manifest_binding,
)
from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES, classify_readiness

# --- golden fixtures -----------------------------------------------------

GOLDEN_POLICY_KWARGS = {
    "revision": "policy-r1",
    "project_id": "90001",
    "project_key": "SYN",
    "issue_type_id": "90002",
    "issue_fields": ("issuetype", "labels", "project", "status", "summary"),
    "search_fields": ("issuetype", "labels", "project", "status", "summary"),
    "search_templates": (
        (
            'project = 90001 AND issuetype = 90002 AND labels = "{label}" '
            "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
        ),
    ),
    "search_max_results": 50,
    "open_status_category_keys": ("syn-new", "syn-progress"),
}

POLICY_DIGEST = "3013f6a10469469651028a5ea422849591fae5a8bb4a7e15b92e2b0caf99a156"
POLICY_CANONICAL_LEN = 546
POLICY_CANONICAL_BYTES = (
    b'{"code_revision":"maoi.forwarder.jira-routes.v1","issue_fields":'
    b'["issuetype","labels","project","status","summary"],"issue_type_id":"90002",'
    b'"open_status_category_keys":["syn-new","syn-progress"],"project_id":"90001",'
    b'"project_key":"SYN","revision":"policy-r1","schema":"maoi.forwarder.jira-policy.v1",'
    b'"search_fields":["issuetype","labels","project","status","summary"],'
    b'"search_max_results":50,"search_templates":["project = 90001 AND issuetype = 90002 '
    b'AND labels = \\"{label}\\" AND statusCategory != Done AND created >= -30m ORDER BY '
    b'created ASC"]}'
)

GOLDEN_SCOPE = JiraScope(
    issues=(ScopedIssue(issue_id="90101", issue_key="SYN-1"),),
    search_labels=("fp-0123456789abcdef",),
)
SCOPE_DIGEST = "849028ca20f4b87db84ad25974dadd560b5d06177e17afad6b6a65fb902de47c"
MANIFEST_CANONICAL_LEN = 361
MANIFEST_CANONICAL_BYTES = (
    b'{"attempt_id":"attempt-1","policy_digest":'
    b'"3013f6a10469469651028a5ea422849591fae5a8bb4a7e15b92e2b0caf99a156",'
    b'"rehearsal_id":"rehearsal-1","revision":"scope-r1",'
    b'"routes":["jira.issue.get","jira.search"],"run_id":"run-1",'
    b'"schema":"maoi.forwarder.scope.v1","scope":{"issues":'
    b'[{"id":"90101","key":"SYN-1"}],"search_labels":["fp-0123456789abcdef"]},'
    b'"service":"jira"}'
)

ISSUE_GET_TARGET = "/rest/api/3/issue/90101?fields=issuetype%2Clabels%2Cproject%2Cstatus%2Csummary"
ISSUE_GET_DIGEST = "43d8b4787de8e9370f79c719f3dbd5463e259bce78b98cd27daa246c7042b929"

SEARCH_BODY_50 = (
    b'{"fields":["issuetype","labels","project","status","summary"],'
    b'"jql":"project = 90001 AND issuetype = 90002 AND labels = '
    b'\\"fp-0123456789abcdef\\" AND statusCategory != Done AND created >= '
    b'-30m ORDER BY created ASC","maxResults":50}'
)
SEARCH_DIGEST_50 = "d416cc8619c619fe09b16796d7b87c515503e74ce6624f3a2d75570ce9d0692e"
SEARCH_DIGEST_10 = "9ae5873f36dda9412cff5e44f04e62581e9445141008d5dc1319991363701552"
SEARCH_BODY_50_SHA256 = "e95499d5e38bcfa206d332410c2b91b34e92bca4f7bc541f889738f785832070"
SEARCH_BODY_10_SHA256 = "c657c4b3bdd53a950d4e320149062a882bd18cd4735b8dc24c88b4ea951628a2"
SEARCH_BODY_LEN = 229

DENIAL_DIGESTS = {
    ("jira", "unmatched"): "4d70175f274bcfc9b1ac634035192fb5f3152f9aa2cd5a8c1baefc06f7db0703",
    ("jira", "jira.issue.get"): "d25b40c66fc9a150a6337bf0aeb2f8bf783b8b2196511a76577a23a2aa0c14ae",
    ("jira", "jira.search"): "e527abd1fe362e9aa4c829160caca2b2894b3fcc152db53a153e375abfa0c7fd",
    ("confluence", "unmatched"): "e8781cb247a2d68303e7886341ffca985c73ac6100fdc95279956cf796fc0d39",
    ("grafana", "unmatched"): "4d8832246e0e81a323e2e21602285d617a6b0592e97eb4d54308ae2f3a4c0dca",
    ("kubernetes", "unmatched"): "e1993eb15d7ca65b407a4d1fc3c61e1ef63c6da4faa8e0ee1eeca67506732d2d",
    ("anthropic", "unmatched"): "1d1782c3413ce7472e58ae146c850f3795a0a4ef8fd2f4457c7e1dfa589488c7",
}


def golden_policy(**overrides) -> JiraVenuePolicy:
    kwargs = {**GOLDEN_POLICY_KWARGS, **overrides}
    return JiraVenuePolicy(**kwargs)


def golden_manifest(**overrides) -> ScopeManifest:
    kwargs = {
        "service": "jira", "run_id": "run-1", "attempt_id": "attempt-1",
        "rehearsal_id": "rehearsal-1", "revision": "scope-r1",
        "routes": ("jira.issue.get", "jira.search"),
        "policy_digest": POLICY_DIGEST, "scope": GOLDEN_SCOPE,
    }
    kwargs.update(overrides)
    return ScopeManifest(**kwargs)


def make_request(
    *, service="jira", method="GET", path="/", query=(), accept="application/json",
    body=b"", sentinel="s" * 43,
) -> ParsedRequest:
    return ParsedRequest(
        service=service, method=method, path=path, query=query, accept=accept, body=body,
        sentinel=sentinel,
    )


def assert_config_error(call, code: str) -> RouteConfigError:
    with pytest.raises(RouteConfigError) as caught:
        call()
    error = caught.value
    assert error.code == code
    assert str(error) == code
    assert error.args == (code,)
    assert error.__cause__ is None
    return error


def assert_denied(call, *, code: str, route_id: str, service: str = "jira") -> RoutePolicyError:
    with pytest.raises(RoutePolicyError) as caught:
        call()
    error = caught.value
    assert error.code == code
    assert error.args == (code,)
    assert error.route_id == route_id
    assert error.receipt_reason == ROUTE_ERROR_REASONS[code]
    assert error.request_digest == denied_request_digest(service, route_id)
    return error


# === golden vectors ========================================================


def test_golden_policy_canonical_bytes_and_digest():
    policy = golden_policy()
    assert len(policy.canonical_bytes()) == POLICY_CANONICAL_LEN
    assert policy.digest == POLICY_DIGEST


def test_golden_manifest_canonical_bytes_and_digest():
    manifest = golden_manifest()
    assert manifest.canonical_bytes() == MANIFEST_CANONICAL_BYTES
    assert len(manifest.canonical_bytes()) == MANIFEST_CANONICAL_LEN
    assert manifest.digest == SCOPE_DIGEST


def test_golden_issue_get_digest():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    assert routed.upstream.target == ISSUE_GET_TARGET
    assert routed.request_digest == ISSUE_GET_DIGEST
    assert routed.route_id == "jira.issue.get"
    assert routed.service == "jira"
    assert routed.scope_digest == SCOPE_DIGEST == manifest.digest
    assert routed.policy_digest == POLICY_DIGEST
    assert routed.requires_permit is False


@pytest.mark.parametrize("max_results,body,digest", [
    (None, SEARCH_BODY_50, SEARCH_DIGEST_50),
    (10, None, SEARCH_DIGEST_10),
])
def test_golden_search_digest(max_results, body, digest):
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    payload = {"jql": jql}
    if max_results is not None:
        payload["maxResults"] = max_results
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json(payload),
    )
    routed = policy.route(request, manifest)
    assert routed.request_digest == digest
    assert routed.route_id == "jira.search"
    assert routed.service == "jira"
    assert routed.scope_digest == SCOPE_DIGEST == manifest.digest
    assert routed.policy_digest == POLICY_DIGEST
    assert routed.requires_permit is False
    if body is not None:
        assert routed.upstream.body == body


def test_golden_search_body_sha256_and_policy_canonical_bytes_are_pinned():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    routed_50 = policy.route(make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": jql}),
    ), manifest)
    assert hashlib.sha256(routed_50.upstream.body).hexdigest() == SEARCH_BODY_50_SHA256
    assert len(routed_50.upstream.body) == SEARCH_BODY_LEN

    routed_10 = policy.route(make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": jql, "maxResults": 10}),
    ), manifest)
    assert hashlib.sha256(routed_10.upstream.body).hexdigest() == SEARCH_BODY_10_SHA256
    assert len(routed_10.upstream.body) == SEARCH_BODY_LEN

    assert golden_policy().canonical_bytes() == POLICY_CANONICAL_BYTES


@pytest.mark.parametrize(
    "service,route_id,digest",
    [(service, route_id, digest) for (service, route_id), digest in DENIAL_DIGESTS.items()],
)
def test_golden_denial_digests(service, route_id, digest):
    assert denied_request_digest(service, route_id) == digest


# === policy validation ======================================================


def test_policy_field_rules_accept_golden():
    assert golden_policy().digest == POLICY_DIGEST


@pytest.mark.parametrize("field,value", [
    ("revision", ""),
    ("revision", "a" * 129),
    ("revision", "bad revision"),
    ("revision", 123),  # well-formed otherwise; non-str must not reach the regex as a str
    ("project_id", "0"),
    ("project_id", "01"),
    ("project_id", 90001),
    ("project_key", "syn"),
    ("project_key", "S"),
    ("project_key", 123),  # non-str project_key
    ("issue_type_id", "0"),
    ("issue_type_id", 90002),  # non-str issue_type_id
    ("search_max_results", 0),
    ("search_max_results", 101),
    ("search_max_results", True),
    ("search_max_results", "50"),
    ("issue_fields", ("project", "issuetype")),  # valid fields, wrong (descending) order
    # A list, not a tuple, of otherwise-valid, ascending, required fields:
    # without the tuple-type guard this would satisfy every other rule.
    ("issue_fields", ["issuetype", "project"]),
    ("search_templates", ()),  # min_len: no templates at all
    ("open_status_category_keys", ()),  # min_len: no keys at all
    # A non-str item: the per-item str-type guard must reject this before
    # item_ok ever runs a string operation on it (which would raise TypeError).
    ("search_templates", (1,)),
    ("open_status_category_keys", (1,)),
    (
        "search_templates",
        (
            'project = 1 AND labels = "{label}" AND b',
            'project = 1 AND labels = "{label}" AND a',
        ),
    ),  # valid templates, wrong (descending) order
    ("open_status_category_keys", ("a", "b", "c", "d", "e")),  # one over the max of 4
])
def test_policy_field_rejections(field, value):
    assert_config_error(lambda: golden_policy(**{field: value}), "policy_invalid")


def test_policy_rejects_a_single_template_over_the_byte_cap():
    # Exercises the per-template MAX_TEMPLATE_BYTES check in isolation, from
    # the eight-templates-of-max-size case below, which fails on total
    # policy size (policy_too_large) rather than any one template's length.
    prefix = 'x "{label}" '
    long_template = prefix + "a" * (MAX_TEMPLATE_BYTES - len(prefix) + 1)
    assert len(long_template) == MAX_TEMPLATE_BYTES + 1
    assert_config_error(
        lambda: golden_policy(search_templates=(long_template,)), "policy_invalid",
    )


def test_policy_rejects_nine_templates_by_count_not_by_size():
    # Nine small, ascending templates: only the 8-template maximum (not the
    # byte-size cap exercised above) can reject this.
    templates = tuple(f'a{i} "{{label}}"' for i in range(9))
    assert list(templates) == sorted(templates)
    assert_config_error(lambda: golden_policy(search_templates=templates), "policy_invalid")


@pytest.mark.parametrize("bad_field", [
    "comment", "reporter", "*all", "-description", "description", "customfield_10085",
])
def test_policy_rejects_excluded_fields(bad_field):
    fields = GOLDEN_POLICY_KWARGS["issue_fields"] + (bad_field,)
    assert_config_error(lambda: golden_policy(issue_fields=fields), "policy_invalid")


def test_policy_requires_issuetype_and_project_in_issue_fields():
    assert_config_error(
        lambda: golden_policy(issue_fields=("labels", "status", "summary")), "policy_invalid",
    )


@pytest.mark.parametrize("fields", [
    ("labels", "project", "status", "summary"),  # issuetype dropped alone
    ("issuetype", "labels", "status", "summary"),  # project dropped alone
])
def test_policy_requires_issuetype_and_project_individually(fields):
    assert_config_error(lambda: golden_policy(issue_fields=fields), "policy_invalid")


def test_policy_requires_core_fields_in_search_fields():
    assert_config_error(
        lambda: golden_policy(search_fields=("labels", "project", "status", "summary")),
        "policy_invalid",
    )


@pytest.mark.parametrize("fields", [
    ("issuetype", "project", "status", "summary"),  # labels dropped alone
    ("issuetype", "labels", "project", "summary"),  # status dropped alone
])
def test_policy_requires_labels_and_status_in_search_fields_individually(fields):
    assert_config_error(lambda: golden_policy(search_fields=fields), "policy_invalid")


@pytest.mark.parametrize("template", [
    'project = 1 AND labels = "z"',  # no {label} at all
    'project = 1 AND labels = {label}',  # unquoted
    'project = 1 AND labels = "{label}" OR labels = "{label}"',  # twice
    'project = {label} AND x = "{label}"',  # extra brace elsewhere
    "x { y } \"{label}\"",  # stray braces
    'project = 1 AND labels = "{label}"\n',  # otherwise valid; a raw newline
    'project = 1 AND labels = "{label}"' + "\x7f",  # otherwise valid; DEL
    'project = 1 AND labels = "{label}" café',  # otherwise valid; non-ASCII
])
def test_policy_rejects_malformed_templates(template):
    assert_config_error(lambda: golden_policy(search_templates=(template,)), "policy_invalid")


def test_policy_rejects_eight_maximum_size_templates():
    def padded(marker: str) -> str:
        prefix = f'{marker} "{{label}}"'
        return prefix + "x" * (MAX_TEMPLATE_BYTES - len(prefix))

    templates = tuple(padded(str(i)) for i in range(8))
    assert all(len(t) == MAX_TEMPLATE_BYTES for t in templates)
    assert_config_error(lambda: golden_policy(search_templates=templates), "policy_too_large")


def test_policy_canonical_bytes_and_digest_never_raise_once_constructed():
    policy = golden_policy()
    for _ in range(3):
        assert len(policy.canonical_bytes()) == POLICY_CANONICAL_LEN
        assert policy.digest == POLICY_DIGEST


# === manifest validation =====================================================


def test_manifest_field_rules_accept_golden():
    assert golden_manifest().digest == SCOPE_DIGEST


@pytest.mark.parametrize("field,value", [
    ("service", "confluence"),
    ("run_id", ""),
    ("run_id", "bad id!"),
    ("run_id", 123),  # non-str: the safe-ID regex must never see a non-str value
    ("attempt_id", "bad id!"),
    ("attempt_id", ""),
    ("attempt_id", 123),  # attempt_id's own inclusion in the safe-ID loop
    ("rehearsal_id", "bad id!"),
    ("revision", "bad id!"),
    ("routes", ()),
    ("routes", ("jira.issue.get", "jira.search", "jira.issue.get")),
    ("routes", ("jira.search", "jira.issue.get")),  # valid IDs, wrong (descending) order
    ("routes", ("jira.transition",)),
    # A list, not a tuple, of otherwise-valid routes: without the tuple-type
    # guard on _valid_tuple this single-item list would satisfy every other
    # rule (length, membership, vacuous ordering) and be silently accepted.
    ("routes", ["jira.issue.get"]),
    ("policy_digest", "not-hex"),
    ("policy_digest", "F" * 64),
    ("policy_digest", 12345),  # non-str: _valid_hex64 must never see a non-str value
    ("scope", "not-a-scope"),
])
def test_manifest_field_rejections(field, value):
    assert_config_error(lambda: golden_manifest(**{field: value}), "manifest_invalid")


class _AlwaysEqualStr(str):
    """A str subclass that compares equal to anything; exercises the exact-type check."""

    def __eq__(self, _other: object) -> bool:
        return True

    def __ne__(self, _other: object) -> bool:
        return False

    def __hash__(self) -> int:
        return super().__hash__()


def test_manifest_rejects_a_non_exact_str_service_that_compares_equal():
    assert_config_error(
        lambda: golden_manifest(service=_AlwaysEqualStr("jira")), "manifest_invalid",
    )


def test_manifest_requires_issues_iff_issue_get_in_routes():
    empty_scope = JiraScope(issues=(), search_labels=("fp-0123456789abcdef",))
    assert_config_error(
        lambda: golden_manifest(scope=empty_scope), "manifest_invalid",
    )


def test_manifest_requires_labels_iff_search_in_routes():
    bad_scope = JiraScope(issues=GOLDEN_SCOPE.issues, search_labels=("fp-0123456789abcdef",))
    assert_config_error(
        lambda: golden_manifest(routes=("jira.issue.get",), scope=bad_scope),
        "manifest_invalid",
    )


def test_manifest_rejects_issues_present_without_issue_get_in_routes():
    # The reverse direction of the issues-iff-issue.get biconditional: issues
    # must not be smuggled in when the route that would use them is absent.
    scope = JiraScope(issues=GOLDEN_SCOPE.issues, search_labels=("fp-0123456789abcdef",))
    assert_config_error(
        lambda: golden_manifest(routes=("jira.search",), scope=scope),
        "manifest_invalid",
    )


def test_scoped_issue_grammar_rejections():
    assert_config_error(lambda: ScopedIssue(issue_id="0", issue_key="SYN-1"), "manifest_invalid")
    assert_config_error(
        lambda: ScopedIssue(issue_id="90101", issue_key="syn-1"), "manifest_invalid",
    )
    assert_config_error(
        lambda: ScopedIssue(issue_id="90101", issue_key="SYN-0"), "manifest_invalid",
    )


def test_scoped_issue_rejects_non_str_fields():
    # The exact-type checks, distinct from the grammar checks above: a
    # well-formed-looking int must never reach the compiled regex as a str.
    assert_config_error(lambda: ScopedIssue(issue_id=90101, issue_key="SYN-1"), "manifest_invalid")
    assert_config_error(lambda: ScopedIssue(issue_id="90101", issue_key=90101), "manifest_invalid")


def test_numeric_id_eighteen_digits_accepted_nineteen_rejected():
    eighteen_digits = "1" + "0" * 17
    assert len(eighteen_digits) == 18
    ScopedIssue(issue_id=eighteen_digits, issue_key="SYN-" + eighteen_digits)  # does not raise
    nineteen_digits = "1" + "0" * 18
    assert len(nineteen_digits) == 19
    assert_config_error(
        lambda: ScopedIssue(issue_id=nineteen_digits, issue_key="SYN-1"), "manifest_invalid",
    )
    assert_config_error(
        lambda: ScopedIssue(issue_id="1", issue_key="SYN-" + nineteen_digits), "manifest_invalid",
    )


class _DuckScopedIssue:
    """Duck-types ScopedIssue's public attributes but is not one; exercises
    JiraScope's item-type guard (as opposed to its own tuple-type guard)."""

    def __init__(self, issue_id: str, issue_key: str) -> None:
        self.issue_id = issue_id
        self.issue_key = issue_key


def test_jira_scope_rejects_a_duck_typed_non_scoped_issue_item():
    forged = _DuckScopedIssue(issue_id="90101", issue_key="SYN-1")
    assert_config_error(
        lambda: JiraScope(issues=(forged,), search_labels=()), "manifest_invalid",
    )


def test_jira_scope_rejects_a_list_of_issues_instead_of_a_tuple():
    # The tuple-type guard on JiraScope.issues, distinct from the per-item
    # ScopedIssue type guard above: a list of otherwise-valid ScopedIssue
    # instances must still be rejected.
    issue = ScopedIssue(issue_id="90101", issue_key="SYN-1")
    assert_config_error(
        lambda: JiraScope(issues=[issue], search_labels=()), "manifest_invalid",
    )


def test_jira_scope_rejects_duplicate_and_unordered_issues():
    a = ScopedIssue(issue_id="90101", issue_key="SYN-1")
    b = ScopedIssue(issue_id="90102", issue_key="SYN-2")
    assert_config_error(lambda: JiraScope(issues=(b, a), search_labels=()), "manifest_invalid")
    assert_config_error(lambda: JiraScope(issues=(a, a), search_labels=()), "manifest_invalid")


def test_jira_scope_rejects_distinct_ids_sharing_one_key():
    # Duplicate-id and duplicate-key are checked independently; a shared key
    # alone (distinct IDs) must not slip through as only a duplicate-id bug.
    a = ScopedIssue(issue_id="90101", issue_key="SYN-1")
    b = ScopedIssue(issue_id="90102", issue_key="SYN-1")
    assert_config_error(lambda: JiraScope(issues=(a, b), search_labels=()), "manifest_invalid")


def test_jira_scope_orders_issue_ids_as_integers_not_strings():
    # "10" < "9" as strings but not as integers; ascending-by-int must be
    # what is enforced, so this must construct without error.
    nine = ScopedIssue(issue_id="9", issue_key="SYN-9")
    ten = ScopedIssue(issue_id="10", issue_key="SYN-10")
    JiraScope(issues=(nine, ten), search_labels=())


def test_jira_scope_rejects_bad_label_grammar():
    for label in ("Upper", "with space", 'quote"', "back\\slash"):
        assert_config_error(
            lambda label=label: JiraScope(issues=(), search_labels=(label,)), "manifest_invalid",
        )


def test_jira_scope_rejects_a_list_of_labels_instead_of_a_tuple():
    assert_config_error(
        lambda: JiraScope(issues=(), search_labels=["fp-0123456789abcdef"]), "manifest_invalid",
    )


def test_jira_scope_rejects_a_non_str_label_item():
    # Without the per-item str-type guard, the label regex would receive a
    # non-str value and raise TypeError instead of a clean manifest_invalid.
    assert_config_error(lambda: JiraScope(issues=(), search_labels=(1,)), "manifest_invalid")


def test_jira_scope_rejects_duplicate_and_unordered_labels():
    assert_config_error(
        lambda: JiraScope(issues=(), search_labels=("b", "a")), "manifest_invalid",
    )
    assert_config_error(
        lambda: JiraScope(issues=(), search_labels=("a", "a")), "manifest_invalid",
    )


def test_jira_scope_rejects_257_issues_by_count_not_by_leaking_a_json_error():
    # Distinct from the byte-size cap below: these issues are short, so only
    # MAX_SCOPED_ISSUES (the count check) can catch this, before the eager
    # canonical_json call that a ScopeManifest would make would otherwise
    # leak JSONPolicyError("json_array_too_long") instead of a RouteConfigError.
    issues = tuple(
        ScopedIssue(issue_id=str(1000 + i), issue_key=f"AA-{1000 + i}") for i in range(257)
    )
    assert_config_error(
        lambda: JiraScope(issues=issues, search_labels=()), "manifest_invalid",
    )


def test_jira_scope_rejects_257_search_labels_by_count_not_by_leaking_a_json_error():
    labels = tuple(f"l{i:03d}" for i in range(257))  # zero-padded: strictly ascending as text
    assert_config_error(
        lambda: JiraScope(issues=(), search_labels=labels), "manifest_invalid",
    )


def test_256_maximum_length_issues_fail_at_construction():
    project_key = "A" * 10
    issues = tuple(
        ScopedIssue(issue_id=str(10**17 + i), issue_key=f"{project_key}-{10**17 + i}")
        for i in range(256)
    )
    scope = JiraScope(issues=issues, search_labels=())
    assert_config_error(
        lambda: ScopeManifest(
            service="jira", run_id="run-1", attempt_id="attempt-1", rehearsal_id="rehearsal-1",
            revision="scope-r1", routes=("jira.issue.get",), policy_digest=POLICY_DIGEST,
            scope=scope,
        ),
        "manifest_too_large",
    )


# === parse_scope_manifest: canonical-only ====================================


def test_parse_scope_manifest_round_trips_the_golden_manifest():
    parsed = parse_scope_manifest(MANIFEST_CANONICAL_BYTES)
    assert parsed == golden_manifest()
    assert parsed.digest == SCOPE_DIGEST


def test_parse_scope_manifest_rejects_whitespace():
    mutated = MANIFEST_CANONICAL_BYTES.replace(b'"service":"jira"', b'"service": "jira"')
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_reordered_keys():
    # Move "service" to the front: still valid JSON, no longer canonical order.
    body_without_service = MANIFEST_CANONICAL_BYTES[1:-1].replace(b',"service":"jira"', b"")
    reordered = b'{"service":"jira",' + body_without_service + b"}"
    assert_config_error(lambda: parse_scope_manifest(reordered), "manifest_invalid")


def test_parse_scope_manifest_rejects_an_escaped_character():
    mutated = MANIFEST_CANONICAL_BYTES.replace(b'"attempt-1"', b'"attempt\\u002d1"')
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_extra_key():
    mutated = MANIFEST_CANONICAL_BYTES[:-1] + b',"extra":"x"}'
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_missing_key():
    mutated = MANIFEST_CANONICAL_BYTES.replace(
        b'"policy_digest":'
        b'"3013f6a10469469651028a5ea422849591fae5a8bb4a7e15b92e2b0caf99a156",',
        b"",
    )
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_non_ascii():
    mutated = MANIFEST_CANONICAL_BYTES.replace(b'"attempt-1"', '"attempt-1é"'.encode())
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_an_extra_key_inside_scope():
    # The nested "scope" object has its own exact key set, checked
    # independently of the top-level key set exercised above.
    mutated = MANIFEST_CANONICAL_BYTES.replace(
        b'"scope":{"issues":', b'"scope":{"extra":1,"issues":',
    )
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_an_extra_key_inside_an_issue_entry():
    mutated = MANIFEST_CANONICAL_BYTES.replace(
        b'{"id":"90101","key":"SYN-1"}', b'{"extra":"x","id":"90101","key":"SYN-1"}',
    )
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_rejects_issues_that_are_not_an_array():
    mutated = MANIFEST_CANONICAL_BYTES.replace(
        b'"issues":[{"id":"90101","key":"SYN-1"}]', b'"issues":{}',
    )
    assert_config_error(lambda: parse_scope_manifest(mutated), "manifest_invalid")


def test_parse_scope_manifest_size_and_type_checks():
    # The type check is distinct from the size check: a small non-bytes
    # argument is manifest_invalid, not a mislabeled manifest_too_large.
    assert_config_error(lambda: parse_scope_manifest(b"x" * 16_385), "manifest_too_large")
    assert_config_error(lambda: parse_scope_manifest("not bytes"), "manifest_invalid")
    assert_config_error(
        lambda: parse_scope_manifest(bytearray(MANIFEST_CANONICAL_BYTES)), "manifest_invalid",
    )
    assert_config_error(
        lambda: parse_scope_manifest(memoryview(MANIFEST_CANONICAL_BYTES)), "manifest_invalid",
    )
    assert_config_error(lambda: parse_scope_manifest(12345), "manifest_invalid")
    assert_config_error(lambda: parse_scope_manifest(None), "manifest_invalid")
    assert_config_error(lambda: parse_scope_manifest(b"not json"), "manifest_invalid")


# === require_manifest_binding ===============================================


def test_require_manifest_binding_accepts_the_golden_binding():
    manifest = golden_manifest()
    require_manifest_binding(
        manifest, service="jira", run_id="run-1", attempt_id="attempt-1",
        scope_digest=SCOPE_DIGEST,
    )


@pytest.mark.parametrize("field,value", [
    ("service", "confluence"),
    ("run_id", "run-2"),
    ("attempt_id", "attempt-2"),
    ("scope_digest", "f" * 64),
    ("scope_digest", "é" * 64),  # well-typed but non-hex/non-ASCII: still a closed denial
])
def test_require_manifest_binding_rejects_each_field_mismatch(field, value):
    manifest = golden_manifest()
    kwargs = {
        "service": "jira", "run_id": "run-1", "attempt_id": "attempt-1",
        "scope_digest": SCOPE_DIGEST,
    }
    kwargs[field] = value
    with pytest.raises(RouteConfigError) as caught:
        require_manifest_binding(manifest, **kwargs)
    assert caught.value.code == "manifest_binding_mismatch"


def test_require_manifest_binding_type_errors():
    manifest = golden_manifest()
    with pytest.raises(TypeError):
        require_manifest_binding(
            "not-a-manifest", service="jira", run_id="run-1", attempt_id="attempt-1",
            scope_digest=SCOPE_DIGEST,
        )
    with pytest.raises(TypeError):
        require_manifest_binding(
            manifest, service=1, run_id="run-1", attempt_id="attempt-1", scope_digest=SCOPE_DIGEST,
        )


@pytest.mark.parametrize("field", ["run_id", "attempt_id", "scope_digest"])
def test_require_manifest_binding_type_errors_for_each_str_keyword(field):
    # A wrongly-typed value must raise TypeError, the programming-error
    # contract, and never the closed RouteConfigError("manifest_binding_mismatch").
    manifest = golden_manifest()
    kwargs = {
        "service": "jira", "run_id": "run-1", "attempt_id": "attempt-1",
        "scope_digest": SCOPE_DIGEST,
    }
    kwargs[field] = 12345
    with pytest.raises(TypeError):
        require_manifest_binding(manifest, **kwargs)


# === route catalog ===========================================================


def test_route_catalog_has_25_entries():
    assert len(ROUTE_CATALOG) == 25


def test_route_catalog_ids_unique_and_match_grammar():
    import re
    pattern = re.compile(ROUTE_ID_PATTERN)
    for route_id in ROUTE_CATALOG:
        assert len(route_id) <= 64
        assert pattern.fullmatch(route_id)


def test_spec_and_local_route_ids():
    assert len(fr.SPEC_ROUTE_IDS) == 24
    assert fr.LOCAL_ROUTE_IDS == frozenset({"anthropic.messages"})
    assert fr.SPEC_ROUTE_IDS | fr.LOCAL_ROUTE_IDS == frozenset(ROUTE_CATALOG)
    assert fr.SPEC_ROUTE_IDS.isdisjoint(fr.LOCAL_ROUTE_IDS)


def test_optional_route_ids():
    assert fr.OPTIONAL_ROUTE_IDS == frozenset({"traces_search", "trace_get"})
    for route_id in fr.OPTIONAL_ROUTE_IDS:
        assert ROUTE_CATALOG[route_id].optional is True
    for route_id, status in ROUTE_CATALOG.items():
        if route_id not in fr.OPTIONAL_ROUTE_IDS:
            assert status.optional is False


def test_missing_inputs_nonempty_and_closed():
    for status in ROUTE_CATALOG.values():
        assert status.missing_inputs
        assert set(status.missing_inputs) <= MISSING_INPUT_CODES
        assert list(status.missing_inputs) == sorted(status.missing_inputs)
        assert len(set(status.missing_inputs)) == len(status.missing_inputs)


def test_partial_state_is_exactly_the_matchable_routes():
    partial = {rid for rid, status in ROUTE_CATALOG.items() if status.state == "partial"}
    assert partial == MATCHABLE_ROUTE_IDS
    assert all(status.state != "enabled" for status in ROUTE_CATALOG.values())
    assert all(status.state in {"partial", "unavailable"} for status in ROUTE_CATALOG.values())


# === readiness ===============================================================


def test_policy_readiness_facts_all_false():
    facts = policy_readiness_facts()
    assert set(facts) == set(SERVICE_PROFILES)
    assert all(value is False for value in facts.values())


def test_classify_readiness_of_policy_readiness_facts():
    readiness = classify_readiness(policy_readiness_facts())
    assert readiness.mandatory_ready is False
    assert set(readiness.unavailable_mandatory) == {"jira", "grafana", "kubernetes", "anthropic"}
    assert set(readiness.degraded_optional) == {"confluence"}


# === RoutePolicy API: parser_options / policy_digest =========================


def test_policy_digest_and_parser_options_per_service_with_jira_configured():
    policy = RoutePolicy(jira=golden_policy())
    for service in SERVICE_PROFILES:
        options = policy.parser_options(service)
        digest = policy.policy_digest(service)
        if service == "jira":
            assert digest == POLICY_DIGEST
            assert options == ParserOptions(frozenset({"fields"}), "application/json")
        else:
            assert digest is None
            assert options == ParserOptions(frozenset(), "application/json")


def test_policy_digest_and_parser_options_with_jira_none():
    policy = RoutePolicy()
    for service in SERVICE_PROFILES:
        assert policy.policy_digest(service) is None
        assert policy.parser_options(service) == ParserOptions(frozenset(), "application/json")


def test_check_service_rejects_unknown_and_non_str():
    policy = RoutePolicy()
    with pytest.raises(TypeError):
        policy.policy_digest(123)
    with pytest.raises(ValueError):
        policy.policy_digest("bogus-service")
    with pytest.raises(TypeError):
        policy.parser_options(None)
    with pytest.raises(ValueError):
        policy.parser_options("bogus-service")


def test_route_policy_constructor_type_error():
    with pytest.raises(TypeError):
        RoutePolicy(jira="not-a-policy")


# === happy paths and equivalences ============================================


def test_issue_get_selector_and_fields_equivalences_share_one_digest():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    csv = "issuetype,labels,project,status,summary"
    requests = [
        make_request(path="/rest/api/3/issue/90101"),
        make_request(path="/rest/api/3/issue/SYN-1"),
        make_request(path="/rest/api/3/issue/90101", query=(("fields", csv),)),
        make_request(path="/rest/api/3/issue/SYN-1", query=(("fields", csv),)),
    ]
    digests = {policy.route(request, manifest).request_digest for request in requests}
    assert digests == {ISSUE_GET_DIGEST}


def test_search_fields_reordering_gives_identical_digest():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    canonical_order = ("issuetype", "labels", "project", "status", "summary")
    reordered = ("summary", "status", "project", "labels", "issuetype")
    digests = set()
    for fields in (None, canonical_order, reordered):
        payload = {"jql": jql}
        if fields is not None:
            payload["fields"] = list(fields)
        request = make_request(
            method="POST", path="/rest/api/3/search/jql", body=canonical_json(payload),
        )
        digests.add(policy.route(request, manifest).request_digest)
    assert digests == {SEARCH_DIGEST_50}


def test_search_maxresults_omitted_equals_fifty():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    omitted = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": jql}),
    )
    explicit = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": jql, "maxResults": 50}),
    )
    assert policy.route(omitted, manifest).request_digest == SEARCH_DIGEST_50
    assert policy.route(explicit, manifest).request_digest == SEARCH_DIGEST_50


def test_search_body_whitespace_member_order_and_escapes_give_identical_digest():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    plain = canonical_json({"jql": jql, "maxResults": 50})
    jql_literal = json.dumps(jql)
    # Reordered members, extra whitespace: still decodes to the identical value.
    padded = ('{ "maxResults" : 50 ,\n  "jql" : ' + jql_literal + " }").encode("ascii")
    # The same "p" in "project", spelled as a \u escape: identical decoded string.
    escaped_literal = jql_literal.replace("project", "\\u0070roject", 1)
    escaped = ('{"jql":' + escaped_literal + ',"maxResults":50}').encode("ascii")
    digests = set()
    for body in (plain, padded, escaped):
        request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
        digests.add(policy.route(request, manifest).request_digest)
    assert digests == {SEARCH_DIGEST_50}


def test_issue_get_and_search_field_lists_are_not_swapped():
    # A policy with distinct field lists: catches any of the six call sites
    # in route()/check_response() reading the wrong one of the two lists.
    distinct_policy = golden_policy(
        issue_fields=("issuetype", "project", "summary"),
        search_fields=("issuetype", "labels", "project", "status"),
    )
    manifest = golden_manifest(policy_digest=distinct_policy.digest)
    policy = RoutePolicy(jira=distinct_policy)

    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    assert routed.upstream.target == (
        "/rest/api/3/issue/90101?fields=issuetype%2Cproject%2Csummary"
    )

    bad_query = make_request(
        path="/rest/api/3/issue/90101",
        query=(("fields", "issuetype,labels,project,status"),),
    )
    assert_denied(
        lambda: policy.route(bad_query, manifest),
        code="query_rejected", route_id="jira.issue.get",
    )

    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    search_request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": jql}),
    )
    routed_search = policy.route(search_request, manifest)
    body = json.loads(routed_search.upstream.body)
    assert sorted(body["fields"]) == ["issuetype", "labels", "project", "status"]

    swapped_fields_body = canonical_json(
        {"jql": jql, "fields": list(distinct_policy.issue_fields)},
    )
    swapped_request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=swapped_fields_body,
    )
    assert_denied(
        lambda: policy.route(swapped_request, manifest),
        code="body_rejected", route_id="jira.search",
    )

    issue_body_with_labels = canonical_json({
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["x"],
        },
    })
    verdict = policy.check_response(
        routed, ParsedResponse(status=200, body=issue_body_with_labels),
    )
    assert verdict.detail == "schema_invalid"

    valid_search_issue_fields = {
        "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
        "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
    }
    ok_search_body = canonical_json({
        "issues": [{"id": "90101", "key": "SYN-1", "fields": valid_search_issue_fields}],
    })
    ok_verdict_search = policy.check_response(
        routed_search, ParsedResponse(status=200, body=ok_search_body),
    )
    # Uses exactly search_fields, none of which issue_fields also has: a swap
    # to issue_fields here would reject "labels"/"status" as unconfigured.
    assert ok_verdict_search.detail == "ok"

    search_issue_with_summary = {
        "id": "90101", "key": "SYN-1",
        "fields": {**valid_search_issue_fields, "summary": "x"},
    }
    search_body = canonical_json({"issues": [search_issue_with_summary]})
    verdict_search = policy.check_response(
        routed_search, ParsedResponse(status=200, body=search_body),
    )
    assert verdict_search.detail == "schema_invalid"


# === digest sensitivity ======================================================


def test_digest_is_sensitive_to_issue_identity():
    policy = RoutePolicy(jira=golden_policy())
    other_scope = JiraScope(
        issues=(ScopedIssue(issue_id="90102", issue_key="SYN-2"),), search_labels=(),
    )
    other_manifest = golden_manifest(routes=("jira.issue.get",), scope=other_scope)
    routed = policy.route(make_request(path="/rest/api/3/issue/90102"), other_manifest)
    assert routed.request_digest != ISSUE_GET_DIGEST


def test_digest_is_sensitive_to_search_label():
    policy = RoutePolicy(jira=golden_policy())
    other_scope = JiraScope(issues=(), search_labels=("fp-fedcba9876543210",))
    other_manifest = golden_manifest(routes=("jira.search",), scope=other_scope)
    label = "fp-fedcba9876543210"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": jql}),
    )
    routed = policy.route(request, other_manifest)
    assert routed.request_digest not in (SEARCH_DIGEST_50, SEARCH_DIGEST_10)


def test_digest_is_sensitive_to_max_results():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": jql, "maxResults": 10}),
    )
    assert policy.route(request, manifest).request_digest == SEARCH_DIGEST_10


def test_digest_is_sensitive_to_a_policy_field():
    other_policy = RoutePolicy(jira=golden_policy(search_max_results=99))
    manifest = golden_manifest(policy_digest=golden_policy(search_max_results=99).digest)
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": jql}),
    )
    routed = other_policy.route(request, manifest)
    assert routed.request_digest not in (SEARCH_DIGEST_50, SEARCH_DIGEST_10)


def test_digest_is_sensitive_to_manifest_revision():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest(revision="scope-r2")
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    assert routed.request_digest != ISSUE_GET_DIGEST
    assert routed.scope_digest != SCOPE_DIGEST


# === rejection matrix =========================================================


def test_denied_for_non_jira_service_whatever_the_manifest():
    policy = RoutePolicy(jira=golden_policy())
    request = make_request(service="grafana", method="GET", path="/anything")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="service_unavailable", route_id="unmatched", service="grafana",
    )


def test_denied_when_jira_not_configured():
    policy = RoutePolicy()
    request = make_request(path="/rest/api/3/issue/90101")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="service_unavailable", route_id="unmatched",
    )


def test_denied_for_manifest_policy_digest_mismatch():
    policy = RoutePolicy(jira=golden_policy())
    manifest = golden_manifest(policy_digest="f" * 64)
    request = make_request(path="/anything", accept="application/json")
    assert_denied(
        lambda: policy.route(request, manifest), code="manifest_mismatch", route_id="unmatched",
    )


def test_denied_for_manifest_issue_key_not_prefixed_by_project_key():
    scope = JiraScope(issues=(ScopedIssue(issue_id="1", issue_key="ABC-1"),), search_labels=())
    manifest = golden_manifest(routes=("jira.issue.get",), scope=scope)
    request = make_request(path="/anything", accept="application/json")
    assert_denied(
        lambda: policy_with_golden().route(request, manifest),
        code="manifest_mismatch", route_id="unmatched",
    )


def test_denied_for_manifest_issue_key_sharing_project_key_as_a_prefix_only():
    # "SYNX-1" starts with "SYN" but not with the required "SYN-" separator:
    # a distinct project, not an ordinary member of the golden project.
    scope = JiraScope(issues=(ScopedIssue(issue_id="1", issue_key="SYNX-1"),), search_labels=())
    manifest = golden_manifest(routes=("jira.issue.get",), scope=scope)
    request = make_request(path="/anything", accept="application/json")
    assert_denied(
        lambda: policy_with_golden().route(request, manifest),
        code="manifest_mismatch", route_id="unmatched",
    )


def policy_with_golden() -> RoutePolicy:
    return RoutePolicy(jira=golden_policy())


def test_denied_for_bad_accept_header():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101", accept="text/plain")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="request_invalid", route_id="unmatched",
    )


def test_denied_for_route_unknown():
    policy = policy_with_golden()
    request = make_request(method="DELETE", path="/rest/api/3/issue/SYN-1")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="route_unknown", route_id="unmatched",
    )


def test_denied_for_empty_issue_selector_is_route_unknown_not_selector_invalid():
    # The empty-selector guard sits in the matcher itself: without it, a
    # trailing-slash path would match jira.issue.get with an empty selector
    # and fail downstream as selector_invalid (request_rejected) instead of
    # never matching at all (route_unknown, route_denied).
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="route_unknown", route_id="unmatched",
    )


def test_search_path_does_not_match_with_get_or_put():
    # The POST-only method check in the matcher: GET is covered by the
    # native-form matrix, but a non-GET/non-POST verb like PUT takes the
    # matcher's other branch entirely, so it needs its own case.
    policy = policy_with_golden()
    for method in ("GET", "PUT"):
        request = make_request(method=method, path="/rest/api/3/search/jql")
        assert_denied(
            lambda request=request: policy.route(request, golden_manifest()),
            code="route_unknown", route_id="unmatched",
        )


def test_denied_for_route_not_in_scope():
    policy = policy_with_golden()
    scope = JiraScope(issues=(), search_labels=("fp-0123456789abcdef",))
    manifest = golden_manifest(routes=("jira.search",), scope=scope)
    request = make_request(path="/rest/api/3/issue/90101")
    assert_denied(
        lambda: policy.route(request, manifest),
        code="route_not_in_scope", route_id="jira.issue.get",
    )


def test_denied_for_issue_get_nonempty_body():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101", body=b"{}")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="request_invalid", route_id="jira.issue.get",
    )


def test_denied_for_issue_get_bad_query():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101", query=(("fields", "issuetype"),))
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="query_rejected", route_id="jira.issue.get",
    )


def test_denied_for_issue_get_bad_selector():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101;")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="selector_invalid", route_id="jira.issue.get",
    )


def test_denied_for_issue_get_selector_out_of_scope():
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/99999")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="selector_out_of_scope", route_id="jira.issue.get",
    )


@pytest.mark.parametrize("selector", [
    "9010",     # a proper prefix of the registered id "90101"
    "901010",   # the registered id with an extra trailing digit
    "SYN-10",   # a numeric extension of the registered key "SYN-1"
])
def test_denied_for_issue_get_selector_that_is_a_prefix_or_superstring_of_scope(selector):
    # _lookup_issue must use exact equality: a selector that merely shares a
    # prefix or is an extension of a registered id/key must still be
    # out-of-scope, never resolved to the registered entry.
    policy = policy_with_golden()
    request = make_request(path=f"/rest/api/3/issue/{selector}")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="selector_out_of_scope", route_id="jira.issue.get",
    )


def test_denied_for_search_bad_query():
    policy = policy_with_golden()
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", query=(("expand", "x"),), body=b"{}",
    )
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="query_rejected", route_id="jira.search",
    )


_VALID_JQL = (
    'project = 90001 AND issuetype = 90002 AND labels = "fp-0123456789abcdef" '
    "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
)


@pytest.mark.parametrize("body", [
    b"not json",
    b"",
    b"[]",
    b'{"maxResults": 50}',
    b'{"jql": "x", "extra": 1}',
    b'{"jql": 1}',
])
def test_denied_for_search_body_shape_rejected(body):
    policy = policy_with_golden()
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="body_rejected", route_id="jira.search",
    )


def test_search_body_at_the_262144_byte_cap_is_accepted_one_byte_over_is_rejected():
    # Padding with JSON whitespace (accepted, and stripped by canonicalization
    # -- see the whitespace-equivalence test above) lets this hit the exact
    # byte boundary of MAX_REQUEST_JSON_BYTES without changing the decoded
    # value, isolating the cap itself from every other body-shape check.
    policy = policy_with_golden()
    manifest = golden_manifest()
    base = canonical_json({"jql": _VALID_JQL})
    assert base.endswith(b"}")
    pad_needed = MAX_REQUEST_JSON_BYTES - len(base)
    assert pad_needed > 0

    at_cap = base[:-1] + b" " * pad_needed + b"}"
    assert len(at_cap) == MAX_REQUEST_JSON_BYTES
    at_cap_request = make_request(method="POST", path="/rest/api/3/search/jql", body=at_cap)
    routed = policy.route(at_cap_request, manifest)
    assert routed.route_id == "jira.search"

    over_cap = base[:-1] + b" " * (pad_needed + 1) + b"}"
    assert len(over_cap) == MAX_REQUEST_JSON_BYTES + 1
    over_cap_request = make_request(method="POST", path="/rest/api/3/search/jql", body=over_cap)
    assert_denied(
        lambda: policy.route(over_cap_request, manifest),
        code="body_rejected", route_id="jira.search",
    )


@pytest.mark.parametrize("payload", [
    {"jql": _VALID_JQL, "maxResults": True},
    {"jql": _VALID_JQL, "maxResults": 0},
    {"jql": _VALID_JQL, "maxResults": 101},
    # Between the operator cap (50, golden policy) and the global ceiling
    # (100): must be denied by policy.search_max_results, not MAX_SEARCH_RESULTS.
    {"jql": _VALID_JQL, "maxResults": 51},
    {"jql": _VALID_JQL, "maxResults": 100},
    {"jql": _VALID_JQL, "fields": ["issuetype"]},
    {"jql": _VALID_JQL, "fields": None},  # present-but-null must deny, not act as absent
    {"jql": _VALID_JQL, "fields": [{}]},  # item wrong type (dict)
    {"jql": _VALID_JQL, "fields": [1]},  # item wrong type (int)
    {"jql": _VALID_JQL, "fields": [["issuetype"]]},  # item wrong type (list)
    # Duplicate name; the *set* equals policy.search_fields, but the list
    # is not unique, which the plan requires to be rejected on its own.
    {"jql": _VALID_JQL,
     "fields": ["issuetype", "issuetype", "labels", "project", "status", "summary"]},
])
def test_denied_for_search_body_value_rejected(payload):
    policy = policy_with_golden()
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json(payload),
    )
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="body_rejected", route_id="jira.search",
    )


def test_denied_for_search_selector_out_of_scope():
    policy = policy_with_golden()
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": "no template matches this"}),
    )
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="selector_out_of_scope", route_id="jira.search",
    )


def test_denied_for_search_selector_ambiguous():
    # Strictly ascending: 'a' (0x61) sorts before '{' (0x7b).
    templates = ('x "a" y "{label}"', 'x "{label}" y "z"')
    ambiguous_policy = RoutePolicy(jira=golden_policy(search_templates=templates))
    scope = JiraScope(issues=(), search_labels=("a", "z"))
    manifest = golden_manifest(
        routes=("jira.search",), scope=scope,
        policy_digest=golden_policy(search_templates=templates).digest,
    )
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": 'x "a" y "z"'}),
    )
    assert_denied(
        lambda: ambiguous_policy.route(request, manifest),
        code="selector_ambiguous", route_id="jira.search",
    )


def test_manifest_mismatch_takes_priority_over_a_bad_accept_header():
    # Two faults at once: proves the check order (manifest agreement before
    # accept), not just each check in isolation.
    policy = policy_with_golden()
    manifest = golden_manifest(policy_digest="f" * 64)
    request = make_request(path="/rest/api/3/issue/90101", accept="text/plain")
    assert_denied(
        lambda: policy.route(request, manifest),
        code="manifest_mismatch", route_id="unmatched",
    )


def test_bad_accept_header_takes_priority_over_route_matching():
    policy = policy_with_golden()
    request = make_request(method="DELETE", path="/rest/api/3/issue/SYN-1", accept="text/plain")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="request_invalid", route_id="unmatched",
    )


def test_search_template_matching_takes_priority_over_maxresults_validation():
    policy = policy_with_golden()
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": "no template matches this", "maxResults": 0}),
    )
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="selector_out_of_scope", route_id="jira.search",
    )


def test_denied_upstream_unbuildable_via_monkeypatched_helper(monkeypatch):
    policy = policy_with_golden()

    def _raiser(_value):
        raise RouteConfigError("digest_input_invalid")

    monkeypatch.setattr(fr, "encode_query_value", _raiser)
    request = make_request(path="/rest/api/3/issue/90101")
    assert_denied(
        lambda: policy.route(request, golden_manifest()),
        code="upstream_unbuildable", route_id="jira.issue.get",
    )


def test_denied_upstream_unbuildable_on_the_search_path(monkeypatch):
    # The search branch builds its body with canonical_json, not
    # encode_query_value; step 8 must convert a JSONPolicyError from either
    # helper, not just RouteConfigError.
    policy = policy_with_golden()
    manifest = golden_manifest()  # built before the monkeypatch below
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": _VALID_JQL}),
    )

    def _raiser(_value, **_kwargs):
        raise JSONPolicyError("json_type")

    monkeypatch.setattr(fr, "canonical_json", _raiser)
    assert_denied(
        lambda: policy.route(request, manifest),
        code="upstream_unbuildable", route_id="jira.search",
    )


def test_every_route_error_code_has_a_reason_and_matches_receipts():
    assert dict(ROUTE_ERROR_REASONS) == {
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
    }


# === programming errors (check 1) ============================================


def test_route_type_errors():
    policy = policy_with_golden()
    with pytest.raises(TypeError):
        policy.route("not-a-request", golden_manifest())
    with pytest.raises(TypeError):
        policy.route(make_request(path="/x"), "not-a-manifest")
    bad_query_request = dataclasses.replace(
        make_request(path="/x"), query=(("a", 1),),  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        policy.route(bad_query_request, golden_manifest())
    bad_accept_request = dataclasses.replace(
        make_request(path="/x"), accept=None,  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        policy.route(bad_accept_request, golden_manifest())
    # bytearray(b"") == b"" is True, so an exact-type check is load-bearing:
    # a lenient == check would let a wrongly-typed body silently route.
    bad_body_request = dataclasses.replace(
        make_request(path="/rest/api/3/issue/90101"), body=bytearray(),  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        policy.route(bad_body_request, golden_manifest())


@pytest.mark.parametrize("bad_query", [
    [("a", "b")],  # the query itself is a list, not a tuple
    (["a", "b"],),  # a pair that is a list, not a tuple
    (("a", "b", "c"),),  # a 3-element pair
    (("a",),),  # a 1-element pair
])
def test_route_rejects_malformed_query_shapes(bad_query):
    # ParsedRequest.query's own shape checks: tuple-of-tuples, each a
    # 2-element (str, str) pair. Distinct from test_route_type_errors above,
    # which only exercises a wrong *item* type inside an otherwise
    # well-shaped pair.
    policy = policy_with_golden()
    bad_query_request = dataclasses.replace(
        make_request(path="/x"), query=bad_query,  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        policy.route(bad_query_request, golden_manifest())


@pytest.mark.parametrize("field,value", [
    ("service", None),
    ("method", None),
    ("path", 123),
])
def test_route_rejects_each_malformed_scalar_field(field, value):
    policy = policy_with_golden()
    bad_request = dataclasses.replace(
        make_request(path="/rest/api/3/issue/90101"), **{field: value},  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        policy.route(bad_request, golden_manifest())


def test_route_unknown_service_value_error():
    policy = policy_with_golden()
    bad_service_request = ParsedRequest(
        service="not-a-service", method="GET", path="/x", query=(), accept="application/json",
        body=b"", sentinel="s" * 43,
    )
    with pytest.raises(ValueError):
        policy.route(bad_service_request, golden_manifest())


# === response details / check_response =======================================


def _routed_issue_get() -> tuple[RoutePolicy, RoutedRequest]:
    policy = policy_with_golden()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), golden_manifest())
    return policy, routed


def _routed_search() -> tuple[RoutePolicy, RoutedRequest]:
    policy = policy_with_golden()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    request = make_request(
        method="POST", path="/rest/api/3/search/jql", body=canonical_json({"jql": jql}),
    )
    routed = policy.route(request, golden_manifest())
    return policy, routed


def test_check_response_ok_issue_get():
    policy, routed = _routed_issue_get()
    body = canonical_json({
        "id": "90101", "key": "SYN-1",
        "fields": {"project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"}},
    })
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict == ResponseVerdict("jira.issue.get", "ok", "ok")


def test_check_response_ok_search():
    policy, routed = _routed_search()
    issue = {
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    body = canonical_json({"issues": [issue]})
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict == ResponseVerdict("jira.search", "ok", "ok")


def test_check_response_ok_issue_get_with_self_and_expand_present():
    policy, routed = _routed_issue_get()
    body = canonical_json({
        "expand": "renderedFields,names",
        "self": "https://example.atlassian.net/rest/api/3/issue/90101",
        "id": "90101", "key": "SYN-1",
        "fields": {"project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"}},
    })
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict == ResponseVerdict("jira.issue.get", "ok", "ok")


def test_check_response_ok_search_with_warnings_and_islast_present():
    policy, routed = _routed_search()
    issue = {
        "expand": "names",
        "self": "https://example.atlassian.net/rest/api/3/issue/90101",
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    body = canonical_json({
        "issues": [issue], "isLast": True, "nextPageToken": "tok", "warnings": ["w"],
    })
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict == ResponseVerdict("jira.search", "ok", "ok")


def test_check_response_routed_unknown_for_a_foreign_object():
    policy, routed = _routed_issue_get()
    forged = dataclasses.replace(routed)
    verdict = policy.check_response(forged, ParsedResponse(status=200, body=b'{"a":1}'))
    assert verdict.detail == "routed_unknown"
    assert verdict.receipt_reason == "response_policy_rejected"


@pytest.mark.parametrize("status,body", [
    (404, b'{"errorMessages":["not found"]}'),
    (500, b'{"errorMessages":["boom"]}'),
    (201, b'{"id":"90101"}'),
    (204, b""),
])
def test_check_response_status_not_allowed(status, body):
    policy, routed = _routed_issue_get()
    verdict = policy.check_response(routed, ParsedResponse(status=status, body=body))
    assert verdict.receipt_reason == "response_policy_rejected"
    assert verdict.detail == "status_not_allowed"


def test_check_response_response_invalid():
    policy, routed = _routed_issue_get()
    # 204 with a body is not a legal ParsedResponse per serialize_response.
    verdict = policy.check_response(routed, ParsedResponse(status=204, body=b"x"))
    assert verdict.detail == "response_invalid"


@pytest.mark.parametrize("body", [
    b"1e400",
    b'{"a":1,"a":2}',
    b"[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]",  # depth 18 (root=1) > 16
])
def test_check_response_json_invalid(body):
    policy, routed = _routed_issue_get()
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "json_invalid"


def test_check_response_issue_get_extra_top_level_key():
    policy, routed = _routed_issue_get()
    body = (
        b'{"avatarUrls":{},"id":"90101","key":"SYN-1","fields":'
        b'{"project":{"id":"90001","key":"SYN"},"issuetype":{"id":"90002"}}}'
    )
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "schema_invalid"


def test_check_response_issue_get_unconfigured_field():
    policy, routed = _routed_issue_get()
    body = (
        b'{"id":"90101","key":"SYN-1","fields":{"project":{"id":"90001","key":"SYN"},'
        b'"issuetype":{"id":"90002"},"description":"x"}}'
    )
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "schema_invalid"


_VALID_IDENTITY_FIELDS = b'"project":{"id":"90001","key":"SYN"},"issuetype":{"id":"90002"}'


@pytest.mark.parametrize("body", [
    b'{"key":"SYN-1","fields":{}}',  # missing id
    b'{"id":"90101","fields":{}}',  # missing key
    b'{"id":"90101","key":"SYN-1"}',  # missing fields
    b'{"id":"90101","key":"SYN-1","fields":{"project":"SYN","issuetype":{"id":"90002"}}}',
    b'{"id":"90101","key":"SYN-1","fields":{"project":{"id":"90001","key":"SYN"},'
    + b'"issuetype":"90002"}}',  # issuetype not a dict
    b'{"id":90101,"key":"SYN-1","fields":{' + _VALID_IDENTITY_FIELDS + b'}}',  # id not a str
    b'{"id":"90101","key":90101,"fields":{' + _VALID_IDENTITY_FIELDS + b'}}',  # key not a str
    b'{"id":"90101","key":"SYN-1","self":1,"fields":{'
    + _VALID_IDENTITY_FIELDS + b'}}',  # self not a str
    b'{"id":"90101","key":"SYN-1","expand":1,"fields":{'
    + _VALID_IDENTITY_FIELDS + b'}}',  # expand not a str
    b'{"id":"90101","key":"SYN-1","fields":"not-a-dict"}',  # fields not a dict
    b'[]',  # root not a dict at all (issue.get, not the search top level)
    b'"90101"',  # root a scalar string, not a dict
    b'1',  # root a scalar number, not a dict
])
def test_check_response_issue_get_shape_rejections(body):
    # Each of these guards, if ever dropped, either lets malformed data
    # through as "ok" or raises out of check_response instead of a verdict.
    policy, routed = _routed_issue_get()
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "schema_invalid"


def test_check_response_tolerates_a_json_decimal_field_value():
    policy, routed = _routed_issue_get()
    body = (
        b'{"id":"90101","key":"SYN-1","fields":{"project":{"id":"90001","key":"SYN"},'
        b'"issuetype":{"id":"90002"},"summary":1.5}}'
    )
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict == ResponseVerdict("jira.issue.get", "ok", "ok")


@pytest.mark.parametrize("mutation", ["id", "key", "project.id", "project.key", "issuetype.id"])
def test_check_response_issue_get_identity_mismatches(mutation):
    policy, routed = _routed_issue_get()
    document = {
        "id": "90101", "key": "SYN-1",
        "fields": {"project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"}},
    }
    if mutation == "id":
        document["id"] = "90199"
    elif mutation == "key":
        document["key"] = "SYN-9"
    elif mutation == "project.id":
        document["fields"]["project"]["id"] = "99999"
    elif mutation == "project.key":
        document["fields"]["project"]["key"] = "OPS"
    else:
        document["fields"]["issuetype"]["id"] = "99999"
    body = canonical_json(document)
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "scope_mismatch"


def test_check_response_search_missing_label():
    policy, routed = _routed_search()
    issue = {
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["some-other-label"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    body = canonical_json({"issues": [issue]})
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "scope_mismatch"


def test_check_response_search_closed_status_category():
    policy, routed = _routed_search()
    issue = {
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-done"}},
        },
    }
    body = canonical_json({"issues": [issue]})
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "scope_mismatch"


def test_check_response_search_count_exceeded():
    policy, routed = _routed_search()
    # selection.max_results defaults to policy.search_max_results (50).
    issue_template = {
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    issues = [
        {"id": str(90101 + i), "key": f"SYN-{1 + i}", **issue_template} for i in range(51)
    ]
    body = canonical_json({"issues": issues})
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "count_exceeded"


def test_check_response_search_count_exceeded_respects_requested_max_results():
    policy = policy_with_golden()
    label = "fp-0123456789abcdef"
    jql = (
        'project = 90001 AND issuetype = 90002 AND labels = "' + label + '" '
        "AND statusCategory != Done AND created >= -30m ORDER BY created ASC"
    )
    request = make_request(
        method="POST", path="/rest/api/3/search/jql",
        body=canonical_json({"jql": jql, "maxResults": 10}),
    )
    routed = policy.route(request, golden_manifest())
    issue_template = {
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }

    def issues(count: int) -> list:
        return [
            {"id": str(90101 + i), "key": f"SYN-{1 + i}", **issue_template} for i in range(count)
        ]

    ok_body = canonical_json({"issues": issues(10)})
    ok_verdict = policy.check_response(routed, ParsedResponse(status=200, body=ok_body))
    assert ok_verdict.detail == "ok"

    over_body = canonical_json({"issues": issues(11)})
    over_verdict = policy.check_response(routed, ParsedResponse(status=200, body=over_body))
    assert over_verdict.detail == "count_exceeded"


def test_check_response_search_duplicate_issue_ids():
    policy, routed = _routed_search()
    issue = {
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    body = canonical_json({"issues": [issue, issue]})
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "schema_invalid"


def test_check_response_search_islast_wrong_type():
    policy, routed = _routed_search()
    body = b'{"issues":[],"isLast":"true"}'
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "schema_invalid"


@pytest.mark.parametrize("body", [
    b'{}',  # issues missing
    b'{"issues":{}}',  # issues not a tuple (object)
    b'{"issues":5}',  # issues not a tuple (int)
    b'{"issues":""}',  # issues not a tuple (str)
    b'{"issues":null}',  # issues not a tuple (null)
    b'[]',  # root not a dict
])
def test_check_response_search_top_level_shape_rejections(body):
    policy, routed = _routed_search()
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == "schema_invalid"


@pytest.mark.parametrize("mutation,expected_detail", [
    ("project_mismatch", "scope_mismatch"),
    ("issuetype_mismatch", "scope_mismatch"),
    ("key_wrong_project", "schema_invalid"),
    ("key_extended_project", "schema_invalid"),
    ("key_non_numeric_suffix", "schema_invalid"),
    ("id_non_numeric", "schema_invalid"),
    ("labels_not_a_tuple", "schema_invalid"),
    ("status_category_missing", "schema_invalid"),
    ("status_not_a_dict", "schema_invalid"),
    ("fields_not_a_dict", "schema_invalid"),
    ("extra_unconfigured_field", "schema_invalid"),
    ("top_level_extra_key", "schema_invalid"),
    ("next_page_token_wrong_type", "schema_invalid"),
    ("warnings_wrong_type", "schema_invalid"),
    ("labels_item_not_str", "schema_invalid"),
])
def test_check_response_search_rejections(mutation, expected_detail):
    # The returned-scope backstop (spec L268-269): a template must never let
    # another project's/type's issues, or an out-of-schema page, through.
    policy, routed = _routed_search()
    issue = {
        "id": "90101", "key": "SYN-1",
        "fields": {
            "project": {"id": "90001", "key": "SYN"}, "issuetype": {"id": "90002"},
            "labels": ["fp-0123456789abcdef"], "status": {"statusCategory": {"key": "syn-new"}},
        },
    }
    document: dict = {"issues": [issue]}
    if mutation == "project_mismatch":
        issue["fields"]["project"] = {"id": "99999", "key": "OPS"}
    elif mutation == "issuetype_mismatch":
        issue["fields"]["issuetype"] = {"id": "99999"}
    elif mutation == "key_wrong_project":
        issue["key"] = "OPS-1"
    elif mutation == "key_extended_project":
        issue["key"] = "SYNX-1"
    elif mutation == "key_non_numeric_suffix":
        # Starts with the required "SYN-" prefix (unlike the two cases
        # above), but the suffix grammar itself -- _issue_key_matches's own
        # numeric check -- must still reject a non-numeric tail.
        issue["key"] = "SYN-1a"
    elif mutation == "id_non_numeric":
        issue["id"] = "abc"
    elif mutation == "labels_not_a_tuple":
        issue["fields"]["labels"] = "xfp-0123456789abcdefx"
    elif mutation == "status_category_missing":
        issue["fields"]["status"] = {}
    elif mutation == "status_not_a_dict":
        # _nested_str's own dict-type guard: "status" present but not itself
        # a dict, distinct from the "statusCategory" missing case above.
        issue["fields"]["status"] = "syn-new"
    elif mutation == "fields_not_a_dict":
        issue["fields"] = "not-a-dict"
    elif mutation == "extra_unconfigured_field":
        issue["fields"]["created"] = "2024-01-01"
    elif mutation == "top_level_extra_key":
        document["names"] = {}
    elif mutation == "next_page_token_wrong_type":
        document["nextPageToken"] = 1
    elif mutation == "labels_item_not_str":
        issue["fields"]["labels"] = ["fp-0123456789abcdef", 1]
    else:
        document["warnings"] = "x"
    body = canonical_json(document)
    verdict = policy.check_response(routed, ParsedResponse(status=200, body=body))
    assert verdict.detail == expected_detail


def test_check_response_type_errors():
    policy, routed = _routed_issue_get()
    with pytest.raises(TypeError):
        policy.check_response("not-a-routed-request", ParsedResponse(status=200, body=b"{}"))
    with pytest.raises(TypeError):
        policy.check_response(routed, "not-a-response")


# === encode_query_value and request_digest ===================================


def test_encode_query_value_known_pairs():
    assert encode_query_value("a,b") == "a%2Cb"
    assert encode_query_value("a b") == "a%20b"
    assert encode_query_value("a-._~Z9") == "a-._~Z9"


def test_encode_query_value_rejects_non_printable_ascii():
    with pytest.raises(RouteConfigError) as caught:
        encode_query_value("café")
    assert caught.value.code == "digest_input_invalid"


def test_encode_query_value_rejects_non_str_type():
    with pytest.raises(RouteConfigError) as caught:
        encode_query_value(123)  # type: ignore[arg-type]
    assert caught.value.code == "digest_input_invalid"


def test_request_digest_input_validation():
    upstream = UpstreamRequest("GET", "/rest/api/3/issue/1", "application/json", None, b"")
    with pytest.raises(RouteConfigError):
        request_digest(
            service="bogus", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )
    with pytest.raises(RouteConfigError):
        request_digest(
            service="jira", route_id="Not Valid", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )
    with pytest.raises(RouteConfigError):
        request_digest(
            service="jira", route_id="jira.issue.get", policy_digest="short",
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )
    with pytest.raises(RouteConfigError):
        request_digest(
            service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream="not-an-upstream",
        )


def test_request_digest_route_id_length_boundary_64_accepted_65_rejected():
    upstream = UpstreamRequest("GET", "/rest/api/3/issue/1", "application/json", None, b"")
    exactly_64 = "a" * 64
    assert len(exactly_64) == 64
    request_digest(
        service="jira", route_id=exactly_64, policy_digest=POLICY_DIGEST,
        scope_digest=SCOPE_DIGEST, upstream=upstream,
    )  # does not raise
    over_64 = "a" * 65
    with pytest.raises(RouteConfigError) as caught:
        request_digest(
            service="jira", route_id=over_64, policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )
    assert caught.value.code == "digest_input_invalid"


def test_request_digest_get_with_body_rejected():
    upstream = UpstreamRequest("GET", "/x", "application/json", "application/json", b"{}")
    with pytest.raises(RouteConfigError):
        request_digest(
            service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )


class _StrSubtype(str):
    pass


@pytest.mark.parametrize("upstream", [
    UpstreamRequest(_StrSubtype("GET"), "/rest/api/3/issue/1", "application/json", None, b""),
    UpstreamRequest("DELETE", "/rest/api/3/issue/1", "application/json", None, b""),
    UpstreamRequest("GET", "rest/x", "application/json", None, b""),
    UpstreamRequest("GET", "/a b", "application/json", None, b""),
    UpstreamRequest("GET", "/a#b", "application/json", None, b""),
    UpstreamRequest("GET", "/" + "a" * 2_048, "application/json", None, b""),
    UpstreamRequest("GET", "/x", "application/jsoné", None, b""),
    UpstreamRequest("GET", "/x", "application/json" + "x" * 300, None, b""),
    UpstreamRequest("POST", "/x", "application/json", "application/json\x00", b"{}"),
    UpstreamRequest("POST", "/x", "application/json", None, b"{}"),
    UpstreamRequest("POST", "/x", "application/json", "application/json", b""),
    UpstreamRequest(
        "POST", "/x", "application/json", "application/json", b"a" * (MAX_REQUEST_JSON_BYTES + 1),
    ),
])
def test_request_digest_rejects_each_malformed_upstream_field(upstream):
    with pytest.raises(RouteConfigError) as caught:
        request_digest(
            service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )
    assert caught.value.code == "digest_input_invalid"


def test_request_digest_rejects_an_unhashable_method():
    upstream = dataclasses.replace(
        UpstreamRequest("GET", "/x", "application/json", None, b""),
        method=["GET"],  # type: ignore[arg-type]
    )
    with pytest.raises(RouteConfigError) as caught:
        request_digest(
            service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=upstream,
        )
    assert caught.value.code == "digest_input_invalid"


def test_request_digest_rejects_an_uppercase_scope_digest():
    upstream = UpstreamRequest("GET", "/rest/api/3/issue/1", "application/json", None, b"")
    with pytest.raises(RouteConfigError) as caught:
        request_digest(
            service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest="F" * 64, upstream=upstream,
        )
    assert caught.value.code == "digest_input_invalid"


def test_denied_request_digest_input_validation():
    with pytest.raises(RouteConfigError):
        denied_request_digest("bogus", "unmatched")
    with pytest.raises(RouteConfigError):
        denied_request_digest("jira", "not-a-route")
    with pytest.raises(RouteConfigError):
        denied_request_digest("confluence", "jira.issue.get")


# === result types =============================================================


def test_upstream_request_repr_excludes_target_and_body():
    upstream = UpstreamRequest(
        "GET", "/rest/api/3/issue/90101?fields=x", "application/json", None, b"secret-body",
    )
    text = repr(upstream)
    assert "/rest/api/3/issue/90101" not in text
    assert "secret-body" not in text


def test_routed_request_repr_excludes_upstream_and_selection():
    policy = policy_with_golden()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), golden_manifest())
    text = repr(routed)
    assert "UpstreamRequest" not in text
    assert "RouteSelection" not in text
    assert "90101?fields" not in text


def test_result_types_are_frozen():
    upstream = UpstreamRequest("GET", "/x", "application/json", None, b"")
    with pytest.raises(dataclasses.FrozenInstanceError):
        upstream.method = "POST"  # type: ignore[misc]
    selection = RouteSelection(None, None, None, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        selection.issue_id = "x"  # type: ignore[misc]
    verdict = ResponseVerdict("jira.issue.get", "ok", "ok")
    with pytest.raises(dataclasses.FrozenInstanceError):
        verdict.detail = "x"  # type: ignore[misc]
    status = ROUTE_CATALOG["jira.search"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        status.state = "enabled"  # type: ignore[misc]
    policy = golden_policy()
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.revision = "x"  # type: ignore[misc]
    manifest = golden_manifest()
    with pytest.raises(dataclasses.FrozenInstanceError):
        manifest.revision = "x"  # type: ignore[misc]


def test_routed_request_uses_identity_equality():
    policy = policy_with_golden()
    manifest = golden_manifest()
    routed = policy.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    same_reference = routed
    copy = dataclasses.replace(routed)
    assert routed != copy
    assert routed == same_reference
    assert routed is same_reference


def test_routed_request_weakset_is_lock_guarded_and_per_instance():
    policy_a = policy_with_golden()
    policy_b = policy_with_golden()
    manifest = golden_manifest()
    routed = policy_a.route(make_request(path="/rest/api/3/issue/90101"), manifest)
    assert routed in policy_a._issued
    assert routed not in policy_b._issued
