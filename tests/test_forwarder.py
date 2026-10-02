"""The Forwarder holds the Jira credential; a Run only ever holds a sentinel."""

import gzip
import http.client
import json
import logging
import socket
import sys
import threading
import zlib
from email.message import Message
from urllib.parse import urlsplit

import pytest

from grafana_jsm_sandbox.forwarder import (
    CREATE_INCOMPLETE,
    CREATE_REFUSAL,
    DIAGNOSES,
    GROUP_LABEL_PREFIX,
    IP_ALLOWLIST_DIAGNOSIS,
    SESSION_LABEL_PREFIX,
    UNSEARCHED_403_DIAGNOSIS,
    Forwarder,
    IncompleteJiraCredential,
    JiraCredential,
    diagnose,
)
from tests.conftest import REAL_EMAIL, REAL_TOKEN, Response, basic_auth_header, http_request

SENTINEL = "sentinel-for-this-run"


def jira_request(forwarder, path="/rest/api/3/search", sentinel=SENTINEL, **kwargs):
    """One request as jira-as makes it: basic auth whose password is the sentinel."""
    auth = None if sentinel is None else (REAL_EMAIL, sentinel)
    return http_request(forwarder.url + path, basic_auth=auth, **kwargs)


def raw_request(forwarder, target, method="GET", sentinel=SENTINEL, body=None) -> Response:
    """One request down a bare connection, which follows no redirect and rewrites no target."""
    site = urlsplit(forwarder.url)
    connection = http.client.HTTPConnection(site.hostname, site.port, timeout=5)
    headers = {} if sentinel is None else {"Authorization": basic_auth_header(REAL_EMAIL, sentinel)}
    try:
        connection.request(method, target, body=body, headers=headers)
        answer = connection.getresponse()
        return Response(answer.status, answer.read(), dict(answer.getheaders()))
    finally:
        connection.close()


def test_request_with_the_active_sentinel_reaches_upstream_with_the_real_credential(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder)

    assert response.status == 200
    assert len(upstream.received) == 1
    forwarded = upstream.received[0]
    assert forwarded.basic_auth == (REAL_EMAIL, REAL_TOKEN)
    assert SENTINEL not in forwarded.headers.get("Authorization", "")
    assert forwarded.path == "/rest/api/3/search"


def test_request_without_the_active_sentinel_is_refused_and_never_reaches_upstream(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder, sentinel="a-guess")

    assert response.status == 401
    assert upstream.received == []


def test_request_with_no_credential_at_all_is_refused_and_never_reaches_upstream(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder, sentinel=None)

    assert response.status == 401
    assert upstream.received == []


def test_sentinel_of_a_finished_run_is_refused_once_it_is_cleared(forwarder, upstream):
    forwarder.set_sentinel(SENTINEL)
    assert jira_request(forwarder).status == 200

    forwarder.clear_sentinel()

    assert jira_request(forwarder).status == 401
    assert len(upstream.received) == 1


def test_sentinel_of_a_previous_run_is_refused_once_the_next_run_replaces_it(forwarder, upstream):
    forwarder.set_sentinel("sentinel-of-the-previous-run")
    forwarder.set_sentinel(SENTINEL)

    assert jira_request(forwarder, sentinel="sentinel-of-the-previous-run").status == 401
    assert jira_request(forwarder).status == 200
    assert len(upstream.received) == 1


def test_no_request_is_forwarded_before_any_run_has_registered_a_sentinel(forwarder, upstream):
    assert jira_request(forwarder).status == 401
    assert upstream.received == []


@pytest.mark.parametrize(
    "method,body",
    [
        pytest.param("GET", None, id="get"),
        pytest.param("POST", b'{"fields": {"summary": "rolldice is silent"}}', id="post-json"),
        pytest.param("PUT", b'{"transition": {"id": "31"}}', id="put-json"),
    ],
)
def test_method_path_and_body_reach_upstream_unchanged(forwarder, upstream, method, body):
    forwarder.set_sentinel(SENTINEL)

    jira_request(
        forwarder,
        path="/rest/api/3/issue/OPS-12?expand=transitions",
        method=method,
        data=body,
        content_type="application/json" if body else None,
    )

    forwarded = upstream.received[0]
    assert forwarded.method == method
    assert forwarded.path == "/rest/api/3/issue/OPS-12?expand=transitions"
    assert forwarded.body == (body or b"")
    if body:
        assert forwarded.headers["Content-Type"] == "application/json"


def test_upstream_status_headers_and_body_pass_back_unchanged(forwarder, upstream):
    upstream.status = 201
    upstream.body = b'{"key": "OPS-12"}'
    upstream.headers = {"Content-Type": "application/json", "X-AREQUESTID": "abc123"}
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder, method="POST", data=b"{}", content_type="application/json")

    assert response.status == 201
    assert response.body == b'{"key": "OPS-12"}'
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["X-AREQUESTID"] == "abc123"


def test_an_upstream_error_passes_back_rather_than_becoming_a_forwarder_error(forwarder, upstream):
    upstream.status = 404
    upstream.body = b'{"errorMessages": ["Issue does not exist"]}'
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder, path="/rest/api/3/issue/OPS-999")

    assert response.status == 404
    assert response.body == b'{"errorMessages": ["Issue does not exist"]}'


def test_no_log_line_carries_the_real_token_the_sentinel_or_an_authorization_header(
    forwarder, upstream, caplog
):
    caplog.set_level(logging.DEBUG)
    forwarder.set_sentinel(SENTINEL)

    jira_request(forwarder, method="POST", data=b"{}", content_type="application/json")
    jira_request(forwarder, path="/rest/api/3/myself", sentinel="a-guess")

    assert "/rest/api/3/search" in caplog.text, "the Forwarder logged nothing to inspect"
    assert "/rest/api/3/myself" in caplog.text, "a refusal must be visible in the log"
    assert REAL_TOKEN not in caplog.text
    assert SENTINEL not in caplog.text
    assert "authorization" not in caplog.text.lower()


COMPLETE_ENVIRONMENT = {
    "JIRA_SITE_URL": "https://example.atlassian.net",
    "JIRA_EMAIL": REAL_EMAIL,
    "JIRA_API_TOKEN": REAL_TOKEN,
}


def test_credential_is_read_from_the_environment_of_the_owning_process():
    credential = JiraCredential.from_environment(COMPLETE_ENVIRONMENT)

    assert credential.site_url == "https://example.atlassian.net"
    assert credential.email == REAL_EMAIL
    assert credential.api_token == REAL_TOKEN


@pytest.mark.parametrize(
    "missing",
    [
        pytest.param(["JIRA_SITE_URL"], id="no-site-url"),
        pytest.param(["JIRA_EMAIL"], id="no-email"),
        pytest.param(["JIRA_API_TOKEN"], id="no-token"),
        pytest.param(["JIRA_EMAIL", "JIRA_API_TOKEN"], id="no-email-and-no-token"),
    ],
)
def test_startup_fails_with_a_message_naming_every_missing_variable(missing):
    environment = {
        name: value for name, value in COMPLETE_ENVIRONMENT.items() if name not in missing
    }

    with pytest.raises(IncompleteJiraCredential) as failure:
        JiraCredential.from_environment(environment)

    for name in missing:
        assert name in str(failure.value)
    for name in set(COMPLETE_ENVIRONMENT) - set(missing):
        assert name not in str(failure.value)


def test_an_empty_variable_counts_as_missing():
    with pytest.raises(IncompleteJiraCredential) as failure:
        JiraCredential.from_environment({**COMPLETE_ENVIRONMENT, "JIRA_API_TOKEN": ""})

    assert "JIRA_API_TOKEN" in str(failure.value)


def test_a_site_url_that_is_not_an_http_url_fails_at_startup():
    with pytest.raises(IncompleteJiraCredential) as failure:
        JiraCredential.from_environment(
            {**COMPLETE_ENVIRONMENT, "JIRA_SITE_URL": "example.atlassian.net"}
        )

    assert "JIRA_SITE_URL" in str(failure.value)


def test_forwarder_will_not_bind_anything_but_loopback():
    credential = JiraCredential.from_environment(COMPLETE_ENVIRONMENT)

    with pytest.raises(ValueError, match="loopback"):
        Forwarder(credential, host="0.0.0.0")


def test_forwarder_listens_on_loopback(forwarder):
    assert forwarder.url.startswith("http://127.0.0.1:")


def test_the_upstream_host_comes_from_configuration_and_never_from_the_request(forwarder, upstream):
    """A proxy-style absolute request target must not choose the Forwarder's upstream."""
    forwarder.set_sentinel(SENTINEL)

    response = raw_request(forwarder, "http://not-the-configured-site.invalid/rest/api/3/myself")

    assert response.status == 200
    assert upstream.received[0].path == "/rest/api/3/myself"


def test_a_redirect_is_handed_back_rather_than_followed_with_the_real_credential(
    forwarder, upstream
):
    upstream.status = 302
    upstream.body = b""
    upstream.headers = {"Location": "https://not-the-configured-site.invalid/"}
    forwarder.set_sentinel(SENTINEL)

    response = raw_request(forwarder, "/rest/api/3/search")

    assert response.status == 302
    assert response.headers["Location"] == "https://not-the-configured-site.invalid/"
    assert len(upstream.received) == 1


def test_an_unreachable_upstream_becomes_a_gateway_error_rather_than_a_dropped_connection():
    """A Run must get a status it can report, not a connection that closes on it."""
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        nothing_is_listening = f"http://127.0.0.1:{taken.getsockname()[1]}"

    forwarder = Forwarder(
        JiraCredential(site_url=nothing_is_listening, email=REAL_EMAIL, api_token=REAL_TOKEN)
    )
    forwarder.set_sentinel(SENTINEL)
    forwarder.start()
    try:
        response = jira_request(forwarder)
    finally:
        forwarder.stop()

    assert response.status == 502


def test_localhost_is_a_loopback_host_the_forwarder_will_bind(upstream):
    forwarder = Forwarder(
        JiraCredential(site_url=upstream.url, email=REAL_EMAIL, api_token=REAL_TOKEN),
        host="localhost",
    )

    assert forwarder.url.startswith("http://localhost:")
    forwarder.stop()


@pytest.mark.parametrize(
    "presented",
    [
        pytest.param("sentinel-with-an-accent-é", id="non-ascii"),
        pytest.param("", id="empty-password"),
        pytest.param("a password with spaces in it", id="password-with-spaces"),
    ],
)
def test_a_password_that_is_not_a_sentinel_at_all_is_refused(forwarder, upstream, presented):
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder, sentinel=presented)

    assert response.status == 401
    assert upstream.received == []


def test_an_authorization_header_that_is_not_basic_auth_is_refused(forwarder, upstream):
    forwarder.set_sentinel(SENTINEL)

    response = http_request(
        forwarder.url + "/rest/api/3/myself",
        headers={"Authorization": f"Bearer {SENTINEL}"},
    )

    assert response.status == 401
    assert upstream.received == []


# --- Upstream errors say what they most likely mean (step 05 of demo-onboarding) ---

IP_REFUSAL = b'{"message": "The IP address has been rejected by the site\'s IP allowlist"}'
"""What an Atlassian site's IP-allowlist 403 says, per the audit. It is only searched, never
logged."""


def forwarded(caplog) -> logging.LogRecord:
    [record] = [r for r in caplog.records if r.getMessage().startswith("forwarded ")]
    return record


@pytest.mark.parametrize(
    ("status", "body", "diagnosis"),
    [
        pytest.param(401, b"", DIAGNOSES[401], id="401-credential-refused"),
        pytest.param(403, IP_REFUSAL, IP_ALLOWLIST_DIAGNOSIS, id="403-ip-allowlist"),
        pytest.param(403, b'{"errorMessages": ["no"]}', DIAGNOSES[403], id="403-permission"),
        pytest.param(404, b'{"errorMessages": ["gone"]}', DIAGNOSES[404], id="404-not-found"),
    ],
)
def test_a_known_upstream_refusal_is_a_warning_that_says_what_it_likely_means(
    forwarder, upstream, caplog, status, body, diagnosis
):
    caplog.set_level(logging.INFO)
    upstream.status, upstream.body = status, body
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(forwarder, path="/rest/api/3/myself")

    assert response.status == status
    record = forwarded(caplog)
    assert record.levelno == logging.WARNING
    assert record.getMessage() == (
        f"forwarded GET /rest/api/3/myself, upstream said {status}: {diagnosis}"
    )


def test_another_upstream_error_is_a_warning_without_a_diagnosis(forwarder, upstream, caplog):
    caplog.set_level(logging.INFO)
    upstream.status, upstream.body = 500, b"oops"
    forwarder.set_sentinel(SENTINEL)

    jira_request(forwarder)

    record = forwarded(caplog)
    assert record.levelno == logging.WARNING
    assert record.getMessage() == "forwarded GET /rest/api/3/search, upstream said 500"


def test_a_success_stays_an_info_line(forwarder, upstream, caplog):
    caplog.set_level(logging.INFO)
    forwarder.set_sentinel(SENTINEL)

    jira_request(forwarder)

    record = forwarded(caplog)
    assert record.levelno == logging.INFO
    assert record.getMessage() == "forwarded GET /rest/api/3/search, upstream said 200"


def test_an_upstream_error_body_is_searched_and_never_logged(forwarder, upstream, caplog):
    caplog.set_level(logging.DEBUG)
    upstream.status, upstream.body = 403, IP_REFUSAL
    forwarder.set_sentinel(SENTINEL)

    jira_request(forwarder)

    assert IP_ALLOWLIST_DIAGNOSIS in caplog.text
    assert "has been rejected by the site" not in caplog.text
    assert "authorization" not in caplog.text.lower()


def test_an_identity_encoded_403_is_searched_as_it_is():
    assert diagnose(403, {"content-encoding": "identity"}, IP_REFUSAL) == IP_ALLOWLIST_DIAGNOSIS


def raw_deflate(body: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(body) + compressor.flush()


@pytest.mark.parametrize(
    ("coding", "compress"),
    [
        pytest.param("gzip", gzip.compress, id="gzip"),
        pytest.param("x-gzip", gzip.compress, id="x-gzip"),
        pytest.param("deflate", zlib.compress, id="deflate-zlib-wrapped"),
        pytest.param("deflate", raw_deflate, id="deflate-raw"),
    ],
)
def test_a_compressed_ip_refusal_is_still_recognised(coding, compress):
    """jira-as's HTTP client asks for gzip and deflate, and the Forwarder passes that upstream,
    so the IP-allowlist refusal a newcomer meets most may well arrive compressed."""
    assert diagnose(403, {"Content-Encoding": coding}, compress(IP_REFUSAL)) == (
        IP_ALLOWLIST_DIAGNOSIS
    )
    assert diagnose(403, {"Content-Encoding": coding}, compress(b'{"no": 1}')) == DIAGNOSES[403]


def test_a_large_compressed_body_is_only_inflated_as_far_as_is_searched():
    bomb = gzip.compress(b"x" * 5_000_000)

    assert diagnose(403, {"Content-Encoding": "gzip"}, bomb) == DIAGNOSES[403]


@pytest.mark.parametrize(
    ("coding", "body"),
    [
        pytest.param("br", b"\x1b\x03\x00", id="an-unknown-coding"),
        pytest.param("gzip", b"not gzip at all", id="a-body-that-does-not-inflate"),
    ],
)
def test_a_403_that_cannot_be_searched_names_both_likely_causes(coding, body):
    assert diagnose(403, {"Content-Encoding": coding}, body) == UNSEARCHED_403_DIAGNOSIS


def test_an_ip_refusal_over_several_lines_of_html_is_still_recognised():
    body = b"<html><body>\n<h1>Forbidden</h1>\n<p>Your IP address\nhas been rejected.</p>"

    assert diagnose(403, {}, body) == IP_ALLOWLIST_DIAGNOSIS


def test_a_status_with_no_diagnosis_has_none():
    assert diagnose(400, {}, b"bad request") is None


# --- One create attempt per Run ---


def incident_body(**fields) -> bytes:
    """A create body as the Skill's `incident-payload` has jira-as send it: the Incident's
    Description as an ADF bullet list, and its group, session and Fingerprint labels. Keyword
    arguments replace a field; a value of None leaves it out."""
    body = {
        "project": {"key": "DEMO"},
        "issuetype": {"name": "Incident"},
        "summary": "checkout-outage: 2 alerts firing",
        "description": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "Partial Report: 2 alerts firing."}],
                },
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": "HighLatency on web-1"}],
                                }
                            ],
                        }
                    ],
                },
            ],
        },
        "labels": ["grp-checkout-outage", "ses-demo", "fp-0a1b2c"],
    }
    body.update(fields)
    return json.dumps({"fields": {k: v for k, v in body.items() if v is not None}}).encode()


ISSUE_BODY = incident_body()

CREATE_PATHS = [
    pytest.param("/rest/api/3/issue", id="issue-v3"),
    pytest.param("/rest/api/2/issue", id="issue-v2"),
    pytest.param("/rest/api/latest/issue", id="issue-latest"),
    pytest.param("/rest/api/3/issue/bulk", id="bulk-v3"),
    pytest.param("/rest/api/2/issue/bulk", id="bulk-v2"),
    pytest.param("/rest/servicedeskapi/request", id="service-management-request"),
]
"""Every path a POST can create an issue at: the two API versions and `latest`, their bulk
forms, and the Service Management request. jira-as 2.0.0 reaches the issue paths through
`issue create`, the epic, subtask and clone commands and `api call createIssue` or
`createIssues`, and the request path through `jsm request create` or `api call
createCustomerRequest`."""

VARIANTS_OF_THE_ISSUE_PATH = [
    pytest.param("/rest/api/3/issue/", id="trailing-slash"),
    pytest.param("/rest/api/3/issue?updateHistory=true", id="query-string"),
    pytest.param("/rest/api/3/issue/?updateHistory=true", id="trailing-slash-and-query"),
    pytest.param("/rest/api/3//issue", id="doubled-slash"),
    pytest.param("/rest/api/3/./issue", id="dot-segment"),
    pytest.param("/rest/api/3/issuetype/../issue", id="parent-segment"),
    pytest.param("/rest/API/3/Issue", id="upper-case"),
    pytest.param("/rest/api/3/%69ssue", id="percent-encoded"),
    pytest.param("/rest/api/3/issue;jsessionid=1", id="path-parameter"),
]
"""Spellings of the same create that a server may well read as the one it is: refusing them
is the safe reading, since the Forwarder cannot know how Atlassian's edge treats each."""


def create_request(forwarder, path="/rest/api/3/issue", sentinel=SENTINEL):
    """One create as jira-as sends it: a POST with a JSON body."""
    return jira_request(
        forwarder,
        path=path,
        method="POST",
        data=ISSUE_BODY,
        content_type="application/json",
        sentinel=sentinel,
    )


def refusal_message(response) -> str:
    """The one message of a Jira-shaped error body, which is what jira-as prints."""
    answer = json.loads(response.body)
    assert answer["errors"] == {}
    [message] = answer["errorMessages"]
    return message


def test_the_first_create_is_forwarded_and_the_second_is_refused_without_reaching_upstream(
    forwarder, upstream
):
    upstream.status = 201
    upstream.body = b'{"key": "OPS-12"}'
    forwarder.set_sentinel(SENTINEL)

    first = create_request(forwarder)
    second = create_request(forwarder)

    assert (first.status, first.body) == (201, b'{"key": "OPS-12"}')
    assert second.status == 409
    assert second.headers["Content-Type"] == "application/json"
    assert CREATE_REFUSAL in refusal_message(second)
    assert len(upstream.received) == 1
    assert upstream.received[0].body == ISSUE_BODY


@pytest.mark.parametrize("path", CREATE_PATHS)
def test_every_create_path_is_forwarded_once_and_then_refused(forwarder, upstream, path):
    forwarder.set_sentinel(SENTINEL)

    assert create_request(forwarder, path).status == 200
    assert create_request(forwarder, path).status == 409

    assert [request.path for request in upstream.received] == [path]


@pytest.mark.parametrize("second", CREATE_PATHS[1:])
def test_a_create_on_one_path_spends_the_attempt_for_every_other_create_path(
    forwarder, upstream, second
):
    forwarder.set_sentinel(SENTINEL)

    assert create_request(forwarder, "/rest/api/3/issue").status == 200
    assert create_request(forwarder, second).status == 409

    assert len(upstream.received) == 1


@pytest.mark.parametrize("variant", VARIANTS_OF_THE_ISSUE_PATH)
def test_another_spelling_of_the_create_path_is_still_a_create(forwarder, upstream, variant):
    forwarder.set_sentinel(SENTINEL)

    assert create_request(forwarder).status == 200
    assert create_request(forwarder, variant).status == 409

    assert len(upstream.received) == 1


def test_a_create_sent_as_a_proxy_style_absolute_request_target_is_still_a_create(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)

    assert raw_request(forwarder, "/rest/api/3/issue", method="POST", body=ISSUE_BODY).status == 200
    refused = raw_request(
        forwarder,
        "http://not-the-configured-site.invalid/rest/api/3/issue",
        method="POST",
        body=ISSUE_BODY,
    )

    assert refused.status == 409
    assert len(upstream.received) == 1


@pytest.mark.parametrize("status", [201, 400, 403, 404, 429, 500, 502])
def test_the_first_create_is_the_attempt_whatever_upstream_answers(forwarder, upstream, status):
    upstream.status, upstream.body = status, b'{"errorMessages": ["no"], "errors": {}}'
    forwarder.set_sentinel(SENTINEL)

    first = create_request(forwarder)
    upstream.status = 201
    second = create_request(forwarder)

    assert first.status == status
    assert second.status == 409
    assert len(upstream.received) == 1


def test_a_create_that_could_not_reach_upstream_is_still_the_attempt():
    """The site may have made the Incident before the connection failed, so a retry is not safe."""
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        nothing_is_listening = f"http://127.0.0.1:{taken.getsockname()[1]}"
    forwarder = Forwarder(
        JiraCredential(site_url=nothing_is_listening, email=REAL_EMAIL, api_token=REAL_TOKEN)
    )
    forwarder.set_sentinel(SENTINEL)
    forwarder.start()
    try:
        first = create_request(forwarder)
        second = create_request(forwarder)
    finally:
        forwarder.stop()

    assert first.status == 502
    assert second.status == 409


def test_the_refusal_is_plain_text_a_jira_client_can_print_and_never_a_forwarder_error(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)
    create_request(forwarder)

    message = refusal_message(create_request(forwarder))

    assert "do not retry" in message.lower()
    assert len(message) < 150, "jira-as prefixes it, and the log shows a line only so wide"
    assert REAL_TOKEN not in message
    assert SENTINEL not in message


@pytest.mark.parametrize(
    ("method", "path"),
    [
        pytest.param("POST", "/rest/api/3/issue/OPS-12/comment", id="comment"),
        pytest.param("POST", "/rest/api/3/issue/OPS-12/transitions", id="transition"),
        pytest.param("POST", "/rest/api/3/issueLink", id="link"),
        pytest.param("POST", "/rest/api/3/search/jql", id="search"),
        pytest.param("POST", "/rest/api/3/issue/bulkfetch", id="bulk-fetch"),
        pytest.param("POST", "/rest/api/3/issue/OPS-12/notify", id="notify"),
        pytest.param("POST", "/rest/api/3/issuetype", id="issue-type"),
        pytest.param("POST", "/rest/servicedeskapi/request/OPS-12/comment", id="request-comment"),
        pytest.param("POST", "/rest/servicedeskapi/request/OPS-12/transition", id="request-move"),
        pytest.param("POST", "/rest/servicedeskapi/request/validate", id="request-validate"),
        pytest.param("GET", "/rest/servicedeskapi/request", id="list-requests"),
        pytest.param("GET", "/rest/api/3/issue/OPS-12", id="read-issue"),
        pytest.param("GET", "/rest/api/3/issue/createmeta", id="create-metadata"),
        pytest.param("GET", "/rest/api/3/issue/bulk", id="read-on-a-bulk-path"),
        pytest.param("PUT", "/rest/api/3/issue/OPS-12", id="edit-issue"),
        pytest.param("PUT", "/rest/api/3/issue/OPS-12/assignee", id="assign"),
        pytest.param("DELETE", "/rest/api/3/issue/OPS-12/comment/1", id="delete-comment"),
        pytest.param("PATCH", "/rest/api/3/issue", id="patch-on-the-create-path"),
    ],
)
def test_nothing_but_a_post_that_creates_is_counted_or_refused(forwarder, upstream, method, path):
    """Comments, label edits, transitions, searches and reads go through as often as a Run likes,
    before the create and after it, and none of them spends the attempt."""
    forwarder.set_sentinel(SENTINEL)

    def send():
        return jira_request(
            forwarder,
            path=path,
            method=method,
            data=b"{}" if method != "GET" else None,
            content_type="application/json" if method != "GET" else None,
        )

    assert [send().status for _ in range(3)] == [200, 200, 200]
    assert create_request(forwarder).status == 200
    assert [send().status for _ in range(3)] == [200, 200, 200]
    assert len(upstream.received) == 7


def test_a_create_with_the_wrong_sentinel_is_refused_and_does_not_spend_the_attempt(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)

    assert create_request(forwarder, sentinel="a-guess").status == 401
    assert create_request(forwarder, sentinel=None).status == 401
    assert upstream.received == []

    assert create_request(forwarder).status == 200


def test_a_second_create_after_the_sentinel_is_cleared_is_a_plain_refusal(forwarder, upstream):
    forwarder.set_sentinel(SENTINEL)
    create_request(forwarder)
    forwarder.clear_sentinel()

    assert create_request(forwarder).status == 401
    assert len(upstream.received) == 1


def test_a_new_sentinel_starts_its_run_with_a_create_attempt_to_spend(forwarder, upstream):
    forwarder.set_sentinel("sentinel-of-the-previous-run")
    assert create_request(forwarder, sentinel="sentinel-of-the-previous-run").status == 200
    assert create_request(forwarder, sentinel="sentinel-of-the-previous-run").status == 409

    forwarder.set_sentinel(SENTINEL)

    assert create_request(forwarder).status == 200
    assert create_request(forwarder).status == 409
    assert create_request(forwarder, sentinel="sentinel-of-the-previous-run").status == 401
    assert len(upstream.received) == 2


def test_clearing_the_sentinel_ends_the_count_so_the_next_run_starts_at_zero(forwarder, upstream):
    forwarder.set_sentinel(SENTINEL)
    create_request(forwarder)
    forwarder.clear_sentinel()
    forwarder.set_sentinel(SENTINEL)

    assert create_request(forwarder).status == 200
    assert len(upstream.received) == 2


def test_creates_racing_under_one_sentinel_let_exactly_one_through(
    forwarder, upstream, monkeypatch
):
    """The first create is still in flight when the others arrive, so the count cannot wait for
    an answer, and the check and the spending of the attempt have to be one step."""
    racers = 8
    send_upstream = forwarder._send_upstream

    def slow(*args, **kwargs):
        threading.Event().wait(0.3)
        return send_upstream(*args, **kwargs)

    monkeypatch.setattr(forwarder, "_send_upstream", slow)
    forwarder.set_sentinel(SENTINEL)
    start = threading.Barrier(racers)
    statuses: list[int] = []

    def race():
        start.wait(5)
        statuses.append(create_request(forwarder).status)

    threads = [threading.Thread(target=race) for _ in range(racers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert sorted(statuses) == [200] + [409] * (racers - 1)
    assert len(upstream.received) == 1


def create_races(forwarder, headers, racers: int) -> list[int]:
    """The statuses of `racers` creates sent at once, with no HTTP in the way."""
    start = threading.Barrier(racers)
    statuses: list[int] = []

    def race():
        start.wait(5)
        statuses.append(forwarder.handle("POST", "/rest/api/3/issue", headers, ISSUE_BODY)[0])

    threads = [threading.Thread(target=race) for _ in range(racers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    return statuses


def test_the_check_and_the_spending_of_the_attempt_cannot_be_split_between_threads(
    forwarder, monkeypatch
):
    """The same race over many rounds, with the interpreter asked to switch threads as often as
    it can, so a check separated from the spending of the attempt shows itself."""
    monkeypatch.setattr(forwarder, "_send_upstream", lambda *args: (200, {}, b"{}"))
    headers = Message()
    headers["Authorization"] = basic_auth_header(REAL_EMAIL, SENTINEL)
    switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for _ in range(200):
            forwarder.set_sentinel(SENTINEL)

            assert sorted(create_races(forwarder, headers, racers=6)) == [200] + [409] * 5
    finally:
        sys.setswitchinterval(switch_interval)


def test_a_refused_create_is_a_warning_that_says_why_and_carries_no_credential(
    forwarder, upstream, caplog
):
    caplog.set_level(logging.DEBUG)
    forwarder.set_sentinel(SENTINEL)
    create_request(forwarder)

    create_request(forwarder)

    [record] = [r for r in caplog.records if r.getMessage().startswith("refused ")]
    assert record.levelno == logging.WARNING
    assert record.getMessage() == f"refused a POST /rest/api/3/issue: {CREATE_REFUSAL}"
    assert REAL_TOKEN not in caplog.text
    assert SENTINEL not in caplog.text
    assert "authorization" not in caplog.text.lower()


# --- The first create must carry an Incident's content ---


def paragraph_only_description() -> dict:
    """What jira-as makes of `--description Test`: one plain paragraph, no bullet list."""
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Test"}]}],
    }


def a_bullet_list(items=1) -> dict:
    return {
        "type": "bulletList",
        "content": [
            {"type": "listItem", "content": [{"type": "paragraph", "content": []}]}
            for _ in range(items)
        ],
    }


INCOMPLETE_CREATES = [
    pytest.param(
        incident_body(description=paragraph_only_description()), "bullet list", id="haiku-test"
    ),
    pytest.param(incident_body(description="Test"), "bullet list", id="description-as-text"),
    pytest.param(
        incident_body(description=json.dumps(json.loads(ISSUE_BODY)["fields"]["description"])),
        "bullet list",
        id="adf-sent-as-a-string",
    ),
    pytest.param(incident_body(description=None), "bullet list", id="no-description"),
    pytest.param(
        incident_body(description={"type": "doc", "version": 1, "content": []}),
        "bullet list",
        id="empty-document",
    ),
    pytest.param(
        incident_body(description={"type": "doc", "content": [a_bullet_list(items=0)]}),
        "bullet list",
        id="empty-bullet-list",
    ),
    pytest.param(
        incident_body(description={"type": "paragraph", "content": [a_bullet_list()]}),
        "bullet list",
        id="not-a-document",
    ),
    pytest.param(
        incident_body(description={"type": "doc", "content": {"type": "bulletList"}}),
        "bullet list",
        id="content-not-a-list",
    ),
    pytest.param(
        incident_body(description={"type": "doc", "content": [a_bullet_list()], "x": 1}),
        None,
        id="control-this-one-is-complete",
    ),
    pytest.param(
        incident_body(labels=["ses-demo", "fp-0a1b2c"]), "group label", id="no-group-label"
    ),
    pytest.param(
        incident_body(labels=["grp-checkout-outage", "fp-0a1b2c"]),
        "session label",
        id="no-session-label",
    ),
    pytest.param(incident_body(labels=None), "group label", id="no-labels"),
    pytest.param(
        incident_body(labels="grp-checkout-outage,ses-demo"), "group label", id="labels-as-text"
    ),
    pytest.param(incident_body(labels=[7, None]), "group label", id="labels-not-text"),
    pytest.param(b'{"fields": {"summary": "x"}', "is not JSON", id="truncated-json"),
    pytest.param(b"", "is not JSON", id="empty-body"),
    pytest.param(b"\xff\xfe\x00", "is not JSON", id="not-text"),
    pytest.param(b"[1, 2]", "no fields object", id="json-array"),
    pytest.param(b'{"fields": "Test"}', "no fields object", id="fields-not-an-object"),
    pytest.param(b'{"summary": "x"}', "no fields object", id="no-fields"),
    pytest.param(
        json.dumps({"issueUpdates": [{"fields": json.loads(ISSUE_BODY)["fields"]}]}).encode(),
        "no fields object",
        id="bulk-shaped-body",
    ),
    pytest.param(
        json.dumps({"serviceDeskId": "1", "requestFieldValues": {"summary": "x"}}).encode(),
        "no fields object",
        id="service-management-shaped-body",
    ),
    pytest.param(b"[" * 100_000, "is not JSON", id="nested-past-the-parser's-depth"),
]
"""A create body and what it lacks. The first row is the case the findings recorded: jira-as
sent `-d Test` as the Run's first create, so it was the one attempt, and made an Incident whose
Description was `Test`. jira-as passes any JSON object given as `--description` through as ADF,
so only the Forwarder reads whether a bullet list is in it."""


def forwarder_says(response) -> str:
    """The one message the Forwarder's 400 carries, after checking it is Jira-shaped."""
    assert response.status == 400
    assert response.headers["Content-Type"] == "application/json"
    return refusal_message(response)


@pytest.mark.parametrize(("body", "lacks"), INCOMPLETE_CREATES)
def test_a_create_without_an_incidents_content_is_refused_and_never_reaches_upstream(
    forwarder, upstream, body, lacks
):
    forwarder.set_sentinel(SENTINEL)

    response = jira_request(
        forwarder,
        path="/rest/api/3/issue",
        method="POST",
        data=body,
        content_type="application/json",
    )

    if lacks is None:
        assert response.status == 200
        assert len(upstream.received) == 1
        return
    message = forwarder_says(response)
    assert CREATE_INCOMPLETE in message
    assert lacks in message
    assert "do not retry" in message.lower()
    assert upstream.received == []


@pytest.mark.parametrize(("body", "lacks"), [p for p in INCOMPLETE_CREATES if p.values[1]])
def test_a_refused_create_spends_the_attempt_so_the_run_cannot_try_again(
    forwarder, upstream, body, lacks
):
    forwarder.set_sentinel(SENTINEL)

    first = jira_request(
        forwarder,
        path="/rest/api/3/issue",
        method="POST",
        data=body,
        content_type="application/json",
    )
    second = create_request(forwarder)

    assert first.status == 400
    assert second.status == 409
    assert CREATE_REFUSAL in refusal_message(second)
    assert upstream.received == []


@pytest.mark.parametrize("path", CREATE_PATHS)
def test_the_content_check_reads_every_create_path_the_same_way(forwarder, upstream, path):
    forwarder.set_sentinel(SENTINEL)

    first = jira_request(
        forwarder,
        path=path,
        method="POST",
        data=incident_body(description="Test"),
        content_type="application/json",
    )

    assert first.status == 400
    assert upstream.received == []


def test_a_complete_create_is_forwarded_unchanged_with_every_other_field_it_carries(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)
    body = incident_body(customfield_10010="1", components=[{"name": "rolldice"}])

    response = create_request_with(forwarder, body)

    assert response.status == 200
    assert upstream.received[0].body == body


def create_request_with(forwarder, body, path="/rest/api/3/issue"):
    return jira_request(
        forwarder, path=path, method="POST", data=body, content_type="application/json"
    )


def test_only_a_create_is_read_for_content(forwarder, upstream):
    """A comment, an edit or a transition has no Description and is not asked for one."""
    forwarder.set_sentinel(SENTINEL)

    comment = create_request_with(
        forwarder, b'{"body": "Update: 2 firing."}', path="/rest/api/3/issue/OPS-12/comment"
    )
    edit = jira_request(
        forwarder,
        path="/rest/api/3/issue/OPS-12",
        method="PUT",
        data=b'{"update": {"labels": [{"add": "fp-0a1b2c"}]}}',
        content_type="application/json",
    )

    assert (comment.status, edit.status) == (200, 200)


def test_a_refused_create_is_a_warning_that_names_what_is_missing_and_carries_no_credential(
    forwarder, upstream, caplog
):
    caplog.set_level(logging.DEBUG)
    forwarder.set_sentinel(SENTINEL)

    create_request_with(forwarder, incident_body(description="Test"))

    [record] = [r for r in caplog.records if r.getMessage().startswith("refused ")]
    assert record.levelno == logging.WARNING
    assert record.getMessage() == (
        f"refused a POST /rest/api/3/issue: {CREATE_INCOMPLETE} "
        "(its description is not a document with a bullet list)"
    )
    assert "Test" not in record.getMessage()
    assert REAL_TOKEN not in caplog.text
    assert SENTINEL not in caplog.text
    assert "authorization" not in caplog.text.lower()


def test_the_refusal_of_an_incomplete_create_is_short_enough_for_the_log_and_hides_no_secret(
    forwarder, upstream
):
    forwarder.set_sentinel(SENTINEL)

    message = forwarder_says(create_request_with(forwarder, incident_body(description="Test")))

    assert len(message) < 220, "jira-as prefixes it, and the log shows a line only so wide"
    assert REAL_TOKEN not in message
    assert SENTINEL not in message


def test_a_run_whose_create_was_refused_may_still_comment_edit_and_search(forwarder, upstream):
    forwarder.set_sentinel(SENTINEL)
    create_request_with(forwarder, incident_body(description="Test"))

    assert jira_request(forwarder, path="/rest/api/3/search/jql").status == 200
    assert (
        create_request_with(forwarder, b"{}", path="/rest/api/3/issue/OPS-12/comment").status == 200
    )


def test_the_forwarder_keeps_serving_after_a_body_nested_past_the_jsons_depth(forwarder, upstream):
    forwarder.set_sentinel(SENTINEL)

    refused = create_request_with(forwarder, b"[" * 100_000)

    assert refused.status == 400
    assert jira_request(forwarder).status == 200


def test_the_label_prefixes_are_the_ones_the_demo_and_its_verification_spell():
    from grafana_jsm_sandbox.demo_config import SESSION_LABEL_PREFIX as demos_session_prefix
    from grafana_jsm_sandbox.verify_mvp import GROUP_PREFIX as verifys_group_prefix

    assert SESSION_LABEL_PREFIX == demos_session_prefix
    assert GROUP_LABEL_PREFIX == verifys_group_prefix
