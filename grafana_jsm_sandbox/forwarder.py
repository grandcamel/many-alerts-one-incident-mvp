"""The Forwarder: the localhost process that holds the real Jira credential.

A Run's environment points jira-as at this Forwarder over plain http with a
per-Run sentinel as its API token. The Forwarder swaps that sentinel for the
real email and token and forwards the request to the configured Atlassian site,
so the token exists only in the Receiver's process (ADR 0002).

A sentinel also carries one issue-create attempt, spent by the first create it presents
whatever Jira answers. A second is refused here, so a Run that gets its create wrong
cannot probe the project with altered payloads. The first is forwarded only if it carries an
Incident's content, so a create jira-as built from a mangled argument cannot leave a
placeholder Incident behind (ADR 0002's 2026-10-01 amendment).

Run it on its own to point a jira-as on this machine at the real site through a
sentinel, which is the manual check for the credential boundary:

    python3 -m grafana_jsm_sandbox.forwarder
"""

from __future__ import annotations

import base64
import binascii
import enum
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
import urllib.error
import urllib.request
import zlib
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit, urlunsplit

logger = logging.getLogger(__name__)

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
"""Headers that belong to one hop and must not be forwarded to the next."""

_HEADERS_NOT_SENT_UPSTREAM = HOP_BY_HOP_HEADERS | {"authorization", "host", "content-length"}
"""On the way up, the Forwarder sets these itself; a Run's own versions are dropped."""

_HEADERS_NOT_SENT_BACK = HOP_BY_HOP_HEADERS | {"content-length"}
"""On the way back, the body passes through unchanged, so its length is recomputed here."""

UPSTREAM_TIMEOUT = 30
"""Seconds to wait on the Atlassian site before a Run is told the gateway failed."""

SHUTDOWN_POLL_INTERVAL = 0.05
"""How long `stop` may wait for the serving loop to notice it. The module's own default
of half a second is time a container spends on the way down, and time a test suite pays
for every server it starts."""

_TEXT = {"Content-Type": "text/plain; charset=utf-8"}
"""The headers on an answer the Forwarder writes itself rather than forwarding."""

UNREACHABLE_BODY = b"upstream is unreachable"
"""The body of the 502 the Forwarder writes itself when the site cannot be reached at all, so a
caller can tell it from a 502 the site sent: `doctor` reads the one as a network problem."""

CREATE_REFUSAL = "this Run already made its one create attempt"
"""Why a second issue create is refused. The log formatter looks for these words in a Run's
tool result, to show the refusal as the deliberate one it is."""

CREATE_INCOMPLETE = "this create does not carry an Incident's content"
"""Why a first issue create is refused: its body is not the Incident the Skill builds. The log
formatter looks for these words too."""

CREATE_REFUSALS = (CREATE_REFUSAL, CREATE_INCOMPLETE)
"""The words that mark a create the Forwarder refused on purpose, whichever the reason."""

CREATE_REFUSED_BODY = json.dumps(
    {
        "errorMessages": [
            (
                f"Refused: {CREATE_REFUSAL}. No second create reaches Jira, so do not retry or "
                "change the fields."
            )
        ],
        "errors": {},
    }
).encode()
"""What a Run's jira-as reads for the 409: Jira's own error shape, so it prints the message
rather than a parsing failure. It is short because jira-as prefixes it and the log shows a
line only so wide."""

GROUP_LABEL_PREFIX = "grp-"
SESSION_LABEL_PREFIX = "ses-"
"""The two labels every Incident a Run creates carries. `demo_config` and `verify_mvp` own
these spellings, and a test pins them equal: this module cannot import `demo_config`, which
imports it."""

_JSON = {"Content-Type": "application/json"}
"""The headers on the Jira-shaped error the Forwarder writes itself."""

_ISSUE_CREATE_PATH = re.compile(
    r"/rest/api/(?:2|3|latest)/issue(?:/bulk)?|/rest/servicedeskapi/request"
)
"""The paths a POST creates an issue at: either API version (or `latest`), its bulk form, and
the Service Management request. jira-as reaches them through `issue create`, `agile epic
create`, `agile subtask`, the two `clone` commands, `jsm request create` and the `api call`
operations createIssue, createIssues and createCustomerRequest. Its other POSTs are
comments, transitions, links, searches and administration, and everything else a Run sends
is not counted."""

DIAGNOSED_BODY_BYTES = 4096
"""How much of an upstream error body is searched for the words of an IP-allowlist refusal.
It is only searched, never logged: a body can quote anything the site holds."""

IP_ALLOWLIST = re.compile(r"(?is)\bIP address\b.*\b(rejected|not allowed|allowlist)|IP allowlist")
"""How an Atlassian site's IP-allowlist refusal reads. The audit recorded its 403 body as
saying the "IP address has been rejected"; the other words cover rephrasings of the same
refusal, which is still unverified live."""

DIAGNOSES = {
    401: (
        "Jira refused the credential in .env: JIRA_API_TOKEN is expired, revoked or blocked by "
        "an org policy, JIRA_EMAIL is not the account it belongs to, or it is a scoped token, "
        "which works only through an api.atlassian.com/ex/jira/<cloudId> JIRA_SITE_URL"
    ),
    403: "the account in .env lacks a Jira permission this call needs",
    404: (
        "Jira has no such thing, or the account in .env cannot see it: check DEMO_PROJECT_KEY "
        "and that the account can browse that project"
    ),
}
"""What a Jira status most likely means for the demo, for the statuses a newcomer's site is
known to answer when it is set up wrong. Every other 4xx and 5xx is still logged, undiagnosed.
They name `.env` because the Receiver takes its credential from there; the stand-alone
Forwarder reads the same variables from its shell."""

IP_ALLOWLIST_DIAGNOSIS = (
    "the site's IP allowlist rejected this address: ask the Atlassian org admin to allow the "
    "demo's address, or connect from a network the allowlist already has"
)

UNSEARCHED_403_DIAGNOSIS = (
    "the account in .env lacks a Jira permission this call needs, or the site's IP allowlist "
    "rejected this address; the body's encoding hid which"
)
"""A 403 whose body could not be read names both causes, rather than send a newcomer to the
Jira admin when it is the org admin's allowlist that refused."""


ENVIRONMENT_VARIABLES = {
    "site_url": "JIRA_SITE_URL",
    "email": "JIRA_EMAIL",
    "api_token": "JIRA_API_TOKEN",
}
"""Where the owning process reads the real credential from. A Run sees none of these values."""


class _Admission(enum.Enum):
    """What the Forwarder makes of a request before it decides to forward it."""

    ADMITTED = enum.auto()
    NOT_THE_SENTINEL = enum.auto()
    FIRST_CREATE = enum.auto()
    SECOND_CREATE = enum.auto()


class IncompleteJiraCredential(ValueError):
    """The owning process has no usable Jira credential, so nothing should start."""


@dataclass(frozen=True)
class JiraCredential:
    """The real Atlassian site and the credential to reach it with."""

    site_url: str
    email: str
    api_token: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> JiraCredential:
        """Read the credential, or raise naming every variable that is not set.

        Called before anything else starts, so a misconfigured container says so
        instead of silently no-opping in front of an audience.
        """
        environment = os.environ if environment is None else environment
        values = {
            field: environment.get(variable, "").strip()
            for field, variable in ENVIRONMENT_VARIABLES.items()
        }
        missing = [ENVIRONMENT_VARIABLES[field] for field, value in values.items() if not value]
        if missing:
            raise IncompleteJiraCredential(f"{' and '.join(missing)} is not set")
        if urlsplit(values["site_url"]).scheme not in ("http", "https"):
            raise IncompleteJiraCredential(
                f"{ENVIRONMENT_VARIABLES['site_url']} must be an http or https URL"
            )
        return cls(**values)


class Forwarder:
    """Forwards a Run's Jira requests upstream with the real credential attached."""

    def __init__(self, credential: JiraCredential, host: str = "127.0.0.1", port: int = 0):
        if not _is_loopback(host):
            raise ValueError(f"the Forwarder binds to loopback only, not {host}")
        self._credential = credential
        self._host = host
        self._sentinel: str | None = None
        self._create_attempted = False
        self._create_fields: dict | None = None
        self._sentinel_lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, port), _build_handler(self))
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        """Where the Forwarder is actually listening, once an ephemeral port is bound."""
        return f"http://{self._host}:{self._server.server_address[1]}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            args=(SHUTDOWN_POLL_INTERVAL,),
            name="forwarder",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop serving and release the port. Safe on a Forwarder that never started."""
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._server.server_close()

    def set_sentinel(self, sentinel: str, create_fields: dict | None = None) -> None:
        """Accept this sentinel, and only this one, until it is replaced or cleared.

        It starts with its Run's one create attempt unspent. Only the registered
        create fields can pass; without them every create is refused.
        """
        with self._sentinel_lock:
            self._create_fields = deepcopy(create_fields)
            self._sentinel = sentinel
            self._create_attempted = False

    def clear_sentinel(self) -> None:
        """Accept nothing. A sentinel from a Run that has ended is worth nothing."""
        with self._sentinel_lock:
            self._sentinel = None
            self._create_fields = None
            self._create_attempted = False

    def handle(
        self, method: str, path: str, headers: Message, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        """Answer one request from a Run: check its sentinel, then forward it upstream.

        The first issue create a sentinel presents is that Run's attempt. It is forwarded if
        its judged fields equal the registered create, and answered 400 here if not. Either
        way the attempt is spent, and whatever upstream answers, or whether it answers at all, does
        not give it back. Any later one is answered 409 here and goes nowhere.
        """
        admission, problem = self._admit(
            _presented_sentinel(headers.get("Authorization")), method, path, body
        )
        if admission is _Admission.NOT_THE_SENTINEL:
            logger.warning("refused a %s %s with no valid sentinel", method, path)
            return 401, dict(_TEXT), b"the presented token is not the active sentinel"
        if admission is _Admission.SECOND_CREATE:
            logger.warning("refused a %s %s: %s", method, path, CREATE_REFUSAL)
            return 409, dict(_JSON), CREATE_REFUSED_BODY
        if admission is _Admission.FIRST_CREATE and problem is not None:
            logger.warning("refused a %s %s: %s (%s)", method, path, CREATE_INCOMPLETE, problem)
            return 400, dict(_JSON), incomplete_create_body(problem)
        status, upstream_headers, upstream_body = self._send_upstream(
            method, path, _headers_to_send_upstream(headers), body
        )
        if status < 400:
            logger.info("forwarded %s %s, upstream said %s", method, path, status)
        else:
            diagnosis = diagnose(status, upstream_headers, upstream_body)
            logger.warning(
                "forwarded %s %s, upstream said %s%s",
                method,
                path,
                status,
                f": {diagnosis}" if diagnosis else "",
            )
        return status, _headers_to_send_back(upstream_headers), upstream_body

    def _admit(
        self, presented: str | None, method: str, path: str, body: bytes
    ) -> tuple[_Admission, str | None]:
        """Whether this is the sentinel of the Run that is currently allowed to call Jira, and
        if it is creating an issue, whether the Run still has its attempt.

        The sentinel check, content check and spending are one step under one lock, so creates
        racing on a sentinel cannot both be admitted.
        """
        with self._sentinel_lock:
            sentinel = self._sentinel
            if sentinel is None or presented is None:
                return _Admission.NOT_THE_SENTINEL, None
            if not secrets.compare_digest(sentinel, presented):
                return _Admission.NOT_THE_SENTINEL, None
            if _creates_an_issue(method, path):
                if self._create_attempted:
                    return _Admission.SECOND_CREATE, None
                self._create_attempted = True
                if not re.fullmatch(r"/rest/api/(?:2|3|latest)/issue", _create_path(path)):
                    problem = "only single-issue creates are allowed"
                else:
                    problem = missing_from_incident(body, self._create_fields)
                return _Admission.FIRST_CREATE, problem
            return _Admission.ADMITTED, None

    def _send_upstream(
        self, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        """Send one request upstream with the real credential in place of the sentinel."""
        request = urllib.request.Request(
            self._upstream_url(path),
            data=body or None,
            headers=headers,
            method=method,
        )
        request.add_header("Authorization", self._authorization())
        try:
            with _UPSTREAM_OPENER.open(request, timeout=UPSTREAM_TIMEOUT) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()
        except (urllib.error.URLError, TimeoutError) as error:
            logger.warning("upstream %s %s could not be reached: %s", method, path, error)
            return 502, dict(_TEXT), UNREACHABLE_BODY

    def _upstream_url(self, path: str) -> str:
        """The configured site plus the request's path and query, and nothing else."""
        site = urlsplit(self._credential.site_url)
        requested = urlsplit(path)
        return urlunsplit(
            (site.scheme, site.netloc, site.path.rstrip("/") + requested.path, requested.query, "")
        )

    def _authorization(self) -> str:
        encoded = base64.b64encode(
            f"{self._credential.email}:{self._credential.api_token}".encode()
        ).decode()
        return f"Basic {encoded}"


def _build_handler(forwarder: Forwarder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _forward(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            status, headers, answer = forwarder.handle(self.command, self.path, self.headers, body)
            self._respond(status, headers, answer)

        def _respond(self, status: int, headers: dict[str, str], body: bytes) -> None:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward

        def log_message(self, format, *args):
            """Silence the stderr access log; the Forwarder logs what is safe to log."""

    return Handler


class _StopAtRedirect(urllib.request.HTTPRedirectHandler):
    """Hands a 3xx back to the Run instead of following it.

    Following one would take the request somewhere other than the configured
    Atlassian site, which is the one thing the Forwarder must not do.
    """

    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


_UPSTREAM_OPENER = urllib.request.build_opener(_StopAtRedirect)


def diagnose(status: int, headers: Mapping[str, str], body: bytes) -> str | None:
    """What an upstream error most likely means, or None when the status has no diagnosis.

    A Run sees Jira's error only as a tool result trimmed to a few lines, so a site
    that refuses the demo's credential or address is diagnosed here, once, where the
    status is plain. A 403 is an IP-allowlist refusal when its body says so; a body
    whose encoding cannot be undone gets a diagnosis naming both likely causes.
    """
    if status == 403:
        searched = _searchable_prefix(headers, body)
        if searched is None:
            return UNSEARCHED_403_DIAGNOSIS
        if IP_ALLOWLIST.search(searched):
            return IP_ALLOWLIST_DIAGNOSIS
    return DIAGNOSES.get(status)


def _searchable_prefix(headers: Mapping[str, str], body: bytes) -> str | None:
    """The start of a body as text, or None when its content coding cannot be undone here.

    A Run's own Accept-Encoding goes upstream, and jira-as's HTTP client asks for gzip
    and deflate, so a refusal may well arrive compressed. Those two are undone with
    zlib, capped at the searched length so a large body costs no more than a small one.
    Any other coding, or a body that does not decompress, cannot be searched.
    """
    coding = next(
        (value for name, value in headers.items() if name.lower() == "content-encoding"), ""
    )
    coding = coding.strip().lower()
    if coding in ("", "identity"):
        prefix = body[:DIAGNOSED_BODY_BYTES]
    elif coding in ("gzip", "x-gzip", "deflate"):
        prefix = _inflated_prefix(body, deflate=coding == "deflate")
        if prefix is None:
            return None
    else:
        return None
    return prefix.decode("utf-8", errors="replace")


def _inflated_prefix(body: bytes, *, deflate: bool) -> bytes | None:
    # MAX_WBITS | 32 reads a gzip or a zlib header. HTTP's "deflate" is meant to be
    # zlib-wrapped, but some servers send the raw stream, which needs negative wbits.
    attempts = (zlib.MAX_WBITS | 32, -zlib.MAX_WBITS) if deflate else (zlib.MAX_WBITS | 32,)
    for wbits in attempts:
        try:
            return zlib.decompressobj(wbits).decompress(body, DIAGNOSED_BODY_BYTES)
        except zlib.error:
            continue
    return None


def _is_loopback(host: str) -> bool:
    """Whether every address this host resolves to is a loopback address."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(info[4][0]).is_loopback for info in resolved)


def _creates_an_issue(method: str, target: str) -> bool:
    """Whether a request asks Jira to create an issue: a POST to one of the create paths.

    The path is read as `_upstream_url` reads it, so a proxy-style absolute target counts
    by the path it is sent to. It is then spelled out plainly: percent-escapes undone, path
    parameters dropped, `.` and `..` resolved, slashes collapsed and case ignored. Atlassian's
    edge may read any of those spellings as the create path and the Forwarder cannot know
    which, so each counts as one.
    """
    if method.upper() != "POST":
        return False
    return _ISSUE_CREATE_PATH.fullmatch(_create_path(target)) is not None


def _create_path(target: str) -> str:
    """The canonical create path used by both counting and endpoint admission."""
    try:
        path = unquote(urlsplit(target).path)
    except ValueError:
        return ""  # a target that cannot be read is never sent upstream either
    segments: list[str] = []
    for segment in path.split("/"):
        segment = segment.partition(";")[0]
        if segment == "..":
            if segments:
                segments.pop()
        elif segment not in ("", "."):
            segments.append(segment)
    return "/" + "/".join(segments).lower()


def missing_from_incident(body: bytes, expected: dict | None) -> str | None:
    """Which field differs from incident-payload's registered create, if any."""
    if expected is None:
        return "no create content is registered for this Notification"
    try:
        document = json.loads(body)
    except (ValueError, RecursionError):
        return "its body is not JSON"
    fields = document.get("fields") if isinstance(document, dict) else None
    if not isinstance(fields, dict):
        return "its body has no fields object"
    for name in ("summary", "description"):
        if fields.get(name) != expected[name]:
            return f"its fields.{name} differs from the registered create"
    labels = fields.get("labels")
    if (
        not isinstance(labels, list)
        or not all(isinstance(label, str) for label in labels)
        or set(labels) != set(expected["labels"])
    ):
        return "its fields.labels differs from the registered create"
    return None


def incomplete_create_body(problem: str) -> bytes:
    """The Jira-shaped 400 for a create that does not carry an Incident's content."""
    return json.dumps(
        {
            "errorMessages": [
                (
                    f"Refused: {CREATE_INCOMPLETE} ({problem}). This Run's one create attempt is "
                    "spent, so do not retry or change the fields."
                )
            ],
            "errors": {},
        }
    ).encode()


def _headers_to_send_upstream(headers: Message) -> dict[str, str]:
    """The Run's own headers, minus the ones this hop owns. jira-as works unmodified."""
    return _without(headers.items(), _HEADERS_NOT_SENT_UPSTREAM)


def _headers_to_send_back(headers: dict[str, str]) -> dict[str, str]:
    """Upstream's own headers, minus the ones that belonged to that hop."""
    return _without(headers.items(), _HEADERS_NOT_SENT_BACK)


def _without(headers: Iterable[tuple[str, str]], unwanted: frozenset[str]) -> dict[str, str]:
    return {name: value for name, value in headers if name.lower() not in unwanted}


def _presented_sentinel(authorization: str | None) -> str | None:
    """The basic-auth password from a request, which is all a Run ever has to offer."""
    if not authorization:
        return None
    scheme, _, encoded = authorization.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    _, separator, password = decoded.partition(":")
    if not separator or not password.isascii():
        return None
    return password


def main(argv: list[str] | None = None) -> int:
    """Serve one sentinel on loopback until interrupted, and say how to use it.

    The real token is read from this process's environment and printed nowhere.
    """
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: python3 -m grafana_jsm_sandbox.forwarder", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        credential = JiraCredential.from_environment()
    except IncompleteJiraCredential as failure:
        print(failure, file=sys.stderr)
        return 1

    forwarder = Forwarder(credential)
    sentinel = secrets.token_urlsafe(24)
    forwarder.set_sentinel(sentinel)
    forwarder.start()
    print(f"forwarding to {credential.site_url} as {credential.email}", flush=True)
    print("point jira-as at the Forwarder with a sentinel in place of the token:\n", flush=True)
    print(f"    export JIRA_SITE_URL={forwarder.url}", flush=True)
    print(f"    export JIRA_API_TOKEN={sentinel}\n", flush=True)
    print(
        "the sentinel may make one issue-create attempt, as a Run's does, and only one that "
        "carries an Incident's content\n",
        flush=True,
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        forwarder.clear_sentinel()
        forwarder.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
