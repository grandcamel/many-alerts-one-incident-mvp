"""The Forwarder: the localhost process that holds the real Jira credential.

A Run's environment points jira-as at this Forwarder over plain http with a
per-Run sentinel as its API token. The Forwarder swaps that sentinel for the
real email and token and forwards the request to the configured Atlassian site,
so the token exists only in the Receiver's process (ADR 0002).

Run it on its own to point a jira-as on this machine at the real site through a
sentinel, which is the manual check for the credential boundary:

    python3 -m grafana_jsm_sandbox.forwarder
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
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
from dataclasses import dataclass
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

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

    def set_sentinel(self, sentinel: str) -> None:
        """Accept this sentinel, and only this one, until it is replaced or cleared."""
        with self._sentinel_lock:
            self._sentinel = sentinel

    def clear_sentinel(self) -> None:
        """Accept nothing. A sentinel from a Run that has ended is worth nothing."""
        with self._sentinel_lock:
            self._sentinel = None

    def handle(
        self, method: str, path: str, headers: Message, body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        """Answer one request from a Run: check its sentinel, then forward it upstream."""
        if not self._accepts(_presented_sentinel(headers.get("Authorization"))):
            logger.warning("refused a %s %s with no valid sentinel", method, path)
            return 401, dict(_TEXT), b"the presented token is not the active sentinel"
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

    def _accepts(self, presented: str | None) -> bool:
        """Whether this is the sentinel of the Run that is currently allowed to call Jira."""
        with self._sentinel_lock:
            sentinel = self._sentinel
        if sentinel is None or presented is None:
            return False
        return secrets.compare_digest(sentinel, presented)

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
