"""A stand-in for the Atlassian site the Forwarder is configured to talk to.

It runs on its own ephemeral port and records what arrived, so a test can assert
on the credential the Forwarder attached without a real site being involved.
"""

from __future__ import annotations

import base64
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from grafana_jsm_sandbox.forwarder import SHUTDOWN_POLL_INTERVAL


@dataclass
class UpstreamRequest:
    """One request the fake Atlassian site saw, exactly as it arrived."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    @property
    def basic_auth(self) -> tuple[str, str] | None:
        """The basic-auth user and password the request carried, if any."""
        header = self.headers.get("Authorization", "")
        scheme, _, encoded = header.partition(" ")
        if scheme.lower() != "basic":
            return None
        user, _, password = base64.b64decode(encoded).decode().partition(":")
        return user, password


class FakeUpstream:
    """The Atlassian site the Forwarder talks to, on its own ephemeral port.

    It records every request it saw and answers with whatever `status`, `body`
    and `headers` the test asked for.
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.received: list[UpstreamRequest] = []
        self.status = 200
        self.body = b'{"issues": []}'
        self.headers = {"Content-Type": "application/json"}
        self._host = host
        self._server = ThreadingHTTPServer((host, 0), _build_upstream_handler(self))
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._server.server_address[1]}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            args=(SHUTDOWN_POLL_INTERVAL,),
            name="fake-upstream",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def _build_upstream_handler(upstream: FakeUpstream):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _record_and_answer(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            upstream.received.append(
                UpstreamRequest(self.command, self.path, dict(self.headers), body)
            )
            self.send_response(upstream.status)
            for name, value in upstream.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(upstream.body)))
            self.end_headers()
            self.wfile.write(upstream.body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _record_and_answer

        def log_message(self, format, *args):
            """Silence the stderr access log; tests assert on `received` instead."""

    return Handler
