"""A loopback Grafana datasource proxy, shared by query and Run-flow tests."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class GrafanaRequest:
    """One request exactly as it arrived, including its encoded query string."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class FakeGrafana:
    """Answer queued responses in order, then successful empty vectors."""

    def __init__(self):
        self.received: list[GrafanaRequest] = []
        self.responses: list[tuple[int, bytes, float]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self))
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever, args=(0.01,), name="fake-grafana", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
        self._server.server_close()


def _handler(upstream: FakeGrafana):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            upstream.received.append(
                GrafanaRequest(
                    self.command, self.path, dict(self.headers),
                    self.rfile.read(int(self.headers.get("Content-Length") or 0)),
                )
            )
            status, body, delay = (
                upstream.responses.pop(0) if upstream.responses else
                (200, b'{"status":"success","data":{"resultType":"vector","result":[]}}', 0)
            )
            time.sleep(delay)
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format, *args):
            """Tests inspect received requests rather than stderr access logs."""

    return Handler
