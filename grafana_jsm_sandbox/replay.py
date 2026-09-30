"""Replaying the canned Notification sequence at a Receiver.

The three committed fixtures are one Alert seen three times: a Firing, a repeat
Firing, and a Resolved. Posting them in order drives the whole Incident
lifecycle without Grafana being involved, which is the demo's fallback and what
the end-to-end check uses.

    python3 -m grafana_jsm_sandbox.replay --pause 30

Without `--receiver` it posts where compose publishes the Receiver on this
laptop, `127.0.0.1:8080` unless `.env` or the shell moves it (`laptop_url`).

The Receiver runs Notifications one at a time in arrival order, so the pause is
about pacing what an audience sees, not about keeping the Runs apart.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path

from grafana_jsm_sandbox.demo_config import ConfigurationError, compose_environment

logger = logging.getLogger(__name__)

SEQUENCE = (
    "notification-firing.json",
    "notification-firing-repeat.json",
    "notification-resolved.json",
)
"""The canned Notifications, in the order a demo replays them."""

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
"""Where the canned Notifications live in this repo."""

NOTIFICATION_PATH = "/notification"
"""The Receiver's endpoint, the one Grafana's contact point points at."""

BIND_ADDRESS_VARIABLE = "BIND_ADDRESS"
RECEIVER_HOST_PORT_VARIABLE = "RECEIVER_HOST_PORT"
"""What compose publishes the Receiver on:
`${BIND_ADDRESS:-127.0.0.1}:${RECEIVER_HOST_PORT:-8080}`."""

DEFAULT_BIND_ADDRESS = "127.0.0.1"
"""The laptop's loopback, and nowhere else, unless the presenter says otherwise."""

DEFAULT_RECEIVER_HOST_PORT = 8080
"""The Receiver's port on the laptop when 8080 is free, which is also its port in the container."""

WILDCARD_ADDRESSES = ("0.0.0.0", "::")
"""Every interface, which includes the laptop's own, so the laptop reaches it as localhost."""

DEFAULT_PAUSE = 30.0
"""Seconds between Notifications: long enough to watch one Run finish before the next."""

POST_TIMEOUT = 10.0
"""Seconds to wait for the Receiver's acknowledgement, which it sends before the Run."""


def laptop_url(
    port_variable: str, default_port: int, environment: Mapping[str, str] | None = None
) -> str:
    """Where this laptop reaches a port compose publishes as `${BIND_ADDRESS}:${port_variable}`.

    Read from the variables compose interpolates the published ports from, with
    compose's own defaults, so moving the Receiver off a taken 8080 moves this with
    it. By default those are compose's own: `.env`, with the shell over it.
    """
    environment = compose_environment() if environment is None else environment
    address = environment.get(BIND_ADDRESS_VARIABLE, "").strip() or DEFAULT_BIND_ADDRESS
    if address in WILDCARD_ADDRESSES:
        address = "localhost"
    elif ":" in address:
        address = f"[{address}]"
    port = environment.get(port_variable, "").strip() or str(default_port)
    return f"http://{address}:{port}"


def default_receiver(environment: Mapping[str, str] | None = None) -> str:
    """The container's Receiver as compose publishes it on this laptop."""
    return laptop_url(RECEIVER_HOST_PORT_VARIABLE, DEFAULT_RECEIVER_HOST_PORT, environment)


def replay(
    receiver_url: str | None = None,
    pause: float = DEFAULT_PAUSE,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> list[int]:
    """Post the canned sequence in order and return what the Receiver answered each time.

    `sleep` is how the pause is waited out. A test hands in its own to see where each
    pause falls between the posts, which a wall clock on a loaded machine cannot show.
    """
    receiver_url = default_receiver() if receiver_url is None else receiver_url
    url = receiver_url.rstrip("/") + NOTIFICATION_PATH
    statuses = []
    for index, filename in enumerate(SEQUENCE):
        if index:
            sleep(pause)
        status = post(url, (FIXTURES / filename).read_bytes())
        logger.info("posted %s, receiver said %s", filename, status)
        statuses.append(status)
    return statuses


def post(url: str, notification: bytes) -> int:
    """POST one Notification and return the status, whatever it was."""
    request = urllib.request.Request(
        url,
        data=notification,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=POST_TIMEOUT) as response:
            return response.status
    except urllib.error.HTTPError as refusal:
        refusal.read()
        return refusal.code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--receiver",
        help="the Receiver's base URL; by default where compose publishes it on this laptop",
    )
    parser.add_argument(
        "--pause", type=float, default=DEFAULT_PAUSE, help="seconds between Notifications"
    )
    arguments = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        receiver_url = arguments.receiver or default_receiver()
    except ConfigurationError as failure:
        # Only a `.env` compose would refuse too gets here, and it names the line.
        print(failure, file=sys.stderr)
        return 1
    statuses = replay(receiver_url, arguments.pause)
    return 0 if all(status == 202 for status in statuses) else 1


if __name__ == "__main__":
    raise SystemExit(main())
