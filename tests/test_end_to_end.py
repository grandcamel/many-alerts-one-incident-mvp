"""The whole loop, against a running demo and the demo's real Jira project.

This is the only test that touches Jira, so it is opt-in: set `DEMO_END_TO_END`
and it runs, otherwise it is skipped and the default suite stays offline and
fast. It is `python3 -m grafana_jsm_sandbox.verify` run as a test: by default
it replays the canned Notification sequence at a Receiver that is already
running (`python3 -m grafana_jsm_sandbox`, or the container) and watches the
project until the Incident those Runs created is Completed with a resolution:

    DEMO_END_TO_END=1 python3 -m pytest tests/test_end_to_end.py

`DEMO_END_TO_END=live` runs `verify --live` instead, which stops the traffic,
waits for the real Alert, and starts the traffic again on the way out.

What it checks, and how it tells its own Incident from a rehearsal's, is
`verify`'s: through `jira-as` started with the project and the credential in
`.env` and nothing of this shell's own (`demo_config`), which is the same
credential compose hands the Forwarder inside the demo. Like `verify`, it
closes and deletes nothing: a Completed Incident with a resolution is already
out of the Incidents queue, and anything a failed run leaves open is
`python3 -m grafana_jsm_sandbox.reset`'s to take out.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

import pytest

from grafana_jsm_sandbox import verify

END_TO_END_VARIABLE = "DEMO_END_TO_END"
"""Set it to anything and this check runs against a live demo and the real project; set it
to `live` and it drives the real Alert rather than the replay."""

RECEIVER_VARIABLE = "DEMO_RECEIVER_URL"
"""Where the demo is listening, when it is not where compose publishes it on this laptop. Only
the replay posts at it; `--live` leaves the posting to Grafana, so it is not passed then."""

RUN_TIMEOUT_VARIABLE = "DEMO_END_TO_END_RUN_TIMEOUT"
"""Seconds to give each Run, when a demo machine is slower than `verify`'s default allows."""


pytestmark = pytest.mark.skipif(
    not os.environ.get(END_TO_END_VARIABLE),
    reason=f"drives a running demo and the real project; set {END_TO_END_VARIABLE}=1 to run",
)


def verify_arguments(environment: Mapping[str, str]) -> list[str]:
    """The `verify` command line this check runs, from its opt-in variables."""
    mode = environment.get(END_TO_END_VARIABLE, "").strip().lower()
    arguments = ["--live" if mode == verify.LIVE else "--replay"]
    receiver = environment.get(RECEIVER_VARIABLE, "").strip()
    if receiver and mode != verify.LIVE:
        arguments += ["--receiver", receiver]
    if run_timeout := environment.get(RUN_TIMEOUT_VARIABLE, "").strip():
        arguments += ["--run-timeout", run_timeout]
    return arguments


def test_the_canned_sequence_drives_one_incident_from_firing_to_completed():
    assert verify.main(verify_arguments(os.environ)) == 0, "verify's lines above say which stage"
