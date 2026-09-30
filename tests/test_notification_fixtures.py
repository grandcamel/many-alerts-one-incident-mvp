"""The canned Notification sequence: a Firing, a repeat Firing, and a Resolved.

These three fixtures are the demo's fallback when Grafana is uncooperative, and
the input to the end-to-end check. They are what Grafana actually posted during
ticket 07's rehearsal, so the Fingerprint is the real Alert's and the replay
drives the same Incident the live stack would. They only mean anything as a
sequence: one Alert, one Fingerprint, seen three times. A fixture edited out of
step with the other two breaks a demo rather than a test, so the sequence is
what is asserted here.
"""

from __future__ import annotations

import json

import pytest

from grafana_jsm_sandbox.notification import validate_notification
from grafana_jsm_sandbox.replay import SEQUENCE
from tests.conftest import FIXTURES


def canned(filename: str) -> dict:
    """One canned Notification, validated the way the Receiver validates it."""
    return validate_notification((FIXTURES / filename).read_bytes())


def only_alert(notification: dict) -> dict:
    alerts = notification["alerts"]
    assert len(alerts) == 1, "each canned Notification carries exactly one Alert"
    return alerts[0]


@pytest.fixture
def sequence() -> list[dict]:
    return [canned(filename) for filename in SEQUENCE]


@pytest.mark.parametrize("filename", SEQUENCE)
def test_each_fixture_is_a_notification_the_receiver_accepts(filename):
    notification = canned(filename)
    assert notification["alerts"]

    # The bytes on disk are what Grafana would post, formatting included.
    raw = (FIXTURES / filename).read_text()
    assert json.loads(raw) == notification


def test_the_three_notifications_report_one_alert_by_one_fingerprint(sequence):
    fingerprints = {only_alert(notification)["fingerprint"] for notification in sequence}
    assert len(fingerprints) == 1, f"the sequence is one Alert, not {fingerprints}"


def test_the_sequence_is_firing_then_repeat_firing_then_resolved(sequence):
    assert [only_alert(notification)["status"] for notification in sequence] == [
        "firing",
        "firing",
        "resolved",
    ]
    assert [notification["status"] for notification in sequence] == [
        "firing",
        "firing",
        "resolved",
    ]


def test_a_repeat_firing_is_the_same_notification_sent_again(sequence):
    """Grafana repeats a Firing verbatim, values included; the trend comment says so."""
    first, repeat, _ = sequence
    assert repeat == first


def test_the_alert_keeps_one_start_and_ends_only_when_resolved(sequence):
    first, repeat, resolved = (only_alert(notification) for notification in sequence)
    assert first["startsAt"] == repeat["startsAt"] == resolved["startsAt"], (
        "a repeat Firing does not restart the Alert"
    )
    assert first["endsAt"] == repeat["endsAt"] == "0001-01-01T00:00:00Z"
    assert resolved["endsAt"] > resolved["startsAt"]


@pytest.mark.parametrize("filename", SEQUENCE)
def test_every_alert_carries_what_the_field_mapping_reads(filename):
    alert = only_alert(canned(filename))
    assert set(alert["labels"]) >= {"alertname", "instance", "service", "severity"}
    assert set(alert["annotations"]) >= {"summary", "description"}
    assert {"generatorURL", "dashboardURL", "panelURL"} <= set(alert)
