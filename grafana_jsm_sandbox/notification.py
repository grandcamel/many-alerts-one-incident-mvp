"""Validation of a Grafana Notification as it arrives on the wire.

A Notification is one webhook POST from Grafana carrying one or more Alerts.
The Receiver only checks enough to know it is a Notification at all: every
Alert must carry the Fingerprint and status a Run needs to act on it.
"""

from __future__ import annotations

import json

NOTIFICATION_FILENAME = "notification.json"
"""What the Receiver calls the Notification in a Run's working directory."""

REQUIRED_ALERT_FIELDS = ("fingerprint", "status")


class InvalidNotification(ValueError):
    """The body is not a Grafana Notification."""


def validate_notification(body: bytes) -> dict:
    """Return the parsed Notification, or raise InvalidNotification."""
    try:
        notification = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise InvalidNotification(f"body is not JSON: {error}") from error

    if not isinstance(notification, dict):
        raise InvalidNotification("body is not a JSON object")

    alerts = notification.get("alerts")
    if not isinstance(alerts, list):
        raise InvalidNotification("body has no alerts array")

    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            raise InvalidNotification(f"alert {index} is not a JSON object")
        missing = [field for field in REQUIRED_ALERT_FIELDS if not alert.get(field)]
        if missing:
            raise InvalidNotification(f"alert {index} has no {' and no '.join(missing)}")

    return notification
