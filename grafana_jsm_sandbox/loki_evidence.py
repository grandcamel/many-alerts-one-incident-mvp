"""Mechanical presentation of Loki streams; raw evidence stays with the caller."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta


def _strings(value) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    )


def summarize_logs(response, limit: int) -> dict:
    """Validate streams and return their counts and newest three brief excerpts.

    Raises ValueError for an invalid limit or response. Nanosecond timestamps
    retain their original spelling and are ordered using integers, never floats.
    Equal timestamps use labels, metadata, full line and original timestamp as
    deterministic tie breakers, independent of the upstream stream order.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("invalid log limit")
    if not isinstance(response, dict) or response.get("status") != "success":
        raise ValueError("invalid Loki response")
    data = response.get("data")
    if (
        not isinstance(data, dict) or data.get("resultType") != "streams"
        or not isinstance(data.get("result"), list)
    ):
        raise ValueError("invalid Loki streams")
    entries = []
    for stream in data["result"]:
        if (
            not isinstance(stream, dict) or not _strings(stream.get("stream"))
            or not isinstance(stream.get("values"), list)
        ):
            raise ValueError("invalid Loki stream")
        labels = stream["stream"]
        for value in stream["values"]:
            if (
                not isinstance(value, list) or len(value) not in {2, 3}
                or not isinstance(value[0], str) or not re.fullmatch(r"[0-9]+", value[0])
                or not isinstance(value[1], str)
                or (len(value) == 3 and not _strings(value[2]))
            ):
                raise ValueError("invalid Loki entry")
            timestamp = int(value[0])
            try:
                datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
                    seconds=timestamp // 1_000_000_000,
                    microseconds=(timestamp % 1_000_000_000) // 1000,
                )
            except OverflowError:
                raise ValueError("unrepresentable Loki timestamp") from None
            line = value[1]
            metadata = value[2] if len(value) == 3 else {}
            tie = (
                json.dumps(labels, sort_keys=True, ensure_ascii=False),
                json.dumps(metadata, sort_keys=True, ensure_ascii=False), line, value[0],
            )
            entries.append((timestamp, tie, {
                "timestamp_ns": value[0], "labels": dict(labels), "metadata": dict(metadata),
                "line": line[:600], "truncated": len(line) > 600,
            }))
    entries.sort(key=lambda entry: (-entry[0], entry[1]))
    return {
        "stream_count": len(data["result"]), "entry_count": len(entries),
        "limit_reached": len(entries) >= limit,
        "excerpts": [entry[2] for entry in entries[:3]],
    }
