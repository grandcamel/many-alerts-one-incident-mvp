"""Pinned, read-only, in-process synthetic queries. No native tools or Incident writes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from .executor import Lifecycle
from .outcomes import seconds

HISTORICAL_COMMIT = "79a14c8904f3a125d1f03b192d10797d30979c86"
PINNED_INPUTS = {
    "notification.json": "a916f500db4c069c5397eac8b49e689f208225ab43f6898554bc836d6da4b744",
    "changes.json": "cda98e82286ad8a9532fd2941221c64e5dd4847e444f762bf8ac6a613b6be956",
    "logs.jsonl": "a01dc708847f315cefe5627684b3590f660da6d1be6bd26ec0e77ee7bc54386b",
    "metrics.json": "943fd2ec1177f6bac283c1f37a85b7a07741ea4a64ec2df00ca5768b5b5920ae",
    "traces.json": "4395cb01ebcd5c747a39b0175e925cf7680a804d0e5dacfc93154cfa5bed2b3c",
}
MAX_FILE_BYTES = MAX_RESPONSE_BYTES = 65536
MAX_RESPONSES = 128
SCOPE = "OFFLINE_PINNED_QUERIES_ONLY"
# Each operation has a single fixed source and accepted argument names. No path arguments.
OPERATIONS = {
    "notification.get": ("notification.json", ()),
    "metrics.list": ("metrics.json", ()),
    "metrics.query": ("metrics.json", ("metric", "since", "until", "limit")),
    "logs.query": ("logs.jsonl", ("service", "contains", "since", "until", "limit")),
    "traces.list": ("traces.json", ("service", "since", "until", "limit")),
    "traces.get": ("traces.json", ("trace_id",)),
    "changes.list": ("changes.json", ("since", "until", "limit")),
}


class QueryRejected(ValueError):
    """Invalid adapter identity or rejected query; never a successful empty retrieval."""


class FixtureDataUnavailable(RuntimeError):
    """Pinned fixture bytes cannot be loaded; no adapter is ready."""


def _encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise QueryRejected("invalid fixture identity")
    return value


def _load(directory: Path) -> dict:
    data = {}
    try:
        for name, expected in PINNED_INPUTS.items():
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                    raise FixtureDataUnavailable("invalid fixture source type or size")
                raw = handle.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES or hashlib.sha256(raw).hexdigest() != expected:
                raise FixtureDataUnavailable("pinned fixture digest mismatch")
            data[name] = ([json.loads(line) for line in raw.splitlines()] if name.endswith(".jsonl")
                          else json.loads(raw))
    except (OSError, ValueError) as exc:
        raise FixtureDataUnavailable("pinned fixture source unavailable") from exc
    return data


def _stamp(value):
    if value is not None:
        if not isinstance(value, str) or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value, flags=re.ASCII):
            raise QueryRejected("timestamps require canonical UTC seconds")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError as exc:
            raise QueryRejected("invalid fixture timestamp") from exc
    return value


def _arguments(operation, arguments):
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise QueryRejected("unknown fixed operation")
    allowed = OPERATIONS[operation][1]
    if type(arguments) is not dict or set(arguments) - set(allowed):
        raise QueryRejected("unsupported query arguments")
    result = dict(arguments)
    for key in ("metric", "trace_id"):
        if key in allowed and key not in result:
            raise QueryRejected("missing exact selector")
    for key in ("metric", "trace_id", "service", "contains"):
        if key in result:
            value = result[key]
            if not isinstance(value, str) or not 1 <= len(value) <= 256:
                raise QueryRejected("invalid or oversized query text")
    if "since" in allowed:
        result["since"] = _stamp(result.get("since"))
        result["until"] = _stamp(result.get("until"))
        if result["since"] and result["until"] and result["since"] > result["until"]:
            raise QueryRejected("reversed query window")
    if "limit" in allowed:
        result.setdefault("limit", 50)
        if type(result["limit"]) is not int or not 1 <= result["limit"] <= 100:
            raise QueryRejected("limit must be an integer from 1 to 100")
    return result


def _within(stamp, args):
    return ((args.get("since") is None or stamp >= args["since"]) and
            (args.get("until") is None or stamp <= args["until"]))


def _item(pointer, value, projection="full"):
    return {"source_pointer": pointer, "projection": projection, "value": value}


class TimingQueries:
    """Single-threaded fixture adapter; IDs are correlation, not authentication authority."""

    def __init__(self, attempt_id: str, lifecycle: Lifecycle, *, fixture_root: Path | None = None):
        self.attempt_id = _identifier(attempt_id)
        self.session_id = uuid4().hex
        if not isinstance(lifecycle, Lifecycle):
            raise TypeError("fixture Lifecycle required")
        self.lifecycle = lifecycle
        self._data = _load(Path(fixture_root) if fixture_root is not None else
                           Path(__file__).with_name("timing_data"))
        self._requests: set[str] = set()
        self._responses: dict[str, bytes] = {}

    def describe(self) -> dict:
        """Static local API discovery, not a native tool or deployment manifest."""
        return {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                "operations": {name: {"source": value[0], "arguments": list(value[1]),
                                      "required": [key for key in value[1]
                                                   if key in ("metric", "trace_id")]}
                               for name, value in OPERATIONS.items()},
                "argument_contract": {
                    "text": "metric/trace_id/service/contains: 1..256 characters; exact case-sensitive",
                    "contains": "literal case-sensitive substring in log body",
                    "window": "since/until: optional canonical UTC YYYY-MM-DDTHH:MM:SSZ or null; inclusive",
                    "limit": "optional integer 1..100, default 50; booleans rejected",
                    "unknown_arguments": "rejected"},
                "max_responses": MAX_RESPONSES, "max_response_bytes": MAX_RESPONSE_BYTES}

    def query(self, request_id: str, operation: str, arguments: dict) -> dict:
        request_id = _identifier(request_id)
        args = _arguments(operation, arguments)
        if not self.lifecycle.work_allowed:
            raise QueryRejected("fixture work revoked or finished")
        if request_id in self._requests:
            raise QueryRejected("request ID already has a response")
        if len(self._responses) >= MAX_RESPONSES:
            raise QueryRejected("fixture response capacity exhausted")
        at = seconds(self.lifecycle.now)
        source = OPERATIONS[operation][0]
        status, selected = self._select(operation, args)
        limit = args.get("limit", len(selected))
        response_id = f"{self.attempt_id}/{self.session_id}/response/{len(self._responses) + 1:04d}"
        response = {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                    "request_id": request_id, "response_id": response_id,
                    "observed_at_virtual_seconds": at, "event_time_basis": "fixture_event_time",
                    "operation": operation, "arguments": args,
                    "source": {"file": source, "sha256": PINNED_INPUTS[source],
                               "historical_commit": HISTORICAL_COMMIT},
                    "status": status, "matched_count": len(selected),
                    "returned_count": min(len(selected), limit), "truncated": len(selected) > limit,
                    "items": selected[:limit]}
        response["response_sha256"] = hashlib.sha256(_encode(response)).hexdigest()
        encoded = _encode(response)
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise QueryRejected("fixture response exceeds byte capacity")
        self._responses[response_id] = encoded
        self._requests.add(request_id)
        return json.loads(encoded)

    def read_response(self, response_id: str) -> dict:
        """Retained in-memory read-back remains possible after work revocation."""
        if not isinstance(response_id, str) or response_id not in self._responses:
            raise QueryRejected("unknown fixture response")
        return json.loads(self._responses[response_id])

    def audit_snapshot(self) -> dict:
        """Operator-only detached inventory; does not perform a query or prove native capture."""
        return {"version": 1, "scope": SCOPE, "native_launch": "CLOSED",
                "attempt_id": self.attempt_id, "session_id": self.session_id,
                "responses": [json.loads(raw) for raw in self._responses.values()]}

    def _select(self, operation, args):
        data = self._data[OPERATIONS[operation][0]]
        if operation == "notification.get":
            return "ok", [_item("", data)]
        if operation == "metrics.list":
            return "ok", [_item("/" + name.replace("~", "~0").replace("/", "~1"),
                                {"name": name, "unit": body["unit"], "help": body["help"]},
                                "metric_metadata") for name, body in data.items()]
        if operation == "metrics.query":
            name = args["metric"]
            if name not in data:
                return "not_found", []
            pointer = "/" + name.replace("~", "~0").replace("/", "~1") + "/series/"
            return "ok", [_item(pointer + str(i), {"metric": name, "unit": data[name]["unit"],
                              "timestamp": stamp, "value": value}, "metric_point")
                          for i, (stamp, value) in enumerate(data[name]["series"])
                          if _within(stamp, args)]
        if operation == "traces.get":
            return next((("ok", [_item(f"/{i}", trace)]) for i, trace in enumerate(data)
                         if trace["traceId"] == args["trace_id"]), ("not_found", []))
        selected = []
        for i, row in enumerate(data):
            stamp = row["timestamp"] if operation == "logs.query" else (
                row["startTime"] if operation == "traces.list" else row["time"])
            if not _within(stamp, args):
                continue
            if operation == "logs.query":
                if ("service" in args and args["service"] != row["service"] or
                        "contains" in args and args["contains"] not in row["body"]):
                    continue
            elif operation == "traces.list":
                if "service" in args and not any(s["service"] == args["service"] for s in row["spans"]):
                    continue
                row = {key: row[key] for key in ("traceId", "startTime", "durationMs",
                                                "rootService", "rootName", "status")}
            selected.append((stamp, _item(f"/{i}", row,
                             "trace_summary" if operation == "traces.list" else "full")))
        return "ok", [item for _, item in sorted(selected, key=lambda pair: pair[0])]
