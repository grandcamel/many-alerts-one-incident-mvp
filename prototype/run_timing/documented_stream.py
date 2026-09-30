"""Bounded offline parser for a fixed, documented Claude stream subset.

This module accepts evidence-shaped JSON supplied by a receiver.  It is not a
Claude launcher, a native-schema qualification, an authentication mechanism, or
a billing record.  Digests identify submitted bytes only.  Unknown documented
families are deliberately held rather than interpreted optimistically.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

SOURCE_PROFILE = "claude-agent-sdk-python:f7547d7233527739ece8b12ed28c57be96c966b5"
_MAX_TEXT = 200
_RESULT_SUBTYPES = frozenset((
    "success",
    "error_during_execution",
    "error_max_turns",
    "error_max_budget_usd",
    "error_max_structured_output_retries",
))
_TERMINAL_REASONS = frozenset((
    "completed", "max_turns", "api_error", "aborted_streaming", "aborted_tools",
))
_INCOMPLETE_REASONS = frozenset((
    "capture_limit", "malformed_input", "unsupported_event", "unsupported_content",
    "sequence_error", "time_error", "session_mismatch", "model_mismatch",
    "tool_pairing", "unresolved_tool", "missing_terminal", "missing_exit",
    "duplicate_terminal", "record_after_terminal", "diagnostic_hold",
    "malformed_observation",
))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _decimal(value: str) -> Decimal:
    """Parse every JSON float exactly, while retaining a finite IEEE range bound.

    The float-range check intentionally rejects JSON such as ``1e999`` even in
    ignored keys.  Costs are still retained as their original Decimal value, so
    the check never rounds a valid cost.
    """
    try:
        parsed = Decimal(value)
        if not parsed.is_finite() or not math.isfinite(float(parsed)):
            raise ValueError("nonfinite JSON number")
    except (InvalidOperation, OverflowError, ValueError) as exc:
        raise ValueError("nonfinite JSON number") from exc
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {value}")


def _depth(value: object, limit: int, current: int = 1) -> None:
    if current > limit:
        raise ValueError("JSON nesting exceeds bound")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, limit, current + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, limit, current + 1)


def _bounded_string(value: object) -> str:
    if type(value) is not str or not value or len(value) > _MAX_TEXT:
        raise ValueError("invalid bounded string")
    return value


def _nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("invalid nonnegative integer")
    return value


def _exact_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("invalid boolean")
    return value


def _optional_string(mapping: dict[str, object], key: str, *, nullable: bool = False) -> str | None:
    if key not in mapping:
        return None
    value = mapping[key]
    if nullable and value is None:
        return None
    return _bounded_string(value)


def _nonempty_diagnostic(value: object, *, expected: type | tuple[type, ...]) -> bool:
    if not isinstance(value, expected):
        raise TypeError("invalid diagnostic")
    return bool(value)


@dataclass(frozen=True)
class ProcessObservation:
    """Receiver-side process facts; none is inferred from stream content."""

    exit_code: int | None
    capture_complete: bool
    root_reaped: bool
    group_gone: bool
    pipes_closed: bool
    timed_out: bool = False
    cancelled: bool = False
    spawn_failed: bool = False


@dataclass(frozen=True)
class StreamRecord:
    attempt_id: str
    sequence: int
    received_at: float
    raw_bytes: int
    raw_sha256: str
    kind: str
    accepted: bool
    reasons: tuple[str, ...]
    reported_session_id: str | None
    reported_model: str | None
    proposed_tool_ids: tuple[str, ...]
    returned_tool_ids: tuple[str, ...]


@dataclass(frozen=True)
class StreamOutcome:
    attempt_id: str
    status: str
    reasons: tuple[str, ...]
    reported_models: tuple[str, ...]
    reported_session_id: str | None
    reported_estimate_usd: Decimal | None
    actual_model: None = None
    provider_actual_usd: None = None
    native_qualification: str = "NOT_ASSESSED"
    further_dispatch: str = "hold"
    source_profile: str = SOURCE_PROFILE


class DocumentedStream:
    """Incrementally normalize only the documented complete-message subset."""

    def __init__(self, attempt_id: str, requested_model: str, *, max_events: int = 1000,
                 max_line_bytes: int = 65536, max_total_bytes: int = 1048576,
                 max_depth: int = 32):
        self.attempt_id = _bounded_string(attempt_id)
        self.requested_model = _bounded_string(requested_model)
        if (type(max_events) is not int or not 1 <= max_events <= 10000 or
                type(max_line_bytes) is not int or not 1 <= max_line_bytes <= 1048576 or
                type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 16777216 or
                type(max_depth) is not int or not 1 <= max_depth <= 64):
            raise ValueError("invalid documented stream bounds")
        self.max_events = max_events
        self.max_line_bytes = max_line_bytes
        self.max_total_bytes = max_total_bytes
        self.max_depth = max_depth
        self._expected_sequence = 1
        self._last_received_at: float | None = None
        self._events = 0
        self._total_bytes = 0
        self._halted = False
        self._reasons: set[str] = set()
        self._models: set[str] = set()
        self._session_id: str | None = None
        self._pending_tools: set[str] = set()
        self._seen_tools: set[str] = set()
        self._terminal = False
        self._estimate: Decimal | None = None
        self._receiver_failed = False
        self._receiver_failure_reasons: set[str] = set()
        self._current_reasons: set[str] = set()

    def _receiver_metadata(self, raw: bytes, sequence: int, received_at: float) -> None:
        if type(raw) is not bytes:
            self._hold("malformed_input")
            self._receiver_failed = True
            self._receiver_failure_reasons.add("malformed_input")
            raise ValueError("raw stream input must be bytes")
        if type(sequence) is not int or sequence != self._expected_sequence:
            self._hold("sequence_error")
            self._receiver_failed = True
            self._receiver_failure_reasons.add("sequence_error")
            raise ValueError("receiver sequence must be contiguous and start at one")
        try:
            receiver_time = float(received_at)
        except (OverflowError, TypeError, ValueError):
            receiver_time = float("nan")
        if (isinstance(received_at, bool) or not isinstance(received_at, (int, float)) or
                not math.isfinite(receiver_time) or receiver_time < 0 or
                (self._last_received_at is not None and receiver_time < self._last_received_at)):
            self._hold("time_error")
            self._receiver_failed = True
            self._receiver_failure_reasons.add("time_error")
            raise ValueError("receiver time must be finite, nonnegative, and monotonic")
        self._expected_sequence += 1
        self._last_received_at = receiver_time

    def _hold(self, reason: str) -> None:
        self._reasons.add(reason)
        self._current_reasons.add(reason)

    def _record(self, raw: bytes, sequence: int, received_at: float, kind: str,
                reasons: set[str], *, accepted: bool, session_id: str | None = None,
                model: str | None = None, proposed: tuple[str, ...] = (),
                returned: tuple[str, ...] = ()) -> StreamRecord:
        reasons = set(reasons) | self._current_reasons
        self._reasons.update(reasons)
        return StreamRecord(self.attempt_id, sequence, float(received_at), len(raw),
                            hashlib.sha256(raw).hexdigest(), kind, accepted,
                            tuple(sorted(reasons)), session_id, model, proposed, returned)

    def _session(self, event: dict[str, object], *, required: bool = False) -> str | None:
        if "session_id" not in event:
            if required:
                raise ValueError("missing session ID")
            return None
        session_id = _bounded_string(event["session_id"])
        if self._session_id is not None and session_id != self._session_id:
            self._hold("session_mismatch")
            raise ValueError("session ID mismatch")
        return session_id

    def _assistant(self, event: dict[str, object]) -> tuple[str | None, tuple[str, ...]]:
        if event.get("parent_tool_use_id") is not None:
            self._hold("unsupported_event")
            raise ValueError("subagent assistant output")
        message = event.get("message")
        if not isinstance(message, dict):
            raise TypeError("assistant message is required")
        model = _bounded_string(message.get("model"))
        content = message.get("content")
        if not isinstance(content, list):
            raise TypeError("assistant content must be an array")
        _optional_string(event, "uuid", nullable=True)
        _optional_string(message, "id", nullable=True)
        _optional_string(message, "stop_reason", nullable=True)
        if "usage" in message and message["usage"] is not None:
            usage = message["usage"]
            if not isinstance(usage, dict):
                raise ValueError("assistant usage must be an object")
            for key in ("input_tokens", "output_tokens"):
                if key in usage:
                    _nonnegative_int(usage[key])
        if "error" in event and event["error"] is not None:
            if type(event["error"]) is not str:
                raise ValueError("assistant error must be a string")
            if event["error"]:
                self._hold("diagnostic_hold")
        proposed: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                raise TypeError("assistant content block must be an object")
            if block.get("type") == "text":
                if type(block.get("text")) is not str:
                    raise ValueError("text block requires text")
            elif block.get("type") == "tool_use":
                tool_id = _bounded_string(block.get("id"))
                _bounded_string(block.get("name"))
                if (not isinstance(block.get("input"), dict) or tool_id in self._seen_tools or
                        tool_id in proposed):
                    self._hold("tool_pairing")
                    raise ValueError("invalid tool proposal")
                proposed.append(tool_id)
            else:
                self._hold("unsupported_content")
                raise ValueError("unsupported assistant content")
        if model != self.requested_model:
            self._hold("model_mismatch")
        self._models.add(model)
        self._pending_tools.update(proposed)
        self._seen_tools.update(proposed)
        return model, tuple(proposed)

    def _user(self, event: dict[str, object]) -> tuple[str, ...]:
        if event.get("parent_tool_use_id") is not None:
            self._hold("unsupported_event")
            raise ValueError("subagent user output")
        message = event.get("message")
        if not isinstance(message, dict):
            raise TypeError("user message is required")
        content = message.get("content")
        if type(content) is str:
            return ()
        if not isinstance(content, list):
            raise TypeError("user content must be text or an array")
        returned: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                raise TypeError("user content block must be an object")
            block_type = block.get("type")
            if block_type == "text":
                if type(block.get("text")) is not str:
                    raise ValueError("text block requires text")
            elif block_type == "tool_result":
                tool_id = _bounded_string(block.get("tool_use_id"))
                if tool_id not in self._pending_tools or tool_id in returned:
                    self._hold("tool_pairing")
                    raise ValueError("unknown or duplicate tool result")
                if "is_error" in block and block["is_error"] is not None and type(block["is_error"]) is not bool:
                    raise ValueError("tool result is_error must be boolean")
                if block.get("is_error") is True:
                    self._hold("tool_error")
                if "content" in block and block["content"] is not None and not isinstance(block["content"], (str, list)):
                    raise ValueError("tool result content must be text, blocks, or null")
                if isinstance(block.get("content"), list) and any(
                        not isinstance(item, dict) for item in block["content"]):
                    raise ValueError("tool result content blocks must be objects")
                returned.append(tool_id)
            else:
                self._hold("unsupported_content")
                raise ValueError("unsupported user content")
        self._pending_tools.difference_update(returned)
        return tuple(returned)

    def _result(self, event: dict[str, object]) -> Decimal | None:
        subtype = event.get("subtype")
        if type(subtype) is not str or subtype not in _RESULT_SUBTYPES:
            raise ValueError("unsupported result subtype")
        _nonnegative_int(event.get("duration_ms"))
        _nonnegative_int(event.get("duration_api_ms"))
        _nonnegative_int(event.get("num_turns"))
        is_error = _exact_bool(event.get("is_error"))
        terminal_reason = _optional_string(event, "terminal_reason", nullable=True)
        if terminal_reason is not None and terminal_reason not in _TERMINAL_REASONS:
            raise ValueError("unsupported terminal reason")
        for key in ("uuid", "stop_reason"):
            _optional_string(event, key, nullable=True)
        if "origin" in event and event["origin"] is not None:
            origin = event["origin"]
            if not isinstance(origin, dict) or type(origin.get("kind")) is not str:
                raise ValueError("origin must be an object with a string kind")
        if "api_error_status" in event and event["api_error_status"] is not None:
            _nonnegative_int(event["api_error_status"])
            self._hold("result_error")
        if "usage" in event and event["usage"] is not None:
            usage = event["usage"]
            if not isinstance(usage, dict):
                raise ValueError("result usage must be an object")
            for key in ("input_tokens", "output_tokens"):
                if key in usage:
                    _nonnegative_int(usage[key])
        if "modelUsage" in event and event["modelUsage"] is not None and not isinstance(event["modelUsage"], dict):
            raise ValueError("modelUsage must be an object")
        if "result" in event and event["result"] is not None and type(event["result"]) is not str:
            raise ValueError("result text must be a string")
        for key in ("permission_denials", "errors"):
            if (key in event and event[key] is not None and
                    _nonempty_diagnostic(event[key], expected=list)):
                self._hold("diagnostic_hold")
        if "errors" in event and event["errors"] is not None:
            for error in event["errors"]:
                if type(error) is not str:
                    raise ValueError("result errors must be strings")
        if "deferred_tool_use" in event and event["deferred_tool_use"] is not None:
            deferred = event["deferred_tool_use"]
            if not isinstance(deferred, dict):
                raise ValueError("deferred tool use must be an object")
            _bounded_string(deferred.get("id"))
            _bounded_string(deferred.get("name"))
            if not isinstance(deferred.get("input"), dict):
                raise ValueError("deferred tool input must be an object")
            self._hold("diagnostic_hold")
        estimate = None
        if "total_cost_usd" in event and event["total_cost_usd"] is not None:
            value = event["total_cost_usd"]
            if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
                raise ValueError("total cost must be a JSON number")
            estimate = Decimal(value)
            if not estimate.is_finite() or estimate < 0:
                raise ValueError("invalid total cost")
        if is_error or subtype != "success" or terminal_reason in {"max_turns", "api_error"}:
            self._hold("result_error")
        if terminal_reason in {"aborted_streaming", "aborted_tools"}:
            self._hold("cancelled")
        return estimate

    def feed(self, raw: bytes, *, sequence: int, received_at: float) -> StreamRecord:
        """Consume one submitted JSON object and return only bounded metadata."""
        self._current_reasons = set()
        self._receiver_metadata(raw, sequence, received_at)
        if self._receiver_failed:
            return self._record(raw, sequence, received_at, "unknown",
                                self._receiver_failure_reasons, accepted=False)
        if self._halted:
            return self._record(raw, sequence, received_at, "unknown", {"capture_limit"}, accepted=False)
        self._events += 1
        self._total_bytes += len(raw)
        if (self._events > self.max_events or len(raw) > self.max_line_bytes or
                self._total_bytes > self.max_total_bytes):
            self._halted = True
            return self._record(raw, sequence, received_at, "unknown", {"capture_limit"}, accepted=False)
        try:
            event = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant, parse_float=_decimal)
            if not isinstance(event, dict):
                raise TypeError("stream item must be an object")
            _depth(event, self.max_depth)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            return self._record(raw, sequence, received_at, "unknown", {"malformed_input"}, accepted=False)
        raw_kind = event.get("type")
        kind = raw_kind if type(raw_kind) is str and len(raw_kind) <= _MAX_TEXT else "unknown"
        if self._terminal:
            terminal_reasons = {"record_after_terminal"}
            if kind == "result":
                terminal_reasons.add("duplicate_terminal")
            return self._record(raw, sequence, received_at, kind, terminal_reasons, accepted=False)
        try:
            if kind == "system" and event.get("subtype") == "init":
                session = self._session(event)
                model = _optional_string(event, "model", nullable=True)
                self._session_id = session or self._session_id
                return self._record(raw, sequence, received_at, kind, set(), accepted=True,
                                    session_id=session, model=model)
            if kind == "assistant":
                session = self._session(event)
                model, proposed = self._assistant(event)
                self._session_id = session or self._session_id
                return self._record(raw, sequence, received_at, kind, set(), accepted=True,
                                    session_id=session, model=model, proposed=proposed)
            if kind == "user":
                session = self._session(event)
                returned = self._user(event)
                self._session_id = session or self._session_id
                return self._record(raw, sequence, received_at, kind, set(), accepted=True,
                                    session_id=session, returned=returned)
            if kind == "result":
                session = self._session(event, required=True)
                estimate = self._result(event)
                self._session_id = session
                self._terminal = True
                self._estimate = estimate
                return self._record(raw, sequence, received_at, kind, set(), accepted=True,
                                    session_id=session)
            self._hold("unsupported_event")
            return self._record(raw, sequence, received_at, kind, {"unsupported_event"}, accepted=False)
        except (ValueError, TypeError, KeyError, RecursionError):
            # Semantic checks may attach their more specific sticky hold first.
            return self._record(raw, sequence, received_at, kind, {"malformed_input"}, accepted=False)

    def _validate_observation(self, observation: ProcessObservation) -> None:
        if not isinstance(observation, ProcessObservation):
            self._hold("malformed_observation")
            raise ValueError("process observation is required")  # noqa: TRY004 - public API contract
        if observation.exit_code is not None and type(observation.exit_code) is not int:
            self._hold("malformed_observation")
            raise ValueError("exit code must be an int or None")
        for key in ("capture_complete", "root_reaped", "group_gone", "pipes_closed",
                    "timed_out", "cancelled", "spawn_failed"):
            if type(getattr(observation, key)) is not bool:
                self._hold("malformed_observation")
                raise ValueError("process observation flags must be booleans")

    def outcome(self, observation: ProcessObservation) -> StreamOutcome:
        """Combine sticky stream holds with supplied, independent process facts."""
        self._validate_observation(observation)
        reasons = set(self._reasons)
        if not observation.capture_complete:
            reasons.add("capture_incomplete")
        if not observation.root_reaped:
            reasons.add("root_unreaped")
        if not observation.group_gone:
            reasons.add("group_present")
        if not observation.pipes_closed:
            reasons.add("pipes_open")
        if observation.spawn_failed:
            reasons.add("spawn_failed")
        if observation.timed_out:
            reasons.add("timed_out")
        if observation.cancelled:
            reasons.add("cancelled")
        if observation.exit_code is None:
            reasons.add("missing_exit")
        elif observation.exit_code != 0:
            reasons.add("nonzero_exit")
        if not self._terminal:
            reasons.add("missing_terminal")
        if not self._models:
            reasons.add("identity_missing")
        if self._pending_tools:
            reasons.add("unresolved_tool")
        if reasons & {"root_unreaped", "group_present", "pipes_open"}:
            status = "containment_failed"
        elif "spawn_failed" in reasons:
            status = "spawn_failed"
        elif "timed_out" in reasons:
            status = "timed_out"
        elif "cancelled" in reasons:
            status = "cancelled"
        elif reasons & _INCOMPLETE_REASONS or "capture_incomplete" in reasons or "identity_missing" in reasons:
            status = "incomplete"
        elif reasons & {"nonzero_exit", "result_error", "tool_error"}:
            status = "failed"
        else:
            status = "stream_consistent"
        return StreamOutcome(self.attempt_id, status, tuple(sorted(reasons)),
                             tuple(sorted(self._models)), self._session_id, self._estimate)
