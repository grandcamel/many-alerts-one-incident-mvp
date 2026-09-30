"""Conservative outcome parsing for bounded synthetic Claude-shaped transcripts.

This adapter's schema is NOT qualified against a native client. Unknown event shapes
invalidate evidence rather than being silently ignored. It never infers permissions
from model prose or treats init metadata as actual assistant-model identity.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation


def money(value: object) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise TypeError("invalid money")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("invalid money") from exc
    if not result.is_finite() or result < 0:
        raise ValueError("invalid money")
    return result


def seconds(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("invalid elapsed time")
    if not math.isfinite(value) or value < 0:
        raise ValueError("invalid elapsed time")
    return float(value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {value}")


@dataclass(frozen=True)
class Outcome:
    execution: str
    reasons: tuple[str, ...]
    comparison: str
    actual_models: tuple[str, ...]
    estimate_usd: Decimal | None
    further_dispatch: str


class Transcript:
    """Streaming fixture parser with bounded lines, events and retained metadata."""

    def __init__(self, requested_model: str, *, max_events: int = 1000,
                 max_line_bytes: int = 65536):
        if not requested_model or len(requested_model) > 200:
            raise ValueError("an exact requested model is required")
        if not 1 <= max_events <= 10000 or not 1 <= max_line_bytes <= 1048576:
            raise ValueError("invalid parser bounds")
        self.requested_model = requested_model
        self.max_events = max_events
        self.max_line_bytes = max_line_bytes
        self.count = 0
        self.terminals = 0
        self.reasons: set[str] = set()
        self.models: set[str] = set()
        self.estimate: Decimal | None = None
        self.stop_requested = False

    def feed(self, line: bytes) -> None:
        self.count = min(self.count + 1, self.max_events + 1)
        if self.count > self.max_events or len(line) > self.max_line_bytes:
            self.reasons.add("capture_limit")
            self.stop_requested = True
            return
        try:
            event = json.loads(line, object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant)
            if not isinstance(event, dict):
                raise TypeError()
            kind = event.get("type")
            if kind == "assistant":
                message = event["message"]
                model = message["model"]
                if not isinstance(model, str) or not model or len(model) > 200:
                    raise ValueError()
                if not isinstance(message.get("content"), list):
                    raise ValueError()
                # At most two identities are needed to establish a mismatch.
                if len(self.models) < 2:
                    self.models.add(model)
                if model != self.requested_model:
                    self.reasons.add("model_mismatch")
                    self.stop_requested = True
            elif kind == "result":
                self.terminals = min(self.terminals + 1, 2)
                if self.terminals > 1:
                    self.reasons.add("duplicate_terminal")
                subtype = event["subtype"]
                is_error = event["is_error"]
                if type(is_error) is not bool or subtype not in ("success", "error"):
                    raise ValueError()
                if is_error or subtype == "error":
                    self.reasons.add("result_error")
                value = event.get("total_cost_usd")
                self.estimate = money(value) if value is not None else None
                # Missing usage is deliberately not zero.
                usage = event.get("usage")
                if usage is not None:
                    if not isinstance(usage, dict):
                        raise ValueError()
                    for key in ("input_tokens", "output_tokens"):
                        if key not in usage or type(usage[key]) is not int or usage[key] < 0:
                            raise ValueError()
            elif kind == "system" and event.get("subtype") == "init":
                pass  # Requested/init model never confirms actual identity.
            else:
                raise ValueError()
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            self.reasons.add("malformed_evidence")
            self.stop_requested = True

    def outcome(self, exit_code: int | None, observed: set[str] | None = None) -> Outcome:
        reasons = self.reasons | (observed or set())
        if not self.terminals:
            reasons.add("missing_terminal")
        if exit_code is None:
            reasons.add("missing_exit")
        elif type(exit_code) is not int:
            reasons.add("malformed_evidence")
        elif exit_code != 0:
            reasons.add("nonzero_exit")
        if not self.models:
            reasons.add("identity_missing")
        if "containment_failure" in reasons:
            execution = "containment_failed"
        elif "spawn_failure" in reasons:
            execution = "spawn_failed"
        elif "timeout" in reasons:
            execution = "timed_out"
        elif "cancelled" in reasons:
            execution = "cancelled"
        elif reasons & {"missing_terminal", "missing_exit", "duplicate_terminal",
                        "malformed_evidence", "capture_limit"}:
            execution = "incomplete"
        elif reasons & {"result_error", "nonzero_exit"}:
            execution = "failed"
        else:
            execution = "completed"
        comparison = "invalid" if reasons & {"model_mismatch", "identity_missing"} else "eligible"
        estimate = None if reasons & {"duplicate_terminal", "malformed_evidence",
                                     "capture_limit"} else self.estimate
        return Outcome(execution, tuple(sorted(reasons)), comparison,
                       tuple(sorted(self.models)), estimate,
                       "hold" if reasons else "requires_budget_recheck")
