"""Offline executor for ticket 23: virtual time and inert Python fixtures only.

No subprocess, sockets, credential reads or native launcher. Lifecycle actions are
requirements emitted to a future binding, not evidence that a host process was killed.
Receipts prove dispatch inside this object only, not OS isolation or a live tool call.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

from .outcomes import Outcome, Transcript, money, seconds


class Lifecycle:
    """Monotonic 270/20/10 state machine; deadlines never slide with new output."""

    def __init__(self):
        self.now = 0.0
        self.cleanup_at: float | None = None
        self.kill_at = 290.0
        self.end_at = 300.0
        self.revoked = False
        self.finished = False
        self.killed = False
        self.reasons: set[str] = set()

    def advance(self, at: float, *, cancel: bool = False, parent_exited: bool = False,
                reaped: bool = False, pipes_closed: bool = False) -> tuple[str, ...]:
        at = seconds(at)
        if any(type(value) is not bool for value in (cancel, parent_exited, reaped, pipes_closed)):
            raise TypeError("lifecycle observations must be explicit booleans")
        if at < self.now:
            raise ValueError("clock moved backwards")
        if self.finished:
            raise ValueError("lifecycle already closed")
        self.now = at
        actions = []
        if cancel:
            self.reasons.add("cancelled")
        if self.cleanup_at is None:
            if at >= 270:
                self.reasons.add("timeout")
                self.cleanup_at = 270.0
            elif cancel:
                self.reasons.add("cancelled")
                self.cleanup_at = at
            elif parent_exited:
                self.cleanup_at = at
            if self.cleanup_at is not None:
                self.revoked = True
                self.kill_at = min(self.cleanup_at + 20, 290)
                self.end_at = min(self.kill_at + 10, 300)
                actions.extend(("revoke", "interrupt"))
        if parent_exited and reaped and pipes_closed and at <= self.end_at:
            self.finished = True
            return tuple(actions + ["closed"])
        if self.cleanup_at is not None and at >= self.kill_at and not self.killed:
            self.killed = True
            actions.append("kill_and_reap")
        if at >= self.end_at:
            self.reasons.add("containment_failure")
            self.finished = True
            actions.append("hold")
        return tuple(actions)

    @property
    def work_allowed(self) -> bool:
        return not self.revoked and not self.finished and self.now < 270


@dataclass(frozen=True)
class Charge:
    week: str
    actual_usd: Decimal | None
    reservation_usd: Decimal = Decimal(3)
    diagnostic: bool = True


def admission(charges: tuple[Charge, ...] | None, now: datetime, *,
              billing_current: bool) -> tuple[str, ...]:
    """Predicate over supplied synthetic ledger evidence. Does not reserve real money."""
    if now.tzinfo is None:
        raise ValueError("timezone-aware timestamp required")
    if type(billing_current) is not bool:
        raise TypeError("billing readiness must be explicit")
    local = now.astimezone(ZoneInfo("America/New_York")).date()
    week = (local - timedelta(days=local.weekday())).isoformat()
    reasons = set()
    if not billing_current:
        reasons.add("billing_not_current")
    if charges is None:
        return tuple(sorted(reasons | {"missing_ledger"}))
    if len(charges) > 10000:
        return ("ledger_limit",)
    weekly = Decimal(0)
    diagnostic = Decimal(0)
    attempts = 0
    for charge in charges:
        if type(charge.diagnostic) is not bool:
            raise TypeError("allocation must be explicit")
        reserve = money(charge.reservation_usd)
        if reserve < 3:
            reasons.add("invalid_reservation")
        if charge.actual_usd is None:
            reasons.add("unknown_exposure")  # Applies across week rollover too.
            amount = reserve
        else:
            amount = money(charge.actual_usd)
        try:
            start = date.fromisoformat(charge.week)
            if start.weekday() != 0 or start > local or start.isoformat() != charge.week:
                raise ValueError()
        except (TypeError, ValueError):
            reasons.add("invalid_week")
        if charge.week == week:
            weekly += amount
            if charge.diagnostic:
                diagnostic += amount
                attempts += 1
    if weekly + 3 > 150:
        reasons.add("weekly_budget")
    if diagnostic + 3 > 30:
        reasons.add("diagnostic_budget")
    if attempts >= 10:
        reasons.add("diagnostic_attempts")
    return tuple(sorted(reasons))


class Capture:
    """Bounded synthetic bytes in memory, never a private production audit store."""

    def __init__(self, *, limit: int = 100 * 1024 * 1024,
                 total_remaining: int = 2 * 1024 * 1024 * 1024):
        if type(limit) is not int or not 0 <= limit <= 100 * 1024 * 1024:
            raise ValueError("invalid Run capture cap")
        if type(total_remaining) is not int or not 0 <= total_remaining <= 2 * 1024**3:
            raise ValueError("invalid total capture capacity")
        self.limit = min(limit, total_remaining)
        self.data = bytearray()
        self.complete = True

    def append(self, data: bytes) -> bool:
        if not self.complete or len(data) > self.limit - len(self.data):
            self.complete = False
            return False
        self.data.extend(data)
        return True


LENGTHS = (9500, 11000, 12000, 13000, 14000)


def command_for(length: int) -> bytes:
    if length not in LENGTHS:
        raise ValueError("case not in the frozen grid")
    prefix = b"jira-as collaborate comment add OPS-1 -b '"
    return prefix + b"x" * (length - len(prefix) - 1) + b"'"


@dataclass(frozen=True)
class Receipt:
    case: int
    tool_id: str
    command_sha256: str
    stub_exit: int


class LengthProbe:
    """Inert ordered experiment; never sends command bytes to a shell or executable."""

    def __init__(self, lifecycle: Lifecycle):
        self.lifecycle = lifecycle
        self.index = 0
        self.hold = False
        self.results: list[str] = []
        self._issued: list[Receipt] = []
        self._tool_ids: set[str] = set()
        self._active: tuple[bytes, str] | None = None
        self.cleanup_actions: tuple[str, ...] = ()
        self._records = [{"case_bytes": n, "expected_command": self._command_record(command_for(n)),
                          "request": None, "dispatch": None, "observation": None,
                          "classification": "not_attempted"} for n in LENGTHS]

    @staticmethod
    def _command_record(command: bytes) -> dict:
        return {"bytes": len(command), "sha256": hashlib.sha256(command).hexdigest()}

    def begin(self, command: bytes, tool_id: str) -> None:
        """Record the tool request before permission resolution or stub entry."""
        self._check_work()
        if self._active is not None:
            self.hold = True
            raise ValueError("a case is already pending")
        if type(command) is not bytes or len(command) > max(LENGTHS):
            self.hold = True
            raise ValueError("invalid or oversized command data")
        if not isinstance(tool_id, str) or not tool_id or len(tool_id) > 200:
            self.hold = True
            raise ValueError("invalid tool id")
        if tool_id in self._tool_ids:
            self.hold = True
            raise ValueError("duplicate tool id")
        self._tool_ids.add(tool_id)
        self._active = (command, tool_id)
        self._records[self.index]["request"] = {
            "command": self._command_record(command), "tool_id": tool_id,
            "at": self.lifecycle.now}
        self._records[self.index]["classification"] = "pending"

    def dispatch(self, command: bytes, tool_id: str, *, stub_exit: int = 0) -> Receipt:
        self._check_work()
        if self._active is None:
            self.begin(command, tool_id)
        if command != command_for(LENGTHS[self.index]) or self._active != (command, tool_id):
            self.hold = True
            raise ValueError("edited, uncorrelated or out-of-order command")
        if type(stub_exit) is not int or not -(2**31) <= stub_exit < 2**31:
            self.hold = True
            raise ValueError("invalid stub exit")
        if any(r.case == self.index for r in self._issued):
            self.hold = True
            raise ValueError("duplicate case dispatch")
        receipt = Receipt(self.index, tool_id, hashlib.sha256(command).hexdigest(), stub_exit)
        self._issued.append(receipt)
        self._records[self.index]["dispatch"] = {
            "at": self.lifecycle.now, "tool_id": tool_id,
            "command_sha256": receipt.command_sha256, "stub_exit": stub_exit,
            "receipt_scope": "IN_MEMORY_ISSUED_HERE"}
        return receipt

    def observe(self, command: bytes, *, receipt: Receipt | None = None,
                native_decision: str | None = None, coverage_complete: bool = False,
                decision_reference: str | None = None) -> str:
        if type(coverage_complete) is not bool:
            self.hold = True
            raise TypeError("coverage must be an explicit boolean")
        if self.hold or self.index >= len(LENGTHS) or self._active is None:
            raise ValueError("no pending case to observe")
        if (type(command) is not bytes or len(command) > max(LENGTHS) or
                any(value is not None and (not isinstance(value, str) or len(value) > 200)
                    for value in (native_decision, decision_reference))):
            self.hold = True
            raise ValueError("invalid or oversized synthetic observation")
        issued = [r for r in self._issued if r.case == self.index]
        valid = any(r is receipt for r in issued)
        if native_decision in ("provider_refusal", "model_unavailable", "fallback"):
            result = "not_length_evidence"
            if not self.lifecycle.finished:
                self.cleanup_actions = self.lifecycle.advance(self.lifecycle.now, cancel=True)
        elif command != command_for(LENGTHS[self.index]) or command != self._active[0]:
            result = "invalid_case"
        else:
            if native_decision == "permission_denied_before_dispatch":
                result = ("permission_denied_no_dispatch" if coverage_complete and not issued
                          and receipt is None else "dispatch_unknown")
            elif native_decision is None and valid:
                result = "dispatched"
            else:
                result = "dispatch_unknown"
        self._records[self.index]["observation"] = {
            "command": self._command_record(command), "at": self.lifecycle.now,
            "synthetic_decision": native_decision, "decision_reference": decision_reference,
            "coverage_complete": coverage_complete,
            "supplied_receipt": "absent" if receipt is None else
                                "issued_here" if valid else "unrecognized"}
        self._records[self.index]["classification"] = result
        self.results.append(result)
        self.index += 1
        self._active = None
        if result not in ("dispatched", "permission_denied_no_dispatch"):
            self.hold = True
        return result

    def _check_work(self) -> None:
        if self.hold or self.index >= len(LENGTHS) or not self.lifecycle.work_allowed:
            raise ValueError("probe closed, held or beyond work deadline")

    def bracket(self) -> dict:
        if len(self.results) != len(LENGTHS) or self.hold:
            return {"status": "inconclusive"}
        accepted = [n for n, r in zip(LENGTHS, self.results) if r == "dispatched"]
        denied = [n for n, r in zip(LENGTHS, self.results)
                  if r == "permission_denied_no_dispatch"]
        if not accepted:
            return {"status": "all_denied"}
        if not denied:
            return {"status": "all_dispatched"}
        if max(accepted) > min(denied):
            return {"status": "nonmonotonic"}
        return {"status": "observed_bracket", "largest_dispatched": max(accepted),
                "smallest_denied": min(denied), "scope": "synthetic fixed-shape replay only"}

    def report(self) -> dict:
        """Snapshot bounded synthetic metadata; neither native proof nor dispatch authority."""
        return {"version": 1, "scope": "OFFLINE_LENGTH_RECORDS_ONLY", "native_launch": "CLOSED",
                "clock": "virtual_seconds", "receipt_authority": "in_memory_object_identity",
                "at": self.lifecycle.now, "hold": self.hold,
                "work_allowed": not self.hold and self.index < len(LENGTHS) and
                                self.lifecycle.work_allowed,
                "probe_cleanup_actions": list(self.cleanup_actions),
                "lifecycle": {"finished": self.lifecycle.finished,
                              "revoked": self.lifecycle.revoked,
                              "cleanup_at": self.lifecycle.cleanup_at,
                              "reasons": sorted(self.lifecycle.reasons)},
                "bracket": self.bracket(), "cases": deepcopy(self._records)}


@dataclass(frozen=True)
class Frame:
    at: float
    line: bytes | None = None
    exit_code: int | None = None
    reaped: bool = False
    pipes_closed: bool = False
    cancel: bool = False
    spawn_failure: bool = False

    def __post_init__(self) -> None:
        seconds(self.at)
        if any(type(value) is not bool for value in
               (self.reaped, self.pipes_closed, self.cancel, self.spawn_failure)):
            raise TypeError("frame observations must be explicit booleans")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise TypeError("exit code must be an integer or unknown")
        if self.line is not None and type(self.line) is not bytes:
            raise TypeError("synthetic transcript input must be bytes")


@dataclass(frozen=True)
class ReplayResult:
    outcome: Outcome
    actions: tuple[tuple[float, tuple[str, ...]], ...]
    audit_complete: bool
    evidence_sha256: str
    scope: str = "OFFLINE_REPLAY_ONLY"
    native_launch: str = "CLOSED"


def replay(frames: tuple[Frame, ...], requested_model: str, *,
           capture_limit: int = 100 * 1024 * 1024) -> ReplayResult:
    """Execute finite synthetic observations; never infer containment from EOF."""
    if len(frames) > 10000:
        raise ValueError("too many replay frames")
    lifecycle = Lifecycle()
    transcript = Transcript(requested_model)
    capture = Capture(limit=capture_limit)
    actions = []
    exit_code = None

    def advance_before(target: float) -> None:
        # A virtual clock runs scheduled transitions even when the stream is silent.
        while not lifecycle.finished:
            boundary = (270 if lifecycle.cleanup_at is None else
                        lifecycle.end_at if lifecycle.killed else lifecycle.kill_at)
            if boundary >= target:
                return
            actions.append((boundary, lifecycle.advance(boundary)))

    for frame in frames:
        if lifecycle.finished:
            raise ValueError("evidence after closed lifecycle")
        at = seconds(frame.at)
        if at < lifecycle.now:
            raise ValueError("clock moved backwards")
        advance_before(at)
        if lifecycle.finished:
            break
        if at > lifecycle.end_at:
            actions.append((at, lifecycle.advance(at)))
            break
        if frame.spawn_failure:
            if lifecycle.now != 0 or exit_code is not None or transcript.count:
                raise ValueError("spawn failure after process activity")
            lifecycle.reasons.add("spawn_failure")
            lifecycle.finished = True
            lifecycle.revoked = True
            actions.append((frame.at, ("revoke", "hold")))
            break
        if frame.line is not None:
            if capture.append(frame.line):
                transcript.feed(frame.line)
            else:
                transcript.reasons.add("capture_limit")
                transcript.stop_requested = True
        if frame.exit_code is not None:
            if exit_code is not None and exit_code != frame.exit_code:
                transcript.reasons.add("malformed_evidence")
            exit_code = frame.exit_code
        # Discovery with fully completed process evidence is retrospective.
        complete = exit_code is not None and frame.reaped and frame.pipes_closed
        cancel = frame.cancel or (transcript.stop_requested and not complete)
        changed = lifecycle.advance(frame.at, cancel=cancel,
                                    parent_exited=exit_code is not None,
                                    reaped=frame.reaped, pipes_closed=frame.pipes_closed)
        if changed:
            actions.append((frame.at, changed))
    if not lifecycle.finished:
        # Enter timeout before computing the final deadline if no cleanup began.
        advance_before(lifecycle.end_at)
        at = lifecycle.end_at
        actions.append((at, lifecycle.advance(at)))
    return ReplayResult(transcript.outcome(exit_code, lifecycle.reasons), tuple(actions),
                        capture.complete, hashlib.sha256(capture.data).hexdigest())
