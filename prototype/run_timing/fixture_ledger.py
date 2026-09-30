"""Durable *synthetic* diagnostic accounting. Never an authority for real billing.

Each operation opens an existing database and serializes mutation with BEGIN IMMEDIATE.
Only explicit fixture initialization may create a store. Missing/corrupt stores hold,
not zero. Paths, clock and receipt inputs belong to a trusted local fixture operator.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

from .outcomes import money
from .process_fixture import ProcessResult, run_fixture, validate_fixture_request

SCOPE = "SYNTHETIC_DIAGNOSTIC_LEDGER_ONLY"
RESERVATION = 3_000_000
DIAGNOSTIC_LIMIT = 30_000_000
WEEKLY_LIMIT = 150_000_000
MAX_RECORDS = 10000

SCHEMA = """
BEGIN IMMEDIATE;
CREATE TABLE control (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE attempts (
    id TEXT PRIMARY KEY, week TEXT NOT NULL, created_at TEXT NOT NULL,
    claimed INTEGER NOT NULL DEFAULT 0 CHECK(claimed IN (0,1))
) STRICT;
CREATE TABLE receipts (
    id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE REFERENCES attempts(id),
    week TEXT NOT NULL, micros INTEGER NOT NULL CHECK(micros >= 0)
) STRICT;
INSERT INTO control VALUES ('version','1'), ('scope','SYNTHETIC_DIAGNOSTIC_LEDGER_ONLY'),
    ('hold',''), ('last_admitted_at','');
COMMIT;
"""


class LedgerUnavailable(RuntimeError):
    """Admission is closed because accounting cannot be read or committed safely."""


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}", value):
        raise ValueError("invalid fixture identifier")
    return value


def _micros(value: Decimal | str | int) -> int:
    if type(value) not in (Decimal, str, int):
        raise TypeError("use exact decimal amounts, not floats")
    amount = money(value)
    if amount > 1_000_000:
        raise ValueError("fixture amount outside supported range")
    if amount == 0:
        return 0
    if len(amount.as_tuple().digits) > 128 or amount.as_tuple().exponent < -128:
        raise ValueError("fixture amount precision outside supported range")
    numerator, denominator = amount.as_integer_ratio()
    scaled = numerator * 1_000_000
    if scaled % denominator:
        raise ValueError("amount has fractions of a microdollar")
    return scaled // denominator


def _time(now: datetime) -> tuple[str, str]:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("aware fixture timestamp required")
    local = now.astimezone(ZoneInfo("America/New_York")).date()
    week = (local - timedelta(days=local.weekday())).isoformat()
    return week, now.astimezone(UTC).isoformat(timespec="microseconds")


def _week(value: str) -> str:
    parsed = date.fromisoformat(value)
    if parsed.weekday() != 0 or parsed.isoformat() != value:
        raise ValueError("week must be the canonical Monday date")
    return value


@dataclass(frozen=True)
class Admission:
    accepted: bool
    reasons: tuple[str, ...]
    scope: str = SCOPE
    native_launch: str = "CLOSED"


@dataclass(frozen=True)
class Snapshot:
    week: str
    diagnostic_micros: int
    weekly_micros: int
    attempts: int
    unresolved: int
    hold: str
    scope: str = SCOPE
    native_launch: str = "CLOSED"


class FixtureLedger:
    def __init__(self, path: Path):
        self.path = Path(path).absolute()

    @classmethod
    def create(cls, path: Path) -> FixtureLedger:
        """Explicit empty fixture initialization. Never call this to recover lost accounting."""
        path = Path(path).absolute()
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        # Initialization failure leaves a non-admissible file; do not erase ambiguity.
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(SCHEMA)
        finally:
            connection.close()
        return cls(path)

    @contextmanager
    def _transaction(self):
        connection = None
        try:
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                         timeout=2, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise LedgerUnavailable("unsupported fixture journal mode")
            connection.execute("BEGIN IMMEDIATE")
            meta = dict(connection.execute("SELECT key,value FROM control"))
            if meta.get("version") != "1" or meta.get("scope") != SCOPE:
                raise LedgerUnavailable("fixture ledger identity mismatch")
            if set(meta) != {"version", "scope", "hold", "last_admitted_at"}:
                raise LedgerUnavailable("incomplete fixture ledger metadata")
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise LedgerUnavailable("fixture ledger integrity check failed")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            raise LedgerUnavailable("fixture ledger unavailable; admission held") from exc
        finally:
            if connection is not None:
                connection.close()  # Rolls back any incomplete transaction, including exceptions.

    @staticmethod
    def _snapshot(connection, week: str) -> Snapshot:
        row = connection.execute("""
            SELECT count(*) AS attempts, coalesce(sum(coalesce(r.micros, ?)),0) AS total
            FROM attempts a LEFT JOIN receipts r ON r.attempt_id=a.id WHERE a.week=?
        """, (RESERVATION, week)).fetchone()
        other = connection.execute("""
            SELECT coalesce(sum(micros),0) FROM receipts WHERE attempt_id IS NULL AND week=?
        """, (week,)).fetchone()[0]
        unknown = connection.execute("""
            SELECT count(*) FROM attempts a LEFT JOIN receipts r ON r.attempt_id=a.id
            WHERE r.id IS NULL
        """).fetchone()[0]
        hold = connection.execute("SELECT value FROM control WHERE key='hold'").fetchone()[0]
        return Snapshot(week, row["total"], row["total"] + other, row["attempts"], unknown, hold)

    @staticmethod
    def _gates(connection, week, stamp, billing_current, *, own_pending=False, extra=0):
        if type(billing_current) is not bool:
            raise TypeError("billing readiness must be an explicit fixture boolean")
        view = FixtureLedger._snapshot(connection, week)
        reasons = []
        if not billing_current:
            reasons.append("billing_not_current")
        if view.hold:
            reasons.append(view.hold)
        if view.unresolved > int(own_pending):
            reasons.append("unknown_exposure")
        last = connection.execute(
            "SELECT value FROM control WHERE key='last_admitted_at'").fetchone()[0]
        if stamp < last:
            reasons.append("clock_regression")
        if view.diagnostic_micros + extra > DIAGNOSTIC_LIMIT:
            reasons.append("diagnostic_budget")
        if view.weekly_micros + extra > WEEKLY_LIMIT:
            reasons.append("weekly_budget")
        if view.attempts + int(extra > 0) > 10:
            reasons.append("diagnostic_attempts")
        return reasons

    @staticmethod
    def _capacity(connection, needed=1) -> bool:
        count = connection.execute("""
            SELECT (SELECT count(*) FROM attempts)+(SELECT count(*) FROM receipts)
        """).fetchone()[0]
        return count + needed <= MAX_RECORDS

    def snapshot(self, now: datetime) -> Snapshot:
        week, _ = _time(now)
        with self._transaction() as connection:
            return self._snapshot(connection, week)

    def reserve(self, attempt_id: str, now: datetime, *, billing_current: bool) -> Admission:
        attempt_id = _identifier(attempt_id)
        week, stamp = _time(now)
        with self._transaction() as connection:
            if connection.execute("SELECT 1 FROM attempts WHERE id=?", (attempt_id,)).fetchone():
                return Admission(False, ("attempt_exists",))
            reasons = self._gates(connection, week, stamp, billing_current, extra=RESERVATION)
            if not self._capacity(connection, needed=2):
                reasons.append("ledger_capacity")
            if reasons:
                return Admission(False, tuple(reasons))
            connection.execute("INSERT INTO attempts(id,week,created_at) VALUES(?,?,?)",
                               (attempt_id, week, stamp))
            connection.execute("UPDATE control SET value=? WHERE key='last_admitted_at'", (stamp,))
            return Admission(True, ())

    def claim_launch(self, attempt_id: str, now: datetime, *, billing_current: bool) -> Admission:
        attempt_id = _identifier(attempt_id)
        week, stamp = _time(now)
        with self._transaction() as connection:
            row = connection.execute("""
                SELECT a.week,a.claimed,r.id AS receipt FROM attempts a
                LEFT JOIN receipts r ON r.attempt_id=a.id WHERE a.id=?
            """, (attempt_id,)).fetchone()
            if row is None or row["claimed"] or row["receipt"] is not None:
                return Admission(False, ("not_unclaimed_reservation",))
            reasons = self._gates(connection, week, stamp, billing_current, own_pending=True)
            if row["week"] != week:
                reasons.append("reservation_week_changed")
            if reasons:
                return Admission(False, tuple(reasons))
            connection.execute("UPDATE attempts SET claimed=1 WHERE id=?", (attempt_id,))
            connection.execute("UPDATE control SET value=? WHERE key='last_admitted_at'", (stamp,))
            return Admission(True, ())

    def reconcile(self, attempt_id: str, receipt_id: str, actual_usd: Decimal | str | int) -> str:
        """Supply a synthetic final actual, never a transcript estimate or real provider claim."""
        attempt_id, receipt_id = _identifier(attempt_id), _identifier(receipt_id)
        amount = _micros(actual_usd)
        with self._transaction() as connection:
            row = connection.execute("SELECT week FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            if row is None:
                raise ValueError("unknown attempt")
            return self._receipt(connection, receipt_id, attempt_id, row["week"], amount)

    def record_other_actual(self, receipt_id: str, week: str, actual_usd: Decimal | str | int) -> str:
        """Synthetic actual for another model allocation, not a cloud or diagnostic charge."""
        receipt_id, week, amount = _identifier(receipt_id), _week(week), _micros(actual_usd)
        with self._transaction() as connection:
            return self._receipt(connection, receipt_id, None, week, amount)

    @staticmethod
    def _receipt(connection, receipt_id, attempt_id, week, amount):
        old = connection.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
        if old is not None and (old["attempt_id"], old["week"], old["micros"]) == (
                attempt_id, week, amount):
            return "duplicate"
        existing = (attempt_id is not None and connection.execute(
            "SELECT 1 FROM receipts WHERE attempt_id=?", (attempt_id,)).fetchone())
        if old is not None or existing:
            connection.execute(
                "UPDATE control SET value='receipt_conflict' WHERE key='hold' AND value=''")
            return "conflict_hold"  # Commit this hold; never silently replace a prior actual.
        if not FixtureLedger._capacity(connection):
            connection.execute(
                "UPDATE control SET value='ledger_capacity' WHERE key='hold' AND value=''")
            return "capacity_hold"
        connection.execute("INSERT INTO receipts VALUES(?,?,?,?)",
                           (receipt_id, attempt_id, week, amount))
        return "recorded"


def run_budgeted_fixture(ledger: FixtureLedger, scenario: str, output_parent: Path,
                         attempt_id: str, now: datetime, *, billing_current: bool,
                         time_scale: float = 1.0, capture_limit: int = 1024 * 1024,
                         cancel: threading.Event | None = None) -> ProcessResult:
    """Durably reserve, then durably claim before one fixed fixture; never auto-reconcile."""
    validate_fixture_request(scenario, attempt_id, time_scale=time_scale,
                             capture_limit=capture_limit, cancel=cancel)
    reserved = ledger.reserve(attempt_id, now, billing_current=billing_current)
    if not reserved.accepted:
        raise LedgerUnavailable("fixture reservation denied: " + ",".join(reserved.reasons))
    claimed = ledger.claim_launch(attempt_id, now, billing_current=billing_current)
    if not claimed.accepted:
        raise LedgerUnavailable("fixture launch held: " + ",".join(claimed.reasons))
    # Exceptions/crashes retain the claimed reservation. A repeated call cannot relaunch it.
    return run_fixture(scenario, output_parent, attempt_id, time_scale=time_scale,
                       capture_limit=capture_limit, cancel=cancel)
