"""Real local SQLite transactions/processes with synthetic receipts; no provider access."""

import multiprocessing
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from prototype.run_timing import fixture_ledger
from prototype.run_timing.fixture_ledger import (
    FixtureLedger,
    LedgerUnavailable,
    run_budgeted_fixture,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path):
    return FixtureLedger.create(tmp_path / 'fixture.db')


def _reserve_process(path, attempt, gate, queue):
    gate.wait(5)
    result = FixtureLedger(path).reserve(attempt, NOW, billing_current=True)
    queue.put(result.accepted)


def _crash_process(path, phase):
    ledger = FixtureLedger(path)
    if phase != 'uncommitted':
        assert ledger.reserve('crash', NOW, billing_current=True).accepted
        if phase == 'claimed':
            assert ledger.claim_launch('crash', NOW, billing_current=True).accepted
    else:
        with ledger._transaction() as connection:
            connection.execute("INSERT INTO attempts(id,week,created_at) VALUES(?,?,?)",
                               ('crash', '2026-09-21', NOW.isoformat()))
            os._exit(17)
    os._exit(17)


def test_initialization_is_exclusive_and_missing_store_does_not_become_zero(tmp_path):
    path = tmp_path / 'fixture.db'
    with pytest.raises(LedgerUnavailable):
        FixtureLedger(path).snapshot(NOW)
    assert not path.exists()
    ledger = FixtureLedger.create(path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        FixtureLedger.create(path)
    assert path.read_bytes() == before
    assert ledger.snapshot(NOW).native_launch == 'CLOSED'
    assert path.stat().st_mode & 0o777 == 0o600


def test_corrupt_or_wrong_scope_store_holds(tmp_path, ledger):
    corrupt = tmp_path / 'corrupt.db'
    corrupt.write_bytes(b'not a database')
    with pytest.raises(LedgerUnavailable):
        FixtureLedger(corrupt).snapshot(NOW)
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("UPDATE control SET value='real' WHERE key='scope'")
    with pytest.raises(LedgerUnavailable):
        ledger.reserve('attempt', NOW, billing_current=True)


def test_reservation_survives_reopen_and_missing_actual_holds(ledger):
    assert ledger.reserve('one', NOW, billing_current=True).accepted
    reopened = FixtureLedger(ledger.path)
    view = reopened.snapshot(NOW)
    assert (view.attempts, view.unresolved, view.diagnostic_micros) == (1, 1, 3_000_000)
    assert reopened.reserve('two', NOW, billing_current=True).reasons == ('unknown_exposure',)
    assert reopened.reserve('one', NOW, billing_current=True).reasons == ('attempt_exists',)


def test_launch_claim_is_once_and_reserved_before_claim(ledger):
    assert not ledger.claim_launch('missing', NOW, billing_current=True).accepted
    assert ledger.reserve('one', NOW, billing_current=True).accepted
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: ledger.claim_launch('one', NOW, billing_current=True),
                                range(8)))
    assert sum(result.accepted for result in results) == 1
    assert ledger.snapshot(NOW).unresolved == 1


def test_concurrent_processes_cannot_both_admit_unknown_exposure(ledger):
    ctx = multiprocessing.get_context('spawn')
    gate, queue = ctx.Event(), ctx.Queue()
    children = [ctx.Process(target=_reserve_process, args=(ledger.path, str(i), gate, queue))
                for i in range(4)]
    for child in children:
        child.start()
    gate.set()
    try:
        results = [queue.get(timeout=10) for _ in children]
        assert sum(results) == 1
    finally:
        for child in children:
            child.join(10)
            if child.is_alive():
                child.kill()
                child.join(2)
        queue.close()
    assert all(child.exitcode == 0 for child in children)
    assert ledger.snapshot(NOW).attempts == 1


@pytest.mark.parametrize('phase', ['uncommitted', 'reserved', 'claimed'])
def test_actual_process_crash_windows(ledger, phase):
    ctx = multiprocessing.get_context('spawn')
    child = ctx.Process(target=_crash_process, args=(ledger.path, phase))
    child.start()
    child.join(10)
    if child.is_alive():
        child.kill()
        child.join(2)
    assert child.exitcode == 17
    view = FixtureLedger(ledger.path).snapshot(NOW)
    assert view.attempts == int(phase != 'uncommitted')
    assert view.unresolved == int(phase != 'uncommitted')
    if phase == 'claimed':
        assert not ledger.claim_launch('crash', NOW, billing_current=True).accepted


def test_receipts_replace_reservations_without_double_counting(ledger):
    ledger.reserve('one', NOW, billing_current=True)
    ledger.claim_launch('one', NOW, billing_current=True)
    assert ledger.reconcile('one', 'bill-1', '0.123456') == 'recorded'
    assert ledger.reconcile('one', 'bill-1', Decimal('0.1234560')) == 'duplicate'
    view = ledger.snapshot(NOW)
    assert view.diagnostic_micros == view.weekly_micros == 123456
    assert view.unresolved == 0
    assert not ledger.claim_launch('one', NOW, billing_current=True).accepted


@pytest.mark.parametrize('same_id', [True, False])
def test_conflicting_actuals_persist_hold_without_overwriting(ledger, same_id):
    ledger.reserve('one', NOW, billing_current=True)
    ledger.reconcile('one', 'bill', 1)
    assert ledger.reconcile('one', 'bill' if same_id else 'other-bill', 2) == 'conflict_hold'
    view = FixtureLedger(ledger.path).snapshot(NOW)
    assert view.hold == 'receipt_conflict' and view.weekly_micros == 1_000_000
    assert not ledger.reserve('two', NOW, billing_current=True).accepted


def test_receipt_identity_cannot_be_reused_for_other_allocations(ledger):
    ledger.reserve('one', NOW, billing_current=True)
    ledger.reconcile('one', 'bill', 1)
    assert ledger.record_other_actual('bill', '2026-09-21', 1) == 'conflict_hold'
    assert ledger.snapshot(NOW).weekly_micros == 1_000_000


def test_unknown_old_week_survives_rollover_and_reconciles_to_original_week(ledger):
    ledger.reserve('one', NOW, billing_current=True)
    next_week = NOW + timedelta(days=7)
    assert not ledger.reserve('two', next_week, billing_current=True).accepted
    assert not ledger.claim_launch('one', next_week, billing_current=True).accepted
    assert ledger.snapshot(next_week).unresolved == 1
    ledger.reconcile('one', 'late-bill', 4)
    assert ledger.snapshot(NOW).weekly_micros == 4_000_000
    assert ledger.snapshot(next_week).weekly_micros == 0
    assert ledger.reserve('two', next_week, billing_current=True).accepted


def test_week_uses_new_york_boundary_and_rejects_clock_regression(ledger):
    sunday_ny = datetime(2026, 9, 21, 1, tzinfo=UTC)
    assert ledger.reserve('one', sunday_ny, billing_current=True).accepted
    assert ledger.snapshot(sunday_ny).week == '2026-09-14'
    ledger.reconcile('one', 'bill', 0)
    assert 'clock_regression' in ledger.reserve('old', sunday_ny - timedelta(seconds=1),
                                                billing_current=True).reasons
    assert ledger.reserve('two', NOW, billing_current=True).accepted


def test_exact_diagnostic_limit_attempt_limit_and_above_reservation_cost(ledger):
    for i in range(10):
        assert ledger.reserve(f'a{i}', NOW, billing_current=True).accepted
        assert ledger.reconcile(f'a{i}', f'bill{i}', 3) == 'recorded'
    denied = ledger.reserve('eleven', NOW, billing_current=True)
    assert {'diagnostic_attempts', 'diagnostic_budget'} <= set(denied.reasons)
    assert ledger.snapshot(NOW).weekly_micros == 30_000_000


def test_weekly_cost_and_receipt_arrival_between_reserve_and_launch(ledger):
    ledger.record_other_actual('other', '2026-09-21', 147)
    assert ledger.reserve('one', NOW, billing_current=True).accepted
    ledger.record_other_actual('late', '2026-09-21', '0.000001')
    assert 'weekly_budget' in ledger.claim_launch('one', NOW, billing_current=True).reasons
    assert ledger.snapshot(NOW).unresolved == 1


def test_large_actuals_are_not_capped_at_reservation(ledger):
    ledger.reserve('one', NOW, billing_current=True)
    ledger.reconcile('one', 'large', 200)
    view = ledger.snapshot(NOW)
    assert view.weekly_micros == 200_000_000
    assert {'diagnostic_budget', 'weekly_budget'} <= set(
        ledger.reserve('two', NOW, billing_current=True).reasons)


@pytest.mark.parametrize('amount', [True, None, 0.1, '-1', 'NaN', 'Infinity',
                                   '0.0000001', '1.000000000000000000000000000001', '1e-100000'])
def test_invalid_actual_cannot_release_reservation(ledger, amount):
    ledger.reserve('one', NOW, billing_current=True)
    with pytest.raises((TypeError, ValueError)):
        ledger.reconcile('one', 'invalid', amount)
    assert ledger.snapshot(NOW).unresolved == 1


def test_capacity_refuses_new_records_without_deleting_unknowns(ledger, monkeypatch):
    monkeypatch.setattr(fixture_ledger, 'MAX_RECORDS', 2)
    assert ledger.reserve('one', NOW, billing_current=True).accepted
    assert ledger.record_other_actual('late', '2026-09-21', 0) == 'recorded'
    assert ledger.reconcile('one', 'bill', 0) == 'capacity_hold'
    view = ledger.snapshot(NOW)
    assert view.unresolved == 1 and view.hold == 'ledger_capacity'


def test_capacity_admission_requires_room_for_attempt_and_receipt(ledger, monkeypatch):
    monkeypatch.setattr(fixture_ledger, 'MAX_RECORDS', 2)
    assert ledger.record_other_actual('other', '2026-09-21', 0) == 'recorded'
    assert ledger.reserve('one', NOW, billing_current=True).reasons == ('ledger_capacity',)
    assert ledger.snapshot(NOW).attempts == 0


@pytest.mark.parametrize('first_hold', ['receipt_conflict', 'ledger_capacity'])
def test_first_hold_reason_survives_subsequent_failure(ledger, monkeypatch, first_hold):
    monkeypatch.setattr(fixture_ledger, 'MAX_RECORDS', 1)
    assert ledger.record_other_actual('other', '2026-09-21', 0) == 'recorded'

    def conflict():
        assert ledger.record_other_actual('other', '2026-09-21', 1) == 'conflict_hold'

    def capacity():
        assert ledger.record_other_actual('extra', '2026-09-21', 0) == 'capacity_hold'

    actions = [conflict, capacity] if first_hold == 'receipt_conflict' else [capacity, conflict]
    for action in actions:
        action()
    view = ledger.snapshot(NOW)
    assert view.hold == first_hold and view.weekly_micros == 0
    assert first_hold in ledger.reserve('denied', NOW, billing_current=True).reasons


def test_billing_readiness_is_explicit_and_rechecked(ledger):
    assert not ledger.reserve('no-bill', NOW, billing_current=False).accepted
    with pytest.raises(TypeError):
        ledger.reserve('bad', NOW, billing_current='true')
    ledger.reserve('one', NOW, billing_current=True)
    assert not ledger.claim_launch('one', NOW, billing_current=False).accepted


def test_fixed_fixture_launch_is_claimed_before_spawn_and_cannot_repeat(ledger, tmp_path, monkeypatch):
    real_run = fixture_ledger.run_fixture
    calls = []

    def observed_launch(*args, **kwargs):
        with sqlite3.connect(ledger.path) as connection:
            assert connection.execute("SELECT claimed FROM attempts WHERE id='one'").fetchone() == (1,)
        calls.append(1)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(fixture_ledger, 'run_fixture', observed_launch)
    result = run_budgeted_fixture(ledger, 'success', tmp_path, 'one', NOW,
                                  billing_current=True, time_scale=0.01)
    assert result.outcome.execution == 'completed' and result.native_launch == 'CLOSED'
    assert ledger.snapshot(NOW).unresolved == 1  # Successful fixture exit is not a bill.
    with pytest.raises(LedgerUnavailable):
        run_budgeted_fixture(ledger, 'success', tmp_path, 'one', NOW,
                              billing_current=True, time_scale=0.01)
    assert calls == [1]


def test_launch_exception_preserves_claim_and_unknown_exposure(ledger, tmp_path, monkeypatch):
    def failed_launch(*args, **kwargs):
        raise OSError('synthetic launch failure')
    monkeypatch.setattr(fixture_ledger, 'run_fixture', failed_launch)
    with pytest.raises(OSError):
        run_budgeted_fixture(ledger, 'success', tmp_path, 'one', NOW, billing_current=True)
    reopened = FixtureLedger(ledger.path)
    assert reopened.snapshot(NOW).unresolved == 1
    assert not reopened.claim_launch('one', NOW, billing_current=True).accepted
    assert not reopened.reserve('two', NOW, billing_current=True).accepted


@pytest.mark.parametrize('scenario,attempt,scale', [
    ('success', 'Uppercase', 0.01), ('success', 'a' * 65, 0.01),
    ('claude', 'one', 0.01), ('success', '../path', 0.01),
    ('success', 'one', 1.1), ('success', 'one', float('nan')),
])
def test_invalid_fixture_request_cannot_consume_reservation(ledger, tmp_path, scenario, attempt, scale):
    with pytest.raises(ValueError):
        run_budgeted_fixture(ledger, scenario, tmp_path, attempt, NOW,
                              billing_current=True, time_scale=scale)
    view = ledger.snapshot(NOW)
    assert view.attempts == view.unresolved == view.diagnostic_micros == 0


def test_busy_database_does_not_grant_admission_or_silently_retry(ledger):
    with ledger._transaction(), ThreadPoolExecutor(max_workers=1) as pool:
        task = pool.submit(ledger.reserve, 'blocked', NOW, billing_current=True)
        with pytest.raises(LedgerUnavailable):
            task.result(timeout=5)
    assert ledger.snapshot(NOW).attempts == 0
    assert ledger.reserve('after-lock', NOW, billing_current=True).accepted
