"""Real-thread race tests for the atomic dispatch gate (plan revision 2, R1-R11).

These tests use real ``threading`` primitives, not a single-thread ``FakeClock``
narrative, to exercise the lock hierarchy (``G`` then ``R``, and ``G`` then
``L``) and the two linearization points (``admit``/L1, ``begin_write``/L2)
under genuine concurrency. ``BlockableClock`` wraps the shared base clock and
is used only as the *ledger's* clock, so a test can widen the window between
an authorizing check and its ledger consequence -- legal only in tests (see
the plan's "Clock contract"). Helpers (``new_system``, ``install``,
``do_reserve``, ``reserve_and_admit``, golden fixtures, ``assert_error``) are
reused from ``tests.test_forwarder_dispatch`` so every scenario here observes
the same construction rules Implementer A's deterministic tests do.
"""

from __future__ import annotations

import os
import queue
import socket
import threading
import time
from dataclasses import dataclass

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox.forwarder_control import ForwarderControl, authenticate_receiver
from grafana_jsm_sandbox.forwarder_control_protocol import recv_frame, send_frame
from grafana_jsm_sandbox.forwarder_dispatch import DispatchGate
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_leases import HEARTBEAT_SECONDS, LeaseError, LeaseRegistry
from grafana_jsm_sandbox.forwarder_receipts import ReceiptLedger
from tests.test_forwarder_dispatch import (
    BOOT,
    FakeClock,
    assert_error,
    do_reserve,
    install,
    make_routed,
    reserve_and_admit,
    snapshot_from_worker,
)
from tests.test_forwarder_routes import golden_manifest

JOIN_TIMEOUT = 5.0
CONTROL_SECRET = b"r" * 32


# --- shared threading helpers ------------------------------------------------


@dataclass
class _ThreadResult:
    value: object = None
    error: BaseException | None = None


def _call_in_thread(fn):
    """Run ``fn`` on a fresh thread; return (thread, result) without joining."""
    result = _ThreadResult()

    def runner():
        try:
            result.value = fn()
        except BaseException as exc:  # noqa: BLE001 - the test asserts on this directly.
            result.error = exc

    thread = threading.Thread(target=runner)
    thread.start()
    return thread, result


def _join(thread):
    thread.join(JOIN_TIMEOUT)
    assert not thread.is_alive(), "deadlock watchdog: a thread failed to terminate"


class BlockableClock:
    """A clock wrapper whose next call, once armed, blocks until released.

    This widens the race window around one ledger transition; it is legal
    only in tests (see the plan's Clock contract). The base clock is read
    only at the moment the block is released, exactly like a real caller
    that happened to be delayed.
    """

    def __init__(self, base):
        self._base = base
        self._state_lock = threading.Lock()
        self._armed = False
        self._entered = threading.Event()
        self._release = threading.Event()

    def arm(self) -> None:
        with self._state_lock:
            self._armed = True
        self._entered.clear()
        self._release.clear()

    def wait_entered(self, timeout: float = JOIN_TIMEOUT) -> None:
        assert self._entered.wait(timeout), "the armed clock call never happened"

    def release(self) -> None:
        self._release.set()

    def __call__(self) -> float:
        with self._state_lock:
            fire = self._armed
            if fire:
                self._armed = False
        if fire:
            self._entered.set()
            assert self._release.wait(JOIN_TIMEOUT), "clock block was never released"
        return self._base()


class CounterClock:
    """A strictly increasing, thread-safe clock: each call bumps a counter.

    Used where many real threads must share one monotonic domain without a
    test manually sequencing every clock read (R8-R10).
    """

    def __init__(self, start: float = 1_000.0, step: float = 1e-4):
        self._value = start
        self._step = step
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            self._value += self._step
            return self._value


def new_blockable_system(base=None):
    """Like ``tests.test_forwarder_dispatch.new_system``, but the ledger's
    clock is a ``BlockableClock`` wrapping the shared base clock, so a test
    can pause a thread inside one ledger transition.
    """
    base = base or FakeClock()
    registry = LeaseRegistry(clock=base)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger_clock = BlockableClock(base)
    ledger = ReceiptLedger(generation=registry.generation, clock=ledger_clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=base)
    return gate, registry, ledger, base, ledger_clock


def _install_with_counter_clock(gate, registry, clock, *, ttl=250.0):
    """Install one active lease using a plain ``CounterClock`` (no ``.value``)."""
    manifest = golden_manifest()
    grant = registry.register(
        run_id="run-1", attempt_id="attempt-1", receiver_boot_id=BOOT, service="jira",
        scope_digest=manifest.digest, expires_at=clock() + ttl, generation=registry.generation,
    )
    registry.activate(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                       generation=registry.generation, launch_at=clock())
    entry = gate.install_scope(grant=grant, manifest=manifest)
    return grant, entry


# --- R1 / R1b / R2 / R3 / R4 / R5 / R6: admit/fence races around retirement --


def _admit_then_retire_then_fence(
    *, retire, base_clock_advance=1.0, closeout_state_while_paused="draining",
    final_closeout_state="quiescent",
):
    """Shared shape for R1-R6.

    Thread A pauses inside ``begin_connect`` (the ledger call right after its
    admit check). While it is paused, ``retire`` runs a retirement that is
    ordered after A's check but before A's fence. A concurrent closeout (C)
    blocks on ``G`` the whole time A holds it, then -- once A is released --
    observes the in-flight entry. A's own fence then reflects the retirement.
    """
    gate, registry, _ledger, clock, ledger_clock = new_blockable_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)

    ledger_clock.arm()
    admit_thread, admit_result = _call_in_thread(
        lambda: gate.admit(handle, sentinel=grant.sentinel)
    )
    ledger_clock.wait_entered()

    # So that admitted_at < the retirement's observed_at is meaningful, not
    # merely equal on an unmoved FakeClock.
    clock.advance(base_clock_advance)

    closeout_thread, closeout_result = _call_in_thread(lambda: gate.closeout(grant.lease_id))
    time.sleep(0.2)
    assert closeout_thread.is_alive(), "closeout must block on G while A holds it"

    retired_at = retire(registry, grant, clock)

    ledger_clock.release()
    _join(admit_thread)
    assert admit_result.error is None, admit_result.error
    outcome = admit_result.value
    assert outcome.code == "admitted"
    admission = outcome.admission
    assert admission.admitted_at < retired_at

    _join(closeout_thread)
    assert closeout_result.error is None, closeout_result.error
    interim = closeout_result.value
    assert interim.closeout_state == closeout_state_while_paused
    if closeout_state_while_paused == "draining":
        assert interim.in_flight == 1

    write_outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert write_outcome.code != "write_admitted"
    assert write_outcome.denial.dispatch_state == "FAILED"
    assert write_outcome.denial.reason == "connect_failed"

    final = gate.closeout(grant.lease_id)
    assert final.closeout_state == final_closeout_state


def _direct_revoke(registry, grant, clock):
    receipt = registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                               generation=registry.generation, reason="operator_cancel")
    return receipt.observed_at


def test_r1_admit_paused_then_revoke_races_ahead_of_fence():
    _admit_then_retire_then_fence(retire=_direct_revoke)


def test_r1b_write_fence_paused_then_revoke_write_still_completes():
    gate, registry, _ledger, clock, ledger_clock = new_blockable_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=30.0)

    ledger_clock.arm()
    write_thread, write_result = _call_in_thread(
        lambda: gate.begin_write(admission, sentinel=grant.sentinel)
    )
    ledger_clock.wait_entered()
    clock.advance(1.0)

    closeout_thread, closeout_result = _call_in_thread(lambda: gate.closeout(grant.lease_id))
    time.sleep(0.2)
    assert closeout_thread.is_alive()

    revoke_receipt = registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                                      generation=registry.generation, reason="operator_cancel")

    ledger_clock.release()
    _join(write_thread)
    assert write_result.error is None, write_result.error
    write_outcome = write_result.value
    # The fence's own lease check already ran (and passed) before the pause,
    # so the write proceeds even though the lease is revoked by the time the
    # ledger transition (begin_dispatch) actually lands.
    assert write_outcome.code == "write_admitted"
    assert admission.admitted_at < revoke_receipt.observed_at

    _join(closeout_thread)
    assert closeout_result.error is None, closeout_result.error
    draining = closeout_result.value
    assert draining.closeout_state == "draining"
    assert draining.in_flight == 1

    receipt = gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                           upstream_response=ParsedResponse(200, b"{}"))
    assert receipt.dispatch_state == "TRANSPORT_CONFIRMED"

    final = gate.closeout(grant.lease_id)
    assert final.closeout_state == "quiescent"


def _control_revoke(registry, grant, clock, *, reason="operator_cancel"):
    """Revoke ``grant`` through a real ``ForwarderControl`` session over a
    ``socketpair``, authenticated with ``authenticate_receiver``.
    """
    control = ForwarderControl(registry, receiver_uid=os.geteuid(),
                                control_secret=CONTROL_SECRET, timeout=JOIN_TIMEOUT)
    client, server = socket.socketpair()
    outcomes: queue.Queue = queue.Queue()
    worker = threading.Thread(target=lambda: outcomes.put(control.serve_connection(server)))
    worker.start()
    try:
        authenticate_receiver(client, control_secret=CONTROL_SECRET, forwarder_uid=os.geteuid(),
                               receiver_boot_id=BOOT, timeout=JOIN_TIMEOUT)
        send_frame(client, {"op": "revoke", "seq": 1,
                             "params": {"lease_id": grant.lease_id, "reason": reason}},
                   timeout=JOIN_TIMEOUT)
        reply = recv_frame(client, timeout=JOIN_TIMEOUT)
        assert reply["ok"] is True
        return reply["result"]["observed_at"]
    finally:
        client.close()
        _join(worker)


def test_r2_admit_paused_then_control_revoke_over_socketpair():
    _admit_then_retire_then_fence(retire=_control_revoke)


def _control_eof_disconnect(registry, grant, clock):
    receipt = registry.disconnect(receiver_boot_id=BOOT, generation=registry.generation)
    return receipt.observed_at


def test_r3_admit_paused_then_control_eof_disconnect():
    _admit_then_retire_then_fence(retire=_control_eof_disconnect)


def _fresh_boot_replacement(registry, grant, clock):
    registry.handshake(receiver_boot_id="receiver-b", generation=registry.generation)
    revocations = [item for item in registry.snapshot()["history"]
                   if item["reason"] == "receiver_replaced"]
    return revocations[-1]["observed_at"]


def test_r4_admit_paused_then_fresh_boot_replacement():
    _admit_then_retire_then_fence(retire=_fresh_boot_replacement)


def _shutdown_hold(registry, grant, clock):
    control = ForwarderControl(registry, receiver_uid=os.geteuid(), control_secret=CONTROL_SECRET)
    observed_before = clock.value
    control.shutdown()
    return observed_before


def test_r5_admit_paused_then_shutdown_holds_registry():
    # A held registry (not a targeted revoke) makes every closeout "unknown"
    # for the rest of the lease's life, not "draining" then "quiescent".
    _admit_then_retire_then_fence(
        retire=_shutdown_hold, closeout_state_while_paused="unknown",
        final_closeout_state="unknown",
    )


def _heartbeat_loss(registry, grant, clock):
    # Heartbeat loss needs no timer: any later registry call discovers and
    # retires it as a side effect (leases._now()).
    clock.advance(HEARTBEAT_SECONDS + 0.5)
    snapshot = registry.snapshot()
    losses = [item for item in snapshot["history"] if item["reason"] == "heartbeat_late"]
    return losses[-1]["observed_at"]


def test_r6_admit_paused_then_heartbeat_loss_surfaces_on_next_call():
    _admit_then_retire_then_fence(retire=_heartbeat_loss)


def test_r7_revoke_completed_before_admit_denies_with_zero_connecting():
    gate, registry, ledger, clock = _plain_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    handle = do_reserve(gate, entry, clock, ttl=30.0)
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")

    outcome = gate.admit(handle, sentinel=grant.sentinel)
    assert outcome.code == "lease_denied"
    assert outcome.denial.dispatch_state == "NOT_DISPATCHED"
    assert ledger.snapshot()["counts_by_state"]["connecting"] == 0


def _plain_system():
    clock = FakeClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    return gate, registry, ledger, clock


# --- R8: high concurrency against one revoker --------------------------------


def test_r8_sixteen_threads_fifty_handles_against_one_revoker():
    clock = CounterClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    grant, entry = _install_with_counter_clock(gate, registry, clock)

    threads_count = 16
    handles_per_thread = 50
    lock = threading.Lock()
    first_admitted = threading.Event()
    revoked = threading.Event()
    admissions: list[tuple[str, float]] = []
    fence_observations: list[float] = []
    late: list[tuple[str, str, str | None]] = []  # (step, code, denial state), begun after revoke
    unexpected_codes: list[str] = []
    errors: list[BaseException] = []

    def worker():
        try:
            attempts = 0
            late_admits = 0
            # Run the batch, then keep going until one admit has begun after the revoke.
            while attempts < handles_per_thread or (late_admits == 0 and attempts < 400):
                attempts += 1
                routed = make_routed(entry)
                try:
                    # +30 s keeps write_deadline = fence reading + WRITE_SECONDS (unclipped).
                    handle = gate.reserve(entry, routed, request_digest=routed.request_digest,
                                           request_bytes=64, deadline=clock() + 30.0)
                except fd.DispatchError:
                    continue
                begun_late = revoked.is_set()
                try:
                    outcome = gate.admit(handle, sentinel=grant.sentinel)
                except fd.DispatchError as exc:
                    gate.release(handle)
                    with lock:
                        unexpected_codes.append(exc.code)
                    continue
                if begun_late:
                    late_admits += 1
                    denial = outcome.denial.dispatch_state if outcome.denial else None
                    with lock:
                        late.append(("admit", outcome.code, denial))
                if outcome.code != "admitted":
                    continue
                admission = outcome.admission
                with lock:
                    admissions.append((admission.receipt_id, admission.admitted_at))
                first_admitted.set()
                begun_late = revoked.is_set()
                try:
                    write_outcome = gate.begin_write(admission, sentinel=grant.sentinel)
                except fd.DispatchError as exc:
                    gate.release(admission)
                    with lock:
                        unexpected_codes.append(exc.code)
                    continue
                if begun_late:
                    denial = write_outcome.denial.dispatch_state if write_outcome.denial else None
                    with lock:
                        late.append(("fence", write_outcome.code, denial))
                if write_outcome.code != "write_admitted":
                    continue
                assert write_outcome.write_deadline < admission.exchange_deadline
                with lock:
                    fence_observations.append(write_outcome.write_deadline - fd.WRITE_SECONDS)
                try:
                    gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                                upstream_response=ParsedResponse(200, b"{}"))
                except fd.DispatchError:
                    gate.release(admission)
        except BaseException as exc:  # noqa: BLE001 - surfaced via `errors` below.
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for thread in threads:
        thread.start()
    assert first_admitted.wait(JOIN_TIMEOUT), "no admission landed before the revoke"
    revoke_receipt = registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                                      generation=registry.generation, reason="operator_cancel")
    revoked.set()
    for thread in threads:
        _join(thread)
    assert not errors, errors
    assert unexpected_codes == []

    revoked_at = revoke_receipt.observed_at
    # Guaranteed by construction, not merely likely: check() and revoke() are
    # both serialized under the registry's own lock with one monotonic clock,
    # so any check() that returned "authorized" strictly precedes revoke()'s
    # own reading, or the record would already show revoked.
    assert admissions, "the race produced no successful admission to check"
    assert all(admitted_at < revoked_at for _, admitted_at in admissions)
    assert all(observed < revoked_at for observed in fence_observations)

    # Every admit or fence that began after revoke() returned was denied.
    assert any(step == "admit" for step, _code, _state in late)
    for step, code, state in late:
        if step == "admit":
            assert (code, state) == ("lease_denied", "NOT_DISPATCHED")
        else:
            assert (code, state) == ("lease_denied", "FAILED")

    admitted_ids = {receipt_id for receipt_id, _ in admissions}
    assert len(admitted_ids) == len(admissions)
    entries = ledger.snapshot()["entries"]
    non_not_dispatched = [item for item in entries if item["dispatch_state"] not in
                           (None, "NOT_DISPATCHED")]
    assert non_not_dispatched, "expected at least one FAILED or TRANSPORT_CONFIRMED entry"
    for item in non_not_dispatched:
        assert item["receipt_id"] in admitted_ids

    # No false hold: the tick reads (and their sweep) run entirely under G.
    assert gate.snapshot()["hold_code"] is None


# --- R9: shutdown concurrent with admits and fences --------------------------


def test_r9_shutdown_concurrent_with_admits_and_fences():
    clock = CounterClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    grant, entry = _install_with_counter_clock(gate, registry, clock)
    errors: list[BaseException] = []
    workers_count = 8
    started = threading.Barrier(workers_count + 1)
    shut = threading.Event()
    lock = threading.Lock()
    late: list[tuple[str, str, str | None]] = []  # (step, code, denial state), begun after shutdown

    def reserve_one():
        routed = make_routed(entry)
        return gate.reserve(entry, routed, request_digest=routed.request_digest,
                             request_bytes=64, deadline=clock() + 30.0)

    def record_if_late(step, begun_late, outcome):
        if begun_late:
            denial = outcome.denial.dispatch_state if outcome.denial else None
            with lock:
                late.append((step, outcome.code, denial))

    def worker():
        try:
            # Tokens taken before shutdown and used only after it returns, so
            # every worker makes at least one admit and one fence after it.
            spare_handle = reserve_one()
            spare_admission = gate.admit(reserve_one(), sentinel=grant.sentinel).admission
            started.wait(JOIN_TIMEOUT)
            for _ in range(200):
                routed = make_routed(entry)
                try:
                    handle = gate.reserve(entry, routed, request_digest=routed.request_digest,
                                           request_bytes=64, deadline=clock() + 5.0)
                except fd.DispatchError:
                    continue
                begun_late = shut.is_set()
                try:
                    outcome = gate.admit(handle, sentinel=grant.sentinel)
                except fd.DispatchError:
                    gate.release(handle)
                    continue
                record_if_late("admit", begun_late, outcome)
                if outcome.code != "admitted":
                    continue
                admission = outcome.admission
                begun_late = shut.is_set()
                try:
                    write_outcome = gate.begin_write(admission, sentinel=grant.sentinel)
                except fd.DispatchError:
                    gate.release(admission)
                    continue
                record_if_late("fence", begun_late, write_outcome)
                if write_outcome.code == "write_admitted":
                    try:
                        gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED",
                                    reason="ok", upstream_response=ParsedResponse(200, b"{}"))
                    except fd.DispatchError:
                        gate.release(admission)
            assert shut.wait(JOIN_TIMEOUT)
            record_if_late("admit", True, gate.admit(spare_handle, sentinel=grant.sentinel))
            record_if_late("fence", True,
                           gate.begin_write(spare_admission, sentinel=grant.sentinel))
        except BaseException as exc:  # noqa: BLE001 - surfaced via `errors` below.
            errors.append(exc)

    # Two flights reserved before shutdown, to prove I3 directly and
    # deterministically rather than only under a race against `stop`.
    probe_admit_handle = reserve_one()
    probe_fence_handle = reserve_one()
    probe_fence_admission = gate.admit(probe_fence_handle, sentinel=grant.sentinel).admission

    threads = [threading.Thread(target=worker) for _ in range(workers_count)]
    for thread in threads:
        thread.start()
    started.wait(JOIN_TIMEOUT)

    report = gate.shutdown()
    shut.set()

    # I3: once shutdown() has returned (linearized under G), no L1 or L2 for
    # any flight -- including ones reserved/admitted before the call -- can
    # still succeed.
    admit_after = gate.admit(probe_admit_handle, sentinel=grant.sentinel)
    assert admit_after.code == "gate_closed"
    assert admit_after.denial.dispatch_state == "NOT_DISPATCHED"

    fence_after = gate.begin_write(probe_fence_admission, sentinel=grant.sentinel)
    assert fence_after.code == "gate_closed"
    assert fence_after.denial.dispatch_state == "FAILED"

    for thread in threads:
        _join(thread)
    assert not errors, errors
    assert gate.snapshot()["gate_state"] == "closed"
    assert isinstance(report, fd.ShutdownReport)

    # No admit or fence that began after shutdown() returned was admitted.
    assert len([step for step, _code, _state in late if step == "fence"]) >= workers_count
    for step, code, state in late:
        assert (code, state) == ("gate_closed", "NOT_DISPATCHED" if step == "admit" else "FAILED")


# --- R10: mixed load with a deadlock watchdog --------------------------------


def test_r10_mixed_load_with_deadlock_watchdog():
    clock = CounterClock()
    registry = LeaseRegistry(clock=clock)
    registry.handshake(receiver_boot_id=BOOT, generation=registry.generation)
    ledger = ReceiptLedger(generation=registry.generation, clock=clock)
    gate = DispatchGate(registry=registry, ledger=ledger, clock=clock)
    grant, entry = _install_with_counter_clock(gate, registry, clock)

    stop = threading.Event()
    errors: list[BaseException] = []
    lock = threading.Lock()

    def dispatch_worker():
        try:
            while not stop.is_set():
                routed = make_routed(entry)
                try:
                    handle = gate.reserve(entry, routed, request_digest=routed.request_digest,
                                           request_bytes=64, deadline=clock() + 5.0)
                except fd.DispatchError:
                    continue
                try:
                    outcome = gate.admit(handle, sentinel=grant.sentinel)
                except fd.DispatchError:
                    gate.release(handle)
                    continue
                if outcome.code != "admitted":
                    continue
                admission = outcome.admission
                try:
                    write_outcome = gate.begin_write(admission, sentinel=grant.sentinel)
                except fd.DispatchError:
                    gate.release(admission)
                    continue
                if write_outcome.code == "write_admitted":
                    try:
                        gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED",
                                    reason="ok", upstream_response=ParsedResponse(200, b"{}"))
                    except fd.DispatchError:
                        gate.release(admission)
                else:
                    gate.release(admission)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    def control_worker():
        try:
            tick = 0
            while not stop.is_set():
                tick += 1
                try:
                    if tick % 2 == 0:
                        registry.heartbeat(receiver_boot_id=BOOT, generation=registry.generation)
                    else:
                        registry.snapshot()
                except LeaseError:
                    pass  # e.g. a stale heartbeat right after a concurrent revoke: expected
                time.sleep(0.01)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    def observer_worker():
        try:
            while not stop.is_set():
                gate.closeout(grant.lease_id)
                gate.snapshot()
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = (
        [threading.Thread(target=dispatch_worker) for _ in range(4)]
        + [threading.Thread(target=control_worker)]
        + [threading.Thread(target=observer_worker) for _ in range(2)]
    )
    for thread in threads:
        thread.start()

    time.sleep(1.0)
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    time.sleep(0.6)
    gate.shutdown()
    time.sleep(0.4)
    stop.set()

    for thread in threads:
        _join(thread)
    assert not errors, errors
    assert gate.snapshot()["gate_state"] == "closed"


# --- R11: overdue race -------------------------------------------------------


def test_r11_overdue_flight_ticked_by_another_thread_before_owner_finish():
    gate, registry, _ledger, clock = _plain_system()
    grant, entry = install(gate, registry, clock, active=True, ttl=200.0)
    admission = reserve_and_admit(gate, entry, grant, clock, ttl=2.0)
    write_outcome = gate.begin_write(admission, sentinel=grant.sentinel)
    assert write_outcome.code == "write_admitted"

    abort_calls: list[threading.Thread] = []
    probe: list = []

    def abort():
        abort_calls.append(threading.current_thread())
        snapshot_from_worker(gate, probe)  # another thread proves G is free here

    assert gate.attach_abort(admission, abort) is True

    # Fill every remaining slot so A's flight sits exactly at the capacity
    # boundary: if the overdue mark ever freed its slot early (critic issue
    # #1), B's reserve below would wrongly succeed instead of being denied.
    for _ in range(fd.MAX_OPEN_DISPATCHES - 1):
        do_reserve(gate, entry, clock, ttl=30.0)
    assert gate.snapshot()["open_dispatches"] == fd.MAX_OPEN_DISPATCHES

    clock.advance(3.0)  # A's deadline has passed; no tick has observed it yet

    def b_reserve():
        routed = make_routed(entry, route_id="jira.search")
        return gate.reserve(entry, routed, request_digest=routed.request_digest,
                             request_bytes=64, deadline=clock.value + 30.0)

    b_thread, b_result = _call_in_thread(b_reserve)
    _join(b_thread)
    assert isinstance(b_result.error, fd.DispatchError)
    assert b_result.error.code == "dispatch_capacity"  # A's overdue flight still counts

    assert len(abort_calls) == 1
    assert abort_calls[0] is b_thread  # fired on B's thread, outside G, exactly once
    assert probe == [fd.MAX_OPEN_DISPATCHES, ("worker_alive", False)]
    assert gate.is_admitted(admission) is False

    flights = {row[0]: row for row in gate.snapshot()["flights"]}
    assert flights[admission.receipt_id][5] is True  # overdue flag
    assert gate.snapshot()["open_dispatches"] == fd.MAX_OPEN_DISPATCHES  # slot not yet freed

    # "open" (registered/active) outranks "overdue" in the closeout order, so
    # revoke to observe the overdue state distinctly.
    registry.revoke(lease_id=grant.lease_id, receiver_boot_id=BOOT,
                     generation=registry.generation, reason="operator_cancel")
    overdue_closeout = gate.closeout(grant.lease_id)
    assert overdue_closeout.closeout_state == "overdue"
    assert overdue_closeout.overdue == 1

    finish_error = assert_error(
        lambda: gate.finish(admission, dispatch_state="TRANSPORT_CONFIRMED", reason="ok",
                             upstream_response=ParsedResponse(200, b"{}")),
        "deadline_expired",
    )
    assert finish_error.code == "deadline_expired"  # never admission_unknown
    assert gate.snapshot()["open_dispatches"] == fd.MAX_OPEN_DISPATCHES - 1  # now freed

    final_closeout = gate.closeout(grant.lease_id)
    assert final_closeout.closeout_state == "quiescent"
    assert final_closeout.uncertain == 1
