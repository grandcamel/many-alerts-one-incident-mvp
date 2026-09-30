"""Real host fixture processes; no model/client/container or tenant operations."""

import hashlib
import json
import os
import signal
import threading

import pytest

from prototype.run_timing import process_fixture
from prototype.run_timing.process_fixture import SCENARIOS, run_fixture

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX fixed-process harness')


def run(tmp_path, scenario, **kwargs):
    scale = kwargs.pop('time_scale', 0.01)
    return run_fixture(scenario, tmp_path, scenario, time_scale=scale, **kwargs)


@pytest.mark.parametrize('scenario,expected', [
    ('success', 'completed'), ('nonzero', 'failed'), ('result_error', 'failed'),
    ('duplicate', 'incomplete'), ('malformed', 'cancelled'),
])
def test_real_terminal_and_exit_evidence(tmp_path, scenario, expected):
    result = run(tmp_path, scenario)
    # Malformed output may be observed with an already-exited process; either is non-success.
    if scenario == 'malformed':
        assert result.outcome.execution in ('incomplete', 'cancelled')
    else:
        assert result.outcome.execution == expected
    assert result.root_reaped and result.group_gone and result.pipes_closed
    assert result.scope == 'FIXED_HOST_FIXTURES_ONLY' and result.native_launch == 'CLOSED'
    assert json.loads((tmp_path / scenario / 'result.json').read_text())['native_launch'] == 'CLOSED'
    assert hashlib.sha256((tmp_path / scenario / 'fixture.py').read_bytes()).hexdigest() == (
        result.worker_sha256)


def test_minimal_environment_excludes_host_configuration_and_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'synthetic-test-value-not-a-credential')
    monkeypatch.setenv('PYTHONPATH', '/not/a/real/import/path')
    monkeypatch.setenv('JIRA_API_TOKEN', 'synthetic-test-value')
    result = run(tmp_path, 'success')
    assert result.outcome.execution == 'completed'


@pytest.mark.parametrize('scenario,force_kill', [('silence', False), ('ignore_interrupt', True)])
def test_real_silence_deadline_and_forced_kill(tmp_path, scenario, force_kill):
    result = run(tmp_path, scenario, time_scale=0.02 if force_kill else 0.01)
    actions = [name for _, group in result.actions for name in group]
    assert result.outcome.execution == 'timed_out'
    assert 'interrupt' in actions
    assert ('kill_and_reap' in actions) == force_kill
    assert result.root_reaped and result.group_gone and result.pipes_closed
    assert result.elapsed_seconds <= result.total_bound_seconds


def test_operator_cancellation_cleans_up_early(tmp_path):
    event = threading.Event()
    timer = threading.Timer(0.2, event.set)
    timer.start()
    try:
        result = run(tmp_path, 'ignore_interrupt', cancel=event)
    finally:
        timer.join()
    assert result.outcome.execution == 'cancelled'
    assert result.root_reaped and result.group_gone and result.pipes_closed
    assert result.elapsed_seconds < 1


@pytest.mark.parametrize('scenario', ['held_pipe', 'held_pipe_ignore'])
def test_parent_exit_does_not_finish_before_descendants_and_pipes(tmp_path, scenario):
    result = run(tmp_path, scenario)
    assert result.root_reaped and result.group_gone and result.pipes_closed
    actions = [name for _, group in result.actions for name in group]
    assert 'interrupt' in actions and actions[-1] == 'closed'
    if scenario.endswith('ignore'):
        assert 'kill_and_reap' in actions
        assert result.outcome.execution == 'cancelled'


def test_closed_pipes_do_not_prove_a_living_descendant_is_gone(tmp_path):
    result = run(tmp_path, 'closed_pipes_alive', time_scale=0.02)
    actions = [name for _, group in result.actions for name in group]
    assert 'kill_and_reap' in actions
    assert result.root_reaped and result.group_gone and result.pipes_closed
    assert result.outcome.execution == 'cancelled'


def test_spawn_failure_is_recorded_without_claiming_a_completed_process(tmp_path, monkeypatch):
    def cannot_spawn(*args, **kwargs):
        raise OSError('synthetic spawn failure')
    monkeypatch.setattr(process_fixture.subprocess, 'Popen', cannot_spawn)
    result = run(tmp_path, 'success')
    assert result.outcome.execution == 'spawn_failed'
    assert result.root_pid is None and not result.root_reaped
    assert result.outcome.further_dispatch == 'hold'


def test_supervisor_exception_still_reaps_its_fixture(tmp_path, monkeypatch):
    real_popen = process_fixture.subprocess.Popen
    real_selector = process_fixture.selectors.DefaultSelector
    children = []

    def capture_child(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    class FailedSelector(real_selector):
        def select(self, timeout=None):
            raise OSError('synthetic selector failure')

    monkeypatch.setattr(process_fixture.subprocess, 'Popen', capture_child)
    monkeypatch.setattr(process_fixture.selectors, 'DefaultSelector', FailedSelector)
    with pytest.raises(OSError, match='synthetic selector failure'):
        run(tmp_path, 'ignore_interrupt')
    assert len(children) == 1
    assert children[0].poll() is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(children[0].pid, 0)
    assert not (tmp_path / 'ignore_interrupt' / 'result.json').exists()
    # An incomplete attempt remains reserved as a path; it cannot be silently rerun.
    with pytest.raises(FileExistsError):
        run(tmp_path, 'ignore_interrupt')


@pytest.mark.parametrize('scenario,cap', [('flood', 1024), ('oversized_line', 1024 * 1024)])
def test_output_bounds_stop_process_without_deadlock(tmp_path, scenario, cap):
    result = run(tmp_path, scenario, capture_limit=cap)
    assert result.outcome.execution != 'completed'
    assert 'capture_limit' in result.outcome.reasons
    assert result.captured_bytes <= cap
    assert result.root_reaped and result.group_gone and result.pipes_closed


def test_attempt_collision_preserves_evidence_and_refuses_symlink(tmp_path):
    result = run(tmp_path, 'success')
    content = (tmp_path / 'success' / 'result.json').read_bytes()
    with pytest.raises(FileExistsError):
        run(tmp_path, 'success')
    assert (tmp_path / 'success' / 'result.json').read_bytes() == content
    (tmp_path / 'link').symlink_to(tmp_path / 'success', target_is_directory=True)
    with pytest.raises(FileExistsError):
        run_fixture('success', tmp_path, 'link', time_scale=0.01)
    assert result.outcome.execution == 'completed'


@pytest.mark.parametrize('name', ['claude', 'sh', 'echo test', '../success', '/tmp/other'])
def test_no_arbitrary_command_path_or_fixture(tmp_path, name):
    assert name not in SCENARIOS
    with pytest.raises(ValueError):
        run_fixture(name, tmp_path, 'attempt')
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('scale', [0, -1, 1.01, float('nan'), True])
def test_budget_cannot_be_enlarged_or_invalid(tmp_path, scale):
    with pytest.raises((TypeError, ValueError)):
        run_fixture('success', tmp_path, 'attempt', time_scale=scale)
    assert list(tmp_path.iterdir()) == []


def test_uncaptured_terminal_bytes_do_not_influence_classification(tmp_path):
    result = run(tmp_path, 'duplicate', capture_limit=1)
    assert result.captured_bytes == 0 and not result.capture_complete
    assert 'capture_limit' in result.outcome.reasons
    assert 'missing_terminal' in result.outcome.reasons
    assert 'duplicate_terminal' not in result.outcome.reasons
    assert result.outcome.actual_models == ()
    assert result.outcome.estimate_usd is None


def test_completed_process_with_malformed_output_is_not_retrospectively_cancelled(
        tmp_path, monkeypatch):
    real_popen = process_fixture.subprocess.Popen
    real_selector = process_fixture.selectors.DefaultSelector
    children = []

    def capture_child(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    class AfterExitSelector(real_selector):
        def select(self, timeout=None):
            children[0].wait(timeout=1)
            return super().select(timeout)

    monkeypatch.setattr(process_fixture.subprocess, 'Popen', capture_child)
    monkeypatch.setattr(process_fixture.selectors, 'DefaultSelector', AfterExitSelector)
    result = run(tmp_path, 'malformed')
    assert result.outcome.execution == 'incomplete'
    assert 'malformed_evidence' in result.outcome.reasons
    assert 'cancelled' not in result.outcome.reasons


def test_cooperative_fixture_resets_inherited_ignored_sigint(tmp_path):
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        result = run(tmp_path, 'silence')
    finally:
        signal.signal(signal.SIGINT, previous)
    assert result.outcome.execution == 'timed_out'
    assert not any('kill_and_reap' in group for _, group in result.actions)
    assert result.root_reaped and result.group_gone


def test_unreadable_worker_does_not_consume_attempt_id(tmp_path, monkeypatch):
    def unreadable_worker(*args, **kwargs):
        raise PermissionError('synthetic worker read failure')
    monkeypatch.setattr(process_fixture.Path, 'read_bytes', unreadable_worker)
    with pytest.raises(PermissionError, match='synthetic worker read failure'):
        run(tmp_path, 'success')
    assert list(tmp_path.iterdir()) == []


def test_read_failure_is_not_complete_capture_or_observed_eof(tmp_path, monkeypatch):
    real_popen = process_fixture.subprocess.Popen
    real_read = process_fixture.os.read
    stdout_fds = []

    def capture_child(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        stdout_fds.append(child.stdout.fileno())
        return child

    def failed_stdout(fd, size):
        if fd in stdout_fds:
            raise OSError('synthetic read failure')
        return real_read(fd, size)

    monkeypatch.setattr(process_fixture.subprocess, 'Popen', capture_child)
    monkeypatch.setattr(process_fixture.os, 'read', failed_stdout)
    result = run(tmp_path, 'success')
    assert not result.capture_complete and not result.pipes_closed
    assert result.captured_bytes == 0
    assert result.outcome.execution != 'completed'
    assert {'malformed_evidence', 'missing_terminal'} <= set(result.outcome.reasons)
    assert result.outcome.actual_models == ()
    assert result.outcome.further_dispatch == 'hold'
