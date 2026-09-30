import hashlib
import json
from dataclasses import replace

import pytest

from prototype.run_timing.executor import LENGTHS, LengthProbe, Lifecycle, command_for


def test_empty_and_pending_cases_are_distinct_and_do_not_invent_observations():
    life = Lifecycle()
    probe = LengthProbe(life)
    empty = probe.report()
    assert [c['case_bytes'] for c in empty['cases']] == list(LENGTHS)
    assert all(c['classification'] == 'not_attempted' for c in empty['cases'])
    assert all(c['request'] is c['dispatch'] is c['observation'] is None for c in empty['cases'])
    life.advance(12)
    probe.begin(command_for(9500), 'first')
    pending = probe.report()['cases'][0]
    assert pending['classification'] == 'pending'
    assert pending['request']['at'] == 12 and pending['request']['tool_id'] == 'first'
    assert pending['dispatch'] is pending['observation'] is None
    assert probe.report()['bracket']['status'] == 'inconclusive'


def test_full_grid_exports_correlated_metadata_without_command_bodies():
    life = Lifecycle()
    probe = LengthProbe(life)
    for i, length in enumerate(LENGTHS):
        command = command_for(length)
        life.advance(i * 3)
        probe.begin(command, f'tool-{i}')
        life.advance(i * 3 + 1)
        receipt = probe.dispatch(command, f'tool-{i}', stub_exit=7) if i < 2 else None
        life.advance(i * 3 + 2)
        probe.observe(command, receipt=receipt,
                      native_decision=None if i < 2 else 'permission_denied_before_dispatch',
                      coverage_complete=i >= 2, decision_reference=f'synthetic-event-{i}')
    report = probe.report()
    assert report['scope'] == 'OFFLINE_LENGTH_RECORDS_ONLY' and report['native_launch'] == 'CLOSED'
    assert report['clock'] == 'virtual_seconds'
    assert report['receipt_authority'] == 'in_memory_object_identity'
    assert report['bracket']['largest_dispatched'] == 11000
    assert report['bracket']['smallest_denied'] == 12000
    assert not report['work_allowed']
    for i, case in enumerate(report['cases']):
        expected = {'bytes': LENGTHS[i], 'sha256': hashlib.sha256(command_for(LENGTHS[i])).hexdigest()}
        assert case['expected_command'] == case['request']['command'] == case['observation']['command']
        assert case['expected_command'] == expected
        assert case['request']['at'] == i * 3 and case['observation']['at'] == i * 3 + 2
        assert case['observation']['decision_reference'] == f'synthetic-event-{i}'
        if i < 2:
            assert case['classification'] == 'dispatched'
            assert case['dispatch']['at'] == i * 3 + 1 and case['dispatch']['stub_exit'] == 7
            assert case['observation']['supplied_receipt'] == 'issued_here'
        else:
            assert case['classification'] == 'permission_denied_no_dispatch'
            assert case['dispatch'] is None and case['observation']['coverage_complete']
    encoded = json.dumps(report, allow_nan=False)
    assert json.loads(encoded) == report
    assert 'jira-as' not in encoded and 'x' * 100 not in encoded


@pytest.mark.parametrize('kind', ['missing', 'copied', 'foreign', 'conflicting-denial'])
def test_issued_and_supplied_receipt_evidence_remain_separate(kind):
    probe = LengthProbe(Lifecycle())
    command = command_for(9500)
    issued = probe.dispatch(command, 'one')
    supplied = None
    if kind == 'copied':
        supplied = replace(issued)
    elif kind == 'foreign':
        supplied = LengthProbe(Lifecycle()).dispatch(command, 'one')
    elif kind == 'conflicting-denial':
        supplied = issued
    probe.observe(command, receipt=supplied, coverage_complete=True,
                  native_decision='permission_denied_before_dispatch' if kind == 'conflicting-denial'
                  else None)
    report = probe.report()
    case = report['cases'][0]
    assert case['classification'] == 'dispatch_unknown' and report['hold']
    assert case['dispatch']['tool_id'] == 'one'  # Locally issued receipt never disappears.
    expected = 'absent' if kind == 'missing' else 'issued_here' if kind == 'conflicting-denial' else 'unrecognized'
    assert case['observation']['supplied_receipt'] == expected
    assert all(c['classification'] == 'not_attempted' for c in report['cases'][1:])


def test_request_and_observation_digests_preserve_edited_command():
    probe = LengthProbe(Lifecycle())
    command = command_for(9500)
    edited = command[:-1] + b'!'
    probe.begin(command, 'one')
    probe.observe(edited)
    case = probe.report()['cases'][0]
    assert case['classification'] == 'invalid_case'
    assert case['request']['command'] == case['expected_command']
    assert case['observation']['command']['sha256'] == hashlib.sha256(edited).hexdigest()
    assert case['observation']['command'] != case['expected_command']


@pytest.mark.parametrize('decision', ['provider_refusal', 'model_unavailable', 'fallback'])
def test_refusal_preserves_case_and_stops_without_fabricating_later_attempts(decision):
    probe = LengthProbe(Lifecycle())
    probe.begin(command_for(9500), 'one')
    probe.observe(command_for(9500), native_decision=decision)
    report = probe.report()
    assert report['cases'][0]['classification'] == 'not_length_evidence'
    assert report['cases'][0]['observation']['synthetic_decision'] == decision
    assert report['probe_cleanup_actions'] == ['revoke', 'interrupt']
    assert report['lifecycle']['revoked'] and report['hold'] and not report['work_allowed']
    assert all(c['classification'] == 'not_attempted' for c in report['cases'][1:])
    assert report['bracket'] == {'status': 'inconclusive'}


def test_external_cancellation_keeps_pending_case_visible():
    life = Lifecycle()
    probe = LengthProbe(life)
    probe.begin(command_for(9500), 'one')
    life.advance(20, cancel=True)
    report = probe.report()
    assert report['cases'][0]['classification'] == 'pending'
    assert report['lifecycle']['cleanup_at'] == 20 and report['lifecycle']['revoked']
    assert not report['work_allowed']
    assert report['probe_cleanup_actions'] == []  # Cancellation was external to the probe.


def test_report_mutation_cannot_change_probe_state():
    probe = LengthProbe(Lifecycle())
    command = command_for(9500)
    probe.begin(command, 'one')
    before = probe.report()
    changed = probe.report()
    changed['cases'][0]['request']['tool_id'] = 'forged'
    changed['cases'][1]['expected_command']['sha256'] = 'forged'
    changed['bracket']['status'] = 'forged'
    changed['lifecycle']['reasons'].append('forged')
    assert probe.report() == before
    receipt = probe.dispatch(command, 'one')
    probe.observe(command, receipt=receipt)
    assert before['cases'][0]['classification'] == 'pending'
    assert probe.report()['cases'][0]['classification'] == 'dispatched'


@pytest.mark.parametrize('overrides', [
    {'native_decision': 'x' * 201}, {'native_decision': []},
    {'decision_reference': 'x' * 201}, {'decision_reference': 3},
    {'command': b'x' * 14001}, {'command': 'not bytes'}, {'coverage_complete': 1},
])
def test_invalid_observation_is_bounded_and_holds_without_advancing(overrides):
    probe = LengthProbe(Lifecycle())
    command = command_for(9500)
    probe.begin(command, 'one')
    args = {'command': command, **overrides}
    with pytest.raises((TypeError, ValueError)):
        probe.observe(**args)
    report = probe.report()
    assert report['hold'] and report['cases'][0]['classification'] == 'pending'
    assert report['cases'][0]['observation'] is None
    assert probe.results == []


@pytest.mark.parametrize('exit_code', [True, 2**31, -(2**31) - 1])
def test_stub_exit_is_bounded_without_issuing_receipt(exit_code):
    probe = LengthProbe(Lifecycle())
    with pytest.raises(ValueError):
        probe.dispatch(command_for(9500), 'one', stub_exit=exit_code)
    report = probe.report()
    assert report['hold'] and report['cases'][0]['dispatch'] is None
