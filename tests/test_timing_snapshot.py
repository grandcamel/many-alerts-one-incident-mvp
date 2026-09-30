import hashlib
import json
import os
import stat
from copy import deepcopy

import pytest

from prototype.run_timing import timing_snapshot
from prototype.run_timing.executor import Lifecycle
from prototype.run_timing.fixture_evidence import EvidenceUnavailable
from prototype.run_timing.timing_incidents import SECTIONS, TimingIncidents
from prototype.run_timing.timing_queries import TimingQueries
from prototype.run_timing.timing_snapshot import (
    capture_timing_snapshot,
    read_timing_snapshot,
    validate_timing_snapshot,
    write_timing_snapshot,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def resign(record, key='sha256'):
    record[key] = hashlib.sha256(canonical({k: v for k, v in record.items() if k != key})).hexdigest()


@pytest.fixture
def scenario():
    queries = TimingQueries('snapshot-one', Lifecycle())
    notification = queries.query('notification', 'notification.get', {})
    logs = queries.query('logs', 'logs.query', {'contains': 'cache', 'limit': 1})
    store = TimingIncidents(queries, notification['response_id'])
    alerts = notification['items'][0]['value']['alerts']
    report = {'sections': dict.fromkeys(SECTIONS, 'Synthetic unsupported example'),
              'references': [{'response_id': logs['response_id'], 'item_index': 0}],
              'explanations': [{'fingerprint': a['fingerprint'],
                                'relation': 'direct' if i == 0 else 'unexplained'}
                               for i, a in enumerate(alerts)], 'correction_of': None}
    payload = {'summary': 'Synthetic snapshot', 'members': [alerts[0]['fingerprint']], 'report': report}
    return store, queries, payload


def populated(scenario):
    store, _, payload = scenario
    first = store.complete(store.dispatch('create', 'create', payload)['dispatch_id'])
    content = deepcopy(payload['report'])
    content['correction_of'] = first['report_revision_id']
    store.complete(store.dispatch('append', 'append', {'incident_id': first['incident_id'],
        'expected_revision': 1, 'members': [], 'report': content})['dispatch_id'])
    return store


def test_retained_roundtrip_after_objects_are_gone(tmp_path):
    queries = TimingQueries('standalone', Lifecycle())
    notification = queries.query('notification', 'notification.get', {})
    store = TimingIncidents(queries, notification['response_id'])
    alerts = notification['items'][0]['value']['alerts']
    report = {'sections': dict.fromkeys(SECTIONS, 'Synthetic statement'),
        'references': [{'response_id': notification['response_id'], 'item_index': 0}],
        'explanations': [{'fingerprint': a['fingerprint'], 'relation': 'direct'} for a in alerts],
        'correction_of': None}
    store.complete(store.dispatch('one', 'create', {'summary': 'Synthetic',
        'members': [a['fingerprint'] for a in alerts], 'report': report})['dispatch_id'])
    directory = tmp_path / 'bundle'
    expected = write_timing_snapshot(directory, store)
    del store, queries
    actual = read_timing_snapshot(directory)
    assert actual == expected and actual['audit_completeness'] == 'NOT_ASSESSED'
    retained = actual['store']['queries']['responses'][0]
    assert retained == notification
    assert actual['store']['revisions'][0]['report'] == report
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in directory.iterdir())
    assert {p.name for p in directory.iterdir()} == {'snapshot.json', 'manifest.json'}


def test_all_revisions_refs_and_detached_inventories(scenario, tmp_path):
    store = populated(scenario)
    snapshot = capture_timing_snapshot(store)
    assert len(snapshot['store']['revisions']) == 2
    assert len(snapshot['store']['effects']) == 2
    assert snapshot['store']['queries']['responses'][1]['truncated']
    original = deepcopy(snapshot)
    snapshot['store']['revisions'][0]['report']['sections']['summary'] = 'tamper'
    snapshot['store']['queries']['responses'][0]['items'].clear()
    snapshot['store']['state']['incident']['members'].clear()
    assert capture_timing_snapshot(store) == original
    assert write_timing_snapshot(tmp_path / 'snapshot', store) == original
    assert read_timing_snapshot(tmp_path / 'snapshot') == original


@pytest.mark.parametrize('disposition', ['pending', 'confirmed', 'failed',
    'unknown_before_apply', 'unknown_after_apply'])
@pytest.mark.parametrize('revoked', [False, True])
def test_capture_preserves_uncertainty_and_never_completes_or_clears(scenario, tmp_path, disposition, revoked):
    store, queries, payload = scenario
    dispatch_id = store.dispatch('create', 'create', payload)['dispatch_id']
    if disposition != 'pending':
        store.complete(dispatch_id, disposition=disposition)
    if revoked:
        queries.lifecycle.advance(270)
    before = store.audit_snapshot()
    captured = write_timing_snapshot(tmp_path / 'bundle', store)
    assert store.audit_snapshot() == before == captured['store']
    assert captured['store']['lifecycle']['work_allowed'] is (not revoked)
    if disposition == 'unknown_after_apply':
        assert len(captured['store']['revisions']) == 1
        assert captured['store']['effects'][0]['effect_outcome'] == 'unknown'
        assert captured['store']['state']['hold']
    if disposition == 'pending':
        assert captured['store']['state']['pending_dispatch_id'] == dispatch_id
        assert captured['store']['effects'] == [] and captured['store']['revisions'] == []


def test_empty_and_repeated_snapshot_do_not_issue_work(scenario, tmp_path):
    store = scenario[0]
    first = write_timing_snapshot(tmp_path / 'first', store)
    second = write_timing_snapshot(tmp_path / 'second', store)
    assert first == second
    assert first['store']['state']['incident'] is None
    assert first['store']['dispatches'] == []


@pytest.mark.parametrize('fault', ['digest', 'missing_response', 'reference_index', 'duplicate_response',
    'foreign_response_id', 'source_hash', 'count', 'missing_notification', 'revision_chain',
    'correction', 'missing_dispatch', 'missing_effect', 'duplicate_revision_dispatch',
    'confirmed_without_revision', 'state_inventory', 'current_revision', 'pending', 'hold',
    'coverage', 'scope', 'lifecycle', 'revision_cap', 'query_cap'])
def test_broken_records_or_links_fail_even_when_outer_hash_can_be_recomputed(scenario, fault):
    snapshot = capture_timing_snapshot(populated(scenario))
    store = snapshot['store']
    response = store['queries']['responses'][1]
    revision = store['revisions'][1]
    state = store['state']
    if fault == 'digest': response['items'] = []
    elif fault == 'missing_response': store['queries']['responses'].pop()
    elif fault == 'reference_index':
        revision['report']['references'][0]['item_index'] = 10
        resign(revision)
    elif fault == 'duplicate_response': store['queries']['responses'].append(deepcopy(response))
    elif fault == 'foreign_response_id':
        response['response_id'] = 'foreign/response/0002'
        resign(response, 'response_sha256')
    elif fault == 'source_hash':
        response['source']['sha256'] = '0' * 64
        resign(response, 'response_sha256')
    elif fault == 'count':
        response['returned_count'] = True
        resign(response, 'response_sha256')
    elif fault == 'missing_notification': store['notification_response_id'] = 'foreign'
    elif fault == 'revision_chain':
        revision['previous_revision_id'] = None
        resign(revision)
    elif fault == 'correction':
        revision['report']['correction_of'] = revision['revision_id']
        resign(revision)
    elif fault == 'missing_dispatch': store['dispatches'].pop()
    elif fault == 'missing_effect': store['effects'].pop()
    elif fault == 'duplicate_revision_dispatch':
        revision['dispatch_id'] = store['revisions'][0]['dispatch_id']
        resign(revision)
    elif fault == 'confirmed_without_revision':
        store['effects'][1]['report_revision_id'] = 'missing'
        resign(store['effects'][1])
    elif fault == 'state_inventory':
        state['revision_ids'].pop()
        resign(state)
    elif fault == 'current_revision':
        state['incident']['revision'] = 1
        resign(state)
    elif fault == 'pending':
        state['pending_dispatch_id'] = store['dispatches'][0]['dispatch_id']
        resign(state)
    elif fault == 'hold':
        state['hold'] = True
        resign(state)
    elif fault == 'coverage': snapshot['audit_completeness'] = 'complete'
    elif fault == 'scope': snapshot['native_launch'] = 'OPEN'
    elif fault == 'lifecycle': store['lifecycle']['work_allowed'] = False
    elif fault == 'revision_cap': store['revisions'] *= 17
    elif fault == 'query_cap': store['queries']['responses'] *= 65
    with pytest.raises(EvidenceUnavailable):
        validate_timing_snapshot(snapshot)


@pytest.mark.parametrize('fault', ['missing_manifest', 'missing_snapshot', 'bytes', 'manifest_digest',
    'manifest_size', 'duplicate_keys', 'nonfinite', 'directory', 'symlink', 'fifo', 'oversized'])
def test_readback_rejects_bad_files(scenario, tmp_path, fault):
    directory = tmp_path / 'bundle'
    write_timing_snapshot(directory, populated(scenario))
    path = directory / 'snapshot.json'
    manifest_path = directory / 'manifest.json'
    if fault == 'missing_manifest': manifest_path.unlink()
    elif fault == 'missing_snapshot': path.unlink()
    elif fault == 'bytes': path.write_bytes(path.read_bytes() + b' ')
    elif fault == 'manifest_digest':
        manifest = json.loads(manifest_path.read_text()); manifest['sha256'] = '0' * 64
        manifest_path.write_bytes(canonical(manifest))
    elif fault == 'manifest_size':
        manifest = json.loads(manifest_path.read_text()); manifest['bytes'] = True
        manifest_path.write_bytes(canonical(manifest))
    elif fault == 'duplicate_keys': manifest_path.write_text('{"version":1,"version":1}')
    elif fault == 'nonfinite': manifest_path.write_text('{"version":NaN}')
    elif fault in ('directory', 'symlink', 'fifo'):
        path.unlink()
        if fault == 'directory': path.mkdir()
        elif fault == 'symlink': path.symlink_to(manifest_path)
        else: os.mkfifo(path)
    elif fault == 'oversized':
        with path.open('wb') as handle: handle.truncate(timing_snapshot.MAX_SNAPSHOT_BYTES + 1)
    with pytest.raises(EvidenceUnavailable):
        read_timing_snapshot(directory)


def test_collision_refuses_without_touching_original(scenario, tmp_path):
    directory = tmp_path / 'bundle'
    expected = write_timing_snapshot(directory, scenario[0])
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(EvidenceUnavailable, match='publication failed'):
        write_timing_snapshot(directory, populated(scenario))
    assert before == {p.name: p.read_bytes() for p in directory.iterdir()}
    assert read_timing_snapshot(directory) == expected


@pytest.mark.parametrize('failure', ['write', 'sync', 'link'])
def test_failure_preserves_partial_evidence_and_does_not_change_store(scenario, tmp_path, monkeypatch, failure):
    store = populated(scenario)
    expected = store.audit_snapshot()
    def fail(*args, **kwargs):
        raise OSError('injected failure')
    if failure == 'write': monkeypatch.setattr(timing_snapshot, '_write', fail)
    elif failure == 'sync': monkeypatch.setattr(timing_snapshot, '_sync_directory', fail)
    else: monkeypatch.setattr(timing_snapshot.os, 'link', fail)
    directory = tmp_path / 'bundle'
    with pytest.raises(EvidenceUnavailable):
        write_timing_snapshot(directory, store)
    assert directory.is_dir() and store.audit_snapshot() == expected
    if failure != 'write': assert (directory / 'snapshot.json').is_file()
    if failure == 'link': assert (directory / 'manifest.pending').is_file()
    with pytest.raises(EvidenceUnavailable): read_timing_snapshot(directory)


def test_size_limit_is_checked_before_creating_directory(scenario, tmp_path, monkeypatch):
    monkeypatch.setattr(timing_snapshot, 'MAX_SNAPSHOT_BYTES', 16)
    directory = tmp_path / 'oversized'
    with pytest.raises(EvidenceUnavailable): write_timing_snapshot(directory, scenario[0])
    assert not directory.exists()


def test_readback_never_queries_or_constructs_live_adapters(scenario, tmp_path, monkeypatch):
    directory = tmp_path / 'bundle'
    expected = write_timing_snapshot(directory, populated(scenario))
    def forbidden(*args, **kwargs): raise AssertionError('no adapter calls allowed on readback')
    monkeypatch.setattr(TimingQueries, 'query', forbidden)
    monkeypatch.setattr(TimingQueries, '__init__', forbidden)
    monkeypatch.setattr(TimingIncidents, 'dispatch', forbidden)
    monkeypatch.setattr(TimingIncidents, '__init__', forbidden)
    assert read_timing_snapshot(directory) == expected


@pytest.mark.parametrize('from_file', [False, True])
def test_huge_integer_time_is_normalized_to_evidence_unavailable(scenario, tmp_path, from_file):
    directory = tmp_path / 'bundle'
    snapshot = write_timing_snapshot(directory, scenario[0])
    snapshot['store']['lifecycle']['now'] = 10 ** 400
    if from_file:
        raw = canonical(snapshot)
        (directory / 'snapshot.json').write_bytes(raw)
        manifest = json.loads((directory / 'manifest.json').read_text())
        manifest.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        (directory / 'manifest.json').write_bytes(canonical(manifest))
    with pytest.raises(EvidenceUnavailable, match='malformed timing snapshot'):
        if from_file:
            read_timing_snapshot(directory)
        else:
            validate_timing_snapshot(snapshot)


def test_incident_without_any_retained_revision_cannot_pass_linkage(scenario):
    snapshot = capture_timing_snapshot(scenario[0])
    state = snapshot['store']['state']
    state['incident'] = {'incident_id': 'SYNTHETIC-INCIDENT-1', 'revision': 0,
                         'report_revision_id': None}
    resign(state)
    with pytest.raises(EvidenceUnavailable, match='current Incident revision mismatch'):
        validate_timing_snapshot(snapshot)


def test_revision_order_must_follow_dispatch_order(scenario):
    snapshot = capture_timing_snapshot(populated(scenario))
    store = snapshot['store']
    first, second = store['revisions']
    first['dispatch_id'], second['dispatch_id'] = second['dispatch_id'], first['dispatch_id']
    resign(first)
    resign(second)
    # Keep individual effect/revision links consistent while reversing their chronology.
    for effect in store['effects']:
        effect['report_revision_id'] = next(r['revision_id'] for r in store['revisions']
                                           if r['dispatch_id'] == effect['dispatch_id'])
        resign(effect)
    with pytest.raises(EvidenceUnavailable, match='revision dispatch order mismatch'):
        validate_timing_snapshot(snapshot)


@pytest.mark.parametrize('now', [-1, True, '1'])
def test_invalid_lifecycle_times_have_controlled_exception(scenario, now):
    snapshot = capture_timing_snapshot(scenario[0])
    snapshot['store']['lifecycle']['now'] = now
    with pytest.raises(EvidenceUnavailable, match='malformed timing snapshot'):
        validate_timing_snapshot(snapshot)
