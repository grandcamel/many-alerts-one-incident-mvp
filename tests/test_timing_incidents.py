import hashlib
import json
from copy import deepcopy

import pytest

from prototype.run_timing.executor import Lifecycle
from prototype.run_timing.timing_incidents import (
    INCIDENT_ID,
    MAX_WRITES,
    SECTIONS,
    IncidentRejected,
    TimingIncidents,
)
from prototype.run_timing.timing_queries import TimingQueries


@pytest.fixture
def setup():
    queries = TimingQueries('incident-test', Lifecycle())
    notification = queries.query('notification', 'notification.get', {})
    alerts = notification['items'][0]['value']['alerts']
    store = TimingIncidents(queries, notification['response_id'])
    return store, queries, notification, alerts


def report(setup, members):
    _, _, notification, alerts = setup
    return {'sections': dict.fromkeys(SECTIONS, 'Synthetic statement; human support review required.'),
            'references': [{'response_id': notification['response_id'], 'item_index': 0}],
            'explanations': [{'fingerprint': a['fingerprint'],
                              'relation': 'direct' if a['fingerprint'] in members else 'unexplained'}
                             for a in alerts], 'correction_of': None}


def create(setup, members=None, request_id='create'):
    store, _, _, alerts = setup
    members = members if members is not None else [alerts[1]['fingerprint']]
    return store.dispatch(request_id, 'create', {'summary': 'Synthetic investigation',
                                                'members': members, 'report': report(setup, members)})


def append(setup, members, *, request_id='append', revision=None, correction=None):
    store = setup[0]
    incident = store.inspect()['incident']
    content = report(setup, set(incident['members']) | set(members))
    content['correction_of'] = correction
    return store.dispatch(request_id, 'append', {'incident_id': INCIDENT_ID,
        'expected_revision': incident['revision'] if revision is None else revision,
        'members': members, 'report': content})


def digest(record):
    body = deepcopy(record)
    expected = body.pop('sha256')
    assert hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest() == expected
    assert body['scope'] == 'OFFLINE_SYNTHETIC_INCIDENT_ONLY'
    assert body['native_launch'] == 'CLOSED'


def test_empty_candidate_dispatch_is_not_effect_and_readback_is_detached(setup):
    store, queries, _, _ = setup
    empty = store.candidates()
    assert empty['items'] == []
    dispatch = create(setup)
    assert dispatch['effect_outcome'] == 'pending'
    assert store.candidates()['items'] == [] and store.inspect()['incident'] is None
    dispatch_id = dispatch['dispatch_id']
    dispatch['effect_outcome'] = 'confirmed'
    assert store.read_record('dispatch', dispatch_id)['effect_outcome'] == 'pending'
    queries.lifecycle.advance(4)
    effect = store.complete(dispatch_id)
    candidate = store.candidates()['items'][0]
    revision = candidate['report']
    assert candidate['severity'] == 'Sev-2' and candidate['urgency'] == 'High'
    assert candidate['source'] == 'Monitoring systems' and candidate['status'] == 'open'
    assert revision['prepared_at_virtual_seconds'] == 0
    assert effect['observed_at_virtual_seconds'] == 4
    assert effect['report_revision_id'] == revision['revision_id']
    for record in [empty, store.read_record('dispatch', dispatch_id), effect, revision,
                   store.candidates(), store.inspect()]:
        digest(record)
    candidate['members'].clear()
    revision['report']['sections']['summary'] = 'tampered'
    assert store.candidates()['items'][0]['members']
    assert store.read_record('revision', effect['report_revision_id'])['report']['sections']['summary'] != 'tampered'


def test_append_ratchets_preserves_labels_and_immutable_correction_history(setup):
    store, _, _, alerts = setup
    initial = store.complete(create(setup)['dispatch_id'])
    old = store.read_record('revision', initial['report_revision_id'])
    critical = alerts[0]['fingerprint']
    new = store.complete(append(setup, [critical], correction=old['revision_id'])['dispatch_id'])
    incident = store.inspect()['incident']
    assert incident['revision'] == 2 and incident['severity'] == 'Sev-1' and incident['urgency'] == 'Critical'
    assert incident['labels'] == sorted(['synthetic-timing', 'fp-' + critical, 'fp-' + alerts[1]['fingerprint']])
    current = store.read_record('revision', new['report_revision_id'])
    assert current['previous_revision_id'] == old['revision_id']
    assert current['report']['correction_of'] == old['revision_id']
    assert store.read_record('revision', old['revision_id']) == old
    store.complete(append(setup, [], request_id='third')['dispatch_id'])
    assert store.inspect()['incident']['severity'] == 'Sev-1'
    assert store.inspect()['incident']['summary'] == 'Synthetic investigation'
    assert len(store.inspect()['revision_ids']) == 3


@pytest.mark.parametrize('disposition,applied', [('confirmed', True), ('failed', False),
    ('unknown_before_apply', False), ('unknown_after_apply', True)])
def test_effect_windows_hold_without_replay_or_promotion(setup, disposition, applied):
    store = setup[0]
    dispatch_id = create(setup)['dispatch_id']
    effect = store.complete(dispatch_id, disposition=disposition)
    snapshot = store.inspect()
    assert (snapshot['incident'] is not None) is applied
    assert len(snapshot['revision_ids']) == int(applied)
    assert snapshot['pending_dispatch_id'] is None
    assert snapshot['hold'] is (disposition != 'confirmed')
    assert effect['effect_outcome'] == ('unknown' if disposition.startswith('unknown') else disposition)
    assert (effect['incident_id'] is not None) is (disposition == 'confirmed')
    assert store.read_record('effect', dispatch_id) == effect
    with pytest.raises(IncidentRejected):
        store.complete(dispatch_id)
    if disposition != 'confirmed':
        with pytest.raises(IncidentRejected, match='held'):
            store.candidates()
        with pytest.raises(IncidentRejected, match='held'):
            create(setup, request_id='retry')
        assert store.inspect()['hold']  # Operator read-back never clears uncertain effect.


def test_append_uncertain_after_apply_retains_both_revisions(setup):
    store = setup[0]
    first = store.complete(create(setup)['dispatch_id'])
    store.complete(append(setup, [])['dispatch_id'], disposition='unknown_after_apply')
    assert store.inspect()['incident']['revision'] == 2
    assert store.read_record('revision', first['report_revision_id'])['previous_revision_id'] is None
    assert store.inspect()['hold'] and len(store.inspect()['revision_ids']) == 2


@pytest.mark.parametrize('at,cancel', [(5, True), (270, False), (300, False)])
def test_revocation_blocks_new_work_but_allows_pending_completion(setup, at, cancel):
    store, queries, _, _ = setup
    dispatch_id = create(setup)['dispatch_id']
    queries.lifecycle.advance(at, cancel=cancel)
    with pytest.raises(IncidentRejected, match='closed'):
        store.candidates()
    with pytest.raises(IncidentRejected, match='closed'):
        create(setup, request_id='next')
    assert store.complete(dispatch_id)['effect_outcome'] == 'confirmed'
    assert store.inspect()['incident']['revision'] == 1


def test_pending_unknown_completion_duplicate_request_and_second_create(setup):
    store = setup[0]
    first = create(setup)
    for request in ['create', 'second']:
        with pytest.raises(IncidentRejected, match='pending'):
            create(setup, request_id=request)
    with pytest.raises(IncidentRejected):
        store.complete('foreign', disposition='confirmed')
    with pytest.raises(IncidentRejected):
        store.complete(first['dispatch_id'], disposition='unsupported')
    assert store.inspect()['pending_dispatch_id'] == first['dispatch_id']
    store.complete(first['dispatch_id'])
    with pytest.raises(IncidentRejected, match='duplicate'):
        append(setup, [], request_id='create')
    with pytest.raises(IncidentRejected, match='already exists'):
        create(setup, request_id='second')


@pytest.mark.parametrize('revision', [0, 2, True, 1.0, '1'])
def test_stale_or_invalid_expected_revision_is_not_a_dispatch(setup, revision):
    store = setup[0]
    store.complete(create(setup)['dispatch_id'])
    before = store.inspect()
    with pytest.raises(IncidentRejected, match='revision mismatch'):
        append(setup, [], revision=revision)
    assert store.inspect() == before
    assert append(setup, [])['dispatch_id'].endswith('/02')


@pytest.mark.parametrize('fault', ['extra', 'empty_members', 'foreign_member', 'duplicate_member',
    'blank_summary', 'long_summary', 'missing_section', 'blank_section', 'long_section',
    'missing_explanation', 'duplicate_explanation', 'foreign_explanation', 'bad_relation',
    'unexplained_member', 'foreign_reference', 'negative_index', 'boolean_index',
    'large_index', 'many_references', 'foreign_correction', 'byte_cap'])
def test_invalid_payload_consumes_no_identity_or_sequence(setup, fault):
    store, _, _, alerts = setup
    member = alerts[1]['fingerprint']
    content = report(setup, [member])
    payload = {'summary': 'Synthetic', 'members': [member], 'report': content}
    if fault == 'extra': payload['extra'] = 1
    elif fault == 'empty_members': payload['members'] = []
    elif fault == 'foreign_member': payload['members'] = ['unknown']
    elif fault == 'duplicate_member': payload['members'] *= 2
    elif fault == 'blank_summary': payload['summary'] = ' '
    elif fault == 'long_summary': payload['summary'] = 'x' * 201
    elif fault == 'missing_section': del content['sections']['summary']
    elif fault == 'blank_section': content['sections']['summary'] = ' '
    elif fault == 'long_section': content['sections']['summary'] = 'x' * 2049
    elif fault == 'missing_explanation': content['explanations'].pop()
    elif fault == 'duplicate_explanation': content['explanations'][0] = content['explanations'][1]
    elif fault == 'foreign_explanation': content['explanations'][0]['fingerprint'] = 'foreign'
    elif fault == 'bad_relation': content['explanations'][0]['relation'] = 'maybe'
    elif fault == 'unexplained_member': content['explanations'][1]['relation'] = 'unexplained'
    elif fault == 'foreign_reference': content['references'][0]['response_id'] = 'foreign'
    elif fault == 'negative_index': content['references'][0]['item_index'] = -1
    elif fault == 'boolean_index': content['references'][0]['item_index'] = True
    elif fault == 'large_index': content['references'][0]['item_index'] = 1
    elif fault == 'many_references': content['references'] *= 33
    elif fault == 'foreign_correction': content['correction_of'] = 'foreign'
    elif fault == 'byte_cap': content['sections'] = dict.fromkeys(SECTIONS, '雪' * 2048)
    before = store.inspect()
    with pytest.raises(IncidentRejected):
        store.dispatch('create', 'create', payload)
    assert store.inspect() == before
    assert create(setup)['dispatch_id'].endswith('/01')


def test_unknown_or_empty_query_envelope_reference_is_linkage_not_support(setup):
    store, queries, _, alerts = setup
    absent = queries.query('absent', 'traces.get', {'trace_id': 'does-not-exist'})
    member = alerts[0]['fingerprint']
    content = report(setup, [member])
    content['references'] = [{'response_id': absent['response_id'], 'item_index': None}]
    content['explanations'][0]['relation'] = 'downstream'
    accepted = store.dispatch('create', 'create', {'summary': 'Unverified claim',
        'members': [member], 'report': content})
    store.complete(accepted['dispatch_id'])
    assert store.candidates()['items'][0]['report']['report'] == content


def test_same_response_id_must_be_retained_in_same_query_instance(setup):
    store, queries, notification, _ = setup
    other = TimingQueries('incident-test', Lifecycle())
    with pytest.raises(IncidentRejected):
        TimingIncidents(other, notification['response_id'])
    metric = queries.query('metrics', 'metrics.list', {})
    with pytest.raises(IncidentRejected):
        TimingIncidents(queries, metric['response_id'])
    with pytest.raises(TypeError):
        TimingIncidents(None, notification['response_id'])
    restarted = TimingIncidents(queries, notification['response_id'])
    assert restarted.inspect()['session_id'] != store.inspect()['session_id']
    assert restarted.candidates()['items'] == []  # No restart/deduplication guarantee.


def test_write_cap_preserves_all_prior_records(setup):
    store = setup[0]
    first = store.complete(create(setup)['dispatch_id'])
    for number in range(1, MAX_WRITES):
        store.complete(append(setup, [], request_id=f'append-{number}')['dispatch_id'])
    before = store.inspect()
    with pytest.raises(IncidentRejected, match='capacity'):
        append(setup, [], request_id='overflow')
    assert store.inspect() == before
    assert len(before['revision_ids']) == MAX_WRITES
    assert store.read_record('revision', first['report_revision_id'])


@pytest.mark.parametrize('request_id', ['', 'UPPER', 'x' * 65, True, '../path'])
def test_invalid_request_ids_reject_without_dispatch(setup, request_id):
    with pytest.raises(IncidentRejected):
        create(setup, request_id=request_id)
    assert setup[0].inspect()['dispatch_ids'] == []


def test_returned_payload_mutation_cannot_change_prepared_revision(setup):
    store, _, _, alerts = setup
    member = alerts[0]['fingerprint']
    content = report(setup, [member])
    payload = {'summary': 'Original', 'members': [member], 'report': content}
    dispatch = store.dispatch('create', 'create', payload)
    payload['members'].clear()
    content['sections']['summary'] = 'tampered'
    effect = store.complete(dispatch['dispatch_id'])
    assert store.read_record('revision', effect['report_revision_id'])['report']['sections']['summary'] != 'tampered'
    assert store.inspect()['incident']['members'] == [member]
    for kind, identity in [('effect', 'foreign'), ('revision', []), ('unsupported', 'x')]:
        with pytest.raises(IncidentRejected):
            store.read_record(kind, identity)
