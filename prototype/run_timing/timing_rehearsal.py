"""Integrated fixed-process timing rehearsal with retained same-attempt evidence.

No model, native transport, real billing, arbitrary client, callback or write replay.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime
from pathlib import Path

from .executor import seconds
from .fixture_evidence import EvidenceUnavailable, _json, _read, read_fixture_evidence
from .fixture_ledger import FixtureLedger, run_budgeted_fixture
from .process_fixture import ProcessResult
from .rehearsal_bundle import TIMING_SCENARIOS
from .timing_binding import MAX_CALLS, MAX_REQUEST_BYTES
from .timing_binding import SCOPE as BINDING_SCOPE
from .timing_binding import _identifier as _binding_identifier
from .timing_incidents import SCOPE as INCIDENT_SCOPE
from .timing_queries import _arguments
from .timing_snapshot import read_timing_snapshot

SCOPE = 'FIXED_TIMING_REHEARSAL_ONLY'
MAX_AUDIT_BYTES = 16 * 1024 * 1024
RECEIPT_FIELDS = {'type', 'version', 'scope', 'native_launch', 'scenario', 'attempt_id',
                  'query_session_id', 'incident_session_id', 'snapshot_manifest_sha256',
                  'snapshot_manifest_bytes', 'binding_audit_sha256', 'binding_audit_bytes',
                  'capture_phase'}


class RehearsalEvidenceError(EvidenceUnavailable):
    """The fixed process ran, but linked rehearsal evidence was not verified."""

    def __init__(self, result: ProcessResult):
        super().__init__('fixed rehearsal evidence unavailable; preserve process result and reservation')
        self.process_result = result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _require(condition, message):
    if not condition:
        raise EvidenceUnavailable(message)


def _receipt(capture):
    receipts = []
    for line in capture.splitlines():
        event = _json(line)
        if event.get('type') != 'assistant':
            continue
        message = event['message']
        _require(type(message) is dict and message.get('model') == 'fixture-only' and
                 type(message.get('content')) is list,
                 'invalid fixed-client message')
        for content in message['content']:
            if type(content) is dict and content.get('type') == 'timing_rehearsal_receipt':
                receipts.append(content)
    _require(len(receipts) == 1, 'exactly one retained rehearsal receipt required')
    receipt = receipts[0]
    _require(set(receipt) == RECEIPT_FIELDS and type(receipt['version']) is int and
             receipt['version'] == 1 and receipt['scope'] == SCOPE and receipt['native_launch'] == 'CLOSED',
             'invalid rehearsal receipt schema')
    return receipt


def _audit_links(audit, snapshot, attempt_id):
    _require(type(audit) is dict and type(audit.get('version')) is int and audit['version'] == 1 and
             audit.get('scope') == BINDING_SCOPE and audit.get('native_launch') == 'CLOSED' and
             audit.get('attempt_id') == attempt_id, 'binding audit scope or attempt mismatch')
    store = snapshot['store']
    _require(audit.get('incident') == store and audit.get('queries') == store['queries'] and
             audit.get('initial_notification_response_id') == store['notification_response_id'],
             'binding and Incident snapshots differ')
    history = audit['history']
    status = audit['history_status']
    _require(type(history) is list and 0 < len(history) <= MAX_CALLS and
             type(status['retained_calls']) is int and status['retained_calls'] == len(history) and
             type(status['dropped_observations']) is int and status['dropped_observations'] == 0 and
             status['coverage'] == 'complete_for_retained_calls_only', 'binding history incomplete')
    queries = {row['request_id']: row for row in store['queries']['responses']}
    dispatches = {row['request_id']: row for row in store['dispatches']}
    seen_queries, seen_dispatches, seen_calls = set(), set(), set()
    for sequence, row in enumerate(history, 1):
        _require(type(row['sequence']) is int and row['sequence'] == sequence and
                 row['outcome'] == 'accepted', 'fixed rehearsal call rejected or reordered')
        request, response = row['request'], row['response']
        _require(type(request) is dict and set(request) == {'call_id', 'operation', 'arguments'} and
                 len(_canonical(request)) <= MAX_REQUEST_BYTES and
                 row['call_id'] == request['call_id'] and type(row['call_id']) is str and
                 _binding_identifier(row['call_id']) == row['call_id'] and
                 row['call_id'] not in seen_calls and
                 row['response_sha256'] == hashlib.sha256(_canonical(response)).hexdigest(),
                 'binding call identity or response bytes mismatch')
        call_id = row['call_id']
        seen_calls.add(call_id)
        if call_id in queries:
            _require(response == queries[call_id] and request['operation'] == response['operation'] and
                     response['arguments'] == _arguments(request['operation'], request['arguments']),
                     'query history linkage mismatch')
            seen_queries.add(call_id)
        elif call_id in dispatches:
            _require(response == dispatches[call_id] and
                     request['operation'] == 'incidents.' + response['operation'] and
                     response['payload_sha256'] == hashlib.sha256(_canonical(request['arguments'])).hexdigest(),
                     'dispatch history linkage mismatch')
            seen_dispatches.add(call_id)
        else:
            _require(type(response) is dict and
                     request['operation'] == 'incidents.candidates' and request['arguments'] == {} and
                     response.get('kind') == 'candidates' and
                     response.get('session_id') == store['state']['session_id'], 'unlinked binding call')
            _require(set(response) == {'version', 'scope', 'native_launch', 'kind', 'session_id',
                     'observed_at_virtual_seconds', 'candidate_window_seconds',
                     'notification_response_id', 'items', 'sha256'} and
                     type(response['version']) is int and response['version'] == 1 and
                     response['scope'] == INCIDENT_SCOPE and response['native_launch'] == 'CLOSED' and
                     response['notification_response_id'] == store['notification_response_id'] and
                     type(response['candidate_window_seconds']) is int and
                     response['candidate_window_seconds'] == 1800 and response['items'] == [] and
                     seconds(response['observed_at_virtual_seconds']) == 0,
                     'fixed initial candidate response malformed')
            body = {key: value for key, value in response.items() if key != 'sha256'}
            _require(response.get('sha256') == hashlib.sha256(_canonical(body)).hexdigest(),
                     'candidate response digest mismatch')
    _require(seen_queries == set(queries) and seen_dispatches == set(dispatches),
             'binding history lacks retained query or dispatch')


def read_rehearsal_evidence(directory: Path, *, scenario: str) -> dict:
    """Check the actual child's artifacts and receipt; never run an in-parent replacement flow."""
    directory = Path(directory).absolute()
    try:
        _require(scenario in TIMING_SCENARIOS, 'unknown fixed rehearsal scenario')
        process_receipt = read_fixture_evidence(directory)
        process = process_receipt.result
        _require(process.get('scenario') == scenario, 'supervisor scenario mismatch')
        _require(process_receipt.stdout is not None and process_receipt.stderr is not None,
                 'integrated rehearsal requires version-2 stream evidence')
        stdout, stderr = process_receipt.stdout, process_receipt.stderr
        _require(not stderr, 'integrated rehearsal fixture emitted stderr')
        receipt = _receipt(stdout)
        _require(receipt['scenario'] == scenario and receipt['attempt_id'] == directory.name,
                 'rehearsal receipt identity mismatch')
        manifest_bytes = _read(directory / 'timing-snapshot/manifest.json', 4096)
        audit_bytes = _read(directory / 'binding-audit.json', MAX_AUDIT_BYTES)
        for prefix, raw in [('snapshot_manifest', manifest_bytes), ('binding_audit', audit_bytes)]:
            _require(type(receipt[prefix + '_bytes']) is int and receipt[prefix + '_bytes'] == len(raw) and
                     receipt[prefix + '_sha256'] == hashlib.sha256(raw).hexdigest(),
                     'rehearsal receipt file digest mismatch')
        snapshot = read_timing_snapshot(directory / 'timing-snapshot')
        # Recheck the manifest used by the nested reader in the trusted stable directory.
        _require(_read(directory / 'timing-snapshot/manifest.json', 4096) == manifest_bytes,
                 'snapshot manifest changed during read-back')
        store = snapshot['store']
        _require(store['queries']['attempt_id'] == directory.name and
                 receipt['query_session_id'] == store['queries']['session_id'] and
                 receipt['incident_session_id'] == store['state']['session_id'], 'snapshot namespace mismatch')
        audit = _json(audit_bytes)
        _audit_links(audit, snapshot, directory.name)
        state = store['state']
        effects = [row['effect_outcome'] for row in store['effects']]
        if scenario == 'timing_rehearsal':
            _require(receipt['capture_phase'] == 'final' and effects == ['confirmed', 'confirmed'] and
                     len(store['revisions']) == 2 and not state['hold'] and
                     state['pending_dispatch_id'] is None, 'fixed successful flow incomplete')
        elif scenario == 'timing_unknown':
            _require(receipt['capture_phase'] == 'final' and effects == ['unknown'] and state['hold'] and
                     len(store['revisions']) == 1 and state['pending_dispatch_id'] is None,
                     'fixed uncertain flow was promoted or lost')
        else:
            _require(receipt['capture_phase'] == 'before_wait' and effects == [] and
                     state['pending_dispatch_id'] is not None and not store['revisions'],
                     'waiting flow must retain its pending dispatch')
        _require(all(type(process[field]) is bool for field in
                     ('capture_complete', 'root_reaped', 'group_gone', 'pipes_closed')),
                 'invalid process completion flags')
        execution = process['outcome']['execution']
        completed = (scenario == 'timing_rehearsal' and execution == 'completed' and
                     process['capture_complete'] and process['root_reaped'] and process['group_gone'] and
                     process['pipes_closed'])
        return {'version': 1, 'scope': SCOPE, 'native_launch': 'CLOSED',
                'attempt_id': directory.name, 'scenario': scenario,
                'integration_outcome': 'completed' if completed else 'held',
                'process': process, 'process_manifest_sha256': process_receipt.manifest_sha256,
                'receipt': receipt, 'effect_outcomes': effects,
                'retained_revisions': len(store['revisions']), 'pending_dispatch_id': state['pending_dispatch_id'],
                'effect_hold': state['hold'], 'audit_completeness': 'NOT_ASSESSED',
                'billing_actual': None, 'qualification': 'NOT_ASSESSED'}
    except (OSError, KeyError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise EvidenceUnavailable('fixed rehearsal read-back malformed or unavailable') from exc


def run_timing_rehearsal(ledger: FixtureLedger, scenario: str, output_parent: Path,
                         attempt_id: str, now: datetime, *, billing_current: bool,
                         time_scale: float = 1.0, capture_limit: int = 1024 * 1024,
                         cancel: threading.Event | None = None) -> dict:
    """Reserve/claim once, supervise fixed child, verify linked evidence; never reconcile cost."""
    if scenario not in TIMING_SCENARIOS:
        raise ValueError('unknown fixed timing rehearsal')
    result = run_budgeted_fixture(ledger, scenario, output_parent, attempt_id, now,
                                  billing_current=billing_current, time_scale=time_scale,
                                  capture_limit=capture_limit, cancel=cancel)
    try:
        return read_rehearsal_evidence(Path(result.attempt_directory), scenario=scenario)
    except EvidenceUnavailable as exc:
        raise RehearsalEvidenceError(result) from exc
