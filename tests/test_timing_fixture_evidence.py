import hashlib
import json
import multiprocessing
import os
from dataclasses import asdict, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from prototype.run_timing import fixture_evidence, process_fixture
from prototype.run_timing.fixture_evidence import (
    EvidenceUnavailable,
    read_fixture_evidence,
    write_fixture_evidence,
)
from prototype.run_timing.fixture_ledger import FixtureLedger, run_budgeted_fixture

NOW = datetime(2026, 9, 21, 16, tzinfo=UTC)


def _inputs(directory):
    directory.mkdir()
    worker = b'# synthetic evidence-only worker\n'
    (directory / 'fixture.py').write_bytes(worker)
    capture = b'{"fixture":"retained"}\n'
    result = {'scope': 'FIXED_HOST_FIXTURES_ONLY', 'native_launch': 'CLOSED',
              'attempt_directory': str(directory), 'captured_bytes': len(capture),
              'capture_sha256': hashlib.sha256(capture).hexdigest(),
              'worker_sha256': hashlib.sha256(worker).hexdigest()}
    return capture, result


@pytest.fixture
def receipt(tmp_path):
    directory = tmp_path / 'receipt'
    capture, result = _inputs(directory)
    write_fixture_evidence(directory, capture, result)
    return directory


def test_fixed_process_retains_verifiable_output(tmp_path):
    result = process_fixture.run_fixture('success', tmp_path, 'one', time_scale=0.01)
    directory = Path(result.attempt_directory)
    evidence = read_fixture_evidence(directory)
    assert evidence.native_launch == 'CLOSED'
    assert evidence.scope == 'FIXED_FIXTURE_BYTE_INTEGRITY_ONLY'
    assert evidence.result['outcome']['execution'] == 'completed'
    assert evidence.result == json.loads(json.dumps(asdict(result)))  # This fixture has no estimate.
    capture = (directory / 'capture.bin').read_bytes()
    assert capture and len(capture) == result.captured_bytes
    assert hashlib.sha256(capture).hexdigest() == result.capture_sha256
    assert not (directory / 'closeout.pending').exists()
    for name in ('capture.bin', 'result.json', 'closeout.json'):
        assert (directory / name).stat().st_mode & 0o777 == 0o600


def test_failed_process_receipt_does_not_become_success(tmp_path):
    result = process_fixture.run_fixture('nonzero', tmp_path, 'one', time_scale=0.01)
    evidence = read_fixture_evidence(Path(result.attempt_directory))
    assert evidence.result['outcome']['execution'] == result.outcome.execution != 'completed'


def test_cost_estimate_serialization_preserves_exact_value(tmp_path, monkeypatch):
    original = process_fixture.Transcript.outcome

    def estimated(self, *args, **kwargs):
        return replace(original(self, *args, **kwargs), estimate_usd=Decimal('0.1234567890123456789'))

    monkeypatch.setattr(process_fixture.Transcript, 'outcome', estimated)
    result = process_fixture.run_fixture('success', tmp_path, 'one', time_scale=0.01)
    evidence = read_fixture_evidence(Path(result.attempt_directory))
    assert evidence.result['outcome']['estimate_usd'] == '0.1234567890123456789'
    assert result.outcome.estimate_usd == Decimal('0.1234567890123456789')


def test_incomplete_capture_remains_incomplete_after_readback(tmp_path):
    result = process_fixture.run_fixture('flood', tmp_path, 'one', time_scale=0.01,
                                         capture_limit=64)
    evidence = read_fixture_evidence(Path(result.attempt_directory))
    assert evidence.result['capture_complete'] is False
    assert len((tmp_path / 'one' / 'capture.bin').read_bytes()) <= 64
    assert evidence.result['outcome']['execution'] != 'completed'


@pytest.mark.parametrize('name', ['fixture.py', 'capture.bin', 'result.json', 'closeout.json'])
@pytest.mark.parametrize('operation', ['missing', 'truncated', 'modified', 'symlink', 'fifo', 'directory'])
def test_missing_corrupt_and_nonregular_evidence_is_rejected(receipt, name, operation):
    path = receipt / name
    data = path.read_bytes()
    path.unlink()
    if operation == 'truncated':
        path.write_bytes(data[:len(data) // 2])
    elif operation == 'modified':
        path.write_bytes(b'!' + data[1:])
    elif operation == 'symlink':
        outside = receipt.parent / 'outside'
        outside.write_bytes(data)
        path.symlink_to(outside)
    elif operation == 'fifo':
        os.mkfifo(path)
    elif operation == 'directory':
        path.mkdir()
    with pytest.raises(EvidenceUnavailable):
        read_fixture_evidence(receipt)


@pytest.mark.parametrize('mutation', ['extra-file', 'missing-file', 'version', 'bool-size',
                                      'native-open', 'extra-field', 'duplicate-key', 'oversized'])
def test_manifest_contract_is_bounded_and_closed(receipt, mutation):
    path = receipt / 'closeout.json'
    manifest = json.loads(path.read_bytes())
    if mutation == 'extra-file':
        manifest['files']['../outside'] = {'bytes': 0, 'sha256': '0' * 64}
    elif mutation == 'missing-file':
        del manifest['files']['capture.bin']
    elif mutation == 'version':
        manifest['version'] = True
    elif mutation == 'bool-size':
        manifest['files']['capture.bin']['bytes'] = True
    elif mutation == 'native-open':
        manifest['native_launch'] = 'OPEN'
    elif mutation == 'extra-field':
        manifest['new'] = 'unsupported'
    raw = json.dumps(manifest)
    if mutation == 'duplicate-key':
        raw = '{"version":1,' + raw[1:]
    elif mutation == 'oversized':
        raw += ' ' * 4096
    path.write_text(raw)
    with pytest.raises(EvidenceUnavailable):
        read_fixture_evidence(receipt)


@pytest.mark.parametrize('field,value', [('captured_bytes', -1), ('native_launch', 'OPEN'),
                                       ('scope', 'OTHER'), ('attempt_directory', '/elsewhere'),
                                       ('worker_sha256', '0' * 64)])
def test_matching_manifest_cannot_hide_broken_result_linkage(receipt, field, value):
    path = receipt / 'result.json'
    result = json.loads(path.read_bytes())
    result[field] = value
    path.write_text(json.dumps(result))
    manifest_path = receipt / 'closeout.json'
    manifest = json.loads(manifest_path.read_bytes())
    manifest['files']['result.json'] = {'bytes': path.stat().st_size,
                                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(EvidenceUnavailable, match='linkage'):
        read_fixture_evidence(receipt)


def test_second_publication_cannot_overwrite_receipt(receipt):
    before = {p.name: p.read_bytes() for p in receipt.iterdir()}
    with pytest.raises(EvidenceUnavailable):
        write_fixture_evidence(receipt, before['capture.bin'], json.loads(before['result.json']))
    assert {p.name: p.read_bytes() for p in receipt.iterdir()} == before


def _crash_publication(directory, after_link):
    directory = Path(directory)
    capture, result = _inputs(directory)

    original_link = fixture_evidence.os.link

    def crash(*args):
        if after_link:
            original_link(*args)
        os._exit(17)

    fixture_evidence.os.link = crash
    write_fixture_evidence(directory, capture, result)


@pytest.mark.parametrize('after_link', [False, True])
def test_process_crash_publication_boundary(tmp_path, after_link):
    directory = tmp_path / 'crash'
    child = multiprocessing.get_context('spawn').Process(
        target=_crash_publication, args=(str(directory), after_link))
    child.start()
    child.join(10)
    assert child.exitcode == 17
    assert (directory / 'capture.bin').exists() and (directory / 'closeout.pending').exists()
    if after_link:
        assert read_fixture_evidence(directory).native_launch == 'CLOSED'
    else:
        assert not (directory / 'closeout.json').exists()
        with pytest.raises(EvidenceUnavailable):
            read_fixture_evidence(directory)


def test_failed_flush_prevents_publication(tmp_path, monkeypatch):
    directory = tmp_path / 'failure'
    capture, result = _inputs(directory)

    def failed(*args):
        raise OSError('synthetic storage failure')

    monkeypatch.setattr(fixture_evidence.os, 'fsync', failed)
    with pytest.raises(EvidenceUnavailable):
        write_fixture_evidence(directory, capture, result)
    assert not (directory / 'closeout.json').exists()


def test_closeout_failure_retains_ledger_claim(tmp_path, monkeypatch):
    ledger = FixtureLedger.create(tmp_path / 'fixture.db')

    def failed(*args, **kwargs):
        raise EvidenceUnavailable('synthetic closeout failure')

    monkeypatch.setattr(process_fixture, 'write_fixture_evidence', failed)
    with pytest.raises(process_fixture.FixtureCloseoutError) as error:
        run_budgeted_fixture(ledger, 'success', tmp_path, 'one', NOW,
                             billing_current=True, time_scale=0.01)
    assert error.value.process_result.outcome.execution == 'completed'
    assert error.value.process_result.native_launch == 'CLOSED'
    assert ledger.snapshot(NOW).unresolved == 1
    assert not ledger.claim_launch('one', NOW, billing_current=True).accepted
    assert not ledger.reserve('two', NOW, billing_current=True).accepted


@pytest.mark.parametrize('mutation', ['non-bytes', 'large-capture', 'large-result',
                                      'non-json', 'linkage'])
def test_invalid_write_inputs_leave_no_closeout_files(tmp_path, mutation):
    directory = tmp_path / 'invalid'
    capture, result = _inputs(directory)
    if mutation == 'non-bytes':
        capture = bytearray(capture)
    elif mutation == 'large-capture':
        capture = b'x' * (1024 * 1024 + 1)
    elif mutation == 'large-result':
        result['extra'] = 'x' * (64 * 1024)
    elif mutation == 'non-json':
        result['extra'] = {1, 2}
    else:
        result['capture_sha256'] = '0' * 64
    with pytest.raises(EvidenceUnavailable):
        write_fixture_evidence(directory, capture, result)
    assert {p.name for p in directory.iterdir()} == {'fixture.py'}


def test_final_sync_failure_raises_despite_readable_manifest(tmp_path, monkeypatch):
    directory = tmp_path / 'final-sync'
    capture, result = _inputs(directory)
    original = fixture_evidence._sync_directory
    calls = []

    def fail_final(path):
        calls.append(path)
        if len(calls) == 3:
            raise OSError('synthetic final sync failure')
        original(path)

    monkeypatch.setattr(fixture_evidence, '_sync_directory', fail_final)
    with pytest.raises(EvidenceUnavailable):
        write_fixture_evidence(directory, capture, result)
    assert read_fixture_evidence(directory).native_launch == 'CLOSED'
