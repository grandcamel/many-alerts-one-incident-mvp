"""Parent-owned bridge for one closed supervised synthetic stream fixture.

This joins a fixed child to the local incremental TLS harness. It is deliberately
not a public client configuration, generic callback, or authenticated control API.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from prototype.mediated_client import (
    FIXTURE_REQUEST,
    STREAM_FIXTURE_DELTA,
    STREAM_FIXTURE_RESPONSE,
    IncrementalStreamHarness,
    create_certificates,
)

from ._streaming_worker import STREAM_SCENARIOS
from .fixture_evidence import (
    EvidenceUnavailable,
    _json,
    _read,
    _sync_directory,
    _write,
    read_fixture_evidence,
)
from .outcomes import seconds

_SCOPE = "FIXED_SUPERVISED_STREAM_ONLY"
_VERSION = 1
_BOOTSTRAP = "stream-bootstrap.json"
_SIDECAR = "stream-supervisor.json"
_PENDING = "stream-supervisor.pending"
_MAX_BOOTSTRAP = 12 * 1024
_MAX_SIDECAR = 16 * 1024
_MAX_LINE = 64 * 1024
_SAFE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_LEASE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_STREAM_MODES = {
    "stream_complete": "complete",
    "stream_truncate": "truncate",
    "stream_duplicate_terminal": "duplicate_terminal",
    "stream_wait": "complete",
    "stream_child_failure": "complete",
    "stream_missing_receipt": "complete",
    "stream_bad_ack": "complete",
    "stream_duplicate_ack": "complete",
    "stream_bad_receipt": "complete",
}


@dataclass(frozen=True)
class _ChildRecords:
    acknowledgements: tuple[dict[str, object], ...]
    receipts: tuple[dict[str, object], ...]
    gaps: tuple[str, ...]
    ack_line: int | None
    receipt_line: int | None


def build_streaming_worker() -> bytes:
    """Return exactly the closed child source after enforcing the 64 KiB cap."""
    worker = Path(__file__).with_name("_streaming_worker.py").read_bytes()
    if len(worker) > 64 * 1024:
        raise ValueError("fixed streaming worker capacity exceeded")
    return worker


class StreamSession:
    """Internal bridge constructed only for a closed ``STREAM_SCENARIOS`` entry."""

    def __init__(self, directory: Path, scenario: str, worker_sha256: str, time_scale: float):
        directory = Path(directory).absolute()
        if scenario not in STREAM_SCENARIOS or scenario not in _STREAM_MODES:
            raise ValueError("unknown fixed streaming scenario")
        if not directory.is_dir() or not _SAFE.fullmatch(directory.name):
            raise ValueError("invalid stream attempt directory")
        if not isinstance(worker_sha256, str) or not _HEX.fullmatch(worker_sha256):
            raise ValueError("invalid streaming worker digest")
        scale = seconds(time_scale)
        if not 0.001 <= scale <= 1:
            raise ValueError("time scale must be between 0.001 and 1")
        self.directory = directory
        self.scenario = scenario
        self.worker_sha256 = worker_sha256
        self.time_scale = scale
        self._lock = threading.RLock()
        self._hold = False
        self._gaps: set[str] = set()
        self._released = False
        self._revoke_requested = False
        self._revoke_acknowledged = False
        self._close_failures: list[str] = []
        self._ack: dict[str, object] | None = None
        self._receipt: dict[str, object] | None = None
        self._started = time.monotonic()
        self._ack_observed_us: int | None = None
        self._released_us: int | None = None
        self._revoke_requested_us: int | None = None
        self._revoke_acknowledged_us: int | None = None
        self._closeout_finished_us: int | None = None
        self._closeout_duration_us: int | None = None
        self._cert_directory = directory / ".stream-tls"
        self._bootstrap_removed = False
        self._closed = False
        self._harness: IncrementalStreamHarness | None = None
        try:
            self._certificates = create_certificates(self._cert_directory)
            # A fixed local transport bound avoids TLS scheduling races at scaled
            # supervisor time; the parent still enforces its own work deadline.
            self._harness = IncrementalStreamHarness(
                self._certificates, stream_mode=_STREAM_MODES[scenario], timeout_seconds=2.0,
            )
            self._harness.start()
            self._grant = self._harness.register(directory.name, ttl_seconds=270.0)
            self._harness.activate(self._grant.lease_id)
            self._bootstrap_raw = self._write_bootstrap()
            self._bootstrap_sha256 = hashlib.sha256(self._bootstrap_raw).hexdigest()
        except Exception:
            if self._harness is not None:
                try:
                    self._harness.stop()
                except RuntimeError:
                    pass
            try:
                (directory / _BOOTSTRAP).unlink()
            except FileNotFoundError:
                pass
            shutil.rmtree(self._cert_directory, ignore_errors=True)
            raise

    @property
    def hold(self) -> bool:
        with self._lock:
            return self._hold

    def observe_stdout(self, line: bytes, elapsed: float, allow_release: bool) -> None:
        """Inspect one already-retained complete stdout line; never accept a parent copy."""
        seconds(elapsed)
        if type(allow_release) is not bool:
            raise TypeError("release gate must be explicit")
        if type(line) is not bytes or len(line) > _MAX_LINE:
            with self._lock:
                self._gap("malformed_child_stdout")
            return
        value = _line_json(line)
        if value is None:
            return
        content = _typed_content(value)
        for item in content:
            kind = item.get("type")
            with self._lock:
                if kind == "fixture_stream_ack":
                    self._observe_ack(item, elapsed, allow_release)
                elif kind == "fixture_stream_receipt":
                    self._observe_receipt(item)

    def request_revoke(self, reason: str, elapsed: float) -> None:
        """Record a revoke immediately and poll the harness lock without blocking supervision."""
        seconds(elapsed)
        if not isinstance(reason, str) or not reason or len(reason) > 64:
            raise ValueError("invalid stream revoke reason")
        with self._lock:
            self._revoke_requested = True
            if self._revoke_requested_us is None:
                self._revoke_requested_us = _session_elapsed_us(self._started)
            # Lifecycle emits revoke after an ordinary parent exit as well as
            # for interruption.  It stops any future release, but the process
            # outcome decides whether that completed drain is eligible.
            if reason != "lifecycle":
                self._hold = True
                self._gap("revoke_" + reason)
        self.poll_revoke()

    def poll_revoke(self) -> bool:
        """Best-effort nonblocking lease revocation; actual acknowledgement is retained."""
        with self._lock:
            if not self._revoke_requested or self._revoke_acknowledged:
                return self._revoke_acknowledged
        assert self._harness is not None
        lock = self._harness._lock  # Internal fixture bridge; not a public harness API.
        if not lock.acquire(blocking=False):
            return False
        try:
            lease = self._harness._leases.get(self._grant.lease_id)
            if lease is None:
                with self._lock:
                    self._gap("revoke_lease_missing")
                return False
            lease.state = "REVOKED"
            with self._lock:
                self._revoke_acknowledged = True
                self._revoke_acknowledged_us = max(
                    self._revoke_requested_us or 0, _session_elapsed_us(self._started)
                )
            return True
        finally:
            lock.release()

    def close(self) -> None:
        """Run bounded bridge closeout after process containment, never inside work time."""
        close_started = time.monotonic()
        with self._lock:
            if self._closed:
                return
            self._revoke_requested = True
            if self._revoke_requested_us is None:
                self._revoke_requested_us = _session_elapsed_us(self._started)
        deadline = time.monotonic() + 5.0
        while not self.poll_revoke() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self._revoke_acknowledged:
            with self._lock:
                self._close_failures.append("revoke_unacknowledged")
                self._gap("revoke_unacknowledged")
        try:
            assert self._harness is not None
            self._harness.stop()
        except RuntimeError:
            with self._lock:
                self._close_failures.append("harness_stop_failed")
                self._gap("harness_stop_failed")
        self._remove_bootstrap()
        try:
            shutil.rmtree(self._cert_directory)
        except OSError:
            with self._lock:
                self._close_failures.append("tls_cleanup_failed")
                self._gap("tls_cleanup_failed")
        with self._lock:
            self._closeout_finished_us = _session_elapsed_us(self._started)
            self._closeout_duration_us = max(0, int((time.monotonic() - close_started) * 1_000_000))
            if self._closeout_finished_us > 310_000_000:
                self._gap("closeout_age_exceeded")
            if self._closeout_duration_us > 5_000_000:
                self._close_failures.append("close_duration_exceeded")
                self._gap("close_duration_exceeded")
            self._closed = True

    def write_evidence(self, process_result: object) -> dict[str, object]:
        """Publish a small immutable join only after ordinary version-2 closeout exists."""
        if not self._closed:
            raise EvidenceUnavailable("stream bridge closeout must finish before evidence publication")
        if (getattr(process_result, "attempt_directory", None) != str(self.directory) or
                getattr(process_result, "worker_sha256", None) != self.worker_sha256 or
                getattr(process_result, "scenario", None) != self.scenario):
            raise EvidenceUnavailable("stream process result does not bind this session")
        base = read_fixture_evidence(self.directory)
        if base.stdout is None or base.stderr is None:
            raise EvidenceUnavailable("stream integration requires version-2 fixture evidence")
        if base.stderr:
            self._gap("stderr_nonempty")
        records = _parse_child_records(base.stdout, self.directory.name, self._grant.lease_id,
                                       self._bootstrap_sha256)
        with self._lock:
            gaps = set(self._gaps) | set(records.gaps)
            if self._ack is not None and self._ack not in records.acknowledgements:
                raise EvidenceUnavailable("parent stream acknowledgement lacks retained stdout evidence")
            if self._receipt is not None and self._receipt not in records.receipts:
                raise EvidenceUnavailable("parent stream receipt lacks retained stdout evidence")
            assert self._harness is not None
            parent_stream = tuple(asdict(item) for item in self._harness.stream_receipts)
            parent_upstream = tuple(asdict(item) for item in self._harness.upstream_receipts)
            if len(parent_stream) != 1 or len(parent_upstream) != 1:
                gaps.add("parent_receipt_count")
            payload = {
                "version": _VERSION,
                "scope": _SCOPE,
                "native_launch": "CLOSED",
                "attempt_id": self.directory.name,
                "lease_id": self._grant.lease_id,
                "scenario": self.scenario,
                "worker_sha256": self.worker_sha256,
                "process_manifest_sha256": base.manifest_sha256,
                "stdout": {"bytes": len(base.stdout), "sha256": hashlib.sha256(base.stdout).hexdigest()},
                "bootstrap": {"bytes": len(self._bootstrap_raw), "sha256": self._bootstrap_sha256,
                              "removed": self._bootstrap_removed},
                "control": {"released": self._released, "revoke_requested": self._revoke_requested,
                            "revoke_acknowledged": self._revoke_acknowledged,
                            "ack_observed_us": self._ack_observed_us, "released_us": self._released_us,
                            "revoke_requested_us": self._revoke_requested_us,
                            "revoke_acknowledged_us": self._revoke_acknowledged_us,
                            "closeout_finished_us": self._closeout_finished_us,
                            "closeout_duration_us": self._closeout_duration_us,
                            "close_failures": list(self._close_failures)},
                "parent": {"stream_receipts": list(parent_stream), "upstream_receipts": list(parent_upstream)},
                "child": {"acknowledgements": list(records.acknowledgements),
                          "receipts": list(records.receipts)},
                "gaps": sorted(gaps),
            }
        _write(self.directory / _PENDING, _encoded(payload, _MAX_SIDECAR))
        os.link(self.directory / _PENDING, self.directory / _SIDECAR)
        (self.directory / _PENDING).unlink()
        _sync_directory(self.directory)
        return read_stream_evidence(self.directory)

    def _write_bootstrap(self) -> bytes:
        assert self._harness is not None
        endpoint = self._harness.url + "/v1/messages"
        value = {
            "version": _VERSION,
            "scenario": self.scenario,
            "attempt_id": self.directory.name,
            "lease_id": self._grant.lease_id,
            "worker_sha256": self.worker_sha256,
            "endpoint": endpoint,
            "ca_pem": self._certificates.ca_cert.read_text(encoding="utf-8"),
            "token": self._grant.token,
        }
        raw = _encoded(value, _MAX_BOOTSTRAP)
        _write(self.directory / _BOOTSTRAP, raw)
        _sync_directory(self.directory)
        return raw

    def _remove_bootstrap(self) -> None:
        if self._bootstrap_removed:
            return
        try:
            (self.directory / _BOOTSTRAP).unlink()
            _sync_directory(self.directory)
            self._bootstrap_removed = True
        except OSError:
            with self._lock:
                self._close_failures.append("bootstrap_cleanup_failed")
                self._gap("bootstrap_cleanup_failed")

    def _observe_ack(self, item: dict[str, object], elapsed: float, allow_release: bool) -> None:
        if not _valid_ack(item, self.directory.name, self._grant.lease_id, self._bootstrap_sha256):
            self._gap("bad_ack")
            self._hold = True
            return
        if self._ack is not None:
            self._gap("duplicate_ack")
            self._hold = True
            return
        self._ack = item
        self._ack_observed_us = _session_elapsed_us(self._started)
        if self.scenario == "stream_wait":
            return
        if self._hold or not allow_release or self._revoke_requested:
            self._gap("release_not_allowed")
            return
        if not self._harness._first_frame_forwarded.is_set():
            self._gap("parent_first_frame_missing")
            self._hold = True
            return
        try:
            self._harness.release_final_frame()
        except RuntimeError:
            self._gap("release_failed")
            self._hold = True
            return
        self._released = True
        self._released_us = _session_elapsed_us(self._started)

    def _observe_receipt(self, item: dict[str, object]) -> None:
        if not _valid_receipt(item, self.directory.name, self._grant.lease_id, self._bootstrap_sha256):
            self._gap("bad_receipt")
            self._hold = True
            return
        if self._receipt is not None:
            self._gap("duplicate_receipt")
            self._hold = True
            return
        self._receipt = item

    def _gap(self, value: str) -> None:
        self._gaps.add(value)


def read_stream_evidence(directory: Path) -> dict[str, object]:
    """Re-read physical stdout/base closeout/sidecar and return completed or held summary."""
    directory = Path(directory).absolute()
    try:
        base = read_fixture_evidence(directory)
        if base.stdout is None or base.stderr is None:
            raise EvidenceUnavailable("stream integration requires retained stream evidence")
        raw = _read(directory / _SIDECAR, _MAX_SIDECAR)
        sidecar = _json(raw)
        if not isinstance(sidecar, dict) or set(sidecar) != {
            "version", "scope", "native_launch", "attempt_id", "lease_id", "scenario", "worker_sha256",
            "process_manifest_sha256", "stdout", "bootstrap", "control", "parent", "child", "gaps",
        }:
            raise EvidenceUnavailable("unsupported stream supervisor manifest")
        if (type(sidecar["version"]) is not int or sidecar["version"] != _VERSION or sidecar["scope"] != _SCOPE or
                sidecar["native_launch"] != "CLOSED" or not _SAFE.fullmatch(sidecar["attempt_id"]) or
                sidecar["attempt_id"] != directory.name or sidecar["scenario"] not in STREAM_SCENARIOS or
                not isinstance(sidecar["lease_id"], str) or _LEASE.fullmatch(sidecar["lease_id"]) is None or
                not _HEX.fullmatch(sidecar["worker_sha256"]) or
                base.result.get("scenario") != sidecar["scenario"] or
                base.result.get("worker_sha256") != sidecar["worker_sha256"] or
                sidecar["process_manifest_sha256"] != base.manifest_sha256):
            raise EvidenceUnavailable("stream supervisor identity mismatch")
        stdout = sidecar["stdout"]
        bootstrap = sidecar["bootstrap"]
        control = sidecar["control"]
        parent = sidecar["parent"]
        child = sidecar["child"]
        gaps = sidecar["gaps"]
        if (not _byte_record(stdout, base.stdout) or not isinstance(bootstrap, dict) or
                set(bootstrap) != {"bytes", "sha256", "removed"} or
                type(bootstrap["bytes"]) is not int or not 1 <= bootstrap["bytes"] <= _MAX_BOOTSTRAP or
                not isinstance(bootstrap["sha256"], str) or not _HEX.fullmatch(bootstrap["sha256"]) or
                type(bootstrap["removed"]) is not bool or not isinstance(control, dict) or
                set(control) != {"released", "revoke_requested", "revoke_acknowledged", "ack_observed_us",
                                 "released_us", "revoke_requested_us", "revoke_acknowledged_us",
                                 "closeout_finished_us", "closeout_duration_us", "close_failures"} or
                any(type(control[key]) is not bool for key in ("released", "revoke_requested", "revoke_acknowledged")) or
                not isinstance(control["close_failures"], list) or len(control["close_failures"]) > 8 or
                not all(isinstance(item, str) and len(item) <= 64 for item in control["close_failures"]) or
                not isinstance(parent, dict) or set(parent) != {"stream_receipts", "upstream_receipts"} or
                not isinstance(child, dict) or set(child) != {"acknowledgements", "receipts"} or
                not isinstance(gaps, list) or len(gaps) > 32 or not all(isinstance(item, str) and len(item) <= 64 for item in gaps)):
            raise EvidenceUnavailable("malformed stream supervisor manifest")
        _validate_control(control)
        stream_receipts = parent["stream_receipts"]
        upstream_receipts = parent["upstream_receipts"]
        if (not isinstance(stream_receipts, list) or len(stream_receipts) > 1 or
                not isinstance(upstream_receipts, list) or len(upstream_receipts) > 1):
            raise EvidenceUnavailable("stream parent receipt cardinality malformed")
        local_gaps = set(gaps)
        # Re-derive bounds from retained observations; an omitted producer gap
        # must not turn a timing overrun into completed evidence.
        if control["closeout_finished_us"] > 310_000_000:
            local_gaps.add("closeout_age_exceeded")
        if control["closeout_duration_us"] > 5_000_000:
            local_gaps.add("close_duration_exceeded")
        stream = upstream = None
        if len(stream_receipts) != 1 or len(upstream_receipts) != 1:
            local_gaps.add("parent_receipt_count")
        else:
            stream = _stream_receipt(stream_receipts[0])
            upstream = _upstream_receipt(upstream_receipts[0])
            if stream["lease_id"] != sidecar["lease_id"]:
                raise EvidenceUnavailable("stream parent lease mismatch")
        records = _parse_child_records(base.stdout, directory.name, sidecar["lease_id"], bootstrap["sha256"])
        if child != {"acknowledgements": list(records.acknowledgements), "receipts": list(records.receipts)}:
            raise EvidenceUnavailable("sidecar child records do not match retained stdout")
        local_gaps |= set(records.gaps)
        if base.stderr:
            local_gaps.add("stderr_nonempty")
        if not _process_clean(base.result):
            local_gaps.add("process_not_clean")
        if stream is not None and (stream["disposition"] != "stream_complete" or
                                   not stream["transport_complete"] or not stream["terminal_observed"]):
            local_gaps.add("parent_stream_incomplete")
        if stream is not None and (not stream["upstream_attempted"] or
                                   stream["validated_frame_count"] != 2 or
                                   stream["validated_bytes"] != len(STREAM_FIXTURE_RESPONSE) or
                                   stream["forwarded_frame_count"] != 2 or
                                   stream["forwarded_bytes"] != len(STREAM_FIXTURE_RESPONSE) or
                                   not stream["bytes_may_have_crossed"] or
                                   stream["stream_sha256"] != hashlib.sha256(STREAM_FIXTURE_RESPONSE).hexdigest()):
            local_gaps.add("parent_stream_metadata_mismatch")
        if upstream is not None and (not upstream["credential_replaced"] or not upstream["host_matches"] or
                                     upstream["body_sha256"] != hashlib.sha256(FIXTURE_REQUEST).hexdigest()):
            local_gaps.add("upstream_binding_mismatch")
        if not control["released"]:
            local_gaps.add("release_missing")
        if not bootstrap["removed"]:
            local_gaps.add("bootstrap_not_removed")
        if not control["revoke_acknowledged"]:
            local_gaps.add("revoke_unacknowledged")
        if records.receipts and (records.receipts[0]["reason"] != "complete" or
                                 records.receipts[0]["terminal_observed"] is not True or
                                 records.receipts[0]["transport_eof"] is not True):
            local_gaps.add("child_stream_incomplete")
        if records.receipts and (records.receipts[0]["validated_frames"] != 2 or
                                 records.receipts[0]["stream_bytes"] != len(STREAM_FIXTURE_RESPONSE) or
                                 records.receipts[0]["stream_sha256"] != hashlib.sha256(STREAM_FIXTURE_RESPONSE).hexdigest()):
            local_gaps.add("child_stream_metadata_mismatch")
        completed = (
            not local_gaps and not control["close_failures"] and control["released"] and
            stream is not None and upstream is not None and
            stream["disposition"] == "stream_complete" and stream["transport_complete"] and
            stream["terminal_observed"] and stream["validated_frame_count"] == 2 and
            stream["validated_bytes"] == len(STREAM_FIXTURE_RESPONSE) and
            stream["forwarded_frame_count"] == 2 and stream["forwarded_bytes"] == len(STREAM_FIXTURE_RESPONSE) and
            stream["bytes_may_have_crossed"] and
            stream["stream_sha256"] == hashlib.sha256(STREAM_FIXTURE_RESPONSE).hexdigest() and
            upstream["credential_replaced"] and upstream["host_matches"] and
            upstream["body_sha256"] == hashlib.sha256(FIXTURE_REQUEST).hexdigest() and
            bootstrap["removed"] and control["revoke_acknowledged"] and
            len(records.acknowledgements) == len(records.receipts) == 1 and
            records.ack_line < records.receipt_line and
            records.receipts[0]["terminal_observed"] is True and records.receipts[0]["transport_eof"] is True and
            records.receipts[0]["reason"] == "complete" and
            records.receipts[0]["stream_bytes"] == len(STREAM_FIXTURE_RESPONSE) and
            records.receipts[0]["stream_sha256"] == hashlib.sha256(STREAM_FIXTURE_RESPONSE).hexdigest() and
            _process_clean(base.result)
        )
        if not completed and not local_gaps:
            local_gaps.add("integration_predicate_failed")
        return {
            "version": _VERSION,
            "scope": _SCOPE,
            "native_launch": "CLOSED",
            "attempt_id": directory.name,
            "scenario": sidecar["scenario"],
            "integration_outcome": "completed" if completed else "held",
            "process": base.result,
            "stream": {"parent": {"stream_receipt": stream, "upstream_receipt": upstream},
                       "child": {"acknowledgements": list(records.acknowledgements), "receipts": list(records.receipts)},
                       "control": control, "bootstrap": bootstrap},
            "child": {"acknowledgements": list(records.acknowledgements), "receipts": list(records.receipts)},
            "gaps": sorted(local_gaps),
            "billing_actual": None,
            "qualification": "NOT_ASSESSED",
        }
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise EvidenceUnavailable("stream integration evidence unavailable or malformed") from exc


def _line_json(line: bytes) -> dict[str, object] | None:
    try:
        value = json.loads(line, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _typed_content(value: dict[str, object]) -> tuple[dict[str, object], ...]:
    if value.get("type") != "assistant" or not isinstance(value.get("message"), dict):
        return ()
    message = value["message"]
    if message.get("model") != "fixture-only" or not isinstance(message.get("content"), list):
        return ()
    if len(message["content"]) > 4:
        return ()
    return tuple(item for item in message["content"] if isinstance(item, dict))


def _parse_child_records(stdout: bytes, attempt_id: str, lease_id: str | None,
                         bootstrap_sha256: str) -> _ChildRecords:
    acknowledgements: list[dict[str, object]] = []
    receipts: list[dict[str, object]] = []
    gaps: set[str] = set()
    if len(stdout) > 1024 * 1024:
        raise EvidenceUnavailable("retained stdout exceeds fixture bound")
    if stdout and not stdout.endswith(b"\n"):
        gaps.add("incomplete_child_stdout")
    ack_line = receipt_line = None
    for index, line in enumerate(stdout.split(b"\n")[:-1]):
        if len(line) > _MAX_LINE:
            gaps.add("oversize_child_line")
            continue
        value = _line_json(line)
        if value is None:
            continue
        for item in _typed_content(value):
            if item.get("type") == "fixture_stream_ack":
                if _valid_ack(item, attempt_id, lease_id, bootstrap_sha256):
                    if len(acknowledgements) < 2:
                        acknowledgements.append(item)
                        if ack_line is None:
                            ack_line = index
                    else:
                        gaps.add("duplicate_ack")
                else:
                    gaps.add("bad_ack")
            elif item.get("type") == "fixture_stream_receipt":
                if _valid_receipt(item, attempt_id, lease_id, bootstrap_sha256):
                    if len(receipts) < 2:
                        receipts.append(item)
                        if receipt_line is None:
                            receipt_line = index
                    else:
                        gaps.add("duplicate_receipt")
                else:
                    gaps.add("bad_receipt")
    if len(acknowledgements) != 1:
        gaps.add("missing_ack" if not acknowledgements else "duplicate_ack")
    if len(receipts) != 1:
        gaps.add("missing_receipt" if not receipts else "duplicate_receipt")
    if ack_line is not None and receipt_line is not None and receipt_line <= ack_line:
        gaps.add("out_of_order_child_records")
    return _ChildRecords(tuple(acknowledgements), tuple(receipts), tuple(sorted(gaps)), ack_line, receipt_line)


def _valid_ack(value: dict[str, object], attempt_id: str, lease_id: str | None,
               bootstrap_sha256: str) -> bool:
    return (
        set(value) == {"type", "version", "attempt_id", "lease_id", "sequence", "frame_bytes", "frame_sha256", "bootstrap_sha256"} and
        value.get("type") == "fixture_stream_ack" and type(value.get("version")) is int and value.get("version") == _VERSION and
        value.get("attempt_id") == attempt_id and (lease_id is None or value.get("lease_id") == lease_id) and
        type(value.get("lease_id")) is str and _LEASE.fullmatch(value["lease_id"]) is not None and
        type(value.get("sequence")) is int and value.get("sequence") == 1 and
        type(value.get("frame_bytes")) is int and value.get("frame_bytes") == len(STREAM_FIXTURE_DELTA) and
        value.get("frame_sha256") == hashlib.sha256(STREAM_FIXTURE_DELTA).hexdigest() and
        value.get("bootstrap_sha256") == bootstrap_sha256
    )


def _valid_receipt(value: dict[str, object], attempt_id: str, lease_id: str | None,
                   bootstrap_sha256: str) -> bool:
    return (
        set(value) == {"type", "version", "attempt_id", "lease_id", "sequence", "bootstrap_sha256", "stream_bytes", "stream_sha256", "validated_frames", "terminal_observed", "transport_eof", "reason"} and
        value.get("type") == "fixture_stream_receipt" and type(value.get("version")) is int and value.get("version") == _VERSION and
        value.get("attempt_id") == attempt_id and (lease_id is None or value.get("lease_id") == lease_id) and
        type(value.get("lease_id")) is str and _LEASE.fullmatch(value["lease_id"]) is not None and
        type(value.get("sequence")) is int and value.get("sequence") == 1 and value.get("bootstrap_sha256") == bootstrap_sha256 and
        type(value.get("stream_bytes")) is int and 0 <= value["stream_bytes"] <= 16 * 1024 and
        isinstance(value.get("stream_sha256"), str) and _HEX.fullmatch(value["stream_sha256"]) is not None and
        type(value.get("validated_frames")) is int and 0 <= value["validated_frames"] <= 8 and
        type(value.get("terminal_observed")) is bool and type(value.get("transport_eof")) is bool and
        value.get("reason") in {"complete", "stream_invalid"}
    )


def _stream_receipt(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "sequence", "lease_id", "disposition", "reason", "upstream_attempted", "validated_frame_count",
        "validated_bytes", "forwarded_frame_count", "forwarded_bytes", "stream_sha256", "bytes_may_have_crossed",
        "terminal_observed", "transport_complete",
    }:
        raise EvidenceUnavailable("malformed parent stream receipt")
    if (type(value["sequence"]) is not int or value["sequence"] != 1 or
            not isinstance(value["lease_id"], str) or _LEASE.fullmatch(value["lease_id"]) is None or
            not all(isinstance(value[key], str) and len(value[key]) <= 64 for key in ("disposition", "reason")) or
            type(value["upstream_attempted"]) is not bool or
            any(type(value[key]) is not int or value[key] < 0 or value[key] > 16 * 1024
                for key in ("validated_bytes", "forwarded_bytes")) or
            any(type(value[key]) is not int or value[key] < 0 or value[key] > 8
                for key in ("validated_frame_count", "forwarded_frame_count")) or
            not isinstance(value["stream_sha256"], str) or not _HEX.fullmatch(value["stream_sha256"]) or
            any(type(value[key]) is not bool for key in ("bytes_may_have_crossed", "terminal_observed", "transport_complete"))):
        raise EvidenceUnavailable("invalid parent stream receipt")
    return value


def _upstream_receipt(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "sequence", "request_bytes", "body_sha256", "credential_replaced", "host_matches", "header_names",
    }:
        raise EvidenceUnavailable("malformed parent upstream receipt")
    if (type(value["sequence"]) is not int or value["sequence"] != 1 or
            type(value["request_bytes"]) is not int or value["request_bytes"] != len(FIXTURE_REQUEST) or
            not isinstance(value["body_sha256"], str) or not _HEX.fullmatch(value["body_sha256"]) or
            type(value["credential_replaced"]) is not bool or type(value["host_matches"]) is not bool or
            not isinstance(value["header_names"], (tuple, list)) or len(value["header_names"]) > 16 or
            not all(isinstance(item, str) and len(item) <= 64 for item in value["header_names"])):
        raise EvidenceUnavailable("invalid parent upstream receipt")
    return value


def _byte_record(value: object, data: bytes) -> bool:
    return (isinstance(value, dict) and set(value) == {"bytes", "sha256"} and
            type(value.get("bytes")) is int and value.get("bytes") == len(data) and
            value.get("sha256") == hashlib.sha256(data).hexdigest())


def _process_clean(value: object) -> bool:
    return (
        isinstance(value, dict) and isinstance(value.get("outcome"), dict) and
        value["outcome"].get("execution") == "completed" and
        all(value.get(name) is True for name in ("capture_complete", "root_reaped", "group_gone", "pipes_closed"))
    )


def _session_elapsed_us(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000_000))


def _validate_control(control: dict[str, object]) -> None:
    time_fields = ("ack_observed_us", "released_us", "revoke_requested_us",
                   "revoke_acknowledged_us", "closeout_finished_us")
    for name in time_fields:
        value = control[name]
        if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
            raise EvidenceUnavailable("invalid stream control chronology")
    if control["released"] != (control["released_us"] is not None):
        raise EvidenceUnavailable("stream release chronology mismatch")
    if control["released"] and (control["ack_observed_us"] is None or
                                control["released_us"] < control["ack_observed_us"]):
        raise EvidenceUnavailable("stream release precedes acknowledgement")
    if control["revoke_requested"] != (control["revoke_requested_us"] is not None):
        raise EvidenceUnavailable("stream revoke request chronology mismatch")
    if control["revoke_acknowledged"] != (control["revoke_acknowledged_us"] is not None):
        raise EvidenceUnavailable("stream revoke acknowledgement chronology mismatch")
    if control["revoke_acknowledged"] and (not control["revoke_requested"] or
                                              control["revoke_acknowledged_us"] < control["revoke_requested_us"]):
        raise EvidenceUnavailable("stream revoke acknowledgement precedes request")
    if (type(control["closeout_duration_us"]) is not int or
            not 0 <= control["closeout_duration_us"] <= 2**63 - 1):
        raise EvidenceUnavailable("invalid stream closeout duration")
    if control["closeout_finished_us"] is None:
        raise EvidenceUnavailable("stream closeout chronology absent")
    observed = [control[name] for name in time_fields[:-1] if control[name] is not None]
    if any(control["closeout_finished_us"] < value for value in observed):
        raise EvidenceUnavailable("stream closeout precedes observed phase")
    if control["closeout_duration_us"] > control["closeout_finished_us"]:
        raise EvidenceUnavailable("stream closeout duration exceeds observed age")
    if control["revoke_acknowledged"] and control["closeout_finished_us"] < control["revoke_acknowledged_us"]:
        raise EvidenceUnavailable("stream closeout precedes revoke acknowledgement")
    if (control["released"] and control["revoke_requested"] and
            control["released_us"] > control["revoke_requested_us"]):
        raise EvidenceUnavailable("stream release follows revoke")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = item
    return result


def _encoded(value: dict[str, object], limit: int) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(raw) > limit:
        raise EvidenceUnavailable("stream fixture evidence exceeds fixed limit")
    return raw
