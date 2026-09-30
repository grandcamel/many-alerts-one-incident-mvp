"""Join fixed child, loopback TLS and process evidence without opening native launch."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

from .fixture_evidence import EvidenceUnavailable
from .fixture_ledger import FixtureLedger, run_budgeted_fixture
from .process_fixture import ProcessResult
from .streaming_session import STREAM_SCENARIOS, read_stream_evidence


class StreamEvidenceError(EvidenceUnavailable):
    """Actual process observations survive failed post-process stream read-back."""

    def __init__(self, result: ProcessResult):
        super().__init__("supervised stream evidence unavailable; retain process result and reservation")
        self.process_result = result


def read_supervised_streaming_evidence(directory: Path, *, scenario: str) -> dict:
    """Re-read real child and parent evidence; never reconstruct child execution."""
    if scenario not in STREAM_SCENARIOS:
        raise ValueError("unknown supervised streaming fixture")
    result = read_stream_evidence(Path(directory).absolute())
    if result.get("process", {}).get("scenario") != scenario:
        raise EvidenceUnavailable("supervised streaming scenario mismatch")
    return result


def run_supervised_streaming(ledger: FixtureLedger, scenario: str, output_parent: Path,
                             attempt_id: str, now: datetime, *, billing_current: bool,
                             time_scale: float = 1.0, capture_limit: int = 1024 * 1024,
                             cancel: threading.Event | None = None) -> dict:
    """Reserve/claim once, supervise a fixed TLS child, then verify its linked artifacts."""
    if scenario not in STREAM_SCENARIOS:
        raise ValueError("unknown supervised streaming fixture")
    process_result = run_budgeted_fixture(
        ledger, scenario, output_parent, attempt_id, now, billing_current=billing_current,
        time_scale=time_scale, capture_limit=capture_limit, cancel=cancel,
    )
    try:
        return read_supervised_streaming_evidence(Path(process_result.attempt_directory),
                                                  scenario=scenario)
    except (EvidenceUnavailable, OSError, KeyError, ValueError, TypeError) as exc:
        raise StreamEvidenceError(process_result) from exc
