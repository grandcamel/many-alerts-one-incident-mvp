# Fixed-fixture closeout evidence

The fixed process harness retains `capture.bin`, `stdout.bin`, `stderr.bin`, `result.json`, its existing `fixture.py`
snapshot and a version-2 `closeout.json` manifest. All content is synthetic from the
closed worker scenarios. Never use this module to capture native model prompts,
credentials, Ground truth or real audit traffic: it is not a sanitizer or access boundary.

`stdout.bin` and `stderr.bin` retain each stream in its own accepted read order. `capture.bin`
remains a diagnostic merge in supervisor read order, capped at 1 MiB across both streams.
The stream lengths must sum to the diagnostic capture length, and each stream result count and
digest is linked to its file. A single nonempty stream must exactly equal the diagnostic capture;
the diagnostic merge cannot reconstruct cross-stream emission order.
`capture_complete=false` remains incomplete even when every retained byte verifies.
The worker and result each have a 64 KiB limit, each retained stream and their aggregate have a
1 MiB limit, and the manifest has a 4 KiB limit. The version-2 manifest has exactly five fixed
filenames and records each size and SHA-256. Its linkage check also verifies the result's
aggregate and stream sizes/digests, worker digest, attempt directory, fixture scope and closed
native-launch flag. A byte-integrity receipt is not a success verdict:
failed/cancelled/partial fixture executions can have valid receipts.
Version-1 three-file receipts (`fixture.py`, `capture.bin`, `result.json`) remain readable as
historical evidence with `stdout` and `stderr` unavailable. New publication permits version 1
only when no non-null stream metadata is supplied; partial stream metadata and a one-stream
downgrade are rejected.
Result serialization accepts JSON values only; the process binding explicitly renders
its optional Decimal cost estimate as a decimal string. Unsupported values cannot silently
become strings or lose structure.

Publication uses exclusive mode-0600 aggregate-capture, result and stream files and flush/fsync,
flushes the existing worker snapshot, syncs the attempt directory and its parent, writes and syncs
`closeout.pending`, then hard-links it to `closeout.json` without overwrite. The pending
link is removed and the directory synced before return and read-back. Existing files
are never overwritten or deleted for recovery. On failure, partial evidence is preserved
and the call raises; no automatic retry, adoption, cleanup or budget reconciliation occurs.
The caller's previously committed ledger claim remains unknown even after clean process
exit. Only an explicitly supplied synthetic final billing receipt can reconcile it.
`FixtureCloseoutError.process_result` preserves the observed in-memory result for diagnosis;
it is not acknowledgement of evidence closeout or billing settlement.

A crash before manifest publication leaves no accepted receipt. A crash after publication
may leave both links or an unacknowledged final directory sync; read-back can verify the
retained content if it exists, but cannot prove that the writer returned successfully or
that a final directory flush completed. It never authorizes rerun or releases a reservation.
Non-crash unlink or final-sync errors can likewise raise after a readable manifest exists.
Software-level file/directory flushes do not establish hardware power-loss behavior.

`read_fixture_evidence(path)` rejects missing/corrupt/oversized files, duplicate JSON keys,
unsupported manifest shapes, and symlink/nonregular file leaves. Reads are bounded and
FIFO opens cannot block waiting for a writer. Directory ancestry, same-user adversarial
mutation, authenticated provenance and stale-copy detection remain outside this trusted
fixture contract. Hashes detect changed bytes relative to the manifest; a writer capable
of replacing all artifacts is not detected. No result-schema or semantic re-adjudication
is claimed beyond the explicit linkage checks. Preserve the result's existing outcome.
Read-back requires the exact absolute directory path recorded by the supervisor; reading
through an alias can reject valid bytes and is not evidence of tampering. Closeout is
attempted even if containment failed. A surviving fixture can occupy an output filename;
exclusive creation then fails conservatively rather than replacing it.

Closeout occurs after supervision; its storage operations have no bounded completion
latency. Neither reported supervision time nor successful read-back proves the full
300-second launch-to-durable-closeout contract. Production quota/retention, mount custody,
credential sanitization, native adapter qualification and real billing integration remain
unimplemented. Native launch is `CLOSED` in every receipt.

Run local acceptance with `python3 -m pytest -q tests/test_timing_fixture_evidence.py`.
