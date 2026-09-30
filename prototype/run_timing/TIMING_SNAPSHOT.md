# Operator-only retained timing snapshots

The in-process query and Incident adapters now expose `audit_snapshot()` inventories.
`capture_timing_snapshot(store)` takes a detached inventory without issuing a query,
admitting a dispatch, completing an effect or clearing a hold. Capture is coherent only
under the existing trusted single-threaded contract. It works while held or revoked.

A snapshot contains the Notification response identity, query attempt/session identities,
every retained exact query response, every dispatch/effect receipt, every committed Report
revision, the current Incident state and an observation of the shared virtual Lifecycle.
A Report reference can therefore be resolved to its originally returned response after the
original adapter objects are gone. No query is rerun and no writable adapter is restored.
Canonical serialization of each retained response/revision preserves its existing digest.

## Publication and read-back

`write_timing_snapshot(new_directory, store)` first captures and validates the inventory,
then creates a new directory with mode 0700 and exclusive mode-0600 files. An existing
file/directory/symlink at the destination is refused without replacement. The parent must
already exist and be a trusted operator-owned location outside Git and future Run mounts.
The caller owns path selection; no model-side path or transport is provided.

The writer stores compact canonical `snapshot.json`, flushes it and the directory/parent,
then writes and flushes `manifest.pending`. A hard link publishes `manifest.json` without
overwrite, the pending name is removed, and the directory is flushed. The writer then calls
`read_timing_snapshot(directory)` and returns that verified read-back. Failure preserves
any partial files; it does not mutate the source store, clear accounting or retry. A leftover
pending file is not a published manifest. A sync/read-back failure after publication may
leave a readable manifest but the write operation still raises; later read-back does not
retroactively prove the failed operation's durability or timing.

The JSON snapshot is capped at 16 MiB and the manifest at 4 KiB. Reads reject oversized,
nonregular and symlinked leaf files; nonblocking opens avoid a substituted FIFO hanging.
Directory ancestry, interpreter and storage are trusted. POSIX file operations, hashes,
private modes and fsync do not establish an adversarial mount/ownership boundary, production
retention policy, quotas, secure erasure or a launch-to-durable-closeout deadline.

## What verification establishes

`validate_timing_snapshot(snapshot)` checks scope/version, canonical record byte limits and
hashes, response/dispatch/revision count bounds (128/32/32), unique request and record IDs,
query/store namespaces and sequence, pinned source metadata, response counts/truncation,
Notification identity, dispatch/effect/revision links, increasing revision-to-dispatch order, predecessor/correction links,
current revision inventory, pending dispatch and failed/unknown hold consistency. Each Report
reference must resolve to a retained response and valid returned item, or null for an envelope.
Lifecycle fields have finite nonnegative time and boolean flags consistent with work admission.
Per-record canonical bounds are 64 KiB per response, 4 KiB per dispatch/effect, 20 KiB per
revision and 32 KiB for current state. These checks are deliberately limited to retained structure and links, not full replay of the
query selection or Incident business logic. They do not validate every application field.

The manifest SHA-256 and byte count cover the full canonical snapshot; each embedded response
and receipt also retains its own original digest. Raw JSON read-back rejects duplicate keys
and nonfinite numbers. Corrupted bytes, mismatched scopes/identities and broken checked links
raise `EvidenceUnavailable`; they do not become an empty snapshot or successful effect.
A caller able to replace all bytes and recompute all hashes can fabricate a self-consistent
snapshot. Hashes provide integrity comparisons, not authenticity or native provenance.

## Preserved uncertainty and missing observations

Pending dispatches remain pending. An unknown effect remains unknown even when an applied
revision is visible to the operator. Failed and unknown-before-apply proposals have no retained
Report body; only their original dispatch hash survives. All earlier committed revisions and
returned query responses remain present. Rejected requests, candidate-read observations and completed-but-unapplied proposal bodies were never retained
for later read-back by the existing adapters. A pending proposal body still exists transiently
in the store, but the snapshot intentionally excludes it; capture cannot reconstruct missing
proposal content. The snapshot carries these coverage gaps explicitly and always sets
`audit_completeness=NOT_ASSESSED` and native launch `CLOSED`.

The scope is `SYNTHETIC_TIMING_SNAPSHOT_ONLY`. This is operator evidence, never a Run input.
It contains no new human grades, Ground truth, credential access, model identity, billing or
native execution evidence. A retained unsupported claim stays unsupported. Native transport,
ADR 0014 audit acceptance, named human adjudication, production custody/sanitization/expiry and
recovery remain separate work. Capturing a historical snapshot neither freezes future adapter
activity nor admits another Run. Repeated capture requires another new output directory.

Run focused tests: `python3 -m pytest -q tests/test_timing_snapshot.py`.
