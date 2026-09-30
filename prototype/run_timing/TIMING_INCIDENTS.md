# In-process synthetic Incident store

`TimingIncidents` holds at most one Incident per instance for the pinned timing Notification.
Construct it with the existing `TimingQueries` instance and its retained `notification.get`
response ID. Both adapters share a Lifecycle. Construction is not work admission and can occur after
revocation; every new candidate query or dispatch still checks the shared work window.
It has no network, Jira, filesystem persistence,
native tool binding, credential handling, matching intelligence or human grading. It is trusted,
single-threaded fixture code; Python access to controller methods is not an authorization boundary.
All envelopes advertise `OFFLINE_SYNTHETIC_INCIDENT_ONLY` and native launch `CLOSED`.

## Read and write contract

`candidates()` initially returns a successful empty list; after confirmed creation it returns
one open Incident with its current Report revision. An Incident is eligible within 1,800 virtual
seconds of its creation, though normal Lifecycle admission ends at 270 seconds. This is a local
fixture projection, not qualification of the production 30-minute candidate-search policy.
Match judgment and evidence support assessment remain with the investigator and human audit.
Candidates are blocked by lifecycle revocation or a failed/unknown-effect hold.

`dispatch(request_id, operation, payload)` admits one write intent and returns a dispatch receipt
with `effect_outcome=pending`. It does not apply the write. Request IDs are 1–64 lowercase
alphanumeric/hyphen/underscore characters, starting alphanumeric. One write may be pending at a
time. Accepted IDs cannot be reused; rejected IDs consume no sequence and may be corrected.
Only these exact payload shapes are accepted:

- `create`: `summary`, `members`, `report`. Summary is nonblank and at most 200 characters.
- `append`: `incident_id`, `expected_revision`, `members`, `report`. The exact ID is
  `SYNTHETIC-INCIDENT-1`; expected revision must be an integer equal to current revision.

Members are unique known fingerprints from the seven-Alert Notification. Creation needs at least
one member; append adds members to accumulated membership and may add none. This bounded model
has no removal or metadata-edit operation. It preserves summary, source `Monitoring systems`,
status `open`, the unrelated label `synthetic-timing`, and every previous fingerprint label.
Severity and urgency derive from accumulated membership: critical → Sev-1/Critical,
warning → Sev-2/High, otherwise Sev-3/Medium. They can only ratchet upward. The pinned corpus
contains only critical and warning Alerts; this does not qualify real OPS field identifiers,
permissions, severity decisions, or Jira label-add behavior.

## Reports and references

Each Report is a complete immutable revision with exactly four fields:

- `sections`: exactly `summary`, `blast_radius`, `timeline`, `evidence`,
  `suggested_root_cause`, `suggested_remediation`, `fingerprints_explained`.
  Each is nonblank text, at most 2,048 characters.
- `references`: at most 32 objects containing `response_id` and `item_index`.
  The ID must resolve in the same TimingQueries instance; integer indices must identify a
  returned item. Null index references the envelope, including an empty/not-found observation.
- `explanations`: exactly one `{fingerprint, relation}` object for each of the seven Alerts.
  Relation is `direct`, `downstream`, or `unexplained`. Direct/downstream fingerprints must
  equal accumulated Incident members. This checks declared membership, not causal truth.
- `correction_of`: null, or the ID of a retained Report revision. Corrections append new
  content; no previous revision is edited. All appended revisions also identify their predecessor.

Canonical Report JSON is capped at 16,384 bytes including ASCII escapes. This aggregate cap
also applies when every individual field is within its own limit; all maxima need not fit
together. Reference validation
proves local identity/index linkage only. It does not check that prose is true, a cited item
supports a claim, an empty response proves health, or the stated root cause is correct. Empty
reference lists are permitted and do not imply support. Human support/correctness grading remains
NOT RUN. Ground truth and grades are never loaded by this store. References store response
IDs and indices, not copied response bytes/digests. The paired query adapter retains those
bytes; a detached revision export alone is not a self-contained evidence bundle.

## Completion, uncertainty and read-back

`complete(dispatch_id, disposition=...)` is a trusted controller simulation, never a model-side
operation. `confirmed` applies the proposed Incident and revision; `failed` applies neither;
`unknown_before_apply` applies neither but emits unknown; `unknown_after_apply` retains the write
and revision but emits unknown. Both unknown cases omit Incident/revision IDs from the effect
receipt. Any failed/unknown outcome holds future work, with no retry, replay, reconciliation or
hold-clear API. Unapplied proposals are discarded on completion: their dispatch retains the
payload hash, not the proposed Report bytes. This is not a recoverable write-intent journal.
A duplicate/mismatched completion is rejected. Completion of an admitted write
remains possible after revocation, modeling a dispatched operation finishing after work closes.
This is not proof of native cancellation, remote commit, or delivery semantics.

Report revisions label their dispatch preparation time `prepared_at_virtual_seconds`. Effect
receipts separately record `observed_at_virtual_seconds`; neither is a remote wall-clock commit
timestamp. `inspect()` exposes operator state plus dispatch/revision IDs, including state after an
unknown applied write. `read_record(kind, identity)` reads `dispatch`, `effect`, or `revision`.
Effect records use their corresponding dispatch ID; an effect read for a still-pending
dispatch is rejected. These operator methods remain available while held/revoked and never convert unknown to confirmed.
A dispatch receipt remains pending forever as the historical intent; consult its separate effect
receipt for completion. Unknown and failed effects leave previous committed revisions untouched.

Returned records are detached parses of retained canonical bytes. SHA-256 covers sorted compact
JSON with ASCII escaping and nonfinite numbers forbidden, excluding only `sha256`. Hashes provide
byte comparison, not authenticity. Session UUIDs prevent accidental identity reuse across store
instances; they are not credentials. At most 32 writes are admitted, bounding retained revisions
and receipts. Restart loses all state and allows a new empty store; cross-instance deduplication,
concurrency, durable recovery and authenticated receipts are explicitly unimplemented. No claim
about production Incident uniqueness follows from this instance-local limit.

The operator-only `audit_snapshot()` now inventories query responses, Incident records,
current state and Lifecycle without admitting work or clearing holds. The separate
[timing snapshot writer](TIMING_SNAPSHOT.md) preserves that inventory for read-back; it
does not restore a writable store or turn a failed/unknown outcome into confirmation.

Run local checks: `python3 -m pytest -q tests/test_timing_incidents.py`.
