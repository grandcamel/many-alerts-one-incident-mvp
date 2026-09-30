# Integrated fixed-client timing rehearsal

`run_timing_rehearsal(ledger, scenario, output_parent, attempt_id, now, ...)` now joins a
synthetic durable reservation/launch claim, the real POSIX fixture supervisor, an actual
scripted child using the timing binding, and correlated artifact read-back. The parent does
not recreate the child's query/Incident work after an unrelated process exits.

The exact closed scenarios are:

| Scenario | Actual child work | Expected integrated result |
| --- | --- | --- |
| timing_rehearsal | Notification, empty candidates, logs, create/confirmed effect, append/confirmed effect, snapshot and binding history | completed only with clean process containment/capture and both revisions linked |
| timing_unknown | Same initial queries, create, unknown-after-apply effect, snapshot and history | held even when the process exits successfully; unknown effect remains unknown |
| timing_wait | Initial queries, pending create, snapshot/history, then wait for supervisor interrupt | held; pending dispatch persists in the pre-wait snapshot and real timeout/cancellation is reported separately |

The fixed Report text describes storage exercises, not a diagnosis or human-scored answer.
References use actual returned synthetic response IDs. The normal flow also tests additive
membership and a correction linked to the previous immutable revision. The scripted client's
virtual Lifecycle observations (0–3 seconds) are distinct from host supervisor elapsed time.
A `before_wait` snapshot is historical pre-interruption state, not a final revoked-state claim.
No further tool calls occur during the fixed wait. This does not prove distributed native
revocation or transport policy enforcement.

## Closed executable bundle

`rehearsal_bundle.py` reads only an explicit allowlist of fixed timing modules and the five
pinned input files. Each source has an embedded byte count/digest. Compressed canonical JSON
is embedded in `fixture.py`, within the existing 64 KiB worker cap. The ordinary supervisor
worker digest therefore covers the exact modules/data used by the child. The original
supervision scenarios still use their existing worker. No general executable, callback,
extra argument, caller environment, module selector or arbitrary source path was introduced.

The bootstrap runs under the existing `python -I -S` and minimal environment contract. It
extracts fixed names into a newly created private `timing_bundle/`, writes read-only source
files, then imports the fixed client from that directory with bytecode writes disabled. Ground truth, the human rubric,
account configuration, credentials and repository tools are outside the allowlist. This is
trusted source/interpreter execution with normal process-group containment assumptions;
it is not an adversarial OS sandbox and does not establish native credential isolation.

## Correlated output and failure

The child publishes the existing `timing-snapshot/` bundle and an exclusive, fsynced
`binding-audit.json` (at most 16 MiB). It emits exactly one `timing_rehearsal_receipt` inside
an assistant-shaped fixture event naming the scenario, attempt/query/Incident namespaces,
manifest and audit byte counts/digests, and capture phase. Only after publication does the
normal child emit its terminal success. The wait case emits an error terminal when interrupted.
The synthetic model label is always `fixture-only`; it is not actual model-identity evidence.

`read_rehearsal_evidence(directory, scenario=...)` verifies ordinary fixed-process closeout,
re-reads the capture and unique receipt, checks the supervisor scenario and attempt identity,
then verifies the nested snapshot, binding history and their exact digest/session linkage.
Each retained query/dispatch must appear in accepted history with its original envelope;
query arguments are checked after the existing deterministic normalization. Dispatch payload
hashes bind their original arguments. Candidate reads retain their exact response digest.
These are bounded structural links, not independent support judgments or authentication.

A clean terminal event without these linked child artifacts is not integrated success.
Missing, duplicated, corrupt or mismatched evidence raises `EvidenceUnavailable`; the runner
wraps post-process verification failures as `RehearsalEvidenceError` carrying the actual
`ProcessResult`. Existing `FixtureCloseoutError` also preserves its observed process result.
No exception erases the attempt directory or ledger claim, and there is no automatic replay.
The supervisor retains stream-separated evidence. Integrated read-back requires version-2
evidence, parses receipts from retained stdout only, and rejects any nonempty retained stderr.
The merged capture remains diagnostic and does not prove cross-stream emission order. Stream
authenticity is outside this fixed fixture. A deterministic bundle-build failure
after launch claim likewise preserves an unresolved reservation, even if no child started.

The returned summary separates execution, effects, retained revisions, pending dispatch,
effect hold, audit completeness and unknown billing. A normal integration result can be
`completed` while audit/qualification remain NOT_ASSESSED. Unknown and wait scenarios return
`held`. Captured hashes are byte comparisons; rewriting all trusted artifacts and hashes
can fabricate a consistent bundle. This is not authenticated native tool provenance.

## Accounting and limits

The ledger is deliberately synthetic. Reserve and one-time launch claim precede the child;
the child never opens the ledger. Completion, a zero-exit process and snapshot publication
never reconcile costs. An unresolved reservation continues to hold later admission until an
explicit fixture receipt is supplied. This proves no provider charge or billing enforcement.

`capture_limit` and a trusted `threading.Event` cancellation signal now pass through the
existing budgeted fixture helper, with validation before reservation. Time scaling applies
only to fixed fixture tests, never to an approved model budget. Child snapshot publication
occurs inside supervised execution; parent process closeout and verification still occur
after supervision. The full launch-to-durable-closeout deadline remains unqualified.
Production quota/retention, writable recovery, model execution, live Jira/tenant effects and
native transport/auth/billing remain outside this implementation. Native launch is CLOSED.

Run local checks: `python3 -m pytest -q tests/test_timing_binding.py tests/test_timing_rehearsal.py`.
