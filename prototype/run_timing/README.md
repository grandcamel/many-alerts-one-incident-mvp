# Ticket 23 offline execution core

The core executes **synthetic replay observations**. A separate
[fixed host-process harness](PROCESS_FIXTURES.md) now supervises reviewed Python fixture
programs to test real scheduling and cleanup. Neither entry point can launch Claude,
arbitrary commands, containers or network requests. Production Receiver and historical
`prototype/run-timing` source are unchanged. Ticket 23's measurement card remains CLOSED.

The [synthetic diagnostic ledger](FIXTURE_LEDGER.md) adds SQLite reservation and one-time
launch claims for those fixed fixtures. It tests persistent unknown exposure, receipt
reconciliation, concurrent admission and weekly limits using synthetic inputs only.
It does not access real account balances or authorize a paid model call.

[Fixed-fixture closeout](FIXTURE_EVIDENCE.md) now retains the bounded capture bytes and
verifies worker/capture/result linkage on read-back. Version-2 closeout also retains
separate stdout/stderr bytes under the shared capture cap; historical version-1
receipts remain stream-unknown. Integrated rehearsal requires version 2 and empty stderr. These byte-integrity receipts do not
establish semantic success, real audit acceptance or a durable-closeout time bound.

The timing instruction drafts
separate future Run text from the operator-only rubric and preflight. They are not installed;
the user has approved the pinned rubric/baseline, recorded in its operator-only approval
receipt. A reviewed native binding and Report-by-Report human adjudication remain required.

[Pinned timing queries](TIMING_QUERIES.md) now provide bounded in-process retrieval of the
historical synthetic Notification and telemetry with correlated response read-back. This
is the read-only fixture API only; native transport remains unimplemented.

The [synthetic Incident store](TIMING_INCIDENTS.md) adds instance-local create/append,
immutable Report revisions, linked query references and separate simulated dispatch/effect
receipts. Failed or uncertain effects hold further work. It has no durable or live Jira binding.

[Retained timing snapshots](TIMING_SNAPSHOT.md) now export the exact query responses and
Incident records together for bounded operator read-back. Pending/unknown effects and
coverage gaps stay explicit; snapshots are not authenticated audit or recovery journals.

The [fixed local binding](TIMING_BINDING.md) and [integrated rehearsal](TIMING_REHEARSAL.md)
now let an actual supervised scripted child query fixtures, create/update synthetic Reports
and publish linked evidence under a synthetic ledger claim. Unknown effects and real fixture
timeouts remain held; this adds no native model client or paid measurement.

`outcomes.py` parses bounded synthetic Claude-shaped JSON events and derives execution
outcomes without discarding malformed evidence, duplicate terminals or receiver-observed
failures. The deliberately small schema accepts assistant messages with explicit model
identity, init metadata and result records with explicit success/error fields. It rejects
other shapes. It is not a qualified native-client adapter, and must not consume an actual
native stream as if its schema compatibility had been established. Missing cost remains
unknown; a returned estimate is never a provider actual. `comparison: eligible` concerns
observed identity only, not diagnostic quality or model qualification.

The separate [documented stream normalizer](DOCUMENTED_STREAM.md) parses a fixed
source-derived subset of Claude Code events using a pinned official SDK reference.
It keeps reported models and cost estimates separate from actual identity and billing,
and combines offline stream checks with explicit supplied process observations.
Its best result is `stream_consistent`; native qualification remains `NOT_ASSESSED`
and further dispatch stays held. It is not wired to a launcher or the synthetic parser.

The separate [local mediated-client harness](../mediated_client/README.md) now
exercises real loopback TLS, scoped fixture leases, fixed request routing, header
replacement and held transport failures with synthetic credentials. It does not
launch a native model client or alter the production Forwarder.

`executor.py` provides:

- A virtual-clock lifecycle with fixed 270/20/10 boundaries, early cancellation,
  descendant/pipe observations and dispatch revocation. Returned interrupt/kill actions
  are simulated requirements. They do not send signals or prove host containment.
- An inert fixed-grid length probe. It compares command bytes and issues receipts from
  an in-memory stub; it never executes the command. Receipt object identity rejects
  fabricated/copied/foreign receipts within this trusted process. This is not a security
  boundary against arbitrary code in that process or a native receipt transport. `begin`
  records a tool request before resolving permission; `dispatch` can begin it implicitly.
  Cleanup may collect a pending request's result but cannot begin another. Provider
  refusal/fallback cancels the linked lifecycle and exposes the required cleanup actions.
  [Case-record snapshots](LENGTH_RECORDS.md) retain digests, virtual times, request/receipt
  observations and pending/unattempted cases without exporting command bodies or native
  authority.
- A diagnostic admission predicate over explicit supplied ledger snapshots. Unknown
  prior-week exposure holds admission too. This does not persist a ledger, reserve real
  funds, authenticate provider actuals, or supply atomic/concurrent admission. Empty
  synthetic data is not evidence of an empty real ledger. Lifecycle/rehearsal-specific
  accounting remains ticket 38's integration work.
- Bounded in-memory capture of synthetic bytes. It is not a credential sanitizer or
  private disk audit store. Replay input must be synthetic, contain no secrets and be
  bounded before loading; the functions do not authorize reading private transcripts.
- `replay`: a finite observation driver that advances deadlines even during silence,
  classifies terminal evidence and labels every result `OFFLINE_REPLAY_ONLY` with native
  launch `CLOSED`. Missing reaping/exit observations at EOF cannot become success.

Run offline acceptance from the repository root:

```sh
python3 -m pytest -q tests/test_timing_outcomes.py tests/test_timing_executor.py
```

Tests verify the five inert command strings against the frozen planning fixtures. They
cover execution outcomes, identity, dispatch and budget/capture predicates from the 26
case specifications. Reservation persistence now has separate synthetic ledger tests;
authoritative provider accounting and semantic audit/qualification verdicts remain
integration gates. The abstract case data
is not treated as native events and its embedded commands are never executed.

## Before any native executor can be admitted

Implement and review an OS isolation/process binding with descendant membership and
reaping evidence, fixed executable resolution and protected fixture mounts; native
stream/permission normalization qualified against the exact CLI; authenticated external
receipt correlation; mediated Forwarder auth/routing/TLS/revocation; atomic durable
budget reservation and provider reconciliation; bounded sanitized private audit storage
with retention and exclusive attempt directories; revised timing Skill/prompt and human
rubric. The native binding must enforce emitted actions on time, not wait for transcript
activity. Offline comparisons or booleans cannot stand in for these proofs.

Output collision and process-group cleanup now have fixed-fixture host evidence;
adversarial containment, direct-route denial, credential custody, actual model/fallback
behavior, provider charges, tenant effects and venue qualification remain NOT RUN. No
local result here opens the execution card or authorizes a paid experiment.

The integrated rehearsal outcome
records the fixed child flows, review corrections and retained evidence. The approved rubric
is a prerequisite for future human grading, not an adjudication of these scripted storage exercises.
