# Synthetic diagnostic ledger

`fixture_ledger.py` implements persistent accounting for ticket 23's fixed local fixtures.
All stores and supplied amounts are **synthetic**. No API key, account balance, provider
receipt, existing user ledger or paid model call is accessed. Every view/admission keeps
native launch `CLOSED`. This is the diagnostic slice only, not ticket 38 completion.

`FixtureLedger.create` explicitly creates a new private fixture database and refuses an
existing path. All subsequent operations open existing storage only: missing, unreadable,
wrong-scope or corrupt storage cannot silently turn into zero spend. Each operation uses
its own SQLite connection and transaction; reserve and launch claim are distinct durable
steps. A reserve response is not permission to call an arbitrary launcher. The integration
function `run_budgeted_fixture` can call only the existing fixed-process harness.
Shared scenario/identifier/timing validation runs before reservation, so an invalid
request cannot consume an attempt. Storage/spawn failures after admission still hold.

Reservation consumes one diagnostic attempt and $3 of synthetic allocation before launch.
Claims are one-time and recheck billing readiness, date, holds and limits. Repeated IDs
cannot launch again. A crash after commit or claim leaves unknown exposure, even if no
child was spawned. Neither clean fixture exit nor an exception reconciles a charge.
That includes a [fixture closeout](FIXTURE_EVIDENCE.md) storage/read-back failure after
the child exits; retained output and byte-integrity receipts are not billing receipts.
Operators supply an explicit synthetic final actual to settle it. Estimates are not
accepted as reconciliation evidence. IDs/amounts are validated before state changes.

Amounts use exact integer microdollars. An actual replaces its reservation for totals;
above-reservation amounts remain visible, and all attempts count even at zero actual.
Diagnostic limits are $30 and ten attempts; weekly model cost is capped at $150 for
admission. Synthetic actuals from other model allocations share the weekly sum but not
the diagnostic sum. Cloud costs are excluded. America/New_York Monday boundaries apply;
delayed receipts remain attributed to the original attempt week. Unresolved exposure
across all weeks holds new admission. Launch claims cannot cross their reservation week.

Identical receipts are idempotent. Reuse with different attribution/amount or a different
receipt for an already-reconciled attempt creates a persistent conflict hold, preserving
the original amount. The first hold reason survives subsequent failures; each receipt
operation also returns its own result. Holds have no automatic clear/reset API.
Capacity is 10,000 combined attempt/receipt records. Admission requires room for both
the attempt and its eventual receipt; intervening other-allocation receipts can still
consume that headroom. Exhaustion holds without deleting unresolved records. This is
a record-count bound, not a production disk quota or retention policy. Conflicts and
capacity exhaustion require a future explicit reconstruction/disposition procedure.

The code uses `BEGIN IMMEDIATE` so competing writers cannot both read an admissible state
and reserve it, with rollback journaling and `synchronous=FULL`. SQLite documents write
serialization and commit behavior in its [transaction reference](https://www.sqlite.org/lang_transaction.html)
and [synchronous setting](https://www.sqlite.org/pragma.html#pragma_synchronous). Tests
exercise concurrent processes, abrupt process exit and reopen; they do not prove storage
hardware, power-loss persistence or filesystem snapshot freshness.

## Limits before real use

Storage parent, timestamps, billing-readiness booleans and receipt inputs are trusted
fixture-operator inputs, not authenticated provider evidence. Same-user tampering or
restoring a stale but internally valid database is not detected by an external authority
anchor. There is no Run mount/access enforcement, reconstruction/hold-clear workflow,
production retention, lifecycle/retry allocation, real Receiver/Forwarder binding or
launch-to-durable-closeout timing guarantee. Initialization never authorizes treating
a missing real ledger as a new budget week. Real accounting must preserve the user's
existing obligations independently of these fixture databases.

Run local acceptance with:

```sh
python3 -m pytest -q tests/test_timing_fixture_ledger.py
```

The budgeted helper also forwards the existing bounded capture limit and trusted cancellation
event to the supervisor, validating both before reservation. The closed timing scenarios are
integrated by [run_timing_rehearsal](TIMING_REHEARSAL.md); they still leave billing unresolved.
