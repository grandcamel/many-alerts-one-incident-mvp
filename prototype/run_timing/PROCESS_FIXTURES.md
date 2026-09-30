# Fixed host-process acceptance harness

`process_fixture.run_fixture` runs one scenario from a closed list of reviewed local
Python fixtures. No executable, shell command, model, extra argument or environment
can be supplied. It snapshots the fixed worker into a new exclusive attempt directory
and records its SHA-256. The interpreter uses `-I -S`, a fresh process group, closed
inherited descriptors and an explicitly built environment. No credentials are read.

The supervisor polls independently of stdout, emits revocation/interruption/kill actions
using the existing lifecycle, drains nonblocking stdout/stderr, bounds captured bytes
and pending lines, reaps the direct child and separately observes process-group existence
and pipe EOF. A clean parent exit or EOF alone cannot establish group termination.
Cleanup may still retain local output; exhaustion requests cancellation and holds results.
Exceptions trigger bounded cleanup rather than unbounded `communicate` or `wait`.
Rejected capture bytes never enter the transcript parser. Pipe-read failure is distinct
from EOF: capture becomes incomplete, affected pending bytes are discarded and confirmed
pipe closure remains false. Already-exited processes can drain malformed retained output
without inventing cancellation of their completed execution.

Default phase bounds are 270/20/10 seconds. Test-only scaling reduces all phases equally;
it cannot enlarge them. Tests use scale 0.01 (2.7/0.2/0.1 seconds), or 0.02 for selected
forced-kill tests to allow more scheduler/reaping margin. Cancellation enters
cleanup earlier. A forced orphan kill remains visible as cancellation. The result records
observed elapsed supervision time, original and cleanup deadlines, root reaping, group
disappearance, pipe EOF, capture completeness/digest and lifecycle actions. Compact JSON, a
bounded diagnostic merge, and separately bounded accepted stdout and stderr bytes are written
only after supervision returns, with a
[verifiable closeout manifest](FIXTURE_EVIDENCE.md). These artifact writes are not included in the
supervision duration. Thus these results do not establish the complete native 300-second
launch-to-durable-closeout contract.

Use a trusted private operator-owned output parent. Existing attempts, files and symlinks
are refused, never deleted. Filesystem permissions and process groups here are not an
adversarial sandbox; a hostile same-user process or escaping descendant is outside this
fixture contract. No C2 ancestry/ingestion code is reused. This is not the production
private audit store or authenticated external receipt transport.

The harness assumes the host's normal orphan reaper. Running it as PID 1 or a child
subreaper is unsupported: adopted descendants require additional explicit reaping logic.
Such unconfirmed groups must remain containment failures. Cooperative fixtures reset
SIGINT explicitly; they do not depend on the invoking shell's signal disposition.

Run the real-process tests from the repository root:

```sh
python3 -m pytest -q tests/test_timing_process_fixture.py
```

These are real host-process observations for synthetic, fixed, cooperative fixtures.
They are distinct from the virtual-clock tests and from native Claude/venue acceptance.
Full-duration 270/20/10 testing, Linux/cgroup confinement, escaping descendants, mediated
API custody/network enforcement, actual client event shapes, durable budget admission,
private audit retention and paid timing/length probes remain NOT RUN. Every result is
labelled `FIXED_HOST_FIXTURES_ONLY`, with native model launch `CLOSED`.

The three closed [timing rehearsal](TIMING_REHEARSAL.md) scenarios now use an embedded
fixed module/data bundle inside the captured worker bytes. They exercise actual child-side
queries, synthetic Incident calls and evidence writes; `ProcessResult.scenario` records the
selected closed scenario. The original fixture scenarios retain their original worker.
The `stderr_noise` and `stderr_json` scenarios otherwise produce the normal successful stdout
sequence while emitting fixed non-JSON or JSON bytes on stderr; they exist only to exercise
supervisor stream attribution and do not accept an executable or arbitrary payload.

The closed [supervised streaming](SUPERVISED_STREAMING.md) scenarios use a separate
bounded stdlib child. They join actual child decoding to parent TLS receipts and
the existing process evidence. Only a retained validated acknowledgement can
release the terminal frame; revocation intent precedes interruption. TLS setup
and transport cleanup remain outside the process supervision duration, and the
sidecar records transport cleanup timing separately. Synthetic ledger claims
remain unresolved until explicit reconciliation.
