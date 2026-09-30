# Pinned in-process timing queries

`TimingQueries` exposes read-only Python queries over five exact historical synthetic
inputs in `timing_data/`. Notification bytes are unchanged from the historical
`notification-cascade.json`; only its local filename differs. All five compiled-in
SHA-256 values match the source manifest at commit
`79a14c8904f3a125d1f03b192d10797d30979c86`. Historical executables and Ground truth are
excluded. A loader rejects missing, nonregular, oversized, symlinked-leaf or changed
files before constructing a usable adapter. Each source is limited to 64 KiB.

The source/interpreter and storage ancestry are trusted operator inputs. This is not
an adversarial mount boundary, sandbox, native transport or production audit store.
The files are supervisor-side data for a future isolated binding, not a directory to
mount into a Run. Queries use the loaded snapshot; later filesystem changes neither
change that snapshot nor imply fresh source validation.

## Local protocol

Construct `TimingQueries(attempt_id, lifecycle)` and call
`query(request_id, operation, arguments)`. `describe()` returns accepted operation names,
argument names, required selectors and scalar contracts. These are local Python protocol
names, not registered model tools, shell commands or a native capability manifest.
No caller-supplied path, URL, executable, arbitrary query expression or Incident mutation
operation exists. `fixture_root` is a constructor-only trusted operator input.

| Operation | Arguments | Returned items |
| --- | --- | --- |
| notification.get | none | Whole pinned Notification |
| metrics.list | none | Metric name/unit/help, no series values |
| metrics.query | required metric; optional since/until/limit | Points for one exact metric with unit and timestamp |
| logs.query | optional service/contains/since/until/limit | Exact-service log records with literal body substring matching |
| traces.list | optional service/since/until/limit | Trace metadata for exact span-service membership; no spans/attributes |
| traces.get | required trace_id | Full trace for the exact ID; prefixes do not match |
| changes.list | optional since/until/limit | Historical Change records, not present-day action-stage proof |

All string matching is case-sensitive. Text selectors are 1–256 characters. Request and
attempt IDs match lower-case alphanumeric plus hyphen/underscore, 1–64 characters.
Time bounds are inclusive canonical ASCII UTC seconds (`YYYY-MM-DDTHH:MM:SSZ`), omitted/null
for unbounded; reversed or invalid windows are rejected. Log timestamp, trace startTime,
Change time and metric point time are the respective event-time selectors. Event selections
are stably ordered by time; metric points retain the pinned chronological series order.
Limit is 1–100 (default 50), excluding booleans. Catalogue and Notification operations do
not accept a limit; their pinned sizes are bounded by the response cap.
Truncation retains the earliest matching items. Narrow the time window to retrieve later
events; this fixed corpus API has no pagination or latest-first option.

A successful no-match query returns `status=ok`, zero counts and an empty item list.
An unknown exact metric/trace selector returns `status=not_found`; a known metric with no
points in the requested window returns `ok`. An invalid, revoked, duplicate-ID or
capacity-exhausted request raises `QueryRejected` and issues no response. It never becomes
an empty success. Rejected request IDs have not been accepted and may be reused with a
valid request; already issued IDs cannot be reused, even for identical read requests.

## Correlation and read-back

Each response includes request ID, attempt/session/sequence response ID, effective arguments,
virtual observation time, pinned source filename/digest/commit, exact counts, truncation,
items and response digest. Session IDs are random correlation namespaces so independent
instances do not reuse IDs. They are not credentials or authentic provenance. Event times
remain historical fixture times; the observation clock is explicitly virtual seconds.

Items carry a JSON-pointer-style index into the parsed pinned source and a projection label.
For JSONL, the pointer indexes its parsed line array. Metric metadata/points and trace
summaries are projections, not retrieval of every field behind the source pointer. A trace
summary cannot support claims about omitted span attributes. Ground truth and human grades
are never supplied by these queries. Returned historical Change source labels do not prove
an ADR 0015 coordinator exists or that any current actuation stage was observed.

The response digest is SHA-256 of canonical JSON (sorted keys, compact separators,
ASCII escaping, nonfinite numbers forbidden), excluding only `response_sha256`. The final
serialized envelope including digest is capped at 64 KiB. The adapter retains at most
128 encoded responses (at most 8 MiB) and accepts one response per request ID. Byte-cap
failure consumes no ID or sequence; count-cap failure retains all earlier responses.
Truncation reports total matched and returned counts, never silently discarding matches.

`read_response(response_id)` returns independent parsed bytes from that adapter's retained
record and remains available after work revocation. Caller mutation cannot change the
loaded data or retained response. New queries require the shared Lifecycle's work window;
revocation/timeout closes it. The adapter is single-threaded, in-memory and trusted. Restart
loses its records; these are neither durable audit receipts nor authenticated native tool
responses. Any future transport must preserve exact response bodies and prove attribution
independently. Hashes alone do not authenticate a supplied response.

A separate [synthetic Incident store](TIMING_INCIDENTS.md) uses these retained responses
for local Report references and simulated writes. Native binding, sealed access, real billing
and paid execution remain unimplemented. Every response advertises `OFFLINE_PINNED_QUERIES_ONLY`
and native launch `CLOSED`. The timing prompt/Skill remains an uninstalled draft.

The operator-only `audit_snapshot()` returns all retained responses and query identity as
detached objects. The [timing snapshot writer](TIMING_SNAPSHOT.md) can persist these with
Incident revisions; this does not make the query adapter itself recoverable or authenticated.

Run local tests: `python3 -m pytest -q tests/test_timing_queries.py`.
