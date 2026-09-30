# Fixed local timing binding

`TimingBinding(attempt_id, lifecycle)` is a bounded Python-only rehearsal adapter. Construction
creates `TimingQueries` only. The first successful model-side `notification.get` uses that caller's
`call_id`, stores its exact response, and constructs the one `TimingIncidents` store. Later
`notification.get` calls receive their own underlying query response and correlation ID. Incident
operations before that first successful Notification reject with no effect.

Use `describe()` to obtain the model protocol and `call(request)` for one request. The request is
canonical JSON with exactly `call_id`, `operation`, and `arguments`. Call IDs are lower-case
alphanumeric initially, followed by lowercase alphanumeric, hyphen or underscore, 1--64 characters. Their namespace is session-global
across reads and writes: before the 64-call retention cap, a valid ID is consumed even when the
request later rejects. Calls after that cap are terminal unretained observations and do not expand
the ID set. The finite operation set is the seven `TimingQueries` operation names plus `incidents.candidates`,
`incidents.create`, and `incidents.append`. Query successes and Incident candidate/dispatch
successes are returned as the unchanged underlying envelopes, preserving their backend IDs and
hashes. `incidents.create` and `incidents.append` only return a pending dispatch receipt.

`call()` first checks the shared Lifecycle. Revoked, finished, or expired work produces a
structured rejection before request routing. Invalid schema, unsupported fields/operations,
invalid IDs, oversized canonical JSON, duplicate IDs, and backend validation failures also return
structured rejections with `effect: none`; none are empty or `not_found` query successes. The
binding performs no automatic retry. It accepts no paths, callbacks, executable references,
schema extensions, supplied identities, model injection, evaluation input, or controller command.

The binding retains at most 64 admitted call request/response pairs, including rejected calls and
candidate reads. Canonical requests are limited to 16 KiB. Every retained request is copied from
its canonical JSON bytes before backend dispatch, so later caller mutation cannot alter history. A
rejected oversized request retains only its byte count and SHA-256, so the unbounded input is not
kept. Once call capacity is exhausted, later calls return `call_capacity_exhausted` with
`retained: false`. Their bounded, saturating `dropped_observations` count is shown in the response
and `audit_snapshot()`; the snapshot never claims those later calls are complete.
`history_max_bytes` is a derived ceiling for these fixed request/response bounds, not a
separately enforced storage quota; response limits come from the fixed query/Incident backends.

`complete(dispatch_id, disposition='confirmed')`, `capture_incident_snapshot()`,
`incident_store`, and `audit_snapshot()` are separate, controller-only Python APIs. They are
deliberately absent from `describe()` and the dispatcher allowlist. `complete` is the existing
synthetic effect observation and can leave the Incident store held; it is never exposed to model
calls. `incident_store` is `None` before the first successful Notification and otherwise exposes
the trusted `TimingIncidents` object solely so an operator can pass it to the existing
`write_timing_snapshot(directory, store)` implementation.
`capture_incident_snapshot()` invokes the existing validated in-memory timing snapshot capture
after Notification initialization and takes no filesystem path. `audit_snapshot()` exports binding
history plus the existing query and, when initialized, Incident audit snapshots. Neither method
admits work nor completes a pending dispatch.

This binding is trusted, single-threaded, in-process fixture composition. It is **not** a security
boundary and provides no OS/process isolation, native authentication, network access, native tool
registration, model invocation, evaluation, durable audit retention, or production Incident/Jira
effect. Its `native_launch` is always `CLOSED`.

Run local checks:

```sh
python3 -m py_compile prototype/run_timing/timing_binding.py
ruff check prototype/run_timing/timing_binding.py
```
