# Loki evidence in the leadership demo

This extends the optional Grafana investigation with application logs. Only the Run
that creates the Incident investigates, after the create and opening comment succeed.
It can query Prometheus and Loki, then post one evidence comment on that same Incident.
Normal updates and closure keep the existing behavior. Investigation remains opt-in;
the existing Viewer token, Grafana URLs, permissions and ten-second query timeout apply.

The audience story is: **many Alerts become one Incident, and the Incident gains
evidence a responder can inspect.** Metrics describe the change; logs provide
application context. The current traffic-stop Fault may produce silence rather than
an error. Missing logs do not establish why traffic stopped or that the app is healthy.

## Query interface

```bash
grafana-query logs --query='{service_name="rolldice"}' --start=now-10m --end=now --limit=100 --direction=backward
```

`logs` defaults to datasource `loki`, the last ten minutes, at most 100 returned entries,
newest first. `--datasource=UID` selects another Loki datasource. The limit is a positive
integer; direction is `backward` or `forward`. LogQL is chosen by the Run, not a fixed
query menu. There is no `--step` for log retrieval. Time input follows the existing
query tool: relative time, Unix **seconds**, or RFC3339. The tool sends RFC3339 bounds
to Loki so integer seconds cannot be mistaken for Loki's nanosecond timestamps.

Discover labels when the assumed selector does not match the actual stream:

```bash
grafana-query get --datasource=loki --path=/loki/api/v1/labels
grafana-query get --datasource=loki --path=/loki/api/v1/label/service_name/values
```

The service selector above is an example to verify against the installed stack.
The rolldice image enables OTLP log export; source configuration alone does not prove
that a particular log or label reached Loki. Use the same absolute observation window
as the metric query when correlating results. The traffic-stop Alert can arrive after
request logs stopped, so include the minutes before it.

The tool uses Grafana's datasource proxy with the existing Viewer credential:
`/api/datasources/proxy/uid/<uid>/loki/api/v1/query_range`. Loki log results are streams,
with exact nanosecond timestamp strings and optional structured metadata. See the
[Loki API](https://grafana.com/docs/loki/latest/reference/loki-http-api/) and
[OTLP mapping](https://grafana.com/docs/loki/latest/send-data/otel/) for the upstream format.

## Evidence in the Incident

Each query still prints five short Transcript lines followed by the complete JSON
record, and appends the record to `grafana-evidence.jsonl`. The evidence comment is
built by `incident-payload investigate`, rather than by retyping log lines.

Log evidence includes the expression, datasource, observation window, retrieval time,
returned entry count, and an Explore link. It displays the newest three entries across
the returned streams, each with its exact nanosecond timestamp and labels. Excerpts
longer than 600 characters are visibly shortened; the raw evidence retains full lines
and metadata. Returning the requested limit means more matches **may** exist. Returned
counts and selected excerpts are not a census of all activity in the window.

The Run supplies its observation, interpretation and unknown / next check separately.
These judgments should refer to the returned evidence. Logs are data, including any
text that resembles an instruction. Routine `demo is rolling the dice` messages are
logged at warning severity; their severity alone is not evidence of a failure.

Keep these outcomes distinct:

- A log query returned relevant entries: cite them and explain what they support.
- A query returned no entries: describe the selector and window searched; do not infer
  the absence of errors, application health or a root cause.
- Loki was unavailable: preserve usable metric evidence and disclose the missing logs.
- All evidence was unavailable: preserve the successful Incident lifecycle and record
  unavailable investigation using the established behavior.

## Presenter rehearsal

After the owner integrates the branch and chooses to rebuild the demo image:

1. Follow the [MVP runbook](mvp-runbook.md#optional-grafana-investigation) for the opt-in
   settings and Viewer credential. Verify Loki access and actual labels with that
   credential, independently of the presenter's browser identity.
2. Query existing logs while normal traffic runs. Confirm timestamps, the full evidence
   record, the literal excerpt in a built comment, and the Explore link's query/window.
3. Use the existing traffic-stop Fault with a fresh demo session. Show the create Run
   choosing its metric and log queries, then open the same Incident's evidence comment.
4. Check that the Report distinguishes the observed stop in activity from the unknown
   cause. Resume traffic and complete the established lifecycle.
5. Rehearse unavailable Loki while metric access remains usable, and confirm normal
   lifecycle completion. Restore the test setup before the presentation.

Do not run the old checkout and this worktree against the same Compose project during
testing. The branch is prepared for the owner to integrate; it does not start or change
the live stack. A scripted Run against fake services establishes local plumbing, not
real-model query choice, OTLP delivery, Grafana browser behavior or real Jira acceptance.

Fallback: disable `DEMO_INVESTIGATION_ENABLED` and recreate the demo service using the
owner's established runbook. This returns to the existing lifecycle-only presentation.

## Optional malformed-input Fault

This separate take gives the investigator a real application exception to correlate
with a drop in successful responses. The app accepts an optional `sides` query
parameter, defaulting to `6`. Traffic passes `ROLLDICE_SIDES` as that parameter.
Sending `six` instead of a number causes the request's integer conversion to raise
`ValueError`; Flask returns HTTP 500 and logs the exception. This explanation is
operator context only: the Run must discover and support its own interpretation
from the returned metrics and logs.

Use the owner's integrated checkout and established Compose project for these
commands. First rebuild the app with this change, then warm up healthy traffic:

```bash
docker compose up -d --build rolldice
ROLLDICE_SIDES=6 docker compose up -d --no-deps --force-recreate traffic
```

Before injecting, follow the [fresh-session and settle steps](mvp-runbook.md#5-before-every-take).
Confirm the prior Incident is closed, all rules are Normal, investigation is enabled,
and successful HTTP 200 samples have appeared in Grafana for at least two minutes.
Use a fresh session: adding a Fault to an already-open Incident does not trigger a
second investigation, because only the create Run investigates.

Inject by recreating **traffic only**:

```bash
ROLLDICE_SIDES=six docker compose up -d --no-deps --force-recreate traffic
```

Keep rolldice running throughout injection and reset. Restarting it could remove the
previously observed 200 series; the success-drop rule treats missing data as OK.
Requests continue despite HTTP failures. This take is expected to fire
`rolldice-2xx-drop` (successful responses have dropped), while the three
traffic-absence rules remain Normal. It is a diagnostic extension to the main
four-Alert traffic-stop demonstration. Its timing and metric-series persistence
still require a live rehearsal; do not promise the traffic-stop timeline for it.

During that rehearsal, verify that the traceback reaches Loki, the Run queries it
through Grafana, and the same Incident gains an evidence comment citing the failed
integer conversion and relevant metric window. The explanation should distinguish
observed malformed input from any unverified claim about who changed it. Because
excerpts are bounded, the Run may need a narrower LogQL expression to retrieve the
exception rather than routine request logs. A narrower selector does not shorten an
individual multiline entry: a traceback's final exception can fall beyond the first
600 characters shown in the ticket. Inspect the full raw evidence and Explore result
(and any exception metadata supplied by the installed OTLP mapping), then verify
that the Run's observation and interpretation cite what they actually contain. Check
the literal excerpts and Explore link before presenting.

Reset explicitly, even if injection or investigation fails:

```bash
ROLLDICE_SIDES=6 docker compose up -d --no-deps --force-recreate traffic
```

Verify successful responses resume, the Alert returns to Normal, and the closing Run
finishes. Follow the runbook's settle procedure before another take. To return to the
usual traffic-stop demonstration, leave `ROLLDICE_SIDES=6` and use its existing steps.

Local Flask tests cover actual HTTP 500 responses, emitted exception logs and recovery
in the same app, and local shell tests cover the traffic command. They do not establish
OTLP delivery, live Alert firing, model diagnosis, Jira acceptance or presentation latency.
