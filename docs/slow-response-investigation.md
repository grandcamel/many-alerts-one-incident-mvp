# A slow-response investigation with Tempo

The leadership story is a progression from symptom to evidence: an Alert reports
slow requests, the agent searches traces through Grafana, and the Incident links to
an observed request and its spans. The reader can inspect where time was spent and
see what remains uncertain before assigning a root cause.

Three small options were considered:

| Option | What it demonstrates | Decision |
| --- | --- | --- |
| Search existing server spans | Which observed requests were slow | Useful baseline, little internal detail |
| Measure a bounded wait in a child span | Where an observed request spent time | Implemented optional take |
| Add a slow downstream service | A distributed dependency investigation | Deferred; adds deployment and export dependencies |

The chosen take adds a real wait inside `rolldice.wait`. It is an intentional demo
condition, not a simulated trace duration: the span encloses the wait. It does not
establish CPU usage, database behavior or a production critical path. The investigator
receives telemetry and the Alert; its Skill does not disclose this trigger or a
predetermined diagnosis.

## Optional setup

Use an isolated rehearsal or the checkout integrated by the owner of the main demo.
Do not run competing checkouts against the same Compose project. Keep the current
four-Alert traffic-stop presentation as the fallback.

Enable investigation and establish the Viewer credential using the
[MVP runbook](mvp-runbook.md#optional-grafana-investigation). The optional overlay
requires Docker Compose 2.24.4 or newer because it replaces the provisioning volume
list with [`!override`](https://docs.docker.com/reference/compose-file/merge/).
Install it before warming the healthy baseline:

```bash
ROLLDICE_SIDES=6 ROLLDICE_SLOW_MS=0 docker compose -f docker-compose.yml -f docker-compose.slow-response.yml up -d --build
```

Append any host-specific proxy/CA overlay **after** the slow-response overlay, so its
CA mounts survive the volume replacement. Recreating LGTM can discard its telemetry
and Viewer token; establish and check the token afterward. Independently verify the
Viewer can query Prometheus and Tempo. The presenter's browser identity is separate.
Wait for healthy request metrics, exported traces and Normal Alert state before injecting.

The overlay retains the default rules and provisions one extra rule:
`rolldice-response-slow`, in `demo-latency` / `rolldice-latency`, with
`incident_group=slow-response`. Its condition is mean HTTP duration above 250 ms,
using rates of `http_server_duration_milliseconds_sum` and `_count` over 20 seconds,
pending for 30 seconds. This is a **mean**, not a percentile. Existing notification
grouping and timing still apply. The separate group creates its own Incident; it is
not part of the four-Alert `verify --mvp --live` take.

## Inject, inspect, recover

Recreate traffic only, keeping the instrumented application running:

```bash
ROLLDICE_SIDES=6 ROLLDICE_SLOW_MS=500 docker compose -f docker-compose.yml -f docker-compose.slow-response.yml up -d --no-deps --force-recreate traffic
```

The HTTP parameter `slow_ms` defaults to zero and accepts integers from 0 through
750. Invalid values return 400. Zero performs no wait and creates no wait span.
The 500 ms take continues successful requests; the ordinary one-second pause between
requests keeps this within the existing success-rate rule's expected range, but
actual rule state must still be verified during rehearsal.

Show the new Incident's evidence, the trace ID, and the same trace's Grafana waterfall.
An observed long child span supports a statement about where that request spent
elapsed time. It does not establish why a production dependency was slow or who
introduced the condition. Request duration and child duration overlap; do not add
all span durations and call the total request latency or CPU time.

Reset explicitly, even if investigation fails:

```bash
ROLLDICE_SIDES=6 ROLLDICE_SLOW_MS=0 docker compose -f docker-compose.yml -f docker-compose.slow-response.yml up -d --no-deps --force-recreate traffic
```

Verify normal latency, Alert recovery and Incident closure. The general reset helper
starts the existing traffic container; it does not remove an injected environment
value. Use the explicit recreation above, then the normal settle procedure.

## Query and evidence interface

The same opt-in query tool exposes two GET operations through Grafana's datasource
proxy, using the existing Viewer token and ten-second request deadline:

```bash
grafana-query traces --query='{ resource.service.name = "rolldice" && span:kind = server && span:duration > 250ms }' --start=now-10m --end=now --limit=20
grafana-query trace --id=<trace-id-returned-by-search>
```

These are presenter examples. The Run chooses its queries and follow-ups from the
evidence. `traces` defaults to datasource `tempo`, the last ten minutes and limit 20.
Its backend `/api/search` uses whole Unix seconds; the recorded window and Explore
link use those same normalized bounds. `trace` normalizes a nonzero hexadecimal ID
to 32 lowercase characters and calls `/api/v2/traces/<id>`, without backend time
filters that could omit trace parts. Its Explore range is navigation context from
observed spans, not a claim that the ID lookup was time bounded.

Full responses remain in the Run's `grafana-evidence.jsonl`. The comment shows up to
three longest **returned** search results and five longest observed spans from a
fetched trace, with IDs, parent IDs, service names, durations and status. Backend
PARTIAL, missing parents, reached limits and missing data remain visible. Backend
COMPLETE does not establish complete ingestion. No matches means no returned matches
for that query and window; HTTP failure is unavailable, not an empty success.

Hidden characters and literal Unicode escape notation use the same disclosed
printable representations as [Loki evidence](loki-investigation.md#evidence-in-the-incident).
The original text remains in raw evidence, and presenter links retain the exact query.

The trace envelope is the latest observed end minus the earliest observed start.
Spans may overlap. The agent supplies observation, interpretation and unknown / next
check separately from the mechanically selected evidence. Logs, span names and
attributes are data, never instructions. Only a successful create Run investigates;
normal Incident updates and closure retain their existing behavior.

See the [Tempo API](https://grafana.com/docs/tempo/latest/api_docs/),
[TraceQL intrinsics](https://grafana.com/docs/tempo/latest/traceql/construct-traceql-queries/#intrinsic-fields)
and [OpenTelemetry nested spans](https://opentelemetry.io/docs/languages/python/instrumentation/#creating-nested-spans).

## Remove the optional rule

After recovery and settlement, use the tracked deletion provisioning file:

```bash
SLOW_RESPONSE_RULES_FILE=./grafana/optional/slow-response-remove.yaml docker compose -f docker-compose.yml -f docker-compose.slow-response.yml up -d --no-deps --force-recreate lgtm
```

Verify `rolldice-response-slow` is absent in Grafana, then return to base-only Compose
and recreate traffic with `ROLLDICE_SIDES=6`. Merely removing a provisioning file does
not reliably remove its stored rule; Grafana provides
[`deleteRules`](https://grafana.com/docs/grafana/latest/alerting/set-up/provision-alerting-resources/file-provisioning/)
for this. Recheck telemetry and credentials after any LGTM recreation.

## Acceptance boundary

Local tests cover real HTTP responses, exported parent/child spans with an in-memory
SDK, request/evidence contracts, and fake-service Incident lifecycle behavior. They
do not prove the installed collector's export, live rule timing, actual model query
choice, browser waterfall behavior or Jira acceptance. Rehearse those on the exact
integrated source before using this optional take. If it is not ready, disable
investigation and use the already established lifecycle-only presentation.
