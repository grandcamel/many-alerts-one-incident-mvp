# Run telemetry is sanitized, correlated and best effort

Status: accepted, 2026-09-18, through both decision rounds of ticket 15.

The audience and the Run need to distinguish execution problems from the system Fault being investigated. We choose operational metrics and structured events plus a Receiver-owned sanitized Transcript projection, with explicit correlation and visible gaps. Telemetry may explain what a Run did; it does not independently prove its diagnosis. Beta traces are outside the required demo path.

## Feeds and correlation

The Receiver sends sanitized structured Run events through the collector to Loki. Event type, timing, operation/tool name, outcome category, safe diagnostic summary, available usage and verified source/query references survive projection. Human-readable rendering is a presentation layer, not the stored schema. Do not send raw Transcript bodies or complete assistant text, commands, arguments or tool output by default. Unknown shapes produce an omission marker rather than unfiltered content.

The Receiver's Run ID is canonical. Map an observed native session identity to it explicitly; never assume equality or invent a missing join. Link every admitted Notification and every touched Incident, including zero/one/many relationships. Candidate reads must not appear as accepted Matches. This is a planned correlation contract, not a claim that the current argv or export implements it.

Separate Run telemetry from system telemetry through a dedicated service namespace and feed origin. Keep Run/session/rehearsal IDs, Notification IDs and Incident keys in log fields/structured metadata, not per-Run metric dimensions or Loki index labels. Per-Run dashboard usage comes from correlated event records; aggregate metrics remain bounded. The exact field mapping and native event inventory need verification in the integration specification.

## Read scope and trust

A Run may read retained execution telemetry from itself and earlier Runs within the current rehearsal, to diagnose tool or transport problems. This is an access boundary, not a guarantee that all records remain available: expired, dropped or missing records are unavailable, never evidence that nothing happened. The 24-hour retention policy does not cap rehearsal duration. Enforce this scope through Eyes/Forwarder, not just dashboard filters. These records do not become independent evidence of a system Fault: system claims must trace back to retrieved system evidence. Bound self-observation so queries about query telemetry cannot become an endless investigation.

Remove account identity and exclude credentials/sentinels, raw prompts and unfiltered tool bodies before shared-stack ingestion, even with a demo account. Preserve only approved diagnostic fields and references, with visible omissions and provenance distinguishing tool execution from a Run's assertions. Existing formatter redaction is not proof of arbitrary structured-data sanitization. ADR 0008's repository adjudication Ground truth and scoring material never enter these feeds. Sanitized telemetry is not the complete Transcript required for every citation audit; ticket 24 owns that separate evidence contract.

## Delivery, retention and audience view

Export is bounded best effort and must not block Incident work. Use a bounded in-memory queue, with no new persistent spool. On overload, discard oldest queued records, count loss and expose gaps. Restart makes unconfirmed delivery unknown. Retain shared Run telemetry for 24 hours, while Run read access remains scoped to the current rehearsal; this does not authorize purging system telemetry or OPS/Confluence history. Exact queue limits, send budgets and backend retention enforcement belong in the implementation specification and must be verified.

Assign Receiver-projected events stable Run ID plus sequence identities before enqueueing, so retry delivery cannot appear as repeated actions. Preserve event and observation/ingestion times where available. Show gaps and late arrivals honestly; no fabricated missing events. Native export and Transcript-derived values keep their source attribution. Choose one source for each displayed measure and never sum overlapping usage/cost counters.

The audience gets a compact per-Run dashboard for activity, elapsed time, usage and outcome plus a linked sanitized event timeline, correlated to Notifications and touched Incidents. Unknown final usage or outcome stays unknown/incomplete. Quiet telemetry, exit code or successful export alone never establishes Run success. Ticket 21 owns terminal classification, refusal, timeout and retry mechanics; telemetry must reflect that contract rather than invent another success rule.

## Evidence and consequences

Offline facts and historical research provenance separate current source from earlier probes. The current source renders a lossy redacted projection to container logs; Transcript export and a shared Receiver/native session mapping are not implemented. The old Compose temporality result does not prove the intended venue's behavior. No new model/exporter compatibility, delivery, sanitizer, retention or dashboard acceptance is claimed.

Ticket 35 specifies schemas, queue bounds, sanitization, correlation, collector configuration, dashboard queries and offline/live acceptance boundaries. Tickets 12/17 retain Eyes/Forwarder enforcement, ticket 21 terminal classification, and ticket 24 citation auditing. This is a planning decision; no runtime or Skill code was changed.
