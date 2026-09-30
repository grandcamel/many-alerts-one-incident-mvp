# Changes record operator actions and observed stages

Status: accepted, 2026-09-18, resolving ticket 25 through two approved rounds. Extends ADR 0005 persistence and supplies Change evidence to ADRs 0008, 0011 and 0014 without changing their diagnosis or Run authority rules.

A ConfigMap write is not proof a flag was served, and a rollout is not proof of recovery. Use one operator-controlled in-cluster action coordinator to perform the accepted presenter action and record progress for every injection and undo, including the designated fallback. It is separate from Runs and their read-only Kubernetes route. Direct action recording replaces the earlier unverified proposal that a small passive flagd watcher supplies a complete Change. Existing evaluations and Kubernetes Events remain independent observations; arbitrary out-of-band edits are not comprehensively audited and are marked untracked/unknown when detected.

## Action and evidence contract

A stable Change ID links append-only stages for request, accepted configuration write, rollout observation and served-value/evaluation verification. Record target environment/resource identity, intended flag/variant, observed old/new values where actually read, available resource versions, explicit injection/undo intent, presenter alias, event time, observation time and outcome. Distinguish accepted write, rollout health, served value and application evaluation; do not promote one into another. Attach evidence or mark unknown. Symptom/recovery confirmation remains separate system evidence. Never include adjudication Mechanism prose, Ground truth, scoring hints or personal identity in Change telemetry. A Change supports only the action/stage it records, not the causal conclusion that it produced an Incident.

Serialize actions across the whole demo because flags share configuration and flagd rollout. Allow one active action and no queued injections. An immutable request payload and stable Change ID make re-submission return recorded progress; conflicting reuse is rejected. Persist stage/dispatch intent before mutations. After interruption, restart, version drift or uncertain dispatch, hold admission and reconcile journal plus observed state instead of repeating a mutation blindly. Sequence numbers order request/stages; wall-clock and ingestion order do not establish causal order.

Undo is a distinct linked Change. Give it priority after reconciling in-flight state; never race an unresolved injection. Restore the recorded pre-injection value under fresh version/value checks, preserve unrelated configuration, and perform the accepted Fault-specific service restart. Unexpected drift requires explicit operator selection/reconciliation. An off value or completed restart does not prove symptoms recovered or an Incident completed; accepted Alert/member rules still govern Incident handling.

## Authority

The coordinator has a separate operator-controlled identity scoped to the named demo ConfigMap, necessary named Deployments and required read-back resources. Enforce allowed flag/variant fields and permitted rollout actions as well as API permissions. No arbitrary shell/exec or caller-selected targets. Runs receive neither mutation tokens nor coordinator control/emergency operator credentials. Publish only a stable presenter alias; privately record the authenticated calling principal where available without presenting the alias as proof of a natural person's identity. Disable or restrict flagd-ui editing during managed demonstrations. Direct administrator intervention remains an explicit emergency path, not another silent injection route.

## Journal and retrieval

Keep an operator-only durable in-cluster Change journal separate from Receiver recovery and Memory. It survives coordinator/pod restarts within a rehearsal, not assumed cluster destruction. Cap it at 100 MiB, reserving 10 MiB for recovery/undo; ordinary injections cannot consume the reserve. Retain journal records and the dedicated Loki Change stream for seven days. Before expiry, reset or destruction, reconcile unresolved actions or explicitly hand them off to a private operator recovery record. Capacity, failed durable writes or overdue unresolved retention holds new injections. The recovery handoff must preserve unresolved state rather than silently declare completion.

Emit a dedicated structured Change stream through the collector to Loki, with producer identity distinguishable from application and Run logs; Runs retrieve it through approved Eyes/Forwarder queries. Prove current-rehearsal retrieval readiness with a clearly marked diagnostic record before injection. A transport receipt alone is insufficient. Optional Grafana annotations derive from the same Change IDs; they are audience views, not another authority or a required annotation API for Runs. Their failure does not gate actuation.

The journal is a new explicit planned persistence exception to ADR 0005. Its durable delivery is separate from ADR 0010's best-effort in-memory Run telemetry; seven-day Change retention does not alter that feed's 24-hour retention. All limits and boundaries require specification/acceptance rather than assuming the current runtime implements them.

## Deadlines and failure

Allow 180 seconds per coordinated actuation attempt, including config write, rollout and bounded read-back, measured monotonically. Allow 30 seconds after each stage is queued for it to become queryable through Eyes. These are hold thresholds, not guarantees that an upstream operation stopped at timeout. Missing a deadline records incomplete/unknown state and holds further injections; reconcile before recovery. Symptom and Incident recovery timing are separate.

Retry only telemetry delivery automatically, with stable Change/stage IDs, bounded backoff and at most three sends per stage per operator-authorized delivery attempt. Deduplicate display while retaining delivery provenance. Exhaustion leaves the stage pending for operator inspection/resume, not repeated actuation or an infinite send loop. Missing delivery cannot produce a model retry, new Incident or prescribed diagnosis.

Keep operator recovery/undo available during telemetry failure, recording locally for later delivery. If even recovery recording is unavailable, permit direct operator emergency undo with an explicit audit gap. Restoring the system takes precedence over a complete record. Qualification excludes lifecycles with untracked interventions, unresolved stages or material Change-record gaps, even when recovery succeeds. Later repairs do not erase the original defect; retain labelled replay until this path and the other qualification gates pass.

## Evidence and remaining work

Offline facts distinguish the current Compose implementation from historical intended-venue measurements. Some traced evaluations expose a Trigger, but their existence does not provide complete actor/action-stage recording. A supported causal inference may qualify without a directly observed Trigger under ADR 0014; Change evidence does not supply the diagnosis or soften Mechanism scoring.

Ticket 41 owns the schema, capabilities, identity/grants, persistence, delivery and acceptance specification. Tickets 12/36 consume the read-only retrieval contract, ticket 30 consumes teardown/recovery requirements, and tickets 38/39 consume qualification evidence. No scripts, Skill, collector, runtime or cluster changes, paid Runs or live acceptance occurred.
