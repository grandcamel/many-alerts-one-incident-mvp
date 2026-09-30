# Venue lifetime is bounded with protected teardown

Status: accepted, 2026-09-18, resolving ticket 30 through two approved rounds. Extends ADR 0007's venue contract and integrates recovery, accounting, audit and Change obligations from ADRs 0009–0015.

Historical memory growth and one observed load-generator OOM do not establish a safe session duration. Use a fresh venue for each presentation or full rehearsal lifecycle, keeping the historically tested resource allocation as the specification baseline. Verify and pin actual settings before acceptance. Do not raise limits based on a single headroom snapshot or assume a linear leak. Defer leak-versus-cache investigation and extended-uptime tuning until short-session acceptance fails or longer operation is explicitly requested.

## Age and health admission

Measure venue age from cluster creation, including provisioning; pod/coordinator restarts never reset it. Start the planned 30-minute session by cluster age 30 minutes. Missed setup, readiness or prior-OPS-eligibility gates hold the live attempt; use labelled replay or explicitly rebook/rebuild after preserving state. No automatic replacement cluster or new spending authority follows from failure.

Before injection require five continuous healthy baseline minutes with all Faults at declared baseline values, stable intended replicas, no unexpected restarts or critical infrastructure Alerts, working mandatory service boundaries and fresh system telemetry. Required health observations must be no older than 60 seconds. Require LGTM and load-generator working sets below 80 percent of verified limits, at least 25 percent node memory available, and no pressure or evictions. Verify metric semantics, actual limits and freshness; missing evidence fails readiness. Complete the baseline before the age-30 start cutoff. Apply existing OPS eligibility, recovery/Change reconciliation, spend, audit-capture and mediated-client gates as well.

During a Fault, distinguish expected symptoms/restarts from unrelated venue failure. Node pressure, exhausted mandatory backends and unexpected critical infrastructure conditions still hold admission. Keep C4 cluster-wide, including load-generator and cluster infrastructure; preserve actual identity and never force an unrelated Alert into the injected Fault's Incident. Follow accepted Match and uncertainty rules. Material contamination prevents a clean qualification sample; do not suppress evidence to improve the demo count. A later alert-scope change needs its own decision and acceptance.

After the 30-minute live window, mark overrun and switch audience presentation to labelled replay. Already-admitted Incident/recovery work may continue within remaining bounds, without claiming on-stage completion. Launch no model Run at or after cluster age 85 minutes, leaving its existing five-minute maximum within age 90. Earlier health/spend holds take precedence. At age 90 ordinary injections and Run dispatch remain held; recovery/handoff/teardown is operator-owned. These are policy thresholds requiring validation, not uptime guarantees or a blind deletion timer. Show actual stage and recovery durations separately.

## Cloud accounting

Budget venue spend separately from ADR 0013's $150 model envelope: $10 per Monday–Sunday week in America/New_York, reserving $2 before every cluster creation attempt, including failed setups and replacements. Count attributable node, control-plane, storage, network and residual-resource charges. Verify applicable current prices and billing behavior before creation. A reservation is not a maximum possible provider charge.

Admit creation only when known spend and outstanding reservations/exposure leave defensible room. Preserve unknown charges, reconcile late bills without double-counting, and keep the weekly record outside the destructible cluster. No automatic top-up, recreation, higher resource tier or budget extension. This policy authorizes no purchases or provisioning. Recovery beyond the age threshold remains visible as incurred venue cost, not free time or an erased reservation.

## Draining and protected teardown

At age/readiness breach, hold new injections and model dispatch while retaining bounded pending Notification admission and unresolved-state bookkeeping. Existing Runs remain under ADR 0012's deadlines and containment/recovery rules; do not extend authority or discard effects. Operator undo and reconciliation remain available. Export/handoff preserves obligations, not automatic success or permission to resume model work.

Before destruction, stop ordinary admissions, reconcile/cancel active work under existing bounds, undo or explicitly hand off Fault state, and save a private off-cluster recovery manifest plus required artifacts. Include environment identity, outstanding Notification/Run/Change identities and stages, uncertain external effects and evidence references, OPS disposition, weekly model/cloud reservations, private audit artifacts/digests and the named operator accepting unresolved obligations. Exclude credentials. Read back and compare digests before destroying the only source. Preserve external OPS/Confluence history; do not automatically close Incidents or erase uncertain writes by starting a new rehearsal. Fresh-rehearsal OPS eligibility remains ADR 0009's rule. Handoff remains operator-only; it does not automatically expose prior-rehearsal Memory to Runs or promote recovered records into OPS authority.

Verify provider resource inventory after deletion, including residual volumes/IPs and separately billed resources. A command exit is not cleanup proof. Record uncertain deletion and remaining cost and escalate to the operator. Emergency restoration has priority; failed export requires an explicit exceptional human decision about potential evidence loss rather than an automatic deletion path. Age 90 does not itself authorize destructive cleanup.

## Acceptance and evidence

Offline facts correct the historical memory arithmetic: 726 to 1640 MiB over 92 minutes is 9.93 MiB/min, not 14. Linear extrapolation, a repeatable OOM age, current headroom and universal 30-minute safety remain unproven. The bounded review did not verify the claimed 12-minute cold path. Historical artifact measurements are not fresh acceptance.

Ticket 42 specifies clocks, health/admission, accounting, protected export and cleanup, with offline boundary fixtures. Separately authorized intended-venue acceptance requires one no-Fault 90-minute baseline observation, requiring no model Runs, plus the three already budgeted candidate qualification lifecycles on fresh venues. Charge the baseline venue to the cloud envelope; it is not one of the three scored model samples. Record actual timing, health, spend and cleanup. This bounded gate does not diagnose a leak or prove universal safety. Failures retain replay and produce specific tuning/measurement follow-ups rather than silent limit increases.

Tickets 32/37/38/39/41 consume the state-lifetime, recovery, budget, audit and Change interfaces. No runtime, rule, Skill, cluster, credential or model changes, purchases or live acceptance occurred.
