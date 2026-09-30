# Report scoring requires supported claims and human review

Status: accepted, 2026-09-18, resolving ticket 24 through two approved rounds. Applies ADR 0008's Mechanism-only scoring and extends ADRs 0010 and 0013 with an audit and qualification contract.

A keyword match cannot distinguish a cause from a dismissed hypothesis, and a correct cause can accompany invented observations. Deterministic prechecks therefore check structure, reference linkage, retrieval provenance and reproducible arithmetic; a named human decides causal attribution, claim support and the final verdict. No keyword check or paid model judge awards a semantic pass.

## Grades and lifecycle rollup

Grade the Mechanism as correct, partial, wrong or undetermined, and evidence as supported, unsupported or unverifiable. Keep execution/effect outcomes, time and spend separate under ADRs 0012/0013. For each observation or causal claim, record its supporting retrieved evidence and whether it is observed or inferred. A clearly labelled inference supported by system evidence may earn a correct Mechanism grade without a directly observed Trigger. Naming a flag, component or Change alone is not diagnosis. Retrieved Memory is context, not independent confirmation.

An invented observation/control or unsupported causal claim fails evidence even if the Mechanism happens to be correct. Missing audit evidence means unverifiable, not proof of fabrication; it cannot qualify a model. Early Reports may explicitly leave the Mechanism partial or undetermined while investigation proceeds, but their asserted observations and causal claims must remain supported. A clean diagnostic lifecycle requires a correct supported final Mechanism, supported claims throughout, no earlier invented observation or confidently wrong causal assertion, and correct final arithmetic. A missing final Report, incomplete audit or unfinished review prevents a pass. Do not average grades into a score that hides a failure.

Check durations, counts and rates mechanically where retrieved inputs and units permit reproduction. Incorrect displayed arithmetic requires correction before that Report revision earns a clean pass. Preserve the original defect separately from wrong diagnosis or fabricated evidence. A corrected revision can pass without retroactively making the defective lifecycle a clean qualification sample. Stated rounding is allowed; missing inputs remain unverifiable.

Review every created or updated Report revision, linked to its Run and Fault lifecycle. One named human adjudicates an ordinary sample before it counts toward qualification or a reviewed trend. Disputes require a second named human review; exclude disputed samples from qualifying passes until reconciled. Preserve both rationales and append dated superseding adjudications. A reviewer-error correction is distinct from correcting the Report itself. Show pending on stage until human review exists.

## Private audit evidence

Use an operator-owned local audit bundle outside Run mounts, Memory, shared telemetry and Git. Preserve exact reviewed Report revisions and correlated tool requests/returned responses, query/time scope, provenance and explicit gaps sufficient to audit claims. Tool names, sanitized dashboards and later re-queries do not establish what the Run retrieved at the time. Remove credentials and account identity; necessary support lost to redaction or truncation makes affected claims unverifiable. Never expose adjudication Ground truth or scoring feedback to Runs.

Bound stored audit evidence to 100 MiB per Run and 2 GiB total, retained for at most 30 days. Qualification preflight must establish capture readiness and available capacity. Mid-Run capture failure or exhaustion preserves safe evidence and visible gaps; it cannot block required OPS handling, permit unbounded growth or silently evict unreviewed evidence. Affected samples become unverifiable. Expire raw audit evidence at the retention limit and label surviving verdicts historically reviewed but no longer independently re-auditable from the expired bundle. Compact records and artifact digests remain local in the planning repository; a digest identifies an artifact but does not prove its claims after deletion. No upload or publication is authorized.

This private bounded capture is separate from ADR 0010's best-effort sanitized feed and its 24-hour retention. Neither policy authorizes unfiltered secret collection. Ticket 39 specifies capture, access, sanitization, storage and completeness evidence; no current implementation is implied.

## Records and qualification

Store versioned JSON per Report revision and a linked lifecycle manifest, with readable summaries generated from them. Include artifact/revision identities and digests; Fault, Run and Incident links; rubric version; model/auth/venue/Memory condition; reviewer/time; claim-to-retrieval mappings with observed/inferred status and query/time scope; completeness; Mechanism/evidence/arithmetic grades; execution/effect/time/spend references; defects and rationale. Compact records must not embed raw audit bodies or credentials. Freeze the rubric before a comparison set. A changed rubric starts a new series unless retained evidence is explicitly re-adjudicated under it; preserve previous verdicts.

ADR 0013's three lifecycle samples per candidate comprise two primary-presentation Fault samples and one designated-fallback Fault sample, including at least one cold-start and one Memory-assisted condition. Record the actual conditions; this small mixed sample does not establish a controlled Memory comparison or a success rate. Qualify only the demonstrated presentation/fallback scope. Any failed or unverifiable sample prevents its three-sample set from qualifying. Replacements consume the existing allocations or later weeks and do not remove failures from the record. A Fault requires reviewed repository-only Mechanism/Trigger Ground truth before qualification; additional definitions are explicit follow-up work. Diagnosis quality alone does not satisfy the separate timing, effects, billing and mediated-client gates.

## Evidence and remaining work

Historical facts show that the prototype scorer already describes itself as a precheck and records its earlier mention/attribution mistake. Its historical flag-name pass marks are not current Mechanism grades. Raw per-arm Transcripts are not committed, so recorded historical audits cannot be recast as a fresh response-level citation audit.

Ticket 39 specifies evidence capture, records, rollup and offline acceptance. Tickets 16/34/35/38 consume the Report, audience, telemetry and qualification boundaries. Ticket 40 supplies the missing reviewed fallback definition before qualification. Ticket 25 owns Change representation without weakening Mechanism scoring. No scorer, Skill or runtime changes, paid review, model Runs, cluster or live acceptance occurred.
