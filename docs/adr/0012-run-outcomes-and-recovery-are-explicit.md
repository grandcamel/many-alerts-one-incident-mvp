# Run outcomes and recovery are explicit

Status: accepted, 2026-09-18, resolving ticket 21 through two approved decision rounds. Extends ADRs 0003 and 0005 and supplies the failure/recovery contract used by ADRs 0009–0011.

A process can exit cleanly while its terminal result reports an error, and an interrupted Run may already have changed an Incident. We therefore track execution separately from confirmed, partial, uncertain or absent external effects. Failed work stays identifiable until reconciled and explicitly retried or disposed of; neither an exit code nor a model's success claim is enough.

## Outcome and refusal rules

Receiver-observed spawn failure, timeout, cancellation or containment failure overrides apparent terminal success. A recognized, well-formed non-error terminal result with success subtype and clean exit supports completed execution only when no such override exists. Result-level `is_error`, an error terminal reason or nonzero exit prevents success; missing required fields, malformed evidence or conflicting/duplicate terminal results is incomplete. Keep both reported and derived outcomes visible. Missing usage is unknown, not zero. Report model/service unavailability only at the scope the evidence establishes.

Successful handling also requires separately accounted required operations or justified no-op outcomes. Trusted Forwarder responses and read-back evidence confirm effects; a Run's prose alone does not. Preserve confirmed OPS effects when optional Memory writes or telemetry export fail, and identify the incomplete secondary step without repeating the OPS work.

A Run must never create a probe Incident or test permissions with a mutation. After a denial proving the intended mutation was not dispatched, allow one shorter, evidence-backed Report attempt within the existing budget, with explicit omissions. Do not loop, change permission mode or bypass the approved tool. Uncertain dispatch requires reconciliation, not a shorter duplicate create. Ticket 16 owns the compact Report's shape and size; historical command lengths do not establish a universal CLI limit.

## Time and containment

The total Run budget is 300 seconds from launch on a monotonic clock: 270 seconds for startup/work, up to 20 for interruption/local flush, then 10 for forced termination and reaping. Queue wait is separately visible. At the work deadline or operator cancellation, revoke service sentinels and request interruption (SIGINT); only local result/usage flush and cleanup remain permitted. Kill/reap remaining processes if needed. Cancellation enters cleanup earlier and never extends the original deadline. An already-dispatched upstream operation may still complete; revocation is not rollback.

Do not promise that interruption returns a result or final usage. If containment/reaping is not confirmed by the bound, report containment failure and hold dispatch; do not pretend processes are gone or extend authority. Descendants retaining stdout after their parent exits are part of the containment acceptance cases. The historical 370-second Run does not fit this budget; model and Report selection must fit it instead of silently extending the slot.

Silence alone cannot distinguish thinking from a stall. Display elapsed time and last observed activity, mark missing observations honestly, and allow explicit cancellation. New output does not reset the deadline. Progress and telemetry are diagnostics, not success signals.

## Durable admission and recovery

Add a Receiver-owned durable recovery journal, separate in purpose and access from the Run-written Memory directory. It records admitted work identities, pending/held source records and arrival order, latest-admitted dedupe state, execution outcomes, mutation intents before dispatch, and observed confirmations/uncertainties with reconciliation references. Runs cannot alter it. Do not store credentials, raw prompts/tool bodies or repository Ground truth. The journal tracks processing/evidence, not a second authoritative Incident state; fresh OPS reads remain authoritative.

This is an explicit persistence exception to ADR 0005, in addition to ADR 0009's Memory directory. Preserve it across pod/container restarts within a rehearsal, without promising survival of cluster destruction. Admission that cannot be durably recorded must not be acknowledged as successful. Restart begins with dispatch held and old sentinels invalid. Unresolved work requires explicit disposition before reset; do not erase uncertainty by starting a new rehearsal.

After failed/interrupted/incomplete execution or uncertain required OPS effects, hold new Run dispatch while continuing bounded Notification admission/coalescing. Latest-admitted duplicate suppression remains ticket 31's rule, but the journal preserves outstanding failed work independently so a suppressed repeat cannot erase the recovery obligation. Bound the journal and pending admission explicitly in the implementation specification; bounded coalescing is not unbounded storage.

On authorized retry, reconcile external effects first, then derive fresh work from outstanding failed Alerts plus newer pending Alerts. Admission order determines the newest status/values per Fingerprint, retaining source-group provenance; omission never means Resolved. Never reissue a confirmed operation, but a newer state can justify a new operation after fresh Match evaluation. Do not replay a captured command sequence or blindly rewrite an old Report. Apply ticket 14's eligibility at retry time; an Incident aging out does not remove the obligation to reconcile an uncertain operation against it.

## Operator control and acceptance

Provide operator-only cancel, inspect/reconcile, retry and resume controls. A retry starts at most one fresh attempt with a new Run ID and sentinels under the same budget. Another failure holds dispatch again. Resume permits ordinary dispatch only after held work is completed or explicitly disposed of and mandatory boundaries are ready. Record human abandonment of unprocessed work; it cannot silently settle unknown external writes. Do not automatically switch models or replay mutations. Optional Memory repair targets the missing secondary step alone.

The offline facts distinguish current exit-only handling, historical false-success measurements and documentation-only interruption behavior. No new model, interruption, durable journal, tenant or containment acceptance was run. Ticket 37 specifies implementation and acceptance, and the refusal/recovery contract supplies future Skill guidance without editing the Skill. Tickets 32, 35 and 36 consume the accepted journal, outcome and lease requirements; ticket 16 retains Report form.

ADR 0013 adds week-scoped spend accounting and admission holds. Rehearsal reset cannot clear outstanding reservations or weekly spend; ticket 38 specifies that ledger alongside this rehearsal-scoped recovery journal.
