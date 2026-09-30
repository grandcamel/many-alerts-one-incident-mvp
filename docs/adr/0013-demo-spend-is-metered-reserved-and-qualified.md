# Demo spend is metered, reserved and qualified

Status: accepted, 2026-09-18, resolving ticket 22 through two approved decision rounds. Extends ADR 0012 admission/recovery and supersedes the Anthropic credential exception in ADRs 0002 and 0011.

Historical Transcript estimates do not establish billed spend or subscription allowance. Use dedicated metered API billing for demo and rehearsal work. Provider billing is the actual-spend authority; SDK/Transcript cost is an estimate, and missing usage remains unknown. Keep cloud/venue cost separate. A reported number must identify its evidence category, sample, model, auth and date; never translate list-price estimates into subscription credits or guaranteed future Runs.

## Budget and admission

The model-spend planning envelope is $150 per Monday–Sunday week in America/New_York: three rehearsal Fault lifecycles at $30 each, one presentation lifecycle at $30, and $30 for diagnostics and retries. Each lifecycle permits at most ten attempted Runs; diagnostics permit at most ten attempts. Reserve $3 before each attempt. Every retry counts as another attempt and consumes diagnostics; it also remains part of its lifecycle's attempt/spend ceiling without duplicating the charge in the weekly total. Additional presentations require explicit reallocation or a separately approved budget. Cloud/venue spend needs its own approved allocation before provisioning.

These numbers constrain admission, not the maximum possible charge for an in-flight provider request. Reserve durably under Receiver ownership before launch, inaccessible to Runs, and enforce every applicable allocation and attempt limit. Reconcile attributed provider actuals against estimates/reservations without double-counting. Keep unknown attempts reserved and disclose possible exposure beyond the reservation. Hold further model dispatch if billing lag or unknown outstanding exposure prevents a defensible remaining-budget calculation. No automatic top-ups, automatic model switching or silent free retries.

Weekly accounting must not reset with a rehearsal or pod restart. Preserve or reconstruct the week's spend and outstanding reservations from authoritative records before enabling dispatch; a missing ledger cannot imply zero spend. Calendar rollover cannot erase an unsettled charge. This extends ADR 0012's recovery bookkeeping with a budget horizon; ticket 38 specifies persistence and attribution without requiring the rehearsal journal to become an Incident database. A budget hold does not discard admitted Notifications or remove the obligation to reconcile uncertain external writes.

## Credential custody and preflight

Keep the upstream Anthropic API key outside the Run, behind a fifth fixed Forwarder endpoint with a per-Run sentinel. This replaces the earlier Anthropic credential exception. Ticket 36 specifies the additional listener, request policy, streaming, native client endpoint/trust configuration, credential substitution, usage visibility, revocation and direct-route prevention. Actual compatibility is unverified; do not silently restore direct credentials if mediation fails. Anthropic readiness becomes mandatory for model Run admission. An already-dispatched request can still finish and incur cost after revocation/cancellation.

Before enabling paid Runs, verify current account rates, billing visibility and lag, available provider limits, supported client budget-guard behavior, and the mediated client path. A client estimate-based dollar guard is secondary; it does not establish a hard billing ceiling. If admission exposure cannot be controlled with defensible evidence, remain in labelled replay mode. These decisions authorize no purchase, API key creation, auth switch, paid Run or infrastructure provisioning.

## Model qualification and presentation

Choose the least expensive candidate that qualifies on comparable evidence. Require three complete representative Fault lifecycle samples using the intended API auth and venue, including initial Report, supported match/update and final resolution. Every Run must satisfy ADR 0012's 300-second total bound, every sample the accepted attempt/spend ceilings, and every evidence claim the citation rule. Report failures, retries and uncertain charges alongside successful samples; a retry cannot convert a failed sample into a clean pass. Qualification uses rehearsal allocations, and targeted guard checks/retries use diagnostics; there is no hidden qualification allowance. Multiple candidates can require multiple budget weeks.

One qualifying candidate does not prove a globally cheapest model. Historical short/confounded arms and a cheaper arm with fabricated controls do not qualify one. Until representative measurements and enforcement checks pass, use a clearly labelled replay fallback and report cost estimates as estimates. A live presentation contains one Fault lifecycle; the budget does not establish stage timing or a guaranteed Run count from historical Notification filtering.

## Evidence and remaining work

Historical facts refute $4.74 as the total billed cost of five attempts and refute independent per-model balances as an established fact. Official billing sources distinguish API billing, subscription limits and client cancellation. Current prices/account balances, guard enforcement, model qualification and deployment acceptance remain unverified.

Ticket 38 owns the accounting/qualification specification and acceptance plan. Tickets 36/37 consume credential and admission requirements. Ticket 23's historical measurement commands are not current execution authorization and must be redesigned against this auth, budget and safety contract before any future probe. No runtime or Skill implementation is part of this decision.

ADR 0014 specifies the three-sample mix (two primary, one fallback, with cold/Memory conditions), human adjudication and private audit evidence required for qualification. It does not add a spend allowance or authorize paid samples.
