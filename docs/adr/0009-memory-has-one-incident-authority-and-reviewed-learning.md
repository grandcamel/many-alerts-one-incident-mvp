# Memory has one Incident authority and reviewed learning

Status: accepted, 2026-09-18. Resolves ticket 13 after two approved policy rounds and the approved fresh-rehearsal preflight rule.

Memory must help later Runs without turning an earlier hypothesis into authoritative Incident state. OPS therefore owns Incident and current member state; Confluence supplies reviewed reference knowledge; the Memory directory carries cited observations and retrieval hints. We accept persistence and learning, with provenance and human review, instead of a second Incident database or automatic promotion of a Run's diagnosis into a runbook.

## Store responsibilities and lifecycle

- OPS retains authoritative membership, current per-Fingerprint state, lifecycle and Reports. Ticket 14's eligibility, ambiguity, correction and completion rules continue to apply; Memory cannot expand eligibility or establish a Match by itself. The physical representation of member state remains to be specified.
- Confluence starts with a human-reviewed service/dependency catalog and diagnostic runbooks. Do not seed postmortems describing planned demo Faults. Approved reference material may carry forward between rehearsals.
- After confirmed normal completion, a Run creates or updates one draft postmortem for the Incident, linked to the Report. Identify it by the OPS Incident and retain its link in OPS. Use version checks; reconcile an uncertain create before retrying. Normal completion means all accepted members are Resolved, not that the Suggested root cause is proven. Human-forced completion does not qualify for this automatic draft step.
- A human reviews a draft before it becomes reusable curated guidance. Reopening or a pending correction blocks promotion pending review. A Run does not silently rewrite published guidance; later changes become reviewable amendments. Drafts are not approved reference knowledge.
- The Memory directory records observations, hypotheses and retrieval hints with source references, observation time/source version, and Run, Incident and rehearsal identity. It is not a second authority for Incident state. Corrections explicitly supersede or retract entries without erasing history; superseded or unverifiable claims cannot be used as current facts.

## Run sequence and partial failure

Before Match, retrieve fresh OPS candidates/member state under ticket 14's rules and relevant approved Confluence references and directory observations. Scope retrieval to affected services/dependencies and the current rehearsal, and verify cited sources before relying on claims. Append learning only after confirmed OPS writes, referencing the persisted Report; create/update the draft only after confirmed normal completion.

If authoritative OPS access fails, do not infer membership or completion from cached Memory or claim the operation succeeded. If Confluence or directory access fails, investigation may continue with available evidence and disclosed missing context; ticket 14's ambiguity rules still hold. A failed secondary write does not undo a confirmed OPS result. Report the incomplete Memory step separately. Ticket 21 retains refusal, timeout and retry mechanics, including recovery from partially completed work.

## Persistence and trust boundary

The operator starts a named rehearsal and explicitly resets its Memory directory. The directory survives Runs and container/pod restarts within that rehearsal; persistence after cluster destruction is not required. Old OPS/Confluence artifacts remain available to humans but stay outside a fresh rehearsal's Run context unless explicitly approved as reference material. Approval as reference material does not make an old Incident an eligible current Match. Isolation must preserve ticket 14's required labels and never silently delete external history.

A narrow structured append operation grants Runs the ability to record learning. This is an explicit planned extension of ADR 0003's tool authority and ADR 0005's tmpfs-only persistence boundary, not unrestricted shell/file Write. Entries remain untrusted data, never instructions. The dedicated writable path, storage lifetime and reset mechanism need an implementation specification; current runtime behavior is unchanged.

ADR 0008 remains binding: repository adjudication Ground truth never enters any Memory store. Legitimately inferred causes and retrieved Change records are allowed; a Trigger's name is not itself forbidden. Review and provenance do not make Memory trusted for scoring.

## Evidence and follow-on work

Offline source/CLI evidence confirms the current Run lacks Confluence/Memory write authority and persistent storage. Installed confluence-as 1.1.1 exposes native draft creation and versioned updates, but no live tenant draft, permissions, Forwarder passage or persistent-volume behavior was verified. Its HTTPS requirement remains an input to ticket 17, not a TLS decision here.

Follow-on tickets 32–34 specify Memory storage and acceptance, Confluence scope/permissions, and the audience view. Ticket 16 retains Report rendering; ticket 17 retains Forwarder topology. This ADR records the planning contract only; no runtime or Skill code was changed.

## Fresh-rehearsal preflight

A prior-rehearsal open OPS Incident can still satisfy ticket 14's thirty-minute candidate rules. Excluding it silently would change that accepted lookup contract. Fresh-rehearsal admission checks for prior-rehearsal Incidents still eligible under those rules and waits until they age out or a human explicitly disposes of them. Never automatically close or filter them. This is an operator preflight requirement, not a change to Match.

[ADR 0017](0017-confluence-references-and-drafts-have-separate-authority.md) specifies separate reference/draft namespaces, operator-owned approval and identity records, expected-version body binding and revocation recovery. Installed CLI draft support alone is not tenant acceptance or protection against a stale composed body.
