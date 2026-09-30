# One Incident per Fault, and the Match is the Run's judgment

Status: accepted, 2026-09-15, while charting the many-alerts-one-incident map. Partially supersedes ADR 0004.

Chapter one keyed Incidents by one Alert's Fingerprint, so one Alert was one Incident and the Match was an exact label lookup (ADR 0004). This effort's demo is the opposite motion: many Alerts from one Fault become the one Incident a responder acts on, with a suggested root cause. We decided that an Incident represents one Fault's lifetime and carries the Fingerprint of every Alert it explains, and that the Match is a judgment the Run makes against the open Incidents rather than a lookup. The alternative, one Incident per Alert as before plus one Problem linking them, keeps ADR 0004 intact but puts a whole Cascade of Incidents in the queue, which is the alert fatigue the demo argues against, and moves the reduction out of the model, which is the demo's claim.

## Consequences

- A Run can be wrong: an Alert filed under the wrong Incident, or a second Incident opened for a Fault that already has one. The accepted mechanics are in Many-to-one under a Cascade: time-bounded candidate admission, evidence-based judgment, and human-owned correction. The Run flags suspected wrong Matches or duplicates; it does not silently reassign members or merge Incidents.
- An Incident now spans several Runs. Its Report grows as later Alerts of the same Cascade land; the first Run's Report is a partial one by design.
- The Fingerprint label stays, one per Alert explained, so that an Incident can still be found from any of its Alerts and chapter one's search-by-label keeps working on the Alerts it covers.
- Problem stays reserved for recurrence, as chapter one left it.


## Mechanics settled by ticket 14

Both grilling rounds are accepted. The Answer is the detailed contract: ten-minute repeats, ten-second group timers, value-aware exact-repeat suppression, one pending coalesced input, and latest-arrival state per Fingerprint. A Notification remains one POST; a Run may handle Alerts from several Notifications.

Open Incidents qualify for either lookup path only within the agreed thirty-minute created-time window. Candidates are judged from their Reports; ambiguous evidence favors a separate Incident over an unsupported merge. Reports grow by appended evidence and explicit corrections, preserving earlier claims. Severity ratchets with Urgency over accepted members; human-owned correction is explicit. Normal completion requires every accepted member to be Resolved and no pending correction. Forced completion requires explicit human authorization and names unresolved members.

This is a planning decision, not runtime acceptance. Current Skill instructions must be revised by the implementation spec. Live OPS field editability, matched-Run timing, timeout policy and Report rendering retain the boundaries recorded in ticket 14.
