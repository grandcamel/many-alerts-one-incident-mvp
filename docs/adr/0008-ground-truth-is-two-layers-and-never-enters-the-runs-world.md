# The Ground truth is two layers, and it never enters the Run's world

Status: accepted, 2026-09-16, resolving the map ticket "Faults and their Cascades".

The Ground truth rule says every Fault has a documented true cause, and the Citation rule says every claim in a Report's root-cause section cites evidence the Run retrieved. Making a Fault's cause citable — the work of "The Change" — puts those two rules on a collision course: if the Change record carries the feature flag's name and the Ground truth *is* the flag's name, a Run that retrieves the Change and copies the name scores a perfect Suggested root cause without having diagnosed anything. We decided that a Ground truth is written in two layers — the **Mechanism**, what actually breaks stated in system terms, and the **Trigger**, the flag and variant that injected it — that scoring judges the Suggested root cause against the Mechanism alone, and that the Ground truth lives only in this repository: never in the cluster, never in Grafana, never in an OPS Incident, never in the Confluence space, and never in the Memory directory.

## Considered options

- **Ground truth as the Trigger alone** ("`adFailure` was set to `on`"). Simplest to write and to score by string match, and it is what a naive reading of the Ground truth rule suggests. Rejected: it makes the Change a cheat sheet and turns scoring into a test of retrieval rather than of diagnosis.
- **Drop the Change, and soften the Ground truth rule** to "names the failing component" so a Run reasons from symptoms alone. Rejected: it abandons the Citation rule for the one claim that matters most, and a Run that cannot cite its cause is exactly the Haiku 4.5 failure mode measured in "Does a high-effort Run fit the slot", where it asserted two services healthy it had never queried.
- **Ground truth in the cluster, alongside the Fault.** Convenient for a scoring harness that already talks to the cluster. Rejected: it is the leak this ADR exists to prevent.

## Consequences

- The Memory directory is the live risk, not Jira or Confluence. A Run that once saw a Ground truth could write it to Memory, and every later Run's score would be contaminated with no visible symptom. The map ticket "Memory" must treat this as a constraint on what a Run is allowed to record, and "Scoring a Report against ground truth" must assume Memory is untrusted.
- The Change may name the Trigger freely. Because scoring ignores the Trigger, a Run retrieving a flag flip from a Change record is citing evidence, not copying an answer — which is what the Citation rule wanted all along.
- Every Fault added to the menu costs a Mechanism sentence written in system terms and naming no flag. A Mechanism that mentions the Trigger is a defect, and a reviewer can check it by reading one sentence.
- Scoring is no longer a string match. Judging a Suggested root cause against a Mechanism takes a judgment, which is the problem "Scoring a Report against ground truth" now inherits.
