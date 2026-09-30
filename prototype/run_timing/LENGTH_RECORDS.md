# Inert length-case observation records

`LengthProbe.report()` returns a versioned, JSON-compatible snapshot of the existing
five-case in-memory probe. It does not execute the command strings, start processes,
contact Jira, inspect native client permissions or authorize a paid experiment. Every
report is `OFFLINE_LENGTH_RECORDS_ONLY`, with native launch `CLOSED`.

All five lengths stay in their frozen order. Each case records:

- Expected command byte count/digest; accepted request byte count/digest, tool-use ID and
  virtual time; observed command byte count/digest and virtual time. Edited observations
  remain distinguishable from the original request. No command body is exported.
- Locally issued receipt metadata and virtual dispatch time, including the synthetic stub
  exit. A nonzero stub exit remains a dispatch observation, not permission denial.
- Supplied-receipt status: absent, issued_here or unrecognized. The last category includes
  copied, foreign or forged receipt objects; their untrusted contents are not exported.
  Missing supplied evidence does not erase a locally issued receipt.
- Synthetic decision, optional opaque reference, coverage boolean and final classification.
  These labels/booleans are trusted fixture input, not verified native evidence locators.

Before a valid request is accepted, the case is `not_attempted`. An accepted request with
no classification is `pending`, including during cleanup or after external cancellation.
Invalid oversized/non-byte request input does not become an accepted case. Invalid
observation metadata holds the probe without advancing or erasing the pending request.
Observation command bytes are capped at 14,000; decision/reference strings at 200 characters;
synthetic stub exits must be signed 32-bit integers, excluding booleans. Existing tool-ID
and request-size limits continue to apply. Inputs must be synthetic and contain no secrets;
this metadata exporter is not a sanitizer.

The snapshot includes the existing bracket classification, probe hold/work status,
lifecycle cancellation/cleanup state and cleanup actions emitted by this probe. External
lifecycle actions are not invented as probe actions. All timestamps are virtual seconds,
not native wall-clock evidence. Caller changes to the snapshot cannot mutate probe state,
and subsequent probe activity cannot rewrite previously returned snapshots.

Only object identity inside the current trusted probe validates a receipt. Serialization
exports that observation; it does not export an authentication capability or permit receipt
re-import. Missing or conflicting receipt evidence remains `dispatch_unknown`; provider
refusal, model unavailability and fallback remain `not_length_evidence`, hold the probe and
preserve untouched cases. No denied case is retried and no fallback route is selected.

The bracket is still limited to this synthetic fixed shape. All-dispatched, all-denied,
nonmonotonic and incomplete series cannot become an exact or universal threshold.
Native command-boundary observation, authenticated supervisor receipt transport, actual
policy/model/version/auth context and the closed measurement card remain separate gates.
The report is neither a native audit record nor an independent semantic qualification.

Run tests with `python3 -m pytest -q tests/test_timing_length_records.py`.
