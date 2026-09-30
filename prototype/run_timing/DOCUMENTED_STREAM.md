# Documented stream normalizer

`documented_stream.py` is an offline, bounded parser for the fixed documented
subset described in the source map.
Its `SOURCE_PROFILE` pins the consulted Python Agent SDK source revision
`f7547d7233527739ece8b12ed28c57be96c966b5`; that pin is documentation evidence,
not a claim that an installed CLI has that revision or schema.
It accepts receiver-supplied JSON bytes one object at a time and returns immutable
metadata records plus an immutable process-aware outcome.

The accepted families are `system/init`, complete `assistant`, `user`, and a
single final `result`.  It captures only byte digests, counts, bounded identities,
tool IDs, session ID, assistant models, and a Decimal reported estimate.  Text,
tool input and result content, arbitrary optional metadata, and raw payloads are
never retained.  Strict UTF-8, duplicate-key rejection, finite-number parsing,
object-depth limits and line/event/total-byte limits apply to the whole JSON
object, including ignored keys. Known consumed fields also receive explicit type
checks, including exact boolean/integer checks where required.

Unknown event/content families, subagent output, partial streams, fallback
wrappers, malformed values, ordering mistakes, identity disagreements, unresolved
tool proposals, and diagnostic fields create sticky holds.  `result` is the only
terminal message; records after it are rejected.  A rejected record is evidence of
submitted bytes, not an authenticated event origin.

`StreamRecord.accepted` says that the submitted event structurally normalized in
this documented subset.  An accepted record can still carry a semantic hold, such
as a requested-model mismatch or a reported diagnostic.  Those holds remain in the
record and outcome reasons and always keep further dispatch at `hold`.

`outcome(ProcessObservation(...))` keeps process facts separate from reported
stream facts.  Containment, spawn, timeout, cancellation, incomplete, failure, and
`stream_consistent` status are ordered conservatively.  `stream_consistent` means
only offline internal consistency.  It never means a native Claude completion,
model identity qualification, authenticated tool effect, accepted experiment, or
provider billing.  `actual_model` and `provider_actual_usd` remain `None`, native
qualification is always `NOT_ASSESSED`, and further dispatch is always `hold`.
