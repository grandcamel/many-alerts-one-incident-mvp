# Local mediated-client TLS fixture

This package is an offline, synthetic transport experiment.  It runs two fixed
TLS loopback listeners: a test client calls the mediator, and the mediator calls
its own fixed synthetic upstream.  It contains no production Forwarder, Receiver,
Run, native Claude client, provider credential, external destination, or control
channel.

`MediatedClientHarness` permits only `POST /v1/messages` with the exact
`FIXTURE_REQUEST` bytes and buffers only the exact SSE-shaped `FIXTURE_RESPONSE`.
A trusted test controller registers an opaque token for
one bounded lease, activates it, and may revoke it.  The HTTP surface has no
registration, reactivation, revocation, upstream destination, credential, or
handler interface.  Expired/revoked/inactive/non-Anthropic leases and malformed,
oversized, noncanonical, or non-fixture requests are denied before upstream
request bytes are sent.

`IncrementalStreamHarness` is a separate subclass for one fixed synthetic stream.
It uses the same fixed request, two TLS loopback hops, lease, request cap, nonce
correlation, and absolute deadline as the buffered harness. Its only successful
body is `STREAM_FIXTURE_DELTA` followed by `STREAM_FIXTURE_TERMINAL`; the latter
is deliberately withheld by the synthetic upstream until the trusted test
controller calls `release_final_frame()`. `wait_for_first_frame_forwarded()` says
only that the mediator completed its local first-frame write. An independent test
client must decode and acknowledge the exact first frame before releasing the
terminal; this is fixture test ordering, not a production client-ack protocol.
Both controller events are per-harness, one-way latches: release stays released
for later requests, and any partial-stream failure sets the abort latch for
the whole harness. After abort, new requests are denied locally as
`stream_aborted`; a new harness is required for another stream experiment.

The streaming decoder accepts only finite fixture events: a UTF-8 `data: ` JSON
frame ending in `\n\n`, strictly increasing positive sequence, known fields and
kinds, and one `fixture_complete` terminal. It rejects duplicate JSON keys,
non-finite/out-of-range numbers, unpaired surrogates, unknown/deep/oversize
frames, more than eight events, missing/conflicting/duplicate terminals, and any
trailing data. Its fixed fault modes are `split_utf8`, `malformed_utf8`,
`duplicate_key`, `unknown_kind`, `nonfinite`, `oversize`, `deep`, `event_limit`,
`missing_terminal`, `duplicate_terminal`, `conflicting_terminal`, `trailing`,
`trailing_after_length`, `truncate`, `disconnect`, `timeout`, `surrogate`,
`out_of_order`, and `total_oversize`; no caller supplies event bytes, a callback,
destination, or schema. It bounds raw stream bytes to 16 KiB, a frame to 2 KiB,
nesting to eight, and metadata history to the existing 128-request fixture limit.

The stream accepts finite Content-Length framing only. It validates every full
frame before a downstream write and does not retain the stream to simulate an
incremental result. It holds the terminal until the declared body has been parsed
and an explicit read beyond declared length returns EOF, so a terminal cannot be
followed by a hidden duplicate or trailer. A failure before downstream headers
uses the bounded local gateway response; after headers or a frame write, it closes
the response and records partial/unknown delivery without manufacturing a second
response or terminal success. `StreamReceipt` retains counts, a digest, terminal
and transport observations, and the conservative `bytes_may_have_crossed` flag;
its digest covers raw bytes observed from the synthetic upstream, never a client
acknowledgement. It retains no stream body, token, key, or caller credential.
`transport_complete` means verified upstream EOF plus completed local downstream
writes before the deadline. It does not attest remote application consumption;
the independent test client records its own decode acknowledgement separately.

The mediator rebuilds its upstream headers from fixed framing, Content-Type, and
a synthetic API key.  It never forwards caller credentials, host, proxy, hop, or
connection-named headers.  Both hops use TLS 1.2 or later, CA verification, and
hostname checking. In the buffered harness, upstream redirects, incomplete or
oversized responses, TLS errors, disconnects, and timeouts produce a bounded local gateway failure with no
Location, partial response, automatic retry, fallback, or renewal. The buffered
harness (`MediatedClientHarness`) response is SSE-shaped fixture data; neither
harness is native-client compatibility evidence.

Receipts retain only metadata and body digests.  They contain no token, key,
Authorization value, request body, or response body.  A lease check and its one
bounded upstream send share a lock: `revoke()` waits for an in-flight send to
finish and then prevents later dispatch.  It cannot cancel or undo that in-flight
synthetic request.  This is local thread synchronization, not proof of a
Receiver-only OS-protected control plane, sidecar isolation, native admission,
provider billing, tenant authority, or deployment qualification.

For the incremental subclass, the lock is released while it waits for the next
upstream frame or controller barrier. It is retaken for each bounded downstream
frame send and lease check. Therefore a completed `revoke()` prevents a later
frame from beginning dispatch, while a frame whose write already began may have
arrived. Detected downstream disconnect wakes the stalled barrier and closes the
upstream path; an undetected peer closure remains bounded by the connection
deadline. Neither behavior proves cancellation, rollback, or billing outcome.

Each mediated dispatch also carries a one-time internal correlation nonce. The
synthetic upstream records a request only when the nonce and its sequence match a
pending mediator dispatch, then consumes that pair. The nonce and internal header
values never appear in a receipt. This prevents fixture-local receipt forgery; it
does not establish an OS or authenticated control boundary.

The configured timeout bounds one upstream hop. Each accepted TLS connection has
an absolute `2 * timeout + 0.2` second deadline, beginning at accept and enforced
by closing the socket; its TLS handshake uses the configured timeout. That leaves
bounded time for the mediator to return a local gateway failure after an upstream
timeout while still rejecting slow-drip handshakes, headers, and bodies. Per-socket
timeouts bound individual blocking operations; the absolute connection deadline
also bounds their aggregate duration and the mediated outbound connect/send/read.
