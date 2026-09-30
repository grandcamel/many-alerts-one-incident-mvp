# Supervised synthetic streaming

`streaming_rehearsal.run_supervised_streaming` joins a fixed Python child to the
existing two-hop loopback TLS streaming fixture. The child decodes the first
fixed UTF-8 frame and writes a typed acknowledgement to stdout. The supervisor
retains that line and checks the attempt, lease, bootstrap and first-frame
digest against its own observations before releasing the terminal frame.

The child separately records bytes received, decoding, terminal and transport
EOF. Parent receipts describe validated bytes and local writes; they do not
stand in for child receipt. The base process evidence records exit, cancellation,
capture, reaping and pipe EOF independently. Completion requires agreement among
these observations. A child-reported successful terminal cannot override a
nonzero process exit or incomplete capture.

The launcher admits only named `stream_*` scenarios and snapshots a standalone
stdlib worker within the unchanged 64 KiB cap. A bounded private bootstrap file
contains the fixed loopback endpoint, fixture CA, one-use synthetic token and
attempt identity. No executable, endpoint, code, credential, extra argument or
environment can be supplied through the public interface. The bootstrap and
temporary TLS material are removed during cleanup. This cooperative fixture
does not establish isolation from a hostile process running as the same user.

Revocation intent precedes process interruption. Selector-loop revocation polls
do not wait for a network-write lock; terminal release also checks sampled
cancellation and the original work deadline. TLS setup precedes supervised
execution. Bounded transport cleanup follows process containment and records
its own timing. Evidence publication and read-back follow that cleanup. The
process duration therefore remains a supervision measurement, not the complete
launch-to-durable-closeout duration.

The immutable bounded `stream-supervisor.json` sidecar links the existing v2
process manifest and retained stdout by digest. Read-back validates actual
child records, control chronology and parent receipts. Missing or inconsistent
evidence holds the integration or raises `EvidenceUnavailable`; failed closeout
preserves the actual `ProcessResult` on the exception. A held result explains
its gaps. Hash linkage is structural integrity, not authenticated audit custody.

The budgeted wrapper reserves and claims one synthetic attempt before launch.
It never retries or settles a reservation automatically. Every summary keeps
`billing_actual` unknown, `qualification` as `NOT_ASSESSED`, and native launch
`CLOSED`, including complete fixture runs.

Tests cover completion, truncation, duplicate terminal, withholding, cancellation,
nonzero child exit, malformed or missing receipts, duplicate acknowledgement,
capture loss, and invalid evidence. Run from the repository root:

```sh
pytest -q tests/test_supervised_streaming.py
```

This is real local process and TLS evidence for a fixed synthetic fixture.
Installed-client compatibility, provider operations, direct-route prevention,
adversarial OS confinement, actual billing, intended venue acceptance and human
Report adjudication remain separate gates. No C2 implementation is invoked.
