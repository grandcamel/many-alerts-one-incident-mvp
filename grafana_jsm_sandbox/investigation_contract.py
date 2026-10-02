"""What `grafana-query`, `incident-payload investigate` and `verify --mvp` agree on.

A Run that creates an Incident may query Grafana with `grafana-query`, which appends
one record per query to an evidence file in the Run's working directory. The Run
then posts one investigation comment, built by `incident-payload investigate` from
that file and starting with a fixed marker. Lifecycle accounting (the Runs a closing
comment counts, and what `verify --mvp` reads as the opening, update and closing
comments) leaves marked comments out. The marker is a convention of this demo, not a
proof of who wrote a comment.

Pure: no imports from the Receiver, the query CLI, the payload builder or the
verifier, so each of them can import it.
"""

from __future__ import annotations

EVIDENCE_FILENAME = "grafana-evidence.jsonl"
"""The evidence file `grafana-query` appends to, in the Run's working directory."""

EVIDENCE_SCHEMA_VERSION = 1
"""The `schema_version` of every record in the evidence file."""

INVESTIGATION_MARKER = "[grafana-investigation] "
"""How every investigation comment's body begins: case-sensitive, trailing space included."""


def is_investigation(text: str) -> bool:
    """Whether a comment body is an investigation comment, not a lifecycle one."""
    return text.startswith(INVESTIGATION_MARKER)
