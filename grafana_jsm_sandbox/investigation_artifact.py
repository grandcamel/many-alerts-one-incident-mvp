"""Publish one completed investigation comment in its Run's working directory.

The content-derived name preserves previously emitted commands. The Run retains
its existing filesystem authority; a hash name is provenance, not immutability.
This module opens no socket, starts no process and reads no environment variable.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path

MAX_BODY_BYTES = 256 * 1024
"""Local artifact bound, not a guarantee that Jira accepts a body of this size."""


class ArtifactError(ValueError):
    """The completed comment cannot be published safely."""


def _reuse_existing(path: Path, body: bytes) -> None:
    """Reuse only an identical private regular file; never follow a symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        existing = os.fstat(stream.fileno())
        if (not stat.S_ISREG(existing.st_mode) or stat.S_IMODE(existing.st_mode) != 0o600
                or existing.st_size != len(body) or stream.read(len(body) + 1) != body):
            raise ArtifactError("investigation comment artifact destination is unsafe or conflicting")


def publish_comment(body: bytes, directory: Path) -> str:
    """Atomically publish private bytes and return a safe basename, or refuse."""
    if len(body) > MAX_BODY_BYTES:
        raise ArtifactError("investigation comment exceeds the 256 KiB local artifact limit")
    name = f"grafana-investigation-{hashlib.sha256(body).hexdigest()}.adf.json"
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".grafana-investigation-", dir=directory)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, directory / name)
        except FileExistsError:
            _reuse_existing(directory / name, body)
        return name
    except OSError:
        raise ArtifactError("investigation comment artifact could not be written") from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                raise ArtifactError("investigation comment temporary artifact cleanup failed") from None
