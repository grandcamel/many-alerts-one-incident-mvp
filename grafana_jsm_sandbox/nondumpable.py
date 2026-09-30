"""Closing a process's `/proc/<pid>` to the Runs, with nothing imported but the C library.

The real Jira token is in the initial environment of every process that starts
with the container's environment: the Receiver, and whatever `docker compose exec`
starts beside it. Until such a process makes itself non-dumpable, a Run, which is
the same uid, can read that environment back out of `/proc/<pid>/environ`
(ADR 0002's amendment). This module imports nothing of the package, so a command
can close itself before its own imports run and the window stays as short as
the interpreter's start-up.
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Callable

PR_SET_DUMPABLE = 4
"""The `prctl` option for a process's dumpable flag, from `<linux/prctl.h>`."""


def refuse_to_be_read(
    platform: str | None = None, prctl: Callable[[int, int], int] | None = None
) -> bool:
    """Make this process non-dumpable on Linux, so no Run can read its environment.

    A non-dumpable process's `/proc/<pid>` files belong to root, and a process of
    the same uid holding no capability, which is what a Run is in the container,
    can neither read them nor ptrace it. A Run's own `/proc` stays readable to it:
    exec makes a child dumpable again, and a Run holds only its sentinel.

    Returns whether it did. Elsewhere, a Mac in laptop mode, there is no `/proc` to
    close and this does nothing. `platform` and `prctl` are there for the tests.
    """
    platform = sys.platform if platform is None else platform
    if not platform.startswith("linux"):
        return False
    prctl = _libc_prctl() if prctl is None else prctl
    if prctl(PR_SET_DUMPABLE, 0) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"prctl(PR_SET_DUMPABLE, 0) failed: {os.strerror(errno)}")
    return True


def _libc_prctl() -> Callable[[int, int], int]:
    """The C library's `prctl`, taking the two arguments the dumpable flag needs."""
    libc = ctypes.CDLL(None, use_errno=True)
    # The kernel reads the four arguments after the option as unsigned longs, and
    # ctypes would otherwise pass them to the variadic prctl as ints.
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    return lambda option, value: libc.prctl(option, value, 0, 0, 0)
