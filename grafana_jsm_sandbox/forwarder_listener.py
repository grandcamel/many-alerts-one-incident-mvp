"""Private filesystem-backed Unix listener for Forwarder control.

This module establishes only the local socket filesystem boundary.  Accepting a
connection is deliberately separate from authenticating it or admitting a Run.
"""

from __future__ import annotations

import math
import os
import secrets
import socket
import stat
import threading
from dataclasses import dataclass

_CHILD_PREFIX = "fc-"
_SOCKET_NAME = "control.sock"
_MAX_ENDPOINT_BYTES = 100


class ListenerError(ValueError):
    """A fixed, non-diagnostic listener rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ListenerCloseout:
    state: str
    reason: str


class PrivateControlListener:
    """Own one short-lived private control socket below an operator parent."""

    def __init__(self, parent: str | os.PathLike[str], *, owner_uid: int, control_gid: int):
        try:
            self._parent = os.fspath(parent)
        except TypeError:
            raise ListenerError("invalid_parent") from None
        if (not isinstance(self._parent, str) or not os.path.isabs(self._parent)
                or self._parent.startswith("//")
                or self._parent != os.path.normpath(self._parent)):
            raise ListenerError("invalid_parent")
        if type(owner_uid) is not int or type(control_gid) is not int:
            raise ListenerError("invalid_identity")
        if owner_uid < 0 or control_gid < 0 or owner_uid >= 2**32 - 1 or control_gid >= 2**32 - 1:
            raise ListenerError("invalid_identity")
        self._owner_uid = owner_uid
        self._control_gid = control_gid
        self._parent_fd: int | None = None
        self._child_fd: int | None = None
        self._listener: socket.socket | None = None
        self._child_name: str | None = None
        self._endpoint: str | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._child_identity: tuple[int, int] | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._closed = False
        self._opened = False
        self._closeout: ListenerCloseout | None = None
        self._lifecycle_lock = threading.RLock()

    @property
    def endpoint(self) -> str:
        with self._lifecycle_lock:
            if not self._opened or self._closed or self._endpoint is None:
                raise ListenerError("not_open")
            return self._endpoint

    def open(self) -> PrivateControlListener:
        """Create, prepare and publish a fresh private child and socket."""
        with self._lifecycle_lock:
            return self._open()

    def _open(self) -> PrivateControlListener:
        if self._opened or self._closed:
            raise ListenerError("listener_closed")
        self._closed = True  # failures are terminal too: a listener never retries a pathname.
        if self._owner_uid != os.geteuid():
            raise ListenerError("parent_identity")
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            self._parent_fd = os.open(self._parent, flags)
            self._parent_identity = self._identity(os.fstat(self._parent_fd))
            self._verify_parent()
            self._create_child()
            self._create_socket()
            self._verify_all(0o2700)
            os.fchmod(self._child_fd, 0o2710)
            self._verify_all(0o2710)
            self._opened = True
            self._closed = False
            return self
        except ListenerError:
            self._cleanup_creation()
            raise
        except (OSError, ValueError):
            self._cleanup_creation()
            raise ListenerError("listener_open_failed") from None

    def verify(self) -> None:
        with self._lifecycle_lock:
            self._verify()

    def _verify(self) -> None:
        if not self._opened or self._closed:
            raise ListenerError("not_open")
        try:
            self._verify_all(0o2710)
        except ListenerError:
            raise
        except (OSError, ValueError):
            raise ListenerError("listener_identity") from None

    def accept(self, *, timeout: float = 0.1) -> socket.socket | None:
        """Accept one connection with one accept caller at a time.

        Open, close and filesystem guards are lifecycle-serialized; close may
        interrupt a pending accept. Before handoff this checks that close did
        not win. The caller owns accepted-connection shutdown after handoff.
        """
        seconds = self._timeout(timeout)
        accepted: socket.socket | None = None
        previous_timeout: float | None = None
        timeout_changed = False
        listener: socket.socket | None = None
        try:
            with self._lifecycle_lock:
                listener = self._listener
                if not self._opened or self._closed or listener is None:
                    raise ListenerError("not_open")
                self._verify_all(0o2710)
                previous_timeout = listener.gettimeout()
                listener.settimeout(seconds)
                timeout_changed = True
            try:
                accepted, _ = listener.accept()
            except TimeoutError:
                with self._lifecycle_lock:
                    if self._closed or self._listener is not listener:
                        raise ListenerError("listener_closed")
                    return None
            accepted.set_inheritable(False)
            with self._lifecycle_lock:
                if self._closed or self._listener is not listener:
                    raise ListenerError("listener_closed")
                self._verify_all(0o2710)
            return accepted
        except ListenerError:
            if accepted is not None:
                self._close_socket(accepted)
            raise
        except (OSError, ValueError):
            if accepted is not None:
                self._close_socket(accepted)
            raise ListenerError("accept_failed") from None
        finally:
            if timeout_changed and listener is not None:
                try:
                    with self._lifecycle_lock:
                        listener.settimeout(previous_timeout)
                except OSError:
                    pass

    def close(self) -> ListenerCloseout:
        """Close and remove only the exact resources this instance recorded."""
        with self._lifecycle_lock:
            return self._close()

    def _close(self) -> ListenerCloseout:
        if self._closeout is not None:
            return self._closeout
        if not self._opened:
            self._closed = True
            self._closeout = ListenerCloseout("not_open", "not_open")
            return self._closeout
        self._closed = True
        if self._listener is not None:
            try:
                self._listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._close_socket(self._listener)
            self._listener = None
        state, reason = self._remove_owned_resources()
        self._dispose_fds()
        self._closeout = ListenerCloseout(state, reason)
        return self._closeout

    def _create_child(self) -> None:
        assert self._parent_fd is not None
        for _ in range(16):
            name = _CHILD_PREFIX + secrets.token_hex(8)
            try:
                os.mkdir(name, 0o700, dir_fd=self._parent_fd)
            except FileExistsError:
                continue
            self._child_name = name
            self._child_identity = self._identity(
                os.stat(name, dir_fd=self._parent_fd, follow_symlinks=False)
            )
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            self._child_fd = os.open(name, flags, dir_fd=self._parent_fd)
            os.fchown(self._child_fd, self._owner_uid, self._control_gid)
            os.fchmod(self._child_fd, 0o2700)
            if self._identity(os.fstat(self._child_fd)) != self._child_identity:
                raise ListenerError("child_identity")
            self._verify_parent()
            self._verify_child(0o2700)
            return
        raise ListenerError("child_collision")

    def _create_socket(self) -> None:
        assert self._child_fd is not None and self._child_name is not None
        endpoint = os.path.join(self._parent, self._child_name, _SOCKET_NAME)
        if len(os.fsencode(endpoint)) > _MAX_ENDPOINT_BYTES:
            raise ListenerError("endpoint_too_long")
        try:
            os.stat(_SOCKET_NAME, dir_fd=self._child_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ListenerError("socket_exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.set_inheritable(False)
            listener.bind(endpoint)
            self._listener = listener
            self._endpoint = endpoint
            self._socket_identity = self._identity(
                os.stat(_SOCKET_NAME, dir_fd=self._child_fd, follow_symlinks=False)
            )
            os.chmod(_SOCKET_NAME, 0o660, dir_fd=self._child_fd, follow_symlinks=False)
            listener.listen(4)
            self._verify_socket()
        except Exception:
            self._close_socket(listener)
            if self._listener is listener:
                self._listener = None
            raise

    def _verify_all(self, child_mode: int) -> None:
        self._verify_parent()
        self._verify_child(child_mode)
        self._verify_socket()

    def _verify_parent(self) -> None:
        if self._parent_fd is None or self._parent_identity is None:
            raise ListenerError("parent_identity")
        descriptor = os.fstat(self._parent_fd)
        named = os.stat(self._parent, follow_symlinks=False)
        if (not stat.S_ISDIR(descriptor.st_mode) or self._identity(descriptor) != self._parent_identity
                or self._identity(named) != self._parent_identity
                or descriptor.st_uid != self._owner_uid or descriptor.st_gid != self._control_gid
                or stat.S_IMODE(descriptor.st_mode) != 0o710):
            raise ListenerError("parent_identity")

    def _verify_child(self, mode: int) -> None:
        if self._parent_fd is None or self._child_fd is None or self._child_name is None:
            raise ListenerError("child_identity")
        descriptor = os.fstat(self._child_fd)
        named = os.stat(self._child_name, dir_fd=self._parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(descriptor.st_mode) or self._identity(descriptor) != self._child_identity
                or self._identity(named) != self._child_identity
                or descriptor.st_uid != self._owner_uid or descriptor.st_gid != self._control_gid
                or stat.S_IMODE(descriptor.st_mode) != mode):
            raise ListenerError("child_identity")

    def _verify_socket(self) -> None:
        if self._child_fd is None or self._listener is None or self._socket_identity is None:
            raise ListenerError("socket_identity")
        named = os.stat(_SOCKET_NAME, dir_fd=self._child_fd, follow_symlinks=False)
        descriptor = os.fstat(self._listener.fileno())
        if (not stat.S_ISSOCK(named.st_mode) or self._identity(named) != self._socket_identity
                or not stat.S_ISSOCK(descriptor.st_mode)
                or self._listener.getsockname() != self._endpoint
                or named.st_uid != self._owner_uid or named.st_gid != self._control_gid
                or stat.S_IMODE(named.st_mode) != 0o660):
            raise ListenerError("socket_identity")

    def _remove_owned_resources(self) -> tuple[str, str]:
        try:
            self._verify_parent()
            self._verify_child(0o2710)
            assert self._child_fd is not None and self._parent_fd is not None and self._child_name is not None
            names = os.listdir(self._child_fd)
            if names != [_SOCKET_NAME]:
                return "unknown", "child_not_empty"
            self._verify_socket_path()
            os.unlink(_SOCKET_NAME, dir_fd=self._child_fd)
            os.rmdir(self._child_name, dir_fd=self._parent_fd)
            return "removed", "removed"
        except ListenerError as error:
            return "unknown", error.code
        except (OSError, ValueError):
            return "unknown", "cleanup_unknown"

    def _verify_socket_path(self) -> None:
        if self._child_fd is None or self._socket_identity is None:
            raise ListenerError("socket_identity")
        named = os.stat(_SOCKET_NAME, dir_fd=self._child_fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or self._identity(named) != self._socket_identity
                or named.st_uid != self._owner_uid or named.st_gid != self._control_gid
                or stat.S_IMODE(named.st_mode) != 0o660):
            raise ListenerError("socket_identity")

    def _cleanup_creation(self) -> None:
        if self._listener is not None:
            self._close_socket(self._listener)
            self._listener = None
        if self._parent_fd is not None and self._child_name is not None:
            try:
                self._verify_parent()
                if self._child_fd is None:
                    self._verify_recorded_child((0o700,))
                    os.rmdir(self._child_name, dir_fd=self._parent_fd)
                else:
                    self._verify_recorded_child((0o700, 0o2700, 0o2710))
                    names = os.listdir(self._child_fd)
                    if names == [_SOCKET_NAME]:
                        self._verify_recorded_socket_identity()
                        os.unlink(_SOCKET_NAME, dir_fd=self._child_fd)
                        names = []
                    if not names:
                        os.rmdir(self._child_name, dir_fd=self._parent_fd)
            except (ListenerError, OSError, ValueError):
                pass
        self._dispose_fds()

    def _verify_recorded_child(self, modes: tuple[int, ...]) -> None:
        if self._parent_fd is None or self._child_name is None or self._child_identity is None:
            raise ListenerError("child_identity")
        named = os.stat(self._child_name, dir_fd=self._parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or self._identity(named) != self._child_identity
                or stat.S_IMODE(named.st_mode) not in modes):
            raise ListenerError("child_identity")

    def _verify_recorded_socket_identity(self) -> None:
        if self._child_fd is None or self._socket_identity is None:
            raise ListenerError("socket_identity")
        named = os.stat(_SOCKET_NAME, dir_fd=self._child_fd, follow_symlinks=False)
        if not stat.S_ISSOCK(named.st_mode) or self._identity(named) != self._socket_identity:
            raise ListenerError("socket_identity")

    def _dispose_fds(self) -> None:
        for attribute in ("_child_fd", "_parent_fd"):
            descriptor = getattr(self, attribute)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, attribute, None)

    @staticmethod
    def _identity(status: os.stat_result) -> tuple[int, int]:
        return status.st_dev, status.st_ino

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        try:
            sock.close()
        except OSError:
            pass

    @staticmethod
    def _timeout(timeout: object) -> float:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ListenerError("invalid_timeout")
        try:
            seconds = float(timeout)
        except OverflowError:
            raise ListenerError("invalid_timeout") from None
        if not math.isfinite(seconds) or not 0 < seconds <= 1:
            raise ListenerError("invalid_timeout")
        return seconds
