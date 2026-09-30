"""Private control listener filesystem and local-Unix-socket contract tests.

All identities are the current process's synthetic test identity.  These tests
do not claim deployment isolation between the Receiver, Forwarder, or Run.
"""

from __future__ import annotations

import os
import socket
import stat
import tempfile
import threading
import time
from pathlib import Path

import pytest

from grafana_jsm_sandbox import forwarder_listener
from grafana_jsm_sandbox.forwarder_listener import ListenerError, PrivateControlListener


@pytest.fixture
def runtime_parent():
    """A deliberately short, operator-provisioned 0710 parent directory."""
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="maoi-") as temporary:
        parent = Path(temporary).resolve()
        os.chown(parent, -1, os.getegid())
        os.chmod(parent, 0o710)
        assert len(os.fsencode(parent / ("fc-" + "f" * 16) / "control.sock")) <= 100
        yield parent


@pytest.fixture
def listener(runtime_parent):
    opened = PrivateControlListener(
        runtime_parent,
        owner_uid=os.geteuid(),
        control_gid=os.getegid(),
    ).open()
    try:
        yield opened
    finally:
        opened.close()


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def _assert_listener_error(call):
    with pytest.raises(ListenerError) as raised:
        call()
    assert isinstance(raised.value.code, str)
    assert raised.value.code
    assert str(raised.value) == raised.value.code
    return raised.value


class _ObservedSocket:
    """Delegate a listener socket while making its accept boundary observable."""

    def __init__(self, wrapped, *, entered=None):
        self._wrapped = wrapped
        self.accepted = None
        self._entered = entered

    def accept(self):
        if self._entered is not None:
            self._entered.set()
        self.accepted, address = self._wrapped.accept()
        return self.accepted, address

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def _new_listener(parent):
    return PrivateControlListener(parent, owner_uid=os.geteuid(), control_gid=os.getegid())


def test_open_verify_and_actual_unix_connect_accept(listener):
    endpoint = Path(listener.endpoint)
    child = endpoint.parent
    assert endpoint.is_socket()
    assert _mode(child) == 0o2710
    assert _mode(endpoint) == 0o660
    assert os.lstat(endpoint).st_uid == os.geteuid()
    assert os.lstat(endpoint).st_gid == os.getegid()
    assert listener.verify() is None

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(os.fspath(endpoint))
        accepted = listener.accept(timeout=0.5)
        assert accepted is not None
        try:
            assert accepted.family == socket.AF_UNIX
            assert accepted.get_inheritable() is False
        finally:
            accepted.close()


@pytest.mark.parametrize(
    "timeout",
    [0, -0.01, 1.01, 2**1000, True, float("nan"), float("inf"), -float("inf"), "not-a-number"],
)
def test_accept_rejects_non_finite_or_out_of_range_timeout(listener, timeout):
    _assert_listener_error(lambda: listener.accept(timeout=timeout))


def test_accept_is_bounded_and_returns_none_without_client(listener):
    before = time.monotonic()
    assert listener.accept(timeout=0.05) is None
    elapsed = time.monotonic() - before
    assert elapsed < 0.5


def test_bounded_accept_restores_prior_blocking_timeout(listener):
    listener._listener.settimeout(None)
    assert listener.accept(timeout=0.02) is None
    assert listener._listener.gettimeout() is None


def test_rejects_nonabsolute_symlink_insecure_or_too_long_parent(runtime_parent, tmp_path):
    relative = Path("relative-runtime")
    _assert_listener_error(
        lambda: PrivateControlListener(relative, owner_uid=os.geteuid(), control_gid=os.getegid()).open()
    )

    target = tmp_path / "target"
    target.mkdir(mode=0o710)
    os.chown(target, -1, os.getegid())
    os.chmod(target, 0o710)
    link = runtime_parent / "runtime-link"
    link.symlink_to(target, target_is_directory=True)
    _assert_listener_error(
        lambda: PrivateControlListener(link, owner_uid=os.geteuid(), control_gid=os.getegid()).open()
    )
    for spelling in (os.fspath(link) + "/", os.fspath(link) + "/."):
        _assert_listener_error(
            lambda spelling=spelling: PrivateControlListener(
                spelling, owner_uid=os.geteuid(), control_gid=os.getegid()
            ).open()
        )
    doubled_root = "//" + os.fspath(runtime_parent).lstrip("/")
    _assert_listener_error(
        lambda: PrivateControlListener(
            doubled_root, owner_uid=os.geteuid(), control_gid=os.getegid()
        ).open()
    )

    os.chmod(runtime_parent, 0o700)
    _assert_listener_error(
        lambda: PrivateControlListener(
            runtime_parent, owner_uid=os.geteuid(), control_gid=os.getegid()
        ).open()
    )

    not_a_directory = tmp_path / "not-a-directory"
    not_a_directory.write_text("not a directory", encoding="utf-8")
    _assert_listener_error(
        lambda: PrivateControlListener(
            not_a_directory, owner_uid=os.geteuid(), control_gid=os.getegid()
        ).open()
    )

    too_long = tmp_path / ("p" * 160)
    too_long.mkdir(mode=0o710)
    os.chown(too_long, -1, os.getegid())
    os.chmod(too_long, 0o710)
    assert len(os.fsencode(too_long / ("fc-" + "f" * 16) / "control.sock")) > 100
    _assert_listener_error(
        lambda: PrivateControlListener(
            too_long, owner_uid=os.geteuid(), control_gid=os.getegid()
        ).open()
    )


def test_rejects_configured_owner_or_group_that_does_not_match_parent(runtime_parent):
    _assert_listener_error(
        lambda: PrivateControlListener(
            runtime_parent, owner_uid=os.geteuid() + 1, control_gid=os.getegid()
        ).open()
    )
    _assert_listener_error(
        lambda: PrivateControlListener(
            runtime_parent, owner_uid=os.geteuid(), control_gid=os.getegid() + 1
        ).open()
    )


def test_open_does_not_change_parent_or_process_umask(runtime_parent, monkeypatch):
    before = os.stat(runtime_parent)
    original_umask = os.umask

    def unexpected_umask(*_args, **_kwargs):
        raise AssertionError("listener must not alter the process umask")

    monkeypatch.setattr(os, "umask", unexpected_umask)
    try:
        opened = PrivateControlListener(
            runtime_parent, owner_uid=os.geteuid(), control_gid=os.getegid()
        ).open()
    finally:
        monkeypatch.setattr(os, "umask", original_umask)
    try:
        after = os.stat(runtime_parent)
        assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
    finally:
        opened.close()


@pytest.mark.parametrize("target", ["parent", "child", "socket"])
def test_verify_detects_independent_parent_child_and_socket_mode_mutations(listener, target):
    endpoint = Path(listener.endpoint)
    path = {"parent": endpoint.parent.parent, "child": endpoint.parent, "socket": endpoint}[target]
    os.chmod(path, 0o700)
    _assert_listener_error(listener.verify)


def test_close_removes_owned_socket_and_child_and_is_idempotent(listener):
    endpoint = Path(listener.endpoint)
    child = endpoint.parent
    first = listener.close()
    assert first.state == "removed"
    assert not endpoint.exists()
    assert not child.exists()
    second = listener.close()
    assert second == first
    _assert_listener_error(listener.open)
    _assert_listener_error(lambda: listener.accept(timeout=0.1))
    _assert_listener_error(listener.verify)


def test_close_preserves_replaced_socket_and_reports_unknown(listener):
    endpoint = Path(listener.endpoint)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(endpoint)
        replacement.bind(os.fspath(endpoint))
        replacement.listen(1)
        closeout = listener.close()
        assert closeout.state == "unknown"
        assert endpoint.is_socket()
        assert endpoint.parent.exists()
    finally:
        replacement.close()
        if endpoint.exists():
            os.unlink(endpoint)
        if endpoint.parent.exists():
            os.rmdir(endpoint.parent)
    assert listener.close() == closeout


def test_close_preserves_unexpected_child_entry_and_reports_unknown(listener):
    endpoint = Path(listener.endpoint)
    extra = endpoint.parent / "keep-me"
    extra.write_text("unrelated", encoding="utf-8")
    closeout = listener.close()
    assert closeout.state == "unknown"
    assert extra.read_text(encoding="utf-8") == "unrelated"
    assert endpoint.parent.exists()
    if endpoint.exists():
        os.unlink(endpoint)
    os.unlink(extra)
    os.rmdir(endpoint.parent)
    assert listener.close() == closeout


def test_close_preserves_replaced_child_directory_and_reports_unknown(listener):
    endpoint = Path(listener.endpoint)
    child = endpoint.parent
    moved = child.with_name(child.name + "-moved")
    os.rename(child, moved)
    child.mkdir(mode=0o700)
    preserved = child / "keep-me"
    preserved.write_text("replacement", encoding="utf-8")
    closeout = listener.close()
    assert closeout.state == "unknown"
    assert preserved.read_text(encoding="utf-8") == "replacement"
    os.unlink(preserved)
    os.rmdir(child)
    os.unlink(moved / endpoint.name)
    os.rmdir(moved)
    assert listener.close() == closeout


def test_verify_detects_socket_replacement_and_never_accepts_it(listener):
    endpoint = Path(listener.endpoint)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(endpoint)
        replacement.bind(os.fspath(endpoint))
        replacement.listen(1)
        _assert_listener_error(listener.verify)
        _assert_listener_error(lambda: listener.accept(timeout=0.1))
    finally:
        replacement.close()
        if endpoint.exists():
            os.unlink(endpoint)
        if endpoint.parent.exists():
            os.rmdir(endpoint.parent)


def test_close_interrupts_pending_accept_without_leaking_a_thread(listener, monkeypatch):
    entered = threading.Event()
    wrapped = _ObservedSocket(listener._listener, entered=entered)
    monkeypatch.setattr(listener, "_listener", wrapped)
    result = []

    def accept_once():
        try:
            result.append(listener.accept(timeout=1))
        except ListenerError as error:
            result.append(error)

    worker = threading.Thread(target=accept_once)
    worker.start()
    assert entered.wait(1)
    assert listener.close().state == "removed"
    worker.join(1)
    assert not worker.is_alive()
    assert len(result) == 1
    assert isinstance(result[0], ListenerError)


def test_postaccept_guard_failure_closes_the_accepted_descriptor(listener, monkeypatch):
    wrapped = _ObservedSocket(listener._listener)
    monkeypatch.setattr(listener, "_listener", wrapped)
    original_verify = listener._verify_all
    calls = 0

    def fail_after_accept(mode):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ListenerError("injected_guard_failure")
        original_verify(mode)

    monkeypatch.setattr(listener, "_verify_all", fail_after_accept)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(listener.endpoint)
        _assert_listener_error(lambda: listener.accept(timeout=0.5))
    assert wrapped.accepted is not None
    assert wrapped.accepted.fileno() == -1


def test_publication_verification_failure_cleans_recorded_resources(runtime_parent, monkeypatch):
    original_verify = PrivateControlListener._verify_all

    def reject_publication(instance, mode):
        if mode == 0o2710:
            raise ListenerError("injected_publication_failure")
        original_verify(instance, mode)

    monkeypatch.setattr(PrivateControlListener, "_verify_all", reject_publication)
    _assert_listener_error(_new_listener(runtime_parent).open)
    assert list(runtime_parent.iterdir()) == []


@pytest.mark.parametrize("failure", ["chmod", "listen"])
def test_socket_setup_failure_cleans_recorded_resources(runtime_parent, monkeypatch, failure):
    if failure == "chmod":
        original_chmod = forwarder_listener.os.chmod

        def fail_socket_chmod(path, *args, **kwargs):
            if path == "control.sock":
                raise OSError("injected chmod failure")
            return original_chmod(path, *args, **kwargs)

        monkeypatch.setattr(forwarder_listener.os, "chmod", fail_socket_chmod)
    else:
        original_socket = forwarder_listener.socket.socket

        class FailListenSocket:
            def __init__(self, *args, **kwargs):
                self._wrapped = original_socket(*args, **kwargs)

            def listen(self, *_args, **_kwargs):
                raise OSError("injected listen failure")

            def __getattr__(self, name):
                return getattr(self._wrapped, name)

        monkeypatch.setattr(forwarder_listener.socket, "socket", FailListenSocket)

    _assert_listener_error(_new_listener(runtime_parent).open)
    assert list(runtime_parent.iterdir()) == []
