"""Real local TLS integration tests for the synthetic fixed-origin upstream connector.

Every network case here runs behind ``asserting_upstream_adapter``: the only
addresses a socket may ever reach are the synthetic upstream fixture (redirected
from the operator-configured ``(address, port)``) and the inbound ephemeral
listener (redirected from the fixed Jira port). No DNS resolver is ever called.

The upstream server side is real TLS over ``ssl.MemoryBIO`` (``synthetic_upstream``),
so every wire byte -- handshake and application data alike -- is visible to the
fixture as ``raw_in`` and can be asserted as well-formed TLS record framing.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox import forwarder_response_receive as frr
from grafana_jsm_sandbox import forwarder_routes as fr
from grafana_jsm_sandbox import forwarder_upstream as fu
from grafana_jsm_sandbox.forwarder_exchange import UpstreamError
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse, parse_response
from grafana_jsm_sandbox.forwarder_json import canonical_json, tagged_digest
from grafana_jsm_sandbox.forwarder_routes import RoutePolicy
from grafana_jsm_sandbox.forwarder_upstream import (
    BasicCredential,
    JiraUpstreamConnector,
    UpstreamEndpoint,
)
from tests import test_forwarder_server_tls_integration as tls_fixtures
from tests import test_forwarder_tls_integration as material_fixtures
from tests.test_forwarder_exchange import (
    BOOT,
    SERVICE,
    install_lease,
    new_real_system,
    ok_issue_get_body,
    policy_with_golden,
)
from tests.test_forwarder_exchange_integration import (
    SEARCH_JQL,
    assert_local,
    flight_phase,
    ledger_entry,
    ok_search_body,
    raw_get,
    raw_post,
    roundtrip,
    serve_one_exchange,
)
from tests.test_forwarder_routes import golden_manifest, make_request
from tests.test_forwarder_upstream import DENIAL_DIGEST_ISSUE_GET

# The base class every socket the connector or the test client ever creates must
# ultimately derive from: captured before any monkeypatch touches ``socket.socket``.
_ORIGINAL_SOCKET = socket.socket

_ENDPOINT_HOST = "jira-upstream.synthetic.invalid"
_ENDPOINT_ADDRESS = "192.0.2.10"
_CREDENTIAL_ID = "jira-basic-synthetic-1"
_CREDENTIAL_USER = "synthetic-user@example.invalid"
_CREDENTIAL_TOKEN = "synthetic-token-0001"

# Golden wire literals (plan section "Golden vectors"). These do not depend on the
# endpoint digest or trust bundle, only on method/target/authority/accept/
# content-type/body/credential -- so they hold even though this fixture's CA (and
# therefore its endpoint digest) is freshly generated every test session.
GOLDEN_ISSUE_GET_WIRE_LEN = 297
GOLDEN_ISSUE_GET_WIRE_SHA256 = "5d7e615700e1420b602aa1d6fc879370ffd850ad80c6cffb8a7d71f7b371d28f"
GOLDEN_ISSUE_GET_REDACTED_LEN = 233
GOLDEN_ISSUE_GET_REDACTED_SHA256 = (
    "d8b34b81b9c17dd08b0076106e4cfea12be03fdff7260d86bbd79e9c71ef65fd"
)
GOLDEN_SEARCH_WIRE_LEN = 524
GOLDEN_SEARCH_WIRE_SHA256 = "bc63a733582b41ca053957012f0990586c299a043fb996e2ad779ed35391a826"
GOLDEN_SEARCH_REDACTED_LEN = 460
GOLDEN_SEARCH_REDACTED_SHA256 = (
    "096952c097451757b13e1a4c5aaac147aa6ba04ea6e96b60f875fb8719a99c27"
)
GOLDEN_8443_WIRE_LEN = 302
GOLDEN_8443_WIRE_SHA256 = "1aebec6abb6ab933e24225554278826f7012f9468011849c245a3cdcdf6e40f1"
GOLDEN_8443_REDACTED_LEN = 238
GOLDEN_8443_REDACTED_SHA256 = "881a86f8c1e35260a712316ec1df4442349bec5d213de579ff000aea84feeeb3"
GOLDEN_AUTHORIZATION_VALUE = (
    b"Basic c3ludGhldGljLXVzZXJAZXhhbXBsZS5pbnZhbGlkOnN5bnRoZXRpYy10b2tlbi0wMDAx"
)
GOLDEN_ISSUE_GET_V1_DIGEST = "43d8b4787de8e9370f79c719f3dbd5463e259bce78b98cd27daa246c7042b929"
GOLDEN_SEARCH_V1_DIGEST = "d416cc8619c619fe09b16796d7b87c515503e74ce6624f3a2d75570ce9d0692e"


def _run_openssl(directory, executable, *arguments):
    completed = subprocess.run(
        [executable, *arguments], cwd=directory, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10,
        check=False, umask=0o077,
        env={"PATH": os.defpath, "LC_ALL": "C", "OPENSSL_CONF": os.devnull},
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")


@dataclass(frozen=True)
class UpstreamMaterial:
    directory: object
    ca_pem: dict
    leaf_cert: dict
    leaf_key: object


_CA_NAMES = ("upstream-ca", "other-ca", "lax-ca")

# name -> (issuing ca, sanline or None, eku, extra extension lines, start offset, end offset)
_LEAF_VARIANTS = {
    "good": ("upstream-ca", f"DNS:{_ENDPOINT_HOST}", "serverAuth", (),
             timedelta(minutes=-5), timedelta(hours=23)),
    "wildcard": ("upstream-ca", "DNS:*.synthetic.invalid", "serverAuth", (),
                 timedelta(minutes=-5), timedelta(hours=23)),
    "wrong-name": ("upstream-ca", "DNS:other.synthetic.invalid", "serverAuth", (),
                   timedelta(minutes=-5), timedelta(hours=23)),
    "cn-only": ("upstream-ca", None, "serverAuth", (),
                timedelta(minutes=-5), timedelta(hours=23)),
    "ip-only": ("upstream-ca", "IP:192.0.2.10", "serverAuth", (),
                timedelta(minutes=-5), timedelta(hours=23)),
    "expired": ("upstream-ca", f"DNS:{_ENDPOINT_HOST}", "serverAuth", (),
                timedelta(days=-2), timedelta(days=-1)),
    "not-yet-valid": ("upstream-ca", f"DNS:{_ENDPOINT_HOST}", "serverAuth", (),
                      timedelta(hours=1), timedelta(hours=25)),
    "client-eku-only": ("upstream-ca", f"DNS:{_ENDPOINT_HOST}", "clientAuth", (),
                        timedelta(minutes=-5), timedelta(hours=23)),
    "no-aki": ("upstream-ca", f"DNS:{_ENDPOINT_HOST}", "serverAuth", ("no-aki",),
               timedelta(minutes=-5), timedelta(hours=23)),
    "lax-signed": ("lax-ca", f"DNS:{_ENDPOINT_HOST}", "serverAuth", (),
                   timedelta(minutes=-5), timedelta(hours=23)),
    "other-signed": ("other-ca", f"DNS:{_ENDPOINT_HOST}", "serverAuth", (),
                     timedelta(minutes=-5), timedelta(hours=23)),
}


@pytest.fixture(scope="module")
def upstream_tls_material(tmp_path_factory):
    directory = tmp_path_factory.mktemp("upstream-tls")
    executable = shutil.which("openssl")
    assert executable is not None

    version = subprocess.run(
        [executable, "version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, check=False,
    )
    assert version.stdout.startswith(b"OpenSSL 3."), version.stdout

    def run(*arguments):
        _run_openssl(directory, executable, *arguments)

    ca_pem = {}
    for name in _CA_NAMES:
        constraints = "critical,CA:TRUE" if name != "lax-ca" else "CA:TRUE"
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
            "-keyout", f"{name}.key", "-out", f"{name}.pem",
            "-subj", f"/CN=MAOI {name} fixture",
            "-addext", f"basicConstraints={constraints}",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
        ca_pem[name] = (directory / f"{name}.pem").read_text()
        (directory / f"issued-{name}").mkdir()
        (directory / f"index-{name}.txt").write_text("")
        (directory / f"serial-{name}").write_text("1000\n")
        (directory / f"{name}.cnf").write_text(
            "[ca]\ndefault_ca = fixture_ca\n"
            "[fixture_ca]\n"
            f"database = index-{name}.txt\nserial = serial-{name}\n"
            f"new_certs_dir = issued-{name}\ncertificate = {name}.pem\n"
            f"private_key = {name}.key\ndefault_md = sha256\ndefault_days = 1\n"
            "policy = fixture_policy\nunique_subject = no\n"
            "[fixture_policy]\ncommonName = supplied\n",
        )

    run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
        "-out", "leaf.csr", "-subj", f"/CN={_ENDPOINT_HOST}")

    now = datetime.now(UTC).replace(microsecond=0)
    leaf_cert = {}
    for name, (ca, san, eku, extras, start_offset, end_offset) in _LEAF_VARIANTS.items():
        section = f"leaf_{name.replace('-', '_')}"
        lines = [
            f"[{section}]",
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            f"extendedKeyUsage={eku}",
            "subjectKeyIdentifier=hash",
        ]
        if "no-aki" in extras:
            # openssl ca adds an AKI by default unless told otherwise: an absent
            # line is not enough to omit it.
            lines.append("authorityKeyIdentifier=none")
        else:
            lines.append("authorityKeyIdentifier=keyid:always")
        if san is not None:
            lines.append(f"subjectAltName={san}")
        with (directory / f"{ca}.cnf").open("a") as config:
            config.write("\n" + "\n".join(lines) + "\n")
        start = (now + start_offset).strftime("%Y%m%d%H%M%SZ")
        end = (now + end_offset).strftime("%Y%m%d%H%M%SZ")
        out = directory / f"leaf-{name}.pem"
        run("ca", "-batch", "-notext", "-config", f"{ca}.cnf", "-in", "leaf.csr",
            "-out", out.name, "-startdate", start, "-enddate", end, "-extensions", section)
        leaf_cert[name] = out

    return UpstreamMaterial(
        directory=directory, ca_pem=ca_pem, leaf_cert=leaf_cert, leaf_key=directory / "leaf.key",
    )


# The Forwarder listener's own certificate material (separate CA), reused only for
# the "anchor only" and "name only" trust-matrix cases below. A fresh, dedicated
# module-scoped instance: appending to its ``ca.cnf`` never affects other test
# modules that also import this fixture.
service_tls_material = material_fixtures.tls_material


def listener_signed_upstream_leaf(service_tls_material, host):
    """Sign one more leaf under the *Forwarder listener*'s own CA (anchor-only case)."""
    base, _paths = service_tls_material
    directory = base.ca_cert.parent
    executable = shutil.which("openssl")
    assert executable is not None
    now = datetime.now(UTC).replace(microsecond=0)
    start = (now - timedelta(minutes=5)).strftime("%Y%m%d%H%M%SZ")
    end = (now + timedelta(hours=23)).strftime("%Y%m%d%H%M%SZ")
    section = "service_upstream_name_probe"
    marker = f"[{section}]"
    existing = (directory / "ca.cnf").read_text()
    if marker not in existing:
        with (directory / "ca.cnf").open("a") as config:
            config.write(
                f"\n{marker}\nbasicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{host}\n",
            )
    out = directory / "service-upstream-name-probe.pem"
    if not out.exists():
        _run_openssl(
            directory, executable, "ca", "-batch", "-notext", "-config", "ca.cnf",
            "-in", "service.csr", "-out", out.name, "-startdate", start, "-enddate", end,
            "-extensions", section,
        )
    return out


# --- endpoint/credential helpers ------------------------------------------------


def synthetic_endpoint(material, *, port=443, ca="upstream-ca", host=_ENDPOINT_HOST,
                       address=_ENDPOINT_ADDRESS, revision="upstream-r1"):
    return UpstreamEndpoint(
        service="jira", revision=revision, host=host, address=address, port=port,
        ca_pem=material.ca_pem[ca], credential_id=_CREDENTIAL_ID,
    )


def synthetic_credential():
    return BasicCredential(
        service="jira", profile="basic", credential_id=_CREDENTIAL_ID,
        user=_CREDENTIAL_USER, token=_CREDENTIAL_TOKEN,
    )


# --- TLS record framing ---------------------------------------------------------


def assert_tls_records(data: bytes) -> None:
    """Every complete record is well-formed; a final truncated one is a prefix of one."""
    offset = 0
    while offset < len(data):
        header = data[offset:offset + 5]
        assert 20 <= header[0] <= 23, (offset, data[offset:offset + 16])
        version = header[1:3]
        assert version in (b"\x03\x01"[:len(version)], b"\x03\x03"[:len(version)]), version
        if len(header) < 5:
            return
        length = int.from_bytes(header[3:5], "big")
        assert length <= 16_640, length
        offset += 5 + length


# How a client that refused our handshake may end the connection (see ``_drain_raw``).
REFUSAL_EOF_KINDS = ("fin", "reset_after_refusal")


def test_assert_tls_records_refuses_trailing_plaintext():
    record = b"\x17\x03\x03\x00\x02ab"
    assert_tls_records(record + b"\x17\x03")
    assert_tls_records(record + b"\x17\x03\x03\x00")
    assert_tls_records(record + b"\x17\x03\x03\x00\x05abc")
    for tail in (b"G", b"GET ", b"POST", b"\x17\x04", b"\x17\x03\x02", b"\x16\x03\x03\x41\x01"):
        with pytest.raises(AssertionError):
            assert_tls_records(record + tail)


# --- synthetic upstream (real server-side TLS over MemoryBIO) -------------------


@dataclass
class UpstreamRecord:
    address: object = None
    accepts: int = 0
    sni: list = field(default_factory=list)
    alpn: object = None
    version: object = None
    captured: bytes = b""
    raw_in: bytes = b""
    eof_kind: object = None
    errors: list = field(default_factory=list)


class _ServerTLS:
    """Drives one server-side ``SSLObject`` over ``MemoryBIO``s and one raw socket."""

    def __init__(self, raw, tls_obj, incoming, outgoing, record):
        self.raw = raw
        self.tls = tls_obj
        self.incoming = incoming
        self.outgoing = outgoing
        self.record = record

    def _flush_out(self):
        data = self.outgoing.read()
        if data:
            self.raw.sendall(data)

    def _pull_in(self):
        chunk = self.raw.recv(65536)
        self.record.raw_in += chunk
        if chunk:
            self.incoming.write(chunk)
        else:
            self.incoming.write_eof()
        return chunk

    def _drive(self, op):
        while True:
            try:
                result = op()
            except ssl.SSLWantReadError:
                # Flush whatever the op already queued (e.g. ServerHello) before
                # blocking on more input, or the client waits for bytes we never sent.
                self._flush_out()
                self._pull_in()
                continue
            except ssl.SSLWantWriteError:
                self._flush_out()
                continue
            self._flush_out()
            return result

    def do_handshake(self):
        self._drive(self.tls.do_handshake)

    def read(self, amount):
        return self._drive(lambda: self.tls.read(amount))

    def write(self, data):
        self._drive(lambda: self.tls.write(data))


def _wait_eof(engine, allow_reset):
    """Called only after a fully framed request; any other error is a fixture error."""
    try:
        data = engine.read(1)
    except ssl.SSLEOFError:
        return "fin"
    except ConnectionResetError:
        if allow_reset:
            return "reset_after_request"
        raise
    if data == b"":
        return "fin"
    raise AssertionError(f"unexpected trailing application bytes: {data!r}")


def _drain_raw(raw, record):
    """Keep every raw byte the client writes after a refused or stalled handshake.

    A client that refuses our flight closes with it unread, which the kernel turns
    into a reset; bytes it wrote before that reset are still delivered first.
    """
    try:
        while True:
            chunk = raw.recv(65536)
            if not chunk:
                return "fin"
            record.raw_in += chunk
    except ConnectionResetError:
        return "reset_after_refusal"


def _is_framed(data):
    head_end = data.find(b"\r\n\r\n")
    if head_end < 0:
        return False
    body_len = 0
    for line in bytes(data[:head_end]).split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            body_len = int(line.split(b":", 1)[1].strip())
    return len(data) >= head_end + 4 + body_len


def _read_one_request(engine, record, on_first_byte):
    buffer = bytearray()
    first = True
    while b"\r\n\r\n" not in buffer:
        chunk = engine.read(4096)
        if not chunk:
            raise AssertionError("fixture reached EOF before a full request head")
        if first and on_first_byte is not None:
            on_first_byte()
        first = False
        buffer.extend(chunk)
    head_end = buffer.find(b"\r\n\r\n") + 4
    head = bytes(buffer[:head_end])
    body_len = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            body_len = int(line.split(b":", 1)[1].strip())
    body = bytes(buffer[head_end:])
    while len(body) < body_len:
        chunk = engine.read(4096)
        if not chunk:
            raise AssertionError("fixture reached EOF before the full request body")
        body += chunk
    return head + body


@contextmanager
def synthetic_upstream(
    material, leaf="good", *, leaf_override=None, respond=None, stall_until=None,
    head_then_stall=False, close_after_request=False, stall_handshake=False, plaintext=False,
    max_tls=None, rcvbuf=None, allow_reset=False, on_sni=None, on_first_byte=None,
    on_request=None,
):
    listener = _ORIGINAL_SOCKET(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf is not None:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(6.0)
    address = listener.getsockname()
    record = UpstreamRecord()

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    if max_tls is not None:
        server_context.maximum_version = max_tls
    server_context.num_tickets = 0
    server_context.set_alpn_protocols(["h2", "http/1.1"])
    cert_path, key_path = leaf_override if leaf_override is not None else (
        material.leaf_cert[leaf], material.leaf_key,
    )
    server_context.load_cert_chain(cert_path, key_path)

    def sni_cb(sslobj, servername, ctx):
        record.sni.append(servername)
        if on_sni is not None:
            on_sni()
    server_context.sni_callback = sni_cb

    def serve():
        raw = None
        try:
            raw, addr = listener.accept()
            record.accepts += 1
            record.address = addr
            raw.settimeout(6.0)

            if plaintext:
                record.raw_in += raw.recv(4096)
                raw.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                record.eof_kind = _drain_raw(raw, record)
                return

            if stall_handshake:
                record.eof_kind = _drain_raw(raw, record)
                return

            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()
            tls_obj = server_context.wrap_bio(incoming, outgoing, server_side=True)
            engine = _ServerTLS(raw, tls_obj, incoming, outgoing, record)
            try:
                engine.do_handshake()
            except ssl.SSLError:
                # The client refused the handshake (trust-matrix cases).
                record.eof_kind = _drain_raw(raw, record)
                return
            record.alpn = tls_obj.selected_alpn_protocol()
            record.version = tls_obj.version()

            if stall_until is not None:
                stall_until.wait(10.0)

            if respond is None and not head_then_stall and not close_after_request:
                captured = bytearray()
                first = True
                try:
                    while True:
                        chunk = engine.read(65536)
                        if first and chunk and on_first_byte is not None:
                            on_first_byte()
                        first = False
                        if not chunk:
                            record.eof_kind = "fin"
                            break
                        captured.extend(chunk)
                except ssl.SSLEOFError:
                    record.eof_kind = "fin"
                except ConnectionResetError:
                    if not (allow_reset and _is_framed(captured)):
                        raise
                    record.eof_kind = "reset_after_request"
                finally:
                    record.captured = bytes(captured)
                return

            request = _read_one_request(engine, record, on_first_byte)
            record.captured = request
            if on_request is not None:
                on_request()

            if head_then_stall:
                record.eof_kind = _wait_eof(engine, allow_reset)
                return
            if close_after_request:
                return

            engine.write(respond)
            record.eof_kind = _wait_eof(engine, allow_reset)
        except Exception as error:  # noqa: BLE001 - surface fixture-thread failures to the test
            record.errors.append(repr(error))
        finally:
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass

    worker = threading.Thread(target=serve, name="synthetic-upstream", daemon=True)
    worker.start()
    try:
        yield record, address
    finally:
        worker.join(6.0)
        listener.close()
        assert not worker.is_alive(), "synthetic upstream worker did not exit"
        assert not record.errors, record.errors


# --- asserting adapter (redirect only the configured address; DNS tripwires) ---


@contextmanager
def asserting_upstream_adapter(monkeypatch, endpoint, fixture_address, *, client_sndbuf=None):
    from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES
    current = socket.socket
    listener_target = (SERVICE_PROFILES["jira"].bind_host, SERVICE_PROFILES["jira"].port)
    attempts = []
    tripwires = []

    class FixtureSocket(current):
        def connect(self, destination):
            if destination == (endpoint.address, endpoint.port):
                attempts.append(destination)
                if client_sndbuf is not None:
                    self.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, client_sndbuf)
                return super().connect(fixture_address)
            if destination == listener_target:
                return super().connect(destination)
            raise AssertionError(f"unexpected upstream connect destination: {destination!r}")

        def bind(self, address):
            raise AssertionError("the upstream connector must never bind a socket")

    def tripwire(name):
        def _raise(*_args, **_kwargs):
            tripwires.append(name)
            raise AssertionError(f"resolver call reached: {name}")
        return _raise

    # A plain, immediately-scoped save/restore rather than ``monkeypatch.setattr``:
    # several tests nest this context manager (or open it more than once) within one
    # test function, and ``monkeypatch`` only reverts at the end of that function --
    # which would leave a stale, address-specific ``FixtureSocket`` class active for
    # a later, unrelated fixture instance.
    resolver_names = (
        "getaddrinfo", "gethostbyname", "gethostbyname_ex", "getfqdn", "create_connection",
    )
    saved_socket = socket.socket
    saved_resolvers = {name: getattr(socket, name) for name in resolver_names}
    socket.socket = FixtureSocket
    for name in resolver_names:
        setattr(socket, name, tripwire(name))

    class _Handle:
        pass
    handle = _Handle()
    handle.attempts = attempts
    try:
        yield handle
    finally:
        socket.socket = saved_socket
        for name, original in saved_resolvers.items():
            setattr(socket, name, original)
        assert not tripwires, tripwires


def refused_tcp_address():
    """An address nothing is listening on: a bound-then-closed ephemeral port."""
    probe = _ORIGINAL_SOCKET(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    address = probe.getsockname()
    probe.close()
    return address


# --- white-box real-TLS client channel (for 2b/2c) ------------------------------


def whitebox_tls(endpoint, *, timeout=5.0):
    context = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((endpoint.address, endpoint.port))
    secured = context.wrap_socket(raw, server_hostname=endpoint.host, do_handshake_on_connect=False)
    secured.settimeout(timeout)
    secured.do_handshake()
    return secured


# --- real routed requests (via the real RoutePolicy, matching unit-12 goldens) --


def routed_issue_get(manifest=None):
    """A real ``RoutedRequest`` for ``jira.issue.get`` SYN-1, matching unit-12's golden."""
    manifest = manifest or golden_manifest()
    policy = policy_with_golden()
    request = make_request(path="/rest/api/3/issue/90101")
    return policy.route(request, manifest)


def routed_search(manifest=None):
    """A real ``RoutedRequest`` for ``jira.search``, matching unit-12's golden."""
    manifest = manifest or golden_manifest()
    policy = policy_with_golden()
    body = canonical_json({"jql": SEARCH_JQL})
    request = make_request(method="POST", path="/rest/api/3/search/jql", body=body)
    return policy.route(request, manifest)


def build_admission(routed, *, deadline_from_now=2.0):
    now = time.monotonic()
    deadline = now + deadline_from_now
    return fd.Admission(
        receipt_id="receipt-" + routed.route_id, lease_id="lease-1", service=routed.service,
        route_id=routed.route_id, admitted_at=now, deadline=deadline, exchange_deadline=deadline,
        connect_deadline=deadline,
    )


def connect_real(connector, routed, *, deadline_from_now=2.0):
    admission = build_admission(routed, deadline_from_now=deadline_from_now)
    digest = connector.prepare(routed)
    channel = connector.connect(
        admission, routed, request_digest=digest, deadline=admission.connect_deadline,
    )
    return admission, digest, channel


# --- gate-aware wrappers (composition cases: connecting/dispatched assertions) --


class AssertingChannel:
    def __init__(self, real, gate, admission):
        self._real = real
        self._gate = gate
        self._admission = admission
        self.send_calls = 0
        self.receive_calls = 0
        self.abort_calls = 0
        self.close_calls = 0

    def send(self, *, deadline):
        self.send_calls += 1
        entry = ledger_entry(self._gate.ledger, self._admission.receipt_id)
        assert entry["entry_state"] == "dispatched"
        return self._real.send(deadline=deadline)

    def receive(self, *, deadline):
        self.receive_calls += 1
        return self._real.receive(deadline=deadline)

    def abort(self):
        self.abort_calls += 1
        return self._real.abort()

    def close(self):
        self.close_calls += 1
        return self._real.close()


class AssertingConnector:
    """Wraps the real connector, asserting the 13a contract (O2/O3, J13) at each call."""

    def __init__(self, real, gate):
        self._real = real
        self._gate = gate
        self.prepare_calls = 0
        self.connect_calls = 0
        self.channels: list[AssertingChannel] = []

    def prepare(self, routed):
        self.prepare_calls += 1
        return self._real.prepare(routed)

    def connect(self, admission, routed, *, request_digest, deadline):
        self.connect_calls += 1
        entry = ledger_entry(self._gate.ledger, admission.receipt_id)
        assert entry["entry_state"] == "connecting"
        assert self._gate.is_admitted(admission) is True
        probe = {}

        def read_snapshot():
            probe["ok"] = True
            self._gate.snapshot()
        prober = threading.Thread(target=read_snapshot, daemon=True)
        prober.start()
        prober.join(0.5)
        assert not prober.is_alive(), "gate lock appears held across connect()"
        assert probe.get("ok"), "gate.snapshot() from another thread did not complete"

        channel = self._real.connect(
            admission, routed, request_digest=request_digest, deadline=deadline,
        )
        wrapped = AssertingChannel(channel, self._gate, admission)
        self.channels.append(wrapped)
        return wrapped


def _ok_response_bytes(body: bytes, status: int = 200) -> bytes:
    return (
        f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body


# === 1: golden captures (O1/wire-profile) ========================================


def test_golden_issue_get_capture_and_response(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    assert routed.request_digest == GOLDEN_ISSUE_GET_V1_DIGEST
    body = ok_issue_get_body()

    with synthetic_upstream(upstream_tls_material, respond=_ok_response_bytes(body)) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address) as adapter:
        admission, digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        channel.close()

    assert response == ParsedResponse(status=200, body=body)
    assert len(record.captured) == GOLDEN_ISSUE_GET_WIRE_LEN
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_ISSUE_GET_WIRE_SHA256
    assert record.sni == [endpoint.host]
    assert record.alpn == "http/1.1"
    assert record.version in ("TLSv1.2", "TLSv1.3")
    assert record.accepts == 1
    assert record.eof_kind == "fin"
    assert adapter.attempts == [(endpoint.address, endpoint.port)]
    assert_tls_records(record.raw_in)
    assert digest != routed.request_digest


def test_golden_search_capture(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_search()
    assert routed.request_digest == GOLDEN_SEARCH_V1_DIGEST
    body = ok_search_body()

    with synthetic_upstream(upstream_tls_material, respond=_ok_response_bytes(body)) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        channel.close()

    assert response == ParsedResponse(status=200, body=body)
    assert len(record.captured) == GOLDEN_SEARCH_WIRE_LEN
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_SEARCH_WIRE_SHA256
    assert_tls_records(record.raw_in)


def test_golden_8443_endpoint_capture(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material, port=8443)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    body = ok_issue_get_body()

    with synthetic_upstream(upstream_tls_material, respond=_ok_response_bytes(body)) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        channel.receive(deadline=admission.exchange_deadline)
        channel.close()

    assert len(record.captured) == GOLDEN_8443_WIRE_LEN
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_8443_WIRE_SHA256
    assert_tls_records(record.raw_in)


def test_golden_capture_succeeds_on_tls12_only_fixture(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    body = ok_issue_get_body()

    with synthetic_upstream(
        upstream_tls_material, respond=_ok_response_bytes(body), max_tls=ssl.TLSVersion.TLSv1_2,
    ) as (record, address), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        channel.close()

    assert response == ParsedResponse(status=200, body=body)
    assert record.version == "TLSv1.2"
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_ISSUE_GET_WIRE_SHA256
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


# === 2: zero application bytes, each paired with the golden captures above ======


def test_connect_then_close_writes_nothing(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        _admission, _digest, channel = connect_real(connector, routed)
        channel.close()

    assert record.captured == b""
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


def test_connect_abort_send_close_writes_nothing(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission, _digest, channel = connect_real(connector, routed)
        channel.abort()
        # The refusal path only: no plaintext-after-abort evidence here, that is
        # 2b/2c below.
        assert channel._sock._sslobj is not None
        with pytest.raises(UpstreamError) as caught:
            channel.send(deadline=admission.exchange_deadline)
        assert caught.value.code == "write_failed"
        channel.close()

    assert record.captured == b""
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


def test_send_twice_second_raises_with_exactly_one_request_captured(
    monkeypatch, upstream_tls_material,
):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        with pytest.raises(UpstreamError) as caught:
            channel.send(deadline=admission.exchange_deadline)
        assert caught.value.code == "write_failed"
        channel.close()

    assert len(record.captured) == GOLDEN_ISSUE_GET_WIRE_LEN
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_ISSUE_GET_WIRE_SHA256
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


# === 2b: abort during a real blocked SSL_write (critic issue 2a) ================


def _search_parts_with_body(host: str, body_len: int) -> fu.RequestParts:
    body = b"a" * body_len
    prefix = f"POST /rest/api/3/search/jql HTTP/1.1\r\nHost: {host}\r\n".encode()
    suffix = (
        "Accept: application/json\r\nAccept-Encoding: identity\r\n"
        f"Content-Type: application/json\r\nContent-Length: {body_len}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    return fu.RequestParts(prefix=prefix, suffix=suffix)


def test_abort_during_a_real_blocked_send(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    event = threading.Event()
    # A shrunken local send buffer plus a multi-megabyte body reliably exceeds the
    # combined local-buffer + remote-window capacity on loopback, without depending
    # on the remote's receive buffer size (which macOS does not let a listening
    # socket's SO_RCVBUF constrain on its accepted connections).
    body_len = 2 * 1024 * 1024

    with synthetic_upstream(upstream_tls_material, stall_until=event, allow_reset=True) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address, client_sndbuf=4096):
        secured = whitebox_tls(endpoint)
        credential = synthetic_credential()
        parts = _search_parts_with_body(endpoint.host, body_len)
        exchange_deadline = time.monotonic() + 30.0
        channel = fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=secured, parts=parts, credential=credential,
            exchange_deadline=exchange_deadline,
        )
        outcome = {}

        def run_send():
            try:
                channel.send(deadline=time.monotonic() + 10.0)
            except UpstreamError as error:
                outcome["error"] = error
        sender = threading.Thread(target=run_send, daemon=True)
        sender.start()
        time.sleep(0.3)
        assert sender.is_alive(), "send should still be blocked on a full send buffer"

        t0 = time.monotonic()
        channel.abort()
        abort_elapsed = time.monotonic() - t0
        assert abort_elapsed < 0.5

        sender.join(1.0)
        assert not sender.is_alive()
        assert isinstance(outcome.get("error"), UpstreamError)
        assert outcome["error"].code == "write_failed"
        assert secured._sslobj is not None
        authorization_len = len(credential._authorization)
        total_len = (
            len(parts.prefix) + 17 + authorization_len + 2 + len(parts.suffix)
        )
        assert channel.bytes_accepted < total_len

        event.set()

    assert_tls_records(record.raw_in)
    assert b"POST " not in record.raw_in
    assert b"Content-Length:" not in record.raw_in


# === 2c: direct send after _shutdown_fd (critic issue 2b) =======================


def test_direct_send_after_shutdown_fd_raises_and_leaks_no_plaintext(
    monkeypatch, upstream_tls_material,
):
    endpoint = synthetic_endpoint(upstream_tls_material)
    with (
        synthetic_upstream(upstream_tls_material, allow_reset=True) as (record, _address),
        asserting_upstream_adapter(monkeypatch, endpoint, _address),
    ):
        secured = whitebox_tls(endpoint)
        fu._shutdown_fd(secured)
        with pytest.raises(OSError):
            secured.send(b"GET ")
        assert secured._sslobj is not None
    assert b"GET " not in record.raw_in
    assert_tls_records(record.raw_in)


def test_shutdown_fd_control_pins_cpython_sslobj_clearing_behavior(
    monkeypatch, upstream_tls_material,
):
    """A control on a second connection: the base-class call is the barrier, not this."""
    endpoint = synthetic_endpoint(upstream_tls_material)
    with (
        synthetic_upstream(upstream_tls_material, allow_reset=True) as (record, _address),
        asserting_upstream_adapter(monkeypatch, endpoint, _address),
    ):
        secured = whitebox_tls(endpoint)
        ssl.SSLSocket.shutdown(secured, socket.SHUT_RDWR)
        assert secured._sslobj is None
        with pytest.raises(OSError):
            secured.send(b"GET ")
    assert b"GET " not in record.raw_in
    assert_tls_records(record.raw_in)


# === O4: receive timing and codec rejection ======================================


def test_inactivity_limit_bounds_a_stalled_response(monkeypatch, upstream_tls_material):
    monkeypatch.setattr(frr, "_INACTIVITY_LIMIT", 0.3)
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, head_then_stall=True) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission, _digest, channel = connect_real(connector, routed, deadline_from_now=10.0)
        channel.send(deadline=admission.exchange_deadline)
        t0 = time.monotonic()
        with pytest.raises(UpstreamError) as caught:
            channel.receive(deadline=time.monotonic() + 5.0)
        elapsed = time.monotonic() - t0
        channel.close()

    assert caught.value.code == "receive_failed"
    assert 0.2 <= elapsed <= 1.5
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


def test_unpatched_short_deadline_bounds_a_stalled_response(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, head_then_stall=True) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission, _digest, channel = connect_real(connector, routed, deadline_from_now=10.0)
        channel.send(deadline=admission.exchange_deadline)
        t0 = time.monotonic()
        with pytest.raises(UpstreamError) as caught:
            channel.receive(deadline=time.monotonic() + 0.5)
        elapsed = time.monotonic() - t0
        channel.close()

    assert caught.value.code == "receive_failed"
    assert 0.3 <= elapsed <= 1.5
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


@pytest.mark.parametrize("name,response", [
    ("redirect_with_location", (
        b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/x\r\n"
        b"Content-Length: 0\r\n\r\n"
    )),
    ("chunked", (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    )),
    ("charset", (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=UTF-8\r\n"
        b"Content-Length: 2\r\n\r\n{}"
    )),
    ("gzip", (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}"
    )),
    ("over_1mib", (
        # The declared length alone fails validation before any body is read, so
        # the fixture need not actually transfer a megabyte of bytes.
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 1048577\r\n\r\n"
    )),
], ids=["redirect", "chunked", "charset", "gzip", "over-1mib"])
def test_malformed_upstream_responses_give_receive_failed(
    monkeypatch, upstream_tls_material, name, response,
):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with synthetic_upstream(upstream_tls_material, respond=response, allow_reset=True) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        with pytest.raises(UpstreamError) as caught:
            channel.receive(deadline=admission.exchange_deadline)
        assert caught.value.code == "receive_failed"
        channel.close()

    assert record.eof_kind in ("fin", "reset_after_request")
    assert_tls_records(record.raw_in)


def test_close_after_request_gives_receive_failed(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, close_after_request=True) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        with pytest.raises(UpstreamError) as caught:
            channel.receive(deadline=admission.exchange_deadline)
        assert caught.value.code == "receive_failed"
        channel.close()

    assert_tls_records(record.raw_in)


def test_404_json_returns_parsed_response(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    body = b'{"errorMessages":[]}'

    with synthetic_upstream(upstream_tls_material, respond=_ok_response_bytes(body, 404)) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        channel.close()

    assert response == ParsedResponse(status=404, body=body)
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


# === O5/O6: real races (abort, close, receive) ===================================


def test_abort_while_receive_blocks_unblocks_it(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with synthetic_upstream(upstream_tls_material, head_then_stall=True) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed, deadline_from_now=10.0)
        channel.send(deadline=admission.exchange_deadline)
        outcome = {}

        def run_receive():
            try:
                channel.receive(deadline=admission.exchange_deadline)
            except UpstreamError as error:
                outcome["error"] = error
        receiver = threading.Thread(target=run_receive, daemon=True)
        receiver.start()
        time.sleep(0.3)
        assert receiver.is_alive()

        t0 = time.monotonic()
        channel.abort()
        abort_elapsed = time.monotonic() - t0
        receiver.join(1.0)
        assert not receiver.is_alive()
        channel.close()

    assert abort_elapsed < 0.2
    assert isinstance(outcome.get("error"), UpstreamError)
    assert outcome["error"].code == "receive_failed"
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


def test_eight_threads_race_abort_and_close_while_receive_blocks(
    monkeypatch, upstream_tls_material,
):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with synthetic_upstream(upstream_tls_material, head_then_stall=True) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed, deadline_from_now=10.0)
        channel.send(deadline=admission.exchange_deadline)
        target_sock = channel._sock

        close_calls = []
        original_close = ssl.SSLSocket.close

        def counting_close(self, *args, **kwargs):
            if self is target_sock:
                close_calls.append(1)
            return original_close(self, *args, **kwargs)
        monkeypatch.setattr(ssl.SSLSocket, "close", counting_close)

        outcome = {}

        def run_receive():
            try:
                channel.receive(deadline=admission.exchange_deadline)
            except UpstreamError as error:
                outcome["error"] = error
        receiver = threading.Thread(target=run_receive, daemon=True)
        receiver.start()
        time.sleep(0.2)

        errors = []
        barrier = threading.Barrier(9)

        def race(fn):
            barrier.wait(2.0)
            try:
                fn()
            except Exception as error:  # noqa: BLE001 - any raise here is the finding.
                errors.append(error)
        racers = [
            threading.Thread(target=race, args=(channel.abort,), daemon=True) for _ in range(4)
        ] + [
            threading.Thread(target=race, args=(channel.close,), daemon=True) for _ in range(4)
        ]
        for racer in racers:
            racer.start()
        barrier.wait(2.0)
        for racer in racers:
            racer.join(2.0)
        receiver.join(1.0)

    assert not errors
    assert not any(racer.is_alive() for racer in racers)
    assert not receiver.is_alive()
    assert sum(close_calls) == 1
    assert isinstance(outcome.get("error"), UpstreamError)
    assert outcome["error"].code == "receive_failed"
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


def test_close_from_another_thread_while_receive_blocks_is_deferred(
    monkeypatch, upstream_tls_material,
):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with synthetic_upstream(upstream_tls_material, head_then_stall=True) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed, deadline_from_now=10.0)
        channel.send(deadline=admission.exchange_deadline)
        outcome = {}

        def run_receive():
            try:
                channel.receive(deadline=admission.exchange_deadline)
            except UpstreamError as error:
                outcome["error"] = error
        receiver = threading.Thread(target=run_receive, daemon=True)
        receiver.start()
        time.sleep(0.2)
        assert channel.state == "receiving"

        close_t0 = time.monotonic()
        closer = threading.Thread(target=channel.close, daemon=True)
        closer.start()
        closer.join(1.0)
        close_elapsed = time.monotonic() - close_t0
        assert not closer.is_alive()
        # Deferred: close() itself never blocks on the outstanding receive(); it
        # hands off to _finish_io, which the receive() thread runs once it wakes.
        assert close_elapsed < 0.5

        receiver.join(1.0)
        assert not receiver.is_alive()

    assert channel.state == "closed"
    assert isinstance(outcome.get("error"), UpstreamError)
    assert outcome["error"].code == "receive_failed"
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


# --- fd reuse (critic issue 4): TLS-wrapped socketpair ends, no adapter needed --


def tls_socketpair(material, endpoint, credential, leaf="good"):
    """A directly-connected client/server TLS pair; no listener, no adapter."""
    client_raw, server_raw = socket.socketpair()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(material.leaf_cert[leaf], material.leaf_key)
    client_context = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)

    box = {}

    def do_server():
        box["server"] = server_context.wrap_socket(server_raw, server_side=True)
    server_thread = threading.Thread(target=do_server, daemon=True)
    server_thread.start()
    client_secured = client_context.wrap_socket(client_raw, server_hostname=endpoint.host)
    server_thread.join(5.0)
    return client_secured, box["server"]


def test_fd_reuse_deterministic_abort_after_close(upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    credential = synthetic_credential()
    client_secured, server_secured = tls_socketpair(upstream_tls_material, endpoint, credential)
    parts = _search_parts_with_body(endpoint.host, 16)
    channel = fu._UpstreamChannel(
        fu._CHANNEL_TOKEN, sock=client_secured, parts=parts, credential=credential,
        exchange_deadline=time.monotonic() + 5.0,
    )
    old_client_fd = client_secured.fileno()
    old_server_fd = server_secured.fileno()

    channel.close()
    assert client_secured.fileno() == -1
    server_secured.close()

    new_client, new_server = tls_socketpair(upstream_tls_material, endpoint, credential)
    try:
        reused = {new_client.fileno(), new_server.fileno()} & {old_client_fd, old_server_fd}
        assert reused, "expected the new pair to reuse a just-closed descriptor"

        # abort() on the old (already-closed) channel returns early; it must never
        # touch the descriptor number the OS has since reused.
        channel.abort()

        new_client.sendall(b"x")
        assert new_server.recv(1) == b"x"
        new_server.sendall(b"y")
        assert new_client.recv(1) == b"y"
    finally:
        new_client.close()
        new_server.close()


def test_fd_reuse_concurrent_close_and_abort(upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    credential = synthetic_credential()
    errors = []
    iterations = 40

    for _ in range(iterations):
        client_secured, server_secured = tls_socketpair(upstream_tls_material, endpoint, credential)
        parts = _search_parts_with_body(endpoint.host, 16)
        channel = fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=client_secured, parts=parts, credential=credential,
            exchange_deadline=time.monotonic() + 5.0,
        )
        barrier = threading.Barrier(2)
        new_pair = {}

        def thread_a(barrier=barrier, channel=channel, new_pair=new_pair):
            barrier.wait(2.0)
            channel.close()
            new_pair["pair"] = tls_socketpair(upstream_tls_material, endpoint, credential)

        def thread_b(barrier=barrier, channel=channel):
            barrier.wait(2.0)
            channel.abort()

        ta = threading.Thread(target=thread_a, daemon=True)
        tb = threading.Thread(target=thread_b, daemon=True)
        ta.start()
        tb.start()
        ta.join(2.0)
        tb.join(2.0)
        if ta.is_alive() or tb.is_alive():
            errors.append("a race thread did not finish")
            continue

        new_client, new_server = new_pair["pair"]
        try:
            new_client.sendall(b"x")
            if new_server.recv(1) != b"x":
                errors.append("byte exchange (client->server) failed after the race")
            new_server.sendall(b"y")
            if new_client.recv(1) != b"y":
                errors.append("byte exchange (server->client) failed after the race")
        except Exception as error:  # noqa: BLE001 - any raise here is the finding.
            errors.append(repr(error))
        finally:
            new_client.close()
            new_server.close()
            server_secured.close()

    assert not errors, errors


# === Trust matrix (connect only) =================================================


@pytest.mark.parametrize("leaf", [
    "wrong-name", "cn-only", "ip-only", "expired", "not-yet-valid", "client-eku-only",
    "other-signed",
])
def test_trust_matrix_rejects_bad_leaves(monkeypatch, upstream_tls_material, leaf):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, leaf=leaf) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission = build_admission(routed)
        digest = connector.prepare(routed)
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )

    assert caught.value.code == "upstream_tls_failed"
    assert record.captured == b""
    assert record.accepts == 1
    assert record.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record.raw_in)


def test_trust_matrix_accepts_wildcard_leaf(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    body = ok_issue_get_body()

    with synthetic_upstream(
        upstream_tls_material, leaf="wildcard", respond=_ok_response_bytes(body),
    ) as (record, address), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        channel.close()

    assert response == ParsedResponse(status=200, body=body)
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


@pytest.mark.parametrize("leaf", ["no-aki", "lax-signed"])
def test_trust_matrix_strict_flag_is_live(monkeypatch, upstream_tls_material, leaf):
    issuer = {"no-aki": "upstream-ca", "lax-signed": "lax-ca"}[leaf]
    endpoint = synthetic_endpoint(upstream_tls_material, ca=issuer)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, leaf=leaf) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission = build_admission(routed)
        digest = connector.prepare(routed)
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )
    assert caught.value.code == "upstream_tls_failed"
    assert record.captured == b""
    assert record.accepts == 1
    assert record.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record.raw_in)

    # Control: the identical bundle without VERIFY_X509_STRICT completes the
    # handshake, proving the strict flag -- not the CA bundle -- is what rejected it.
    with (
        synthetic_upstream(upstream_tls_material, leaf=leaf) as (record2, address2),
        asserting_upstream_adapter(monkeypatch, endpoint, address2),
    ):
        control = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        control.load_verify_locations(cadata=endpoint.ca_pem)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5.0)
        raw.connect((endpoint.address, endpoint.port))
        secured = control.wrap_socket(raw, server_hostname=endpoint.host)
        secured.close()
    assert record2.version in ("TLSv1.2", "TLSv1.3")
    assert record2.eof_kind == "fin"
    assert_tls_records(record2.raw_in)


def test_trust_matrix_anchor_only_rejects_right_name_wrong_issuer(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    """A leaf with the right name but issued by the Forwarder listener CA is refused."""
    endpoint = synthetic_endpoint(upstream_tls_material)  # trusts only upstream-ca
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    base, _paths = service_tls_material
    listener_leaf = listener_signed_upstream_leaf(service_tls_material, endpoint.host)

    with synthetic_upstream(
        upstream_tls_material, leaf_override=(listener_leaf, base.server_key),
    ) as (record, address), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission = build_admission(routed)
        digest = connector.prepare(routed)
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )

    assert caught.value.code == "upstream_tls_failed"
    assert record.captured == b""
    assert record.accepts == 1
    assert record.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record.raw_in)


def test_trust_matrix_name_only_rejects_wrong_name_right_issuer(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    """A leaf for the real listener host, trusted by its own CA, still needs the name."""
    base, paths = service_tls_material
    endpoint = UpstreamEndpoint(
        service="jira", revision="upstream-r1", host=_ENDPOINT_HOST, address=_ENDPOINT_ADDRESS,
        port=443, ca_pem=base.ca_cert.read_text(), credential_id=_CREDENTIAL_ID,
    )
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with synthetic_upstream(
        upstream_tls_material, leaf_override=(paths["jira"], base.server_key),
    ) as (record, address), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission = build_admission(routed)
        digest = connector.prepare(routed)
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )

    assert caught.value.code == "upstream_tls_failed"
    assert record.captured == b""
    assert record.accepts == 1
    assert record.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record.raw_in)


def test_trust_matrix_plaintext_peer_gives_upstream_tls_failed(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, plaintext=True) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission = build_admission(routed)
        digest = connector.prepare(routed)
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )

    assert caught.value.code == "upstream_tls_failed"
    assert record.captured == b""
    assert record.accepts == 1
    assert record.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record.raw_in)


def test_trust_matrix_handshake_stall_fails_within_a_second(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()

    with (
        synthetic_upstream(upstream_tls_material, stall_handshake=True) as (record, address),
        asserting_upstream_adapter(monkeypatch, endpoint, address),
    ):
        admission = build_admission(routed, deadline_from_now=0.3)
        digest = connector.prepare(routed)
        t0 = time.monotonic()
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )
        elapsed = time.monotonic() - t0

    assert caught.value.code == "upstream_tls_failed"
    assert elapsed < 1.0
    assert record.captured == b""
    assert record.accepts == 1
    assert record.eof_kind == "fin"
    assert record.raw_in
    assert_tls_records(record.raw_in)


def test_trust_matrix_refused_tcp_gives_connect_failed(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    closed_address = refused_tcp_address()

    with asserting_upstream_adapter(monkeypatch, endpoint, closed_address):
        admission = build_admission(routed)
        digest = connector.prepare(routed)
        with pytest.raises(UpstreamError) as caught:
            connector.connect(
                admission, routed, request_digest=digest, deadline=admission.connect_deadline,
            )

    assert caught.value.code == "connect_failed"


def test_trust_matrix_ignores_process_level_openssl_env_vars(
    monkeypatch, upstream_tls_material, tmp_path,
):
    endpoint = synthetic_endpoint(upstream_tls_material)
    other_ca_path = upstream_tls_material.directory / "other-ca.pem"
    keylog = tmp_path / "keylog.txt"
    monkeypatch.setenv("SSL_CERT_FILE", str(other_ca_path))
    monkeypatch.setenv("SSL_CERT_DIR", str(upstream_tls_material.directory))
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))

    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed = routed_issue_get()
    body = ok_issue_get_body()
    with synthetic_upstream(upstream_tls_material, respond=_ok_response_bytes(body)) as (
        record, address,
    ), asserting_upstream_adapter(monkeypatch, endpoint, address):
        admission, _digest, channel = connect_real(connector, routed)
        channel.send(deadline=admission.exchange_deadline)
        response = channel.receive(deadline=admission.exchange_deadline)
        channel.close()
    assert response == ParsedResponse(status=200, body=body)
    assert_tls_records(record.raw_in)

    connector2 = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    routed2 = routed_issue_get()
    with (
        synthetic_upstream(upstream_tls_material, leaf="other-signed") as (record2, address2),
        asserting_upstream_adapter(monkeypatch, endpoint, address2),
    ):
        admission2 = build_admission(routed2)
        digest2 = connector2.prepare(routed2)
        with pytest.raises(UpstreamError) as caught:
            connector2.connect(
                admission2, routed2, request_digest=digest2,
                deadline=admission2.connect_deadline,
            )
    assert caught.value.code == "upstream_tls_failed"
    assert record2.captured == b""
    assert record2.accepts == 1
    assert record2.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record2.raw_in)
    assert not keylog.exists()


def test_two_connects_build_two_fresh_contexts(monkeypatch, upstream_tls_material):
    endpoint = synthetic_endpoint(upstream_tls_material)
    connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    contexts = []
    original_build_context = fu._build_context

    def spy(ca_pem, trust_sha256):
        context = original_build_context(ca_pem, trust_sha256)
        contexts.append(context)
        return context
    monkeypatch.setattr(fu, "_build_context", spy)

    for _ in range(2):
        routed = routed_issue_get()
        body = ok_issue_get_body()
        with (
            synthetic_upstream(upstream_tls_material, respond=_ok_response_bytes(body)) as (
                record, address,
            ),
            asserting_upstream_adapter(monkeypatch, endpoint, address),
        ):
            admission, _digest, channel = connect_real(connector, routed, deadline_from_now=2.0)
            channel.send(deadline=admission.exchange_deadline)
            channel.receive(deadline=admission.exchange_deadline)
            channel.close()
        assert_tls_records(record.raw_in)

    assert len(contexts) == 2
    assert contexts[0] is not contexts[1]


# === Composition: serve_one with the real connector, wrapped in AssertingConnector =


@contextmanager
def composition_stack(monkeypatch, upstream_tls_material, service_tls_material, endpoint,
                      gate, policy, connector, **upstream_kwargs):
    # ``ephemeral_listener`` must be entered first: it installs its own fixed-port
    # redirecting ``FixtureSocket``, which the upstream adapter's own ``FixtureSocket``
    # then layers on top of (its ``bind`` override would otherwise break the
    # listener's own bind, which runs while opening it).
    try:
        with (
            tls_fixtures.ephemeral_listener(monkeypatch, service_tls_material, SERVICE) as (
                listener, _addr,
            ),
            synthetic_upstream(upstream_tls_material, **upstream_kwargs) as (record, address),
            asserting_upstream_adapter(monkeypatch, endpoint, address) as adapter,
            serve_one_exchange(
                listener, gate=gate, policy=policy, upstream=connector,
            ) as (outcomes, completed),
        ):
            yield record, adapter, outcomes, completed
    finally:
        # ``ephemeral_listener`` (an existing, unmodified test module) relies on
        # ``monkeypatch`` reverting only at test-function end; several cases here
        # open it more than once per test, so restore ``socket.socket`` immediately
        # or the next call's ``FixtureSocket`` layers on a stale, address-specific one.
        socket.socket = _ORIGINAL_SOCKET


@contextmanager
def unreached_upstream():
    """A listener no denial may reach; on exit it counts every connection that arrived."""
    listener = _ORIGINAL_SOCKET(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    record = UpstreamRecord()
    try:
        yield record, listener.getsockname()
    finally:
        listener.setblocking(False)
        try:
            while True:
                stray, _peer = listener.accept()
                stray.close()
                record.accepts += 1
        except BlockingIOError:
            pass
        listener.close()


@contextmanager
def denial_composition_stack(monkeypatch, service_tls_material, endpoint, gate, policy,
                             connector):
    """The adapter redirects the endpoint to a listener these cases must never reach."""
    try:
        with (
            tls_fixtures.ephemeral_listener(monkeypatch, service_tls_material, SERVICE) as (
                listener, _addr,
            ),
            unreached_upstream() as (record, address),
            asserting_upstream_adapter(monkeypatch, endpoint, address) as adapter,
            serve_one_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
                outcomes, completed,
            ),
        ):
            yield record, adapter, outcomes, completed
    finally:
        socket.socket = _ORIGINAL_SOCKET


def run_denial(monkeypatch, base, service_tls_material, endpoint, gate, policy, connector,
               wire, *, wait=3.0):
    """One denied or closed request: zero adapter attempts and zero fixture accepts."""
    with denial_composition_stack(
        monkeypatch, service_tls_material, endpoint, gate, policy, connector,
    ) as (record, adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(wait)
    assert adapter.attempts == []
    assert record.accepts == 0
    return data, outcomes[0]


def independent_v2_digest(material, routed, *, ca="upstream-ca"):
    """Rule v2 recomputed from the fixture PEM's DER digests, outside the module."""
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", material.ca_pem[ca],
        re.DOTALL,
    )
    trust = sorted(hashlib.sha256(base64.b64decode("".join(b.split()))).hexdigest() for b in blocks)
    endpoint_digest = tagged_digest("maoi.forwarder.upstream-endpoint.v1", {
        "address": _ENDPOINT_ADDRESS, "base_path": "/rest/api/3/", "credential_id": _CREDENTIAL_ID,
        "credential_profile": "basic", "endpoint_policy": "synthetic-only.v1",
        "host": _ENDPOINT_HOST, "port": 443, "revision": "upstream-r1",
        "schema": "maoi.forwarder.upstream-endpoint.v1", "service": "jira",
        "tls_profile": "maoi.forwarder.upstream-tls.v1", "trust_sha256": trust,
        "wire_profile": "maoi.forwarder.upstream-wire.v1",
    })
    upstream = routed.upstream
    return tagged_digest("maoi.forwarder.request.v2", {
        "v": 2, "service": routed.service, "route_id": routed.route_id,
        "policy_digest": routed.policy_digest, "scope_digest": routed.scope_digest,
        "endpoint_digest": endpoint_digest, "method": upstream.method, "target": upstream.target,
        "authority": _ENDPOINT_HOST, "accept": upstream.accept,
        "content_type": upstream.content_type, "body_bytes": len(upstream.body),
        "body_sha256": hashlib.sha256(upstream.body).hexdigest() if upstream.body else None,
    })


def assert_not_dispatched(ledger, outcome, reason, digest):
    receipt = ledger_entry(ledger, outcome.receipt_id)
    assert (receipt["dispatch_state"], receipt["reason"]) == ("NOT_DISPATCHED", reason)
    assert receipt["request_digest"] == digest


def test_composition_issue_get_success(monkeypatch, upstream_tls_material, service_tls_material):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    body = ok_issue_get_body()

    probe = {}

    def on_first_byte():
        entries = gate.ledger.snapshot()["entries"]
        probe["entry_state"] = entries[0]["entry_state"] if entries else None
        probe["flight_phase"] = flight_phase(gate, grant.lease_id)

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, respond=_ok_response_bytes(body), on_first_byte=on_first_byte,
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    parsed = parse_response(data)
    assert parsed == ParsedResponse(status=200, body=body)

    receipt = ledger_entry(ledger, outcome.receipt_id)
    independent_digest = real_connector.prepare(routed_issue_get())
    assert receipt["request_digest"] == independent_digest
    assert independent_digest == independent_v2_digest(upstream_tls_material, routed_issue_get())
    assert receipt["request_digest"] != GOLDEN_ISSUE_GET_V1_DIGEST
    assert receipt["request_bytes"] == len(wire)
    assert len(record.captured) == GOLDEN_ISSUE_GET_WIRE_LEN
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_ISSUE_GET_WIRE_SHA256

    assert connector.prepare_calls == 1
    assert connector.connect_calls == 1
    assert probe["entry_state"] == "dispatched"
    assert probe["flight_phase"] == "writing"

    sentinel_b64 = base64.b64encode(f"run:{grant.sentinel}".encode())
    assert grant.sentinel.encode() not in record.captured
    assert f"run:{grant.sentinel}".encode() not in record.captured
    assert sentinel_b64 not in record.captured
    assert b"forwarder-jira.maoi.local:17441" not in record.captured
    assert b"User-Agent" not in record.captured
    assert_tls_records(record.raw_in)


def test_composition_search_success_with_whitespace_and_reordering(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    body = canonical_json({"jql": SEARCH_JQL})
    # Whitespace padding and reordered members: RoutePolicy always renders the
    # upstream body from the matched template, never the caller's raw bytes.
    padded = b'{ "maxResults" : 50 , "jql" : ' + body.split(b'"jql":')[1][:-1] + b" }"
    wire = raw_post(SERVICE, grant.sentinel, "/rest/api/3/search/jql", padded)
    response_body = ok_search_body()

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, respond=_ok_response_bytes(response_body),
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    assert parse_response(data) == ParsedResponse(status=200, body=response_body)
    assert len(record.captured) == GOLDEN_SEARCH_WIRE_LEN
    assert hashlib.sha256(record.captured).hexdigest() == GOLDEN_SEARCH_WIRE_SHA256
    assert_tls_records(record.raw_in)


def test_composition_sni_callback_revocation_denies_at_the_fence(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    def on_sni():
        registry.revoke(
            lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
            reason="operator_cancel",
        )

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, on_sni=on_sni,
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "connect_failed"
    assert_local(data, "upstream_failed")
    assert record.captured == b""
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)
    assert connector.connect_calls == 1
    assert gate.closeout(grant.lease_id).closeout_state == "quiescent"

    # The public dispatch_state/reason pair above ("FAILED"/"connect_failed") is
    # produced both by a genuine E10 connect failure (connect() itself raises, no
    # channel is ever built) and by an E12 fence denial (connect() succeeds -- the
    # revoke lands only in the *inbound* registry, so it never disturbs the outbound
    # TLS handshake -- and the dispatch layer's admission fence then refuses to write
    # before any bytes go out). ``record.eof_kind == "fin"`` above is itself evidence
    # for the E12 case (a real, cleanly shut-down TLS connection, not a mid-handshake
    # abort), but only the channel-level counters can say so unambiguously: connect()
    # must have returned a real channel, it must never have been asked to send, and it
    # must have been aborted rather than simply dropped.
    assert len(connector.channels) == 1, "connect() must have returned a channel (E12, not E10)"
    channel = connector.channels[0]
    assert channel.send_calls == 0
    assert channel.abort_calls >= 1


def test_composition_revocation_after_full_request_still_delivers_ok(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    body = ok_issue_get_body()

    def on_request():
        registry.revoke(
            lease_id=grant.lease_id, receiver_boot_id=BOOT, generation=registry.generation,
            reason="operator_cancel",
        )

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, respond=_ok_response_bytes(body), on_request=on_request,
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "ok"
    assert parse_response(data) == ParsedResponse(status=200, body=body)
    assert registry.snapshot()["leases"][0]["state"] == "revoked"
    assert_tls_records(record.raw_in)


@pytest.mark.parametrize("status,body,expected_class", [
    (404, b'{"errorMessages":[]}', "4xx"),
], ids=["404"])
def test_composition_upstream_4xx_gives_response_rejected(
    monkeypatch, upstream_tls_material, service_tls_material, status, body, expected_class,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, respond=_ok_response_bytes(body, status),
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "TRANSPORT_CONFIRMED"
    assert outcome.reason == "response_policy_rejected"
    assert_local(data, "response_rejected")
    entry = ledger_entry(ledger, outcome.receipt_id)
    assert entry["http_status_class"] == expected_class
    assert_tls_records(record.raw_in)


def test_composition_upstream_redirect_gives_receive_failed(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    redirect = (
        b"HTTP/1.1 302 Found\r\nLocation: https://attacker.invalid/x\r\n"
        b"Content-Length: 0\r\n\r\n"
    )

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, respond=redirect, allow_reset=True,
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "receive_failed"
    assert_local(data, "upstream_unknown")
    assert b"Location" not in data
    assert b"attacker" not in data
    assert_tls_records(record.raw_in)


def test_composition_stall_gives_receive_failed_before_dispatch_deadline(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    monkeypatch.setattr(frr, "_INACTIVITY_LIMIT", 0.5)
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=4.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    dispatch_deadline = time.monotonic() + 4.0

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, head_then_stall=True,
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire, timeout=6.0)
        assert completed.wait(6.0)

    assert time.monotonic() < dispatch_deadline
    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "receive_failed"
    assert_local(data, "upstream_unknown")
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)


def test_composition_shutdown_during_a_stall_gives_receive_failed(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=20.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    request_seen = threading.Event()

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, head_then_stall=True, on_request=request_seen.set,
    ) as (record, _adapter, outcomes, completed):
        data = None

        def run_client():
            nonlocal data
            data = roundtrip(base, wire, timeout=6.0)
        client_thread = threading.Thread(target=run_client, daemon=True)
        client_thread.start()

        # Shut down only once the fixture holds the full request, so the abort
        # always lands during receive rather than racing the write.
        assert request_seen.wait(3.0)
        t0 = time.monotonic()
        report = gate.shutdown()
        client_thread.join(6.0)
        assert not client_thread.is_alive()
        elapsed = time.monotonic() - t0
        assert completed.wait(1.0)

    assert elapsed < 1.0
    assert report.aborted == 1
    outcome = outcomes[0]
    assert outcome.dispatch_state == "DISPATCHED_UNKNOWN"
    assert outcome.reason == "receive_failed"
    assert_local(data, "upstream_unknown")
    assert record.eof_kind == "fin"
    assert_tls_records(record.raw_in)

    # The gate is now closed: the next request gets 403 with zero adapter attempts.
    second_wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    second_data, second_outcome = run_denial(
        monkeypatch, base, service_tls_material, endpoint, gate, policy, connector, second_wire,
    )
    assert second_outcome.reason == "lease_denied"
    assert parse_response(second_data).status == 403


@pytest.mark.parametrize("leaf", ["wrong-name"])
def test_composition_upstream_tls_failure_gives_failed_with_zero_bytes(
    monkeypatch, upstream_tls_material, service_tls_material, leaf,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    with composition_stack(
        monkeypatch, upstream_tls_material, service_tls_material, endpoint, gate, policy,
        connector, leaf=leaf,
    ) as (record, _adapter, outcomes, completed):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "upstream_tls_failed"
    assert_local(data, "upstream_failed")
    assert record.captured == b""
    assert record.eof_kind in REFUSAL_EOF_KINDS
    assert_tls_records(record.raw_in)


def test_composition_refused_tcp_gives_failed_connect_failed(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, _ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    closed_address = refused_tcp_address()

    with (
        tls_fixtures.ephemeral_listener(
            monkeypatch, service_tls_material, SERVICE,
        ) as (listener, _addr),
        asserting_upstream_adapter(monkeypatch, endpoint, closed_address),
        serve_one_exchange(listener, gate=gate, policy=policy, upstream=connector) as (
            outcomes, completed,
        ),
    ):
        data = roundtrip(base, wire)
        assert completed.wait(5)

    outcome = outcomes[0]
    assert outcome.dispatch_state == "FAILED"
    assert outcome.reason == "connect_failed"
    assert_local(data, "upstream_failed")


def test_composition_denials_touch_neither_adapter_nor_fixture(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()

    def denial(connector, wire, *, wait=3.0):
        return run_denial(
            monkeypatch, base, service_tls_material, endpoint, gate, policy, connector, wire,
            wait=wait,
        )

    # upstream=None: the unavailability proof.
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")
    data, outcome = denial(None, wire)
    assert parse_response(data).status == 403
    assert_not_dispatched(ledger, outcome, "route_denied", DENIAL_DIGEST_ISSUE_GET)

    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    connector = AssertingConnector(real_connector, gate)

    # An unknown sentinel: EOF, zero prepare/connect, no ledger entry.
    entries_before = len(ledger.snapshot()["entries"])
    unknown_wire = raw_get(SERVICE, "s" * 43, "/rest/api/3/issue/SYN-1")
    data2, outcome2 = denial(connector, unknown_wire)
    assert data2 == b""
    assert outcome2.reason == "sentinel_unknown"
    assert len(ledger.snapshot()["entries"]) == entries_before
    assert connector.prepare_calls == 0
    assert connector.connect_calls == 0

    # SYN-2 is out of scope: route_denied, zero prepare.
    grant2, _entry2 = install_lease(gate, registry, ttl=10.0, run_id="run-2")
    syn2_wire = raw_get(SERVICE, grant2.sentinel, "/rest/api/3/issue/SYN-2")
    data3, outcome3 = denial(connector, syn2_wire)
    assert parse_response(data3).status == 403
    assert_not_dispatched(ledger, outcome3, "route_denied", DENIAL_DIGEST_ISSUE_GET)
    assert connector.prepare_calls == 0

    # A fields subset: 400 request_rejected, zero prepare.
    grant3, _entry3 = install_lease(gate, registry, ttl=10.0, run_id="run-3")
    subset_wire = raw_get(
        SERVICE, grant3.sentinel, "/rest/api/3/issue/SYN-1?fields=issuetype,labels",
    )
    data4, outcome4 = denial(connector, subset_wire)
    assert parse_response(data4).status == 400
    assert_not_dispatched(ledger, outcome4, "request_rejected", DENIAL_DIGEST_ISSUE_GET)
    assert connector.prepare_calls == 0

    # A lease with 1.5s left: one prepare, then 504 deadline, zero connect.
    grant4, entry4 = install_lease(gate, registry, ttl=1.5, run_id="run-4")
    short_wire = raw_get(SERVICE, grant4.sentinel, "/rest/api/3/issue/SYN-1")
    data5, outcome5 = denial(connector, short_wire, wait=1.4)
    assert parse_response(data5).status == 504
    run4_routed = routed_issue_get(golden_manifest(run_id="run-4"))
    v2_digest = independent_v2_digest(upstream_tls_material, run4_routed)
    assert_not_dispatched(ledger, outcome5, "deadline", v2_digest)
    assert v2_digest == real_connector.prepare(run4_routed)
    assert connector.prepare_calls == 1
    assert connector.connect_calls == 0
    assert time.monotonic() < entry4.expires_at


def test_composition_unbuildable_request_denies_at_e7c(
    monkeypatch, upstream_tls_material, service_tls_material,
):
    base, _paths = service_tls_material
    endpoint = synthetic_endpoint(upstream_tls_material)
    real_connector = JiraUpstreamConnector(endpoint=endpoint, credential=synthetic_credential())
    gate, registry, ledger = new_real_system()
    policy = policy_with_golden()
    grant, _entry = install_lease(gate, registry, ttl=10.0)
    connector = AssertingConnector(real_connector, gate)
    wire = raw_get(SERVICE, grant.sentinel, "/rest/api/3/issue/SYN-1")

    oversized = routed_issue_get()
    prefix = "/rest/api/3/issue/90101?fields="
    names = ["summary"]
    while len(prefix) + len("%2C".join(names)) <= 2033:
        names.append("summary")
    target = prefix + "%2C".join(names)
    assert len(target) <= 2048  # still v1-valid; only the wire bound (2,048) is exceeded
    new_upstream = dataclasses.replace(oversized.upstream, target=target)
    new_digest = fr.request_digest(
        service="jira", route_id="jira.issue.get", policy_digest=oversized.policy_digest,
        scope_digest=oversized.scope_digest, upstream=new_upstream,
    )
    oversized = dataclasses.replace(oversized, upstream=new_upstream, request_digest=new_digest)
    monkeypatch.setattr(RoutePolicy, "route", lambda self, request, manifest: oversized)
    with pytest.raises(fu.UpstreamPrepareError) as raised:
        real_connector.prepare(oversized)
    assert raised.value.code == "request_unbuildable"

    data, outcome = run_denial(
        monkeypatch, base, service_tls_material, endpoint, gate, policy, connector, wire,
    )
    assert parse_response(data).status == 403
    assert_not_dispatched(ledger, outcome, "route_denied", DENIAL_DIGEST_ISSUE_GET)
    assert connector.prepare_calls == 1
    assert connector.connect_calls == 0


# === T3: 50 concurrent abort/close pairs, fd and warning hygiene =================


def test_fifty_concurrent_abort_close_pairs_leave_fds_closed_and_warn_free(
    upstream_tls_material,
):
    """Plan O5/O6: 50 concurrent abort/close pairs end with ``fileno() == -1``
    and raise no ``ResourceWarning`` -- a channel that skipped closing its
    socket, or left an aborted one's fd open, would leak an open fd, which
    warns on GC.
    """
    import gc
    import warnings

    endpoint = synthetic_endpoint(upstream_tls_material)
    credential = synthetic_credential()
    pairs = 50

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(pairs):
            client_secured, server_secured = tls_socketpair(
                upstream_tls_material, endpoint, credential,
            )
            parts = _search_parts_with_body(endpoint.host, 16)
            channel = fu._UpstreamChannel(
                fu._CHANNEL_TOKEN, sock=client_secured, parts=parts, credential=credential,
                exchange_deadline=time.monotonic() + 5.0,
            )
            barrier = threading.Barrier(2)

            def do_close(barrier=barrier, channel=channel):
                barrier.wait(2.0)
                channel.close()

            def do_abort(barrier=barrier, channel=channel):
                barrier.wait(2.0)
                channel.abort()

            ta = threading.Thread(target=do_close, daemon=True)
            tb = threading.Thread(target=do_abort, daemon=True)
            ta.start()
            tb.start()
            ta.join(2.0)
            tb.join(2.0)
            assert not ta.is_alive()
            assert not tb.is_alive()

            assert client_secured.fileno() == -1
            server_secured.close()

        gc.collect()

    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == [], [str(w.message) for w in resource_warnings]
