"""Synthetic fixed-origin Jira upstream connector: endpoint, credential and wire.

This is the trusted ``UpstreamConnector`` for ``jira.issue.get`` and
``jira.search``. It validates an operator endpoint shape and adopts one
redacted Basic credential bound to ``jira``/``basic``. It computes the
endpoint digest and the rule-v2 request digest as pure functions, and renders
the credential-free parts of the canonical request as a pure function: a
successful ``prepare`` implies a successful ``render_parts``. It opens one
fresh, strictly verified TLS connection per request to an operator-pinned
IPv4 literal -- there is no DNS, and connect writes zero application bytes.
The channel writes the request exactly once, after the 13a fence; it reads
only through ``receive_response``; it aborts and closes thread-safely.

Every production route stays unavailable: ``ENDPOINT_POLICY`` accepts only a
synthetic RFC 6761 ``.invalid`` host on an RFC 5737 documentation address,
there is no configuration or credential loader, and ``UpstreamEndpoint``/
``BasicCredential`` are filled only in memory, by tests.

The module-1 error discipline applies: an ``except`` block only records a
fixed code, and a fresh error is raised once the ``try`` statement has ended,
with ``from None``; nothing caught here is ever re-raised.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import math
import re
import socket
import ssl
import threading
import time
import weakref
from dataclasses import dataclass, field
from types import MappingProxyType

from .forwarder_dispatch import CONNECT_SECONDS, WRITE_SECONDS, Admission
from .forwarder_exchange import UpstreamError
from .forwarder_http_response import ParsedResponse
from .forwarder_json import tagged_digest
from .forwarder_response_receive import ResponseReceiveError, receive_response
from .forwarder_routes import (
    JIRA_READABLE_SYSTEM_FIELDS,
    MAX_REQUEST_JSON_BYTES,
    ROUTE_CATALOG,
    RouteConfigError,
    RoutedRequest,
    UpstreamRequest,
)
from .forwarder_routes import request_digest as _v1_request_digest

# --- schemas, tags and profiles ------------------------------------------------

ENDPOINT_SCHEMA = "maoi.forwarder.upstream-endpoint.v1"
ENDPOINT_POLICY = "synthetic-only.v1"
REQUEST_DIGEST_V2_TAG = "maoi.forwarder.request.v2"
TLS_PROFILE = "maoi.forwarder.upstream-tls.v1"
WIRE_PROFILE = "maoi.forwarder.upstream-wire.v1"
UPSTREAM_BASE_PATH = "/rest/api/3/"
CREDENTIAL_PROFILES = MappingProxyType({"jira": "basic"})


@dataclass(frozen=True)
class RequestShape:
    method: str
    target_pattern: str
    content_type: str | None


DISPATCHABLE_SHAPES = MappingProxyType({
    "jira.issue.get": RequestShape(
        "GET", r"/rest/api/3/issue/[1-9][0-9]{0,17}\?fields=[a-z]+(?:%2C[a-z]+)*", None,
    ),
    "jira.search": RequestShape("POST", r"/rest/api/3/search/jql", "application/json"),
})

# --- closed origin gate (spec L441-448) ----------------------------------------

SYNTHETIC_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
DENIED_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)

# --- size bounds ----------------------------------------------------------------

MAX_TRUST_PEM_BYTES = 131_072
MAX_TRUST_CERTIFICATES = 16
MAX_REQUEST_LINE_BYTES = 2_048
MAX_REQUEST_HEAD_BYTES = 16_384
MAX_REQUEST_BODY_BYTES = 262_144
MAX_WRITE_CHUNK_BYTES = 16_384
MAX_AUTHORIZATION_BYTES = 2_048
CHANNEL_STATES = (
    "open", "sending", "sent", "receiving", "received", "failed", "aborted", "closed",
)

# --- private constants ------------------------------------------------------

_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x0004_0000
_CHANNEL_SOCKET_TYPE = ssl.SSLSocket
_CHANNEL_TOKEN = object()
_CLAIM_LOCK = threading.Lock()

# --- closed codes and errors -----------------------------------------------

UPSTREAM_CONFIG_CODES = frozenset({
    "endpoint_invalid", "trust_invalid", "endpoint_unqualified",
    "credential_invalid", "credential_mismatch", "credential_claimed",
})
UPSTREAM_PREPARE_CODES = frozenset({
    "shape_unavailable", "request_inconsistent", "request_unbuildable",
})


class UpstreamConfigError(ValueError):
    """A fixed, non-diagnostic operator-configuration rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class UpstreamPrepareError(ValueError):
    """A fixed, non-diagnostic pure-preparation rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


# --- grammar -----------------------------------------------------------------

_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_ID_GRAMMAR = re.compile(r"[A-Za-z0-9._-]{1,128}")
_HOST_GRAMMAR = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_DOTTED_QUAD = re.compile(
    r"((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
)
_AUTHORITY_PORT = re.compile(r"[1-9][0-9]{0,4}")
_USER_GRAMMAR = re.compile(r"[\x21-\x39\x3b-\x7e]{1,256}")
_TOKEN_GRAMMAR = re.compile(r"[\x21-\x7e]{1,1024}")

# A source string byte-identical to forwarder_tls._PEM_BUNDLE.pattern (parity test).
_PEM_BUNDLE = re.compile(
    r"(?:-----BEGIN CERTIFICATE-----\r?\n"
    r"(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+"
    r"-----END CERTIFICATE-----\r?\n?)+\Z"
)
_PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----")
_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/]{1,64}={0,2}\r?\n)+"
    r"-----END CERTIFICATE-----\r?\n?"
)


def _valid_id(value: object) -> bool:
    return type(value) is str and _ID_GRAMMAR.fullmatch(value) is not None


def _valid_host(value: object) -> bool:
    return (
        type(value) is str
        and _HOST_GRAMMAR.fullmatch(value) is not None
        and value != "localhost"
        and not value.endswith(".localhost")
        and not value.endswith(".local")
    )


def _valid_address(value: object) -> ipaddress.IPv4Address | None:
    if type(value) is not str or _DOTTED_QUAD.fullmatch(value) is None:
        return None
    parsed = None
    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value:
        return None
    return parsed


def _valid_authority(value: object) -> bool:
    if type(value) is not str:
        return False
    host, sep, port_text = value.rpartition(":")
    if not sep:
        return _valid_host(value)
    if not _valid_host(host) or _AUTHORITY_PORT.fullmatch(port_text) is None:
        return False
    port = int(port_text)
    return port <= 65535 and port != 443


def _valid_hex64(value: object) -> bool:
    return type(value) is str and _HEX64_RE.fullmatch(value) is not None


def _finite(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _read_clock() -> float | None:
    """``time.monotonic()``, or ``None`` for a faulting or non-finite clock."""
    try:
        observed = time.monotonic()
    except Exception:  # noqa: BLE001 - a failed clock cannot establish a deadline.
        return None
    return float(observed) if _finite(observed) else None


def _valid_trust_tuple(value: object) -> bool:
    if type(value) is not tuple or not 1 <= len(value) <= MAX_TRUST_CERTIFICATES:
        return False
    if any(not _valid_hex64(item) for item in value):
        return False
    return all(value[index] < value[index + 1] for index in range(len(value) - 1))


def _valid_target_text(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("/")
        and " " not in value
        and "#" not in value
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _valid_header_text(value: object) -> bool:
    return (
        type(value) is str
        and len(value) > 0
        and " " not in value
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


# --- endpoint core validation (steps 1-6) --------------------------------------


def _validate_endpoint_core(
    *, service: object, revision: object, host: object, address: object,
    port: object, credential_id: object,
) -> ipaddress.IPv4Address:
    if (
        type(service) is not str or type(revision) is not str or type(host) is not str
        or type(address) is not str or type(credential_id) is not str
        or type(port) is not int
    ):
        raise UpstreamConfigError("endpoint_invalid")
    if service not in CREDENTIAL_PROFILES:
        raise UpstreamConfigError("endpoint_invalid")
    if not _valid_id(revision) or not _valid_id(credential_id):
        raise UpstreamConfigError("endpoint_invalid")
    if not _valid_host(host):
        raise UpstreamConfigError("endpoint_invalid")
    parsed_address = _valid_address(address)
    if parsed_address is None:
        raise UpstreamConfigError("endpoint_invalid")
    if any(parsed_address in network for network in DENIED_NETWORKS):
        raise UpstreamConfigError("endpoint_invalid")
    if (
        parsed_address.is_loopback or parsed_address.is_link_local
        or parsed_address.is_multicast or parsed_address.is_reserved
        or parsed_address.is_unspecified
    ):
        raise UpstreamConfigError("endpoint_invalid")
    if not 1 <= port <= 65535:
        raise UpstreamConfigError("endpoint_invalid")
    return parsed_address


def endpoint_document(
    *, service: object, revision: object, host: object, address: object, port: object,
    trust_sha256: object, credential_id: object,
) -> dict:
    """The pure v1 endpoint document; the same field checks as the endpoint."""
    parsed_address = _validate_endpoint_core(
        service=service, revision=revision, host=host, address=address,
        port=port, credential_id=credential_id,
    )
    if not _valid_trust_tuple(trust_sha256):
        raise UpstreamConfigError("trust_invalid")
    qualified = host.endswith(".invalid") and any(
        parsed_address in network for network in SYNTHETIC_NETWORKS
    )
    if not qualified:
        raise UpstreamConfigError("endpoint_unqualified")
    return {
        "address": address,
        "base_path": UPSTREAM_BASE_PATH,
        "credential_id": credential_id,
        "credential_profile": CREDENTIAL_PROFILES[service],
        "endpoint_policy": ENDPOINT_POLICY,
        "host": host,
        "port": port,
        "revision": revision,
        "schema": ENDPOINT_SCHEMA,
        "service": service,
        "tls_profile": TLS_PROFILE,
        "trust_sha256": list(trust_sha256),
        "wire_profile": WIRE_PROFILE,
    }


# --- trust bundle (step 7) -------------------------------------------------


def _check_trust_grammar(ca_pem: object) -> None:
    """Steps 7.1-7.3: type/size, grammar, block count. White-box, for parity."""
    if type(ca_pem) is not str or not ca_pem or len(ca_pem) > MAX_TRUST_PEM_BYTES:
        raise UpstreamConfigError("trust_invalid")
    if _PEM_BUNDLE.fullmatch(ca_pem) is None:
        raise UpstreamConfigError("trust_invalid")
    if len(_PEM_CERTIFICATE.findall(ca_pem)) > MAX_TRUST_CERTIFICATES:
        raise UpstreamConfigError("trust_invalid")


def _trust_digest_tuple(ca_pem: str) -> tuple[str, ...]:
    """Step 7.4: per-block DER SHA-256, sorted and unique (a deliberate difference)."""
    blocks = _PEM_BLOCK.findall(ca_pem)
    digests: list[str] = []
    failed = False
    try:
        for block in blocks:
            der = ssl.PEM_cert_to_DER_cert(block)
            digests.append(hashlib.sha256(der).hexdigest())
    except (ValueError, TypeError):
        failed = True
    if failed:
        raise UpstreamConfigError("trust_invalid") from None
    if len(set(digests)) != len(digests):
        raise UpstreamConfigError("trust_invalid")
    return tuple(sorted(digests))


# --- TLS context (step 7.5) -------------------------------------------------


def _verify_context_readback(context: ssl.SSLContext, trust_sha256: tuple[str, ...]) -> None:
    ok = (
        ssl.HAS_SNI is True
        and ssl.HAS_ALPN is True
        and context.protocol == ssl.PROTOCOL_TLS_CLIENT
        and context.verify_mode == ssl.CERT_REQUIRED
        and context.check_hostname is True
        and context.hostname_checks_common_name is False
        and context.minimum_version == ssl.TLSVersion.TLSv1_2
        and context.maximum_version in (
            ssl.TLSVersion.MAXIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
        )
        and context.verify_flags == (ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_TRUSTED_FIRST)
        and (context.options & ssl.OP_NO_COMPRESSION) == ssl.OP_NO_COMPRESSION
        and (context.options & ssl.OP_NO_RENEGOTIATION) == ssl.OP_NO_RENEGOTIATION
        and (context.options & ssl.OP_NO_TICKET) == ssl.OP_NO_TICKET
        and (context.options & ssl.OP_IGNORE_UNEXPECTED_EOF) == 0
        # ssl names it from Python 3.12; 0x4 is OpenSSL's SSL_OP_LEGACY_SERVER_CONNECT on 3.11.
        and (context.options & getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)) == 0
        and (context.options & _OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION) == 0
        and context.keylog_filename is None
        and context.post_handshake_auth is False
    )
    if not ok:
        raise ValueError("context_readback_failed")
    store = context.cert_store_stats()
    x509 = store.get("x509")
    x509_ca = store.get("x509_ca")
    if (
        type(x509) is not int or type(x509_ca) is not int
        or x509 != x509_ca or x509 != len(trust_sha256)
    ):
        raise ValueError("context_readback_failed")
    observed = tuple(
        sorted(hashlib.sha256(der).hexdigest() for der in context.get_ca_certs(binary_form=True))
    )
    if observed != tuple(trust_sha256):
        raise ValueError("context_readback_failed")


def _build_context(ca_pem: str, trust_sha256: tuple[str, ...]) -> ssl.SSLContext:
    """The module's only ``ssl.SSLContext(...)`` call site."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.verify_flags = ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_TRUSTED_FIRST
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_TICKET
    context.set_alpn_protocols(["http/1.1"])
    context.load_verify_locations(cadata=ca_pem)
    _verify_context_readback(context, trust_sha256)
    return context


def _verify_post_handshake(secured: ssl.SSLSocket) -> None:
    if secured.version() not in ("TLSv1.2", "TLSv1.3"):
        raise ValueError("upstream_tls_failed")
    if secured.selected_alpn_protocol() not in (None, "http/1.1"):
        raise ValueError("upstream_tls_failed")
    if secured.compression() is not None:
        raise ValueError("upstream_tls_failed")
    if secured.session_reused is not False:
        raise ValueError("upstream_tls_failed")
    peer = secured.getpeercert(binary_form=True)
    if type(peer) is not bytes or not peer:
        raise ValueError("upstream_tls_failed")


# --- endpoint canonical bytes (no json import; a hand-rolled encoder) ----------


def _encode_json_string(value: str) -> str:
    # Only validated printable ASCII may reach here; anything else would diverge from JSON.
    if not value.isascii() or not value.isprintable():
        raise UpstreamConfigError("endpoint_invalid")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


def _endpoint_canonical_bytes(document: dict) -> bytes:
    members = (
        ("address", document["address"], "str"),
        ("base_path", document["base_path"], "str"),
        ("credential_id", document["credential_id"], "str"),
        ("credential_profile", document["credential_profile"], "str"),
        ("endpoint_policy", document["endpoint_policy"], "str"),
        ("host", document["host"], "str"),
        ("port", document["port"], "int"),
        ("revision", document["revision"], "str"),
        ("schema", document["schema"], "str"),
        ("service", document["service"], "str"),
        ("tls_profile", document["tls_profile"], "str"),
        ("trust_sha256", document["trust_sha256"], "list"),
        ("wire_profile", document["wire_profile"], "str"),
    )
    rendered = []
    for key, value, kind in members:
        if kind == "int":
            encoded_value = str(value)
        elif kind == "list":
            encoded_value = "[" + ",".join(_encode_json_string(item) for item in value) + "]"
        else:
            encoded_value = _encode_json_string(value)
        rendered.append(_encode_json_string(key) + ":" + encoded_value)
    return ("{" + ",".join(rendered) + "}").encode("ascii")


# --- UpstreamEndpoint -----------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class UpstreamEndpoint:
    service: str
    revision: str
    host: str
    address: str
    port: int
    ca_pem: str = field(repr=False)
    credential_id: str
    _trust_sha256: tuple[str, ...] = field(init=False, repr=False, compare=False)
    _document: dict = field(init=False, repr=False, compare=False)
    _canonical: bytes = field(init=False, repr=False, compare=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.ca_pem) is not str:
            raise UpstreamConfigError("endpoint_invalid")
        _validate_endpoint_core(
            service=self.service, revision=self.revision, host=self.host,
            address=self.address, port=self.port, credential_id=self.credential_id,
        )
        _check_trust_grammar(self.ca_pem)
        trust_sha256 = _trust_digest_tuple(self.ca_pem)
        context_failed = False
        try:
            _build_context(self.ca_pem, trust_sha256)
        except (ssl.SSLError, ValueError, TypeError, AttributeError, OSError):
            context_failed = True
        if context_failed:
            raise UpstreamConfigError("trust_invalid") from None
        document = endpoint_document(
            service=self.service, revision=self.revision, host=self.host,
            address=self.address, port=self.port, trust_sha256=trust_sha256,
            credential_id=self.credential_id,
        )
        object.__setattr__(self, "_trust_sha256", trust_sha256)
        object.__setattr__(self, "_document", document)
        object.__setattr__(self, "_canonical", _endpoint_canonical_bytes(document))
        object.__setattr__(self, "_digest", tagged_digest(ENDPOINT_SCHEMA, document))

    @property
    def trust_sha256(self) -> tuple[str, ...]:
        return self._trust_sha256

    @property
    def authority(self) -> str:
        return self.host if self.port == 443 else f"{self.host}:{self.port}"

    @property
    def digest(self) -> str:
        return self._digest

    def document(self) -> dict:
        document = dict(self._document)
        document["trust_sha256"] = list(self._trust_sha256)
        return document

    def canonical_bytes(self) -> bytes:
        return self._canonical


# --- BasicCredential ---------------------------------------------------------


class BasicCredential:
    """A redacted, non-copyable, claim-once Basic credential for one service."""

    __slots__ = ("_authorization", "_claimed", "_credential_id", "_profile", "_service")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("BasicCredential cannot be subclassed")

    def __init__(
        self, *, service: str, profile: str, credential_id: str, user: str, token: str,
    ) -> None:
        # A second __init__ would reset the claim and swap the secret under a connector.
        initialized = True
        try:
            object.__getattribute__(self, "_claimed")
        except AttributeError:
            initialized = False
        if initialized:
            del user, token
            raise AttributeError("BasicCredential is immutable")
        types_ok = (
            type(service) is str and type(profile) is str and type(credential_id) is str
            and type(user) is str and type(token) is str
        )
        service_ok = types_ok and service in CREDENTIAL_PROFILES
        profile_ok = service_ok and profile == CREDENTIAL_PROFILES[service]
        id_ok = types_ok and _ID_GRAMMAR.fullmatch(credential_id) is not None
        user_ok = types_ok and _USER_GRAMMAR.fullmatch(user) is not None
        token_ok = types_ok and _TOKEN_GRAMMAR.fullmatch(token) is not None
        bound_ok = (
            user_ok and token_ok
            and 6 + 4 * ((len(user) + 1 + len(token) + 2) // 3) <= MAX_AUTHORIZATION_BYTES
        )
        valid = service_ok and profile_ok and id_ok and user_ok and token_ok and bound_ok
        if not valid:
            del user, token
            raise UpstreamConfigError("credential_invalid") from None
        object.__setattr__(self, "_service", service)
        object.__setattr__(self, "_profile", profile)
        object.__setattr__(self, "_credential_id", credential_id)
        object.__setattr__(
            self, "_authorization",
            b"Basic " + base64.b64encode((user + ":" + token).encode("ascii")),
        )
        del user, token
        object.__setattr__(self, "_claimed", False)

    @property
    def service(self) -> str:
        return self._service

    @property
    def profile(self) -> str:
        return self._profile

    @property
    def credential_id(self) -> str:
        return self._credential_id

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("BasicCredential is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("BasicCredential is immutable")

    def _redacted(self) -> str:
        return (
            f"BasicCredential(service={self._service!r}, profile={self._profile!r}, "
            f"credential_id={self._credential_id!r}, <redacted>)"
        )

    def __repr__(self) -> str:
        return self._redacted()

    def __str__(self) -> str:
        return self._redacted()

    def __format__(self, format_spec: str) -> str:
        return self._redacted()

    def __reduce__(self) -> object:
        raise TypeError("credential_not_copyable")

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError("credential_not_copyable")

    def __getstate__(self) -> object:
        raise TypeError("credential_not_copyable")

    def __copy__(self) -> object:
        raise TypeError("credential_not_copyable")

    def __deepcopy__(self, memo: object) -> object:
        raise TypeError("credential_not_copyable")


# --- wire lengths, UpstreamDescriptor -------------------------------------------


def _wire_lengths(
    method: str, target: str, authority: str, accept: str,
    content_type: str | None, body_bytes: int,
) -> tuple[int, int, int]:
    """Pure lengths of the request line, the head (worst-case Authorization) and body."""
    request_line = len(method) + 1 + len(target) + 1 + len("HTTP/1.1") + 2
    head = len("Host: ") + len(authority) + 2
    head += 17 + MAX_AUTHORIZATION_BYTES
    head += len("Accept: ") + len(accept) + 2
    head += len("Accept-Encoding: identity") + 2
    if body_bytes > 0:
        head += len("Content-Type: ") + len(content_type) + 2
        head += len("Content-Length: ") + len(str(body_bytes)) + 2
    head += len("Connection: close") + 2
    head += 2
    return request_line, head, body_bytes


@dataclass(frozen=True)
class UpstreamDescriptor:
    service: str
    route_id: str
    policy_digest: str
    scope_digest: str
    endpoint_digest: str
    method: str
    target: str = field(repr=False)
    authority: str
    accept: str
    content_type: str | None
    body_bytes: int
    body_sha256: str | None
    body: bytes = field(repr=False)
    _document: dict = field(init=False, repr=False, compare=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        body_ok = (
            type(self.body) is bytes and type(self.body_bytes) is int
            and self.body_bytes == len(self.body)
        )
        digest_ok = (
            (self.body_sha256 is None and body_ok and self.body_bytes == 0)
            or (
                body_ok and self.body_bytes > 0
                and _valid_hex64(self.body_sha256)
                and self.body_sha256 == hashlib.sha256(self.body).hexdigest()
            )
        )
        valid = (
            type(self.service) is str and self.service in CREDENTIAL_PROFILES
            and type(self.route_id) is str and self.route_id in DISPATCHABLE_SHAPES
            and _valid_hex64(self.policy_digest)
            and _valid_hex64(self.scope_digest)
            and _valid_hex64(self.endpoint_digest)
            and type(self.method) is str
            and self.method == DISPATCHABLE_SHAPES[self.route_id].method
            and _valid_target_text(self.target)
            and _valid_authority(self.authority)
            and _valid_header_text(self.accept)
            and (self.content_type is None or _valid_header_text(self.content_type))
            and body_ok
            and digest_ok
            and (self.content_type is None) == (self.body_bytes == 0)
        )
        if not valid:
            raise UpstreamPrepareError("request_unbuildable")
        request_line, head, body_len = _wire_lengths(
            self.method, self.target, self.authority, self.accept,
            self.content_type, self.body_bytes,
        )
        if (
            request_line > MAX_REQUEST_LINE_BYTES
            or head > MAX_REQUEST_HEAD_BYTES
            or body_len > MAX_REQUEST_BODY_BYTES
        ):
            raise UpstreamPrepareError("request_unbuildable")
        document = {
            "v": 2,
            "service": self.service,
            "route_id": self.route_id,
            "policy_digest": self.policy_digest,
            "scope_digest": self.scope_digest,
            "endpoint_digest": self.endpoint_digest,
            "method": self.method,
            "target": self.target,
            "authority": self.authority,
            "accept": self.accept,
            "content_type": self.content_type,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
        }
        object.__setattr__(self, "_document", document)
        object.__setattr__(self, "_digest", tagged_digest(REQUEST_DIGEST_V2_TAG, document))

    def document(self) -> dict:
        return dict(self._document)

    @property
    def digest(self) -> str:
        return self._digest


def _valid_issue_get_fields(target: str) -> bool:
    _prefix, _sep, query = target.partition("?fields=")
    names = query.split("%2C")
    return len(names) > 0 and all(name in JIRA_READABLE_SYSTEM_FIELDS for name in names)


def request_descriptor(
    routed: object, *, endpoint_digest: object, authority: object,
) -> UpstreamDescriptor:
    """Pure; no clock, socket, ssl, credential or I/O. See rule v2, steps 1-6."""
    if type(routed) is not RoutedRequest or type(routed.upstream) is not UpstreamRequest:
        raise TypeError(
            "request_descriptor requires an exact RoutedRequest with an UpstreamRequest"
        )

    available = False
    if routed.service == "jira" and routed.route_id in DISPATCHABLE_SHAPES:
        entry_state = None
        try:
            entry = ROUTE_CATALOG.get(routed.route_id)
            entry_state = entry.state if entry is not None else None
        except Exception:  # noqa: BLE001 - an injected catalog must never escape here.
            entry_state = None
        available = entry_state in ("partial", "enabled") and routed.requires_permit is False
    if not available:
        raise UpstreamPrepareError("shape_unavailable")

    shape = DISPATCHABLE_SHAPES[routed.route_id]
    upstream = routed.upstream
    shape_ok = (
        upstream.method == shape.method
        and upstream.content_type == shape.content_type
        and upstream.accept == "application/json"
        and type(upstream.target) is str
        and upstream.target.startswith(UPSTREAM_BASE_PATH)
        and re.fullmatch(shape.target_pattern, upstream.target) is not None
        and type(upstream.body) is bytes
    )
    if shape_ok:
        if routed.route_id == "jira.issue.get":
            shape_ok = upstream.body == b"" and _valid_issue_get_fields(upstream.target)
        else:
            shape_ok = 1 <= len(upstream.body) <= MAX_REQUEST_JSON_BYTES
    if not shape_ok:
        raise UpstreamPrepareError("shape_unavailable")

    if type(routed.request_digest) is not str or _HEX64_RE.fullmatch(routed.request_digest) is None:
        raise UpstreamPrepareError("request_inconsistent")
    recomputed = None
    consistency_failed = False
    try:
        recomputed = _v1_request_digest(
            service=routed.service, route_id=routed.route_id,
            policy_digest=routed.policy_digest, scope_digest=routed.scope_digest,
            upstream=routed.upstream,
        )
    except RouteConfigError:
        consistency_failed = True
    if consistency_failed:
        raise UpstreamPrepareError("request_inconsistent") from None
    if not hmac.compare_digest(recomputed, routed.request_digest):
        raise UpstreamPrepareError("request_inconsistent")

    if (
        type(endpoint_digest) is not str or _HEX64_RE.fullmatch(endpoint_digest) is None
        or not _valid_authority(authority)
    ):
        raise UpstreamPrepareError("request_unbuildable")

    body_bytes = len(upstream.body)
    body_sha256 = hashlib.sha256(upstream.body).hexdigest() if body_bytes else None
    return UpstreamDescriptor(
        service=routed.service, route_id=routed.route_id, policy_digest=routed.policy_digest,
        scope_digest=routed.scope_digest, endpoint_digest=endpoint_digest,
        method=upstream.method, target=upstream.target, authority=authority,
        accept=upstream.accept, content_type=upstream.content_type,
        body_bytes=body_bytes, body_sha256=body_sha256, body=upstream.body,
    )


# --- wire profile ------------------------------------------------------------


@dataclass(frozen=True)
class RequestParts:
    prefix: bytes = field(repr=False)
    suffix: bytes = field(repr=False)


def render_parts(descriptor: object) -> RequestParts:
    """Pure and credential-free. Cannot fail on bounds for a valid descriptor."""
    if type(descriptor) is not UpstreamDescriptor:
        raise TypeError("render_parts requires an exact UpstreamDescriptor")
    method = descriptor.method
    target = descriptor.target
    authority = descriptor.authority
    accept = descriptor.accept
    content_type = descriptor.content_type
    body = descriptor.body
    body_bytes = descriptor.body_bytes

    request_line = f"{method} {target} HTTP/1.1\r\n".encode("ascii")
    host_line = f"Host: {authority}\r\n".encode("ascii")
    prefix = request_line + host_line

    suffix_head = f"Accept: {accept}\r\nAccept-Encoding: identity\r\n".encode("ascii")
    if body_bytes > 0:
        suffix_head += (
            f"Content-Type: {content_type}\r\nContent-Length: {body_bytes}\r\n"
        ).encode("ascii")
    suffix_head += b"Connection: close\r\n\r\n"
    suffix = suffix_head + body

    expected_line, expected_head, expected_body = _wire_lengths(
        method, target, authority, accept, content_type, body_bytes,
    )
    actual_head = len(host_line) + (17 + MAX_AUTHORIZATION_BYTES) + len(suffix_head)
    if (
        len(request_line) != expected_line
        or actual_head != expected_head
        or len(body) != expected_body
    ):
        raise UpstreamPrepareError("request_unbuildable")
    return RequestParts(prefix=prefix, suffix=suffix)


# --- transport: close and shutdown helpers --------------------------------------


def _close_quietly(sock: object) -> None:
    failed = False
    try:
        sock.close()
    except Exception:  # noqa: BLE001 - cleanup must not mask the caller's outcome.
        failed = True
    if not failed:
        return
    descriptor = -1
    try:
        descriptor = sock.detach()
    except Exception:  # noqa: BLE001 - retain the original failure.
        descriptor = -1
    if type(descriptor) is int and descriptor >= 0:
        try:
            socket.close(descriptor)
        except Exception:  # noqa: BLE001, S110 - retain the original failure.
            pass


def _shutdown_fd(sock: object) -> None:
    """The module's only ``shutdown`` call: the base-class call keeps ``_sslobj`` set."""
    try:
        super(ssl.SSLSocket, sock).shutdown(socket.SHUT_RDWR)
    except Exception:  # noqa: BLE001, S110 - abort/close must never raise.
        pass


# --- JiraUpstreamConnector ----------------------------------------------------


class JiraUpstreamConnector:
    __slots__ = ("_connected", "_credential", "_endpoint", "_lock")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("JiraUpstreamConnector cannot be subclassed")

    def __init__(self, *, endpoint: object, credential: object) -> None:
        if type(endpoint) is not UpstreamEndpoint or type(credential) is not BasicCredential:
            raise TypeError(
                "JiraUpstreamConnector requires an exact UpstreamEndpoint and BasicCredential"
            )
        if (
            credential.service != endpoint.service
            or credential.profile != CREDENTIAL_PROFILES.get(endpoint.service)
            or not hmac.compare_digest(endpoint.credential_id, credential.credential_id)
        ):
            raise UpstreamConfigError("credential_mismatch")
        with _CLAIM_LOCK:
            claimed = credential._claimed
            if not claimed:
                object.__setattr__(credential, "_claimed", True)
        if claimed:
            raise UpstreamConfigError("credential_claimed")
        self._endpoint = endpoint
        self._credential = credential
        self._lock = threading.Lock()
        self._connected: weakref.WeakSet = weakref.WeakSet()

    @property
    def service(self) -> str:
        return "jira"

    @property
    def endpoint_digest(self) -> str:
        return self._endpoint.digest

    def prepare(self, routed: object) -> str:
        return request_descriptor(
            routed, endpoint_digest=self._endpoint.digest, authority=self._endpoint.authority,
        ).digest

    def connect(
        self, admission: object, routed: object, *, request_digest: object, deadline: object,
    ) -> _UpstreamChannel:
        if (
            type(admission) is not Admission
            or type(routed) is not RoutedRequest
            or type(request_digest) is not str
            or _HEX64_RE.fullmatch(request_digest) is None
            or not _finite(deadline)
        ):
            raise UpstreamError("connect_failed")
        with self._lock:
            already = admission in self._connected
            if not already:
                self._connected.add(admission)
        if already:
            raise UpstreamError("connect_failed")
        if (
            admission.service != "jira" or routed.service != "jira"
            or admission.route_id != routed.route_id
        ):
            raise UpstreamError("connect_failed")

        descriptor = None
        descriptor_code: str | None = None
        try:
            descriptor = request_descriptor(
                routed, endpoint_digest=self._endpoint.digest, authority=self._endpoint.authority,
            )
        except (UpstreamPrepareError, TypeError):
            descriptor_code = "connect_failed"
        if descriptor_code is not None:
            raise UpstreamError(descriptor_code) from None
        if not hmac.compare_digest(descriptor.digest, request_digest):
            raise UpstreamError("connect_failed")

        parts = None
        parts_code: str | None = None
        try:
            parts = render_parts(descriptor)
        except UpstreamPrepareError:
            parts_code = "connect_failed"
        if parts_code is not None:
            raise UpstreamError(parts_code) from None

        if deadline > admission.connect_deadline:
            raise UpstreamError("connect_failed")

        t0 = _read_clock()
        if t0 is None:
            raise UpstreamError("connect_failed")
        if deadline <= t0:
            raise UpstreamError("deadline")
        limit = min(deadline, t0 + CONNECT_SECONDS)

        context = None
        context_code: str | None = None
        try:
            context = _build_context(self._endpoint.ca_pem, self._endpoint.trust_sha256)
        except (ssl.SSLError, ValueError, TypeError, AttributeError, OSError):
            context_code = "connect_failed"
        if context_code is not None:
            raise UpstreamError(context_code) from None
        now = _read_clock()
        if now is None:
            raise UpstreamError("connect_failed")
        if limit <= now:
            raise UpstreamError("deadline")

        raw = None
        secured = None
        returned = False
        try:
            tcp_code: str | None = None
            try:
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw.set_inheritable(False)
                raw.settimeout(limit - now)
                raw.connect((self._endpoint.address, self._endpoint.port))
            except (OSError, ValueError, TypeError):
                tcp_code = "connect_failed"
            if tcp_code is not None:
                raise UpstreamError(tcp_code) from None

            now = _read_clock()
            if now is None:
                raise UpstreamError("connect_failed")
            if limit <= now:
                raise UpstreamError("deadline")

            tls_code: str | None = None
            try:
                secured = context.wrap_socket(
                    raw, server_hostname=self._endpoint.host, do_handshake_on_connect=False,
                )
                raw = None
                secured.set_inheritable(False)
                secured.settimeout(limit - now)
                secured.do_handshake()
                _verify_post_handshake(secured)
            except (OSError, ssl.SSLError, ValueError, TypeError):
                tls_code = "upstream_tls_failed"
            if tls_code is not None:
                raise UpstreamError(tls_code) from None

            now = _read_clock()
            if now is None:
                raise UpstreamError("connect_failed")
            if limit <= now:
                raise UpstreamError("deadline")

            channel = _UpstreamChannel(
                _CHANNEL_TOKEN, sock=secured, parts=parts, credential=self._credential,
                exchange_deadline=admission.exchange_deadline,
            )
            returned = True
            return channel
        finally:
            if not returned:
                if secured is not None:
                    _close_quietly(secured)
                elif raw is not None:
                    _close_quietly(raw)

    def __repr__(self) -> str:
        return (
            f"JiraUpstreamConnector(service={self.service!r}, "
            f"endpoint_digest={self.endpoint_digest!r})"
        )

    def __reduce__(self) -> object:
        raise TypeError("connector_not_copyable")

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError("connector_not_copyable")

    def __getstate__(self) -> object:
        raise TypeError("connector_not_copyable")

    def __copy__(self) -> object:
        raise TypeError("connector_not_copyable")

    def __deepcopy__(self, memo: object) -> object:
        raise TypeError("connector_not_copyable")


# --- _UpstreamChannel ----------------------------------------------------------


class _UpstreamChannel:
    """Private; constructed only by ``JiraUpstreamConnector.connect``."""

    __slots__ = (
        "_aborted", "_bytes_accepted", "_close_pending", "_closed", "_credential",
        "_exchange_deadline", "_io_active", "_lock", "_parts", "_phase", "_sock",
    )

    def __init__(
        self, token: object, *, sock: object, parts: object, credential: object,
        exchange_deadline: object,
    ) -> None:
        if (
            token is not _CHANNEL_TOKEN
            or type(sock) is not _CHANNEL_SOCKET_TYPE
            or type(parts) is not RequestParts
            or type(credential) is not BasicCredential
            or not _finite(exchange_deadline)
        ):
            raise TypeError("_UpstreamChannel requires its private token and exact argument types")
        self._lock = threading.Lock()
        self._phase = "open"
        self._aborted = False
        self._closed = False
        self._io_active = False
        self._close_pending = False
        self._sock = sock
        self._credential = credential
        self._parts = parts
        self._exchange_deadline = float(exchange_deadline)
        self._bytes_accepted = 0

    @property
    def state(self) -> str:
        with self._lock:
            if self._closed:
                return "closed"
            if self._aborted:
                return "aborted"
            return self._phase

    @property
    def bytes_accepted(self) -> int:
        with self._lock:
            return self._bytes_accepted

    def _finish_io(self, phase: str) -> None:
        sock_to_close = None
        with self._lock:
            self._io_active = False
            self._phase = phase
            self._credential = None
            if self._close_pending and not self._closed:
                self._closed = True
                sock_to_close = self._sock
                self._sock = None
        if sock_to_close is not None:
            _close_quietly(sock_to_close)

    def send(self, *, deadline: object) -> None:
        with self._lock:
            blocked = (
                self._closed or self._aborted or self._phase != "open"
                or self._sock is None or self._credential is None
            )
            sock = None if blocked else self._sock
            credential = None if blocked else self._credential
            if not blocked:
                self._phase = "sending"
                self._io_active = True
        if blocked:
            raise UpstreamError("write_failed")

        code: str | None = None
        completed = False
        buffer: bytearray | None = None
        view: memoryview | None = None
        chunk: memoryview | None = None
        try:
            if not _finite(deadline) or deadline > self._exchange_deadline:
                code = "write_failed"
            now: float | None = None
            if code is None:
                now = _read_clock()
                if now is None:
                    code = "write_failed"
            if code is None and deadline <= now:
                code = "deadline"
            limit = 0.0
            if code is None:
                limit = min(deadline, now + WRITE_SECONDS)
                assembly_failed = False
                try:
                    prefix = self._parts.prefix
                    suffix = self._parts.suffix
                    header_prefix = b"Authorization: "
                    header_suffix = b"\r\n"
                    authorization_length = len(credential._authorization)
                    total = (
                        len(prefix) + len(header_prefix) + authorization_length
                        + len(header_suffix) + len(suffix)
                    )
                    buffer = bytearray(total)
                    offset = len(prefix)
                    buffer[0:offset] = prefix
                    buffer[offset:offset + len(header_prefix)] = header_prefix
                    offset += len(header_prefix)
                    buffer[offset:offset + authorization_length] = credential._authorization
                    offset += authorization_length
                    buffer[offset:offset + len(header_suffix)] = header_suffix
                    offset += len(header_suffix)
                    buffer[offset:offset + len(suffix)] = suffix
                except Exception:  # noqa: BLE001 - an assembly fault writes nothing.
                    assembly_failed = True
                if assembly_failed:
                    code = "write_failed"
            if code is None:
                view = memoryview(buffer)
                total_len = len(buffer)
                sent = 0
                while sent < total_len:
                    with self._lock:
                        stop = self._aborted or self._close_pending
                    if stop:
                        code = "write_failed"
                        break
                    previous = now
                    now = _read_clock()
                    if now is None or now < previous:
                        code = "write_failed"
                        break
                    remaining = limit - now
                    if remaining <= 0:
                        code = "deadline"
                        break
                    chunk = view[sent:sent + MAX_WRITE_CHUNK_BYTES]
                    send_started = now
                    count = None
                    try:
                        sock.settimeout(min(WRITE_SECONDS, remaining))
                        count = sock.send(chunk)
                    except Exception:  # noqa: BLE001 - a send fault stops the write.
                        code = "write_failed"
                    if code is not None:
                        break
                    if type(count) is not int or not 0 < count <= len(chunk):
                        code = "write_failed"
                        break
                    sent += count
                    with self._lock:
                        self._bytes_accepted = sent
                    chunk.release()
                    chunk = None
                    previous = now
                    now = _read_clock()
                    if now is None or now < previous or now - send_started >= WRITE_SECONDS:
                        code = "write_failed"
                        break
            completed = True
        finally:
            if chunk is not None:
                chunk.release()
            chunk = None
            if view is not None:
                view.release()
            if buffer is not None:
                buffer[:] = bytes(len(buffer))
            credential = None
            self._finish_io("sent" if completed and code is None else "failed")
        if code is not None:
            raise UpstreamError(code) from None

    def receive(self, *, deadline: object) -> ParsedResponse:
        with self._lock:
            blocked = (
                self._closed or self._aborted or self._phase != "sent" or self._sock is None
            )
            sock = None if blocked else self._sock
            if not blocked:
                self._phase = "receiving"
                self._io_active = True
        if blocked:
            raise UpstreamError("receive_failed")

        code: str | None = None
        completed = False
        result: ParsedResponse | None = None
        try:
            if not _finite(deadline) or deadline > self._exchange_deadline:
                code = "receive_failed"
            now = None
            if code is None:
                now = _read_clock()
                if now is None:
                    code = "receive_failed"
            if code is None and deadline <= now:
                code = "deadline"
            if code is None:
                response = None
                error_code: str | None = None
                try:
                    response = receive_response(sock, deadline=deadline)
                except ResponseReceiveError as caught:
                    error_code = caught.code
                except Exception:  # noqa: BLE001 - any other fault maps to receive_failed.
                    error_code = "receive_failed"
                if error_code is not None:
                    code = "deadline" if error_code == "deadline_expired" else "receive_failed"
                elif type(response) is not ParsedResponse:
                    code = "receive_failed"
                else:
                    result = response
            completed = True
        finally:
            self._finish_io("received" if completed and code is None else "failed")
        if code is not None:
            raise UpstreamError(code) from None
        return result

    def abort(self) -> None:
        with self._lock:
            if self._closed or self._aborted:
                return
            self._aborted = True
            sock = self._sock
            self._credential = None
            if sock is not None:
                _shutdown_fd(sock)

    def close(self) -> None:
        sock = None
        with self._lock:
            if self._closed:
                return
            if self._io_active:
                self._close_pending = True
                if not self._aborted:
                    self._aborted = True
                    if self._sock is not None:
                        _shutdown_fd(self._sock)
                return
            self._closed = True
            sock = self._sock
            self._sock = None
            self._credential = None
        if sock is not None:
            _close_quietly(sock)

    def __repr__(self) -> str:
        return f"_UpstreamChannel(state={self.state!r})"

    def __reduce__(self) -> object:
        raise TypeError("channel_not_copyable")

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError("channel_not_copyable")

    def __getstate__(self) -> object:
        raise TypeError("channel_not_copyable")

    def __copy__(self) -> object:
        raise TypeError("channel_not_copyable")

    def __deepcopy__(self, memo: object) -> object:
        raise TypeError("channel_not_copyable")


__all__ = [
    "CHANNEL_STATES",
    "CREDENTIAL_PROFILES",
    "DENIED_NETWORKS",
    "DISPATCHABLE_SHAPES",
    "ENDPOINT_POLICY",
    "ENDPOINT_SCHEMA",
    "MAX_AUTHORIZATION_BYTES",
    "MAX_REQUEST_BODY_BYTES",
    "MAX_REQUEST_HEAD_BYTES",
    "MAX_REQUEST_LINE_BYTES",
    "MAX_TRUST_CERTIFICATES",
    "MAX_TRUST_PEM_BYTES",
    "MAX_WRITE_CHUNK_BYTES",
    "REQUEST_DIGEST_V2_TAG",
    "SYNTHETIC_NETWORKS",
    "TLS_PROFILE",
    "UPSTREAM_BASE_PATH",
    "UPSTREAM_CONFIG_CODES",
    "UPSTREAM_PREPARE_CODES",
    "WIRE_PROFILE",
    "BasicCredential",
    "JiraUpstreamConnector",
    "RequestParts",
    "RequestShape",
    "UpstreamConfigError",
    "UpstreamDescriptor",
    "UpstreamEndpoint",
    "UpstreamPrepareError",
    "endpoint_document",
    "render_parts",
    "request_descriptor",
]
