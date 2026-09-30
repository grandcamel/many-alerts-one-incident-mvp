"""Deterministic unit tests for the synthetic upstream connector (13b).

No sockets are opened. Real CA PEM material for endpoint/context tests comes
from ``prototype.mediated_client.certificates.create_certificates`` in a
module-scoped temporary directory. Channel tests use the documented
white-box path: ``_CHANNEL_SOCKET_TYPE`` monkeypatched to ``FakeTLSSocket``
and the private ``_CHANNEL_TOKEN`` passed deliberately.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import random
import ssl
import threading
import time
import types
from types import MappingProxyType

import pytest

from grafana_jsm_sandbox import forwarder_dispatch as fd
from grafana_jsm_sandbox import forwarder_tls
from grafana_jsm_sandbox import forwarder_upstream as fu
from grafana_jsm_sandbox.forwarder_dispatch import Admission
from grafana_jsm_sandbox.forwarder_exchange import UpstreamError
from grafana_jsm_sandbox.forwarder_http_response import ParsedResponse
from grafana_jsm_sandbox.forwarder_json import canonical_json, tagged_digest
from grafana_jsm_sandbox.forwarder_response_receive import ResponseReceiveError
from grafana_jsm_sandbox.forwarder_response_send import _MAX_CHUNK_BYTES
from grafana_jsm_sandbox.forwarder_routes import (
    MATCHABLE_ROUTE_IDS,
    MAX_REQUEST_JSON_BYTES,
    ROUTE_CATALOG,
    RoutedRequest,
    UpstreamRequest,
)
from grafana_jsm_sandbox.forwarder_routes import request_digest as v1_request_digest
from prototype.mediated_client.certificates import create_certificates

# --- golden fixtures (unit 12 / plan literals) ----------------------------------

POLICY_DIGEST = "3013f6a10469469651028a5ea422849591fae5a8bb4a7e15b92e2b0caf99a156"
SCOPE_DIGEST = "849028ca20f4b87db84ad25974dadd560b5d06177e17afad6b6a65fb902de47c"
ISSUE_GET_TARGET = "/rest/api/3/issue/90101?fields=issuetype%2Clabels%2Cproject%2Cstatus%2Csummary"
ISSUE_GET_V1_DIGEST = "43d8b4787de8e9370f79c719f3dbd5463e259bce78b98cd27daa246c7042b929"
SEARCH_BODY_50 = (
    b'{"fields":["issuetype","labels","project","status","summary"],'
    b'"jql":"project = 90001 AND issuetype = 90002 AND labels = '
    b'\\"fp-0123456789abcdef\\" AND statusCategory != Done AND created >= '
    b'-30m ORDER BY created ASC","maxResults":50}'
)
SEARCH_V1_DIGEST = "d416cc8619c619fe09b16796d7b87c515503e74ce6624f3a2d75570ce9d0692e"
DENIAL_DIGEST_ISSUE_GET = "d25b40c66fc9a150a6337bf0aeb2f8bf783b8b2196511a76577a23a2aa0c14ae"

# ssl names this option only from Python 3.12; on 3.11 it is OpenSSL's documented value.
OP_LEGACY_SERVER_CONNECT = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

TRUST_STANDIN = ("5c8b39e14dbaa86a0d3aa5655bc6f88015319f5603cd7463ba3820887887b60f",)
ENDPOINT_DIGEST_443 = "70b8b3d344d69be09c88244ad87b83d3928fae456b0f8ee7c52bb52c788eba21"
ENDPOINT_DIGEST_8443 = "0360f89d6dd4f5c633bfa490d76129e4a1643746a65503d8ef589803b54b3d69"
ENDPOINT_CANONICAL_LEN_443 = 480
ENDPOINT_CANONICAL_LEN_8443 = 481
ENDPOINT_CANONICAL_BYTES_443 = (
    b'{"address":"192.0.2.10","base_path":"/rest/api/3/","credential_id":'
    b'"jira-basic-synthetic-1","credential_profile":"basic","endpoint_policy":'
    b'"synthetic-only.v1","host":"jira-upstream.synthetic.invalid","port":443,'
    b'"revision":"upstream-r1","schema":"maoi.forwarder.upstream-endpoint.v1",'
    b'"service":"jira","tls_profile":"maoi.forwarder.upstream-tls.v1","trust_sha256":'
    b'["5c8b39e14dbaa86a0d3aa5655bc6f88015319f5603cd7463ba3820887887b60f"],'
    b'"wire_profile":"maoi.forwarder.upstream-wire.v1"}'
)

V2_ISSUE_GET_DIGEST = "0eaa6e61bb60d9a8663ef2807ac777beb41963a1e01d22cbd2d4731f82fd8dce"
V2_ISSUE_GET_LEN = 535
V2_SEARCH_DIGEST = "37f859dd0e55320f14709ab86ffb94d6ae2bb9277a954f3c264708c6988c4127"
V2_SEARCH_LEN = 555
V2_ISSUE_GET_8443_DIGEST = "f11826c2e26046e477e09ad0b987329b5977a8f5b237d50441f7e515e6d4880a"
V2_ISSUE_GET_8443_LEN = 540

SYNTHETIC_USER = "synthetic-user@example.invalid"
SYNTHETIC_TOKEN = "synthetic-token-0001"
SYNTHETIC_AUTH_VALUE = (
    b"Basic c3ludGhldGljLXVzZXJAZXhhbXBsZS5pbnZhbGlkOnN5bnRoZXRpYy10b2tlbi0wMDAx"
)

PREFIX_ISSUE_GET_LEN = 132
SUFFIX_ISSUE_GET_LEN = 74
FULL_WIRE_ISSUE_GET_LEN = 297
FULL_WIRE_ISSUE_GET_SHA256 = "5d7e615700e1420b602aa1d6fc879370ffd850ad80c6cffb8a7d71f7b371d28f"
REDACTED_ISSUE_GET_LEN = 233
REDACTED_ISSUE_GET_SHA256 = "d8b34b81b9c17dd08b0076106e4cfea12be03fdff7260d86bbd79e9c71ef65fd"

PREFIX_SEARCH_LEN = 77
SUFFIX_SEARCH_LEN = 356
FULL_WIRE_SEARCH_LEN = 524
FULL_WIRE_SEARCH_SHA256 = "bc63a733582b41ca053957012f0990586c299a043fb996e2ad779ed35391a826"
REDACTED_SEARCH_LEN = 460
REDACTED_SEARCH_SHA256 = "096952c097451757b13e1a4c5aaac147aa6ba04ea6e96b60f875fb8719a99c27"

FULL_WIRE_8443_LEN = 302
FULL_WIRE_8443_SHA256 = "1aebec6abb6ab933e24225554278826f7012f9468011849c245a3cdcdf6e40f1"
REDACTED_8443_LEN = 238
REDACTED_8443_SHA256 = "881a86f8c1e35260a712316ec1df4442349bec5d213de579ff000aea84feeeb3"

FULL_WIRE_ISSUE_GET = (
    b"GET /rest/api/3/issue/90101?fields=issuetype%2Clabels%2Cproject%2Cstatus%2Csummary"
    b" HTTP/1.1\r\nHost: jira-upstream.synthetic.invalid\r\nAuthorization: "
    + SYNTHETIC_AUTH_VALUE
    + b"\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
)


# --- shared builders ------------------------------------------------------------


@pytest.fixture(scope="module")
def real_ca_pem(tmp_path_factory) -> str:
    directory = tmp_path_factory.mktemp("forwarder_upstream_ca")
    certs = create_certificates(directory)
    return certs.ca_cert.read_text()


@pytest.fixture(scope="module")
def leaf_only_pem(tmp_path_factory) -> str:
    certs = create_certificates(tmp_path_factory.mktemp("forwarder_upstream_leaf"))
    return certs.server_cert.read_text()


def make_endpoint(ca_pem: str, **overrides) -> fu.UpstreamEndpoint:
    kwargs = {
        "service": "jira", "revision": "upstream-r1", "host": "jira-upstream.synthetic.invalid",
        "address": "192.0.2.10", "port": 443, "ca_pem": ca_pem,
        "credential_id": "jira-basic-synthetic-1",
    }
    kwargs.update(overrides)
    return fu.UpstreamEndpoint(**kwargs)


def golden_issue_get_routed(**overrides) -> RoutedRequest:
    upstream = UpstreamRequest("GET", ISSUE_GET_TARGET, "application/json", None, b"")
    digest = v1_request_digest(
        service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
        scope_digest=SCOPE_DIGEST, upstream=upstream,
    )
    assert digest == ISSUE_GET_V1_DIGEST
    kwargs = {
        "route_id": "jira.issue.get", "service": "jira", "scope_digest": SCOPE_DIGEST,
        "policy_digest": POLICY_DIGEST, "request_digest": digest, "requires_permit": False,
        "upstream": upstream, "selection": None,
    }
    kwargs.update(overrides)
    return RoutedRequest(**kwargs)


def golden_search_routed(**overrides) -> RoutedRequest:
    upstream = UpstreamRequest(
        "POST", "/rest/api/3/search/jql", "application/json", "application/json", SEARCH_BODY_50,
    )
    digest = v1_request_digest(
        service="jira", route_id="jira.search", policy_digest=POLICY_DIGEST,
        scope_digest=SCOPE_DIGEST, upstream=upstream,
    )
    assert digest == SEARCH_V1_DIGEST
    kwargs = {
        "route_id": "jira.search", "service": "jira", "scope_digest": SCOPE_DIGEST,
        "policy_digest": POLICY_DIGEST, "request_digest": digest, "requires_permit": False,
        "upstream": upstream, "selection": None,
    }
    kwargs.update(overrides)
    return RoutedRequest(**kwargs)


def golden_credential(**overrides) -> fu.BasicCredential:
    kwargs = {
        "service": "jira", "profile": "basic", "credential_id": "jira-basic-synthetic-1",
        "user": SYNTHETIC_USER, "token": SYNTHETIC_TOKEN,
    }
    kwargs.update(overrides)
    return fu.BasicCredential(**kwargs)


def issue_target_with_length(total_length: int) -> str:
    """A ``jira.issue.get`` target of exactly ``total_length`` bytes, all valid fields."""
    prefix = "/rest/api/3/issue/90101?fields="
    first = "labels"
    remaining = total_length - len(prefix) - len(first)
    for count_project in range(remaining // 10 + 1):
        leftover = remaining - 10 * count_project
        if leftover % 9 == 0:
            count_labels = leftover // 9
            return prefix + first + ("%2Clabels" * count_labels) + ("%2Cproject" * count_project)
    raise AssertionError("no combination reaches the requested length")


def assert_upstream_error(callable_, code: str) -> None:
    with pytest.raises(UpstreamError) as raised:
        callable_()
    assert raised.value.args == (code,)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def assert_config_error(callable_, code: str) -> None:
    with pytest.raises(fu.UpstreamConfigError) as raised:
        callable_()
    assert raised.value.args == (code,)
    assert str(raised.value) == code
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def assert_prepare_error(callable_, code: str) -> None:
    with pytest.raises(fu.UpstreamPrepareError) as raised:
        callable_()
    assert raised.value.args == (code,)
    assert str(raised.value) == code
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


class FakeTLSSocket:
    """The documented white-box path for ``_CHANNEL_SOCKET_TYPE``."""

    def __init__(self, *, send_results=None, on_send=None):
        self.settimeout_calls: list[float] = []
        self.send_calls: list[object] = []
        self.captured_chunks: list[tuple[object, bytes]] = []
        self.close_calls = 0
        self._send_results = list(send_results) if send_results is not None else None
        self._on_send = on_send

    def settimeout(self, value: float) -> None:
        self.settimeout_calls.append(value)

    def send(self, chunk) -> int:
        index = len(self.send_calls)
        self.captured_chunks.append((chunk.obj, bytes(chunk)))
        if self._on_send is not None:
            self._on_send(index)
        if self._send_results is not None:
            result = self._send_results[index]
            self.send_calls.append(result)
            if isinstance(result, BaseException):
                raise result
            return result
        self.send_calls.append(len(chunk))
        return len(chunk)

    def close(self) -> None:
        self.close_calls += 1


def make_channel(monkeypatch, sock, *, exchange_deadline=None, parts=None, credential=None):
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", FakeTLSSocket)
    if parts is None:
        parts = fu.RequestParts(
            prefix=b"GET / HTTP/1.1\r\nHost: h\r\n", suffix=b"Accept: a\r\n\r\n",
        )
    if credential is None:
        credential = golden_credential()
    if exchange_deadline is None:
        exchange_deadline = time.monotonic() + 100.0
    return fu._UpstreamChannel(
        fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential=credential,
        exchange_deadline=exchange_deadline,
    )


# =============================================================================
# 1. Constants
# =============================================================================


def test_schema_and_profile_constants_are_pinned():
    assert fu.ENDPOINT_SCHEMA == "maoi.forwarder.upstream-endpoint.v1"
    assert fu.ENDPOINT_POLICY == "synthetic-only.v1"
    assert fu.REQUEST_DIGEST_V2_TAG == "maoi.forwarder.request.v2"
    assert fu.TLS_PROFILE == "maoi.forwarder.upstream-tls.v1"
    assert fu.WIRE_PROFILE == "maoi.forwarder.upstream-wire.v1"
    assert fu.UPSTREAM_BASE_PATH == "/rest/api/3/"
    assert dict(fu.CREDENTIAL_PROFILES) == {"jira": "basic"}
    assert set(fu.DISPATCHABLE_SHAPES) == MATCHABLE_ROUTE_IDS


def test_network_tuples_are_pinned():
    assert [str(n) for n in fu.SYNTHETIC_NETWORKS] == [
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    ]
    assert [str(n) for n in fu.DENIED_NETWORKS] == [
        "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    ]


def test_private_constants_are_pinned():
    assert fu._OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION == 0x0004_0000
    assert fu._CHANNEL_SOCKET_TYPE is ssl.SSLSocket
    assert not hasattr(ssl, "OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION")


def test_the_legacy_server_connect_fallback_is_the_bit_ssl_names():
    # On 3.12 and later this proves the 3.11 fallback, 0x4, is the bit ssl itself uses.
    assert OP_LEGACY_SERVER_CONNECT == 0x4


def test_shared_constants_match_their_owning_modules():
    assert fd.CONNECT_SECONDS == 5.0
    assert fd.WRITE_SECONDS == 10.0
    import grafana_jsm_sandbox.forwarder_response_receive as frr

    assert frr._INACTIVITY_LIMIT == fd.READ_INACTIVITY_SECONDS == 20.0
    assert fu.MAX_WRITE_CHUNK_BYTES == _MAX_CHUNK_BYTES
    assert fu.MAX_TRUST_PEM_BYTES == forwarder_tls._MAX_CA_PEM_BYTES
    assert fu.MAX_TRUST_CERTIFICATES == forwarder_tls._MAX_CA_CERTIFICATES
    assert fu.MAX_REQUEST_BODY_BYTES == MAX_REQUEST_JSON_BYTES
    assert fu.CHANNEL_STATES == (
        "open", "sending", "sent", "receiving", "received", "failed", "aborted", "closed",
    )


# =============================================================================
# 2. Endpoint
# =============================================================================


VALID_ENDPOINT_KWARGS = {
    "service": "jira", "revision": "upstream-r1", "host": "jira-upstream.synthetic.invalid",
    "address": "192.0.2.10", "port": 443, "credential_id": "jira-basic-synthetic-1",
}


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"service": 1}, "endpoint_invalid"),
        ({"port": "443"}, "endpoint_invalid"),
        ({"port": True}, "endpoint_invalid"),
        ({"service": "confluence"}, "endpoint_invalid"),
        ({"revision": "bad@revision"}, "endpoint_invalid"),
        ({"credential_id": "bad@id"}, "endpoint_invalid"),
        ({"host": "UPPER.invalid.invalid"}, "endpoint_invalid"),
        ({"host": "localhost"}, "endpoint_invalid"),
        ({"host": "forwarder-jira.maoi.local"}, "endpoint_invalid"),
        ({"host": "a.local"}, "endpoint_invalid"),
        ({"address": "999.0.2.10"}, "endpoint_invalid"),
        ({"address": "127.0.0.1"}, "endpoint_invalid"),
        ({"address": "010.0.2.10"}, "endpoint_invalid"),
        ({"port": 0}, "endpoint_invalid"),
        ({"port": 65536}, "endpoint_invalid"),
    ],
)
def test_endpoint_shape_ordered_rules_give_endpoint_invalid(real_ca_pem, overrides, code):
    assert_config_error(
        lambda: make_endpoint(real_ca_pem, **overrides), code,
    )


def test_endpoint_shape_earliest_failure_wins(real_ca_pem):
    # Both service and host are invalid; service (step 2) precedes host (step 4).
    assert_config_error(
        lambda: make_endpoint(real_ca_pem, service="bogus", host="UPPER"), "endpoint_invalid",
    )


def test_bad_pem_on_nonsynthetic_host_gives_trust_invalid_not_unqualified(monkeypatch):
    monkeypatch.setattr("socket.socket", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert_config_error(
        lambda: make_endpoint("not a pem", host="jira.example.com"), "trust_invalid",
    )


def test_valid_pem_on_nonsynthetic_host_gives_unqualified(monkeypatch, real_ca_pem):
    monkeypatch.setattr("socket.socket", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert_config_error(
        lambda: make_endpoint(real_ca_pem, host="jira.example.com"), "endpoint_unqualified",
    )


@pytest.mark.parametrize(
    "address",
    ["10.0.0.5", "100.64.0.1", "192.168.1.1", "8.8.8.8", "198.18.0.1", "192.0.0.8"],
)
def test_unqualified_addresses_on_synthetic_host(monkeypatch, real_ca_pem, address):
    monkeypatch.setattr("socket.socket", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    assert_config_error(
        lambda: make_endpoint(real_ca_pem, address=address), "endpoint_unqualified",
    )


def test_trust_order_rejects_oversize_and_empty_before_fullmatch(monkeypatch):
    calls = []
    real_fullmatch = fu._PEM_BUNDLE.fullmatch

    class Recorder:
        def fullmatch(self, *a, **k):
            calls.append(1)
            return real_fullmatch(*a, **k)

    monkeypatch.setattr(fu, "_PEM_BUNDLE", Recorder())
    assert_config_error(lambda: make_endpoint("x" * (131_072 + 1)), "trust_invalid")
    assert_config_error(lambda: make_endpoint(""), "trust_invalid")
    assert calls == []


@pytest.mark.parametrize(
    "ca_pem",
    [
        "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n",
        "not a pem at all",
        "x" * 200_000,
        "",
        "é" * 40,
    ],
)
def test_trust_invalid_for_malformed_pem(ca_pem):
    assert_config_error(lambda: make_endpoint(ca_pem), "trust_invalid")


def test_trust_invalid_for_too_many_certificates(real_ca_pem):
    bundle = real_ca_pem * 17
    assert_config_error(lambda: make_endpoint(bundle), "trust_invalid")


def test_trust_invalid_for_duplicated_block_deliberate_difference(real_ca_pem):
    bundle = real_ca_pem + real_ca_pem
    # forwarder_tls accepts the duplicate; the upstream module does not.
    forwarder_tls._validate_ca_pem(bundle)
    forwarder_tls._strict_context(bundle)
    assert_config_error(lambda: make_endpoint(bundle), "trust_invalid")


def test_trust_invalid_for_a_leaf_only_pem(leaf_only_pem):
    # Grammar and DER parsing accept a leaf; only the context read-back refuses it.
    fu._check_trust_grammar(leaf_only_pem)
    assert len(fu._trust_digest_tuple(leaf_only_pem)) == 1
    assert_config_error(lambda: make_endpoint(leaf_only_pem), "trust_invalid")


def test_golden_endpoint_document_and_digest():
    document = fu.endpoint_document(
        service="jira", revision="upstream-r1", host="jira-upstream.synthetic.invalid",
        address="192.0.2.10", port=443, trust_sha256=TRUST_STANDIN,
        credential_id="jira-basic-synthetic-1",
    )
    canonical = canonical_json(document, ascii_only=True)
    assert canonical == ENDPOINT_CANONICAL_BYTES_443
    assert len(canonical) == ENDPOINT_CANONICAL_LEN_443
    assert tagged_digest(fu.ENDPOINT_SCHEMA, document) == ENDPOINT_DIGEST_443


def test_golden_endpoint_document_port_8443():
    document = fu.endpoint_document(
        service="jira", revision="upstream-r1", host="jira-upstream.synthetic.invalid",
        address="192.0.2.10", port=8443, trust_sha256=TRUST_STANDIN,
        credential_id="jira-basic-synthetic-1",
    )
    canonical = canonical_json(document, ascii_only=True)
    assert len(canonical) == ENDPOINT_CANONICAL_LEN_8443
    assert tagged_digest(fu.ENDPOINT_SCHEMA, document) == ENDPOINT_DIGEST_8443


def test_live_endpoint_digest_matches_reference_encoder(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    reference_document = fu.endpoint_document(
        service="jira", revision="upstream-r1", host="jira-upstream.synthetic.invalid",
        address="192.0.2.10", port=443, trust_sha256=endpoint.trust_sha256,
        credential_id="jira-basic-synthetic-1",
    )
    assert endpoint.document() == reference_document
    assert endpoint.canonical_bytes() == canonical_json(reference_document, ascii_only=True)
    assert endpoint.digest == tagged_digest(fu.ENDPOINT_SCHEMA, reference_document)


def test_endpoint_document_is_a_fresh_copy(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    document = endpoint.document()
    document["trust_sha256"].append("f" * 64)
    document["host"] = "changed.synthetic.invalid"
    fresh = endpoint.document()
    assert fresh["trust_sha256"] == list(endpoint.trust_sha256)
    assert fresh["host"] == "jira-upstream.synthetic.invalid"
    assert tagged_digest(fu.ENDPOINT_SCHEMA, fresh) == endpoint.digest
    assert canonical_json(fresh, ascii_only=True) == endpoint.canonical_bytes()


def test_reencoded_ca_gives_same_digest(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    crlf = real_ca_pem.replace("\n", "\r\n")
    reencoded = make_endpoint(crlf)
    assert reencoded.digest == endpoint.digest
    assert reencoded.trust_sha256 == endpoint.trust_sha256


@pytest.mark.parametrize(
    "field",
    ["revision", "host", "address", "port", "credential_id"],
)
def test_every_field_change_changes_the_digest(real_ca_pem, field):
    endpoint = make_endpoint(real_ca_pem)
    other_values = {
        "revision": "upstream-r2", "host": "jira-upstream2.synthetic.invalid",
        "address": "192.0.2.11", "port": 8443, "credential_id": "jira-basic-synthetic-2",
    }
    changed = make_endpoint(real_ca_pem, **{field: other_values[field]})
    assert changed.digest != endpoint.digest


def test_authority_rendering_for_443_and_8443(real_ca_pem):
    assert make_endpoint(real_ca_pem, port=443).authority == "jira-upstream.synthetic.invalid"
    assert (
        make_endpoint(real_ca_pem, port=8443).authority
        == "jira-upstream.synthetic.invalid:8443"
    )


def test_trust_grammar_parity_with_forwarder_tls(real_ca_pem):
    def fake_block(marker: bytes) -> str:
        import base64

        body = base64.b64encode(marker * 20).decode("ascii")
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

    corpus = [
        (real_ca_pem, True),
        ("", False),
        ("x" * (131_072 + 1), False),
        ("garbage, not a pem", False),
        ("".join(fake_block(bytes([i])) for i in range(17)), False),
        ("é" * 40, False),
    ]
    for candidate, expected_ok in corpus:
        tls_ok = True
        try:
            forwarder_tls._validate_ca_pem(candidate)
        except forwarder_tls.TLSBoundaryError:
            tls_ok = False
        upstream_ok = True
        try:
            fu._check_trust_grammar(candidate)
        except fu.UpstreamConfigError:
            upstream_ok = False
        assert tls_ok == upstream_ok == expected_ok


def test_endpoint_pattern_matches_forwarder_tls_source():
    assert fu._PEM_BUNDLE.pattern == forwarder_tls._PEM_BUNDLE.pattern
    assert fu.MAX_TRUST_PEM_BYTES == forwarder_tls._MAX_CA_PEM_BYTES
    assert fu.MAX_TRUST_CERTIFICATES == forwarder_tls._MAX_CA_CERTIFICATES


def test_dataclasses_replace_revalidates(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    assert_config_error(
        lambda: dataclasses.replace(endpoint, host="UPPER.invalid.invalid"), "endpoint_invalid",
    )
    assert_config_error(
        lambda: dataclasses.replace(endpoint, port=0), "endpoint_invalid",
    )


# =============================================================================
# 3. Context
# =============================================================================


def test_build_context_settings_and_readback(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    context = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.hostname_checks_common_name is False
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version in (
        ssl.TLSVersion.MAXIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
    )
    assert context.verify_flags == (ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_TRUSTED_FIRST)
    assert context.options & ssl.OP_NO_COMPRESSION
    assert context.options & ssl.OP_NO_RENEGOTIATION
    assert context.options & ssl.OP_NO_TICKET
    assert not context.options & ssl.OP_IGNORE_UNEXPECTED_EOF
    assert not context.options & OP_LEGACY_SERVER_CONNECT
    assert not context.options & fu._OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    assert context.keylog_filename is None
    assert context.post_handshake_auth is False
    observed = tuple(
        sorted(hashlib.sha256(der).hexdigest() for der in context.get_ca_certs(binary_form=True))
    )
    assert observed == endpoint.trust_sha256


def test_build_context_returns_distinct_objects(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    first = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)
    second = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)
    assert first is not second


class _FakeReadbackContext:
    """A minimal stand-in exposing exactly what ``_verify_context_readback`` reads."""

    def __init__(self, trust_sha256, **overrides):
        self.protocol = ssl.PROTOCOL_TLS_CLIENT
        self.verify_mode = ssl.CERT_REQUIRED
        self.check_hostname = True
        self.hostname_checks_common_name = False
        self.minimum_version = ssl.TLSVersion.TLSv1_2
        self.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        self.verify_flags = ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_TRUSTED_FIRST
        self.options = ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_TICKET
        self.keylog_filename = None
        self.post_handshake_auth = False
        self._trust_sha256 = trust_sha256
        for key, value in overrides.items():
            setattr(self, key, value)

    def cert_store_stats(self):
        return {"x509": len(self._trust_sha256), "x509_ca": len(self._trust_sha256)}

    def get_ca_certs(self, binary_form=False):
        return [bytes.fromhex(digest) for digest in self._trust_sha256]


def test_verify_context_readback_accepts_a_correct_context():
    # A single fixed DER blob whose own sha256 hexdigest is the trust tuple.
    der = b"a fake DER certificate blob"
    trust = (hashlib.sha256(der).hexdigest(),)
    context = _FakeReadbackContext(trust)
    context.get_ca_certs = lambda binary_form=False: [der]
    fu._verify_context_readback(context, trust)  # must not raise


@pytest.mark.parametrize(
    "overrides",
    [
        {"options": ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION},  # missing OP_NO_TICKET
        {"options": (
            ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_TICKET
            | OP_LEGACY_SERVER_CONNECT
        )},
        {"options": (
            ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_TICKET
            | ssl.OP_IGNORE_UNEXPECTED_EOF
        )},
        {"minimum_version": ssl.TLSVersion.TLSv1},
        {"verify_mode": ssl.CERT_OPTIONAL},
        {"check_hostname": False},
        {"hostname_checks_common_name": True},
        {"verify_flags": ssl.VERIFY_X509_STRICT},
        {"keylog_filename": "/tmp/keylog"},
        {"post_handshake_auth": True},
        {"protocol": ssl.PROTOCOL_TLS},
        {"maximum_version": ssl.TLSVersion.TLSv1_1},
        {"options": ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_TICKET},  # missing OP_NO_COMPRESSION
        {"options": ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET},  # missing OP_NO_RENEGOTIATION
        {"options": (
            ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION | ssl.OP_NO_TICKET
            | fu._OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
        )},
    ],
)
def test_verify_context_readback_is_live(overrides):
    trust = ()
    context = _FakeReadbackContext(trust, **overrides)
    with pytest.raises(ValueError):
        fu._verify_context_readback(context, trust)


@pytest.mark.parametrize("attribute", ["HAS_SNI", "HAS_ALPN"])
def test_verify_context_readback_requires_module_sni_and_alpn_support(monkeypatch, attribute):
    # These two clauses read the module-level ``ssl.HAS_SNI``/``ssl.HAS_ALPN`` flags,
    # not anything on ``context`` -- so they need their own (non-``_FakeReadbackContext``)
    # coverage: patching the real ``ssl`` module, which ``fu`` reads at call time.
    monkeypatch.setattr(ssl, attribute, False)
    trust = ()
    context = _FakeReadbackContext(trust)
    with pytest.raises(ValueError):
        fu._verify_context_readback(context, trust)


def test_verify_context_readback_checks_cert_store_and_ca_set():
    trust = ("aa" * 32,)
    context = _FakeReadbackContext(trust)
    context.cert_store_stats = lambda: {"x509": 2, "x509_ca": 2}
    with pytest.raises(ValueError):
        fu._verify_context_readback(context, trust)

    context2 = _FakeReadbackContext(trust)
    context2.get_ca_certs = lambda binary_form=False: [b"wrong-der-bytes"]
    with pytest.raises(ValueError):
        fu._verify_context_readback(context2, trust)


def test_build_context_failure_maps_to_trust_invalid_and_connect_failed(monkeypatch, real_ca_pem):
    endpoint_kwargs = dict(VALID_ENDPOINT_KWARGS)

    def raising_build_context(*_a, **_k):
        raise ValueError("bad context")

    monkeypatch.setattr(fu, "_build_context", raising_build_context)
    assert_config_error(
        lambda: fu.UpstreamEndpoint(ca_pem=real_ca_pem, **endpoint_kwargs), "trust_invalid",
    )
    monkeypatch.undo()

    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    conn = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)

    def boom_socket(*_a, **_k):
        raise AssertionError("no socket for a context build failure")

    monkeypatch.setattr("socket.socket", boom_socket)
    monkeypatch.setattr(fu, "_build_context", raising_build_context)
    assert_upstream_error(
        lambda: conn.connect(
            _admission(), routed, request_digest=digest, deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


_REAL_OPTIONS = ssl.SSLContext.options
_REAL_MINIMUM_VERSION = ssl.SSLContext.minimum_version
WEAKENED_READBACKS = {
    "adds-legacy-server-connect": {"options": property(
        lambda self: _REAL_OPTIONS.__get__(self) | OP_LEGACY_SERVER_CONNECT,
        _REAL_OPTIONS.__set__,
    )},
    "drops-no-ticket": {"options": property(
        lambda self: int(_REAL_OPTIONS.__get__(self)) & ~int(ssl.OP_NO_TICKET),
        _REAL_OPTIONS.__set__,
    )},
    "minimum-reads-tlsv1": {"minimum_version": property(
        lambda self: ssl.TLSVersion.TLSv1, _REAL_MINIMUM_VERSION.__set__,
    )},
}


def patch_module_ssl_context(monkeypatch, context_type) -> None:
    """Only the module's ``ssl.SSLContext`` changes: ``ssl.py``'s own setters name the real one."""
    proxy = types.ModuleType("ssl")
    proxy.__getattr__ = lambda name: getattr(ssl, name)
    proxy.SSLContext = context_type
    monkeypatch.setattr(fu, "ssl", proxy)


def test_context_subclass_control_builds_through_the_patched_constructor(
    monkeypatch, real_ca_pem,
):
    patch_module_ssl_context(monkeypatch, type("PassThrough", (ssl.SSLContext,), {}))
    endpoint = make_endpoint(real_ca_pem)
    context = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)
    assert type(context).__name__ == "PassThrough"


@pytest.mark.parametrize("variant", sorted(WEAKENED_READBACKS))
def test_context_readback_is_live_through_build_context(
    monkeypatch, real_ca_pem, blocked_socket, variant,
):
    endpoint = make_endpoint(real_ca_pem)
    conn = fu.JiraUpstreamConnector(endpoint=endpoint, credential=golden_credential())
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    weakened = type("Weakened", (ssl.SSLContext,), WEAKENED_READBACKS[variant])
    patch_module_ssl_context(monkeypatch, weakened)
    assert_config_error(lambda: make_endpoint(real_ca_pem), "trust_invalid")
    admission = _admission()
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline,
        ),
        "connect_failed",
    )


def test_context_readback_ignores_keylog_and_cert_env(monkeypatch, tmp_path, real_ca_pem):
    keylog_path = tmp_path / "keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog_path))
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "wrong-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    endpoint = make_endpoint(real_ca_pem)
    context = fu._build_context(endpoint.ca_pem, endpoint.trust_sha256)
    assert context.keylog_filename is None
    assert not keylog_path.exists()


# =============================================================================
# 4. Credential
# =============================================================================


@pytest.mark.parametrize(
    "kwargs",
    [
        {"user": "bad:user"},
        {"user": "bad user"},
        {"user": "bad\ruser"},
        {"user": "bad\nuser"},
        {"user": "café"},
        {"token": "café"},
        {"user": ""},
        {"token": ""},
        {"user": "x" * 257},
        {"token": "x" * 1025},
        {"service": "confluence"},
        {"profile": "bearer"},
        {"credential_id": "bad@id"},
    ],
)
def test_credential_validation_matrix(kwargs):
    assert_config_error(lambda: golden_credential(**kwargs), "credential_invalid")


def test_credential_str_subclass_is_never_touched():
    calls: list[str] = []

    class RecordingStr(str):
        def encode(self, *a, **k):
            calls.append("encode")
            return super().encode(*a, **k)

        def __add__(self, other):
            calls.append("add")
            return super().__add__(other)

        def __radd__(self, other):
            calls.append("radd")
            return super().__radd__(other)

        def __len__(self):
            calls.append("len")
            return super().__len__()

        def __iter__(self):
            calls.append("iter")
            return super().__iter__()

        def __getitem__(self, item):
            calls.append("getitem")
            return super().__getitem__(item)

    assert_config_error(
        lambda: golden_credential(user=RecordingStr(SYNTHETIC_USER)), "credential_invalid",
    )
    assert calls == []
    assert_config_error(
        lambda: golden_credential(token=RecordingStr(SYNTHETIC_TOKEN)), "credential_invalid",
    )
    assert calls == []


@pytest.mark.parametrize(
    "kwargs",
    [{"user": "bad:user"}, {"token": ""}, {"service": "confluence"}, {"user": "x" * 257}],
)
def test_credential_failure_has_no_cause_or_context(kwargs):
    try:
        golden_credential(**kwargs)
    except fu.UpstreamConfigError as error:
        assert error.__cause__ is None
        assert error.__context__ is None
    else:
        pytest.fail("expected UpstreamConfigError")


@pytest.mark.parametrize(
    "kwargs",
    [{"user": "bad:user"}, {"token": ""}, {"service": "confluence"}],
)
def test_credential_failure_frame_locals_never_leak(kwargs):
    marker_user = "marker-user-value"
    marker_token = "marker-token-value"
    base = {"user": marker_user, "token": marker_token}
    base.update(kwargs)
    try:
        golden_credential(**base)
    except fu.UpstreamConfigError as error:
        frame = None
        tb = error.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_name == "__init__":
                frame = tb.tb_frame
            tb = tb.tb_next
        assert frame is not None
        assert "user" not in frame.f_locals
        assert "token" not in frame.f_locals
        for value in frame.f_locals.values():
            try:
                text = repr(value)
            except Exception:  # noqa: BLE001, S112 - an unreprable value cannot leak via repr.
                continue
            assert marker_user not in text
            assert marker_token not in text
    else:
        pytest.fail("expected UpstreamConfigError")


def test_credential_header_value_is_golden():
    credential = golden_credential()
    assert credential._authorization == SYNTHETIC_AUTH_VALUE


def test_credential_repr_str_format_are_redacted():
    credential = golden_credential()
    redacted = (
        "BasicCredential(service='jira', profile='basic', "
        "credential_id='jira-basic-synthetic-1', <redacted>)"
    )
    assert repr(credential) == redacted
    assert str(credential) == redacted
    assert format(credential) == redacted
    assert f"{credential!r}" == redacted
    assert "%r" % credential == redacted  # noqa: UP031 - exercising the % form deliberately
    assert SYNTHETIC_USER not in repr(credential)
    assert SYNTHETIC_TOKEN not in repr(credential)


def test_credential_is_not_copyable_and_immutable():
    import copy
    import pickle

    credential = golden_credential()
    with pytest.raises(TypeError):
        vars(credential)
    with pytest.raises(TypeError):
        pickle.dumps(credential)
    with pytest.raises(TypeError):
        copy.copy(credential)
    with pytest.raises(TypeError):
        copy.deepcopy(credential)
    with pytest.raises(AttributeError):
        credential.service = "confluence"
    with pytest.raises(AttributeError):
        del credential.service
    with pytest.raises(TypeError):

        class Sub(fu.BasicCredential):
            pass


def test_credential_equality_is_identity():
    a = golden_credential()
    b = golden_credential()
    assert a != b
    assert a == a  # noqa: PLR0124 - identity check is deliberate
    assert hash(a) == hash(a)


def test_connector_credential_mismatch(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    assert_config_error(
        lambda: fu.JiraUpstreamConnector(
            endpoint=endpoint, credential=golden_credential(credential_id="other-id"),
        ),
        "credential_mismatch",
    )


def test_connector_refuses_a_service_or_profile_mismatch(monkeypatch, real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    monkeypatch.setattr(
        fu, "CREDENTIAL_PROFILES", MappingProxyType({"jira": "basic", "confluence": "basic"}),
    )
    other_service = golden_credential(service="confluence")
    jira_credential = golden_credential()
    assert_config_error(
        lambda: fu.JiraUpstreamConnector(endpoint=endpoint, credential=other_service),
        "credential_mismatch",
    )
    assert other_service._claimed is False

    monkeypatch.setattr(fu, "CREDENTIAL_PROFILES", MappingProxyType({"jira": "bearer"}))
    assert_config_error(
        lambda: fu.JiraUpstreamConnector(endpoint=endpoint, credential=jira_credential),
        "credential_mismatch",
    )
    assert jira_credential._claimed is False


def test_connector_second_claim_is_refused(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    assert_config_error(
        lambda: fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential),
        "credential_claimed",
    )


def test_connector_wrong_types_raise_type_error(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    with pytest.raises(TypeError):
        fu.JiraUpstreamConnector(endpoint="not an endpoint", credential=credential)
    with pytest.raises(TypeError):
        fu.JiraUpstreamConnector(endpoint=endpoint, credential="not a credential")


def test_connector_refused_construction_leaves_credential_unclaimed(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    mismatched_endpoint = make_endpoint(real_ca_pem, credential_id="jira-basic-synthetic-9")
    credential = golden_credential()
    assert_config_error(
        lambda: fu.JiraUpstreamConnector(endpoint=mismatched_endpoint, credential=credential),
        "credential_mismatch",
    )
    connector = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    assert connector.service == "jira"


# =============================================================================
# 5. O1, prepare and descriptor
# =============================================================================


def test_golden_v2_digests():
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    assert descriptor.digest == V2_ISSUE_GET_DIGEST
    assert len(canonical_json(descriptor.document(), ascii_only=True)) == V2_ISSUE_GET_LEN
    assert descriptor.digest != ISSUE_GET_V1_DIGEST

    search_descriptor = fu.request_descriptor(
        golden_search_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    assert search_descriptor.digest == V2_SEARCH_DIGEST
    assert len(canonical_json(search_descriptor.document(), ascii_only=True)) == V2_SEARCH_LEN
    assert search_descriptor.digest != SEARCH_V1_DIGEST

    descriptor_8443 = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_8443,
        authority="jira-upstream.synthetic.invalid:8443",
    )
    assert descriptor_8443.digest == V2_ISSUE_GET_8443_DIGEST
    assert len(canonical_json(descriptor_8443.document(), ascii_only=True)) == V2_ISSUE_GET_8443_LEN


def test_prepare_matches_request_descriptor(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    connector = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    routed = golden_issue_get_routed()
    expected = fu.request_descriptor(
        routed, endpoint_digest=endpoint.digest, authority=endpoint.authority,
    ).digest
    assert connector.prepare(routed) == expected


def test_prepare_is_pure_across_many_calls(monkeypatch, real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    connector = fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    routed = golden_issue_get_routed()

    def boom(*a, **k):
        raise AssertionError("prepare must not touch this")

    monkeypatch.setattr("socket.socket", boom)
    monkeypatch.setattr(ssl, "SSLContext", boom)
    monkeypatch.setattr(time, "monotonic", boom)
    monkeypatch.setattr("socket.getaddrinfo", boom)

    results = {connector.prepare(routed) for _ in range(100)}
    expected = fu.request_descriptor(
        routed, endpoint_digest=endpoint.digest, authority=endpoint.authority,
    ).digest
    assert results == {expected}
    assert len(results) == 1


@pytest.mark.parametrize("length, should_pass", [(2033, True), (2034, False)])
def test_request_line_boundary_through_prepare(length, should_pass):
    target = issue_target_with_length(length)
    routed = golden_issue_get_routed()
    new_upstream = dataclasses.replace(routed.upstream, target=target)
    new_digest = v1_request_digest(
        service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
        scope_digest=SCOPE_DIGEST, upstream=new_upstream,
    )
    new_routed = dataclasses.replace(routed, upstream=new_upstream, request_digest=new_digest)

    def call():
        return fu.request_descriptor(
            new_routed, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        )

    if should_pass:
        descriptor = call()
        parts = fu.render_parts(descriptor)
        request_line_len = parts.prefix.index(b"\r\n") + 2
        assert request_line_len == fu.MAX_REQUEST_LINE_BYTES
    else:
        assert_prepare_error(call, "request_unbuildable")


def test_shape_unavailable_refusals():
    routed = golden_issue_get_routed()
    changed_route = dataclasses.replace(routed, route_id="jira.issue.create")
    assert_prepare_error(
        lambda: fu.request_descriptor(
            changed_route, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )
    changed_service = dataclasses.replace(routed, service="confluence")
    assert_prepare_error(
        lambda: fu.request_descriptor(
            changed_service, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )
    permit_required = dataclasses.replace(routed, requires_permit=True)
    assert_prepare_error(
        lambda: fu.request_descriptor(
            permit_required, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


def test_shape_unavailable_for_bad_catalog(monkeypatch):
    routed = golden_issue_get_routed()

    class UnavailableStatus:
        state = "unavailable"

    fake_catalog = dict(ROUTE_CATALOG)
    fake_catalog["jira.issue.get"] = UnavailableStatus()
    monkeypatch.setattr(fu, "ROUTE_CATALOG", fake_catalog)
    assert_prepare_error(
        lambda: fu.request_descriptor(
            routed, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


def test_shape_unavailable_for_missing_catalog_entry_no_keyerror(monkeypatch):
    routed = golden_issue_get_routed()
    monkeypatch.setattr(fu, "ROUTE_CATALOG", {})
    assert_prepare_error(
        lambda: fu.request_descriptor(
            routed, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


def test_shape_unavailable_for_raising_catalog(monkeypatch):
    routed = golden_issue_get_routed()

    class RaisingCatalog:
        def get(self, key):
            raise RuntimeError("boom")

    monkeypatch.setattr(fu, "ROUTE_CATALOG", RaisingCatalog())
    assert_prepare_error(
        lambda: fu.request_descriptor(
            routed, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


def test_shape_unavailable_for_target_outside_base_or_wrong_shape():
    routed = golden_issue_get_routed()
    bad_target = dataclasses.replace(
        routed.upstream, target="/rest/api/3/issue/90101/comment?fields=labels",
    )
    replaced = dataclasses.replace(
        routed, upstream=bad_target,
        request_digest=v1_request_digest(
            service="jira", route_id="jira.issue.get", policy_digest=POLICY_DIGEST,
            scope_digest=SCOPE_DIGEST, upstream=bad_target,
        ),
    )
    assert_prepare_error(
        lambda: fu.request_descriptor(
            replaced, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


@pytest.mark.parametrize(
    ("make_routed", "field_name", "bad_value"),
    [
        (golden_issue_get_routed, "method", "POST"),
        (golden_search_routed, "method", "PUT"),
        (golden_issue_get_routed, "content_type", "application/json"),
        (golden_search_routed, "content_type", None),
        (golden_issue_get_routed, "accept", "text/plain"),
        (golden_search_routed, "accept", "text/plain"),
        (golden_issue_get_routed, "body", b"{}"),
    ],
    ids=[
        "issue_get-wrong-method", "search-wrong-method",
        "issue_get-wrong-content_type", "search-missing-content_type",
        "issue_get-wrong-accept", "search-wrong-accept",
        "issue_get-nonempty-body",
    ],
)
def test_shape_ok_clause_refusals(make_routed, field_name, bad_value):
    # Rule-v2 step 3 re-verifies the upstream's method, content_type, accept and (for
    # ``jira.issue.get``) that it carries no body, independently of whatever a --
    # trusted, but still re-checked -- ``RoutedRequest`` claims. Each case below
    # tampers with exactly one of those fields; deleting the matching clause in
    # ``request_descriptor`` would let it through to the fully different
    # ``request_inconsistent``/no-error outcome instead of this closed code.
    routed = make_routed()
    tampered_upstream = dataclasses.replace(routed.upstream, **{field_name: bad_value})
    tampered = dataclasses.replace(routed, upstream=tampered_upstream)
    assert_prepare_error(
        lambda: fu.request_descriptor(
            tampered, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


def test_shape_unavailable_for_an_unreadable_issue_get_field():
    # A syntactically valid (lowercase-letters) field name that is still outside
    # ``JIRA_READABLE_SYSTEM_FIELDS`` -- the ``_valid_issue_get_fields`` clause is the
    # only thing that catches this; the target-pattern regex alone accepts it.
    routed = golden_issue_get_routed()
    bad_target = dataclasses.replace(
        routed.upstream, target="/rest/api/3/issue/90101?fields=zzzzz",
    )
    tampered = dataclasses.replace(routed, upstream=bad_target)
    assert_prepare_error(
        lambda: fu.request_descriptor(
            tampered, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "shape_unavailable",
    )


def test_request_inconsistent_refusals():
    routed = golden_issue_get_routed()
    other_hex = "a" * 64
    wrong_digest = dataclasses.replace(routed, request_digest=other_hex)
    assert_prepare_error(
        lambda: fu.request_descriptor(
            wrong_digest, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "request_inconsistent",
    )

    # A different, still shape-valid target with the *old*, un-recomputed v1 digest.
    other_valid_target = "/rest/api/3/issue/90101?fields=labels"
    tampered_target = dataclasses.replace(
        routed, upstream=dataclasses.replace(routed.upstream, target=other_valid_target),
    )
    assert_prepare_error(
        lambda: fu.request_descriptor(
            tampered_target, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "request_inconsistent",
    )

    non_ascii_digest = dataclasses.replace(routed, request_digest="é" * 64)
    assert_prepare_error(
        lambda: fu.request_descriptor(
            non_ascii_digest, endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        ),
        "request_inconsistent",
    )


@pytest.mark.parametrize(
    "authority",
    [
        "jira-upstream.synthetic.invalid:",
        "jira-upstream.synthetic.invalid:0",
        "jira-upstream.synthetic.invalid:0443",
        "jira-upstream.synthetic.invalid:443",
        "jira-upstream.synthetic.invalid:65536",
        "JIRA-UPSTREAM.SYNTHETIC.INVALID",
        "x.local",
        "192.0.2.10",
    ],
)
def test_request_unbuildable_authority_refusals(authority):
    assert_prepare_error(
        lambda: fu.request_descriptor(
            golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443, authority=authority,
        ),
        "request_unbuildable",
    )


def test_authority_with_8443_is_accepted():
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid:8443",
    )
    assert descriptor.authority == "jira-upstream.synthetic.invalid:8443"


def test_request_unbuildable_for_malformed_endpoint_digest():
    assert_prepare_error(
        lambda: fu.request_descriptor(
            golden_issue_get_routed(), endpoint_digest="not-hex",
            authority="jira-upstream.synthetic.invalid",
        ),
        "request_unbuildable",
    )


def test_request_descriptor_wrong_types_raise_type_error():
    with pytest.raises(TypeError):
        fu.request_descriptor(
            "not a routed request", endpoint_digest=ENDPOINT_DIGEST_443,
            authority="jira-upstream.synthetic.invalid",
        )


@pytest.mark.parametrize("route_id", sorted(MATCHABLE_ROUTE_IDS))
def test_seeded_property_v2_digest_never_equals_v1_and_binds_correctly(route_id):
    rng = random.Random(20260923)
    for _ in range(60):
        if route_id == "jira.issue.get":
            routed = golden_issue_get_routed()
        else:
            max_results = rng.randint(1, 50)
            body = (
                b'{"fields":["issuetype","labels","project","status","summary"],'
                b'"jql":"project = 90001 AND issuetype = 90002 AND labels = '
                b'\\"fp-0123456789abcdef\\" AND statusCategory != Done AND created >= '
                b'-30m ORDER BY created ASC","maxResults":' + str(max_results).encode() + b"}"
            )
            upstream = UpstreamRequest(
                "POST", "/rest/api/3/search/jql", "application/json", "application/json", body,
            )
            digest = v1_request_digest(
                service="jira", route_id="jira.search", policy_digest=POLICY_DIGEST,
                scope_digest=SCOPE_DIGEST, upstream=upstream,
            )
            routed = RoutedRequest(
                route_id="jira.search", service="jira", scope_digest=SCOPE_DIGEST,
                policy_digest=POLICY_DIGEST, request_digest=digest, requires_permit=False,
                upstream=upstream, selection=None,
            )
        endpoint_digest = f"{rng.getrandbits(256):064x}"
        authority = "jira-upstream.synthetic.invalid"
        descriptor = fu.request_descriptor(
            routed, endpoint_digest=endpoint_digest, authority=authority,
        )
        assert len(descriptor.digest) == 64
        assert all(c in "0123456789abcdef" for c in descriptor.digest)
        assert descriptor.digest != routed.request_digest
        same = fu.request_descriptor(routed, endpoint_digest=endpoint_digest, authority=authority)
        assert same.digest == descriptor.digest
        other_endpoint_digest = f"{rng.getrandbits(256):064x}"
        different = fu.request_descriptor(
            routed, endpoint_digest=other_endpoint_digest, authority=authority,
        )
        assert different.digest != descriptor.digest


# =============================================================================
# 6. Wire
# =============================================================================


def test_golden_wire_issue_get():
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    assert len(parts.prefix) == PREFIX_ISSUE_GET_LEN
    assert len(parts.suffix) == SUFFIX_ISSUE_GET_LEN
    full_wire = parts.prefix + b"Authorization: " + SYNTHETIC_AUTH_VALUE + b"\r\n" + parts.suffix
    assert len(full_wire) == FULL_WIRE_ISSUE_GET_LEN
    assert hashlib.sha256(full_wire).hexdigest() == FULL_WIRE_ISSUE_GET_SHA256
    assert full_wire == FULL_WIRE_ISSUE_GET
    redacted = parts.prefix + b"Authorization: <redacted>\r\n" + parts.suffix
    assert len(redacted) == REDACTED_ISSUE_GET_LEN
    assert hashlib.sha256(redacted).hexdigest() == REDACTED_ISSUE_GET_SHA256


def test_golden_wire_search():
    descriptor = fu.request_descriptor(
        golden_search_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    assert len(parts.prefix) == PREFIX_SEARCH_LEN
    assert len(parts.suffix) == SUFFIX_SEARCH_LEN
    full_wire = parts.prefix + b"Authorization: " + SYNTHETIC_AUTH_VALUE + b"\r\n" + parts.suffix
    assert len(full_wire) == FULL_WIRE_SEARCH_LEN
    assert hashlib.sha256(full_wire).hexdigest() == FULL_WIRE_SEARCH_SHA256
    redacted = parts.prefix + b"Authorization: <redacted>\r\n" + parts.suffix
    assert len(redacted) == REDACTED_SEARCH_LEN
    assert hashlib.sha256(redacted).hexdigest() == REDACTED_SEARCH_SHA256


def test_golden_wire_8443():
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_8443,
        authority="jira-upstream.synthetic.invalid:8443",
    )
    parts = fu.render_parts(descriptor)
    full_wire = parts.prefix + b"Authorization: " + SYNTHETIC_AUTH_VALUE + b"\r\n" + parts.suffix
    assert len(full_wire) == FULL_WIRE_8443_LEN
    assert hashlib.sha256(full_wire).hexdigest() == FULL_WIRE_8443_SHA256
    redacted = parts.prefix + b"Authorization: <redacted>\r\n" + parts.suffix
    assert len(redacted) == REDACTED_8443_LEN
    assert hashlib.sha256(redacted).hexdigest() == REDACTED_8443_SHA256


def test_bodyless_get_has_no_content_headers():
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    assert b"Content-Length" not in parts.suffix
    assert b"Content-Type" not in parts.suffix
    assert b"User-Agent" not in parts.prefix + parts.suffix
    assert b"Connection: close" in parts.suffix


@pytest.mark.parametrize(
    ("field", "value", "expect_ok"),
    [
        ("target", "/x y", False),
        ("target", "/x#y", False),
        ("target", "/x\ry", False),
        ("target", "/x\ny", False),
        ("authority", "bad host.invalid", False),
        ("accept", "application/json bad", False),
        ("content_type", "application/json\r\n", False),
    ],
)
def test_descriptor_rejects_cr_lf_space_hash(field, value, expect_ok):
    kwargs = {
        "service": "jira", "route_id": "jira.issue.get", "policy_digest": POLICY_DIGEST,
        "scope_digest": SCOPE_DIGEST, "endpoint_digest": ENDPOINT_DIGEST_443, "method": "GET",
        "target": "/rest/api/3/issue/90101?fields=labels",
        "authority": "jira-upstream.synthetic.invalid",
        "accept": "application/json", "content_type": None, "body_bytes": 0,
        "body_sha256": None, "body": b"",
    }
    kwargs[field] = value
    assert_prepare_error(lambda: fu.UpstreamDescriptor(**kwargs), "request_unbuildable")


@pytest.mark.parametrize(
    ("route_id", "shape_method", "bad_method"),
    [
        ("jira.issue.get", "GET", "PUT"),
        ("jira.issue.get", "GET", "get"),
        ("jira.issue.get", "GET", "GET /x HTTP/1.1\r\nX:"),
        ("jira.search", "POST", "PUT"),
    ],
)
def test_descriptor_rejects_a_wrong_or_injected_method(route_id, shape_method, bad_method):
    # __post_init__ cross-checks ``method`` against ``DISPATCHABLE_SHAPES[route_id].method``;
    # a direct construction with any other value (including a case variant or a request-line
    # injection attempt) must be refused with the closed code, never let through to
    # ``tagged_digest``/``canonical_json`` (which would raise a different, non-fixed error
    # for non-ASCII injections, or -- for a plain wrong method -- render a request the
    # dispatched route never agreed to).
    assert bad_method != shape_method
    if route_id == "jira.issue.get":
        kwargs = {
            "service": "jira", "route_id": route_id, "policy_digest": POLICY_DIGEST,
            "scope_digest": SCOPE_DIGEST, "endpoint_digest": ENDPOINT_DIGEST_443,
            "method": bad_method, "target": "/rest/api/3/issue/90101?fields=labels",
            "authority": "jira-upstream.synthetic.invalid", "accept": "application/json",
            "content_type": None, "body_bytes": 0, "body_sha256": None, "body": b"",
        }
    else:
        body = b"{}"
        kwargs = {
            "service": "jira", "route_id": route_id, "policy_digest": POLICY_DIGEST,
            "scope_digest": SCOPE_DIGEST, "endpoint_digest": ENDPOINT_DIGEST_443,
            "method": bad_method, "target": "/rest/api/3/search/jql",
            "authority": "jira-upstream.synthetic.invalid", "accept": "application/json",
            "content_type": "application/json", "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(), "body": body,
        }
    assert_prepare_error(lambda: fu.UpstreamDescriptor(**kwargs), "request_unbuildable")


@pytest.mark.parametrize(
    ("length", "should_pass"),
    [(fu.MAX_REQUEST_LINE_BYTES, True), (fu.MAX_REQUEST_LINE_BYTES + 1, False)],
)
def test_wire_lengths_request_line_boundary(length, should_pass):
    target_len = length - 15
    target = issue_target_with_length(target_len)
    request_line, _head, _body = fu._wire_lengths(
        "GET", target, "jira-upstream.synthetic.invalid", "application/json", None, 0,
    )
    assert request_line == length
    kwargs = {
        "service": "jira", "route_id": "jira.issue.get", "policy_digest": POLICY_DIGEST,
        "scope_digest": SCOPE_DIGEST, "endpoint_digest": ENDPOINT_DIGEST_443, "method": "GET",
        "target": target, "authority": "jira-upstream.synthetic.invalid",
        "accept": "application/json",
        "content_type": None, "body_bytes": 0, "body_sha256": None, "body": b"",
    }
    if should_pass:
        fu.UpstreamDescriptor(**kwargs)
    else:
        assert_prepare_error(lambda: fu.UpstreamDescriptor(**kwargs), "request_unbuildable")


@pytest.mark.parametrize(
    ("length", "should_pass"),
    [(MAX_REQUEST_JSON_BYTES, True), (MAX_REQUEST_JSON_BYTES + 1, False)],
)
def test_wire_lengths_body_boundary(length, should_pass):
    body = b"{" + b"a" * (length - 2) + b"}" if length >= 2 else b"{}"
    kwargs = {
        "service": "jira", "route_id": "jira.search", "policy_digest": POLICY_DIGEST,
        "scope_digest": SCOPE_DIGEST, "endpoint_digest": ENDPOINT_DIGEST_443, "method": "POST",
        "target": "/rest/api/3/search/jql", "authority": "jira-upstream.synthetic.invalid",
        "accept": "application/json", "content_type": "application/json", "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(), "body": body,
    }
    if should_pass:
        fu.UpstreamDescriptor(**kwargs)
    else:
        assert_prepare_error(lambda: fu.UpstreamDescriptor(**kwargs), "request_unbuildable")


def _reference_render(document: dict, body: bytes, auth_value: bytes) -> bytes:
    prefix = f"{document['method']} {document['target']} HTTP/1.1\r\n".encode("ascii")
    prefix += f"Host: {document['authority']}\r\n".encode("ascii")
    suffix = f"Accept: {document['accept']}\r\nAccept-Encoding: identity\r\n".encode("ascii")
    if document["body_bytes"] > 0:
        suffix += (
            f"Content-Type: {document['content_type']}\r\n"
            f"Content-Length: {document['body_bytes']}\r\n"
        ).encode("ascii")
    suffix += b"Connection: close\r\n\r\n" + body
    return prefix + b"Authorization: " + auth_value + b"\r\n" + suffix


@pytest.mark.parametrize("routed_factory", [golden_issue_get_routed, golden_search_routed])
def test_reference_render_matches_production_wire(routed_factory):
    routed = routed_factory()
    descriptor = fu.request_descriptor(
        routed, endpoint_digest=ENDPOINT_DIGEST_443, authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    actual = parts.prefix + b"Authorization: " + SYNTHETIC_AUTH_VALUE + b"\r\n" + parts.suffix
    reference = _reference_render(descriptor.document(), routed.upstream.body, SYNTHETIC_AUTH_VALUE)
    assert actual == reference
    assert reference.split(b"Host: ")[1].split(b"\r\n")[0] == descriptor.authority.encode("ascii")
    if descriptor.body_bytes:
        assert str(descriptor.body_bytes).encode("ascii") in reference


def test_two_credentials_differ_only_in_authorization_value():
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    other_credential = golden_credential(user="other-user@example.invalid")
    wire_a = parts.prefix + b"Authorization: " + SYNTHETIC_AUTH_VALUE + b"\r\n" + parts.suffix
    wire_b = (
        parts.prefix + b"Authorization: " + other_credential._authorization
        + b"\r\n" + parts.suffix
    )
    lines_a = wire_a.split(b"\r\n")
    lines_b = wire_b.split(b"\r\n")
    assert lines_a[2].startswith(b"Authorization: ")
    for index, (line_a, line_b) in enumerate(zip(lines_a, lines_b)):
        if index == 2:
            assert line_a != line_b
        else:
            assert line_a == line_b


def test_sentinel_never_reaches_descriptor_or_parts():
    sentinel = "run:super-secret-sentinel-value"
    routed = golden_issue_get_routed()
    descriptor = fu.request_descriptor(
        routed, endpoint_digest=ENDPOINT_DIGEST_443, authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    haystacks = [repr(descriptor), repr(parts), parts.prefix, parts.suffix]
    for haystack in haystacks:
        text = haystack if isinstance(haystack, (bytes, bytearray)) else haystack.encode("utf-8")
        assert sentinel.encode("ascii") not in text


def test_render_parts_wrong_type_raises_type_error():
    with pytest.raises(TypeError):
        fu.render_parts("not a descriptor")


# =============================================================================
# 7. O2, pre-socket connect refusals
# =============================================================================


@pytest.fixture
def blocked_socket(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("connect must not create a socket for this case")

    monkeypatch.setattr("socket.socket", boom)


@pytest.fixture
def connector(real_ca_pem):
    endpoint = make_endpoint(real_ca_pem)
    credential = golden_credential()
    return fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential), endpoint


def _admission(**overrides):
    now = time.monotonic()
    kwargs = {
        "receipt_id": "r1", "lease_id": "l1", "service": "jira", "route_id": "jira.issue.get",
        "admitted_at": now, "deadline": now + 100.0, "exchange_deadline": now + 99.0,
        "connect_deadline": now + 5.0,
    }
    kwargs.update(overrides)
    return Admission(**kwargs)


def test_connect_rejects_v1_digest(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    assert_upstream_error(
        lambda: conn.connect(
            _admission(), routed, request_digest=ISSUE_GET_V1_DIGEST, deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


def test_connect_rejects_another_routes_v2_digest(blocked_socket, connector):
    conn, endpoint = connector
    other_digest = fu.request_descriptor(
        golden_search_routed(), endpoint_digest=endpoint.digest, authority=endpoint.authority,
    ).digest
    assert_upstream_error(
        lambda: conn.connect(
            _admission(), golden_issue_get_routed(), request_digest=other_digest,
            deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


class RefusingSocket:
    """Stands in for ``socket.socket``: records its calls, and ``connect`` is refused."""

    def __init__(self, created: list) -> None:
        self.timeouts: list[float] = []
        self.destinations: list[object] = []
        self.close_calls = 0
        created.append(self)

    def set_inheritable(self, value: bool) -> None:
        pass

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, destination) -> None:
        self.destinations.append(destination)
        raise ConnectionRefusedError("refused by the test double")

    def close(self) -> None:
        self.close_calls += 1


@pytest.fixture
def refusing_socket(monkeypatch) -> list:
    created: list[RefusingSocket] = []
    monkeypatch.setattr("socket.socket", lambda *args: RefusingSocket(created))
    return created


def test_connect_rejects_second_connect_for_same_admission(refusing_socket, connector):
    conn, endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission()

    def attempt():
        return conn.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline,
        )

    assert_upstream_error(attempt, "connect_failed")
    assert_upstream_error(attempt, "connect_failed")
    assert len(refusing_socket) == 1
    assert refusing_socket[0].destinations == [(endpoint.address, endpoint.port)]
    assert refusing_socket[0].close_calls == 1


def test_connect_consumes_the_admission_even_when_the_digest_is_refused(
    refusing_socket, connector,
):
    conn, endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission()

    def attempt(request_digest):
        return conn.connect(
            admission, routed, request_digest=request_digest,
            deadline=admission.connect_deadline,
        )

    assert_upstream_error(lambda: attempt(ISSUE_GET_V1_DIGEST), "connect_failed")
    assert_upstream_error(lambda: attempt(digest), "connect_failed")
    assert refusing_socket == []

    # Control: a fresh Admission with the same digest reaches the refused TCP connect.
    fresh = _admission()
    assert_upstream_error(
        lambda: conn.connect(
            fresh, routed, request_digest=digest, deadline=fresh.connect_deadline,
        ),
        "connect_failed",
    )
    assert [sock.destinations for sock in refusing_socket] == [
        [(endpoint.address, endpoint.port)],
    ]


def test_connect_clips_its_tcp_timeout_to_connect_seconds(refusing_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    now = time.monotonic()
    admission = _admission(
        admitted_at=now, deadline=now + 100.0, exchange_deadline=now + 90.0,
        connect_deadline=now + 60.0,
    )
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline,
        ),
        "connect_failed",
    )
    assert len(refusing_socket) == 1
    assert refusing_socket[0].timeouts
    assert max(refusing_socket[0].timeouts) <= fd.CONNECT_SECONDS


def test_connect_huge_int_deadline_gives_connect_failed(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    assert_upstream_error(
        lambda: conn.connect(
            _admission(), routed, request_digest=conn.prepare(routed), deadline=10**400,
        ),
        "connect_failed",
    )


class WhiteboxSecured:
    """A handshaken stand-in whose accessors pass ``_verify_post_handshake``."""

    session_reused = False

    def __init__(self, state: dict) -> None:
        self._state = state
        self.timeouts: list[float] = []
        self.send_calls: list[bytes] = []
        self.close_calls = 0

    def set_inheritable(self, value: bool) -> None:
        pass

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def do_handshake(self) -> None:
        self._state["handshaken"] = True

    def version(self) -> str:
        return "TLSv1.3"

    def selected_alpn_protocol(self) -> str:
        return "http/1.1"

    def compression(self) -> None:
        return None

    def getpeercert(self, binary_form: bool = False) -> bytes:
        return b"synthetic-der"

    def send(self, chunk) -> int:
        self.send_calls.append(bytes(chunk))
        return len(chunk)

    def close(self) -> None:
        self.close_calls += 1


class ConnectingSocket(RefusingSocket):
    def connect(self, destination) -> None:
        self.destinations.append(destination)


def whitebox_connect(
    monkeypatch, connector, *, clock, connect_deadline=1005.0, on_build=None,
    secured_type=WhiteboxSecured,
):
    """Drive ``connect`` over fakes, with a scripted ``forwarder_upstream.time``.

    The admission uses synthetic times from 1000.0; ``clock(state)`` sees
    ``state["handshaken"]`` flip once ``do_handshake`` has run.
    """
    state = {"handshaken": False}
    secured = secured_type(state)
    created: list[ConnectingSocket] = []

    class Context:
        def wrap_socket(self, raw, *, server_hostname, do_handshake_on_connect):
            assert (server_hostname, do_handshake_on_connect) == (
                "jira-upstream.synthetic.invalid", False,
            )
            return secured

    def build_context(ca_pem, trust_sha256):
        if on_build is not None:
            on_build()
        return Context()

    monkeypatch.setattr("socket.socket", lambda *args: ConnectingSocket(created))
    monkeypatch.setattr(fu, "_build_context", build_context)
    monkeypatch.setattr(fu, "time", types.SimpleNamespace(monotonic=lambda: clock(state)))
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission(
        admitted_at=1000.0, deadline=1100.0, exchange_deadline=1099.0,
        connect_deadline=connect_deadline,
    )

    def attempt():
        return conn.connect(admission, routed, request_digest=digest, deadline=connect_deadline)

    return attempt, secured, created


def _faulting_clock():
    raise RuntimeError("clock fault")


@pytest.mark.parametrize(
    ("final_reading", "code"),
    [(lambda: 1006.0, "deadline"), (lambda: math.nan, "connect_failed"),
     (lambda: 10**400, "connect_failed"), (_faulting_clock, "connect_failed")],
)
def test_connect_final_recheck_after_the_handshake(monkeypatch, connector, final_reading, code):
    def clock(state):
        return final_reading() if state["handshaken"] else 1000.0

    attempt, secured, created = whitebox_connect(monkeypatch, connector, clock=clock)
    assert_upstream_error(attempt, code)
    assert secured.close_calls == 1
    assert [sock.destinations for sock in created] == [[("192.0.2.10", 443)]]


@pytest.mark.parametrize("connect_deadline", [1005.0, 1060.0])
def test_connect_whitebox_control_returns_an_open_channel(
    monkeypatch, connector, connect_deadline,
):
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", WhiteboxSecured)
    attempt, secured, created = whitebox_connect(
        monkeypatch, connector, clock=lambda state: 1000.0, connect_deadline=connect_deadline,
    )
    channel = attempt()
    assert channel.state == "open"
    assert secured.close_calls == 0
    assert created[0].timeouts == [5.0]
    assert secured.timeouts == [5.0]
    channel.close()
    assert secured.close_calls == 1


def test_connect_hands_the_admission_exchange_deadline_to_the_channel(monkeypatch, connector):
    # The whitebox admission has exchange_deadline 1099.0 and deadline 1100.0.
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", WhiteboxSecured)
    attempt, secured, _created = whitebox_connect(
        monkeypatch, connector, clock=lambda state: 1000.0,
    )
    channel = attempt()
    assert_upstream_error(lambda: channel.send(deadline=1099.5), "write_failed")
    assert secured.send_calls == []

    attempt, secured, _created = whitebox_connect(
        monkeypatch, connector, clock=lambda state: 1000.0,
    )
    channel = attempt()
    channel.send(deadline=1099.0)
    assert len(secured.send_calls) == 1
    calls = _receive_spy(monkeypatch)
    assert_upstream_error(lambda: channel.receive(deadline=1099.5), "receive_failed")
    assert calls == []


def _secured_with(**overrides):
    return type("FaultySecured", (WhiteboxSecured,), overrides)


POST_HANDSHAKE_FAULTS = {
    "tls11": _secured_with(version=lambda self: "TLSv1.1"),
    "alpn-h2": _secured_with(selected_alpn_protocol=lambda self: "h2"),
    "compression": _secured_with(compression=lambda self: "zlib"),
    "session-reused": _secured_with(session_reused=True),
    "empty-peer-cert": _secured_with(getpeercert=lambda self, binary_form=False: b""),
    "no-peer-cert": _secured_with(getpeercert=lambda self, binary_form=False: None),
}


@pytest.mark.parametrize("fault", sorted(POST_HANDSHAKE_FAULTS))
def test_connect_post_handshake_checks_give_upstream_tls_failed(monkeypatch, connector, fault):
    secured_type = POST_HANDSHAKE_FAULTS[fault]
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", secured_type)
    attempt, secured, _created = whitebox_connect(
        monkeypatch, connector, clock=lambda state: 1000.0, secured_type=secured_type,
    )
    assert_upstream_error(attempt, "upstream_tls_failed")
    assert secured.close_calls == 1


@pytest.mark.parametrize(("after_build", "code"), [(1000.3, "deadline"), (1000.05, None)])
def test_connect_rereads_the_clock_after_building_the_context(
    monkeypatch, connector, after_build, code,
):
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", WhiteboxSecured)
    readings = {"now": 1000.0}
    attempt, _secured, created = whitebox_connect(
        monkeypatch, connector, clock=lambda state: readings["now"], connect_deadline=1000.1,
        on_build=lambda: readings.update(now=after_build),
    )
    if code is not None:
        assert_upstream_error(attempt, code)
        assert created == []
    else:
        attempt().close()
        assert created[0].timeouts == [pytest.approx(1000.1 - after_build)]


def test_connect_rejects_mismatched_route_or_service(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    admission = _admission(route_id="jira.search")
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=conn.prepare(routed), deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


def test_connect_rejects_a_mismatched_admission_service(blocked_socket, connector):
    # ``connect`` guards on ``admission.service != "jira"`` as its own clause, distinct
    # from ``routed.service`` and ``admission.route_id``/``routed.route_id``. Only the
    # route half of that guard had a dedicated test; this pins the service half so a
    # deleted ``admission.service != "jira" or `` clause cannot silently let a
    # cross-service admission reach a real socket (``blocked_socket`` fails loudly if it did).
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    admission = _admission(service="confluence")
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=conn.prepare(routed), deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


def test_connect_rejects_wrong_types(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    assert_upstream_error(
        lambda: conn.connect(
            "not an admission", routed, request_digest="a" * 64, deadline=1.0,
        ),
        "connect_failed",
    )
    assert_upstream_error(
        lambda: conn.connect(
            _admission(), "not a routed request", request_digest="a" * 64, deadline=1.0,
        ),
        "connect_failed",
    )


def test_connect_rejects_non_hex_digest(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    assert_upstream_error(
        lambda: conn.connect(
            _admission(), routed, request_digest="not-hex", deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


def test_connect_rejects_deadline_beyond_connect_deadline(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission()
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline + 10,
        ),
        "connect_failed",
    )


def test_connect_gives_deadline_for_a_passed_deadline(blocked_socket, connector):
    conn, _endpoint = connector
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission()
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=digest, deadline=time.monotonic() - 1,
        ),
        "deadline",
    )


def test_connect_faulting_clock_gives_connect_failed(monkeypatch, connector):
    conn, _endpoint = connector

    def boom(*a, **k):
        raise AssertionError("no socket")

    monkeypatch.setattr("socket.socket", boom)
    routed = golden_issue_get_routed()
    digest = conn.prepare(routed)
    admission = _admission()

    def bad_clock():
        raise RuntimeError("clock fault")

    monkeypatch.setattr(fu.time, "monotonic", bad_clock)
    assert_upstream_error(
        lambda: conn.connect(
            admission, routed, request_digest=digest, deadline=admission.connect_deadline,
        ),
        "connect_failed",
    )


def test_connect_8443_connector_digest_rejected_by_443_connector(real_ca_pem, blocked_socket):
    endpoint_443 = make_endpoint(real_ca_pem)
    endpoint_8443 = make_endpoint(real_ca_pem, port=8443)
    conn_443 = fu.JiraUpstreamConnector(endpoint=endpoint_443, credential=golden_credential())
    conn_8443 = fu.JiraUpstreamConnector(endpoint=endpoint_8443, credential=golden_credential())
    routed = golden_issue_get_routed()
    digest_8443 = conn_8443.prepare(routed)
    assert_upstream_error(
        lambda: conn_443.connect(
            _admission(), routed, request_digest=digest_8443, deadline=time.monotonic() + 1,
        ),
        "connect_failed",
    )


# =============================================================================
# 8. Channel
# =============================================================================


def test_channel_constructor_rejects_wrong_token_and_types(monkeypatch):
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", FakeTLSSocket)
    sock = FakeTLSSocket()
    parts = fu.RequestParts(prefix=b"a", suffix=b"b")
    credential = golden_credential()
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            object(), sock=sock, parts=parts, credential=credential, exchange_deadline=10.0,
        )
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock="not a socket", parts=parts, credential=credential,
            exchange_deadline=10.0,
        )
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=sock, parts="not parts", credential=credential,
            exchange_deadline=10.0,
        )
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential="not a credential",
            exchange_deadline=10.0,
        )
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential=credential,
            exchange_deadline=True,
        )
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential=credential,
            exchange_deadline=math.nan,
        )


def test_channel_constructor_requires_the_monkeypatched_socket_type():
    sock = FakeTLSSocket()
    parts = fu.RequestParts(prefix=b"a", suffix=b"b")
    credential = golden_credential()
    with pytest.raises(TypeError):
        fu._UpstreamChannel(
            fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential=credential,
            exchange_deadline=10.0,
        )


def test_send_writes_golden_bytes_once(monkeypatch):
    descriptor = fu.request_descriptor(
        golden_issue_get_routed(), endpoint_digest=ENDPOINT_DIGEST_443,
        authority="jira-upstream.synthetic.invalid",
    )
    parts = fu.render_parts(descriptor)
    credential = golden_credential()
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock, parts=parts, credential=credential)
    channel.send(deadline=time.monotonic() + 5)
    assert channel.state == "sent"
    captured = b"".join(bytes(chunk) for _obj, chunk in sock.captured_chunks)
    assert captured == FULL_WIRE_ISSUE_GET
    assert hashlib.sha256(captured).hexdigest() == FULL_WIRE_ISSUE_GET_SHA256
    assert channel.bytes_accepted == len(FULL_WIRE_ISSUE_GET)


def test_second_send_and_send_after_abort_or_close_write_nothing(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.send(deadline=time.monotonic() + 5)
    first_call_count = len(sock.send_calls)
    assert_upstream_error(lambda: channel.send(deadline=time.monotonic() + 5), "write_failed")
    assert len(sock.send_calls) == first_call_count

    sock2 = FakeTLSSocket()
    channel2 = make_channel(monkeypatch, sock2)
    channel2.abort()
    assert_upstream_error(lambda: channel2.send(deadline=time.monotonic() + 5), "write_failed")
    assert sock2.send_calls == []

    sock3 = FakeTLSSocket()
    channel3 = make_channel(monkeypatch, sock3)
    channel3.close()
    assert_upstream_error(lambda: channel3.send(deadline=time.monotonic() + 5), "write_failed")
    assert sock3.send_calls == []


def test_send_deadline_past_exchange_deadline_writes_nothing(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock, exchange_deadline=time.monotonic() + 1.0)
    assert_upstream_error(
        lambda: channel.send(deadline=time.monotonic() + 5.0), "write_failed",
    )
    assert sock.send_calls == []


def test_send_chunks_a_large_body(monkeypatch):
    body = b"B" * 40_000
    parts = fu.RequestParts(prefix=b"", suffix=body)
    sock = FakeTLSSocket()
    credential = golden_credential()
    channel = make_channel(monkeypatch, sock, parts=parts, credential=credential)
    channel.send(deadline=time.monotonic() + 5)
    sizes = [len(chunk) for _obj, chunk in sock.captured_chunks]
    total = len(b"Authorization: ") + len(credential._authorization) + len(b"\r\n") + len(body)
    expected_sizes = []
    remaining = total
    while remaining > 0:
        step = min(fu.MAX_WRITE_CHUNK_BYTES, remaining)
        expected_sizes.append(step)
        remaining -= step
    assert sizes == expected_sizes
    assert all(size <= fu.MAX_WRITE_CHUNK_BYTES for size in sizes)


def test_send_handles_partial_counts(monkeypatch):
    body = b"C" * 30
    parts = fu.RequestParts(prefix=b"", suffix=body)
    credential = golden_credential()
    total = len(b"Authorization: ") + len(credential._authorization) + len(b"\r\n") + len(body)
    results = [7] * (total // 7) + ([total % 7] if total % 7 else [])
    sock = FakeTLSSocket(send_results=results)
    channel = make_channel(monkeypatch, sock, parts=parts, credential=credential)
    channel.send(deadline=time.monotonic() + 5)
    assert channel.state == "sent"
    assert len(sock.send_calls) == len(results)


def test_send_settimeout_is_bounded(monkeypatch):
    sock = FakeTLSSocket()
    deadline = time.monotonic() + 3.0
    channel = make_channel(monkeypatch, sock, exchange_deadline=deadline)
    channel.send(deadline=deadline)
    for value in sock.settimeout_calls:
        assert value <= fd.WRITE_SECONDS + 0.05
        assert value <= 3.05


def test_send_between_chunk_deadline_gives_deadline(monkeypatch):
    body = b"D" * 40_000
    parts = fu.RequestParts(prefix=b"", suffix=body)
    sock = FakeTLSSocket()
    real_monotonic = time.monotonic
    deadline = real_monotonic() + 100.0
    channel = make_channel(monkeypatch, sock, parts=parts, exchange_deadline=deadline + 50.0)

    calls = {"count": 0}

    def fake_monotonic():
        calls["count"] += 1
        if calls["count"] <= 3:
            return real_monotonic()
        return deadline + 1.0

    monkeypatch.setattr(fu.time, "monotonic", fake_monotonic)
    assert_upstream_error(lambda: channel.send(deadline=deadline), "deadline")


def test_send_per_chunk_abort_check(monkeypatch):
    body = b"E" * 40_000
    parts = fu.RequestParts(prefix=b"", suffix=body)

    channel_holder = {}

    def on_send(index):
        if index == 0:
            channel_holder["channel"].abort()

    sock = FakeTLSSocket(on_send=on_send)
    channel = make_channel(monkeypatch, sock, parts=parts)
    channel_holder["channel"] = channel
    assert_upstream_error(lambda: channel.send(deadline=time.monotonic() + 5), "write_failed")
    assert len(sock.send_calls) == 1


def test_send_abort_between_step_and_assembly(monkeypatch):
    channel_holder = {}
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel_holder["channel"] = channel

    real_monotonic = time.monotonic
    calls = {"count": 0}

    def stub_monotonic():
        calls["count"] += 1
        if calls["count"] == 1:
            channel_holder["channel"].abort()
        return real_monotonic()

    monkeypatch.setattr(fu.time, "monotonic", stub_monotonic)
    assert_upstream_error(lambda: channel.send(deadline=real_monotonic() + 5), "write_failed")
    assert sock.send_calls == []


def test_send_assembly_uses_the_captured_credential_not_self_credential(monkeypatch):
    # By the time assembly runs, ``abort()`` (triggered below between the initial step
    # and assembly) has already dropped ``self._credential`` to ``None``. Assembly must
    # still succeed, using the local ``credential`` captured under the lock before any
    # I/O -- never re-reading ``self._credential``. A mutant that re-reads
    # ``self._credential`` would hit ``None._authorization`` and fail assembly *before*
    # ``memoryview(buffer)`` is ever called, which this test can tell apart from a
    # successful assembly that reaches -- and is captured at -- that exact point.
    channel_holder = {}
    sock = FakeTLSSocket()
    credential = golden_credential()
    channel = make_channel(monkeypatch, sock, credential=credential)
    channel_holder["channel"] = channel

    real_monotonic = time.monotonic
    calls = {"count": 0}

    def stub_monotonic():
        calls["count"] += 1
        if calls["count"] == 1:
            channel_holder["channel"].abort()
        return real_monotonic()

    monkeypatch.setattr(fu.time, "monotonic", stub_monotonic)

    captured: list[bytes] = []
    import builtins
    real_memoryview = builtins.memoryview

    def spy_memoryview(buf):
        captured.append(bytes(buf))
        return real_memoryview(buf)

    monkeypatch.setattr(fu, "memoryview", spy_memoryview, raising=False)

    assert_upstream_error(lambda: channel.send(deadline=real_monotonic() + 5), "write_failed")
    assert sock.send_calls == []
    assert channel._credential is None  # abort really did drop it before assembly ran
    # If assembly never reaches memoryview(), it must have read self._credential instead.
    assert len(captured) == 1
    assert SYNTHETIC_AUTH_VALUE in captured[0]


def test_send_custody_zeroes_buffer_on_success(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.send(deadline=time.monotonic() + 5)
    for buffer_obj, _copy in sock.captured_chunks:
        assert buffer_obj is sock.captured_chunks[0][0]
        assert bytes(buffer_obj) == bytes(len(buffer_obj))


def test_send_custody_zeroes_buffer_on_failure_and_drops_credential(monkeypatch):
    sock = FakeTLSSocket(send_results=[RuntimeError("boom")])
    credential = golden_credential()
    channel = make_channel(monkeypatch, sock, credential=credential)
    with pytest.raises(UpstreamError) as raised:
        channel.send(deadline=time.monotonic() + 5)
    tb = raised.value.__traceback__
    send_frame = None
    while tb is not None:
        if tb.tb_frame.f_code.co_name == "send":
            send_frame = tb.tb_frame
        tb = tb.tb_next
    assert send_frame is not None
    buffer_local = send_frame.f_locals.get("buffer")
    if buffer_local is not None:
        assert bytes(buffer_local) == bytes(len(buffer_local))
    assert send_frame.f_locals.get("credential") is None


def test_receive_before_send_gives_receive_failed(monkeypatch):
    spy_calls = []

    def spy(sock, *, deadline):
        spy_calls.append((sock, deadline))
        return ParsedResponse(200, b"{}")

    monkeypatch.setattr(fu, "receive_response", spy)
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    assert_upstream_error(lambda: channel.receive(deadline=time.monotonic() + 5), "receive_failed")
    assert spy_calls == []


def test_receive_calls_the_spy_once_with_identical_args(monkeypatch):
    spy_calls = []

    def spy(sock, *, deadline):
        spy_calls.append((sock, deadline))
        return ParsedResponse(200, b'{"ok":true}')

    monkeypatch.setattr(fu, "receive_response", spy)
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.send(deadline=time.monotonic() + 5)
    deadline = time.monotonic() + 5
    result = channel.receive(deadline=deadline)
    assert result.status == 200
    assert len(spy_calls) == 1
    assert spy_calls[0] == (sock, deadline)
    assert channel.state == "received"

    assert_upstream_error(lambda: channel.receive(deadline=time.monotonic() + 5), "receive_failed")
    assert len(spy_calls) == 1


@pytest.mark.parametrize(
    ("error_code", "expected"),
    [
        ("deadline_expired", "deadline"),
        ("invalid_deadline", "receive_failed"),
        ("receive_failed", "receive_failed"),
        ("invalid_connection", "receive_failed"),
        ("connection_claimed", "receive_failed"),
        ("clock_fault", "receive_failed"),
        ("timeout_restore_failed", "receive_failed"),
    ],
)
def test_receive_mapping_table(monkeypatch, error_code, expected):
    def spy(sock, *, deadline):
        raise ResponseReceiveError(error_code)

    monkeypatch.setattr(fu, "receive_response", spy)
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.send(deadline=time.monotonic() + 5)
    assert_upstream_error(lambda: channel.receive(deadline=time.monotonic() + 5), expected)


def test_receive_maps_other_exception_and_wrong_result_type(monkeypatch):
    def raises_runtime(sock, *, deadline):
        raise RuntimeError("stall")

    monkeypatch.setattr(fu, "receive_response", raises_runtime)
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.send(deadline=time.monotonic() + 5)
    assert_upstream_error(lambda: channel.receive(deadline=time.monotonic() + 5), "receive_failed")

    def returns_wrong_type(sock, *, deadline):
        return object()

    monkeypatch.setattr(fu, "receive_response", returns_wrong_type)
    sock2 = FakeTLSSocket()
    channel2 = make_channel(monkeypatch, sock2)
    channel2.send(deadline=time.monotonic() + 5)
    assert_upstream_error(lambda: channel2.receive(deadline=time.monotonic() + 5), "receive_failed")


def _receive_spy(monkeypatch) -> list:
    calls: list[object] = []

    def spy(sock, *, deadline):
        calls.append(deadline)
        return ParsedResponse(200, b"{}")

    monkeypatch.setattr(fu, "receive_response", spy)
    return calls


def test_receive_refuses_a_deadline_past_exchange_deadline(monkeypatch):
    calls = _receive_spy(monkeypatch)
    exchange_deadline = time.monotonic() + 5.0
    channel = make_channel(monkeypatch, FakeTLSSocket(), exchange_deadline=exchange_deadline)
    channel.send(deadline=exchange_deadline)
    assert_upstream_error(
        lambda: channel.receive(deadline=exchange_deadline + 10.0), "receive_failed",
    )
    assert calls == []
    assert channel.state == "failed"


def test_receive_after_abort_reads_nothing(monkeypatch):
    calls = _receive_spy(monkeypatch)
    monkeypatch.setattr(fu, "_shutdown_fd", lambda sock: None)
    channel = make_channel(monkeypatch, FakeTLSSocket())
    channel.send(deadline=time.monotonic() + 5)
    channel.abort()
    assert_upstream_error(lambda: channel.receive(deadline=time.monotonic() + 5), "receive_failed")
    assert calls == []


def test_huge_int_deadlines_map_to_closed_codes(monkeypatch):
    calls = _receive_spy(monkeypatch)
    huge = 10**400
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    assert_upstream_error(lambda: channel.send(deadline=huge), "write_failed")
    assert sock.send_calls == []
    assert channel.state == "failed"

    sent = make_channel(monkeypatch, FakeTLSSocket())
    sent.send(deadline=time.monotonic() + 5)
    assert_upstream_error(lambda: sent.receive(deadline=huge), "receive_failed")
    assert calls == []
    assert sent.state == "failed"

    with pytest.raises(TypeError):
        make_channel(monkeypatch, FakeTLSSocket(), exchange_deadline=huge)


class _Escape(BaseException):
    """Not an ``Exception``: it escapes every handler in the module."""


def test_an_escaping_error_never_marks_send_or_receive_complete(monkeypatch):
    sock = FakeTLSSocket(send_results=[_Escape()])
    channel = make_channel(monkeypatch, sock)
    with pytest.raises(_Escape):
        channel.send(deadline=time.monotonic() + 5)
    assert channel.state == "failed"
    assert_upstream_error(lambda: channel.receive(deadline=time.monotonic() + 5), "receive_failed")

    def escaping(sock, *, deadline):
        raise _Escape

    monkeypatch.setattr(fu, "receive_response", escaping)
    received = make_channel(monkeypatch, FakeTLSSocket())
    received.send(deadline=time.monotonic() + 5)
    with pytest.raises(_Escape):
        received.receive(deadline=time.monotonic() + 5)
    assert received.state == "failed"


def scripted_clock(monkeypatch, readings) -> None:
    """Replace ``forwarder_upstream.time``; once the script ends, the last reading repeats."""
    remaining = list(readings)

    def monotonic():
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    monkeypatch.setattr(fu, "time", types.SimpleNamespace(monotonic=monotonic))


def test_send_total_write_is_clipped_to_write_seconds(monkeypatch):
    sock = FakeTLSSocket()
    parts = fu.RequestParts(prefix=b"", suffix=b"F" * 40_000)
    channel = make_channel(monkeypatch, sock, parts=parts, exchange_deadline=1600.0)
    scripted_clock(monkeypatch, [1000.0 + 3.0 * step for step in range(20)])
    assert_upstream_error(lambda: channel.send(deadline=1600.0), "deadline")
    assert len(sock.send_calls) == 2
    assert sock.settimeout_calls == [7.0, 1.0]


@pytest.mark.parametrize(
    "readings",
    [(1000.0, 1001.0, 1002.0, 1000.5), (1000.0, 1001.0, 1000.5)],
    ids=["before-a-chunk", "after-a-chunk"],
)
def test_send_clock_regression_gives_write_failed(monkeypatch, readings):
    sock = FakeTLSSocket()
    parts = fu.RequestParts(prefix=b"", suffix=b"G" * 40_000)
    channel = make_channel(monkeypatch, sock, parts=parts, exchange_deadline=1600.0)
    scripted_clock(monkeypatch, readings)
    assert_upstream_error(lambda: channel.send(deadline=1600.0), "write_failed")
    assert len(sock.send_calls) == 1


def test_send_single_chunk_stall_gives_write_failed(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock, exchange_deadline=1600.0)
    scripted_clock(monkeypatch, [1000.0, 1001.0, 1011.0])
    assert_upstream_error(lambda: channel.send(deadline=1600.0), "write_failed")
    assert len(sock.send_calls) == 1


@pytest.mark.parametrize("reading", [math.nan, 10**400], ids=["nan", "huge-int"])
def test_send_non_finite_clock_gives_write_failed(monkeypatch, reading):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock, exchange_deadline=1600.0)
    scripted_clock(monkeypatch, [reading])
    assert_upstream_error(lambda: channel.send(deadline=1600.0), "write_failed")
    assert sock.send_calls == []


def test_abort_and_close_drop_the_credential_without_a_send(monkeypatch):
    monkeypatch.setattr(fu, "_shutdown_fd", lambda sock: None)
    aborted = make_channel(monkeypatch, FakeTLSSocket())
    aborted.abort()
    assert aborted._credential is None
    closed = make_channel(monkeypatch, FakeTLSSocket())
    closed.close()
    assert closed._credential is None


def test_abort_is_idempotent_with_one_shutdown_call(monkeypatch):
    calls = []
    monkeypatch.setattr(fu, "_shutdown_fd", lambda sock: calls.append(sock))
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.abort()
    channel.abort()
    assert calls == [sock]
    assert channel.state == "aborted"


def test_abort_after_close_makes_no_shutdown_call(monkeypatch):
    calls = []
    monkeypatch.setattr(fu, "_shutdown_fd", lambda sock: calls.append(sock))
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.close()
    channel.abort()
    assert calls == []
    assert channel.state == "closed"


def test_abort_runs_shutdown_fd_while_holding_the_lock(monkeypatch):
    # The fd-reuse safety argument for ``abort()`` rests on ``_shutdown_fd`` executing
    # under the same ``_lock`` that guards ``close()``'s fd hand-off. Proven here by
    # having the (monkeypatched) ``_shutdown_fd`` try to acquire that very lock,
    # non-blocking, from inside the call: it must fail, because ``abort()`` is still
    # holding it. If ``_shutdown_fd(sock)`` were moved outside the ``with self._lock:``
    # block, the lock would already be free and this acquire would succeed.
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    observed: dict[str, object] = {}

    def shutdown_recorder(observed_sock):
        observed["lock_was_free"] = channel._lock.acquire(blocking=False)
        if observed["lock_was_free"]:
            channel._lock.release()
        observed["sock"] = observed_sock

    monkeypatch.setattr(fu, "_shutdown_fd", shutdown_recorder)
    channel.abort()
    assert observed["sock"] is sock
    assert observed["lock_was_free"] is False


def test_shutdown_fd_swallows_the_type_error_from_a_non_sslsocket():
    fu._shutdown_fd(object())  # super(ssl.SSLSocket, ...) raises TypeError; swallowed.
    fu._shutdown_fd(FakeTLSSocket())  # likewise for the documented white-box fake.


def test_unpatched_shutdown_fd_on_fake_socket_is_swallowed(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.abort()  # real _shutdown_fd raises TypeError internally; swallowed
    assert channel.state == "aborted"


def test_close_is_idempotent_with_one_sock_close(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    channel.close()
    channel.close()
    assert sock.close_calls == 1
    assert channel.state == "closed"


def test_close_swallows_close_exceptions(monkeypatch):
    class RaisingCloseSocket(FakeTLSSocket):
        def close(self):
            self.close_calls += 1
            raise OSError("close failed")

    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", RaisingCloseSocket)
    sock = RaisingCloseSocket()
    parts = fu.RequestParts(prefix=b"a", suffix=b"b")
    channel = fu._UpstreamChannel(
        fu._CHANNEL_TOKEN, sock=sock, parts=parts, credential=golden_credential(),
        exchange_deadline=time.monotonic() + 10,
    )
    channel.close()  # must not raise
    assert sock.close_calls == 1


def test_close_during_active_send_defers_until_finish_io(monkeypatch):
    # A close() that lands mid-send (while _io_active) cannot stop bytes already
    # in flight for the current chunk; it shuts down the fd and defers the actual
    # close to _finish_io, which runs once send() completes.
    events: list[str] = []
    channel_holder = {}

    def on_send(index):
        channel_holder["channel"].close()
        events.append("close")

    def shutdown_recorder(sock):
        events.append("shutdown")

    monkeypatch.setattr(fu, "_shutdown_fd", shutdown_recorder)
    sock = FakeTLSSocket(on_send=on_send)
    channel = make_channel(monkeypatch, sock)
    channel_holder["channel"] = channel
    channel.send(deadline=time.monotonic() + 5)  # the single small chunk still completes
    events.append("send returns")
    assert events == ["shutdown", "close", "send returns"]
    assert sock.close_calls == 1
    assert channel.state == "closed"


def test_close_during_active_send_never_closes_the_socket_before_send_returns(monkeypatch):
    # The invariant behind the defer: while ``send()`` still owns the socket
    # (``_io_active``), a concurrent ``close()`` must set ``_close_pending`` and return
    # *without* touching the socket -- the actual close only happens later, from
    # ``_finish_io``, once ``send()`` is done with it. If ``close()``'s ``_io_active``
    # branch fell through instead of returning, it would close the live socket right
    # here, synchronously, while ``send()`` is still using it (the fd-reuse hazard).
    # ``on_send`` runs synchronously inside the one chunk's ``sock.send()`` call, so this
    # is deterministic and needs no real threads to observe the ordering.
    channel_holder = {}
    close_calls_during_send: list[int] = []

    def on_send(index):
        channel_holder["channel"].close()
        close_calls_during_send.append(sock.close_calls)

    sock = FakeTLSSocket(on_send=on_send)
    channel = make_channel(monkeypatch, sock)
    channel_holder["channel"] = channel
    channel.send(deadline=time.monotonic() + 5)  # the single small chunk still completes
    assert close_calls_during_send == [0]
    assert sock.close_calls == 1
    assert channel.state == "closed"


def test_channel_repr_shows_only_state(monkeypatch):
    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    assert repr(channel) == "_UpstreamChannel(state='open')"


def test_channel_is_not_copyable(monkeypatch):
    import copy
    import pickle

    sock = FakeTLSSocket()
    channel = make_channel(monkeypatch, sock)
    with pytest.raises(TypeError):
        pickle.dumps(channel)
    with pytest.raises(TypeError):
        copy.copy(channel)
    with pytest.raises(TypeError):
        copy.deepcopy(channel)


def _run_channel_race_action(channel, action: str, abort_seconds: list[float]) -> None:
    if action == "abort":
        started = time.perf_counter()
        channel.abort()
        abort_seconds.append(time.perf_counter() - started)
    elif action == "close":
        channel.close()
    elif action == "send":
        try:
            channel.send(deadline=time.monotonic() + 5)
        except UpstreamError:
            pass
    else:
        try:
            channel.receive(deadline=time.monotonic() + 5)
        except UpstreamError:
            pass


class SlowSendSocket(FakeTLSSocket):
    def send(self, chunk) -> int:
        time.sleep(0.001)  # widens the window in which a racing close finds the send active
        return super().send(chunk)


def test_channel_races_under_a_barrier(monkeypatch):
    monkeypatch.setattr(fu, "_CHANNEL_SOCKET_TYPE", SlowSendSocket)
    _receive_spy(monkeypatch)
    workers, iterations = 8, 200
    rng = random.Random(20260923)
    plan = [
        rng.choices(("abort", "close", "send", "receive"), k=workers) for _ in range(iterations)
    ]
    socks = [SlowSendSocket() for _ in range(iterations)]
    channels: list = [None] * iterations
    credential = golden_credential()
    parts = fu.RequestParts(prefix=b"GET / HTTP/1.1\r\nHost: h\r\n", suffix=b"Accept: a\r\n\r\n")
    start = threading.Barrier(workers + 1)
    finish = threading.Barrier(workers + 1)
    abort_seconds: list[float] = []
    exceptions: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            for iteration in range(iterations):
                start.wait(timeout=4)
                _run_channel_race_action(channels[iteration], plan[iteration][index], abort_seconds)
                finish.wait(timeout=4)
        except BaseException as error:  # noqa: BLE001 - collected for the assertion below.
            exceptions.append(error)
            start.abort()
            finish.abort()

    pool = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(workers)]
    for thread in pool:
        thread.start()
    try:
        for iteration in range(iterations):
            channels[iteration] = fu._UpstreamChannel(
                fu._CHANNEL_TOKEN, sock=socks[iteration], parts=parts, credential=credential,
                exchange_deadline=time.monotonic() + 100.0,
            )
            start.wait(timeout=4)
            finish.wait(timeout=4)
            channels[iteration].close()
    except threading.BrokenBarrierError as error:
        exceptions.append(error)
        start.abort()
        finish.abort()
    for thread in pool:
        thread.join(timeout=4)
    assert not any(thread.is_alive() for thread in pool)
    assert exceptions == []
    assert [sock.close_calls for sock in socks] == [1] * iterations
    assert abort_seconds
    assert max(abort_seconds) < 0.1


# =============================================================================
# 9. Error discipline
# =============================================================================


def test_all_upstream_config_codes_have_clean_args():
    for code in fu.UPSTREAM_CONFIG_CODES:
        error = fu.UpstreamConfigError(code)
        assert error.args == (code,)
        assert error.__cause__ is None
        assert error.__context__ is None
        assert str(error) == code


def test_all_upstream_prepare_codes_have_clean_args():
    for code in fu.UPSTREAM_PREPARE_CODES:
        error = fu.UpstreamPrepareError(code)
        assert error.args == (code,)
        assert error.__cause__ is None
        assert error.__context__ is None
        assert str(error) == code


def test_connect_and_channel_errors_are_clean(monkeypatch, connector):
    conn, _endpoint = connector

    def boom(*a, **k):
        raise AssertionError

    monkeypatch.setattr("socket.socket", boom)
    routed = golden_issue_get_routed()
    try:
        conn.connect(_admission(), routed, request_digest="not-hex", deadline=time.monotonic() + 1)
    except UpstreamError as error:
        assert error.args == ("connect_failed",)
        assert error.__cause__ is None
        assert error.__context__ is None
    else:
        pytest.fail("expected UpstreamError")


def test_endpoint_document_pure_function_no_side_effects():
    before = dict(fu.CREDENTIAL_PROFILES)
    fu.endpoint_document(
        service="jira", revision="upstream-r1", host="jira-upstream.synthetic.invalid",
        address="192.0.2.10", port=443, trust_sha256=TRUST_STANDIN,
        credential_id="jira-basic-synthetic-1",
    )
    assert dict(fu.CREDENTIAL_PROFILES) == before


def test_route_catalog_states_and_policy_readiness_are_unchanged():
    from grafana_jsm_sandbox.forwarder_routes import policy_readiness_facts

    assert ROUTE_CATALOG["jira.issue.get"].state == "partial"
    assert ROUTE_CATALOG["jira.search"].state == "partial"
    facts = policy_readiness_facts()
    assert all(value is False for value in facts.values())


# =============================================================================
# 10. Gap closures (S1, S2, T2, T5)
# =============================================================================


def test_basic_credential_reinit_after_claim_is_refused_and_inert(real_ca_pem):
    # S1: a second __init__ on an already-initialized credential must refuse,
    # even once claimed by a connector, and must disturb neither the secret,
    # the id, nor the claim state -- a deleted guard would silently reset all three.
    credential = golden_credential()
    endpoint = make_endpoint(real_ca_pem)
    fu.JiraUpstreamConnector(endpoint=endpoint, credential=credential)
    assert credential._claimed is True

    with pytest.raises(AttributeError) as raised:
        fu.BasicCredential.__init__(
            credential, service="jira", profile="basic",
            credential_id="jira-basic-synthetic-1", user="new-user@example.invalid",
            token="new-token-0002",
        )
    assert raised.value.args == ("BasicCredential is immutable",)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None

    # still claimed: a second connector claim is still refused, not silently reset.
    assert credential._claimed is True
    assert_config_error(
        lambda: fu.JiraUpstreamConnector(
            endpoint=make_endpoint(real_ca_pem), credential=credential,
        ),
        "credential_claimed",
    )
    # the secret and id the custody tests inspect are unchanged.
    assert credential._authorization == SYNTHETIC_AUTH_VALUE
    assert credential._credential_id == "jira-basic-synthetic-1"


def test_encode_json_string_refuses_non_printable_or_non_ascii():
    # S2: control characters, DEL, non-ASCII and a lone surrogate are all refused,
    # with no chained context (no UnicodeEncodeError or similar survives).
    cases = ["\x00", "\x1f", "\x7f", "\n", "\t", "\u2028", "\udc80", "café"]
    for value in cases:
        assert_config_error(lambda value=value: fu._encode_json_string(value), "endpoint_invalid")


def test_encode_json_string_matches_json_dumps_for_printable_ascii():
    # S2: for printable ASCII, including the two characters this hand-rolled
    # encoder escapes itself, the result is byte-for-byte what json.dumps gives.
    import json

    cases = [
        "", "a", 'has "quotes"', "back\\slash", 'both\\ and "',
        "".join(chr(c) for c in range(0x20, 0x7F)),
    ]
    for value in cases:
        assert fu._encode_json_string(value) == json.dumps(value, ensure_ascii=True)


def test_verify_context_readback_store_count_alone_is_checked():
    # T2: the existing paired test corrupts get_ca_certs too, so the digest
    # clause fires regardless of the store-count clause. Here get_ca_certs
    # returns a digest-matching DER set -- only the store-count clause can
    # be what raises, isolating it from the digest-equality clause after it.
    der = b"a fake DER certificate blob, count-isolation variant"
    trust = (hashlib.sha256(der).hexdigest(),)
    context = _FakeReadbackContext(trust)
    context.get_ca_certs = lambda binary_form=False: [der]
    context.cert_store_stats = lambda: {"x509": 2, "x509_ca": 2}
    with pytest.raises(ValueError):
        fu._verify_context_readback(context, trust)


def test_seeded_property_500_policy_routed_variants_bind_v2_and_avoid_denials():
    """T5: ~500 requests through the committed unit-12 ``RoutePolicy`` (not
    hand-built), varying selector form and query spelling for
    ``jira.issue.get``, ``maxResults``/body whitespace/fields order for
    ``jira.search``, and manifests of 1..256 scoped entries for both. v2 is
    64 hex, differs from v1 and from every unit-12 denial digest, agrees for
    equal upstreams reached through genuinely different wire forms, and
    moves when a binding-only field (the endpoint digest) changes -- and,
    isolated from everything else, when only the target differs.
    """
    import json

    from grafana_jsm_sandbox.forwarder_http import ParsedRequest
    from grafana_jsm_sandbox.forwarder_routes import (
        JiraScope,
        RoutePolicy,
        ScopedIssue,
        ScopeManifest,
    )
    from tests.test_forwarder_routes import DENIAL_DIGESTS, golden_policy

    jira_policy = golden_policy()
    policy = RoutePolicy(jira=jira_policy)
    denial_digests = set(DENIAL_DIGESTS.values())
    authority = "jira-upstream.synthetic.invalid"
    rng = random.Random(20260924)

    def assert_v2_is_sound(routed):
        descriptor = fu.request_descriptor(
            routed, endpoint_digest=ENDPOINT_DIGEST_443, authority=authority,
        )
        digest = descriptor.digest
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)
        assert digest != routed.request_digest
        assert digest not in denial_digests
        different = fu.request_descriptor(
            routed, endpoint_digest=ENDPOINT_DIGEST_8443, authority=authority,
        )
        assert different.digest != digest
        return digest

    # --- jira.issue.get: selector form, query spelling, manifest size 1..256 ---
    # Building a manifest is O(entry count); to cover the full 1..256 range and
    # still run ~250 variant checks in budget, each manifest size is built once
    # and reused for several selector/query variants (the plan's "manifests of
    # 1..256 entries" bounds the sizes, not how many checks share one).
    issue_get_sizes = sorted({1, 256, *(rng.randint(1, 256) for _ in range(23))})
    checks_per_size = 10

    def issue_request(selector, query):
        return ParsedRequest(
            service="jira", method="GET", path=f"/rest/api/3/issue/{selector}",
            query=query, accept="application/json", body=b"", sentinel="s" * 43,
        )

    for count in issue_get_sizes:
        issues = tuple(
            ScopedIssue(issue_id=str(90101 + i), issue_key=f"SYN-{i + 1}") for i in range(count)
        )
        manifest = ScopeManifest(
            service="jira", run_id="run-1", attempt_id="attempt-1", rehearsal_id="rehearsal-1",
            revision="scope-r1", routes=("jira.issue.get",), policy_digest=jira_policy.digest,
            scope=JiraScope(issues=issues, search_labels=()),
        )
        csv = ",".join(jira_policy.issue_fields)

        for _ in range(checks_per_size):
            index = rng.randrange(count)
            entry = issues[index]
            routed_by_id = policy.route(issue_request(entry.issue_id, ()), manifest)
            routed_by_key = policy.route(
                issue_request(entry.issue_key, (("fields", csv),)), manifest,
            )
            # equal upstreams (same issue, two different wire forms) give equal v1/v2.
            assert routed_by_id.request_digest == routed_by_key.request_digest
            digest = assert_v2_is_sound(routed_by_id)
            digest_via_key = fu.request_descriptor(
                routed_by_key, endpoint_digest=ENDPOINT_DIGEST_443, authority=authority,
            ).digest
            assert digest_via_key == digest

            if count > 1:
                other_entry = issues[(index + 1) % count]
                other_routed = policy.route(issue_request(other_entry.issue_id, ()), manifest)
                other_digest = assert_v2_is_sound(other_routed)
                # same manifest, policy, endpoint and authority -- only the target
                # (a different issue's path) differs, isolating that one input.
                assert other_digest != digest

    # --- jira.search: maxResults, body whitespace, fields order, manifest size ---
    template = jira_policy.search_templates[0]
    search_filler_counts = sorted({0, 255, *(rng.randint(0, 255) for _ in range(23))})

    def search_request(body):
        return ParsedRequest(
            service="jira", method="POST", path="/rest/api/3/search/jql", query=(),
            accept="application/json", body=body, sentinel="s" * 43,
        )

    for filler_count in search_filler_counts:
        label = f"fp-{rng.getrandbits(32):08x}"
        fillers = {f"filler-{i:06x}" for i in range(filler_count)}
        fillers.discard(label)
        labels = tuple(sorted(fillers | {label}))
        manifest = ScopeManifest(
            service="jira", run_id="run-1", attempt_id="attempt-1", rehearsal_id="rehearsal-1",
            revision="scope-r1", routes=("jira.search",), policy_digest=jira_policy.digest,
            scope=JiraScope(issues=(), search_labels=labels),
        )
        jql = template.replace("{label}", label)

        for _ in range(checks_per_size):
            max_results = rng.randint(1, 50)
            fields = list(jira_policy.search_fields)
            rng.shuffle(fields)
            payload_plain = {"jql": jql, "maxResults": max_results}
            payload_with_fields = {"jql": jql, "maxResults": max_results, "fields": fields}

            body_a = canonical_json(payload_plain)
            body_b = json.dumps(payload_with_fields, indent=2).encode("ascii")

            routed_a = policy.route(search_request(body_a), manifest)
            routed_b = policy.route(search_request(body_b), manifest)
            # equal upstreams (same jql/maxResults, compact vs. whitespace-heavy,
            # fields omitted vs. shuffled-and-present) give equal v1 and v2.
            assert routed_a.request_digest == routed_b.request_digest
            digest = assert_v2_is_sound(routed_a)
            digest_b = fu.request_descriptor(
                routed_b, endpoint_digest=ENDPOINT_DIGEST_443, authority=authority,
            ).digest
            assert digest_b == digest
