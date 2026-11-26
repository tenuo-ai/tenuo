"""Proxy-forwarded identity: the header reader, the peer check, issuance, and the HTTP endpoint."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
import json
import logging
import os
import socket
import ssl
import threading
import time

import pytest

pytest.importorskip("cryptography")

from tenuo import Authorizer, SigningKey, Warrant  # noqa: E402
from tenuo.exceptions import AuthorizationError, TenuoError  # noqa: E402
from tenuo.spiffe import SpiffeError, SpiffeGrant, SpiffeHolderProof, SpiffeWarrantIssuer  # noqa: E402
from tenuo.spiffe_forwarded import (  # noqa: E402
    UNIX_SOCKET,
    SpiffeForwardedIdentity,
    SpiffeForwardedIssuerApp,
    _parse_forwarded,
    request_warrant_forwarded,
    sign_forwarded_holder_proof,
)

from .test_spiffe import AGENT, DOMAIN, REFUND, SERVER, eventually, pki  # noqa: E402, F401  (fixture)
from .test_spiffe import ca as ca  # noqa: E402, F401  (fixture)

AUDIENCE = "https://issuer.example.test/warrants"
HASH = "ab" * 32
PROXY = "127.0.0.1"


def element(uri=AGENT, by=SERVER, digest=HASH, extra=""):
    parts = [f"By={by}"] if by else []
    if digest:
        parts.append(f"Hash={digest}")
    if uri:
        parts.append(f"URI={uri}")
    return ";".join(parts) + extra


def reader(*arguments, **options):
    """A reader that accepts a header without the certificate, as a mesh that cannot forward it sends."""
    options.setdefault("require_certificate", False)
    return SpiffeForwardedIdentity(*arguments, **options)


@pytest.fixture
def forwarded():
    return reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY])


# -- header -------------------------------------------------------------------


def test_reads_what_envoy_writes(forwarded):
    # The shape Envoy writes with subject and uri forwarding on.
    header = f'By={SERVER};Hash={HASH};Subject="CN=agent,O=Example \\"Quoted\\", Inc.";URI={AGENT}'
    identity = forwarded.authenticate(header, peer=PROXY)
    # With dns forwarding on as well, the URI no longer ends the header.
    for names in (";DNS=agent.example.test", ";DNS=agent.example.test;DNS=agent"):
        with pytest.raises(SpiffeError, match="must end with the certificate's URI"):
            forwarded.authenticate(header + names, peer=PROXY)
    assert (identity.spiffe_id, identity.certificate_sha256, identity.svid_type) == (AGENT, HASH, "forwarded")
    assert identity.trust_domain == DOMAIN
    assert 298 < identity.expires_at - time.time() <= 300
    parsed = _parse_forwarded(header)
    assert len(parsed) == 1 and dict(parsed[0])["subject"] == 'CN=agent,O=Example "Quoted", Inc.'
    # Keys are case-insensitive, the hash may be upper case, and an empty quoted value is fine.
    identity = forwarded.authenticate(f'by={SERVER};HASH={HASH.upper()};Subject="";uri={AGENT}', peer=PROXY)
    assert identity.certificate_sha256 == HASH


def test_a_header_with_more_than_one_entry_is_refused(forwarded):
    """Nothing a client sends ahead of the proxy's entry is read, and the proxy's own entry is not read around it."""
    admin = f"spiffe://{DOMAIN}/admin"
    for header in (f"{element(admin)},{element()}", f"{element(admin)}, {element()}", f"{element()},{element()}"):
        with pytest.raises(SpiffeError, match="more than one client certificate"):
            forwarded.authenticate(header, peer=PROXY)
    # A client cannot make its own text swallow or merge with what an appending proxy adds.
    for from_proxy in (element(), element(extra=';Subject="CN=agent"'), element(extra=';Subject=""')):
        for sent_by_client in (
            f'{element(admin)};X="',
            f'{element(admin)};X="a\\',
            f'URI={admin};Hash={HASH};X="',
            'X="',
            '"',
            f"{element(admin)};",
            f"{element(admin)},",
            "[",
            "",
        ):
            with pytest.raises(SpiffeError):
                forwarded.authenticate(f"{sent_by_client},{from_proxy}", peer=PROXY)


def test_a_client_quote_cannot_reach_across_the_entry_an_appending_proxy_adds():
    """A header sent by a client whose certificate carries a name ending in a quote, as Envoy 1.40.2 forwarded it."""
    both = reader(
        DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], federates_with=["partner.test"], expected_by=SERVER
    )
    admin = f"spiffe://{DOMAIN}/admin"
    sent = f'By={SERVER};Hash={HASH};URI={admin};X="'
    for appended in (
        f'By={SERVER};Hash={"cd" * 32};URI=spiffe://partner.test/x"',
        f'By={SERVER};Hash={"cd" * 32};URI=spiffe://partner.test/x;DNS=a"',
        f'Hash={"cd" * 32};URI=spiffe://partner.test/x"',
        f'By={SERVER};Hash={"cd" * 32};Subject="";URI=spiffe://partner.test/x"',
        f'By={SERVER};Hash={"cd" * 32};Subject="CN=x\\"";URI=spiffe://partner.test/x"',
    ):
        for prefix in (sent, sent + "\\", f'X="{sent}', f'{sent}a"b', f"{sent},"):
            with pytest.raises(SpiffeError):
                both.authenticate(f"{prefix},{appended}", peer=PROXY)
    # Exhaustively for short prefixes: nothing a client puts first makes the proxy's entry disappear.
    import itertools

    appended = f'By={SERVER};Hash={"cd" * 32};URI=spiffe://partner.test/x"'
    pieces = ['"', "\\", ";", ",", "=", "X", f"URI={admin}", f"Hash={HASH}", f"By={SERVER}", " "]
    for length in range(1, 5):
        for combination in itertools.product(pieces, repeat=length):
            try:
                identity = both.authenticate("".join(combination) + "," + appended, peer=PROXY)
            except SpiffeError:
                continue
            raise AssertionError(f"accepted {identity.spiffe_id} for prefix {combination}")


def test_names_copied_from_a_certificate_cannot_name_someone_else(forwarded):
    """Envoy writes URI and DNS names into the header unescaped. These are headers it produced for crafted certificates."""
    admin = f"spiffe://{DOMAIN}/admin"
    prefix = f"By={SERVER};Hash={HASH}"
    for header in (
        # A URI name that continues with a comma and a whole second entry (captured from Envoy 1.40.2).
        f"{prefix};URI=spiffe://{DOMAIN}/a,By={SERVER};Hash={'cd' * 32};URI={admin}",
        # A URI name carrying a second URI, or a quote.
        f"{prefix};URI=spiffe://{DOMAIN}/a;URI={admin}",
        f'{prefix};URI=spiffe://{DOMAIN}/q"uote',
        # Two URI names on one certificate.
        f"{prefix};URI=spiffe://{DOMAIN}/one;URI=spiffe://{DOMAIN}/two",
        # No URI name at all, and a DNS name that supplies one.
        f"{prefix};DNS=x;URI={admin}",
        f"{prefix};DNS=a;DNS=b;URI={admin}",
        # A subject ending in a backslash, then a URI name that tries to close the quote for it.
        f'{prefix};Subject="CN=x\\\\";URI=spiffe://{DOMAIN}/x";URI={admin}',
    ):
        with pytest.raises(SpiffeError):
            forwarded.authenticate(header, peer=PROXY)
    # A name is never cut short either: whatever follows a separator inside it leaves the URI
    # short of the end of the header. The identity is the certificate's whole URI name or nothing.
    for name in (f"{AGENT};DNS=x", f"{AGENT};Other=y", f"{AGENT};x", f"{AGENT};", f'{AGENT};Subject="CN=x"'):
        with pytest.raises(SpiffeError):
            forwarded.authenticate(f"{prefix};URI={name}", peer=PROXY)
    # Nor can something ahead of the URI be anything but what Envoy writes there.
    for ahead in ("DNS=x", "Other=y", f"Hash={HASH};DNS=x"):
        with pytest.raises(SpiffeError):
            forwarded.authenticate(f"By={SERVER};{ahead};Hash={HASH};URI={AGENT}", peer=PROXY)
    # Escapes inside a quoted subject are read in pairs.
    header = f'{prefix};Subject="CN=a \\"q\\"\\, b\\\\";URI={AGENT}'
    assert forwarded.authenticate(header, peer=PROXY).spiffe_id == AGENT
    assert dict(_parse_forwarded(header)[0])["subject"] == 'CN=a "q"\\, b\\\\'


@pytest.mark.parametrize(
    "header, message",
    [
        ("", "Malformed"),
        ("   ", "Malformed"),
        ("URI", "Malformed"),
        (f"=x;{element()}", "Malformed"),
        (f"{element()};", "Malformed"),
        (f"{element()},", "Malformed"),
        (f",{element()}", "Malformed"),
        (f"{element()},{element()}", "more than one client certificate"),
        (f"DNS=agent.example.test;{element()}", "must end with the certificate's URI"),
        (f"Other=x;{element()}", "must end with the certificate's URI"),
        (element() + ";DNS=agent.example.test", "must end with the certificate's URI"),
        (element() + ";Other=x", "must end with the certificate's URI"),
        (element() + f";By={SERVER}", "must end with the certificate's URI"),
        (f'{element()};X="open', "Malformed"),
        (f'{element()};X="closed"trailing', "Malformed"),
        (f'{element()};X=un"quoted', "Malformed"),
        (f"{element()};U RI=x", "Malformed"),
        (f"{element()};Bad-Key=x", "Malformed"),
        (f'[{{"URI":"{AGENT}","Hash":"{HASH}"}}]', "JSON form"),
        (element(uri=None), "exactly one URI"),
        (element() + f";URI={AGENT}", "exactly one URI"),
        (element() + f";URI=spiffe://{DOMAIN}/admin", "exactly one URI"),
        (element(digest=None), "certificate hash"),
        (element(digest="ab" * 31), "certificate hash"),
        (element(digest="zz" * 32), "certificate hash"),
        (element() + f";Hash={HASH}", "certificate hash"),
        (f"By={SERVER};Hash={HASH};Hash={HASH};URI={AGENT}", "certificate hash"),
        (element(uri="https://example.test/agent"), "Invalid workload SPIFFE ID"),
        (element(uri=f"spiffe://{DOMAIN}"), "Invalid workload SPIFFE ID"),
        (element(uri=f"spiffe://{DOMAIN}/a/../admin"), "Invalid workload SPIFFE ID"),
        (element(uri=f"spiffe://{DOMAIN}/a%2Fb"), "Invalid workload SPIFFE ID"),
        (element(uri=f'"spiffe://{DOMAIN}/a,b"'), "Malformed"),
        (element(uri=f'"{AGENT}"'), "Malformed"),  # Envoy never quotes these.
        (element(digest=f'"{HASH}"'), "Malformed"),
        (element(by=f'"{SERVER}"'), "Malformed"),
        (element(extra=';DNS="agent.example.test"'), "Malformed"),
        (element(extra=';Subject="CN=a;b"'), "Malformed"),  # Envoy writes that semicolon escaped.
        (element(extra=';X="a;b"'), "Malformed"),
        (element(uri="spiffe://other.test/agent"), "different trust domain"),
        (element() + " ", "Invalid workload SPIFFE ID"),  # Nothing may follow the SPIFFE ID, not even a space.
        (element() + "\t", "Invalid workload SPIFFE ID"),
        (element(uri=AGENT + " x"), "Invalid workload SPIFFE ID"),
        ("x" * (32 * 1024 + 1), "Malformed"),
    ],
    ids=lambda value: None if len(str(value)) < 40 else str(value)[:24] + "...",
)
def test_refused_headers(forwarded, header, message):
    with pytest.raises(SpiffeError, match=message):
        forwarded.authenticate(header, peer=PROXY)


def test_header_must_be_text(forwarded):
    for header in (None, b"URI=x", 7):
        with pytest.raises(SpiffeError, match="Malformed"):
            forwarded.authenticate(header, peer=PROXY)


def test_dns_names_are_accepted_only_when_the_operator_says_so(forwarded):
    """What Istio 1.30.8 forwarded for a SPIRE-issued certificate with two DNS names."""
    header = f'By={SERVER};Hash={HASH};Subject="";URI={AGENT};DNS=agent.tenuo.svc.cluster.local;DNS=agent'
    with pytest.raises(SpiffeError, match="see allow_dns_names"):
        forwarded.authenticate(header, peer=PROXY)
    lenient = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], allow_dns_names=True)
    identity = lenient.authenticate(header, peer=PROXY)
    assert (identity.spiffe_id, identity.certificate_sha256) == (AGENT, HASH)
    assert lenient.authenticate(element(), peer=PROXY).spiffe_id == AGENT
    assert lenient.authenticate(element(extra=";DNS=*.example.test"), peer=PROXY).spiffe_id == AGENT
    # Nothing but DNS names may follow, nothing but Envoy's own fields may come first, and the rest still holds.
    for refused in (
        element(extra=";Other=x"),
        element(extra=";DNS=a;Other=x"),
        element(extra=f";DNS=a;URI={AGENT}"),
        element(extra=f";DNS=a;Hash={HASH}"),
        element(extra=f";DNS=a;By={SERVER}"),
        element(extra=';DNS=a;Subject="CN=x"'),
        element(extra=";DNS="),
        element(extra=";DNS=a b"),
        element(extra=";DNS=a/b"),
        element(extra=";DNS=" + "a" * 254),
        f"DNS=a;{element()}",
        f"{element()};DNS=a,{element()}",
        f"{element(f'spiffe://{DOMAIN}/admin')};DNS=a,{element()};DNS=b",
        element(uri=f'{AGENT}";DNS=a'),
    ):
        with pytest.raises(SpiffeError):
            lenient.authenticate(refused, peer=PROXY)
    with pytest.raises(ValueError, match="allow_dns_names"):
        reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], allow_dns_names="yes")


def forwarded_leaf(ca, uris=(AGENT,), dns=(), expires=600, starts=-10):  # noqa: F811
    """A certificate from the test authority, as Envoy encodes it in the header, and its SHA-256."""
    import urllib.parse
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    names = [x509.UniformResourceIdentifier(uri) for uri in uris] + [x509.DNSName(name) for name in dns]
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca.name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(seconds=starts))
        .not_valid_after(now + timedelta(seconds=expires))
        .add_extension(x509.BasicConstraints(False, None), True)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), True)
    certificate = builder.sign(ca.key, hashes.SHA256())
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    return urllib.parse.quote(pem, safe=""), certificate.fingerprint(hashes.SHA256()).hex()


def with_certificate(encoded, digest, uri=AGENT, extra=""):
    return f'By={SERVER};Hash={digest};Cert="{encoded}";Subject="";URI={uri}{extra}'


def test_a_forwarded_certificate_is_checked_against_the_identity(forwarded, ca):  # noqa: F811
    """When the proxy forwards the certificate, the URI is checked against it instead of being taken as read."""
    encoded, digest = forwarded_leaf(ca, expires=60)
    identity = forwarded.authenticate(with_certificate(encoded, digest), peer=PROXY)
    assert (identity.spiffe_id, identity.certificate_sha256) == (AGENT, digest)
    assert 50 < identity.expires_at - time.time() <= 60  # The certificate's own expiry, not the 300-second cap.
    # A chain forwarded as well is ignored, and DNS names are fine once the certificate vouches for the URI.
    with_names, names_digest = forwarded_leaf(ca, dns=("agent.example.test", "agent"))
    header = with_certificate(with_names, names_digest, extra=";DNS=agent.example.test;DNS=agent")
    assert forwarded.authenticate(header, peer=PROXY).spiffe_id == AGENT
    chained = header.replace(';Subject=""', f';Chain="{with_names}{encoded}";Subject=""')
    assert forwarded.authenticate(chained, peer=PROXY).spiffe_id == AGENT

    admin = f"spiffe://{DOMAIN}/admin"
    separator, separator_digest = forwarded_leaf(ca, uris=(f"{AGENT};DNS=x",))
    spaced, spaced_digest = forwarded_leaf(ca, uris=(f"{AGENT} ",))
    two, two_digest = forwarded_leaf(ca, uris=(AGENT, admin))
    none, none_digest = forwarded_leaf(ca, uris=())
    expired, expired_digest = forwarded_leaf(ca, expires=-5, starts=-60)
    future, future_digest = forwarded_leaf(ca, starts=60)
    lenient = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], allow_dns_names=True)
    for header, message in (
        (with_certificate(encoded, digest, uri=admin), "not the certificate's only URI name"),
        (with_certificate(encoded, HASH), "not the one the header's hash names"),
        # A name with a separator in it, as Envoy would write it: read as the shorter name, and caught.
        (with_certificate(separator, separator_digest, extra=";DNS=x"), "not the certificate's only URI name"),
        # A name ending in a space, which HTTP trims from the end of the header.
        (with_certificate(spaced, spaced_digest), "not the certificate's only URI name"),
        (with_certificate(two, two_digest), "not the certificate's only URI name"),
        (with_certificate(none, none_digest), "not the certificate's only URI name"),
        (with_certificate(expired, expired_digest), "not currently valid"),
        (with_certificate(future, future_digest), "not currently valid"),
        (with_certificate(encoded + encoded, digest), "cannot be read"),
        (with_certificate("not%20a%20certificate", digest), "cannot be read"),
        (with_certificate("", digest), "cannot be read"),
        (with_certificate(encoded, digest).replace(';Subject=""', f';Cert="{encoded}";Subject=""'), "Malformed"),
        (with_certificate(encoded, digest, extra=";Other=x"), "must end with the certificate's URI"),
    ):
        for each in (forwarded, lenient):  # The opt-in for DNS names does not loosen any of this.
            with pytest.raises(SpiffeError, match=message):
                each.authenticate(header, peer=PROXY)

    # By default the certificate must be there. Only a reader told otherwise accepts a header without it.
    default = SpiffeForwardedIdentity(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY])
    assert default.authenticate(with_certificate(encoded, digest), peer=PROXY).spiffe_id == AGENT
    with pytest.raises(SpiffeError, match="did not forward the client certificate"):
        default.authenticate(element(), peer=PROXY)
    assert forwarded.authenticate(element(), peer=PROXY).spiffe_id == AGENT
    with pytest.raises(ValueError, match="require_certificate"):
        SpiffeForwardedIdentity(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], require_certificate=1)


def test_a_warrant_never_outlives_a_forwarded_certificate(ca):  # noqa: F811
    from datetime import datetime

    forwarded = SpiffeForwardedIdentity(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY])
    issuer = SpiffeWarrantIssuer(
        signing_key=SigningKey.generate(), policy=lambda *_: SpiffeGrant(REFUND, ttl_seconds=3600), forwarded=forwarded
    )
    encoded, digest = forwarded_leaf(ca, expires=40)
    warrant = issue(issuer, SigningKey.generate(), header=with_certificate(encoded, digest))
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() - time.time() <= 40


def test_expected_proxy_identity():
    pinned = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], expected_by=SERVER)
    assert pinned.authenticate(element(), peer=PROXY).spiffe_id == AGENT
    for header in (
        element(by=f"spiffe://{DOMAIN}/other-proxy"),
        element(by=None),
        f"By=spiffe://{DOMAIN}/other-proxy;{element()}",
    ):
        with pytest.raises(SpiffeError, match="expected proxy"):
            pinned.authenticate(header, peer=PROXY)


def test_federated_trust_domains():
    partner = "spiffe://partner.test/agent"
    both = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], federates_with=["partner.test"])
    assert both.authenticate(element(partner), peer=PROXY).trust_domain == "partner.test"
    assert both.authenticate(element(), peer=PROXY).trust_domain == DOMAIN
    with pytest.raises(SpiffeError, match="different trust domain"):
        both.authenticate(element("spiffe://elsewhere.test/agent"), peer=PROXY)


# -- peer ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "trusted, peer, accepted",
    [
        (["127.0.0.1"], "127.0.0.1", True),
        (["127.0.0.1"], "127.0.0.2", False),
        (["127.0.0.0/8"], "127.0.0.6", True),
        (["127.0.0.1"], "::ffff:127.0.0.1", True),  # Dual-stack listener.
        (["127.0.0.1"], "::ffff:127.0.0.2", False),
        # The proxy listed in its IPv4-mapped form matches either way the peer is reported.
        (["::ffff:127.0.0.1"], "::ffff:127.0.0.1", True),
        (["::ffff:127.0.0.1"], "127.0.0.1", True),
        (["::ffff:127.0.0.1"], "127.0.0.2", False),
        (["::ffff:127.0.0.1"], "::1", False),
        (["::ffff:10.1.0.0/112"], "10.1.200.3", True),
        (["::ffff:10.1.0.0/112"], "::ffff:10.1.200.3", True),
        (["::ffff:10.1.0.0/112"], "10.2.0.1", False),
        (["::ffff:10.1.0.7/112"], "::ffff:10.1.9.9", True),  # Host bits ignored here too.
        (["127.0.0.1"], "::1", False),
        (["::1"], "::1", True),
        (["::1"], "127.0.0.1", False),
        (["10.1.0.0/16"], "10.1.200.3", True),
        (["10.1.0.0/16"], "10.2.0.1", False),
        (["10.1.0.7/16"], "10.1.0.9", True),  # Host bits in a network are ignored.
        (["fd00::/8"], "fd12::1", True),
        (["127.0.0.1"], UNIX_SOCKET, False),
        ([UNIX_SOCKET], UNIX_SOCKET, True),
        ([UNIX_SOCKET], "127.0.0.1", False),
        (["127.0.0.1", UNIX_SOCKET], "127.0.0.1", True),
        (["127.0.0.1"], None, False),
        ([UNIX_SOCKET], None, False),
        (["127.0.0.1"], "", False),
        (["127.0.0.1"], "localhost", False),
        (["127.0.0.1"], "127.0.0.1:80", False),
        (["127.0.0.1"], "127.0.0.1, 10.0.0.1", False),
        (["127.0.0.1"], ("127.0.0.1", 80), False),
    ],
)
def test_peer_must_be_a_trusted_proxy(trusted, peer, accepted):
    forwarded = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=trusted)
    assert forwarded.trusts_peer(peer) is accepted
    if accepted:
        assert forwarded.authenticate(element(), peer=peer).spiffe_id == AGENT
    else:
        with pytest.raises(SpiffeError, match="trusted proxy"):
            forwarded.authenticate(element(), peer=peer)


@pytest.mark.parametrize(
    "options",
    [
        dict(trusted_proxies=[]),
        dict(trusted_proxies="127.0.0.1"),
        dict(trusted_proxies=["localhost"]),
        dict(trusted_proxies=["0.0.0.0/0"]),
        dict(trusted_proxies=["::/0"]),
        dict(trusted_proxies=["::ffff:0:0/96"]),  # Every IPv4 address, written the IPv6 way.
        dict(trusted_proxies=["::ffff:0.0.0.0/96"]),
        dict(trusted_proxies=["::/1"]),  # Covers that range as well.
        dict(trusted_proxies=[None]),
        dict(audience=""),
        dict(audience=None),
        dict(expected_by="issuer"),
        dict(federates_with="partner.test"),
        dict(federates_with=[DOMAIN]),
        dict(max_warrant_seconds=1),
        dict(max_warrant_seconds=4),
        dict(max_warrant_seconds=3601),
        dict(max_warrant_seconds=True),
        dict(trust_domain="Example.test"),
    ],
)
def test_configuration_is_validated(options):
    settings = {"trust_domain": DOMAIN, "audience": AUDIENCE, "trusted_proxies": [PROXY], **options}
    with pytest.raises(ValueError):
        SpiffeForwardedIdentity(settings.pop("trust_domain"), **settings)


def test_trusted_proxies_is_required():
    with pytest.raises(TypeError):
        SpiffeForwardedIdentity(DOMAIN, audience=AUDIENCE)  # type: ignore[call-arg]


# -- issuance -----------------------------------------------------------------


@pytest.fixture
def forwarded_issuer(forwarded):
    root = SigningKey.generate()
    seen, records = [], []

    def policy(identity, task_id):
        seen.append((identity.spiffe_id, identity.svid_type, task_id))
        if identity.spiffe_id == AGENT and task_id == "task-123":
            return SpiffeGrant(REFUND, ttl_seconds=120, max_depth=1)
        return None

    issuer = SpiffeWarrantIssuer(signing_key=root, policy=policy, forwarded=forwarded, audit=records.append)
    return issuer, root, seen, records


def issue(issuer, holder, task="task-123", header=None, peer=PROXY, **proof):
    signed = sign_forwarded_holder_proof(
        holder, audience=proof.pop("audience", AUDIENCE), task_id=proof.pop("signed_task", task), **proof
    )
    return issuer.issue_forwarded(header or element(), peer, holder.public_key, task, signed)


def test_issuance_and_tool_enforcement(forwarded_issuer):
    issuer, root, seen, records = forwarded_issuer
    holder = SigningKey.generate()
    warrant = issue(issuer, holder)
    assert seen == [(AGENT, "forwarded", "task-123")]
    assert warrant.authorized_holder == holder.public_key and warrant.issuer == root.public_key
    assert records[0].identity.certificate_sha256 == HASH and records[0].warrant_id == warrant.id
    authorizer = Authorizer(trusted_roots=[root.public_key])
    args = {"customer": "123", "cents": 4000}
    authorizer.authorize(warrant, "refund", args, warrant.sign(holder, "refund", args, int(time.time())))
    with pytest.raises(AuthorizationError):
        over = {"customer": "123", "cents": 9000}
        authorizer.authorize(warrant, "refund", over, warrant.sign(holder, "refund", over, int(time.time())))
    with pytest.raises(TenuoError):  # Someone without the holder key.
        thief = SigningKey.generate()
        authorizer.authorize(warrant, "refund", args, warrant.sign(thief, "refund", args, int(time.time())))


def test_peer_and_header_are_checked_before_policy(forwarded_issuer):
    issuer, _, seen, _ = forwarded_issuer
    holder = SigningKey.generate()
    with pytest.raises(SpiffeError, match="trusted proxy"):
        issue(issuer, holder, peer="10.0.0.9")
    with pytest.raises(SpiffeError, match="different trust domain"):
        issue(issuer, holder, header=element("spiffe://other.test/agent"))
    with pytest.raises(SpiffeError, match="not authorized"):
        issue(issuer, holder, header=element(f"spiffe://{DOMAIN}/someone-else"))
    with pytest.raises(SpiffeError, match="not authorized"):
        issue(issuer, holder, task="other-task")
    assert [entry[0] for entry in seen] == [f"spiffe://{DOMAIN}/someone-else", AGENT]


def test_warrant_lifetime_is_capped(forwarded):
    root = SigningKey.generate()
    short = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], max_warrant_seconds=30)
    for source, limit in ((forwarded, 300), (short, 30)):
        issuer = SpiffeWarrantIssuer(
            signing_key=root, policy=lambda *_: SpiffeGrant(REFUND, ttl_seconds=3600), forwarded=source
        )
        warrant = issue(issuer, SigningKey.generate())
        from datetime import datetime

        remaining = datetime.fromisoformat(warrant.expires_at()).timestamp() - time.time()
        assert limit - 5 < remaining <= limit


def test_holder_proof_is_bound_to_audience_task_and_key(forwarded_issuer):
    issuer, *_ = forwarded_issuer
    holder, other = SigningKey.generate(), SigningKey.generate()
    for wrong in (dict(audience="https://another-issuer.example.test/warrants"), dict(signed_task="task-999")):
        with pytest.raises(SpiffeError, match="Invalid holder proof"):
            issue(issuer, holder, **wrong)
    proof = sign_forwarded_holder_proof(other, audience=AUDIENCE, task_id="task-123")
    with pytest.raises(SpiffeError, match="Invalid holder proof"):
        issuer.issue_forwarded(element(), PROXY, holder.public_key, "task-123", proof)
    for stale in (int(time.time()) - 600, int(time.time()) + 600):
        with pytest.raises(SpiffeError, match="too old or from the future"):
            issue(issuer, holder, timestamp=stale)
    # An exact replay is refused; a new proof for the same task is not.
    proof = sign_forwarded_holder_proof(holder, audience=AUDIENCE, task_id="task-123")
    issuer.issue_forwarded(element(), PROXY, holder.public_key, "task-123", proof)
    with pytest.raises(SpiffeError, match="already used"):
        issuer.issue_forwarded(element(), PROXY, holder.public_key, "task-123", proof)
    issue(issuer, holder)


def test_holder_proof_layout_matches_the_documented_bytes(forwarded_issuer):
    """Another language can build the proof from the guide's description alone."""
    issuer, *_ = forwarded_issuer
    holder = SigningKey.generate()
    stamp, nonce = int(time.time()), bytes(range(16))
    message = (
        b"tenuo.spiffe.forwarded-holder-binding.v1\x00"
        + bytes(holder.public_key.to_bytes())
        + stamp.to_bytes(8, "big")
        + nonce
        + hashlib.sha256(AUDIENCE.encode()).digest()
        + hashlib.sha256(b"task-123").digest()
    )
    proof = SpiffeHolderProof(stamp, nonce, bytes(holder.sign_raw(message)))
    assert issuer.issue_forwarded(element(), PROXY, holder.public_key, "task-123", proof).id


def test_proofs_do_not_cross_exchanges(forwarded_issuer):
    """A proof made for the JWT-SVID exchange is not one for the forwarded exchange, even with every field equal."""
    issuer, *_ = forwarded_issuer
    holder = SigningKey.generate()
    from tenuo.spiffe import _jwt_proof_bytes

    stamp, nonce = int(time.time()), bytes(16)
    for token_digest in (bytes(32), hashlib.sha256(b"token").digest()):
        message = _jwt_proof_bytes(
            AUDIENCE, bytes(holder.public_key.to_bytes()), "task-123", stamp, nonce, token_digest
        )
        proof = SpiffeHolderProof(stamp, nonce, bytes(holder.sign_raw(message)))
        with pytest.raises(SpiffeError, match="Invalid holder proof"):
            issuer.issue_forwarded(element(), PROXY, holder.public_key, "task-123", proof)


def test_issuer_modes_are_explicit(forwarded, forwarded_issuer, pki):  # noqa: F811
    issuer, *_ = forwarded_issuer
    holder = SigningKey.generate()
    proof = sign_forwarded_holder_proof(holder, audience=AUDIENCE, task_id="task-123")
    mtls_only = SpiffeWarrantIssuer(signing_key=SigningKey.generate(), policy=lambda *_: None, tls=pki(server=True))
    with pytest.raises(SpiffeError, match="does not accept proxy-forwarded identities"):
        mtls_only.issue_forwarded(element(), PROXY, holder.public_key, "task-123", proof)
    with pytest.raises(ValueError, match="forwarded=SpiffeForwardedIdentity"):
        SpiffeForwardedIssuerApp(mtls_only)
    with pytest.raises(SpiffeError, match="does not accept JWT-SVIDs"):
        issuer.issue_jwt("a.b.c", holder.public_key, "task-123", proof)
    with pytest.raises(SpiffeError, match="does not accept X.509-SVIDs"):
        issuer.challenge(None, holder.public_key, "task-123")
    # An identity authenticated another way cannot be passed off as forwarded, or the reverse.
    identity = forwarded.authenticate(element(), peer=PROXY)
    from dataclasses import replace

    with pytest.raises(SpiffeError, match="does not accept proxy-forwarded"):
        issuer._issue_forwarded(replace(identity, svid_type="x509"), holder.public_key, "task-123", proof)
    with pytest.raises(SpiffeError, match="does not accept JWT-SVIDs"):
        issuer._issue_jwt(identity, holder.public_key, "task-123", proof)
    with pytest.raises(ValueError, match="forwarded"):
        SpiffeWarrantIssuer(signing_key=SigningKey.generate(), policy=lambda *_: None)


# -- endpoint -----------------------------------------------------------------


def request_body(holder_key, task="task-123", audience=AUDIENCE, **overrides):
    proof = sign_forwarded_holder_proof(holder_key, audience=audience, task_id=task)
    body = {
        "v": 1,
        "holder": base64.b64encode(bytes(holder_key.public_key.to_bytes())).decode(),
        "task": task,
        "timestamp": proof.timestamp,
        "nonce": base64.b64encode(proof.nonce).decode(),
        "signature": base64.b64encode(proof.signature).decode(),
    }
    body.update(overrides)
    return json.dumps(body).encode()


_DEFAULT = object()
NOTHING = object()


def call_app(app, *, method="POST", path="/warrants", headers=_DEFAULT, body=b"", client=(PROXY, 40000), server=None):
    """Drive the ASGI app directly and return (status, headers, json, body-was-read)."""

    async def run():
        sent, reads = [], []

        async def receive():
            reads.append(1)
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        chosen = [("x-forwarded-client-cert", element())] if headers is _DEFAULT else headers
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "root_path": "",
            "client": client,
            "server": None if server is NOTHING else server or ("127.0.0.1", 8080),
            "headers": [(name.lower().encode(), value.encode("latin-1")) for name, value in chosen],
        }
        await app(scope, receive, send)
        await asyncio.sleep(0.01)  # Let worker completions land.
        start, reply = sent[0], sent[1]
        return start["status"], dict(start["headers"]), json.loads(reply["body"]), bool(reads)

    return asyncio.run(run())


@pytest.fixture
def app(forwarded_issuer):
    issuer, root, *_ = forwarded_issuer
    application = SpiffeForwardedIssuerApp(issuer)
    yield application, issuer, root
    application.close()


def test_endpoint_issues_a_warrant(app):
    application, _, root = app
    holder = SigningKey.generate()
    status, headers, reply, _ = call_app(application, body=request_body(holder))
    assert status == 200 and headers[b"cache-control"] == b"no-store"
    warrant = Warrant.from_base64(reply["warrant"])
    assert warrant.authorized_holder == holder.public_key and warrant.issuer == root.public_key
    # A server that reports the port as text (Granian) is understood.
    assert call_app(application, body=request_body(holder), client=(PROXY, "40000"))[0] == 200
    # The header name is matched whatever its case, and a dual-stack peer address is understood.
    status, *_ = call_app(
        application,
        headers=[("X-Forwarded-Client-Cert", element())],
        body=request_body(holder),
        client=("::ffff:127.0.0.1", 40000),
    )
    assert status == 200


def test_endpoint_requires_the_certificate_by_default(ca):  # noqa: F811
    issuer = SpiffeWarrantIssuer(
        signing_key=SigningKey.generate(),
        policy=lambda identity, task_id: SpiffeGrant(REFUND),
        forwarded=SpiffeForwardedIdentity(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY]),
    )
    application = SpiffeForwardedIssuerApp(issuer)
    try:
        holder = SigningKey.generate()
        status, _, reply, read = call_app(application, body=request_body(holder))  # URI and hash only.
        assert (status, reply["error"], read) == (403, "unauthenticated", False)
        assert "did not forward the client certificate" in reply["message"] and len(reply["message"]) < 200
        header = with_certificate(*forwarded_leaf(ca))
        status, *_ = call_app(application, headers=[("x-forwarded-client-cert", header)], body=request_body(holder))
        assert status == 200
    finally:
        application.close()


def test_endpoint_refuses_other_peers_before_reading_anything(app, caplog):
    application, *_ = app
    holder = SigningKey.generate()
    caplog.set_level(logging.WARNING, logger="tenuo.spiffe")
    for client, server in (
        (("10.0.0.9", 40000), None),
        (("::1", 40000), None),
        (None, None),  # No peer reported, on a TCP listener.
        (None, ("/run/issuer.sock", None)),  # A Unix socket, which this issuer does not list.
        (None, NOTHING),
        (("", 0), None),
        ("127.0.0.1", None),
        ((PROXY,), None),
    ):
        status, headers, reply, read = call_app(application, body=request_body(holder), client=client, server=server)
        assert (status, reply["error"], read) == (403, "forbidden", False), client
        assert reply["message"] == "Requests must arrive through the issuer's proxy"
        assert b"www-authenticate" not in headers
    # Operators are told once, with the likely cause, not once per request.
    warnings = [record for record in caplog.records if "trusted_proxies" in record.getMessage()]
    assert len(warnings) == 1 and "--no-proxy-headers" in warnings[0].getMessage()
    assert "10.0.0.9" in warnings[0].getMessage()


def test_endpoint_over_a_unix_socket(forwarded_issuer):
    issuer, root, *_ = forwarded_issuer
    local = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[UNIX_SOCKET])
    application = SpiffeForwardedIssuerApp(
        SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: SpiffeGrant(REFUND), forwarded=local)
    )
    try:
        holder = SigningKey.generate()
        unix = dict(client=None, server=("/run/issuer.sock", None))
        assert call_app(application, body=request_body(holder), **unix)[0] == 200
        # Older ASGI servers report nothing at all for a Unix socket.
        assert call_app(application, body=request_body(holder), client=None, server=NOTHING)[0] == 200
        # TCP peers are not trusted by this issuer, loopback included.
        assert call_app(application, body=request_body(holder))[0] == 403
        assert call_app(application, body=request_body(holder), client=None)[0] == 403
    finally:
        application.close()


def test_endpoint_refusals(app):
    application, *_ = app
    holder = SigningKey.generate()
    body = request_body(holder)

    def refused(status, error, message=None, **options):
        got, _, reply, _ = call_app(application, **{"body": body, **options})
        assert (got, reply["error"]) == (status, error), reply
        if message:
            assert message in reply["message"]

    refused(403, "unauthenticated", "No forwarded client identity", headers=[])
    refused(403, "unauthenticated", "No forwarded client identity", headers=[("x-forwarded-client-cert", " ")])
    refused(
        403,
        "unauthenticated",
        "No forwarded client identity",
        headers=[
            ("x-forwarded-client-cert", element(f"spiffe://{DOMAIN}/admin")),
            ("X-Forwarded-Client-Cert", element()),
        ],
    )
    refused(403, "unauthenticated", "too large", headers=[("x-forwarded-client-cert", "x" * (32 * 1024 + 1))])
    refused(403, "unauthenticated", "exactly one URI", headers=[("x-forwarded-client-cert", element(uri=None))])
    refused(
        403,
        "unauthenticated",
        "different trust domain",
        headers=[("x-forwarded-client-cert", element("spiffe://other.test/agent"))],
    )
    # Other names for the same idea are not read.
    refused(403, "unauthenticated", headers=[("x-client-cert", element()), ("forwarded", "for=203.0.113.7")])
    refused(403, "refused", "not authorized", body=request_body(holder, task="other-task"))
    refused(403, "refused", "Invalid holder proof", body=request_body(holder, audience="https://elsewhere.test"))
    refused(400, "invalid_request", body=b"{")
    refused(400, "invalid_request", body=request_body(holder, v=2))
    refused(400, "invalid_request", body=request_body(holder, extra=1))
    refused(404, "not_found", path="/other")
    refused(405, "method_not_allowed", method="GET")
    refused(413, "too_large", body=b"x" * (64 * 1024 + 1))
    # A refused request leaves nothing behind: the same holder can still be served.
    assert call_app(application, body=request_body(holder))[0] == 200


def test_endpoint_reports_a_failing_policy_as_unavailable(forwarded):
    def broken(identity, task_id):
        raise RuntimeError("policy backend is down")

    application = SpiffeForwardedIssuerApp(
        SpiffeWarrantIssuer(signing_key=SigningKey.generate(), policy=broken, forwarded=forwarded)
    )
    try:
        status, _, reply, _ = call_app(application, body=request_body(SigningKey.generate()))
        assert status == 503 and "policy backend" not in json.dumps(reply)
    finally:
        application.close()


# -- over real sockets --------------------------------------------------------


class InjectIdentity:
    """Stands in for the proxy: sets the forwarded header the way Envoy's SANITIZE_SET does."""

    def __init__(self, application, header=None):
        self.application, self.header, self.scopes = application, header or element(), []

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            self.scopes.append(scope)
            headers = [(name, value) for name, value in scope["headers"] if name != b"x-forwarded-client-cert"]
            scope = {**scope, "headers": headers + [(b"x-forwarded-client-cert", self.header.encode())]}
        await self.application(scope, receive, send)


@pytest.fixture
def serve():
    uvicorn = pytest.importorskip("uvicorn")
    running = []

    def start(application, **options):
        if "uds" not in options:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                options.update(host="127.0.0.1", port=probe.getsockname()[1])
        options.setdefault("proxy_headers", False)
        server = uvicorn.Server(uvicorn.Config(application, log_level="warning", **options))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        assert eventually(lambda: server.started, seconds=10)
        running.append((server, thread))
        return options.get("port")

    yield start
    for server, thread in running:
        server.should_exit = True
        thread.join(timeout=10)


def post(connection, body, headers=()):
    connection.request("POST", "/warrants", body=body, headers={"Content-Type": "application/json", **dict(headers)})
    response = connection.getresponse()
    return response.status, json.loads(response.read())


def test_client_through_a_sidecar(app, serve):
    application, _, root = app
    holder = SigningKey.generate()
    proxy = InjectIdentity(application)
    port = serve(proxy)
    options = dict(audience=AUDIENCE, issuer_key=root.public_key, holder_key=holder, task_id="task-123")
    warrant = request_warrant_forwarded(f"http://127.0.0.1:{port}/warrants", **options)
    assert warrant.authorized_holder == holder.public_key and warrant.issuer == root.public_key
    # The client sends no identity of its own.
    sent = dict(proxy.scopes[0]["headers"])
    assert b"x-forwarded-client-cert" not in sent and b"authorization" not in sent
    with pytest.raises(SpiffeError, match=r"Issuer refused \(HTTP 403\): Workload is not authorized"):
        request_warrant_forwarded(f"http://127.0.0.1:{port}/warrants", **{**options, "task_id": "unknown"})
    with pytest.raises(SpiffeError, match=r"Issuer refused \(HTTP 403\): Invalid holder proof"):
        request_warrant_forwarded(f"http://127.0.0.1:{port}/warrants", **{**options, "audience": "wrong"})
    with pytest.raises(SpiffeError, match="Issued warrant failed verification"):
        request_warrant_forwarded(
            f"http://127.0.0.1:{port}/warrants", **{**options, "issuer_key": SigningKey.generate().public_key}
        )
    with pytest.raises(SpiffeError, match="Could not complete the exchange"):
        request_warrant_forwarded("http://127.0.0.1:9/warrants", timeout=2, **options)


def test_without_a_proxy_nothing_is_issued(app, serve):
    """A client that reaches the issuer directly cannot name itself, whatever it sends."""
    application, *_ = app
    port = serve(application)
    holder = SigningKey.generate()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        status, reply = post(connection, request_body(holder))
        assert (status, reply["error"]) == (403, "unauthenticated")
    finally:
        connection.close()
    # (From loopback, which this test issuer trusts, a forged header does work:
    # that is the documented limit, and why the port must be reachable by the proxy alone.)


def test_default_uvicorn_address_rewriting_fails_closed(app, serve, caplog):
    """With uvicorn's proxy-header handling left on, the peer check sees the wrong address and refuses."""
    application, *_ = app
    proxy = InjectIdentity(application)
    port = serve(proxy, proxy_headers=True)  # uvicorn's default.
    holder = SigningKey.generate()
    caplog.set_level(logging.WARNING, logger="tenuo.spiffe")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        status, reply = post(connection, request_body(holder), {"X-Forwarded-For": "203.0.113.7"})
        assert (status, reply["error"]) == (403, "forbidden")
    finally:
        connection.close()
    assert any("--no-proxy-headers" in record.getMessage() for record in caplog.records)


def test_real_unix_socket_listener(forwarded_issuer, serve):
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        pytest.skip("needs a Unix socket listener")
    issuer, root, *_ = forwarded_issuer
    local = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[UNIX_SOCKET])
    application = SpiffeForwardedIssuerApp(
        SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: SpiffeGrant(REFUND), forwarded=local)
    )
    import tempfile

    with tempfile.TemporaryDirectory(dir="/tmp") as directory:  # Short path: socket names are length-limited.
        path = f"{directory}/issuer.sock"
        serve(application, uds=path)

        class UnixConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.settimeout(5)
                self.sock.connect(path)

        connection = UnixConnection("localhost")
        try:
            status, reply = post(
                connection, request_body(SigningKey.generate()), {"x-forwarded-client-cert": element()}
            )
            assert status == 200, reply
        finally:
            connection.close()
            application.close()


def test_client_with_its_own_mutual_tls(app, serve, pki, ca, tmp_path):  # noqa: F811
    """The agent opens mutual TLS to the proxy itself and pins the proxy's SPIFFE ID."""
    application, _, root = app
    proxy = InjectIdentity(application)
    edge = ca.files("edge", SERVER)
    port = serve(
        proxy,
        ssl_certfile=str(edge["cert"]),
        ssl_keyfile=str(edge["key"]),
        ssl_ca_certs=str(edge["bundle"]),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    holder = SigningKey.generate()
    options = dict(audience=AUDIENCE, issuer_key=root.public_key, holder_key=holder, task_id="task-123")
    url = f"https://127.0.0.1:{port}/warrants"
    client = pki()
    warrant = request_warrant_forwarded(url, tls=client, issuer_id=SERVER, **options)
    assert warrant.authorized_holder == holder.public_key
    # A proxy with another identity gets nothing, not even the request.
    seen = len(proxy.scopes)
    with pytest.raises(SpiffeError, match="SPIFFE ID"):
        request_warrant_forwarded(url, tls=client, issuer_id=f"spiffe://{DOMAIN}/another", **options)
    assert len(proxy.scopes) == seen
    with pytest.raises(ValueError, match="https:// needs tls="):
        request_warrant_forwarded(url, **options)
    with pytest.raises(ValueError, match="https:// needs tls="):
        request_warrant_forwarded(url, tls=client, **options)
    with pytest.raises(ValueError, match="apply to https:// only"):
        request_warrant_forwarded(f"http://127.0.0.1:{port}/warrants", tls=client, issuer_id=SERVER, **options)
    with pytest.raises(ValueError, match="client-side"):
        request_warrant_forwarded(url, tls=pki(server=True), issuer_id=SERVER, **options)
    with pytest.raises(SpiffeError, match="Invalid workload SPIFFE ID"):
        request_warrant_forwarded(url, tls=client, issuer_id="issuer", **options)
    # A plain TLS server (not in the trust domain) is refused during the handshake.
    stranger = type(ca)(tmp_path, "another root").files("stranger", SERVER)
    other = serve(application, ssl_certfile=str(stranger["cert"]), ssl_keyfile=str(stranger["key"]))
    with pytest.raises(SpiffeError, match="not accepted|TLS with the issuer"):
        request_warrant_forwarded(f"https://127.0.0.1:{other}/warrants", tls=client, issuer_id=SERVER, **options)


def test_guide_forwarded_code_runs(tmp_path, monkeypatch, serve, ca):  # noqa: F811
    """Execute the guide's forwarded-identity issuer and agent blocks behind a stand-in for the proxy."""
    from .test_spiffe import _guide_blocks

    blocks = _guide_blocks()

    def localize(code):
        code = code.replace("/run/secrets/tenuo-issuer.pem", (tmp_path / "tenuo-issuer.pem").as_posix()).replace(
            "/etc/tenuo/tenuo-issuer.pub", (tmp_path / "tenuo-issuer.pub").as_posix()
        )
        assert "/run/" not in code and "/etc/" not in code
        return code

    monkeypatch.chdir(tmp_path)
    exec(blocks["make_issuer_key.py"], {})
    issuer_scope: dict = {}
    agent_scope: dict = {}
    try:
        exec(localize(blocks["forwarded_issuer.py"]), issuer_scope)
        agent = "spiffe://acme.test/agents/refund"
        # As Envoy writes it with uri and cert forwarded.
        proxy = InjectIdentity(issuer_scope["app"], with_certificate(*forwarded_leaf(ca, uris=(agent,)), uri=agent))
        port = serve(proxy)
        agent_code = localize(blocks["forwarded_agent.py"])
        assert agent_code.count('"http://issuer.acme.internal/warrants"') == 1
        exec(
            agent_code.replace('"http://issuer.acme.internal/warrants"', repr(f"http://127.0.0.1:{port}/warrants")),
            agent_scope,
        )
    finally:
        if "app" in issuer_scope:
            issuer_scope["app"].close()

    warrant, holder = agent_scope["warrant"], agent_scope["holder_key"]
    tool_scope: dict = {}
    exec(
        blocks["tool.py"].replace("/etc/tenuo/tenuo-issuer.pub", (tmp_path / "tenuo-issuer.pub").as_posix()), tool_scope
    )

    def call(args):
        proof = warrant.sign(holder, "refund", args, int(time.time()))
        return {"chain": [warrant.to_base64()], "args": args, "proof": base64.b64encode(proof).decode()}

    refund = tool_scope["refund"]
    assert refund(call({"customer": "123", "cents": 2000})) == "refunded 2000 cents to customer 123"
    # The guide's policy grants a forwarded identity less than an mTLS peer.
    assert refund(call({"customer": "123", "cents": 4000})).startswith("denied: ")
    assert refund(call({"customer": "999", "cents": 100})).startswith("denied: ")


def test_endpoint_reads_the_identity_before_the_body(app):
    """A request without a usable identity is refused without waiting for its body."""
    application, *_ = app
    for headers in (
        [],
        [("x-forwarded-client-cert", "not an identity")],
        [("x-forwarded-client-cert", element("spiffe://other.test/agent"))],
        [("x-forwarded-client-cert", f"{element()},{element()}")],
    ):
        status, _, reply, read = call_app(application, headers=headers, body=request_body(SigningKey.generate()))
        assert (status, reply["error"], read) == (403, "unauthenticated", False)


@pytest.mark.parametrize(
    "client",
    [
        (PROXY, 0),  # How Uvicorn reports an address it took from X-Forwarded-For.
        (PROXY, None),
        (PROXY, "0"),
        (PROXY, "-1"),
        (PROXY, "4e4"),
        (PROXY, ""),
        (PROXY, True),
        ("unix", 40000),
        ("unix", 0),
        ("localhost", 40000),
        (b"127.0.0.1", 40000),
        [PROXY],
        "unix",
    ],
)
def test_only_a_real_socket_address_is_a_peer(forwarded_issuer, client):
    issuer, root, *_ = forwarded_issuer
    everything = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY, UNIX_SOCKET])
    application = SpiffeForwardedIssuerApp(
        SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: SpiffeGrant(REFUND), forwarded=everything)
    )
    try:
        status, _, reply, read = call_app(application, body=request_body(SigningKey.generate()), client=client)
        assert (status, reply["error"], read) == (403, "forbidden", False)
    finally:
        application.close()


def test_rewritten_client_address_is_never_trusted(forwarded_issuer, serve):
    """Even with Uvicorn told to believe X-Forwarded-For from anyone, a sender cannot pick a trusted address."""
    issuer, root, *_ = forwarded_issuer
    for trusted, claimed in ((["10.0.0.5"], "10.0.0.5"), ([UNIX_SOCKET], "unix"), (["10.0.0.5"], "unix")):
        remote = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=trusted)
        application = SpiffeForwardedIssuerApp(
            SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: SpiffeGrant(REFUND), forwarded=remote)
        )
        port = serve(application, proxy_headers=True, forwarded_allow_ips="*")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            status, reply = post(
                connection,
                request_body(SigningKey.generate()),
                {"x-forwarded-client-cert": element(), "X-Forwarded-For": claimed},
            )
            assert (status, reply["error"]) == (403, "forbidden"), (trusted, claimed)
        finally:
            connection.close()
            application.close()


def test_one_workload_cannot_hold_every_slot(forwarded_issuer):
    """Requests in progress are counted per SPIFFE ID, from before the body is read."""
    issuer, root, *_ = forwarded_issuer
    with pytest.raises(ValueError, match="max_per_identity"):
        SpiffeForwardedIssuerApp(issuer, max_per_identity=0)
    application = SpiffeForwardedIssuerApp(issuer, max_per_identity=2, max_concurrent=8, body_timeout=0.5)
    noisy, quiet = f"spiffe://{DOMAIN}/noisy", AGENT

    async def run():
        stalled = asyncio.Event()

        async def request(identity, stall):
            sent = []

            async def receive():
                if stall:
                    await stalled.wait()
                return {"type": "http.request", "body": request_body(SigningKey.generate()), "more_body": False}

            async def send(message):
                sent.append(message)

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/warrants",
                "root_path": "",
                "client": (PROXY, 40000),
                "server": ("127.0.0.1", 8080),
                "headers": [(b"x-forwarded-client-cert", element(identity).encode())],
            }
            await application(scope, receive, send)
            return sent[0]["status"], json.loads(sent[1]["body"])

        slow = [asyncio.ensure_future(request(noisy, True)) for _ in range(2)]
        await asyncio.sleep(0.05)
        # The noisy workload is at its limit; another workload is served as usual.
        status, reply = await request(noisy, False)
        assert status == 503 and "for this workload" in reply["message"]
        assert (await request(quiet, False))[0] == 200
        results = await asyncio.gather(*slow)
        assert [status for status, _ in results] == [408, 408]
        # The slots come back.
        assert application._per_key == {}
        assert (await request(noisy, False))[0] == 403  # Served again (and refused by policy, not by the limit).
        await asyncio.sleep(0.01)

    try:
        asyncio.run(run())
    finally:
        application.close()


def test_shortest_warrant_cap_still_issues(forwarded_issuer):
    _, root, *_ = forwarded_issuer
    brief = reader(DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY], max_warrant_seconds=5)
    issuer = SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: SpiffeGrant(REFUND), forwarded=brief)
    assert issue(issuer, SigningKey.generate()).id


def test_client_reports_an_unusable_host_name_as_a_spiffe_error():
    holder = SigningKey.generate()
    with pytest.raises(SpiffeError, match="Could not complete the exchange"):
        request_warrant_forwarded(
            "http://" + "a" * 64 + ".example/warrants",
            audience=AUDIENCE,
            issuer_key=SigningKey.generate().public_key,
            holder_key=holder,
            task_id="task-123",
            timeout=2,
        )


def test_cancelled_request_keeps_its_slot_while_its_policy_call_runs(forwarded):
    """Cancelling a request does not free the workload's place while the work it started is still running."""
    import threading

    entered, finish = threading.Event(), threading.Event()

    def slow_policy(identity, task_id):
        entered.set()
        finish.wait(10)
        return SpiffeGrant(REFUND)

    issuer = SpiffeWarrantIssuer(signing_key=SigningKey.generate(), policy=slow_policy, forwarded=forwarded)
    application = SpiffeForwardedIssuerApp(issuer, max_per_identity=1)

    async def request(identity=AGENT):
        sent = []

        async def receive():
            return {"type": "http.request", "body": request_body(SigningKey.generate()), "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/warrants",
            "root_path": "",
            "client": (PROXY, 40000),
            "server": ("127.0.0.1", 8080),
            "headers": [(b"x-forwarded-client-cert", element(identity).encode())],
        }
        await application(scope, receive, send)
        return sent[0]["status"], json.loads(sent[1]["body"])

    async def run():
        first = asyncio.ensure_future(request())
        while not entered.is_set():
            await asyncio.sleep(0.01)
        first.cancel()  # The client went away; the policy call is still running.
        with pytest.raises(asyncio.CancelledError):
            await first
        await asyncio.sleep(0.05)
        assert application._per_key == {AGENT: 1}
        status, reply = await request()
        assert status == 503 and "for this workload" in reply["message"]
        finish.set()
        for _ in range(200):
            if not application._per_key:
                break
            await asyncio.sleep(0.01)
        assert application._per_key == {} and application._in_progress == 0
        assert (await request())[0] == 200
        # A request cancelled before any work started gives its place back at once.
        stalled = asyncio.Event()

        async def never_sends(scope_identity=AGENT):
            async def receive():
                await stalled.wait()

            async def send(message):
                pass

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/warrants",
                "root_path": "",
                "client": (PROXY, 40000),
                "server": ("127.0.0.1", 8080),
                "headers": [(b"x-forwarded-client-cert", element(scope_identity).encode())],
            }
            await application(scope, receive, send)

        waiting = asyncio.ensure_future(never_sends())
        await asyncio.sleep(0.05)
        assert application._per_key == {AGENT: 1}
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert application._per_key == {} and application._in_progress == 0

    try:
        asyncio.run(run())
    finally:
        finish.set()
        application.close()


def test_a_client_in_another_language_gets_a_usable_warrant(app, serve, tmp_path):
    """The Node.js example builds the request from the guide's wire description alone."""
    import shutil
    import subprocess
    from pathlib import Path

    from tenuo import PublicKey

    script = Path(__file__).resolve().parents[2] / "examples" / "spiffe" / "clients" / "request_warrant.mjs"
    node = shutil.which("node")
    if node is None or not script.exists():
        pytest.skip("needs Node.js and the examples directory")
    application, _, root = app
    port = serve(InjectIdentity(application))
    url = f"http://127.0.0.1:{port}/warrants"

    key_file = tmp_path / "holder.pem"
    environment = {**os.environ, "HOLDER_KEY_FILE": str(key_file)}

    def request(*arguments):
        result = subprocess.run(
            [node, str(script), *arguments], capture_output=True, text=True, timeout=60, env=environment
        )
        if not result.stdout.strip():
            pytest.skip(f"this Node.js cannot run the example: {result.stderr.strip()[:200]}")
        return json.loads(result.stdout)

    reply = request(url, AUDIENCE, "task-123")
    assert reply["status"] == 200, reply
    warrant = Warrant.from_base64(reply["warrant"])
    assert warrant.issuer == root.public_key
    assert warrant.authorized_holder == PublicKey.from_bytes(base64.b64decode(reply["holder"]))
    # The point of the exchange: the caller still has the holder key, and with it the warrant works at a tool.
    assert key_file.stat().st_mode & 0o077 == 0 or os.name == "nt"
    holder = SigningKey.from_pem(key_file.read_text())
    assert warrant.authorized_holder == holder.public_key
    args = {"customer": "123", "cents": 100}
    Authorizer(trusted_roots=[root.public_key]).authorize(
        warrant, "refund", args, warrant.sign(holder, "refund", args, int(time.time()))
    )
    # A second request reuses the key in the file, and the example will not run without somewhere to keep it.
    assert request(url, AUDIENCE, "task-123")["holder"] == reply["holder"]
    forgetful = subprocess.run(
        [node, str(script), url, AUDIENCE, "task-123"],
        capture_output=True,
        text=True,
        timeout=60,
        env=dict(os.environ, HOLDER_KEY_FILE=""),
    )
    assert forgetful.returncode == 2 and not forgetful.stdout and "HOLDER_KEY_FILE" in forgetful.stderr
    # The same refusals as any other client.
    assert request(url, "https://another-issuer.example.test", "task-123")["message"] == "Invalid holder proof"
    assert "not authorized" in request(url, AUDIENCE, "another-task")["message"]


@pytest.mark.parametrize(
    ("client", "name", "value"),
    [
        (PROXY, "X-Forwarded-For", PROXY),
        (
            PROXY,
            "X-Forwarded-For",
            f"{PROXY}:40000",
        ),  # Uvicorn copies this port, so the address looks like a real peer.
        (PROXY, "X-Forwarded-For", f"203.0.113.7, {PROXY}:1234"),
        (PROXY, "x-forwarded-for", f"  {PROXY}  "),
        (PROXY, "Forwarded", f"for={PROXY}"),
        (PROXY, "Forwarded", f'for="{PROXY}:40000";proto=http, for=203.0.113.7'),
        (PROXY, "X-Real-IP", PROXY),
        (PROXY, "X-Forwarded-For", f"::ffff:{PROXY}"),
        (f"::ffff:{PROXY}", "X-Forwarded-For", f"{PROXY}:5"),
        ("::1", "X-Forwarded-For", "[::1]:40000"),
        ("::1", "Forwarded", 'for="[::1]:40000"'),
        ("::1", "X-Forwarded-For", "0:0:0:0:0:0:0:1"),
    ],
)
def test_a_peer_address_also_named_in_the_request_is_not_trusted(forwarded_issuer, caplog, client, name, value):
    """A server that rewrites client addresses takes them, port included, from these headers."""
    issuer, *_ = forwarded_issuer
    reader = SpiffeForwardedIdentity(
        DOMAIN, audience=AUDIENCE, trusted_proxies=[PROXY, "::1"], require_certificate=False
    )
    issuer.forwarded = reader
    application = SpiffeForwardedIssuerApp(issuer)
    caplog.set_level(logging.WARNING, logger="tenuo.spiffe")
    try:
        status, _, reply, read = call_app(
            application,
            headers=[("x-forwarded-client-cert", element()), (name, value)],
            body=request_body(SigningKey.generate()),
            client=(client, 40000),
        )
        assert (status, reply["error"], read) == (403, "forbidden", False)
        assert "also named in a forwarding header" in reply["message"]
        assert "uvicorn --no-proxy-headers" in caplog.text
    finally:
        application.close()


@pytest.mark.parametrize(
    "value",
    ["203.0.113.7", "203.0.113.7:40000", "unknown", "_hidden", "127.0.0.10", "1127.0.0.1", "127.0.0.1.5", "[::2]:1"],
)
def test_a_forwarding_header_that_names_someone_else_changes_nothing(app, value):
    """What a proxy adds about the original client is none of the issuer's business."""
    application, *_ = app
    for name in ("X-Forwarded-For", "Forwarded", "X-Real-IP"):
        text = f"for={value}" if name == "Forwarded" else value
        status, *_ = call_app(
            application,
            headers=[("x-forwarded-client-cert", element()), (name, text)],
            body=request_body(SigningKey.generate()),
        )
        assert status == 200, (name, text)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0, -1, True])
def test_time_settings_must_be_positive_and_finite(forwarded_issuer, value):
    issuer, root, *_ = forwarded_issuer
    with pytest.raises(ValueError, match="body_timeout"):
        SpiffeForwardedIssuerApp(issuer, body_timeout=value)
    holder = SigningKey.generate()
    with pytest.raises(ValueError, match="timeout"):
        request_warrant_forwarded(
            "http://127.0.0.1:1/warrants",
            audience=AUDIENCE,
            issuer_key=root.public_key,
            holder_key=holder,
            task_id="task-123",
            timeout=value,
        )
