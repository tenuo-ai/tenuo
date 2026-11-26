"""Real TLS handshakes and adversarial issuance tests (no SPIRE required)."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tenuo import Authorizer, Exact, Range, SigningKey
from tenuo.exceptions import AuthorizationError, DepthExceeded, SignatureInvalid
from tenuo.spiffe import (
    ANY_ARGUMENTS,
    SpiffeError,
    SpiffeGrant,
    SpiffeIdentity,
    SpiffeIssuerServer,
    SpiffeTLS,
    SpiffeWarrantIssuer,
    request_warrant,
    sign_holder_challenge,
)

DOMAIN = "example.test"
AGENT = f"spiffe://{DOMAIN}/agent"
SERVER = f"spiffe://{DOMAIN}/issuer"
REFUND = {"refund": {"customer": Exact("123"), "cents": Range(1, 5000)}}


class CA:
    """A test certificate authority that writes SVID-shaped leaves."""

    def __init__(self, directory: Path, name: str = "test root"):
        self.directory = directory
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.now(timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(self.name)
            .issuer_name(self.name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(True, None), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), False)
            .sign(self.key, hashes.SHA256())
        )
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM)

    def leaf(self, identity, *, ids=None, is_ca=False, usage=True, critical=True, eku=None, expires=600, starts=-10):
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(seconds=starts))
            .not_valid_after(now + timedelta(seconds=expires))
            .add_extension(x509.BasicConstraints(is_ca, None), True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(i) for i in (ids if ids is not None else [identity])]
                ),
                True,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False)
        )
        if usage:
            cert = cert.add_extension(
                x509.KeyUsage(True, False, False, False, False, is_ca, is_ca, False, False), critical
            )
        cert = cert.add_extension(
            x509.ExtendedKeyUsage(
                eku if eku is not None else [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            False,
        ).sign(self.key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    def files(self, prefix, identity, bundle=None, **options):
        cert, key = self.leaf(identity, **options)
        paths = {name: self.directory / f"{prefix}.{name}.pem" for name in ("bundle", "cert", "key")}
        paths["bundle"].write_bytes(bundle if bundle is not None else self.pem)
        paths["cert"].write_bytes(cert)
        paths["key"].write_bytes(key)
        return paths


@pytest.fixture
def ca(tmp_path):
    return CA(tmp_path)


@pytest.fixture
def pki(ca, tmp_path):
    counter = iter(range(10**6))

    def config(*, server=False, ids=None, trust_domain=DOMAIN, bundle_file=None, peer_only=False, **options):
        identity = SERVER if server else AGENT
        paths = ca.files(f"leaf{next(counter)}", identity, ids=ids, **options)
        if bundle_file is not None:
            paths["bundle"] = Path(bundle_file)
        if peer_only:
            # A raw client context that presents whatever certificate we built,
            # for testing how the issuer handles nonconforming peers.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.load_verify_locations(cafile=str(paths["bundle"]))
            context.load_cert_chain(str(paths["cert"]), str(paths["key"]))
            return SimpleNamespace(context=context)
        return SpiffeTLS(
            trust_domain=trust_domain,
            bundle_file=str(paths["bundle"]),
            cert_file=str(paths["cert"]),
            key_file=str(paths["key"]),
            server_side=server,
        )

    return config


def connect(server, client):
    """Complete an actual OpenSSL handshake over memory BIOs, without sockets."""
    si, so, ci, co = (ssl.MemoryBIO() for _ in range(4))
    s = server.context.wrap_bio(si, so, server_side=True)
    c = client.context.wrap_bio(ci, co, server_side=False)
    done = set()
    for _ in range(20):
        for connection, source, destination in ((c, co, si), (s, so, ci)):
            if connection not in done:
                try:
                    connection.do_handshake()
                    done.add(connection)
                except ssl.SSLWantReadError:
                    pass
            data = source.read()
            if data:
                destination.write(data)
        if len(done) == 2:
            return s, c
    raise AssertionError("TLS handshake did not complete")


@pytest.fixture
def exchange(pki):
    server, client = pki(server=True), pki()
    connection, peer = connect(server, client)
    root, holder = SigningKey.generate(), SigningKey.generate()
    seen = []

    def policy(identity, task_id):
        seen.append((identity.spiffe_id, task_id))
        if identity.spiffe_id == AGENT and task_id == "task-123":
            return SpiffeGrant(REFUND, ttl_seconds=120, max_depth=1)
        return None

    issuer = SpiffeWarrantIssuer(tls=server, signing_key=root, policy=policy)
    return issuer, connection, holder, root, seen, client, peer


def sign(challenge, holder, task="task-123"):
    return sign_holder_challenge(challenge, holder, task_id=task)


def mint(exchange, task="task-123"):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, task)
    return issuer.issue(connection, challenge, sign(challenge, holder, task))


# -- authentication -----------------------------------------------------------


def test_authenticate_both_peers(exchange):
    issuer, connection, _, _, _, client, peer = exchange
    assert issuer.tls.authenticate(connection).spiffe_id == AGENT
    assert client.authenticate(peer, expected_id=SERVER).spiffe_id == SERVER
    with pytest.raises(SpiffeError, match="expected server"):
        client.authenticate(peer)
    with pytest.raises(SpiffeError, match="Unexpected peer SPIFFE ID"):
        client.authenticate(peer, expected_id=AGENT)


@pytest.mark.parametrize(
    "identity",
    [
        "spiffe://evil.test/agent",
        "https://example.test/agent",
        "spiffe://example.test",
        "spiffe://example.test/",
        "spiffe://example.test/agent/",
        "spiffe://example.test/a//b",
        "spiffe://example.test/a/../b",
        "spiffe://example.test/./agent",
        "spiffe://example.test/%61gent",
        "spiffe://example.test/agent?admin=true",
        "spiffe://example.test/agent#admin",
        "spiffe://example.test:443/agent",
        "spiffe://user@example.test/agent",
        "spiffe://example.test/" + "a" * 2048,
    ],
)
def test_invalid_id_or_wrong_trust_domain(pki, identity):
    server = pki(server=True)
    connection, _ = connect(server, pki(ids=[identity], peer_only=True))
    with pytest.raises(SpiffeError):
        server.authenticate(connection)


@pytest.mark.parametrize(
    "options",
    [
        {"ids": []},
        {"ids": [AGENT, SERVER]},
        {"ids": [AGENT, "https://example.test"]},
        {"is_ca": True},
        {"usage": False},
        {"critical": False},
        {"eku": [ExtendedKeyUsageOID.CLIENT_AUTH]},
    ],
)
def test_nonconforming_svid(pki, options):
    server = pki(server=True)
    # Depending on OpenSSL version, malformed profiles may fail in TLS itself.
    with pytest.raises((SpiffeError, ssl.SSLError)):
        connection, _ = connect(server, pki(peer_only=True, **options))
        server.authenticate(connection)


@pytest.mark.parametrize("options", [{"ids": ["spiffe://other.test/agent"]}, {"usage": False}, {"expires": -1}])
def test_local_svid_validated_at_load(pki, options):
    with pytest.raises(SpiffeError):
        pki(**options)


def test_bundle_must_contain_only_authorities(ca, tmp_path):
    leaf, _ = ca.leaf(AGENT)
    paths = ca.files("bad-bundle", SERVER, bundle=ca.pem + leaf)
    with pytest.raises(SpiffeError, match="only CA"):
        SpiffeTLS(
            trust_domain=DOMAIN,
            bundle_file=str(paths["bundle"]),
            cert_file=str(paths["cert"]),
            key_file=str(paths["key"]),
            server_side=True,
        )
    same_root, _ = ca.leaf(f"spiffe://{DOMAIN}", is_ca=True)
    same_intermediate, _ = ca.leaf(f"spiffe://{DOMAIN}/intermediate", is_ca=True)
    ok_paths = ca.files("domain-bundle", SERVER, bundle=ca.pem + same_root + same_intermediate)
    assert _tls(ok_paths, True).identity.spiffe_id == SERVER
    for foreign_id in ("spiffe://foreign.test", "spiffe://foreign.test/ca", "https://example.test"):
        foreign_ca, _ = ca.leaf(foreign_id, is_ca=True)
        bad_paths = ca.files("foreign-bundle", SERVER, bundle=ca.pem + foreign_ca)
        with pytest.raises(SpiffeError, match="different trust domain"):
            _tls(bad_paths, True)


@pytest.mark.parametrize("options", [{"expires": -1}, {"starts": 60}])
def test_tls_rejects_expired_or_future_certificate(pki, options):
    with pytest.raises(ssl.SSLError):
        connect(pki(server=True), pki(peer_only=True, **options))


def test_live_connection_expiry_rechecked(exchange, monkeypatch):
    issuer, connection, *_ = exchange
    future = issuer.tls.authenticate(connection).expires_at + 1
    monkeypatch.setattr("tenuo.spiffe.time.time", lambda: future)
    with pytest.raises(SpiffeError, match="not currently valid"):
        issuer.tls.authenticate(connection)


def test_no_unverified_identity_input(exchange, pki):
    issuer, connection, *_ = exchange
    with pytest.raises(SpiffeError):
        issuer.tls.authenticate({"X-SPIFFE-ID": AGENT})
    with pytest.raises(SpiffeError):
        pki(server=True).authenticate(connection)
    issuer.tls.context.verify_mode = ssl.CERT_OPTIONAL
    with pytest.raises(SpiffeError):
        issuer.tls.authenticate(connection)


def test_unswitched_listener_handshake_cannot_complete(pki):
    server = pki(server=True)
    server.context.sni_callback = None  # Simulate the generation switch not running.
    with pytest.raises(ssl.SSLError):
        connect(server, pki())


def test_untrusted_certificate(pki, tmp_path):
    other = CA(tmp_path, "untrusted")
    other_bundle = tmp_path / "other.pem"
    other_bundle.write_bytes(other.pem)
    with pytest.raises(ssl.SSLError):
        connect(pki(server=True, bundle_file=other_bundle), pki(peer_only=True))


def test_tls_requires_client_certificate(pki, ca):
    server = pki(server=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.load_verify_locations(cadata=ca.pem.decode())
    with pytest.raises(ssl.SSLError):
        connect(server, SimpleNamespace(context=context))


# -- holder proof ---------------------------------------------------------------


def test_warrant_and_delegated_tool_boundary(exchange):
    _, _, holder, root, seen, *_ = exchange
    warrant = mint(exchange)
    assert seen == [(AGENT, "task-123")]
    authorizer = Authorizer(trusted_roots=[root.public_key])
    args = {"customer": "123", "cents": 4000}
    authorizer.authorize(warrant, "refund", args, warrant.sign(holder, "refund", args, int(time.time())))
    for tool, bad in [
        ("refund", {"customer": "999", "cents": 4000}),
        ("refund", {"customer": "123", "cents": 5001}),
        ("delete", args),
    ]:
        with pytest.raises(AuthorizationError):
            authorizer.authorize(warrant, tool, bad, warrant.sign(holder, tool, bad, int(time.time())))
    worker = SigningKey.generate()
    with pytest.raises(SignatureInvalid):
        authorizer.authorize(warrant, "refund", args, warrant.sign(worker, "refund", args, int(time.time())))
    child = (
        warrant.grant_builder()
        .holder(worker.public_key)
        .ttl(30)
        .capability("refund", customer=Exact("123"), cents=Range(1, 1000))
        .grant(holder)
    )
    narrow = {"customer": "123", "cents": 800}
    authorizer.check_chain([warrant, child], "refund", narrow, child.sign(worker, "refund", narrow, int(time.time())))
    with pytest.raises(AuthorizationError):
        authorizer.check_chain([warrant, child], "refund", args, child.sign(worker, "refund", args, int(time.time())))


def test_unprefixed_signature_rejected(exchange):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError, match="Invalid holder proof"):
        issuer.issue(connection, challenge, bytes(holder.sign_raw(challenge)))


def _pop_bytes(warrant, tool, args, ts):
    import cbor2

    body = cbor2.dumps([warrant.id.split("_")[-1], tool, sorted(args.items()), (ts // 30) * 30])
    return b"tenuo-warrant-v1tenuo-pop-v1" + body


def test_holder_refuses_to_sign_other_messages(exchange):
    """An issuer cannot turn the holder signature into a tool-call proof."""
    issuer, connection, holder, root, *_ = exchange
    warrant = mint(exchange)
    args, ts = {"customer": "123", "cents": 5000}, int(time.time())
    crafted = [warrant.payload_bytes, b"tenuo-warrant-v1" + warrant.payload_bytes]
    if importlib.util.find_spec("cbor2"):
        # Exact signed bytes of a tool-call proof (checked against the SDK).
        pop = _pop_bytes(warrant, "refund", args, ts)
        assert bytes(holder.sign_raw(pop)) == bytes(warrant.sign(holder, "refund", args, ts))
        crafted.append(pop)
    for message in crafted:
        with pytest.raises(SpiffeError, match="Invalid holder challenge"):
            sign_holder_challenge(message, holder, task_id="task-123")


def test_holder_checks_challenge_fields(exchange):
    issuer, connection, holder, root, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    fields = json.loads(challenge)
    with pytest.raises(SpiffeError, match="different holder"):
        sign_holder_challenge(challenge, SigningKey.generate(), task_id="task-123")
    with pytest.raises(SpiffeError, match="different task"):
        sign_holder_challenge(challenge, holder, task_id="task-999")
    with pytest.raises(SpiffeError, match="different issuer"):
        sign_holder_challenge(challenge, holder, task_id="task-123", issuer_key=SigningKey.generate().public_key)
    with pytest.raises(SpiffeError, match="different SPIFFE ID"):
        sign_holder_challenge(challenge, holder, task_id="task-123", spiffe_id=SERVER)
    for variant in (
        json.dumps(fields).encode(),  # not canonical
        json.dumps({**fields, "extra": "x"}, sort_keys=True, separators=(",", ":")).encode(),
        json.dumps({**fields, "nonce": "00"}, sort_keys=True, separators=(",", ":")).encode(),
        b"\xff" + challenge,
    ):
        with pytest.raises(SpiffeError, match="Invalid holder challenge"):
            sign_holder_challenge(variant, holder, task_id="task-123")
    signature = sign_holder_challenge(
        challenge, holder, task_id="task-123", issuer_key=root.public_key, spiffe_id=AGENT
    )
    issuer.issue(connection, challenge, signature)


def test_longest_accepted_fields_still_produce_a_signable_challenge(pki):
    """The holder must not reject a challenge the issuer legitimately built.

    The worst case is a maximal SPIFFE ID plus a maximal task_id of
    supplementary characters, which the issuer escapes at 12 bytes each.
    """
    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = SpiffeWarrantIssuer(
        tls=pki(server=True), signing_key=root, policy=lambda *_: SpiffeGrant(REFUND, ttl_seconds=60)
    )
    identity = SpiffeIdentity(
        spiffe_id=f"spiffe://{DOMAIN}/" + "a" * (2048 - len(f"spiffe://{DOMAIN}/")),
        certificate_sha256="b" * 64,
        expires_at=time.time() + 3600,
    )
    task_id = "\U0001f600" * 256

    challenge = issuer._challenge(identity, holder.public_key, task_id)

    assert len(challenge) > 4096, "expected a case the previous 4 KiB bound rejected"
    sign_holder_challenge(challenge, holder, task_id=task_id, issuer_key=root.public_key, spiffe_id=identity.spiffe_id)


@pytest.mark.parametrize("length, within_bound", [(256, True), (257, False)])
def test_task_id_length_boundary(exchange, length, within_bound):
    issuer, connection, holder, *_ = exchange
    task_id = "t" * length
    # Within the bound the length check passes and this fixture's policy is the
    # one that refuses; past it, the length check refuses first.
    expected = "not authorized" if within_bound else "1–256 characters"
    with pytest.raises(SpiffeError, match=expected):
        issuer.challenge(connection, holder.public_key, task_id)


def test_replay_and_wrong_holder(exchange):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    other = SigningKey.generate()
    with pytest.raises(SpiffeError, match="Invalid holder proof"):
        issuer.issue(connection, challenge, bytes(other.sign_raw(b"tenuo.spiffe.holder-binding.v1\x00" + challenge)))
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, sign(challenge, holder))
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    issuer.issue(connection, challenge, sign(challenge, holder))
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, sign(challenge, holder))


def test_challenge_tampering(exchange):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    altered = challenge.replace(b"task-123", b"task-999")
    with pytest.raises(SpiffeError, match="Unknown"):
        issuer.issue(connection, altered, sign(altered, holder, "task-999"))


def test_expired_challenge(exchange, monkeypatch):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    future = time.monotonic() + 31
    monkeypatch.setattr("tenuo.spiffe.time.monotonic", lambda: future)
    with pytest.raises(SpiffeError, match="expired"):
        issuer.issue(connection, challenge, sign(challenge, holder))


def test_other_certificate_cannot_redeem(exchange, pki):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    # Even the same SPIFFE ID with a renewed/different certificate must restart.
    other, _ = connect(issuer.tls, pki())
    with pytest.raises(SpiffeError, match="different SVID"):
        issuer.issue(other, challenge, sign(challenge, holder))


def test_single_use_under_concurrency(exchange):
    issuer, connection, holder, _, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    signature = sign(challenge, holder)

    def redeem(_):
        try:
            issuer.issue(connection, challenge, signature)
            return True
        except SpiffeError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(redeem, range(8))) == 1
    assert len(seen) == 1


@pytest.mark.parametrize("signature", ["abc", None, b"", b"\x00" * 63, bytearray(64)])
def test_malformed_signature_inputs(exchange, signature):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError):
        issuer.issue(connection, challenge, signature)
    with pytest.raises(SpiffeError):
        issuer.issue(connection, ["not", "bytes"], b"\x00" * 64)


def test_challenge_cannot_cross_issuer_instances(exchange):
    issuer, connection, holder, root, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    other = SpiffeWarrantIssuer(tls=issuer.tls, signing_key=root, policy=issuer._policy)
    with pytest.raises(SpiffeError, match="Unknown"):
        other.issue(connection, challenge, sign(challenge, holder))


# -- policy, limits, audit --------------------------------------------------------


@pytest.mark.parametrize("task", ["unknown", "task-123;admin=true"])
def test_policy_denies_unknown_task(exchange, task):
    issuer, *_ = exchange
    with pytest.raises(SpiffeError, match="not authorized"):
        mint(exchange, task)
    assert issuer._pending == {}


def test_valid_but_unauthorized_workload_gets_no_challenge(exchange, pki):
    issuer, _, holder, _, seen, *_ = exchange
    connection, _ = connect(issuer.tls, pki(ids=[f"spiffe://{DOMAIN}/other-agent"]))
    with pytest.raises(SpiffeError, match="not authorized"):
        issuer.challenge(connection, holder.public_key, "task-123")
    assert seen == [(f"spiffe://{DOMAIN}/other-agent", "task-123")]
    assert issuer._pending == {}


def test_unauthorized_workload_cannot_exhaust_challenges(exchange, pki):
    issuer, connection, holder, *_ = exchange
    noisy, _ = connect(issuer.tls, pki(ids=[f"spiffe://{DOMAIN}/batch"]))
    for i in range(2000):
        with pytest.raises(SpiffeError, match="not authorized"):
            issuer.challenge(noisy, SigningKey.generate().public_key, f"junk-{i}")
    mint(exchange)


def test_per_identity_pending_limit(exchange, pki):
    issuer, connection, holder, *_ = exchange
    issuer._policy = lambda identity, task: SpiffeGrant(REFUND)
    for _ in range(16):
        issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError, match="for this workload"):
        issuer.challenge(connection, holder.public_key, "task-123")
    other, _ = connect(issuer.tls, pki(ids=[f"spiffe://{DOMAIN}/second-agent"]))
    issuer.challenge(other, holder.public_key, "task-123")


def test_pending_limit_and_cleanup(exchange, monkeypatch):
    issuer, connection, holder, *_ = exchange
    issuer._max_pending = 1
    issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError, match="Too many"):
        issuer.challenge(connection, holder.public_key, "task-123")
    future = time.monotonic() + 31
    monkeypatch.setattr("tenuo.spiffe.time.monotonic", lambda: future)
    issuer.challenge(connection, holder.public_key, "task-123")
    assert len(issuer._pending) == 1


def test_policy_error_fails_closed(exchange):
    issuer, connection, holder, *_ = exchange

    def broken(*_):
        raise RuntimeError("policy unavailable")

    issuer._policy = broken
    with pytest.raises(RuntimeError, match="policy unavailable"):
        issuer.challenge(connection, holder.public_key, "task-123")
    assert issuer._pending == {}


@pytest.mark.parametrize(
    "grant",
    [
        SpiffeGrant({}),
        SpiffeGrant({"read": ANY_ARGUMENTS}, ttl_seconds=0),
        SpiffeGrant({"read": ANY_ARGUMENTS}, ttl_seconds=True),
        SpiffeGrant({"read": {}}),
        SpiffeGrant({"": ANY_ARGUMENTS}),
        SpiffeGrant({"read": ANY_ARGUMENTS}, max_depth=-1),
        SpiffeGrant({"read": ANY_ARGUMENTS}, max_depth=65),
        SpiffeGrant({"read": ANY_ARGUMENTS}, max_depth=True),
        SpiffeGrant({"read": ANY_ARGUMENTS}, max_depth=2**40),
        {"read": ANY_ARGUMENTS},
    ],
)
def test_invalid_policy_grant(exchange, grant):
    issuer, *_ = exchange
    issuer._policy = lambda *_: grant
    with pytest.raises(SpiffeError):
        mint(exchange)
    assert issuer._pending == {}


def test_any_arguments_is_explicit(exchange):
    issuer, _, holder, root, *_ = exchange
    issuer._policy = lambda *_: SpiffeGrant({"read": ANY_ARGUMENTS})
    warrant = mint(exchange)
    args = {"path": "anything"}
    Authorizer(trusted_roots=[root.public_key]).authorize(
        warrant, "read", args, warrant.sign(holder, "read", args, int(time.time()))
    )


def test_ttl_capped_to_svid(pki):
    server = pki(server=True)
    connection, _ = connect(server, pki(expires=20))
    key = SigningKey.generate()
    issuer = SpiffeWarrantIssuer(
        tls=server, signing_key=key, policy=lambda *_: SpiffeGrant({"read": ANY_ARGUMENTS}, ttl_seconds=300)
    )
    challenge = issuer.challenge(connection, key.public_key, "task")
    warrant = issuer.issue(connection, challenge, sign(challenge, key, "task"))
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() <= server.authenticate(connection).expires_at
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() < time.time() + 21


def test_identity_expiring_before_proof_cannot_mint(exchange, monkeypatch):
    issuer, connection, holder, *_ = exchange
    identity = issuer.tls.authenticate(connection)
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    monkeypatch.setattr("tenuo.spiffe.time.time", lambda: identity.expires_at - 0.5)
    with pytest.raises(SpiffeError, match="expires too soon"):
        issuer.issue(connection, challenge, sign(challenge, holder))


def test_default_grant_is_terminal(exchange):
    issuer, _, holder, *_ = exchange
    issuer._policy = lambda *_: SpiffeGrant({"refund": {"customer": Exact("123")}})
    warrant = mint(exchange)
    with pytest.raises(DepthExceeded):
        (
            warrant.grant_builder()
            .holder(SigningKey.generate().public_key)
            .capability("refund", customer=Exact("123"))
            .grant(holder)
        )


def test_audit_record_and_fail_closed(exchange):
    issuer, connection, holder, *_ = exchange
    records = []
    issuer._audit = records.append
    warrant = mint(exchange)
    (record,) = records
    assert (record.identity.spiffe_id, record.task_id, record.warrant_id) == (AGENT, "task-123", warrant.id)
    assert record.holder == bytes(holder.public_key.to_bytes()).hex() and record.tools == ("refund",)

    def broken(_):
        raise RuntimeError("audit store down")

    issuer._audit = broken
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(RuntimeError, match="audit store down"):
        issuer.issue(connection, challenge, sign(challenge, holder))
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, sign(challenge, holder))


# -- rotation ---------------------------------------------------------------------


def _tls(paths, server):
    return SpiffeTLS(
        trust_domain=DOMAIN,
        bundle_file=str(paths["bundle"]),
        cert_file=str(paths["cert"]),
        key_file=str(paths["key"]),
        server_side=server,
    )


def _rewrite(ca, paths, identity, bundle=None, **options):
    cert, key = ca.leaf(identity, **options)
    paths["cert"].write_bytes(cert)
    paths["key"].write_bytes(key)
    if bundle is not None:
        paths["bundle"].write_bytes(bundle)


def _served(client_connection):
    return x509.load_der_x509_certificate(client_connection.getpeercert(True)).fingerprint(hashes.SHA256()).hex()


def test_reload_rotates_svid_on_existing_listener(ca, pki):
    paths = ca.files("rotating", SERVER)
    server = _tls(paths, True)
    listener = server.context  # Held by a long-lived listener; never replaced.
    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = SpiffeWarrantIssuer(tls=server, signing_key=root, policy=lambda *_: SpiffeGrant(REFUND))
    old_connection, old_peer = connect(server, pki())
    challenge = issuer.challenge(old_connection, holder.public_key, "task-123")
    first = _served(old_peer)
    assert server.reload_if_changed() is False
    time.sleep(0.01)
    _rewrite(ca, paths, SERVER)
    assert server.reload_if_changed() is True
    assert server.context is listener
    new_connection, new_peer = connect(server, pki())
    assert _served(new_peer) != first
    assert _served(new_peer) == server.identity.certificate_sha256
    # Connections and challenges from before the rotation keep working.
    issuer.issue(old_connection, challenge, sign(challenge, holder))
    issuer.tls.authenticate(new_connection)


def test_reload_removing_authority_drops_old_connections(ca, pki, tmp_path):
    successor = CA(tmp_path, "successor root")
    paths = ca.files("ca-rotation", SERVER, bundle=ca.pem + successor.pem)
    server = _tls(paths, True)
    old_connection, _ = connect(server, pki())  # Agent from the original CA.
    # Remove the original authority, as after revocation of a compromised CA.
    _rewrite(successor, paths, SERVER, bundle=successor.pem)
    server.reload()
    with pytest.raises(SpiffeError, match="not verified by this SPIFFE TLS context"):
        server.authenticate(old_connection)
    with pytest.raises(ssl.SSLError):
        connect(server, pki(peer_only=True))
    agent_paths = successor.files("successor-agent", AGENT)
    connection, _ = connect(server, _tls(agent_paths, False))
    assert server.authenticate(connection).spiffe_id == AGENT


def test_reload_adding_authority_keeps_old_connections(ca, pki, tmp_path):
    successor = CA(tmp_path, "successor root")
    paths = ca.files("ca-add", SERVER)
    server = _tls(paths, True)
    old_connection, _ = connect(server, pki())
    paths["bundle"].write_bytes(ca.pem + successor.pem)
    server.reload()
    assert server.authenticate(old_connection).spiffe_id == AGENT


@pytest.mark.parametrize("damage", ["mismatched key", "garbage cert", "other domain", "missing file"])
def test_failed_reload_keeps_current_credentials(ca, pki, damage):
    paths = ca.files("damaged", SERVER)
    server = _tls(paths, True)
    before = server.identity
    if damage == "mismatched key":
        _, key = ca.leaf(SERVER)
        paths["key"].write_bytes(key)
    elif damage == "garbage cert":
        paths["cert"].write_bytes(b"not a certificate")
    elif damage == "other domain":
        _rewrite(ca, paths, SERVER, ids=["spiffe://other.test/issuer"])
    else:
        paths["cert"].unlink()
    with pytest.raises((SpiffeError, OSError)):
        server.reload()
    server._refresh()  # Logs, never raises.
    assert server.identity == before
    connection, _ = connect(server, pki())
    assert server.authenticate(connection).spiffe_id == AGENT


def test_client_context_rotates(ca, pki):
    paths = ca.files("client-rotation", AGENT)
    client = _tls(paths, False)
    server = pki(server=True)
    _, old_peer = connect(server, client)
    first = client.identity.certificate_sha256
    _rewrite(ca, paths, AGENT)
    client.reload()
    assert client.identity.certificate_sha256 != first
    connection, peer = connect(server, client)
    assert server.authenticate(connection).certificate_sha256 == client.identity.certificate_sha256
    assert client.authenticate(old_peer, expected_id=SERVER).spiffe_id == SERVER


# -- bundled server and client -----------------------------------------------------


@pytest.fixture
def served(pki):
    server_tls, client_tls = pki(server=True), pki()
    root, holder = SigningKey.generate(), SigningKey.generate()

    def policy(identity, task_id):
        if identity.spiffe_id == AGENT and task_id == "task-123":
            return SpiffeGrant(REFUND, ttl_seconds=60)
        return None

    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=root, policy=policy)
    return issuer, client_tls, root, holder


def run_server(issuer, body, **options):
    async def main():
        async with SpiffeIssuerServer(issuer, host="127.0.0.1", port=0, **options) as server:
            return await body(server.address)

    return asyncio.run(main())


def test_server_issues_and_client_verifies(served):
    issuer, client_tls, root, holder = served

    async def body(address):
        options = dict(issuer_id=SERVER, issuer_key=root.public_key, holder_key=holder, task_id="task-123")
        return await asyncio.to_thread(request_warrant, client_tls, address, **options)

    warrant = run_server(issuer, body)
    args = {"customer": "123", "cents": 100}
    Authorizer(trusted_roots=[root.public_key]).authorize(
        warrant, "refund", args, warrant.sign(holder, "refund", args, int(time.time()))
    )


@pytest.mark.parametrize(
    "change, message",
    [
        ({"task_id": "unknown"}, "not authorized"),
        ({"issuer_id": f"spiffe://{DOMAIN}/someone-else"}, "Unexpected peer SPIFFE ID"),
        ({"issuer_key": SigningKey.generate().public_key}, "different issuer key"),
    ],
)
def test_client_refusals(served, change, message):
    issuer, client_tls, root, holder = served
    options = {"issuer_id": SERVER, "issuer_key": root.public_key, "holder_key": holder, "task_id": "task-123"}
    options.update(change)

    async def body(address):
        with pytest.raises(SpiffeError, match=message):
            await asyncio.to_thread(request_warrant, client_tls, address, **options)

    run_server(issuer, body)
    assert issuer._pending == {}


def test_client_accepts_any_listed_issuer_key(served):
    """During issuer key rotation, agents list the old and the new key."""
    issuer, client_tls, root, holder = served
    retired = SigningKey.generate().public_key
    options = dict(issuer_id=SERVER, holder_key=holder, task_id="task-123")

    async def body(address):
        warrant = await asyncio.to_thread(
            request_warrant, client_tls, address, issuer_key=[retired, root.public_key], **options
        )
        with pytest.raises(SpiffeError, match="different issuer key"):
            await asyncio.to_thread(request_warrant, client_tls, address, issuer_key=[retired], **options)
        with pytest.raises(ValueError):
            await asyncio.to_thread(request_warrant, client_tls, address, issuer_key=[], **options)
        return warrant

    assert run_server(issuer, body).issuer == root.public_key


def test_client_reports_every_failure_as_spiffe_error(served, pki, tmp_path):
    issuer, client_tls, root, holder = served
    options = dict(issuer_id=SERVER, issuer_key=root.public_key, holder_key=holder, task_id="task-123")
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        closed_port = unused.getsockname()
    with pytest.raises(SpiffeError, match="Could not complete the exchange with the issuer at 127.0.0.1"):
        request_warrant(client_tls, closed_port, timeout=2, **options)

    other = CA(tmp_path, "another root")
    stranger_paths = other.files("stranger", AGENT)
    stranger = _tls(stranger_paths, False)

    def failing_policy(*_):
        raise RuntimeError("database down")

    async def body(address):
        # An agent from another CA: it rejects the issuer's SVID.
        with pytest.raises(SpiffeError, match="was not accepted"):
            await asyncio.to_thread(request_warrant, stranger, address, **options)
        issuer._policy = failing_policy
        with pytest.raises(SpiffeError, match="Issuer error; see the issuer's log"):
            await asyncio.to_thread(request_warrant, client_tls, address, **options)

    run_server(issuer, body)


def _raw_session(client_tls, address, payload, read=True):
    with socket.create_connection(address, timeout=5) as raw:
        with client_tls.context.wrap_socket(raw) as tls:
            tls.sendall(payload)
            if not read:
                return b""
            data = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    return data
                data += chunk


@pytest.mark.parametrize(
    "payload",
    [
        b"x" * (70 * 1024) + b"\n",
        b"not json\n",
        b'{"v": 2, "holder": "", "task": "task-123"}\n',
        b'{"v": 1, "holder": "AAAA", "task": "task-123"}\n',
        b'{"v": 1, "holder": "AAAA", "task": "task-123", "extra": 1}\n',
        b"[]\n",
    ],
    ids=["oversized", "not-json", "wrong-version", "short-holder", "extra-key", "not-an-object"],
)
def test_server_rejects_malformed_requests(served, payload):
    issuer, client_tls, *_ = served

    async def body(address):
        return await asyncio.to_thread(_raw_session, client_tls, address, payload)

    response = run_server(issuer, body)
    assert b"warrant" not in response and b"challenge" not in response


def test_server_times_out_idle_connections(served):
    issuer, client_tls, *_ = served

    def idle(address):
        with socket.create_connection(address, timeout=5) as raw:
            with client_tls.context.wrap_socket(raw) as tls:
                start = time.monotonic()
                assert tls.recv(1) == b""
                return time.monotonic() - start

    async def body(address):
        return await asyncio.to_thread(idle, address)

    assert run_server(issuer, body, timeout=0.5) < 4


def test_server_connection_limit(served):
    issuer, client_tls, root, holder = served

    def hold_and_try(address):
        with socket.create_connection(address, timeout=5) as raw:
            with client_tls.context.wrap_socket(raw):
                time.sleep(0.2)
                with pytest.raises(SpiffeError):
                    request_warrant(
                        client_tls,
                        address,
                        issuer_id=SERVER,
                        issuer_key=root.public_key,
                        holder_key=holder,
                        task_id="task-123",
                    )

    async def body(address):
        await asyncio.to_thread(hold_and_try, address)

    run_server(issuer, body, max_connections=1)


def test_server_reloads_rotated_credentials(ca, pki):
    paths = ca.files("served-rotation", SERVER)
    server_tls, client_tls = _tls(paths, True), pki()
    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=root, policy=lambda *_: SpiffeGrant(REFUND))

    def fetch(address):
        return request_warrant(
            client_tls, address, issuer_id=SERVER, issuer_key=root.public_key, holder_key=holder, task_id="t"
        )

    def served_fingerprint(address):
        with socket.create_connection(address, timeout=5) as raw:
            with client_tls.context.wrap_socket(raw) as tls:
                return _served(tls)

    async def body(address):
        before = await asyncio.to_thread(served_fingerprint, address)
        _rewrite(ca, paths, SERVER)
        await asyncio.sleep(0.5)
        after = await asyncio.to_thread(served_fingerprint, address)
        await asyncio.to_thread(fetch, address)
        return before, after

    before, after = run_server(issuer, body, reload_interval=0.1)
    assert before != after == server_tls.identity.certificate_sha256


def connect_resuming(server, client, session=None):
    """Like connect(), optionally offering a saved client session."""
    si, so, ci, co = (ssl.MemoryBIO() for _ in range(4))
    s = server.context.wrap_bio(si, so, server_side=True)
    c = client.context.wrap_bio(ci, co, server_side=False, session=session)
    done = set()
    for _ in range(20):
        for connection, source, destination in ((c, co, si), (s, so, ci)):
            if connection not in done:
                try:
                    connection.do_handshake()
                    done.add(connection)
                except ssl.SSLWantReadError:
                    pass
            data = source.read()
            if data:
                destination.write(data)
        if len(done) == 2:
            # Deliver post-handshake messages (TLS 1.3 session tickets) to the client.
            try:
                c.read(1)
            except ssl.SSLWantReadError:
                pass
            return s, c
    raise AssertionError("TLS handshake did not complete")


@pytest.mark.parametrize("maximum", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_resumed_session_cannot_outlive_removed_authority(ca, pki, tmp_path, maximum):
    if maximum == ssl.TLSVersion.TLSv1_3 and not ssl.HAS_TLSv1_3:
        pytest.skip("TLS 1.3 unavailable")
    successor = CA(tmp_path, "successor root")
    paths = ca.files("resume", SERVER, bundle=ca.pem + successor.pem)
    server = _tls(paths, True)
    client = pki(peer_only=True, bundle_file=paths["bundle"])  # Agent from the original CA.
    client.context.maximum_version = maximum
    connection, peer = connect_resuming(server, client)
    assert server.authenticate(connection).spiffe_id == AGENT
    session = peer.session
    _rewrite(successor, paths, SERVER, bundle=successor.pem)
    server.reload()
    client.context.load_verify_locations(cadata=successor.pem.decode())
    try:
        resumed, _ = connect_resuming(server, client, session=session)
    except ssl.SSLError:
        return  # No resumption offered: the full handshake fails against the new bundle.
    with pytest.raises(SpiffeError):
        server.authenticate(resumed)


def test_resumed_sessions_are_never_accepted(pki):
    server, client = pki(server=True), pki()
    connection, peer = connect_resuming(server, client)
    resumed, resumed_peer = connect_resuming(server, client, session=peer.session)
    if resumed.session_reused:
        with pytest.raises(SpiffeError, match="Resumed TLS sessions"):
            server.authenticate(resumed)
    else:
        assert server.authenticate(resumed).spiffe_id == AGENT


def test_unreadable_bundle_does_not_stop_reloading(ca, pki):
    paths = ca.files("unreadable", SERVER)
    server = _tls(paths, True)
    before = server.identity
    paths["bundle"].write_bytes(b"\xff\xfe not a bundle")
    with pytest.raises(SpiffeError, match="must contain PEM certificates"):
        server.reload()
    server._refresh()
    assert server.identity == before
    # Text around the PEM blocks is ignored: only the parsed certificates are trusted.
    _rewrite(ca, paths, SERVER, bundle="# Bündel\n".encode() + ca.pem)
    server._refresh()
    assert server.identity != before
    connection, _ = connect(server, pki())
    assert server.authenticate(connection).spiffe_id == AGENT


def test_server_reload_loop_survives_bad_files(ca):
    paths = ca.files("served-bad", SERVER)
    server_tls = _tls(paths, True)
    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=SigningKey.generate(), policy=lambda *_: None)
    before = server_tls.identity

    async def body(address):
        paths["bundle"].write_bytes(b"\xff\xfe not a bundle")
        await asyncio.sleep(0.4)
        _rewrite(ca, paths, SERVER, bundle=ca.pem)
        await asyncio.sleep(0.4)

    run_server(issuer, body, reload_interval=0.1)
    assert server_tls.identity != before


def test_connection_limit_counts_sockets_before_handshake(served):
    issuer, client_tls, root, holder = served
    options = dict(issuer_id=SERVER, issuer_key=root.public_key, holder_key=holder, task_id="task-123")

    def scenario(address):
        idle = [socket.create_connection(address, timeout=5) for _ in range(2)]  # No TLS, no bytes.
        try:
            time.sleep(0.2)
            with pytest.raises(SpiffeError):
                request_warrant(client_tls, address, **options)
            # The deadline closes idle sockets that never start a handshake.
            start = time.monotonic()
            assert idle[0].recv(1) == b""
            assert time.monotonic() - start < 4
        finally:
            for raw in idle:
                raw.close()
        time.sleep(0.2)
        return request_warrant(client_tls, address, **options)

    async def body(address):
        return await asyncio.to_thread(scenario, address)

    assert run_server(issuer, body, max_connections=2, timeout=1.0).id


def test_constraint_values_checked_before_challenge(exchange, caplog):
    issuer, connection, holder, *_ = exchange
    issuer._policy = lambda *_: SpiffeGrant({"refund": {"cents": 5}})  # Not a constraint object.
    with caplog.at_level("WARNING", logger="tenuo.spiffe"), pytest.raises(SpiffeError, match="invalid constraints"):
        issuer.challenge(connection, holder.public_key, "task-123")
    assert "Invalid policy grant for spiffe://example.test/agent task 'task-123'" in caplog.text
    assert issuer._pending == {}


def test_abandoned_server_exchange_releases_pending_slot(served):
    issuer, client_tls, root, holder = served
    options = dict(
        issuer_id=SERVER, issuer_key=[SigningKey.generate().public_key], holder_key=holder, task_id="task-123"
    )

    async def body(address):
        # Each attempt obtains a challenge and disconnects when the client rejects the issuer key.
        for _ in range(20):
            with pytest.raises(SpiffeError, match="different issuer key"):
                await asyncio.to_thread(request_warrant, client_tls, address, **options)
        return await asyncio.to_thread(
            request_warrant,
            client_tls,
            address,
            issuer_id=SERVER,
            issuer_key=root.public_key,
            holder_key=holder,
            task_id="task-123",
        )

    assert run_server(issuer, body).id
    assert issuer._pending == {}


def _parked_policy_server(pki):
    """An issuer whose single policy thread parks until the returned gate opens.

    ``entered`` reports that a callback actually reached the pool, so a server
    too slow to get that far fails loudly instead of vacuously passing. The
    gate's own timeout is only a backstop against hanging the suite; it is long
    enough that no runner can reach it while a test is still working.
    """
    root, holder = SigningKey.generate(), SigningKey.generate()
    gate, entered = threading.Event(), threading.Event()

    def policy(identity, task_id):
        entered.set()
        gate.wait(60)
        return SpiffeGrant(REFUND, ttl_seconds=60)

    issuer = SpiffeWarrantIssuer(tls=pki(server=True), signing_key=root, policy=policy)
    client_tls = pki()

    def fetch(address, task_id="task-123"):
        return request_warrant(
            client_tls, address, issuer_id=SERVER, issuer_key=root.public_key, holder_key=holder, task_id=task_id
        )

    return issuer, fetch, gate, entered


def test_timed_out_exchanges_do_not_pile_up_in_the_policy_queue(pki):
    """Reconnecting clients must not grow the policy pool's queue without limit.

    A timed-out exchange frees its connection slot as it unwinds, so the
    connection count alone does not bound anything the pool has been handed:
    with every policy thread parked, replacement connections would keep
    enqueueing work items that nothing drains. Reads the pool's queue directly
    because a submission that is never picked up has no other observable.
    """
    issuer, fetch, gate, entered = _parked_policy_server(pki)

    async def main():
        async with SpiffeIssuerServer(
            issuer, host="127.0.0.1", port=0, max_connections=1, max_workers=1, timeout=1.0
        ) as server:
            try:
                with pytest.raises(SpiffeError):
                    await asyncio.to_thread(fetch, server.address, "parked")
                assert entered.wait(10), "the policy callback never reached the pool"
                for attempt in range(3):
                    with pytest.raises(SpiffeError):
                        await asyncio.to_thread(fetch, server.address, f"attempt-{attempt}")
                return server._workers._work_queue.qsize()
            finally:
                gate.set()

    # The first exchange's callback holds the one thread; the reconnects time
    # out waiting to be submitted, so nothing accumulates behind it.
    assert asyncio.run(main()) == 0


def test_parked_policy_thread_releases_its_submission_slot(pki):
    """The slot must be freed when the callback runs, not when its caller gives up.

    Releasing on cancellation instead would hand the slot back while the work
    item still occupied a thread, letting submissions outrun the bound; holding
    it past completion would wedge the issuer for every later exchange.
    """
    issuer, fetch, gate, entered = _parked_policy_server(pki)

    async def main():
        async with SpiffeIssuerServer(
            issuer, host="127.0.0.1", port=0, max_connections=1, max_workers=1, timeout=1.0
        ) as server:
            with pytest.raises(SpiffeError):
                await asyncio.to_thread(fetch, server.address, "abandoned")
            assert entered.wait(10), "the policy callback never reached the pool"
            gate.set()
            return await asyncio.to_thread(fetch, server.address)

    assert asyncio.run(main()).id


def test_grant_is_snapshotted_at_challenge(exchange):
    issuer, connection, holder, root, *_ = exchange
    cached = {"refund": {"customer": Exact("123"), "cents": Range(1, 5000)}}
    issuer._policy = lambda *_: SpiffeGrant(cached)
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    cached["refund"].clear()
    cached["delete"] = {"customer": Exact("123")}
    warrant = issuer.issue(connection, challenge, sign(challenge, holder))
    authorizer = Authorizer(trusted_roots=[root.public_key])
    for tool, args in (("refund", {"customer": "999", "cents": 1}), ("delete", {"customer": "123"})):
        with pytest.raises(AuthorizationError):
            authorizer.authorize(warrant, tool, args, warrant.sign(holder, tool, args, int(time.time())))


def test_malformed_signature_consumes_challenge(exchange):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError, match="Invalid holder proof"):
        issuer.issue(connection, challenge, b"short")
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, sign(challenge, holder))


def test_deeply_nested_json_is_refused_quietly(exchange):
    from tenuo.spiffe import _parse_frame

    _, _, holder, *_ = exchange
    with pytest.raises(SpiffeError, match="Invalid frame"):
        _parse_frame(b"[" * 60000 + b"\n", frozenset({"signature"}))
    with pytest.raises(SpiffeError, match="Invalid holder challenge"):
        sign_holder_challenge(b"[" * 4000, holder, task_id="task-123")


def test_demo_over_localhost(tmp_path):
    path = Path(__file__).parents[2] / "examples/spiffe/demo.py"
    spec = importlib.util.spec_from_file_location("spiffe_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.development_credentials(tmp_path)
    assert module.run(tmp_path) == ["ALLOWED", "DENIED", "DENIED", "ALLOWED"]


# -- SPIRE Workload API source -------------------------------------------------------


def _varint(value):
    out = bytearray()
    while True:
        out.append((value & 0x7F) | (0x80 if value > 0x7F else 0))
        value >>= 7
        if not value:
            return bytes(out)


def _field(number, data):
    return _varint(number << 3 | 2) + _varint(len(data)) + data


def _der(pem):
    return b"".join(c.public_bytes(serialization.Encoding.DER) for c in x509.load_pem_x509_certificates(pem))


def svid_entry(authority, identity, *, bundle=None, key_from=None, label=None, **options):
    """One X509SVID message, as a SPIRE agent would send it."""
    cert, key = authority.leaf(identity, **options)
    if key_from is not None:
        _, key = key_from.leaf(identity)
    key_der = serialization.load_pem_private_key(key, None).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return (
        _field(1, (label or identity).encode())
        + _field(2, _der(cert))
        + _field(3, key_der)
        + _field(4, _der(bundle if bundle is not None else authority.pem))
    )


def x509_response(*entries, federated=()):
    message = b"".join(_field(1, entry) for entry in entries)
    for domain, pem in federated:
        message += _field(3, _field(1, domain.encode()) + _field(2, _der(pem)))
    return message


class FakeWorkloadAPI:
    """A stand-in for the SPIRE agent's Workload API endpoint."""

    def __init__(self, grpc, bind="127.0.0.1:0"):
        import queue

        self._grpc, self._queue = grpc, queue
        self._lock = threading.Lock()
        self._streams = []
        self._current = None
        self.refuse = None  # A grpc.StatusCode to answer with instead of streaming.
        self.calls = 0
        self.saw_header = []
        self._jwt_streams = []
        self._jwt_current = None
        self.jwt_svid_response = None  # Bytes, or a function of the raw request.
        self.jwt_svid_requests = []
        api = self

        class Handler(grpc.GenericRpcHandler):
            def service(self, details):
                raw = dict(request_deserializer=lambda data: data, response_serializer=lambda data: data)
                if api.refuse == "unimplemented":
                    return None
                if details.method == "/SpiffeWorkloadAPI/FetchX509SVID":
                    return grpc.unary_stream_rpc_method_handler(api._fetch, **raw)
                if details.method == "/SpiffeWorkloadAPI/FetchJWTBundles":
                    return grpc.unary_stream_rpc_method_handler(api._fetch_jwt_bundles, **raw)
                if details.method == "/SpiffeWorkloadAPI/FetchJWTSVID":
                    return grpc.unary_unary_rpc_method_handler(api._fetch_jwt_svid, **raw)
                return None

        self._server = grpc.server(ThreadPoolExecutor(max_workers=8))
        self._server.add_generic_rpc_handlers((Handler(),))
        port = self._server.add_insecure_port(bind)
        self.address = bind if bind.startswith("unix:") else f"tcp://127.0.0.1:{port}"
        self._server.start()

    def _fetch(self, request, context):
        self.calls += 1
        self.saw_header.append(dict(context.invocation_metadata()).get("workload.spiffe.io"))
        if self.refuse is not None:
            context.abort(self.refuse, "no identity issued")
        stream = self._queue.Queue()
        with self._lock:
            self._streams.append(stream)
            if self._current is not None:
                stream.put(self._current)
        while True:
            message = stream.get()
            if message is None or not context.is_active():
                return
            yield message

    def _fetch_jwt_bundles(self, request, context):
        self.calls += 1
        if self.refuse is not None:
            context.abort(self.refuse, "no identity issued")
        stream = self._queue.Queue()
        with self._lock:
            self._jwt_streams.append(stream)
            if self._jwt_current is not None:
                stream.put(self._jwt_current)
        while True:
            message = stream.get()
            if message is None or not context.is_active():
                return
            yield message

    def _fetch_jwt_svid(self, request, context):
        self.jwt_svid_requests.append(request)
        self.saw_header.append(dict(context.invocation_metadata()).get("workload.spiffe.io"))
        if self.refuse is not None:
            context.abort(self.refuse, "no identity issued")
        response = self.jwt_svid_response
        return response(request) if callable(response) else (response or b"")

    def publish(self, message):
        with self._lock:
            self._current = message
            for stream in self._streams:
                stream.put(message)

    def publish_jwt_bundles(self, message):
        with self._lock:
            self._jwt_current = message
            for stream in self._jwt_streams:
                stream.put(message)

    def drop_streams(self):
        with self._lock:
            streams, self._streams = self._streams + self._jwt_streams, []
            self._jwt_streams = []
        for stream in streams:
            stream.put(None)

    def stop(self):
        self.drop_streams()
        self._server.stop(0)


@pytest.fixture
def workload_api(monkeypatch):
    grpc = pytest.importorskip("grpc")
    monkeypatch.setattr("tenuo.spiffe._WORKLOAD_API_BACKOFF", (0.05, 0.2))
    started = []

    def start(bind="127.0.0.1:0"):
        api = FakeWorkloadAPI(grpc, bind)
        started.append(api)
        return api

    yield start
    for api in started:
        api.stop()


@pytest.fixture
def from_api():
    opened = []

    def build(api, *, server=True, **options):
        options.setdefault("timeout", 5)
        tls = SpiffeTLS.from_workload_api(trust_domain=DOMAIN, server_side=server, socket_path=api.address, **options)
        opened.append(tls)
        return tls

    yield build
    for tls in opened:
        tls.close()


def eventually(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_workload_api_supplies_and_renews_credentials(ca, pki, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api)
    assert server.identity.spiffe_id == SERVER and api.saw_header == ["true"]
    listener = server.context
    old_connection, old_peer = connect(server, pki())
    assert server.authenticate(old_connection).spiffe_id == AGENT
    first = server.identity.certificate_sha256
    assert _served(old_peer) == first

    api.publish(x509_response(svid_entry(ca, SERVER)))
    assert eventually(lambda: server.identity.certificate_sha256 != first)
    assert server.context is listener
    _, peer = connect(server, pki())
    assert _served(peer) == server.identity.certificate_sha256
    assert server.authenticate(old_connection).spiffe_id == AGENT
    assert server.reload_if_changed() is False
    server.reload()  # A no-op for this source.


def test_workload_api_end_to_end_issuance(ca, workload_api, from_api):
    issuer_api, agent_api = workload_api(), workload_api()
    issuer_api.publish(x509_response(svid_entry(ca, SERVER)))
    agent_api.publish(x509_response(svid_entry(ca, AGENT)))
    server_tls, client_tls = from_api(issuer_api), from_api(agent_api, server=False)
    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=root, policy=lambda *_: SpiffeGrant(REFUND))
    options = dict(issuer_id=SERVER, issuer_key=root.public_key, holder_key=holder, task_id="task-123")

    async def body(address):
        first = await asyncio.to_thread(request_warrant, client_tls, address, **options)
        before = (server_tls.identity.certificate_sha256, client_tls.identity.certificate_sha256)
        issuer_api.publish(x509_response(svid_entry(ca, SERVER)))
        agent_api.publish(x509_response(svid_entry(ca, AGENT)))
        assert await asyncio.to_thread(
            eventually,
            lambda: (
                server_tls.identity.certificate_sha256 != before[0]
                and client_tls.identity.certificate_sha256 != before[1]
            ),
        )
        second = await asyncio.to_thread(request_warrant, client_tls, address, **options)
        return first, second

    first, second = run_server(issuer, body)
    assert first.id != second.id


def test_workload_api_selects_svid_by_spiffe_id(ca, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, AGENT), svid_entry(ca, SERVER)))
    assert from_api(api).identity.spiffe_id == AGENT  # The first SVID is the default.
    assert from_api(api, spiffe_id=SERVER).identity.spiffe_id == SERVER
    with pytest.raises(SpiffeError, match=f"did not offer spiffe://{DOMAIN}/absent"):
        from_api(api, spiffe_id=f"spiffe://{DOMAIN}/absent", timeout=0.5)
    with pytest.raises(ValueError):
        from_api(api, spiffe_id="spiffe://other.test/issuer")


def test_workload_api_ignores_unusable_updates(ca, pki, workload_api, from_api, tmp_path):
    other = CA(tmp_path, "other root")
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api)
    before = server.identity
    for bad in (
        b"\xff\xff\xff not protobuf",
        x509_response(),
        x509_response(svid_entry(ca, "spiffe://other.test/issuer")),
        x509_response(svid_entry(ca, SERVER, expires=-5)),
        x509_response(svid_entry(ca, SERVER, key_from=other)),
        x509_response(_field(1, b"spiffe://example.test/issuer") + _field(2, b"\x30\x82\xff\xff")),
    ):
        calls = api.calls
        api.publish(bad)
        time.sleep(0.15)
        assert server.identity == before
        assert api.calls == calls  # Still on the same stream: a bad update does not disconnect.
    connection, _ = connect(server, pki())
    assert server.authenticate(connection).spiffe_id == AGENT
    api.publish(x509_response(svid_entry(ca, SERVER)))
    assert eventually(lambda: server.identity != before)


def test_workload_api_reconnects_after_stream_loss(ca, pki, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api)
    before = server.identity
    api.drop_streams()
    assert eventually(lambda: api.calls >= 2)
    connect(server, pki())  # Current credentials keep working while disconnected.
    api.publish(x509_response(svid_entry(ca, SERVER)))
    assert eventually(lambda: server.identity != before)


def test_workload_api_waits_for_identity(ca, workload_api, from_api):
    grpc = pytest.importorskip("grpc")
    api = workload_api()
    api.refuse = grpc.StatusCode.PERMISSION_DENIED

    def provision():
        time.sleep(0.3)
        api.refuse = None
        api.publish(x509_response(svid_entry(ca, SERVER)))

    worker = threading.Thread(target=provision)
    worker.start()
    try:
        assert from_api(api).identity.spiffe_id == SERVER
    finally:
        worker.join()
    assert api.calls >= 2

    never = workload_api()
    never.refuse = grpc.StatusCode.PERMISSION_DENIED
    with pytest.raises(SpiffeError, match="PERMISSION_DENIED: no identity issued"):
        from_api(never, timeout=0.4)


def test_workload_api_stops_on_unsupported_endpoint(workload_api, from_api):
    api = workload_api()
    api.refuse = "unimplemented"
    start = time.monotonic()
    with pytest.raises(SpiffeError, match="UNIMPLEMENTED"):
        from_api(api, timeout=10)
    assert time.monotonic() - start < 5  # Reported at once, not after the timeout.


def test_workload_api_authority_removal_and_federated_bundles(ca, pki, workload_api, from_api, tmp_path):
    successor, foreign = CA(tmp_path, "successor root"), CA(tmp_path, "foreign root")
    api = workload_api()
    api.publish(
        x509_response(
            svid_entry(ca, SERVER, bundle=ca.pem + successor.pem), federated=[("spiffe://foreign.test", foreign.pem)]
        )
    )
    server = from_api(api)
    old_connection, _ = connect(server, pki())
    # Authorities of other trust domains in the response are not trusted.
    foreign_agent = foreign.files("foreign-agent", AGENT, bundle=ca.pem + successor.pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.load_verify_locations(cafile=str(foreign_agent["bundle"]))
    context.load_cert_chain(str(foreign_agent["cert"]), str(foreign_agent["key"]))
    with pytest.raises(ssl.SSLError):
        connect(server, SimpleNamespace(context=context))

    before = server.identity
    api.publish(x509_response(svid_entry(successor, SERVER)))  # The original authority is gone.
    assert eventually(lambda: server.identity != before)
    with pytest.raises(SpiffeError, match="not verified by this SPIFFE TLS context"):
        server.authenticate(old_connection)
    with pytest.raises(ssl.SSLError):
        connect(server, pki(peer_only=True))


def test_workload_api_close_stops_following(ca, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api)
    before = server.identity
    watcher = server._watcher
    server.close()
    assert not watcher._thread.is_alive()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    time.sleep(0.2)
    assert server.identity == before
    server.close()  # Idempotent.


@pytest.mark.skipif(os.name == "nt", reason="Unix domain sockets")
def test_workload_api_over_unix_socket_and_environment(ca, workload_api, monkeypatch):
    import shutil
    import tempfile

    directory = tempfile.mkdtemp(prefix="wl", dir="/tmp")  # Socket paths must be short.
    try:
        path = os.path.join(directory, "agent.sock")
        api = workload_api(f"unix:{path}")
        api.publish(x509_response(svid_entry(ca, SERVER)))
        for address in (path, f"unix://{path}"):
            tls = SpiffeTLS.from_workload_api(trust_domain=DOMAIN, server_side=True, socket_path=address, timeout=5)
            tls.close()
        monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", f"unix://{path}")
        tls = SpiffeTLS.from_workload_api(trust_domain=DOMAIN, server_side=True, timeout=5)
        assert tls.identity.spiffe_id == SERVER
        tls.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_workload_api_address_forms(monkeypatch):
    from tenuo.spiffe import _workload_api_target

    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
    assert _workload_api_target("/run/spire/agent.sock") == "unix:///run/spire/agent.sock"
    assert _workload_api_target("unix:///run/spire/agent.sock") == "unix:///run/spire/agent.sock"
    assert _workload_api_target("tcp://127.0.0.1:8081") == "127.0.0.1:8081"
    assert _workload_api_target("tcp://[::1]:8081") == "[::1]:8081"
    for bad in (
        None,
        "",
        "agent.sock",
        "unix://relative.sock",
        "tcp://localhost:8081",
        "tcp://10.0.0.5:8081",
        "tcp://169.254.1.1:8081",
        "tcp://0.0.0.0:8081",
        "tcp://[fd00::1]:8081",
        "tcp://127.0.0.1",
        "http://x",
        "/tmp/a%41.sock",
        "/tmp/a?b.sock",
        "unix:///tmp/a#b.sock",
        "tcp://::1:8081",
        "tcp://[127.0.0.1]:80",
        "tcp://127.0.0.1: 80",
        "tcp://127.0.0.1:8_0",
        "tcp://127.0.0.1:0",
        "tcp://127.0.0.1:99999",
    ):
        with pytest.raises(ValueError):
            _workload_api_target(bad)


def test_workload_api_ignores_http_proxy_settings(ca, workload_api, from_api, monkeypatch):
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "grpc_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    for name in ("no_proxy", "NO_PROXY", "no_grpc_proxy"):
        monkeypatch.delenv(name, raising=False)
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    assert from_api(api).identity.spiffe_id == SERVER and api.calls == 1


def test_workload_api_uses_update_once_it_becomes_valid(ca, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER, starts=2)))  # Valid two seconds from now.
    server = from_api(api, timeout=8)
    assert server.identity.spiffe_id == SERVER and api.calls == 1  # No new push was needed.

    before = server.identity
    api.publish(x509_response(svid_entry(ca, SERVER, starts=2)))
    time.sleep(0.3)
    assert server.identity == before and server.reload_if_changed() is False
    assert eventually(lambda: server.reload_if_changed() or server.identity != before, seconds=6)
    assert server.identity != before and server.reload_if_changed() is False


def test_workload_api_installs_a_waiting_renewal_by_itself(ca, workload_api, from_api):
    """Nothing has to call reload for a renewal that was not valid yet to take effect."""
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api)
    before = server.identity
    api.publish(x509_response(svid_entry(ca, SERVER, starts=2)))  # Valid two seconds from now.
    time.sleep(0.3)
    assert server.identity == before
    assert eventually(lambda: server.identity != before, seconds=10)
    assert server._watcher._pending is None
    # A watcher that is stopped does not keep retrying.
    api.publish(x509_response(svid_entry(ca, SERVER, starts=2)))
    assert eventually(lambda: server._watcher._pending is not None)
    current = server.identity
    server.close()
    time.sleep(2.6)
    assert server.identity == current


def test_workload_api_newer_response_supersedes_a_waiting_update(ca, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api, spiffe_id=SERVER)
    before = server.identity
    for newer in (x509_response(), x509_response(svid_entry(ca, AGENT)), b"\xff\xff not protobuf"):
        api.publish(x509_response(svid_entry(ca, SERVER, starts=2)))  # Valid two seconds from now.
        assert eventually(lambda: server._watcher._pending is not None)
        api.publish(newer)  # SPIRE no longer offers that SVID.
        assert eventually(lambda: server._watcher._pending is None)
    time.sleep(2.3)
    assert server.reload_if_changed() is False and server.identity == before


def test_workload_api_startup_retries_stay_frequent():
    from tenuo.spiffe import _next_delay

    delay, waited = 1.0, []
    for _ in range(12):
        waited.append(delay)
        delay = _next_delay(delay, usable=False)
    assert max(waited) <= 2.0 and sum(waited) < 30
    delay = 1.0
    for _ in range(12):
        delay = _next_delay(delay, usable=True)
    assert delay == 30.0


def test_workload_api_keeps_following_after_unsupported_reply(ca, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    server = from_api(api)
    before = server.identity
    api.refuse = "unimplemented"
    api.drop_streams()
    time.sleep(0.4)
    assert server._watcher._thread.is_alive() and server.identity == before
    api.refuse = None
    api.publish(x509_response(svid_entry(ca, SERVER)))
    assert eventually(lambda: server.identity != before)


def test_workload_api_checks_the_certificate_not_the_label(ca, workload_api, from_api):
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, AGENT, label=SERVER)))
    with pytest.raises(SpiffeError, match="different SPIFFE ID"):
        from_api(api, spiffe_id=SERVER, timeout=0.6)


def test_workload_api_error_lists_a_bounded_number_of_offers(ca, workload_api, from_api):
    api = workload_api()
    entries = [_field(1, f"spiffe://{DOMAIN}/w{i}\n".encode() * 100) for i in range(12)]
    api.publish(x509_response(*entries))
    with pytest.raises(SpiffeError) as refused:
        from_api(api, spiffe_id=f"spiffe://{DOMAIN}/absent", timeout=0.4)
    message = str(refused.value)
    assert "and 4 more" in message and len(message) < 3000 and "\n" not in message


def test_workload_api_thread_stops_when_instance_is_dropped(ca, workload_api):
    import gc

    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER)))
    tls = SpiffeTLS.from_workload_api(trust_domain=DOMAIN, server_side=True, socket_path=api.address, timeout=5)
    thread = tls._watcher._thread
    assert thread.is_alive()
    del tls
    gc.collect()
    assert eventually(lambda: not thread.is_alive())


@pytest.mark.skipif(not hasattr(os, "memfd_create") or not os.path.isdir("/proc/self/fd"), reason="needs Linux memfd")
def test_private_key_is_loaded_without_touching_disk(pki, monkeypatch):
    def no_disk(*_, **__):
        raise AssertionError("credentials were written to a temporary directory")

    monkeypatch.setattr("tenuo.spiffe.tempfile.TemporaryDirectory", no_disk)
    server = pki(server=True)
    connection, _ = connect(server, pki())
    assert server.authenticate(connection).spiffe_id == AGENT


@pytest.mark.parametrize(
    "message",
    [b"\x0a", b"\x0a\x05ab", b"\xff" * 12, b"\x0b", b"\x0a\x02\x12\x7f"],
    ids=["truncated-length", "short-body", "endless-varint", "unknown-wire-type", "nested-truncated"],
)
def test_workload_api_message_decoder_rejects_malformed_input(message):
    from tenuo.spiffe import _x509_snapshot

    with pytest.raises(SpiffeError):
        _x509_snapshot(message, None)


# -- federation ----------------------------------------------------------------------

PARTNER = "partner.test"
PARTNER_AGENT = f"spiffe://{PARTNER}/agent"


def sub_ca(parent, directory, name="intermediate"):
    """An intermediate CA signed by ``parent``, able to issue leaves."""
    child = CA.__new__(CA)
    child.directory = directory
    child.key = ec.generate_private_key(ec.SECP256R1())
    child.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    child.cert = (
        x509.CertificateBuilder()
        .subject_name(child.name)
        .issuer_name(parent.name)
        .public_key(child.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(True, 0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(child.key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(parent.key.public_key()), False)
        .sign(parent.key, hashes.SHA256())
    )
    child.pem = child.cert.public_bytes(serialization.Encoding.PEM)
    return child


def tls_in(domain, paths, server, federated=None):
    return SpiffeTLS(
        trust_domain=domain,
        bundle_file=str(paths["bundle"]),
        cert_file=str(paths["cert"]),
        key_file=str(paths["key"]),
        server_side=server,
        federated_bundle_files={name: str(path) for name, path in (federated or {}).items()},
    )


def raw_client(paths, trusted_pem):
    """A plain TLS client presenting whatever certificate ``paths`` holds."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.load_verify_locations(cadata=trusted_pem.decode())
    context.load_cert_chain(str(paths["cert"]), str(paths["key"]))
    return SimpleNamespace(context=context)


@pytest.fixture
def federation(ca, tmp_path):
    """An issuer in example.test that also accepts workloads from partner.test."""
    partner = CA(tmp_path, "partner root")
    bundles = {DOMAIN: tmp_path / "own-bundle.pem", PARTNER: tmp_path / "partner-bundle.pem"}
    bundles[DOMAIN].write_bytes(ca.pem)
    bundles[PARTNER].write_bytes(partner.pem)
    server = tls_in(DOMAIN, ca.files("fed-server", SERVER), True, {PARTNER: bundles[PARTNER]})
    return server, partner, bundles


def test_federated_peers_authenticate_each_other(ca, federation, pki):
    server, partner, bundles = federation
    agent = tls_in(PARTNER, partner.files("fed-agent", PARTNER_AGENT), False, {DOMAIN: bundles[DOMAIN]})
    connection, peer = connect(server, agent)
    identity = server.authenticate(connection)
    assert (identity.spiffe_id, identity.trust_domain) == (PARTNER_AGENT, PARTNER)
    assert agent.authenticate(peer, expected_id=SERVER).trust_domain == DOMAIN
    # Workloads of the issuer's own trust domain are accepted as before.
    own, _ = connect(server, pki())
    assert server.authenticate(own).spiffe_id == AGENT
    # A domain that is not listed stays untrusted, whoever signed the SVID.
    stranger = partner.files("fed-stranger", "spiffe://other.test/agent")
    unlisted, _ = connect(server, raw_client(stranger, ca.pem))
    with pytest.raises(SpiffeError, match="different trust domain"):
        server.authenticate(unlisted)


def test_one_trust_domain_cannot_issue_identities_for_another(ca, federation, monkeypatch):
    server, partner, bundles = federation
    # The partner's authority signs an SVID that names the issuer's own trust domain, and the reverse.
    forged_own = partner.files("forged-own", AGENT)
    forged_partner = ca.files("forged-partner", PARTNER_AGENT)
    for forged in (forged_own, forged_partner):
        connection, _ = connect(server, raw_client(forged, ca.pem))  # The TLS handshake alone succeeds.
        with pytest.raises(SpiffeError, match="not issued (directly )?by its own trust domain's authorities"):
            server.authenticate(connection)
    # The same holds where Python does not expose the verified chain.
    monkeypatch.setattr("tenuo.spiffe._verified_chain", lambda connection: None)
    for forged in (forged_own, forged_partner):
        connection, _ = connect(server, raw_client(forged, ca.pem))
        with pytest.raises(SpiffeError, match="not issued directly by its own trust domain's authorities"):
            server.authenticate(connection)
    genuine, _ = connect(server, raw_client(partner.files("genuine", PARTNER_AGENT), ca.pem))
    assert server.authenticate(genuine).spiffe_id == PARTNER_AGENT


def test_client_checks_the_issuers_domain_binding(ca, federation):
    _, partner, bundles = federation
    # A partner-domain authority runs a server that claims to be the issuer in example.test.
    impostor = SimpleNamespace(context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    forged = partner.files("forged-issuer", SERVER)
    impostor.context.verify_mode = ssl.CERT_REQUIRED
    impostor.context.load_verify_locations(cadata=partner.pem.decode())
    impostor.context.load_cert_chain(str(forged["cert"]), str(forged["key"]))
    agent = tls_in(PARTNER, partner.files("fed-agent-2", PARTNER_AGENT), False, {DOMAIN: bundles[DOMAIN]})
    _, peer = connect(impostor, agent)
    with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
        agent.authenticate(peer, expected_id=SERVER)


def test_federated_svid_through_an_intermediate_authority(ca, federation, tmp_path):
    from tenuo.spiffe import _verified_chain

    server, partner, bundles = federation
    intermediate = sub_ca(partner, tmp_path)
    paths = intermediate.files("via-intermediate", PARTNER_AGENT)
    paths["cert"].write_bytes(paths["cert"].read_bytes() + intermediate.pem)  # Leaf, then its issuer.
    connection, _ = connect(server, raw_client(paths, ca.pem))
    if _verified_chain(connection) is None:  # Python 3.9
        with pytest.raises(SpiffeError, match="Python 3.10 or newer"):
            server.authenticate(connection)
    else:
        assert server.authenticate(connection).spiffe_id == PARTNER_AGENT
    # An intermediate under the partner's root still cannot vouch for the issuer's domain.
    forged = intermediate.files("forged-via-intermediate", AGENT)
    forged["cert"].write_bytes(forged["cert"].read_bytes() + intermediate.pem)
    connection, _ = connect(server, raw_client(forged, ca.pem))
    with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
        server.authenticate(connection)


def test_federated_bundle_rotation_and_withdrawal(ca, federation, tmp_path):
    server, partner, bundles = federation
    old_connection, _ = connect(server, raw_client(partner.files("before", PARTNER_AGENT), ca.pem))
    assert server.authenticate(old_connection).spiffe_id == PARTNER_AGENT
    successor = CA(tmp_path, "partner successor root")
    time.sleep(0.01)
    bundles[PARTNER].write_bytes(successor.pem)  # The partner replaced its authority.
    assert server.reload_if_changed() is True
    with pytest.raises(SpiffeError):
        server.authenticate(old_connection)
    with pytest.raises(ssl.SSLError):
        connect(server, raw_client(partner.files("retired", PARTNER_AGENT), ca.pem))
    connection, _ = connect(server, raw_client(successor.files("after", PARTNER_AGENT), ca.pem))
    assert server.authenticate(connection).spiffe_id == PARTNER_AGENT


def test_federation_configuration_is_validated(ca, tmp_path):
    partner = CA(tmp_path, "partner root")
    partner_bundle = tmp_path / "partner.pem"
    partner_bundle.write_bytes(partner.pem)
    paths = ca.files("fed-config", SERVER)
    for bad in ({DOMAIN: partner_bundle}, {"Partner.Test": partner_bundle}, {"": partner_bundle}):
        with pytest.raises(ValueError):
            tls_in(DOMAIN, paths, True, bad)


def partner_refused_home_served(server, ca, partner, pki):
    """The partner's workloads are refused, and the home domain is unaffected."""
    try:
        connection, _ = connect(
            server, raw_client(partner.files(f"refused-{time.monotonic_ns()}", PARTNER_AGENT), ca.pem)
        )
    except ssl.SSLError:
        refused = True  # Its authority is not in the trust store at all.
    else:
        with pytest.raises(SpiffeError):
            server.authenticate(connection)
        refused = True
    own, _ = connect(server, pki())
    return refused and server.authenticate(own).spiffe_id == AGENT


def lookalike(original, name="lookalike"):
    """A self-signed certificate copying another authority's subject and key identifier, under its own key."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    identifier = original.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(True, None), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(identifier, False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def test_unusable_federated_bundles_only_cost_that_domain(ca, federation, pki, caplog):
    server, partner, bundles = federation
    tagged, _ = partner.leaf(f"spiffe://{DOMAIN}", is_ca=True)  # An authority naming another trust domain.
    leaf, _ = partner.leaf(PARTNER_AGENT)
    for bad in (partner.pem + tagged, leaf, b"\xff\xfe garbage", b"", ca.pem, partner.pem + ca.pem):
        time.sleep(0.01)
        bundles[PARTNER].write_bytes(bad)
        with caplog.at_level("WARNING", logger="tenuo.spiffe"):
            server.reload()
        assert partner_refused_home_served(server, ca, partner, pki)
        assert PARTNER in caplog.text
        caplog.clear()
    bundles[PARTNER].unlink()  # A missing file withdraws the domain too.
    assert server.reload_if_changed() is True
    assert partner_refused_home_served(server, ca, partner, pki)
    bundles[PARTNER].write_bytes(partner.pem)
    assert server.reload_if_changed() is True
    connection, _ = connect(server, raw_client(partner.files("restored", PARTNER_AGENT), ca.pem))
    assert server.authenticate(connection).spiffe_id == PARTNER_AGENT


def test_broken_federated_bundle_does_not_hold_back_home_rotation(ca, tmp_path, pki):
    partner = CA(tmp_path, "partner root")
    partner_bundle = tmp_path / "partner.pem"
    partner_bundle.write_bytes(partner.pem)
    paths = ca.files("fed-rotating", SERVER)
    server = tls_in(DOMAIN, paths, True, {PARTNER: partner_bundle})
    before = server.identity
    time.sleep(0.01)
    partner_bundle.write_bytes(b"half-written")
    _rewrite(ca, paths, SERVER)
    assert server.reload_if_changed() is True
    assert server.identity != before  # The home SVID rotated regardless.
    assert partner_refused_home_served(server, ca, partner, pki)


def test_shared_root_topologies_keep_domains_apart(ca, tmp_path, pki):
    """One domain's authority chains to a root in the other's bundle: the nearest authority decides."""
    # The partner's authority is an intermediate issued by the home root.
    partner_ca = sub_ca(ca, tmp_path, "partner intermediate")
    bundle = tmp_path / "partner-intermediate.pem"
    bundle.write_bytes(partner_ca.pem)
    server = tls_in(DOMAIN, ca.files("shared-server", SERVER), True, {PARTNER: bundle})

    def present(issuer, identity, name):
        paths = issuer.files(name, identity)
        if issuer is not ca:
            paths["cert"].write_bytes(paths["cert"].read_bytes() + issuer.pem)
        return connect(server, raw_client(paths, ca.pem))[0]

    assert server.authenticate(present(partner_ca, PARTNER_AGENT, "shared-genuine")).spiffe_id == PARTNER_AGENT
    assert server.authenticate(present(ca, AGENT, "shared-home")).spiffe_id == AGENT
    with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
        server.authenticate(present(partner_ca, AGENT, "shared-forged-home"))
    with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
        server.authenticate(present(ca, PARTNER_AGENT, "shared-forged-partner"))

    # The mirror image: the home authority is an intermediate under the partner's root.
    partner_root = CA(tmp_path, "partner root")
    home_ca = sub_ca(partner_root, tmp_path, "home intermediate")
    home_bundle, partner_bundle = tmp_path / "home-intermediate.pem", tmp_path / "partner-root.pem"
    home_bundle.write_bytes(home_ca.pem)
    partner_bundle.write_bytes(partner_root.pem)
    mirror_paths = home_ca.files("mirror-server", SERVER, bundle=home_ca.pem)
    mirror = tls_in(DOMAIN, mirror_paths, True, {PARTNER: partner_bundle})
    trusted = home_ca.pem + partner_root.pem

    def show(issuer, identity, name):
        return connect(mirror, raw_client(issuer.files(name, identity), trusted))[0]

    assert mirror.authenticate(show(home_ca, AGENT, "mirror-home")).spiffe_id == AGENT
    assert mirror.authenticate(show(partner_root, PARTNER_AGENT, "mirror-partner")).spiffe_id == PARTNER_AGENT
    for issuer, identity, name in (
        (partner_root, AGENT, "mirror-forged-home"),
        (home_ca, PARTNER_AGENT, "mirror-forged-partner"),
    ):
        with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
            mirror.authenticate(show(issuer, identity, name))


def test_overlapping_or_lookalike_authorities_drop_the_federated_domain(ca, tmp_path, pki, caplog):
    partner = CA(tmp_path, "partner root")
    bundle = tmp_path / "partner.pem"
    paths = ca.files("overlap-server", SERVER)
    without_identifier = x509.load_pem_x509_certificate(lookalike(ca.cert))
    for name, content in (
        ("the home authority itself", partner.pem + ca.pem),
        (
            "copies of the home root's subject and key identifier",
            partner.pem + b"".join(lookalike(ca.cert) for _ in range(8)),
        ),
    ):
        bundle.write_bytes(content)
        with caplog.at_level("WARNING", logger="tenuo.spiffe"):
            server = tls_in(DOMAIN, paths, True, {PARTNER: bundle})
        assert "shares an authority with another domain" in caplog.text, name
        caplog.clear()
        # The partner is not trusted, and genuine home workloads still complete every handshake.
        for _ in range(12):
            assert partner_refused_home_served(server, ca, partner, pki), name
    assert without_identifier.subject == ca.cert.subject

    # Two federated domains that overlap with each other are both dropped; the home domain is not.
    second = tmp_path / "second.pem"
    bundle.write_bytes(partner.pem)
    second.write_bytes(partner.pem)
    server = tls_in(DOMAIN, paths, True, {PARTNER: bundle, "second.test": second})
    assert partner_refused_home_served(server, ca, partner, pki)


def test_workload_api_broken_federated_bundle_does_not_hold_back_home(ca, workload_api, from_api, tmp_path, pki):
    partner = CA(tmp_path, "partner root")
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER), federated=[(f"spiffe://{PARTNER}", partner.pem)]))
    server = from_api(api, federates_with=[PARTNER])
    connection, _ = connect(server, raw_client(partner.files("wl-before", PARTNER_AGENT), ca.pem))
    assert server.authenticate(connection).spiffe_id == PARTNER_AGENT
    before = server.identity
    # The partner's bundle is garbage in the same response that renews the home SVID.
    broken = _field(1, svid_entry(ca, SERVER)) + _field(
        3, _field(1, f"spiffe://{PARTNER}".encode()) + _field(2, b"\x30\x82\xff\xff")
    )
    api.publish(broken)
    assert eventually(lambda: server.identity != before)
    assert partner_refused_home_served(server, ca, partner, pki)


def test_workload_api_federated_bundles(ca, workload_api, from_api, tmp_path):
    partner, foreign = CA(tmp_path, "partner root"), CA(tmp_path, "foreign root")
    offered = [(f"spiffe://{PARTNER}", partner.pem), ("spiffe://foreign.test", foreign.pem)]
    api = workload_api()
    api.publish(x509_response(svid_entry(ca, SERVER), federated=offered))
    server = from_api(api, federates_with=[PARTNER])
    connection, _ = connect(server, raw_client(partner.files("wl-partner", PARTNER_AGENT), ca.pem))
    assert server.authenticate(connection).trust_domain == PARTNER
    # A federated bundle that was not asked for is ignored, and forgery is refused.
    with pytest.raises(ssl.SSLError):
        connect(server, raw_client(foreign.files("wl-foreign", "spiffe://foreign.test/agent"), ca.pem))
    forged, _ = connect(server, raw_client(partner.files("wl-forged", AGENT), ca.pem))
    with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
        server.authenticate(forged)
    # SPIRE stops offering the partner's bundle: its workloads are refused.
    before = server.identity
    api.publish(x509_response(svid_entry(ca, SERVER)))
    assert eventually(lambda: server.identity != before)
    with pytest.raises(SpiffeError):
        server.authenticate(connection)
    with pytest.raises(ssl.SSLError):
        connect(server, raw_client(partner.files("wl-partner-2", PARTNER_AGENT), ca.pem))
    with pytest.raises(ValueError, match="list of names"):
        from_api(api, federates_with=PARTNER)


def test_issuance_across_trust_domains(ca, federation):
    server, partner, bundles = federation
    agent = tls_in(PARTNER, partner.files("fed-issuance", PARTNER_AGENT), False, {DOMAIN: bundles[DOMAIN]})
    root, holder = SigningKey.generate(), SigningKey.generate()
    seen = []

    def policy(identity, task_id):
        seen.append((identity.trust_domain, identity.spiffe_id))
        if identity.trust_domain == PARTNER and identity.spiffe_id == PARTNER_AGENT:
            return SpiffeGrant({"refund": {"customer": Exact("123"), "cents": Range(1, 500)}})
        return None

    issuer = SpiffeWarrantIssuer(tls=server, signing_key=root, policy=policy)

    async def body(address):
        return await asyncio.to_thread(
            request_warrant,
            agent,
            address,
            issuer_id=SERVER,
            issuer_key=root.public_key,
            holder_key=holder,
            task_id="task-123",
        )

    warrant = run_server(issuer, body)
    assert seen == [(PARTNER, PARTNER_AGENT)] and warrant.authorized_holder == holder.public_key


# -- the guide's code ---------------------------------------------------------------

GUIDE = Path(__file__).parents[3] / "docs" / "spiffe.md"


def _guide_blocks():
    if not GUIDE.exists():
        pytest.skip("guide not present in this distribution")
    blocks = dict(re.findall(r"```python\n# (\S+\.py)[^\n]*\n(.*?)```", GUIDE.read_text(), re.S))
    assert set(blocks) == {
        "transport_from_files.py",
        "make_issuer_key.py",
        "issuer.py",
        "agent.py",
        "call_tool.py",
        "tool.py",
        "delegate.py",
        "jwt_issuer.py",
        "jwt_agent.py",
        "federated_issuer.py",
    }
    return blocks


def test_guide_file_option_runs(tmp_path):
    """The guide's credential-file alternative builds a working transport."""
    acme = CA(tmp_path, "acme.test root")
    cert, key = acme.leaf("spiffe://acme.test/issuer")
    for name, data in (("svid.pem", cert), ("svid_key.pem", key), ("svid_bundle.pem", acme.pem)):
        (tmp_path / name).write_bytes(data)
    code = _guide_blocks()["transport_from_files.py"]
    assert code.count("/run/spiffe/") == 3
    scope: dict = {}
    exec(code.replace("/run/spiffe/", f"{tmp_path.as_posix()}/"), scope)
    assert scope["transport"].identity.spiffe_id == "spiffe://acme.test/issuer"


def test_guide_code_runs(tmp_path, monkeypatch, caplog, workload_api):
    """Execute the named code blocks in docs/spiffe.md against a test trust domain."""
    blocks = _guide_blocks()
    acme = CA(tmp_path, "acme.test root")
    apis = {}
    for role, identity in (("issuer", "spiffe://acme.test/issuer"), ("agent", "spiffe://acme.test/agents/refund")):
        apis[role] = workload_api()
        apis[role].publish(x509_response(svid_entry(acme, identity)))

    def localize(code, role, address=None):
        if role is not None:
            assert code.count('"/run/spire/sockets/agent.sock"') == 1
            code = code.replace('"/run/spire/sockets/agent.sock"', repr(apis[role].address))
        code = code.replace("/run/secrets/tenuo-issuer.pem", (tmp_path / "tenuo-issuer.pem").as_posix()).replace(
            "/etc/tenuo/tenuo-issuer.pub", (tmp_path / "tenuo-issuer.pub").as_posix()
        )
        if address is not None:
            assert '("issuer.acme.internal", 8443)' in code
            code = code.replace('("issuer.acme.internal", 8443)', repr(tuple(address)))
        assert "/run/" not in code and "/etc/" not in code
        return code

    monkeypatch.chdir(tmp_path)
    exec(blocks["make_issuer_key.py"], {})
    if os.name != "nt":
        assert (tmp_path / "tenuo-issuer.pem").stat().st_mode & 0o077 == 0

    issuer_code = localize(blocks["issuer.py"], "issuer").rstrip()
    assert issuer_code.endswith("asyncio.run(main())")
    issuer_scope: dict = {}
    agent_scope: dict = {}
    try:
        with caplog.at_level("INFO", logger="tenuo.spiffe"):
            exec(issuer_code[: -len("asyncio.run(main())")], issuer_scope)

            def agent_side(address):
                exec(localize(blocks["agent.py"], "agent", address), agent_scope)
                exec(blocks["call_tool.py"], agent_scope)
                exec(blocks["delegate.py"], agent_scope)

            async def body(address):
                await asyncio.to_thread(agent_side, address)

            run_server(issuer_scope["issuer"], body)
    finally:
        for scope in (issuer_scope, agent_scope):
            if "transport" in scope:
                scope["transport"].close()
    logged = caplog.text
    assert "Loaded SVID spiffe://acme.test/issuer" in logged
    assert "Issuing warrants on" in logged and "as spiffe://acme.test/issuer" in logged
    assert "to spiffe://acme.test/agents/refund for task 'refund-task-123'" in logged

    tool_scope: dict = {}
    exec(localize(blocks["tool.py"], None), tool_scope)
    refund = tool_scope["refund"]
    assert refund(agent_scope["call"]) == "refunded 4000 cents to customer 123"
    assert refund(agent_scope["worker_call"]) == "refunded 800 cents to customer 123"

    import base64

    def call(warrant_chain, signer, key, args):
        proof = signer.sign(key, "refund", args, int(time.time()))
        return {
            "chain": [w.to_base64() for w in warrant_chain],
            "args": args,
            "proof": base64.b64encode(proof).decode(),
        }

    warrant, child = agent_scope["warrant"], agent_scope["child"]
    holder, worker = agent_scope["holder_key"], agent_scope["worker_key"]
    for attempt in (
        call([warrant], warrant, holder, {"customer": "999", "cents": 4000}),
        call([warrant], warrant, holder, {"customer": "123", "cents": 6000}),
        call([warrant, child], child, worker, {"customer": "123", "cents": 4000}),
        call([warrant], warrant, worker, {"customer": "123", "cents": 100}),
        {},
        {"chain": ["AAAA"], "args": {}, "proof": "!!"},
    ):
        assert refund(attempt).startswith("denied: ")


def test_guide_federation_code_runs(tmp_path, workload_api):
    """Execute the guide's federated issuer block: a partner's workload is accepted and bound to its domain."""
    code = _guide_blocks()["federated_issuer.py"]
    acme, partner = CA(tmp_path, "acme.test root"), CA(tmp_path, "partner.test root")
    api = workload_api()
    api.publish(
        x509_response(svid_entry(acme, "spiffe://acme.test/issuer"), federated=[("spiffe://partner.test", partner.pem)])
    )
    assert code.count('"/run/spire/sockets/agent.sock"') == 1
    scope: dict = {}
    exec(code.replace('"/run/spire/sockets/agent.sock"', repr(api.address)), scope)
    transport, policy = scope["transport"], scope["policy"]
    try:
        refund_agent = "spiffe://partner.test/agents/refund"
        connection, _ = connect(transport, raw_client(partner.files("guide-partner", refund_agent), acme.pem))
        identity = transport.authenticate(connection)
        assert (identity.spiffe_id, identity.trust_domain) == (refund_agent, "partner.test")
        assert policy(identity, "refund-task-123") is not None
        assert policy(identity, "another-task") is None
        # The same path in the issuer's own domain is a different workload, and the policy says so.
        lookalike, _ = connect(
            transport, raw_client(acme.files("guide-lookalike", "spiffe://acme.test/agents/refund"), acme.pem)
        )
        assert policy(transport.authenticate(lookalike), "refund-task-123") is None
        # The partner's authority cannot name a workload in acme.test.
        forged, _ = connect(
            transport, raw_client(partner.files("guide-forged", "spiffe://acme.test/agents/refund"), acme.pem)
        )
        with pytest.raises(SpiffeError, match="its own trust domain's authorities"):
            transport.authenticate(forged)
    finally:
        transport.close()
