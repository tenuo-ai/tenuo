"""Real TLS handshakes and adversarial issuance tests (no SPIRE required)."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import socket
import ssl
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
    assert issuer._pending == {} or "issuer_key" in change


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


def test_non_ascii_bundle_does_not_stop_reloading(ca, pki):
    paths = ca.files("non-ascii", SERVER)
    server = _tls(paths, True)
    before = server.identity
    paths["bundle"].write_bytes("# Bündel\n".encode() + ca.pem)
    with pytest.raises(SpiffeError, match="ASCII PEM"):
        server.reload()
    server._refresh()
    assert server.identity == before
    _rewrite(ca, paths, SERVER, bundle=ca.pem)
    server._refresh()
    assert server.identity != before


def test_server_reload_loop_survives_bad_files(ca):
    paths = ca.files("served-bad", SERVER)
    server_tls = _tls(paths, True)
    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=SigningKey.generate(), policy=lambda *_: None)
    before = server_tls.identity

    async def body(address):
        paths["bundle"].write_bytes("# Bündel\n".encode() + ca.pem)
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


def test_constraint_values_checked_before_challenge(exchange):
    issuer, connection, holder, *_ = exchange
    issuer._policy = lambda *_: SpiffeGrant({"refund": {"cents": 5}})  # Not a constraint object.
    with pytest.raises(SpiffeError, match="invalid constraints"):
        issuer.challenge(connection, holder.public_key, "task-123")
    assert issuer._pending == {}


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


# -- the guide's code ---------------------------------------------------------------

GUIDE = Path(__file__).parents[3] / "docs" / "spiffe.md"


def test_guide_code_runs(tmp_path, monkeypatch, caplog):
    """Execute the named code blocks in docs/spiffe.md against a test trust domain."""
    if not GUIDE.exists():
        pytest.skip("guide not present in this distribution")
    blocks = dict(re.findall(r"```python\n# (\S+\.py)[^\n]*\n(.*?)```", GUIDE.read_text(), re.S))
    assert set(blocks) == {"make_issuer_key.py", "issuer.py", "agent.py", "call_tool.py", "tool.py", "delegate.py"}

    acme = CA(tmp_path, "acme.test root")
    directories = {}
    for role, identity in (("issuer", "spiffe://acme.test/issuer"), ("agent", "spiffe://acme.test/agents/refund")):
        directory = tmp_path / role
        directory.mkdir()
        cert, key = acme.leaf(identity)
        (directory / "svid.pem").write_bytes(cert)
        (directory / "svid_key.pem").write_bytes(key)
        (directory / "svid_bundle.pem").write_bytes(acme.pem)
        directories[role] = directory

    def localize(code, role, address=None):
        code = (
            code.replace("/run/spiffe/", f"{directories[role]}/")
            .replace("/run/secrets/tenuo-issuer.pem", str(tmp_path / "tenuo-issuer.pem"))
            .replace("/etc/tenuo/tenuo-issuer.pub", str(tmp_path / "tenuo-issuer.pub"))
        )
        if address is not None:
            assert '("issuer.acme.internal", 8443)' in code
            code = code.replace('("issuer.acme.internal", 8443)', repr(tuple(address)))
        return code

    monkeypatch.chdir(tmp_path)
    exec(blocks["make_issuer_key.py"], {})
    if os.name != "nt":
        assert (tmp_path / "tenuo-issuer.pem").stat().st_mode & 0o077 == 0

    issuer_code = localize(blocks["issuer.py"], "issuer").rstrip()
    assert issuer_code.endswith("asyncio.run(main())")
    issuer_scope: dict = {}
    exec(issuer_code[: -len("asyncio.run(main())")], issuer_scope)

    agent_scope: dict = {}

    def agent_side(address):
        exec(localize(blocks["agent.py"], "agent", address), agent_scope)
        exec(blocks["call_tool.py"], agent_scope)
        exec(blocks["delegate.py"], agent_scope)

    async def body(address):
        await asyncio.to_thread(agent_side, address)

    with caplog.at_level("INFO", logger="tenuo.spiffe"):
        run_server(issuer_scope["issuer"], body)
    logged = caplog.text
    assert "Issuing warrants on" in logged and "as spiffe://acme.test/issuer" in logged
    assert "to spiffe://acme.test/agents/refund for task 'refund-task-123'" in logged
    assert "/run/" not in localize(blocks["agent.py"], "agent") and "/etc/" not in localize(blocks["tool.py"], "agent")

    tool_scope: dict = {}
    exec(localize(blocks["tool.py"], "agent"), tool_scope)
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
