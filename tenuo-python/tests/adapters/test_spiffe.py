"""Real TLS handshakes and adversarial issuance tests (no SPIRE required)."""

from __future__ import annotations

import importlib.util
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tenuo import Authorizer, Exact, Range, SigningKey
from tenuo.exceptions import AuthorizationError, DepthExceeded, SignatureInvalid
from tenuo.spiffe import SpiffeError, SpiffeGrant, SpiffeTLS, SpiffeWarrantIssuer

DOMAIN = "example.test"
AGENT = f"spiffe://{DOMAIN}/agent"
SERVER = f"spiffe://{DOMAIN}/issuer"


@pytest.fixture
def pki(tmp_path):
    """An isolated root and leaf factory with deliberate malformed-SVID options."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test root")])
    now = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(True, None), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def config(
        *,
        server=False,
        ids=None,
        is_ca=False,
        usage=True,
        critical=True,
        eku=None,
        expires=600,
        starts=-10,
        trust_domain=DOMAIN,
        bundle_file=None,
    ):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(seconds=starts))
            .not_valid_after(now + timedelta(seconds=expires))
            .add_extension(x509.BasicConstraints(is_ca, None), True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(i)
                        for i in (ids if ids is not None else [SERVER if server else AGENT])
                    ]
                ),
                True,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        )
        if usage:
            cert = cert.add_extension(
                x509.KeyUsage(True, False, False, False, False, is_ca, is_ca, False, False), critical
            )
        cert = cert.add_extension(
            x509.ExtendedKeyUsage(
                eku
                if eku is not None
                else [
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            False,
        ).sign(ca_key, hashes.SHA256())
        prefix = str(x509.random_serial_number())
        cert_path, key_path = tmp_path / f"{prefix}.pem", tmp_path / f"{prefix}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        return SpiffeTLS(
            trust_domain=trust_domain,
            bundle_file=str(bundle_file or bundle),
            cert_file=str(cert_path),
            key_file=str(key_path),
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
            return SpiffeGrant(
                {"refund": {"customer": Exact("123"), "cents": Range(1, 5000)}}, ttl_seconds=120, max_depth=1
            )
        return None

    issuer = SpiffeWarrantIssuer(tls=server, signing_key=root, policy=policy)
    return issuer, connection, holder, root, seen, client, peer


def mint(exchange, task="task-123"):
    issuer, connection, holder, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, task)
    return issuer.issue(connection, challenge, holder.sign_raw(challenge))


def test_authenticate_both_peers(exchange):
    issuer, connection, _, _, _, client, peer = exchange
    assert issuer.tls.authenticate(connection).spiffe_id == AGENT
    assert client.authenticate(peer, expected_id=SERVER).spiffe_id == SERVER
    with pytest.raises(SpiffeError):
        client.authenticate(peer)
    with pytest.raises(SpiffeError):
        client.authenticate(peer, expected_id=AGENT)


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


@pytest.mark.parametrize("task", ["unknown", "task-123;admin=true"])
def test_policy_denies_unknown_task(exchange, task):
    with pytest.raises(SpiffeError, match="not authorized"):
        mint(exchange, task)


def test_replay_and_wrong_holder(exchange):
    issuer, connection, holder, _, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError, match="Invalid holder proof"):
        issuer.issue(connection, challenge, SigningKey.generate().sign_raw(challenge))
    assert seen == []
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, holder.sign_raw(challenge))
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    issuer.issue(connection, challenge, holder.sign_raw(challenge))
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, holder.sign_raw(challenge))


def test_challenge_tampering(exchange):
    issuer, connection, holder, _, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    altered = challenge.replace(b"task-123", b"task-999")
    with pytest.raises(SpiffeError, match="Unknown"):
        issuer.issue(connection, altered, holder.sign_raw(altered))
    assert seen == []


def test_expired_challenge(exchange, monkeypatch):
    issuer, connection, holder, _, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    future = time.monotonic() + 31
    monkeypatch.setattr("tenuo.spiffe.time.monotonic", lambda: future)
    with pytest.raises(SpiffeError, match="expired"):
        issuer.issue(connection, challenge, holder.sign_raw(challenge))
    assert seen == []


def test_other_certificate_cannot_redeem(exchange, pki):
    issuer, connection, holder, _, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    # Even the same SPIFFE ID with a renewed/different certificate must restart.
    other, _ = connect(issuer.tls, pki())
    with pytest.raises(SpiffeError, match="different SVID"):
        issuer.issue(other, challenge, holder.sign_raw(challenge))
    assert seen == []


def test_single_use_under_concurrency(exchange):
    issuer, connection, holder, _, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    signature = holder.sign_raw(challenge)

    def redeem(_):
        try:
            issuer.issue(connection, challenge, signature)
            return True
        except SpiffeError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(redeem, range(8))) == 1
    assert len(seen) == 1


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
    connection, _ = connect(server, pki(ids=[identity]))
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
        connection, _ = connect(server, pki(**options))
        server.authenticate(connection)


@pytest.mark.parametrize("options", [{"expires": -1}, {"starts": 60}])
def test_tls_rejects_expired_or_future_certificate(pki, options):
    with pytest.raises(ssl.SSLError):
        connect(pki(server=True), pki(**options))


def test_live_connection_expiry_rechecked(exchange, monkeypatch):
    issuer, connection, *_ = exchange
    future = issuer.tls.authenticate(connection).expires_at + 1
    monkeypatch.setattr("tenuo.spiffe.time.time", lambda: future)
    with pytest.raises(SpiffeError):
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


def test_untrusted_certificate(pki, tmp_path):
    # A different CA, not simply a different URI under an authorized CA.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted")])
    now = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(True, None), True)
        .sign(key, hashes.SHA256())
    )
    other_bundle = tmp_path / "other.pem"
    other_bundle.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(ssl.SSLError):
        connect(pki(server=True, bundle_file=other_bundle), pki())


def test_ttl_capped_to_svid(pki):
    server = pki(server=True)
    connection, _ = connect(server, pki(expires=20))
    key = SigningKey.generate()
    issuer = SpiffeWarrantIssuer(
        tls=server, signing_key=key, policy=lambda *_: SpiffeGrant({"read": {}}, ttl_seconds=300)
    )
    challenge = issuer.challenge(connection, key.public_key, "task")
    warrant = issuer.issue(connection, challenge, key.sign_raw(challenge))
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() <= server.authenticate(connection).expires_at
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() < time.time() + 21


def test_policy_error_fails_closed(exchange):
    issuer, connection, holder, *_ = exchange

    def broken(*_):
        raise RuntimeError("policy unavailable")

    issuer._policy = broken
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(RuntimeError, match="policy unavailable"):
        issuer.issue(connection, challenge, holder.sign_raw(challenge))
    with pytest.raises(SpiffeError, match="consumed"):
        issuer.issue(connection, challenge, holder.sign_raw(challenge))


def test_demo_over_localhost(tmp_path):
    path = Path(__file__).parents[2] / "examples/spiffe/demo.py"
    spec = importlib.util.spec_from_file_location("spiffe_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.development_credentials(tmp_path)
    assert module.run(tmp_path) == ["ALLOWED", "DENIED", "DENIED", "ALLOWED"]


def test_valid_but_unauthorized_workload(exchange, pki):
    issuer, _, holder, _, seen, *_ = exchange
    connection, _ = connect(issuer.tls, pki(ids=[f"spiffe://{DOMAIN}/other-agent"]))
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    with pytest.raises(SpiffeError, match="not authorized"):
        issuer.issue(connection, challenge, holder.sign_raw(challenge))
    assert seen == [(f"spiffe://{DOMAIN}/other-agent", "task-123")]


def test_tls_requires_client_certificate(pki):
    server, client = pki(server=True), pki()
    # The client still trusts the server, but offers no certificate of its own.
    client.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.context.check_hostname = False
    client.context.load_verify_locations(
        cadata=ssl.DER_cert_to_PEM_cert(server.context.get_ca_certs(binary_form=True)[0])
    )
    with pytest.raises(ssl.SSLError):
        connect(server, client)


def test_challenge_cannot_cross_issuer_instances(exchange):
    issuer, connection, holder, root, seen, *_ = exchange
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    other = SpiffeWarrantIssuer(tls=issuer.tls, signing_key=root, policy=issuer._policy)
    with pytest.raises(SpiffeError, match="Unknown"):
        other.issue(connection, challenge, holder.sign_raw(challenge))
    assert seen == []


@pytest.mark.parametrize(
    "grant", [SpiffeGrant({}), SpiffeGrant({"read": {}}, ttl_seconds=0), SpiffeGrant({"read": {}}, ttl_seconds=True)]
)
def test_invalid_policy_grant(exchange, grant):
    issuer, *_ = exchange
    issuer._policy = lambda *_: grant
    with pytest.raises(SpiffeError, match="Policy must provide"):
        mint(exchange)


def test_slow_policy_cannot_outlive_identity(exchange, monkeypatch):
    issuer, connection, *_ = exchange
    expiry = issuer.tls.authenticate(connection).expires_at

    def slow_policy(*_):
        monkeypatch.setattr("tenuo.spiffe.time.time", lambda: expiry + 1)
        return SpiffeGrant({"read": {}})

    issuer._policy = slow_policy
    with pytest.raises(SpiffeError, match="expires too soon"):
        mint(exchange)


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
