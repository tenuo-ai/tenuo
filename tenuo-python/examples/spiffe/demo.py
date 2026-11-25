#!/usr/bin/env python3
"""SPIFFE mTLS -> holder-bound task warrant -> protected refund tool.

Run with --credentials DIR to use exported SVIDs instead of development PKI.
See README.md for the credential layout and SPIRE setup.
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tenuo import Authorizer, Exact, Range, SigningKey, Warrant
from tenuo.exceptions import AuthorizationError
from tenuo.spiffe import (
    SpiffeGrant,
    SpiffeIdentity,
    SpiffeIssuerServer,
    SpiffeTLS,
    SpiffeWarrantIssuer,
    arequest_warrant,
)

DOMAIN = "demo.test"
AGENT_ID = f"spiffe://{DOMAIN}/agent"
ISSUER_ID = f"spiffe://{DOMAIN}/issuer"


def development_credentials(directory: Path) -> None:
    """Generate disposable test credentials, never a production identity provider."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DEVELOPMENT ONLY")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "bundle.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for role, identity in (("agent", AGENT_ID), ("issuer", ISSUER_ID)):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=5))
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                False,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .sign(ca_key, hashes.SHA256())
        )
        (directory / f"{role}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path = directory / f"{role}-key.pem"
        key_path.touch(mode=0o600)
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )


def tls_config(directory: Path, role: str) -> SpiffeTLS:
    return SpiffeTLS(
        trust_domain=DOMAIN,
        bundle_file=str(directory / "bundle.pem"),
        cert_file=str(directory / f"{role}.pem"),
        key_file=str(directory / f"{role}-key.pem"),
        server_side=role == "issuer",
    )


def policy(identity: SpiffeIdentity, task_id: str):
    # This record represents a task approved by the organization's control plane.
    # The caller provides only its lookup key, never the scope or customer ID.
    if identity.spiffe_id == AGENT_ID and task_id == "approved-refund-123":
        return SpiffeGrant(
            {"refund": {"customer": Exact("123"), "cents": Range(1, 5000)}}, ttl_seconds=120, max_depth=1
        )
    return None


def refund_tool(authorizer: Authorizer, chain, args, pop: bytes, executed: list) -> str:
    """The protected tool. Verification happens before any side effect."""
    try:
        authorizer.check_chain(chain, "refund", args, pop)
    except AuthorizationError:
        return "DENIED"
    executed.append(args)  # Stand-in for the real refund.
    return "ALLOWED"


def run(directory: Path) -> list[str]:
    server_tls, client_tls = tls_config(directory, "issuer"), tls_config(directory, "agent")
    root, holder, worker = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    audit: list = []
    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=root, policy=policy, audit=audit.append)

    async def obtain_warrant() -> Warrant:
        async with SpiffeIssuerServer(issuer, host="127.0.0.1", port=0) as server:
            return await arequest_warrant(
                client_tls,
                server.address,
                issuer_id=ISSUER_ID,
                issuer_key=root.public_key,
                holder_key=holder,
                task_id="approved-refund-123",
            )

    warrant = asyncio.run(obtain_warrant())
    assert [(record.identity.spiffe_id, record.warrant_id) for record in audit] == [(AGENT_ID, warrant.id)]
    child = (
        warrant.grant_builder()
        .holder(worker.public_key)
        .ttl(30)
        .capability("refund", customer=Exact("123"), cents=Range(1, 1000))
        .grant(holder)
    )
    authorizer = Authorizer(trusted_roots=[root.public_key])
    executed: list = []
    results = []
    cases = [
        ("approved customer, $40", [warrant], holder, {"customer": "123", "cents": 4000}),
        ("different customer", [warrant], holder, {"customer": "999", "cents": 4000}),
        ("over $50 task limit", [warrant], holder, {"customer": "123", "cents": 6000}),
        ("delegated worker, $8", [warrant, child], worker, {"customer": "123", "cents": 800}),
    ]
    for label, chain, key, args in cases:
        pop = chain[-1].sign(key, "refund", args, int(time.time()))
        result = refund_tool(authorizer, chain, args, pop, executed)
        results.append(result)
        print(f"{result}: {label}")
    assert results == ["ALLOWED", "DENIED", "DENIED", "ALLOWED"]
    assert len(executed) == 2
    print("Verified: only the two authorized refunds reached the tool body.")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, help="Directory containing exported SPIRE SVIDs")
    options = parser.parse_args()
    if options.credentials:
        run(options.credentials)
    else:
        with tempfile.TemporaryDirectory(prefix="tenuo-spiffe-demo-") as temp:
            directory = Path(temp)
            development_credentials(directory)
            print("Using disposable development SVIDs (no SPIRE attestation).")
            run(directory)
