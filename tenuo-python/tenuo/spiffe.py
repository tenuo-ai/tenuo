"""X.509-SVID authentication and task-scoped warrant issuance.

Install ``tenuo[spiffe]``. TLS terminates in this process: never pass identity
headers or caller-supplied certificates to this adapter. Each SpiffeTLS instance
trusts exactly one domain's bundle; pooled federation bundles are unsupported.
"""

from __future__ import annotations

import json
import re
import secrets
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Union

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.x509.oid import ExtendedKeyUsageOID
except ImportError as exc:
    raise ImportError("SPIFFE integration requires pip install 'tenuo[spiffe]'") from exc

from tenuo import PublicKey, SigningKey, Warrant

TLSConnection = Union[ssl.SSLSocket, ssl.SSLObject]


class SpiffeError(ValueError):
    """Authentication, holder proof, or issuance was rejected."""


def _trust_domain(spiffe_id: str) -> str:
    # Parse without URL normalization: encoded separators and relative segments
    # must never turn into an authorized identity.
    match = re.fullmatch(r"spiffe://([a-z0-9._-]{1,255})/([a-zA-Z0-9._/-]+)", spiffe_id)
    if not match or len(spiffe_id) > 2048 or any(segment in ("", ".", "..") for segment in match[2].split("/")):
        raise SpiffeError("Invalid workload SPIFFE ID")
    return match[1]


@dataclass(frozen=True)
class SpiffeIdentity:
    """Peer identity authenticated against a domain-specific TLS trust bundle."""

    spiffe_id: str
    certificate_sha256: str
    expires_at: float


class SpiffeTLS:
    """Own a TLS context and validate its peers as X.509-SVIDs.

    ``bundle_file`` must contain ONLY the configured trust domain's authorities.
    No system roots are loaded. Keep the context immutable after construction.
    For rotation, construct a new instance and replace the listener/client;
    existing connections retain their original context and expiry checks.
    """

    def __init__(self, *, trust_domain: str, bundle_file: str, cert_file: str, key_file: str, server_side: bool):
        if not re.fullmatch(r"[a-z0-9._-]{1,255}", trust_domain):
            raise ValueError("Invalid trust domain")
        self.trust_domain = trust_domain
        self.server_side = server_side
        protocol = ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
        self.context = ssl.SSLContext(protocol)
        self.context.check_hostname = False  # URI identity is checked below, not DNS.
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cafile=bundle_file)
        self.context.load_cert_chain(cert_file, key_file)

    def authenticate(self, connection: TLSConnection, *, expected_id: Optional[str] = None) -> SpiffeIdentity:
        """Authenticate a completed TLS connection. Clients must pin a server ID."""
        if not isinstance(connection, (ssl.SSLSocket, ssl.SSLObject)):
            raise SpiffeError("A live TLS connection is required")
        if (
            connection.context is not self.context
            or connection.server_side != self.server_side
            or self.context.verify_mode != ssl.CERT_REQUIRED
            or connection.version() is None
        ):
            raise SpiffeError("Connection was not verified by this SPIFFE TLS context")
        if not self.server_side and expected_id is None:
            raise SpiffeError("Clients must specify the expected server SPIFFE ID")
        der = connection.getpeercert(binary_form=True)
        if not der:
            raise SpiffeError("Missing peer SVID")
        try:
            cert = x509.load_der_x509_certificate(der)
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if len(uris) != 1 or basic.ca:
                raise SpiffeError("Expected a leaf SVID with exactly one URI SAN")
            if (
                not usage.critical
                or not usage.value.digital_signature
                or usage.value.key_cert_sign
                or usage.value.crl_sign
            ):
                raise SpiffeError("Invalid SVID key usage")
            if not cert.subject and not san.critical:
                raise SpiffeError("An empty subject requires a critical SAN")
            try:
                eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except x509.ExtensionNotFound:
                eku = None
            if eku is not None and not all(
                oid in eku for oid in (ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH)
            ):
                raise SpiffeError("SVID EKU must allow client and server authentication")
            identity = uris[0]
            if _trust_domain(identity) != self.trust_domain:
                raise SpiffeError("SVID belongs to a different trust domain")
            if expected_id is not None and identity != expected_id:
                raise SpiffeError("Unexpected peer SPIFFE ID")
            expiry = cert.not_valid_after_utc.timestamp()
            if not cert.not_valid_before_utc.timestamp() <= time.time() < expiry:
                raise SpiffeError("SVID is not currently valid")
            return SpiffeIdentity(identity, cert.fingerprint(hashes.SHA256()).hex(), expiry)
        except (ValueError, x509.ExtensionNotFound) as exc:
            raise SpiffeError("Invalid peer X.509-SVID") from exc


@dataclass(frozen=True)
class SpiffeGrant:
    """Server policy output. Empty argument constraints explicitly allow any arguments.

    ``task_id`` supplied to the policy is an untrusted lookup key, not proof of
    user consent. Resolve it against trusted task records and check ownership.
    """

    capabilities: Dict[str, Dict[str, Any]]
    ttl_seconds: int = 300
    max_depth: int = 0


@dataclass(frozen=True)
class _Pending:
    identity: SpiffeIdentity
    holder: bytes
    task_id: str
    deadline: float


class SpiffeWarrantIssuer:
    """Exchange authenticated workload identity + holder proof for a warrant.

    Policy returns a grant or None (deny). Challenges are bounded, single-use,
    expire after 30 seconds, and are local to this issuer process. Route both
    exchange steps to the same instance. Apply service-level rate limits too.
    """

    def __init__(
        self,
        *,
        tls: SpiffeTLS,
        signing_key: SigningKey,
        policy: Callable[[SpiffeIdentity, str], Optional[SpiffeGrant]],
        max_pending: int = 1024,
    ):
        if not tls.server_side:
            raise ValueError("Issuance requires a server-side SPIFFE TLS context")
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self.tls = tls
        self._key = signing_key
        self._policy = policy
        self._max_pending = max_pending
        self._pending: Dict[bytes, _Pending] = {}
        self._lock = threading.Lock()

    def challenge(self, connection: TLSConnection, holder: PublicKey, task_id: str) -> bytes:
        """Return bytes for the holder to sign with ``SigningKey.sign_raw``."""
        identity = self.tls.authenticate(connection)
        if not isinstance(task_id, str) or not task_id or len(task_id) > 256:
            raise SpiffeError("task_id must contain 1–256 characters")
        key = bytes(holder.to_bytes())
        now = time.monotonic()
        payload = b"tenuo.spiffe.holder-binding.v1\x00" + json.dumps(
            {
                "nonce": secrets.token_hex(32),
                "issuer": bytes(self._key.public_key.to_bytes()).hex(),
                "spiffe_id": identity.spiffe_id,
                "certificate": identity.certificate_sha256,
                "holder": key.hex(),
                "task_id": task_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v.deadline > now}
            if len(self._pending) >= self._max_pending:
                raise SpiffeError("Too many pending holder challenges")
            self._pending[payload] = _Pending(identity, key, task_id, now + 30)
        return payload

    def issue(self, connection: TLSConnection, challenge: bytes, signature: bytes) -> Warrant:
        """Consume a challenge, verify holder possession, evaluate policy, mint."""
        identity = self.tls.authenticate(connection)
        with self._lock:
            pending = self._pending.pop(challenge, None)
        if pending is None or pending.deadline <= time.monotonic():
            raise SpiffeError("Unknown, expired, or already consumed holder challenge")
        if identity != pending.identity:
            raise SpiffeError("Holder challenge belongs to a different SVID")
        try:
            Ed25519PublicKey.from_public_bytes(pending.holder).verify(signature, challenge)
        except (InvalidSignature, ValueError) as exc:
            raise SpiffeError("Invalid holder proof") from exc
        grant = self._policy(identity, pending.task_id)
        if grant is None:
            raise SpiffeError("Workload is not authorized for this task")
        if (
            not grant.capabilities
            or isinstance(grant.ttl_seconds, bool)
            or not isinstance(grant.ttl_seconds, int)
            or grant.ttl_seconds < 1
        ):
            raise SpiffeError("Policy must provide capabilities and a positive integer TTL")
        # Recheck time after policy evaluation; a slow policy cannot extend SVID life.
        ttl = min(grant.ttl_seconds, int(identity.expires_at - time.time()) - 1)
        if ttl < 1:
            raise SpiffeError("SVID expires too soon to issue a warrant")
        builder = (
            Warrant.mint_builder().holder(PublicKey.from_bytes(pending.holder)).ttl(ttl).max_depth(grant.max_depth)
        )
        for tool, constraints in grant.capabilities.items():
            builder.capability(tool, constraints)
        warrant = builder.mint(self._key)
        if datetime.fromisoformat(warrant.expires_at()).timestamp() > identity.expires_at:
            raise SpiffeError("Warrant would outlive the authenticated SVID")
        return warrant
