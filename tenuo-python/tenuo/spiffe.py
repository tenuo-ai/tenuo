"""X.509-SVID authentication and task-scoped warrant issuance.

Install ``tenuo[spiffe-workload-api]`` to take SVIDs from the SPIRE agent, or
``tenuo[spiffe]`` for credential files only. TLS terminates in this process: never pass identity
headers or caller-supplied certificates to this adapter. A SpiffeTLS instance
trusts one trust domain and, with federation, the other domains you name. Each
domain's bundle is given separately and a peer is always tied to its own
domain's bundle; a single file of pooled authorities is not supported.

Production deployments normally run :class:`SpiffeIssuerServer` as the issuance
endpoint and call :func:`request_warrant` from agents. Both reload rotated SPIRE
credentials from disk without restarting.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import heapq
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_der_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.x509.oid import ExtendedKeyUsageOID
except ImportError as exc:
    raise ImportError("SPIFFE integration requires pip install 'tenuo[spiffe]'") from exc

from tenuo import Authorizer, PublicKey, SigningKey, Warrant

__all__ = [
    "ANY_ARGUMENTS",
    "SpiffeError",
    "SpiffeGrant",
    "SpiffeIdentity",
    "SpiffeIssuance",
    "SpiffeHolderProof",
    "SpiffeIssuerServer",
    "SpiffeJWTProof",
    "SpiffeTLS",
    "SpiffeWarrantIssuer",
    "arequest_warrant",
    "request_warrant",
    "sign_holder_challenge",
]

logger = logging.getLogger("tenuo.spiffe")

TLSConnection = Union[ssl.SSLSocket, ssl.SSLObject]
IssuerKeys = Union[PublicKey, Sequence[PublicKey]]

# Prepended by the signer and the verifier, never sent by the issuer. The issuer
# therefore cannot choose the first bytes of what the holder key signs, and the
# signature cannot be reused as any other Tenuo signature (all start "tenuo-").
_HOLDER_CONTEXT = b"tenuo.spiffe.holder-binding.v1\x00"
# JWT-SVID exchanges are a single request, so the holder signs a timestamped
# statement bound to the exact token instead of an issuer challenge.
_JWT_HOLDER_CONTEXT = b"tenuo.spiffe.jwt-holder-binding.v1\x00"
# A proxy-forwarded identity has no token to bind to: the proof covers the
# issuer's audience, the task, and the time.
_FORWARDED_HOLDER_CONTEXT = b"tenuo.spiffe.forwarded-holder-binding.v1\x00"
_JWT_PROOF_SECONDS = 60  # Accepted distance between the proof timestamp and the issuer clock.
_JWT_PROOF_MEMORY = 16384  # Default number of live proofs remembered to refuse an exact replay.
_JWT_NONCE_BYTES = 16
_CHALLENGE_FIELDS = frozenset({"nonce", "issuer", "spiffe_id", "certificate", "holder", "task_id"})
_CHALLENGE_SECONDS = 30
_MAX_SPIFFE_ID = 2048
_MAX_TASK_ID = 256
# The largest challenge the issuer can serialize from inputs it accepts, so the
# holder never refuses a challenge the issuer legitimately produced. `nonce`,
# `issuer`, `certificate`, and `holder` are fixed-width hex and the SPIFFE ID
# grammar is ASCII; only `task_id` is unrestricted text, and `_challenge()`
# serializes with the json default `ensure_ascii=True`, where a supplementary
# character costs 12 bytes as an escaped surrogate pair.
_MAX_CHALLENGE_BYTES = len(
    json.dumps(
        {
            "nonce": "0" * 64,
            "issuer": "0" * 64,
            "spiffe_id": "a" * _MAX_SPIFFE_ID,
            "certificate": "0" * 64,
            "holder": "0" * 64,
            "task_id": "\U0001f600" * _MAX_TASK_ID,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
)
_MAX_DELEGATION_DEPTH = 64
_MAX_TOOL_NAME = 256
_FRAME_LIMIT = 64 * 1024
_CONNECTION_BYTE_LIMIT = 4 * _FRAME_LIMIT  # Handshake plus two frames, with room to spare.
_PROTOCOL_VERSION = 1
_VALIDATION_KEY = SigningKey.generate()

#: Grant constraint value that explicitly allows any arguments for a tool.
#: An empty dict is rejected so that "no constraints" is never accidental.
ANY_ARGUMENTS: Mapping[str, Any] = MappingProxyType({})


class SpiffeError(ValueError):
    """Authentication, holder proof, or issuance was rejected."""


class _IssuerBusy(SpiffeError):
    """The issuer cannot take the request right now; the caller should retry."""


def _jwt_proof_bytes(
    audience: str, holder: bytes, task_id: str, timestamp: int, nonce: bytes, token_sha256: bytes
) -> bytes:
    """What the holder key signs to bind itself to one JWT-SVID, issuer audience, and task.

    Fixed-width binary fields, so every language produces the same bytes:
    context, SHA-256 of the token, holder key, 8-byte big-endian timestamp,
    16-byte nonce, SHA-256 of the audience, SHA-256 of the task ID.
    """
    try:
        texts = hashlib.sha256(audience.encode("utf-8")).digest() + hashlib.sha256(task_id.encode("utf-8")).digest()
    except UnicodeEncodeError as exc:
        raise SpiffeError("audience and task_id must be valid Unicode text") from exc
    return _JWT_HOLDER_CONTEXT + token_sha256 + holder + timestamp.to_bytes(8, "big") + nonce + texts


def _forwarded_proof_bytes(audience: str, holder: bytes, task_id: str, timestamp: int, nonce: bytes) -> bytes:
    """What the holder key signs when its identity is forwarded by a proxy.

    Fixed-width binary fields: context, holder key, 8-byte big-endian
    timestamp, 16-byte nonce, SHA-256 of the audience, SHA-256 of the task ID.
    """
    try:
        texts = hashlib.sha256(audience.encode("utf-8")).digest() + hashlib.sha256(task_id.encode("utf-8")).digest()
    except UnicodeEncodeError as exc:
        raise SpiffeError("audience and task_id must be valid Unicode text") from exc
    return _FORWARDED_HOLDER_CONTEXT + holder + timestamp.to_bytes(8, "big") + nonce + texts


def _trust_domain(spiffe_id: str) -> str:
    # Parse without URL normalization: encoded separators and relative segments
    # must never turn into an authorized identity.
    match = re.fullmatch(r"spiffe://([a-z0-9._-]{1,255})/([a-zA-Z0-9._/-]+)", spiffe_id)
    if (
        not match
        or len(spiffe_id) > _MAX_SPIFFE_ID
        or any(segment in ("", ".", "..") for segment in match[2].split("/"))
    ):
        raise SpiffeError("Invalid workload SPIFFE ID")
    return match[1]


@dataclass(frozen=True)
class SpiffeIdentity:
    """A workload identity, and how the issuer learned it.

    ``svid_type`` is ``"x509"`` for a peer authenticated over mTLS, ``"jwt"``
    for a JWT-SVID bearer token, both checked against one trust domain's
    bundle, and ``"forwarded"`` for an identity a trusted proxy reported, which
    the issuer could not check itself. ``certificate_sha256`` is the SHA-256 of
    the SVID: the certificate (as the proxy reported it, when forwarded), or
    the token.
    """

    spiffe_id: str
    certificate_sha256: str
    expires_at: float
    svid_type: str = "x509"

    @property
    def trust_domain(self) -> str:
        """The trust domain part of ``spiffe_id``. With federation, check it in your policy."""
        return self.spiffe_id[len("spiffe://") :].split("/", 1)[0]


def _svid_identity(cert: x509.Certificate, trust_domains: Collection[str]) -> Tuple[SpiffeIdentity, float]:
    """Check the X.509-SVID leaf profile. Returns the identity and not-before time."""
    try:
        extensions = cert.extensions
        try:
            san = extensions.get_extension_for_class(x509.SubjectAlternativeName)
            basic = extensions.get_extension_for_class(x509.BasicConstraints).value
            usage = extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound as exc:
            raise SpiffeError(f"SVID is missing a required extension ({exc.oid.dotted_string})") from exc
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        try:
            eku: Optional[x509.ExtendedKeyUsage] = extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            eku = None
        not_before = cert.not_valid_before_utc.timestamp()
        expires_at = cert.not_valid_after_utc.timestamp()
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except SpiffeError:
        raise
    except Exception as exc:  # The library reports unreadable content with several unrelated types.
        raise SpiffeError("Malformed X.509-SVID") from exc
    if len(uris) != 1 or basic.ca:
        raise SpiffeError("Expected a leaf SVID with exactly one URI SAN")
    if not usage.critical or not usage.value.digital_signature or usage.value.key_cert_sign or usage.value.crl_sign:
        raise SpiffeError("Invalid SVID key usage")
    if not cert.subject and not san.critical:
        raise SpiffeError("An empty subject requires a critical SAN")
    if eku is not None and not all(
        oid in eku for oid in (ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH)
    ):
        raise SpiffeError("SVID EKU must allow client and server authentication")
    if _trust_domain(uris[0]) not in trust_domains:
        raise SpiffeError("SVID belongs to a different trust domain")
    return SpiffeIdentity(uris[0], fingerprint, expires_at), not_before


def _trust_domain_names(own: str, federated: Sequence[str]) -> Tuple[str, ...]:
    """Validate a trust domain and the other domains it accepts peers from."""
    if isinstance(federated, str):
        raise ValueError("Pass federated trust domains as a list of names")
    names = tuple(federated)
    for name in (own, *names):
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9._-]{1,255}", name):
            raise ValueError("Invalid trust domain")
    if own in names or len(set(names)) != len(names):
        raise ValueError("Federated trust domains must be distinct and exclude your own")
    return names


def _check_authorities(authorities: Sequence[x509.Certificate], trust_domain: str) -> None:
    """A bundle may hold only CA certificates, and none that names another trust domain."""
    for authority in authorities:
        # Certificates are parsed lazily, and the library reports unreadable
        # content with several unrelated exception types. Read everything used
        # later now, so a bad certificate is refused here and nowhere else.
        try:
            authority.extensions
            authority.subject
            authority.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        except Exception as exc:
            raise SpiffeError("Malformed or unsupported X.509 certificate in trust bundle") from exc
        try:
            is_ca = authority.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except (x509.ExtensionNotFound, ValueError):
            is_ca = False
        if not is_ca:
            raise SpiffeError("Trust bundle may contain only CA certificates")
        try:
            uris = authority.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.UniformResourceIdentifier
            )
        except x509.ExtensionNotFound:
            uris = []
        except ValueError as exc:
            raise SpiffeError("Malformed X.509 certificate in trust bundle") from exc
        for uri in uris:
            if uri != f"spiffe://{trust_domain}" and (
                not uri.startswith(f"spiffe://{trust_domain}/") or _trust_domain(uri) != trust_domain
            ):
                raise SpiffeError("Trust bundle contains an authority for a different trust domain")


def _issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
    except Exception:  # A wrong name or signature, or a key type the library cannot check.
        return False
    return True


def _anchored(chain: Sequence[x509.Certificate], authorities: Sequence[x509.Certificate]) -> bool:
    """Whether the SVID was issued by one of ``authorities``, directly or through the intermediates sent with it.

    Names and signatures only: dates and constraints are for the TLS library,
    at each handshake. This catches an SVID delivered next to a bundle that
    does not hold its authority, which no peer with that bundle could accept.
    """
    current, intermediates = chain[0], list(chain[1:])
    for _ in range(len(chain)):
        if any(_issued_by(current, authority) for authority in authorities):
            return True
        issuer = next((candidate for candidate in intermediates if _issued_by(current, candidate)), None)
        if issuer is None:
            return False
        intermediates.remove(issuer)
        current = issuer
    return False


def _verified_chain(connection: Any) -> Optional[List[bytes]]:
    """The peer's chain as the TLS library verified it (leaf first, DER), where Python exposes it."""
    getter = getattr(connection, "get_verified_chain", None)  # Python 3.13 and newer.
    if getter is None:
        # CPython 3.10 to 3.12 keep the same call on the wrapped object.
        getter = getattr(getattr(connection, "_sslobj", None), "get_verified_chain", None)
    if getter is None:
        return None
    try:
        chain = getter()
        if not chain:
            return None
        if all(isinstance(certificate, bytes) for certificate in chain):
            return list(chain)
        import _ssl

        der = getattr(_ssl, "ENCODING_DER")  # Not in the type stubs for every Python version.
        return [bytes(certificate.public_bytes(der)) for certificate in chain]
    except Exception:
        return None


def _key_identifier(certificate: x509.Certificate) -> Optional[bytes]:
    try:
        return certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except (x509.ExtensionNotFound, ValueError):
        return None


def _same_authority(first: x509.Certificate, second: x509.Certificate) -> bool:
    """Whether two bundle certificates could stand in for each other during chain building.

    True for the same key, and for the same subject unless both carry key
    identifiers that differ (which is how the TLS library tells such certificates apart).
    """
    if first.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == second.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo):
        return True
    if first.subject != second.subject:
        return False
    identifiers = (_key_identifier(first), _key_identifier(second))
    return None in identifiers or identifiers[0] == identifiers[1]


def _overlapping_domains(domains: Mapping[str, Sequence[x509.Certificate]], home: str) -> Set[str]:
    """Federated trust domains whose bundle shares an authority with another domain's.

    A shared or lookalike authority would let one domain vouch for another, or
    misdirect chain building, so such a domain is not trusted at all. The home
    domain is never dropped; two federated domains that overlap are both dropped.
    """
    names = list(domains)
    overlapping: Set[str] = set()
    for index, first in enumerate(names):
        for second in names[index + 1 :]:
            if any(_same_authority(a, b) for a in domains[first] for b in domains[second]):
                overlapping.update({first, second} - {home})
    return overlapping


def _read_snapshot(path: str, limit: int = 1024 * 1024) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if not data or len(data) > limit:
        raise SpiffeError(f"Credential file is empty or too large: {path}")
    return data


def _file_signature(paths: Tuple[str, ...]) -> Tuple[Tuple[int, int, int, int], ...]:
    signature = []
    for path in paths:
        try:
            info = os.stat(path)
        except OSError:
            signature.append((0, 0, 0, 0))  # Missing: reading it reports the problem.
            continue
        signature.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns))
    return tuple(signature)


@contextlib.contextmanager
def _private_files(cert_pem: bytes, key_pem: bytes) -> Iterator[Tuple[str, str]]:
    """Paths holding exactly these bytes, for ``load_cert_chain``, which only reads paths.

    On Linux the bytes stay in anonymous memory. Elsewhere they pass through a
    private temporary directory that is removed straight after the load.
    """
    memfd_create = getattr(os, "memfd_create", None)
    if memfd_create is not None and os.path.isdir("/proc/self/fd"):
        descriptors: List[int] = []
        try:
            for data in (cert_pem, key_pem):
                descriptor = memfd_create("tenuo-spiffe")
                descriptors.append(descriptor)
                os.write(descriptor, data)
            yield f"/proc/self/fd/{descriptors[0]}", f"/proc/self/fd/{descriptors[1]}"
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
        return
    with tempfile.TemporaryDirectory(prefix="tenuo-spiffe-") as private:
        cert_path, key_path = os.path.join(private, "svid.pem"), os.path.join(private, "key.pem")
        for path, data in ((cert_path, cert_pem), (key_path, key_pem)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
        yield cert_path, key_path


@dataclass(frozen=True)
class _Snapshot:
    """One consistent set of credentials, from files or from the Workload API."""

    chain: List[x509.Certificate]  # Leaf first.
    key_pem: bytes
    authorities: List[x509.Certificate]
    federated: Mapping[str, Sequence[x509.Certificate]] = field(default_factory=dict)  # By trust domain.


def _pem(certificates: Sequence[x509.Certificate]) -> bytes:
    return b"".join(certificate.public_bytes(Encoding.PEM) for certificate in certificates)


# -- SPIFFE Workload API (X.509) ---------------------------------------------
#
# The X.509 call is one server-streaming RPC with a small message, so the
# adapter speaks it with grpcio alone and reads the protobuf wire format
# directly instead of depending on protobuf and generated code.

_FETCH_X509_SVID = "/SpiffeWorkloadAPI/FetchX509SVID"
_WORKLOAD_API_METADATA = (("workload.spiffe.io", "true"),)
_WORKLOAD_API_BACKOFF = (1.0, 30.0)  # First and longest wait between attempts, in seconds.
_WORKLOAD_API_STARTUP_BACKOFF = 2.0  # Longest wait until the first usable SVID has arrived.
_PENDING_RETRY = (1.0, 30.0)  # First and longest wait before trying an unusable update again.


def _proto_fields(data: bytes) -> Iterator[Tuple[int, Union[int, bytes]]]:
    """Yield (field number, value) for one protobuf message."""
    position, size = 0, len(data)

    def varint() -> int:
        nonlocal position
        value = shift = 0
        while True:
            if position >= size or shift > 63:
                raise SpiffeError("Malformed Workload API response")
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7

    while position < size:
        key = varint()
        field, wire = key >> 3, key & 7
        if wire == 0:
            yield field, varint()
            continue
        length = {1: 8, 5: 4}.get(wire) if wire != 2 else varint()
        if length is None or position + length > size:
            raise SpiffeError("Malformed Workload API response")
        yield field, data[position : position + length]
        position += length


def _split_der(data: bytes) -> List[bytes]:
    """Split concatenated DER certificates."""
    parts, position = [], 0
    while position < len(data):
        if data[position] != 0x30 or position + 2 > len(data):
            raise SpiffeError("Malformed certificate data from the Workload API")
        first = data[position + 1]
        header = 2
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            if not 1 <= count <= 4 or position + 2 + count > len(data):
                raise SpiffeError("Malformed certificate data from the Workload API")
            length = int.from_bytes(data[position + 2 : position + 2 + count], "big")
            header += count
        end = position + header + length
        if end > len(data):
            raise SpiffeError("Malformed certificate data from the Workload API")
        parts.append(data[position:end])
        position = end
    return parts


def _x509_snapshot(message: bytes, wanted: Optional[str], federates_with: Sequence[str] = ()) -> _Snapshot:
    """Pick one SVID from an X509SVIDResponse.

    Federated bundles are taken only for the trust domains in ``federates_with``;
    any others in the response are ignored.
    """
    chosen: Optional[Dict[int, bytes]] = None
    offered = []
    foreign: Dict[str, bytes] = {}
    for number, value in _proto_fields(message):
        if number == 3 and isinstance(value, bytes):  # federated_bundles: map<string, bytes>
            try:
                entry = {key: item for key, item in _proto_fields(value) if isinstance(item, bytes)}
            except SpiffeError:
                logger.warning("Ignoring a malformed federated bundle entry in the Workload API response")
                continue
            name = entry.get(1, b"").decode("utf-8", "replace")
            if name.startswith("spiffe://") and name[len("spiffe://") :] in federates_with:
                foreign[name[len("spiffe://") :]] = entry.get(2, b"")
            continue
        if number != 1 or not isinstance(value, bytes):  # svids
            continue
        svid = {number: item for number, item in _proto_fields(value) if isinstance(item, bytes)}
        identity = svid.get(1, b"").decode("utf-8", "replace")
        offered.append(identity)
        if chosen is None and (wanted is None or identity == wanted):
            chosen = svid
    if chosen is None:
        if wanted is None:
            raise SpiffeError("The Workload API returned no SVID")
        shown = ", ".join(repr(identity[:200]) for identity in offered[:8]) or "none"
        more = f" and {len(offered) - 8} more" if len(offered) > 8 else ""
        raise SpiffeError(f"The Workload API did not offer {wanted} (offered: {shown}{more})")
    try:
        chain = [x509.load_der_x509_certificate(der) for der in _split_der(chosen.get(2, b""))]
        authorities = [x509.load_der_x509_certificate(der) for der in _split_der(chosen.get(4, b""))]
        key = load_der_private_key(chosen.get(3, b""), password=None)
        key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    except Exception as exc:  # Bad encodings, and versions, key types or curves the library does not know.
        raise SpiffeError("Malformed SVID from the Workload API") from exc
    if not chain or not authorities:
        raise SpiffeError("The Workload API returned an SVID without a certificate or bundle")
    federated: Dict[str, List[x509.Certificate]] = {}
    for domain, bundle in foreign.items():
        try:
            certificates = [x509.load_der_x509_certificate(der) for der in _split_der(bundle)]
        except Exception as exc:
            logger.warning("Ignoring a malformed bundle for federated trust domain %s: %s", domain, exc)
            continue
        if certificates:
            federated[domain] = certificates
    return _Snapshot(chain, key_pem, authorities, federated)


def _workload_api_target(address: Optional[str]) -> str:
    """Turn a socket path or SPIFFE_ENDPOINT_SOCKET value into a gRPC target."""
    address = address or os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if not address:
        raise ValueError("Pass socket_path or set SPIFFE_ENDPOINT_SOCKET")
    if address.startswith("unix://"):
        address = address[len("unix://") :]
    if address.startswith("/"):
        # gRPC reads the target as a URI: these would be decoded or cut off.
        if any(character in address for character in "%?#"):
            raise ValueError("Workload API socket paths may not contain %, ? or #")
        return "unix://" + address
    match = re.fullmatch(r"tcp://(\[[0-9A-Fa-f:.]+\]|[0-9.]+):([0-9]{1,5})", address)
    if match:
        host = match[1]
        try:
            ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
            ip = ipaddress.IPv6Address(host[1:-1]) if host.startswith("[") else ipaddress.IPv4Address(host)
            valid = 0 < int(match[2]) < 65536
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("A tcp:// Workload API address must be tcp://IP:PORT")
        # The Workload API is unencrypted and unauthenticated by design: it hands
        # out private keys to whoever connects, and relies on being local.
        if not ip.is_loopback:
            raise ValueError("A tcp:// Workload API address must be a loopback address; use the Unix socket otherwise")
        return f"{host}:{match[2]}"
    raise ValueError("Workload API address must be an absolute socket path, unix:///path, or tcp://IP:PORT on loopback")


def _next_delay(delay: float, usable: bool) -> float:
    """Double the reconnect wait. Before the first SVID, stay eager."""
    longest = _WORKLOAD_API_BACKOFF[1] if usable else min(_WORKLOAD_API_STARTUP_BACKOFF, _WORKLOAD_API_BACKOFF[1])
    return min(delay * 2, longest)


class _WorkloadAPIWatcher:
    """Background thread that follows the X.509-SVID stream and reconnects."""

    def __init__(
        self,
        target: str,
        method: str,
        parse: Callable[[bytes], Any],
        deliver: Callable[[Any], None],
        on_lost: Optional[Callable[[str], None]] = None,
        on_received: Optional[Callable[[], None]] = None,
    ):
        self.target = target
        self.last_error: Optional[str] = None
        self._method = method
        self._parse = parse
        self._deliver = deliver
        self._on_lost = on_lost  # Called with a gRPC status name each time the stream ends.
        self._on_received = on_received  # Called for each message that actually arrives, never for a retry.
        # Re-entrant: the owner may be closed from inside its own delivery.
        self._deliver_lock = threading.RLock()
        self._pending: Optional[Any] = None  # Newest update that could not be used yet.
        self._first = threading.Event()  # A usable SVID arrived, or retrying is pointless.
        self._usable = False
        self._stop = threading.Event()
        self._channel: Any = None
        self._thread = threading.Thread(target=self._run, name="tenuo-spiffe-workload-api", daemon=True)
        self._retry_timer: Optional[threading.Timer] = None
        self._retry_delay = _PENDING_RETRY[0]

    def start(self, timeout: float) -> bool:
        self._thread.start()
        deadline = time.monotonic() + timeout
        while not self._first.wait(min(0.5, max(0.0, deadline - time.monotonic()))):
            if time.monotonic() >= deadline:
                break
            self.retry_pending()  # For example an SVID that was not valid yet.
        return self._usable

    def stop(self, join: bool = True) -> None:
        # Wait out a delivery in progress, so nothing is installed once this returns.
        with self._deliver_lock:
            self._stop.set()
        timer = self._retry_timer
        if timer is not None:
            timer.cancel()
        channel = self._channel
        if channel is not None:
            channel.close()  # Cancels the stream the thread is reading.
        if join and self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)

    def _schedule_retry(self) -> None:
        """Try a waiting update again later, without relying on anyone to call reload."""
        if self._stop.is_set() or self._retry_timer is not None:
            return
        timer = threading.Timer(self._retry_delay, self._retry_tick)
        timer.args = (timer,)
        timer.daemon = True
        self._retry_timer = timer
        self._retry_delay = min(self._retry_delay * 2, _PENDING_RETRY[1])
        timer.start()

    def _retry_tick(self, timer: Optional[threading.Timer] = None) -> None:
        # One step under the delivery lock: a newer update arriving in the middle
        # could otherwise have its timer forgotten here and a second one started.
        with self._deliver_lock:
            if timer is not None and self._retry_timer is not timer:
                return  # Replaced by a newer update's timer, which does the retrying now.
            self._retry_timer = None
            if not self._stop.is_set():
                self.retry_pending()

    def _offer(self, snapshot: Any, retry: bool = False) -> bool:
        """Hand one update to the owner. Callers hold ``_deliver_lock``."""
        if self._stop.is_set():
            return False
        try:
            self._deliver(snapshot)
        except _OwnerGone:
            self._stop.set()
            return False
        except Exception as exc:  # Keep the current credentials and keep listening.
            if self._pending is not snapshot:
                # A new update: start the retry schedule over, including a wait already under way.
                self._retry_delay = _PENDING_RETRY[0]
                waiting, self._retry_timer = self._retry_timer, None
                if waiting is not None:
                    waiting.cancel()
            self._pending = snapshot
            self.last_error = str(exc)
            if not retry:
                logger.warning("Ignoring an unusable Workload API update: %s", exc)
            self._schedule_retry()
            return False
        self._pending = None
        self.last_error = None
        self._usable = True
        self._first.set()
        return True

    def _received(self) -> None:
        if self._on_received is not None and not self._stop.is_set():
            try:
                self._on_received()
            except _OwnerGone:
                self._stop.set()
            except Exception:
                logger.exception("Workload API message handler failed")

    def _lost(self, status: str) -> None:
        if self._on_lost is not None and not self._stop.is_set():
            try:
                self._on_lost(status)
            except _OwnerGone:
                self._stop.set()
            except Exception:
                logger.exception("Workload API stream-loss handler failed")

    def retry_pending(self) -> bool:
        """Try again an update that was refused earlier. Returns True if it is now in use."""
        with self._deliver_lock:
            return self._pending is not None and self._offer(self._pending, retry=True)

    def _run(self) -> None:
        import grpc

        delay = _WORKLOAD_API_BACKOFF[0]
        while not self._stop.is_set():
            # The endpoint is local: never send this traffic through an HTTP proxy.
            channel = self._channel = grpc.insecure_channel(self.target, options=[("grpc.enable_http_proxy", 0)])
            try:
                if self._stop.is_set():
                    break
                fetch = channel.unary_stream(
                    self._method, request_serializer=lambda _: b"", response_deserializer=lambda raw: raw
                )
                for message in fetch(None, metadata=_WORKLOAD_API_METADATA):
                    self._received()
                    try:
                        snapshot = self._parse(message)
                    except Exception as exc:
                        with self._deliver_lock:
                            # The newest response supersedes an older update that was
                            # waiting to become usable, even when it offers nothing.
                            self._pending = None
                        self.last_error = str(exc)
                        logger.warning("Ignoring an unusable Workload API update: %s", exc)
                        continue
                    with self._deliver_lock:
                        if self._offer(snapshot):
                            delay = _WORKLOAD_API_BACKOFF[0]
                self.last_error = "the Workload API closed the stream"
                self._lost("CLOSED")
            except grpc.RpcError as exc:
                if self._stop.is_set():
                    break
                code = exc.code()
                self.last_error = f"{code.name}: {exc.details()}"
                self._lost(code.name)
                unsupported = code in (grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.UNIMPLEMENTED)
                if unsupported and not self._usable:
                    # Not a Workload API endpoint: report at once instead of waiting out the timeout.
                    logger.error("The Workload API at %s rejected the request (%s)", self.target, self.last_error)
                    self._first.set()
                    break
            except Exception as exc:
                self.last_error = str(exc)
                self._lost("ERROR")
            finally:
                channel.close()
            if self._stop.is_set():
                break
            logger.warning(
                "Workload API stream at %s ended (%s); retrying in %.0f s", self.target, self.last_error, delay
            )
            self._stop.wait(delay)
            delay = _next_delay(delay, self._usable)


class _OwnerGone(Exception):
    """The SpiffeTLS that owned a watcher was garbage-collected."""


@dataclass(frozen=True)
class _Generation:
    context: ssl.SSLContext
    identity: SpiffeIdentity
    not_before: float
    authorities: FrozenSet[bytes]  # Every trusted authority, as DER.
    domains: Mapping[str, Tuple[x509.Certificate, ...]] = field(default_factory=dict)  # By trust domain.
    owners: Mapping[bytes, str] = field(default_factory=dict)  # Authority (DER) to its trust domain.


class SpiffeTLS:
    """Own TLS contexts and validate their peers as X.509-SVIDs.

    ``bundle_file`` must contain ONLY the configured trust domain's authorities.
    No system roots are loaded. The local SVID is validated at load time.

    Federation: to accept peers from other trust domains, give each domain's
    bundle separately (``federated_bundle_files``, or ``federates_with`` with the
    Workload API). The TLS handshake has to trust every accepted domain's
    authorities at once, so the per-domain decision is made after it: a peer's
    SVID belongs to the first bundle authority above it in the verified chain,
    and that authority must be in the bundle of the trust domain the SVID
    names. A federated domain whose bundle is missing, invalid, or shares an
    authority with another domain is not trusted; the home domain is unaffected.

    Credentials come from PEM files (this constructor) or straight from the
    SPIRE agent with :meth:`from_workload_api`, which follows renewals itself.
    With files, call :meth:`reload` (or :meth:`reload_if_changed`) after SPIRE or
    spiffe-helper writes new ones. On the server side ``context`` is a stable
    listener context: each new handshake switches to the newest credentials and
    trust bundle, so listeners never need to be rebuilt. On the client side,
    read ``context`` for each new connection. Connections made before a reload
    stay valid unless the reload removed an authority, in which case they are
    rejected and must reconnect.
    """

    _paths: Optional[Tuple[str, ...]]
    _signature: Tuple[Tuple[int, int, int, int], ...]

    def __init__(
        self,
        *,
        trust_domain: str,
        bundle_file: str,
        cert_file: str,
        key_file: str,
        server_side: bool,
        federated_bundle_files: Optional[Mapping[str, str]] = None,
    ):
        federated = dict(federated_bundle_files or {})
        self._init_common(trust_domain, server_side, tuple(federated))
        self._paths = (bundle_file, cert_file, key_file, *federated.values())
        self._signature = _file_signature(self._paths)
        self._install(self._build(self._read_files()))

    @classmethod
    def from_workload_api(
        cls,
        *,
        trust_domain: str,
        server_side: bool,
        socket_path: Optional[str] = None,
        spiffe_id: Optional[str] = None,
        timeout: float = 30.0,
        federates_with: Sequence[str] = (),
    ) -> "SpiffeTLS":
        """Take the SVID, key and bundle from the SPIRE agent's Workload API.

        Needs ``pip install 'tenuo[spiffe-workload-api]'``. ``socket_path`` is an
        absolute socket path, ``unix:///path`` or, for a loopback address only,
        ``tcp://IP:PORT`` (the Workload API is unencrypted); without it
        ``SPIFFE_ENDPOINT_SOCKET`` is used. If SPIRE offers this process several
        SVIDs, name the one to use with ``spiffe_id``; otherwise the first is
        used. Waits up to ``timeout`` seconds for a usable SVID, then follows
        renewals in a background thread until :meth:`close`. A lost stream is
        retried with backoff while the current credentials stay in use.

        ``federates_with`` names other trust domains whose workloads this one
        accepts. Their bundles come from the Workload API too, which offers
        them when the registration entry has ``-federatesWith``. A domain the
        response does not carry is not trusted.
        """
        try:
            import grpc  # noqa: F401
        except ImportError as exc:
            raise ImportError("The Workload API source requires pip install 'tenuo[spiffe-workload-api]'") from exc
        self = cls.__new__(cls)
        self._init_common(trust_domain, server_side, federates_with)
        domains = self._federates_with
        if spiffe_id is not None and _trust_domain(spiffe_id) != trust_domain:
            raise ValueError("spiffe_id is not in trust_domain")
        timeout = _seconds("timeout", timeout)
        owner = weakref.ref(self)

        def deliver(snapshot: _Snapshot) -> None:
            tls = owner()
            if tls is None:
                raise _OwnerGone
            generation = tls._build(snapshot)
            if spiffe_id is not None and generation.identity.spiffe_id != spiffe_id:
                raise SpiffeError(f"The Workload API returned a certificate for a different SPIFFE ID than {spiffe_id}")
            tls._install(generation)

        watcher = _WorkloadAPIWatcher(
            _workload_api_target(socket_path),
            _FETCH_X509_SVID,
            lambda raw: _x509_snapshot(raw, spiffe_id, domains),
            deliver,
        )
        self._watcher = watcher
        # Stop the thread if the instance is dropped without close().
        weakref.finalize(self, watcher.stop, False)
        if not watcher.start(timeout):
            watcher.stop()
            reason = watcher.last_error or "no response"
            raise SpiffeError(f"No usable SVID from the Workload API at {watcher.target}: {reason}")
        return self

    def _init_common(self, trust_domain: str, server_side: bool, federates_with: Sequence[str] = ()) -> None:
        self._federates_with = _trust_domain_names(trust_domain, federates_with)
        self.trust_domain = trust_domain
        self.server_side = server_side
        self._paths = None
        self._signature = ()
        self._watcher: Optional[_WorkloadAPIWatcher] = None
        self._lock = threading.Lock()
        self._reload_lock = threading.Lock()
        self._previous: "weakref.WeakKeyDictionary[ssl.SSLContext, FrozenSet[bytes]]" = weakref.WeakKeyDictionary()
        # Our own earlier contexts that trusted an authority since removed.
        self._retired: "weakref.WeakSet[ssl.SSLContext]" = weakref.WeakSet()
        self._generation: Optional[_Generation] = None
        self._front: Optional[ssl.SSLContext] = None
        if server_side:
            # Holds no credentials or trust anchors of its own: a handshake that
            # is not switched to a generation cannot complete.
            front = self._new_context()
            front.sni_callback = self._select_generation
            self._front = front

    def close(self) -> None:
        """Stop following the Workload API. Existing connections are unaffected."""
        if self._watcher is not None:
            self._watcher.stop()

    @property
    def _current(self) -> _Generation:
        generation = self._generation
        if generation is None:
            raise SpiffeError("No SVID has been loaded yet")
        return generation

    # -- contexts ---------------------------------------------------------

    def _new_context(self) -> ssl.SSLContext:
        protocol = ssl.PROTOCOL_TLS_SERVER if self.server_side else ssl.PROTOCOL_TLS_CLIENT
        context = ssl.SSLContext(protocol)
        context.check_hostname = False  # URI identity is checked in authenticate(), not DNS.
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Every certificate in a SPIFFE bundle is a trust anchor, self-signed or not,
        # so a chain ends at the first bundle authority it reaches.
        context.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0x80000)
        # A resumed session is not verified again, so it would outlive a reload
        # that removes its authority. Issue no tickets; authenticate() also
        # rejects any resumed session.
        context.options |= ssl.OP_NO_TICKET
        if self.server_side:
            try:
                context.num_tickets = 0
            except (AttributeError, NotImplementedError, ValueError):  # TLS library without TLS 1.3 tickets
                pass
        return context

    def _read_files(self) -> _Snapshot:
        assert self._paths is not None
        bundle_pem, cert_pem, key_pem = (_read_snapshot(path) for path in self._paths[:3])
        try:
            authorities = x509.load_pem_x509_certificates(bundle_pem)
            chain = x509.load_pem_x509_certificates(cert_pem)
        except Exception as exc:  # Not PEM, or a certificate the library refuses outright.
            raise SpiffeError("Trust bundle and certificate files must contain PEM certificates") from exc
        federated: Dict[str, List[x509.Certificate]] = {}
        for domain, path in zip(self._federates_with, self._paths[3:]):
            # A missing, empty or unreadable file means the domain is not trusted
            # for now. It never holds back the home domain's credentials.
            try:
                federated[domain] = x509.load_pem_x509_certificates(_read_snapshot(path))
            except Exception as exc:  # Whatever is wrong with it costs that domain only.
                logger.warning("Trust bundle for federated trust domain %s is unusable: %s", domain, exc)
        return _Snapshot(chain, key_pem, authorities, federated)

    def _build(self, snapshot: _Snapshot) -> _Generation:
        if not snapshot.chain or not snapshot.authorities:
            raise SpiffeError("An SVID and at least one authority are required")
        _check_authorities(snapshot.authorities, self.trust_domain)
        if not _anchored(snapshot.chain, snapshot.authorities):
            raise SpiffeError("Local SVID was not issued by an authority in the trust bundle delivered with it")
        domains: Dict[str, Tuple[x509.Certificate, ...]] = {self.trust_domain: tuple(snapshot.authorities)}
        for domain in self._federates_with:
            bundle = snapshot.federated.get(domain)
            if not bundle:
                continue
            # Whatever is wrong with a federated bundle costs that domain only.
            try:
                _check_authorities(bundle, domain)
                # The TLS library must accept it too, or it would fail the whole trust store below.
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=_pem(bundle).decode("ascii"))
            except Exception as exc:
                logger.warning("Trust bundle for federated trust domain %s is refused: %s", domain, exc)
                continue
            domains[domain] = tuple(bundle)
        # The intermediates sent with this workload's own SVID are home authorities
        # too, for this purpose: a federated certificate that imitates one would be
        # picked ahead of it when a home peer's chain is built.
        compared = {**domains, self.trust_domain: (*snapshot.authorities, *snapshot.chain[1:])}
        for domain in sorted(_overlapping_domains(compared, self.trust_domain)):
            logger.warning(
                "Trust bundle for federated trust domain %s is refused: it shares an authority with another domain",
                domain,
            )
            del domains[domain]
        trusted = [authority for bundle in domains.values() for authority in bundle]
        owners = {
            authority.public_bytes(Encoding.DER): domain for domain, bundle in domains.items() for authority in bundle
        }
        identity, not_before = _svid_identity(snapshot.chain[0], (self.trust_domain,))
        if not not_before <= time.time() < identity.expires_at:
            raise SpiffeError("Local SVID is not currently valid")
        context = self._new_context()
        # Trust exactly the certificates validated above, re-encoded.
        try:
            context.load_verify_locations(cadata=_pem(trusted).decode("ascii"))
        except ssl.SSLError as exc:
            raise SpiffeError("Trust bundle could not be loaded") from exc
        with _private_files(_pem(snapshot.chain), snapshot.key_pem) as (cert_path, key_path):
            try:
                context.load_cert_chain(cert_path, key_path)
            except ssl.SSLError as exc:
                raise SpiffeError("Local SVID certificate and key do not match") from exc
        der = frozenset(authority.public_bytes(Encoding.DER) for authority in trusted)
        return _Generation(context, identity, not_before, der, domains, owners)

    def _install(self, generation: _Generation) -> None:
        with self._lock:
            old = self._generation
            known = list(self._previous.items()) + ([(old.context, old.authorities)] if old is not None else [])
            # Generations whose authorities all remain are kept as they are. A
            # connection made under one that trusted an authority since removed
            # is accepted only if its peer is anchored in an authority still
            # trusted (see authenticate).
            # Retired first: authenticate reads these without the lock, and a
            # context must never be, even for a moment, in neither collection.
            for context, authorities in known:
                if not authorities <= generation.authorities:
                    self._retired.add(context)
            self._previous = weakref.WeakKeyDictionary(
                {context: authorities for context, authorities in known if authorities <= generation.authorities}
            )
            self._generation = generation
        logger.info(
            "Loaded SVID %s (expires %s)",
            generation.identity.spiffe_id,
            datetime.fromtimestamp(generation.identity.expires_at, timezone.utc).isoformat(),
        )
        missing = [domain for domain in self._federates_with if domain not in generation.domains]
        if missing:
            logger.warning("No trust bundle for federated trust domain(s) %s; their workloads are refused", missing)

    def _select_generation(self, connection: TLSConnection, server_name: Optional[str], _: ssl.SSLContext) -> None:
        connection.context = self._current.context

    @property
    def context(self) -> ssl.SSLContext:
        """Server: the stable listener context. Client: the newest context."""
        return self._front if self._front is not None else self._current.context

    @property
    def identity(self) -> SpiffeIdentity:
        """This workload's current SVID."""
        return self._current.identity

    def reload(self) -> None:
        """Load the credential files again. On failure, keep the current credentials.

        Does nothing with :meth:`from_workload_api`, where updates arrive on their own.
        """
        if self._paths is None:
            return
        with self._reload_lock:
            signature = _file_signature(self._paths)
            self._install(self._build(self._read_files()))
            self._signature = signature

    def reload_if_changed(self) -> bool:
        """Reload when any credential file changed. Cheap enough to call often.

        With :meth:`from_workload_api`, retries an update that was not usable
        when it arrived (for example an SVID that was not valid yet).
        """
        if self._paths is None:
            return self._watcher is not None and self._watcher.retry_pending()
        if _file_signature(self._paths) == self._signature:
            return False
        self.reload()
        return True

    def _refresh(self) -> None:
        """Best-effort rotation check used by the bundled server and client."""
        try:
            self.reload_if_changed()
        except Exception as exc:  # Never let a bad file stop later reloads.
            logger.warning("Could not reload SPIFFE credentials; keeping the current SVID: %s", exc)
        generation = self._current
        remaining = generation.identity.expires_at - time.time()
        if remaining < (generation.identity.expires_at - generation.not_before) / 5:
            logger.warning(
                "Local SVID %s expires in %d s and has not been renewed",
                generation.identity.spiffe_id,
                max(0, int(remaining)),
            )

    def _accepts(self, context: ssl.SSLContext) -> bool:
        return context is self._current.context or context in self._previous or context in self._retired

    # -- authentication ----------------------------------------------------

    def authenticate(self, connection: TLSConnection, *, expected_id: Optional[str] = None) -> SpiffeIdentity:
        """Authenticate a completed TLS connection. Clients must pin a server ID."""
        if not isinstance(connection, (ssl.SSLSocket, ssl.SSLObject)):
            raise SpiffeError("A live TLS connection is required")
        context = connection.context
        if (
            not self._accepts(context)
            or connection.server_side != self.server_side
            or context.verify_mode != ssl.CERT_REQUIRED
            or (self._front is not None and self._front.verify_mode != ssl.CERT_REQUIRED)
            or connection.version() is None
        ):
            raise SpiffeError("Connection was not verified by this SPIFFE TLS context")
        if connection.session_reused:
            raise SpiffeError("Resumed TLS sessions are not accepted; open a new connection")
        if not self.server_side and expected_id is None:
            raise SpiffeError("Clients must specify the expected server SPIFFE ID")
        der = connection.getpeercert(binary_form=True)
        if not der:
            raise SpiffeError("Missing peer SVID")
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError as exc:
            raise SpiffeError("Malformed X.509-SVID") from exc
        identity, not_before = _svid_identity(cert, (self.trust_domain, *self._federates_with))
        if context in self._retired:
            # The handshake ran under a bundle that has since lost an authority,
            # for example a connection that was being set up while the update
            # arrived. It stands only if the peer is anchored in an authority
            # that is still trusted.
            try:
                self._check_domain_binding(connection, cert, identity.trust_domain)
            except SpiffeError:
                raise SpiffeError(
                    "Connection was verified by an authority that is no longer trusted; open a new connection"
                ) from None
        elif self._federates_with:
            self._check_domain_binding(connection, cert, identity.trust_domain)
        if expected_id is not None and identity.spiffe_id != expected_id:
            raise SpiffeError("Unexpected peer SPIFFE ID")
        if not not_before <= time.time() < identity.expires_at:
            raise SpiffeError("SVID is not currently valid")
        return identity

    def _check_domain_binding(self, connection: TLSConnection, cert: x509.Certificate, trust_domain: str) -> None:
        """With several bundles trusted, tie the peer's SVID to its own trust domain's bundle.

        The TLS handshake only proves the chain ends at *some* trusted authority.
        Without this check an authority of one domain could issue an SVID that
        names another domain.
        """
        generation = self._current  # The newest bundles, not the ones the handshake saw.
        authorities = generation.domains.get(trust_domain)
        if not authorities:
            raise SpiffeError(f"No trust bundle is loaded for trust domain {trust_domain}")
        chain = _verified_chain(connection)
        if chain is not None:
            # The SVID belongs to the first bundle authority above it, whatever
            # that authority itself chains to.
            for certificate in chain[1:]:
                owner = generation.owners.get(certificate)
                if owner is not None:
                    if owner == trust_domain:
                        return
                    break
            raise SpiffeError("SVID was not issued by its own trust domain's authorities")
        # This Python does not expose the verified chain: accept only an SVID
        # signed directly by one of its trust domain's authorities.
        for authority in authorities:
            try:
                cert.verify_directly_issued_by(authority)
                return
            except Exception:
                continue
        raise SpiffeError(
            "SVID was not issued directly by its own trust domain's authorities "
            "(with federation, SVID chains through intermediate CAs need Python 3.10 or newer)"
        )


# -- issuance ---------------------------------------------------------------


@dataclass(frozen=True)
class SpiffeGrant:
    """Server policy output.

    ``capabilities`` maps each tool to its argument constraints. Use
    :data:`ANY_ARGUMENTS` to allow any arguments; an empty dict is rejected.
    ``task_id`` supplied to the policy is an untrusted lookup key, not proof of
    user consent. Resolve it against trusted task records and check ownership.
    """

    capabilities: Mapping[str, Mapping[str, Any]]
    ttl_seconds: int = 300
    max_depth: int = 0


@dataclass(frozen=True)
class SpiffeHolderProof:
    """A holder key's signed statement for one single-request exchange.

    Build it with :func:`tenuo.spiffe_jwt.sign_jwt_holder_proof` or
    :func:`tenuo.spiffe_forwarded.sign_forwarded_holder_proof`.
    """

    timestamp: int
    nonce: bytes
    signature: bytes


SpiffeJWTProof = SpiffeHolderProof


@dataclass(frozen=True)
class SpiffeIssuance:
    """Audit record passed to the issuer's ``audit`` callback before release."""

    identity: SpiffeIdentity
    task_id: str
    holder: str
    warrant_id: str
    expires_at: str
    tools: Tuple[str, ...]


@dataclass(frozen=True)
class _Pending:
    identity: SpiffeIdentity
    holder: bytes
    task_id: str
    grant: SpiffeGrant
    deadline: float


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _seconds(name: str, value: Any) -> float:
    """A positive, finite number of seconds. NaN and infinity would switch a limit off without saying so."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return float(value)


def _validate_grant(grant: Any) -> SpiffeGrant:
    if not isinstance(grant, SpiffeGrant):
        raise SpiffeError("Policy must return a SpiffeGrant or None")
    if not isinstance(grant.capabilities, Mapping) or not grant.capabilities:
        raise SpiffeError("Policy must provide capabilities and a positive integer TTL")
    for tool, constraints in grant.capabilities.items():
        if not isinstance(tool, str) or not tool or len(tool) > _MAX_TOOL_NAME:
            raise SpiffeError("Grant tool names must be non-empty strings")
        if not isinstance(constraints, Mapping):
            raise SpiffeError(f"Constraints for {tool!r} must be a mapping")
        if not constraints and constraints is not ANY_ARGUMENTS:
            raise SpiffeError(f"Empty constraints for {tool!r}; use ANY_ARGUMENTS to allow any arguments")
    if not _positive_int(grant.ttl_seconds) or grant.ttl_seconds < 1:
        raise SpiffeError("Policy must provide capabilities and a positive integer TTL")
    if not _positive_int(grant.max_depth) or not 0 <= grant.max_depth <= _MAX_DELEGATION_DEPTH:
        raise SpiffeError(f"max_depth must be an integer from 0 to {_MAX_DELEGATION_DEPTH}")
    # Copy, so later changes to a policy's cached objects cannot alter the grant.
    # The core checks constraint values when it mints, so do a trial mint with a
    # validation key now rather than discovering a bad grant after the proof.
    capabilities = {tool: dict(constraints) for tool, constraints in grant.capabilities.items()}
    try:
        builder = Warrant.mint_builder().holder(_VALIDATION_KEY.public_key).ttl(1).max_depth(grant.max_depth)
        for tool, constraints in capabilities.items():
            builder.capability(tool, dict(constraints))
        builder.mint(_VALIDATION_KEY)
    except Exception as exc:
        raise SpiffeError(f"Policy grant has invalid constraints: {exc}") from exc
    return SpiffeGrant(MappingProxyType(capabilities), grant.ttl_seconds, grant.max_depth)


class SpiffeWarrantIssuer:
    """Exchange authenticated workload identity + holder proof for a warrant.

    ``policy(identity, task_id)`` returns a grant or None (deny). It runs once,
    when the challenge is requested, so denied workloads never hold a challenge
    slot; the grant is used if a valid proof arrives within 30 seconds.
    Challenges are single-use and local to this issuer process: route both
    exchange steps to the same instance. ``max_pending_per_identity`` stops one
    workload from exhausting ``max_pending``. ``audit`` receives every issuance
    before the warrant is released; if it raises, the warrant is not released.

    With ``jwt=`` (a :class:`tenuo.spiffe_jwt.SpiffeJWT`) the issuer also, or
    instead, accepts JWT-SVIDs through :meth:`issue_jwt`. It remembers up to
    ``max_jwt_proofs`` recent holder proofs (each for about a minute) to refuse
    exact replays, and asks callers to retry when that memory is full. One
    SPIFFE ID may hold at most ``max_jwt_proofs_per_identity`` of them (a
    quarter by default), so one busy workload cannot keep the others out.
    """

    def __init__(
        self,
        *,
        tls: Optional[SpiffeTLS] = None,
        signing_key: SigningKey,
        policy: Callable[[SpiffeIdentity, str], Optional[SpiffeGrant]],
        max_pending: int = 1024,
        max_pending_per_identity: int = 16,
        audit: Optional[Callable[[SpiffeIssuance], None]] = None,
        jwt: Optional[Any] = None,
        max_jwt_proofs: int = _JWT_PROOF_MEMORY,
        forwarded: Optional[Any] = None,
        max_jwt_proofs_per_identity: Optional[int] = None,
    ):
        if tls is None and jwt is None and forwarded is None:
            raise ValueError(
                "Pass tls (X.509-SVIDs over mTLS), jwt (JWT-SVIDs), forwarded (identity from a trusted proxy), or several"
            )
        if tls is not None and not tls.server_side:
            raise ValueError("Issuance requires a server-side SPIFFE TLS context")
        for name, value in (
            ("max_pending", max_pending),
            ("max_pending_per_identity", max_pending_per_identity),
            ("max_jwt_proofs", max_jwt_proofs),
        ):
            if not _positive_int(value) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_jwt_proofs_per_identity is None:
            max_jwt_proofs_per_identity = max(1, max_jwt_proofs // 4)
        if not _positive_int(max_jwt_proofs_per_identity) or not 1 <= max_jwt_proofs_per_identity <= max_jwt_proofs:
            raise ValueError("max_jwt_proofs_per_identity must be a positive integer, at most max_jwt_proofs")
        self._max_jwt_proofs = max_jwt_proofs
        self._max_jwt_proofs_per_identity = max_jwt_proofs_per_identity
        self.tls = tls
        self.jwt = jwt  # A tenuo.spiffe_jwt.SpiffeJWT, or None.
        self.forwarded = forwarded  # A tenuo.spiffe_forwarded.SpiffeForwardedIdentity, or None.
        # Each remembered proof: the wall-clock time until which its timestamp stays
        # acceptable, and whose it is. The heap orders them by that time; an entry
        # dropped early (a failed request) stays in the heap until it is skipped.
        self._proofs: Dict[bytes, Tuple[float, str]] = {}
        self._proof_order: List[Tuple[float, bytes]] = []
        self._proofs_held: Dict[str, int] = {}
        self._proofs_forgotten_to = float("-inf")  # Proofs acceptable no later than this have been forgotten.
        self._key = signing_key
        self._issuer_hex = bytes(signing_key.public_key.to_bytes()).hex()
        self._policy = policy
        self._audit = audit
        self._max_pending = max_pending
        self._max_per_identity = max_pending_per_identity
        self._pending: Dict[bytes, _Pending] = {}
        self._lock = threading.Lock()

    def challenge(self, connection: TLSConnection, holder: PublicKey, task_id: str) -> bytes:
        """Return a challenge for the holder to sign with :func:`sign_holder_challenge`."""
        return self._challenge(self._mtls().authenticate(connection), holder, task_id)

    def issue(self, connection: TLSConnection, challenge: bytes, signature: bytes) -> Warrant:
        """Consume a challenge, verify holder possession, and mint the approved grant."""
        return self._issue(self._mtls().authenticate(connection), challenge, signature)

    def issue_jwt(self, token: str, holder: PublicKey, task_id: str, proof: SpiffeHolderProof) -> Warrant:
        """Authenticate a JWT-SVID, verify the holder proof, run policy, and mint.

        ``proof`` comes from :func:`tenuo.spiffe_jwt.sign_jwt_holder_proof`. A
        JWT-SVID is a bearer token: send it only over TLS, and prefer the mTLS
        exchange where you can.
        """
        if self.jwt is None:
            raise SpiffeError("This issuer does not accept JWT-SVIDs")
        return self._issue_jwt(self.jwt.authenticate(token), holder, task_id, proof)

    def _mtls(self) -> SpiffeTLS:
        if self.tls is None:
            raise SpiffeError("This issuer does not accept X.509-SVIDs")
        return self.tls

    def _issue_jwt(
        self, identity: SpiffeIdentity, holder: PublicKey, task_id: str, proof: SpiffeHolderProof
    ) -> Warrant:
        if self.jwt is None or identity.svid_type != "jwt":
            raise SpiffeError("This issuer does not accept JWT-SVIDs")
        audience, token = self.jwt.audience, bytes.fromhex(identity.certificate_sha256)
        return self._issue_with_proof(
            identity,
            holder,
            task_id,
            proof,
            lambda key, timestamp, nonce: _jwt_proof_bytes(audience, key, task_id, timestamp, nonce, token),
        )

    def issue_forwarded(
        self, header: str, peer: Optional[str], holder: PublicKey, task_id: str, proof: SpiffeHolderProof
    ) -> Warrant:
        """Accept the identity a trusted proxy forwarded, verify the holder proof, run policy, and mint.

        ``header`` is the ``x-forwarded-client-cert`` value and ``peer`` the
        address the request arrived from, as the socket reports it. The issuer
        cannot verify this identity itself: it is exactly as trustworthy as the
        proxy and the path from the proxy to this process. See
        :class:`tenuo.spiffe_forwarded.SpiffeForwardedIdentity`.
        """
        if self.forwarded is None:
            raise SpiffeError("This issuer does not accept proxy-forwarded identities")
        return self._issue_forwarded(self.forwarded.authenticate(header, peer=peer), holder, task_id, proof)

    def _issue_forwarded(
        self, identity: SpiffeIdentity, holder: PublicKey, task_id: str, proof: SpiffeHolderProof
    ) -> Warrant:
        if self.forwarded is None or identity.svid_type != "forwarded":
            raise SpiffeError("This issuer does not accept proxy-forwarded identities")
        audience = self.forwarded.audience
        return self._issue_with_proof(
            identity,
            holder,
            task_id,
            proof,
            lambda key, timestamp, nonce: _forwarded_proof_bytes(audience, key, task_id, timestamp, nonce),
        )

    def _issue_with_proof(
        self,
        identity: SpiffeIdentity,
        holder: PublicKey,
        task_id: str,
        proof: SpiffeHolderProof,
        statement: Callable[[bytes, int, bytes], bytes],
    ) -> Warrant:
        """The single-request exchange: check the holder's signed statement, then policy, then mint."""
        if not isinstance(task_id, str) or not task_id or len(task_id) > _MAX_TASK_ID:
            raise SpiffeError(f"task_id must contain 1–{_MAX_TASK_ID} characters")
        if not isinstance(holder, PublicKey):
            raise SpiffeError("holder must be a Tenuo PublicKey")
        if not isinstance(proof, SpiffeHolderProof):
            raise SpiffeError("Invalid holder proof")
        timestamp, nonce, signature = proof.timestamp, proof.nonce, proof.signature
        if (
            not _positive_int(timestamp)
            or not 0 <= timestamp < 2**40
            or abs(time.time() - timestamp) > _JWT_PROOF_SECONDS
        ):
            raise SpiffeError("Holder proof is too old or from the future; check the clocks on both sides")
        if (
            not isinstance(nonce, bytes)
            or len(nonce) != _JWT_NONCE_BYTES
            or not isinstance(signature, bytes)
            or len(signature) != 64
        ):
            raise SpiffeError("Invalid holder proof")
        key = bytes(holder.to_bytes())
        message = statement(key, timestamp, nonce)
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        except (InvalidSignature, ValueError) as exc:
            raise SpiffeError("Invalid holder proof") from exc
        # Refuse an exact replay seen by this process. The proof is reserved
        # while the request runs and kept only if a warrant is issued, so a
        # denied or failed request leaves nothing behind and can be retried.
        # It is remembered until the wall clock passes the last moment its
        # timestamp is acceptable: the same clock that judges freshness above.
        # A live entry is never dropped to make room: when the memory is full,
        # or this workload holds its share, new requests wait their turn instead.
        spiffe_id = identity.spiffe_id
        keep_until = float(timestamp + _JWT_PROOF_SECONDS + 1)
        with self._lock:
            self._forget_old_proofs()
            if keep_until <= self._proofs_forgotten_to:
                # Had this proof been used, it would be forgotten by now. That only
                # happens to a timestamp that passed the check above when the clock
                # has been set back, so it cannot be told from a replay.
                raise SpiffeError("Holder proof is too old or from the future; check the clocks on both sides")
            if signature in self._proofs:
                raise SpiffeError("This holder proof was already used; sign a new one")
            if len(self._proofs) >= self._max_jwt_proofs:
                raise _IssuerBusy("Issuer is at its limit for recent single-request exchanges; retry shortly")
            if self._proofs_held.get(spiffe_id, 0) >= self._max_jwt_proofs_per_identity:
                raise _IssuerBusy("This workload is at its limit for recent single-request exchanges; retry shortly")
            self._proofs[signature] = (keep_until, spiffe_id)
            self._proofs_held[spiffe_id] = self._proofs_held.get(spiffe_id, 0) + 1
            heapq.heappush(self._proof_order, (keep_until, signature))
        try:
            grant = self._policy(identity, task_id)
            if grant is None:
                raise SpiffeError("Workload is not authorized for this task")
            try:
                grant = _validate_grant(grant)
            except SpiffeError as exc:
                logger.warning("Invalid policy grant for %s task %r: %s", identity.spiffe_id, task_id, exc)
                raise
            return self._mint(identity, key, task_id, grant)
        except BaseException:
            with self._lock:
                self._forget_proof(signature)
            raise

    def _forget_proof(self, signature: bytes) -> None:
        """Drop one remembered proof. Call with the lock held."""
        entry = self._proofs.pop(signature, None)
        if entry is None:
            return
        held = self._proofs_held[entry[1]] - 1
        if held:
            self._proofs_held[entry[1]] = held
        else:
            del self._proofs_held[entry[1]]

    def _forget_old_proofs(self) -> None:
        """Drop the proofs whose timestamps are no longer acceptable. Call with the lock held."""
        now, order = time.time(), self._proof_order
        self._proofs_forgotten_to = max(self._proofs_forgotten_to, now)
        while order and order[0][0] <= now:
            until, signature = heapq.heappop(order)
            entry = self._proofs.get(signature)
            if entry is not None and entry[0] == until:
                self._forget_proof(signature)
        # Entries of failed requests are skipped above only when their time comes.
        # Rebuild before they outnumber the live ones by much.
        if len(order) > 2 * len(self._proofs) + 1024:
            self._proof_order = [(until, signature) for signature, (until, _) in self._proofs.items()]
            heapq.heapify(self._proof_order)

    def _challenge(self, identity: SpiffeIdentity, holder: PublicKey, task_id: str) -> bytes:
        if not isinstance(task_id, str) or not task_id or len(task_id) > _MAX_TASK_ID:
            raise SpiffeError(f"task_id must contain 1–{_MAX_TASK_ID} characters")
        if not isinstance(holder, PublicKey):
            raise SpiffeError("holder must be a Tenuo PublicKey")
        grant = self._policy(identity, task_id)
        if grant is None:
            raise SpiffeError("Workload is not authorized for this task")
        try:
            grant = _validate_grant(grant)
        except SpiffeError as exc:
            logger.warning("Invalid policy grant for %s task %r: %s", identity.spiffe_id, task_id, exc)
            raise
        key = bytes(holder.to_bytes())
        payload = json.dumps(
            {
                "nonce": secrets.token_hex(32),
                "issuer": self._issuer_hex,
                "spiffe_id": identity.spiffe_id,
                "certificate": identity.certificate_sha256,
                "holder": key.hex(),
                "task_id": task_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        now = time.monotonic()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v.deadline > now}
            if len(self._pending) >= self._max_pending:
                raise SpiffeError("Too many pending holder challenges")
            if (
                sum(p.identity.spiffe_id == identity.spiffe_id for p in self._pending.values())
                >= self._max_per_identity
            ):
                raise SpiffeError("Too many pending holder challenges for this workload")
            self._pending[payload] = _Pending(identity, key, task_id, grant, now + _CHALLENGE_SECONDS)
        return payload

    def _issue(self, identity: SpiffeIdentity, challenge: bytes, signature: bytes) -> Warrant:
        if not isinstance(challenge, bytes):
            raise SpiffeError("Unknown, expired, or already consumed holder challenge")
        with self._lock:
            pending = self._pending.pop(challenge, None)
        if pending is None or pending.deadline <= time.monotonic():
            raise SpiffeError("Unknown, expired, or already consumed holder challenge")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise SpiffeError("Invalid holder proof")
        if identity != pending.identity:
            raise SpiffeError("Holder challenge belongs to a different SVID")
        try:
            Ed25519PublicKey.from_public_bytes(pending.holder).verify(signature, _HOLDER_CONTEXT + challenge)
        except (InvalidSignature, ValueError) as exc:
            raise SpiffeError("Invalid holder proof") from exc
        return self._mint(identity, pending.holder, pending.task_id, pending.grant)

    def _mint(self, identity: SpiffeIdentity, holder: bytes, task_id: str, grant: SpiffeGrant) -> Warrant:
        """Mint a validated grant for a proven holder key, bounded by the SVID's expiry."""
        ttl = min(grant.ttl_seconds, int(identity.expires_at - time.time()) - 1)
        if ttl < 1:
            raise SpiffeError("SVID expires too soon to issue a warrant")
        builder = Warrant.mint_builder().holder(PublicKey.from_bytes(holder)).ttl(ttl).max_depth(grant.max_depth)
        for tool, constraints in grant.capabilities.items():
            builder.capability(tool, dict(constraints))
        warrant = builder.mint(self._key)
        if datetime.fromisoformat(warrant.expires_at()).timestamp() > identity.expires_at:
            raise SpiffeError("Warrant would outlive the authenticated SVID")
        record = SpiffeIssuance(
            identity, task_id, holder.hex(), warrant.id, warrant.expires_at(), tuple(grant.capabilities)
        )
        if self._audit is not None:
            self._audit(record)
        logger.info("Issued warrant %s to %s for task %r", warrant.id, identity.spiffe_id, task_id)
        return warrant

    def _discard(self, challenge: Optional[bytes]) -> None:
        if challenge is not None:
            with self._lock:
                self._pending.pop(challenge, None)


# -- holder side ------------------------------------------------------------


def sign_holder_challenge(
    challenge: bytes,
    holder_key: SigningKey,
    *,
    task_id: str,
    issuer_key: Optional[IssuerKeys] = None,
    spiffe_id: Optional[str] = None,
) -> bytes:
    """Check an issuer challenge and sign it with the holder key.

    Refuses anything that is not a challenge for this holder key and task (and,
    when given, this issuer key and SPIFFE ID). Never sign challenges with
    ``sign_raw`` directly.
    """
    if not isinstance(challenge, bytes) or len(challenge) > _MAX_CHALLENGE_BYTES:
        raise SpiffeError("Invalid holder challenge")
    try:
        fields = json.loads(challenge.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SpiffeError("Invalid holder challenge") from exc
    if (
        not isinstance(fields, dict)
        or set(fields) != _CHALLENGE_FIELDS
        or not all(isinstance(value, str) for value in fields.values())
        or json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8") != challenge
        or not re.fullmatch(r"[0-9a-f]{64}", fields["nonce"])
    ):
        raise SpiffeError("Invalid holder challenge")
    if fields["holder"] != bytes(holder_key.public_key.to_bytes()).hex():
        raise SpiffeError("Challenge is for a different holder key")
    if fields["task_id"] != task_id:
        raise SpiffeError("Challenge is for a different task")
    if issuer_key is not None and fields["issuer"] not in {bytes(k.to_bytes()).hex() for k in _key_list(issuer_key)}:
        raise SpiffeError("Challenge is from a different issuer key")
    if spiffe_id is not None and fields["spiffe_id"] != spiffe_id:
        raise SpiffeError("Challenge is for a different SPIFFE ID")
    return bytes(holder_key.sign_raw(_HOLDER_CONTEXT + challenge))


def _key_list(keys: IssuerKeys) -> List[PublicKey]:
    found = [keys] if isinstance(keys, PublicKey) else list(keys)
    if not found or not all(isinstance(key, PublicKey) for key in found):
        raise ValueError("issuer_key must be a PublicKey or a non-empty sequence of them")
    return found


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(value: Any, *, limit: int = _FRAME_LIMIT) -> bytes:
    if not isinstance(value, str) or len(value) > limit:
        raise SpiffeError("Invalid request")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SpiffeError("Invalid request") from exc


def _frame(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"


def _parse_frame(line: bytes, keys: FrozenSet[str]) -> Dict[str, Any]:
    if not line:
        raise SpiffeError("Connection closed before a reply")
    if not line.endswith(b"\n") or len(line) > _FRAME_LIMIT:
        raise SpiffeError("Invalid or oversized frame")
    try:
        value = json.loads(line)
    except (ValueError, RecursionError) as exc:
        raise SpiffeError("Invalid frame") from exc
    if not isinstance(value, dict):
        raise SpiffeError("Invalid frame")
    if "error" in value:
        if value["error"] == "unavailable":
            raise SpiffeError("Issuer error; see the issuer's log")
        message = value.get("message")
        raise SpiffeError(f"Issuer refused: {str(message)[:200] if message else value['error']}")
    if set(value) != keys:
        raise SpiffeError("Unexpected frame")
    return value


def _exchange_with_issuer(
    tls: SpiffeTLS,
    address: Tuple[str, int],
    issuer_id: str,
    issuer_key: IssuerKeys,
    holder_key: SigningKey,
    task_id: str,
    timeout: float,
) -> Any:
    with socket.create_connection(address, timeout=timeout) as raw:
        raw.settimeout(timeout)
        with tls.context.wrap_socket(raw) as connection, connection.makefile("rwb") as stream:
            tls.authenticate(connection, expected_id=issuer_id)
            holder = _encode(bytes(holder_key.public_key.to_bytes()))
            stream.write(_frame({"v": _PROTOCOL_VERSION, "holder": holder, "task": task_id}))
            stream.flush()
            challenge = _decode(_parse_frame(stream.readline(_FRAME_LIMIT + 1), frozenset({"challenge"}))["challenge"])
            signature = sign_holder_challenge(
                challenge, holder_key, task_id=task_id, issuer_key=issuer_key, spiffe_id=tls.identity.spiffe_id
            )
            stream.write(_frame({"signature": _encode(signature)}))
            stream.flush()
            return _parse_frame(stream.readline(_FRAME_LIMIT + 1), frozenset({"warrant"}))["warrant"]


def request_warrant(
    tls: SpiffeTLS,
    address: Tuple[str, int],
    *,
    issuer_id: str,
    issuer_key: IssuerKeys,
    holder_key: SigningKey,
    task_id: str,
    timeout: float = 10.0,
) -> Warrant:
    """Obtain a warrant from a :class:`SpiffeIssuerServer`.

    Pins the issuer's SPIFFE ID before sending anything, signs only a valid
    challenge for this holder and task, and checks that the warrant is signed
    by ``issuer_key``, bound to ``holder_key``, and unexpired. ``issuer_key``
    may be a list, to accept the old and new key during rotation. Every failure,
    including connection and TLS errors, is raised as :class:`SpiffeError`.
    """
    if tls.server_side:
        raise ValueError("request_warrant requires a client-side SpiffeTLS")
    trusted = _key_list(issuer_key)
    _trust_domain(issuer_id)
    timeout = _seconds("timeout", timeout)
    tls._refresh()
    where = f"{address[0]}:{address[1]}"
    try:
        encoded = _exchange_with_issuer(tls, address, issuer_id, issuer_key, holder_key, task_id, timeout)
    except SpiffeError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise SpiffeError(f"The SVID presented by {where} was not accepted: {exc.verify_message}") from exc
    except ssl.SSLError as exc:
        raise SpiffeError(f"TLS with the issuer at {where} failed: {exc.reason or exc}") from exc
    except OSError as exc:  # Refused, reset, or timed out.
        raise SpiffeError(f"Could not complete the exchange with the issuer at {where}: {exc}") from exc
    return _checked_warrant(encoded, trusted, holder_key)


def _checked_warrant(encoded: Any, trusted: List[PublicKey], holder_key: SigningKey) -> Warrant:
    """Accept an issuer's reply only if it is a current warrant from a trusted key for this holder."""
    if not isinstance(encoded, str):
        raise SpiffeError("Invalid warrant response")
    try:
        warrant = Warrant.from_base64(encoded)
        Authorizer(trusted_roots=trusted).verify(warrant)
    except Exception as exc:
        raise SpiffeError("Issued warrant failed verification") from exc
    if warrant.authorized_holder != holder_key.public_key:
        raise SpiffeError("Issued warrant is bound to a different holder")
    return warrant


async def arequest_warrant(tls: SpiffeTLS, address: Tuple[str, int], **kwargs: Any) -> Warrant:
    """Async wrapper for :func:`request_warrant` (runs in a worker thread)."""
    return await asyncio.to_thread(request_warrant, tls, address, **kwargs)


# -- bundled issuance endpoint ----------------------------------------------


class _ServerConnection:
    """TLS over an accepted TCP stream.

    The server drives TLS itself (rather than handing the socket to asyncio's
    TLS transport) so that the connection cap, the deadline, and the byte limit
    all apply from accept, before a peer has completed a handshake.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, context: ssl.SSLContext):
        self._incoming, self._outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self._reader, self._writer = reader, writer
        self._buffer = bytearray()
        self._received = 0

    async def _flush(self) -> None:
        data = self._outgoing.read()
        if data:
            self._writer.write(data)
            await self._writer.drain()

    async def _run(self, operation: Callable[..., Any], *args: Any) -> Any:
        while True:
            try:
                result = operation(*args)
            except ssl.SSLWantReadError:
                await self._flush()
                data = await self._reader.read(16384)
                if not data:
                    raise ConnectionError("Peer closed the connection")
                self._received += len(data)
                if self._received > _CONNECTION_BYTE_LIMIT:
                    raise ConnectionError("Peer sent too much data")
                self._incoming.write(data)
            else:
                await self._flush()
                return result

    async def handshake(self) -> None:
        await self._run(self.tls.do_handshake)

    async def readline(self) -> bytes:
        while b"\n" not in self._buffer:
            if len(self._buffer) > _FRAME_LIMIT:
                raise SpiffeError("Invalid or oversized frame")
            try:
                chunk = await self._run(self.tls.read, 16384)
            except ssl.SSLZeroReturnError:
                chunk = b""
            if not chunk:
                raise ConnectionError("Peer closed the connection")
            self._buffer += chunk
        end = self._buffer.index(b"\n") + 1
        line = bytes(self._buffer[:end])
        del self._buffer[:end]
        return line

    async def send(self, value: Dict[str, Any]) -> None:
        await self._run(self.tls.write, _frame(value))

    async def close(self) -> None:
        try:
            self.tls.unwrap()  # Queue close_notify; do not wait for the peer's.
        except (ssl.SSLError, ValueError):
            pass
        try:
            await self._flush()  # Also delivers a pending handshake alert.
        except (ConnectionError, OSError):
            pass
        self._writer.close()


class _CallbackFailed(Exception):
    """A policy or audit callback raised. The cause is chained."""


def _consume_result(work: "asyncio.Future[Any]") -> None:
    """Retrieve a shielded result nobody awaited, so it is not logged as unhandled."""
    if not work.cancelled():
        work.exception()


class SpiffeIssuerServer:
    """Asyncio mTLS endpoint for :class:`SpiffeWarrantIssuer`.

    One exchange per connection, newline-delimited JSON frames of at most
    64 KiB, and a deadline (``timeout``) that covers the TLS handshake and the
    exchange. ``max_connections`` counts every accepted socket, including ones
    that have not completed a handshake. Credentials are reloaded from disk
    every ``reload_interval`` seconds. Policy and audit callbacks run in up to
    ``max_workers`` threads, with at most ``max_connections`` submitted or
    queued at once; a callback that has been submitted when the deadline
    passes still runs to completion in its thread, so ``audit`` can record a
    warrant the agent never received.

    Example::

        async with SpiffeIssuerServer(issuer, host="0.0.0.0", port=8443) as server:
            await server.serve_forever()
    """

    def __init__(
        self,
        issuer: SpiffeWarrantIssuer,
        *,
        host: str,
        port: int,
        max_connections: int = 256,
        timeout: float = 10.0,
        reload_interval: float = 30.0,
        max_workers: int = 32,
    ):
        for name, value in (("max_connections", max_connections), ("max_workers", max_workers)):
            if not _positive_int(value) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        timeout, reload_interval = _seconds("timeout", timeout), _seconds("reload_interval", reload_interval)
        if issuer.tls is None:
            raise ValueError("SpiffeIssuerServer needs an issuer built with tls=; for JWT-SVIDs use SpiffeJWTIssuerApp")
        self._tls: SpiffeTLS = issuer.tls
        self.issuer = issuer
        self.host, self.port = host, port
        self._max_connections = max_connections
        self._max_workers = max_workers
        self._timeout = timeout
        self._reload_interval = reload_interval
        self._active = 0
        self._tasks: Set["asyncio.Task[Any]"] = set()
        self._server: Optional[asyncio.AbstractServer] = None
        self._reloader: Optional["asyncio.Future[None]"] = None
        self._workers: Optional[ThreadPoolExecutor] = None
        self._reload_worker: Optional[ThreadPoolExecutor] = None
        self._work_slots: Optional[asyncio.Semaphore] = None

    @property
    def address(self) -> Tuple[str, int]:
        """The bound (host, port); useful with ``port=0``."""
        if self._server is None:
            raise RuntimeError("Server is not started")
        sockets = getattr(self._server, "sockets", None) or []
        return sockets[0].getsockname()[:2]

    async def start(self) -> None:
        # Separate pools: a policy stuck on a slow database cannot delay rotation.
        self._workers = ThreadPoolExecutor(self._max_workers, thread_name_prefix="tenuo-spiffe-policy")
        self._reload_worker = ThreadPoolExecutor(1, thread_name_prefix="tenuo-spiffe-reload")
        # An exchange submits at most one callback at a time, so bounding
        # submissions by `max_connections` caps the pool's queue without
        # refusing work any accepted connection could legitimately need.
        self._work_slots = asyncio.Semaphore(self._max_connections)
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self._reloader = asyncio.ensure_future(self._reload_loop())
        host, port = self.address
        logger.info("Issuing warrants on %s:%s as %s", host, port, self._tls.identity.spiffe_id)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        await self._server.serve_forever()

    async def close(self) -> None:
        if self._reloader is not None:
            self._reloader.cancel()
            self._reloader = None
        if self._server is not None:
            self._server.close()
            for task in list(self._tasks):
                task.cancel()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            await self._server.wait_closed()
            self._server = None
        for pool in (self._workers, self._reload_worker):
            if pool is not None:
                pool.shutdown(wait=False)
        self._workers = self._reload_worker = None
        self._work_slots = None

    async def __aenter__(self) -> "SpiffeIssuerServer":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def _reload_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(self._reload_interval)
            try:
                await loop.run_in_executor(self._reload_worker, self._tls._refresh)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("SPIFFE credential reload check failed")

    async def _in_worker(self, function: Callable[..., Any], *args: Any) -> Any:
        """Run a blocking issuer callback in the policy pool, under a bound.

        A timed-out exchange frees its connection slot as soon as it unwinds,
        but a work item it already submitted stays in the pool's unbounded
        queue until a thread picks it up. With every thread parked on a slow
        dependency, replacement connections could keep enqueueing items that
        nothing ever drains, so the queue — not the connection count — was the
        thing that grew. Submissions are therefore capped, and a slot is held
        until the work item itself has run rather than until the awaiting
        coroutine is cancelled: cancelling an asyncio future only marks the
        queued item dead, it does not remove it.
        """
        loop = asyncio.get_running_loop()
        slots, pool = self._work_slots, self._workers
        if slots is None or pool is None:
            raise SpiffeError("Issuer is shutting down")
        await slots.acquire()

        def run() -> Any:
            try:
                return function(*args)
            except SpiffeError:
                raise
            except Exception as exc:
                # A policy or audit callback may fail with anything, including the
                # OSError family (a database connection refused, a disk full). That
                # is the issuer's failure, not the agent's connection breaking.
                raise _CallbackFailed() from exc
            finally:
                try:
                    loop.call_soon_threadsafe(slots.release)
                except RuntimeError:
                    pass  # The loop closed while shutting down; the slot dies with it.

        try:
            work = asyncio.wrap_future(pool.submit(run))
        except RuntimeError as exc:  # Pool already shut down.
            slots.release()
            raise SpiffeError("Issuer is shutting down") from exc
        try:
            # Shielded so a cancelled exchange cannot strand a reserved slot on
            # a work item that never runs. `_exchange` discards the pending
            # challenge as it unwinds, so a late `_issue` still mints nothing.
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            work.add_done_callback(_consume_result)
            raise

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= self._max_connections:
            writer.close()
            return
        self._active += 1
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        connection = _ServerConnection(reader, writer, self._tls.context)
        try:
            await asyncio.wait_for(self._exchange(connection), self._timeout)
        except asyncio.TimeoutError:
            logger.info("Issuance exchange timed out")
        except (ConnectionError, ssl.SSLError, OSError) as exc:
            logger.info("Issuance connection failed: %s", exc)
        except Exception:
            logger.exception("Issuance exchange failed")
            try:
                await asyncio.wait_for(connection.send({"error": "unavailable", "message": "Issuer error"}), 1)
            except Exception:
                pass
        finally:
            self._active -= 1
            if task is not None:
                self._tasks.discard(task)
            await connection.close()

    async def _exchange(self, connection: _ServerConnection) -> None:
        await connection.handshake()
        tls = self._tls
        challenge: Optional[bytes] = None
        guard = threading.Lock()
        made: List[bytes] = []
        abandoned = False

        def make_challenge(identity: SpiffeIdentity, holder: PublicKey, task_id: Any) -> bytes:
            # Runs in a worker, and may finish after the exchange has timed out and
            # unwound. Then nobody is left to discard the challenge but this function.
            created = self.issuer._challenge(identity, holder, task_id)
            with guard:
                if abandoned:
                    self.issuer._discard(created)
                    raise SpiffeError("The exchange ended before its challenge was ready")
                made.append(created)
            return created

        try:
            identity = tls.authenticate(connection.tls)
            request = _parse_frame(await connection.readline(), frozenset({"v", "holder", "task"}))
            if type(request["v"]) is not int or request["v"] != _PROTOCOL_VERSION:  # Not true, not 1.0.
                raise SpiffeError("Unsupported protocol version")
            try:
                holder = PublicKey.from_bytes(_decode(request["holder"], limit=64))
            except SpiffeError:
                raise
            except Exception as exc:
                raise SpiffeError("Invalid holder key") from exc
            challenge = await self._in_worker(make_challenge, identity, holder, request["task"])
            await connection.send({"challenge": _encode(challenge)})
            proof = _parse_frame(await connection.readline(), frozenset({"signature"}))
            signature = _decode(proof["signature"], limit=128)
            # Re-authenticate: the peer SVID may have expired while waiting.
            identity = tls.authenticate(connection.tls)
            warrant = await self._in_worker(self.issuer._issue, identity, challenge, signature)
        except SpiffeError as exc:
            logger.info("Issuance refused: %s", exc)
            await connection.send({"error": "refused", "message": str(exc)})
            return
        finally:
            with guard:
                abandoned = True
            self.issuer._discard(made[0] if made else None)
        await connection.send({"warrant": warrant.to_base64()})
