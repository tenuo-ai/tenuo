"""JWT-SVID authentication for warrant issuance, for places mTLS cannot reach.

Install ``tenuo[spiffe-jwt]``. Use this when a TLS-terminating load balancer,
a service mesh, or a serverless platform sits between agents and the issuer, so
the issuer never sees the agent's X.509-SVID. The agent presents a JWT-SVID as
a bearer token over HTTPS instead.

A JWT-SVID is a bearer token: whoever holds it can use it until it expires. The
mTLS exchange in :mod:`tenuo.spiffe` has no such gap, so prefer it where it is
available. This module narrows the gap as far as a bearer token allows: the
token must name this issuer as its audience, the warrant never outlives the
token, and the agent's holder key signs a statement bound to that exact token.

The exchange is one request with no challenge round trip and no state shared
between replicas, so it works behind load balancers without session affinity. See
:class:`SpiffeJWTIssuerApp` for the wire format.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import logging
import re
import secrets
import ssl
import threading
import time
import urllib.parse
import weakref
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError as exc:
    raise ImportError("JWT-SVID support requires pip install 'tenuo[spiffe-jwt]'") from exc

from tenuo import PublicKey, SigningKey, Warrant
from tenuo.spiffe import (
    _MAX_TASK_ID,
    _WORKLOAD_API_METADATA,
    IssuerKeys,
    SpiffeError,
    SpiffeIdentity,
    SpiffeJWTProof,
    SpiffeWarrantIssuer,
    _checked_warrant,
    _IssuerBusy,
    _consume_result,
    _file_signature,
    _jwt_proof_bytes,
    _key_list,
    _OwnerGone,
    _positive_int,
    _proto_fields,
    _read_snapshot,
    _trust_domain,
    _trust_domain_names,
    _workload_api_target,
    _WorkloadAPIWatcher,
)

__all__ = [
    "SpiffeJWT",
    "SpiffeJWTIssuerApp",
    "SpiffeJWTProof",
    "arequest_warrant_jwt",
    "fetch_jwt_svid",
    "request_warrant_jwt",
    "sign_jwt_holder_proof",
]

logger = logging.getLogger("tenuo.spiffe")

_FETCH_JWT_BUNDLES = "/SpiffeWorkloadAPI/FetchJWTBundles"
_FETCH_JWT_SVID = "/SpiffeWorkloadAPI/FetchJWTSVID"
_MAX_TOKEN_BYTES = 16 * 1024
_MAX_BODY_BYTES = 64 * 1024
_MIN_RSA_BITS = 2048
_FILE_CHECK_SECONDS = 5.0
_PROTOCOL_VERSION = 1
_NONCE_BYTES = 16
_COMPACT_JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
# RFC 7518 signature algorithms the JWT-SVID standard allows, by key family.
_RSA_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
_EC_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}

_Key = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]


def _jwk_number(value: Any) -> int:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("not base64url")
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def _public_key(entry: Mapping[str, Any]) -> _Key:
    """Build a public key from an RSA or EC JWK with ``cryptography``, whatever PyJWT is installed."""
    if entry["kty"] == "RSA":
        return rsa.RSAPublicNumbers(_jwk_number(entry["e"]), _jwk_number(entry["n"])).public_key()
    curves: Dict[str, ec.EllipticCurve] = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    curve = curves[entry["crv"]]
    return ec.EllipticCurvePublicNumbers(_jwk_number(entry["x"]), _jwk_number(entry["y"]), curve).public_key()


def _jwks_keys(document: bytes, trust_domain: str) -> Dict[str, _Key]:
    """Read one trust domain's JWT-SVID signing keys from a JWKS document.

    Also accepts the file ``spiffe-helper`` writes: a JSON object mapping trust
    domain names to base64-encoded JWKS documents. Keys this adapter cannot use
    (another key type, too small, malformed) are skipped with a warning rather
    than failing the bundle, so an update that adds one still removes retired keys.
    A well-formed bundle with no usable key yields an empty result: the caller
    decides whether that is a startup error or a withdrawal.
    """
    try:
        data = json.loads(document)
        if isinstance(data, dict) and "keys" not in data:
            encoded = data.get(trust_domain, data.get(f"spiffe://{trust_domain}"))
            if encoded is None:
                # The helper's file no longer lists this trust domain: its keys are withdrawn.
                return {}
            if not isinstance(encoded, str):
                raise SpiffeError("JWT bundle is not a JWKS document")
            data = json.loads(base64.b64decode(encoded, validate=True))
    except SpiffeError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SpiffeError("JWT bundle is not a JWKS document") from exc
    entries = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise SpiffeError("JWT bundle is not a JWKS document")
    # A SPIFFE-format bundle marks every key with its use, and holds X.509
    # authorities next to JWT keys: there, only keys marked "jwt-svid" count.
    # The JWT bundles SPIRE's Workload API and spiffe-helper deliver are plain
    # JWKS documents with no "use" at all, and every key in them is a JWT key.
    marked = "spiffe_sequence" in data or any(isinstance(entry, dict) and "use" in entry for entry in entries)
    keys: Dict[str, _Key] = {}
    for entry in entries:
        if not isinstance(entry, dict) or "x5c" in entry:
            continue  # Not a key, or an X.509 authority.
        if marked and entry.get("use") != "jwt-svid":
            if "use" not in entry:
                logger.warning("Skipping a key without a use in a SPIFFE-format bundle for %s", trust_domain)
            continue
        kid, kty = entry.get("kid"), entry.get("kty")
        if not isinstance(kid, str) or not kid:
            logger.warning("Skipping a JWT bundle key without a key ID")
            continue
        if kid in keys:
            raise SpiffeError("JWT bundle key IDs must be unique")
        problem = None
        key: Any = None
        if "d" in entry:
            problem = "is a private key"
        elif kty not in ("RSA", "EC"):
            problem = "has an unsupported type"
        else:
            try:
                key = _public_key(entry)
            except Exception:  # Bad encodings, off-curve points, impossible RSA numbers.
                problem = "is malformed"
        if problem is None and isinstance(key, rsa.RSAPublicKey) and key.key_size < _MIN_RSA_BITS:
            problem = "is too small"
        if problem is not None:
            logger.warning("Skipping JWT bundle key %r: it %s", kid[:64], problem)
            continue
        keys[kid] = key
    return keys


def _no_keys(trust_domain: str) -> SpiffeError:
    return SpiffeError(f"JWT bundle for {trust_domain} contains no usable JWT-SVID signing keys")


_Keys = Dict[str, _Key]


class _Malformed:
    """Stands for a home-domain bundle that could not be read, with the reason."""

    def __init__(self, reason: str):
        self.reason = reason


def _jwt_bundles_from_response(
    message: bytes, trust_domain: str, federates_with: Sequence[str] = ()
) -> Tuple[Union[_Keys, None, _Malformed], Dict[str, _Keys]]:
    """Read the JWKS of this trust domain and of each federated one from a JWTBundlesResponse.

    The first result is None when the response has no bundle for this domain
    and a ``_Malformed`` when it has one that cannot be read. A federated domain
    appears in the second result only with a readable bundle; one that is absent
    or malformed is simply not trusted. Domains that were not asked for are ignored.
    """
    documents: Dict[str, bytes] = {}
    for field, value in _proto_fields(message):
        if field != 1 or not isinstance(value, bytes):  # bundles: map<string, bytes>
            continue
        entry = {number: item for number, item in _proto_fields(value) if isinstance(item, bytes)}
        name = entry.get(1, b"").decode("utf-8", "replace")
        if name.startswith("spiffe://"):
            documents[name[len("spiffe://") :]] = entry.get(2, b"")
    own: Union[_Keys, None, _Malformed] = None
    if trust_domain in documents:
        try:
            own = _jwks_keys(documents[trust_domain], trust_domain)
        except SpiffeError as exc:
            own = _Malformed(str(exc))
    federated: Dict[str, _Keys] = {}
    for domain in federates_with:
        if domain not in documents:
            continue
        try:
            federated[domain] = _jwks_keys(documents[domain], domain)
        except SpiffeError as exc:
            logger.warning("JWT bundle for federated trust domain %s is unusable: %s", domain, exc)
    return own, federated


def _without_overlap(home: _Keys, federated: Mapping[str, _Keys], home_domain: str) -> Dict[str, _Keys]:
    """Drop federated trust domains that share a signing key with another domain.

    A shared key could sign for either domain, so such a domain is not trusted.
    The home domain is never dropped; two federated domains that overlap both are.
    """

    def fingerprints(keys: _Keys) -> set:
        return {key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) for key in keys.values()}

    prints = {home_domain: fingerprints(home)}
    prints.update({domain: fingerprints(keys) for domain, keys in federated.items() if keys})
    names = list(prints)
    overlapping = set()
    for index, first in enumerate(names):
        for second in names[index + 1 :]:
            if prints[first] & prints[second]:
                overlapping.update({first, second} - {home_domain})
    for domain in sorted(overlapping):
        logger.warning(
            "JWT bundle for federated trust domain %s is refused: it shares a signing key with another domain", domain
        )
    return {domain: keys for domain, keys in federated.items() if keys and domain not in overlapping}


class SpiffeJWT:
    """Validate JWT-SVIDs for one trust domain and one audience.

    ``audience`` is the name agents request tokens for. Make it specific to this
    issuer (its SPIFFE ID is the usual choice): a token for any other audience
    is refused. Signing keys come from a JWKS file (this constructor; the file
    ``spiffe-helper`` writes also works) or from the SPIRE agent with
    :meth:`from_workload_api`, which follows key rotation. A changed file is
    picked up within a few seconds.

    Federation: to accept tokens from other trust domains, give each domain's
    keys separately (``federated_bundle_files``, or ``federates_with`` with the
    Workload API). A token is only ever checked against the keys of the trust
    domain its subject names.
    """

    _paths: Optional[Tuple[str, ...]]
    _signature: Tuple[Tuple[int, int, int, int], ...]
    _keys: _Keys
    _federated_keys: Dict[str, _Keys]

    def __init__(
        self,
        *,
        trust_domain: str,
        audience: str,
        bundle_file: str,
        leeway_seconds: float = 5.0,
        federated_bundle_files: Optional[Mapping[str, str]] = None,
    ):
        federated = dict(federated_bundle_files or {})
        self._init_common(trust_domain, audience, leeway_seconds, tuple(federated))
        self._paths = (bundle_file, *federated.values())
        self._signature = _file_signature(self._paths)
        self._keys = self._read_home()
        if not self._keys:
            raise _no_keys(trust_domain)
        self._federated_keys = _without_overlap(self._keys, self._read_federated(), trust_domain)

    @classmethod
    def from_workload_api(
        cls,
        *,
        trust_domain: str,
        audience: str,
        socket_path: Optional[str] = None,
        timeout: float = 30.0,
        leeway_seconds: float = 5.0,
        max_stale_seconds: float = 300.0,
        federates_with: Sequence[str] = (),
    ) -> "SpiffeJWT":
        """Take the trust domain's JWT signing keys from the SPIRE agent.

        Needs ``tenuo[spiffe-workload-api]`` as well. ``socket_path`` works as in
        :meth:`tenuo.spiffe.SpiffeTLS.from_workload_api`. Waits up to ``timeout``
        seconds for the first bundle, then follows updates until :meth:`close`.

        Signing keys carry no expiry, so the validator never trusts them on old
        information: when SPIRE withdraws the domain's keys or refuses this
        workload its identity, tokens are refused at once; when the SPIRE agent
        has been unreachable for ``max_stale_seconds``, tokens are refused
        until the stream returns.

        ``federates_with`` names other trust domains whose tokens are accepted;
        their keys come from the same stream when the registration entry has
        ``-federatesWith``.
        """
        try:
            import grpc  # noqa: F401
        except ImportError as exc:
            raise ImportError("The Workload API source requires pip install 'tenuo[spiffe-workload-api]'") from exc
        self = cls.__new__(cls)
        self._init_common(trust_domain, audience, leeway_seconds, federates_with)
        domains = self._federates_with
        if timeout <= 0 or max_stale_seconds <= 0:
            raise ValueError("timeout and max_stale_seconds must be positive")
        self._max_stale = max_stale_seconds
        owner = weakref.ref(self)

        def deliver(update: Tuple[Union[_Keys, None, _Malformed], Dict[str, _Keys]]) -> None:
            validator = owner()
            if validator is None:
                raise _OwnerGone
            keys, foreign = update
            validator._lost_since = None
            validator._stale_warned = False
            malformed = isinstance(keys, _Malformed)
            home: _Keys = validator._keys if isinstance(keys, _Malformed) or keys is None else keys
            if validator._loaded or (keys and not malformed):
                # Federated domains follow this response whatever happens to the home bundle.
                validator._federated_keys = _without_overlap(home, foreign, trust_domain)
            if isinstance(keys, _Malformed):
                raise SpiffeError(keys.reason)  # Keep the home keys in use.
            if not keys:
                # A well-formed answer that offers nothing: SPIRE has withdrawn the keys.
                reason = (
                    f"The Workload API returned no JWT bundle for {trust_domain}"
                    if keys is None
                    else str(_no_keys(trust_domain))
                )
                if not validator._loaded:
                    raise SpiffeError(reason)  # Not usable to start with.
                validator._withdraw(reason)
                return
            validator._keys = keys
            validator._loaded = True
            logger.info("Loaded %d JWT-SVID signing key(s) for %s", len(keys), trust_domain)

        def lost(status: str) -> None:
            validator = owner()
            if validator is None:
                raise _OwnerGone
            if validator._lost_since is None:
                validator._lost_since = time.monotonic()
            if status == "PERMISSION_DENIED" and validator._loaded:
                validator._withdraw("SPIRE no longer issues this workload an identity")
                validator._federated_keys = {}

        watcher = _WorkloadAPIWatcher(
            _workload_api_target(socket_path),
            _FETCH_JWT_BUNDLES,
            lambda raw: _jwt_bundles_from_response(raw, trust_domain, domains),
            deliver,
            lost,
        )
        self._watcher = watcher
        weakref.finalize(self, watcher.stop, False)
        if not watcher.start(timeout):
            watcher.stop()
            reason = watcher.last_error or "no response"
            raise SpiffeError(f"No usable JWT bundle from the Workload API at {watcher.target}: {reason}")
        return self

    def _init_common(
        self, trust_domain: str, audience: str, leeway_seconds: float, federates_with: Sequence[str] = ()
    ) -> None:
        self._federates_with = _trust_domain_names(trust_domain, federates_with)
        if not isinstance(audience, str) or not audience or len(audience) > 2048:
            raise ValueError("audience must be a non-empty string")
        if not 0 <= leeway_seconds <= 60:
            raise ValueError("leeway_seconds must be between 0 and 60")
        self.trust_domain = trust_domain
        self.audience = audience
        self._leeway = leeway_seconds
        self._paths = None
        self._signature = ()
        self._watcher: Optional[_WorkloadAPIWatcher] = None
        self._reload_lock = threading.Lock()
        self._checked = time.monotonic()
        self._keys = {}
        self._federated_keys = {}
        self._loaded = False  # A usable bundle has been installed at least once.
        self._lost_since: Optional[float] = None  # When the Workload API stream was last lost.
        self._stale_warned = False
        self._max_stale = 0.0

    def _read_home(self) -> _Keys:
        assert self._paths is not None
        return _jwks_keys(_read_snapshot(self._paths[0]), self.trust_domain)

    def _read_federated(self) -> Dict[str, _Keys]:
        """Each federated domain's keys. A missing or unreadable bundle means the domain is not trusted."""
        assert self._paths is not None
        federated: Dict[str, _Keys] = {}
        for domain, path in zip(self._federates_with, self._paths[1:]):
            try:
                federated[domain] = _jwks_keys(_read_snapshot(path), domain)
            except (OSError, SpiffeError) as exc:
                logger.warning("JWT bundle for federated trust domain %s is unusable: %s", domain, exc)
        return federated

    def _withdraw(self, reason: str) -> None:
        if self._keys:
            logger.warning("JWT-SVIDs for %s are refused until keys return: %s", self.trust_domain, reason)
        self._keys = {}

    def reload(self) -> None:
        """Read the bundle file again.

        An unreadable or malformed file keeps the current keys. A well-formed
        bundle replaces them, including one with no usable key, which withdraws them.
        Federated domains are read separately: a problem with one never holds
        back the home domain, and a domain without a usable bundle is not trusted.
        """
        if self._paths is None:
            return
        with self._reload_lock:
            signature = _file_signature(self._paths)
            federated = self._read_federated()
            try:
                keys = self._read_home()
            except Exception:
                self._federated_keys = _without_overlap(self._keys, federated, self.trust_domain)
                raise
            self._federated_keys = _without_overlap(keys, federated, self.trust_domain)
            self._signature = signature
            if not keys:
                self._withdraw(str(_no_keys(self.trust_domain)))
                return
            self._keys = keys
        logger.info("Loaded %d JWT-SVID signing key(s) for %s", len(self._keys), self.trust_domain)

    def reload_if_changed(self) -> bool:
        """Reload when the bundle file changed. Called automatically while tokens arrive."""
        if self._paths is None or _file_signature(self._paths) == self._signature:
            return False
        self.reload()
        return True

    def close(self) -> None:
        """Stop following the Workload API."""
        if self._watcher is not None:
            self._watcher.stop()

    def _refresh(self) -> None:
        if self._paths is None or time.monotonic() - self._checked < _FILE_CHECK_SECONDS:
            return
        self._checked = time.monotonic()
        try:
            self.reload_if_changed()
        except Exception as exc:  # Never let a bad file stop later reloads.
            logger.warning("Could not reload the JWT bundle; keeping the current keys: %s", exc)

    def authenticate(self, token: str) -> SpiffeIdentity:
        """Validate a JWT-SVID and return the workload identity it names."""
        self._refresh()
        # Refuse on old information without touching the shared keys: the watcher
        # may be installing a recovered bundle at this very moment.
        lost = self._lost_since
        if lost is not None and time.monotonic() - lost > self._max_stale:
            if not self._stale_warned:
                self._stale_warned = True
                logger.warning(
                    "JWT-SVIDs for %s are refused until the SPIRE agent is reachable again", self.trust_domain
                )
            raise SpiffeError("JWT-SVIDs are refused while the SPIRE agent is unreachable")
        # Exactly three unpadded base64url segments, so one token has one spelling
        # (and one SHA-256) whatever the installed PyJWT tolerates.
        if not isinstance(token, str) or len(token) > _MAX_TOKEN_BYTES or not _COMPACT_JWS.fullmatch(token):
            raise SpiffeError("Malformed JWT-SVID")
        try:
            header = pyjwt.get_unverified_header(token)
        except (pyjwt.PyJWTError, ValueError, TypeError, RecursionError) as exc:
            raise SpiffeError("Malformed JWT-SVID") from exc
        # The JWT-SVID standard allows these three headers and no others.
        if not isinstance(header, dict) or not set(header) <= {"alg", "kid", "typ"}:
            raise SpiffeError("Malformed JWT-SVID")
        algorithm, kid, kind = header.get("alg"), header.get("kid"), header.get("typ")
        if kind is not None and kind not in ("JWT", "JOSE"):
            raise SpiffeError("Malformed JWT-SVID")
        if not isinstance(algorithm, str):
            raise SpiffeError("Malformed JWT-SVID")
        if not isinstance(kid, str) or not kid:
            raise SpiffeError("JWT-SVID names no signing key")
        # A key ID may exist in more than one trust domain. Each candidate key can
        # only vouch for subjects in the trust domain it belongs to.
        candidates: List[Tuple[str, _Key]] = []
        home_key = self._keys.get(kid)
        if home_key is not None:
            candidates.append((self.trust_domain, home_key))
        for domain, keys in self._federated_keys.items():
            federated_key = keys.get(kid)
            if federated_key is not None:
                candidates.append((domain, federated_key))
        if not candidates:
            raise SpiffeError("JWT-SVID was signed by a key that is not in the trust bundle")
        refusals: List[SpiffeError] = []
        for domain, key in candidates:
            try:
                return self._verify(token, algorithm, key, domain)
            except SpiffeError as exc:
                refusals.append(exc)
        # With one key ID in several domains, report the most specific refusal.
        raise next((refusal for refusal in refusals if str(refusal) != "Invalid JWT-SVID"), refusals[0])

    def _verify(self, token: str, algorithm: str, key: _Key, key_domain: str) -> SpiffeIdentity:
        # Tie the algorithm to the key's own type, so a token cannot pick one the key was not made for.
        if isinstance(key, rsa.RSAPublicKey):
            supported = algorithm in _RSA_ALGORITHMS
        else:
            supported = _EC_CURVES.get(algorithm) == key.curve.name
        if not supported:
            raise SpiffeError("JWT-SVID uses an algorithm its signing key does not support")
        try:
            claims = pyjwt.decode(
                token,
                key=key,
                algorithms=[algorithm],
                audience=self.audience,
                leeway=self._leeway,
                options={"require": ["exp", "sub", "aud"]},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise SpiffeError("JWT-SVID has expired") from exc
        except pyjwt.InvalidAudienceError as exc:
            raise SpiffeError(f"JWT-SVID is not for this issuer's audience ({self.audience})") from exc
        except (pyjwt.PyJWTError, ValueError, TypeError, OverflowError, RecursionError) as exc:
            raise SpiffeError("Invalid JWT-SVID") from exc
        subject, expires = (claims.get("sub"), claims.get("exp")) if isinstance(claims, dict) else (None, None)
        if (
            not isinstance(subject, str)
            or not isinstance(expires, (int, float))
            or isinstance(expires, bool)
            or not 0 < expires < 2**40
        ):
            raise SpiffeError("Invalid JWT-SVID")
        subject_domain = _trust_domain(subject)
        if subject_domain != self.trust_domain and subject_domain not in self._federates_with:
            raise SpiffeError("JWT-SVID belongs to a different trust domain")
        if subject_domain != key_domain:
            raise SpiffeError("JWT-SVID was not signed by its own trust domain's keys")
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        return SpiffeIdentity(subject, digest, float(expires), "jwt")


# -- agent side -------------------------------------------------------------


def fetch_jwt_svid(
    audience: str, *, socket_path: Optional[str] = None, spiffe_id: Optional[str] = None, timeout: float = 10.0
) -> str:
    """Ask the SPIRE agent for a JWT-SVID for ``audience`` (needs ``tenuo[spiffe-workload-api]``).

    If SPIRE offers this process several identities, name one with
    ``spiffe_id``; otherwise the first is used.
    """
    try:
        import grpc
    except ImportError as exc:
        raise ImportError("The Workload API source requires pip install 'tenuo[spiffe-workload-api]'") from exc
    if not isinstance(audience, str) or not audience:
        raise ValueError("audience must be a non-empty string")
    target = _workload_api_target(socket_path)

    def text(number: int, value: str) -> bytes:
        data = value.encode("utf-8")
        if len(data) > 2048:
            raise ValueError("audience and spiffe_id must be at most 2048 bytes")
        length = bytearray()
        size = len(data)
        while True:
            length.append((size & 0x7F) | (0x80 if size > 0x7F else 0))
            size >>= 7
            if not size:
                break
        return bytes([number << 3 | 2]) + bytes(length) + data

    request = text(1, audience) + (text(2, spiffe_id) if spiffe_id else b"")
    channel = grpc.insecure_channel(target, options=[("grpc.enable_http_proxy", 0)])
    try:
        call = channel.unary_unary(
            _FETCH_JWT_SVID, request_serializer=lambda raw: raw, response_deserializer=lambda raw: raw
        )
        response = call(request, metadata=_WORKLOAD_API_METADATA, timeout=timeout)
    except grpc.RpcError as exc:
        reason = f"{exc.code().name}: {exc.details()}"
        raise SpiffeError(f"Could not fetch a JWT-SVID from the Workload API at {target}: {reason}") from exc
    finally:
        channel.close()
    for field, value in _proto_fields(response):
        if field != 1 or not isinstance(value, bytes):  # svids
            continue
        svid = {number: item for number, item in _proto_fields(value) if isinstance(item, bytes)}
        if spiffe_id is None or svid.get(1, b"") == spiffe_id.encode():
            try:
                token = svid.get(2, b"").decode("ascii")
            except UnicodeDecodeError as exc:
                raise SpiffeError("The Workload API returned a malformed JWT-SVID") from exc
            if token:
                return token
    raise SpiffeError(f"The Workload API at {target} returned no JWT-SVID" + (f" for {spiffe_id}" if spiffe_id else ""))


def sign_jwt_holder_proof(
    token: str, holder_key: SigningKey, *, audience: str, task_id: str, timestamp: Optional[int] = None
) -> SpiffeJWTProof:
    """Bind a holder key to one JWT-SVID, issuer audience, and task.

    Returns the proof for :meth:`tenuo.spiffe.SpiffeWarrantIssuer.issue_jwt`.
    The signed statement starts with a fixed context and names the token by its
    SHA-256, so it is useless for any other token, issuer, task, or Tenuo
    signature. Each call uses a fresh random nonce, so a retry is a new proof.
    """
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_BYTES or not _COMPACT_JWS.fullmatch(token):
        raise SpiffeError("Malformed JWT-SVID")
    if not isinstance(task_id, str) or not task_id or len(task_id) > _MAX_TASK_ID:
        raise SpiffeError(f"task_id must contain 1–{_MAX_TASK_ID} characters")
    stamp = int(time.time()) if timestamp is None else timestamp
    if not _positive_int(stamp) or not 0 <= stamp < 2**40:
        raise SpiffeError("timestamp must be Unix seconds")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    digest = hashlib.sha256(token.encode("ascii")).digest()
    holder = bytes(holder_key.public_key.to_bytes())
    message = _jwt_proof_bytes(audience, holder, task_id, stamp, nonce, digest)
    return SpiffeJWTProof(stamp, nonce, bytes(holder_key.sign_raw(message)))


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def request_warrant_jwt(
    url: str,
    *,
    token: Union[str, Callable[[], str]],
    audience: str,
    issuer_key: IssuerKeys,
    holder_key: SigningKey,
    task_id: str,
    ca_file: Optional[str] = None,
    timeout: float = 10.0,
) -> Warrant:
    """Obtain a warrant from a :class:`SpiffeJWTIssuerApp` with a JWT-SVID.

    ``token`` is the JWT-SVID or a function returning one, for example
    ``lambda: fetch_jwt_svid(audience)``. ``audience`` must be the issuer's
    configured audience. The token is only ever sent over verified HTTPS
    (``ca_file`` for a private CA, otherwise the system roots); plain ``http``
    is accepted for loopback addresses only. Redirects are not followed. The
    returned warrant is checked against ``issuer_key`` and ``holder_key``.
    Every failure is raised as :class:`tenuo.spiffe.SpiffeError`.
    """
    trusted = _key_list(issuer_key)
    try:
        parts = urllib.parse.urlsplit(url)
        host, explicit_port = parts.hostname, parts.port
    except ValueError:
        raise ValueError("url must look like https://host[:port]/path") from None
    if parts.scheme not in ("https", "http") or not host or parts.username or parts.password or parts.fragment:
        raise ValueError("url must look like https://host[:port]/path")
    # Always pass the port: http.client would otherwise read the tail of a bare IPv6 address as one.
    port = explicit_port or (443 if parts.scheme == "https" else 80)
    if parts.scheme == "http" and not _is_loopback(host):
        raise ValueError("A JWT-SVID is a bearer token: use https:// (http:// is allowed for loopback only)")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    value = token() if callable(token) else token
    if not isinstance(value, str):
        raise SpiffeError("Malformed JWT-SVID")
    value = value.strip()
    proof = sign_jwt_holder_proof(value, holder_key, audience=audience, task_id=task_id)
    body = json.dumps(
        {
            "v": _PROTOCOL_VERSION,
            "holder": base64.b64encode(bytes(holder_key.public_key.to_bytes())).decode("ascii"),
            "task": task_id,
            "timestamp": proof.timestamp,
            "nonce": base64.b64encode(proof.nonce).decode("ascii"),
            "signature": base64.b64encode(proof.signature).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    where = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    connection: Optional[http.client.HTTPConnection] = None
    try:
        if parts.scheme == "https":
            connection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl.create_default_context(cafile=ca_file)
            )
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Authorization": f"Bearer {value}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        status = response.status
        payload = response.read(_MAX_BODY_BYTES + 1)
    except ssl.SSLCertVerificationError as exc:
        raise SpiffeError(f"The TLS certificate presented by {where} was not accepted: {exc.verify_message}") from exc
    except ssl.SSLError as exc:
        raise SpiffeError(f"TLS with the issuer at {where} failed: {exc.reason or exc}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise SpiffeError(f"Could not complete the exchange with the issuer at {where}: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()
    try:
        reply = json.loads(payload) if len(payload) <= _MAX_BODY_BYTES else None
    except (ValueError, RecursionError):
        reply = None
    if status != 200 or not isinstance(reply, dict):
        message = reply.get("message") if isinstance(reply, dict) else None
        if isinstance(message, str) and message:
            raise SpiffeError(f"Issuer refused (HTTP {status}): {message[:200]}")
        raise SpiffeError(f"The issuer at {where} answered HTTP {status} without a warrant")
    return _checked_warrant(reply.get("warrant"), trusted, holder_key)


async def arequest_warrant_jwt(url: str, **kwargs: Any) -> Warrant:
    """Async wrapper for :func:`request_warrant_jwt` (runs in a worker thread)."""
    return await asyncio.to_thread(request_warrant_jwt, url, **kwargs)


# -- issuer endpoint --------------------------------------------------------

_Scope = Mapping[str, Any]
_Receive = Callable[[], Awaitable[Mapping[str, Any]]]
_Send = Callable[[Mapping[str, Any]], Awaitable[None]]


class _Refusal(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


class SpiffeJWTIssuerApp:
    """ASGI application that issues warrants to JWT-SVID bearers.

    Run it with any ASGI server (``uvicorn module:app``) or mount it in an
    existing app. TLS is terminated by whatever sits in front: a load balancer,
    a mesh sidecar, or the ASGI server itself.

    One request per warrant::

        POST <path>
        Authorization: Bearer <JWT-SVID>
        Content-Type: application/json

        {"v": 1, "holder": "<base64 Ed25519 public key>", "task": "<task ID>",
         "timestamp": <unix seconds>, "nonce": "<base64, 16 bytes>",
         "signature": "<base64 holder proof>"}

    The reply is ``200 {"warrant": "<base64>"}``, or ``{"error": ..., "message":
    ...}`` with 400 (malformed), 401 (token not accepted), 403 (refused), 408,
    413, or 503 (busy, or the policy or audit callback failed). Policy and audit run
    in up to ``max_workers`` threads; at most ``max_concurrent`` requests are in
    progress at once and the rest get 503.
    """

    def __init__(
        self,
        issuer: SpiffeWarrantIssuer,
        *,
        path: str = "/warrants",
        max_concurrent: int = 256,
        max_workers: int = 32,
        body_timeout: float = 10.0,
    ):
        if issuer.jwt is None:
            raise ValueError("SpiffeJWTIssuerApp needs an issuer built with jwt=SpiffeJWT(...)")
        if not path.startswith("/"):
            raise ValueError("path must start with /")
        for name, value in (("max_concurrent", max_concurrent), ("max_workers", max_workers)):
            if not _positive_int(value) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.issuer = issuer
        self._validator: Any = issuer.jwt
        self._path = path
        if body_timeout <= 0:
            raise ValueError("body_timeout must be positive")
        self._max_concurrent = max_concurrent
        self._body_timeout = body_timeout
        self._busy = 0
        self._reading = 0
        self._pool = ThreadPoolExecutor(max_workers, thread_name_prefix="tenuo-spiffe-jwt")

    def close(self) -> None:
        """Release the worker threads. Called on ASGI lifespan shutdown."""
        self._pool.shutdown(wait=False)

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self.close()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        try:
            status, reply = 200, {"warrant": (await self._issue(scope, receive)).to_base64()}
        except _Refusal as refusal:
            status, reply = refusal.status, {"error": refusal.error, "message": refusal.message}
            logger.info("JWT-SVID issuance refused (%d): %s", status, refusal.message)
        except Exception:
            logger.exception("JWT-SVID issuance failed")
            status, reply = 503, {"error": "unavailable", "message": "Issuer error"}
        body = json.dumps(reply, separators=(",", ":")).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        if status == 401:
            headers.append((b"www-authenticate", b"Bearer"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def _issue(self, scope: _Scope, receive: _Receive) -> Warrant:
        path, root = scope.get("path", ""), scope.get("root_path", "")
        if root and path.startswith(root):
            path = path[len(root) :]  # Mounted under a prefix.
        if path != self._path:
            raise _Refusal(404, "not_found", "No such endpoint")
        if scope.get("method") != "POST":
            raise _Refusal(405, "method_not_allowed", "Use POST")
        tokens = [value for name, value in scope.get("headers", ()) if name.lower() == b"authorization"]
        scheme, _, credential = (tokens[0] if len(tokens) == 1 else b"").partition(b" ")
        if scheme.lower() != b"bearer" or not credential or len(credential) > _MAX_TOKEN_BYTES:
            raise _Refusal(401, "unauthorized", "Send the JWT-SVID as one Authorization: Bearer header")
        # Bound the requests being read as well as those being worked on, and
        # give each a deadline, so slow senders cannot pile up before the token is checked.
        if self._reading >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        self._reading += 1
        try:
            body = await asyncio.wait_for(self._read_body(receive), self._body_timeout)
        except asyncio.TimeoutError:
            raise _Refusal(408, "timeout", "Request body was not received in time") from None
        finally:
            self._reading -= 1
        try:
            request = json.loads(body)
            fields = {"v", "holder", "task", "timestamp", "nonce", "signature"}
            if not isinstance(request, dict) or set(request) != fields:
                raise ValueError
            if request["v"] != _PROTOCOL_VERSION:
                raise _Refusal(400, "invalid_request", "Unsupported protocol version")
            holder = PublicKey.from_bytes(base64.b64decode(request["holder"], validate=True))
            proof = SpiffeJWTProof(
                request["timestamp"],
                base64.b64decode(request["nonce"], validate=True),
                base64.b64decode(request["signature"], validate=True),
            )
            token = credential.decode("ascii")
        except _Refusal:
            raise
        except (ValueError, TypeError, RecursionError, binascii.Error):
            raise _Refusal(400, "invalid_request", "Malformed request") from None
        except Exception:  # A holder key the core rejects.
            raise _Refusal(400, "invalid_request", "Invalid holder key") from None
        validator, issuer = self._validator, self.issuer

        def work() -> Warrant:
            try:
                identity = validator.authenticate(token)
            except SpiffeError as exc:
                raise _Refusal(401, "unauthorized", str(exc)) from exc
            try:
                return issuer._issue_jwt(identity, holder, request["task"], proof)
            except _IssuerBusy as exc:
                raise _Refusal(503, "unavailable", str(exc)) from exc
            except SpiffeError as exc:
                raise _Refusal(403, "refused", str(exc)) from exc

        return await self._in_worker(work)

    @staticmethod
    async def _read_body(receive: _Receive) -> bytes:
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                raise _Refusal(400, "invalid_request", "Request was not completed")
            body += message.get("body", b"")
            if len(body) > _MAX_BODY_BYTES:
                raise _Refusal(413, "too_large", "Request body is too large")
            if not message.get("more_body"):
                return bytes(body)

    async def _in_worker(self, function: Callable[[], Warrant]) -> Warrant:
        """Run blocking work in the pool. A slot is held until the work itself has finished."""
        loop = asyncio.get_running_loop()
        if self._busy >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        self._busy += 1

        def release() -> None:
            self._busy -= 1

        def run() -> Warrant:
            try:
                return function()
            finally:
                try:
                    loop.call_soon_threadsafe(release)
                except RuntimeError:
                    pass  # The loop closed during shutdown.

        try:
            work = asyncio.wrap_future(self._pool.submit(run))
        except RuntimeError:
            self._busy -= 1
            raise _Refusal(503, "unavailable", "Issuer is shutting down") from None
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            work.add_done_callback(_consume_result)
            raise
