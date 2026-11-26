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
import weakref
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError as exc:
    raise ImportError("JWT-SVID support requires pip install 'tenuo[spiffe-jwt]'") from exc

from tenuo import PublicKey, SigningKey, Warrant
from tenuo._spiffe_http import _IssuerApp, _post_for_warrant, _Refusal, _request_body, _split_url, _where
from tenuo.spiffe import (
    _MAX_TASK_ID,
    _WORKLOAD_API_METADATA,
    IssuerKeys,
    SpiffeError,
    SpiffeIdentity,
    SpiffeJWTProof,
    SpiffeWarrantIssuer,
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
_MIN_RSA_BITS = 2048
_FILE_CHECK_SECONDS = 5.0
# How long "no identity issued" from the SPIRE agent is waited out before tokens are refused.
# An agent answers that way for a moment while it replaces SVIDs after a forced rotation.
_DENIED_GRACE_SECONDS = 30.0
_NONCE_BYTES = 16
# A JWT-SVID need not name its signing key. Without a key ID every key that fits the
# token's algorithm is tried, up to this many, so such a token cannot buy unbounded work.
_MAX_UNNAMED_KEY_ATTEMPTS = 16
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


def _claimed_trust_domain(token: str) -> str:
    """The trust domain in a token's subject, read before any signature is checked.

    Use it only to choose which keys to try: nothing here is verified.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, IndexError, RecursionError) as exc:
        raise SpiffeError("Invalid JWT-SVID") from exc
    subject = claims.get("sub") if isinstance(claims, dict) else None
    if not isinstance(subject, str):
        raise SpiffeError("Invalid JWT-SVID")
    return _trust_domain(subject)


def _fits(algorithm: str, key: _Key) -> bool:
    """Whether a signature algorithm belongs to this key's own type."""
    if isinstance(key, rsa.RSAPublicKey):
        return algorithm in _RSA_ALGORITHMS
    return _EC_CURVES.get(algorithm) == key.curve.name


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

    Entries are read one by one. One that cannot be decoded costs only the
    domain it was for: a readable entry for this domain still applies. If this
    domain has no readable entry and some entry could not be decoded, that
    entry may have been this domain's, so the result is ``_Malformed`` rather
    than a withdrawal.
    """
    documents: Dict[str, bytes] = {}
    undecodable = 0
    for field, value in _proto_fields(message):
        if field != 1 or not isinstance(value, bytes):  # bundles: map<string, bytes>
            continue
        try:
            entry = {number: item for number, item in _proto_fields(value) if isinstance(item, bytes)}
        except SpiffeError:
            undecodable += 1
            continue
        name = entry.get(1, b"").decode("utf-8", "replace")
        if name.startswith("spiffe://"):
            documents[name[len("spiffe://") :]] = entry.get(2, b"")
    if undecodable:
        logger.warning(
            "Ignoring %d JWT bundle entr%s that cannot be decoded", undecodable, "y" if undecodable == 1 else "ies"
        )
    own: Union[_Keys, None, _Malformed] = None
    if trust_domain in documents:
        try:
            own = _jwks_keys(documents[trust_domain], trust_domain)
        except SpiffeError as exc:
            own = _Malformed(str(exc))
    elif undecodable:
        own = _Malformed(f"The Workload API response has no readable JWT bundle for {trust_domain}")
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
    # The home domain's keys and each federated domain's, replaced together in one
    # assignment. Requests run in other threads: read both from one look at this.
    _trusted: Tuple[_Keys, Dict[str, _Keys]]

    @property
    def _keys(self) -> _Keys:
        return self._trusted[0]

    @property
    def _federated_keys(self) -> Dict[str, _Keys]:
        return self._trusted[1]

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
        home = self._read_home()
        if not home:
            raise _no_keys(trust_domain)
        self._trusted = (home, _without_overlap(home, self._read_federated(), trust_domain))

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
        information: when SPIRE withdraws the domain's keys, tokens are refused
        at once; when SPIRE has refused this workload its identity for 30
        seconds, or the SPIRE agent has been unreachable for
        ``max_stale_seconds``, tokens are refused until the stream returns.

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

        def parse(raw: bytes) -> Tuple[Union[_Keys, None, _Malformed], Dict[str, _Keys]]:
            try:
                return _jwt_bundles_from_response(raw, trust_domain, domains)
            except Exception as exc:
                # A broken envelope says nothing usable about any domain. Route
                # it through the same bounded retention as an unreadable JWKS;
                # the watcher's generic parse-error path cannot track key age.
                return _Malformed(str(exc)), {}

        def deliver(update: Tuple[Union[_Keys, None, _Malformed], Dict[str, _Keys]]) -> None:
            validator = owner()
            if validator is None:
                raise _OwnerGone
            keys, foreign = update
            malformed = isinstance(keys, _Malformed)
            home_now, federated = validator._trusted
            # The home keys that will be in force once this response is applied: kept
            # when its home bundle cannot be read, none when it withdraws them. Federated
            # bundles are compared with those, not with keys that are on their way out.
            home: _Keys = home_now if isinstance(keys, _Malformed) else (keys or {})
            if validator._loaded or (keys and not malformed):
                # Federated domains follow this response whatever happens to the home bundle.
                federated = _without_overlap(home, foreign, trust_domain)
            if isinstance(keys, _Malformed):
                if not validator._loaded:
                    raise SpiffeError(keys.reason)  # Not usable to start with.
                # Consumed once: keep the home keys, and leave nothing behind to be
                # delivered again as if SPIRE had sent it afresh. They are kept for a
                # bounded time only: what SPIRE meant to say about them is unknown.
                if validator._unreadable_since is None:
                    validator._unreadable_since = time.monotonic()
                logger.warning(
                    "Ignoring a malformed JWT bundle for %s; keeping the keys in use: %s", trust_domain, keys.reason
                )
                validator._trusted = (home_now, federated)
                return
            if not keys:
                # A well-formed answer that offers nothing: SPIRE has withdrawn the keys.
                reason = (
                    f"The Workload API returned no JWT bundle for {trust_domain}"
                    if keys is None
                    else str(_no_keys(trust_domain))
                )
                if not validator._loaded:
                    raise SpiffeError(reason)  # Not usable to start with.
                validator._withdraw(reason, federated)
            else:
                # One assignment for both: a key that moves between domains is
                # never trusted for the old and the new one at once.
                validator._trusted = (keys, federated)
                validator._loaded = True
            # Receiving bytes alone is not recovery. Only a readable home bundle
            # (including an explicit withdrawal) ends an outage, and only once the
            # keys it describes are in force: requests run in other threads, and
            # must never find the outage over while the earlier keys are still in place.
            validator._lost_since = None
            validator._stale_warned = False
            validator._denied_since = None
            validator._denied_warned = False
            validator._unreadable_since = None
            if keys:
                logger.info("Loaded %d JWT-SVID signing key(s) for %s", len(keys), trust_domain)

        def lost(status: str) -> None:
            validator = owner()
            if validator is None:
                raise _OwnerGone
            if validator._lost_since is None:
                validator._lost_since = time.monotonic()
            # Not a withdrawal yet: a SPIRE agent says this for a moment while it
            # replaces a workload's SVIDs. authenticate() refuses once it has lasted.
            if status == "PERMISSION_DENIED" and validator._loaded and validator._denied_since is None:
                validator._denied_since = time.monotonic()

        watcher = _WorkloadAPIWatcher(
            _workload_api_target(socket_path),
            _FETCH_JWT_BUNDLES,
            parse,
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
        self._trusted = ({}, {})
        self._loaded = False  # A usable bundle has been installed at least once.
        self._lost_since: Optional[float] = None  # When the Workload API stream was last lost.
        self._unreadable_since: Optional[float] = None  # Since when the home bundle could not be read.
        self._stale_warned = False
        self._denied_since: Optional[float] = None  # Since when SPIRE has refused this workload an identity.
        self._denied_warned = False
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

    def _withdraw(self, reason: str, federated: Optional[Dict[str, _Keys]] = None) -> None:
        """Drop the home domain's keys, installing ``federated`` (or keeping the current ones) in the same step."""
        home, current = self._trusted
        if home:
            logger.warning("JWT-SVIDs for %s are refused until keys return: %s", self.trust_domain, reason)
        self._trusted = ({}, current if federated is None else federated)

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
                home = self._keys
                self._trusted = (home, _without_overlap(home, federated, self.trust_domain))
                raise
            federated = _without_overlap(keys, federated, self.trust_domain)
            self._signature = signature
            if not keys:
                self._withdraw(str(_no_keys(self.trust_domain)), federated)
                return
            self._trusted = (keys, federated)
        logger.info("Loaded %d JWT-SVID signing key(s) for %s", len(keys), self.trust_domain)

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
        # An unreadable home bundle says nothing about the other domains, whose
        # bundles in the same responses were read. It is looked at here, before
        # the keys, and acted on below for home-domain tokens only.
        unreadable = self._unreadable_since
        home_keys_too_old = unreadable is not None and time.monotonic() - unreadable > self._max_stale
        denied = self._denied_since
        if denied is not None and time.monotonic() - denied > _DENIED_GRACE_SECONDS:
            if not self._denied_warned:
                self._denied_warned = True
                logger.warning(
                    "JWT-SVIDs for %s are refused until SPIRE issues this workload an identity again",
                    self.trust_domain,
                )
            raise SpiffeError("JWT-SVIDs are refused while SPIRE issues this workload no identity")
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
        if kid is not None and (not isinstance(kid, str) or not kid):
            raise SpiffeError("Malformed JWT-SVID")
        # A key can only vouch for subjects in the trust domain it belongs to, so
        # only the keys of the domain the token says it is from are tried. What
        # another domain's bundle holds (a key ID may exist in several) never adds
        # work. That claim is not trusted here: it only picks the keys, and
        # _verify checks the signed subject against the domain of the key used.
        home_keys, federated_keys = self._trusted  # One look: the two always belong together.
        claimed = _claimed_trust_domain(token)
        if claimed != self.trust_domain and claimed not in self._federates_with:
            raise SpiffeError("JWT-SVID belongs to a different trust domain")
        if home_keys_too_old and claimed == self.trust_domain:
            if not self._stale_warned:
                self._stale_warned = True
                logger.warning(
                    "JWT-SVIDs for %s are refused until SPIRE sends a JWT bundle that can be read", self.trust_domain
                )
            raise SpiffeError("JWT-SVIDs are refused while SPIRE's JWT bundle cannot be read")
        keys = home_keys if claimed == self.trust_domain else federated_keys.get(claimed, {})
        if kid is not None:
            named = keys.get(kid)
            if named is None:
                elsewhere = [home_keys, *federated_keys.values()]
                if any(kid in other for other in elsewhere):
                    raise SpiffeError("JWT-SVID was not signed by its own trust domain's keys")
                raise SpiffeError("JWT-SVID was signed by a key that is not in the trust bundle")
            return self._verify(token, algorithm, named, claimed)  # One signature check.
        # The standard makes the key ID optional (JWT-SVID, section 2.2): try
        # each key of that domain the token's algorithm fits.
        candidates = [key for key in keys.values() if _fits(algorithm, key)]
        if not candidates:
            raise SpiffeError("JWT-SVID was signed by a key that is not in the trust bundle")
        if len(candidates) > _MAX_UNNAMED_KEY_ATTEMPTS:
            raise SpiffeError(
                "JWT-SVID names no signing key, and its trust domain's bundle holds too many keys to try each"
            )
        refusals: List[SpiffeError] = []
        for key in candidates:
            try:
                return self._verify(token, algorithm, key, claimed)
            except SpiffeError as exc:
                refusals.append(exc)
        # Report the most specific refusal.
        raise next((refusal for refusal in refusals if str(refusal) != "Invalid JWT-SVID"), refusals[0])

    def _verify(self, token: str, algorithm: str, key: _Key, key_domain: str) -> SpiffeIdentity:
        # Tie the algorithm to the key's own type, so a token cannot pick one the key was not made for.
        if not _fits(algorithm, key):
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
    scheme, host, port, path = _split_url(url)
    if scheme == "http" and not _is_loopback(host):
        raise ValueError("A JWT-SVID is a bearer token: use https:// (http:// is allowed for loopback only)")
    value = token() if callable(token) else token
    if not isinstance(value, str):
        raise SpiffeError("Malformed JWT-SVID")
    value = value.strip()
    proof = sign_jwt_holder_proof(value, holder_key, audience=audience, task_id=task_id)

    def connect() -> http.client.HTTPConnection:
        if scheme == "https":
            return http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl.create_default_context(cafile=ca_file)
            )
        return http.client.HTTPConnection(host, port, timeout=timeout)

    return _post_for_warrant(
        connect,
        _where(host, port),
        path,
        _request_body(holder_key, task_id, proof),
        {"Authorization": f"Bearer {value}"},
        trusted,
        holder_key,
    )


async def arequest_warrant_jwt(url: str, **kwargs: Any) -> Warrant:
    """Async wrapper for :func:`request_warrant_jwt` (runs in a worker thread)."""
    return await asyncio.to_thread(request_warrant_jwt, url, **kwargs)


# -- issuer endpoint --------------------------------------------------------


class SpiffeJWTIssuerApp(_IssuerApp):
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

    _what = "JWT-SVID issuance"
    _challenge = b"Bearer"

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
        super().__init__(
            issuer, path=path, max_concurrent=max_concurrent, max_workers=max_workers, body_timeout=body_timeout
        )
        self._validator: Any = issuer.jwt

    def _credential(self, scope: Mapping[str, Any]) -> bytes:
        tokens = [value for name, value in scope.get("headers", ()) if name.lower() == b"authorization"]
        scheme, _, credential = (tokens[0] if len(tokens) == 1 else b"").partition(b" ")
        if scheme.lower() != b"bearer" or not credential or len(credential) > _MAX_TOKEN_BYTES:
            raise _Refusal(401, "unauthorized", "Send the JWT-SVID as one Authorization: Bearer header")
        return credential

    def _authorize(self, credential: bytes, holder: PublicKey, task_id: Any, proof: SpiffeJWTProof) -> Warrant:
        try:
            identity = self._validator.authenticate(credential.decode("ascii"))
        except UnicodeDecodeError:
            raise _Refusal(400, "invalid_request", "Malformed request") from None
        except SpiffeError as exc:
            raise _Refusal(401, "unauthorized", str(exc)) from exc
        return self.issuer._issue_jwt(identity, holder, task_id, proof)
