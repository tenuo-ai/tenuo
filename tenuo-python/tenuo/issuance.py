"""SKETCH: one warrant issuer for any credential that proves who is asking.

This is a design sketch, not a supported API. It sits beside ``tenuo.oauth``
and shows the shape proposed in the review of that module:

* **One issuer.** ``WarrantIssuer`` knows nothing about OAuth. It takes
  ``Credential`` objects, each of which turns what a caller presents into an
  ``Identity``. One holder proof, one replay store, one grant, one audit record.
  SPIFFE's mTLS, JWT-SVID and forwarded sources would become credentials too
  (not done here).
* **Trust as data.** ``Trust`` says which issuer and audience are accepted,
  where that provider puts the client, scopes and tenant (``ClaimMap``), and
  which claim values are required (``where``). The same code then accepts a
  Keycloak token, an RFC 9068 token and a GitHub Actions OIDC token. A provider
  is a few lines of data, not a branch in the validator.
* **Identity only.** The token says who is asking. What they may do comes from
  the policy callback, as in ``tenuo.oauth``.
* **Lessons from the SPIFFE endpoints, applied from the start.** The token is
  checked in a pool of its own before the request takes a place or its body
  is read; requests in progress and remembered proofs are both limited per
  identity; a denied request leaves no proof behind; a slow key fetch does not
  hold up tokens signed by keys already known; what a callback raises is the
  issuer's error, not a refusal.

Not sketched: DPoP in place of the holder proof, the RFC 8693 request shape,
RAR ``authorization_details`` as a source of task authority, opaque tokens.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Protocol, Sequence, Tuple, Union, cast

import httpx
import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from tenuo import PublicKey, SigningKey, Warrant
from tenuo._spiffe_http import _IssuerApp, _Refusal
from tenuo.oauth import OAuthError, OAuthUnavailable, _integer, _json, _text, _url
from tenuo.spiffe import SpiffeHolderProof, _CallbackFailed, _from_callback, _positive_int, _run_callback

_MAX_TOKEN = 16384
_MAX_JSON = 262144
_PROOF_SECONDS = 60  # The same window as the SPIFFE exchanges.
_CONTEXT = b"tenuo.issuance.holder-binding.v1\0"

# ---------------------------------------------------------------------------
# Who is asking
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    """What a credential proved. ``claims`` holds only verified values the policy may read."""

    issuer: str
    subject: str
    expires_at: float
    client: Optional[str] = None
    tenant: Optional[str] = None
    scopes: FrozenSet[str] = frozenset()
    claims: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """The name limits are counted against: one workload or user at one issuer."""
        return f"{self.issuer} {self.client or ''} {self.subject}"


class Credential(Protocol):
    """Turns what a caller presents into an identity, or raises ``OAuthError``."""

    audience: str

    def accepts(self, presented: str) -> bool:
        """Whether this credential is the one to check ``presented`` with. Nothing is trusted yet."""
        ...

    def authenticate(self, presented: str) -> Identity: ...


@dataclass(frozen=True)
class ClaimMap:
    """Where one kind of provider puts things in its tokens. The first claim present is used."""

    client: Tuple[str, ...] = ("client_id",)
    scopes: Tuple[str, ...] = ("scope",)  # A space-separated string or a list of strings.
    tenant: Optional[str] = None
    header_types: FrozenSet[str] = frozenset({"at+jwt"})
    constants: Mapping[str, str] = field(default_factory=dict)  # Claims that must have exactly this value.
    needs_client: bool = True
    needs_token_id: bool = False


RFC9068 = ClaimMap(needs_token_id=True)
KEYCLOAK = ClaimMap(client=("azp",), header_types=frozenset({"JWT"}), constants={"typ": "Bearer"})
# A workflow run, not an OAuth client: no client and no scopes. Who it is lives in sub, repository, ref, environment.
GITHUB_ACTIONS = ClaimMap(client=(), scopes=(), header_types=frozenset({"JWT"}), needs_client=False)

Condition = Union[str, FrozenSet[str]]


@dataclass(frozen=True)
class Trust:
    """Whose tokens are accepted, for which audience, and what they must say.

    ``where`` lists claims that must match: one exact value, or one of a set.
    A claim that is missing does not match. This is the whole trust decision,
    in one place an operator can read.
    """

    issuer: str
    audience: str
    jwks_url: str
    claims: ClaimMap = RFC9068
    where: Mapping[str, Condition] = field(default_factory=dict)
    required_scopes: FrozenSet[str] = frozenset()
    leeway_seconds: int = 5


class JWTCredential:
    """Signed JWTs from one issuer, checked against one ``Trust``."""

    def __init__(
        self,
        trust: Trust,
        *,
        cache_seconds: float = 300,
        refresh_interval: float = 5,
        timeout: float = 5,
        allow_loopback_http: bool = False,
    ):
        _url(trust.issuer, allow_loopback_http)
        _url(trust.jwks_url, allow_loopback_http)
        self.trust, self.audience = trust, _text(trust.audience, "audience")
        self._cache_seconds, self._refresh_interval = cache_seconds, refresh_interval
        self._keys: Dict[str, Tuple[str, Any]] = {}
        self._loaded = self._attempted = float("-inf")
        self._refreshing = False
        self._lock = threading.Lock()
        self._http = httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)

    def close(self) -> None:
        self._http.close()

    # -- keys -------------------------------------------------------------

    def _fetch(self) -> Dict[str, Tuple[str, Any]]:
        with self._http.stream("GET", self.trust.jwks_url) as response:
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > _MAX_JSON:
                    raise ValueError("JWKS too large")
        entries = _json(raw)["keys"]
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("Invalid keys")
        keys: Dict[str, Tuple[str, Any]] = {}
        for entry in entries:
            kid = _text(entry.get("kid"), "key ID")
            if kid in keys:
                raise ValueError("Duplicate key ID")
            if entry.get("use", "sig") != "sig" or any(k in entry for k in ("d", "p", "q", "k")):
                continue
            algorithm = entry.get("alg") or {"RSA": "RS256", "EC": "ES256"}.get(entry.get("kty"))
            if algorithm not in ("RS256", "ES256"):
                continue
            key = jwt.PyJWK.from_dict(entry, algorithm=algorithm).key
            usable = (
                isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048
                if algorithm == "RS256"
                else isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
            )
            if usable:
                keys[kid] = (algorithm, key)
        return keys

    def _key(self, kid: str) -> Tuple[str, Any]:
        """The key with this ID. At most one caller fetches at a time, and never while holding the lock.

        Tokens signed by a key already known keep being checked while a fetch
        is under way, for as long as the cached keys are fresh.
        """
        with self._lock:
            now = time.monotonic()
            fresh = now - self._loaded < self._cache_seconds
            if fresh and kid in self._keys:
                return self._keys[kid]
            fetch = not self._refreshing and now - self._attempted >= self._refresh_interval
            if fetch:
                self._refreshing, self._attempted = True, now
        if fetch:
            try:
                keys = self._fetch()
            except Exception as exc:
                with self._lock:
                    self._refreshing = False
                    still_fresh = time.monotonic() - self._loaded < self._cache_seconds
                if not still_fresh:
                    raise OAuthUnavailable("Signing keys unavailable") from exc
            else:
                with self._lock:
                    self._keys, self._loaded, self._refreshing = keys, time.monotonic(), False
        with self._lock:
            if time.monotonic() - self._loaded >= self._cache_seconds:
                raise OAuthUnavailable("Signing keys unavailable")
            if kid not in self._keys:
                raise OAuthError("Invalid access token")
            return self._keys[kid]

    # -- tokens -----------------------------------------------------------

    @staticmethod
    def _parts(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        _text(token, "access token", _MAX_TOKEN)
        segments = token.split(".")
        if len(segments) != 3:
            raise ValueError()
        decoded = []
        for segment in segments[:2]:
            raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
                raise ValueError()  # One spelling per token.
            decoded.append(_json(raw))
        header, payload = decoded
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError()
        return header, payload

    def accepts(self, presented: str) -> bool:
        try:
            return self._parts(presented)[1].get("iss") == self.trust.issuer
        except Exception:
            return False

    def authenticate(self, presented: str) -> Identity:
        trust, shape = self.trust, self.trust.claims
        try:
            header, _ = self._parts(presented)
            if set(header) - {"alg", "kid", "typ"} or header.get("typ") not in shape.header_types:
                raise ValueError()
            algorithm, key = self._key(_text(header.get("kid"), "key ID"))
            if algorithm != header.get("alg"):
                raise ValueError()
            claims = jwt.decode(
                presented,
                key,
                algorithms=[algorithm],
                issuer=trust.issuer,
                audience=trust.audience,
                leeway=trust.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
            if any(name in claims for name in ("cnf", "act", "may_act")):
                raise OAuthError("Sender-constrained and actor-chain tokens are not supported")
            if shape.needs_token_id:
                _text(claims.get("jti"), "token ID")
            for name, value in shape.constants.items():
                if claims.get(name) != value:
                    raise ValueError()
            for name, wanted in trust.where.items():
                found = claims.get(name)
                if not isinstance(found, str) or (found != wanted if isinstance(wanted, str) else found not in wanted):
                    raise ValueError()
            client = next((claims[name] for name in shape.client if name in claims), None)
            if shape.needs_client:
                _text(client, "client")
            listed = next((claims[name] for name in shape.scopes if name in claims), "")
            scopes = frozenset(listed.split() if isinstance(listed, str) else [_text(s, "scope") for s in listed])
            if not trust.required_scopes <= scopes:
                raise ValueError()
            tenant = _text(claims.get(shape.tenant), "tenant") if shape.tenant else None
            return Identity(
                issuer=trust.issuer,
                subject=_text(claims["sub"], "subject"),
                expires_at=_integer(claims["exp"], "expiry"),
                client=client,
                tenant=tenant,
                scopes=scopes,
                claims=MappingProxyType({name: value for name, value in claims.items() if isinstance(value, str)}),
            )
        except OAuthError:
            raise
        except Exception as exc:
            raise OAuthError("Invalid access token") from exc


# ---------------------------------------------------------------------------
# What they may do, and proof that the holder asked
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    capabilities: Mapping[str, Mapping[str, Any]]
    ttl_seconds: int = 120
    max_depth: int = 0
    expires_at: Optional[float] = None  # When the approval behind it ends, if it has an end.


@dataclass(frozen=True)
class Issuance:
    identity: Identity
    task_id: str
    holder: str
    warrant_id: str
    expires_at: str


class ProofStore(Protocol):
    def claim(self, key: str, expires_at: float, owner: str) -> bool:
        """Remember a proof until it expires. False if already there; ``OAuthUnavailable`` if there is no room."""
        ...

    def release(self, key: str) -> None:
        """Forget a proof whose request did not end in a warrant."""
        ...


class SQLiteProofStore:
    """Proofs shared by the processes on one host. One owner holds at most ``per_owner`` of them."""

    def __init__(self, path: str, *, capacity: int = 100000, per_owner: Optional[int] = None):
        if path == ":memory:":
            raise ValueError("The proof store needs a file")
        self.path, self.capacity = str(Path(path)), _integer(capacity, "capacity", 1, 10000000)
        self.per_owner = max(1, capacity // 4) if per_owner is None else _integer(per_owner, "share", 1, capacity)
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("CREATE TABLE IF NOT EXISTS proofs (key TEXT PRIMARY KEY, expires REAL NOT NULL, owner TEXT)")
            db.execute("CREATE INDEX IF NOT EXISTS proofs_owner ON proofs (owner)")

    def claim(self, key: str, expires_at: float, owner: str) -> bool:
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM proofs WHERE expires < ?", (time.time(),))
            if db.execute("SELECT 1 FROM proofs WHERE key = ?", (key,)).fetchone():
                return False
            if db.execute("SELECT COUNT(*) FROM proofs").fetchone()[0] >= self.capacity:
                raise OAuthUnavailable("Issuer is at its limit for recent exchanges; retry shortly")
            if db.execute("SELECT COUNT(*) FROM proofs WHERE owner = ?", (owner,)).fetchone()[0] >= self.per_owner:
                raise OAuthUnavailable("This caller is at its limit for recent exchanges; retry shortly")
            db.execute("INSERT INTO proofs VALUES (?, ?, ?)", (key, expires_at, owner))
        return True

    def release(self, key: str) -> None:
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("DELETE FROM proofs WHERE key = ?", (key,))


def _proof_bytes(presented: str, audience: str, task_id: str, holder: bytes, stamp: int, nonce: bytes) -> bytes:
    def digest(value: str) -> bytes:
        return hashlib.sha256(value.encode("utf-8")).digest()

    return _CONTEXT + digest(presented) + digest(audience) + digest(task_id) + holder + stamp.to_bytes(8, "big") + nonce


def sign_holder_proof(presented: str, holder_key: SigningKey, *, audience: str, task_id: str) -> SpiffeHolderProof:
    """Bind a holder key to one credential, one issuer audience and one task. The same call for every credential."""
    stamp, nonce = int(time.time()), secrets.token_bytes(16)
    message = _proof_bytes(presented, audience, task_id, bytes(holder_key.public_key.to_bytes()), stamp, nonce)
    return SpiffeHolderProof(stamp, nonce, bytes(holder_key.sign_raw(message)))


# ---------------------------------------------------------------------------
# The issuer
# ---------------------------------------------------------------------------


class WarrantIssuer:
    """Identity in, task-scoped warrant out, whatever proved the identity."""

    def __init__(
        self,
        *,
        credentials: Sequence[Credential],
        signing_key: SigningKey,
        policy: Callable[[Identity, str], Optional[Grant]],
        proofs: ProofStore,
        audit: Callable[[Issuance], None],
        max_ttl_seconds: int = 120,
    ):
        if not credentials or not callable(policy) or not callable(audit):
            raise ValueError("credentials, policy and audit are required")
        self.credentials, self._signing_key = tuple(credentials), signing_key
        self._policy, self._proofs, self._audit = policy, proofs, audit
        self._max_ttl = _integer(max_ttl_seconds, "maximum TTL", 1, 3600)

    def authenticate(self, presented: str) -> Tuple[Credential, Identity]:
        """Check ``presented`` with the one credential that claims it."""
        for credential in self.credentials:
            if credential.accepts(presented):
                return credential, credential.authenticate(presented)
        raise OAuthError("Invalid access token")

    def issue(self, presented: str, holder: PublicKey, task_id: str, proof: SpiffeHolderProof) -> Warrant:
        credential, identity = self.authenticate(presented)
        return self._issue(credential, identity, presented, holder, task_id, proof)

    def _issue(
        self,
        credential: Credential,
        identity: Identity,
        presented: str,
        holder: PublicKey,
        task_id: str,
        proof: SpiffeHolderProof,
    ) -> Warrant:
        _text(task_id, "task ID")
        key = bytes(holder.to_bytes())
        if not _positive_int(proof.timestamp) or abs(time.time() - proof.timestamp) > _PROOF_SECONDS:
            raise OAuthError("Holder proof is too old or from the future")
        message = _proof_bytes(presented, credential.audience, task_id, key, proof.timestamp, proof.nonce)
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(key).verify(proof.signature, message)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise OAuthError("Invalid holder proof") from exc
        claimed = hashlib.sha256(message).hexdigest()
        if not self._proofs.claim(claimed, proof.timestamp + _PROOF_SECONDS + 1, identity.key):
            raise OAuthError("Holder proof already used")
        try:
            grant = _run_callback(self._policy, identity, task_id)
            if grant is None:
                raise OAuthError("Not authorized for this task")
            ends = min(identity.expires_at, grant.expires_at if grant.expires_at is not None else float("inf"))
            ttl = min(self._max_ttl, _integer(grant.ttl_seconds, "TTL", 1, 3600), int(ends - time.time()) - 1)
            if ttl < 1 or not grant.capabilities:
                raise OAuthError("Grant is empty or ends too soon")
            builder = (
                Warrant.mint_builder().holder(holder).ttl(ttl).max_depth(_integer(grant.max_depth, "depth", 0, 16))
            )
            for tool, constraints in grant.capabilities.items():
                if not constraints:
                    raise OAuthError("Tools must have explicit argument constraints")
                builder.capability(_text(tool, "tool"), dict(constraints))
            warrant = builder.mint(self._signing_key)
            if datetime.fromisoformat(warrant.expires_at()).timestamp() > ends:
                raise OAuthError("Warrant would outlive its grant")
            _run_callback(self._audit, Issuance(identity, task_id, key.hex(), warrant.id, warrant.expires_at()))
            return warrant
        except BaseException:
            self._proofs.release(claimed)  # A request that got no warrant leaves nothing behind.
            raise


class WarrantIssuerApp(_IssuerApp):
    """ASGI ``POST /warrants`` for a ``WarrantIssuer``.

    The credential is checked in a pool of its own before the request takes a
    place or its body is read. (This pool belongs in the shared base; the
    JWT-SVID endpoint has the same few lines.)
    """

    _what = "Warrant issuance"
    _challenge = b"Bearer"

    def __init__(self, issuer: WarrantIssuer, *, max_per_identity: int = 16, **options: Any):
        if not _positive_int(max_per_identity) or max_per_identity < 1:
            raise ValueError("max_per_identity must be a positive integer")
        super().__init__(cast(Any, issuer), **options)
        self._issuer, self._max_per_key = issuer, max_per_identity

    def _new_pool(self) -> ThreadPoolExecutor:
        self._check_pool = ThreadPoolExecutor(min(4, self._max_workers), thread_name_prefix="tenuo-issuance-check")
        return super()._new_pool()

    def close(self) -> None:
        super().close()
        self._check_pool.shutdown(wait=False)

    def _credential(self, scope: Mapping[str, Any]) -> str:
        values = [value for name, value in scope.get("headers", ()) if name.lower() == b"authorization"]
        scheme, _, value = (values[0] if len(values) == 1 else b"").partition(b" ")
        if scheme.lower() != b"bearer" or not value or len(value) > _MAX_TOKEN:
            raise _Refusal(401, "invalid_token", "Send one Bearer access token")
        try:
            return value.decode("ascii")
        except UnicodeError:
            raise _Refusal(401, "invalid_token", "Invalid access token") from None

    def _authenticate(self, presented: str) -> Tuple[Credential, Identity]:
        try:
            return self._issuer.authenticate(presented)
        except OAuthUnavailable:
            raise _Refusal(503, "unavailable", "Credential validation temporarily unavailable") from None
        except OAuthError:
            raise _Refusal(401, "invalid_token", "Access token not accepted") from None

    async def _checked(self, credential: str) -> Tuple[str, Identity]:
        places = self._places
        if places.checking >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        try:
            work = asyncio.wrap_future(self._check_pool.submit(self._authenticate, credential))
        except RuntimeError:
            raise _Refusal(503, "unavailable", "Issuer is shutting down") from None
        places.checking += 1

        def checked(done: "asyncio.Future[Any]") -> None:
            places.checking -= 1
            if not done.cancelled():
                done.exception()

        work.add_done_callback(checked)
        return credential, (await asyncio.shield(work))[1]

    def _limit_key(self, credential: Tuple[str, Identity]) -> str:
        return credential[1].key

    def _authorize(self, credential: Tuple[str, Identity], holder: PublicKey, task_id: Any, proof: Any) -> Warrant:
        source, identity = self._authenticate(credential[0])  # Again: keys can change while the body arrives.
        try:
            return self._issuer._issue(source, identity, credential[0], holder, task_id, proof)
        except OAuthError as exc:
            if _from_callback(exc):
                raise _CallbackFailed() from exc  # The policy's or audit's own failure: logged, not sent.
            if isinstance(exc, OAuthUnavailable):
                raise _Refusal(503, "unavailable", str(exc)) from exc
            raise _Refusal(403, "refused", str(exc)) from exc
