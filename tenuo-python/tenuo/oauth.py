"""OAuth access-token authentication and task-scoped warrant issuance.

Supports explicitly configured Keycloak JWT access tokens and RFC 9068 JWTs.
Opaque and sender-constrained tokens are rejected. This is a resource server,
not an OAuth authorization server or an AAT token-exchange implementation.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Protocol, Tuple
from urllib.parse import urlsplit

try:
    import httpx
    import jwt
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
except ImportError as exc:
    raise ImportError("Install tenuo[oauth] to use the OAuth adapter") from exc

from tenuo import Exact, PublicKey, Range, SigningKey, Warrant
from tenuo._spiffe_http import _IssuerApp, _Refusal, _request_body
from tenuo.spiffe import SpiffeHolderProof, _checked_warrant

__all__ = [
    "OAuthError",
    "OAuthUnavailable",
    "OAuthCaller",
    "OAuthAccessTokens",
    "OAuthHolderProof",
    "OAuthWarrantIssuer",
    "OAuthWarrantIssuerApp",
    "OAuthIssuance",
    "ReplayStore",
    "SQLiteReplayStore",
    "TaskGrant",
    "TaskTemplate",
    "ExactFrom",
    "MaximumFrom",
    "sign_oauth_holder_proof",
    "request_warrant_oauth",
    "arequest_warrant_oauth",
]

_MAX_TOKEN = 16384
_MAX_JSON = 262144
_WINDOW = 30
_CONTEXT = b"tenuo.oauth.holder-binding.v1\0"
OAuthHolderProof = SpiffeHolderProof


class OAuthError(ValueError):
    """Invalid credential, holder proof, or task authorization (no token in errors)."""


class OAuthUnavailable(OAuthError):
    """A required issuance dependency is unavailable; authority was not granted."""


def _object(pairs: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OAuthError("Duplicate JSON member")
        result[key] = value
    return result


def _json(raw: Any) -> Any:
    return json.loads(raw, object_pairs_hook=_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def _text(value: Any, name: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise OAuthError(f"Invalid {name}")
    return value


def _integer(value: Any, name: str, minimum: int = 0, maximum: int = 2**40) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OAuthError(f"Invalid {name}")
    return value


def _url(value: str, allow_loopback_http: bool) -> None:
    parts = urlsplit(value)
    try:
        loopback = parts.hostname == "localhost" or ipaddress.ip_address(parts.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if (
        parts.scheme != "https" and not (allow_loopback_http and parts.scheme == "http" and loopback)
    ) or not parts.hostname:
        raise ValueError("Use HTTPS; local HTTP requires allow_loopback_http=True")
    if parts.username or parts.password or parts.fragment or parts.query:
        raise ValueError("Endpoint URLs must not contain credentials, query, or fragment")


@dataclass(frozen=True)
class OAuthCaller:
    issuer: str
    subject: str
    client_id: str
    tenant_id: str
    scopes: FrozenSet[str]
    expires_at: int


class OAuthAccessTokens:
    """Validate JWT access tokens against one configured issuer and resource.

    ``jwks_url`` is operator configuration, never read from a token. A successful
    refresh replaces the whole key set. Expired caches never survive a failed
    refresh; unknown-key refreshes are throttled. Call ``refresh()`` to apply an
    operator-requested withdrawal immediately. No automatic discovery or redirects.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        allowed_clients: FrozenSet[str],
        profile: str = "rfc9068",
        tenant_claim: str = "tenant_id",
        required_scopes: FrozenSet[str] = frozenset(),
        cache_seconds: float = 300,
        refresh_interval: float = 5,
        timeout: float = 5,
        allow_loopback_http: bool = False,
    ):
        _url(issuer, allow_loopback_http)
        _url(jwks_url, allow_loopback_http)
        if profile not in ("keycloak", "rfc9068"):
            raise ValueError("profile must be keycloak or rfc9068")
        if not allowed_clients or isinstance(allowed_clients, str):
            raise ValueError("allowed_clients must name explicitly trusted OAuth clients")
        for value in (cache_seconds, refresh_interval, timeout):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("Cache and timeout settings must be finite and positive")
        self.issuer, self.audience = issuer, _text(audience, "audience")
        self.jwks_url, self.profile = jwks_url, profile
        self.allowed_clients = frozenset(_text(c, "client") for c in allowed_clients)
        self.required_scopes = frozenset(required_scopes)
        self.tenant_claim = _text(tenant_claim, "tenant claim")
        self.cache_seconds, self.refresh_interval = cache_seconds, refresh_interval
        self._keys: Dict[str, Tuple[str, Any]] = {}
        self._loaded = self._attempted = float("-inf")
        self._lock = threading.Lock()
        self._http = httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)

    def close(self) -> None:
        self._http.close()

    def _load(self) -> None:
        self._attempted = time.monotonic()
        try:
            with self._http.stream("GET", self.jwks_url) as response:
                response.raise_for_status()
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > _MAX_JSON:
                        raise ValueError("JWKS too large")
            document = _json(raw)
            entries = document["keys"]
            if not isinstance(entries, list) or len(entries) > 100:
                raise ValueError("Invalid keys")
            keys: Dict[str, Tuple[str, Any]] = {}
            seen = set()
            for entry in entries:
                kid = _text(entry.get("kid"), "key ID")
                if kid in seen:
                    raise ValueError("Duplicate key ID")
                seen.add(kid)
                if entry.get("use", "sig") != "sig" or entry.get("key_ops", ["verify"]) != ["verify"]:
                    continue
                if any(k in entry for k in ("d", "p", "q", "k")):
                    raise ValueError("Private or symmetric key")
                algorithm = entry.get("alg") or {"RSA": "RS256", "EC": "ES256"}.get(entry.get("kty"))
                if algorithm not in ("RS256", "ES256"):
                    continue
                key = jwt.PyJWK.from_dict(entry, algorithm=algorithm).key
                if algorithm == "RS256" and not (isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048):
                    raise ValueError("Invalid RSA key")
                if algorithm == "ES256" and not (
                    isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
                ):
                    raise ValueError("Invalid EC key")
                keys[kid] = (algorithm, key)
            self._keys, self._loaded = keys, time.monotonic()
        except Exception as exc:
            raise OAuthUnavailable("OAuth signing keys unavailable") from exc

    def refresh(self) -> None:
        with self._lock:
            self._load()

    def authenticate(self, token: str) -> OAuthCaller:
        try:
            _text(token, "access token", _MAX_TOKEN)
            segments = token.split(".")
            if len(segments) != 3:
                raise ValueError()
            decoded = []
            for segment in segments:
                raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
                if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
                    raise ValueError()
                decoded.append(raw)
            header, payload = _json(decoded[0]), _json(decoded[1])
            if not isinstance(header, dict) or not isinstance(payload, dict):
                raise ValueError()
            if set(header) - {"alg", "kid", "typ"}:
                raise ValueError()
            expected_type = "JWT" if self.profile == "keycloak" else "at+jwt"
            if header.get("typ") != expected_type or header.get("alg") not in ("RS256", "ES256"):
                raise ValueError()
            kid = _text(header.get("kid"), "key ID")
            with self._lock:
                now = time.monotonic()
                expired = now - self._loaded >= self.cache_seconds
                if expired or kid not in self._keys:
                    if now - self._attempted >= self.refresh_interval:
                        self._load()
                    elif expired:
                        raise OAuthUnavailable("OAuth signing keys unavailable")
                algorithm, key = self._keys[kid]
            if algorithm != header["alg"]:
                raise ValueError()
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
            if self.profile == "rfc9068":
                _text(claims.get("jti"), "token ID")
            if "cnf" in claims or "act" in claims or "may_act" in claims:
                raise OAuthError("Sender-constrained and actor-chain tokens are not supported")
            if self.profile == "keycloak" and claims.get("typ") != "Bearer":
                raise ValueError()
            client = _text(claims.get("azp" if self.profile == "keycloak" else "client_id"), "client")
            if client not in self.allowed_clients:
                raise ValueError()
            expiry = _integer(claims["exp"], "expiry")
            issued = _integer(claims["iat"], "issued at")
            if issued >= expiry:
                raise ValueError()
            if "nbf" in claims:
                _integer(claims["nbf"], "not before")
            scope = claims.get("scope", "")
            if not isinstance(scope, str):
                raise ValueError()
            scopes = frozenset(scope.split())
            if not self.required_scopes <= scopes:
                raise ValueError()
            return OAuthCaller(
                self.issuer,
                _text(claims["sub"], "subject"),
                client,
                _text(claims.get(self.tenant_claim), "tenant"),
                scopes,
                expiry,
            )
        except OAuthError:
            raise
        except Exception as exc:
            raise OAuthError("Invalid OAuth access token") from exc


@dataclass(frozen=True)
class ExactFrom:
    """Bind one argument to a field in a trusted task record."""

    field: str


@dataclass(frozen=True)
class MaximumFrom:
    """An integer per-call limit. This is not cumulative accounting."""

    field: str
    minimum: int = 1


@dataclass(frozen=True)
class TaskGrant:
    capabilities: Mapping[str, Mapping[str, Any]]
    expires_at: int
    ttl_seconds: int = 120
    max_depth: int = 0


class TaskTemplate:
    """Compile a server-owned approved task to concrete constraints.

    The loader must return a trusted record, not fields supplied by the agent.
    Required record fields: task_id, issuer, subject, tenant_id, status,
    expires_at. All configured argument fields must be present. Unknown tool
    arguments remain unauthorized. This template is for user-owned tasks.
    """

    def __init__(
        self,
        *,
        tool: str,
        arguments: Mapping[str, Any],
        required_scopes: FrozenSet[str],
        ttl_seconds: int = 120,
        max_depth: int = 0,
    ):
        self.tool = _text(tool, "tool")
        if not arguments or any(not isinstance(v, (ExactFrom, MaximumFrom)) for v in arguments.values()):
            raise ValueError("Every argument needs ExactFrom or MaximumFrom")
        for key, binding in arguments.items():
            _text(key, "argument")
            _text(binding.field, "task field")
            if isinstance(binding, MaximumFrom):
                _integer(binding.minimum, "minimum", 0, 2**53 - 1)
        self.arguments = MappingProxyType(dict(arguments))
        self.required_scopes = frozenset(required_scopes)
        self.ttl_seconds = _integer(ttl_seconds, "TTL", 1, 3600)
        self.max_depth = _integer(max_depth, "delegation depth", 0, 16)

    def compile(self, caller: OAuthCaller, task_id: str, record: Mapping[str, Any]) -> TaskGrant:
        if (
            record.get("task_id") != task_id
            or record.get("issuer") != caller.issuer
            or record.get("subject") != caller.subject
            or record.get("tenant_id") != caller.tenant_id
            or record.get("status") != "approved"
            or not self.required_scopes <= caller.scopes
        ):
            raise OAuthError("Task is not authorized for this caller")
        expiry = _integer(record.get("expires_at"), "task expiry")
        if expiry <= time.time():
            raise OAuthError("Task approval expired")
        constraints = {}
        for argument, binding in self.arguments.items():
            if binding.field not in record:
                raise OAuthError("Task is missing an authorization field")
            value = record[binding.field]
            if isinstance(binding, MaximumFrom):
                value = _integer(value, "task limit", binding.minimum, 2**53 - 1)
                constraints[argument] = Range(binding.minimum, value)
            else:
                if not isinstance(value, (str, bool, int)) or (type(value) is int and abs(value) > 2**53 - 1):
                    raise OAuthError("Exact task fields must be strings, booleans, or safe integers")
                constraints[argument] = Exact(value)
        return TaskGrant(
            MappingProxyType({self.tool: MappingProxyType(constraints)}), expiry, self.ttl_seconds, self.max_depth
        )


class ReplayStore(Protocol):
    def claim(self, key: str, expires_at: float) -> bool:
        """Atomically reserve a proof until expiry; fail closed on store failure."""
        ...


class SQLiteReplayStore:
    """Durable replay store shared by processes on one host (not network filesystems).

    Use a shared transactional implementation of ReplayStore for multi-host
    deployments. Entries remain consumed after policy/audit failure; retry with
    a fresh proof. This store does not make business operations idempotent.
    """

    def __init__(self, path: str, *, capacity: int = 100000):
        if path == ":memory:":
            raise ValueError("Replay store requires a persistent file")
        self.path = str(Path(path))
        self.capacity = _integer(capacity, "replay capacity", 1, 10000000)
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("CREATE TABLE IF NOT EXISTS oauth_proofs (key TEXT PRIMARY KEY, expires REAL NOT NULL)")

    def claim(self, key: str, expires_at: float) -> bool:
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM oauth_proofs WHERE expires < ?", (time.time(),))
            if db.execute("SELECT 1 FROM oauth_proofs WHERE key = ?", (key,)).fetchone():
                return False
            if db.execute("SELECT COUNT(*) FROM oauth_proofs").fetchone()[0] >= self.capacity:
                raise OAuthUnavailable("Issuance replay store is full")
            db.execute("INSERT INTO oauth_proofs VALUES (?, ?)", (key, expires_at))
        return True


def _proof_bytes(token: str, audience: str, task_id: str, holder: bytes, stamp: int, nonce: bytes) -> bytes:
    _text(token, "access token", _MAX_TOKEN)
    _text(audience, "audience")
    _text(task_id, "task ID")
    _integer(stamp, "timestamp")
    if not isinstance(nonce, bytes) or len(nonce) != 16:
        raise OAuthError("Invalid nonce")

    def digest(value: str) -> bytes:
        return hashlib.sha256(value.encode("utf-8")).digest()

    return _CONTEXT + digest(token) + digest(audience) + digest(task_id) + holder + stamp.to_bytes(8, "big") + nonce


def sign_oauth_holder_proof(token: str, holder_key: SigningKey, *, audience: str, task_id: str) -> OAuthHolderProof:
    stamp, nonce = int(time.time()), secrets.token_bytes(16)
    message = _proof_bytes(token, audience, task_id, bytes(holder_key.public_key.to_bytes()), stamp, nonce)
    return OAuthHolderProof(stamp, nonce, bytes(holder_key.sign_raw(message)))


@dataclass(frozen=True)
class OAuthIssuance:
    caller: OAuthCaller
    task_id: str
    holder: str
    warrant_id: str
    expires_at: str


class OAuthWarrantIssuer:
    """Issue only after credential, holder proof, and application policy checks.

    audit is required and runs before a warrant is released. Callbacks run in
    bounded HTTP worker threads and must impose their own dependency deadlines.
    No refresh tokens are accepted or stored. No OAuth revocation propagation is
    implied: existing warrants remain valid until their expiry or verifier-side revocation.
    """

    def __init__(
        self,
        *,
        credentials: OAuthAccessTokens,
        signing_key: SigningKey,
        policy: Callable[[OAuthCaller, str], Optional[TaskGrant]],
        replay_store: ReplayStore,
        audit: Callable[[OAuthIssuance], None],
        max_ttl_seconds: int = 120,
    ):
        self.credentials, self.signing_key = credentials, signing_key
        self.policy, self.replay_store, self.audit = policy, replay_store, audit
        if not callable(policy) or not callable(audit):
            raise ValueError("policy and audit callbacks are required")
        self.max_ttl = _integer(max_ttl_seconds, "maximum TTL", 1, 3600)

    def issue(self, token: str, holder: PublicKey, task_id: str, proof: OAuthHolderProof) -> Warrant:
        caller = self.credentials.authenticate(token)
        return self._issue_authenticated(caller, token, holder, task_id, proof)

    def _issue_authenticated(
        self, caller: OAuthCaller, token: str, holder: PublicKey, task_id: str, proof: OAuthHolderProof
    ) -> Warrant:
        message = _proof_bytes(
            token, self.credentials.audience, task_id, bytes(holder.to_bytes()), proof.timestamp, proof.nonce
        )
        if abs(time.time() - proof.timestamp) > _WINDOW:
            raise OAuthError("Holder proof expired")
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(bytes(holder.to_bytes())).verify(proof.signature, message)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise OAuthError("Invalid holder proof") from exc
        # Reservation is based on the signed message, not signature bytes.
        if not self.replay_store.claim(hashlib.sha256(message).hexdigest(), proof.timestamp + _WINDOW + 1):
            raise OAuthError("Holder proof already used")
        grant = self.policy(caller, task_id)
        if grant is None:
            raise OAuthError("Task is not authorized for this caller")
        expiry = min(caller.expires_at, _integer(grant.expires_at, "task expiry"))
        ttl = min(self.max_ttl, _integer(grant.ttl_seconds, "TTL", 1, 3600), int(expiry - time.time()) - 1)
        depth = _integer(grant.max_depth, "delegation depth", 0, 16)
        if ttl < 1 or not grant.capabilities:
            raise OAuthError("Grant is empty or expires too soon")
        builder = Warrant.mint_builder().holder(holder).ttl(ttl).max_depth(depth)
        for tool, constraints in grant.capabilities.items():
            if not constraints:
                raise OAuthError("Tools must have explicit argument constraints")
            builder.capability(_text(tool, "tool"), dict(constraints))
        warrant = builder.mint(self.signing_key)
        if datetime.fromisoformat(warrant.expires_at()).timestamp() > expiry:
            raise OAuthError("Warrant would outlive its grant")
        self.audit(OAuthIssuance(caller, task_id, bytes(holder.to_bytes()).hex(), warrant.id, warrant.expires_at()))
        return warrant


class OAuthWarrantIssuerApp(_IssuerApp):
    """Bounded ASGI POST /warrants endpoint. Terminate HTTPS at the ASGI server or trusted ingress."""

    _what = "OAuth issuance"
    _challenge = b"Bearer"

    def __init__(self, issuer: OAuthWarrantIssuer, **kwargs: Any):
        super().__init__(issuer, **kwargs)  # type: ignore[arg-type]
        self.oauth_issuer = issuer

    @staticmethod
    def _decode_request(body: bytes) -> Any:
        request = _json(body)
        if not isinstance(request, dict) or type(request.get("v")) is not int:
            raise ValueError("Invalid request version")
        return request

    def _credential(self, scope: Mapping[str, Any]) -> str:
        headers = scope.get("headers", ())
        types = [v for k, v in headers if k.lower() == b"content-type"]
        if len(types) != 1 or types[0].split(b";")[0].strip().lower() != b"application/json":
            raise _Refusal(415, "invalid_request", "Use application/json")
        values = [v for k, v in headers if k.lower() == b"authorization"]
        scheme, _, value = (values[0] if len(values) == 1 else b"").partition(b" ")
        if scheme.lower() != b"bearer" or not value or len(value) > _MAX_TOKEN:
            raise _Refusal(401, "invalid_token", "Send one Bearer access token")
        try:
            return value.decode("ascii")
        except UnicodeError:
            raise _Refusal(401, "invalid_token", "Invalid access token") from None

    def _authorize(self, credential: str, holder: PublicKey, task_id: Any, proof: OAuthHolderProof) -> Warrant:
        try:
            caller = self.oauth_issuer.credentials.authenticate(credential)
        except OAuthUnavailable:
            raise _Refusal(503, "unavailable", "Credential validation temporarily unavailable") from None
        except OAuthError:
            raise _Refusal(401, "invalid_token", "Access token not accepted") from None
        try:
            return self.oauth_issuer._issue_authenticated(caller, credential, holder, task_id, proof)
        except OAuthUnavailable:
            raise _Refusal(503, "unavailable", "Issuance temporarily unavailable") from None
        except OAuthError as exc:
            raise _Refusal(403, "refused", str(exc)) from exc


def request_warrant_oauth(
    url: str,
    *,
    token: str,
    audience: str,
    issuer_key: PublicKey,
    holder_key: SigningKey,
    task_id: str,
    timeout: float = 10,
    allow_loopback_http: bool = False,
) -> Warrant:
    """Request and verify a warrant; never follow credential-bearing redirects."""
    _url(url, allow_loopback_http)
    proof = sign_oauth_holder_proof(token, holder_key, audience=audience, task_id=task_id)
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        with client.stream(
            "POST",
            url,
            content=_request_body(holder_key, task_id, proof),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        ) as response:
            if response.status_code != 200:
                raise OAuthError(f"Warrant issuance refused ({response.status_code})")
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > _MAX_JSON:
                    raise OAuthError("Issuer response too large")
    try:
        warrant = _checked_warrant(_json(raw)["warrant"], [issuer_key], holder_key)
    except Exception as exc:
        raise OAuthError("Invalid warrant response") from exc
    return warrant


async def arequest_warrant_oauth(url: str, **kwargs: Any) -> Warrant:
    return await asyncio.to_thread(request_warrant_oauth, url, **kwargs)
