"""Task-scoped warrants for callers who already have a token from your identity provider.

Use this when agents sign in with OAuth 2.0 or OpenID Connect (through an API
gateway, an MCP gateway, a CI system) and you want each task to carry only
the authority that task needs.

The token says who is asking. It carries no Tenuo permissions. A ``Trust``
names whose tokens you accept: the issuer, the audience, where that provider
puts its claims, and which claim values are required. Your policy decides
what an identity may do for a task, and the issuer mints a warrant bound to
the agent's holder key that ends no later than the token.

This is a resource server. It is not an authorization server, and the
warrant is not an OAuth access token. Opaque tokens, sender-constrained
tokens and tokens with an actor chain are refused.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
import inspect
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError as exc:
    raise ImportError("Install tenuo[oauth] to use the OAuth adapter") from exc

from tenuo import Exact, PublicKey, Range, SigningKey, Warrant
from tenuo._issuance import (
    HolderProof,
    IssuanceBusy,
    IssuanceError,
    MemoryProofStore,
    ProofStore,
    SingleRequestIssuer,
    SQLiteProofStore,
    Wording,
    _positive_int,
    _seconds,
)
from tenuo._issuance_http import (
    _IssuerApp,
    _post_for_warrant,
    _Refusal,
    _request_body,
    _split_url,
    _strict_json,
    _where,
)

__all__ = [
    "GITHUB_ACTIONS",
    "KEYCLOAK",
    "RFC9068",
    "ClaimMap",
    "ExactFrom",
    "MaximumFrom",
    "MemoryProofStore",
    "OAuthError",
    "OAuthHolderProof",
    "OAuthIdentity",
    "OAuthIssuance",
    "OAuthTokens",
    "OAuthUnavailable",
    "OAuthWarrantIssuer",
    "OAuthWarrantIssuerApp",
    "ProofStore",
    "SQLiteProofStore",
    "TaskGrant",
    "TaskTemplate",
    "Trust",
    "arequest_warrant_oauth",
    "request_warrant_oauth",
    "sign_oauth_holder_proof",
]

logger = logging.getLogger("tenuo.oauth")

_MAX_TOKEN = 16384
_MAX_JSON = 262144
_CONTEXT = b"tenuo.oauth.holder-binding.v1\0"
OAuthHolderProof = HolderProof


class OAuthError(IssuanceError):
    """A credential, holder proof or task was refused. Messages never contain the token."""


class OAuthUnavailable(OAuthError, IssuanceBusy):
    """Something issuance depends on is unavailable or at its limit. Nothing was granted; try again."""


def _json(raw: Any) -> Any:
    try:
        return _strict_json(raw)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None


def _text(value: Any, name: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OAuthError(f"Invalid {name}")
    if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):  # Control characters and lone surrogates.
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
    parts.port  # Raises ValueError for a port that is not one.


# ---------------------------------------------------------------------------
# Whose tokens are accepted
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OAuthIdentity:
    """What a verified token said about the caller.

    ``claims`` holds the token's other string claims (a repository, a branch,
    an environment), for a policy to read. Everything here was signed by the
    provider; nothing was supplied by the agent.
    """

    issuer: str
    subject: str
    client_id: Optional[str]
    tenant_id: Optional[str]
    scopes: FrozenSet[str]
    expires_at: int
    claims: Mapping[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """The name limits are counted against: one user or workload, through one client, at one issuer."""
        return json.dumps([self.issuer, self.client_id, self.subject], separators=(",", ":"))


@dataclass(frozen=True)
class ClaimMap:
    """How one provider writes its tokens. The first claim listed that is present is used.

    The presets are the providers this adapter is tested against. For another
    provider, write its ``ClaimMap`` from one of its tokens.
    """

    client: Tuple[str, ...] = ("client_id",)
    scopes: Tuple[str, ...] = ("scope",)  # A space-separated string, or a list of strings.
    header_type: str = "at+jwt"
    extra_headers: FrozenSet[str] = frozenset()  # Header names allowed besides alg, kid and typ.
    constants: Mapping[str, str] = field(default_factory=dict)  # Claims that must have exactly this value.
    has_clients: bool = True
    needs_token_id: bool = False


RFC9068 = ClaimMap(needs_token_id=True)
"""JWT access tokens as RFC 9068 defines them (``typ: at+jwt``, ``client_id``, ``jti``)."""

KEYCLOAK = ClaimMap(client=("azp",), header_type="JWT", constants={"typ": "Bearer"})
"""Keycloak access tokens: the client is in ``azp`` and the payload says ``typ: Bearer``."""

GITHUB_ACTIONS = ClaimMap(client=(), scopes=(), header_type="JWT", extra_headers=frozenset({"x5t"}), has_clients=False)
"""GitHub Actions OIDC tokens. A workflow run is not an OAuth client and has no scopes:
say which runs you trust with ``Trust.where`` (``repository``, ``ref``, ``environment``)."""

Condition = Union[str, FrozenSet[str]]


@dataclass(frozen=True)
class Trust:
    """Whose tokens are accepted, for which audience, and what they must say.

    ``clients`` lists the OAuth clients allowed to ask for warrants. ``where``
    lists further claims that must match: one exact value, or one of a set. A
    claim that is missing does not match. ``tenant_claim`` names the claim
    that holds the caller's tenant, if you have tenants; it must be data an
    administrator controls, not something a user can edit.

    This is the whole trust decision, in one place an operator can read.
    """

    issuer: str
    audience: str
    jwks_url: str
    claims: ClaimMap = RFC9068
    clients: FrozenSet[str] = frozenset()
    where: Mapping[str, Condition] = field(default_factory=dict)
    tenant_claim: Optional[str] = None
    required_scopes: FrozenSet[str] = frozenset()
    leeway_seconds: int = 5


class OAuthTokens:
    """Checks tokens against one ``Trust``.

    Signing keys come from ``trust.jwks_url``, which is configuration and is
    never read from a token. A fetched key set replaces the one before it.
    Keys are used for ``cache_seconds`` after a successful fetch and fetched
    again in the background from half that age; past ``cache_seconds``, with
    the provider unreachable, tokens are refused.

    A token signed by a known key is never held up by a fetch. A token that
    needs one (a key ID not yet known, or no usable keys at all) sends its own
    caller to fetch, one at a time and at most every ``refresh_interval``
    seconds. Nobody waits for someone else's fetch: while one is under way,
    or after one failed, such a token is answered "unavailable" at once, to be
    tried again. No discovery, no redirects, no environment proxies.
    """

    def __init__(
        self,
        trust: Trust,
        *,
        cache_seconds: float = 300,
        refresh_interval: float = 5,
        timeout: float = 5,
        ca_file: Optional[str] = None,
        allow_loopback_http: bool = False,
    ):
        _url(trust.issuer, allow_loopback_http)
        _url(trust.jwks_url, allow_loopback_http)
        shape = trust.claims
        if isinstance(trust.clients, str) or isinstance(trust.required_scopes, str):
            raise ValueError("clients and required_scopes are sets of names")
        if shape.has_clients and not trust.clients:
            raise ValueError("clients must name the OAuth clients allowed to ask for warrants")
        if not shape.has_clients and (trust.clients or not trust.where):
            raise ValueError("This provider has no clients: say which tokens are trusted with where={claim: value}")
        if not _positive_int(trust.leeway_seconds) or not 0 <= trust.leeway_seconds <= 60:
            raise ValueError("leeway_seconds must be between 0 and 60")
        self.trust, self.audience = trust, _text(trust.audience, "audience")
        self._clients = frozenset(_text(client, "client") for client in trust.clients)
        self._cache_seconds = _seconds("cache_seconds", cache_seconds)
        self._refresh_interval = _seconds("refresh_interval", refresh_interval)
        self._timeout, self._ca_file = _seconds("timeout", timeout), ca_file
        self._keys: Dict[str, Tuple[str, Any]] = {}
        self._loaded = self._attempted = float("-inf")
        self._under_way = 0  # Fetches in progress, from any caller.
        self._failed = False  # Whether the latest fetch to finish failed.
        self._begun = self._in_use = 0  # Fetches begun, and which of them the keys in use came from.
        self._lock = threading.Lock()

    def close(self) -> None:
        """Nothing is held open between fetches. Kept so callers can treat every source alike."""

    # -- keys -------------------------------------------------------------

    def _fetch(self) -> Dict[str, Tuple[str, Any]]:
        scheme, host, port, path = _split_url(self.trust.jwks_url)
        deadline = time.monotonic() + self._timeout
        connection: http.client.HTTPConnection
        if scheme == "https":
            context = ssl.create_default_context(cafile=self._ca_file)
            connection = http.client.HTTPSConnection(host, port, timeout=self._timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=self._timeout)
        # The socket timeout bounds each read, not their sum, so a timer cuts off a
        # provider that sends a little at a time. It holds the socket itself (the
        # connection lets go of it once a reply says it will close), and shares a
        # lock with the code that closes it, so it never acts on a closed socket.
        ending = threading.Lock()
        held: Dict[str, Any] = {"socket": None, "over": False}

        def give_up() -> None:
            with ending:
                if held["over"] or held["socket"] is None:
                    return
                try:
                    socket.socket.shutdown(held["socket"], socket.SHUT_RDWR)
                except OSError:
                    pass

        timer = threading.Timer(self._timeout, give_up)
        timer.daemon = True
        timer.start()
        response: Optional[http.client.HTTPResponse] = None
        try:
            connection.connect()
            with ending:
                held["socket"] = connection.sock
            if time.monotonic() > deadline:
                raise ValueError("Key endpoint too slow")
            connection.request("GET", path, headers={"Accept": "application/json"})
            response = connection.getresponse()
            if response.status != 200:  # A redirect included: the key location is configuration.
                raise ValueError(f"HTTP {response.status}")
            raw = bytearray()
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > _MAX_JSON or time.monotonic() > deadline:
                    raise ValueError("Key set too large or too slow")
            if time.monotonic() > deadline:
                raise ValueError("Key endpoint too slow")
        finally:
            timer.cancel()
            with ending:
                held["over"] = True
                if response is not None:
                    response.close()  # Otherwise a refused answer keeps the socket until it is collected.
                connection.close()
        entries = _json(bytes(raw))["keys"]
        if not isinstance(entries, list) or len(entries) > 100 or any(not isinstance(e, dict) for e in entries):
            raise ValueError("Invalid keys")
        keys: Dict[str, Tuple[str, Any]] = {}
        seen = set()
        for entry in entries:
            # Two things refuse the whole set, whatever else the entry says: private
            # key material, and one key ID twice. An entry this adapter has no use
            # for is passed over, and a token signed by it is simply not accepted.
            if any(name in entry for name in ("d", "p", "q", "k")):
                raise ValueError("Private or symmetric key")
            kid = entry.get("kid")
            if isinstance(kid, str):
                if kid in seen:
                    raise ValueError("Duplicate key ID")
                seen.add(kid)
            if entry.get("use", "sig") != "sig" or entry.get("key_ops", ["verify"]) != ["verify"]:
                continue
            algorithm = entry.get("alg") or {"RSA": "RS256", "EC": "ES256"}.get(entry.get("kty"))
            if algorithm not in ("RS256", "ES256") or not isinstance(kid, str) or not kid or len(kid) > 1024:
                continue
            try:
                key = jwt.PyJWK.from_dict(entry, algorithm=algorithm).key
            except Exception:
                continue
            if algorithm == "RS256" and not (isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048):
                continue
            if algorithm == "ES256" and not (
                isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
            ):
                continue
            keys[kid] = (algorithm, key)
        return keys

    def _begin(self) -> int:
        """Count and number a fetch that is about to start. Call with the lock held."""
        self._begun += 1
        self._under_way += 1
        self._attempted = time.monotonic()
        return self._begun

    def _run(self, number: int) -> Optional[BaseException]:
        """Carry out fetch ``number`` and record how it went. Returns what went wrong, or None."""
        keys: Dict[str, Tuple[str, Any]] = {}
        failure: Optional[BaseException] = OAuthUnavailable("The key fetch was interrupted")
        try:
            keys = self._fetch()
            failure = None
        except Exception as exc:
            failure = exc
        finally:  # Whatever ended it, an interruption included, the fetch is over.
            with self._lock:
                self._under_way -= 1
                if (
                    failure is None and number > self._in_use
                ):  # A set fetched later is never replaced by an earlier one.
                    self._keys, self._loaded, self._in_use = keys, time.monotonic(), number
                if number >= self._in_use:
                    if failure is not None and not self._failed:
                        logger.warning("Could not fetch signing keys from %s: %r", self.trust.jwks_url, failure)
                    self._failed = failure is not None
        return failure

    def refresh(self) -> None:
        """Fetch the keys now, for example at start-up or right after the provider withdrew one."""
        with self._lock:
            number = self._begin()
        failure = self._run(number)
        if failure is not None:
            raise OAuthUnavailable("OAuth signing keys unavailable") from failure

    def _key(self, kid: str) -> Tuple[str, Any]:
        with self._lock:
            now = time.monotonic()
            age = now - self._loaded
            usable = age < self._cache_seconds
            due = self._under_way == 0 and now - self._attempted >= self._refresh_interval
            if usable and kid in self._keys:
                if due and age >= self._cache_seconds / 2:
                    # Fetch again well before the keys age out, without holding anyone up.
                    number = self._begin()
                    try:
                        threading.Thread(target=self._run, args=(number,), daemon=True, name="tenuo-oauth-keys").start()
                    except RuntimeError:  # No thread to be had: the next caller will try.
                        self._under_way -= 1
                return self._keys[kid]
            if not due:
                if not usable or self._under_way or self._failed:
                    # No keys to judge by, or a key that may be new and has not been fetched yet.
                    raise OAuthUnavailable("OAuth signing keys unavailable")
                raise OAuthError("Invalid OAuth access token")
            number = self._begin()
        failure = self._run(number)  # This caller only, and never while holding the lock.
        with self._lock:
            if time.monotonic() - self._loaded < self._cache_seconds and kid in self._keys:
                return self._keys[kid]
            if failure is not None or number != self._in_use:
                # The fetch failed, or another one overtook it: this token cannot be judged yet.
                raise OAuthUnavailable("OAuth signing keys unavailable") from failure
            raise OAuthError("Invalid OAuth access token")

    # -- tokens -----------------------------------------------------------

    @staticmethod
    def _parts(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        _text(token, "access token", _MAX_TOKEN)
        segments = token.split(".")
        if len(segments) != 3:
            raise ValueError()
        decoded = []
        for position, segment in enumerate(segments):
            raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
                raise ValueError()  # One spelling per token.
            if position < 2:
                decoded.append(_json(raw))
        header, payload = decoded
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError()
        return header, payload

    def issued(self, token: str) -> bool:
        """Whether the token says it is from this trust's issuer. Nothing is verified yet: it only picks who checks it."""
        try:
            return self._parts(token)[1].get("iss") == self.trust.issuer
        except Exception:
            return False

    def authenticate(self, token: str) -> OAuthIdentity:
        """Verify a token and return who it is for, or raise ``OAuthError``."""
        trust, shape = self.trust, self.trust.claims
        try:
            header, _ = self._parts(token)
            if set(header) - {"alg", "kid", "typ"} - shape.extra_headers:
                raise ValueError()
            if header.get("typ") != shape.header_type or header.get("alg") not in ("RS256", "ES256"):
                raise ValueError()
            algorithm, key = self._key(_text(header.get("kid"), "key ID"))
            if algorithm != header["alg"]:
                raise ValueError()
            claims = jwt.decode(
                token,
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
            for name, constant in shape.constants.items():
                if claims.get(name) != constant:
                    raise ValueError()
            client = next((claims[name] for name in shape.client if name in claims), None)
            if client is not None or shape.has_clients:
                _text(client, "client")
            if shape.has_clients and client not in self._clients:
                raise ValueError()
            for name, wanted in trust.where.items():
                found = claims.get(name)
                if not isinstance(found, str) or (found != wanted if isinstance(wanted, str) else found not in wanted):
                    raise ValueError()
            expiry, issued = _integer(claims["exp"], "expiry"), _integer(claims["iat"], "issued at")
            if issued >= expiry:
                raise ValueError()
            if "nbf" in claims:
                _integer(claims["nbf"], "not before")
            listed = next((claims[name] for name in shape.scopes if name in claims), "")
            if not isinstance(listed, (str, list)):
                raise ValueError()
            scopes = frozenset(listed.split() if isinstance(listed, str) else [_text(s, "scope") for s in listed])
            if not frozenset(trust.required_scopes) <= scopes:
                raise ValueError()
            return OAuthIdentity(
                issuer=trust.issuer,
                subject=_text(claims["sub"], "subject"),
                client_id=client,
                tenant_id=_text(claims.get(trust.tenant_claim), "tenant") if trust.tenant_claim else None,
                scopes=scopes,
                expires_at=expiry,
                claims=MappingProxyType({name: value for name, value in claims.items() if isinstance(value, str)}),
            )
        except OAuthError:
            raise
        except Exception as exc:
            raise OAuthError("Invalid OAuth access token") from exc


# ---------------------------------------------------------------------------
# What a task allows
# ---------------------------------------------------------------------------


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
    """What the policy grants: tools with argument constraints, for a time."""

    capabilities: Mapping[str, Mapping[str, Any]]
    expires_at: Optional[int] = None  # When the approval behind it ends, if it has an end.
    ttl_seconds: int = 120
    max_depth: int = 0


class TaskTemplate:
    """Turns an approved task record from your own database into argument constraints.

    The record must come from a store you trust, never from the agent. It
    carries ``task_id``, ``status`` (``"approved"``), integer ``expires_at``,
    one field for each name in ``owner``, and the fields the arguments refer
    to. ``owner`` says whose task it is, as attributes of the verified
    identity. By default it is a person's task: issuer and subject, and the
    tenant as well when the trust has a ``tenant_claim``. For a service acting
    for itself use ``("issuer", "client_id")``. An identity that lacks an
    attribute the owner names owns nothing. Arguments not named here stay
    unauthorized.

    ``compile`` returns ``None`` when there is no record, or the record is not
    this caller's approved and unexpired task: return that from your policy to
    deny. It raises when the record itself is unusable (a field missing or of
    the wrong type), which is a fault in your data, not in the request.
    """

    def __init__(
        self,
        *,
        tool: str,
        arguments: Mapping[str, Any],
        required_scopes: FrozenSet[str] = frozenset(),
        owner: Optional[Sequence[str]] = None,
        ttl_seconds: int = 120,
        max_depth: int = 0,
    ):
        self.tool = _text(tool, "tool")
        if isinstance(required_scopes, str) or isinstance(owner, str):
            raise ValueError("required_scopes and owner are collections of names")
        if not arguments or any(not isinstance(v, (ExactFrom, MaximumFrom)) for v in arguments.values()):
            raise ValueError("Every argument needs ExactFrom or MaximumFrom")
        for key, binding in arguments.items():
            _text(key, "argument")
            _text(binding.field, "task field")
            if isinstance(binding, MaximumFrom):
                _integer(binding.minimum, "minimum", 0, 2**53 - 1)
        if owner is not None:
            if not owner or any(name not in ("issuer", "subject", "client_id", "tenant_id") for name in owner):
                raise ValueError("owner names identity attributes: issuer, subject, client_id, tenant_id")
            if "issuer" not in owner:
                raise ValueError("owner must include the issuer: a subject or client means nothing without it")
        self.arguments = MappingProxyType(dict(arguments))
        self.owner = None if owner is None else tuple(owner)
        self.required_scopes = frozenset(required_scopes)
        self.ttl_seconds = _integer(ttl_seconds, "TTL", 1, 3600)
        self.max_depth = _integer(max_depth, "delegation depth", 0, 16)

    def compile(
        self, identity: OAuthIdentity, task_id: str, record: Optional[Mapping[str, Any]]
    ) -> Optional[TaskGrant]:
        if record is None:
            return None
        owner = self.owner or (("issuer", "subject") + (("tenant_id",) if identity.tenant_id is not None else ()))
        owned = all(
            getattr(identity, name) is not None and record.get(name) == getattr(identity, name) for name in owner
        )
        if (
            record.get("task_id") != task_id
            or not owned
            or record.get("status") != "approved"
            or not self.required_scopes <= identity.scopes
        ):
            return None
        expiry = _integer(record.get("expires_at"), "task expiry")
        if expiry <= time.time():
            return None
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


def _validated(grant: Any) -> TaskGrant:
    """Check what a policy returned, and return a copy of it.

    The copy is what gets minted. A policy may hand out mappings it keeps and
    changes (a cache, a shared default), and a change made after this check
    must not reach the warrant.
    """
    if not isinstance(grant, TaskGrant):
        raise OAuthError("Policy must return a TaskGrant or None")
    if not isinstance(grant.capabilities, Mapping):
        raise OAuthError("Grant is empty")
    capabilities: Dict[str, Mapping[str, Any]] = {}
    for tool, constraints in dict(grant.capabilities).items():
        _text(tool, "tool")
        if not isinstance(constraints, Mapping):
            raise OAuthError("Tools must have explicit argument constraints")
        copied = dict(constraints)
        # The core reads this key as a setting (accept arguments that are not listed),
        # not as a constraint. On its own it would allow any call to the tool.
        if not any(name != "_allow_unknown" for name in copied):
            raise OAuthError("Tools must have explicit argument constraints")
        capabilities[tool] = MappingProxyType(copied)
    if not capabilities:
        raise OAuthError("Grant is empty")
    ttl, depth, expiry = grant.ttl_seconds, grant.max_depth, grant.expires_at
    _integer(ttl, "TTL", 1, 3600)
    _integer(depth, "delegation depth", 0, 16)
    if expiry is not None:
        _integer(expiry, "task expiry")
    return TaskGrant(MappingProxyType(capabilities), expiry, ttl, depth)


# ---------------------------------------------------------------------------
# The issuer
# ---------------------------------------------------------------------------


def _proof_bytes(token: str, audience: str, task_id: str, holder: bytes, stamp: int, nonce: bytes) -> bytes:
    def digest(value: str) -> bytes:
        return hashlib.sha256(value.encode("utf-8")).digest()

    return _CONTEXT + digest(token) + digest(audience) + digest(task_id) + holder + stamp.to_bytes(8, "big") + nonce


def sign_oauth_holder_proof(token: str, holder_key: SigningKey, *, audience: str, task_id: str) -> OAuthHolderProof:
    """Bind a holder key to one token, one issuer audience and one task. Each call is a new proof."""
    _text(token, "access token", _MAX_TOKEN)
    _text(audience, "audience")
    _text(task_id, "task ID")
    stamp, nonce = int(time.time()), secrets.token_bytes(16)
    message = _proof_bytes(token, audience, task_id, bytes(holder_key.public_key.to_bytes()), stamp, nonce)
    return OAuthHolderProof(stamp, nonce, bytes(holder_key.sign_raw(message)))


@dataclass(frozen=True)
class OAuthIssuance:
    """Audit record passed to the issuer's ``audit`` callback before a warrant is released."""

    identity: OAuthIdentity
    task_id: str
    holder: str
    warrant_id: str
    expires_at: str


class OAuthWarrantIssuer:
    """Verified token and holder proof in, task-scoped warrant out.

    ``credentials`` is one ``OAuthTokens`` or several, one per issuer you
    trust. ``policy(identity, task_id)`` returns a ``TaskGrant`` or ``None``.
    ``audit`` is required and runs before a warrant is released: if it raises,
    no warrant is issued. Both run in the endpoint's worker threads and must
    set their own deadlines on what they call.

    Holder proofs are remembered in this process unless you pass a
    ``proof_store``: use ``SQLiteProofStore`` for several processes on one
    host. A warrant ends no later than the token, the task approval and
    ``max_ttl_seconds``. Revoking a token or changing a task afterwards does
    not revoke a warrant already issued.
    """

    def __init__(
        self,
        *,
        credentials: Union[OAuthTokens, Sequence[OAuthTokens]],
        signing_key: SigningKey,
        policy: Callable[[OAuthIdentity, str], Optional[TaskGrant]],
        audit: Callable[[OAuthIssuance], None],
        proof_store: Optional[ProofStore] = None,
        max_ttl_seconds: int = 120,
    ):
        self.credentials = (credentials,) if isinstance(credentials, OAuthTokens) else tuple(credentials)
        if not self.credentials or not callable(policy) or not callable(audit):
            raise ValueError("credentials, policy and audit are required")
        if inspect.iscoroutinefunction(policy) or inspect.iscoroutinefunction(audit):
            raise ValueError("policy and audit are plain functions: they run in worker threads, not on the event loop")
        if len({source.trust.issuer for source in self.credentials}) != len(self.credentials):
            raise ValueError("Each issuer may be trusted once")
        self.policy, self.audit = policy, audit
        self._single = SingleRequestIssuer(
            signing_key=signing_key,
            # Looked up at each call: the callbacks may be replaced on a running issuer.
            policy=lambda identity, task_id: self.policy(identity, task_id),
            audit=lambda record: self.audit(record),
            store=MemoryProofStore() if proof_store is None else proof_store,
            refused=OAuthError,
            busy=OAuthUnavailable,
            validate=_validated,
            record=lambda identity, task_id, holder, warrant, grant: OAuthIssuance(
                identity, task_id, holder, warrant.id, warrant.expires_at()
            ),
            wording=Wording(
                denied="Task is not authorized for this caller",
                ends_too_soon="The token or the task approval ends too soon to issue a warrant",
                outlives="Warrant would outlive its grant",
                who="caller",
            ),
            max_ttl_seconds=_integer(max_ttl_seconds, "maximum TTL", 1, 3600),
            logger=logger,
            unusable_grant_is_issuer_fault=True,
        )

    def close(self) -> None:
        for source in self.credentials:
            source.close()

    def _source(self, token: str) -> OAuthTokens:
        """The one trust whose issuer the token names. Its claim is not trusted here, only used to choose."""
        if len(self.credentials) == 1:
            return self.credentials[0]
        for source in self.credentials:
            if source.issued(token):
                return source
        raise OAuthError("Invalid OAuth access token")

    def authenticate(self, token: str) -> OAuthIdentity:
        """Verify a token against the trust for its issuer."""
        return self._source(token).authenticate(token)

    def issue(self, token: str, holder: PublicKey, task_id: str, proof: OAuthHolderProof) -> Warrant:
        """Verify the token and the holder proof, ask the policy, and mint."""
        source = self._source(token)
        return self._issue(source, source.authenticate(token), token, holder, task_id, proof)

    def _issue(
        self,
        source: OAuthTokens,
        identity: OAuthIdentity,
        token: str,
        holder: PublicKey,
        task_id: str,
        proof: OAuthHolderProof,
    ) -> Warrant:
        audience = source.audience
        return self._single.issue(
            identity,
            owner=identity.key,
            expires_at=identity.expires_at,
            holder=holder,
            task_id=task_id,
            proof=proof,
            statement=lambda key, stamp, nonce: _proof_bytes(token, audience, task_id, key, stamp, nonce),
        )


class OAuthWarrantIssuerApp(_IssuerApp):
    """ASGI application that issues warrants to callers with a token from a trusted provider.

    Run it with any ASGI server behind HTTPS, or mount it in an existing app.
    Two request shapes are accepted on ``POST <path>``.

    The compact one::

        Authorization: Bearer <token>
        Content-Type: application/json

        {"v": 1, "holder": "<base64 Ed25519 public key>", "task": "<task ID>",
         "timestamp": <unix seconds>, "nonce": "<base64, 16 bytes>",
         "signature": "<base64 holder proof>"}

    answered with ``200 {"warrant": "<base64>"}``.

    OAuth 2.0 Token Exchange (RFC 8693), form-encoded, for callers and
    gateways that already speak it: ``grant_type`` (token-exchange),
    ``subject_token``, ``subject_token_type`` (access_token or jwt),
    ``requested_token_type=urn:tenuo:params:oauth:token-type:warrant`` and
    ``authorization_details`` holding one object of type ``tenuo_task`` with
    the same ``task``, ``holder``, ``timestamp``, ``nonce`` and ``signature``.
    It is answered as a token response whose ``access_token`` is the warrant.

    In the compact shape the token is checked before the body is read, so only
    a caller with a valid one holds a place. At most ``max_per_identity``
    requests from one identity are in progress at once.
    """

    _what = "OAuth issuance"
    _challenge = b"Bearer"
    _log = logger
    _who = "caller"
    _check_in_pool = True  # Signature checks and a key fetch are not work for the event loop.
    _subject_token_types = frozenset(
        {"urn:ietf:params:oauth:token-type:access_token", "urn:ietf:params:oauth:token-type:jwt"}
    )

    def __init__(self, issuer: OAuthWarrantIssuer, *, max_per_identity: int = 16, **options: Any):
        if not _positive_int(max_per_identity) or max_per_identity < 1:
            raise ValueError("max_per_identity must be a positive integer")
        super().__init__(issuer, **options)
        self._issuer: OAuthWarrantIssuer = issuer
        self._max_per_key = max_per_identity

    async def _started(self) -> None:
        """Fetch each provider's keys before the server takes requests, so the first callers find them there.

        Each fetch has its own deadline. A provider that cannot be reached
        does not stop the start: it is logged where it failed, and the first
        caller that needs its keys tries again.
        """

        def warm(source: OAuthTokens) -> None:
            try:
                source.refresh()
            except OAuthError:
                pass

        loop = asyncio.get_running_loop()
        sources = self._issuer.credentials
        fetches = [loop.run_in_executor(None, warm, source) for source in sources]
        try:
            await asyncio.wait_for(asyncio.gather(*fetches), 2 * max(source._timeout for source in sources) + 1)
        except asyncio.TimeoutError:
            pass

    def _credential(self, scope: Mapping[str, Any]) -> str:
        headers = scope.get("headers", ())
        types = [value for name, value in headers if name.lower() == b"content-type"]
        if len(types) != 1 or types[0].split(b";")[0].strip().lower() != b"application/json":
            raise _Refusal(415, "invalid_request", "Use application/json")
        values = [value for name, value in headers if name.lower() == b"authorization"]
        scheme, _, value = (values[0] if len(values) == 1 else b"").partition(b" ")
        if scheme.lower() != b"bearer" or not value or len(value) > _MAX_TOKEN:
            raise _Refusal(401, "invalid_token", "Send one Bearer access token")
        try:
            return value.decode("ascii")
        except UnicodeError:
            raise _Refusal(401, "invalid_token", "Invalid access token") from None

    def _exchange_credential(self, token: str) -> str:
        if not token or len(token) > _MAX_TOKEN:
            raise _Refusal(401, "invalid_token", "Invalid access token")
        return token

    def _verify(self, credential: str) -> Tuple[str, OAuthIdentity]:
        try:
            return credential, self._issuer.authenticate(credential)
        except OAuthUnavailable:
            raise _Refusal(503, "unavailable", "Credential validation temporarily unavailable") from None
        except OAuthError:
            raise _Refusal(401, "invalid_token", "Access token not accepted") from None

    def _limit_key(self, credential: Tuple[str, OAuthIdentity]) -> str:
        return credential[1].key

    def _authorize(
        self, credential: Tuple[str, OAuthIdentity], holder: PublicKey, task_id: Any, proof: OAuthHolderProof
    ) -> Warrant:
        # Checked again: the body may have taken seconds to arrive, and the keys can change meanwhile.
        token, identity = self._verify(credential[0])
        return self._issuer._issue(self._issuer._source(token), identity, token, holder, task_id, proof)


# ---------------------------------------------------------------------------
# The agent's side
# ---------------------------------------------------------------------------


def request_warrant_oauth(
    url: str,
    *,
    token: str,
    audience: str,
    issuer_key: PublicKey,
    holder_key: SigningKey,
    task_id: str,
    timeout: float = 10,
    ca_file: Optional[str] = None,
    allow_loopback_http: bool = False,
) -> Warrant:
    """Ask an ``OAuthWarrantIssuerApp`` for a warrant and check what comes back.

    ``audience`` is the issuer's configured audience. The token is sent over
    verified HTTPS only (``ca_file`` for a private CA), or to a loopback
    address with ``allow_loopback_http=True``. Redirects are not followed.
    ``timeout`` bounds the whole call. The warrant must be signed by
    ``issuer_key`` and bound to ``holder_key``. Every failure is an
    ``OAuthError``. Keep the token and the holder key out of model prompts and logs.
    """
    try:
        _url(url, allow_loopback_http)
        scheme, host, port, path = _split_url(url)
        timeout = _seconds("timeout", timeout)
    except OAuthError:
        raise
    except ValueError as exc:
        raise OAuthError(str(exc)) from None
    proof = sign_oauth_holder_proof(token, holder_key, audience=audience, task_id=task_id)

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
        {"Authorization": f"Bearer {token}"},
        [issuer_key],
        holder_key,
        timeout=timeout,
        error=OAuthError,
    )


async def arequest_warrant_oauth(url: str, **kwargs: Any) -> Warrant:
    """Async wrapper for :func:`request_warrant_oauth` (runs in a worker thread)."""
    return await asyncio.to_thread(request_warrant_oauth, url, **kwargs)
