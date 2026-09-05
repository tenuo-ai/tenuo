"""OIDC bearer in, run warrant out. Refuse rather than trim."""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from tenuo import PublicKey, SigningKey, Warrant
from tenuo.mcp import exact_argument_constraints
from tenuo_core import encode_warrant_stack

from .commitment import CommitmentError, compact_task_binding, exchange_request_hash, verify_holder_proof
from .config import ConfigError, GatewayConfig
from .oidc import OidcError, assert_conditions, load_jwks, verify_oidc
from .task import expand_issuance_constraints


class ExchangeError(ValueError):
    """Issuance refused. ``code`` is the wire error name."""

    def __init__(self, code: str, detail: str, status: int = 403) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status


@dataclass
class ExchangeResult:
    warrant: str
    warrant_id: str
    expires_at: str
    root_public_keys: list[str]
    task_binding: Optional[Dict[str, Any]] = None


GITHUB_EXCHANGE_FIELDS = frozenset(
    {"holder_public_key", "holder_proof", "ttl_seconds", "capabilities", "task_binding"}
)


def assert_github_exchange_fields(body: Mapping[str, Any]) -> None:
    """Cloud ``DisallowUnknownFields``: reject ``task_context`` and identifiers."""
    unknown = sorted(set(body) - GITHUB_EXCHANGE_FIELDS)
    if unknown:
        raise ExchangeError("invalid_request", f"unknown field: {unknown[0]}", status=400)


def normalize_task_binding(raw: Any) -> Optional[Dict[str, Any]]:
    """Accept only ``{type, number}``. Assurance is not runner-supplied."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ExchangeError("invalid_request", "task_binding must be a mapping", status=400)
    extra = sorted(set(raw) - {"type", "number"})
    if extra:
        raise ExchangeError("invalid_request", "task_binding must contain only type and number", status=400)
    kind = raw.get("type")
    number = raw.get("number")
    if kind not in {"issue", "pull_request"}:
        raise ExchangeError("invalid_request", "task_binding.type must be issue or pull_request", status=400)
    try:
        parsed = int(number)
    except (TypeError, ValueError) as exc:
        raise ExchangeError("invalid_request", "task_binding.number must be a positive integer", status=400) from exc
    if parsed <= 0:
        raise ExchangeError("invalid_request", "task_binding.number must be a positive integer", status=400)
    return compact_task_binding({"type": str(kind), "number": parsed})


def encode_exchange_stack(warrants: list) -> str:
    encoded = encode_warrant_stack(warrants)
    if not encoded:
        raise ExchangeError("outside_ceiling", "could not encode warrant stack", status=500)
    return encoded


class ReplayCache:
    """Remember JWT ids until they expire."""

    def __init__(self) -> None:
        self._seen: Dict[str, int] = {}
        self._lock = threading.Lock()

    def check_and_record(self, token_id: str, expires_at: int, *, now: Optional[int] = None) -> bool:
        """Return True if this id is new and was recorded."""
        if now is None:
            now = int(time.time())
        with self._lock:
            expired = [key for key, exp in self._seen.items() if exp <= now]
            for key in expired:
                del self._seen[key]
            if token_id in self._seen:
                return False
            self._seen[token_id] = expires_at
            return True


def _signing_key(config: GatewayConfig, override: Optional[SigningKey]) -> SigningKey:
    if override is not None:
        return override
    if config.signing_provider == "secret":
        if config.secret_mount is None or not config.secret_issuer_key:
            raise ConfigError("issuer_key is required under signing.secret.mount")
        from .secrets import signing_key_from_mount

        return signing_key_from_mount(config.secret_mount, config.secret_issuer_key)
    raw = config.exchange_signing_key
    if not raw:
        if config.signing_provider == "memory":
            return SigningKey.generate()
        raise ConfigError("TENUO_EXCHANGE_SIGNING_KEY is required")
    try:
        return SigningKey.from_base64(raw)
    except AttributeError:
        return SigningKey.from_bytes(base64.b64decode(raw))
    except Exception:
        return SigningKey.from_bytes(bytes.fromhex(raw))


def _public_key(value: str) -> PublicKey:
    raw = value.strip()
    if raw.startswith("hex:"):
        raw = raw[4:]
    try:
        return PublicKey.from_bytes(bytes.fromhex(raw))
    except Exception:
        return PublicKey.from_bytes(base64.b64decode(raw))


def _token_id(claims: Mapping[str, Any], token: str) -> str:
    jti = claims.get("jti")
    if jti:
        return str(jti)
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Exchange:
    """Mint a run warrant from a verified GitHub Actions OIDC token."""

    def __init__(
        self,
        config: GatewayConfig,
        *,
        issuer_key: Optional[SigningKey] = None,
        jwks: Optional[Mapping[str, Any]] = None,
        jwks_fetcher: Optional[Callable[[str], Mapping[str, Any]]] = None,
        replay: Optional[ReplayCache] = None,
    ) -> None:
        if config.signing_provider == "kms":
            raise ConfigError("signing.provider=kms is not supported")
        if config.role == "gateway":
            raise ConfigError("exchange is not served by role=gateway")
        if not config.audience:
            raise ConfigError("exchange.audience is required")
        self.config = config
        self._issuer = _signing_key(config, issuer_key)
        self._jwks = load_jwks(jwks=jwks, jwks_url=config.jwks_url, fetcher=jwks_fetcher)
        self._replay = replay or ReplayCache()
        self.self_test()

    def self_test(self) -> None:
        """Sign with the issuer key. Never log material."""
        try:
            self._issuer.sign_raw(b"tenuo-gha-ready")
        except Exception as exc:
            raise ConfigError("issuer key self-test failed") from exc

    def bind_capabilities(
        self,
        capabilities: Mapping[str, Any],
        *,
        repository: str,
    ) -> Dict[str, Dict[str, Any]]:
        """Bind requested tools. Repository comes from the OIDC subject."""
        bound: Dict[str, Dict[str, Any]] = {}
        for tool, raw_args in capabilities.items():
            args = dict(raw_args or {})
            requested_repo = args.get("repository")
            if requested_repo is not None and str(requested_repo) != repository:
                raise ExchangeError("outside_ceiling", "repository does not match the OIDC subject")
            args["repository"] = repository
            bound[str(tool)] = expand_issuance_constraints(str(tool), exact_argument_constraints(args))
        return bound

    def validate(
        self,
        token: str,
        body: Mapping[str, Any],
        *,
        now: Optional[int] = None,
    ) -> tuple[Dict[str, Any], Any, int, Dict[str, Any], Optional[Dict[str, Any]]]:
        """OIDC, holder proof, replay, and issuance identity. Returns claims, holder, ttl, capabilities, task."""
        if now is None:
            now = int(time.time())
        try:
            claims = verify_oidc(
                token,
                issuer=self.config.oidc_issuer,
                audience=self.config.audience,
                jwks=self._jwks,
                clock_tolerance_seconds=self.config.clock_tolerance_seconds,
                now=now,
            )
            assert_conditions(
                claims,
                repository_owner_id=self.config.repository_owner_id,
                repository_ids=self.config.repository_ids,
                job_workflow_ref=self.config.job_workflow_ref,
                event_names=self.config.event_names,
                repositories=self.config.repositories,
            )
        except OidcError as exc:
            raise ExchangeError(exc.code, exc.detail) from exc

        assert_github_exchange_fields(body)

        holder_raw = body.get("holder_public_key")
        if not holder_raw or not isinstance(holder_raw, str):
            raise ExchangeError("outside_ceiling", "holder_public_key is required", status=400)
        try:
            holder = _public_key(holder_raw)
        except Exception as exc:
            raise ExchangeError("outside_ceiling", "holder_public_key is invalid", status=400) from exc

        ttl = body.get("ttl_seconds")
        if ttl is None:
            ttl = self.config.ttl_max
        try:
            ttl_i = int(ttl)
        except (TypeError, ValueError) as exc:
            raise ExchangeError("outside_ceiling", "ttl_seconds is invalid", status=400) from exc
        if ttl_i <= 0:
            raise ExchangeError("outside_ceiling", "ttl_seconds must be positive", status=400)
        if ttl_i > self.config.ttl_max:
            raise ExchangeError("outside_ceiling", "ttl_seconds exceeds ttl_max")

        capabilities = body.get("capabilities")
        if not isinstance(capabilities, dict) or not capabilities:
            raise ExchangeError("outside_ceiling", "capabilities are required", status=400)
        task_binding = normalize_task_binding(body.get("task_binding"))

        proof = body.get("holder_proof")
        if not isinstance(proof, str) or not proof:
            raise ExchangeError("holder_proof_invalid", "holder_proof is required", status=403)
        try:
            request_hash = exchange_request_hash(
                issuer=str(claims.get("iss") or ""),
                jti=str(claims.get("jti") or ""),
                holder_public_key=holder_raw,
                ttl_seconds=ttl_i,
                capabilities=capabilities,
                task_binding=task_binding,
            )
            verify_holder_proof(holder_raw, proof, request_hash)
        except CommitmentError as exc:
            raise ExchangeError("holder_proof_invalid", "holder_proof is invalid", status=403) from exc

        token_id = _token_id(claims, token)
        expires = int(claims.get("exp") or now)
        if not self._replay.check_and_record(token_id, expires, now=now):
            raise ExchangeError("token_reused", "OIDC token was already exchanged")
        return claims, holder, ttl_i, capabilities, task_binding

    def mint(
        self,
        token: str,
        body: Mapping[str, Any],
        *,
        now: Optional[int] = None,
    ) -> ExchangeResult:
        claims, holder, ttl_i, capabilities, task_binding = self.validate(token, body, now=now)
        repository = str(claims["repository"])
        bound = self.bind_capabilities(capabilities, repository=repository)
        builder = Warrant.mint_builder().holder(holder).ttl(ttl_i)
        run_id = claims.get("run_id")
        if run_id is not None:
            builder = builder.session_id(str(run_id))
        for tool, constraints in bound.items():
            builder = builder.capability(tool, constraints)

        warrant = builder.mint(self._issuer)
        expires_at = warrant.expires_at()
        if callable(expires_at):
            expires_at = expires_at()
        return ExchangeResult(
            warrant=encode_exchange_stack([warrant]),
            warrant_id=str(warrant.id),
            expires_at=str(expires_at),
            root_public_keys=list(self.config.root_public_keys),
            task_binding=task_binding,
        )
