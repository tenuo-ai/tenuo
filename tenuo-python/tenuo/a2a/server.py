"""
A2A Adapter - Server implementation.

Provides A2AServer with @skill decorator for warrant-enforced skill execution.

Security Considerations
=======================

**Rate Limiting**: The server includes replay protection (JTI cache) but does NOT
include request rate limiting. Attackers can flood with unique JTIs. Deploy with
a rate-limiting reverse proxy (nginx, envoy) or use a transport-layer solution.

**PoP Verification**: When PoP is provided, warrant.authorize() verifies:
1. Signature was made by the key matching warrant.sub (holder)
2. Skill is granted in the warrant
3. Arguments satisfy constraint requirements

Constraint Validation Architecture
==================================

All constraint validation uses tenuo_core (Rust) where possible. This ensures
security-critical checks happen in compiled, memory-safe code rather than Python.

Runtime Validation (_check_constraint):
- Subpath: tenuo_core.Subpath.contains() - Rust path normalization & containment
- UrlSafe: tenuo_core.UrlSafe.is_safe() - Rust URL parsing & SSRF protection
- Pattern: tenuo_core.Pattern.matches() - Rust glob matching (NO Python fallback)
- Shlex: tenuo.constraints.Shlex.matches() - Python only (shell parsing)

Attenuation Validation (_constraint_is_narrower):
All constraints with validate_attenuation() use Rust core:
- Subpath: tenuo_core.Subpath.validate_attenuation() - checks root containment
- UrlSafe: tenuo_core.UrlSafe.validate_attenuation() - checks schemes, domains, flags
- Pattern: tenuo_core.Pattern.validate_attenuation() - checks pattern narrowing
- Range: tenuo_core.Range.validate_attenuation() - checks bounds
- Cidr: tenuo_core.Cidr.validate_attenuation() - checks subnet containment
- OneOf/NotOneOf: tenuo_core validate_attenuation() - checks value sets
- All/Contains/Subset: tenuo_core validate_attenuation() - checks constraint sets
- Shlex: Python set comparison on allowed_bins (no Rust implementation)

SECURITY: All checks fail-closed. If tenuo_core is not available for a constraint
type that requires it, validation fails rather than falling back to Python.

The only Python-native constraint is Shlex, which uses Python's shlex module
for shell parsing. This is intentional - shell syntax parsing is complex and
the Rust core doesn't implement it.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, FrozenSet, List, Optional, Protocol, runtime_checkable

from .errors import (
    A2AError,
    A2AErrorCode,
    AudienceMismatchError,
    ChainValidationError,
    ConstraintBindingError,
    ConstraintViolationError,
    InvalidSignatureError,
    MissingWarrantError,
    PopRequiredError,
    PopVerificationError,
    RegistrationDeniedError,
    RegistrationDisabledError,
    ReplayDetectedError,
    RevokedError,
    SkillNotFoundError,
    SkillNotGrantedError,
    UnknownConstraintError,
    UntrustedIssuerError,
    WarrantExpiredError,
)
from .types import (
    AgentCard,
    AuditEvent,
    AuditEventType,
    SkillInfo,
    TenuoExtension,
    VerifiedWarrantRequest,
    WarrantRequest,
    current_task_warrant,
)

if TYPE_CHECKING:
    from starlette.requests import Request

    from .types import Warrant

__all__ = [
    "A2AServer",
    "A2AServerBuilder",
    "ReplayBackend",
    "InMemoryReplayBackend",
    "ReplayCache",  # backward-compatible alias
    "SkillDefinition",
]

# Maximum warrant token size accepted (64 KB) — mirrors wire.MAX_WARRANT_SIZE.
# WarrantStack inputs may be larger (up to 256 KB); the limit here applies only
# to the extracted leaf token passed into validate_warrant.
MAX_WARRANT_TOKEN_BYTES = 65_536

# HTTP header names — imported from tenuo_core so they stay in sync with the wire spec.
try:
    from tenuo_core import WARRANT_HEADER
except ImportError:
    WARRANT_HEADER = "X-Tenuo-Warrant"

# Delegation chain header (legacy transport; WarrantStack is preferred).
WARRANT_CHAIN_HEADER = "X-Tenuo-Warrant-Chain"

logger = logging.getLogger("tenuo.a2a.server")


# =============================================================================
# Replay Cache (in-memory for MVP)
# =============================================================================


@runtime_checkable
class ReplayBackend(Protocol):
    """Pluggable backend for JTI replay detection.

    The default implementation (:class:`InMemoryReplayBackend`) is suitable for
    single-instance deployments. For multi-instance environments, implement this
    protocol backed by a shared cache (e.g., Redis) so JTI deduplication is
    coordinated across all server instances.

    Rate limiting: A2AServer does not throttle requests. In production, put a
    rate-limiting reverse proxy (nginx ``limit_req``, Envoy RateLimit) in front.

    Example (Redis backend sketch)::

        class RedisReplayBackend:
            def __init__(self, redis_client) -> None:
                self._redis = redis_client

            async def check_and_add(self, jti: str, ttl_seconds: int) -> bool:
                # SET key value EX ttl NX — returns True only if key was new
                return bool(await self._redis.set(jti, 1, ex=ttl_seconds, nx=True))

            async def clear(self) -> None:
                pass  # TTL handles expiry; no-op for tests

    Register with :meth:`A2AServerBuilder.with_replay_backend`.
    """

    async def check_and_add(self, jti: str, ttl_seconds: int) -> bool:
        """Check if jti is new and register it if so.

        Returns:
            True if jti is new (allow request).
            False if jti was already seen (replay — deny request).
        """
        ...

    async def clear(self) -> None:
        """Remove all entries (for testing / maintenance)."""
        ...


class InMemoryReplayBackend:
    """
    Simple in-memory replay cache with TTL.

    NOTE on time.time() usage:
    We use wall clock time (time.time()) rather than monotonic time because:
    1. JWT 'exp' claims are Unix timestamps (wall clock)
    2. We need to compare against those timestamps for consistency
    3. Ensure your server's NTP is synced to prevent clock drift issues

    PERFORMANCE: Uses amortized cleanup to avoid O(N) scan on every request.
    Cleanup runs every CLEANUP_INTERVAL requests instead of every request.
    This prevents DoS attacks via JTI flooding.

    For production deployments, consider using Redis or similar for:
    - Multi-instance coordination
    - Persistence across restarts
    - Better memory management
    """

    CLEANUP_INTERVAL = 1000  # Cleanup every N requests

    def __init__(self) -> None:
        self._cache: Dict[str, float] = {}  # jti -> expiry_time (wall clock)
        self._lock: Optional[asyncio.Lock] = None  # Lazy init to avoid event loop issues
        self._counter: int = 0  # Request counter for amortized cleanup

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the lock (lazy initialization)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def check_and_add(self, jti: str, ttl_seconds: int) -> bool:
        """
        Check if jti exists, add if not.

        Returns:
            True if jti is new (not a replay)
            False if jti already exists (replay detected)
        """
        async with self._get_lock():
            now = time.time()

            # Amortized cleanup: only clean every CLEANUP_INTERVAL requests
            # This prevents O(N) scan on every request (DoS mitigation)
            self._counter += 1
            if self._counter % self.CLEANUP_INTERVAL == 0:
                expired = [k for k, v in self._cache.items() if v < now]
                for k in expired:
                    del self._cache[k]

            # Check for replay (O(1) dict lookup)
            if jti in self._cache:
                # Also check if this specific entry is expired
                if self._cache[jti] < now:
                    # Expired entry - clean it and allow
                    del self._cache[jti]
                else:
                    return False

            # Add to cache
            self._cache[jti] = now + ttl_seconds
            return True

    async def clear(self) -> None:
        """Clear all entries (for testing). Async to prevent race with check_and_add."""
        async with self._get_lock():
            self._cache.clear()
            self._counter = 0


# Backward-compatible alias
ReplayCache = InMemoryReplayBackend


# =============================================================================
# Skill Registration
# =============================================================================


class SkillDefinition:
    """Internal representation of a registered skill."""

    def __init__(
        self,
        skill_id: str,
        func: Callable,
        constraints: Dict[str, Any],
        name: Optional[str] = None,
    ) -> None:
        self.skill_id = skill_id
        self.func = func
        self.constraints = constraints
        self.name = name or skill_id

        # Get function signature for validation
        sig = inspect.signature(func)
        self.param_names = list(sig.parameters.keys())

        # Validate constraint keys match parameters
        for key in constraints:
            if key not in self.param_names:
                raise ConstraintBindingError(skill_id, key, self.param_names)

    def to_skill_info(self) -> SkillInfo:
        """Convert to SkillInfo for AgentCard."""
        from .types import ConstraintInfo

        constraint_infos = {}
        for key, constraint in self.constraints.items():
            type_name = type(constraint).__name__
            constraint_infos[key] = ConstraintInfo(type=type_name, required=True)

        return SkillInfo(
            id=self.skill_id,
            name=self.name,
            constraints=constraint_infos,
        )


# =============================================================================
# A2A Server
# =============================================================================


class A2AServerBuilder:
    """
    Build an A2A server that accepts warrant-authorized requests.

    **What is A2A?**
    Agent-to-Agent (A2A) is a protocol for agents to call each other's skills
    with cryptographic authorization. The server defines skills, and clients
    call them with warrants that prove they're allowed.

    **Quick Start:**
        from tenuo.a2a import A2AServerBuilder

        server = (A2AServerBuilder()
            .name("Research Agent")                     # Display name
            .url("https://research.example.com")        # Your public URL
            .key(my_signing_key)                        # Your identity
            .accept_warrants_from(orchestrator_key)     # Who can give you tasks
            .build())

        @server.skill("search")
        async def search(query: str):
            return {"results": [...]}

        # Run with: uvicorn server.app:app

    **Key Concepts:**
    - **skill**: A function this agent can perform (like "search", "read_file")
    - **warrant**: A signed token proving the caller is allowed to invoke a skill
    - **accept_warrants_from**: Which public keys can issue valid warrants

    **Fluent Methods:**
    - `.name()` - Agent display name (required)
    - `.url()` - Public URL for audience validation (required)
    - `.key()` - Your signing key (required, extracts public_key)
    - `.accept_warrants_from()` - Who can issue warrants to you (required)
    - `.require_warrant()` - Reject requests without warrants (default: True)
    - `.require_pop()` - Require Proof-of-Possession signatures (default: True)
    """

    def __init__(self) -> None:
        """Initialize with defaults."""
        self._name: Optional[str] = None
        self._url: Optional[str] = None
        self._public_key: Optional[Any] = None
        self._signing_key: Optional[Any] = None
        self._trusted_issuers: List[Any] = []
        self._trust_delegated: bool = True
        self._require_warrant: Optional[bool] = None
        self._require_audience: Optional[bool] = None
        self._require_pop: Optional[bool] = None
        self._check_replay: Optional[bool] = None
        self._replay_window: Optional[int] = None
        self._max_chain_depth: Optional[int] = None
        self._audit_log: Any = None
        self._audit_format: str = "json"
        self._previous_keys: Optional[List[Any]] = None
        self._replay_backend: Optional[Any] = None
        self._revoked_issuers: List[Any] = []
        self._registration_handler: Optional[Any] = None

    def name(self, name: str) -> "A2AServerBuilder":
        """Set the agent display name (required)."""
        self._name = name
        return self

    def url(self, url: str) -> "A2AServerBuilder":
        """Set the agent's public URL (required, used for audience validation)."""
        self._url = url
        return self

    def key(self, key: Any) -> "A2AServerBuilder":
        """
        Set the agent's key.

        Accepts:
        - SigningKey: extracts public_key automatically; retains signing key
          for warrant issuance (required by ``registration_handler()``)
        - PublicKey: uses directly (no signing capability)
        - str: multibase or DID format (no signing capability)
        """
        if hasattr(key, "public_key"):
            # SigningKey: retain both public and private key
            self._public_key = key.public_key
            self._signing_key = key
        else:
            # PublicKey or str: no signing capability
            self._public_key = key
            self._signing_key = None
        return self

    def public_key(self, key: Any) -> "A2AServerBuilder":
        """Set the agent's public key directly."""
        self._public_key = key
        return self

    def accept_warrants_from(self, *issuers: Any) -> "A2AServerBuilder":
        """
        Accept warrants signed by these issuers.

        This defines WHO can give this agent instructions. Only warrants
        signed by (or delegated from) these keys will be accepted.

        Args:
            *issuers: Public keys of trusted warrant issuers.
                     Can be called multiple times to add more.

        Example:
            # Accept warrants from orchestrator
            builder.accept_warrants_from(orchestrator_key)

            # Accept warrants from multiple sources
            builder.accept_warrants_from(orchestrator_key, admin_key)
        """
        self._trusted_issuers.extend(issuers)
        return self

    def trust(self, *issuers: Any) -> "A2AServerBuilder":
        """Alias for accept_warrants_from(). Kept for brevity."""
        return self.accept_warrants_from(*issuers)

    def trust_delegated(self, enabled: bool = True) -> "A2AServerBuilder":
        """Accept warrants attenuated from trusted issuers (default: True)."""
        self._trust_delegated = enabled
        return self

    def require_warrant(self, enabled: bool = True) -> "A2AServerBuilder":
        """Reject tasks without warrant (default: True via env)."""
        self._require_warrant = enabled
        return self

    def require_audience(self, enabled: bool = True) -> "A2AServerBuilder":
        """Require aud claim matches our URL (default: True via env)."""
        self._require_audience = enabled
        return self

    def require_pop(self, enabled: bool = True) -> "A2AServerBuilder":
        """Require Proof-of-Possession signature (default: True via env)."""
        self._require_pop = enabled
        return self

    def check_replay(self, enabled: bool = True) -> "A2AServerBuilder":
        """Enforce jti uniqueness to prevent replay (default: True via env)."""
        self._check_replay = enabled
        return self

    def replay_window(self, seconds: int) -> "A2AServerBuilder":
        """Set replay cache window in seconds (default: 3600)."""
        self._replay_window = seconds
        return self

    def max_chain_depth(self, depth: int) -> "A2AServerBuilder":
        """Set maximum delegation chain depth (default: 10)."""
        self._max_chain_depth = depth
        return self

    def audit_log(self, destination: Any, format: str = "json") -> "A2AServerBuilder":
        """
        Set audit log destination.

        Args:
            destination: File path, file handle, or "stderr"
            format: "json" or "text"
        """
        self._audit_log = destination
        self._audit_format = format
        return self

    def previous_keys(self, *keys: Any) -> "A2AServerBuilder":
        """Add previous public keys for key rotation support."""
        if self._previous_keys is None:
            self._previous_keys = []
        self._previous_keys.extend(keys)
        return self

    def with_replay_backend(self, backend: Any) -> "A2AServerBuilder":
        """Inject a custom replay detection backend.

        Replaces the default :class:`InMemoryReplayBackend` with a custom
        implementation, e.g. Redis, for multi-instance deployments.

        The backend must implement :class:`ReplayBackend` (async
        ``check_and_add(jti, ttl_seconds) -> bool`` and ``clear()``).

        Example::

            server = (A2AServerBuilder()
                ...
                .with_replay_backend(RedisReplayBackend(redis_client))
                .build())
        """
        self._replay_backend = backend
        return self

    def revoke_issuers(self, *keys: Any) -> "A2AServerBuilder":
        """Mark issuer keys as revoked.

        Requests from warrants issued by these keys will be rejected with
        :class:`~tenuo.a2a.errors.RevokedError` even if the key was previously
        trusted.  Use this for immediate incident response.

        To remove a key from the trust list permanently, remove it from
        :meth:`accept_warrants_from` instead.

        Args:
            *keys: Public keys (``PublicKey`` objects or multibase strings) of
                   revoked issuers.  Can be called multiple times.
        """
        self._revoked_issuers.extend(keys)
        return self

    def registration_handler(self, handler: Any) -> "A2AServerBuilder":
        """
        Enable automated agent registration (CSR pattern).

        The handler is called after the server has cryptographically verified
        key ownership via a self-signed challenge warrant. It receives a
        :class:`~tenuo.a2a.types.VerifiedWarrantRequest` and an ``issue()``
        oracle that mints warrants using the server's signing key.

        Handler signature::

            async def handle_reg(req: VerifiedWarrantRequest, issue: Callable) -> None:
                if req.verified_key_hex not in ALLOWLIST:
                    raise RegistrationDeniedError("Key not pre-enrolled")
                await issue(capabilities=req.capabilities, ttl=3600)

        The ``issue(capabilities, ttl, audience)`` callable is bound to the
        server's signing key — the handler cannot extract the key, only call it.

        **Requires:** ``key()`` must receive a ``SigningKey`` (not just a
        ``PublicKey``) so the server can sign issued warrants.

        .. note::
            Extension point: inspect ``req.extensions`` for TEE attestations
            before calling ``issue()``. Example::

                {"tee_type": "sgx", "mrenclave": "<hex>", "report": "<base64>"}

        .. note::
            Future direction: Hierarchical Deterministic (HD) keys for
            zero-handshake bulk worker derivation from a root key. Useful for
            hyperscale worker pools. Not yet implemented.
        """
        self._registration_handler = handler
        return self

    def build(self) -> "A2AServer":
        """
        Build the A2AServer.

        Raises:
            ValueError: If required fields (name, url, key, trust) are missing
            ValueError: If registration_handler() set without a signing key
        """
        if not self._name:
            raise ValueError("A2AServerBuilder requires .name()")
        if not self._url:
            raise ValueError("A2AServerBuilder requires .url()")
        if not self._public_key:
            raise ValueError("A2AServerBuilder requires .key() or .public_key()")
        if not self._trusted_issuers:
            raise ValueError("A2AServerBuilder requires at least one .trust()")
        if self._registration_handler is not None and self._signing_key is None:
            raise ValueError(
                "registration_handler() requires a signing key. "
                "Pass a SigningKey (not just a PublicKey) to .key()."
            )

        return A2AServer(
            name=self._name,
            url=self._url,
            public_key=self._public_key,
            trusted_issuers=self._trusted_issuers,
            trust_delegated=self._trust_delegated,
            require_warrant=self._require_warrant,
            require_audience=self._require_audience,
            require_pop=self._require_pop,
            check_replay=self._check_replay,
            replay_window=self._replay_window,
            max_chain_depth=self._max_chain_depth,
            audit_log=self._audit_log,
            audit_format=self._audit_format,
            previous_keys=self._previous_keys,
            replay_backend=self._replay_backend,
            revoked_issuers=self._revoked_issuers if self._revoked_issuers else None,
            signing_key=self._signing_key,
            registration_handler=self._registration_handler,
        )


class A2AServer:
    """
    A2A server with warrant-based authorization.

    Direct initialization:
        server = A2AServer(
            name="Research Agent",
            url="https://research-agent.example.com",
            public_key=my_public_key,
            trusted_issuers=[orchestrator_key],
        )

    Or use the builder for a fluent API:
        server = (A2AServerBuilder()
            .name("Research Agent")
            .url("https://research-agent.example.com")
            .key(my_key)
            .trust(orchestrator_key)
            .build())

        @server.skill("search", constraints={"query": str})
        async def search(query: str) -> list[dict]:
            return await do_search(query)

        # Run with uvicorn
        uvicorn.run(server.app, port=8000)
    """

    def __init__(
        self,
        name: str,
        url: str,
        public_key: Any,
        trusted_issuers: List[Any],
        *,
        trust_delegated: bool = True,
        require_warrant: Optional[bool] = None,
        require_audience: Optional[bool] = None,
        require_pop: Optional[bool] = None,
        check_replay: Optional[bool] = None,
        replay_window: Optional[int] = None,
        max_chain_depth: Optional[int] = None,
        audit_log: Any = None,
        audit_format: str = "json",
        previous_keys: Optional[List[Any]] = None,
        replay_backend: Optional[Any] = None,
        revoked_issuers: Optional[List[Any]] = None,
        signing_key: Optional[Any] = None,
        registration_handler: Optional[Callable] = None,
    ) -> None:
        """
        Initialize A2A server.

        Args:
            name: Display name of this agent
            url: Public URL of this agent (used for audience validation)
            public_key: This agent's public key (PublicKey object, multibase, or DID)
            trusted_issuers: List of public keys to trust as warrant issuers
                (accepts PublicKey objects, multibase strings, or DIDs)
            trust_delegated: Accept warrants attenuated from trusted issuers
            require_warrant: Reject tasks without warrant (env: TENUO_A2A_REQUIRE_WARRANT)
            require_audience: Require aud claim matches our URL (env: TENUO_A2A_REQUIRE_AUDIENCE)
            require_pop: Require Proof-of-Possession signature (env: TENUO_A2A_REQUIRE_POP)
            check_replay: Enforce jti uniqueness (env: TENUO_A2A_CHECK_REPLAY)
            replay_window: Seconds to remember jti values (env: TENUO_A2A_REPLAY_WINDOW)
            max_chain_depth: Maximum delegation chain depth (env: TENUO_A2A_MAX_CHAIN_DEPTH)
            audit_log: Destination for audit events (env: TENUO_A2A_AUDIT_LOG for path)
            audit_format: "json" or "text"
            previous_keys: List of previous public keys for key rotation
            replay_backend: Custom ReplayBackend implementation (default: InMemoryReplayBackend)
            revoked_issuers: List of issuer keys to unconditionally reject
            signing_key: Optional signing key retained for warrant issuance
                (required when registration_handler is set)
            registration_handler: Optional async callable for automated agent
                registration (CSR pattern). Called after key ownership is verified.

        Rate limiting:
            A2AServer does not throttle requests. In production, put a
            rate-limiting reverse proxy (nginx ``limit_req``, Envoy RateLimit)
            in front of this server.
        """
        self.name = name
        self.url = url.rstrip("/")
        self.public_key = self._normalize_key(public_key)
        # Convert all trusted issuers to canonical string form for comparison
        self.trusted_issuers = {self._normalize_key(k) for k in trusted_issuers}
        self.trust_delegated = trust_delegated

        # Apply environment variable defaults
        # Explicit args take precedence over env vars
        self.require_warrant = self._get_bool_config(require_warrant, "TENUO_A2A_REQUIRE_WARRANT", default=True)
        self.require_audience = self._get_bool_config(require_audience, "TENUO_A2A_REQUIRE_AUDIENCE", default=True)
        self.require_pop = self._get_bool_config(require_pop, "TENUO_A2A_REQUIRE_POP", default=True)
        self.check_replay = self._get_bool_config(check_replay, "TENUO_A2A_CHECK_REPLAY", default=True)
        self.replay_window = self._get_int_config(replay_window, "TENUO_A2A_REPLAY_WINDOW", default=3600)
        self.max_chain_depth = self._get_int_config(max_chain_depth, "TENUO_A2A_MAX_CHAIN_DEPTH", default=10)

        # Audit log: handle env var for file path
        self._owns_audit_log = False  # Track if we should close the file
        if audit_log is None:
            env_log = os.environ.get("TENUO_A2A_AUDIT_LOG", "").strip()
            if env_log and env_log.lower() != "stderr":
                try:
                    self.audit_log = open(env_log, "a")  # noqa: SIM115
                    self._owns_audit_log = True  # We opened it, we should close it
                except (OSError, IOError) as e:
                    # Fall back to stderr if file can't be opened
                    import logging

                    logging.warning(f"Failed to open audit log '{env_log}': {e}. Falling back to stderr.")
                    self.audit_log = sys.stderr  # type: ignore[assignment]
            else:
                self.audit_log = sys.stderr  # type: ignore[assignment]
        else:
            self.audit_log = audit_log
        self.audit_format = audit_format
        self.previous_keys = previous_keys or []

        # Revocation denylist: normalized key strings → deny immediately
        self._revoked_issuers: FrozenSet[str] = frozenset(
            self._normalize_key(k) for k in (revoked_issuers or [])
        )

        # SECURITY: Validate configuration for insecure combinations
        self._validate_config()

        # Build a cached Authorizer from trusted_issuers so we don't rebuild
        # it on every request and share revocation state across requests.
        # Fails loudly at init time if key parsing fails — better than silent
        # production outage during PoP verification.
        self._authorizer = self._build_authorizer()

        # Skill registry
        self._skills: Dict[str, SkillDefinition] = {}

        # Replay cache (pluggable)
        self._replay_cache: Any = replay_backend if replay_backend is not None else InMemoryReplayBackend()

        # Registration (CSR handshake)
        self._signing_key: Optional[Any] = signing_key
        self._registration_handler: Optional[Callable] = registration_handler

        # ASGI app (lazy init)
        self._app = None

    def close(self) -> None:
        """Close any resources owned by the server (e.g., audit log file)."""
        if self._owns_audit_log and hasattr(self.audit_log, "close"):
            try:
                self.audit_log.close()
            except Exception:
                pass  # Best effort cleanup
            self._owns_audit_log = False

    def __del__(self) -> None:
        """Cleanup on garbage collection."""
        self.close()

    def _validate_config(self) -> None:
        """
        Validate configuration for insecure combinations.

        SECURITY: Certain configuration combinations are ineffective or insecure.
        This method logs warnings to help operators identify misconfigurations.
        """
        # Check 1: require_audience=True without require_warrant is ineffective
        if self.require_audience and not self.require_warrant:
            logger.warning(
                "INSECURE CONFIG: require_audience=True but require_warrant=False. "
                "Audience validation is ineffective without warrants. "
                "Set require_warrant=True for secure operation."
            )

        # Check 2: require_pop=True without require_warrant is ineffective
        if self.require_pop and not self.require_warrant:
            logger.warning(
                "INSECURE CONFIG: require_pop=True but require_warrant=False. "
                "PoP validation is ineffective without warrants. "
                "Set require_warrant=True for secure operation."
            )

        # Check 3: check_replay=True without require_warrant is ineffective
        if self.check_replay and not self.require_warrant:
            logger.warning(
                "INSECURE CONFIG: check_replay=True but require_warrant=False. "
                "Replay protection is ineffective without warrants. "
                "Set require_warrant=True for secure operation."
            )

        # Check 4: Production deployment without PoP
        if self.require_warrant and not self.require_pop:
            logger.warning(
                "INSECURE CONFIG: require_warrant=True but require_pop=False. "
                "Warrants without Proof-of-Possession can be stolen and reused. "
                "Set require_pop=True for secure operation."
            )

    # -------------------------------------------------------------------------
    # Configuration Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_bool_config(explicit: Optional[bool], env_var: str, default: bool) -> bool:
        """Get boolean config value from explicit arg or env var."""
        if explicit is not None:
            return explicit
        env_val = os.environ.get(env_var, "").strip().lower()
        if env_val in ("true", "1", "yes", "on"):
            return True
        elif env_val in ("false", "0", "no", "off"):
            return False
        return default

    @staticmethod
    def _get_int_config(explicit: Optional[int], env_var: str, default: int) -> int:
        """Get integer config value from explicit arg or env var."""
        if explicit is not None:
            return explicit
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            try:
                return int(env_val)
            except ValueError:
                logger.warning(f"Invalid int for {env_var}: {env_val!r}, using default {default}")
        return default

    def _build_authorizer(self) -> Any:
        """
        Build a cached Authorizer from self.trusted_issuers.

        Handles all key formats produced by _normalize_key():
        - 64-char hex strings (canonical form for most keys)
        - Multibase strings (z6Mk...) that couldn't be decoded to hex
        - PublicKey objects (passed directly)

        Raises RuntimeError at server init if tenuo_core is unavailable.
        Logs a warning if some keys fail to parse so operators know their
        Authorizer has fewer roots than intended — but does NOT silently
        proceed with zero roots.
        """
        try:
            from tenuo_core import Authorizer as _Authorizer
            from tenuo_core import PublicKey as _PublicKey
        except ImportError as e:
            raise RuntimeError("tenuo_core is required for A2A server authorization") from e

        parsed_keys = []
        failed_reasons = []  # Only store reasons, not keys (security)

        for raw_key in self.trusted_issuers:
            try:
                if hasattr(raw_key, "to_bytes"):  # Already a PublicKey object
                    parsed_keys.append(raw_key)
                elif isinstance(raw_key, str) and len(raw_key) == 64:
                    # Canonical hex (64 hex chars = 32 bytes = Ed25519 public key)
                    parsed_keys.append(_PublicKey.from_bytes(bytes.fromhex(raw_key)))
                elif isinstance(raw_key, str):
                    # Non-hex string (multibase / DID fragment that couldn't be decoded).
                    # Try hex anyway — raises ValueError on malformed input.
                    parsed_keys.append(_PublicKey.from_bytes(bytes.fromhex(raw_key)))
            except Exception as exc:
                # Security: Don't store the key, only the parse error reason
                failed_reasons.append(str(exc))

        if failed_reasons:
            # Security: Log failures without exposing key material
            for reason in failed_reasons:
                logger.warning(
                    f"A2A: trusted issuer key could not be parsed and will NOT be trusted: "
                    f"reason={reason}"
                )

        if not parsed_keys and self.trusted_issuers:
            # Every configured key failed to parse. The Authorizer will have zero roots
            # and will reject all warrants. Log a prominent warning so operators notice.
            logger.warning(
                f"A2A server: all {len(self.trusted_issuers)} trusted_issuers failed to parse "
                f"into PublicKey objects. All warrants will be REJECTED. "
                f"Check key formats (expected 64-char hex)."
            )

        return _Authorizer(trusted_roots=parsed_keys)

    @staticmethod
    def _normalize_key(key: Any) -> str:
        """
        Convert a public key to a canonical string form for comparison.

        Accepts:
        - PublicKey objects (converted to hex of bytes)
        - DID strings (did:key:z6Mk... - extracts multibase key)
        - Multibase strings (z6Mk... - converted to hex)
        - Hex strings (unchanged)

        Returns:
            Canonical hex string representation for consistent comparison.

        Note: All formats are normalized to hex to enable cross-format comparison.
        """

        if isinstance(key, str):
            # Handle DID format: did:key:z6Mk...
            if key.startswith("did:key:"):
                key = key[8:]  # Strip "did:key:" prefix

            # Handle multibase (z = base58btc for Ed25519)
            if key.startswith("z"):
                try:
                    import base58  # type: ignore[import-not-found]

                    # Strip multibase prefix and decode
                    decoded = base58.b58decode(key[1:])
                    # Ed25519 multicodec prefix is 0xed01 (2 bytes)
                    if len(decoded) > 2 and decoded[:2] == b"\xed\x01":
                        return decoded[2:].hex()
                    return decoded.hex()
                except ImportError:
                    # base58 not installed - return as-is
                    logger.debug("base58 not installed, cannot normalize multibase key")
                    return key
                except Exception:
                    # Decoding failed - return as-is
                    return key

            # Already hex or unknown format
            return key

        # Handle PublicKey objects from tenuo_core
        if hasattr(key, "to_bytes"):
            return key.to_bytes().hex()

        # Fallback: string representation
        return str(key)

    # -------------------------------------------------------------------------
    # Skill Decorator
    # -------------------------------------------------------------------------

    def skill(
        self,
        skill_id: str,
        *,
        constraints: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
    ) -> Callable:
        """
        Register a skill with optional constraints.

        Args:
            skill_id: Unique identifier for this skill
            constraints: Map of parameter names to constraint types
            name: Display name (defaults to skill_id)

        Example:
            @server.skill("read_file", constraints={"path": Subpath})
            async def read_file(path: str) -> str:
                ...
        """
        constraints = constraints or {}

        def decorator(func: Callable) -> Callable:
            # Register skill
            skill_def = SkillDefinition(
                skill_id=skill_id,
                func=func,
                constraints=constraints,
                name=name,
            )
            self._skills[skill_id] = skill_def

            # Return original function - constraint enforcement happens in validate_warrant()
            # which is called before skill execution in _handle_task_send()
            return func

        return decorator

    # -------------------------------------------------------------------------
    # Warrant Property Access
    # -------------------------------------------------------------------------

    @staticmethod
    def _get_warrant_prop(warrant: Any, *names: str, default: Any = None) -> Any:
        """
        Get a property from a warrant object, trying multiple attribute names.

        This exists because Warrant objects may use either JWT-style names (iss, aud, jti)
        or descriptive names (issuer, audience, id). The Rust Warrant type exposes both,
        but we want to handle any warrant-like object consistently.

        Args:
            warrant: Warrant object
            *names: Attribute names to try in order
            default: Value to return if no attribute found

        Returns:
            First found attribute value, or default
        """
        for name in names:
            value = getattr(warrant, name, None)
            if value is not None:
                return value
        return default

    # -------------------------------------------------------------------------
    # Warrant Validation
    # -------------------------------------------------------------------------

    async def validate_warrant(
        self,
        warrant_token: str,
        skill_id: str,
        arguments: Dict[str, Any],
        *,
        warrant_chain: Optional[str] = None,
        _preloaded_parents: Optional[List[Any]] = None,
        pop_signature: Optional[bytes] = None,
    ) -> "Warrant":
        """
        Validate a warrant for a skill invocation.

        Args:
            warrant_token: Base64-encoded leaf warrant token
            skill_id: Requested skill
            arguments: Skill arguments to check against constraints
            warrant_chain: Optional semicolon-separated parent warrants (legacy)
            _preloaded_parents: Already-decoded parent warrants from a WarrantStack
                (takes precedence over ``warrant_chain`` when provided)
            pop_signature: Optional Proof-of-Possession signature bytes

        Returns:
            Validated Warrant object

        Raises:
            Various A2AErrors for validation failures
        """
        start_time = time.time()

        # Size guard — reject oversized tokens before any parsing cost
        if len(warrant_token) > MAX_WARRANT_TOKEN_BYTES:
            raise A2AError(
                f"Warrant token size ({len(warrant_token)} bytes) exceeds the "
                f"{MAX_WARRANT_TOKEN_BYTES}-byte limit"
            )

        try:
            from tenuo_core import Warrant
        except ImportError as e:
            raise RuntimeError("tenuo_core not available") from e

        # Decode and verify warrant signature
        # Note: Warrant.from_base64() / from_jwt() performs cryptographic verification
        # against the embedded public key. The issuer trust check below ensures we
        # only accept warrants signed by keys we trust.
        try:
            warrant = Warrant.from_base64(warrant_token)
        except Exception as e:
            raise InvalidSignatureError(f"Failed to decode/verify warrant: {e}")

        # Check expiry (SECURITY: use Rust core method when available)
        # The Rust core's is_expired() method is preferred as it handles
        # edge cases consistently. We fall back to manual check only if needed.
        is_expired_attr = getattr(warrant, "is_expired", None)
        if is_expired_attr is not None:
            try:
                # Call the method to get the boolean result
                if callable(is_expired_attr):
                    is_expired = is_expired_attr()
                else:
                    is_expired = is_expired_attr

                if is_expired:
                    raise WarrantExpiredError()
            except WarrantExpiredError:
                raise  # Re-raise expected errors
            except Exception as e:
                # SECURITY: Fail-closed - if we can't check expiry, deny
                logger.warning(f"Warrant expiry check failed: {e}")
                raise WarrantExpiredError("Expiry check failed (fail-closed)")
        else:
            # Fallback: check exp claim manually
            # Note: This path should rarely be taken with tenuo_core warrants
            now = int(time.time())
            exp = self._get_warrant_prop(warrant, "exp", "expires_at")
            if exp is not None and exp < now:
                raise WarrantExpiredError()

        # Check issuer trust (direct or via chain)
        issuer = self._get_warrant_prop(warrant, "iss", "issuer")
        # Normalize issuer to match the format used in trusted_issuers
        issuer_normalized = self._normalize_key(issuer) if issuer else None

        # Revocation check — explicit denylist takes precedence over trust
        if issuer_normalized and issuer_normalized in self._revoked_issuers:
            raise RevokedError(f"Issuer key '{issuer_normalized}' is revoked")

        # Decoded parent warrants from the chain (populated when delegation is used).
        # Kept in scope so the PoP check can call check_chain instead of authorize_one
        # when the leaf's issuer is a delegated agent (not a direct trusted root).
        _resolved_chain_parents: Optional[List[Any]] = None

        if issuer_normalized and issuer_normalized not in self.trusted_issuers:
            if _preloaded_parents is not None and len(_preloaded_parents) > 0:
                # WarrantStack path: parents already decoded by the HTTP handler.
                # Verify chain structure now; PoP (if required) is done below
                # via check_chain so the full chain is validated atomically.
                if not self.require_pop:
                    await self._validate_chain_warrants(warrant, _preloaded_parents)
                _resolved_chain_parents = _preloaded_parents
            elif self.trust_delegated and warrant_chain:
                # Legacy path: semicolon-separated header.
                _resolved_chain_parents = await self._validate_chain(warrant, warrant_chain)
            else:
                raise UntrustedIssuerError(issuer_normalized)

        # Check audience (SECURITY: must be present AND match when required)
        if self.require_audience:
            aud = self._get_warrant_prop(warrant, "aud", "audience")
            if not aud:
                # SECURITY: Missing aud claim when require_audience=True is a failure
                raise AudienceMismatchError(expected=self.url, actual="", reason="Audience claim missing but required")
            if aud != self.url:
                raise AudienceMismatchError(expected=self.url, actual=aud)

        # Check replay
        if self.check_replay:
            jti = self._get_warrant_prop(warrant, "jti", "id")
            if jti:
                is_new = await self._replay_cache.check_and_add(jti, self.replay_window)
                if not is_new:
                    raise ReplayDetectedError(jti)

        # Verify Proof-of-Possession (I6)
        if self.require_pop:
            if pop_signature is None:
                raise PopRequiredError()

            # Verify PoP via the cached Authorizer.
            # Both authorize_one and check_chain accept plain bytes for the
            # signature and a plain dict for args — no ConstraintValue needed.
            # When a delegation chain was supplied, use check_chain so the full
            # chain (issuer trust + linkage + capabilities + PoP) is verified
            # atomically.  Using authorize_one on the leaf alone would fail
            # because the leaf's issuer is a delegated agent, not a trusted root.
            try:
                if _resolved_chain_parents:
                    all_chain = list(_resolved_chain_parents) + [warrant]
                    self._authorizer.check_chain(
                        all_chain, skill_id, arguments, signature=pop_signature
                    )
                else:
                    self._authorizer.authorize_one(
                        warrant, skill_id, arguments, signature=pop_signature
                    )
                logger.debug(f"PoP verified for skill '{skill_id}'")
            except Exception as e:
                # Map tenuo_core errors to A2A errors
                error_msg = str(e)
                if "Proof-of-Possession" in error_msg or "signature" in error_msg.lower():
                    raise PopVerificationError(error_msg)
                # Re-raise other errors (constraint violations, etc.)
                raise

        # Check skill is granted in warrant
        grants = getattr(warrant, "grants", [])
        if not grants:
            # Try to get grants from tools/capabilities
            tools = getattr(warrant, "tools", None)
            if tools:
                grants = [{"skill": t} for t in tools]

        granted_skills = [g.get("skill", g) if isinstance(g, dict) else g for g in grants]
        if skill_id not in granted_skills:
            raise SkillNotGrantedError(skill_id, granted_skills)

        # Get warrant constraints for this skill (if any)
        warrant_constraints = {}
        for grant in grants:
            if isinstance(grant, dict):
                grant_skill = grant.get("skill")
                if grant_skill == skill_id:
                    warrant_constraints = grant.get("constraints", {})
                    break

        # Check constraints - warrant constraints take precedence over server constraints
        # Server constraints define what the skill CAN check
        # Warrant constraints define what this invocation IS LIMITED TO
        # Both must pass, but warrant may be more restrictive
        skill_def = self._skills.get(skill_id)
        if skill_def:
            for param, server_constraint in skill_def.constraints.items():
                if param in arguments:
                    value = arguments[param]

                    # First check server constraint (the skill's declared requirement)
                    if not self._check_constraint(server_constraint, value, param):
                        raise ConstraintViolationError(
                            param=param,
                            constraint_type=type(server_constraint).__name__,
                            value=value,
                            reason="Value does not satisfy server constraint",
                        )

                    # Then check warrant constraint if present (may be more restrictive)
                    if param in warrant_constraints:
                        # Warrant constraints come as dicts from JSON - deserialize
                        warrant_constraint = self._deserialize_constraint(warrant_constraints[param], param)
                        if not self._check_constraint(warrant_constraint, value, param):
                            raise ConstraintViolationError(
                                param=param,
                                constraint_type=type(warrant_constraint).__name__,
                                value=value,
                                reason="Value does not satisfy warrant constraint",
                            )

        # Log audit event
        latency_ms = int((time.time() - start_time) * 1000)
        await self._audit(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                event=AuditEventType.WARRANT_VALIDATED,
                task_id="",
                skill=skill_id,
                warrant_jti=self._get_warrant_prop(warrant, "jti", "id", default=""),
                warrant_iss=issuer_normalized or "",
                warrant_sub=self._normalize_key(self._get_warrant_prop(warrant, "sub", "subject")) or "",
                outcome="allowed",
                latency_ms=latency_ms,
            )
        )

        return warrant

    async def _validate_chain_warrants(
        self,
        leaf_warrant: Any,
        parents: List[Any],
    ) -> None:
        """
        Validate a delegation chain using the Rust ``Authorizer.verify_chain``.

        The Rust core performs full cryptographic validation:
          - Root warrant issuer is in the server's trusted roots
          - Every warrant's signature is cryptographically valid
          - Each child carries a ``parent_hash`` that matches the hash of its
            parent (stronger than mere issuer/holder key comparison)
          - No warrant in the chain is expired
          - Capability monotonicity is enforced at the Rust level

        The only server-side policy applied here in Python is ``max_chain_depth``,
        which is a deployment limit not encoded into the warrant payloads.

        Args:
            leaf_warrant: The leaf warrant (already decoded, NOT included in parents)
            parents: Parent warrants in root-first order, excluding the leaf

        Raises:
            ChainValidationError, UntrustedIssuerError, WarrantExpiredError
        """
        if not parents:
            raise ChainValidationError("Empty warrant chain")

        if len(parents) > self.max_chain_depth:
            raise ChainValidationError(
                f"Chain depth {len(parents)} exceeds maximum {self.max_chain_depth}"
            )

        # Full chain passed to the Rust verifier: [root, ..., intermediates, leaf]
        all_warrants = list(parents) + [leaf_warrant]

        try:
            self._authorizer.verify_chain(all_warrants)
        except Exception as e:
            _msg = str(e)
            try:
                from tenuo.exceptions import ChainError, ExpiredError, SignatureInvalid
            except ImportError:
                raise ChainValidationError(f"Chain verification error: {_msg}") from e

            if isinstance(e, ExpiredError):
                raise WarrantExpiredError(_msg) from e

            if isinstance(e, SignatureInvalid):
                # "root warrant issuer not trusted" surfaces as SignatureInvalid
                root = all_warrants[0]
                root_issuer = getattr(root, "iss", None) or getattr(root, "issuer", None)
                root_issuer_str = self._normalize_key(root_issuer) if root_issuer else "unknown"
                raise UntrustedIssuerError(
                    root_issuer_str,
                    reason=f"Chain validation failed: {_msg}",
                ) from e

            if isinstance(e, (ChainError, ValueError)):
                raise ChainValidationError(_msg) from e

            # Unexpected Rust error — surface as generic chain failure
            raise ChainValidationError(f"Chain verification error: {_msg}") from e

        logger.debug("Chain validated via Authorizer: %d warrants", len(all_warrants))

    async def _validate_chain(
        self,
        leaf_warrant: Any,
        chain_header: str,
    ) -> List[Any]:
        """
        Validate a delegation chain from a semicolon-separated header string.

        The chain header contains parent warrants in root-first order; the leaf
        warrant is passed separately and is NOT expected to appear in the header.

        This is the legacy transport interface kept for backward compatibility.
        New clients should use WarrantStack transport (a single
        ``X-Tenuo-Warrant`` header containing the packed CBOR array) instead.

        Args:
            leaf_warrant: The leaf warrant (already decoded)
            chain_header: Semicolon-separated base64 parent warrants (parent-first)

        Returns:
            Decoded parent warrants (root-first order, excluding the leaf), so
            the caller can pass the full chain to ``check_chain`` for PoP.

        Raises:
            ChainValidationError, UntrustedIssuerError, WarrantExpiredError
        """
        try:
            from tenuo_core import Warrant
        except ImportError as e:
            raise RuntimeError("tenuo_core not available") from e

        # Parse parent chain (root-first order)
        chain_tokens = [t.strip() for t in chain_header.split(";") if t.strip()]

        if not chain_tokens:
            raise ChainValidationError("Empty warrant chain")

        if len(chain_tokens) > self.max_chain_depth:
            raise ChainValidationError(
                f"Chain depth {len(chain_tokens)} exceeds maximum {self.max_chain_depth}"
            )

        parents: List[Any] = []
        for i, token in enumerate(chain_tokens):
            try:
                w = Warrant.from_base64(token)
                parents.append(w)
            except Exception as e:
                raise ChainValidationError(f"Invalid warrant at position {i}: {e}")

        # Validate structure now (skipped when PoP is required — check_chain does
        # both structure and PoP atomically in validate_warrant's PoP step).
        if not self.require_pop:
            await self._validate_chain_warrants(leaf_warrant, parents)

        return parents

    def _grants_are_subset(self, child: Any, parent: Any) -> bool:
        """
        Check if child's grants are a valid attenuation (subset) of parent's grants.

        Returns True if:
        - Child has fewer or equal skills than parent
        - Each child skill exists in parent
        - For matching skills, child constraints are STRICTLY NARROWER than parent

        SECURITY: Enforces the monotonicity invariant - child warrants can only
        restrict capabilities, never expand them.
        """
        # Get grants from both warrants
        child_grants = getattr(child, "grants", []) or []
        parent_grants = getattr(parent, "grants", []) or []

        # Build skill -> constraints mapping for parent
        parent_skill_map = self._build_skill_constraint_map(parent_grants)

        # Fallback to tools field if no grants
        if not parent_skill_map:
            parent_tools = getattr(parent, "tools", []) or []
            parent_skill_map = {t: {} for t in parent_tools}

        # If parent has no grants/tools, allow any child (root warrant)
        if not parent_skill_map:
            return True

        # Build skill -> constraints mapping for child
        child_skill_map = self._build_skill_constraint_map(child_grants)

        # Fallback to tools field if no grants
        if not child_skill_map:
            child_tools = getattr(child, "tools", []) or []
            child_skill_map = {t: {} for t in child_tools}

        # Check 1: Child skills must be subset of parent skills
        if not set(child_skill_map.keys()).issubset(set(parent_skill_map.keys())):
            return False

        # Check 2: For each child skill, validate constraint narrowing
        for skill, child_constraints in child_skill_map.items():
            parent_constraints = parent_skill_map.get(skill, {})
            if not self._constraints_are_narrower(child_constraints, parent_constraints, skill):
                return False

        return True

    def _build_skill_constraint_map(self, grants: list) -> dict:
        """
        Build a mapping of skill name -> constraints dict from grants list.

        Grants can be:
        - Dict with 'skill' and 'constraints' keys
        - Dict with 'skill' only (no constraints)
        - String (skill name only, no constraints)
        """
        skill_map = {}
        for g in grants:
            if isinstance(g, dict):
                skill = g.get("skill", "")
                if skill:
                    # Check if 'constraints' key is explicitly present
                    if "constraints" in g:
                        # Use the explicit constraints value (even if empty dict)
                        constraints = g["constraints"] or {}
                    else:
                        # Fallback: check for inline constraints (deprecated format)
                        # Exclude 'skill' key
                        constraints = {k: v for k, v in g.items() if k != "skill"}
                    skill_map[skill] = constraints
            elif isinstance(g, str):
                skill_map[g] = {}
        return skill_map

    def _constraints_are_narrower(self, child_constraints: dict, parent_constraints: dict, skill: str = "") -> bool:
        """
        Validate that child constraints are strictly narrower or equal to parent.

        Rules:
        - Every parent constraint field MUST have a corresponding child constraint
        - Child constraints MUST be at least as restrictive as parent

        Constraint-specific validation:
        - Subpath: parent.contains(child.root) must be True
        - UrlSafe: Child flags cannot be less restrictive than parent
        - Unknown: FAIL CLOSED (deny for security)

        Args:
            child_constraints: Dict of {field: constraint} from child grant
            parent_constraints: Dict of {field: constraint} from parent grant
            skill: Skill name for error context

        Returns:
            True if child is valid attenuation of parent
        """
        # If parent has no constraints, child can have any constraints (adding is OK)
        if not parent_constraints:
            return True

        # For each parent constraint, child must have equal or narrower constraint
        for field, parent_constraint in parent_constraints.items():
            child_constraint = child_constraints.get(field)

            # SECURITY: Child MUST have constraint if parent does
            # Removing a constraint would expand capabilities
            if child_constraint is None:
                logger.warning(
                    f"Attenuation violation: skill='{skill}' field='{field}' - child missing constraint that parent has"
                )
                return False

            # Validate narrowing based on constraint type
            if not self._constraint_is_narrower(child_constraint, parent_constraint, field):
                return False

        return True

    def _constraint_is_narrower(self, child: Any, parent: Any, field: str = "") -> bool:
        """
        Check if a single child constraint is narrower or equal to parent.

        Uses duck typing to identify constraint types (PyO3 compatibility).
        """
        # Get constraint type names for comparison
        child_type = type(child).__name__
        parent_type = type(parent).__name__

        # Same type required for comparison
        if child_type != parent_type:
            logger.warning(
                f"Attenuation violation: field='{field}' - "
                f"constraint type mismatch: child={child_type}, parent={parent_type}"
            )
            return False

        # PREFERRED: Use tenuo_core's validate_attenuation() method (Rust)
        # This is available for: Subpath, UrlSafe, Pattern, Range, Cidr, OneOf,
        # NotOneOf, Contains, Subset, All, Regex, UrlPattern, CEL
        if hasattr(parent, "validate_attenuation"):
            try:
                parent.validate_attenuation(child)
                return True
            except Exception as e:
                logger.warning(f"Attenuation violation: field='{field}' - {e}")
                return False

        # Shlex: Python-only constraint (no Rust implementation)
        # Uses allowed_bins attribute for attenuation check
        if hasattr(parent, "matches") and hasattr(parent, "allowed_bins"):
            try:
                parent_exec = set(getattr(parent, "allowed_bins", []))
                child_exec = set(getattr(child, "allowed_bins", []))
                if not child_exec.issubset(parent_exec):
                    logger.warning(f"Attenuation violation: field='{field}' - child executables not subset of parent")
                    return False
                return True
            except Exception as e:
                logger.warning(f"Shlex comparison failed: {e}")
                return False

        # SECURITY: Unknown constraint type - FAIL CLOSED
        logger.warning(
            f"Attenuation check failed: field='{field}' - unknown constraint type '{parent_type}' (fail-closed)"
        )
        return False

    def _check_constraint(self, constraint: Any, value: Any, param: str = "") -> bool:
        """
        Check if value satisfies constraint using Rust core bindings.

        Fails closed: unknown constraint types are denied for security.

        NOTE on duck typing:
        We use duck typing (hasattr checks) because:
        1. tenuo_core constraints are PyO3-compiled Rust types
        2. isinstance() doesn't work well across the FFI boundary
        3. The method names are part of the stable API contract

        All constraint runtime checks use Rust core bindings:
          - Subpath.contains()     -> Rust core
          - UrlSafe.is_safe()      -> Rust core
          - Cidr.contains_ip()     -> Rust core
          - Pattern.matches()      -> Rust core
          - Shlex.matches()        -> Rust core
          - Range.contains()       -> Rust core
          - Exact.matches()        -> Rust core
          - OneOf.contains()       -> Rust core
          - NotOneOf.allows()      -> Rust core
          - Wildcard.matches()     -> Rust core

        If tenuo_core changes these method names, tests in test_a2a.py will fail.
        See TestConstraintMethodNames for regression tests.

        Args:
            constraint: The constraint to check against
            value: The value to validate
            param: Parameter name (for error reporting)

        Returns:
            True if value satisfies constraint

        Raises:
            UnknownConstraintError: If constraint type is not recognized
        """
        constraint_type = type(constraint).__name__

        # =================================================================
        # RUST CORE METHODS - Type-aware dispatch
        # =================================================================

        # Subpath - filesystem path containment (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "Subpath":
            return constraint.contains(str(value))

        # UrlSafe - SSRF protection (Rust core)
        if hasattr(constraint, "is_safe"):
            if isinstance(value, list):
                return all(constraint.is_safe(str(v)) for v in value)
            return constraint.is_safe(str(value))

        # Cidr - IP address range (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "Cidr":
            return constraint.contains(str(value))

        # Pattern - glob matching (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Pattern":
            return constraint.matches(value)

        # Shlex - shell command validation (Rust core via Python shlex)
        if hasattr(constraint, "matches") and constraint_type == "Shlex":
            return constraint.matches(str(value))

        # UrlPattern - URL pattern matching (Rust core)
        if hasattr(constraint, "matches_url"):
            return constraint.matches_url(str(value))

        # Range - numeric bounds (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "Range":
            try:
                return constraint.contains(float(value))
            except (ValueError, TypeError):
                return False  # Non-numeric value fails Range check

        # Exact - exact value match (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Exact":
            return constraint.matches(str(value))

        # OneOf - set membership (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "OneOf":
            return constraint.contains(str(value))

        # NotOneOf - exclusion list (Rust core)
        if hasattr(constraint, "allows") and constraint_type == "NotOneOf":
            return constraint.allows(str(value))

        # Wildcard - matches anything (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Wildcard":
            return constraint.matches(str(value))

        # Regex - regex matching (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Regex":
            return constraint.matches(value)

        # Type constraint (e.g., str, int)
        if isinstance(constraint, type):
            return isinstance(value, constraint)

        # SECURITY: Unknown constraint type - FAIL CLOSED
        # We don't recognize this constraint, so we cannot validate it.
        # Allowing by default would be a security hole.
        raise UnknownConstraintError(
            constraint_type=constraint_type,
            param=param,
        )

    def _deserialize_constraint(self, data: Any, param: str = "") -> Any:
        """
        Convert wire format (dict) to constraint object.

        Warrant constraints come over the wire as dicts like:
            {"type": "Subpath", "root": "/data"}
            {"type": "Range", "min": 0, "max": 100}
            {"type": "OneOf", "values": ["prod", "staging"]}

        This converts them to actual constraint objects for _check_constraint().

        Supported constraint types:
        - Subpath: Filesystem path containment
        - UrlSafe: SSRF protection
        - Pattern: Glob matching
        - Shlex: Shell command validation
        - Range: Numeric bounds
        - Cidr: IP address ranges
        - OneOf: Set membership
        - NotOneOf: Exclusion list
        - Regex: Regular expression matching

        Args:
            data: Constraint dict or already-instantiated constraint
            param: Parameter name (for error reporting)

        Returns:
            Constraint object (Subpath, UrlSafe, Shlex, etc.)

        Raises:
            UnknownConstraintError: If constraint type is not recognized
        """
        # Already a constraint object? Return as-is
        if not isinstance(data, dict):
            return data

        constraint_type = data.get("type", "")

        try:
            # Filesystem path containment
            if constraint_type == "Subpath":
                from tenuo_core import Subpath

                return Subpath(data.get("root", "/"))

            # SSRF protection
            elif constraint_type == "UrlSafe":
                from tenuo_core import UrlSafe

                return UrlSafe(allow_domains=data.get("allow_domains"))

            # Shell command validation (Python-only)
            elif constraint_type == "Shlex":
                from tenuo.constraints import Shlex

                return Shlex(allow=data.get("allow", []))

            # Glob pattern matching
            elif constraint_type == "Pattern":
                from tenuo_core import Pattern

                return Pattern(data.get("pattern", "*"))

            # Numeric range bounds
            elif constraint_type == "Range":
                from tenuo_core import Range

                min_val = data.get("min")
                max_val = data.get("max")
                if min_val is None or max_val is None:
                    raise ValueError("Range constraint requires 'min' and 'max' fields")
                return Range(min=float(min_val), max=float(max_val))

            # IP address range (CIDR notation)
            elif constraint_type == "Cidr":
                from tenuo_core import Cidr

                cidr = data.get("cidr")
                if not cidr:
                    raise ValueError("Cidr constraint requires 'cidr' field")
                return Cidr(cidr)

            # Set membership (allowlist)
            elif constraint_type == "OneOf":
                from tenuo_core import OneOf

                values = data.get("values", [])
                if not values:
                    raise ValueError("OneOf constraint requires non-empty 'values' list")
                # Convert values to strings for OneOf
                return OneOf(values=[str(v) for v in values])

            # Exclusion list (blocklist)
            elif constraint_type == "NotOneOf":
                from tenuo_core import NotOneOf

                values = data.get("values", [])
                if not values:
                    raise ValueError("NotOneOf constraint requires non-empty 'values' list")
                # Convert values to strings for NotOneOf
                return NotOneOf(values=[str(v) for v in values])

            # Regular expression matching
            elif constraint_type == "Regex":
                from tenuo_core import Regex

                pattern = data.get("pattern")
                if not pattern:
                    raise ValueError("Regex constraint requires 'pattern' field")
                return Regex(pattern)

            else:
                # Unknown type - fail closed
                raise UnknownConstraintError(constraint_type=constraint_type, param=param)

        except UnknownConstraintError:
            raise  # Re-raise expected errors
        except ImportError as e:
            logger.warning(f"Failed to import constraint type {constraint_type}: {e}")
            raise UnknownConstraintError(constraint_type=constraint_type, param=param)
        except Exception as e:
            # SECURITY: Fail-closed - deserialization errors mean we can't validate
            logger.warning(f"Failed to deserialize {constraint_type} constraint: {e}")
            raise UnknownConstraintError(constraint_type=constraint_type, param=param)

    # -------------------------------------------------------------------------
    # Audit Logging
    # -------------------------------------------------------------------------

    async def _audit(self, event: AuditEvent):
        """Write audit event."""
        if callable(self.audit_log):
            # Custom handler
            if asyncio.iscoroutinefunction(self.audit_log):
                await self.audit_log(event)
            else:
                self.audit_log(event)
        elif hasattr(self.audit_log, "write"):
            # File-like object
            if self.audit_format == "json":
                self.audit_log.write(json.dumps(event.to_dict()) + "\n")
            else:
                self.audit_log.write(f"[{event.event.value}] {event.skill}: {event.outcome}\n")
            self.audit_log.flush()

    # -------------------------------------------------------------------------
    # Agent Card
    # -------------------------------------------------------------------------

    def get_agent_card(self) -> AgentCard:
        """Generate AgentCard for discovery."""
        skills = [s.to_skill_info() for s in self._skills.values()]
        return AgentCard(
            name=self.name,
            url=self.url,
            skills=skills,
            tenuo_extension=TenuoExtension(
                version="0.1.0",
                required=self.require_warrant,
                public_key=self.public_key,
                previous_keys=self.previous_keys,
            ),
        )

    def get_agent_card_dict(self) -> Dict[str, Any]:
        """Generate AgentCard as dict for JSON response."""
        card = self.get_agent_card()
        skills = []
        for s in card.skills:
            skill_dict: Dict[str, Any] = {"id": s.id, "name": s.name}
            if s.constraints:
                skill_dict["x-tenuo-constraints"] = {
                    k: {"type": v.type, "required": v.required} for k, v in s.constraints.items()
                }
            skills.append(skill_dict)

        return {
            "name": card.name,
            "url": card.url,
            "skills": skills,
            "x-tenuo": {
                "version": card.tenuo_extension.version,
                "required": card.tenuo_extension.required,
                "public_key": card.tenuo_extension.public_key,
                "previous_keys": card.tenuo_extension.previous_keys,
            }
            if card.tenuo_extension
            else None,
        }

    # -------------------------------------------------------------------------
    # ASGI App
    # -------------------------------------------------------------------------

    @property
    def app(self):
        """Get ASGI application for uvicorn."""
        if self._app is None:
            self._app = self._create_app()
        return self._app

    def _create_app(self):
        """Create Starlette ASGI app."""
        try:
            from starlette.applications import Starlette
            from starlette.requests import Request  # noqa: F401 (used in handle_a2a below)
            from starlette.responses import JSONResponse
            from starlette.routing import Route
        except ImportError:
            raise ImportError("starlette is required for A2A server. Install with: uv pip install tenuo[a2a]")

        async def handle_a2a(request: Request) -> JSONResponse:
            """Handle JSON-RPC A2A requests."""
            try:
                body = await request.json()
            except Exception:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {"code": A2AErrorCode.PARSE_ERROR, "message": "Parse error"},
                        "id": None,
                    }
                )

            method = body.get("method", "")
            params = body.get("params", {})
            request_id = body.get("id")

            try:
                if method == "agent/discover":
                    result = self.get_agent_card_dict()
                elif method == "agent/register":
                    result = await self._handle_register(params)
                elif method == "task/send":
                    result = await self._handle_task_send(request, params)
                elif method == "task/sendSubscribe":
                    # Streaming response
                    return await self._handle_task_send_subscribe(request, params, request_id)
                else:
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "error": {"code": A2AErrorCode.METHOD_NOT_FOUND, "message": "Method not found"},
                            "id": request_id,
                        }
                    )

                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": request_id,
                    }
                )

            except A2AError as e:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": e.to_jsonrpc_error(),
                        "id": request_id,
                    }
                )
            except Exception as e:
                logger.exception("Unexpected error in A2A handler")
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {"code": A2AErrorCode.INTERNAL_ERROR, "message": str(e)},
                        "id": request_id,
                    }
                )

        async def handle_discover(request: Request) -> JSONResponse:
            """Handle agent discovery requests."""
            return JSONResponse(self.get_agent_card_dict())

        routes = [
            Route("/a2a", handle_a2a, methods=["POST"]),
            Route("/.well-known/agent.json", handle_discover, methods=["GET"]),
        ]

        return Starlette(routes=routes)

    async def _handle_register(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle agent/register JSON-RPC method (CSR handshake).

        Validation pipeline (fail-closed at every step):

        1. Check registration handler is configured → RegistrationDisabledError
        2. Parse WarrantRequest from params → A2AError on malformed input
        3. Size guard on challenge_token → A2AError if > MAX_WARRANT_TOKEN_BYTES
        4. Warrant.from_base64(challenge_token) → InvalidSignatureError on bad sig
        5. is_expired() check → InvalidSignatureError if expired
        6. Normalize iss == public_key → InvalidSignatureError if mismatch
        7. JTI → replay_cache.check_and_add() → ReplayDetectedError if replayed
        8. Build VerifiedWarrantRequest
        9. Build issue() oracle (signing key bound inside closure)
        10. Call handler(verified_req, issue) → RegistrationDeniedError on denial
        11. Check issue() was called → RegistrationDeniedError if not
        12. Return {"warrant": base64_token}
        """
        # Step 1: Check handler configured
        if self._registration_handler is None:
            raise RegistrationDisabledError(
                "Agent registration is not enabled on this server. "
                "Obtain a warrant out-of-band from the server operator."
            )

        # Step 2: Parse WarrantRequest
        try:
            req = WarrantRequest.from_dict(params)
        except (KeyError, TypeError, ValueError) as e:
            raise A2AError(f"Invalid registration request: {e}")

        # Step 3: Size guard on challenge_token
        if len(req.challenge_token) > MAX_WARRANT_TOKEN_BYTES:
            raise InvalidSignatureError(
                f"Challenge token size ({len(req.challenge_token)} bytes) exceeds "
                f"the {MAX_WARRANT_TOKEN_BYTES}-byte limit"
            )

        # Step 4: Parse and verify challenge warrant signature
        try:
            from tenuo_core import Warrant
        except ImportError as e:
            raise RuntimeError("tenuo_core not available") from e

        try:
            challenge_warrant = Warrant.from_base64(req.challenge_token)
        except Exception as e:
            raise InvalidSignatureError(f"Challenge token signature invalid: {e}")

        # Step 5: Check challenge token not expired (fail-closed)
        is_expired_attr = getattr(challenge_warrant, "is_expired", None)
        try:
            if callable(is_expired_attr):
                expired = is_expired_attr()
            else:
                now = int(time.time())
                exp = getattr(challenge_warrant, "exp", None)
                expired = exp is not None and exp < now
            if expired:
                raise InvalidSignatureError("Challenge token has expired")
        except InvalidSignatureError:
            raise
        except Exception:
            raise InvalidSignatureError("Could not verify challenge token expiry (fail-closed)")

        # Step 6: Verify iss == public_key (proves key ownership)
        # The challenge token is self-signed: iss must equal the claimed public_key.
        challenge_iss = (
            getattr(challenge_warrant, "iss", None)
            or getattr(challenge_warrant, "issuer", None)
        )
        iss_normalized = self._normalize_key(challenge_iss) if challenge_iss else None
        req_key_normalized = self._normalize_key(req.public_key)

        if not iss_normalized or iss_normalized != req_key_normalized:
            raise InvalidSignatureError(
                "Challenge token issuer does not match claimed public key "
                "(self-signed proof-of-key-possession failed)"
            )

        # Step 7: Replay protection — prefix with "reg:" to isolate from task JTIs
        challenge_jti = (
            getattr(challenge_warrant, "jti", None)
            or getattr(challenge_warrant, "id", None)
        )
        if challenge_jti:
            is_new = await self._replay_cache.check_and_add(
                f"reg:{challenge_jti}", self.replay_window
            )
            if not is_new:
                raise ReplayDetectedError(challenge_jti)

        # Step 8: Build VerifiedWarrantRequest
        try:
            from tenuo_core import PublicKey
            verified_key = PublicKey.from_bytes(bytes.fromhex(req_key_normalized))
        except Exception as e:
            raise InvalidSignatureError(f"Cannot parse claimed public key: {e}")

        verified_req = VerifiedWarrantRequest(
            verified_key=verified_key,
            verified_key_hex=req_key_normalized,
            capabilities=req.capabilities,
            extensions=req.extensions,
        )

        # Step 9: Build issue() oracle — signing key never leaves this closure
        issued_warrant_token: Optional[str] = None

        async def issue(
            capabilities: Dict[str, Any],
            ttl: int = 3600,
            audience: Optional[str] = None,
        ) -> None:
            nonlocal issued_warrant_token
            try:
                granted = Warrant.mint(
                    keypair=self._signing_key,
                    holder=verified_req.verified_key,
                    capabilities=capabilities,
                    ttl_seconds=ttl,
                )
                issued_warrant_token = granted.to_base64()
            except Exception as e:
                raise RegistrationDeniedError(f"Failed to issue warrant: {e}")

        # Step 10: Call handler
        try:
            await self._registration_handler(verified_req, issue)
        except (RegistrationDeniedError, A2AError):
            raise
        except Exception as e:
            raise RegistrationDeniedError(f"Registration handler error: {e}")

        # Step 11: Check issue() was called
        if issued_warrant_token is None:
            raise RegistrationDeniedError(
                "Registration handler returned without issuing a warrant. "
                "Call await issue(capabilities=...) inside the handler to approve registration."
            )

        # Step 12: Return warrant token
        logger.info(
            "Registration approved for key %s...",
            verified_req.verified_key_hex[:16],
        )
        return {"warrant": issued_warrant_token}

    async def _handle_task_send(self, request: "Request", params: Dict) -> Dict[str, Any]:
        """Handle task/send method."""
        task = params.get("task", {})
        _message = task.get("message", "")  # Extracted for future use (logging, context)
        skill_id = task.get("skill", "")
        arguments = task.get("arguments", {})
        task_id = task.get("id") or str(uuid.uuid4())

        # Get warrant from header or params
        warrant_token_raw = request.headers.get(WARRANT_HEADER)
        if not warrant_token_raw:
            warrant_token_raw = params.get("x-tenuo-warrant")

        # Try to decode as a packed WarrantStack (new single-header transport).
        # If the value is a multi-warrant CBOR array, split it into leaf + parents
        # so the chain validation path can proceed without the legacy chain header.
        _preloaded_parents: Optional[List[Any]] = None
        warrant_token = warrant_token_raw
        if warrant_token_raw:
            try:
                from tenuo_core import decode_warrant_stack_base64

                stack_warrants = decode_warrant_stack_base64(warrant_token_raw)
                if len(stack_warrants) >= 1:
                    # Re-encode only the leaf so validate_warrant sees a normal token
                    warrant_token = stack_warrants[-1].to_base64()
                    _preloaded_parents = stack_warrants[:-1]  # empty list for 1-element stacks
            except Exception:
                # Not a WarrantStack — treat as a plain single-warrant token
                pass

        # Legacy fallback: chain header (only consulted when no WarrantStack decoded).
        warrant_chain: Optional[str] = None
        if not _preloaded_parents:
            warrant_chain = request.headers.get(WARRANT_CHAIN_HEADER)
            if not warrant_chain:
                warrant_chain = params.get("x-tenuo-warrant-chain")

        # Get Proof-of-Possession signature (base64 URL-safe encoded)
        pop_b64 = request.headers.get("X-Tenuo-PoP")
        if not pop_b64:
            pop_b64 = params.get("x-tenuo-pop")

        pop_signature = None
        if pop_b64:
            import base64

            try:
                pop_signature = base64.urlsafe_b64decode(pop_b64)
            except Exception as e:
                logger.warning(f"Failed to decode PoP signature: {e}")

        if self.require_warrant and not warrant_token:
            raise MissingWarrantError("Warrant required")

        # Validate warrant (with optional chain and PoP)
        warrant = None
        if warrant_token:
            warrant = await self.validate_warrant(
                warrant_token,
                skill_id,
                arguments,
                warrant_chain=warrant_chain,
                _preloaded_parents=_preloaded_parents,
                pop_signature=pop_signature,
            )

        # Set current warrant context
        token = current_task_warrant.set(warrant)

        try:
            # Get skill handler
            skill_def = self._skills.get(skill_id)
            if not skill_def:
                # Note: This is different from SkillNotGrantedError
                # - SkillNotFoundError: skill doesn't exist on this server
                # - SkillNotGrantedError: skill exists but not granted in warrant
                raise SkillNotFoundError(skill_id, list(self._skills.keys()))

            # Execute skill
            result = await skill_def.func(**arguments)

            return {
                "task_id": task_id,
                "status": "complete",
                "output": result,
            }
        finally:
            current_task_warrant.reset(token)

    async def _handle_task_send_subscribe(self, request: "Request", params: Dict, request_id: Any) -> Any:
        """Handle task/sendSubscribe method with SSE streaming response."""
        try:
            from starlette.responses import StreamingResponse
        except ImportError:
            raise RuntimeError("starlette is required for streaming")

        task = params.get("task", {})
        _message = task.get("message", "")
        skill_id = task.get("skill", "")
        arguments = task.get("arguments", {})
        task_id = task.get("id") or str(uuid.uuid4())

        # Get warrant from header or params — same WarrantStack logic as task/send
        warrant_token_raw = request.headers.get(WARRANT_HEADER) or params.get("x-tenuo-warrant")

        _preloaded_parents: Optional[List[Any]] = None
        warrant_token = warrant_token_raw
        if warrant_token_raw:
            try:
                from tenuo_core import decode_warrant_stack_base64

                stack_warrants = decode_warrant_stack_base64(warrant_token_raw)
                if len(stack_warrants) >= 1:
                    warrant_token = stack_warrants[-1].to_base64()
                    _preloaded_parents = stack_warrants[:-1]
            except Exception:
                pass

        warrant_chain: Optional[str] = None
        if not _preloaded_parents:
            warrant_chain = request.headers.get(WARRANT_CHAIN_HEADER) or params.get("x-tenuo-warrant-chain")

        # Get Proof-of-Possession signature
        pop_b64 = request.headers.get("X-Tenuo-PoP") or params.get("x-tenuo-pop")
        pop_signature = None
        if pop_b64:
            import base64

            try:
                pop_signature = base64.urlsafe_b64decode(pop_b64)
            except Exception as e:
                logger.warning(f"Failed to decode PoP signature: {e}")

        # Validate warrant (same as task/send)
        warrant = None
        if self.require_warrant and not warrant_token:
            raise MissingWarrantError("Warrant required for streaming")

        if warrant_token:
            warrant = await self.validate_warrant(
                warrant_token,
                skill_id,
                arguments,
                warrant_chain=warrant_chain,
                _preloaded_parents=_preloaded_parents,
                pop_signature=pop_signature,
            )

        # Get warrant expiry for mid-stream checks
        warrant_exp = getattr(warrant, "exp", None) if warrant else None

        async def event_generator():
            """Generate SSE events."""
            import json

            # Set current warrant context
            token = current_task_warrant.set(warrant)

            try:
                # Get skill handler
                skill_def = self._skills.get(skill_id)
                if not skill_def:
                    error_event = {
                        "type": "error",
                        "task_id": task_id,
                        "code": A2AErrorCode.SKILL_NOT_FOUND,
                        "message": f"Skill '{skill_id}' not found",
                    }
                    yield f"data: {json.dumps(error_event)}\n\n"
                    return

                # Emit status event
                status_event = {
                    "type": "status",
                    "task_id": task_id,
                    "status": "running",
                }
                yield f"data: {json.dumps(status_event)}\n\n"

                # Execute skill - check for generator/streaming skill
                result = skill_def.func(**arguments)

                # Check if result is async generator (streaming skill)
                if hasattr(result, "__anext__"):
                    async for chunk in result:
                        # Mid-stream expiry check
                        if warrant_exp and time.time() > warrant_exp:
                            error_event = {
                                "type": "error",
                                "task_id": task_id,
                                "code": A2AErrorCode.EXPIRED,
                                "message": "Warrant expired",
                                "data": {"mid_stream": True},
                            }
                            yield f"data: {json.dumps(error_event)}\n\n"
                            return

                        # Emit chunk
                        chunk_event = {
                            "type": "message",
                            "task_id": task_id,
                            "content": str(chunk),
                        }
                        yield f"data: {json.dumps(chunk_event)}\n\n"
                else:
                    # Await if coroutine
                    if hasattr(result, "__await__"):
                        result = await result

                # Final expiry check before completion
                # (catches expiry during long-running non-streaming skills)
                if warrant_exp and time.time() > warrant_exp:
                    error_event = {
                        "type": "error",
                        "task_id": task_id,
                        "code": A2AErrorCode.EXPIRED,
                        "message": "Warrant expired during execution",
                        "data": {"at_completion": True},
                    }
                    yield f"data: {json.dumps(error_event)}\n\n"
                    return

                # Emit completion
                complete_event = {
                    "type": "complete",
                    "task_id": task_id,
                    "output": result if not hasattr(result, "__anext__") else None,
                }
                yield f"data: {json.dumps(complete_event)}\n\n"

            except A2AError as e:
                error_event = {
                    "type": "error",
                    "task_id": task_id,
                    "code": e.code.value if hasattr(e.code, "value") else e.code,
                    "message": str(e),
                }
                yield f"data: {json.dumps(error_event)}\n\n"
            except Exception as e:
                error_event = {
                    "type": "error",
                    "task_id": task_id,
                    "code": A2AErrorCode.INTERNAL_ERROR,
                    "message": str(e),
                }
                yield f"data: {json.dumps(error_event)}\n\n"
            finally:
                current_task_warrant.reset(token)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
