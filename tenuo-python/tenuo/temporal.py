"""
Tenuo Temporal Integration - Warrant-based Authorization for Durable Workflows

Compatibility:
    Temporal SDK: 1.4.0+
    Python: 3.9+

Setup (required):
    Tenuo's core library (``tenuo_core``) is a PyO3 native module that
    cannot be re-initialised inside Temporal's workflow sandbox.  You
    **must** declare ``tenuo`` and ``tenuo_core`` as passthrough modules
    when creating the worker::

        from temporalio.worker.workflow_sandbox import (
            SandboxedWorkflowRunner, SandboxRestrictions,
        )

        worker = Worker(
            client,
            task_queue="my-queue",
            workflows=[MyWorkflow],
            activities=[my_activity],
            interceptors=[TenuoInterceptor(config)],
            workflow_runner=SandboxedWorkflowRunner(
                restrictions=SandboxRestrictions.default.with_passthrough_modules(
                    "tenuo", "tenuo_core",
                )
            ),
        )

    Without this, ``tenuo_execute_activity()`` and ``AuthorizedWorkflow``
    will fail with ``ImportError: PyO3 modules compiled for CPython 3.8
    or older may only be initialized once per interpreter process``.

    See ``examples/temporal/demo.py`` for a complete working example, or
    ``examples/temporal/authorized_workflow_demo.py`` for the simpler
    ``AuthorizedWorkflow`` base-class pattern.

Overview:
    This module provides seamless integration between Tenuo's warrant-based
    authorization and Temporal's durable workflow orchestration. Activity
    execution is transparently authorized against the workflow's warrant.

Key Concepts:
    - Warrants propagate via Temporal headers, no code changes to activities
    - TenuoInterceptor enforces authorization at the activity boundary
    - KeyResolver abstraction for secure key material management

Security Philosophy (Fail-Closed by Default):
    - Missing warrant headers: Denied (require_warrant=True by default)
    - Invalid warrant: Raises ChainValidationError
    - Expired warrant: Raises WarrantExpired
    - Constraint violation: Raises ConstraintViolation
    - PoP failure: Raises PopVerificationError (PoP is always mandatory)
    - Local activity without @unprotected: Raises LocalActivityError

Usage Patterns:
    **AuthorizedWorkflow (recommended for most cases)**::

        @workflow.defn
        class MyWorkflow(AuthorizedWorkflow):
            @workflow.run
            async def run(self, arg: str) -> str:
                return await self.execute_authorized_activity(
                    my_activity, args=[arg],
                    start_to_close_timeout=timedelta(seconds=30),
                )

    **tenuo_execute_activity (for delegation / multi-warrant)**::

        @workflow.defn
        class PipelineWorkflow:
            @workflow.run
            async def run(self, data_dir: str) -> str:
                return await tenuo_execute_activity(
                    my_activity, args=[data_dir],
                    start_to_close_timeout=timedelta(seconds=30),
                )

Proof-of-Possession (PoP) Challenge Format:
    PoP ensures that only the entity holding the private key matching the
    warrant's ``authorized_holder`` can invoke a tool.  Each activity call
    produces a fresh 64-byte Ed25519 signature over a deterministic challenge.

    Challenge construction (implemented in tenuo-core)::

        domain_context = b"tenuo-pop-v1"
        window_ts      = (unix_now // 30) * 30          # 30-second bucket
        challenge_data = CBOR( (warrant_id, tool, sorted_args, window_ts) )
        preimage       = domain_context || challenge_data
        signature      = Ed25519.sign(signing_key, preimage)   # 64 bytes

    Field details:
        - ``warrant_id``:  Hex-encoded warrant ID (``warrant.id``).
        - ``tool``:        Activity / tool name as a string.
        - ``sorted_args``: Key-sorted ``[(name, ConstraintValue), ...]`` pairs.
        - ``window_ts``:   Unix timestamp floored to 30-second windows for
          replay tolerance.  Signatures are valid for 4 windows (2 minutes).
        - CBOR (RFC 8949) is the canonical serialisation format.

    Wire encoding:
        ``tenuo_execute_activity()`` computes the signature via
        ``warrant.sign(signing_key, tool, args_dict)`` and stores it as
        base64-encoded bytes in a per-``(workflow_id, tool, args)`` FIFO
        queue (``_pending_pop``).  This keying scheme ensures parallel
        activities (e.g. via ``asyncio.gather``) don't overwrite each
        other's signatures.  The activity interceptor computes the same
        key, pops the oldest entry, decodes the base64, and passes the
        raw 64-byte signature to ``Authorizer.check_chain()`` or ``Authorizer.authorize_one()``.

Troubleshooting:
    ``ImportError: PyO3 modules ... may only be initialized once``
        You forgot to configure passthrough modules.  See **Setup** above.

    ``TenuoContextError: No Tenuo headers in store``
        The workflow was started without ``tenuo_headers()``.  Make sure the
        client calls ``TenuoClientInterceptor.set_headers(tenuo_headers(...))``
        before ``client.execute_workflow()``.

    ``ConstraintViolation: No warrant provided (require_warrant=True)``
        The activity interceptor received no warrant.  Common causes:
        (a) ``set_headers()`` was never called, (b) headers were cleared
        between workflows, or (c) the ``TenuoClientInterceptor`` is missing
        from the client's interceptor list.

    ``ConstraintViolation: ... Incorrect padding`` or ``signature must be 64 bytes``
        PoP encoding mismatch.  Ensure you're using ``tenuo_execute_activity()``
        or ``AuthorizedWorkflow.execute_authorized_activity()`` — do **not**
        call ``workflow.execute_activity()`` directly for protected activities.

    ``WarrantExpired: Warrant '...' expired at ...``
        The warrant's TTL has elapsed.  Mint a new warrant with a longer
        ``ttl()`` or refresh the warrant before starting the workflow.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import threading
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Literal, Optional, TypeVar

logger = logging.getLogger("tenuo.temporal")

# Type variable for decorator
F = TypeVar("F", bound=Callable[..., Any])

# =============================================================================
# Header Constants
# =============================================================================

TENUO_WARRANT_HEADER = "x-tenuo-warrant"
TENUO_KEY_ID_HEADER = "x-tenuo-key-id"
TENUO_COMPRESSED_HEADER = "x-tenuo-compressed"
TENUO_POP_HEADER = "x-tenuo-pop"
TENUO_SIGNING_KEY_HEADER = "x-tenuo-signing-key"
TENUO_CHAIN_HEADER = "x-tenuo-warrant-chain"

# PoP timestamp validation window (seconds). The scheduled_time must be
# within this window. This is not configurable — security is non-negotiable.
POP_WINDOW_SECONDS = 300

# =============================================================================
# Module-level stores for warrant propagation
# =============================================================================
# Temporal's workflow.execute_activity() does not accept a headers kwarg, and
# workflow-start headers are not automatically forwarded to activities.
#
# The TenuoClientInterceptor populates _workflow_headers_store when a workflow
# is started (runs in the main process, outside any sandbox).  The activity
# interceptor reads from the same dict.
#
# tenuo_execute_activity() (inside the sandbox, accessing tenuo as a
# passthrough module) writes PoP signatures to _pending_pop for the
# activity interceptor to consume.
#
# _workflow_headers_store: workflow_id → raw Tenuo header bytes
# _pending_pop:           pop_key → FIFO queue of PoP signatures
#
# The pop_key is computed from (workflow_id, tool_name, positional_args)
# so that parallel activities (e.g. via asyncio.gather) each get their
# own PoP slot.  For identical calls (same tool + same args), the PoP
# signatures are deterministic within a 30-second window, so FIFO order
# is safe.
#
# Thread safety: _store_lock protects all mutations.  Temporal workers
# may execute activities from different workflows concurrently on
# separate threads.

_store_lock = threading.Lock()
_workflow_headers_store: Dict[str, Dict[str, bytes]] = {}
_pending_pop: Dict[str, Deque[bytes]] = {}
_pending_child_headers: Dict[str, Dict[str, bytes]] = {}
_pop_dedup_cache: Dict[str, float] = {}
_pop_dedup_last_evict: float = 0.0
_DEDUP_EVICT_INTERVAL: float = 60.0
_interceptor_config: Optional["TenuoInterceptorConfig"] = None
_workflow_config_store: Dict[str, "TenuoInterceptorConfig"] = {}


def _pop_key(wf_id: str, tool_name: str, args: Any) -> str:
    """Compute a deterministic key for PoP storage.

    The key uniquely identifies a (workflow, tool, arguments) triple so
    that parallel activity calls don't collide.
    """
    args_tuple = tuple(args) if isinstance(args, (list, tuple)) else (args,)
    args_str = ":".join(str(a) for a in args_tuple)
    h = hashlib.sha256(f"{tool_name}:{args_str}".encode()).hexdigest()
    return f"{wf_id}:{h}"


# =============================================================================
# Exceptions
# =============================================================================


class TenuoTemporalError(Exception):
    """Base exception for tenuo.temporal module."""


class TenuoContextError(TenuoTemporalError):
    """Raised when Tenuo context is missing or invalid."""


class LocalActivityError(TenuoTemporalError):
    """Raised when a protected activity is used as local activity."""

    error_code = "LOCAL_ACTIVITY_BLOCKED"

    def __init__(self, activity_name: str):
        self.activity_name = activity_name
        super().__init__(
            f"Activity '{activity_name}' cannot be used as local activity. "
            "Protected activities must be executed as regular activities for "
            "authorization enforcement. Mark with @unprotected to allow local execution."
        )


@dataclass
class PopVerificationError(TenuoTemporalError):
    """Raised when Proof-of-Possession verification fails.

    Attributes:
        reason: Why PoP verification failed
        activity_name: The activity that failed PoP
        error_code: Wire format error code
    """

    reason: str
    activity_name: str
    error_code: str = field(default="POP_VERIFICATION_FAILED", init=False)

    def __str__(self) -> str:
        return f"PoP verification failed for '{self.activity_name}': {self.reason}"


@dataclass
class ConstraintViolation(TenuoTemporalError):
    """Raised when an activity violates warrant constraints.

    Attributes:
        tool: The tool/activity that was denied
        arguments: The arguments that were checked
        constraint: The constraint that was violated
        warrant_id: The warrant that denied the action
        error_code: Wire format error code
    """

    tool: str
    arguments: Dict[str, Any]
    constraint: str
    warrant_id: str
    error_code: str = field(default="CONSTRAINT_VIOLATED", init=False)

    def __str__(self) -> str:
        return f"Activity '{self.tool}' denied: {self.constraint} (warrant: {self.warrant_id})"


@dataclass
class WarrantExpired(TenuoTemporalError):
    """Raised when the warrant has expired.

    Attributes:
        warrant_id: The expired warrant
        expired_at: When the warrant expired
        error_code: Wire format error code
    """

    warrant_id: str
    expired_at: datetime
    error_code: str = field(default="WARRANT_EXPIRED", init=False)

    def __str__(self) -> str:
        return f"Warrant '{self.warrant_id}' expired at {self.expired_at}"


@dataclass
class ChainValidationError(TenuoTemporalError):
    """Raised when warrant chain validation fails.

    Attributes:
        reason: Description of the validation failure
        depth: The depth at which validation failed
        error_code: Wire format error code
    """

    reason: str
    depth: int
    error_code: str = field(default="CHAIN_INVALID", init=False)

    def __str__(self) -> str:
        return f"Warrant chain invalid at depth {self.depth}: {self.reason}"


@dataclass
class KeyResolutionError(TenuoTemporalError):
    """Raised when a signing key cannot be resolved.

    Attributes:
        key_id: The key ID that could not be resolved
        error_code: Wire format error code
    """

    key_id: str
    error_code: str = field(default="KEY_NOT_FOUND", init=False)

    def __str__(self) -> str:
        return f"Cannot resolve key: {self.key_id}"


# =============================================================================
# Audit Event
# =============================================================================


@dataclass
class TemporalAuditEvent:
    """Audit event emitted for each authorization decision.

    Compatible with tenuo.audit.AuditEvent pattern.
    """

    # Temporal context
    workflow_id: str
    workflow_type: str
    workflow_run_id: str
    activity_name: str
    activity_id: str
    task_queue: str

    # Authorization decision
    decision: Literal["ALLOW", "DENY"]
    tool: str
    arguments: Dict[str, Any]

    # Warrant info
    warrant_id: str
    warrant_expires_at: Optional[datetime]
    warrant_capabilities: List[str]

    # Denial details (populated if denied)
    denial_reason: Optional[str] = None
    constraint_violated: Optional[str] = None

    # Metadata
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tenuo_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for structured logging."""
        return {
            "workflow_id": self.workflow_id,
            "workflow_type": self.workflow_type,
            "workflow_run_id": self.workflow_run_id,
            "activity_name": self.activity_name,
            "activity_id": self.activity_id,
            "task_queue": self.task_queue,
            "decision": self.decision,
            "tool": self.tool,
            "arguments": self.arguments,
            "warrant_id": self.warrant_id,
            "warrant_expires_at": (self.warrant_expires_at.isoformat() if self.warrant_expires_at else None),
            "warrant_capabilities": self.warrant_capabilities,
            "denial_reason": self.denial_reason,
            "constraint_violated": self.constraint_violated,
            "timestamp": self.timestamp.isoformat(),
            "tenuo_version": self.tenuo_version,
        }


# =============================================================================
# Observability: Metrics (Phase 4)
# =============================================================================


class TenuoMetrics:
    """Prometheus metrics for Tenuo-Temporal authorization.

    Collects metrics for monitoring authorization decisions:
    - activities_authorized: Counter of allowed activities
    - activities_denied: Counter of denied activities
    - authorization_latency_seconds: Histogram of auth check duration

    Args:
        prefix: Metric name prefix (default: "tenuo_temporal")

    Example:
        metrics = TenuoMetrics()
        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            metrics=metrics,
        )

        # Metrics available at /metrics:
        # tenuo_temporal_activities_authorized_total{tool="read_file"}
        # tenuo_temporal_activities_denied_total{tool="write_file",reason="expired"}
        # tenuo_temporal_authorization_latency_seconds_bucket{...}
    """

    def __init__(self, prefix: str = "tenuo_temporal") -> None:
        self._prefix = prefix
        self._authorized_count: Dict[str, int] = {}
        self._denied_count: Dict[str, int] = {}
        self._latencies: List[float] = []

        # Try to use prometheus_client if available
        self._prom_authorized: Optional[Any] = None
        self._prom_denied: Optional[Any] = None
        self._prom_latency: Optional[Any] = None

        try:
            from prometheus_client import Counter, Histogram  # type: ignore[import-not-found]

            self._prom_authorized = Counter(
                f"{prefix}_activities_authorized_total",
                "Total authorized activities",
                ["tool", "workflow_type"],
            )
            self._prom_denied = Counter(
                f"{prefix}_activities_denied_total",
                "Total denied activities",
                ["tool", "reason", "workflow_type"],
            )
            self._prom_latency = Histogram(
                f"{prefix}_authorization_latency_seconds",
                "Authorization check latency",
                ["tool"],
                buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            )
            logger.info(f"Prometheus metrics enabled with prefix: {prefix}")
        except ImportError:
            logger.debug("prometheus_client not available, using internal counters")

    def record_authorized(
        self,
        tool: str,
        workflow_type: str,
        latency_seconds: float,
    ) -> None:
        """Record an authorized activity."""
        key = f"{tool}:{workflow_type}"
        self._authorized_count[key] = self._authorized_count.get(key, 0) + 1
        self._latencies.append(latency_seconds)

        if self._prom_authorized:
            self._prom_authorized.labels(tool=tool, workflow_type=workflow_type).inc()
        if self._prom_latency:
            self._prom_latency.labels(tool=tool).observe(latency_seconds)

    def record_denied(
        self,
        tool: str,
        reason: str,
        workflow_type: str,
        latency_seconds: float,
    ) -> None:
        """Record a denied activity."""
        key = f"{tool}:{reason}:{workflow_type}"
        self._denied_count[key] = self._denied_count.get(key, 0) + 1
        self._latencies.append(latency_seconds)

        if self._prom_denied:
            self._prom_denied.labels(tool=tool, reason=reason, workflow_type=workflow_type).inc()
        if self._prom_latency:
            self._prom_latency.labels(tool=tool).observe(latency_seconds)

    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics as a dict (for testing/debugging)."""
        return {
            "authorized": dict(self._authorized_count),
            "denied": dict(self._denied_count),
            "latency_count": len(self._latencies),
            "latency_avg": (sum(self._latencies) / len(self._latencies) if self._latencies else 0.0),
        }


# =============================================================================
# Key Resolver
# =============================================================================


class KeyResolver(ABC):
    """Abstract interface for resolving key IDs to signing keys.

    Implementations should fetch keys from secure storage
    (Vault, KMS, HSM, etc.) and cache appropriately.
    """

    @abstractmethod
    async def resolve(self, key_id: str) -> Any:  # Returns SigningKey
        """Resolve a key ID to a signing key.

        Args:
            key_id: The key identifier

        Returns:
            The signing key (tenuo_core.SigningKey)

        Raises:
            KeyResolutionError: If key cannot be resolved
        """
        ...


class EnvKeyResolver(KeyResolver):
    """Resolves keys from environment variables.

    For development/testing only. Do not use in production.

    Expects: TENUO_KEY_{key_id}=<base64-encoded-key>

    Args:
        prefix: Environment variable prefix (default: "TENUO_KEY_")
    """

    def __init__(self, prefix: str = "TENUO_KEY_") -> None:
        self._prefix = prefix

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from environment variable."""
        import os

        env_name = f"{self._prefix}{key_id}"
        value = os.environ.get(env_name)

        if value is None:
            raise KeyResolutionError(key_id=key_id)

        try:
            from tenuo_core import SigningKey

            key_bytes = base64.b64decode(value)
            return SigningKey.from_bytes(key_bytes)
        except Exception as e:
            logger.error(f"Failed to decode key from {env_name}: {e}")
            raise KeyResolutionError(key_id=key_id)


class VaultKeyResolver(KeyResolver):
    """Resolve keys from HashiCorp Vault.

    Production-ready key resolver using Vault's KV secrets engine.

    Args:
        url: Vault server URL (e.g. "https://vault.example.com:8200")
        mount: Secrets engine mount path (default: "secret")
        path_template: Path template with {key_id} placeholder
            (default: "tenuo/keys/{key_id}")
        token: Vault token. If None, uses VAULT_TOKEN env var.
        cache_ttl: Cache TTL in seconds (default: 300)

    Example:
        resolver = VaultKeyResolver(
            url="https://vault.company.com:8200",
            path_template="production/tenuo/{key_id}",
        )
    """

    def __init__(
        self,
        url: str,
        mount: str = "secret",
        path_template: str = "tenuo/keys/{key_id}",
        token: Optional[str] = None,
        cache_ttl: int = 300,
    ) -> None:
        self._url = url.rstrip("/")
        self._mount = mount
        self._path_template = path_template
        self._token = token
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from Vault."""
        import os
        import time

        # Check cache
        now = time.time()
        if key_id in self._cache:
            cached_key, cached_at = self._cache[key_id]
            if now - cached_at < self._cache_ttl:
                logger.debug(f"Vault cache hit for key: {key_id}")
                return cached_key

        # Get token
        token = self._token or os.environ.get("VAULT_TOKEN")
        if not token:
            raise KeyResolutionError(key_id=key_id)

        # Build path
        path = self._path_template.format(key_id=key_id)

        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._url}/v1/{self._mount}/data/{path}",
                    headers={"X-Vault-Token": token},
                    timeout=10.0,
                )

                if resp.status_code == 404:
                    raise KeyResolutionError(key_id=key_id)

                resp.raise_for_status()
                data = resp.json()

                # Extract key from Vault response
                key_b64 = data["data"]["data"]["key"]
                from tenuo_core import SigningKey

                key_bytes = base64.b64decode(key_b64)
                key = SigningKey.from_bytes(key_bytes)

                # Cache
                self._cache[key_id] = (key, now)
                logger.debug(f"Vault resolved key: {key_id}")
                return key

        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(f"Vault key resolution failed: {e}")
            raise KeyResolutionError(key_id=key_id)


class AWSSecretsManagerKeyResolver(KeyResolver):
    """Resolve keys from AWS Secrets Manager.

    Secrets Manager handles both storage and encryption (via KMS under the hood).
    Store your signing key as a binary secret.

    Args:
        secret_prefix: Prefix for secret names (default: "tenuo/keys/")
            Full secret name will be: {secret_prefix}{key_id}
        region_name: AWS region (default: uses boto3 default)
        cache_ttl: Cache TTL in seconds (default: 300)

    Example:
        resolver = AWSSecretsManagerKeyResolver(
            secret_prefix="prod/tenuo/",
            region_name="us-west-2",
        )

        # Store key in AWS CLI:
        # aws secretsmanager create-secret --name prod/tenuo/my-key-id \\
        #     --secret-binary fileb://signing_key.bin
    """

    def __init__(
        self,
        secret_prefix: str = "tenuo/keys/",
        region_name: Optional[str] = None,
        cache_ttl: int = 300,
    ) -> None:
        self._secret_prefix = secret_prefix
        self._region_name = region_name
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from AWS Secrets Manager."""
        import time

        # Check cache
        now = time.time()
        if key_id in self._cache:
            cached_key, cached_at = self._cache[key_id]
            if now - cached_at < self._cache_ttl:
                logger.debug(f"AWS Secrets Manager cache hit for key: {key_id}")
                return cached_key

        secret_name = f"{self._secret_prefix}{key_id}"

        try:
            import boto3  # type: ignore[import-not-found, import-untyped]

            client = boto3.client("secretsmanager", region_name=self._region_name)
            response = client.get_secret_value(SecretId=secret_name)

            # Secret can be binary or string (base64)
            if "SecretBinary" in response:
                key_bytes = response["SecretBinary"]
            elif "SecretString" in response:
                key_bytes = base64.b64decode(response["SecretString"])
            else:
                raise KeyResolutionError(key_id=key_id)

            from tenuo_core import SigningKey

            signing_key = SigningKey.from_bytes(key_bytes)

            # Cache the result
            self._cache[key_id] = (signing_key, now)
            logger.debug(f"AWS Secrets Manager resolved key: {key_id}")
            return signing_key

        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            raise KeyResolutionError(key_id=key_id)
        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(f"AWS Secrets Manager key resolution failed: {e}")
            raise KeyResolutionError(key_id=key_id)


class GCPSecretManagerKeyResolver(KeyResolver):
    """Resolve keys from GCP Secret Manager.

    Secret Manager handles both storage and encryption (via Cloud KMS under the hood).
    Store your signing key as a binary secret.

    Args:
        project_id: GCP project ID
        secret_prefix: Prefix for secret names (default: "tenuo-keys-")
            Full secret name will be: {secret_prefix}{key_id}
        version: Secret version (default: "latest")
        cache_ttl: Cache TTL in seconds (default: 300)

    Example:
        resolver = GCPSecretManagerKeyResolver(
            project_id="my-project-123",
            secret_prefix="prod-tenuo-",
        )

        # Store key in gcloud CLI:
        # gcloud secrets create prod-tenuo-my-key-id --data-file=signing_key.bin
    """

    def __init__(
        self,
        project_id: str,
        secret_prefix: str = "tenuo-keys-",
        version: str = "latest",
        cache_ttl: int = 300,
    ) -> None:
        self._project_id = project_id
        self._secret_prefix = secret_prefix
        self._version = version
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from GCP Secret Manager."""
        import time

        # Check cache
        now = time.time()
        if key_id in self._cache:
            cached_key, cached_at = self._cache[key_id]
            if now - cached_at < self._cache_ttl:
                logger.debug(f"GCP Secret Manager cache hit for key: {key_id}")
                return cached_key

        secret_name = f"{self._secret_prefix}{key_id}"
        resource_name = f"projects/{self._project_id}/secrets/{secret_name}/versions/{self._version}"

        try:
            from google.cloud import secretmanager  # type: ignore[import-not-found,import-untyped]

            client = secretmanager.SecretManagerServiceClient()
            response = client.access_secret_version(name=resource_name)
            key_bytes = response.payload.data

            from tenuo_core import SigningKey

            signing_key = SigningKey.from_bytes(key_bytes)

            # Cache the result
            self._cache[key_id] = (signing_key, now)
            logger.debug(f"GCP Secret Manager resolved key: {key_id}")
            return signing_key

        except ImportError:
            logger.error(
                "google-cloud-secret-manager not installed. "
                "Install with: pip install google-cloud-secret-manager"
            )
            raise KeyResolutionError(key_id=key_id)
        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(f"GCP Secret Manager key resolution failed: {e}")
            raise KeyResolutionError(key_id=key_id)


class CompositeKeyResolver(KeyResolver):
    """Try multiple resolvers in order (fallback chain).

    Useful for graceful degradation:
    - Try Vault first (production)
    - Fall back to cloud secrets manager (backup)
    - Fall back to env vars (local dev)

    Args:
        resolvers: List of resolvers to try in order

    Example:
        resolver = CompositeKeyResolver([
            VaultKeyResolver(url="https://vault.prod.internal"),
            AWSSecretsManagerKeyResolver(secret_prefix="tenuo/"),
            EnvKeyResolver(),  # Fallback for local dev
        ])
    """

    def __init__(self, resolvers: List[KeyResolver]) -> None:
        if not resolvers:
            raise ValueError("CompositeKeyResolver requires at least one resolver")
        self._resolvers = resolvers

    async def resolve(self, key_id: str) -> Any:
        """Try each resolver in order until one succeeds."""
        errors: List[str] = []

        for i, resolver in enumerate(self._resolvers):
            try:
                key = await resolver.resolve(key_id)
                logger.debug(f"CompositeKeyResolver: resolved {key_id} via resolver {i} ({type(resolver).__name__})")
                return key
            except KeyResolutionError as e:
                errors.append(f"{type(resolver).__name__}: {e}")
                continue

        logger.error(f"CompositeKeyResolver: all resolvers failed for {key_id}: {errors}")
        raise KeyResolutionError(key_id=key_id)


# =============================================================================
# Interceptor Config
# =============================================================================


@dataclass
class TenuoInterceptorConfig:
    """Configuration for TenuoInterceptor."""

    key_resolver: KeyResolver
    """Required. Resolves key IDs to signing keys.

    Note: The key_resolver is used by ``tenuo_execute_activity()`` to
    reconstruct signing keys for PoP generation.  In the lightweight
    authorization path (``trusted_roots=None``), only constraint checks
    are performed and the key_resolver is not invoked.  Set
    ``trusted_roots`` to enable full Authorizer + PoP verification.
    """

    on_denial: Literal["raise", "log", "skip"] = "raise"
    """
    Behavior when authorization fails:
    - "raise": Raise ConstraintViolation (default)
    - "log": Log denial, continue execution
    - "skip": Silent denial, return None
    """

    tool_mappings: Dict[str, str] = field(default_factory=dict)
    """
    Optional explicit activity-to-tool mappings.
    Example: {"fetch_document": "read_file"}
    If not specified, activity name = tool name.
    """

    audit_callback: Optional[Callable[[TemporalAuditEvent], None]] = None
    """Optional callback for authorization audit events."""

    audit_allow: bool = True
    """Whether to emit audit events for allowed actions."""

    audit_deny: bool = True
    """Whether to emit audit events for denied actions."""

    max_chain_depth: int = 10
    """Maximum warrant chain depth to accept."""

    # Phase 2: Security hardening options
    block_local_activities: bool = True
    """
    Block protected activities from being used as local activities.
    Local activities bypass the worker interceptor, so protected
    activities must be marked @unprotected to run locally.
    """

    # Phase 4: Observability options
    metrics: Optional["TenuoMetrics"] = None
    """
    Optional metrics collector for Prometheus.
    Pass a TenuoMetrics instance to enable metrics.
    """

    enable_tracing: bool = False
    """
    Enable OpenTelemetry tracing spans for authorization.
    Requires opentelemetry-api to be installed.
    """

    # Security: Fail-closed options
    require_warrant: bool = True
    """
    Require a warrant for all activities (fail-closed).
    When True, activities without a warrant are denied.
    When False, activities without a warrant pass through (opt-in).
    Default: True (secure by default).
    """

    redact_args_in_logs: bool = True
    """
    Redact argument values in logs and audit events.
    When True, argument values are replaced with "[REDACTED]".
    Prevents leaking sensitive data like passwords, tokens, etc.
    Default: True (secure by default).
    """

    trusted_roots: Optional[List[Any]] = None
    """
    Trusted root public keys for warrant verification and PoP checking.
    When provided, the interceptor uses the Authorizer to verify warrants
    and PoP signatures cryptographically. When None, only constraint
    checks are performed (no chain-of-trust or PoP verification).

    For root warrants (created via ``Warrant.mint_builder().mint(key)``),
    pass ``[key.public_key]`` here.  The Authorizer verifies that the
    warrant's signing key is in this list, even for depth-0 (root)
    warrants.  For delegated warrants, include the original root's
    public key so the full chain can be validated.
    """

    authorized_signals: Optional[List[str]] = None
    """
    When set, only signals whose name is in this list are accepted.
    Unrecognized signals are denied and logged. When None (default),
    all signals pass through (backward compatible).
    """

    authorized_updates: Optional[List[str]] = None
    """
    When set, only workflow updates whose name is in this list are
    accepted.  Unrecognized updates are rejected at the validator
    stage.  When None (default), all updates pass through.
    """


# =============================================================================
# Client Interceptor — injects Tenuo headers into workflow start
# =============================================================================


class TenuoClientInterceptor:
    """Temporal client interceptor for injecting Tenuo warrant headers.

    This interceptor:
      1. Wraps raw header bytes as ``Payload`` protobufs for Temporal
      2. Stores the **raw** bytes in ``_workflow_headers_store`` (keyed by
         ``workflow_id``) so the activity interceptor can read them without
         going through Temporal's serialization pipeline.

    Usage::

        client_interceptor = TenuoClientInterceptor()
        client = await Client.connect("localhost:7233",
                                      interceptors=[client_interceptor])

        # Before starting a workflow, set the headers:
        client_interceptor.set_headers(tenuo_headers(warrant, key_id, key))

        await client.execute_workflow(MyWorkflow.run, ...)
    """

    def __init__(self) -> None:
        self._headers: Dict[str, bytes] = {}

    def set_headers(self, headers: Dict[str, bytes]) -> None:
        """Set Tenuo headers for the *next* workflow start."""
        self._headers = headers

    def clear_headers(self) -> None:
        """Clear headers (e.g. after a workflow is started)."""
        self._headers = {}

    # --- Temporal client interceptor interface ---

    def intercept_client(self, next_interceptor: Any) -> "_TenuoClientOutbound":
        return _TenuoClientOutbound(next_interceptor, self)


class _TenuoClientOutbound:
    """Outbound half of the client interceptor — wraps ``start_workflow``.

    Injects Tenuo headers as ``Payload`` objects into the Temporal
    ``StartWorkflow`` request.  The headers travel through the Temporal
    Server and are extracted on the worker by
    ``_TenuoWorkflowInboundInterceptor``.

    As a convenience for single-process setups (e.g. demos), we also
    write the raw bytes directly into ``_workflow_headers_store``.  In
    production (separate client and worker processes) this in-process
    write has no effect — the workflow interceptor's extraction from
    ``input.headers`` is the canonical path.
    """

    def __init__(self, next_interceptor: Any, parent: TenuoClientInterceptor) -> None:
        self._next = next_interceptor
        self._parent = parent

    def __getattr__(self, name: str) -> Any:
        return getattr(self._next, name)

    async def start_workflow(self, input: Any) -> Any:
        if self._parent._headers:
            try:
                from temporalio.api.common.v1 import Payload  # type: ignore
            except ImportError:
                raise TenuoContextError("temporalio not installed")

            workflow_id: str = getattr(input, "id", None) or ""
            raw_store: Dict[str, bytes] = {}

            for k, v in self._parent._headers.items():
                raw = v if isinstance(v, bytes) else str(v).encode("utf-8")
                input.headers = {**(input.headers or {}), k: Payload(data=raw)}
                if k.startswith("x-tenuo-"):
                    raw_store[k] = raw

            # Convenience write for single-process mode.  In production
            # the workflow interceptor populates the store from the
            # Temporal-delivered Payload headers (see above docstring).
            if workflow_id:
                with _store_lock:
                    _workflow_headers_store[workflow_id] = raw_store

        return await self._next.start_workflow(input)


# =============================================================================
# Header Utilities
# =============================================================================


def tenuo_headers(
    warrant: Any,  # Warrant type from tenuo_core
    key_id: str,
    signing_key: Any,  # SigningKey from tenuo_core
    *,
    compress: bool = True,
) -> Dict[str, bytes]:
    """Create headers dict for starting a workflow with Tenuo authorization.

    Args:
        warrant: The warrant authorizing this workflow
        key_id: Identifier for the holder's signing key
        signing_key: The holder's signing key (for Proof-of-Possession).
            Must have a `.to_bytes()` method returning 32 raw bytes.
        compress: Whether to gzip compress the warrant (default: True)

    Returns:
        Headers dict to pass to client.start_workflow()

    Example:
        await client.start_workflow(
            MyWorkflow.run,
            args=[...],
            headers=tenuo_headers(warrant, "agent-key-1", signing_key),
        )
    """
    # Serialize warrant to base64
    warrant_b64 = warrant.to_base64()
    warrant_bytes = warrant_b64.encode("utf-8")

    # Encode signing key as base64 for header transport
    if hasattr(signing_key, "secret_key_bytes"):
        signing_key_bytes = signing_key.secret_key_bytes()
    elif hasattr(signing_key, "to_bytes"):
        signing_key_bytes = signing_key.to_bytes()
    else:
        signing_key_bytes = bytes(signing_key)
    signing_key_b64 = base64.b64encode(signing_key_bytes)

    headers: Dict[str, bytes] = {
        TENUO_KEY_ID_HEADER: key_id.encode("utf-8"),
        TENUO_SIGNING_KEY_HEADER: signing_key_b64,
    }

    if compress:
        compressed = gzip.compress(warrant_bytes, compresslevel=9)
        headers[TENUO_WARRANT_HEADER] = base64.b64encode(compressed)
        headers[TENUO_COMPRESSED_HEADER] = b"1"
    else:
        headers[TENUO_WARRANT_HEADER] = warrant_bytes
        headers[TENUO_COMPRESSED_HEADER] = b"0"

    return headers


async def tenuo_execute_activity(
    activity: Any,
    *,
    args: Optional[List[Any]] = None,
    start_to_close_timeout: Any = None,
    schedule_to_close_timeout: Any = None,
    schedule_to_start_timeout: Any = None,
    heartbeat_timeout: Any = None,
    retry_policy: Any = None,
    task_queue: Optional[str] = None,
    cancellation_type: Any = None,
) -> Any:
    """Execute an activity with automatic Proof-of-Possession signing.

    This is the primary way to call activities in Tenuo-protected workflows.
    It reconstructs the warrant and signing key from workflow headers,
    computes a PoP signature using ``warrant.sign()``, and forwards all
    Tenuo headers plus the PoP signature to the activity interceptor.

    Args:
        activity: The activity function to execute
        args: Arguments to pass to the activity
        start_to_close_timeout: Timeout for activity execution
        schedule_to_close_timeout: Timeout from schedule to completion
        schedule_to_start_timeout: Timeout from schedule to start
        heartbeat_timeout: Heartbeat timeout for long-running activities
        retry_policy: Retry policy for the activity
        task_queue: Optional task queue override
        cancellation_type: Cancellation behavior

    Returns:
        The activity's return value

    Example:
        @workflow.defn
        class MyWorkflow:
            @workflow.run
            async def run(self) -> str:
                return await tenuo_execute_activity(
                    read_file,
                    args=["/data/report.txt"],
                    start_to_close_timeout=timedelta(seconds=30),
                )

    Raises:
        TenuoContextError: If called outside a workflow or missing signing key
    """
    import inspect

    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    from tenuo_core import SigningKey  # type: ignore[import-not-found]

    info = workflow.info()
    wf_id = info.workflow_id

    # --- Read Tenuo headers from module-level store ---
    # The _TenuoWorkflowInboundInterceptor populates this when the
    # workflow starts. Using the store avoids the fact that
    # workflow.execute_activity() does not accept a headers kwarg.
    with _store_lock:
        raw_headers = _workflow_headers_store.get(wf_id, {})
    if not raw_headers:
        raise TenuoContextError(
            "No Tenuo headers in store. Ensure TenuoInterceptor is "
            "registered and tenuo_headers() was passed at workflow start."
        )

    # --- Reconstruct warrant from headers ---
    warrant = _extract_warrant_from_headers(raw_headers)
    if warrant is None:
        raise TenuoContextError("No warrant found in workflow headers.")

    # --- Reconstruct signing key from headers ---
    sk_b64 = raw_headers.get(TENUO_SIGNING_KEY_HEADER)
    if sk_b64 is None:
        raise TenuoContextError(
            "No signing key found in workflow headers. "
            "Pass signing_key to tenuo_headers() when starting the workflow."
        )
    try:
        signing_key_raw = base64.b64decode(sk_b64)
        signer = SigningKey.from_bytes(signing_key_raw)
    except Exception as e:
        raise TenuoContextError(f"Invalid signing key in headers: {e}")

    # --- Resolve tool name and build args dict for PoP ---
    tool_name = get_tool_name(activity, getattr(activity, "__name__", str(activity)))
    args_dict: Dict[str, Any] = {}
    if args:
        try:
            sig = inspect.signature(activity)
            params = list(sig.parameters.keys())
            for i, arg in enumerate(args):
                if i < len(params):
                    args_dict[params[i]] = arg
                else:
                    args_dict[f"arg{i}"] = arg
        except (ValueError, TypeError):
            for i, arg in enumerate(args):
                args_dict[f"arg{i}"] = arg

    # --- Compute PoP signature using warrant.sign() ---
    pop_signature = warrant.sign(signer, tool_name, args_dict)

    # Store PoP in a per-(workflow, tool, args) FIFO queue so that
    # parallel activities (asyncio.gather) don't overwrite each other.
    pop_encoded = base64.b64encode(bytes(pop_signature))
    key = _pop_key(wf_id, tool_name, args or [])
    with _store_lock:
        _pending_pop.setdefault(key, deque()).append(pop_encoded)

    # --- Build activity kwargs ---
    activity_kwargs: Dict[str, Any] = {}
    if args is not None:
        activity_kwargs["args"] = args
    if start_to_close_timeout is not None:
        activity_kwargs["start_to_close_timeout"] = start_to_close_timeout
    if schedule_to_close_timeout is not None:
        activity_kwargs["schedule_to_close_timeout"] = schedule_to_close_timeout
    if schedule_to_start_timeout is not None:
        activity_kwargs["schedule_to_start_timeout"] = schedule_to_start_timeout
    if heartbeat_timeout is not None:
        activity_kwargs["heartbeat_timeout"] = heartbeat_timeout
    if retry_policy is not None:
        activity_kwargs["retry_policy"] = retry_policy
    if task_queue is not None:
        activity_kwargs["task_queue"] = task_queue
    if cancellation_type is not None:
        activity_kwargs["cancellation_type"] = cancellation_type

    return await workflow.execute_activity(activity, **activity_kwargs)


def attenuated_headers(
    *,
    tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Any]] = None,
    ttl_seconds: Optional[int] = None,
    child_key_id: Optional[str] = None,
    compress: bool = True,
) -> Dict[str, bytes]:
    """Create headers for a child workflow with attenuated scope.

    Must be called from within a workflow context. Creates a new warrant
    with reduced capabilities from the parent warrant.

    Args:
        tools: Tools to allow (subset of parent). None = inherit all.
        constraints: Per-tool constraint overrides, e.g.
            ``{"read_file": {"path": Pattern("/safe/*")}}``.
            Merged on top of the parent's constraints (must be narrower).
        ttl_seconds: Max TTL for child warrant. None = inherit parent.
        child_key_id: Key ID for child. None = inherit parent.
        compress: Whether to gzip compress (default: True).

    Returns:
        Headers dict with attenuated warrant

    NOTE: Temporal's ``execute_child_workflow()`` does not accept a
    ``headers`` kwarg directly.  Use ``tenuo_execute_child_workflow()``
    instead — it calls ``attenuated_headers()`` internally and injects
    the attenuated warrant via the outbound workflow interceptor.

    Raises:
        TenuoContextError: If no parent warrant in context
        ConstraintViolation: If requested tools exceed parent scope
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    # Get parent warrant from workflow context
    parent_warrant = current_warrant()
    parent_key_id = current_key_id()

    # Validate tools are subset of parent
    parent_tools = set(parent_warrant.tools or [])
    if tools is not None:
        requested_tools = set(tools)
        if not requested_tools.issubset(parent_tools):
            excess = requested_tools - parent_tools
            raise ConstraintViolation(
                tool=str(list(excess)[0]),
                arguments={},
                constraint=f"Cannot delegate tools not in parent: {excess}",
                warrant_id=parent_warrant.id,
            )
    else:
        tools = list(parent_tools)

    # Get workflow ID to retrieve headers from store
    try:
        from temporalio import workflow as _wf  # type: ignore[import-not-found]
        info = _wf.info()
        wf_id = info.workflow_id
    except ImportError:
        raise TenuoContextError("temporalio not available")

    # Retrieve signing key from workflow headers store
    # (Same pattern as tenuo_execute_activity)
    with _store_lock:
        raw_headers = _workflow_headers_store.get(wf_id, {})
    if not raw_headers:
        raise TenuoContextError(
            "No Tenuo headers in store. Ensure TenuoInterceptor is "
            "registered and tenuo_headers() was passed at workflow start."
        )

    sk_b64 = raw_headers.get(TENUO_SIGNING_KEY_HEADER)
    if sk_b64 is None:
        raise TenuoContextError(
            "No signing key found in parent workflow headers. "
            "Cannot propagate PoP to child workflow."
        )
    from tenuo_core import SigningKey  # type: ignore[import-not-found]

    try:
        signing_key_raw = base64.b64decode(sk_b64)
        signer = SigningKey.from_bytes(signing_key_raw)
    except Exception as e:
        raise TenuoContextError(f"Failed to decode signing key: {e}")

    # Build capabilities dict: start from parent's per-tool constraints,
    # then overlay any caller-supplied narrowing constraints.
    parent_caps = parent_warrant.capabilities or {}
    extra = constraints or {}
    capabilities = {}
    for tool in tools:
        base = dict(parent_caps.get(tool, {}))
        # Monotonic narrowing is enforced by attenuate(), not by this merge.
        # The Rust core rejects any capability that widens the parent scope.
        base.update(extra.get(tool, {}))
        capabilities[tool] = base

    child_warrant = parent_warrant.attenuate(
        capabilities=capabilities,
        signing_key=signer,
        ttl_seconds=ttl_seconds,
    )

    # Use parent key_id if not specified
    key_id = child_key_id or parent_key_id

    hdrs = tenuo_headers(child_warrant, key_id, signing_key_raw, compress=compress)

    # Propagate the delegation chain so the activity interceptor
    # can call check_chain() for full trust-root verification.
    existing_chain_b64 = raw_headers.get(TENUO_CHAIN_HEADER)
    if existing_chain_b64:
        parent_chain = json.loads(base64.b64decode(existing_chain_b64))
    else:
        parent_chain = [parent_warrant.to_base64()]
    parent_chain.append(child_warrant.to_base64())
    hdrs[TENUO_CHAIN_HEADER] = base64.b64encode(
        json.dumps(parent_chain).encode()
    )

    return hdrs


async def tenuo_execute_child_workflow(
    workflow_fn: Any,
    *,
    args: Optional[List[Any]] = None,
    id: Optional[str] = None,
    tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Any]] = None,
    ttl_seconds: Optional[int] = None,
    child_key_id: Optional[str] = None,
    task_queue: Optional[str] = None,
    execution_timeout: Any = None,
    run_timeout: Any = None,
    task_timeout: Any = None,
    cancellation_type: Any = None,
    parent_close_policy: Any = None,
    retry_policy: Any = None,
    id_reuse_policy: Any = None,
    cron_schedule: str = "",
    memo: Any = None,
    search_attributes: Any = None,
) -> Any:
    """Execute a child workflow with an attenuated Tenuo warrant.

    Creates a narrowed warrant via ``attenuated_headers()`` and injects it
    into the child workflow through the outbound interceptor.

    Args:
        workflow_fn: The child workflow function/class to execute.
        args: Arguments to pass to the child workflow.
        id: Workflow ID for the child. Auto-generated if not provided.
        tools: Tools to allow (subset of parent). None = inherit all.
        constraints: Per-tool constraint overrides (must narrow parent).
        ttl_seconds: Max TTL for child warrant.
        child_key_id: Key ID for child. None = inherit parent.
        task_queue: Task queue override.
        execution_timeout: Workflow execution timeout.
        run_timeout: Single workflow run timeout.
        task_timeout: Workflow task timeout.
        cancellation_type: Child workflow cancellation type.
        parent_close_policy: What happens to child when parent closes.
        retry_policy: Retry policy for the child workflow.
        id_reuse_policy: Workflow ID reuse policy.
        cron_schedule: Cron schedule string.
        memo: Memo fields.
        search_attributes: Search attributes.

    Returns:
        The child workflow's return value.

    Example::

        data = await tenuo_execute_child_workflow(
            ReaderChild.run,
            args=[source_dir],
            id=f"reader-{workflow.info().workflow_id}",
            tools=["read_file", "list_directory"],
            ttl_seconds=60,
        )
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    hdrs = attenuated_headers(
        tools=tools,
        constraints=constraints,
        ttl_seconds=ttl_seconds,
        child_key_id=child_key_id,
    )

    child_id = id or f"{workflow.info().workflow_id}-child-{workflow.uuid4()}"

    with _store_lock:
        _pending_child_headers[child_id] = hdrs

    kwargs: Dict[str, Any] = {"id": child_id}
    if args is not None:
        kwargs["args"] = args
    if task_queue is not None:
        kwargs["task_queue"] = task_queue
    if execution_timeout is not None:
        kwargs["execution_timeout"] = execution_timeout
    if run_timeout is not None:
        kwargs["run_timeout"] = run_timeout
    if task_timeout is not None:
        kwargs["task_timeout"] = task_timeout
    if cancellation_type is not None:
        kwargs["cancellation_type"] = cancellation_type
    if parent_close_policy is not None:
        kwargs["parent_close_policy"] = parent_close_policy
    if retry_policy is not None:
        kwargs["retry_policy"] = retry_policy
    if id_reuse_policy is not None:
        kwargs["id_reuse_policy"] = id_reuse_policy
    if cron_schedule:
        kwargs["cron_schedule"] = cron_schedule
    if memo is not None:
        kwargs["memo"] = memo
    if search_attributes is not None:
        kwargs["search_attributes"] = search_attributes

    return await workflow.execute_child_workflow(workflow_fn, **kwargs)


def workflow_grant(
    tool: str,
    constraints: Optional[Dict[str, Any]] = None,
    *,
    ttl_seconds: int = 300,
) -> Any:
    """Issue a scoped warrant for a single tool within a workflow.

    Uses workflow.now() for deterministic timestamp, ensuring
    replay safety. The grant is scoped to one tool with constraints.

    Args:
        tool: The tool to authorize
        constraints: Per-tool constraint overrides, e.g.
            ``{"path_prefix": "/data/"}``. Merged on top of the
            parent's constraints for this tool (must be narrower).
        ttl_seconds: Time-to-live in seconds (default: 5 minutes)

    Returns:
        A new Warrant scoped to the specified tool

    Example:
        # Within a workflow — issue a scoped grant for a single tool
        file_warrant = workflow_grant(
            "read_file",
            constraints={"path_prefix": "/data/"},
            ttl_seconds=60,
        )

        # Activities are authorized via the interceptor automatically;
        # use tenuo_execute_activity() to add PoP signing:
        await tenuo_execute_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )

    Raises:
        TenuoContextError: If called outside workflow context
        ConstraintViolation: If tool not in parent warrant
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    parent_warrant = current_warrant()

    parent_tools = parent_warrant.tools or []
    if tool not in parent_tools:
        raise ConstraintViolation(
            tool=tool,
            arguments={},
            constraint=f"Tool '{tool}' not in parent warrant capabilities",
            warrant_id=parent_warrant.id,
        )

    wf_id = workflow.info().workflow_id
    with _store_lock:
        raw_headers = _workflow_headers_store.get(wf_id, {})
    if not raw_headers:
        raise TenuoContextError(
            "No Tenuo headers in store. Ensure TenuoInterceptor is "
            "registered and tenuo_headers() was passed at workflow start."
        )

    sk_b64 = raw_headers.get(TENUO_SIGNING_KEY_HEADER)
    if sk_b64 is None:
        raise TenuoContextError(
            "No signing key found in workflow headers. "
            "Cannot issue attenuated grant."
        )
    from tenuo_core import SigningKey  # type: ignore[import-not-found]

    try:
        signer = SigningKey.from_bytes(base64.b64decode(sk_b64))
    except Exception as e:
        raise TenuoContextError(f"Failed to decode signing key: {e}")

    parent_caps = parent_warrant.capabilities or {}
    base = dict(parent_caps.get(tool, {}))
    if constraints:
        base.update(constraints)
    capabilities = {tool: base}

    return parent_warrant.attenuate(
        capabilities=capabilities,
        signing_key=signer,
        ttl_seconds=ttl_seconds,
    )


def _extract_warrant_from_headers(headers: Dict[str, bytes]) -> Any:
    """Extract and deserialize warrant from headers.

    Returns:
        Warrant object, or None if no warrant header present.

    Raises:
        ChainValidationError: If warrant cannot be deserialized
    """
    from tenuo_core import Warrant

    raw = headers.get(TENUO_WARRANT_HEADER)
    if raw is None:
        return None

    try:
        # Check if compressed
        is_compressed = headers.get(TENUO_COMPRESSED_HEADER, b"0") == b"1"

        if is_compressed:
            # Decode base64 then decompress
            compressed = base64.b64decode(raw)
            warrant_bytes = gzip.decompress(compressed)
        else:
            warrant_bytes = raw

        # Parse base64-encoded warrant
        warrant_b64 = warrant_bytes.decode("utf-8")
        return Warrant.from_base64(warrant_b64)

    except Exception as e:
        raise ChainValidationError(
            reason=f"Failed to deserialize warrant: {e}",
            depth=0,
        )


def _extract_key_id_from_headers(headers: Dict[str, bytes]) -> Optional[str]:
    """Extract key ID from headers."""
    raw = headers.get(TENUO_KEY_ID_HEADER)
    if raw is None:
        return None
    return raw.decode("utf-8")


# =============================================================================
# Context Accessors (for use within workflows)
# =============================================================================


def _unwrap_payload_headers(headers: Any) -> Dict[str, bytes]:
    """Convert a Temporal header mapping to plain ``Dict[str, bytes]``.

    ``workflow.info().headers`` is ``Mapping[str, Payload]`` where each
    ``Payload`` has a ``.data`` attribute containing the raw bytes.
    ``_workflow_headers_store`` values are already ``Dict[str, bytes]``.

    This helper normalises both representations so callers don't need
    to care which one they received.
    """
    out: Dict[str, bytes] = {}
    for k, v in (headers or {}).items():
        if isinstance(v, bytes):
            out[k] = v
        elif hasattr(v, "data") and isinstance(getattr(v, "data", None), bytes):
            out[k] = v.data
        else:
            # Last resort: coerce to bytes
            out[k] = bytes(v) if v is not None else b""
    return out


def current_warrant() -> Any:
    """Get the warrant from the current workflow context.

    Must be called from within a workflow.

    Returns:
        The warrant attached to this workflow

    Raises:
        TenuoContextError: If no warrant in context
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]

        info = workflow.info()
        raw_headers = _unwrap_payload_headers(getattr(info, "headers", {}))

        warrant = _extract_warrant_from_headers(raw_headers)
        if warrant is None:
            raise TenuoContextError("No Tenuo warrant in workflow context")

        return warrant

    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")


def current_key_id() -> str:
    """Get the key ID from the current workflow context.

    Must be called from within a workflow.

    Returns:
        The key ID for this workflow's holder

    Raises:
        TenuoContextError: If no key ID in context
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]

        info = workflow.info()
        raw_headers = _unwrap_payload_headers(getattr(info, "headers", {}))

        key_id = _extract_key_id_from_headers(raw_headers)
        if key_id is None:
            raise TenuoContextError("No Tenuo key ID in workflow context")

        return key_id

    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")


# =============================================================================
# AuthorizedWorkflow Base Class (Phase 3)
# =============================================================================


class AuthorizedWorkflow:
    """Base class for Tenuo-authorized workflows.

    Provides convenient authorized activity execution with fail-fast
    warrant validation. The workflow's warrant is validated at initialization
    and automatically applied to all activity executions.

    ⚠️ Important: You must use @workflow.defn on your subclass!
        Temporal Python SDK uses decorators, not inheritance, to define workflows.

    Single Warrant Limitation:
        This class assumes all activities execute under the SAME warrant.
        For multi-warrant workflows (delegation chains), use
        tenuo_execute_activity() directly.

    Example:
        from temporalio import workflow
        from tenuo.temporal import AuthorizedWorkflow, tenuo_headers

        @workflow.defn  # ← Required decorator!
        class MyWorkflow(AuthorizedWorkflow):
            @workflow.run
            async def run(self, name: str) -> str:
                return await self.execute_authorized_activity(
                    my_activity,
                    args=[name],
                    start_to_close_timeout=timedelta(seconds=30),
                )

    Starting the workflow:
        await client.execute_workflow(
            MyWorkflow.run,
            "input",
            id="workflow-id",
            task_queue="my-queue",
            headers=tenuo_headers(warrant, "agent-key-1", signing_key),
        )

    Raises:
        TenuoContextError: If workflow is started without Tenuo headers
    """

    def __init__(self) -> None:
        """Validate Tenuo authorization at workflow start.

        This performs fail-fast validation. The warrant is not stored -
        it will be fetched deterministically from headers during each
        activity execution.

        Raises a **non-retryable** ``ApplicationError`` so that Temporal
        fails the workflow immediately instead of retrying forever.
        """
        try:
            # Fail-fast validation only - don't store
            # Warrant will be fetched deterministically during activity calls
            current_warrant()
            current_key_id()
        except TenuoContextError as e:
            try:
                from temporalio.exceptions import ApplicationError  # type: ignore[import-not-found]
            except ImportError:
                raise e
            raise ApplicationError(
                f"AuthorizedWorkflow requires Tenuo headers: {e}",
                type="TenuoContextError",
                non_retryable=True,
            ) from e

    async def execute_authorized_activity(self, activity: Any, **kwargs: Any) -> Any:
        """Execute activity with automatic Tenuo authorization.

        Convenience wrapper around tenuo_execute_activity() that automatically
        uses the workflow's warrant validated at initialization.

        Args:
            activity: The activity function to execute
            **kwargs: Activity execution options (args, start_to_close_timeout, etc.)

        Returns:
            The activity result

        Raises:
            ConstraintViolation: If activity violates warrant constraints
            WarrantExpired: If warrant has expired
            ChainValidationError: If warrant chain is invalid
        """
        return await tenuo_execute_activity(activity, **kwargs)


# =============================================================================
# @unprotected Decorator (Phase 2)
# =============================================================================


def unprotected(func: F) -> F:
    """Mark an activity as unprotected - safe for local execution.

    Protected activities (default) require Tenuo authorization and
    cannot be used as local activities because local activities bypass
    worker interceptors.

    Use this decorator when:
    - The activity only accesses internal/trusted resources
    - The activity doesn't need per-invocation authorization
    - You want to run the activity as a local activity

    Example:
        @activity.defn
        @unprotected
        async def get_config_value(key: str) -> str:
            '''Internal config lookup - no Tenuo needed.'''
            return config[key]

        # Can now be called as local activity:
        await workflow.execute_local_activity(
            get_config_value,
            args=["database_url"],
            ...
        )
    """
    func._tenuo_unprotected = True  # type: ignore
    return func


def is_unprotected(func: Any) -> bool:
    """Check if an activity is marked as unprotected."""
    return getattr(func, "_tenuo_unprotected", False)


# =============================================================================
# @tool() Decorator (Phase 3)
# =============================================================================


def tool(name: str) -> Callable[[F], F]:
    """Map an activity to a specific Tenuo tool name.

    By default, activities are authorized using their function name
    as the tool name. Use this decorator when the activity name
    differs from the warrant tool name.

    Args:
        name: The tool name in the warrant (e.g., "read_file")

    Example:
        @activity.defn
        @tool("read_file")
        async def fetch_document(doc_id: str) -> str:
            '''Fetches document - authorized via 'read_file' capability.'''
            return await storage.get(doc_id)

        # Warrant needs: capability("read_file", {...})
        # Activity is called: fetch_document(doc_id)
    """

    def decorator(func: F) -> F:
        func._tenuo_tool_name = name  # type: ignore
        return func

    return decorator


def get_tool_name(func: Any, default: str) -> str:
    """Get the Tenuo tool name for an activity.

    Returns the @tool() name if set, otherwise the default.
    """
    return getattr(func, "_tenuo_tool_name", default)


# =============================================================================
# PoP Utilities (Phase 2)
# =============================================================================


def _compute_pop_challenge(
    workflow_id: str,
    activity_id: str,
    tool_name: str,
    args: Dict[str, Any],
    scheduled_time: datetime,
) -> bytes:
    """Compute the PoP challenge bytes for an activity.

    The challenge is a SHA-256 hash of:
    - workflow_id
    - activity_id
    - tool_name
    - canonical JSON of arguments
    - scheduled_time (ISO format)

    This ensures the challenge is deterministic and replay-safe.
    """
    # Canonical JSON: sorted keys, no whitespace
    args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))

    message = f"{workflow_id}|{activity_id}|{tool_name}|{args_json}|{scheduled_time.isoformat()}"

    return hashlib.sha256(message.encode()).digest()


# =============================================================================
# Interceptor
# =============================================================================


class _TenuoWorkflowOutboundInterceptor:
    """Outbound workflow interceptor — injects Tenuo headers into activity scheduling.

    When ``start_activity()`` is called (from ``tenuo_execute_activity()``
    or ``AuthorizedWorkflow.execute_authorized_activity()``), this
    interceptor reads the workflow's Tenuo headers from
    ``_workflow_headers_store`` and the pending PoP signature from
    ``_pending_pop``, wraps them as ``Payload`` objects, and injects
    them into ``StartActivityInput.headers``.

    This ensures the activity interceptor on **any** worker — even a
    different process or machine — receives the warrant and PoP via
    Temporal's standard header propagation, rather than relying on
    in-process shared memory.
    """

    def __init__(self, next_outbound: Any) -> None:
        self._next = next_outbound

    def __getattr__(self, name: str) -> Any:
        return getattr(self._next, name)

    def start_activity(self, input: Any) -> Any:
        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        try:
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.start_activity(input)

        wf_id = _wf.info().workflow_id
        tool_name = input.activity

        # Read Tenuo headers from the store (populated by inbound interceptor)
        with _store_lock:
            raw_headers = dict(_workflow_headers_store.get(wf_id, {}))

        if raw_headers:
            # Pop the PoP signature for this specific activity call
            raw_args = getattr(input, "args", ())
            key = _pop_key(wf_id, tool_name, raw_args)
            with _store_lock:
                q = _pending_pop.get(key)
                pop = q.popleft() if q else None
                if q is not None and not q:
                    del _pending_pop[key]

            # Build Payload headers for the activity
            activity_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                activity_headers[k] = Payload(data=v)
            if pop is not None:
                activity_headers[TENUO_POP_HEADER] = Payload(data=pop)

            input = _replace_field(input, "headers", activity_headers)

        return self._next.start_activity(input)

    def start_child_workflow(self, input: Any) -> Any:
        """Inject attenuated Tenuo headers into child workflow starts."""
        try:
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.start_child_workflow(input)

        child_id = input.id
        with _store_lock:
            raw_headers = _pending_child_headers.pop(child_id, None)

        if raw_headers:
            child_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                child_headers[k] = Payload(data=v)
            input = _replace_field(input, "headers", child_headers)

        return self._next.start_child_workflow(input)

    def continue_as_new(self, input: Any) -> None:
        """Re-inject Tenuo headers so the next run keeps its warrant."""
        try:
            from temporalio import workflow as _wf  # type: ignore[import-not-found]
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.continue_as_new(input)

        wf_id = _wf.info().workflow_id
        with _store_lock:
            raw_headers = _workflow_headers_store.get(wf_id, {})

        if raw_headers:
            can_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                can_headers[k] = Payload(data=v)
            input = _replace_field(input, "headers", can_headers)

        return self._next.continue_as_new(input)

    def start_nexus_operation(self, input: Any) -> Any:
        """Propagate Tenuo headers into Nexus cross-namespace operations."""
        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        wf_id = _wf.info().workflow_id
        with _store_lock:
            raw_headers = _workflow_headers_store.get(wf_id, {})

        if raw_headers:
            nexus_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                nexus_headers[k] = base64.b64encode(v).decode()
            input = _replace_field(input, "headers", nexus_headers)

        return self._next.start_nexus_operation(input)

    def start_local_activity(self, input: Any) -> Any:
        return self._next.start_local_activity(input)


def _replace_field(obj: Any, field: str, value: Any) -> Any:
    """Create a copy of a dataclass with one field replaced.

    Falls back to setattr for non-dataclass objects.
    """
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.replace(obj, **{field: value})
    # Fallback: mutate in place (some Temporal versions use mutable objects)
    setattr(obj, field, value)
    return obj


class _TenuoWorkflowInboundInterceptor:
    """Workflow interceptor — extracts Tenuo headers and cleans up on completion.

    **Inbound** half: extracts ``x-tenuo-*`` headers from the Temporal
    ``Payload`` mapping delivered by the server and writes them into
    ``_workflow_headers_store`` for ``tenuo_execute_activity()`` to read.

    **Outbound** half (via ``init()``): wraps the next outbound
    interceptor with ``_TenuoWorkflowOutboundInterceptor``, which
    injects Tenuo headers + PoP into ``StartActivityInput.headers``
    so that activities on **any** worker receive authorization data
    through Temporal's standard header propagation.
    """

    _config: Optional["TenuoInterceptorConfig"] = None

    def __init__(self, next_interceptor: Any) -> None:
        self.next = next_interceptor

    def init(self, outbound: Any) -> None:
        # Wrap the outbound interceptor so activity scheduling carries
        # Tenuo headers through Temporal's header propagation.
        self.next.init(_TenuoWorkflowOutboundInterceptor(outbound))

    async def execute_workflow(self, input: Any) -> Any:
        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        wf_id = _wf.info().workflow_id

        # --- Extract Tenuo headers from the Temporal Payload map ---
        # input.headers is Mapping[str, Payload] propagated by the
        # Temporal Server from the client's StartWorkflow request.
        incoming: Dict[str, bytes] = {}
        for key, payload in (getattr(input, "headers", None) or {}).items():
            if key.startswith("x-tenuo-"):
                data = getattr(payload, "data", None)
                if data is not None:
                    incoming[key] = data

        if incoming:
            with _store_lock:
                _workflow_headers_store[wf_id] = incoming

        if self._config is not None:
            with _store_lock:
                _workflow_config_store[wf_id] = self._config

        try:
            return await self.next.execute_workflow(input)
        finally:
            with _store_lock:
                _workflow_headers_store.pop(wf_id, None)
                _workflow_config_store.pop(wf_id, None)
                stale = [k for k in _pending_pop if k.startswith(f"{wf_id}:")]
                for k in stale:
                    del _pending_pop[k]

    def _resolve_config(self) -> Optional["TenuoInterceptorConfig"]:
        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        wf_id = _wf.info().workflow_id
        with _store_lock:
            cfg = _workflow_config_store.get(wf_id)
        return cfg or _interceptor_config

    async def handle_signal(self, input: Any) -> None:
        config = self._resolve_config()
        if config and config.authorized_signals is not None:
            signal_name = getattr(input, "signal", None)
            if signal_name not in config.authorized_signals:
                logger.warning(
                    f"Signal '{signal_name}' denied: not in authorized_signals"
                )
                raise ConstraintViolation(
                    tool=f"signal:{signal_name}",
                    arguments={},
                    constraint=f"Signal not authorized: {signal_name}",
                    warrant_id="workflow",
                )
        return await self.next.handle_signal(input)

    async def handle_query(self, input: Any) -> Any:
        return await self.next.handle_query(input)

    def handle_update_validator(self, input: Any) -> None:
        config = self._resolve_config()
        if config and config.authorized_updates is not None:
            update_name = getattr(input, "update", None)
            if update_name not in config.authorized_updates:
                logger.warning(
                    f"Update '{update_name}' rejected at validation: "
                    "not in authorized_updates"
                )
                raise ConstraintViolation(
                    tool=f"update:{update_name}",
                    arguments={},
                    constraint=f"Update not authorized: {update_name}",
                    warrant_id="workflow",
                )
        return self.next.handle_update_validator(input)

    async def handle_update_handler(self, input: Any) -> Any:
        config = self._resolve_config()
        if config and config.authorized_updates is not None:
            update_name = getattr(input, "update", None)
            if update_name not in config.authorized_updates:
                raise ConstraintViolation(
                    tool=f"update:{update_name}",
                    arguments={},
                    constraint=f"Update not authorized: {update_name}",
                    warrant_id="workflow",
                )
        return await self.next.handle_update_handler(input)


class TenuoInterceptor:
    """Temporal interceptor that enforces Tenuo warrant authorization.

    Intercepts activity execution and verifies the calling workflow
    has a valid warrant authorizing the activity.

    Important: The worker **must** configure ``tenuo`` and ``tenuo_core``
    as passthrough modules in the workflow sandbox.  Without this, PoP
    verification will fail.  See the module docstring for details.

    Example::

        from temporalio.worker.workflow_sandbox import (
            SandboxedWorkflowRunner, SandboxRestrictions,
        )

        interceptor = TenuoInterceptor(
            TenuoInterceptorConfig(
                key_resolver=EnvKeyResolver(),
                on_denial="raise",
                trusted_roots=[control_key.public_key],
            )
        )

        worker = Worker(
            client,
            task_queue="my-queue",
            workflows=[MyWorkflow],
            activities=[read_file, write_file],
            interceptors=[interceptor],
            workflow_runner=SandboxedWorkflowRunner(
                restrictions=SandboxRestrictions.default.with_passthrough_modules(
                    "tenuo", "tenuo_core",
                )
            ),
        )
    """

    def __init__(self, config: TenuoInterceptorConfig) -> None:
        global _interceptor_config
        self._config = config
        _interceptor_config = config
        self._version = self._get_version()

    def _get_version(self) -> str:
        """Get Tenuo version for audit events."""
        try:
            from tenuo import __version__

            return __version__
        except ImportError:
            return "unknown"

    def intercept_activity(
        self,
        next_interceptor: Any,  # ActivityInboundInterceptor
    ) -> "TenuoActivityInboundInterceptor":
        """Return activity interceptor that wraps the next one."""
        return TenuoActivityInboundInterceptor(
            next_interceptor,
            self._config,
            self._version,
        )

    def workflow_interceptor_class(
        self,
        input: Any,  # WorkflowInterceptorClassInput
    ) -> Optional[type]:
        """Return workflow interceptor class that captures Tenuo headers.

        The returned class stores workflow-start headers in a module-level
        dict so the activity interceptor can read them. This sidesteps the
        fact that workflow.execute_activity() does not accept ``headers``.
        """
        _TenuoWorkflowInboundInterceptor._config = self._config
        return _TenuoWorkflowInboundInterceptor


class TenuoActivityInboundInterceptor:
    """Activity-level interceptor that performs authorization checks."""

    def __init__(
        self,
        next_interceptor: Any,
        config: TenuoInterceptorConfig,
        version: str,
    ) -> None:
        self._next = next_interceptor
        self._config = config
        self._version = version

    def init(self, outbound: Any) -> None:
        """Called by Temporal to initialize the interceptor with an outbound impl."""
        self._next.init(outbound)

    async def execute_activity(self, input: Any) -> Any:
        """Intercept activity execution for authorization."""
        try:
            from temporalio import activity  # type: ignore[import-not-found]
        except ImportError:
            # If temporalio not available, pass through
            return await self._next.execute_activity(input)

        # Get activity info
        info = activity.info()

        # Phase 2: Local activity guard
        # Local activities bypass interceptors at the worker level, but
        # we can detect them here and enforce @unprotected marking.
        is_local = getattr(info, "is_local", False)
        activity_fn = getattr(input, "fn", None)

        if is_local and self._config.block_local_activities:
            # Fail-closed: if we can't determine protection status, deny
            if activity_fn is None:
                logger.warning(
                    f"Local activity {info.activity_type} denied: cannot determine protection status (fail-closed)"
                )
                raise LocalActivityError(info.activity_type)

            # Check if activity is marked @unprotected
            if not is_unprotected(activity_fn):
                raise LocalActivityError(info.activity_type)

            # Unprotected local activities skip authorization
            return await self._next.execute_activity(input)

        # --- Read Tenuo headers ---
        # Primary path (distributed): the outbound workflow interceptor
        # injects headers into StartActivityInput.headers as Payloads.
        # These travel through Temporal's standard header propagation
        # and arrive here in input.headers on ANY worker.
        #
        # Fallback path (legacy / single-process): read from the
        # module-level _workflow_headers_store and _pending_pop dicts.

        headers: Dict[str, bytes] = {}
        input_headers = getattr(input, "headers", None) or {}
        for k, v in input_headers.items():
            if k.startswith("x-tenuo-"):
                if isinstance(v, bytes):
                    headers[k] = v
                elif hasattr(v, "data") and isinstance(getattr(v, "data", None), bytes):
                    headers[k] = v.data

        if not headers:
            # Fallback: module-level store (single-process path)
            with _store_lock:
                headers = dict(
                    _workflow_headers_store.get(info.workflow_id, {})
                )

            # Resolve tool name for PoP lookup from _pending_pop
            activity_fn = getattr(input, "fn", None)
            default_tool = info.activity_type
            if activity_fn:
                default_tool = get_tool_name(activity_fn, info.activity_type)
            tool_for_pop = self._config.tool_mappings.get(
                info.activity_type, default_tool,
            )

            raw_args = getattr(input, "args", ())
            key = _pop_key(info.workflow_id, tool_for_pop, raw_args)
            with _store_lock:
                q = _pending_pop.get(key)
                pop = q.popleft() if q else None
                if q is not None and not q:
                    del _pending_pop[key]
            if pop is not None:
                headers[TENUO_POP_HEADER] = pop

        # Extract warrant (if present)
        try:
            warrant = _extract_warrant_from_headers(headers)
        except ChainValidationError:
            raise  # Re-raise validation errors

        # If no warrant, check require_warrant config (fail-closed by default)
        if warrant is None:
            if self._config.require_warrant:
                # Fail-closed: deny activities without warrant
                logger.warning(f"No warrant for activity {info.activity_type}, denying (require_warrant=True)")
                if self._config.on_denial == "raise":
                    raise ConstraintViolation(
                        tool=info.activity_type,
                        arguments={},
                        constraint="No warrant provided (require_warrant=True)",
                        warrant_id="none",
                    )
                return None
            else:
                # Opt-in mode: allow without warrant
                logger.debug(
                    f"No warrant for activity {info.activity_type}, executing without auth (require_warrant=False)"
                )
                return await self._next.execute_activity(input)

        # Resolve tool name
        activity_fn = getattr(input, "fn", None)
        default_tool = info.activity_type
        if activity_fn:
            default_tool = get_tool_name(activity_fn, info.activity_type)
        tool_name = self._config.tool_mappings.get(
            info.activity_type, default_tool,
        )

        # Get activity arguments
        args = self._extract_arguments(input)

        # Check chain depth (enforce max_chain_depth config)
        chain_depth = warrant.depth if hasattr(warrant, "depth") else 0
        if chain_depth > self._config.max_chain_depth:
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
                constraint="max_chain_depth_exceeded",
            )
            if self._config.on_denial == "raise":
                raise ChainValidationError(
                    reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
                    depth=chain_depth,
                )
            return None

        # --- Full Authorizer path (with PoP verification) ---
        if self._config.trusted_roots:
            try:
                from tenuo_core import Authorizer, Warrant as CoreWarrant  # type: ignore[import-not-found]

                authorizer = Authorizer(trusted_roots=self._config.trusted_roots)

                # Extract PoP signature (base64-encoded in headers)
                pop_bytes = None
                pop_header = headers.get(TENUO_POP_HEADER)
                if pop_header:
                    pop_bytes = base64.b64decode(pop_header)

                # check_chain() is the single authorization entry point.
                # For delegation chains it verifies transitive trust;
                # for standalone warrants authorize_one() wraps it as
                # a single-element chain.
                chain_header = headers.get(TENUO_CHAIN_HEADER)
                if chain_header:
                    chain_list = json.loads(base64.b64decode(chain_header))
                    chain = [CoreWarrant.from_base64(w) for w in chain_list]
                    authorizer.check_chain(
                        chain, tool_name, args, signature=pop_bytes,
                    )
                else:
                    authorizer.authorize_one(
                        warrant, tool_name, args, signature=pop_bytes,
                    )

                # PoP replay detection: reject if the same dedup key
                # was seen within the dedup TTL window.  Skip on
                # Temporal retries (attempt > 1) which reuse the same
                # headers legitimately.
                if info.attempt <= 1:
                    global _pop_dedup_last_evict
                    base_dedup = warrant.dedup_key(tool_name, args)
                    dedup_key = f"{base_dedup}:{info.workflow_id}:{info.activity_id}"
                    now = datetime.now(timezone.utc).timestamp()
                    ttl = float(warrant.dedup_ttl_secs())
                    with _store_lock:
                        last_seen = _pop_dedup_cache.get(dedup_key)
                        if last_seen is not None and (now - last_seen) < ttl:
                            raise PopVerificationError(
                                reason=f"replay detected (dedup_key seen {now - last_seen:.1f}s ago)",
                                activity_name=tool_name,
                            )
                        _pop_dedup_cache[dedup_key] = now
                        if (now - _pop_dedup_last_evict) >= _DEDUP_EVICT_INTERVAL:
                            _pop_dedup_last_evict = now
                            expired = [
                                k for k, t in _pop_dedup_cache.items()
                                if (now - t) >= ttl
                            ]
                            for k in expired:
                                del _pop_dedup_cache[k]

            except Exception as e:
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason=str(e),
                )
                if self._config.on_denial == "raise":
                    raise ConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint=str(e),
                        warrant_id=warrant.id,
                    )
                elif self._config.on_denial == "log":
                    logger.warning(f"Authorization denied for {tool_name}: {e}")
                return None

        else:
            # --- Lightweight path (no trusted_roots, no PoP) ---
            # Check warrant expiry
            if warrant.is_expired():
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason="Warrant expired",
                )
                if self._config.on_denial == "raise":
                    raise WarrantExpired(
                        warrant_id=warrant.id,
                        expired_at=warrant.expires_at(),
                    )
                return None

            # Check tool is in capabilities
            tools = warrant.tools or []
            if tool_name not in tools:
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason=f"Tool '{tool_name}' not in warrant capabilities",
                    constraint="tool_not_allowed",
                )
                if self._config.on_denial == "raise":
                    raise ConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint=f"Tool not in warrant capabilities: {tools}",
                        warrant_id=warrant.id,
                    )
                return None

            # Check constraints — returns None on success, violation string on failure
            try:
                violation = warrant.check_constraints(tool_name, args)
                if violation is not None:
                    self._emit_denial_event(
                        info=info,
                        warrant=warrant,
                        tool=tool_name,
                        args=args,
                        reason=f"Constraint violated: {violation}",
                        constraint="constraint_violated",
                    )
                    if self._config.on_denial == "raise":
                        raise ConstraintViolation(
                            tool=tool_name,
                            arguments=args,
                            constraint=str(violation),
                            warrant_id=warrant.id,
                        )
                    return None

            except ConstraintViolation:
                raise
            except Exception as e:
                logger.error(f"Constraint check error: {e}")
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason=f"Constraint check error: {e}",
                )
                if self._config.on_denial == "raise":
                    raise ConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint=f"Constraint check failed: {e}",
                        warrant_id=warrant.id,
                    )
                return None

        # Authorization passed — emit allow event
        self._emit_allow_event(
            info=info,
            warrant=warrant,
            tool=tool_name,
            args=args,
        )

        # Execute the activity
        return await self._next.execute_activity(input)

    def _extract_arguments(self, input: Any) -> Dict[str, Any]:
        """Extract arguments from activity input with proper signature mapping.

        Handles various input formats and maps positional args to named params.
        """
        import inspect

        args = getattr(input, "args", ())
        activity_fn = getattr(input, "fn", None)

        # If we have the function, use its signature to map args properly
        if activity_fn and args:
            try:
                sig = inspect.signature(activity_fn)
                params = list(sig.parameters.keys())
                result = {}
                for i, arg in enumerate(args):
                    if i < len(params):
                        result[params[i]] = arg
                    else:
                        result[f"arg{i}"] = arg
                return result
            except (ValueError, TypeError):
                # Fallback if signature inspection fails
                pass

        # If first arg is a dict, use it (legacy pattern)
        if args and isinstance(args[0], dict):
            return args[0]

        # Fallback: create dict from positional args
        result = {}
        for i, arg in enumerate(args):
            result[f"arg{i}"] = arg

        return result

    def _redact_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Redact argument values for logging (prevent sensitive data leaks)."""
        if not self._config.redact_args_in_logs:
            return args
        return {k: "[REDACTED]" for k in args.keys()}

    def _emit_allow_event(
        self,
        info: Any,
        warrant: Any,
        tool: str,
        args: Dict[str, Any],
    ) -> None:
        """Emit audit event for allowed action."""
        if not self._config.audit_allow or not self._config.audit_callback:
            return

        event = TemporalAuditEvent(
            workflow_id=info.workflow_id,
            workflow_type=info.workflow_type,
            workflow_run_id=info.workflow_run_id,
            activity_name=info.activity_type,
            activity_id=info.activity_id,
            task_queue=info.task_queue,
            decision="ALLOW",
            tool=tool,
            arguments=self._redact_args(args),
            warrant_id=warrant.id,
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools or []),
            tenuo_version=self._version,
        )

        try:
            self._config.audit_callback(event)
        except Exception as e:
            logger.error(f"Audit callback failed: {e}")

    def _emit_denial_event(
        self,
        info: Any,
        warrant: Any,
        tool: str,
        args: Dict[str, Any],
        reason: str,
        constraint: Optional[str] = None,
    ) -> None:
        """Emit audit event for denied action."""
        if not self._config.audit_deny or not self._config.audit_callback:
            return

        event = TemporalAuditEvent(
            workflow_id=info.workflow_id,
            workflow_type=info.workflow_type,
            workflow_run_id=info.workflow_run_id,
            activity_name=info.activity_type,
            activity_id=info.activity_id,
            task_queue=info.task_queue,
            decision="DENY",
            tool=tool,
            arguments=self._redact_args(args),
            warrant_id=warrant.id,
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools or []),
            denial_reason=reason,
            constraint_violated=constraint,
            tenuo_version=self._version,
        )

        try:
            self._config.audit_callback(event)
        except Exception as e:
            logger.error(f"Audit callback failed: {e}")


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Exceptions
    "TenuoTemporalError",
    "TenuoContextError",
    "ConstraintViolation",
    "WarrantExpired",
    "ChainValidationError",
    "KeyResolutionError",
    # Phase 2 exceptions
    "LocalActivityError",
    "PopVerificationError",
    # Audit
    "TemporalAuditEvent",
    # Key Resolvers
    "KeyResolver",
    "EnvKeyResolver",
    "VaultKeyResolver",  # Phase 4
    "AWSSecretsManagerKeyResolver",  # Phase 4
    "GCPSecretManagerKeyResolver",  # Phase 4
    "CompositeKeyResolver",  # Phase 4
    # Metrics
    "TenuoMetrics",  # Phase 4
    # Config
    "TenuoInterceptorConfig",
    # Interceptors
    "TenuoInterceptor",
    "TenuoClientInterceptor",
    "TenuoActivityInboundInterceptor",
    # Header utilities
    "tenuo_headers",
    "attenuated_headers",  # Phase 3
    # Workflow helpers
    "tenuo_execute_activity",
    "tenuo_execute_child_workflow",
    # Context accessors
    "current_warrant",
    "current_key_id",
    "workflow_grant",  # Phase 3
    "AuthorizedWorkflow",  # Phase 3
    # Phase 2: Decorators
    "unprotected",
    "is_unprotected",
    # Phase 3: Decorators
    "tool",
    "get_tool_name",
    # Constants
    "TENUO_WARRANT_HEADER",
    "TENUO_KEY_ID_HEADER",
    "TENUO_POP_HEADER",
    "TENUO_SIGNING_KEY_HEADER",
    "TENUO_COMPRESSED_HEADER",
    "TENUO_CHAIN_HEADER",
]
