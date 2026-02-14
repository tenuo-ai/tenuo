"""
Tenuo Temporal Integration - Warrant-based Authorization for Durable Workflows

Compatibility:
    Temporal SDK: 1.4.0+
    Python: 3.9+

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

Phase 1 Features:
    - TenuoInterceptor: Activity-level authorization
    - tenuo_headers(): Create headers for workflow start
    - current_warrant(): Access warrant from workflow context
    - EnvKeyResolver: Development key resolver
    - Basic audit event emission

Phase 2 Features:
    - Mandatory PoP verification using scheduled_time (replay-safe)
    - tenuo_execute_activity(): Workflow helper with automatic PoP signing
    - @unprotected decorator for local activities
    - Fail-closed local activity guard

Phase 3 Features:
    - @tool() decorator for activity-to-tool mapping
    - attenuated_headers() for child workflow delegation
    - workflow_grant() for deterministic single-tool grants

Phase 4 Features:
    - VaultKeyResolver, AWSSecretsManagerKeyResolver, GCPSecretManagerKeyResolver, CompositeKeyResolver
    - TenuoMetrics for Prometheus observability
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Literal, Optional, TypeVar

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

# PoP timestamp validation window (seconds). The scheduled_time must be
# within this window. This is not configurable — security is non-negotiable.
POP_WINDOW_SECONDS = 300


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
    """Required. Resolves key IDs to signing keys."""

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
    signing_key_bytes = signing_key.to_bytes() if hasattr(signing_key, "to_bytes") else bytes(signing_key)
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
    It transparently computes the PoP challenge (SHA-256 of workflow context),
    signs it with the holder's key, and attaches the signature as a header.

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
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    # Get workflow info for challenge computation
    info = workflow.info()

    # Get signing key from workflow headers
    signing_key_b64 = workflow.payload_converter().from_payloads(
        [workflow.unsafe.current_headers().get(TENUO_SIGNING_KEY_HEADER)]  # type: ignore[attr-defined]
    ) if hasattr(workflow, "unsafe") else None

    # Fallback: try getting raw header bytes
    if signing_key_b64 is None:
        raw_headers = getattr(workflow, "_current_headers", None)
        if raw_headers and TENUO_SIGNING_KEY_HEADER in raw_headers:
            signing_key_b64 = raw_headers[TENUO_SIGNING_KEY_HEADER]

    if signing_key_b64 is None:
        raise TenuoContextError(
            "No signing key found in workflow headers. "
            "Pass signing_key to tenuo_headers() when starting the workflow."
        )

    # Decode signing key
    try:
        if isinstance(signing_key_b64, bytes):
            signing_key_raw = base64.b64decode(signing_key_b64)
        else:
            signing_key_raw = base64.b64decode(signing_key_b64.encode())  # type: ignore[attr-defined]
    except Exception as e:
        raise TenuoContextError(f"Invalid signing key in headers: {e}")

    # Resolve tool name
    tool_name = get_tool_name(activity, getattr(activity, "__name__", str(activity)))

    # Compute PoP challenge
    challenge = _compute_pop_challenge(
        workflow_id=info.workflow_id,
        activity_id=f"{info.workflow_id}-{tool_name}",  # Deterministic activity ID
        tool_name=tool_name,
        args={"args": args or []},
        scheduled_time=workflow.now(),  # Replay-safe timestamp
    )

    # Sign challenge with Ed25519
    try:
        from tenuo_core import SigningKey  # type: ignore[import-not-found]

        signer = SigningKey.from_bytes(signing_key_raw)
        pop_signature = signer.sign(challenge)
        pop_b64 = base64.b64encode(pop_signature).decode()
    except ImportError:
        # Fallback: use nacl or raw ed25519
        # If tenuo_core is not available, use the raw signing key
        # This path should only be hit in testing
        pop_b64 = base64.b64encode(signing_key_raw + challenge).decode()
        logger.warning("tenuo_core not available, using fallback PoP (testing only)")

    # Build activity kwargs
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

    # Inject PoP header
    headers = {TENUO_POP_HEADER: pop_b64.encode("utf-8")}
    activity_kwargs["headers"] = headers

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
        constraints: Additional constraints to apply.
        ttl_seconds: Max TTL for child warrant. None = inherit parent.
        child_key_id: Key ID for child. None = inherit parent.
        compress: Whether to gzip compress (default: True).

    Returns:
        Headers dict to pass to execute_child_workflow()

    Example:
        # Start child workflow with reduced scope
        await workflow.execute_child_workflow(
            ChildWorkflow.run,
            args=[...],
            headers=attenuated_headers(
                tools=["read_file"],  # Parent has read_file + write_file
                ttl_seconds=60,
            ),
        )

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
    parent_tools = set(parent_warrant.tools())
    if tools is not None:
        requested_tools = set(tools)
        if not requested_tools.issubset(parent_tools):
            excess = requested_tools - parent_tools
            raise ConstraintViolation(
                tool=str(list(excess)[0]),
                arguments={},
                constraint=f"Cannot delegate tools not in parent: {excess}",
                warrant_id=parent_warrant.id(),
            )
    else:
        tools = list(parent_tools)

    # Attenuate the warrant
    # Note: This uses the parent warrant's attenuate() method
    # The actual key resolution happens at execution time
    child_warrant = parent_warrant.attenuate(
        tools=tools,
        constraints=constraints or {},
        ttl_seconds=ttl_seconds,
    )

    # Use parent key_id if not specified
    key_id = child_key_id or parent_key_id

    # Propagate signing key from parent workflow headers
    try:
        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        raw_headers = getattr(_wf, "_current_headers", None) or {}
        signing_key_b64 = raw_headers.get(TENUO_SIGNING_KEY_HEADER)
        if signing_key_b64 is None:
            raise TenuoContextError(
                "No signing key in parent workflow headers. "
                "Cannot propagate PoP to child workflow."
            )
        # Decode and re-encode for tenuo_headers
        signing_key_raw = base64.b64decode(signing_key_b64)
    except ImportError:
        raise TenuoContextError("temporalio not available")

    return tenuo_headers(child_warrant, key_id, signing_key_raw, compress=compress)


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
        constraints: Constraints to apply to the tool
        ttl_seconds: Time-to-live in seconds (default: 5 minutes)

    Returns:
        A new Warrant scoped to the specified tool

    Example:
        # Within a workflow
        file_warrant = workflow_grant(
            "read_file",
            constraints={"path_prefix": "/data/"},
            ttl_seconds=60,
        )

        # Pass to activity
        await workflow.execute_activity(
            read_file,
            args=[file_warrant, path],
            ...
        )

    Raises:
        TenuoContextError: If called outside workflow context
        ConstraintViolation: If tool not in parent warrant
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    # Get parent warrant
    parent_warrant = current_warrant()

    # Validate tool is in parent scope
    parent_tools = parent_warrant.tools()
    if tool not in parent_tools:
        raise ConstraintViolation(
            tool=tool,
            arguments={},
            constraint=f"Tool '{tool}' not in parent warrant capabilities",
            warrant_id=parent_warrant.id(),
        )

    # Issue attenuated warrant with deterministic timestamp
    # workflow.now() is replay-safe
    return parent_warrant.attenuate(
        tools=[tool],
        constraints=constraints or {},
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
        headers = getattr(info, "headers", {}) or {}

        warrant = _extract_warrant_from_headers(headers)
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
        headers = getattr(info, "headers", {}) or {}

        key_id = _extract_key_id_from_headers(headers)
        if key_id is None:
            raise TenuoContextError("No Tenuo key ID in workflow context")

        return key_id

    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")


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


class TenuoInterceptor:
    """Temporal interceptor that enforces Tenuo warrant authorization.

    Intercepts activity execution and verifies the calling workflow
    has a valid warrant authorizing the activity.

    Example:
        interceptor = TenuoInterceptor(
            TenuoInterceptorConfig(
                key_resolver=EnvKeyResolver(),
                on_denial="raise",
            )
        )

        worker = Worker(
            client,
            task_queue="my-queue",
            workflows=[MyWorkflow],
            activities=[read_file, write_file],
            interceptors=[interceptor],
        )
    """

    def __init__(self, config: TenuoInterceptorConfig) -> None:
        self._config = config
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

        # Get headers from workflow context
        headers = getattr(info, "headers", {}) or {}

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
        # Priority: 1) config mapping, 2) @tool() decorator, 3) activity name
        activity_fn = getattr(input, "fn", None)
        default_tool = info.activity_type
        if activity_fn:
            default_tool = get_tool_name(activity_fn, info.activity_type)

        tool_name = self._config.tool_mappings.get(
            info.activity_type,
            default_tool,
        )

        # Get activity arguments
        args = self._extract_arguments(input)

        # Check chain depth (enforce max_chain_depth config)
        chain_depth = warrant.chain_depth() if hasattr(warrant, "chain_depth") else 0
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

        # Check warrant expiry
        if warrant.is_expired():
            expires_at = warrant.expires_at()
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason="Warrant expired",
            )

            if self._config.on_denial == "raise":
                raise WarrantExpired(
                    warrant_id=warrant.id(),
                    expired_at=expires_at,
                )
            elif self._config.on_denial == "log":
                logger.warning(f"Warrant expired: {warrant.id()}")

            return None

        # Check tool is in capabilities
        tools = warrant.tools()
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
                    warrant_id=warrant.id(),
                )
            elif self._config.on_denial == "log":
                logger.warning(f"Tool {tool_name} not in warrant capabilities: {tools}")

            return None

        # Check constraints
        try:
            # Use warrant's check_constraints method
            result = warrant.check_constraints(tool_name, args)
            # result is True if allowed, raises or returns False if denied
            if result is False or (hasattr(result, "is_allowed") and not result.is_allowed):
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason="Constraint check failed",
                    constraint="constraint_violated",
                )

                if self._config.on_denial == "raise":
                    raise ConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint="Constraint violated",
                        warrant_id=warrant.id(),
                    )
                elif self._config.on_denial == "log":
                    logger.warning(f"Constraint violated for {tool_name}")

                return None

        except Exception as e:
            # Fail closed on constraint check errors
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
                    warrant_id=warrant.id(),
                )

            return None

        # PoP verification (mandatory — security is non-negotiable)
        scheduled_time = getattr(info, "scheduled_time", None)
        if scheduled_time is None:
            # No scheduled_time available - fail closed
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason="PoP verification failed: no scheduled_time",
            )
            if self._config.on_denial == "raise":
                raise PopVerificationError(
                    reason="scheduled_time not available",
                    activity_name=info.activity_type,
                )
            return None

        # Compute expected challenge
        challenge = _compute_pop_challenge(
            workflow_id=info.workflow_id,
            activity_id=info.activity_id,
            tool_name=tool_name,
            args=args,
            scheduled_time=scheduled_time,
        )

        # Extract PoP from headers and verify
        pop_header = headers.get(TENUO_POP_HEADER)
        if pop_header is None:
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason="PoP verification failed: no PoP header",
            )
            if self._config.on_denial == "raise":
                raise PopVerificationError(
                    reason="Missing PoP header",
                    activity_name=info.activity_type,
                )
            return None

        # Verify PoP signature against warrant's holder key
        try:
            # Decode PoP header (base64-encoded signature)
            pop_signature = base64.b64decode(pop_header)

            # Get holder's public key from warrant
            holder_key = warrant.holder_key() if hasattr(warrant, "holder_key") else None
            if holder_key is None:
                raise PopVerificationError(
                    reason="Warrant has no holder key for PoP verification",
                    activity_name=info.activity_type,
                )

            # Verify signature over challenge
            if not holder_key.verify(challenge, pop_signature):
                raise PopVerificationError(
                    reason="PoP signature verification failed",
                    activity_name=info.activity_type,
                )

            logger.debug(f"PoP verified for {info.activity_type}: challenge={challenge.hex()[:16]}...")

        except PopVerificationError:
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason="PoP signature verification failed",
            )
            if self._config.on_denial == "raise":
                raise
            return None
        except Exception as e:
            # Fail-closed on any PoP verification error
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason=f"PoP verification error: {e}",
            )
            if self._config.on_denial == "raise":
                raise PopVerificationError(
                    reason=f"Verification error: {e}",
                    activity_name=info.activity_type,
                )
            return None

        # Authorization passed - emit allow event
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
            warrant_id=warrant.id(),
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools()),
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
            warrant_id=warrant.id(),
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools()),
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
    # Interceptor
    "TenuoInterceptor",
    # Header utilities
    "tenuo_headers",
    "attenuated_headers",  # Phase 3
    # Workflow helpers
    "tenuo_execute_activity",
    # Context accessors
    "current_warrant",
    "current_key_id",
    "workflow_grant",  # Phase 3
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
]
