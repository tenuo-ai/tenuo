"""
Tenuo Temporal Integration - Warrant-based Authorization for Durable Workflows

Compatibility:
    Temporal SDK: 1.23+ recommended (``TenuoTemporalPlugin`` / ``SimplePlugin``);
    ``temporalio>=1.23`` is required by the ``tenuo[temporal]`` extra.
    Python: 3.9+

Documentation:
    User guide: ``docs/temporal.md`` (Path to production, security, child
    workflows). Examples: ``examples/temporal/demo.py`` and siblings.

Setup (required):
    ``tenuo_core`` is a PyO3 module. It cannot be initialised again inside
    Temporal's workflow sandbox. Declare ``tenuo`` and ``tenuo_core`` as
    passthrough modules on the workflow worker::

        from temporalio.worker.workflow_sandbox import (
            SandboxedWorkflowRunner, SandboxRestrictions,
        )

        worker = Worker(
            client,
            task_queue="my-queue",
            workflows=[MyWorkflow],
            activities=[my_activity],
            interceptors=[TenuoPlugin(config)],
            workflow_runner=SandboxedWorkflowRunner(
                restrictions=SandboxRestrictions.default.with_passthrough_modules(
                    "tenuo", "tenuo_core",
                )
            ),
        )

    If passthrough is missing, workflow tasks fail with
    ``ImportError: PyO3 modules may only be initialized once per interpreter process``.
    PoP is signed in the sandbox at ``execute_activity()`` time so the dispatch
    binds to the exact tool and arguments. See **Sandbox passthrough explained**
    in ``docs/temporal.md`` for rationale and the full failure sequence.

Overview:
    Warrants and PoP travel in Temporal headers. ``TenuoPlugin`` verifies each
    activity before your ``@activity.defn`` runs. Activity implementations do
    not need Tenuo imports. Workflows need headers on start (typically
    ``execute_workflow_authorized`` or ``set_headers_for_workflow`` plus
    ``execute_workflow``). Holder keys are resolved on the worker via
    ``KeyResolver`` (use ``EnvKeyResolver.preload_keys`` before ``Worker`` when
    keys come from the environment; the sandbox blocks ``os.environ``).

Key concepts:
    - Headers: warrant material and ``key_id`` only (not private keys).
    - ``TenuoPlugin``: inbound/outbound interceptors on the worker.
    - Child workflows: use ``tenuo_execute_child_workflow`` only. Plain
      ``workflow.execute_child_workflow`` does not propagate Tenuo headers.

Activity registry (``activity_fns``) and PoP argument names:
    PoP signs a canonical **dict** of tool arguments. The outbound interceptor
    uses Python parameter names when it can resolve the activity function; else
    it falls back to ``arg0``, ``arg1``, … (see ``TenuoPluginConfig.activity_fns``).

    If the warrant uses **named field constraints** (e.g. ``path=Subpath(...)``),
    PoP and verification expect keys like ``path``, not ``arg0``. Without
    ``input.fn`` or ``activity_fns``, you get a warning or (with
    ``strict_mode=True``) ``TenuoContextError``.

    **Rule:** For named constraints, set ``activity_fns`` to the same callables
    as ``Worker(activities=...)``, or call through ``tenuo_execute_activity``
    (records the function reference).

Security (fail-closed defaults):
    - Missing warrant: denied if ``require_warrant=True`` (default).
    - Invalid chain: ``ChainValidationError``.
    - Expired warrant: ``WarrantExpired``.
    - Args outside warrant: ``TemporalConstraintViolation`` / constraint errors.
    - Bad or missing PoP: ``PopVerificationError`` (PoP is always verified when a
      warrant is present).
    - Local activity without ``@unprotected``: ``LocalActivityError``.

Usage patterns:
    **AuthorizedWorkflow** (fail fast if warrant headers are missing at start)::

        @workflow.defn
        class MyWorkflow(AuthorizedWorkflow):
            @workflow.run
            async def run(self, arg: str) -> str:
                return await self.execute_authorized_activity(
                    my_activity, args=[arg],
                    start_to_close_timeout=timedelta(seconds=30),
                )

    **Plain** ``workflow.execute_activity()`` also works with ``TenuoPlugin``;
    set ``activity_fns`` when warrants name arguments and the SDK does not
    supply a reliable function reference. ``AuthorizedWorkflow`` is optional;
    enforcement is always in ``TenuoPlugin``.

    **tenuo_execute_activity** (same auth as ``execute_activity``, helps PoP
    names when ``activity_fns`` is unset)::

        @workflow.defn
        class PipelineWorkflow:
            @workflow.run
            async def run(self, data_dir: str) -> str:
                return await tenuo_execute_activity(
                    my_activity, args=[data_dir],
                    start_to_close_timeout=timedelta(seconds=30),
                )

Proof-of-Possession (PoP) challenge (tenuo-core):
    Only the holder of the key matching ``authorized_holder`` should be able
    to produce a valid PoP for a dispatch. Each attempt uses a 64-byte Ed25519
    signature over a deterministic preimage.

    Construction::

        domain_context = b"tenuo-pop-v1"
        window_ts      = (unix_now // 30) * 30          # 30-second bucket
        challenge_data = CBOR( (warrant_id, tool, sorted_args, window_ts) )
        preimage       = domain_context || challenge_data
        signature      = Ed25519.sign(signing_key, preimage)   # 64 bytes

    Fields:
        - ``warrant_id``: hex warrant id (``warrant.id``).
        - ``tool``: activity / tool name string.
        - ``sorted_args``: key-sorted ``[(name, ConstraintValue), ...]``.
        - ``window_ts``: floored to 30 s. Defaults (``pop_max_windows=5``)
          give roughly ±60 s skew tolerance around the verifier clock.
        - Encoding: CBOR (RFC 8949).

    In this SDK the outbound interceptor signs using
    ``warrant.sign(..., timestamp=workflow.now())`` for replay-safe workflows.
    The activity interceptor verifies via ``Authorizer.authorize_one`` or
    ``check_chain`` and passes the signature from header ``x-tenuo-pop``.

Troubleshooting:
    ``ImportError: PyO3 modules may only be initialized once per interpreter process``
        Passthrough for ``tenuo`` and ``tenuo_core`` is missing on the workflow
        worker. The process may still poll; workflow tasks fail and activities
        from those workflows are never reached. Inspect workflow task errors in
        Temporal Web, not only worker health.

        Sequence: worker starts; first workflow task loads the sandbox; second
        import of ``tenuo_core`` raises; task fails; later workflow tasks on the
        same worker repeat the same error.

    ``TenuoContextError: No Tenuo headers in store``
        Start path did not bind headers for this ``workflow_id``. Prefer
        ``execute_workflow_authorized`` or call
        ``set_headers_for_workflow(workflow_id, tenuo_headers(...))`` before
        ``execute_workflow``.

    ``TemporalConstraintViolation: No warrant provided (require_warrant=True)``
        No warrant reached the activity worker. Check client interceptors,
        header binding, and that headers were not cleared before start.

    ``TemporalConstraintViolation: ... Incorrect padding`` or ``signature must be 64 bytes``
        Header wire mismatch. Confirm ``TenuoClientInterceptor`` and
        ``TenuoPlugin`` are both registered and versions match.

    ``WarrantExpired: Warrant '...' expired at ...``
        Mint a new warrant or extend TTL before the run exceeds it.

    Log: ``PoP signing for activity ... positional argument keys (arg0, ...)``
        Named warrant fields but positional PoP keys. Add ``activity_fns`` or use
        ``tenuo_execute_activity``. With ``strict_mode=True`` this becomes
        ``TenuoContextError``.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import logging
import threading
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Protocol,
    Sequence,
    TypeVar,
)

from .exceptions import ApprovalGateTriggered

import inspect as _inspect

F = TypeVar("F", bound=Callable[..., Any])

if TYPE_CHECKING:
    from tenuo.temporal_plugin import TenuoTemporalPlugin, ensure_tenuo_workflow_runner

logger = logging.getLogger("tenuo.temporal")

_TemporalClientInterceptor: Any
_TemporalWorkerInterceptor: Any
try:
    from temporalio.client import Interceptor as _tc_interceptor
    from temporalio.worker import Interceptor as _tw_interceptor

    _TemporalClientInterceptor = _tc_interceptor
    _TemporalWorkerInterceptor = _tw_interceptor
except ImportError:  # pragma: no cover
    _TemporalClientInterceptor = object
    _TemporalWorkerInterceptor = object

# =============================================================================
# Header Constants
# =============================================================================

TENUO_WARRANT_HEADER = "x-tenuo-warrant"
TENUO_KEY_ID_HEADER = "x-tenuo-key-id"
TENUO_COMPRESSED_HEADER = "x-tenuo-compressed"
TENUO_POP_HEADER = "x-tenuo-pop"
TENUO_CHAIN_HEADER = "x-tenuo-warrant-chain"
TENUO_ARG_KEYS_HEADER = "x-tenuo-arg-keys"
TENUO_WIRE_FORMAT_HEADER = "x-tenuo-wire-format"
TENUO_APPROVALS_HEADER = "x-tenuo-approvals"

# Stable integration id for logs and Temporal Web activity summaries (partner naming).
TENUO_TEMPORAL_PLUGIN_ID = "tenuo.TenuoTemporalPlugin"

# Value for ``x-tenuo-wire-format`` on outgoing headers: identifies that
# ``x-tenuo-warrant`` carries raw CBOR bytes (optionally gzip-compressed).
_TEMPORAL_WARRANT_ENCODING_VERSION = b"2"

# PoP timestamp validation window (seconds). The scheduled_time must be
# within this window. This is not configurable — security is non-negotiable.
# NOTE: this constant is currently unused; the actual PoP window is controlled
# by the Rust Authorizer (pop_window_secs=30, pop_max_windows=5 → ±60s).
# Kept for reference; do not use POP_WINDOW_SECONDS in new code.
POP_WINDOW_SECONDS = 300

# Hard cap on decompressed warrant bytes — must match tenuo_core.MAX_WARRANT_SIZE
# (64 KB, enforced again by the Rust deserializer). Capping here prevents gzip
# amplification from consuming Python memory before Rust even sees the bytes.
try:
    from tenuo_core import MAX_WARRANT_SIZE as _WARRANT_DECOMPRESS_MAX_BYTES  # type: ignore[import-not-found]
except ImportError:
    _WARRANT_DECOMPRESS_MAX_BYTES = 64 * 1024  # 64 KB fallback


def _gzip_decompress_limited(data: bytes, max_length: int = _WARRANT_DECOMPRESS_MAX_BYTES) -> bytes:
    """Decompress gzip data with a hard cap on the output size.

    ``gzip.decompress`` has no built-in size limit, so we read through a
    ``GzipFile`` and stop early if the output exceeds ``max_length``.
    """
    import io

    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gf:
        result = gf.read(max_length + 1)
    if len(result) > max_length:
        raise ValueError(
            f"Decompressed warrant exceeds {max_length} bytes limit ({len(result)} bytes)"
        )
    return result

# =============================================================================
# Module-level stores for transparent authorization
# =============================================================================
# Tenuo authorization is completely transparent - developers use standard
# workflow.execute_activity() and the interceptor handles everything.
#
# The TenuoClientInterceptor populates _workflow_headers_store when a workflow
# starts. The outbound workflow interceptor (in the sandbox) reads this store,
# computes PoP signatures inline using deterministic timestamps, and injects
# them into activity headers. No queue machinery needed.
#
# _workflow_headers_store: workflow_id → {warrant, key_id}
# _pending_child_headers:  child_wf_id → attenuated headers
# _pop_dedup_cache:        alias of default InMemoryPopDedupStore.cache (replay protection)
# _workflow_config_store:  workflow_id → TenuoPluginConfig
#
# Thread safety: _store_lock protects all mutations. Temporal workers
# may execute activities from different workflows concurrently on
# separate threads.

_store_lock = threading.Lock()
_workflow_headers_store: Dict[str, Dict[str, bytes]] = {}
_pending_child_headers: Dict[str, Dict[str, bytes]] = {}
_DEDUP_EVICT_INTERVAL: float = 60.0
_DEDUP_MAX_SIZE: int = 10_000
_workflow_config_store: Dict[str, "TenuoPluginConfig"] = {}
_pending_activity_fn: Dict[str, Any] = {}  # workflow_id → activity function ref
_pending_activity_approvals: Dict[str, List[Any]] = {}  # workflow_id → SignedApproval list


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

    def __init__(self, activity_name: str) -> None:
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


class PopDedupStore(Protocol):
    """Pluggable PoP replay suppression (default: process-local in-memory).

    Enterprise deployments often run many worker processes. A shared backend
    (Redis, Memcached, DynamoDB, etc.) can implement this protocol so the same
    logical activity attempt cannot pass PoP dedup on two different pods within
    the warrant dedup TTL.

    Implementations must be safe under concurrent activity execution on one
    worker (Temporal may run multiple activities in parallel).

    The method is synchronous; wrap async I/O with ``asyncio.to_thread`` or a
    small connection pool if needed.
    """

    def check_pop_replay(
        self,
        dedup_key: str,
        now: float,
        ttl_seconds: float,
        *,
        activity_name: str,
    ) -> None:
        """Record *dedup_key* or raise ``PopVerificationError`` if seen within TTL.

        Args:
            dedup_key: Stable key for this workflow run + activity + warrant facet.
            now: Unix timestamp (seconds, UTC).
            ttl_seconds: Warrant dedup TTL; suppress reuse inside this window.
            activity_name: Activity type for error messages.

        Raises:
            PopVerificationError: If this key was already recorded within TTL.
        """
        ...


class InMemoryPopDedupStore:
    """Default ``PopDedupStore``: thread-safe ordered dict in this process only.

    Insertion order tracks age (timestamps are monotonically non-decreasing),
    so size-cap eviction pops from the front in O(excess) instead of sorting.
    """

    __slots__ = ("cache", "_last_evict", "_lock")

    def __init__(self) -> None:
        from collections import OrderedDict
        self.cache: OrderedDict[str, float] = OrderedDict()
        self._last_evict: float = 0.0
        self._lock = threading.Lock()

    def check_pop_replay(
        self,
        dedup_key: str,
        now: float,
        ttl_seconds: float,
        *,
        activity_name: str,
    ) -> None:
        with self._lock:
            last_seen = self.cache.get(dedup_key)
            if last_seen is not None and (now - last_seen) < ttl_seconds:
                raise PopVerificationError(
                    reason=(
                        f"replay detected (dedup_key seen {now - last_seen:.1f}s ago)"
                    ),
                    activity_name=activity_name,
                )
            if dedup_key in self.cache:
                del self.cache[dedup_key]
            self.cache[dedup_key] = now

            # Time-based eviction: always evict expired entries when the
            # interval elapses so the TTL guarantee holds under heavy load.
            if (now - self._last_evict) >= _DEDUP_EVICT_INTERVAL:
                self._last_evict = now
                expired = [
                    k for k, t in self.cache.items()
                    if (now - t) >= ttl_seconds
                ]
                for k in expired:
                    del self.cache[k]

            # Size cap: pop oldest entries from the front — O(excess).
            while len(self.cache) > _DEDUP_MAX_SIZE:
                self.cache.popitem(last=False)


_default_pop_dedup_store = InMemoryPopDedupStore()
_pop_dedup_cache = _default_pop_dedup_store.cache


@dataclass
class TemporalConstraintViolation(TenuoTemporalError):
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
        config = TenuoPluginConfig(
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

    **Implementing a custom resolver for use inside Temporal workflows:**
    The outbound workflow interceptor calls ``resolve_sync()``, not ``resolve()``,
    because it runs inside the Temporal workflow sandbox where async I/O is
    restricted.  The default ``resolve_sync()`` implementation spawns a thread
    pool executor, which may behave unexpectedly inside the sandbox.

    If you implement a custom resolver, override ``resolve_sync()`` directly
    with a synchronous implementation (e.g. read from a pre-loaded in-memory
    cache populated before the worker starts).  ``EnvKeyResolver`` does this
    via ``preload_keys()``.
    """

    @abstractmethod
    async def resolve(self, key_id: str) -> Any:  # Returns SigningKey
        """Resolve a key ID to a signing key (async).

        Args:
            key_id: The key identifier

        Returns:
            The signing key (tenuo_core.SigningKey)

        Raises:
            KeyResolutionError: If key cannot be resolved
        """
        ...

    def resolve_sync(self, key_id: str) -> Any:  # Returns SigningKey
        """Resolve a key ID to a signing key (synchronous).

        This method handles the async->sync conversion and is safe to call
        from both sync and async contexts, including from within running
        event loops (e.g., Temporal workflows).

        Default implementation:
        - If no event loop is running: creates temporary loop and runs resolve()
        - If event loop is running: spawns thread pool to run resolve() in new loop

        Subclasses can override this for more efficient sync implementations.

        Args:
            key_id: The key identifier

        Returns:
            The signing key (tenuo_core.SigningKey)

        Raises:
            KeyResolutionError: If key cannot be resolved
        """
        import asyncio
        import concurrent.futures

        try:
            asyncio.get_running_loop()
            # We're in a running loop (e.g., Temporal workflow)
            # Must use thread pool to avoid "loop already running" error
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                try:
                    return pool.submit(self._resolve_in_new_loop, key_id).result(
                        timeout=30,
                    )
                except concurrent.futures.TimeoutError:
                    raise KeyResolutionError(
                        f"Key resolution timed out after 30s for key_id={key_id!r}. "
                        "Check network connectivity to the key store."
                    )
        except RuntimeError:
            # No running loop - safe to create one
            return self._resolve_in_new_loop(key_id)

    def _resolve_in_new_loop(self, key_id: str) -> Any:
        """Helper to run resolve() in a new event loop."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.resolve(key_id))
        finally:
            loop.close()


class EnvKeyResolver(KeyResolver):
    """Resolves keys from environment variables.

    For development/testing only. Do not use in production.

    Expects: TENUO_KEY_{key_id}=<base64-encoded-key>

    Args:
        prefix: Environment variable prefix (default: "TENUO_KEY_")
        warn_in_production: Emit a WARNING log at first resolution if the
            environment does not look like a development setup (i.e.
            the ``TENUO_ENV`` env var is not ``"development"`` or
            ``"test"``).  Default: True.

    For Temporal workflows:
        Call `preload_keys()` before creating the worker to cache keys
        and avoid os.environ access inside the workflow sandbox:

            resolver = EnvKeyResolver()
            resolver.preload_keys(["agent1", "agent2"])  # Cache before workflow
    """

    _DEV_ENVS = {"development", "dev", "test", "testing", "local"}

    def __init__(self, prefix: str = "TENUO_KEY_", *, warn_in_production: bool = True) -> None:
        self._prefix = prefix
        self._warn_in_production = warn_in_production
        self._warned = False
        self._key_cache: Dict[str, Any] = {}  # Pre-loaded keys for Temporal workflows

    def _maybe_warn(self) -> None:
        """Emit a one-time production warning if not suppressed."""
        if self._warned or not self._warn_in_production:
            return
        import os
        env = os.environ.get("TENUO_ENV", "").strip().lower()
        if env not in self._DEV_ENVS:
            logger.warning(
                "EnvKeyResolver is designed for development and testing only. "
                "In production, use VaultKeyResolver, AWSSecretsManagerKeyResolver, "
                "or GCPSecretManagerKeyResolver to fetch keys from secure storage. "
                "Set TENUO_ENV=development to suppress this warning in local environments."
            )
        self._warned = True

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from environment variable."""
        import os

        self._maybe_warn()

        env_name = f"{self._prefix}{key_id}"
        value = os.environ.get(env_name)

        if value is None:
            raise KeyResolutionError(key_id=key_id)

        try:
            from tenuo_core import SigningKey

            key_bytes = base64.b64decode(value)
            return SigningKey.from_bytes(key_bytes)
        except (binascii.Error, ValueError) as e:
            logger.error(f"Failed to decode key from {env_name}: {e}")
            raise KeyResolutionError(key_id=key_id)
        except Exception:
            raise

    def preload_keys(self, key_ids: list[str]) -> None:
        """Pre-load keys from environment to cache for Temporal workflows.

        Call this before creating the Temporal worker to avoid os.environ access
        inside the workflow sandbox, which is blocked as non-deterministic.

        Args:
            key_ids: List of key IDs to pre-load (e.g., ["agent1", "agent2"])

        Raises:
            KeyResolutionError: If any key cannot be loaded
        """
        import os

        for key_id in key_ids:
            env_name = f"{self._prefix}{key_id}"
            value = os.environ.get(env_name)

            if value is None:
                raise KeyResolutionError(key_id=key_id)

            try:
                from tenuo_core import SigningKey

                key_bytes = base64.b64decode(value)
                self._key_cache[key_id] = SigningKey.from_bytes(key_bytes)
            except (binascii.Error, ValueError) as e:
                logger.error(f"Failed to decode key from {env_name}: {e}")
                raise KeyResolutionError(key_id=key_id)
            except Exception:
                raise

    def resolve_sync(self, key_id: str) -> Any:
        """Resolve key from cache or environment variable synchronously.

        Overrides base class to avoid ThreadPoolExecutor, which is blocked
        by Temporal's workflow sandbox.

        For Temporal workflows, use preload_keys() before creating the worker
        to cache keys and avoid os.environ access inside the sandbox.
        """
        # Check cache first (for Temporal workflows)
        if key_id in self._key_cache:
            return self._key_cache[key_id]

        # Fall back to os.environ (for non-workflow contexts)
        import os

        self._maybe_warn()

        env_name = f"{self._prefix}{key_id}"
        value = os.environ.get(env_name)

        if value is None:
            raise KeyResolutionError(key_id=key_id)

        try:
            from tenuo_core import SigningKey

            key_bytes = base64.b64decode(value)
            return SigningKey.from_bytes(key_bytes)
        except (binascii.Error, ValueError) as e:
            logger.error(f"Failed to decode key from {env_name}: {e}")
            raise KeyResolutionError(key_id=key_id)
        except Exception:
            raise


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
        self._cache_lock = threading.Lock()

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from Vault."""
        import os
        import time

        now = time.time()
        with self._cache_lock:
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

                key_b64 = data["data"]["data"]["key"]
                from tenuo_core import SigningKey

                try:
                    key_bytes = base64.b64decode(key_b64)
                    key = SigningKey.from_bytes(key_bytes)
                except (binascii.Error, ValueError) as e:
                    logger.error(f"Vault returned undecodable key for {key_id}: {e}")
                    raise KeyResolutionError(key_id=key_id)

                with self._cache_lock:
                    self._cache[key_id] = (key, now)
                logger.debug(f"Vault resolved key: {key_id}")
                return key

        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(
                "Vault key resolution failed for '%s' (network/TLS/parse error): %s",
                key_id,
                e,
                exc_info=True,
            )
            raise


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
        self._cache_lock = threading.Lock()

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from AWS Secrets Manager.

        The boto3 client is synchronous; this runs it in an executor to avoid
        blocking the event loop.
        """
        import asyncio
        import time

        now = time.time()
        with self._cache_lock:
            if key_id in self._cache:
                cached_key, cached_at = self._cache[key_id]
                if now - cached_at < self._cache_ttl:
                    logger.debug(f"AWS Secrets Manager cache hit for key: {key_id}")
                    return cached_key

        secret_name = f"{self._secret_prefix}{key_id}"

        try:
            import boto3  # type: ignore[import-not-found, import-untyped]

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: boto3.client(
                    "secretsmanager", region_name=self._region_name
                ).get_secret_value(SecretId=secret_name),
            )

            if "SecretBinary" in response:
                key_bytes = response["SecretBinary"]
            elif "SecretString" in response:
                try:
                    key_bytes = base64.b64decode(response["SecretString"])
                except (binascii.Error, ValueError) as e:
                    logger.error(f"AWS Secrets Manager returned undecodable key for {key_id}: {e}")
                    raise KeyResolutionError(key_id=key_id)
            else:
                raise KeyResolutionError(key_id=key_id)

            from tenuo_core import SigningKey

            signing_key = SigningKey.from_bytes(key_bytes)

            with self._cache_lock:
                self._cache[key_id] = (signing_key, now)
            logger.debug(f"AWS Secrets Manager resolved key: {key_id}")
            return signing_key

        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            raise KeyResolutionError(key_id=key_id)
        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(
                "AWS Secrets Manager key resolution failed for '%s' "
                "(network/permissions/parse error): %s",
                key_id,
                e,
                exc_info=True,
            )
            raise


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
        self._cache_lock = threading.Lock()

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from GCP Secret Manager.

        The GCP client is synchronous; this runs it in an executor to avoid
        blocking the event loop.
        """
        import asyncio
        import time

        now = time.time()
        with self._cache_lock:
            if key_id in self._cache:
                cached_key, cached_at = self._cache[key_id]
                if now - cached_at < self._cache_ttl:
                    logger.debug(f"GCP Secret Manager cache hit for key: {key_id}")
                    return cached_key

        secret_name = f"{self._secret_prefix}{key_id}"
        resource_name = f"projects/{self._project_id}/secrets/{secret_name}/versions/{self._version}"

        try:
            from google.cloud import secretmanager  # type: ignore[import-not-found,import-untyped]

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: secretmanager.SecretManagerServiceClient().access_secret_version(
                    name=resource_name
                ),
            )
            key_bytes = response.payload.data

            from tenuo_core import SigningKey

            signing_key = SigningKey.from_bytes(key_bytes)

            with self._cache_lock:
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
            logger.error(
                "GCP Secret Manager key resolution failed for '%s' "
                "(network/permissions/parse error): %s",
                key_id,
                e,
                exc_info=True,
            )
            raise


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

    def __init__(
        self,
        resolvers: List[KeyResolver],
        *,
        warn_on_fallback: bool = True,
    ) -> None:
        if not resolvers:
            raise ValueError("CompositeKeyResolver requires at least one resolver")
        self._resolvers = resolvers
        self._warn_on_fallback = warn_on_fallback

    async def resolve(self, key_id: str) -> Any:
        """Try each resolver in order until one succeeds."""
        errors: List[str] = []

        for i, resolver in enumerate(self._resolvers):
            try:
                key = await resolver.resolve(key_id)
                if i > 0 and self._warn_on_fallback:
                    failed_names = [type(self._resolvers[j]).__name__ for j in range(i)]
                    logger.warning(
                        f"CompositeKeyResolver: primary resolver(s) failed ({', '.join(failed_names)}), "
                        f"resolved {key_id} via fallback {type(resolver).__name__}. "
                        f"Errors: {errors}"
                    )
                else:
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
class TenuoPluginConfig:
    """Configuration for TenuoPlugin."""

    key_resolver: Optional[KeyResolver] = None
    """Resolves key IDs to signing keys for PoP generation.

    Provide this **or** :attr:`signing_key` (a static worker key). When both are
    set, ``key_resolver`` takes precedence.
    """

    signing_key: Optional[Any] = None
    """Optional static ``tenuo_core.SigningKey`` for single-key workers.

    When set and :attr:`key_resolver` is ``None``, a trivial resolver is
    synthesized so you do not need a custom ``KeyResolver`` subclass.
    """

    control_plane: Optional[Any] = None
    """
    Optional ControlPlaneClient for emitting authorization check results
    back to the control plane.
    """

    on_denial: Literal["raise", "log", "skip"] = "raise"
    """
    Behavior when authorization fails:
    - "raise": Raise TemporalConstraintViolation (default)
    - "log": Log denial, continue execution
    - "skip": Silent denial, return None
    """

    dry_run: bool = False
    """
    Shadow mode for integration evaluation. When True, authorization denials
    are NOT enforced: Tenuo emits denial audit/log signals but allows activity
    execution to continue. This setting is for staging and rollout validation
    only and must not be used in production.
    """

    tool_mappings: Dict[str, str] = field(default_factory=dict)
    """
    Optional explicit activity-type → warrant tool name mappings.
    Example: {"fetch_document": "read_file"} when the Temporal activity type
    differs from the tool name used in the warrant and in PoP.

    The outbound workflow interceptor applies the same mapping when signing
    PoP so verification matches the activity inbound interceptor.
    """

    audit_callback: Optional[Callable[[TemporalAuditEvent], None]] = None
    """Optional callback for authorization audit events."""

    audit_allow: bool = True
    """Whether to emit audit events for allowed actions."""

    audit_deny: bool = True
    """Whether to emit audit events for denied actions."""

    @classmethod
    def from_env(cls, **overrides: Any) -> "TenuoPluginConfig":
        """Create config from environment variables.

        Resolves ``TENUO_SIGNING_KEY`` (base64 Ed25519) for PoP generation and
        auto-connects to the control plane via ``TENUO_CONNECT_TOKEN`` (or
        ``TENUO_CONTROL_PLANE_URL`` + ``TENUO_API_KEY`` + ``TENUO_AUTHORIZER_NAME``).

        Any keyword argument overrides the env-derived value::

            config = TenuoPluginConfig.from_env(on_denial="log", dry_run=True)
        """
        import os as _os

        signing_key = overrides.pop("signing_key", None)
        if signing_key is None:
            raw = _os.environ.get("TENUO_SIGNING_KEY")
            if raw:
                from tenuo_core import SigningKey as _SK
                signing_key = _SK.from_base64(raw)

        cp = overrides.pop("control_plane", None)
        if cp is None:
            from .control_plane import get_or_create
            cp = get_or_create()

        return cls(signing_key=signing_key, control_plane=cp, **overrides)

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

    ``True`` (default): activities without a warrant header are denied.
    ``False``: activities without a warrant pass through without authorization.

    Setting this to ``False`` is intended only for **incremental migration**
    scenarios where some task queues or activity types have not yet been
    warranted.  Unauthenticated executions are logged at WARNING level and
    appear in audit events with ``warrant_id="none"``.  Never use in steady-state
    production — the fail-closed guarantee is the core security property.
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
    Trusted issuer public keys for warrant chain-of-trust and PoP verification.

    **Required** unless you use ``trusted_roots_provider`` instead: pass at least
    one root (for example ``[control_key.public_key]`` for warrants minted by that
    key), or set global roots via ``tenuo.configure(trusted_roots=[...])``
    before building the config (empty ``trusted_roots`` falls back to global
    configuration).

    For delegated warrants, include the original root's public key so the full
    chain can be validated.

    Do not set both ``trusted_roots`` and ``trusted_roots_provider``.
    """

    trusted_roots_provider: Optional[Callable[[], Sequence[Any]]] = None
    """
    Callable that returns the current trusted issuer public keys.

    Use with ``trusted_roots_refresh_interval_secs`` to rotate roots without
    redeploying workers: return **overlapping** old + new issuer keys during
    the rotation window so in-flight warrants still verify.

    Mutually exclusive with an explicit non-empty ``trusted_roots`` list (and
    with relying on ``tenuo.configure(trusted_roots=...)`` alone — pass a
    provider that reads the same source of truth if you need refresh).
    """

    trusted_roots_refresh_interval_secs: Optional[float] = None
    """
    When set with ``trusted_roots_provider``, the activity interceptor rebuilds
    the ``Authorizer`` from the provider at most once per this interval
    (monotonic clock). ``None`` means roots are fixed after config construction
    (provider is still called once in ``__post_init__``).
    """

    pop_dedup_store: Optional[PopDedupStore] = None
    """
    Optional ``PopDedupStore`` for fleet-wide PoP deduplication.

    ``None`` uses the shared in-memory default (process-local only). For
    horizontal workers, supply e.g. a Redis-backed implementation of
    ``PopDedupStore``.
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

    activity_fns: Optional[List[Callable]] = None
    """
    Activity functions registered with the Worker.  When provided,
    the outbound workflow interceptor can resolve parameter names
    for transparent PoP signing even when using plain
    ``workflow.execute_activity()``.

    **Why this exists:** PoP signs ``(warrant_id, tool, sorted_args_dict, time)``.
    Warrants with **named field constraints** (e.g. ``path=Subpath("/data")``)
    require ``args_dict`` keys to match those field names.  Resolution order for
    the callable used to build ``args_dict`` is:

    1. ``input.fn`` from the Temporal Python SDK (when present)
    2. Function reference set by ``tenuo_execute_activity()``
    3. This registry: activity type name → function (from ``activity_fns``)
    4. Fallback: ``arg0``, ``arg1``, …

    Without (1)–(3), step (4) is used.  That is valid for **tool-only**
    capabilities (no per-field constraints) because signing and verification
    both use the same ``argN`` keys.  It is **incorrect** for named
    constraints: verification expects e.g. ``path``, not ``arg0``.

    **Detection:** If (4) is used and the warrant has non-empty field
    constraints for that activity type, the worker logs a **warning**; with
    ``strict_mode=True``, it raises ``TenuoContextError`` instead (fail-fast).

    **Required when:** Your warrant uses named constraints for tools you call
    with transparent ``execute_activity``, unless the SDK always provides
    ``input.fn`` in your environment (do not rely on that across versions).

    Pass the **same** list you give to ``Worker(activities=...)``.
    """

    approval_handler: Optional[Callable] = None
    """
    Callback invoked when an approval gate fires and no pre-supplied
    approvals are available in activity headers.  Receives an
    ``ApprovalRequest`` and must return a ``SignedApproval`` (or list).
    Raise ``ApprovalDenied`` to reject.

    When ``None`` (default), approval-gate-triggered calls with no pre-supplied
    approvals are denied with ``ApprovalGateTriggered``.
    """

    trusted_approvers: Optional[List[Any]] = None
    """
    Public keys of trusted approvers for approval gate satisfaction.
    Required when using warrant approval gates with ``required_approvers``.
    If ``None``, the warrant's own ``required_approvers()`` list is used.
    """

    approval_threshold: Optional[int] = None
    """
    Minimum number of valid approvals required to satisfy a guard.
    If ``None``, uses the warrant's ``approval_threshold()``.
    """

    strict_mode: bool = False
    """
    Fail-fast on ambiguous PoP signing (e.g. positional args when the warrant
    has named field constraints).  ``trusted_roots`` is **always** required
    for Temporal workers regardless of this flag; see ``trusted_roots``.
    """

    retry_pop_max_windows: Optional[int] = None
    """
    PoP time-window count to use for Temporal activity **retries** (attempt > 1).

    **Background:** PoP is signed at workflow schedule time using
    ``workflow.now()`` (deterministic replay clock). When Temporal retries an
    activity, it reuses the headers from the original scheduling event in
    workflow history — it does **not** re-invoke the outbound interceptor.
    With the default ``pop_max_windows=5`` (±60 s), an activity retried more
    than ~90 s after its first scheduling will fail PoP verification.

    Set this to accommodate your longest expected retry window:

        # 120 × 30 s = 3600 s — covers up to 1 hour of Temporal retries
        retry_pop_max_windows=120

        # 480 × 30 s = 14400 s — covers up to 4 hours
        retry_pop_max_windows=480

    **Security trade-off:** A wider window means a captured PoP is valid for
    longer on retried tasks (already a lesser concern since dedup is also
    skipped for attempt > 1).  For most deployments the correct value is
    ``ceil(max_retry_window_seconds / 30)``.

    ``None`` (default) uses the same strict window for all attempts, which
    preserves the tightest security guarantee but may cause retry failures for
    long-running workflows.
    """

    def __post_init__(self) -> None:
        if self.dry_run:
            logger.warning(
                "TenuoPluginConfig: dry_run=True enables shadow mode and "
                "does not enforce authorization denials. Do not use in production."
            )
            # Elevate to a Python-level warning so it appears in production logs regardless of
            # logger configuration. Use stacklevel=2 to point at the call site, not this frame.
            warnings.warn(
                "TenuoPluginConfig: dry_run=True — authorization denials will NOT be "
                "enforced. This is a shadow/staging mode; remove dry_run=True before "
                "deploying to production.",
                stacklevel=2,
            )

        if not self.require_warrant:
            logger.warning(
                "TenuoPluginConfig: require_warrant=False — activities without a warrant "
                "will be allowed through without any authorization check. This disables "
                "the fail-closed guarantee. Only use for opt-in migration scenarios."
            )
            warnings.warn(
                "TenuoPluginConfig: require_warrant=False — unwarranted activity "
                "executions will be allowed. Ensure this is intentional.",
                stacklevel=2,
            )

        # Trusted roots are mandatory: explicit list, provider, or global configure().
        if self.trusted_roots_provider is not None:
            if self.trusted_roots:
                from tenuo.exceptions import ConfigurationError
                raise ConfigurationError(
                    "TenuoPluginConfig: pass either trusted_roots= or "
                    "trusted_roots_provider=, not both."
                )
            roots = list(self.trusted_roots_provider())
        elif self.trusted_roots:
            roots = list(self.trusted_roots)
        else:
            from tenuo.config import resolve_trusted_roots as _resolve_tr
            _merged = _resolve_tr(None)
            roots = list(_merged) if _merged else []
        if not roots:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "TenuoPluginConfig requires trusted_roots (issuer public keys). "
                "Pass trusted_roots=[control_key.public_key], trusted_roots_provider=..., "
                "or call tenuo.configure(trusted_roots=[...]) at application startup."
            )
        self.trusted_roots = roots  # type: ignore[assignment]

        if self.signing_key is not None and self.key_resolver is None:

            class _StaticSigningKeyResolver(KeyResolver):
                def __init__(self, sk: Any) -> None:
                    self._sk = sk

                async def resolve(self, key_id: str) -> Any:  # noqa: ARG002
                    return self._sk

                def resolve_sync(self, key_id: str) -> Any:  # noqa: ARG002
                    return self._sk

            self.key_resolver = _StaticSigningKeyResolver(self.signing_key)

        if self.key_resolver is None:
            from tenuo.exceptions import ConfigurationError

            raise ConfigurationError(
                "TenuoPluginConfig requires key_resolver= or signing_key= (worker signing material)."
            )

        if self.approval_handler is not None:
            # Auto-consume trusted_approvers from the handler when the user
            # did not set them explicitly.  This avoids the redundant:
            #   handler = my_approval_handler(...)
            #   config = TenuoPluginConfig(..., trusted_approvers=handler.trusted_approvers)
            # The user can still override by passing trusted_approvers= explicitly.
            if self.trusted_approvers is None:
                _handler_approvers = getattr(self.approval_handler, "trusted_approvers", None)
                if _handler_approvers is not None:
                    resolved = list(_handler_approvers() if callable(_handler_approvers) else _handler_approvers)
                    if resolved:
                        self.trusted_approvers = resolved
                        logger.debug(
                            "TenuoPluginConfig: auto-resolved %d trusted_approvers from approval_handler",
                            len(resolved),
                        )

            if self.retry_pop_max_windows is None or self.retry_pop_max_windows <= 5:
                logger.info(
                    "TenuoPluginConfig: approval_handler set — retry_pop_max_windows=%s is tight for "
                    "human-in-the-loop; using 240 (~2 h PoP slack on activity retries). "
                    "Set retry_pop_max_windows explicitly to override.",
                    self.retry_pop_max_windows,
                )
                self.retry_pop_max_windows = 240

        if self.trusted_roots_refresh_interval_secs is not None:
            if self.trusted_roots_refresh_interval_secs <= 0:
                from tenuo.exceptions import ConfigurationError
                raise ConfigurationError(
                    "trusted_roots_refresh_interval_secs must be positive when set."
                )
            if self.trusted_roots_provider is None:
                from tenuo.exceptions import ConfigurationError
                raise ConfigurationError(
                    "trusted_roots_refresh_interval_secs requires trusted_roots_provider."
                )

        self._activity_registry: Dict[str, Callable] = {}
        if self.activity_fns:
            for fn in self.activity_fns:
                name = getattr(fn, "__temporal_activity_definition", None)
                if name and hasattr(name, "name"):
                    self._activity_registry[name.name] = fn
                else:
                    self._activity_registry[getattr(fn, "__name__", str(fn))] = fn


# =============================================================================
# Client Interceptor — injects Tenuo headers into workflow start
# =============================================================================


class TenuoClientInterceptor(_TemporalClientInterceptor):
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

        # Before starting a workflow, bind headers to a workflow ID:
        client_interceptor.set_headers_for_workflow(
            "wf-123",
            tenuo_headers(warrant, key_id),
        )

        await client.execute_workflow(MyWorkflow.run, ...)
    """

    def __init__(self) -> None:
        super().__init__()
        # One-shot headers for the next workflow start (legacy API).
        self._next_headers: Dict[str, bytes] = {}
        # Preferred API: deterministic mapping by workflow ID.
        self._headers_by_workflow_id: Dict[str, Dict[str, bytes]] = {}
        self._lock = threading.Lock()

    def set_headers(self, headers: Dict[str, bytes]) -> None:
        """Set one-shot headers for the next workflow start.

        This legacy API is consumed once by the next ``start_workflow`` call.
        For concurrent callers, prefer ``set_headers_for_workflow()``.
        """
        warnings.warn(
            "TenuoClientInterceptor.set_headers() is deprecated for concurrent use. "
            "Use set_headers_for_workflow(workflow_id, headers) or "
            "execute_workflow_authorized(...).",
            DeprecationWarning,
            stacklevel=2,
        )
        with self._lock:
            self._next_headers = dict(headers)

    def set_headers_for_workflow(self, workflow_id: str, headers: Dict[str, bytes]) -> None:
        """Set headers for a specific workflow ID.

        This is concurrency-safe and deterministic for multi-tenant clients.
        The headers are consumed once when that workflow ID is started.
        """
        if not workflow_id:
            raise ValueError("workflow_id must be a non-empty string")
        with self._lock:
            self._headers_by_workflow_id[workflow_id] = dict(headers)

    def clear_headers(self) -> None:
        """Clear all pending headers."""
        with self._lock:
            self._next_headers = {}
            self._headers_by_workflow_id.clear()

    async def execute_workflow_authorized(
        self,
        client: Any,
        workflow_run_fn: Any,
        *,
        workflow_id: str,
        warrant: Any,
        key_id: str,
        args: Optional[List[Any]] = None,
        compress: bool = True,
        **execute_kwargs: Any,
    ) -> Any:
        """Bind headers and execute a workflow in one call.

        This helper is the safest way to start authorized workflows from shared
        clients because it binds headers to a specific workflow ID before the
        start request is issued.
        """
        return await execute_workflow_authorized(
            client=client,
            client_interceptor=self,
            workflow_run_fn=workflow_run_fn,
            workflow_id=workflow_id,
            warrant=warrant,
            key_id=key_id,
            args=args,
            compress=compress,
            **execute_kwargs,
        )

    # --- Temporal client interceptor interface ---

    def intercept_client(self, next_interceptor: Any) -> Any:
        """Return outbound wrapper; duck-types as ``OutboundInterceptor`` via delegation."""
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
        workflow_id: str = getattr(input, "id", None) or ""

        selected_headers: Dict[str, bytes] = {}
        with self._parent._lock:
            # Prefer explicit workflow-ID binding when available.
            if workflow_id and workflow_id in self._parent._headers_by_workflow_id:
                selected_headers = self._parent._headers_by_workflow_id.pop(workflow_id)
            # Fallback: consume one-shot "next workflow" headers.
            elif self._parent._next_headers:
                selected_headers = self._parent._next_headers
                self._parent._next_headers = {}

        if selected_headers:
            try:
                from temporalio.api.common.v1 import Payload  # type: ignore
            except ImportError:
                raise TenuoContextError("temporalio not installed")

            raw_store: Dict[str, bytes] = {}

            for k, v in selected_headers.items():
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


async def execute_workflow_authorized(
    *,
    client: Any,
    client_interceptor: TenuoClientInterceptor,
    workflow_run_fn: Any,
    workflow_id: str,
    warrant: Any,
    key_id: str,
    args: Optional[List[Any]] = None,
    compress: bool = True,
    **execute_kwargs: Any,
) -> Any:
    """Execute a workflow with deterministic per-workflow header binding.

    This utility binds Tenuo headers to ``workflow_id`` using
    ``set_headers_for_workflow`` and immediately invokes
    ``client.execute_workflow``.
    """
    if "id" in execute_kwargs:
        raise ValueError(
            "Pass workflow_id via execute_workflow_authorized(..., workflow_id=...). "
            "Do not also pass id= in execute_kwargs."
        )
    client_interceptor.set_headers_for_workflow(
        workflow_id,
        tenuo_headers(warrant, key_id, compress=compress),
    )
    return await client.execute_workflow(
        workflow_run_fn,
        args=args or [],
        id=workflow_id,
        **execute_kwargs,
    )


# =============================================================================
# Header Utilities
# =============================================================================


def tenuo_headers(
    warrant: Any,  # Warrant type from tenuo_core
    key_id: str,
    *,
    compress: bool = True,
) -> Dict[str, bytes]:
    """Create headers dict for starting a workflow with Tenuo authorization.

    Args:
        warrant: The warrant authorizing this workflow
        key_id: Identifier for the holder's signing key. The actual signing
            key is resolved at runtime by workers via KeyResolver from secure
            storage (Vault, AWS Secrets Manager, GCP Secret Manager, etc.).
        compress: Whether to gzip compress the warrant (default: True)

    Returns:
        Headers dict to pass to client.start_workflow()

    Security:
        **CRITICAL**: Private keys are NEVER transmitted in headers. Workers
        resolve keys from secure storage using the key_id. This ensures:
        - Keys never leave secure boundaries (HSM, KMS, Vault)
        - Keys are not persisted in Temporal's database
        - Keys are not transmitted over the network
        - Compliance with NIST SP 800-57, OWASP, SOC2 requirements

    Example:
        # Client side - only passes key_id
        await client.start_workflow(
            MyWorkflow.run,
            args=[...],
            headers=tenuo_headers(warrant, "prod-agent-2024"),
        )

        # Worker side - resolves key from Vault
        config = TenuoPluginConfig(
            key_resolver=VaultKeyResolver(url="https://vault.company.com"),
        )
    """
    # Defensive check: reject SigningKey objects passed as key_id.
    # key_id must be a plain string identifier, never a key object.
    try:
        from tenuo_core import SigningKey
        if isinstance(key_id, SigningKey):
            raise TypeError(
                "key_id must be a string identifier, not a SigningKey. "
                "Private keys must never be transmitted in headers. "
                "Use a string key ID and configure KeyResolver on workers."
            )
    except ImportError:
        pass
    if not isinstance(key_id, str):
        raise TypeError(
            f"key_id must be a string identifier, got {type(key_id).__name__}. "
            "Private keys must never be transmitted in headers."
        )

    # Serialize warrant to raw CBOR bytes for ``x-tenuo-warrant``.
    warrant_bytes = bytes(warrant.to_bytes())

    headers: Dict[str, bytes] = {
        TENUO_KEY_ID_HEADER: key_id.encode("utf-8"),
        TENUO_WIRE_FORMAT_HEADER: _TEMPORAL_WARRANT_ENCODING_VERSION,
    }

    if compress:
        compressed = gzip.compress(warrant_bytes, compresslevel=9)
        headers[TENUO_WARRANT_HEADER] = compressed
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
    summary: Optional[str] = None,
) -> Any:
    """Execute an activity with automatic function-reference registration.

    This is a wrapper around ``workflow.execute_activity()`` with one
    additional behaviour: it stores the activity function reference in
    ``_pending_activity_fn`` before dispatch, so the outbound interceptor
    can resolve real Python parameter names for PoP signing.

    **When to use it:** if your warrant uses named field constraints
    (e.g. ``path=Subpath(...)``) and you have not set ``activity_fns``
    on ``TenuoPluginConfig``, call via ``tenuo_execute_activity()`` to
    ensure the interceptor signs with ``{"path": ...}`` instead of
    ``{"arg0": ...}``.  Setting ``activity_fns`` on the config is the
    simpler alternative for the same effect.

    For most workflows, ``workflow.execute_activity()`` works identically.

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
                # Both work - use standard Temporal API:
                return await workflow.execute_activity(
                    read_file,
                    args=["/data/report.txt"],
                    start_to_close_timeout=timedelta(seconds=30),
                )
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

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
    if summary is not None:
        activity_kwargs["summary"] = summary

    # Store function reference so outbound interceptor can inspect parameters
    wf_id = workflow.info().workflow_id
    with _store_lock:
        _pending_activity_fn[wf_id] = activity

    try:
        return await workflow.execute_activity(activity, **activity_kwargs)
    finally:
        with _store_lock:
            _pending_activity_fn.pop(wf_id, None)


def set_activity_approvals(approvals: List[Any]) -> None:
    """Pre-supply signed approvals for the next activity execution.

    Call this from a workflow before ``workflow.execute_activity()`` when
    the warrant has guards that require approval.  The outbound interceptor
    encodes them into activity headers and the inbound interceptor uses
    them to satisfy the guard check.

    Approvals are consumed on the next activity dispatch (one-shot).

    Args:
        approvals: List of ``SignedApproval`` objects.

    Example::

        set_activity_approvals([signed_approval])
        await workflow.execute_activity(
            delete_file, args=["/etc/config"],
            start_to_close_timeout=timedelta(seconds=30),
        )
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available")

    wf_id = workflow.info().workflow_id
    with _store_lock:
        _pending_activity_approvals[wf_id] = list(approvals)


def _check_subpath_not_widened(
    tool: str,
    field: str,
    parent_val: Any,
    child_val: Any,
    warrant_id: str,
) -> None:
    """Raise TemporalConstraintViolation if child_val is a wider Subpath than parent_val.

    This is a Python-layer belt-and-suspenders check before passing to
    tenuo_core.attenuate().  Rust is the authoritative enforcer; this gives a
    clear, typed error message rather than a raw FFI exception.

    Only Subpath values are checked here — other constraint types (Pattern,
    Exact, Range, …) are entirely Rust's domain.
    """
    try:
        from tenuo_core import Subpath as _Subpath  # type: ignore[import-not-found]
    except ImportError:
        return  # Rust unavailable; attenuate() will catch it

    if not (isinstance(parent_val, _Subpath) and isinstance(child_val, _Subpath)):
        return

    parent_root: str = parent_val.root()
    child_root: str = child_val.root()

    # A child Subpath is narrower iff it starts with the parent path.
    # e.g. parent="/data/" child="/data/reports/" → OK
    #      parent="/data/" child="/"              → widening → reject
    if not child_root.startswith(parent_root):
        raise TemporalConstraintViolation(
            tool=tool,
            arguments={},
            constraint=(
                f"Constraint '{field}' would widen parent Subpath '{parent_root}' "
                f"to '{child_root}'. Child constraints must be equal or narrower."
            ),
            warrant_id=warrant_id,
        )


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
        TemporalConstraintViolation: If requested tools exceed parent scope
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
            raise TemporalConstraintViolation(
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

    # Retrieve key_id from workflow headers store
    # (Same pattern as tenuo_execute_activity)
    with _store_lock:
        raw_headers = _workflow_headers_store.get(wf_id, {})
        config_store_entry = _workflow_config_store.get(wf_id)

    if not raw_headers:
        raise TenuoContextError(
            "No Tenuo headers in store. Ensure TenuoPlugin is "
            "registered and tenuo_headers() was passed at workflow start."
        )

    if not config_store_entry:
        raise TenuoContextError(
            "No interceptor config found. Ensure TenuoPlugin is registered."
        )

    parent_key_id = raw_headers.get(TENUO_KEY_ID_HEADER, b"").decode("utf-8")
    if not parent_key_id:
        raise TenuoContextError(
            "No key_id found in parent workflow headers."
        )

    # Resolve signing key from secure storage via KeyResolver
    config = config_store_entry
    if not config.key_resolver:
        raise TenuoContextError(
            "key_resolver not configured in TenuoPluginConfig. "
            "Required for child workflow delegation."
        )

    try:
        # Use resolve_sync() to safely handle event loop (may be in Temporal workflow)
        signer = config.key_resolver.resolve_sync(parent_key_id)
    except Exception as e:
        raise TenuoContextError(
            f"Failed to resolve signing key for '{parent_key_id}': {e}"
        )

    # Build capabilities dict: start from parent's per-tool constraints,
    # then overlay any caller-supplied narrowing constraints.
    parent_caps = parent_warrant.capabilities or {}
    extra = constraints or {}
    capabilities = {}
    for tool_key in tools:
        base = dict(parent_caps.get(tool_key, {}))
        narrowing = extra.get(tool_key, {})
        # F4: give a clear Python-level error if the caller introduces a
        # constraint key that does not exist in the parent.  Widening of
        # existing keys is still caught by tenuo_core.attenuate(), but
        # introducing *unknown* keys surfaces a confusing FFI error without
        # this check.
        unknown_keys = set(narrowing) - set(base)
        if unknown_keys:
            raise TemporalConstraintViolation(
                tool=tool_key,
                arguments={},
                constraint=(
                    f"Cannot introduce constraint keys not present in parent warrant: "
                    f"{sorted(unknown_keys)}.  Only existing constraint keys may be "
                    "narrowed in a child warrant."
                ),
                warrant_id=parent_warrant.id,
            )
        # Belt-and-suspenders: check Subpath values at the Python layer so
        # widening produces a clear error before reaching the FFI boundary.
        # Rust attenuate() is the authoritative check; this is an early signal.
        for field_name, new_val in narrowing.items():
            parent_val = base.get(field_name)
            _check_subpath_not_widened(tool_key, field_name, parent_val, new_val, parent_warrant.id)
        base.update(narrowing)
        capabilities[tool_key] = base

    child_warrant = parent_warrant.attenuate(
        capabilities=capabilities,
        signing_key=signer,
        ttl_seconds=ttl_seconds,
    )

    # Use parent key_id if not specified
    key_id = child_key_id or parent_key_id

    hdrs = tenuo_headers(child_warrant, key_id, compress=compress)

    # Propagate the delegation chain: WarrantStack (CBOR array of warrants,
    # base64url-encoded), stored as UTF-8 bytes.
    existing_chain_raw = raw_headers.get(TENUO_CHAIN_HEADER)
    from tenuo_core import decode_warrant_stack_base64 as _decode_stack
    from tenuo_core import encode_warrant_stack as _encode_stack

    if existing_chain_raw:
        existing_warrants = _decode_stack(existing_chain_raw.decode("utf-8"))
    else:
        existing_warrants = [parent_warrant]

    all_chain = existing_warrants + [child_warrant]
    hdrs[TENUO_CHAIN_HEADER] = _encode_stack(all_chain).encode("utf-8")

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

    try:
        return await workflow.execute_child_workflow(workflow_fn, **kwargs)
    finally:
        # Clean up pending headers regardless of success or failure.
        # On success the outbound interceptor already consumed the entry
        # via pop(); this handles the case where the child never started.
        with _store_lock:
            _pending_child_headers.pop(child_id, None)


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
        TemporalConstraintViolation: If tool not in parent warrant
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    parent_warrant = current_warrant()

    parent_tools = parent_warrant.tools or []
    if tool not in parent_tools:
        raise TemporalConstraintViolation(
            tool=tool,
            arguments={},
            constraint=f"Tool '{tool}' not in parent warrant capabilities",
            warrant_id=parent_warrant.id,
        )

    wf_id = workflow.info().workflow_id
    with _store_lock:
        raw_headers = _workflow_headers_store.get(wf_id, {})
        config_store_entry = _workflow_config_store.get(wf_id)

    if not raw_headers:
        raise TenuoContextError(
            "No Tenuo headers in store. Ensure TenuoPlugin is "
            "registered and tenuo_headers() was passed at workflow start."
        )

    if not config_store_entry:
        raise TenuoContextError(
            "No interceptor config found. Ensure TenuoPlugin is registered."
        )

    key_id = raw_headers.get(TENUO_KEY_ID_HEADER, b"").decode("utf-8")
    if not key_id:
        raise TenuoContextError(
            "No key_id found in workflow headers. Cannot issue attenuated grant."
        )

    # Resolve signing key from secure storage via KeyResolver
    config = config_store_entry
    if not config.key_resolver:
        raise TenuoContextError(
            "key_resolver not configured in TenuoPluginConfig. "
            "Required for attenuated grants."
        )

    try:
        # Use resolve_sync() to safely handle event loop (may be in Temporal workflow)
        signer = config.key_resolver.resolve_sync(key_id)
    except Exception as e:
        raise TenuoContextError(f"Failed to resolve signing key for '{key_id}': {e}")

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

    ``x-tenuo-warrant`` must be raw CBOR (optionally gzip-compressed when
    ``x-tenuo-compressed`` is ``1``). Payloads that are not valid warrant CBOR
    raise ``ChainValidationError``.

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
        is_compressed = headers.get(TENUO_COMPRESSED_HEADER, b"0") == b"1"

        if is_compressed:
            cbor_bytes = _gzip_decompress_limited(raw)
        else:
            cbor_bytes = raw
            if len(cbor_bytes) > _WARRANT_DECOMPRESS_MAX_BYTES:
                raise ValueError(
                    f"Warrant payload too large: {len(cbor_bytes)} bytes "
                    f"(limit {_WARRANT_DECOMPRESS_MAX_BYTES})"
                )
        return Warrant.from_bytes(cbor_bytes)

    except (ValueError, EOFError, gzip.BadGzipFile, UnicodeDecodeError, binascii.Error) as e:
        raise ChainValidationError(
            reason=f"Failed to deserialize warrant: {e}",
            depth=0,
        )
    except ChainValidationError:
        raise
    except Exception:
        # Propagate unexpected errors (MemoryError, etc.) without re-labelling
        # them as chain validation failures — the caller handles unknown exceptions.
        raise


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
    """Convenience base class for Tenuo-authorized workflows.

    **What it provides:** validates that Tenuo warrant headers are present at
    workflow *start* (fail-fast), then exposes ``execute_authorized_activity()``
    as a named alias for ``workflow.execute_activity()``.

    **What it does not change:** TenuoPlugin enforces authorization on *every*
    activity regardless of which base class you use.  AuthorizedWorkflow adds no
    security guarantee beyond what the interceptor already provides — it only
    surfaces missing-header errors earlier (at workflow start vs at the first
    activity dispatch).

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
            headers=tenuo_headers(warrant, "agent-key-1"),
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
            TemporalConstraintViolation: If activity violates warrant constraints
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


def _warrant_tool_name_for_activity_type(
    config: Optional["TenuoPluginConfig"],
    activity_type: str,
    activity_fn: Optional[Any],
) -> str:
    """Map Temporal activity type to warrant / PoP tool name (inbound + outbound must agree)."""
    default_tool = activity_type
    if activity_fn is not None:
        default_tool = get_tool_name(activity_fn, activity_type)
    if config is None:
        return default_tool
    return config.tool_mappings.get(activity_type, default_tool)


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


def _args_dict_uses_only_positional_fallback_keys(args_dict: Dict[str, Any]) -> bool:
    """True if every key is arg0, arg1, ... (PoP positional fallback)."""
    if not args_dict:
        return False
    for k in args_dict:
        if not (k.startswith("arg") and k[3:].isdigit()):
            return False
    return True


def _warrant_tool_has_non_empty_field_constraints(warrant: Any, tool_name: str) -> bool:
    """True if the warrant attaches at least one field-level constraint to this tool."""
    try:
        gc = getattr(warrant, "get_constraints", None)
        if callable(gc):
            c = gc(tool_name)
            if isinstance(c, dict) and len(c) > 0:
                return True
    except Exception:
        pass
    try:
        caps = getattr(warrant, "capabilities", None)
        if isinstance(caps, dict):
            fields = caps.get(tool_name)
            if isinstance(fields, dict) and len(fields) > 0:
                return True
    except Exception:
        pass
    return False


def _positional_pop_mismatch_message(
    tool_name: str,
    *,
    strict_mode: bool,
) -> str:
    action = "configured incorrectly" if not strict_mode else "blocked (strict_mode=True)"
    return (
        f"PoP signing for activity {tool_name!r} uses positional argument keys "
        f"(arg0, arg1, ...) but this warrant has named field constraints for that "
        f"tool. Constraint and PoP verification expect real parameter names "
        f"(e.g. path=...), not argN. Worker {action}: pass "
        f"activity_fns=<same list as Worker(activities=...)> in TenuoPluginConfig, "
        f"or call the activity via tenuo_execute_activity() so the function "
        f"reference is available. See tenuo.temporal module docstring: "
        f"'Activity registry (activity_fns) and PoP argument names'."
    )


class _TenuoWorkflowOutboundInterceptor:
    """Outbound workflow interceptor — transparently computes and injects PoP.

    This interceptor makes Tenuo authorization completely transparent.
    When ``workflow.execute_activity()`` is called (standard Temporal API),
    this interceptor automatically:
    1. Retrieves the warrant and key_id from workflow headers, resolves signing key via KeyResolver
    2. Computes the Proof-of-Possession signature using deterministic time
    3. Injects warrant + PoP into activity headers

    No special wrapper functions needed — works with standard Temporal code.
    This follows the OpenTelemetry pattern: add interceptor, everything works.
    """

    def __init__(self, next_outbound: Any, config: Optional["TenuoPluginConfig"] = None) -> None:
        self._next = next_outbound
        self.__dict__["_config"] = config

    def __getattr__(self, name: str) -> Any:
        return getattr(self._next, name)

    def start_activity(self, input: Any) -> Any:
        """Transparently compute and inject PoP for every activity.

        This is the key to transparent authorization. Standard
        workflow.execute_activity() calls go through this interceptor,
        which computes PoP inline with no queue machinery needed.
        """
        import inspect

        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        try:
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.start_activity(input)

        try:
            wf_id = _wf.info().workflow_id
            activity_type = input.activity

            # Pop pending approvals at dispatch time regardless of whether we
            # have a warrant. This guarantees they are consumed on the current
            # activity attempt and cannot silently carry over to a later activity
            # if this dispatch is skipped (branch, validation error, etc.).
            with _store_lock:
                pending_approvals = _pending_activity_approvals.pop(wf_id, None)

            # Read warrant and key_id from headers store.
            # We take a dict() *snapshot* under the lock so the local copy is
            # independent of any concurrent _workflow_headers_store.pop() calls.
            # bytes values are immutable, so no further locking is needed for the
            # snapshot itself — there is no TOCTOU gap after the copy is taken.
            with _store_lock:
                raw_headers = dict(_workflow_headers_store.get(wf_id, {}))

            if raw_headers:
                # Extract warrant and key_id
                warrant = _extract_warrant_from_headers(raw_headers)
                key_id_bytes = raw_headers.get(TENUO_KEY_ID_HEADER)

                if warrant and key_id_bytes:
                    key_id = key_id_bytes.decode("utf-8")

                    # Resolve signing key from secure storage via KeyResolver
                    if not self._config or not self._config.key_resolver:
                        raise TenuoContextError(
                            "key_resolver not configured in TenuoPluginConfig. "
                            "Required for PoP signature generation."
                        )

                    # Use resolve_sync() to safely handle event loop (may be in Temporal workflow)
                    signer = self._config.key_resolver.resolve_sync(key_id)

                    # Resolve activity callable (same registry key: Temporal activity type).
                    activity_fn = getattr(input, "fn", None)
                    if activity_fn is None:
                        with _store_lock:
                            activity_fn = _pending_activity_fn.get(wf_id)
                    if activity_fn is None and self._config is not None:
                        activity_fn = self._config._activity_registry.get(activity_type)

                    # Convert positional args to dict for PoP signature.
                    # Resolution order for the activity function reference:
                    #   1. input.fn (Temporal SDK, if available)
                    #   2. _pending_activity_fn (set by tenuo_execute_activity)
                    #   3. config.activity_fns registry (transparent mode)
                    #   4. Positional keys (arg0, arg1, ...)
                    args_dict: Dict[str, Any] = {}
                    raw_args = getattr(input, "args", ())
                    if raw_args:
                        if activity_fn:
                            try:
                                sig = inspect.signature(activity_fn)
                                params = list(sig.parameters.keys())
                                for i, arg in enumerate(raw_args):
                                    if i < len(params):
                                        args_dict[params[i]] = arg
                                    else:
                                        args_dict[f"arg{i}"] = arg
                            except (ValueError, TypeError):
                                for i, arg in enumerate(raw_args):
                                    args_dict[f"arg{i}"] = arg
                        else:
                            # No function reference - use positional keys (consistent with inbound)
                            for i, arg in enumerate(raw_args):
                                args_dict[f"arg{i}"] = arg

                    pop_tool_name = _warrant_tool_name_for_activity_type(
                        self._config, activity_type, activity_fn
                    )

                    if raw_args and _args_dict_uses_only_positional_fallback_keys(
                        args_dict
                    ) and _warrant_tool_has_non_empty_field_constraints(
                        warrant, pop_tool_name
                    ):
                        msg = _positional_pop_mismatch_message(
                            pop_tool_name,
                            strict_mode=bool(
                                self._config and self._config.strict_mode
                            ),
                        )
                        if self._config and self._config.strict_mode:
                            raise TenuoContextError(msg)
                        logger.warning(msg)

                    # ✨ TRANSPARENT POP COMPUTATION ✨
                    # Use workflow.now() for deterministic replay safety.
                    # CRITICAL: timestamp MUST be provided for Temporal workflows
                    # to ensure identical PoP signatures during replay.
                    #
                    # Integer-second precision is intentional: the Rust verifier
                    # buckets time into 30-second windows, so sub-second precision
                    # would not add uniqueness. Dedup keys include activity_id,
                    # which is unique per Temporal dispatch — so two concurrent
                    # activities with identical args do NOT collide in the dedup
                    # store even if they produce the same PoP bytes.
                    timestamp = int(_wf.now().timestamp())
                    pop_signature = warrant.sign(signer, pop_tool_name, args_dict, timestamp)
                    pop_encoded = base64.b64encode(bytes(pop_signature))


                    # Inject all headers into activity
                    activity_headers = dict(input.headers or {})
                    for k, v in raw_headers.items():
                        activity_headers[k] = Payload(data=v)
                    activity_headers[TENUO_POP_HEADER] = Payload(data=pop_encoded)

                    # Include the arg keys used for signing so the inbound
                    # interceptor reconstructs the same dict for verification,
                    # even when it has access to the real function signature.
                    arg_keys_csv = ",".join(args_dict.keys())
                    activity_headers[TENUO_ARG_KEYS_HEADER] = Payload(
                        data=arg_keys_csv.encode("utf-8")
                    )

                    # Forward pre-supplied approvals (set by workflow code
                    # via set_activity_approvals()) so the inbound interceptor
                    # can satisfy guard checks.
                    if pending_approvals:
                        encoded = json.dumps([
                            base64.b64encode(a.to_bytes()).decode("ascii")
                            for a in pending_approvals
                        ])
                        activity_headers[TENUO_APPROVALS_HEADER] = Payload(
                            data=encoded.encode("utf-8")
                        )

                    input = _replace_field(input, "headers", activity_headers)

                    # Temporal Web: activity summary (discoverability in UI)
                    if hasattr(input, "__dataclass_fields__") and "summary" in input.__dataclass_fields__:
                        current_summary = getattr(input, "summary", "") or ""
                        prefix = f"[{TENUO_TEMPORAL_PLUGIN_ID}]"
                        new_summary = (
                            f"{prefix} {current_summary}" if current_summary else f"{prefix} {activity_type}"
                        )
                        input = _replace_field(input, "summary", new_summary)

        except TenuoContextError:
            raise
        except Exception as e:
            # FAIL-CLOSED: Abort the activity instead of proceeding without PoP.
            # Proceeding would let the inbound interceptor see a request with
            # no PoP, which is indistinguishable from a real attack.
            activity = getattr(input, "activity", "<unknown>")
            raise TenuoContextError(
                f"PoP computation failed for activity '{activity}': {e}. "
                f"Activity aborted (fail-closed)."
            ) from e

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

    _config: Optional["TenuoPluginConfig"] = None

    def __init__(self, next_interceptor: Any) -> None:
        self.next = next_interceptor

    def init(self, outbound: Any) -> None:
        # Wrap the outbound interceptor so activity scheduling carries
        # Tenuo headers through Temporal's header propagation.
        self.next.init(_TenuoWorkflowOutboundInterceptor(outbound, self._config))

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

    def _resolve_config(self) -> Optional["TenuoPluginConfig"]:
        from temporalio import workflow as _wf  # type: ignore[import-not-found]

        wf_id = _wf.info().workflow_id
        with _store_lock:
            return _workflow_config_store.get(wf_id)

    async def handle_signal(self, input: Any) -> None:
        config = self._resolve_config()
        if config and config.authorized_signals is not None:
            signal_name = getattr(input, "signal", None)
            if signal_name not in config.authorized_signals:
                logger.warning(
                    f"Signal '{signal_name}' denied: not in authorized_signals"
                )
                raise TemporalConstraintViolation(
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
                raise TemporalConstraintViolation(
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
                raise TemporalConstraintViolation(
                    tool=f"update:{update_name}",
                    arguments={},
                    constraint=f"Update not authorized: {update_name}",
                    warrant_id="workflow",
                )
        return await self.next.handle_update_handler(input)


class TenuoPlugin(_TemporalWorkerInterceptor):
    """Temporal Python SDK Plugin: warrant authorization (middleware / security).

    Stable identifier: :data:`TENUO_TEMPORAL_PLUGIN_ID` (``tenuo.TenuoTemporalPlugin``)
    for worker logs and Temporal Web activity summaries. Prefer
    :class:`tenuo.temporal_plugin.TenuoTemporalPlugin` for ``Client``/``Worker``
    ``plugins=[...]`` registration (Temporal AI Partner Ecosystem).

    Intercepts activity execution and verifies the calling workflow
    has a valid warrant authorizing the activity.

    Important: The worker **must** configure ``tenuo`` and ``tenuo_core``
    as passthrough modules in the workflow sandbox.  Without this, PoP
    verification will fail.  See the module docstring for details.

    Example::

        from temporalio.worker.workflow_sandbox import (
            SandboxedWorkflowRunner, SandboxRestrictions,
        )

        activities = [read_file, write_file]
        interceptor = TenuoPlugin(
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                on_denial="raise",
                trusted_roots=[control_key.public_key],
                activity_fns=activities,
            )
        )

        worker = Worker(
            client,
            task_queue="my-queue",
            workflows=[MyWorkflow],
            activities=activities,
            interceptors=[interceptor],
            workflow_runner=SandboxedWorkflowRunner(
                restrictions=SandboxRestrictions.default.with_passthrough_modules(
                    "tenuo", "tenuo_core",
                )
            ),
        )
    """

    def __init__(self, config: TenuoPluginConfig) -> None:
        super().__init__()
        if config.control_plane is None:
            from .control_plane import get_or_create
            config.control_plane = get_or_create()
        self._config = config
        self._version = self._get_version()
        # Verify tenuo_core is importable in the current process.
        # Note: this check runs in the MAIN process (not in the Temporal workflow
        # sandbox) and only catches the case where tenuo_core is completely absent
        # from the environment.  It does NOT detect a missing passthrough_modules
        # configuration — that error manifests later, as a workflow task failure on
        # the first workflow execution.  See the "Sandbox passthrough explained"
        # section in docs/temporal.md for the full failure sequence.
        try:
            import tenuo_core as _tc  # noqa: F401
        except ImportError as _e:
            raise RuntimeError(
                "tenuo_core is not installed. "
                "Install tenuo with the native extension: pip install 'tenuo[temporal]'.\n\n"
                "If tenuo_core is installed but you are seeing a PyO3 sandbox error, "
                "ensure passthrough_modules are declared on the worker:\n\n"
                "    SandboxRestrictions.default.with_passthrough_modules('tenuo', 'tenuo_core')\n\n"
                "See the module docstring for a full Worker setup example."
            ) from _e

        logger.info(
            "Loaded %s (warrant authorization middleware for Temporal Python SDK)",
            TENUO_TEMPORAL_PLUGIN_ID,
        )

    def __repr__(self) -> str:
        return f"<{TENUO_TEMPORAL_PLUGIN_ID}>"

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
    ) -> Any:
        """Return activity inbound wrapper; duck-types as ``ActivityInboundInterceptor``."""
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

        A new subclass is created for every ``TenuoPlugin`` instance so
        that two interceptors with different configs (e.g. different
        ``trusted_roots`` for different task queues) cannot accidentally
        share or overwrite each other's configuration (F3).
        """
        # F3: create a per-instance subclass so the class-level _config
        # is not shared across multiple TenuoPlugin instances.
        bound_config = self._config
        interceptor_cls = type(
            "_TenuoWorkflowInboundInterceptor",
            (_TenuoWorkflowInboundInterceptor,),
            {"_config": bound_config},
        )
        return interceptor_cls


class TenuoActivityInboundInterceptor:
    """Activity-level interceptor that performs authorization checks."""

    def __init__(
        self,
        next_interceptor: Any,
        config: TenuoPluginConfig,
        version: str,
    ) -> None:
        self._next = next_interceptor
        self._config = config
        self._version = version
        self._pop_dedup_store: PopDedupStore = (
            config.pop_dedup_store or _default_pop_dedup_store
        )
        if config.pop_dedup_store is None:
            logger.warning(
                "TenuoPluginConfig: using in-memory PopDedupStore (single-process only). "
                "In multi-worker deployments, PoP replays from other workers will not be "
                "detected. Set pop_dedup_store= to a shared backend (Redis, Memcached, "
                "etc.) for fleet-wide replay prevention."
            )
        self._trusted_roots_provider = config.trusted_roots_provider
        self._trusted_roots_refresh_interval = config.trusted_roots_refresh_interval_secs
        import time as _time

        self._last_trusted_roots_refresh = _time.monotonic()
        self._authorizer_lock = threading.Lock()
        self._authorizer: Optional[Any] = None
        self._retry_authorizer: Optional[Any] = None
        try:
            from tenuo_core import Authorizer
            self._authorizer = Authorizer(trusted_roots=config.trusted_roots)
            if config.retry_pop_max_windows is not None:
                self._retry_authorizer = Authorizer(
                    trusted_roots=config.trusted_roots,
                    pop_max_windows=config.retry_pop_max_windows,
                )
        except ImportError as e:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "tenuo_core is required for TenuoPlugin (Authorizer). "
                "Install tenuo with the native extension, or ensure the "
                "interpreter can import tenuo_core."
            ) from e

    def _maybe_refresh_trusted_roots(self) -> None:
        """Rebuild Authorizer from ``trusted_roots_provider`` on a fixed interval."""
        import time as _time

        p = self._trusted_roots_provider
        interval = self._trusted_roots_refresh_interval
        if p is None or interval is None:
            return
        now = _time.monotonic()
        if (now - self._last_trusted_roots_refresh) < interval:
            return
        with self._authorizer_lock:
            now2 = _time.monotonic()
            if (now2 - self._last_trusted_roots_refresh) < interval:
                return
            try:
                roots = list(p())
            except Exception as e:
                logger.warning("trusted_roots_provider failed during refresh: %s", e)
                return
            if not roots:
                logger.warning(
                    "trusted_roots_provider returned empty during refresh; "
                    "keeping prior Authorizer"
                )
                return
            try:
                from tenuo_core import Authorizer

                self._authorizer = Authorizer(trusted_roots=roots)
                if self._config.retry_pop_max_windows is not None:
                    self._retry_authorizer = Authorizer(
                        trusted_roots=roots,
                        pop_max_windows=self._config.retry_pop_max_windows,
                    )
            except Exception as e:
                logger.warning(
                    "Authorizer rebuild failed during trusted root refresh: %s", e
                )
                return
            self._last_trusted_roots_refresh = _time.monotonic()

    def init(self, outbound: Any) -> None:
        """Called by Temporal to initialize the interceptor with an outbound impl."""
        self._next.init(outbound)

    @staticmethod
    def _wrap_as_non_retryable(exc: Exception) -> Exception:
        """Wrap authorization failures as non-retryable ApplicationError.

        Temporal's default retry policy retries all non-ApplicationError
        exceptions.  Authorization denials are permanent — retrying the
        same activity with the same warrant will always fail — so we mark
        them non-retryable to avoid wasting resources.
        """
        try:
            from temporalio.exceptions import ApplicationError  # type: ignore[import-not-found]
        except ImportError:
            return exc
        return ApplicationError(
            str(exc),
            type=type(exc).__name__,
            non_retryable=True,
        )

    async def execute_activity(self, input: Any) -> Any:
        """Intercept activity execution for authorization."""
        try:
            from temporalio import activity  # type: ignore[import-not-found]
        except ImportError:
            # If temporalio not available, pass through
            return await self._next.execute_activity(input)

        # Get activity info
        info = activity.info()

        import time
        start_ns = time.perf_counter_ns()
        chain_result = None

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
                raise self._wrap_as_non_retryable(LocalActivityError(info.activity_type))

            # Check if activity is marked @unprotected
            if not is_unprotected(activity_fn):
                raise self._wrap_as_non_retryable(LocalActivityError(info.activity_type))

            # Unprotected local activities skip authorization
            return await self._next.execute_activity(input)

        # --- Read Tenuo headers ---
        # The outbound workflow interceptor transparently computes PoP
        # and injects all Tenuo headers into StartActivityInput.headers
        # as Payloads. These travel through Temporal's standard header
        # propagation and arrive here in input.headers on ANY worker.

        headers: Dict[str, bytes] = {}
        input_headers = getattr(input, "headers", None) or {}
        for k, v in input_headers.items():
            if k.startswith("x-tenuo-"):
                if isinstance(v, bytes):
                    headers[k] = v
                elif hasattr(v, "data") and isinstance(getattr(v, "data", None), bytes):
                    headers[k] = v.data

        # Extract warrant (if present)
        try:
            warrant = _extract_warrant_from_headers(headers)
        except ChainValidationError as chain_exc:
            raise self._wrap_as_non_retryable(chain_exc) from chain_exc

        async def _deny_or_continue(tool: str, reason: str) -> Optional[Any]:
            if self._config.dry_run:
                logger.warning(
                    "DRY-RUN mode: would deny activity %s in workflow %s (%s); "
                    "executing anyway. Not for production.",
                    tool,
                    info.workflow_id,
                    reason,
                )
                return await self._next.execute_activity(input)

            if self._config.on_denial == "log":
                logger.warning(f"Authorization denied for {tool}: {reason}")
            return None

        # If no warrant, check require_warrant config (fail-closed by default)
        if warrant is None:
            if self._config.require_warrant:
                # Fail-closed: deny activities without warrant
                logger.warning(f"No warrant for activity {info.activity_type}, denying (require_warrant=True)")
                if self._config.on_denial == "raise" and not self._config.dry_run:
                    raise self._wrap_as_non_retryable(TemporalConstraintViolation(
                        tool=info.activity_type,
                        arguments={},
                        constraint="No warrant provided (require_warrant=True)",
                        warrant_id="none",
                    ))
                return await _deny_or_continue(
                    tool=info.activity_type,
                    reason="No warrant provided (require_warrant=True)",
                )
            else:
                # Opt-in mode: allow without warrant
                # This path only runs when require_warrant=False — a deliberate
                # opt-out from the fail-closed guarantee. Already warned at config
                # construction. Log at WARNING (not DEBUG) so these executions are
                # visible in production dashboards.
                logger.warning(
                    "Unauthenticated activity execution: %s in workflow %s "
                    "(require_warrant=False — no warrant presented)",
                    info.activity_type,
                    info.workflow_id,
                )
                return await self._next.execute_activity(input)

        # Resolve tool name (must match outbound PoP / tool_mappings)
        activity_fn = getattr(input, "fn", None)
        tool_name = _warrant_tool_name_for_activity_type(
            self._config, info.activity_type, activity_fn
        )

        # Get activity arguments, using outbound-supplied arg keys for
        # PoP consistency when the outbound lacked the function reference.
        args = self._extract_arguments(input, headers)

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
            if self._config.on_denial == "raise" and not self._config.dry_run:
                raise self._wrap_as_non_retryable(ChainValidationError(
                    reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
                    depth=chain_depth,
                ))
            return await _deny_or_continue(
                tool=tool_name,
                reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
            )

        self._maybe_refresh_trusted_roots()

        if self._authorizer is None:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "Tenuo activity interceptor missing Authorizer; "
                "use TenuoPluginConfig with trusted_roots."
            )

        try:
            from tenuo_core import decode_warrant_stack_base64 as _decode_stack

            # On Temporal retries (attempt > 1), headers are reused from the
            # original ACTIVITY_TASK_SCHEDULED history event — the outbound
            # workflow interceptor is NOT re-invoked.  The PoP timestamp
            # (workflow.now() at first scheduling) therefore becomes stale.
            # With the default pop_max_windows=5 (±60s), any retry happening
            # more than ~90s after first scheduling will fail PoP verification.
            # Use a retry-specific Authorizer with a wider window if configured.
            if info.attempt > 1 and self._retry_authorizer is not None:
                authorizer = self._retry_authorizer
            else:
                if info.attempt > 1:
                    logger.debug(
                        "Activity '%s' is a retry (attempt=%d). If this fails with "
                        "PopVerificationError, set TenuoPluginConfig.retry_pop_max_windows "
                        "to accommodate Temporal's retry time offset (e.g. 120 for 1 hour).",
                        tool_name, info.attempt,
                    )
                authorizer = self._authorizer

            # Extract PoP signature (base64-encoded in headers)
            pop_bytes = None
            pop_header = headers.get(TENUO_POP_HEADER)
            if pop_header:
                pop_bytes = base64.b64decode(pop_header)

            # Approval gate evaluation: collect approvals before authorize
            # so Rust can satisfy the gate atomically with PoP.
            gate_approvals = self._resolve_approval_gate_approvals(
                warrant, tool_name, args, headers,
            )

            chain_header = headers.get(TENUO_CHAIN_HEADER)
            if chain_header:
                # WarrantStack: CBOR array of warrants, base64url-encoded.
                chain = _decode_stack(chain_header.decode("utf-8"))
                chain_result = authorizer.check_chain(
                    chain, tool_name, args,
                    signature=pop_bytes,
                    approvals=gate_approvals,
                )
            else:
                chain_result = authorizer.authorize_one(
                    warrant, tool_name, args,
                    signature=pop_bytes,
                    approvals=gate_approvals,
                )

            # PoP replay detection: reject if the same dedup key
            # was seen within the dedup TTL window.  Skip on
            # Temporal retries (attempt > 1) which reuse the same
            # headers legitimately.
            if info.attempt <= 1:
                base_dedup = warrant.dedup_key(tool_name, args)
                # Include run ID so continue-as-new workflows don't
                # false-positive as PoP replays across runs.
                dedup_key = (
                    f"{base_dedup}:{info.workflow_id}:"
                    f"{info.workflow_run_id}:{info.activity_id}"
                )
                now = datetime.now(timezone.utc).timestamp()
                ttl = float(warrant.dedup_ttl_secs())
                self._pop_dedup_store.check_pop_replay(
                    dedup_key, now, ttl, activity_name=tool_name
                )

        except (TemporalConstraintViolation, PopVerificationError, ChainValidationError, WarrantExpired) as auth_exc:
            raise self._wrap_as_non_retryable(auth_exc) from auth_exc
        except Exception as e:
            # Import the tenuo_core base once; if it is unavailable, fall back
            # to the Python-only TenuoTemporalError hierarchy.
            try:
                from tenuo.exceptions import TenuoError as _TenuoError
            except ImportError:
                _TenuoError = TenuoTemporalError  # type: ignore[assignment, misc]

            if isinstance(e, (_TenuoError, TenuoTemporalError)):
                # Authorization denial from tenuo_core or this module — emit
                # audit event and route through on_denial policy.
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason=str(e),
                )
                if self._config.on_denial == "raise" and not self._config.dry_run:
                    raise self._wrap_as_non_retryable(TemporalConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint=str(e),
                        warrant_id=warrant.id,
                    ))
                return await _deny_or_continue(tool=tool_name, reason=str(e))
            else:
                # Internal / unexpected error (bug, MemoryError, etc.) —
                # always propagate as-is regardless of on_denial.
                logger.error(
                    f"Internal error during authorization for {tool_name}: {e}",
                    exc_info=True,
                )
                raise

        # Authorization passed — emit allow event
        self._emit_allow_event(
            info=info,
            warrant=warrant,
            tool=tool_name,
            args=args,
            start_ns=start_ns,
            chain_result=chain_result,
        )

        # Execute the activity
        return await self._next.execute_activity(input)

    def _resolve_approval_gate_approvals(
        self,
        warrant: Any,
        tool_name: str,
        args: Dict[str, Any],
        headers: Dict[str, bytes],
    ) -> Optional[List[Any]]:
        """Evaluate warrant approval gates and collect approvals when a gate fires.

        Resolution order:
          1. Pre-supplied approvals in ``x-tenuo-approvals`` header
             (base64-encoded JSON list of CBOR-serialized SignedApprovals).
          2. ``approval_handler`` callback on TenuoPluginConfig.
          3. Raise ApprovalGateTriggered (gate fires, no approvals available).

        Returns ``None`` when no gate fires (ungated call).
        """
        from tenuo_core import evaluate_approval_gates as _evaluate_approval_gates

        if not _evaluate_approval_gates(warrant, tool_name, args):
            return None

        # Approval gate fired — try to collect approvals.
        from tenuo_core import SignedApproval as CoreSignedApproval

        # 1. Check header for pre-supplied approvals
        raw_approvals_header = headers.get(TENUO_APPROVALS_HEADER)
        if raw_approvals_header:
            try:
                approvals_list = json.loads(raw_approvals_header)
                return [
                    CoreSignedApproval.from_bytes(base64.b64decode(a))
                    for a in approvals_list
                ]
            except Exception as e:
                logger.warning(f"Failed to decode approvals header: {e}")

        # 2. Try approval_handler callback
        handler = self._config.approval_handler if self._config else None
        if handler is not None:
            try:
                from tenuo_core import py_compute_request_hash as _compute_hash
                from tenuo.approval import ApprovalRequest

                holder_key = getattr(warrant, "holder_key", None)
                warrant_id = getattr(warrant, "id", "") or ""
                request_hash = _compute_hash(warrant_id, tool_name, args, holder_key)
                request = ApprovalRequest.for_warrant_gate(
                    tool_name,
                    args,
                    warrant,
                    request_hash,
                    holder_key=holder_key,
                )

                result = handler(request)
                if _inspect.isawaitable(result):
                    import asyncio
                    from typing import cast, Coroutine as _Coro
                    coro = cast(_Coro[Any, Any, Any], result)
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None
                    if loop and loop.is_running():
                        future = asyncio.run_coroutine_threadsafe(coro, loop)
                        result = future.result(timeout=300)
                    else:
                        result = asyncio.run(coro)

                collected = result if isinstance(result, list) else [result]

                # Verify the approvals locally before forwarding to Rust
                approvers = (
                    self._config.trusted_approvers
                    if self._config and self._config.trusted_approvers
                    else warrant.required_approvers()
                )
                threshold = (
                    self._config.approval_threshold
                    if self._config and self._config.approval_threshold is not None
                    else warrant.approval_threshold()
                )
                # Threshold safety: config must not be weaker than the warrant's own minimum.
                if self._config and self._config.approval_threshold is not None:
                    warrant_min = warrant.approval_threshold()
                    if warrant_min is not None and threshold < warrant_min:
                        raise TemporalConstraintViolation(
                            tool=tool_name,
                            arguments=args,
                            constraint=(
                                f"Config approval_threshold ({threshold}) is less than "
                                f"warrant minimum ({warrant_min})"
                            ),
                            warrant_id=getattr(warrant, "id", ""),
                        )
                from tenuo_core import verify_approvals as _verify
                _verify(request_hash, collected, approvers, threshold)

                return collected
            except Exception:
                raise

        # 3. No approvals available — approval gate fired but cannot be satisfied.
        raise ApprovalGateTriggered(
            tool=tool_name,
            hint=(
                "No approvals available — set approval_handler on "
                "TenuoPluginConfig or supply x-tenuo-approvals header"
            ),
        )

    def _extract_arguments(
        self, input: Any, headers: Optional[Dict[str, bytes]] = None,
    ) -> Dict[str, Any]:
        """Extract arguments from activity input with proper signature mapping.

        When the outbound interceptor includes ``x-tenuo-arg-keys`` (because
        ``StartActivityInput`` lacked the function reference), those keys take
        precedence so the inbound reconstructs the exact same dict that was
        signed.  This guarantees PoP consistency for both
        ``tenuo_execute_activity()`` and plain ``workflow.execute_activity()``.
        """
        import inspect

        args = getattr(input, "args", ())

        # Outbound-supplied arg keys override local resolution so the
        # signed dict and the verified dict always match.
        if headers and TENUO_ARG_KEYS_HEADER in headers:
            keys = headers[TENUO_ARG_KEYS_HEADER].decode("utf-8").split(",")
            result: Dict[str, Any] = {}
            for i, arg in enumerate(args):
                if i < len(keys):
                    result[keys[i]] = arg
                else:
                    result[f"arg{i}"] = arg
            return result

        activity_fn = getattr(input, "fn", None)

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
                pass

        if args and isinstance(args[0], dict):
            return args[0]

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
        start_ns: Optional[int] = None,
        chain_result: Optional[Any] = None,
    ) -> None:
        """Emit audit event for allowed action."""
        if self._config.control_plane:
            import time
            from tenuo._enforcement import EnforcementResult
            latency_us = int((time.perf_counter_ns() - start_ns) / 1000) if start_ns else 0

            res = EnforcementResult(
                allowed=True,
                tool=tool,
                arguments=args,
                warrant_id=getattr(warrant, "id", None)
            )
            try:
                self._config.control_plane.emit_for_enforcement(
                    res, chain_result=chain_result, latency_us=latency_us
                )
            except Exception:
                logger.warning("Control plane emission failed for '%s'; audit event lost", tool, exc_info=True)

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
        start_ns: Optional[int] = None,
    ) -> None:
        """Emit audit event for denied action."""
        if self._config.control_plane:
            import time
            from tenuo._enforcement import EnforcementResult
            latency_us = int((time.perf_counter_ns() - start_ns) / 1000) if start_ns else 0

            # Encode single-warrant stack for the denial event so the control
            # plane can reconstruct chain context even without a full check_chain result.
            warrant_stack_b64 = None
            try:
                from tenuo_core import encode_warrant_stack
                warrant_stack_b64 = encode_warrant_stack([warrant])
            except Exception:
                pass

            res = EnforcementResult(
                allowed=False,
                tool=tool,
                arguments=args,
                denial_reason=reason,
                constraint_violated=constraint,
                warrant_id=getattr(warrant, "id", None),
            )
            try:
                self._config.control_plane.emit_for_enforcement(
                    res, chain_result=None, latency_us=latency_us,
                    warrant_stack_override=warrant_stack_b64,
                )
            except Exception:
                logger.warning("Control plane emission failed for '%s'; audit event lost", tool, exc_info=True)

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


def __getattr__(name: str) -> Any:
    """Lazy exports that depend on ``temporalio.plugin`` (avoid import cycles)."""
    if name == "TenuoTemporalPlugin":
        from tenuo.temporal_plugin import TenuoTemporalPlugin

        return TenuoTemporalPlugin
    if name == "ensure_tenuo_workflow_runner":
        from tenuo.temporal_plugin import ensure_tenuo_workflow_runner

        return ensure_tenuo_workflow_runner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Exceptions
    "TenuoTemporalError",
    "TenuoContextError",
    "TemporalConstraintViolation",
    "WarrantExpired",
    "ChainValidationError",
    "KeyResolutionError",
    # Phase 2 exceptions
    "LocalActivityError",
    "PopVerificationError",
    "ApprovalGateTriggered",
    # Audit
    "TemporalAuditEvent",
    # PoP dedup (horizontal workers)
    "PopDedupStore",
    "InMemoryPopDedupStore",
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
    "TenuoPluginConfig",
    # Interceptors
    "TenuoPlugin",
    "TenuoClientInterceptor",
    "TenuoActivityInboundInterceptor",
    # Header utilities
    "tenuo_headers",
    "attenuated_headers",  # Phase 3
    # Workflow helpers
    "tenuo_execute_activity",
    "execute_workflow_authorized",
    "tenuo_execute_child_workflow",
    "set_activity_approvals",
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
    "TENUO_COMPRESSED_HEADER",
    "TENUO_CHAIN_HEADER",
    "TENUO_WIRE_FORMAT_HEADER",
    "TENUO_APPROVALS_HEADER",
    "TENUO_TEMPORAL_PLUGIN_ID",
    "TenuoTemporalPlugin",
    "ensure_tenuo_workflow_runner",
]
