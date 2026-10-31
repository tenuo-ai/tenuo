"""Audit events, metrics, and internal request types for Tenuo-Temporal."""

from __future__ import annotations

import dataclasses as _dataclasses
import logging
import queue
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Literal, Optional, Union

logger = logging.getLogger("tenuo.temporal")


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
    # ``tenuo_core.Warrant.expires_at()`` returns an RFC 3339 string, while
    # callers constructing audit events directly have historically supplied a
    # datetime.  Accept both representations at this public serialization
    # boundary so real warrants and existing integrations remain compatible.
    warrant_expires_at: Optional[Union[datetime, str]]
    warrant_capabilities: List[str]

    # Denial details (populated if denied)
    denial_reason: Optional[str] = None
    constraint_violated: Optional[str] = None

    # Metadata
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tenuo_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for structured logging."""
        warrant_expires_at = self.warrant_expires_at
        if isinstance(warrant_expires_at, datetime):
            warrant_expires_at = warrant_expires_at.isoformat()

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
            "warrant_expires_at": warrant_expires_at,
            "warrant_capabilities": self.warrant_capabilities,
            "denial_reason": self.denial_reason,
            "constraint_violated": self.constraint_violated,
            "timestamp": self.timestamp.isoformat(),
            "tenuo_version": self.tenuo_version,
        }


class _DroppedSignalAuditDispatcher:
    """Bounded, process-local bridge from workflow code to an audit callback.

    The process-wide dispatcher is constructed by ``TenuoWorkerInterceptor``
    before any workflow runs. ``submit`` only performs a non-blocking queue
    write; the daemon thread invokes user code outside Temporal's workflow sandbox.
    Delivery is intentionally best-effort and the bounded queue prevents an
    untrusted signal sender from causing unbounded worker memory growth.
    """

    _QUEUE_SIZE = 1024

    def __init__(self) -> None:
        self._queue: "queue.Queue[tuple[Callable[[TemporalAuditEvent], None], TemporalAuditEvent]]" = (
            queue.Queue(maxsize=self._QUEUE_SIZE)
        )
        self._overflow_lock = threading.Lock()
        self._overflow_count = 0
        self._thread = threading.Thread(
            target=self._run,
            name="tenuo-temporal-signal-audit",
            daemon=True,
        )
        self._thread.start()

    def submit(
        self,
        callback: Callable[[TemporalAuditEvent], None],
        event: TemporalAuditEvent,
    ) -> bool:
        try:
            self._queue.put_nowait((callback, event))
            return True
        except queue.Full:
            # Never invoke logging handlers from workflow code. They may do
            # blocking file/network I/O and trip Temporal's deadlock detector.
            # The dispatcher coalesces and reports this count from its thread.
            with self._overflow_lock:
                self._overflow_count += 1
            return False

    def _run(self) -> None:
        while True:
            callback, event = self._queue.get()
            self._report_overflow()
            try:
                callback(event)
            except Exception:
                logger.error(
                    "Audit callback failed for dropped %s", event.tool, exc_info=True
                )
            finally:
                self._queue.task_done()

    def _report_overflow(self) -> None:
        with self._overflow_lock:
            count = self._overflow_count
            self._overflow_count = 0
        if count:
            logger.error(
                "Dropped-signal audit queue overflowed; %d audit event(s) lost",
                count,
            )


_dropped_signal_dispatcher_lock = threading.Lock()
_dropped_signal_dispatcher: Optional[_DroppedSignalAuditDispatcher] = None


def _install_dropped_signal_audit_dispatcher(config: Any) -> None:
    """Attach the process-wide dispatcher before workflow execution starts."""
    global _dropped_signal_dispatcher

    if getattr(config, "_dropped_signal_audit_dispatcher", None) is not None:
        return
    with _dropped_signal_dispatcher_lock:
        if _dropped_signal_dispatcher is None:
            _dropped_signal_dispatcher = _DroppedSignalAuditDispatcher()
        config._dropped_signal_audit_dispatcher = _dropped_signal_dispatcher


@_dataclasses.dataclass
class _MintRequest:
    """Serializable request for _tenuo_internal_mint_activity.

    Capabilities are stored in ``_pending_mint_capabilities`` (process-local)
    rather than inline, because PyO3 constraint types (Subpath, Pattern, …)
    cannot survive ``dataclasses.asdict()`` → ``copy.deepcopy()`` which
    Temporal's payload converter uses.  Only the lookup key travels through
    Temporal serialization.
    """

    kind: str  # "attenuate" or "issue_execution"
    parent_warrant_bytes: bytes
    key_id: str
    capabilities_ref: str  # key into _pending_mint_capabilities
    ttl_seconds: Optional[int] = None


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

    # Bound on the in-memory rolling latency window used by :meth:`get_stats`.
    # Prometheus is the real latency store (histogram); this ring is only for
    # the introspection/debug path and must not grow unbounded in long-lived
    # workers.
    _LATENCY_RING_SIZE = 1024

    def __init__(self, prefix: str = "tenuo_temporal") -> None:
        self._prefix = prefix
        self._authorized_count: Dict[str, int] = {}
        self._denied_count: Dict[str, int] = {}
        self._latencies: Deque[float] = deque(maxlen=self._LATENCY_RING_SIZE)

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
        """Get current metrics as a dict (for testing/debugging).

        ``latency_count`` / ``latency_avg`` reflect the last
        ``_LATENCY_RING_SIZE`` recorded latencies, not the lifetime total.
        For production latency analysis, use the Prometheus histogram
        (``<prefix>_authorization_latency_seconds``) instead.
        """
        return {
            "authorized": dict(self._authorized_count),
            "denied": dict(self._denied_count),
            "latency_count": len(self._latencies),
            "latency_avg": (sum(self._latencies) / len(self._latencies) if self._latencies else 0.0),
        }
