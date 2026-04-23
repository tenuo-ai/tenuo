"""Client-side interceptor and context propagation for Tenuo-Temporal."""

from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import time
import warnings
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple

from tenuo.temporal._headers import tenuo_headers
from tenuo.temporal._state import _active_tenuo_warrant
from tenuo.temporal.exceptions import TenuoContextError

logger = logging.getLogger("tenuo.temporal")

_TemporalClientInterceptor: Any
try:
    from temporalio.client import Interceptor as _tc_interceptor

    _TemporalClientInterceptor = _tc_interceptor
except ImportError:  # pragma: no cover
    _TemporalClientInterceptor = object


class TenuoClientInterceptor(_TemporalClientInterceptor):
    """Temporal client interceptor for injecting Tenuo warrant headers.

    This interceptor wraps raw header bytes as ``Payload`` protobufs for
    Temporal and injects them into ``start_workflow``. The worker-side
    ``_TenuoWorkflowInboundInterceptor`` then extracts the payloads and
    populates the run-scoped stores that the outbound interceptor reads.

    Usage::

        client_interceptor = TenuoClientInterceptor()
        client = await Client.connect("localhost:7233",
                                      interceptors=[client_interceptor])

        client_interceptor.set_headers_for_workflow(
            "wf-123",
            tenuo_headers(warrant, key_id),
        )

        await client.execute_workflow(MyWorkflow.run, ...)
    """

    #: Default maximum number of pending ``(workflow_id, headers)`` entries
    #: before the oldest are evicted. Protects long-running clients that bind
    #: headers for workflow ids that never start.
    DEFAULT_PENDING_HEADERS_MAX_SIZE: int = 10_000

    #: Default TTL (seconds) for pending ``(workflow_id, headers)`` entries.
    #: ``None`` disables TTL eviction.
    DEFAULT_PENDING_HEADERS_TTL_SECS: Optional[float] = 3600.0

    def __init__(
        self,
        *,
        pending_headers_max_size: Optional[int] = None,
        pending_headers_ttl_secs: Optional[float] = None,
    ) -> None:
        super().__init__()
        self._next_headers: Dict[str, bytes] = {}
        # ``OrderedDict`` so we can evict oldest-first when the bound grows
        # past ``_pending_headers_max_size``. Entry value is
        # ``(headers, insert_monotonic_time)`` so TTL eviction is cheap.
        self._headers_by_workflow_id: "OrderedDict[str, Tuple[Dict[str, bytes], float]]" = (
            OrderedDict()
        )
        self._lock = threading.Lock()
        self._pending_headers_max_size: int = (
            pending_headers_max_size
            if pending_headers_max_size is not None
            else self.DEFAULT_PENDING_HEADERS_MAX_SIZE
        )
        self._pending_headers_ttl_secs: Optional[float] = (
            pending_headers_ttl_secs
            if pending_headers_ttl_secs is not None
            else self.DEFAULT_PENDING_HEADERS_TTL_SECS
        )

    def _evict_expired_locked(self) -> None:
        """Drop expired pending-header entries. Caller must hold ``self._lock``."""
        ttl = self._pending_headers_ttl_secs
        if ttl is None or not self._headers_by_workflow_id:
            return
        now = time.monotonic()
        expired: List[str] = []
        for wf_id, (_headers, inserted_at) in self._headers_by_workflow_id.items():
            if (now - inserted_at) < ttl:
                # OrderedDict preserves insertion order; once we hit a fresh
                # entry everything after is also fresh.
                break
            expired.append(wf_id)
        for wf_id in expired:
            self._headers_by_workflow_id.pop(wf_id, None)

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

        If the workflow is never started (e.g. the start request fails
        upstream), the entry is retained for up to
        ``pending_headers_ttl_secs`` (default 1h) or until the map reaches
        ``pending_headers_max_size`` (default 10000 entries), whichever
        comes first. This protects long-running clients from unbounded
        growth. Callers can also call :meth:`discard_headers_for_workflow`
        to drop an entry explicitly.
        """
        if not workflow_id:
            raise ValueError("workflow_id must be a non-empty string")
        with self._lock:
            self._evict_expired_locked()
            # Move-to-end semantics so explicit re-binding refreshes the TTL.
            self._headers_by_workflow_id.pop(workflow_id, None)
            self._headers_by_workflow_id[workflow_id] = (
                dict(headers),
                time.monotonic(),
            )
            max_size = self._pending_headers_max_size
            if max_size > 0:
                while len(self._headers_by_workflow_id) > max_size:
                    evicted_id, _ = self._headers_by_workflow_id.popitem(last=False)
                    logger.warning(
                        "TenuoClientInterceptor pending-headers map exceeded "
                        "%d entries; evicting oldest workflow_id=%s. "
                        "Consider calling discard_headers_for_workflow() for "
                        "workflows that never start.",
                        max_size,
                        evicted_id,
                    )

    def discard_headers_for_workflow(self, workflow_id: str) -> bool:
        """Drop any pending headers bound to *workflow_id*.

        Returns ``True`` if an entry was removed. Use when a workflow start
        was aborted upstream and the bound headers would otherwise sit in
        the map until TTL eviction.
        """
        with self._lock:
            return self._headers_by_workflow_id.pop(workflow_id, None) is not None

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
        """Bind headers and execute a workflow in one call."""
        from tenuo.temporal._workflow import execute_workflow_authorized

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

    def intercept_client(self, next_interceptor: Any) -> Any:
        """Return outbound wrapper; duck-types as ``OutboundInterceptor`` via delegation."""
        return _TenuoClientOutbound(next_interceptor, self)


class TenuoWarrantContextPropagator:
    """Thin wrapper over a Python :mod:`contextvars` slot that carries the
    currently-active ``(warrant, key_id)`` across ``await`` boundaries.

    This is **not** a Temporal SDK context propagator — Temporal has no plugin
    hook to register one, and Tenuo does not depend on that mechanism.
    Instead, :class:`~tenuo.temporal._client.TenuoClientInterceptor` reads the
    same contextvar on outbound ``start_workflow`` / ``execute_workflow`` calls
    and attaches Tenuo headers automatically, so plain
    ``client.execute_workflow(...)`` picks up the active warrant without the
    caller having to pass headers explicitly.

    Most users should prefer the :func:`tenuo_warrant_context` context manager
    instead of constructing this directly.

    Example — direct use (uncommon)::

        propagator = TenuoWarrantContextPropagator()
        token = propagator.set(warrant, "agent1")
        try:
            await client.execute_workflow(MyWorkflow.run, ...)
        finally:
            propagator.clear(token)
    """

    def set(self, warrant: Any, key_id: str) -> contextvars.Token:
        """Store *(warrant, key_id)* in the current context; return the token."""
        return _active_tenuo_warrant.set((warrant, key_id))

    def clear(self, token: contextvars.Token) -> None:
        """Restore the previous context state using *token*."""
        _active_tenuo_warrant.reset(token)

    def get(self) -> Optional[tuple]:
        """Return the current *(warrant, key_id)* pair, or ``None``."""
        return _active_tenuo_warrant.get()


@asynccontextmanager
async def tenuo_warrant_context(warrant_or_source: Any, key_id: str):
    """Async context manager for passing a Tenuo warrant to plain ``client.execute_workflow`` calls.

    Sets the module-level :data:`_active_tenuo_warrant` contextvar so that
    ``_TenuoClientOutbound.start_workflow`` picks it up automatically — no need
    to call :func:`execute_workflow_authorized`.

    Example::

        async with tenuo_warrant_context(warrant, "agent1"):
            await client.execute_workflow(MyWorkflow.run, ...)

    Also accepts a ``WarrantSource`` (Phase 1.7 — any object with an async
    ``resolve()`` method returning ``(warrant, key_id)``)::

        async with tenuo_warrant_context(EnvWarrantSource("TENUO_WARRANT"), "agent1"):
            await client.execute_workflow(...)

    Args:
        warrant_or_source: A :class:`~tenuo_core.Warrant` object **or** a
            ``WarrantSource`` with an async ``resolve()`` method.
        key_id: The holder key identifier to embed in headers.

    Yields:
        The resolved :class:`~tenuo_core.Warrant` object.
    """
    if hasattr(warrant_or_source, "resolve") and asyncio.iscoroutinefunction(
        warrant_or_source.resolve
    ):
        warrant, key_id = await warrant_or_source.resolve()
    else:
        warrant = warrant_or_source

    propagator = TenuoWarrantContextPropagator()
    token = propagator.set(warrant, key_id)
    try:
        yield warrant
    finally:
        propagator.clear(token)


class _TenuoClientOutbound:
    """Outbound half of the client interceptor — wraps ``start_workflow``.

    Injects Tenuo headers as ``Payload`` objects into the Temporal
    ``StartWorkflow`` request.  The headers travel through the Temporal
    Server and are extracted on the worker by
    ``_TenuoWorkflowInboundInterceptor``, which keys the internal store
    by ``run_id`` (server-assigned, globally unique) rather than
    ``workflow_id`` (only unique per namespace).
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
            self._parent._evict_expired_locked()
            if workflow_id and workflow_id in self._parent._headers_by_workflow_id:
                selected_headers = self._parent._headers_by_workflow_id.pop(
                    workflow_id
                )[0]
            elif self._parent._next_headers:
                selected_headers = self._parent._next_headers
                self._parent._next_headers = {}

        if not selected_headers:
            _ctx_value = _active_tenuo_warrant.get()
            if _ctx_value is not None:
                _ctx_warrant, _ctx_key_id = _ctx_value
                selected_headers = tenuo_headers(_ctx_warrant, _ctx_key_id)

        if selected_headers:
            try:
                from temporalio.api.common.v1 import Payload  # type: ignore
            except ImportError:
                raise TenuoContextError("temporalio not installed")

            for k, v in selected_headers.items():
                raw = v if isinstance(v, bytes) else str(v).encode("utf-8")
                input.headers = {**(input.headers or {}), k: Payload(data=raw)}

            # NB: we deliberately do **not** write to ``_workflow_headers_store``
            # here. That store is keyed by ``run_id`` (populated on the worker
            # by ``_TenuoWorkflowInboundInterceptor.execute_workflow``), which
            # the client does not yet know at start time. A workflow_id-keyed
            # write here would collide across namespaces when two tenants pick
            # the same workflow id.

        return await self._next.start_workflow(input)
