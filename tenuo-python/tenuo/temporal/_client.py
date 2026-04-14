"""Client-side interceptor and context propagation for Tenuo-Temporal."""

from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import warnings
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from tenuo.temporal._headers import tenuo_headers
from tenuo.temporal._state import (
    _active_tenuo_warrant,
    _store_lock,
    _workflow_headers_store,
)
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

    This interceptor:
      1. Wraps raw header bytes as ``Payload`` protobufs for Temporal
      2. Stores the **raw** bytes in ``_workflow_headers_store`` (keyed by
         ``workflow_id``) so the activity interceptor can read them without
         going through Temporal's serialization pipeline.

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

    def __init__(self) -> None:
        super().__init__()
        self._next_headers: Dict[str, bytes] = {}
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
    """Context propagator for passing Tenuo warrants via Python contextvars.

    Used internally by :func:`tenuo_warrant_context`. Registered automatically
    by :class:`~tenuo.temporal_plugin.TenuoTemporalPlugin` so that plain
    ``client.execute_workflow()`` calls pick up the active warrant from context.

    Example — direct use (uncommon; prefer :func:`tenuo_warrant_context`)::

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
            if workflow_id and workflow_id in self._parent._headers_by_workflow_id:
                selected_headers = self._parent._headers_by_workflow_id.pop(workflow_id)
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

            raw_store: Dict[str, bytes] = {}

            for k, v in selected_headers.items():
                raw = v if isinstance(v, bytes) else str(v).encode("utf-8")
                input.headers = {**(input.headers or {}), k: Payload(data=raw)}
                if k.startswith("x-tenuo-"):
                    raw_store[k] = raw

            if workflow_id:
                with _store_lock:
                    _workflow_headers_store[workflow_id] = raw_store

        return await self._next.start_workflow(input)
