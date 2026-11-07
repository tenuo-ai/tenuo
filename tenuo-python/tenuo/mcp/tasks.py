"""
Bind MCP Tasks (SEP-2663, ``io.modelcontextprotocol/tasks``) to the warrant
that created them.

A server may answer ``tools/call`` with a task handle and serve the rest of
the work through ``tasks/get``, ``tasks/update`` and ``tasks/cancel``. The
extension leaves authorization of those follow-up calls to each server, and
otherwise lets the ``taskId`` act as a bearer token. A Tenuo-guarded server
has a better answer: the warrant that authorized the creating ``tools/call``.

At creation the server records a :class:`TaskBinding` (task id, creating
warrant id, holder key). Every later ``tasks/*`` request must then carry
``_meta.tenuo`` with:

- a warrant stack that verifies against the authorizer (trust, expiry,
  revocation) and contains the creating warrant, held by the same key; and
- a PoP signature over the JSON-RPC method name (``"tasks/get"`` …) and the
  request params without ``_meta`` (``taskId`` plus, for ``tasks/update``,
  ``inputResponses``).

Unknown tasks and tasks bound to a different warrant or holder are denied
with the same message, so a caller cannot probe which task ids exist.

The decision is the core's (``tenuo_core.verify_task_request``). This module
supplies the binding store, replay detection and the client-side signer.

A task is only reachable while its creating warrant is valid. Issue the
warrant with a TTL that covers the task's expected lifetime.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from tenuo_core import TaskBinding

from ..meta import argument_json

__all__ = [
    "TASK_METHODS",
    "InMemoryTaskBindingStore",
    "TaskAccessResult",
    "TaskBinding",
    "TaskBindingStore",
    "binding_for_created_task",
    "sign_task_request",
    "verify_task_request",
]

#: SEP-2663 request methods that address an existing task by ``taskId``.
TASK_METHODS = frozenset({"tasks/get", "tasks/update", "tasks/cancel"})


class TaskBindingStore(Protocol):
    """Storage for :class:`TaskBinding`. Use a shared backend when tasks are
    served by more than one process. A binding is a core object; persist its
    ``task_id``, ``warrant_id``, ``holder.to_bytes()`` and ``expires_at`` and
    rebuild it with ``TaskBinding(task_id, warrant_id, PublicKey.from_bytes(h),
    expires_at)``."""

    def put(self, binding: TaskBinding) -> None: ...

    def get(self, task_id: str) -> Optional[TaskBinding]: ...


class InMemoryTaskBindingStore:
    """Process-local :class:`TaskBindingStore`. Expired bindings are evicted."""

    def __init__(self) -> None:
        self._bindings: Dict[str, TaskBinding] = {}
        self._lock = threading.Lock()

    def put(self, binding: TaskBinding) -> None:
        with self._lock:
            self._evict(time.time())
            self._bindings[binding.task_id] = binding

    def get(self, task_id: str) -> Optional[TaskBinding]:
        with self._lock:
            binding = self._bindings.get(task_id)
            if binding is not None and binding.expires_at <= time.time():
                del self._bindings[task_id]
                return None
            return binding

    def _evict(self, now: float) -> None:
        for task_id in [t for t, b in self._bindings.items() if b.expires_at <= now]:
            del self._bindings[task_id]

    def __len__(self) -> int:
        return len(self._bindings)


@dataclass
class TaskAccessResult:
    """Outcome of :func:`verify_task_request`. Never raised.

    Shaped like :class:`~tenuo.mcp.server.MCPVerificationResult` so the
    control plane and receipts treat a task decision like a tool decision,
    with the JSON-RPC method as the tool name.
    """

    allowed: bool
    tool: str
    task_id: Optional[str] = None
    warrant_id: Optional[str] = None
    denial_reason: Optional[str] = None
    jsonrpc_error_code: Optional[int] = None
    error_type: Optional[str] = None
    #: Audit view of the request. ``inputResponses`` are left out.
    arguments: Dict[str, Any] = field(default_factory=dict)
    presented_chain: List[Any] = field(default_factory=list)


def binding_for_created_task(task_id: str, warrant: Any) -> TaskBinding:
    """Build the binding for a task created under *warrant* (the leaf)."""
    return TaskBinding.for_created_task(task_id, warrant)


def _pop_params(params: Mapping[str, Any]) -> Dict[str, Any]:
    """The params a task-request PoP covers: everything except ``_meta``."""
    return {k: v for k, v in params.items() if k != "_meta"}


def sign_task_request(
    chain: List[Any],
    key: Any,
    method: str,
    params: Mapping[str, Any],
    *,
    timestamp: Optional[int] = None,
) -> Dict[str, Any]:
    """Client side: the ``_meta.tenuo`` envelope for a ``tasks/*`` request.

    *chain* is the warrant stack (root first, leaf last) that created the
    task. *params* are the request params; ``_meta`` is ignored.
    """
    from tenuo_core import sign_meta

    return sign_meta(
        list(chain),
        key,
        method,
        argument_json(_pop_params(params)),
        int(time.time()) if timestamp is None else timestamp,
        None,
    )


def verify_task_request(
    method: str,
    params: Mapping[str, Any],
    *,
    store: TaskBindingStore,
    authorizer: Any,
    nonce_store: Any = None,
    now: Optional[float] = None,
) -> TaskAccessResult:
    """Authorize a ``tasks/get``, ``tasks/update`` or ``tasks/cancel`` request.

    *params* is the raw request params mapping, ``_meta`` included. The core
    checks the envelope, warrant chain, PoP and binding; this function then
    rejects replays through *nonce_store* (or the process default).
    """
    from tenuo_core import decode_meta_chain, verify_task_request as core_verify

    task_id = params.get("taskId")
    audit_args: Dict[str, Any] = {"taskId": task_id} if isinstance(task_id, str) else {}

    def deny(reason: str, error_type: str, code: int = -32001, **kw: Any) -> TaskAccessResult:
        return TaskAccessResult(
            allowed=False,
            tool=method,
            task_id=task_id if isinstance(task_id, str) else None,
            denial_reason=reason,
            jsonrpc_error_code=code,
            error_type=error_type,
            arguments=audit_args,
            **kw,
        )

    meta = params.get("_meta")
    envelope = meta.get("tenuo") if isinstance(meta, Mapping) else None
    if not isinstance(envelope, Mapping):
        return deny(
            "No warrant provided for task request. Send _meta.tenuo signed over "
            "the method name and request params (see tenuo.mcp.tasks.sign_task_request).",
            "missing_signature",
        )
    warrant_b64 = envelope.get("warrant")
    signature_b64 = envelope.get("signature")
    if not isinstance(warrant_b64, str) or not isinstance(signature_b64, str):
        return deny("Malformed Tenuo envelope", "malformed_envelope", -32602)

    try:
        params_json = argument_json(_pop_params(params))
    except Exception:
        return deny("Invalid task request params", "invalid_arguments", -32602)

    binding = store.get(task_id) if isinstance(task_id, str) and task_id else None
    outcome = core_verify(
        authorizer,
        method,
        params_json,
        warrant_b64,
        signature_b64,
        binding,
        None if now is None else int(now),
    )

    try:
        presented = list(decode_meta_chain(warrant_b64))
    except Exception:
        presented = []
    warrant_id = presented[-1].id if presented else None

    if not outcome["allowed"]:
        return deny(
            f"Access denied: {outcome['reason']}",
            outcome["code"],
            outcome["jsonrpc_code"],
            warrant_id=warrant_id,
            presented_chain=presented,
        )

    if nonce_store is None:
        from ..nonce import get_default_nonce_store

        nonce_store = get_default_nonce_store()
    if nonce_store is not None and not nonce_store.check_and_record(outcome["signature"]):
        return deny(
            "PoP replay detected. Sign each task request with a fresh timestamp.",
            "replay",
            warrant_id=warrant_id,
            presented_chain=presented,
        )

    return TaskAccessResult(
        allowed=True,
        tool=method,
        task_id=outcome["task_id"],
        warrant_id=outcome["warrant_id"],
        arguments=audit_args,
        presented_chain=presented,
    )
