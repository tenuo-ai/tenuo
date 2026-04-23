"""Module-level stores and context variables for Tenuo-Temporal authorization.

Tenuo authorization is completely transparent — developers use standard
workflow.execute_activity() and the interceptor handles everything.

The ``_TenuoWorkflowInboundInterceptor`` populates ``_workflow_headers_store``
and ``_workflow_config_store`` **keyed by the Temporal ``run_id``** when a
workflow starts. The outbound workflow interceptor (in the sandbox) reads
these stores, computes PoP signatures inline using deterministic timestamps,
and injects them into activity headers.

Why ``run_id`` and not ``workflow_id``
--------------------------------------

``workflow_id`` is only unique **per namespace**. Two workers running in the
same Python process for different namespaces (e.g. ``namespace="tenant-a"``
and ``namespace="tenant-b"``) can each execute a workflow named
``"onboarding-wf"``; keying by ``workflow_id`` would let one tenant's headers
or config overwrite another's and leak capabilities across tenant
boundaries. ``run_id`` is a server-assigned UUID that is globally unique
across namespaces and across ``continue_as_new`` boundaries, so it is the
only safe key for workflow-internal stores.

Exceptions: ``_pending_child_headers`` stays keyed by ``child_wf_id`` because
the parent workflow mints the child's headers **before** the child has a
``run_id`` assigned by the server. Collisions are bounded by the child
workflow id the parent itself chose, inside a single workflow instance.

Thread safety: ``_store_lock`` protects all mutations. Temporal workers
may execute activities from different workflows concurrently on
separate threads.
"""

from __future__ import annotations

import contextvars
import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from tenuo.temporal._config import TenuoPluginConfig

#: Module-level contextvar holding the active (warrant, key_id) pair set by
#: :func:`tenuo_warrant_context`. ``_TenuoClientOutbound.start_workflow`` reads
#: this so that plain ``client.execute_workflow(...)`` calls inside a
#: ``tenuo_warrant_context`` block automatically carry Tenuo headers.
_active_tenuo_warrant: contextvars.ContextVar[Optional[tuple]] = contextvars.ContextVar(
    "tenuo_active_warrant", default=None
)

# _workflow_headers_store:    run_id → {warrant, key_id}
# _pending_child_headers:     child_wf_id → attenuated headers
#                              (keyed by workflow_id because the child's run_id
#                               is not known until the server starts the child)
# _pop_dedup_cache:           alias of default InMemoryPopDedupStore.cache (replay protection)
# _workflow_config_store:     run_id → TenuoPluginConfig
# _pending_activity_fn:       run_id → activity function ref
# _pending_activity_approvals: run_id → SignedApproval list
# _pending_mint_capabilities: ref_key (workflow.uuid4()) → capabilities dict

_store_lock = threading.Lock()
_workflow_headers_store: Dict[str, Dict[str, bytes]] = {}
_pending_child_headers: Dict[str, Dict[str, bytes]] = {}
_DEDUP_EVICT_INTERVAL: float = 60.0
_DEDUP_MAX_SIZE: int = 10_000
_workflow_config_store: Dict[str, "TenuoPluginConfig"] = {}
_pending_activity_fn: Dict[str, Any] = {}
_pending_activity_approvals: Dict[str, List[Any]] = {}
_pending_mint_capabilities: Dict[str, dict] = {}  # avoids Temporal serialization of PyO3 types


def _current_run_key() -> str:
    """Return the current workflow's ``run_id`` for use as a store key.

    Raises ``TenuoContextError`` if called outside an active workflow.
    Centralising the lookup lets us change the key scheme once (e.g. to a
    ``(namespace, run_id)`` tuple) without sweeping every callsite.
    """
    from temporalio import workflow  # type: ignore[import-not-found]

    from tenuo.temporal.exceptions import TenuoContextError

    try:
        info = workflow.info()
    except Exception as e:  # pragma: no cover - temporal raises outside wf
        raise TenuoContextError(
            "No active Temporal workflow context; cannot resolve run_id key."
        ) from e
    run_id = getattr(info, "run_id", None)
    if not run_id:
        raise TenuoContextError(
            "workflow.info().run_id is empty; required for Tenuo store keying."
        )
    return run_id


# ── Worker-level config registry ────────────────────────────────────────
#
# Each worker registers its ``TenuoPluginConfig`` keyed by the worker's
# ``task_queue`` so that when ``_tenuo_internal_mint_activity`` executes
# we can resolve the *correct* key resolver for the worker that actually
# owns this activity.
#
# Registration happens automatically when using ``TenuoTemporalPlugin``
# (via :meth:`TenuoTemporalPlugin.configure_worker`) and when using
# ``TenuoWorkerInterceptor(config, task_queue=...)`` directly. For
# exotic setups that don't know the task queue at interceptor
# construction time (dynamic worker orchestration, test harnesses)
# :func:`register_worker_config` provides an explicit helper.
#
# Keying is **exact-match on task_queue**: no fallback to a "last
# registered" slot, no silent disambiguation when multiple workers run
# in the same process. A process with two workers on different queues
# must register each config on its own queue or the mint path raises a
# configuration error. The cost of being strict is one required kwarg;
# the cost of being lenient was the ability for worker A's internal-mint
# to sign with worker B's key resolver — a silent
# cross-tenant capability leak.

_worker_configs: Dict[str, "TenuoPluginConfig"] = {}


def _set_worker_config(
    config: "TenuoPluginConfig",
    *,
    task_queue: str,
) -> None:
    """Register *config* as the worker-level config for *task_queue*.

    Called by:
      * :meth:`TenuoTemporalPlugin.configure_worker` (automatic path)
      * :class:`TenuoWorkerInterceptor` ``__init__`` when constructed
        with ``task_queue=`` (manual path)
      * :func:`register_worker_config` (public escape hatch for users
        who can't pass ``task_queue`` to either of the above)

    ``task_queue`` is required — there is no "singleton" slot. Multiple
    calls for the same queue overwrite (so reconfiguring a worker during
    tests or hot-reload is supported), but cross-queue contamination is
    impossible.
    """
    if not task_queue:
        raise ValueError(
            "register_worker_config requires a non-empty task_queue. "
            "Pass the same string you pass to Worker(..., task_queue=...)."
        )
    _worker_configs[task_queue] = config


def _get_worker_config(
    task_queue: Optional[str],
) -> "Optional[TenuoPluginConfig]":
    """Return the ``TenuoPluginConfig`` registered for *task_queue*, or
    ``None`` if no exact match exists.

    Exact match only. Callers are responsible for surfacing a helpful
    error when ``None`` comes back — see the mint activity's
    :class:`TenuoContextError` for the canonical remediation message.
    """
    if not task_queue:
        return None
    return _worker_configs.get(task_queue)


def _clear_worker_config(task_queue: Optional[str] = None) -> None:
    """Testing hook: clear the registered worker config(s).

    ``task_queue=None`` clears all registrations; otherwise clears only
    the entry for that queue.
    """
    if task_queue is None:
        _worker_configs.clear()
    else:
        _worker_configs.pop(task_queue, None)


def register_worker_config(
    config: "TenuoPluginConfig",
    *,
    task_queue: str,
) -> None:
    """Register a :class:`TenuoPluginConfig` for a task queue.

    Use this helper when you're **not** using :class:`TenuoTemporalPlugin`
    (which registers automatically) and **can't** pass ``task_queue=`` to
    :class:`TenuoWorkerInterceptor` at construction time (which also
    self-registers). Typical cases:

    * Dynamic worker orchestrators that pick the task queue after the
      interceptor is constructed.
    * Test harnesses that invoke the internal mint activity directly
      without going through ``Worker(...)``.

    Registration must happen **before** the worker starts processing
    tasks. Re-registering the same task_queue overwrites; different
    queues coexist. There is no "singleton" fallback — the mint path
    looks up the config by exact task-queue match.

    Parameters
    ----------
    config:
        The plugin configuration (same object you would pass to
        :class:`TenuoTemporalPlugin` or :class:`TenuoWorkerInterceptor`).
    task_queue:
        The task queue this config should be routed to. Must match the
        ``task_queue=`` the worker is constructed with; otherwise
        ``workflow_grant()`` / ``tenuo_execute_child_workflow(...)``
        can't find the config and raise :class:`TenuoContextError`.

    Raises
    ------
    ValueError
        If *task_queue* is empty.
    """
    _set_worker_config(config, task_queue=task_queue)
