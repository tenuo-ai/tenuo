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
# Each ``TenuoTemporalPlugin.configure_worker`` call records its
# ``TenuoPluginConfig`` keyed by the worker's ``task_queue`` so that when
# ``_tenuo_internal_mint_activity`` executes we can resolve the *correct*
# key resolver for the worker that actually owns this activity.
#
# A single global slot (as we used before) would be overwritten when a
# second worker registers in the same process, and the first worker's
# internal-mint activity would then attempt to sign with the second
# worker's key resolver — producing either a ``KeyResolutionError`` or, far
# worse, a silently mis-signed child warrant.

_worker_configs: Dict[str, "TenuoPluginConfig"] = {}
# Retained as a last-resort fallback so legacy call sites that never learned
# about task_queue routing (e.g. hand-wired workers in old e2e tests that
# call ``_set_worker_config(cfg)`` directly) still function when exactly one
# config is registered. When two or more configs are registered, callers
# *must* disambiguate via task_queue; the fallback returns ``None``.
_last_registered_worker_config: Optional["TenuoPluginConfig"] = None


def _set_worker_config(
    config: "TenuoPluginConfig",
    *,
    task_queue: Optional[str] = None,
) -> None:
    """Register worker-level config, optionally keyed by ``task_queue``.

    Called by :meth:`TenuoTemporalPlugin.configure_worker` with the task
    queue the worker was built for. Legacy call sites without a task queue
    (tests, hand-composed workers) may pass ``task_queue=None``; the
    config is recorded in the fallback slot instead.
    """
    global _last_registered_worker_config
    if task_queue:
        _worker_configs[task_queue] = config
    _last_registered_worker_config = config


def _get_worker_config(
    task_queue: Optional[str] = None,
) -> "Optional[TenuoPluginConfig]":
    """Resolve the worker-level config for *task_queue*.

    Resolution order:

    1. Explicit match in ``_worker_configs[task_queue]`` (the correct answer
       whenever the plugin registered itself via
       :meth:`TenuoTemporalPlugin.configure_worker`).
    2. If no ``task_queue`` is supplied (or no explicit entry exists) and
       **only one** worker config has been registered process-wide, return
       that one. This preserves backward compatibility for tests and
       custom setups with a single worker.
    3. Otherwise return ``None`` — refusing to pick one config at random
       when multiple are registered prevents cross-tenant key leakage.
    """
    if task_queue and task_queue in _worker_configs:
        return _worker_configs[task_queue]
    if len(_worker_configs) == 1:
        only = next(iter(_worker_configs.values()))
        return only
    if not _worker_configs:
        return _last_registered_worker_config
    return None


def _clear_worker_config(task_queue: Optional[str] = None) -> None:
    """Testing hook: clear the registered worker config(s)."""
    global _last_registered_worker_config
    if task_queue is None:
        _worker_configs.clear()
        _last_registered_worker_config = None
    else:
        _worker_configs.pop(task_queue, None)
