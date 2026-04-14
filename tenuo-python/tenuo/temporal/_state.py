"""Module-level stores and context variables for Tenuo-Temporal authorization.

Tenuo authorization is completely transparent — developers use standard
workflow.execute_activity() and the interceptor handles everything.

The TenuoClientInterceptor populates _workflow_headers_store when a workflow
starts. The outbound workflow interceptor (in the sandbox) reads this store,
computes PoP signatures inline using deterministic timestamps, and injects
them into activity headers. No queue machinery needed.

Thread safety: _store_lock protects all mutations. Temporal workers
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

# _workflow_headers_store:    workflow_id → {warrant, key_id}
# _pending_child_headers:     child_wf_id → attenuated headers
# _pop_dedup_cache:           alias of default InMemoryPopDedupStore.cache (replay protection)
# _workflow_config_store:     workflow_id → TenuoPluginConfig
# _pending_mint_capabilities: ref_key → capabilities dict (bypasses Temporal serialization)

_store_lock = threading.Lock()
_workflow_headers_store: Dict[str, Dict[str, bytes]] = {}
_pending_child_headers: Dict[str, Dict[str, bytes]] = {}
_DEDUP_EVICT_INTERVAL: float = 60.0
_DEDUP_MAX_SIZE: int = 10_000
_workflow_config_store: Dict[str, "TenuoPluginConfig"] = {}
_pending_activity_fn: Dict[str, Any] = {}  # workflow_id → activity function ref
_pending_activity_approvals: Dict[str, List[Any]] = {}  # workflow_id → SignedApproval list
_pending_mint_capabilities: Dict[str, dict] = {}  # ref_key → capabilities dict (avoids Temporal serialization of PyO3 types)

# Worker-level config — set once at worker init by TenuoTemporalPlugin.configure_worker.
# Used by _tenuo_internal_mint_activity so it can resolve keys during local activity execution.
_worker_config: Optional["TenuoPluginConfig"] = None


def _get_worker_config() -> "Optional[TenuoPluginConfig]":
    """Return the worker-level TenuoPluginConfig set at worker init time."""
    return _worker_config


def _set_worker_config(config: "TenuoPluginConfig") -> None:
    """Store worker-level config. Called by TenuoTemporalPlugin.configure_worker."""
    global _worker_config
    _worker_config = config
