"""
Temporal ``SimplePlugin`` integration.

Registers Tenuo as a first-class plugin: client + worker interceptors and
workflow sandbox passthrough for ``tenuo`` / ``tenuo_core`` (PyO3).

Requires ``temporalio>=1.23`` (``SimplePlugin`` in ``temporalio.plugin``). SDKs
differ: some expose a single ``interceptors=`` parameter, others
``client_interceptors`` / ``worker_interceptors``. This module picks kwargs using
``inspect.signature(SimplePlugin.__init__)`` so we always match the **installed**
constructor (version numbers alone can mis-classify or go stale). Subclassing
Temporal's interceptor bases keeps plugin filtering working on newer SDKs.

Example::

    from temporalio.client import Client
    from temporalio.worker import Worker

    from tenuo import SigningKey, Warrant
    from tenuo.temporal import TenuoPluginConfig, EnvKeyResolver, execute_workflow_authorized
    from tenuo.temporal_plugin import TenuoTemporalPlugin

    control = SigningKey.generate()
    plugin = TenuoTemporalPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control.public_key],
        )
    )
    client = await Client.connect("localhost:7233", plugins=[plugin])
    worker = Worker(client, task_queue="tq", workflows=[...], activities=[...])
    # Warrant headers still use ``execute_workflow_authorized`` or
    # ``plugin.client_interceptor.set_headers_for_workflow`` — the plugin does
    # not replace those APIs; it registers the same interceptor instance.

Do **not** pass the same plugin again on ``Worker(plugins=[...])`` when the
client already had ``plugins=[plugin]`` — see :class:`TenuoTemporalPlugin`.
"""

from __future__ import annotations

import dataclasses
import inspect
import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, Optional

try:
    from temporalio.plugin import SimplePlugin
except ImportError as e:  # pragma: no cover - guarded by temporalio version
    raise ImportError(
        "TenuoTemporalPlugin requires temporalio>=1.23 "
        "(temporalio.plugin.SimplePlugin). Upgrade: uv pip install 'temporalio>=1.23'"
    ) from e

from tenuo.exceptions import ConfigurationError
from tenuo.temporal._client import (
    TenuoClientInterceptor,
    TenuoWarrantContextPropagator,
)
from tenuo.temporal._config import (
    TenuoPluginConfig,
    _build_activity_registry,
)
from tenuo.temporal._interceptors import TenuoPlugin
from tenuo.temporal._state import _set_worker_config
from tenuo.temporal._workflow import _tenuo_internal_mint_activity

_logger = logging.getLogger("tenuo.temporal")

if TYPE_CHECKING:
    from temporalio.worker import WorkflowRunner

TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME = "tenuo.TenuoTemporalPlugin"


def _simple_plugin_interceptor_kwargs(
    client_interceptor: TenuoClientInterceptor,
    worker_interceptor: TenuoPlugin,
) -> dict[str, Any]:
    """Build ``super().__init__(..., **kwargs)`` for the installed ``SimplePlugin`` shape."""
    params = inspect.signature(SimplePlugin.__init__).parameters
    has_unified = "interceptors" in params
    has_split = (
        "client_interceptors" in params and "worker_interceptors" in params
    )
    if has_unified and not has_split:
        return {"interceptors": [client_interceptor, worker_interceptor]}
    if has_split and not has_unified:
        return {
            "client_interceptors": [client_interceptor],
            "worker_interceptors": [worker_interceptor],
        }
    if has_unified:
        return {"interceptors": [client_interceptor, worker_interceptor]}
    raise RuntimeError(
        "Unsupported temporalio SimplePlugin: expected 'interceptors' or "
        "('client_interceptors' and 'worker_interceptors') on SimplePlugin.__init__. "
        "Upgrade temporalio or report this to Tenuo."
    )


def ensure_tenuo_workflow_runner(
    existing: Optional["WorkflowRunner"],
) -> "WorkflowRunner":
    """Return a workflow runner with ``tenuo`` and ``tenuo_core`` sandbox passthrough.

    Use when **not** adopting :class:`TenuoTemporalPlugin` — for example if you
    register ``TenuoPlugin`` manually but still need PyO3 passthrough.

    - If ``existing`` is ``None``, returns a :class:`SandboxedWorkflowRunner`
      with default restrictions plus passthrough.
    - If ``existing`` is already a :class:`SandboxedWorkflowRunner`, adds
      passthrough modules (idempotent if already present).
    - Otherwise returns ``existing`` unchanged (unsandboxed runners cannot load
      PyO3 in sub-interpreters; prefer sandbox + passthrough for Tenuo).
    """
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner,
        SandboxRestrictions,
    )

    passthrough = ("tenuo", "tenuo_core")
    if existing is None:
        return SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                *passthrough
            )
        )
    if isinstance(existing, SandboxedWorkflowRunner):
        return dataclasses.replace(
            existing,
            restrictions=existing.restrictions.with_passthrough_modules(*passthrough),
        )
    return existing


class TenuoTemporalPlugin(SimplePlugin):
    """Temporal plugin for warrant + PoP enforcement.

    **Plugin name:** :data:`TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME` (``tenuo.TenuoTemporalPlugin``).

    Configures:

    - **Client:** :class:`TenuoClientInterceptor` (warrant headers, workflow-ID binding).
    - **Worker / Replayer:** :class:`TenuoPlugin` with your :class:`TenuoPluginConfig`.
    - **Workflow runner:** sandbox passthrough for ``tenuo`` and ``tenuo_core``.

    After construction, :attr:`client_interceptor` is the instance registered
    on the client (use it with ``execute_workflow_authorized`` or
    ``set_headers_for_workflow``). See ``__init__`` for the duplicate-plugin
    warning.
    """

    #: The :class:`TenuoClientInterceptor` wired into this plugin (same instance
    #: the client uses). Use with ``execute_workflow_authorized(..., client_interceptor=...)``
    #: or ``set_headers_for_workflow``.
    client_interceptor: TenuoClientInterceptor

    #: Context propagator instance for direct access. Behaviour is automatic when
    #: using :func:`~tenuo.temporal.tenuo_warrant_context`; expose here for users
    #: who want to set/clear the contextvar manually.
    context_propagator: TenuoWarrantContextPropagator

    def __init__(
        self,
        config: TenuoPluginConfig,
        *,
        client_interceptor: Optional[TenuoClientInterceptor] = None,
    ) -> None:
        """Create a plugin with the given worker config.

        .. warning::

            Register this plugin on ``Client.connect(..., plugins=[plugin])``
            only. Workers built from that client inherit the plugin; passing the
            same plugin again on ``Worker(..., plugins=[plugin])`` **double-registers**
            interceptors and causes subtle, hard-to-diagnose failures. Only pass
            ``plugins=`` on ``Worker`` when the client was created **without**
            this plugin.
        """
        worker_interceptor = TenuoPlugin(config)
        self.client_interceptor = client_interceptor or TenuoClientInterceptor()
        self.context_propagator = TenuoWarrantContextPropagator()
        self._tenuo_config = config
        # Item 1.5: guard against duplicate configure_worker calls on same instance
        self._tenuo_worker_configured = False

        def _add_activities(
            activities: "Sequence[Callable[..., Any]] | None",
        ) -> "Sequence[Callable[..., Any]]":
            """Append _tenuo_internal_mint_activity and store worker config.

            Also handles:
            - Item 1.2: auto-discovers activity_fns from existing activities if unset.
            - Item 1.5: raises ConfigurationError on duplicate configure_worker calls.
            - Item 1.6: auto-calls preload_keys() if the resolver supports it.
            """
            # Item 1.5: detect duplicate registration
            if self._tenuo_worker_configured:
                raise ConfigurationError(
                    "duplicate Tenuo plugin registered: the same TenuoTemporalPlugin "
                    "instance was used to configure_worker more than once. Create "
                    "separate TenuoTemporalPlugin instances for each worker."
                )
            self._tenuo_worker_configured = True

            _set_worker_config(config)
            existing = list(activities or [])

            # Item 1.2: auto-populate activity_fns if not already set
            if not config.activity_fns and existing:
                config.activity_fns = list(existing)
                # Rebuild the activity registry without re-running full __post_init__
                config._activity_registry = _build_activity_registry(config.activity_fns)
                _logger.info(
                    "Tenuo: auto-discovered %d activity function(s) from worker config",
                    len(config.activity_fns),
                )

            # Auto-preload signing keys so resolve_sync() never touches
            # os.environ (or external storage) inside the workflow sandbox.
            _preload_all = getattr(config.key_resolver, "preload_all", None)
            if _preload_all is not None:
                try:
                    _preload_all()
                except Exception as _exc:
                    _logger.warning("key preload failed: %s", _exc)

            if _tenuo_internal_mint_activity is not None:
                existing.append(_tenuo_internal_mint_activity)
            return existing

        super().__init__(
            TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME,
            workflow_runner=ensure_tenuo_workflow_runner,
            activities=_add_activities,
            **_simple_plugin_interceptor_kwargs(
                self.client_interceptor, worker_interceptor
            ),
        )


__all__ = [
    "TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME",
    "TenuoTemporalPlugin",
    "ensure_tenuo_workflow_runner",
]
