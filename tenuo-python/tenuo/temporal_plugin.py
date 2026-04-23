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
from tenuo.temporal._interceptors import TenuoWorkerInterceptor
from tenuo.temporal._resolvers import EnvKeyResolver
from tenuo.temporal._state import _set_worker_config
from tenuo.temporal._workflow import _tenuo_internal_mint_activity
from tenuo.temporal.exceptions import (
    ChainValidationError,
    KeyResolutionError,
    LocalActivityError,
    PopVerificationError,
    TemporalConstraintViolation,
    TenuoContextError,
    WarrantExpired,
)

_logger = logging.getLogger("tenuo.temporal")

if TYPE_CHECKING:
    from temporalio.worker import WorkflowRunner

TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME = "tenuo.TenuoTemporalPlugin"

# Tenuo exceptions that should fail the workflow cleanly (non-retryable) rather
# than being wrapped by ``ActivityError``. Registered on ``SimplePlugin`` so the
# Temporal SDK treats them as domain-level workflow failures.
_TENUO_WORKFLOW_FAILURE_EXCEPTION_TYPES: tuple[type[BaseException], ...] = (
    TenuoContextError,
    PopVerificationError,
    TemporalConstraintViolation,
    WarrantExpired,
    ChainValidationError,
    KeyResolutionError,
    LocalActivityError,
)


def _simple_plugin_kwargs(
    client_interceptor: TenuoClientInterceptor,
    worker_interceptor: TenuoWorkerInterceptor,
) -> dict[str, Any]:
    """Build ``super().__init__(..., **kwargs)`` for the installed ``SimplePlugin`` shape."""
    params = inspect.signature(SimplePlugin.__init__).parameters
    has_unified = "interceptors" in params
    has_split = (
        "client_interceptors" in params and "worker_interceptors" in params
    )
    if has_unified and not has_split:
        kwargs: dict[str, Any] = {
            "interceptors": [client_interceptor, worker_interceptor]
        }
    elif has_split and not has_unified:
        kwargs = {
            "client_interceptors": [client_interceptor],
            "worker_interceptors": [worker_interceptor],
        }
    elif has_unified:
        kwargs = {"interceptors": [client_interceptor, worker_interceptor]}
    else:
        raise RuntimeError(
            "Unsupported temporalio SimplePlugin: expected 'interceptors' or "
            "('client_interceptors' and 'worker_interceptors') on "
            "SimplePlugin.__init__. Upgrade temporalio or report this to Tenuo."
        )

    if "workflow_failure_exception_types" in params:
        kwargs["workflow_failure_exception_types"] = list(
            _TENUO_WORKFLOW_FAILURE_EXCEPTION_TYPES
        )
    return kwargs


def ensure_tenuo_workflow_runner(
    existing: Optional["WorkflowRunner"],
) -> "WorkflowRunner":
    """Return a workflow runner with ``tenuo`` and ``tenuo_core`` sandbox passthrough.

    Use when **not** adopting :class:`TenuoTemporalPlugin` — for example if you
    register ``TenuoWorkerInterceptor`` manually but still need PyO3 passthrough.

    - If ``existing`` is ``None``, returns a :class:`SandboxedWorkflowRunner`
      with default restrictions plus passthrough.
    - If ``existing`` is already a :class:`SandboxedWorkflowRunner`, adds
      passthrough modules (idempotent if already present).
    - If ``existing`` is an :class:`UnsandboxedWorkflowRunner`, emits a
      :class:`UserWarning` (and a logger warning) and returns it unchanged.
      Tenuo can operate under the unsandboxed runner, but the user loses
      Temporal's determinism guardrails for their own workflow code, so we
      make sure the choice is visible rather than silent.
    - For any other custom runner, returns ``existing`` unchanged and logs a
      warning so the caller notices passthrough was skipped.
    """
    import warnings

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

    unsandboxed_cls: Optional[type] = None
    try:
        from temporalio.worker import UnsandboxedWorkflowRunner

        unsandboxed_cls = UnsandboxedWorkflowRunner
    except ImportError:  # pragma: no cover - older temporalio without this export
        pass

    if unsandboxed_cls is not None and isinstance(existing, unsandboxed_cls):
        msg = (
            "TenuoTemporalPlugin is running with UnsandboxedWorkflowRunner. "
            "Tenuo itself still enforces warrant + PoP authorization, but "
            "you are opting out of Temporal's workflow sandbox, so any "
            "non-deterministic code in your own workflows (time.time(), "
            "random, unguarded I/O, module-level state) can cause replay "
            "divergence. Prefer SandboxedWorkflowRunner in production and "
            "omit ``workflow_runner`` to let the plugin supply one with "
            "passthrough for 'tenuo' and 'tenuo_core' configured."
        )
        warnings.warn(msg, UserWarning, stacklevel=2)
        _logger.warning("%s", msg)
        return existing

    _logger.warning(
        "TenuoTemporalPlugin: unknown workflow runner %s; passthrough for "
        "'tenuo' and 'tenuo_core' was not configured. Workflow code may fail to "
        "import Tenuo modules. Use SandboxedWorkflowRunner or omit "
        "``workflow_runner`` to get automatic passthrough.",
        type(existing).__name__,
    )
    return existing


class TenuoTemporalPlugin(SimplePlugin):
    """Temporal plugin for warrant + PoP enforcement.

    **Plugin name:** :data:`TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME` (``tenuo.TenuoTemporalPlugin``).

    Configures:

    - **Client:** :class:`TenuoClientInterceptor` (warrant headers, workflow-ID binding).
    - **Worker / Replayer:** :class:`TenuoWorkerInterceptor` with your :class:`TenuoPluginConfig`.
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

        The user's ``config`` is never mutated: the plugin works on a shallow
        copy so two workers sharing the same config object cannot leak
        activity registries into each other.
        """
        # Work on a copy so we never mutate the user's config object. This
        # isolates two workers that happen to share a ``TenuoPluginConfig``.
        self._tenuo_config = dataclasses.replace(config)
        if self._tenuo_config.activity_fns is not None:
            self._tenuo_config.activity_fns = list(self._tenuo_config.activity_fns)
        # The activity registry is rebuilt from our copy; any later auto-discovery
        # writes only to ``self._tenuo_config``.
        self._tenuo_config._activity_registry = _build_activity_registry(
            self._tenuo_config.activity_fns
        )

        worker_interceptor = TenuoWorkerInterceptor(self._tenuo_config)
        self.client_interceptor = client_interceptor or TenuoClientInterceptor()
        self.context_propagator = TenuoWarrantContextPropagator()
        self._tenuo_worker_configured = False

        def _add_activities(
            activities: "Sequence[Callable[..., Any]] | None",
        ) -> "Sequence[Callable[..., Any]]":
            """Append _tenuo_internal_mint_activity and record the worker config.

            Responsibilities:

            - Detect duplicate ``configure_worker`` calls on the same instance.
            - Auto-populate ``activity_fns`` on the plugin's private config
              copy when the user didn't set them explicitly.
            - Eagerly preload all signing keys so the workflow sandbox never
              has to touch ``os.environ`` or external secret storage.
            """
            if self._tenuo_worker_configured:
                raise ConfigurationError(
                    "Duplicate Tenuo plugin registration: the same "
                    "TenuoTemporalPlugin instance configured more than one "
                    "worker. The recommended pattern is to pass the plugin "
                    "once to Client.connect(plugins=[plugin]) and let workers "
                    "built from that client inherit it; passing the same "
                    "plugin to Worker(plugins=[...]) in addition causes this "
                    "double-registration. For genuinely different worker "
                    "configurations (different activity_fns, different key "
                    "resolvers), create one TenuoTemporalPlugin per worker."
                )
            self._tenuo_worker_configured = True

            _set_worker_config(self._tenuo_config)
            existing = list(activities or [])

            # Auto-populate activity_fns on our private copy if not set by the
            # user. Never touch the user's original ``config`` object.
            if not self._tenuo_config.activity_fns and existing:
                self._tenuo_config.activity_fns = list(existing)
                self._tenuo_config._activity_registry = _build_activity_registry(
                    self._tenuo_config.activity_fns
                )
                _logger.info(
                    "Tenuo: auto-discovered %d activity function(s) from worker config",
                    len(self._tenuo_config.activity_fns),
                )

            self._preload_keys()

            if _tenuo_internal_mint_activity is not None:
                existing.append(_tenuo_internal_mint_activity)
            return existing

        super().__init__(
            TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME,
            workflow_runner=ensure_tenuo_workflow_runner,
            activities=_add_activities,
            **_simple_plugin_kwargs(self.client_interceptor, worker_interceptor),
        )

    def _preload_keys(self) -> None:
        """Eagerly preload signing keys from the configured resolver.

        Preloading is best-effort by default, but for :class:`EnvKeyResolver`
        it is a hard requirement: ``resolve_sync`` falls back to ``os.environ``
        which is blocked inside the Temporal workflow sandbox. A preload
        failure for an env resolver will deterministically turn into
        ``KeyResolutionError`` on every subsequent workflow, so we raise
        immediately with a clear message instead of logging a warning.
        """
        resolver = self._tenuo_config.key_resolver
        _preload_all = getattr(resolver, "preload_all", None)
        if _preload_all is None:
            return
        resolver_cls = type(resolver).__name__
        try:
            _preload_all()
        except Exception as exc:
            if isinstance(resolver, EnvKeyResolver):
                raise ConfigurationError(
                    f"EnvKeyResolver.preload_all() failed ({exc!r}). Preloading "
                    "is required for EnvKeyResolver because resolve_sync() "
                    "falls back to os.environ, which is blocked inside the "
                    "Temporal workflow sandbox. Fix the environment variables "
                    "(e.g. TENUO_KEY_* entries must be valid base64/seed) or "
                    "switch to a resolver that does not rely on process env."
                ) from exc
            _logger.error(
                "Tenuo %s.preload_all() failed: %s. Workflows that resolve "
                "keys through this resolver at runtime will fail with "
                "KeyResolutionError.",
                resolver_cls,
                exc,
            )


__all__ = [
    "TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME",
    "TenuoTemporalPlugin",
    "ensure_tenuo_workflow_runner",
]
