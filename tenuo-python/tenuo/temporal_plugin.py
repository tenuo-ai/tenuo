"""
Temporal ``SimplePlugin`` integration.

Registers Tenuo as a first-class plugin: client + worker interceptors and
workflow sandbox passthrough for ``tenuo`` / ``tenuo_core`` (PyO3).

Requires ``temporalio>=1.23`` (``SimplePlugin`` in ``temporalio.plugin``); the
dependency floor is enforced in ``pyproject.toml``. Subclassing Temporal's
interceptor bases keeps plugin filtering working on newer SDKs.

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
from tenuo.temporal._workflow import TENUO_TEMPORAL_ACTIVITIES
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


def _extract_task_queue(config: Any) -> "Optional[str]":
    """Return the ``task_queue`` from a Temporal ``WorkerConfig`` or dict.

    Temporal's ``WorkerConfig`` is a :class:`TypedDict` in current SDKs;
    earlier versions used a dataclass-style object. Handle both by
    trying mapping-style access first and falling back to
    :func:`getattr`. Returns ``None`` when the config doesn't expose a
    task queue (e.g. SDK plumbing passing a partial config, or test
    fixtures passing a bare dict without ``task_queue``).
    """
    if isinstance(config, dict):
        task_queue = config.get("task_queue")
    else:
        task_queue = getattr(config, "task_queue", None)
    if isinstance(task_queue, str) and task_queue:
        return task_queue
    return None

if TYPE_CHECKING:
    from temporalio.worker import WorkflowRunner

# Alias of :data:`tenuo.temporal._constants.TENUO_TEMPORAL_PLUGIN_ID`, re-exported
# here so users and tests can import the canonical Temporal plugin name directly
# from ``tenuo.temporal_plugin``.
from tenuo.temporal._constants import TENUO_TEMPORAL_PLUGIN_ID as TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME  # noqa: E402

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
    """Build ``super().__init__(..., **kwargs)`` for ``SimplePlugin`` (>=1.23).

    Both ``interceptors`` and ``workflow_failure_exception_types`` are
    available on the ``SimplePlugin`` constructor for every SDK version
    we support (the ``temporalio>=1.23`` pin is enforced in
    ``pyproject.toml`` and at import time in this module).
    """
    return {
        "interceptors": [client_interceptor, worker_interceptor],
        "workflow_failure_exception_types": list(
            _TENUO_WORKFLOW_FAILURE_EXCEPTION_TYPES
        ),
    }


def _ensure_tenuo_workflow_runner(
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

    # mypy narrowing note: ``unsandboxed_cls`` below is typed as
    # ``Optional[type]`` (the unparameterized ``type``), so
    # ``isinstance(existing, unsandboxed_cls)`` narrows ``existing`` to
    # ``object`` rather than ``WorkflowRunner``. ``runner`` aliases the
    # non-None, correctly-typed binding so the final ``return runner``
    # sites stay type-correct without sprinkling ``cast`` at every exit.
    runner: "WorkflowRunner" = existing

    unsandboxed_cls: Optional[type] = None
    try:
        from temporalio.worker import UnsandboxedWorkflowRunner

        unsandboxed_cls = UnsandboxedWorkflowRunner
    except ImportError:  # pragma: no cover - older temporalio without this export
        pass

    if unsandboxed_cls is not None and isinstance(runner, unsandboxed_cls):
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
        return runner

    _logger.warning(
        "TenuoTemporalPlugin: unknown workflow runner %s; passthrough for "
        "'tenuo' and 'tenuo_core' was not configured. Workflow code may fail to "
        "import Tenuo modules. Use SandboxedWorkflowRunner or omit "
        "``workflow_runner`` to get automatic passthrough.",
        type(runner).__name__,
    )
    return runner


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

            The worker-config registration with ``_set_worker_config`` is
            handled by :meth:`configure_worker` (below) so that we can key
            the registry by ``task_queue``; this closure only appends the
            internal mint activity.
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

            existing.extend(TENUO_TEMPORAL_ACTIVITIES)
            return existing

        super().__init__(
            TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME,
            workflow_runner=_ensure_tenuo_workflow_runner,
            activities=_add_activities,
            **_simple_plugin_kwargs(self.client_interceptor, worker_interceptor),
        )

    def configure_worker(self, config: Any) -> Any:  # type: ignore[override]
        """Register this plugin's :class:`TenuoPluginConfig` under the worker's task queue.

        Keying the worker-config registry by ``task_queue`` is what allows
        :func:`_tenuo_internal_mint_activity` to resolve the correct
        key resolver when multiple workers (with different configs) share
        a single Python process. Without this, the second worker to call
        ``configure_worker`` would overwrite the first worker's global and
        the first worker would start minting warrants with the second
        worker's signing key.
        """
        task_queue = _extract_task_queue(config)
        if task_queue:
            _set_worker_config(self._tenuo_config, task_queue=task_queue)
        # Silently skip when no queue is discoverable (e.g. SDK plumbing
        # that merges runner/interceptor config before the Worker has its
        # task_queue set, or test fixtures that pass a bare ``{}``). The
        # mint activity will fire a targeted ``TenuoContextError`` with
        # remediation steps if delegation is attempted without a
        # registration, so there's no silent-failure risk.
        return super().configure_worker(config)

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
]
