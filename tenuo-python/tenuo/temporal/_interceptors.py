"""Temporal worker interceptors for Tenuo authorization enforcement.

Contains the outbound workflow interceptor (PoP injection), inbound workflow
interceptor (header extraction), TenuoWorkerInterceptor (worker-level
interceptor), and TenuoActivityInboundInterceptor (activity authorization
checks).
"""

from __future__ import annotations

import base64
import inspect as _inspect
import json
import logging
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from tenuo.exceptions import ApprovalGateTriggered
from tenuo.temporal._constants import (
    TENUO_APPROVALS_HEADER,
    TENUO_ARG_KEYS_HEADER,
    TENUO_CHAIN_HEADER,
    TENUO_KEY_ID_HEADER,
    TENUO_POP_HEADER,
    TENUO_TEMPORAL_PLUGIN_ID,
)
from tenuo.temporal._decorators import (
    _warrant_tool_name_for_activity_type,
    is_unprotected,
)
from tenuo.temporal._headers import _extract_warrant_from_headers
from tenuo.temporal._observability import TemporalAuditEvent
from tenuo.temporal._pop import (
    _args_dict_uses_only_positional_fallback_keys,
    _args_to_dict_by_fn,
    _normalize_args_for_pop,
    _positional_pop_mismatch_message,
    _prevalidate_args_against_warrant,
    _warrant_tool_has_non_empty_field_constraints,
)
from tenuo.temporal._state import (
    _pending_activity_approvals,
    _pending_activity_fn,
    _pending_child_headers,
    _store_lock,
    _workflow_config_store,
    _workflow_headers_store,
)
from tenuo.temporal._dedup import PopDedupStore, _default_pop_dedup_store
from tenuo.temporal.exceptions import (
    ChainValidationError,
    LocalActivityError,
    PopVerificationError,
    TemporalConstraintViolation,
    TenuoArgNormalizationError,
    TenuoContextError,
    TenuoTemporalError,
    WarrantExpired,
)

if TYPE_CHECKING:
    from tenuo.temporal._config import TenuoPluginConfig

logger = logging.getLogger("tenuo.temporal")

# OTel is a soft dependency
try:
    from opentelemetry import trace as _otel_trace

    _otel_available = True
except ImportError:
    _otel_trace = None  # type: ignore[assignment]
    _otel_available = False

# Temporal interceptor base classes — fallback to object when not installed
_TemporalWorkerInterceptor: Any
try:
    from temporalio.worker import Interceptor as _tw_interceptor

    _TemporalWorkerInterceptor = _tw_interceptor
except ImportError:  # pragma: no cover
    _TemporalWorkerInterceptor = object


# ── Utility helpers ──────────────────────────────────────────────────────

def _raise_non_retryable(violation: BaseException) -> None:
    """Raise *violation* wrapped in a non-retryable ApplicationError.

    Authorization denials and PoP signing failures must never be retried —
    the warrant constraints and key resolver state do not change between
    attempts.
    """
    try:
        from temporalio.exceptions import ApplicationError  # type: ignore[import-not-found]
    except ImportError:
        raise violation
    raise ApplicationError(
        str(violation),
        type=violation.__class__.__name__,
        non_retryable=True,
    ) from violation


def _replace_field(obj: Any, field: str, value: Any) -> Any:
    """Create a copy of a dataclass with one field replaced.

    Falls back to setattr for non-dataclass objects.
    """
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.replace(obj, **{field: value})
    setattr(obj, field, value)
    return obj


# ── Outbound Workflow Interceptor ────────────────────────────────────────

class _TenuoWorkflowOutboundInterceptor:
    """Outbound workflow interceptor — transparently computes and injects PoP.

    This interceptor makes Tenuo authorization completely transparent.
    When ``workflow.execute_activity()`` is called (standard Temporal API),
    this interceptor automatically:
    1. Retrieves the warrant and key_id from workflow headers, resolves signing key via KeyResolver
    2. Computes the Proof-of-Possession signature using deterministic time
    3. Injects warrant + PoP into activity headers

    No special wrapper functions needed — works with standard Temporal code.
    """

    def __init__(self, next_outbound: Any, config: Optional["TenuoPluginConfig"] = None) -> None:
        self._next = next_outbound
        self.__dict__["_config"] = config

    def __getattr__(self, name: str) -> Any:
        return getattr(self._next, name)

    def start_activity(self, input: Any) -> Any:
        """Transparently compute and inject PoP for every activity."""
        from temporalio import workflow  # type: ignore[import-not-found]

        try:
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.start_activity(input)

        try:
            wf_id = workflow.info().workflow_id
            activity_type = input.activity

            with _store_lock:
                pending_approvals = _pending_activity_approvals.pop(wf_id, None)

            with _store_lock:
                raw_headers = dict(_workflow_headers_store.get(wf_id, {}))

            if raw_headers:
                warrant = _extract_warrant_from_headers(raw_headers)
                key_id_bytes = raw_headers.get(TENUO_KEY_ID_HEADER)

                if warrant and key_id_bytes:
                    key_id = key_id_bytes.decode("utf-8")

                    if not self._config or not self._config.key_resolver:
                        _raise_non_retryable(TenuoContextError(
                            "key_resolver is required for outbound PoP signing. "
                            "Set key_resolver in TenuoPluginConfig, or use a read-only worker "
                            "(no activities that need signing)."
                        ))

                    signer = self._config.key_resolver.resolve_sync(key_id)

                    activity_fn = getattr(input, "fn", None)
                    if activity_fn is None:
                        with _store_lock:
                            activity_fn = _pending_activity_fn.get(wf_id)
                    if activity_fn is None and self._config is not None:
                        activity_fn = self._config._activity_registry.get(activity_type)

                    raw_args = getattr(input, "args", ()) or ()
                    args_dict = _args_to_dict_by_fn(raw_args, activity_fn)

                    pop_tool_name = _warrant_tool_name_for_activity_type(
                        self._config, activity_type, activity_fn
                    )

                    if raw_args and _args_dict_uses_only_positional_fallback_keys(
                        args_dict
                    ) and _warrant_tool_has_non_empty_field_constraints(
                        warrant, pop_tool_name
                    ):
                        msg = _positional_pop_mismatch_message(
                            pop_tool_name,
                            strict_mode=bool(
                                self._config and self._config.strict_mode
                            ),
                        )
                        if self._config and self._config.strict_mode:
                            raise TenuoContextError(msg)
                        logger.warning(msg)

                    args_dict = _normalize_args_for_pop(args_dict)
                    _prevalidate_args_against_warrant(warrant, pop_tool_name, args_dict)

                    timestamp = int(workflow.now().timestamp())
                    pop_signature = warrant.sign(signer, pop_tool_name, args_dict, timestamp)
                    pop_encoded = base64.b64encode(bytes(pop_signature))

                    activity_headers = dict(input.headers or {})
                    for k, v in raw_headers.items():
                        activity_headers[k] = Payload(data=v)
                    activity_headers[TENUO_POP_HEADER] = Payload(data=pop_encoded)

                    arg_keys_csv = ",".join(args_dict.keys())
                    activity_headers[TENUO_ARG_KEYS_HEADER] = Payload(
                        data=arg_keys_csv.encode("utf-8")
                    )

                    if pending_approvals:
                        encoded = json.dumps([
                            base64.b64encode(a.to_bytes()).decode("ascii")
                            for a in pending_approvals
                        ])
                        activity_headers[TENUO_APPROVALS_HEADER] = Payload(
                            data=encoded.encode("utf-8")
                        )

                    input = _replace_field(input, "headers", activity_headers)

                    if hasattr(input, "__dataclass_fields__") and "summary" in input.__dataclass_fields__:
                        current_summary = getattr(input, "summary", "") or ""
                        tool_label = pop_tool_name if pop_tool_name != activity_type else activity_type
                        prefix = f"[{TENUO_TEMPORAL_PLUGIN_ID}]"
                        if current_summary:
                            new_summary = f"{prefix} {tool_label}: {current_summary}"
                        else:
                            new_summary = f"{prefix} {tool_label}"
                        input = _replace_field(input, "summary", new_summary)

        except (TenuoContextError, TenuoArgNormalizationError) as e:
            _raise_non_retryable(e)
        except Exception as e:
            activity = getattr(input, "activity", "<unknown>")
            _raise_non_retryable(TenuoContextError(
                f"PoP computation failed for activity '{activity}': {e}. "
                f"Activity aborted (fail-closed)."
            ))

        return self._next.start_activity(input)

    def start_child_workflow(self, input: Any) -> Any:
        """Inject Tenuo headers into child workflow starts."""
        try:
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.start_child_workflow(input)

        child_id = input.id
        with _store_lock:
            raw_headers = _pending_child_headers.pop(child_id, None)

        if raw_headers:
            child_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                child_headers[k] = Payload(data=v)
            input = _replace_field(input, "headers", child_headers)

        return self._next.start_child_workflow(input)

    def continue_as_new(self, input: Any) -> None:
        """Re-inject Tenuo headers so the next run keeps its warrant."""
        try:
            from temporalio import workflow  # type: ignore[import-not-found]
            from temporalio.api.common.v1 import Payload  # type: ignore
        except ImportError:
            return self._next.continue_as_new(input)

        wf_id = workflow.info().workflow_id
        with _store_lock:
            raw_headers = _workflow_headers_store.get(wf_id, {})

        if raw_headers:
            can_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                can_headers[k] = Payload(data=v)
            input = _replace_field(input, "headers", can_headers)

        return self._next.continue_as_new(input)

    def start_nexus_operation(self, input: Any) -> Any:
        """Propagate Tenuo headers into Nexus cross-namespace operations."""
        from temporalio import workflow  # type: ignore[import-not-found]

        wf_id = workflow.info().workflow_id
        with _store_lock:
            raw_headers = _workflow_headers_store.get(wf_id, {})

        if raw_headers:
            nexus_headers = dict(input.headers or {})
            for k, v in raw_headers.items():
                nexus_headers[k] = base64.b64encode(v).decode()
            input = _replace_field(input, "headers", nexus_headers)

        return self._next.start_nexus_operation(input)

    def start_local_activity(self, input: Any) -> Any:
        """Block protected local activities unless @unprotected is set."""
        if self._config and self._config.block_local_activities:
            activity_fn = getattr(input, "fn", None)
            if activity_fn is not None and not is_unprotected(activity_fn):
                activity_name = getattr(input, "activity", repr(activity_fn))
                raise LocalActivityError(str(activity_name))
        return self._next.start_local_activity(input)


# ── Inbound Workflow Interceptor ─────────────────────────────────────────

class _TenuoWorkflowInboundInterceptor:
    """Workflow interceptor — extracts Tenuo headers and cleans up on completion.

    **Inbound** half: extracts ``x-tenuo-*`` headers from the Temporal
    ``Payload`` mapping delivered by the server and writes them into
    ``_workflow_headers_store``.

    **Outbound** half (via ``init()``): wraps the next outbound
    interceptor with ``_TenuoWorkflowOutboundInterceptor``.
    """

    _config: Optional["TenuoPluginConfig"] = None

    def __init__(self, next_interceptor: Any) -> None:
        self.next = next_interceptor

    def init(self, outbound: Any) -> None:
        self.next.init(_TenuoWorkflowOutboundInterceptor(outbound, self._config))

    async def execute_workflow(self, input: Any) -> Any:
        from temporalio import workflow  # type: ignore[import-not-found]

        wf_id = workflow.info().workflow_id

        incoming: Dict[str, bytes] = {}
        for key, payload in (getattr(input, "headers", None) or {}).items():
            if key.startswith("x-tenuo-"):
                data = getattr(payload, "data", None)
                if data is not None:
                    incoming[key] = data

        if incoming:
            with _store_lock:
                _workflow_headers_store[wf_id] = incoming

        if self._config is not None:
            with _store_lock:
                _workflow_config_store[wf_id] = self._config

        try:
            return await self.next.execute_workflow(input)
        finally:
            with _store_lock:
                _workflow_headers_store.pop(wf_id, None)
                _workflow_config_store.pop(wf_id, None)

    def _resolve_config(self) -> Optional["TenuoPluginConfig"]:
        from temporalio import workflow  # type: ignore[import-not-found]

        wf_id = workflow.info().workflow_id
        with _store_lock:
            return _workflow_config_store.get(wf_id)

    async def handle_signal(self, input: Any) -> None:
        config = self._resolve_config()
        if config and config.authorized_signals is not None:
            signal_name = getattr(input, "signal", None)
            if signal_name not in config.authorized_signals:
                logger.warning(
                    f"Signal '{signal_name}' denied: not in authorized_signals"
                )
                raise TemporalConstraintViolation(
                    tool=f"signal:{signal_name}",
                    arguments={},
                    constraint=f"Signal not authorized: {signal_name}",
                    warrant_id="workflow",
                )
        return await self.next.handle_signal(input)

    async def handle_query(self, input: Any) -> Any:
        return await self.next.handle_query(input)

    def handle_update_validator(self, input: Any) -> None:
        config = self._resolve_config()
        if config and config.authorized_updates is not None:
            update_name = getattr(input, "update", None)
            if update_name not in config.authorized_updates:
                logger.warning(
                    f"Update '{update_name}' rejected at validation: "
                    "not in authorized_updates"
                )
                raise TemporalConstraintViolation(
                    tool=f"update:{update_name}",
                    arguments={},
                    constraint=f"Update not authorized: {update_name}",
                    warrant_id="workflow",
                )
        return self.next.handle_update_validator(input)

    async def handle_update_handler(self, input: Any) -> Any:
        config = self._resolve_config()
        if config and config.authorized_updates is not None:
            update_name = getattr(input, "update", None)
            if update_name not in config.authorized_updates:
                raise TemporalConstraintViolation(
                    tool=f"update:{update_name}",
                    arguments={},
                    constraint=f"Update not authorized: {update_name}",
                    warrant_id="workflow",
                )
        return await self.next.handle_update_handler(input)


# ── TenuoWorkerInterceptor (worker interceptor) ─────────────────────────

class TenuoWorkerInterceptor(_TemporalWorkerInterceptor):
    """Temporal Python SDK worker interceptor: warrant authorization (middleware / security).

    This is the low-level worker interceptor. Most users should use
    :class:`tenuo.temporal_plugin.TenuoTemporalPlugin` (a ``SimplePlugin`` that
    wires this interceptor up for you). Use this class directly only when you
    are hand-composing your own ``SimplePlugin`` or already have a custom
    ``Plugin`` and just want Tenuo's authorization interceptor.

    Stable identifier: :data:`TENUO_TEMPORAL_PLUGIN_ID` (``tenuo.TenuoTemporalPlugin``)
    for worker logs and Temporal Web activity summaries.

    .. note::

        This class was previously named ``TenuoPlugin``. The old name is still
        importable from :mod:`tenuo.temporal` as a deprecated alias and will
        be removed in a future beta. Imports should be updated to
        ``TenuoWorkerInterceptor`` — the new name correctly reflects that this
        is a Temporal SDK **interceptor**, not a Temporal SDK **plugin**.
    """

    def __init__(self, config: "TenuoPluginConfig") -> None:
        super().__init__()
        if config.control_plane is None:
            from tenuo.control_plane import get_or_create
            config.control_plane = get_or_create()
        self._config = config
        self._version = self._get_version()
        try:
            import tenuo_core as _tc  # noqa: F401
        except ImportError as _e:
            raise RuntimeError(
                "tenuo_core is not installed. "
                "Install tenuo with the native extension: pip install 'tenuo[temporal]'.\n\n"
                "If tenuo_core is installed but you are seeing a PyO3 sandbox error, "
                "ensure passthrough_modules are declared on the worker:\n\n"
                "    SandboxRestrictions.default.with_passthrough_modules('tenuo', 'tenuo_core')\n\n"
                "See the module docstring for a full Worker setup example."
            ) from _e

        if config.pop_dedup_store is None:
            logger.debug(
                "TenuoPluginConfig: using in-memory PopDedupStore (single-process only). "
                "In multi-worker deployments, set pop_dedup_store= to a shared backend "
                "(Redis, Memcached, etc.) for fleet-wide PoP replay prevention."
            )

        logger.info(
            "Loaded %s (warrant authorization middleware for Temporal Python SDK)",
            TENUO_TEMPORAL_PLUGIN_ID,
        )

    def __repr__(self) -> str:
        return f"<{TENUO_TEMPORAL_PLUGIN_ID}>"

    def _get_version(self) -> str:
        """Get Tenuo version for audit events."""
        try:
            from tenuo import __version__

            return __version__
        except ImportError:
            return "unknown"

    def intercept_activity(
        self,
        next_interceptor: Any,
    ) -> Any:
        """Return activity inbound wrapper."""
        return TenuoActivityInboundInterceptor(
            next_interceptor,
            self._config,
            self._version,
        )

    def workflow_interceptor_class(
        self,
        input: Any,
    ) -> Optional[type]:
        """Return workflow interceptor class that captures Tenuo headers."""
        bound_config = self._config
        interceptor_cls = type(
            "_TenuoWorkflowInboundInterceptor",
            (_TenuoWorkflowInboundInterceptor,),
            {"_config": bound_config},
        )
        return interceptor_cls


# ── Activity Inbound Interceptor ─────────────────────────────────────────

class TenuoActivityInboundInterceptor:
    """Activity-level interceptor that performs authorization checks."""

    def __init__(
        self,
        next_interceptor: Any,
        config: "TenuoPluginConfig",
        version: str,
    ) -> None:
        self._next = next_interceptor
        self._config = config
        self._version = version
        self._pop_dedup_store: PopDedupStore = (
            config.pop_dedup_store or _default_pop_dedup_store
        )
        self._trusted_roots_provider = config.trusted_roots_provider
        self._trusted_roots_refresh_interval = config.trusted_roots_refresh_interval_secs
        import time as _time

        self._last_trusted_roots_refresh = _time.monotonic()
        self._last_srl_refresh: float = _time.monotonic()
        self._authorizer_lock = threading.Lock()
        self._authorizer: Optional[Any] = None
        self._retry_authorizer: Optional[Any] = None
        try:
            from tenuo_core import Authorizer
            self._authorizer = self._build_authorizer(
                Authorizer, config.trusted_roots, config
            )
            if config.retry_pop_max_windows is not None:
                self._retry_authorizer = self._build_authorizer(
                    Authorizer,
                    config.trusted_roots,
                    config,
                    pop_max_windows=config.retry_pop_max_windows,
                )
        except ImportError as e:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "tenuo_core is required for TenuoWorkerInterceptor (Authorizer). "
                "Install tenuo with the native extension, or ensure the "
                "interpreter can import tenuo_core."
            ) from e

    @staticmethod
    def _build_authorizer(
        authorizer_cls: Any,
        trusted_roots: Any,
        config: "TenuoPluginConfig",
        **kwargs: Any,
    ) -> Any:
        """Build an Authorizer instance and apply config-level policies."""
        auth = authorizer_cls(trusted_roots=trusted_roots, **kwargs)
        if config.clearance_requirements:
            for tool, clearance in config.clearance_requirements.items():
                if hasattr(auth, "require_clearance"):
                    auth.require_clearance(tool, clearance)
        srl = config.revocation_list
        if srl is not None and hasattr(auth, "set_revocation_list"):
            auth.set_revocation_list(srl)
        return auth

    def _maybe_refresh_trusted_roots(self) -> None:
        """Rebuild Authorizer from ``trusted_roots_provider`` on a fixed interval."""
        import time as _time

        p = self._trusted_roots_provider
        interval = self._trusted_roots_refresh_interval
        if p is None or interval is None:
            return
        now = _time.monotonic()
        if (now - self._last_trusted_roots_refresh) < interval:
            return
        with self._authorizer_lock:
            now2 = _time.monotonic()
            if (now2 - self._last_trusted_roots_refresh) < interval:
                return
            try:
                roots = list(p())
            except Exception as e:
                logger.warning("trusted_roots_provider failed during refresh: %s", e)
                return
            if not roots:
                logger.warning(
                    "trusted_roots_provider returned empty during refresh; "
                    "keeping prior Authorizer"
                )
                return
            try:
                from tenuo_core import Authorizer

                self._authorizer = Authorizer(trusted_roots=roots)
                if self._config.retry_pop_max_windows is not None:
                    self._retry_authorizer = Authorizer(
                        trusted_roots=roots,
                        pop_max_windows=self._config.retry_pop_max_windows,
                    )
            except Exception as e:
                logger.warning(
                    "Authorizer rebuild failed during trusted root refresh: %s", e
                )
                return
            self._last_trusted_roots_refresh = _time.monotonic()

    def _maybe_refresh_revocation_list(self) -> None:
        """Refresh the SRL from ``revocation_list_provider`` on a fixed interval."""
        import time as _time

        provider = self._config.revocation_list_provider
        interval = self._config.revocation_refresh_secs
        if provider is None or interval is None:
            return
        now = _time.monotonic()
        if (now - self._last_srl_refresh) < interval:
            return
        with self._authorizer_lock:
            now2 = _time.monotonic()
            if (now2 - self._last_srl_refresh) < interval:
                return
            try:
                srl = provider()
            except Exception as e:
                logger.warning("revocation_list_provider failed during refresh: %s", e)
                return
            if srl is None:
                logger.warning(
                    "revocation_list_provider returned None during refresh; "
                    "keeping prior revocation list"
                )
                return
            import dataclasses as _dc
            try:
                self._config = _dc.replace(self._config, revocation_list=srl)
                for auth in (self._authorizer, self._retry_authorizer):
                    if auth is not None and hasattr(auth, "set_revocation_list"):
                        try:
                            auth.set_revocation_list(srl)
                        except Exception as e:
                            logger.warning(
                                "set_revocation_list failed during SRL refresh: %s", e
                            )
            except Exception as e:
                logger.warning("SRL refresh failed: %s", e)
                return
            self._last_srl_refresh = _time.monotonic()

    def init(self, outbound: Any) -> None:
        """Called by Temporal to initialize the interceptor with an outbound impl."""
        self._next.init(outbound)

    @staticmethod
    def _wrap_as_non_retryable(exc: Exception) -> Exception:
        """Wrap authorization failures as non-retryable ApplicationError."""
        try:
            from temporalio.exceptions import ApplicationError  # type: ignore[import-not-found]
        except ImportError:
            return exc
        return ApplicationError(
            str(exc),
            type=type(exc).__name__,
            non_retryable=True,
        )

    async def execute_activity(self, input: Any) -> Any:
        """Intercept activity execution for authorization."""
        try:
            from temporalio import activity  # type: ignore[import-not-found]
        except ImportError:
            return await self._next.execute_activity(input)

        info = activity.info()

        import time
        start_ns = time.perf_counter_ns()
        chain_result = None

        is_local = getattr(info, "is_local", False)
        activity_fn = getattr(input, "fn", None)

        if is_local and self._config.block_local_activities:
            if activity_fn is None:
                logger.warning(
                    f"Local activity {info.activity_type} denied: cannot determine protection status (fail-closed)"
                )
                raise self._wrap_as_non_retryable(LocalActivityError(info.activity_type))

            if not is_unprotected(activity_fn):
                raise self._wrap_as_non_retryable(LocalActivityError(info.activity_type))

            return await self._next.execute_activity(input)

        headers: Dict[str, bytes] = {}
        input_headers = getattr(input, "headers", None) or {}
        for k, v in input_headers.items():
            if k.startswith("x-tenuo-"):
                if isinstance(v, bytes):
                    headers[k] = v
                elif hasattr(v, "data") and isinstance(getattr(v, "data", None), bytes):
                    headers[k] = v.data

        try:
            warrant = _extract_warrant_from_headers(headers)
        except ChainValidationError as chain_exc:
            raise self._wrap_as_non_retryable(chain_exc) from chain_exc

        async def _deny_or_continue(tool: str, reason: str) -> Optional[Any]:
            if self._config.dry_run:
                logger.warning(
                    "DRY-RUN mode: would deny activity %s in workflow %s (%s); "
                    "executing anyway. Not for production.",
                    tool,
                    info.workflow_id,
                    reason,
                )
                return await self._next.execute_activity(input)

            if self._config.on_denial == "log":
                logger.warning(f"Authorization denied for {tool}: {reason}")
            return None

        if warrant is None:
            if self._config.require_warrant:
                logger.warning(f"No warrant for activity {info.activity_type}, denying (require_warrant=True)")
                if self._config.on_denial == "raise" and not self._config.dry_run:
                    raise self._wrap_as_non_retryable(TemporalConstraintViolation(
                        tool=info.activity_type,
                        arguments={},
                        constraint="No warrant provided (require_warrant=True)",
                        warrant_id="none",
                    ))
                return await _deny_or_continue(
                    tool=info.activity_type,
                    reason="No warrant provided (require_warrant=True)",
                )
            else:
                logger.warning(
                    "Unauthenticated activity execution: %s in workflow %s "
                    "(require_warrant=False — no warrant presented)",
                    info.activity_type,
                    info.workflow_id,
                )
                return await self._next.execute_activity(input)

        activity_fn = getattr(input, "fn", None)
        tool_name = _warrant_tool_name_for_activity_type(
            self._config, info.activity_type, activity_fn
        )

        args = self._extract_arguments(input, headers)

        chain_depth = warrant.depth if hasattr(warrant, "depth") else 0
        if chain_depth > self._config.max_chain_depth:
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
                constraint="max_chain_depth_exceeded",
                start_ns=start_ns,
            )
            if self._config.on_denial == "raise" and not self._config.dry_run:
                raise self._wrap_as_non_retryable(ChainValidationError(
                    reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
                    depth=chain_depth,
                ))
            return await _deny_or_continue(
                tool=tool_name,
                reason=f"Chain depth {chain_depth} exceeds max {self._config.max_chain_depth}",
            )

        self._maybe_refresh_trusted_roots()
        self._maybe_refresh_revocation_list()

        if self._authorizer is None:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "Tenuo activity interceptor missing Authorizer; "
                "use TenuoPluginConfig with trusted_roots."
            )

        _span_ctx: Any = None
        if _otel_available and _otel_trace is not None:
            _tracer = _otel_trace.get_tracer("tenuo.temporal")
            _span_ctx = _tracer.start_as_current_span("tenuo.authorize")
            _span_ctx.__enter__()
            _active_span = _otel_trace.get_current_span()
            _warrant_id_str = getattr(warrant, "id", "") or ""
            _active_span.set_attribute("tenuo.tool", tool_name)
            _active_span.set_attribute("tenuo.warrant_id", _warrant_id_str)
        else:
            _active_span = None

        try:
            from tenuo_core import decode_warrant_stack_base64 as _decode_stack

            if info.attempt > 1 and self._retry_authorizer is not None:
                authorizer = self._retry_authorizer
            else:
                if info.attempt > 1:
                    logger.debug(
                        "Activity '%s' is a retry (attempt=%d). If this fails with "
                        "PopVerificationError, set TenuoPluginConfig.retry_pop_max_windows "
                        "to accommodate Temporal's retry time offset (e.g. 120 for 1 hour).",
                        tool_name, info.attempt,
                    )
                authorizer = self._authorizer

            pop_bytes = None
            pop_header = headers.get(TENUO_POP_HEADER)
            if pop_header:
                pop_bytes = base64.b64decode(pop_header)

            gate_approvals = self._resolve_approval_gate_approvals(
                warrant, tool_name, args, headers,
            )

            chain_header = headers.get(TENUO_CHAIN_HEADER)
            if chain_header:
                chain = _decode_stack(chain_header.decode("utf-8"))
                chain_result = authorizer.check_chain(
                    chain, tool_name, args,
                    signature=pop_bytes,
                    approvals=gate_approvals,
                )
            else:
                chain_result = authorizer.authorize_one(
                    warrant, tool_name, args,
                    signature=pop_bytes,
                    approvals=gate_approvals,
                )

            if info.attempt <= 1:
                base_dedup = warrant.dedup_key(tool_name, args)
                dedup_key = (
                    f"{base_dedup}:{info.workflow_id}:"
                    f"{info.workflow_run_id}:{info.activity_id}"
                )
                now = datetime.now(timezone.utc).timestamp()
                ttl = float(warrant.dedup_ttl_secs())
                self._pop_dedup_store.check_pop_replay(
                    dedup_key, now, ttl, activity_name=tool_name
                )

            if _active_span is not None:
                _active_span.set_attribute("tenuo.decision", "allow")
                _active_span.set_attribute("tenuo.constraint_violated", "")

        except (TemporalConstraintViolation, PopVerificationError, ChainValidationError, WarrantExpired) as auth_exc:
            if _active_span is not None:
                _active_span.set_attribute("tenuo.decision", "deny")
                _active_span.set_attribute("tenuo.constraint_violated", "")
                if _span_ctx is not None:
                    _span_ctx.__exit__(None, None, None)
                    _span_ctx = None
            raise self._wrap_as_non_retryable(auth_exc) from auth_exc
        except Exception as e:
            try:
                from tenuo.exceptions import TenuoError as _TenuoError
                from tenuo.exceptions import ExpiredError as _ExpiredError
            except ImportError:
                _TenuoError = TenuoTemporalError  # type: ignore[assignment, misc]
                _ExpiredError = type(None)  # type: ignore[assignment, misc]

            if isinstance(e, (_TenuoError, TenuoTemporalError)):
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason=str(e),
                    start_ns=start_ns,
                )
                if _active_span is not None:
                    _active_span.set_attribute("tenuo.decision", "deny")
                    _active_span.set_attribute("tenuo.constraint_violated", str(e))
                    if _otel_available and _otel_trace is not None:
                        _active_span.set_status(
                            _otel_trace.Status(_otel_trace.StatusCode.ERROR, str(e))
                        )
                    if _span_ctx is not None:
                        _span_ctx.__exit__(None, None, None)
                        _span_ctx = None
                if self._config.on_denial == "raise" and not self._config.dry_run:
                    if isinstance(e, _ExpiredError):
                        expired_at = getattr(e, "details", {}).get("expired_at")
                        raise self._wrap_as_non_retryable(WarrantExpired(
                            warrant_id=getattr(warrant, "id", ""),
                            expired_at=datetime.fromisoformat(expired_at) if expired_at else datetime.now(timezone.utc),
                        )) from e
                    raise self._wrap_as_non_retryable(TemporalConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint=str(e),
                        warrant_id=warrant.id,
                    )) from e
                return await _deny_or_continue(tool=tool_name, reason=str(e))
            else:
                if _active_span is not None and _span_ctx is not None:
                    _span_ctx.__exit__(None, None, None)
                    _span_ctx = None
                logger.error(
                    f"Internal error during authorization for {tool_name}: {e}",
                    exc_info=True,
                )
                raise
        finally:
            if _span_ctx is not None:
                _span_ctx.__exit__(None, None, None)

        self._emit_allow_event(
            info=info,
            warrant=warrant,
            tool=tool_name,
            args=args,
            start_ns=start_ns,
            chain_result=chain_result,
        )

        return await self._next.execute_activity(input)

    def _resolve_approval_gate_approvals(
        self,
        warrant: Any,
        tool_name: str,
        args: Dict[str, Any],
        headers: Dict[str, bytes],
    ) -> Optional[List[Any]]:
        """Evaluate warrant approval gates and collect approvals when a gate fires."""
        from tenuo_core import evaluate_approval_gates as _evaluate_approval_gates

        if not _evaluate_approval_gates(warrant, tool_name, args):
            return None

        from tenuo_core import SignedApproval as CoreSignedApproval

        raw_approvals_header = headers.get(TENUO_APPROVALS_HEADER)
        if raw_approvals_header:
            try:
                approvals_list = json.loads(raw_approvals_header)
                return [
                    CoreSignedApproval.from_bytes(base64.b64decode(a))
                    for a in approvals_list
                ]
            except Exception as e:
                logger.warning(f"Failed to decode approvals header: {e}")

        handler = self._config.approval_handler if self._config else None
        if handler is not None:
            try:
                from tenuo_core import py_compute_request_hash as _compute_hash
                from tenuo.approval import ApprovalRequest

                holder_key = getattr(warrant, "holder_key", None)
                warrant_id = getattr(warrant, "id", "") or ""
                request_hash = _compute_hash(warrant_id, tool_name, args, holder_key)
                request = ApprovalRequest.for_warrant_gate(
                    tool_name,
                    args,
                    warrant,
                    request_hash,
                    holder_key=holder_key,
                )

                result = handler(request)
                if _inspect.isawaitable(result):
                    import asyncio
                    from typing import cast, Coroutine as _Coro
                    coro = cast(_Coro[Any, Any, Any], result)
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None
                    if loop and loop.is_running():
                        future = asyncio.run_coroutine_threadsafe(coro, loop)
                        result = future.result(timeout=300)
                    else:
                        result = asyncio.run(coro)

                collected = result if isinstance(result, list) else [result]

                approvers = warrant.required_approvers()
                threshold = warrant.approval_threshold()
                from tenuo_core import verify_approvals as _verify
                _verify(request_hash, collected, approvers, threshold)

                return collected
            except Exception:
                raise

        raise ApprovalGateTriggered(
            tool=tool_name,
            hint=(
                "No approvals available — set approval_handler on "
                "TenuoPluginConfig or supply x-tenuo-approvals header"
            ),
        )

    def _extract_arguments(
        self, input: Any, headers: Optional[Dict[str, bytes]] = None,
    ) -> Dict[str, Any]:
        """Extract arguments from activity input with proper signature mapping."""
        args = getattr(input, "args", ()) or ()

        if headers and TENUO_ARG_KEYS_HEADER in headers:
            keys = headers[TENUO_ARG_KEYS_HEADER].decode("utf-8").split(",")
            result: Dict[str, Any] = {}
            for i, arg in enumerate(args):
                result[keys[i] if i < len(keys) else f"arg{i}"] = arg
            return result

        activity_fn = getattr(input, "fn", None)
        if activity_fn and args:
            return _args_to_dict_by_fn(args, activity_fn)

        if args and isinstance(args[0], dict):
            return args[0]

        return {f"arg{i}": arg for i, arg in enumerate(args)}

    def _redact_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Redact argument values for logging."""
        if not self._config.redact_args_in_logs:
            return args
        return {k: "[REDACTED]" for k in args.keys()}

    def _emit_allow_event(
        self,
        info: Any,
        warrant: Any,
        tool: str,
        args: Dict[str, Any],
        start_ns: Optional[int] = None,
        chain_result: Optional[Any] = None,
    ) -> None:
        """Emit audit event for allowed action."""
        import time
        latency_s = (time.perf_counter_ns() - start_ns) / 1e9 if start_ns else 0.0

        if self._config.metrics is not None:
            wf_type = getattr(info, "workflow_type", "")
            self._config.metrics.record_authorized(
                tool=tool,
                workflow_type=wf_type,
                latency_seconds=latency_s,
            )

        if self._config.control_plane:
            from tenuo._enforcement import EnforcementResult
            latency_us = int(latency_s * 1e6)

            res = EnforcementResult(
                allowed=True,
                tool=tool,
                arguments=args,
                warrant_id=getattr(warrant, "id", None)
            )
            try:
                self._config.control_plane.emit_for_enforcement(
                    res, chain_result=chain_result, latency_us=latency_us
                )
            except Exception:
                logger.warning("Control plane emission failed for '%s'; audit event lost", tool, exc_info=True)

        if not self._config.audit_allow or not self._config.audit_callback:
            return

        event = TemporalAuditEvent(
            workflow_id=info.workflow_id,
            workflow_type=info.workflow_type,
            workflow_run_id=info.workflow_run_id,
            activity_name=info.activity_type,
            activity_id=info.activity_id,
            task_queue=info.task_queue,
            decision="ALLOW",
            tool=tool,
            arguments=self._redact_args(args),
            warrant_id=warrant.id,
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools or []),
            tenuo_version=self._version,
        )

        try:
            self._config.audit_callback(event)
        except Exception as e:
            logger.error(f"Audit callback failed: {e}")

    def _emit_denial_event(
        self,
        info: Any,
        warrant: Any,
        tool: str,
        args: Dict[str, Any],
        reason: str,
        constraint: Optional[str] = None,
        start_ns: Optional[int] = None,
    ) -> None:
        """Emit audit event for denied action."""
        import time
        latency_s = (time.perf_counter_ns() - start_ns) / 1e9 if start_ns else 0.0

        if self._config.metrics is not None:
            wf_type = getattr(info, "workflow_type", "")
            self._config.metrics.record_denied(
                tool=tool,
                reason=reason,
                workflow_type=wf_type,
                latency_seconds=latency_s,
            )

        if self._config.control_plane:
            from tenuo._enforcement import EnforcementResult
            latency_us = int(latency_s * 1e6)

            warrant_stack_b64 = None
            try:
                from tenuo_core import encode_warrant_stack
                warrant_stack_b64 = encode_warrant_stack([warrant])
            except Exception:
                pass

            res = EnforcementResult(
                allowed=False,
                tool=tool,
                arguments=args,
                denial_reason=reason,
                constraint_violated=constraint,
                warrant_id=getattr(warrant, "id", None),
            )
            try:
                self._config.control_plane.emit_for_enforcement(
                    res, chain_result=None, latency_us=latency_us,
                    warrant_stack_override=warrant_stack_b64,
                )
            except Exception:
                logger.warning("Control plane emission failed for '%s'; audit event lost", tool, exc_info=True)

        if not self._config.audit_deny or not self._config.audit_callback:
            return

        event = TemporalAuditEvent(
            workflow_id=info.workflow_id,
            workflow_type=info.workflow_type,
            workflow_run_id=info.workflow_run_id,
            activity_name=info.activity_type,
            activity_id=info.activity_id,
            task_queue=info.task_queue,
            decision="DENY",
            tool=tool,
            arguments=self._redact_args(args),
            warrant_id=warrant.id,
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools or []),
            denial_reason=reason,
            constraint_violated=constraint,
            tenuo_version=self._version,
        )

        try:
            self._config.audit_callback(event)
        except Exception as e:
            logger.error(f"Audit callback failed: {e}")
