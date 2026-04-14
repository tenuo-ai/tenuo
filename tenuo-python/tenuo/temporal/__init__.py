"""
Tenuo Temporal Integration — Warrant-based Authorization for Durable Workflows

This package provides transparent authorization for Temporal Python SDK
workflows using Tenuo warrants and Proof-of-Possession (PoP) signatures.

Quick start::

    from tenuo.temporal import TenuoPluginConfig, EnvKeyResolver

    plugin = TenuoTemporalPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
        )
    )
    client = await Client.connect("localhost:7233", plugins=[plugin])

Submodule layout
----------------
For direct imports (preferred in library / internal code)::

    tenuo.temporal._config        TenuoPluginConfig
    tenuo.temporal._resolvers     KeyResolver, EnvKeyResolver, VaultKeyResolver, …
    tenuo.temporal._headers       tenuo_headers
    tenuo.temporal._workflow      execute_workflow_authorized, start_workflow_authorized,
                                  tenuo_execute_activity, tenuo_execute_child_workflow,
                                  AuthorizedWorkflow, current_warrant, current_key_id,
                                  workflow_grant, workflow_issue_execution,
                                  set_activity_approvals, tenuo_continue_as_new, …
    tenuo.temporal._client        TenuoClientInterceptor, TenuoWarrantContextPropagator,
                                  tenuo_warrant_context
    tenuo.temporal._interceptors  TenuoPlugin
    tenuo.temporal._dedup         PopDedupStore, InMemoryPopDedupStore
    tenuo.temporal._decorators    tool, unprotected
    tenuo.temporal._observability TemporalAuditEvent, TenuoMetrics
    tenuo.temporal._constants     TENUO_WARRANT_HEADER, TENUO_KEY_ID_HEADER, …
    tenuo.temporal.exceptions     TenuoContextError, PopVerificationError, …
    tenuo.temporal_plugin         TenuoTemporalPlugin, ensure_tenuo_workflow_runner
"""

from __future__ import annotations

from typing import Any

# Curated public re-exports: the essentials for getting started.
from tenuo.temporal._config import TenuoPluginConfig  # noqa: F401
from tenuo.temporal._resolvers import (  # noqa: F401
    EnvKeyResolver,
    KeyResolver,
)
from tenuo.temporal._headers import tenuo_headers  # noqa: F401
from tenuo.temporal._interceptors import TenuoPlugin  # noqa: F401
from tenuo.temporal._client import TenuoClientInterceptor  # noqa: F401
from tenuo.temporal.exceptions import TenuoContextError  # noqa: F401

# Lazy-loaded symbols: resolved on first access so the package stays lightweight
# while ``from tenuo.temporal import X`` works for all documented names.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    # temporal_plugin (heavy: pulls in temporalio.plugin)
    "TenuoTemporalPlugin": ("tenuo.temporal_plugin", "TenuoTemporalPlugin"),
    "ensure_tenuo_workflow_runner": ("tenuo.temporal_plugin", "ensure_tenuo_workflow_runner"),
    # _workflow — user-facing helpers
    "execute_workflow_authorized": ("tenuo.temporal._workflow", "execute_workflow_authorized"),
    "start_workflow_authorized": ("tenuo.temporal._workflow", "start_workflow_authorized"),
    "tenuo_execute_activity": ("tenuo.temporal._workflow", "tenuo_execute_activity"),
    "tenuo_execute_child_workflow": ("tenuo.temporal._workflow", "tenuo_execute_child_workflow"),
    "AuthorizedWorkflow": ("tenuo.temporal._workflow", "AuthorizedWorkflow"),
    "current_warrant": ("tenuo.temporal._workflow", "current_warrant"),
    "current_key_id": ("tenuo.temporal._workflow", "current_key_id"),
    "workflow_grant": ("tenuo.temporal._workflow", "workflow_grant"),
    "workflow_issue_execution": ("tenuo.temporal._workflow", "workflow_issue_execution"),
    "set_activity_approvals": ("tenuo.temporal._workflow", "set_activity_approvals"),
    "attenuated_headers": ("tenuo.temporal._workflow", "attenuated_headers"),
    "tenuo_continue_as_new": ("tenuo.temporal._workflow", "tenuo_continue_as_new"),
    # _client
    "TenuoWarrantContextPropagator": ("tenuo.temporal._client", "TenuoWarrantContextPropagator"),
    "tenuo_warrant_context": ("tenuo.temporal._client", "tenuo_warrant_context"),
    # _decorators
    "tool": ("tenuo.temporal._decorators", "tool"),
    "unprotected": ("tenuo.temporal._decorators", "unprotected"),
    # _resolvers (additional)
    "VaultKeyResolver": ("tenuo.temporal._resolvers", "VaultKeyResolver"),
    "AWSSecretsManagerKeyResolver": ("tenuo.temporal._resolvers", "AWSSecretsManagerKeyResolver"),
    "GCPSecretManagerKeyResolver": ("tenuo.temporal._resolvers", "GCPSecretManagerKeyResolver"),
    "CompositeKeyResolver": ("tenuo.temporal._resolvers", "CompositeKeyResolver"),
    # _dedup
    "PopDedupStore": ("tenuo.temporal._dedup", "PopDedupStore"),
    "InMemoryPopDedupStore": ("tenuo.temporal._dedup", "InMemoryPopDedupStore"),
    # _observability
    "TemporalAuditEvent": ("tenuo.temporal._observability", "TemporalAuditEvent"),
    "TenuoMetrics": ("tenuo.temporal._observability", "TenuoMetrics"),
    # exceptions (additional)
    "TemporalConstraintViolation": ("tenuo.temporal.exceptions", "TemporalConstraintViolation"),
    "WarrantExpired": ("tenuo.temporal.exceptions", "WarrantExpired"),
    "ChainValidationError": ("tenuo.temporal.exceptions", "ChainValidationError"),
    "PopVerificationError": ("tenuo.temporal.exceptions", "PopVerificationError"),
    "LocalActivityError": ("tenuo.temporal.exceptions", "LocalActivityError"),
    "KeyResolutionError": ("tenuo.temporal.exceptions", "KeyResolutionError"),
    # _constants
    "TENUO_WARRANT_HEADER": ("tenuo.temporal._constants", "TENUO_WARRANT_HEADER"),
    "TENUO_KEY_ID_HEADER": ("tenuo.temporal._constants", "TENUO_KEY_ID_HEADER"),
    "TENUO_POP_HEADER": ("tenuo.temporal._constants", "TENUO_POP_HEADER"),
    "TENUO_COMPRESSED_HEADER": ("tenuo.temporal._constants", "TENUO_COMPRESSED_HEADER"),
}


def __getattr__(name: str) -> Any:
    entry = _LAZY_IMPORTS.get(name)
    if entry is not None:
        module_path, attr = entry
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    eager = list(globals())
    return sorted(set(eager) | set(_LAZY_IMPORTS))


__all__ = [
    # Eagerly loaded
    "TenuoPluginConfig",
    "KeyResolver",
    "EnvKeyResolver",
    "tenuo_headers",
    "TenuoPlugin",
    "TenuoClientInterceptor",
    "TenuoContextError",
    # Lazy-loaded (documented public API)
    *_LAZY_IMPORTS,
]
