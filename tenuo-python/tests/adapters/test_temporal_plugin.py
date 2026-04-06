"""Unit tests for ``TenuoTemporalPlugin`` (temporalio SimplePlugin integration)."""

import inspect
from unittest.mock import MagicMock

import pytest

pytest.importorskip("temporalio")

from temporalio.plugin import SimplePlugin  # noqa: E402
from temporalio.worker.workflow_sandbox import (  # noqa: E402
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

from tenuo import SigningKey  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    EnvKeyResolver,
    TenuoClientInterceptor,
    TenuoPlugin,
    TenuoPluginConfig,
)
from tenuo.temporal_plugin import (  # noqa: E402
    TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME,
    TenuoTemporalPlugin,
    _simple_plugin_interceptor_kwargs,
    ensure_tenuo_workflow_runner,
)


def _minimal_config() -> TenuoPluginConfig:
    sk = SigningKey.generate()
    return TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[sk.public_key],
    )


def test_plugin_name_matches_partner_id() -> None:
    p = TenuoTemporalPlugin(_minimal_config())
    assert p.name() == TENUO_TEMPORAL_SIMPLE_PLUGIN_NAME == "tenuo.TenuoTemporalPlugin"


def test_client_interceptor_exposed_and_shared() -> None:
    ci = TenuoClientInterceptor()
    p = TenuoTemporalPlugin(_minimal_config(), client_interceptor=ci)
    assert p.client_interceptor is ci
    p2 = TenuoTemporalPlugin(_minimal_config())
    assert isinstance(p2.client_interceptor, TenuoClientInterceptor)


def test_simple_plugin_interceptor_kwargs_match_sdk_signature() -> None:
    """Every key we pass to ``SimplePlugin.__init__`` must exist on the installed SDK."""
    ci = TenuoClientInterceptor()
    wi = TenuoPlugin(_minimal_config())
    kw = _simple_plugin_interceptor_kwargs(ci, wi)
    params = inspect.signature(SimplePlugin.__init__).parameters
    for name in kw:
        assert name in params, f"SimplePlugin.__init__ has no {name!r} (got {sorted(kw)})"


def test_configure_worker_merges_interceptor_and_runner() -> None:
    ci = TenuoClientInterceptor()
    p = TenuoTemporalPlugin(_minimal_config(), client_interceptor=ci)
    cfg: dict = {}
    # Unified ``interceptors=`` SimplePlugin reads the client's interceptor list when merging.
    if "interceptors" in inspect.signature(SimplePlugin.__init__).parameters:
        mock_client = MagicMock()
        mock_client.config.return_value = {"interceptors": [ci]}
        cfg["client"] = mock_client
    out = p.configure_worker(cfg)
    inters = out.get("interceptors") or []
    assert len(inters) == 1
    assert isinstance(inters[0], TenuoPlugin)
    wr = out.get("workflow_runner")
    assert isinstance(wr, SandboxedWorkflowRunner)


def test_configure_client_merges_client_interceptors() -> None:
    p = TenuoTemporalPlugin(_minimal_config())
    out = p.configure_client({})
    assert len(out.get("interceptors") or []) == 1


def test_ensure_tenuo_workflow_runner_none() -> None:
    wr = ensure_tenuo_workflow_runner(None)
    assert isinstance(wr, SandboxedWorkflowRunner)


def test_ensure_tenuo_workflow_runner_preserves_custom_restrictions() -> None:
    base = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("json")
    )
    wr = ensure_tenuo_workflow_runner(base)
    assert isinstance(wr, SandboxedWorkflowRunner)
    assert wr is not base


def test_ensure_tenuo_workflow_runner_non_sandbox_unchanged() -> None:
    class _NotSandboxed:
        """Stand-in for an unsandboxed :class:`WorkflowRunner`."""

    existing = _NotSandboxed()
    assert ensure_tenuo_workflow_runner(existing) is existing


def test_lazy_export_from_tenuo_temporal() -> None:
    import tenuo.temporal as tt

    cls = tt.TenuoTemporalPlugin
    assert cls is TenuoTemporalPlugin
    assert tt.ensure_tenuo_workflow_runner is ensure_tenuo_workflow_runner
