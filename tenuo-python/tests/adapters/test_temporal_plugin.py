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
from tenuo.temporal._client import TenuoClientInterceptor  # noqa: E402
from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._interceptors import TenuoPlugin  # noqa: E402
from tenuo.temporal._resolvers import EnvKeyResolver  # noqa: E402
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


def test_plugin_name_matches_expected_id() -> None:
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


def test_internal_mint_activity_registered():
    """_tenuo_internal_mint_activity is auto-registered by TenuoTemporalPlugin."""
    pytest.importorskip("temporalio")
    from tenuo.temporal._workflow import _tenuo_internal_mint_activity

    # The activity should be importable
    assert _tenuo_internal_mint_activity is not None
    # Its registered name should be "__tenuo_internal_mint"
    assert getattr(_tenuo_internal_mint_activity, "__temporal_activity_definition", None) is not None
    defn = _tenuo_internal_mint_activity.__temporal_activity_definition
    assert defn.name == "__tenuo_internal_mint"


# ---------------------------------------------------------------------------
# Item 1.2 — activity_fns auto-discovery
# ---------------------------------------------------------------------------

def test_activity_fns_auto_discovered() -> None:
    """TenuoTemporalPlugin auto-populates activity_fns from worker activities."""
    config = _minimal_config()
    assert not config.activity_fns  # starts empty

    plugin = TenuoTemporalPlugin(config)

    def mock_activity_a() -> None:
        pass

    def mock_activity_b() -> None:
        pass

    # Simulate what SimplePlugin.configure_worker does: call the activities callable
    # with the existing activities list, then check config.activity_fns is populated.
    result = plugin.activities([mock_activity_a, mock_activity_b])  # type: ignore[operator]
    assert len(config.activity_fns) == 2  # noqa: PLR2004
    assert mock_activity_a in config.activity_fns
    assert mock_activity_b in config.activity_fns
    # The internal mint activity should also be appended to the return value
    assert len(result) >= 2  # noqa: PLR2004


def test_activity_fns_not_overwritten_if_already_set() -> None:
    """If activity_fns is already set, auto-discovery should not overwrite it."""

    def explicit_fn() -> None:
        pass

    config = _minimal_config()
    config.activity_fns = [explicit_fn]

    plugin = TenuoTemporalPlugin(config)

    def other_fn() -> None:
        pass

    plugin.activities([other_fn])  # type: ignore[operator]
    # Should still have only explicit_fn (not replaced by other_fn)
    assert config.activity_fns == [explicit_fn]


# ---------------------------------------------------------------------------
# Item 1.5 — Duplicate plugin hard error
# ---------------------------------------------------------------------------

def test_duplicate_plugin_registration_raises() -> None:
    """Calling configure_worker twice on the same instance raises ConfigurationError."""
    from tenuo.exceptions import ConfigurationError as TenuoConfigError

    plugin = TenuoTemporalPlugin(_minimal_config())

    # First call succeeds
    plugin.activities([])  # type: ignore[operator]

    # Second call on the same instance should raise
    with pytest.raises(TenuoConfigError, match="duplicate Tenuo plugin registered"):
        plugin.activities([])  # type: ignore[operator]


# ---------------------------------------------------------------------------
# Item 1.6 — preload_all() auto-called
# ---------------------------------------------------------------------------

def test_preload_all_auto_called() -> None:
    """TenuoTemporalPlugin.configure_worker auto-calls preload_all() if available."""
    preload_called: list[bool] = []

    class MockResolver:
        def resolve_sync(self, key_id: str) -> None:
            return None

        def preload_all(self) -> int:
            preload_called.append(True)
            return 0

    config = _minimal_config()
    config.key_resolver = MockResolver()  # type: ignore[assignment]

    plugin = TenuoTemporalPlugin(config)
    plugin.activities([])  # type: ignore[operator]

    assert preload_called, "preload_all() should have been called automatically"


def test_preload_all_not_called_if_unsupported() -> None:
    """If key_resolver has no preload_all(), configure_worker does not error."""
    class NoPreloadResolver:
        def resolve_sync(self, key_id: str) -> None:
            return None

    config = _minimal_config()
    config.key_resolver = NoPreloadResolver()  # type: ignore[assignment]

    plugin = TenuoTemporalPlugin(config)
    # Should not raise even though NoPreloadResolver has no preload_keys()
    plugin.activities([])  # type: ignore[operator]


# ---------------------------------------------------------------------------
# Item 2.4 — Data-plane-only (read-only) workers
# ---------------------------------------------------------------------------

def test_none_key_resolver_raises() -> None:
    """TenuoPluginConfig rejects key_resolver=None (signing material required)."""
    from tenuo.exceptions import ConfigurationError

    sk = SigningKey.generate()
    with pytest.raises(ConfigurationError, match="key_resolver|signing_key"):
        TenuoPluginConfig(key_resolver=None, trusted_roots=[sk.public_key])


def test_no_signing_material_raises() -> None:
    """TenuoPluginConfig rejects construction without any signing material."""
    from tenuo.exceptions import ConfigurationError

    sk = SigningKey.generate()
    with pytest.raises(ConfigurationError, match="key_resolver|signing_key"):
        TenuoPluginConfig(trusted_roots=[sk.public_key])


def test_signing_key_synthesizes_resolver() -> None:
    """Passing signing_key= synthesizes a key_resolver automatically."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(signing_key=sk, trusted_roots=[sk.public_key])
    assert config.key_resolver is not None


def test_key_resolver_with_value_still_works() -> None:
    """Existing TenuoPluginConfig(key_resolver=EnvKeyResolver()) calls are unchanged."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[sk.public_key],
    )
    assert config.key_resolver is not None


# ---------------------------------------------------------------------------
# Item 2.1a — clearance_requirements config field
# ---------------------------------------------------------------------------


def test_clearance_requirements_none_by_default() -> None:
    """clearance_requirements defaults to None (no behavioral change when unset)."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(signing_key=sk, trusted_roots=[sk.public_key])
    assert config.clearance_requirements is None


def test_clearance_requirements_field_accepted() -> None:
    """clearance_requirements accepts a Dict[str, Clearance] without error."""
    Clearance = pytest.importorskip("tenuo_core", reason="tenuo_core not available").Clearance
    sk = SigningKey.generate()
    config = TenuoPluginConfig(
        signing_key=sk,
        trusted_roots=[sk.public_key],
        clearance_requirements={"send_email": Clearance.INTERNAL},
    )
    assert config.clearance_requirements is not None
    assert "send_email" in config.clearance_requirements


def test_clearance_requirements_multiple_tools() -> None:
    """clearance_requirements accepts multiple tool patterns including wildcard."""
    Clearance = pytest.importorskip("tenuo_core", reason="tenuo_core not available").Clearance
    sk = SigningKey.generate()
    config = TenuoPluginConfig(
        signing_key=sk,
        trusted_roots=[sk.public_key],
        clearance_requirements={
            "*": Clearance.EXTERNAL,
            "admin_*": Clearance.PRIVILEGED,
        },
    )
    assert len(config.clearance_requirements) == 2  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Item 2.1b — SRL (Signed Revocation List) support config fields
# ---------------------------------------------------------------------------


def test_revocation_list_none_by_default() -> None:
    """revocation_list defaults to None (no behavioral change when unset)."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(signing_key=sk, trusted_roots=[sk.public_key])
    assert config.revocation_list is None


def test_revocation_list_field_accepted() -> None:
    """revocation_list=None is accepted without error."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(signing_key=sk, trusted_roots=[sk.public_key], revocation_list=None)
    assert config.revocation_list is None


def test_revocation_list_provider_accepted() -> None:
    """revocation_list_provider and revocation_refresh_secs are accepted."""
    sk = SigningKey.generate()
    provider = lambda: None  # noqa: E731
    config = TenuoPluginConfig(
        signing_key=sk,
        trusted_roots=[sk.public_key],
        revocation_list_provider=provider,
        revocation_refresh_secs=60,
    )
    assert config.revocation_list_provider is provider
    assert config.revocation_refresh_secs == 60


def test_revocation_refresh_secs_none_by_default() -> None:
    """revocation_refresh_secs defaults to None."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(signing_key=sk, trusted_roots=[sk.public_key])
    assert config.revocation_refresh_secs is None


def test_revocation_list_provider_none_by_default() -> None:
    """revocation_list_provider defaults to None."""
    sk = SigningKey.generate()
    config = TenuoPluginConfig(signing_key=sk, trusted_roots=[sk.public_key])
    assert config.revocation_list_provider is None
