"""Regression tests for Temporal integration bugs.

Each test below targets a specific bug where the previous test suite had no
coverage. See CHANGELOG for the corresponding fixes.
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("temporalio")

from tenuo import SigningKey  # noqa: E402
from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._constants import (  # noqa: E402
    TENUO_COMPRESSED_HEADER,
    TENUO_WARRANT_HEADER,
)
from tenuo.temporal._headers import tenuo_headers  # noqa: E402
from tenuo.temporal._interceptors import (  # noqa: E402
    TenuoActivityInboundInterceptor,
    TenuoWorkerInterceptor,
    _TenuoWorkflowInboundInterceptor,
    _store_lock,
    _workflow_headers_store,
)
from tenuo.temporal._observability import TenuoMetrics  # noqa: E402
from tenuo.temporal._resolvers import EnvKeyResolver  # noqa: E402


# ---------------------------------------------------------------------------
# Fix #1: trusted_roots_provider refresh must preserve clearance + SRL
# ---------------------------------------------------------------------------


class _FakeAuthorizer:
    """Minimal Authorizer stand-in that records policy mutations."""

    instances: List["_FakeAuthorizer"] = []

    def __init__(self, *, trusted_roots: Any, **kwargs: Any) -> None:
        self.trusted_roots = list(trusted_roots)
        self.kwargs = kwargs
        self.clearance: dict = {}
        self.srl: Any = None
        _FakeAuthorizer.instances.append(self)

    def require_clearance(self, tool: str, clearance: Any) -> None:
        self.clearance[tool] = clearance

    def set_revocation_list(self, srl: Any) -> None:
        self.srl = srl


def test_trusted_roots_refresh_preserves_clearance_and_srl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refresh must re-apply clearance_requirements and the current SRL.

    Before the fix, ``_maybe_refresh_trusted_roots`` rebuilt the Authorizer
    with only ``trusted_roots=``, silently dropping clearance policy and SRL.
    """
    _FakeAuthorizer.instances.clear()
    import tenuo_core  # type: ignore[import-not-found]

    monkeypatch.setattr(tenuo_core, "Authorizer", _FakeAuthorizer)

    initial_root = SigningKey.generate().public_key
    rotated_root = SigningKey.generate().public_key

    clearance_requirements = {"read_file": "high"}
    srl = object()

    roots_to_return = [initial_root]

    def provider() -> List[Any]:
        return list(roots_to_return)

    cfg = TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots_provider=provider,
        trusted_roots_refresh_interval_secs=1.0,
        clearance_requirements=clearance_requirements,
        revocation_list=srl,
    )
    # The Authorizer is constructed inside the activity interceptor, not the
    # outer worker interceptor, so go straight to the source.
    activity_interceptor = TenuoActivityInboundInterceptor(
        next_interceptor=MagicMock(),
        config=cfg,
        version="test",
    )
    assert _FakeAuthorizer.instances[-1].clearance == clearance_requirements
    assert _FakeAuthorizer.instances[-1].srl is srl

    # Rotate the provider's return value, then force an immediate refresh.
    roots_to_return = [rotated_root]
    activity_interceptor._last_trusted_roots_refresh = -1e9
    activity_interceptor._maybe_refresh_trusted_roots()

    rebuilt = _FakeAuthorizer.instances[-1]
    assert rebuilt.trusted_roots == [rotated_root], "refresh should use rotated roots"
    assert rebuilt.clearance == clearance_requirements, (
        "clearance_requirements must be re-applied after refresh"
    )
    assert rebuilt.srl is srl, "SRL must be re-applied after refresh"


def test_worker_interceptor_accepts_trusted_roots_provider_without_control_plane() -> None:
    """``TenuoWorkerInterceptor`` must not blow up when constructed with a
    provider-based config and no explicit ``control_plane=``.

    Regression: previously ``__init__`` used ``dataclasses.replace`` to attach
    a default control plane, which re-ran ``__post_init__`` and tripped the
    "pass either trusted_roots= or trusted_roots_provider=, not both" check
    because the first post-init had already seeded ``trusted_roots`` from
    the provider.
    """
    root = SigningKey.generate().public_key
    cfg = TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots_provider=lambda: [root],
    )
    # Must not raise.
    interceptor = TenuoWorkerInterceptor(cfg)
    # The provider-based config survives the control-plane attach step: the
    # provider reference is preserved and trusted_roots stays seeded from it.
    assert interceptor._config.trusted_roots_provider is cfg.trusted_roots_provider
    assert interceptor._config.trusted_roots == [root]


# ---------------------------------------------------------------------------
# Fix #2: TenuoMetrics._latencies must be bounded
# ---------------------------------------------------------------------------


def test_tenuo_metrics_latency_ring_is_bounded() -> None:
    """The internal latency ring must not grow without bound.

    Regression test for a memory leak in long-lived workers: before the fix
    ``_latencies`` was a plain list appended on every authorize/deny.
    """
    metrics = TenuoMetrics(prefix="test_tenuo_bounded")
    cap = TenuoMetrics._LATENCY_RING_SIZE

    for i in range(cap * 3):
        metrics.record_authorized(
            tool="read_file", workflow_type="W", latency_seconds=float(i)
        )

    assert len(metrics._latencies) == cap
    stats = metrics.get_stats()
    assert stats["latency_count"] == cap


# ---------------------------------------------------------------------------
# Fix #4: signal/update denials must log the real warrant id
# ---------------------------------------------------------------------------


def test_resolve_warrant_id_returns_real_id_from_headers() -> None:
    """``_resolve_warrant_id`` must decode the warrant and return its id.

    Before the fix, signal/update denial events hard-coded
    ``warrant_id="workflow"``, destroying the audit correlation story.
    """
    from tenuo_core import Warrant  # type: ignore[import-not-found]

    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("noop")
        .ttl(3600)
        .mint(control_key)
    )
    expected_id = warrant.id

    inbound = _TenuoWorkflowInboundInterceptor(next_interceptor=MagicMock())

    wf_id = "wf-warrant-id-regression"
    headers = tenuo_headers(warrant, "agent1")
    stored = {k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
              for k, v in headers.items()}

    try:
        with _store_lock:
            _workflow_headers_store[wf_id] = stored

        fake_info = MagicMock()
        fake_info.workflow_id = wf_id
        with patch("temporalio.workflow.info", return_value=fake_info):
            resolved = inbound._resolve_warrant_id()
    finally:
        with _store_lock:
            _workflow_headers_store.pop(wf_id, None)

    assert resolved == expected_id
    assert resolved != "workflow", "must not fall back to hard-coded placeholder"


def test_resolve_warrant_id_returns_sentinel_when_no_headers() -> None:
    """When no warrant headers are stored, return the no-warrant sentinel."""
    inbound = _TenuoWorkflowInboundInterceptor(next_interceptor=MagicMock())
    fake_info = MagicMock()
    fake_info.workflow_id = "wf-missing-headers"
    with patch("temporalio.workflow.info", return_value=fake_info):
        assert inbound._resolve_warrant_id() == "<no-warrant>"


def test_resolve_warrant_id_returns_sentinel_on_malformed_header() -> None:
    """Malformed warrant bytes must surface a distinct sentinel, not raise."""
    inbound = _TenuoWorkflowInboundInterceptor(next_interceptor=MagicMock())

    wf_id = "wf-malformed-warrant"
    try:
        with _store_lock:
            _workflow_headers_store[wf_id] = {
                TENUO_WARRANT_HEADER: b"not-a-valid-cbor-warrant",
                TENUO_COMPRESSED_HEADER: b"0",
            }

        fake_info = MagicMock()
        fake_info.workflow_id = wf_id
        with patch("temporalio.workflow.info", return_value=fake_info):
            resolved = inbound._resolve_warrant_id()
    finally:
        with _store_lock:
            _workflow_headers_store.pop(wf_id, None)

    assert resolved == "<undecodable-warrant>"
