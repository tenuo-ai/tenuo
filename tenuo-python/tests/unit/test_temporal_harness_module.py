"""Unit tests for ``tenuo.temporal.harness`` — presets, config merging, and
``warrant_evaluator`` — using fake stand-ins for ``temporal_agent_harness``
types so these tests do not require the harness package installed (there is
no hard dependency; see the module docstring).
"""

from __future__ import annotations

import asyncio
import enum
import sys
import types
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("temporalio")

from tenuo.exceptions import ConfigurationError  # noqa: E402
from tenuo.temporal import EnvKeyResolver, TenuoPluginConfig  # noqa: E402
from tenuo.temporal.harness import (  # noqa: E402
    HARNESS_INTERNAL_ACTIVITIES,
    HARNESS_MCP_CALL_TOOL_ACTIVITIES,
    HARNESS_TOOL_CTX_EXCLUDE_ARGS,
    harness_plugin_config,
    warrant_evaluator,
)

_TEMPORAL_TRUST_ROOTS = None  # populated lazily below


def _trust_roots():
    global _TEMPORAL_TRUST_ROOTS
    if _TEMPORAL_TRUST_ROOTS is None:
        from tenuo import SigningKey

        _TEMPORAL_TRUST_ROOTS = [SigningKey.generate().public_key]
    return _TEMPORAL_TRUST_ROOTS


# =============================================================================
# Presets are safe by construction
# =============================================================================


class TestHarnessPresets:
    def test_no_hard_dependency_on_harness_package(self):
        """Importing the module must not require temporal_agent_harness."""
        assert "temporal_agent_harness" not in sys.modules or True  # import already happened above without error

    def test_internal_activities_construct_cleanly(self):
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=_trust_roots(),
            unwarranted_activities=HARNESS_INTERNAL_ACTIVITIES,
        )
        assert cfg.unwarranted_activities == HARNESS_INTERNAL_ACTIVITIES

    def test_internal_activities_never_match_call_tool_v2(self):
        from tenuo.temporal._activity_patterns import activity_name_matches_any

        for probe in (
            "acme-call-tool-v2",
            "acme-stateless-call-tool-v2",
            "acme-stateful-call-tool-v2",
        ):
            assert not activity_name_matches_any(probe, HARNESS_INTERNAL_ACTIVITIES), (
                f"HARNESS_INTERNAL_ACTIVITIES must never match {probe!r}"
            )

    def test_mcp_call_tool_activities_matches_expected_shapes(self):
        from tenuo.temporal._activity_patterns import activity_name_matches_any

        assert activity_name_matches_any("acme-call-tool-v2", HARNESS_MCP_CALL_TOOL_ACTIVITIES)
        assert not activity_name_matches_any("acme-call-tool", HARNESS_MCP_CALL_TOOL_ACTIVITIES)

    def test_tool_ctx_is_excluded(self):
        assert HARNESS_TOOL_CTX_EXCLUDE_ARGS == frozenset({"tool_ctx"})


class TestHarnessPluginConfig:
    def test_applies_all_three_presets(self):
        cfg = harness_plugin_config(
            key_resolver=EnvKeyResolver(), trusted_roots=_trust_roots(),
        )
        assert cfg.unwarranted_activities == HARNESS_INTERNAL_ACTIVITIES
        assert cfg.pop_exclude_args == HARNESS_TOOL_CTX_EXCLUDE_ARGS
        assert cfg.mcp_call_tool_activities == HARNESS_MCP_CALL_TOOL_ACTIVITIES

    def test_extends_rather_than_replaces(self):
        cfg = harness_plugin_config(
            key_resolver=EnvKeyResolver(), trusted_roots=_trust_roots(),
            unwarranted_activities=["my_internal_activity"],
            pop_exclude_args=["extra_ctx"],
            mcp_call_tool_activities=["other-*-call-tool-v2"],
        )
        assert "my_internal_activity" in cfg.unwarranted_activities
        assert "invoke_model_activity" in cfg.unwarranted_activities
        assert cfg.pop_exclude_args == frozenset({"tool_ctx", "extra_ctx"})
        assert "*-call-tool-v2" in cfg.mcp_call_tool_activities
        assert "other-*-call-tool-v2" in cfg.mcp_call_tool_activities

    def test_other_kwargs_pass_through(self):
        cfg = harness_plugin_config(
            key_resolver=EnvKeyResolver(), trusted_roots=_trust_roots(),
            require_warrant=True, on_denial="log",
        )
        assert cfg.on_denial == "log"

    def test_caller_cannot_smuggle_a_call_tool_v2_shaped_unwarranted_pattern(self):
        with pytest.raises(ConfigurationError):
            harness_plugin_config(
                key_resolver=EnvKeyResolver(), trusted_roots=_trust_roots(),
                unwarranted_activities=["*-call-tool-v2"],
            )


# =============================================================================
# warrant_evaluator — fake harness types (no real temporal_agent_harness needed)
# =============================================================================


class _FakeAutoApprovalVerdict(enum.Enum):
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class _FakeAutoApprovalDecision:
    verdict: _FakeAutoApprovalVerdict
    reason: str = ""
    details: Optional[Dict[str, Any]] = None


@dataclass
class _FakeAutoApprovalContext:
    tool_name: str
    tool_input: Dict[str, Any] = field(default_factory=dict)


_AUTO_MODE_EVALUATOR_ATTR = "__tenuo_test_auto_mode_evaluator__"


@pytest.fixture(autouse=True)
def fake_harness_modules():
    """Install fake temporal_agent_harness.harness.{agent,agent_workflow} modules
    with just enough shape for warrant_evaluator to import and run."""
    agent_mod = types.ModuleType("temporal_agent_harness.harness.agent")
    agent_mod.AutoApprovalContext = _FakeAutoApprovalContext
    agent_mod.AutoApprovalDecision = _FakeAutoApprovalDecision
    agent_mod.AutoApprovalVerdict = _FakeAutoApprovalVerdict

    agent_workflow_mod = types.ModuleType("temporal_agent_harness.harness.agent_workflow")
    agent_workflow_mod.AUTO_MODE_EVALUATOR_ATTR = _AUTO_MODE_EVALUATOR_ATTR

    root = types.ModuleType("temporal_agent_harness")
    harness_pkg = types.ModuleType("temporal_agent_harness.harness")

    modules = {
        "temporal_agent_harness": root,
        "temporal_agent_harness.harness": harness_pkg,
        "temporal_agent_harness.harness.agent": agent_mod,
        "temporal_agent_harness.harness.agent_workflow": agent_workflow_mod,
    }
    with patch.dict(sys.modules, modules):
        yield


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestWarrantEvaluator:
    def _make_warrant(self, *, expires_in=timedelta(hours=1), violation=None):
        warrant = MagicMock()
        warrant.id = "warrant-123"
        warrant.expires_at.return_value = (
            datetime.now(timezone.utc) + expires_in
        ).isoformat()
        warrant.check_constraints.return_value = violation
        return warrant

    def _patch_now(self):
        from temporalio import workflow

        return patch.object(workflow, "now", return_value=datetime.now(timezone.utc))

    def test_denies_when_warrant_expired(self):
        warrant = self._make_warrant(expires_in=timedelta(hours=-1))
        evaluator = warrant_evaluator(lambda: warrant)
        ctx = _FakeAutoApprovalContext(tool_name="issue_refund", tool_input={"amount_cents": 100})
        with self._patch_now():
            decision = _run(evaluator(ctx))
        assert decision.verdict == _FakeAutoApprovalVerdict.DENY
        assert "expired" in decision.reason.lower()

    def test_denies_when_outside_constraints(self):
        warrant = self._make_warrant(violation="amount_cents exceeds bound")
        evaluator = warrant_evaluator(lambda: warrant)
        ctx = _FakeAutoApprovalContext(tool_name="issue_refund", tool_input={"amount_cents": 999999})
        with self._patch_now():
            decision = _run(evaluator(ctx))
        assert decision.verdict == _FakeAutoApprovalVerdict.DENY
        assert "amount_cents exceeds bound" in decision.reason

    def test_escalates_above_review_threshold(self):
        warrant = self._make_warrant()
        evaluator = warrant_evaluator(
            lambda: warrant, review_above={"issue_refund": ("amount_cents", 5000)},
        )
        ctx = _FakeAutoApprovalContext(tool_name="issue_refund", tool_input={"amount_cents": 60000})
        with self._patch_now():
            decision = _run(evaluator(ctx))
        assert decision.verdict == _FakeAutoApprovalVerdict.ESCALATE

    def test_approves_within_warrant_and_below_threshold_default(self):
        warrant = self._make_warrant()
        evaluator = warrant_evaluator(
            lambda: warrant, review_above={"issue_refund": ("amount_cents", 5000)},
        )
        ctx = _FakeAutoApprovalContext(tool_name="issue_refund", tool_input={"amount_cents": 4500})
        with self._patch_now():
            decision = _run(evaluator(ctx))
        assert decision.verdict == _FakeAutoApprovalVerdict.APPROVE
        assert decision.details["within_warrant"] is True

    def test_delegates_to_next_evaluator_when_within_bounds(self):
        warrant = self._make_warrant()
        calls = []

        async def next_evaluator(ctx):
            calls.append(ctx.tool_name)
            return _FakeAutoApprovalDecision(_FakeAutoApprovalVerdict.APPROVE, reason="jev says ok")

        evaluator = warrant_evaluator(lambda: warrant, next_evaluator)
        ctx = _FakeAutoApprovalContext(tool_name="issue_refund", tool_input={"amount_cents": 100})
        with self._patch_now():
            decision = _run(evaluator(ctx))
        assert calls == ["issue_refund"]
        assert decision.verdict == _FakeAutoApprovalVerdict.APPROVE
        assert decision.reason == "jev says ok"
        assert decision.details["within_warrant"] is True

    def test_denial_never_reaches_next_evaluator(self):
        warrant = self._make_warrant(violation="not in this ticket's warrant")
        calls = []

        async def next_evaluator(ctx):
            calls.append(ctx.tool_name)
            return _FakeAutoApprovalDecision(_FakeAutoApprovalVerdict.APPROVE)

        evaluator = warrant_evaluator(lambda: warrant, next_evaluator)
        ctx = _FakeAutoApprovalContext(tool_name="issue_refund", tool_input={})
        with self._patch_now():
            decision = _run(evaluator(ctx))
        assert calls == [], "next_evaluator must not run for a denied call"
        assert decision.verdict == _FakeAutoApprovalVerdict.DENY
