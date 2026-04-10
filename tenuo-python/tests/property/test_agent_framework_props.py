"""Property tests for agent framework adapters: CrewAI, OpenAI, AutoGen, Google ADK.

These adapters share a common tier 1 / tier 2 pattern:
- Tier 1 (no warrant): Python-only constraint checking, no Rust Authorizer
- Tier 2 (with warrant): Routes through enforce_tool_call -> Rust

These tests verify:
1. Tier 2 paths call enforce_tool_call (confirmed via spy)
2. Tier 1 paths do NOT claim cryptographic authorization
3. Source-level: all adapters import and reference enforce_tool_call
4. GuardBuilder consistency: .with_warrant() produces tier 2 behavior
"""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings

from tenuo._enforcement import EnforcementResult

from .strategies import st_warrant_bundle

# Map adapter -> (module path, enforce_tool_call import location)
ADAPTERS = {
    "crewai": ("tenuo.crewai", "tenuo.crewai.enforce_tool_call"),
    "openai": ("tenuo.openai", "tenuo.openai.enforce_tool_call"),
    "autogen": ("tenuo.autogen", "tenuo.autogen.enforce_tool_call"),
    "google_adk": ("tenuo.google_adk.guard", "tenuo.google_adk.guard.enforce_tool_call"),
}


# ---------------------------------------------------------------------------
# Source-level: all adapters reference enforce_tool_call
# ---------------------------------------------------------------------------


class TestAdaptersReferenceEnforceToolCall:
    @pytest.mark.parametrize("adapter_name,module_path", [
        ("crewai", "tenuo.crewai"),
        ("openai", "tenuo.openai"),
        ("autogen", "tenuo.autogen"),
        ("google_adk", "tenuo.google_adk.guard"),
    ])
    def test_source_contains_enforce_tool_call(self, adapter_name, module_path):
        """Each adapter module's source references enforce_tool_call."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{adapter_name} not installed")

        source = inspect.getsource(mod)
        assert "enforce_tool_call" in source, \
            f"{adapter_name} module must reference enforce_tool_call for tier 2 authorization"


# ---------------------------------------------------------------------------
# Source-level: all adapters import from tenuo_core or enforce_tool_call
# ---------------------------------------------------------------------------


class TestAdaptersUseRustPath:
    @pytest.mark.parametrize("adapter_name,module_path", [
        ("crewai", "tenuo.crewai"),
        ("openai", "tenuo.openai"),
        ("autogen", "tenuo.autogen"),
        ("google_adk", "tenuo.google_adk.guard"),
        ("langchain", "tenuo.langchain"),
        ("langgraph", "tenuo.langgraph"),
        ("fastapi", "tenuo.fastapi"),
        ("mcp_server", "tenuo.mcp.server"),
        ("temporal", "tenuo.temporal"),
    ])
    def test_has_rust_call_path(self, adapter_name, module_path):
        """Every adapter must have a path to tenuo_core (enforce_tool_call or Authorizer)."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{adapter_name} not installed")

        source = inspect.getsource(mod)
        has_enforce = "enforce_tool_call" in source
        has_authorizer = "Authorizer" in source
        has_authorize = "authorize_one" in source or "check_chain" in source
        assert has_enforce or has_authorizer or has_authorize, \
            f"{adapter_name} has no path to Rust enforcement"


# ---------------------------------------------------------------------------
# CrewAI tier 2 calls enforce_tool_call
# ---------------------------------------------------------------------------


class TestCrewAITier2:
    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_with_warrant_calls_enforce(self, data):
        warrant, key, tool, _ = data
        try:
            from tenuo.crewai import GuardBuilder
        except ImportError:
            pytest.skip("crewai not installed")

        # Use empty args to avoid the closed-world constraint check
        # blocking before enforce_tool_call is reached
        with patch("tenuo.crewai.enforce_tool_call") as spy:
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={}
            )
            try:
                guard = GuardBuilder().with_warrant(warrant, key).allow(tool).build()
                guard._authorize(tool, {})
            except Exception:
                pass
            spy.assert_called()


# ---------------------------------------------------------------------------
# OpenAI tier 2 calls enforce_tool_call
# ---------------------------------------------------------------------------


class TestOpenAITier2:
    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_verify_tool_call_with_warrant(self, data):
        warrant, key, tool, args = data
        try:
            from tenuo.openai import verify_tool_call
        except ImportError:
            pytest.skip("openai not installed")

        with patch("tenuo.openai.enforce_tool_call") as spy:
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments=args
            )
            try:
                verify_tool_call(
                    tool, args,
                    allow_tools=None, deny_tools=None, constraints=None,
                    warrant=warrant, signing_key=key,
                    trusted_roots=[key.public_key],
                )
            except Exception:
                pass
            spy.assert_called()


# ---------------------------------------------------------------------------
# AutoGen tier 2 calls enforce_tool_call
# ---------------------------------------------------------------------------


class TestAutoGenTier2:
    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_with_warrant_calls_enforce(self, data):
        warrant, key, tool, _ = data
        try:
            from tenuo.autogen import GuardBuilder
        except ImportError:
            pytest.skip("autogen not installed")

        with patch("tenuo.autogen.enforce_tool_call") as spy:
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={}
            )
            try:
                guard = GuardBuilder().with_warrant(warrant, key).allow(tool).build()
                guard._authorize(tool, {})
            except Exception:
                pass
            spy.assert_called()


# ---------------------------------------------------------------------------
# Google ADK tier 2 calls enforce_tool_call
# ---------------------------------------------------------------------------


class TestGoogleADKTier2:
    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_before_tool_calls_enforce(self, data):
        """ADK TenuoGuard.before_tool calls enforce_tool_call when warrant + signing key set."""
        warrant, key, tool, _ = data
        try:
            from tenuo.google_adk.guard import TenuoGuard
        except ImportError:
            pytest.skip("google_adk not installed")

        guard = TenuoGuard(
            warrant=warrant,
            signing_key=key,
            trusted_roots=[key.public_key],
        )

        mock_tool = MagicMock()
        mock_tool.name = tool
        mock_context = MagicMock()
        mock_context.state = {}

        with patch("tenuo.google_adk.guard.enforce_tool_call") as spy:
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={}
            )
            try:
                guard.before_tool(mock_tool, {}, mock_context)
            except Exception:
                pass
            spy.assert_called()
