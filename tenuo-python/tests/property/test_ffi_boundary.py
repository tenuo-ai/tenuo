"""Property tests verifying every adapter actually calls into Rust (tenuo_core).

For each integration adapter, these tests confirm that the authorization path
invokes tenuo_core's Authorizer (authorize_one / check_chain) or Warrant.sign,
and does not silently short-circuit in Python.

Strategy: use unittest.mock to spy on tenuo_core call sites within each adapter,
generate arbitrary valid warrants via Hypothesis, and assert the spy was called.
"""

from __future__ import annotations

import base64
import time
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings

from tenuo import Authorizer, SigningKey

from .strategies import st_warrant_bundle


# ---------------------------------------------------------------------------
# Helper: build real PoP and authorizer
# ---------------------------------------------------------------------------


def _make_pop(warrant, key, tool, args):
    return bytes(warrant.sign(key, tool, args, int(time.time())))


def _make_authorizer(key):
    return Authorizer(trusted_roots=[key.public_key])


# ===========================================================================
# MCP Server: MCPVerifier.verify calls Authorizer
# ===========================================================================


class TestMCPServerCallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_verify_accepts_valid_warrant(self, data):
        """MCPVerifier.verify accepts a valid warrant+PoP (proving Rust authorized it)."""
        warrant, key, tool, args = data
        auth = _make_authorizer(key)
        pop = _make_pop(warrant, key, tool, args)

        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=auth, control_plane=None, nonce_store=None)
        meta = {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(pop).decode(),
            }
        }

        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is True

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_verify_rejects_untrusted_issuer(self, data):
        """MCPVerifier.verify with untrusted root rejects (proving Rust enforced)."""
        warrant, key, tool, args = data
        untrusted = SigningKey.generate()
        auth = Authorizer(trusted_roots=[untrusted.public_key])
        pop = _make_pop(warrant, key, tool, args)

        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=auth, control_plane=None, nonce_store=None)
        meta = {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(pop).decode(),
            }
        }

        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is False

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_verify_accepts_warrant_stack(self, data):
        """MCPVerifier.verify accepts single-element WarrantStack via Rust."""
        warrant, key, tool, args = data
        auth = _make_authorizer(key)
        pop = _make_pop(warrant, key, tool, args)

        from tenuo import encode_warrant_stack
        from tenuo.mcp.server import MCPVerifier

        stack_b64 = encode_warrant_stack([warrant])
        verifier = MCPVerifier(authorizer=auth, control_plane=None, nonce_store=None)
        meta = {
            "tenuo": {
                "warrant": stack_b64,
                "signature": base64.b64encode(pop).decode(),
            }
        }

        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is True


# ===========================================================================
# FastAPI: TenuoGuard._enforce_with_pop_signature calls enforce_tool_call
# ===========================================================================


class TestFastAPICallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_guard_calls_enforce_tool_call(self, data):
        """FastAPI TenuoGuard._enforce_with_pop_signature calls enforce_tool_call."""
        warrant, key, tool, args = data
        pop = _make_pop(warrant, key, tool, args)

        try:
            from tenuo.fastapi import TenuoGuard, _config
        except ImportError:
            pytest.skip("fastapi not installed")

        _config["trusted_issuers"] = [key.public_key]
        try:
            guard = TenuoGuard(tool)
            from tenuo._enforcement import enforce_tool_call as _real_enforce

            with patch("tenuo._enforcement.enforce_tool_call", wraps=_real_enforce) as spy:
                try:
                    guard._enforce_with_pop_signature(warrant, tool, args, pop)
                except Exception:
                    pass
                spy.assert_called()
        finally:
            _config.pop("trusted_issuers", None)


# ===========================================================================
# LangChain: TenuoTool._check_authorization calls enforce_tool_call
# ===========================================================================


class TestLangChainCallsRust:
    def test_langchain_source_uses_enforce_tool_call(self):
        """LangChain module source calls enforce_tool_call (Rust path)."""
        try:
            import tenuo.langchain as lc_mod
        except ImportError:
            pytest.skip("langchain not installed")

        import inspect
        source = inspect.getsource(lc_mod)
        assert "enforce_tool_call(" in source, \
            "LangChain module must call enforce_tool_call for tier 2 authorization"

    def test_langchain_imports_canonical_enforce(self):
        """LangChain imports the canonical enforce_tool_call from _enforcement."""
        try:
            from tenuo.langchain import enforce_tool_call as lc_enforce
            from tenuo._enforcement import enforce_tool_call as canonical
        except ImportError:
            pytest.skip("langchain not installed")

        assert lc_enforce is canonical


# ===========================================================================
# LangGraph: TenuoMiddleware calls enforce_tool_call
# ===========================================================================


class TestLangGraphCallsRust:
    def test_langgraph_source_uses_enforce_tool_call(self):
        """LangGraph module source calls enforce_tool_call (Rust path)."""
        try:
            import tenuo.langgraph as lg_mod
        except ImportError:
            pytest.skip("langgraph not installed")

        import inspect
        source = inspect.getsource(lg_mod)
        assert "enforce_tool_call(" in source, \
            "LangGraph module must call enforce_tool_call for authorization"

    def test_langgraph_imports_canonical_enforce(self):
        """LangGraph imports the canonical enforce_tool_call."""
        try:
            from tenuo.langgraph import enforce_tool_call as lg_enforce
            from tenuo._enforcement import enforce_tool_call as canonical
        except ImportError:
            pytest.skip("langgraph not installed")

        assert lg_enforce is canonical


# ===========================================================================
# CrewAI: Tier 2 path calls enforce_tool_call
# ===========================================================================


class TestCrewAICallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_tier2_calls_enforce(self, data):
        """CrewAI tier 2 (with warrant) calls enforce_tool_call."""
        warrant, key, tool, _ = data

        try:
            from tenuo.crewai import GuardBuilder
        except ImportError:
            pytest.skip("crewai not installed")

        with patch("tenuo.crewai.enforce_tool_call") as spy:
            from tenuo._enforcement import EnforcementResult
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={}
            )
            try:
                guard = GuardBuilder().with_warrant(warrant, key).allow(tool).build()
                guard._authorize(tool, {})
            except Exception:
                pass
            spy.assert_called()


# ===========================================================================
# OpenAI: Tier 2 path calls enforce_tool_call
# ===========================================================================


class TestOpenAICallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_tier2_calls_enforce(self, data):
        """OpenAI tier 2 (with warrant) calls enforce_tool_call."""
        warrant, key, tool, args = data

        try:
            from tenuo.openai import verify_tool_call
        except ImportError:
            pytest.skip("openai not installed")

        with patch("tenuo.openai.enforce_tool_call") as spy:
            from tenuo._enforcement import EnforcementResult
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


# ===========================================================================
# AutoGen: Tier 2 path calls enforce_tool_call
# ===========================================================================


class TestAutoGenCallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_tier2_calls_enforce(self, data):
        """AutoGen tier 2 (with warrant) calls enforce_tool_call."""
        warrant, key, tool, _ = data

        try:
            from tenuo.autogen import GuardBuilder
        except ImportError:
            pytest.skip("autogen not installed")

        with patch("tenuo.autogen.enforce_tool_call") as spy:
            from tenuo._enforcement import EnforcementResult
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={}
            )
            try:
                guard = GuardBuilder().with_warrant(warrant, key).allow(tool).build()
                guard._authorize(tool, {})
            except Exception:
                pass
            spy.assert_called()


# ===========================================================================
# Google ADK: Tier 2 path calls enforce_tool_call
# ===========================================================================


class TestGoogleADKCallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_tier2_calls_enforce(self, data):
        """Google ADK tier 2 (with warrant) calls enforce_tool_call."""
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
            from tenuo._enforcement import EnforcementResult
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={}
            )
            try:
                guard.before_tool(mock_tool, {}, mock_context)
            except Exception:
                pass
            spy.assert_called()


# ===========================================================================
# Temporal: execute_activity calls Authorizer
# ===========================================================================


class TestTemporalCallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=10)
    def test_interceptor_calls_authorizer(self, data):
        """Temporal interceptor constructs Authorizer and calls authorize_one or check_chain."""
        warrant, key, tool, args = data

        try:
            import temporalio  # noqa: F401
        except ImportError:
            pytest.skip("temporalio not installed")

        # Verify that the Temporal interceptor code imports and uses Authorizer
        # by checking the module source contains the expected calls.
        import inspect
        from tenuo import temporal as temporal_mod

        source = inspect.getsource(temporal_mod)
        assert "Authorizer(" in source, "Temporal module must construct Authorizer"
        assert "authorize_one(" in source or "check_chain(" in source, \
            "Temporal module must call authorize_one or check_chain"
