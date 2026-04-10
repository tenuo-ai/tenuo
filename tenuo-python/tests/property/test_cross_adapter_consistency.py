"""Cross-adapter consistency property tests.

Verifies properties that must hold identically across ALL adapters:
1. enforce_tool_call is the single enforcement funnel for most adapters
2. Every adapter that uses enforce_tool_call gets the same EnforcementResult
3. Denial reasons follow a consistent taxonomy across adapters
4. All adapters that construct Authorizer use trusted_roots
"""

from __future__ import annotations

import inspect

import pytest
from hypothesis import given, settings

from tenuo import SigningKey
from tenuo._enforcement import enforce_tool_call

from .strategies import st_bound_warrant_bundle, st_tool_name


# ---------------------------------------------------------------------------
# enforce_tool_call is deterministic: same inputs -> same result
# ---------------------------------------------------------------------------


class TestEnforceDeterminism:
    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=20)
    def test_same_inputs_same_result(self, data):
        """enforce_tool_call returns the same allowed status for identical inputs."""
        bound, key, tool, args = data
        result1 = enforce_tool_call(
            tool, args, bound, trusted_roots=[key.public_key]
        )
        result2 = enforce_tool_call(
            tool, args, bound, trusted_roots=[key.public_key]
        )
        assert result1.allowed == result2.allowed
        assert result1.error_type == result2.error_type


# ---------------------------------------------------------------------------
# Denial taxonomy: error_type is always a known value
# ---------------------------------------------------------------------------


KNOWN_ERROR_TYPES = {
    None,  # allowed=True
    "tool_not_allowed",
    "policy_violation",
    "authorization_failed",
    "expired",
    "constraint_violation",
    "tenuo_error",
    "internal_error",
    "invalid_pop",
    "approval_gate_misconfigured",
}


class TestDenialTaxonomy:
    @given(data=st_bound_warrant_bundle(), other=st_tool_name)
    @settings(max_examples=30)
    def test_error_type_is_known(self, data, other):
        """EnforcementResult.error_type is always from a known set."""
        bound, key, tool, args = data
        # Test with matching tool
        result = enforce_tool_call(
            tool, args, bound, trusted_roots=[key.public_key]
        )
        assert result.error_type in KNOWN_ERROR_TYPES

        # Test with non-matching tool (likely denied)
        if other != tool:
            result2 = enforce_tool_call(
                other, args, bound, trusted_roots=[key.public_key]
            )
            assert result2.error_type in KNOWN_ERROR_TYPES

    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=20)
    def test_untrusted_issuer_error_type(self, data):
        """Untrusted issuer produces a consistent error_type."""
        bound, key, tool, args = data
        untrusted = SigningKey.generate()
        result = enforce_tool_call(
            tool, args, bound, trusted_roots=[untrusted.public_key]
        )
        assert result.allowed is False
        assert result.error_type in KNOWN_ERROR_TYPES


# ---------------------------------------------------------------------------
# All adapters using enforce_tool_call get consistent behavior
# ---------------------------------------------------------------------------


class TestAllAdaptersSameEnforceCall:
    """Verify that adapters call the same enforce_tool_call, not a local copy."""

    @pytest.mark.parametrize("module_path,import_attr", [
        ("tenuo.langchain", "enforce_tool_call"),
        ("tenuo.langgraph", "enforce_tool_call"),
        ("tenuo.crewai", "enforce_tool_call"),
        ("tenuo.openai", "enforce_tool_call"),
        ("tenuo.autogen", "enforce_tool_call"),
    ])
    def test_imports_same_function(self, module_path, import_attr):
        """Each adapter imports the same enforce_tool_call function."""
        try:
            mod = __import__(module_path, fromlist=[import_attr])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        adapter_fn = getattr(mod, import_attr, None)
        if adapter_fn is None:
            pytest.skip(f"{module_path} does not expose {import_attr}")

        from tenuo._enforcement import enforce_tool_call as canonical
        assert adapter_fn is canonical, \
            f"{module_path}.{import_attr} is not the canonical enforce_tool_call"


# ---------------------------------------------------------------------------
# Authorizer always constructed with trusted_roots
# ---------------------------------------------------------------------------


class TestAuthorizerAlwaysHasTrustedRoots:
    @pytest.mark.parametrize("module_path", [
        "tenuo._enforcement",
        "tenuo.mcp.server",
        "tenuo.fastapi",
    ])
    def test_authorizer_constructed_with_trusted_roots(self, module_path):
        """Modules that construct Authorizer pass trusted_roots= explicitly."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        if "Authorizer(" in source:
            assert "trusted_roots" in source, \
                f"{module_path} constructs Authorizer without trusted_roots"
