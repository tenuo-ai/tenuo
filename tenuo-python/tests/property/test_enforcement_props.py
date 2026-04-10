"""Property tests for shared enforcement logic (_enforcement.py).

Verifies:
- enforce_tool_call never crashes for valid inputs (returns EnforcementResult)
- enforce_tool_call calls Rust Authorizer for every valid warrant
- filter_tools_by_warrant monotonicity
- _extract_violated_field robustness
"""

from __future__ import annotations

import time

from hypothesis import given, settings

from tenuo import Authorizer, SigningKey
from tenuo._enforcement import (
    EnforcementResult,
    _extract_violated_field,
    enforce_tool_call,
    filter_tools_by_warrant,
)

from .strategies import (
    st_bound_warrant_bundle,
    st_denial_reason,
    st_tool_name,
    st_warrant_bundle,
)


# ---------------------------------------------------------------------------
# _extract_violated_field: never crashes
# ---------------------------------------------------------------------------


class TestExtractViolatedFieldRobustness:
    @given(reason=st_denial_reason)
    def test_never_crashes(self, reason):
        result = _extract_violated_field(reason)
        assert result is None or isinstance(result, str)

    @given(reason=st_denial_reason)
    def test_returns_none_or_str(self, reason):
        result = _extract_violated_field(reason)
        if result is not None:
            assert len(result) > 0


# ---------------------------------------------------------------------------
# enforce_tool_call: always returns EnforcementResult (never unhandled exc)
# ---------------------------------------------------------------------------


class TestEnforceToolCallRobustness:
    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=30)
    def test_returns_enforcement_result_for_valid_warrant(self, data):
        """enforce_tool_call always returns EnforcementResult for valid inputs."""
        bound, key, tool, args = data
        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[key.public_key],
        )
        assert isinstance(result, EnforcementResult)
        assert result.tool == tool

    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=30)
    def test_allowed_for_matching_tool(self, data):
        """When the tool matches the warrant, result is allowed=True."""
        bound, key, tool, args = data
        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[key.public_key],
        )
        assert result.allowed is True
        assert result.denial_reason is None

    @given(data=st_bound_warrant_bundle(), other_tool=st_tool_name)
    @settings(max_examples=30)
    def test_denied_for_non_matching_tool(self, data, other_tool):
        """When the tool doesn't match the warrant, result is allowed=False."""
        bound, key, tool, args = data
        if other_tool == tool:
            return  # skip degenerate case
        result = enforce_tool_call(
            other_tool, args, bound,
            trusted_roots=[key.public_key],
        )
        assert isinstance(result, EnforcementResult)
        assert result.allowed is False

    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=30)
    def test_denied_for_untrusted_root(self, data):
        """Warrants from untrusted issuers are denied."""
        bound, key, tool, args = data
        untrusted = SigningKey.generate()
        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[untrusted.public_key],
        )
        assert isinstance(result, EnforcementResult)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# enforce_tool_call: FFI boundary — Rust Authorizer is always called
# ---------------------------------------------------------------------------


class TestEnforceToolCallCallsRust:
    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=20)
    def test_sign_mode_produces_allowed_via_rust(self, data):
        """enforce_tool_call (sign mode) produces allowed=True only through Rust Authorizer.

        We verify this indirectly: if the result is allowed and the tool is in
        the warrant, that can only happen if Authorizer.authorize_one/check_chain
        succeeded (the Python policy checks only deny, never allow).
        """
        bound, key, tool, args = data
        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[key.public_key],
        )
        assert result.allowed is True
        assert result.chain_result is not None, \
            "allowed=True must come with chain_result from Rust Authorizer"

    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=20)
    def test_sign_mode_untrusted_root_denied_by_rust(self, data):
        """enforce_tool_call (sign mode) with wrong trusted_roots is denied by Rust."""
        bound, key, tool, args = data
        untrusted = SigningKey.generate()
        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[untrusted.public_key],
        )
        assert result.allowed is False
        assert result.chain_result is None

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_verify_mode_produces_allowed_via_rust(self, data):
        """enforce_tool_call (verify mode) produces allowed=True through Rust check_chain.

        Rust Authorizer attributes are read-only (PyO3) so we can't mock them.
        Instead we verify that the result has chain_result (only set by Rust)
        and that wrong PoP is properly rejected by Rust.
        """
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        pop = warrant.sign(key, tool, args, int(time.time()))
        auth = Authorizer(trusted_roots=[key.public_key])

        result = enforce_tool_call(
            tool, args, bound,
            verify_mode="verify",
            precomputed_signature=bytes(pop),
            authorizer=auth,
        )
        assert result.allowed is True
        assert result.chain_result is not None, \
            "verify mode must produce chain_result from Rust check_chain"

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_verify_mode_rejects_bad_signature(self, data):
        """enforce_tool_call (verify mode) with garbage PoP is denied by Rust check_chain."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        auth = Authorizer(trusted_roots=[key.public_key])

        result = enforce_tool_call(
            tool, args, bound,
            verify_mode="verify",
            precomputed_signature=b"\x00" * 64,
            authorizer=auth,
        )
        assert result.allowed is False


# ---------------------------------------------------------------------------
# filter_tools_by_warrant: monotonicity
# ---------------------------------------------------------------------------


class TestFilterToolsMonotonicity:
    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=30)
    def test_warrant_tool_always_in_filtered_set(self, data):
        """A tool named in the warrant is always in filter_tools_by_warrant output."""
        bound, key, tool, args = data

        class FakeTool:
            def __init__(self, name):
                self.name = name

        tools = [FakeTool(tool), FakeTool("unrelated_tool")]
        filtered = filter_tools_by_warrant(tools, bound)
        filtered_names = [t.name for t in filtered]
        assert tool in filtered_names

    @given(data=st_bound_warrant_bundle())
    @settings(max_examples=30)
    def test_non_warrant_tool_excluded(self, data):
        """A tool NOT named in the warrant is excluded from the filtered set."""
        bound, key, tool, args = data

        class FakeTool:
            def __init__(self, name):
                self.name = name

        filtered = filter_tools_by_warrant([FakeTool("definitely_not_in_warrant_xyz")], bound)
        assert len(filtered) == 0
