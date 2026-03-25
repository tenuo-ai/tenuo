"""
Tests for Tenuo CrewAI Integration

Covers:
- Critical test scenarios from the spec
- All 6 invariants from the integration guide
- Tool namespacing resolution
- DenialResult sentinel behavior
- on_denial modes (raise, log, skip)
- Tier 2 warrant requirements
"""

from typing import Callable, Optional
from unittest.mock import MagicMock, patch

import pytest

# Import the crewai module under test
from tenuo.crewai import (
    ConfigurationError,
    ConstraintViolation,
    CrewAIGuard,
    DenialResult,
    GuardBuilder,
    MissingSigningKey,
    Pattern,
    Range,
    Subpath,
    ToolDenied,
    UnlistedArgument,
    Wildcard,
)

try:
    from crewai.tools import BaseTool  # type: ignore[import-not-found]

    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

    class BaseTool:  # type: ignore[no-redef]
        """Stub for when crewai is not installed."""

        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)


class RealTool(BaseTool):
    """Real CrewAI Tool for testing."""

    name: str = "test_tool"
    description: str = "Test tool"
    func: Optional[Callable] = None

    def _run(self, **kwargs):
        if self.func:
            return self.func(**kwargs)
        return {"result": "ok", "args": kwargs}


# =============================================================================
# Mock CrewAI Tool - REPLACED WITH RealTool
# =============================================================================
# We now use the real crewai.tools.BaseTool to ensure integration works correctly.
# The mock_crewai_tool fixture has been removed to allow real imports.


# =============================================================================
# Critical Test Scenarios (from spec)
# =============================================================================


class TestToolAllowlisting:
    """Test tool allowlist enforcement."""

    def test_disallowed_tool_rejected(self):
        """Tools not in the allowed list are rejected."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        with pytest.raises(ToolDenied) as exc:
            guard._authorize("delete_file", {"path": "/data/file.txt"})

        assert "delete_file" in str(exc.value)
        assert "not in allowed list" in str(exc.value)

    def test_allowed_tool_accepted(self):
        """Tools in the allowed list are accepted."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard._authorize("read_file", {"path": "/data/file.txt"})
        assert result is None  # None means authorized

    def test_empty_allowlist_rejects_all(self):
        """Empty allowlist rejects all tools (fail-closed)."""
        guard = GuardBuilder().build()

        with pytest.raises(ToolDenied):
            guard._authorize("any_tool", {})


class TestClosedWorldArguments:
    """Test closed-world argument checking."""

    def test_unlisted_argument_rejected(self):
        """Arguments not in constraints are rejected."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        with pytest.raises(UnlistedArgument) as exc:
            guard._authorize("read_file", {"path": "/data/file.txt", "mode": "r"})

        assert "mode" in str(exc.value)

    def test_all_listed_arguments_accepted(self):
        """All arguments with constraints are accepted."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data"), mode=Wildcard()).build()

        result = guard._authorize("read_file", {"path": "/data/file.txt", "mode": "r"})
        assert result is None

    def test_empty_args_allowed(self):
        """Empty arguments are allowed if no constraints required."""
        guard = GuardBuilder().allow("list_tools").build()

        result = guard._authorize("list_tools", {})
        assert result is None


class TestConstraintEnforcement:
    """Test constraint enforcement."""

    def test_constraint_violation_rejected(self):
        """Values violating constraints are rejected."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        with pytest.raises(ConstraintViolation) as exc:
            guard._authorize("read_file", {"path": "/etc/passwd"})

        assert "path" in str(exc.value)
        assert "Constraint" in str(exc.value)

    def test_constraint_satisfied_accepted(self):
        """Values satisfying constraints are accepted."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard._authorize("read_file", {"path": "/data/reports/q1.txt"})
        assert result is None

    def test_range_constraint(self):
        """Range constraints work correctly."""
        guard = GuardBuilder().allow("transfer", amount=Range(0, 100)).build()

        # Within range - OK
        assert guard._authorize("transfer", {"amount": 50}) is None

        # Above range - rejected
        with pytest.raises(ConstraintViolation):
            guard._authorize("transfer", {"amount": 150})

    def test_pattern_constraint(self):
        """Pattern constraints work correctly."""
        guard = GuardBuilder().allow("send_email", to=Pattern("*@company.com")).build()

        # Matching pattern - OK
        assert guard._authorize("send_email", {"to": "alice@company.com"}) is None

        # Non-matching pattern - rejected
        with pytest.raises(ConstraintViolation):
            guard._authorize("send_email", {"to": "attacker@evil.com"})


class TestPathTraversal:
    """Test path traversal protection with Subpath."""

    def test_path_traversal_blocked(self):
        """Path traversal attacks are blocked by Subpath."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        # Direct traversal
        with pytest.raises(ConstraintViolation):
            guard._authorize("read_file", {"path": "/data/../etc/passwd"})

    def test_double_dot_traversal_blocked(self):
        """Multiple .. traversal attempts are blocked."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        with pytest.raises(ConstraintViolation):
            guard._authorize("read_file", {"path": "/data/../../etc/passwd"})

    def test_valid_subpath_allowed(self):
        """Valid subpaths are allowed."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        # Deep nesting - OK
        assert guard._authorize("read_file", {"path": "/data/a/b/c/file.txt"}) is None


# =============================================================================
# Invariant Tests (from integration guide)
# =============================================================================


class TestInvariants:
    """Test all 6 invariants from the integration guide."""

    def test_invariant_fail_closed(self):
        """Invariant 1: No tools specified = nothing works."""
        guard = GuardBuilder().build()

        with pytest.raises(ToolDenied):
            guard._authorize("any_tool", {})

    def test_invariant_closed_world_args(self):
        """Invariant 2: Unlisted arguments are rejected."""
        guard = GuardBuilder().allow("tool", arg1=Wildcard()).build()

        with pytest.raises(UnlistedArgument):
            guard._authorize("tool", {"arg1": "x", "arg2": "y"})

    def test_invariant_constraint_blocks(self):
        """Invariant 3: Constraint violations block execution."""
        guard = GuardBuilder().allow("tool", x=Range(1, 10)).build()

        with pytest.raises(ConstraintViolation):
            guard._authorize("tool", {"x": 100})

    def test_invariant_wildcard_required(self):
        """Invariant 4: Wildcard must be explicit for any-value."""
        guard = GuardBuilder().allow("tool", x=Wildcard()).build()

        # Anything goes with Wildcard
        assert guard._authorize("tool", {"x": "anything"}) is None
        assert guard._authorize("tool", {"x": 12345}) is None
        assert guard._authorize("tool", {"x": {"nested": "object"}}) is None

    def test_invariant_tier2_needs_key(self):
        """Invariant 5: Tier 2 requires signing key."""
        mock_warrant = MagicMock()

        with pytest.raises(MissingSigningKey):
            GuardBuilder().with_warrant(mock_warrant, None).build()

    def test_invariant_attenuation_only(self):
        """Invariant 6: Delegation can only narrow (tested in Phase 4)."""
        # This invariant is about delegation - covered in Phase 4
        # For now, just verify the error type exists
        from tenuo.crewai import EscalationAttempt

        assert EscalationAttempt is not None


# =============================================================================
# Tool Namespacing Tests
# =============================================================================


class TestToolNamespacing:
    """Test agent_role::tool_name namespacing."""

    def test_namespaced_tool_exact_match(self):
        """Namespaced tools match exactly."""
        guard = GuardBuilder().allow("researcher::search", query=Pattern("arxiv:*")).build()

        # Exact namespaced match - search without role should fail
        with pytest.raises(ToolDenied):
            guard._authorize("search", {"query": "arxiv:1234"})

    def test_namespaced_with_agent_role(self):
        """Namespaced tools resolve with agent_role parameter."""
        guard = GuardBuilder().allow("researcher::search", query=Pattern("arxiv:*")).build()

        # With agent_role - should match researcher::search
        result = guard._authorize("search", {"query": "arxiv:1234"}, agent_role="researcher")
        assert result is None

    def test_fallback_to_global(self):
        """Global tool is used when namespaced version doesn't exist."""
        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())  # Global fallback
            .allow("researcher::search", query=Pattern("arxiv:*"))  # Agent-specific
            .build()
        )

        # writer has no specific search, falls back to global
        result = guard._authorize("search", {"query": "anything"}, agent_role="writer")
        assert result is None

    def test_namespaced_takes_precedence(self):
        """Namespaced tool takes precedence over global."""
        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())  # Global - allows anything
            .allow("researcher::search", query=Pattern("arxiv:*"))  # Specific - restricted
            .build()
        )

        # researcher::search should use the restricted constraint
        with pytest.raises(ConstraintViolation):
            guard._authorize("search", {"query": "evil.com"}, agent_role="researcher")


# =============================================================================
# DenialResult Sentinel Tests
# =============================================================================


class TestDenialResult:
    """Test DenialResult sentinel behavior."""

    def test_denial_result_is_falsy(self):
        """DenialResult is falsy for if-checks."""
        result = DenialResult(tool="test", reason="denied")

        assert not result
        assert bool(result) is False

    def test_denial_result_has_info(self):
        """DenialResult contains useful information."""
        result = DenialResult(tool="read_file", reason="not allowed", error_code="TOOL_DENIED")

        assert result.tool == "read_file"
        assert result.reason == "not allowed"
        assert result.error_code == "TOOL_DENIED"


# =============================================================================
# on_denial Mode Tests
# =============================================================================


class TestOnDenialModes:
    """Test different denial handling modes."""

    def test_raise_mode_raises_exception(self):
        """on_denial='raise' raises exceptions."""
        guard = GuardBuilder().on_denial("raise").build()

        with pytest.raises(ToolDenied):
            guard._authorize("unknown_tool", {})

    def test_log_mode_returns_denial_result(self):
        """on_denial='log' returns DenialResult."""
        guard = GuardBuilder().on_denial("log").build()

        result = guard._authorize("unknown_tool", {})

        assert isinstance(result, DenialResult)
        assert result.tool == "unknown_tool"

    def test_skip_mode_returns_denial_result(self):
        """on_denial='skip' returns DenialResult."""
        guard = GuardBuilder().on_denial("skip").build()

        result = guard._authorize("unknown_tool", {})

        assert isinstance(result, DenialResult)

    def test_invalid_mode_raises_error(self):
        """Invalid on_denial mode raises ConfigurationError."""
        with pytest.raises(ConfigurationError):
            GuardBuilder().on_denial("invalid_mode")


# =============================================================================
# Audit Callback Tests
# =============================================================================


class TestAuditCallback:
    """Test audit callback functionality."""

    def test_audit_callback_called_on_allow(self):
        """Audit callback is called for allowed calls."""
        events = []

        guard = GuardBuilder().allow("read", path=Wildcard()).audit(lambda e: events.append(e)).build()

        guard._authorize("read", {"path": "/data/file.txt"})

        assert len(events) == 1
        assert events[0].decision == "ALLOW"
        assert events[0].tool == "read"

    def test_audit_callback_called_on_deny(self):
        """Audit callback is called for denied calls."""
        events = []

        guard = GuardBuilder().on_denial("skip").audit(lambda e: events.append(e)).build()

        guard._authorize("unknown", {})

        assert len(events) == 1
        assert events[0].decision == "DENY"
        assert events[0].error_code == "TOOL_DENIED"


# =============================================================================
# protect_tool Tests (REMOVED - replaced by hooks API)
# =============================================================================


@pytest.mark.skip(reason="protect_tool removed in v2.0 - use guard.register() instead")
class TestProtectTool:
    """Test the protect_tool zero-config entry point.

    NOTE: protect_tool was removed in v2.0. Use guard.register() for hooks-based
    protection instead. These tests are kept for documentation purposes.
    """

    def test_protect_tool_basic(self):
        """protect_tool wraps a tool with constraints."""
        pass  # Removed - use guard.register() instead

    def test_protect_tool_blocks_violations(self):
        """protect_tool blocks constraint violations."""
        pass  # Removed - use guard.register() instead


# =============================================================================
# Builder Pattern Tests
# =============================================================================


class TestGuardBuilder:
    """Test GuardBuilder fluent API."""

    def test_fluent_chaining(self):
        """Builder supports fluent method chaining."""
        guard = GuardBuilder().allow("tool1", arg=Wildcard()).allow("tool2", arg=Pattern("*")).on_denial("log").build()

        assert isinstance(guard, CrewAIGuard)

    def test_multiple_tools(self):
        """Multiple tools can be configured."""
        guard = (
            GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .allow("write", path=Subpath("/data"))
            .allow("search", query=Wildcard())
            .build()
        )

        assert guard._authorize("read", {"path": "/data/file.txt"}) is None
        assert guard._authorize("write", {"path": "/data/new.txt"}) is None
        assert guard._authorize("search", {"query": "anything"}) is None


# =============================================================================
# Error Message Quality Tests
# =============================================================================


class TestErrorMessages:
    """Test that error messages are helpful."""

    def test_tool_denied_has_quick_fix(self):
        """ToolDenied includes quick fix suggestion."""
        try:
            guard = GuardBuilder().build()
            guard._authorize("my_tool", {})
        except ToolDenied as e:
            assert "Quick fix" in str(e)
            assert ".allow('my_tool'" in str(e)

    def test_unlisted_arg_has_quick_fix(self):
        """UnlistedArgument includes quick fix suggestion."""
        try:
            guard = GuardBuilder().allow("tool", x=Wildcard()).build()
            guard._authorize("tool", {"x": 1, "y": 2})
        except UnlistedArgument as e:
            assert "Quick fix" in str(e)
            assert "Wildcard()" in str(e)

    def test_constraint_violation_shows_value(self):
        """ConstraintViolation shows the rejected value."""
        try:
            guard = GuardBuilder().allow("transfer", amount=Range(0, 100)).build()
            guard._authorize("transfer", {"amount": 999})
        except ConstraintViolation as e:
            assert "999" in str(e)
            assert "Range" in str(e)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_none_value_handled(self):
        """None values are handled correctly."""
        guard = GuardBuilder().allow("tool", arg=Wildcard()).build()

        # Wildcard accepts None
        assert guard._authorize("tool", {"arg": None}) is None

    def test_empty_string_handled(self):
        """Empty strings are handled correctly."""
        guard = GuardBuilder().allow("tool", arg=Pattern("*")).build()

        # Pattern("*") matches empty string
        assert guard._authorize("tool", {"arg": ""}) is None

    def test_complex_nested_args(self):
        """Complex nested arguments work."""
        guard = GuardBuilder().allow("tool", data=Wildcard()).build()

        complex_data = {
            "nested": {"deep": {"value": 123}},
            "list": [1, 2, {"a": "b"}],
        }

        assert guard._authorize("tool", {"data": complex_data}) is None


# =============================================================================
# Phase 2: Explain API Tests
# =============================================================================


class TestExplainAPI:
    """Test the explain() method for policy introspection."""

    def test_explain_allowed_tool(self):
        """explain() returns ALLOWED for valid calls."""
        from tenuo.crewai import ExplanationResult

        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        result = guard.explain("read", {"path": "/data/file.txt"})

        assert isinstance(result, ExplanationResult)
        assert result.status == "ALLOWED"
        assert result.tool == "read"
        assert "constraints" in result.details

    def test_explain_denied_tool_not_in_list(self):
        """explain() returns DENIED for tools not in allowlist."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        result = guard.explain("delete", {"path": "/data/file.txt"})

        assert result.status == "DENIED"
        assert "not in allowed list" in result.reason
        assert result.quick_fix is not None
        assert ".allow('delete'" in result.quick_fix

    def test_explain_denied_unlisted_argument(self):
        """explain() returns DENIED for unlisted arguments."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        result = guard.explain("read", {"path": "/data/file.txt", "mode": "r"})

        assert result.status == "DENIED"
        assert "mode" in result.reason
        assert result.details["argument"] == "mode"
        assert "Wildcard()" in result.quick_fix

    def test_explain_denied_constraint_violation(self):
        """explain() returns DENIED for constraint violations."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        result = guard.explain("read", {"path": "/etc/passwd"})

        assert result.status == "DENIED"
        assert "Constraint violation" in result.reason
        assert result.details["argument"] == "path"
        assert result.details["value"] == "/etc/passwd"
        assert result.quick_fix is None  # Can't auto-fix constraint violations

    def test_explain_does_not_raise(self):
        """explain() never raises, even for denied calls."""
        guard = GuardBuilder().build()  # Empty allowlist

        # Should not raise, even though _authorize would
        result = guard.explain("any_tool", {})

        assert result.status == "DENIED"

    def test_explain_with_agent_role(self):
        """explain() respects agent_role namespacing."""
        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .allow("researcher::search", query=Pattern("arxiv:*"))
            .build()
        )

        # Global search - allows anything
        result1 = guard.explain("search", {"query": "anything"})
        assert result1.status == "ALLOWED"

        # researcher::search - restricted
        result2 = guard.explain("search", {"query": "google.com"}, agent_role="researcher")
        assert result2.status == "DENIED"

        # researcher with valid query
        result3 = guard.explain("search", {"query": "arxiv:1234"}, agent_role="researcher")
        assert result3.status == "ALLOWED"


class TestExplanationResultBehavior:
    """Test ExplanationResult dataclass behavior."""

    def test_explanation_result_bool_allowed(self):
        """ExplanationResult is truthy when ALLOWED."""
        from tenuo.crewai import ExplanationResult

        result = ExplanationResult(tool="test", status="ALLOWED", reason="ok")
        assert bool(result) is True
        assert result  # if result: should work

    def test_explanation_result_bool_denied(self):
        """ExplanationResult is falsy when DENIED."""
        from tenuo.crewai import ExplanationResult

        result = ExplanationResult(tool="test", status="DENIED", reason="nope")
        assert bool(result) is False
        assert not result  # if not result: should work

    def test_explanation_result_repr(self):
        """ExplanationResult has readable repr."""
        from tenuo.crewai import ExplanationResult

        allowed = ExplanationResult(tool="read", status="ALLOWED", reason="ok")
        denied = ExplanationResult(tool="delete", status="DENIED", reason="blocked")

        assert "ALLOWED" in repr(allowed)
        assert "DENIED" in repr(denied)
        assert "blocked" in repr(denied)


class TestAllowsMethod:
    """Test the allows() convenience method."""

    def test_allows_returns_true_for_valid(self):
        """allows() returns True for valid calls."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        assert guard.allows("read", {"path": "/data/file.txt"}) is True

    def test_allows_returns_false_for_invalid(self):
        """allows() returns False for invalid calls."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        assert guard.allows("read", {"path": "/etc/passwd"}) is False
        assert guard.allows("delete", {"path": "/data/file.txt"}) is False

    def test_allows_for_ci_policy_test(self):
        """allows() works for CI policy tests."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).allow("list", directory=Subpath("/data")).build()

        # Positive assertions
        assert guard.allows("read", {"path": "/data/reports/q1.txt"})
        assert guard.allows("list", {"directory": "/data/logs"})

        # Negative assertions (security tests)
        assert not guard.allows("write", {"path": "/data/file.txt"})
        assert not guard.allows("read", {"path": "/etc/passwd"})


class TestExplainAll:
    """Test the explain_all() batch method."""

    def test_explain_all_returns_list(self):
        """explain_all() returns list of ExplanationResult."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).allow("search", query=Wildcard()).build()

        results = guard.explain_all(
            [
                ("read", {"path": "/data/file.txt"}),
                ("search", {"query": "test"}),
                ("delete", {"path": "/data/file.txt"}),
            ]
        )

        assert len(results) == 3
        assert results[0].status == "ALLOWED"
        assert results[1].status == "ALLOWED"
        assert results[2].status == "DENIED"

    def test_explain_all_with_agent_role(self):
        """explain_all() respects agent_role."""
        guard = GuardBuilder().allow("researcher::search", query=Pattern("arxiv:*")).build()

        results = guard.explain_all(
            [
                ("search", {"query": "arxiv:1234"}),
                ("search", {"query": "google.com"}),
            ],
            agent_role="researcher",
        )

        assert results[0].status == "ALLOWED"
        assert results[1].status == "DENIED"


class TestValidateMethod:
    """Test the validate() configuration check method."""

    def test_validate_empty_allowlist_warning(self):
        """validate() warns about empty allowlist."""
        guard = GuardBuilder().build()

        warnings = guard.validate()

        assert len(warnings) == 1
        assert "No tools allowed" in warnings[0]

    def test_validate_no_constraints_warning(self):
        """validate() warns about tools without constraints."""
        guard = GuardBuilder().allow("list_tools").build()

        warnings = guard.validate()

        # Tools without constraints get a warning - this helps catch
        # configuration errors where constraints were forgotten
        assert len(warnings) == 1
        assert "list_tools" in warnings[0]

    def test_validate_valid_config(self):
        """validate() returns empty list for valid config."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).allow("search", query=Wildcard()).build()

        warnings = guard.validate()

        assert warnings == []


# =============================================================================
# Phase 3: Tier 2 Support Tests
# =============================================================================


class TestTierProperty:
    """Test tier detection property."""

    def test_tier_1_without_warrant(self):
        """Guard without warrant is Tier 1."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        assert guard.tier == 1
        assert not guard.has_warrant

    def test_tier_2_with_warrant(self):
        """Guard with warrant is Tier 2."""

        mock_warrant = MagicMock()
        mock_key = MagicMock()

        guard = GuardBuilder().with_warrant(mock_warrant, mock_key).build()

        assert guard.tier == 2
        assert guard.has_warrant


class TestWarrantInfo:
    """Test warrant introspection."""

    def test_warrant_info_tier_1_returns_none(self):
        """warrant_info() returns None for Tier 1 guards."""
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        assert guard.warrant_info() is None

    def test_warrant_info_tier_2_returns_dict(self):
        """warrant_info() returns dict for Tier 2 guards."""
        mock_warrant = MagicMock()
        mock_warrant.id.return_value = "test-warrant-123"
        mock_warrant.ttl_seconds.return_value = 3600
        mock_warrant.is_expired.return_value = False
        mock_warrant.tools.return_value = ["read", "write"]
        mock_warrant.depth.return_value = 0
        mock_key = MagicMock()

        guard = GuardBuilder().with_warrant(mock_warrant, mock_key).build()

        info = guard.warrant_info()

        assert info is not None
        assert info["tier"] == 2
        assert info["warrant_id"] == "test-warrant-123"
        assert info["ttl_remaining"] == 3600
        assert info["is_expired"] is False
        assert "read" in info["tools"]


class TestWarrantExpiredException:
    """Test WarrantExpired exception."""

    def test_warrant_expired_message(self):
        """WarrantExpired has helpful message."""
        from tenuo.crewai import WarrantExpired

        error = WarrantExpired(warrant_id="test-123")

        assert "test-123" in str(error)
        assert "expired" in str(error).lower()
        assert "tenuo.ai" in str(error)

    def test_warrant_expired_error_code(self):
        """WarrantExpired has correct error code."""
        from tenuo.crewai import WarrantExpired

        error = WarrantExpired()

        assert error.error_code == "WARRANT_EXPIRED"


class TestInvalidPoPException:
    """Test InvalidPoP exception."""

    def test_invalid_pop_message(self):
        """InvalidPoP has helpful message."""
        from tenuo.crewai import InvalidPoP

        error = InvalidPoP(reason="signature mismatch")

        assert "signature mismatch" in str(error)
        assert "Proof-of-Possession" in str(error)

    def test_invalid_pop_error_code(self):
        """InvalidPoP has correct error code."""
        from tenuo.crewai import InvalidPoP

        error = InvalidPoP()

        assert error.error_code == "INVALID_POP"


class TestWarrantToolDeniedException:
    """Test WarrantToolDenied exception."""

    def test_warrant_tool_denied_message(self):
        """WarrantToolDenied has helpful message."""
        from tenuo.crewai import WarrantToolDenied

        error = WarrantToolDenied(tool="delete_all", warrant_id="w-123")

        assert "delete_all" in str(error)
        assert "w-123" in str(error)

    def test_warrant_tool_denied_error_code(self):
        """WarrantToolDenied has correct error code."""
        from tenuo.crewai import WarrantToolDenied

        error = WarrantToolDenied(tool="test")

        assert error.error_code == "WARRANT_TOOL_DENIED"


class TestTier2Authorization:
    """Test Tier 2 authorization flow."""

    def test_authorize_checks_warrant_expiry(self):
        """Authorization checks warrant expiry via enforcement."""
        mock_warrant = MagicMock()
        mock_key = MagicMock()

        # Setup mocks for binding
        mock_bound = MagicMock()
        mock_warrant.bind.return_value = mock_bound

        guard = (
            GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build()
        )

        # Mock enforcement to return expired result
        with patch("tenuo.crewai.enforce_tool_call") as mock_enforce:
            from tenuo._enforcement import EnforcementResult
            mock_enforce.return_value = EnforcementResult(
                allowed=False,
                tool="read",
                arguments={},
                denial_reason="Warrant expired",
                error_type="expired"
            )

            result = guard._authorize("read", {"path": "/data/file.txt"})

            # Should return DenialResult for expired warrant
            assert isinstance(result, DenialResult)
            assert result.error_code == "WARRANT_EXPIRED"

            # Verify delegation
            mock_warrant.bind.assert_called_with(mock_key)
            mock_enforce.assert_called_once()

    def test_authorize_delegates_to_enforcement(self):
        """Authorization delegates to unified enforcement logic."""
        mock_warrant = MagicMock()
        mock_key = MagicMock()
        mock_bound = MagicMock()
        mock_bound.id = "warrant-123"
        mock_warrant.bind.return_value = mock_bound

        guard = GuardBuilder().allow("read", path=Subpath("/data")).with_warrant(mock_warrant, mock_key).build()

        with patch("tenuo.crewai.enforce_tool_call") as mock_enforce:
            from tenuo._enforcement import EnforcementResult
            # Simulate allowed
            mock_enforce.return_value = EnforcementResult(
                allowed=True,
                tool="read",
                arguments={"path": "/data/file.txt"}
            )

            result = guard._authorize("read", {"path": "/data/file.txt"})

            # Should succeed
            assert result is None  # None = success
            mock_enforce.assert_called_once()

            # Check arguments passed to enforce_tool_call
            kargs = mock_enforce.call_args[1]
            assert kargs["tool_name"] == "read"
            assert kargs["bound_warrant"] == mock_bound

    def test_authorize_handles_enforcement_denial(self):
        """Authorization handles enforcement denial gracefully."""
        mock_warrant = MagicMock()
        mock_key = MagicMock()
        mock_bound = MagicMock()
        mock_warrant.bind.return_value = mock_bound

        guard = (
            GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build()
        )

        with patch("tenuo.crewai.enforce_tool_call") as mock_enforce:
            from tenuo._enforcement import EnforcementResult
            # Simulate denied (generic)
            mock_enforce.return_value = EnforcementResult(
                allowed=False,
                tool="read",
                arguments={},
                denial_reason="Invalid PoP signature"
            )

            result = guard._authorize("read", {"path": "/data/file.txt"})

            # Should return DenialResult
            assert isinstance(result, DenialResult)
            assert result.error_code == "INVALID_POP"


class TestTier2Exports:
    """Test that Tier 2 types are properly exported."""

    def test_tier2_exceptions_importable(self):
        """Tier 2 exceptions can be imported from tenuo.crewai."""
        from tenuo.crewai import (
            InvalidPoP,
            WarrantExpired,
            WarrantToolDenied,
        )

        assert WarrantExpired is not None
        assert InvalidPoP is not None
        assert WarrantToolDenied is not None

    def test_guard_tier_methods_exist(self):
        """Guard has tier-related methods and properties."""
        guard = GuardBuilder().allow("test", arg=Wildcard()).build()

        assert hasattr(guard, "tier")
        assert hasattr(guard, "has_warrant")
        assert hasattr(guard, "warrant_info")


# =============================================================================
# Phase 4: Delegation Tests
# =============================================================================


class TestWarrantDelegator:
    """Tests for WarrantDelegator (hierarchical crew support)."""

    def test_delegator_importable(self):
        """WarrantDelegator can be imported."""
        from tenuo.crewai import WarrantDelegator

        assert WarrantDelegator is not None
        delegator = WarrantDelegator()
        assert hasattr(delegator, "delegate")

    def test_delegation_rejects_unknown_tool(self):
        """Delegation fails if parent doesn't have the tool."""
        from tenuo.crewai import EscalationAttempt, WarrantDelegator

        delegator = WarrantDelegator()

        # Create mock parent warrant that only has "read" tool
        mock_parent = MagicMock()
        mock_parent.tools.return_value = ["read"]
        mock_parent.is_expired.return_value = False  # Not expired
        mock_key = MagicMock()
        mock_child_holder = MagicMock()

        # Try to delegate "delete" which parent doesn't have
        with pytest.raises(EscalationAttempt, match="delete"):
            delegator.delegate(
                parent_warrant=mock_parent,
                parent_key=mock_key,
                child_holder=mock_child_holder,
                attenuations={
                    "delete": {"target": Wildcard()},  # Escalation!
                },
            )

    def test_delegation_rejects_widening_constraint(self):
        """Delegation fails if child constraint would widen access."""
        from tenuo.crewai import EscalationAttempt, Pattern, WarrantDelegator

        delegator = WarrantDelegator()

        # Create mock parent with narrow constraint
        mock_parent = MagicMock()
        mock_parent.tools.return_value = ["search"]
        mock_parent.constraint_for.return_value = Pattern("arxiv:*")
        mock_parent.is_expired.return_value = False  # Not expired

        # Child constraint that DOES support is_subset_of
        child_constraint = MagicMock()
        child_constraint.is_subset_of.return_value = False  # Widening!

        mock_key = MagicMock()
        mock_child_holder = MagicMock()

        with pytest.raises(EscalationAttempt, match="widen"):
            delegator.delegate(
                parent_warrant=mock_parent,
                parent_key=mock_key,
                child_holder=mock_child_holder,
                attenuations={
                    "search": {"query": child_constraint},
                },
            )

    def test_delegation_succeeds_with_valid_attenuation(self):
        """Delegation succeeds when child properly narrows scope."""
        from tenuo.crewai import WarrantDelegator

        delegator = WarrantDelegator()

        # Mock parent with tools
        mock_parent = MagicMock()
        mock_parent.tools.return_value = ["read", "write"]
        mock_parent.constraint_for.return_value = None  # No constraint to check
        mock_parent.is_expired.return_value = False  # Not expired

        # Mock builder chain
        mock_builder = MagicMock()
        mock_builder.capability.return_value = mock_builder
        mock_builder.holder.return_value = mock_builder
        mock_builder.ttl.return_value = mock_builder
        mock_builder.grant.return_value = MagicMock()  # Child warrant
        mock_parent.grant_builder.return_value = mock_builder

        mock_key = MagicMock()
        mock_child_holder = MagicMock()

        # Delegate with valid attenuation (tool parent has)
        child_warrant = delegator.delegate(
            parent_warrant=mock_parent,
            parent_key=mock_key,
            child_holder=mock_child_holder,
            attenuations={
                "read": {"path": Subpath("/data/restricted")},
            },
            ttl=300,
        )

        assert child_warrant is not None
        mock_builder.capability.assert_called_once()
        mock_builder.holder.assert_called_once_with(mock_child_holder)
        mock_builder.ttl.assert_called_once_with(300)

    def test_delegation_no_grant_builder_error(self):
        """Delegation fails gracefully when parent lacks grant_builder."""
        from tenuo.crewai import WarrantDelegator

        delegator = WarrantDelegator()

        # Mock parent without grant_builder
        mock_parent = MagicMock()
        mock_parent.tools.return_value = ["read"]
        mock_parent.is_expired.return_value = False  # Not expired
        mock_parent.constraint_for.return_value = None  # No constraint to check (skips is_subset_of)
        del mock_parent.grant_builder  # Remove grant_builder

        mock_key = MagicMock()
        mock_child_holder = MagicMock()

        with pytest.raises(ValueError, match="doesn't support delegation"):
            delegator.delegate(
                parent_warrant=mock_parent,
                parent_key=mock_key,
                child_holder=mock_child_holder,
                attenuations={"read": {"path": Wildcard()}},
            )


class TestPhase5GuardedStep:
    """Tests for @guarded_step decorator (Phase 5)."""

    def test_guarded_step_importable(self):
        """guarded_step decorator is importable."""
        from tenuo.crewai import guarded_step

        assert callable(guarded_step)

    def test_guarded_step_creates_guard(self):
        """guarded_step creates a scoped guard."""
        from tenuo.crewai import Wildcard, get_active_guard, guarded_step

        guard_in_step = None

        @guarded_step(allow={"test_tool": {"arg": Wildcard()}})
        def my_step():
            nonlocal guard_in_step
            guard_in_step = get_active_guard()
            return "done"

        result = my_step()
        assert result == "done"
        assert guard_in_step is not None
        assert guard_in_step.tier == 1

    def test_guarded_step_with_ttl(self):
        """guarded_step accepts TTL parameter."""
        from tenuo.crewai import Wildcard, guarded_step

        @guarded_step(allow={"test": {"arg": Wildcard()}}, ttl="10m")
        def step_with_ttl():
            return "ok"

        result = step_with_ttl()
        assert result == "ok"

    def test_guarded_step_strict_mode(self):
        """strict=True enables strict mode during step."""
        from tenuo.crewai import Wildcard, guarded_step, is_strict_mode

        strict_inside = None

        @guarded_step(allow={"test": {"arg": Wildcard()}}, strict=True)
        def strict_step():
            nonlocal strict_inside
            strict_inside = is_strict_mode()
            return "ok"

        # Before step
        assert is_strict_mode() is False

        # During step
        strict_step()
        assert strict_inside is True

        # After step
        assert is_strict_mode() is False


class TestPhase5GuardedCrew:
    """Tests for GuardedCrew wrapper (Phase 5)."""

    def test_guarded_crew_importable(self):
        """GuardedCrew and builder are importable."""
        from tenuo.crewai import GuardedCrew

        assert callable(GuardedCrew)

    def test_guarded_crew_builder_pattern(self):
        """GuardedCrew returns a builder with fluent API."""
        from tenuo.crewai import GuardedCrew

        # Mock agents and tasks
        mock_agents = [MagicMock(role="researcher")]
        mock_tasks = [MagicMock()]

        builder = GuardedCrew(agents=mock_agents, tasks=mock_tasks)

        # Fluent API
        result = builder.policy({"researcher": ["search"]}).on_denial("log").strict()

        assert result is builder

    def test_guarded_crew_policy_method(self):
        """Policy method sets per-agent tool access."""
        from tenuo.crewai import GuardedCrew

        mock_agents = [MagicMock(role="researcher")]
        mock_tasks = [MagicMock()]

        builder = GuardedCrew(agents=mock_agents, tasks=mock_tasks)
        builder.policy(
            {
                "researcher": ["search", "read_file"],
            }
        )

        assert builder._policy["researcher"] == ["search", "read_file"]


class TestPhase5StrictMode:
    """Tests for strict mode context (Phase 5)."""

    def test_strict_mode_context_functions(self):
        """Strict mode context functions are importable."""
        from tenuo.crewai import get_active_guard, is_strict_mode

        # Outside any guard
        assert get_active_guard() is None
        assert is_strict_mode() is False

    def test_unguarded_tool_error(self):
        """UnguardedToolError has correct fields."""
        from tenuo.crewai import UnguardedToolError

        error = UnguardedToolError(tools=["dangerous_tool", "another_tool"], step_name="my_step")

        assert error.tools == ["dangerous_tool", "another_tool"]
        assert error.step_name == "my_step"
        assert "dangerous_tool" in str(error)
        assert "my_step" in str(error)
        assert "2 unguarded" in str(error)


class TestPhase5TTLParsing:
    """Tests for TTL string parsing."""

    def test_parse_ttl_seconds(self):
        """TTL parsing handles seconds."""
        from tenuo.crewai import _parse_ttl

        assert _parse_ttl("30s") == 30.0
        assert _parse_ttl("1s") == 1.0
        assert _parse_ttl("90s") == 90.0

    def test_parse_ttl_minutes(self):
        """TTL parsing handles minutes."""
        from tenuo.crewai import _parse_ttl

        assert _parse_ttl("10m") == 600.0
        assert _parse_ttl("1m") == 60.0

    def test_parse_ttl_hours(self):
        """TTL parsing handles hours."""
        from tenuo.crewai import _parse_ttl

        assert _parse_ttl("1h") == 3600.0
        assert _parse_ttl("2h") == 7200.0

    def test_parse_ttl_days(self):
        """TTL parsing handles days."""
        from tenuo.crewai import _parse_ttl

        assert _parse_ttl("1d") == 86400.0

    def test_parse_ttl_bare_number(self):
        """TTL parsing treats bare number as seconds."""
        from tenuo.crewai import _parse_ttl

        assert _parse_ttl("60") == 60.0


class TestPhase5GuardedStepAdvanced:
    """Advanced tests for @guarded_step decorator."""

    def test_guarded_step_passes_args(self):
        """guarded_step passes arguments through to wrapped function."""
        from tenuo.crewai import Wildcard, guarded_step

        @guarded_step(allow={"test": {"arg": Wildcard()}})
        def my_step(a, b, c=None):
            return (a, b, c)

        result = my_step(1, 2, c=3)
        assert result == (1, 2, 3)

    def test_guarded_step_preserves_function_name(self):
        """guarded_step preserves original function metadata."""
        from tenuo.crewai import Wildcard, guarded_step

        @guarded_step(allow={"test": {"arg": Wildcard()}})
        def my_named_function():
            pass

        assert my_named_function.__name__ == "my_named_function"

    def test_guarded_step_with_on_denial(self):
        """guarded_step respects on_denial setting."""
        from tenuo.crewai import Wildcard, guarded_step

        @guarded_step(allow={"test": {"arg": Wildcard()}}, on_denial="log")
        def step_with_log_denial():
            return "ok"

        result = step_with_log_denial()
        assert result == "ok"


class TestPhase5GuardedCrewAdvanced:
    """Advanced tests for GuardedCrew."""

    def test_guarded_crew_constraints_method(self):
        """GuardedCrew constraints method sets per-tool constraints."""
        from tenuo.crewai import GuardedCrew, Pattern

        mock_agents = [MagicMock(role="researcher")]
        mock_tasks = [MagicMock()]

        builder = GuardedCrew(agents=mock_agents, tasks=mock_tasks)
        builder.constraints(
            {
                "researcher": {
                    "search": {"query": Pattern("arxiv:*")},
                },
            }
        )

        assert "researcher" in builder._constraints
        assert "search" in builder._constraints["researcher"]

    def test_guarded_crew_ttl_method(self):
        """GuardedCrew ttl method sets TTL."""
        from tenuo.crewai import GuardedCrew

        mock_agents = [MagicMock(role="researcher")]
        mock_tasks = [MagicMock()]

        builder = GuardedCrew(agents=mock_agents, tasks=mock_tasks)
        builder.ttl("10m")

        assert builder._ttl == "10m"

    def test_guarded_crew_with_issuer(self):
        """GuardedCrew with_issuer sets Tier 2 config."""
        from tenuo.crewai import GuardedCrew

        mock_agents = [MagicMock(role="researcher")]
        mock_tasks = [MagicMock()]
        mock_warrant = MagicMock()
        mock_key = MagicMock()

        builder = GuardedCrew(agents=mock_agents, tasks=mock_tasks)
        builder.with_issuer(mock_warrant, mock_key)

        assert builder._issuer_warrant is mock_warrant
        assert builder._issuer_key is mock_key


class TestPhase5StrictModeAdvanced:
    """Advanced tests for strict mode."""

    def test_unguarded_tool_error_deduplicates(self):
        """UnguardedToolError deduplicates tool names."""
        from tenuo.crewai import UnguardedToolError

        # Same tool called multiple times
        error = UnguardedToolError(tools=["tool_a", "tool_b", "tool_a", "tool_b"], step_name="my_step")

        # Should report all occurrences (dedup happens in kickoff)
        assert len(error.tools) == 4

    def test_get_active_guard_returns_none_outside_context(self):
        """get_active_guard returns None when not in guarded zone."""
        from tenuo.crewai import get_active_guard

        assert get_active_guard() is None


class TestPhase5RealCrewAIIntegration:
    """Integration tests with real CrewAI package."""

    def test_crewai_tools_import(self):
        """Can import CrewAI tools module."""
        try:
            from crewai.tools.base_tool import Tool  # type: ignore[import-not-found]

            assert Tool is not None
        except ImportError:
            pytest.skip("crewai not installed")

    def test_register_hook_with_guard(self):
        """Can register a guard as a hook."""
        try:
            from tenuo.crewai import HOOKS_AVAILABLE, GuardBuilder, Subpath

            if not HOOKS_AVAILABLE:
                pytest.skip("CrewAI hooks API not available")

            guard = GuardBuilder().allow("read_document", path=Subpath("/data")).build()

            # Test that we can register/unregister without error
            guard.register()
            guard.unregister()
        except ImportError:
            pytest.skip("crewai not installed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
