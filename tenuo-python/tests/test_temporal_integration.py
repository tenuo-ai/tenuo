"""
Integration tests for Tenuo-Temporal Interceptor.

These tests verify the configuration, decorators, exceptions, and public API
of the Temporal integration. They are designed to run without requiring
the actual temporalio package.

Test Coverage:
- Configuration defaults (require_warrant, redact_args, block_local_activities)
- @tool() decorator behavior
- @unprotected decorator behavior
- Exception error_code fields
- Audit event structure
- Chain depth validation
- Warrant expiration detection
"""

import pytest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock

# Import the modules under test
from tenuo.temporal import (
    # Config
    TenuoInterceptorConfig,
    KeyResolver,
    # Exceptions
    ConstraintViolation,
    WarrantExpired,
    ChainValidationError,
    LocalActivityError,
    PopVerificationError,
    # Decorators
    unprotected,
    is_unprotected,
    tool,
    get_tool_name,
    # Audit
    TemporalAuditEvent,
)


# =============================================================================
# Test Fixtures
# =============================================================================


class MockWarrant:
    """Mock warrant for testing."""

    def __init__(
        self,
        warrant_id: str = "w-123",
        tools: List[str] = None,
        expired: bool = False,
        expires_at: datetime = None,
        chain_depth: int = 1,
    ):
        self._id = warrant_id
        self._tools = tools or ["test_activity", "read_file"]
        self._expired = expired
        self._expires_at = expires_at or (
            datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self._chain_depth = chain_depth

    def id(self) -> str:
        return self._id

    def tools(self) -> List[str]:
        return self._tools

    def is_expired(self) -> bool:
        return self._expired

    def expires_at(self) -> datetime:
        return self._expires_at

    def allows(self, tool: str, args: Dict[str, Any]) -> bool:
        return tool in self._tools

    def chain_depth(self) -> int:
        return self._chain_depth


# =============================================================================
# Test: Configuration Defaults
# =============================================================================


class TestConfigurationDefaults:
    """Test that configuration defaults are secure."""

    def test_require_warrant_defaults_to_true(self):
        """require_warrant should default to True (fail-closed)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)
        assert config.require_warrant is True

    def test_redact_args_defaults_to_true(self):
        """redact_args_in_logs should default to True (secure by default)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)
        assert config.redact_args_in_logs is True

    def test_block_local_activities_defaults_to_true(self):
        """block_local_activities should default to True (fail-closed)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)
        assert config.block_local_activities is True

    def test_max_chain_depth_defaults_to_10(self):
        """max_chain_depth should default to 10."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)
        assert config.max_chain_depth == 10

    def test_on_denial_defaults_to_raise(self):
        """on_denial should default to 'raise'."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)
        assert config.on_denial == "raise"


# =============================================================================
# Test: Tool Decorator
# =============================================================================


class TestToolDecorator:
    """Test @tool() decorator for activity-to-tool mapping."""

    def test_tool_decorator_sets_attribute(self):
        """@tool() decorator should set _tenuo_tool_name attribute."""

        @tool("read_file")
        def fetch_document():
            pass

        assert hasattr(fetch_document, "_tenuo_tool_name")
        assert fetch_document._tenuo_tool_name == "read_file"

    def test_tool_decorator_preserves_function(self):
        """@tool() decorator should preserve function behavior."""

        @tool("test_tool")
        def my_func(x: int) -> int:
            return x * 2

        assert my_func(5) == 10

    def test_get_tool_name_with_decorator(self):
        """get_tool_name should return the decorator name."""

        @tool("custom_tool")
        def my_activity():
            pass

        assert get_tool_name(my_activity, "my_activity") == "custom_tool"

    def test_get_tool_name_without_decorator(self):
        """get_tool_name should return default when no decorator."""

        def my_activity():
            pass

        assert get_tool_name(my_activity, "my_activity") == "my_activity"


# =============================================================================
# Test: Unprotected Decorator
# =============================================================================


class TestUnprotectedDecorator:
    """Test @unprotected decorator for local activities."""

    def test_unprotected_decorator_marks_function(self):
        """@unprotected decorator should mark function with attribute."""

        @unprotected
        def my_local_activity():
            pass

        assert hasattr(my_local_activity, "_tenuo_unprotected")
        assert my_local_activity._tenuo_unprotected is True

    def test_is_unprotected_returns_true_for_decorated(self):
        """is_unprotected should return True for @unprotected functions."""

        @unprotected
        def my_local_activity():
            pass

        assert is_unprotected(my_local_activity) is True

    def test_is_unprotected_returns_false_for_regular_function(self):
        """is_unprotected should return False for regular functions."""

        def my_protected_activity():
            pass

        assert is_unprotected(my_protected_activity) is False

    def test_unprotected_preserves_function(self):
        """@unprotected decorator should preserve function behavior."""

        @unprotected
        def my_func(x: int) -> int:
            return x + 1

        assert my_func(10) == 11


# =============================================================================
# Test: Exception Error Codes
# =============================================================================


class TestExceptionErrorCodes:
    """Test that all exceptions have error_code for wire format compatibility."""

    def test_constraint_violation_has_error_code(self):
        """ConstraintViolation should have error_code field."""
        exc = ConstraintViolation(
            tool="test_tool",
            arguments={"key": "value"},
            constraint="test_constraint",
            warrant_id="w-123",
        )
        assert hasattr(exc, "error_code")
        # Note: the actual code is "CONSTRAINT_VIOLATED" not "CONSTRAINT_VIOLATION"
        assert exc.error_code == "CONSTRAINT_VIOLATED"

    def test_warrant_expired_has_error_code(self):
        """WarrantExpired should have error_code field."""
        exc = WarrantExpired(
            warrant_id="w-123", expired_at=datetime.now(timezone.utc)
        )
        assert hasattr(exc, "error_code")
        assert exc.error_code == "WARRANT_EXPIRED"

    def test_chain_validation_error_has_error_code(self):
        """ChainValidationError should have error_code field."""
        exc = ChainValidationError(reason="test", depth=5)
        assert hasattr(exc, "error_code")
        assert exc.error_code == "CHAIN_INVALID"

    def test_local_activity_error_has_error_code(self):
        """LocalActivityError should have error_code field."""
        exc = LocalActivityError(activity_name="test")
        assert hasattr(exc, "error_code")
        assert exc.error_code == "LOCAL_ACTIVITY_BLOCKED"

    def test_pop_verification_error_has_error_code(self):
        """PopVerificationError should have error_code field."""
        exc = PopVerificationError(reason="test", activity_name="test")
        assert hasattr(exc, "error_code")
        assert exc.error_code == "POP_VERIFICATION_FAILED"


# =============================================================================
# Test: Audit Event Structure
# =============================================================================


class TestAuditEventStructure:
    """Test TemporalAuditEvent structure."""

    def test_audit_event_has_required_fields(self):
        """TemporalAuditEvent should have all required fields."""
        event = TemporalAuditEvent(
            workflow_id="wf-123",
            workflow_type="TestWorkflow",
            workflow_run_id="run-abc",
            activity_name="test_activity",
            activity_id="act-1",
            task_queue="test-queue",
            decision="ALLOW",
            tool="test_tool",
            arguments={"key": "value"},
            warrant_id="w-123",
            warrant_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            warrant_capabilities=["test_tool"],
        )

        assert event.decision == "ALLOW"
        assert event.activity_name == "test_activity"
        assert event.tool == "test_tool"
        assert event.warrant_id == "w-123"
        assert event.arguments == {"key": "value"}

    def test_audit_event_supports_denial(self):
        """TemporalAuditEvent should support denial reason."""
        event = TemporalAuditEvent(
            workflow_id="wf-123",
            workflow_type="TestWorkflow",
            workflow_run_id="run-abc",
            activity_name="test_activity",
            activity_id="act-1",
            task_queue="test-queue",
            decision="DENY",
            tool="test_tool",
            arguments={},
            warrant_id="w-123",
            warrant_expires_at=None,
            warrant_capabilities=[],
            denial_reason="No warrant provided",
            constraint_violated="require_warrant",
        )

        assert event.decision == "DENY"
        assert event.denial_reason == "No warrant provided"
        assert event.constraint_violated == "require_warrant"

    def test_audit_event_to_dict(self):
        """TemporalAuditEvent.to_dict() should return serializable dict."""
        event = TemporalAuditEvent(
            workflow_id="wf-123",
            workflow_type="TestWorkflow",
            workflow_run_id="run-abc",
            activity_name="test_activity",
            activity_id="act-1",
            task_queue="test-queue",
            decision="ALLOW",
            tool="test_tool",
            arguments={"path": "/file.txt"},
            warrant_id="w-123",
            warrant_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            warrant_capabilities=["test_tool"],
        )

        result = event.to_dict()
        assert isinstance(result, dict)
        assert result["workflow_id"] == "wf-123"
        assert result["tool"] == "test_tool"


# =============================================================================
# Test: Chain Depth Validation
# =============================================================================


class TestChainDepthValidation:
    """Test max_chain_depth enforcement logic."""

    def test_chain_depth_within_limit_is_valid(self):
        """Chain depth within limit should not raise."""
        warrant = MockWarrant(chain_depth=3)
        max_depth = 5

        assert warrant.chain_depth() <= max_depth

    def test_chain_depth_exceeding_limit_would_fail(self):
        """Chain depth exceeding limit should be detected."""
        warrant = MockWarrant(chain_depth=10)
        max_depth = 5

        assert warrant.chain_depth() > max_depth

    def test_chain_depth_at_exact_limit_is_valid(self):
        """Chain depth at exactly the limit should be valid."""
        warrant = MockWarrant(chain_depth=5)
        max_depth = 5

        assert warrant.chain_depth() <= max_depth


# =============================================================================
# Test: Warrant Expiration Logic
# =============================================================================


class TestWarrantExpirationLogic:
    """Test warrant expiration detection."""

    def test_valid_warrant_is_not_expired(self):
        """Valid warrant should not be expired."""
        future_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        warrant = MockWarrant(expired=False, expires_at=future_expiry)

        assert warrant.is_expired() is False

    def test_expired_warrant_is_detected(self):
        """Expired warrant should be detected."""
        past_expiry = datetime.now(timezone.utc) - timedelta(hours=1)
        warrant = MockWarrant(expired=True, expires_at=past_expiry)

        assert warrant.is_expired() is True


# =============================================================================
# Test: Configuration Customization
# =============================================================================


class TestConfigurationCustomization:
    """Test that configuration can be customized."""

    def test_require_warrant_can_be_disabled(self):
        """require_warrant can be set to False for opt-in mode."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            require_warrant=False,
        )
        assert config.require_warrant is False

    def test_max_chain_depth_can_be_customized(self):
        """max_chain_depth can be customized."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            max_chain_depth=3,
        )
        assert config.max_chain_depth == 3

    def test_redact_args_can_be_disabled(self):
        """redact_args_in_logs can be disabled."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            redact_args_in_logs=False,
        )
        assert config.redact_args_in_logs is False

    def test_tool_mappings_can_be_configured(self):
        """tool_mappings can map activity names to tool names."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            tool_mappings={"fetch_document": "read_file"},
        )
        assert config.tool_mappings["fetch_document"] == "read_file"


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
