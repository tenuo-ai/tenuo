"""
Tests for Tenuo-Temporal Integration (Phase 1 & 2).

These tests verify the core functionality without requiring
a running Temporal server.
"""

import base64
import gzip
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone

from tenuo.temporal import (
    # Exceptions
    TenuoTemporalError,
    TenuoContextError,
    ConstraintViolation,
    WarrantExpired,
    ChainValidationError,
    KeyResolutionError,
    # Phase 2 exceptions
    LocalActivityError,
    PopVerificationError,
    # Audit
    TemporalAuditEvent,
    # Key Resolvers
    KeyResolver,
    EnvKeyResolver,
    # Config
    TenuoInterceptorConfig,
    # Interceptor
    TenuoInterceptor,
    # Header utilities
    tenuo_headers,
    TENUO_WARRANT_HEADER,
    TENUO_KEY_ID_HEADER,
    TENUO_COMPRESSED_HEADER,
    TENUO_POP_HEADER,
    # Internal
    _extract_warrant_from_headers,
    _extract_key_id_from_headers,
    _compute_pop_challenge,
    # Phase 2: Decorators
    unprotected,
    is_unprotected,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_warrant():
    """Create a mock warrant for testing."""
    warrant = MagicMock()
    warrant.id.return_value = "test-warrant-123"
    warrant.to_base64.return_value = "eyJ0ZXN0IjogIndhcnJhbnQifQ=="  # {"test": "warrant"}
    warrant.is_expired.return_value = False
    warrant.expires_at.return_value = datetime(2030, 1, 1, tzinfo=timezone.utc)
    warrant.tools.return_value = ["read_file", "write_file"]
    warrant.check_constraints.return_value = True
    return warrant


@pytest.fixture
def mock_signing_key():
    """Create a mock signing key."""
    key = MagicMock()
    key.public_key.return_value = MagicMock()
    return key


# =============================================================================
# Test Header Utilities
# =============================================================================


class TestTenuoHeaders:
    """Tests for tenuo_headers() function."""

    def test_creates_headers_with_warrant(self, mock_warrant):
        """tenuo_headers creates proper header dict."""
        headers = tenuo_headers(mock_warrant, "key-123")

        assert TENUO_KEY_ID_HEADER in headers
        assert headers[TENUO_KEY_ID_HEADER] == b"key-123"
        assert TENUO_WARRANT_HEADER in headers
        assert TENUO_COMPRESSED_HEADER in headers

    def test_compresses_by_default(self, mock_warrant):
        """Warrant is gzip compressed by default."""
        headers = tenuo_headers(mock_warrant, "key-123")

        assert headers[TENUO_COMPRESSED_HEADER] == b"1"

        # Verify we can decompress
        compressed = base64.b64decode(headers[TENUO_WARRANT_HEADER])
        decompressed = gzip.decompress(compressed)
        assert b"eyJ0ZXN0IjogIndhcnJhbnQifQ==" in decompressed

    def test_uncompressed_option(self, mock_warrant):
        """Can disable compression."""
        headers = tenuo_headers(mock_warrant, "key-123", compress=False)

        assert headers[TENUO_COMPRESSED_HEADER] == b"0"
        # Should be the raw base64
        assert headers[TENUO_WARRANT_HEADER] == b"eyJ0ZXN0IjogIndhcnJhbnQifQ=="


class TestExtractKeyId:
    """Tests for _extract_key_id_from_headers()."""

    def test_extracts_key_id(self):
        """Extracts key ID from headers."""
        headers = {TENUO_KEY_ID_HEADER: b"my-key-id"}

        key_id = _extract_key_id_from_headers(headers)

        assert key_id == "my-key-id"

    def test_returns_none_when_missing(self):
        """Returns None when header is missing."""
        headers = {}

        key_id = _extract_key_id_from_headers(headers)

        assert key_id is None


# =============================================================================
# Test Key Resolvers
# =============================================================================


class TestEnvKeyResolver:
    """Tests for EnvKeyResolver."""

    def test_resolves_key_from_env(self):
        """Resolves key from environment variable."""
        import asyncio

        async def _test():
            # Create a mock key bytes
            key_b64 = base64.b64encode(b"x" * 32).decode()

            with patch.dict(os.environ, {"TENUO_KEY_test": key_b64}):
                with patch("tenuo_core.SigningKey") as MockSigningKey:
                    MockSigningKey.from_bytes.return_value = MagicMock()

                    resolver = EnvKeyResolver()
                    key = await resolver.resolve("test")

                    assert key is not None
                    MockSigningKey.from_bytes.assert_called_once()

        asyncio.run(_test())

    def test_raises_on_missing_key(self):
        """Raises KeyResolutionError for missing key."""
        import asyncio

        async def _test():
            resolver = EnvKeyResolver()

            with pytest.raises(KeyResolutionError) as exc_info:
                await resolver.resolve("nonexistent")

            assert exc_info.value.key_id == "nonexistent"

        asyncio.run(_test())

    def test_custom_prefix(self):
        """Supports custom environment variable prefix."""
        import asyncio

        async def _test():
            key_b64 = base64.b64encode(b"x" * 32).decode()

            with patch.dict(os.environ, {"MY_KEYS_agent1": key_b64}):
                with patch("tenuo_core.SigningKey") as MockSigningKey:
                    MockSigningKey.from_bytes.return_value = MagicMock()

                    resolver = EnvKeyResolver(prefix="MY_KEYS_")
                    key = await resolver.resolve("agent1")

                    assert key is not None

        asyncio.run(_test())


# =============================================================================
# Test Interceptor Config
# =============================================================================


class TestTenuoInterceptorConfig:
    """Tests for TenuoInterceptorConfig."""

    def test_default_values(self):
        """Config has sensible defaults."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)

        assert config.on_denial == "raise"
        assert config.tool_mappings == {}
        assert config.audit_callback is None
        assert config.audit_allow is True
        assert config.audit_deny is True
        assert config.max_chain_depth == 10

    def test_custom_values(self):
        """Can override all config values."""
        resolver = MagicMock(spec=KeyResolver)
        callback = MagicMock()

        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            on_denial="log",
            tool_mappings={"fetch": "read_file"},
            audit_callback=callback,
            audit_allow=False,
            audit_deny=True,
            max_chain_depth=5,
        )

        assert config.on_denial == "log"
        assert config.tool_mappings == {"fetch": "read_file"}
        assert config.audit_callback is callback
        assert config.audit_allow is False
        assert config.max_chain_depth == 5


# =============================================================================
# Test Audit Events
# =============================================================================


class TestTemporalAuditEvent:
    """Tests for TemporalAuditEvent."""

    def test_to_dict(self):
        """Converts to dictionary correctly."""
        event = TemporalAuditEvent(
            workflow_id="wf-123",
            workflow_type="MyWorkflow",
            workflow_run_id="run-456",
            activity_name="read_file",
            activity_id="act-789",
            task_queue="my-queue",
            decision="ALLOW",
            tool="read_file",
            arguments={"path": "/data/file.txt"},
            warrant_id="w-abc",
            warrant_expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            warrant_capabilities=["read_file", "write_file"],
        )

        d = event.to_dict()

        assert d["workflow_id"] == "wf-123"
        assert d["decision"] == "ALLOW"
        assert d["tool"] == "read_file"
        assert d["arguments"] == {"path": "/data/file.txt"}
        assert d["warrant_id"] == "w-abc"
        assert "timestamp" in d

    def test_denial_event(self):
        """Denial events include reason and constraint."""
        event = TemporalAuditEvent(
            workflow_id="wf-123",
            workflow_type="MyWorkflow",
            workflow_run_id="run-456",
            activity_name="read_file",
            activity_id="act-789",
            task_queue="my-queue",
            decision="DENY",
            tool="read_file",
            arguments={"path": "/etc/passwd"},
            warrant_id="w-abc",
            warrant_expires_at=None,
            warrant_capabilities=["read_file"],
            denial_reason="Path outside allowed scope",
            constraint_violated="path_constraint",
        )

        d = event.to_dict()

        assert d["decision"] == "DENY"
        assert d["denial_reason"] == "Path outside allowed scope"
        assert d["constraint_violated"] == "path_constraint"


# =============================================================================
# Test Exceptions
# =============================================================================


class TestExceptions:
    """Tests for Temporal-specific exceptions."""

    def test_constraint_violation_str(self):
        """ConstraintViolation has informative str."""
        exc = ConstraintViolation(
            tool="read_file",
            arguments={"path": "/etc/passwd"},
            constraint="Path not in allowed scope",
            warrant_id="w-123",
        )

        msg = str(exc)

        assert "read_file" in msg
        assert "Path not in allowed scope" in msg
        assert "w-123" in msg

    def test_warrant_expired_str(self):
        """WarrantExpired has informative str."""
        exc = WarrantExpired(
            warrant_id="w-123",
            expired_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        msg = str(exc)

        assert "w-123" in msg
        assert "expired" in msg.lower()

    def test_chain_validation_error_str(self):
        """ChainValidationError has informative str."""
        exc = ChainValidationError(
            reason="Signature mismatch",
            depth=3,
        )

        msg = str(exc)

        assert "depth 3" in msg
        assert "Signature mismatch" in msg

    def test_key_resolution_error_str(self):
        """KeyResolutionError has informative str."""
        exc = KeyResolutionError(key_id="missing-key")

        msg = str(exc)

        assert "missing-key" in msg


# =============================================================================
# Test Interceptor
# =============================================================================


class TestTenuoInterceptor:
    """Tests for TenuoInterceptor."""

    def test_creates_activity_interceptor(self):
        """Creates activity inbound interceptor."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)
        interceptor = TenuoInterceptor(config)

        next_interceptor = MagicMock()
        activity_interceptor = interceptor.intercept_activity(next_interceptor)

        assert activity_interceptor is not None
        assert hasattr(activity_interceptor, "execute_activity")


# =============================================================================
# Phase 2: @unprotected Decorator Tests
# =============================================================================


class TestUnprotectedDecorator:
    """Tests for @unprotected decorator."""

    def test_marks_function_as_unprotected(self):
        """@unprotected sets the marker attribute."""

        @unprotected
        def my_activity():
            pass

        assert hasattr(my_activity, "_tenuo_unprotected")
        assert my_activity._tenuo_unprotected is True

    def test_is_unprotected_returns_true_for_decorated(self):
        """is_unprotected returns True for decorated functions."""

        @unprotected
        def my_activity():
            pass

        assert is_unprotected(my_activity) is True

    def test_is_unprotected_returns_false_for_regular(self):
        """is_unprotected returns False for regular functions."""

        def my_activity():
            pass

        assert is_unprotected(my_activity) is False

    def test_decorator_preserves_function(self):
        """@unprotected doesn't modify function behavior."""

        @unprotected
        def add(a, b):
            return a + b

        assert add(2, 3) == 5


# =============================================================================
# Phase 2: Exception Tests
# =============================================================================


class TestPhase2Exceptions:
    """Tests for Phase 2 exceptions."""

    def test_local_activity_error_str(self):
        """LocalActivityError has informative str."""
        exc = LocalActivityError("read_file")

        msg = str(exc)

        assert "read_file" in msg
        assert "local activity" in msg.lower()
        assert "@unprotected" in msg

    def test_pop_verification_error_str(self):
        """PopVerificationError has informative str."""
        exc = PopVerificationError(
            reason="Missing signature",
            activity_name="write_data",
        )

        msg = str(exc)

        assert "write_data" in msg
        assert "Missing signature" in msg


# =============================================================================
# Phase 2: PoP Challenge Tests
# =============================================================================


class TestPopChallenge:
    """Tests for PoP challenge computation."""

    def test_compute_pop_challenge_deterministic(self):
        """Same inputs produce same challenge."""
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        challenge1 = _compute_pop_challenge(
            workflow_id="wf-123",
            activity_id="act-456",
            tool_name="read_file",
            args={"path": "/data/file.txt"},
            scheduled_time=ts,
        )

        challenge2 = _compute_pop_challenge(
            workflow_id="wf-123",
            activity_id="act-456",
            tool_name="read_file",
            args={"path": "/data/file.txt"},
            scheduled_time=ts,
        )

        assert challenge1 == challenge2

    def test_compute_pop_challenge_different_inputs(self):
        """Different inputs produce different challenges."""
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        challenge1 = _compute_pop_challenge(
            workflow_id="wf-123",
            activity_id="act-456",
            tool_name="read_file",
            args={"path": "/data/file.txt"},
            scheduled_time=ts,
        )

        challenge2 = _compute_pop_challenge(
            workflow_id="wf-123",
            activity_id="act-456",
            tool_name="read_file",
            args={"path": "/data/other.txt"},  # Different path
            scheduled_time=ts,
        )

        assert challenge1 != challenge2

    def test_compute_pop_challenge_returns_bytes(self):
        """Challenge is returned as bytes (SHA-256)."""
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        challenge = _compute_pop_challenge(
            workflow_id="wf-123",
            activity_id="act-456",
            tool_name="read_file",
            args={},
            scheduled_time=ts,
        )

        assert isinstance(challenge, bytes)
        assert len(challenge) == 32  # SHA-256 = 32 bytes


# =============================================================================
# Phase 2: Config Tests
# =============================================================================


class TestPhase2Config:
    """Tests for Phase 2 config options."""

    def test_default_phase2_values(self):
        """Phase 2 config has sensible defaults."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)

        assert config.require_pop is False  # Off for adoption
        assert config.block_local_activities is True  # Secure by default
        assert config.pop_window_seconds == 300  # 5 minutes

    def test_can_enable_require_pop(self):
        """Can enable PoP requirement for production."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(
            key_resolver=resolver,
            require_pop=True,
            pop_window_seconds=60,
        )

        assert config.require_pop is True
        assert config.pop_window_seconds == 60


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
