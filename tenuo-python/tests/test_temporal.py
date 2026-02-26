"""
Tests for Tenuo-Temporal Integration (Phase 1 & 2).

These tests verify the core functionality without requiring
a running Temporal server.
"""

import asyncio
import base64
import gzip
import os
import pytest
import threading
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone

# Skip all tests if temporalio is not installed
pytest.importorskip("temporalio")

from tenuo.temporal import (  # noqa: E402 - must be after importorskip
    # Exceptions
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
    _extract_key_id_from_headers,
    _compute_pop_challenge,
    # Phase 2: Decorators
    unprotected,
    is_unprotected,
    # Phase 3: Decorators and delegation
    tool,
    get_tool_name,
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
    warrant.to_bytes.return_value = b'{"test": "warrant"}'
    warrant.is_expired.return_value = False
    warrant.expires_at.return_value = datetime(2030, 1, 1, tzinfo=timezone.utc)
    warrant.tools.return_value = ["read_file", "write_file"]
    warrant.check_constraints.return_value = True
    return warrant


@pytest.fixture
def mock_signing_key():
    """Create a mock signing key."""
    key = MagicMock()
    key.secret_key_bytes.return_value = b"\x00" * 32  # 32-byte signing key
    key.public_key.return_value = MagicMock()
    return key


# =============================================================================
# Test Header Utilities
# =============================================================================


class TestTenuoHeaders:
    """Tests for tenuo_headers() function."""

    def test_creates_headers_with_warrant(self, mock_warrant, mock_signing_key):
        """tenuo_headers creates proper header dict."""
        headers = tenuo_headers(mock_warrant, "key-123")

        assert TENUO_KEY_ID_HEADER in headers
        assert headers[TENUO_KEY_ID_HEADER] == b"key-123"
        assert TENUO_WARRANT_HEADER in headers
        assert TENUO_COMPRESSED_HEADER in headers
        # Security: Private key should NOT be in headers
        assert "x-tenuo-signing-key" not in headers

    def test_compresses_by_default(self, mock_warrant, mock_signing_key):
        """Warrant is gzip compressed by default."""
        headers = tenuo_headers(mock_warrant, "key-123")

        assert headers[TENUO_COMPRESSED_HEADER] == b"1"

        # V2 format: raw gzip(cbor), no intermediate base64
        decompressed = gzip.decompress(headers[TENUO_WARRANT_HEADER])
        assert decompressed == b'{"test": "warrant"}'

    def test_uncompressed_option(self, mock_warrant, mock_signing_key):
        """Can disable compression."""
        headers = tenuo_headers(mock_warrant, "key-123", compress=False)

        assert headers[TENUO_COMPRESSED_HEADER] == b"0"
        # V2 format: raw CBOR bytes (no base64 wrapping)
        assert headers[TENUO_WARRANT_HEADER] == b'{"test": "warrant"}'

    def test_signing_key_not_in_headers(self, mock_warrant, mock_signing_key):
        """SECURITY: Signing key is NEVER transmitted in headers."""
        headers = tenuo_headers(mock_warrant, "key-123")

        # Private key must NOT be in headers (security requirement)
        assert "x-tenuo-signing-key" not in headers

        # Verify no key material in any header value
        key_bytes = mock_signing_key.to_bytes()
        for value in headers.values():
            assert key_bytes not in value, "Private key bytes found in headers!"


class TestSecurityKeyNeverTransmitted:
    """Security tests: Verify private keys are NEVER transmitted in headers.

    These tests enforce the critical security requirement that private keys
    must never be included in Temporal headers (which are persisted in the
    database and transmitted over the network).
    """

    def test_tenuo_headers_never_contains_private_key_bytes(self):
        """SECURITY: Private key bytes must never appear in any header."""
        from tenuo_core import SigningKey, Warrant

        # Generate a real key with real bytes
        signing_key = SigningKey.generate()
        key_bytes = signing_key.secret_key_bytes()

        # Create a real warrant
        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        # Generate headers
        headers = tenuo_headers(warrant, "test-key-id")

        # Verify key bytes are NOT in any header value
        for header_name, header_value in headers.items():
            assert key_bytes not in header_value, (
                f"SECURITY VIOLATION: Private key bytes found in header {header_name}!"
            )

    def test_tenuo_headers_never_contains_signing_key_header(self):
        """SECURITY: TENUO_SIGNING_KEY_HEADER must never be present."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        headers = tenuo_headers(warrant, "test-key-id")

        # The deprecated header must NOT be present
        assert "x-tenuo-signing-key" not in headers, (
            "SECURITY VIOLATION: TENUO_SIGNING_KEY_HEADER found in headers! "
            "Private keys must never be transmitted."
        )

    def test_only_key_id_transmitted(self):
        """SECURITY: Only key_id (not the key itself) is transmitted."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        headers = tenuo_headers(warrant, "prod-agent-2024")

        # Key ID should be present
        assert TENUO_KEY_ID_HEADER in headers
        assert headers[TENUO_KEY_ID_HEADER] == b"prod-agent-2024"

        # But no key material
        assert "x-tenuo-signing-key" not in headers

    def test_base64_encoded_key_not_in_headers(self):
        """SECURITY: Even base64-encoded keys must not be in headers."""
        import base64
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        key_bytes = signing_key.secret_key_bytes()
        key_b64 = base64.b64encode(key_bytes)

        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        headers = tenuo_headers(warrant, "test-key")

        # Verify base64-encoded key is NOT in headers
        for header_value in headers.values():
            assert key_b64 not in header_value, (
                "SECURITY VIOLATION: Base64-encoded private key found in headers!"
            )

    def test_multiple_headers_no_key_leakage(self):
        """SECURITY: Multiple header generations don't leak keys."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        key_bytes = signing_key.secret_key_bytes()

        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        # Generate headers multiple times
        for i in range(10):
            headers = tenuo_headers(warrant, f"key-{i}")

            # Each time, verify no key leakage
            for header_value in headers.values():
                assert key_bytes not in header_value

    def test_compressed_and_uncompressed_no_key_leakage(self):
        """SECURITY: Both compressed and uncompressed modes never leak keys."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        key_bytes = signing_key.secret_key_bytes()

        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        # Test compressed
        headers_compressed = tenuo_headers(warrant, "key-1", compress=True)
        for header_value in headers_compressed.values():
            assert key_bytes not in header_value

        # Test uncompressed
        headers_uncompressed = tenuo_headers(warrant, "key-1", compress=False)
        for header_value in headers_uncompressed.values():
            assert key_bytes not in header_value


class TestTenuoHeadersRejectsKeyObjects:
    """Runtime guard: tenuo_headers() must reject SigningKey objects as key_id."""

    def test_rejects_signing_key_as_key_id(self):
        """Passing a SigningKey instead of a string key_id raises TypeError."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        with pytest.raises(TypeError, match="not a SigningKey"):
            tenuo_headers(warrant, signing_key)

    def test_rejects_bytes_as_key_id(self):
        """Passing raw bytes instead of a string key_id raises TypeError."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        with pytest.raises(TypeError, match="must be a string"):
            tenuo_headers(warrant, signing_key.secret_key_bytes())

    def test_rejects_int_as_key_id(self):
        """Passing a non-string type raises TypeError."""
        from tenuo_core import SigningKey, Warrant

        signing_key = SigningKey.generate()
        warrant = Warrant.issue(
            signing_key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=signing_key.public_key,
        )

        with pytest.raises(TypeError, match="must be a string"):
            tenuo_headers(warrant, 12345)


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
# Test KeyResolver.resolve_sync()
# =============================================================================


class TestResolveSyncUnderEventLoop:
    """Tests for KeyResolver.resolve_sync() behavior under running event loops.

    resolve_sync() must work from both sync contexts and from within
    running event loops (e.g., Temporal workflow coroutines). The latter
    requires a thread-pool fallback to avoid 'loop already running' errors.
    """

    def test_resolve_sync_without_event_loop(self):
        """resolve_sync works when no event loop is running."""
        import asyncio

        class TestResolver(KeyResolver):
            async def resolve(self, key_id: str):
                return f"key-for-{key_id}"

        resolver = TestResolver()
        result = resolver.resolve_sync("agent-1")
        assert result == "key-for-agent-1"

    def test_resolve_sync_under_running_event_loop(self):
        """resolve_sync works when called from within a running event loop."""
        import asyncio

        class TestResolver(KeyResolver):
            async def resolve(self, key_id: str):
                await asyncio.sleep(0.01)
                return f"key-for-{key_id}"

        resolver = TestResolver()

        async def _run_inside_loop():
            return resolver.resolve_sync("agent-2")

        result = asyncio.run(_run_inside_loop())
        assert result == "key-for-agent-2"

    def test_resolve_sync_propagates_errors(self):
        """resolve_sync propagates KeyResolutionError from resolve()."""

        class FailingResolver(KeyResolver):
            async def resolve(self, key_id: str):
                raise KeyResolutionError(key_id)

        resolver = FailingResolver()
        with pytest.raises(KeyResolutionError) as exc:
            resolver.resolve_sync("missing-key")
        assert exc.value.key_id == "missing-key"

    def test_resolve_sync_override(self):
        """Subclasses can override resolve_sync for efficient sync implementations."""

        class SyncNativeResolver(KeyResolver):
            async def resolve(self, key_id: str):
                raise RuntimeError("should not be called")

            def resolve_sync(self, key_id: str):
                return f"sync-{key_id}"

        resolver = SyncNativeResolver()
        result = resolver.resolve_sync("fast-key")
        assert result == "sync-fast-key"


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
    """Tests for exception types."""

    def test_constraint_violation_str(self):
        """ConstraintViolation has informative str."""
        exc = ConstraintViolation(
            tool="read_file",
            arguments={"path": "/etc/passwd"},
            constraint="path must start with /allowed",
            warrant_id="w-123",
        )

        assert "read_file" in str(exc)
        assert "path must start" in str(exc)
        assert exc.error_code == "CONSTRAINT_VIOLATED"

    def test_warrant_expired_str(self):
        """WarrantExpired has informative str."""
        from datetime import datetime, timezone

        exc = WarrantExpired(
            warrant_id="w-123",
            expired_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        assert "w-123" in str(exc)
        assert "expired" in str(exc).lower()
        assert exc.error_code == "WARRANT_EXPIRED"

    def test_chain_validation_error_str(self):
        """ChainValidationError has informative str."""
        exc = ChainValidationError(reason="Invalid signature at level 2", depth=2)

        assert "depth 2" in str(exc)
        assert "Invalid signature" in str(exc)
        assert exc.error_code == "CHAIN_INVALID"

    def test_key_resolution_error_str(self):
        """KeyResolutionError has informative str."""
        exc = KeyResolutionError(key_id="missing-key")

        assert "missing-key" in str(exc)
        assert exc.error_code == "KEY_NOT_FOUND"

    def test_local_activity_error_has_error_code(self):
        """LocalActivityError has error_code class attribute."""
        exc = LocalActivityError("my_activity")

        assert exc.error_code == "LOCAL_ACTIVITY_BLOCKED"

    def test_pop_verification_error_has_error_code(self):
        """PopVerificationError has error_code field."""
        exc = PopVerificationError(reason="bad sig", activity_name="my_activity")

        assert exc.error_code == "POP_VERIFICATION_FAILED"


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

        assert config.block_local_activities is True  # Secure by default

    def test_pop_is_always_mandatory(self):
        """PoP is always mandatory — no config toggle exists."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)

        # Verify require_pop is no longer a config option
        assert not hasattr(config, "require_pop")
        assert not hasattr(config, "pop_window_seconds")


# =============================================================================
# Phase 3: @tool() Decorator Tests
# =============================================================================


class TestToolDecorator:
    """Tests for @tool() decorator."""

    def test_marks_function_with_tool_name(self):
        """@tool() sets the tool name attribute."""

        @tool("read_file")
        def fetch_document():
            pass

        assert hasattr(fetch_document, "_tenuo_tool_name")
        assert fetch_document._tenuo_tool_name == "read_file"

    def test_get_tool_name_returns_decorated_name(self):
        """get_tool_name returns the @tool() name."""

        @tool("write_file")
        def save_document():
            pass

        assert get_tool_name(save_document, "save_document") == "write_file"

    def test_get_tool_name_returns_default_for_undecorated(self):
        """get_tool_name returns default for undecorated functions."""

        def my_activity():
            pass

        assert get_tool_name(my_activity, "my_activity") == "my_activity"

    def test_decorator_preserves_function(self):
        """@tool() doesn't modify function behavior."""

        @tool("calculator")
        def multiply(a, b):
            return a * b

        assert multiply(3, 4) == 12

    def test_decorator_can_stack_with_unprotected(self):
        """@tool() and @unprotected can be stacked."""

        @unprotected
        @tool("internal_lookup")
        def lookup_config(key):
            return f"value_{key}"

        assert get_tool_name(lookup_config, "default") == "internal_lookup"
        assert is_unprotected(lookup_config) is True
        assert lookup_config("foo") == "value_foo"


# =============================================================================
# Phase 4: Enterprise Key Resolvers & Metrics Tests
# =============================================================================


class TestCompositeKeyResolver:
    """Tests for CompositeKeyResolver fallback behavior."""

    def test_uses_first_successful_resolver(self):
        """CompositeKeyResolver uses first resolver that succeeds."""
        import asyncio
        from tenuo.temporal import CompositeKeyResolver

        # Mock resolvers
        failing_resolver = MagicMock(spec=KeyResolver)
        failing_resolver.resolve = AsyncMock(side_effect=KeyResolutionError("key1"))

        succeeding_resolver = MagicMock(spec=KeyResolver)
        mock_key = MagicMock()
        succeeding_resolver.resolve = AsyncMock(return_value=mock_key)

        composite = CompositeKeyResolver([failing_resolver, succeeding_resolver])
        result = asyncio.run(composite.resolve("key1"))

        assert result == mock_key
        failing_resolver.resolve.assert_called_once_with("key1")
        succeeding_resolver.resolve.assert_called_once_with("key1")

    def test_raises_if_all_fail(self):
        """CompositeKeyResolver raises if all resolvers fail."""
        import asyncio
        from tenuo.temporal import CompositeKeyResolver

        resolver1 = MagicMock(spec=KeyResolver)
        resolver1.resolve = AsyncMock(side_effect=KeyResolutionError("key1"))

        resolver2 = MagicMock(spec=KeyResolver)
        resolver2.resolve = AsyncMock(side_effect=KeyResolutionError("key1"))

        composite = CompositeKeyResolver([resolver1, resolver2])

        with pytest.raises(KeyResolutionError):
            asyncio.run(composite.resolve("key1"))

    def test_requires_at_least_one_resolver(self):
        """CompositeKeyResolver requires at least one resolver."""
        from tenuo.temporal import CompositeKeyResolver

        with pytest.raises(ValueError):
            CompositeKeyResolver([])


class TestAWSSecretsManagerKeyResolver:
    """Tests for AWSSecretsManagerKeyResolver."""

    def test_resolves_binary_secret(self):
        """AWSSecretsManagerKeyResolver handles binary secrets."""
        import asyncio
        import sys
        from unittest.mock import patch

        from tenuo.temporal import AWSSecretsManagerKeyResolver

        mock_key_bytes = b"\x00" * 32  # 32-byte key
        mock_response = {"SecretBinary": mock_key_bytes}

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = mock_response
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            with patch("tenuo_core.SigningKey") as mock_signing_key:
                mock_signing_key.from_bytes.return_value = MagicMock()

                resolver = AWSSecretsManagerKeyResolver(secret_prefix="tenuo/")
                result = asyncio.run(resolver.resolve("my-key"))

                mock_client.get_secret_value.assert_called_once_with(SecretId="tenuo/my-key")
                mock_signing_key.from_bytes.assert_called_once_with(mock_key_bytes)
                assert result is not None

    def test_resolves_string_secret(self):
        """AWSSecretsManagerKeyResolver handles base64 string secrets."""
        import asyncio
        import base64
        import sys
        from unittest.mock import patch

        from tenuo.temporal import AWSSecretsManagerKeyResolver

        mock_key_bytes = b"\x00" * 32
        mock_response = {"SecretString": base64.b64encode(mock_key_bytes).decode()}

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = mock_response
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            with patch("tenuo_core.SigningKey") as mock_signing_key:
                mock_signing_key.from_bytes.return_value = MagicMock()

                resolver = AWSSecretsManagerKeyResolver()
                result = asyncio.run(resolver.resolve("key1"))

                assert result is not None

    def test_caches_resolved_keys(self):
        """AWSSecretsManagerKeyResolver caches keys."""
        import asyncio
        import sys
        from unittest.mock import patch

        from tenuo.temporal import AWSSecretsManagerKeyResolver

        mock_response = {"SecretBinary": b"\x00" * 32}

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = mock_response
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            with patch("tenuo_core.SigningKey") as mock_signing_key:
                mock_signing_key.from_bytes.return_value = MagicMock()

                resolver = AWSSecretsManagerKeyResolver(cache_ttl=300)

                # First call
                asyncio.run(resolver.resolve("key1"))
                # Second call should use cache
                asyncio.run(resolver.resolve("key1"))

                # Should only call AWS once
                assert mock_client.get_secret_value.call_count == 1

    def test_raises_on_missing_boto3(self):
        """AWSSecretsManagerKeyResolver raises KeyResolutionError if boto3 missing."""
        import asyncio
        import builtins
        import sys
        from unittest.mock import patch

        from tenuo.temporal import AWSSecretsManagerKeyResolver, KeyResolutionError

        resolver = AWSSecretsManagerKeyResolver()

        # Mock only boto3 import, not all imports
        original_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("No module named 'boto3'")
            return original_import(name, *args, **kwargs)

        with patch.dict(sys.modules, {"boto3": None}):
            with patch("builtins.__import__", side_effect=mock_import):
                with pytest.raises(KeyResolutionError):
                    asyncio.run(resolver.resolve("key1"))


class TestGCPSecretManagerKeyResolver:
    """Tests for GCPSecretManagerKeyResolver."""

    @staticmethod
    def _gcp_mock_context(mock_sm):
        """Context manager that makes ``from google.cloud import secretmanager``
        resolve to *mock_sm*, regardless of whether google-cloud-secret-manager
        is actually installed.

        Handles two scenarios:
        - google.cloud already in sys.modules (local dev with google-adk):
          sets the secretmanager attribute on the existing namespace package.
        - google.cloud NOT in sys.modules (CI without any google packages):
          injects stub modules for google and google.cloud too.
        """
        import contextlib
        import sys
        import types
        from unittest.mock import patch

        @contextlib.contextmanager
        def _ctx():
            # Build the modules dict we need to inject
            modules_to_inject: dict = {
                "google.cloud.secretmanager": mock_sm,
            }

            # If google / google.cloud aren't in sys.modules yet (CI),
            # create stub namespace modules so the import chain resolves.
            if "google" not in sys.modules:
                mock_google = types.ModuleType("google")
                mock_google.__path__ = []  # type: ignore[attr-defined]
                modules_to_inject["google"] = mock_google
            if "google.cloud" not in sys.modules:
                mock_gc = types.ModuleType("google.cloud")
                mock_gc.__path__ = []  # type: ignore[attr-defined]
                modules_to_inject["google.cloud"] = mock_gc

            with patch.dict(sys.modules, modules_to_inject):
                # Set the attribute on google.cloud so
                # ``from google.cloud import secretmanager`` finds it.
                gc = sys.modules["google.cloud"]
                had_attr = hasattr(gc, "secretmanager")
                old_attr = getattr(gc, "secretmanager", None)
                gc.secretmanager = mock_sm  # type: ignore[attr-defined]
                try:
                    yield
                finally:
                    if had_attr:
                        gc.secretmanager = old_attr  # type: ignore[attr-defined]
                    else:
                        try:
                            delattr(gc, "secretmanager")
                        except AttributeError:
                            pass
        return _ctx()

    def test_resolves_secret(self):
        """GCPSecretManagerKeyResolver resolves secrets."""
        import asyncio
        from unittest.mock import patch

        from tenuo.temporal import GCPSecretManagerKeyResolver

        mock_key_bytes = b"\x00" * 32

        mock_sm = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.payload.data = mock_key_bytes
        mock_client.access_secret_version.return_value = mock_response
        mock_sm.SecretManagerServiceClient.return_value = mock_client

        with self._gcp_mock_context(mock_sm):
            with patch("tenuo_core.SigningKey") as mock_signing_key:
                mock_signing_key.from_bytes.return_value = MagicMock()

                resolver = GCPSecretManagerKeyResolver(project_id="my-project")
                result = asyncio.run(resolver.resolve("my-key"))

                expected_name = "projects/my-project/secrets/tenuo-keys-my-key/versions/latest"
                mock_client.access_secret_version.assert_called_once_with(name=expected_name)
                assert result is not None

    def test_caches_resolved_keys(self):
        """GCPSecretManagerKeyResolver caches keys."""
        import asyncio
        from unittest.mock import patch

        from tenuo.temporal import GCPSecretManagerKeyResolver

        mock_sm = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.payload.data = b"\x00" * 32
        mock_client.access_secret_version.return_value = mock_response
        mock_sm.SecretManagerServiceClient.return_value = mock_client

        with self._gcp_mock_context(mock_sm):
            with patch("tenuo_core.SigningKey") as mock_signing_key:
                mock_signing_key.from_bytes.return_value = MagicMock()

                resolver = GCPSecretManagerKeyResolver(project_id="proj", cache_ttl=300)

                # First call
                asyncio.run(resolver.resolve("key1"))
                # Second call should use cache
                asyncio.run(resolver.resolve("key1"))

                # Should only call GCP once
                assert mock_client.access_secret_version.call_count == 1

    def test_custom_prefix_and_version(self):
        """GCPSecretManagerKeyResolver respects custom prefix and version."""
        import asyncio
        from unittest.mock import patch

        from tenuo.temporal import GCPSecretManagerKeyResolver

        mock_sm = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.payload.data = b"\x00" * 32
        mock_client.access_secret_version.return_value = mock_response
        mock_sm.SecretManagerServiceClient.return_value = mock_client

        with self._gcp_mock_context(mock_sm):
            with patch("tenuo_core.SigningKey") as mock_signing_key:
                mock_signing_key.from_bytes.return_value = MagicMock()

                resolver = GCPSecretManagerKeyResolver(
                    project_id="my-proj",
                    secret_prefix="prod-",
                    version="5",
                )
                asyncio.run(resolver.resolve("key-abc"))

                expected_name = "projects/my-proj/secrets/prod-key-abc/versions/5"
                mock_client.access_secret_version.assert_called_once_with(name=expected_name)


class TestTenuoMetrics:
    """Tests for TenuoMetrics."""

    def test_records_authorized(self):
        """TenuoMetrics records authorized activities."""
        from tenuo.temporal import TenuoMetrics

        metrics = TenuoMetrics(prefix="test")
        metrics.record_authorized("read_file", "MyWorkflow", 0.005)

        stats = metrics.get_stats()
        assert "read_file:MyWorkflow" in stats["authorized"]
        assert stats["authorized"]["read_file:MyWorkflow"] == 1
        assert stats["latency_count"] == 1

    def test_records_denied(self):
        """TenuoMetrics records denied activities."""
        from tenuo.temporal import TenuoMetrics

        metrics = TenuoMetrics(prefix="test")
        metrics.record_denied("write_file", "expired", "MyWorkflow", 0.003)

        stats = metrics.get_stats()
        assert "write_file:expired:MyWorkflow" in stats["denied"]
        assert stats["denied"]["write_file:expired:MyWorkflow"] == 1

    def test_calculates_average_latency(self):
        """TenuoMetrics calculates average latency."""
        from tenuo.temporal import TenuoMetrics

        metrics = TenuoMetrics(prefix="test")
        metrics.record_authorized("read_file", "MyWorkflow", 0.010)
        metrics.record_authorized("read_file", "MyWorkflow", 0.020)

        stats = metrics.get_stats()
        assert stats["latency_avg"] == pytest.approx(0.015, rel=0.01)


class TestPhase4Config:
    """Tests for Phase 4 config options."""

    def test_default_phase4_values(self):
        """Phase 4 config defaults are sensible."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)

        assert config.metrics is None
        assert config.enable_tracing is False

    def test_can_enable_metrics(self):
        """Can enable metrics in config."""
        from tenuo.temporal import TenuoMetrics

        resolver = MagicMock(spec=KeyResolver)
        metrics = TenuoMetrics(prefix="test")
        config = TenuoInterceptorConfig(key_resolver=resolver, metrics=metrics)

        assert config.metrics is metrics

    def test_can_enable_tracing(self):
        """Can enable tracing in config."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver, enable_tracing=True)

        assert config.enable_tracing is True


class TestSecurityConfig:
    """Tests for security hardening config options."""

    def test_require_warrant_defaults_to_true(self):
        """require_warrant defaults to True (fail-closed)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)

        assert config.require_warrant is True

    def test_can_disable_require_warrant(self):
        """Can disable require_warrant for opt-in mode."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver, require_warrant=False)

        assert config.require_warrant is False

    def test_redact_args_defaults_to_true(self):
        """redact_args_in_logs defaults to True (secure by default)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver)

        assert config.redact_args_in_logs is True

    def test_can_disable_redact_args(self):
        """Can disable arg redaction for debugging."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoInterceptorConfig(key_resolver=resolver, redact_args_in_logs=False)

        assert config.redact_args_in_logs is False


# =============================================================================
# Key Resolver Cache & Failure Tests
# =============================================================================


class TestVaultKeyResolverCache:
    """Tests for VaultKeyResolver cache thread safety and failure paths."""

    def test_cache_returns_cached_key_within_ttl(self):
        """Cached key is returned without Vault fetch when within TTL."""
        import time
        from tenuo.temporal import VaultKeyResolver

        resolver = VaultKeyResolver(
            url="https://vault.test:8200",
            token="test-token",
            cache_ttl=300,
        )

        fake_key = MagicMock()
        with resolver._cache_lock:
            resolver._cache["agent-1"] = (fake_key, time.time())

        async def _test():
            return await resolver.resolve("agent-1")

        result = asyncio.run(_test())
        assert result is fake_key

    def test_cache_expires_after_ttl(self):
        """Cached key is NOT returned after TTL expires — triggers fresh fetch."""
        import time
        from tenuo.temporal import VaultKeyResolver

        resolver = VaultKeyResolver(
            url="https://vault.test:8200",
            token="test-token",
            cache_ttl=1,
        )

        fake_key = MagicMock()
        with resolver._cache_lock:
            resolver._cache["agent-1"] = (fake_key, time.time() - 10)

        async def _test():
            return await resolver.resolve("agent-1")

        with pytest.raises(Exception):
            asyncio.run(_test())

    def test_missing_token_raises_key_resolution_error(self):
        """Vault resolver raises KeyResolutionError when no token available."""
        from tenuo.temporal import VaultKeyResolver, KeyResolutionError

        resolver = VaultKeyResolver(
            url="https://vault.test:8200",
            token=None,
            cache_ttl=300,
        )

        async def _test():
            return await resolver.resolve("agent-1")

        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(KeyResolutionError):
                asyncio.run(_test())

    def test_concurrent_cache_access_is_safe(self):
        """Multiple threads reading/writing cache don't corrupt it."""
        import time
        import threading
        from tenuo.temporal import VaultKeyResolver

        resolver = VaultKeyResolver(
            url="https://vault.test:8200",
            token="test-token",
            cache_ttl=300,
        )

        errors = []

        def _write(key_id):
            try:
                with resolver._cache_lock:
                    resolver._cache[key_id] = (MagicMock(), time.time())
            except Exception as e:
                errors.append(e)

        def _read(key_id):
            try:
                with resolver._cache_lock:
                    resolver._cache.get(key_id)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(50):
            t = threading.Thread(target=_write, args=(f"key-{i}",))
            threads.append(t)
            t = threading.Thread(target=_read, args=(f"key-{i % 10}",))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(resolver._cache) == 50


class TestDedupCacheEviction:
    """Tests for the PoP dedup cache size limit."""

    def test_dedup_cache_has_max_size_constant(self):
        """_DEDUP_MAX_SIZE is defined and reasonable."""
        from tenuo.temporal import _DEDUP_MAX_SIZE
        assert _DEDUP_MAX_SIZE > 0
        assert _DEDUP_MAX_SIZE <= 100_000

    def test_dedup_cache_can_be_filled_and_cleared(self):
        """Basic smoke test: cache supports dict operations."""
        from tenuo.temporal import _pop_dedup_cache, _store_lock
        import time

        _pop_dedup_cache.clear()

        now = time.time()
        for i in range(100):
            _pop_dedup_cache[f"nonce-{i}"] = now

        assert len(_pop_dedup_cache) == 100
        _pop_dedup_cache.clear()
        assert len(_pop_dedup_cache) == 0


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
