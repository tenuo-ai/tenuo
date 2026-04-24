"""
Tests for Tenuo-Temporal Integration (Phase 1 & 2).

These tests verify the core functionality without requiring
a running Temporal server.
"""

import asyncio
import base64
import gzip
import os
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Skip all tests if temporalio is not installed
pytest.importorskip("temporalio")

from tenuo.temporal._constants import (  # noqa: E402 - must be after importorskip
    TENUO_COMPRESSED_HEADER,
    TENUO_KEY_ID_HEADER,
    TENUO_POP_HEADER,
    TENUO_WARRANT_HEADER,
)
from tenuo.temporal.exceptions import (  # noqa: E402
    ChainValidationError,
    KeyResolutionError,
    LocalActivityError,
    PopVerificationError,
    TemporalConstraintViolation,
    WarrantExpired,
)
from tenuo.temporal._resolvers import EnvKeyResolver, KeyResolver  # noqa: E402
from tenuo.temporal._observability import TemporalAuditEvent  # noqa: E402
from tenuo.temporal._interceptors import TenuoWorkerInterceptor  # noqa: E402
from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._headers import _extract_key_id_from_headers, tenuo_headers  # noqa: E402
from tenuo.temporal._decorators import get_tool_name, is_unprotected, tool, unprotected  # noqa: E402

from tenuo import SigningKey as _TenCfgSigningKey  # noqa: E402

_TEMPORAL_TRUST_ROOTS = [_TenCfgSigningKey.generate().public_key]

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
    key.to_bytes.return_value = b"\x00" * 32
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

        # Payload is gzip-compressed raw bytes (no base64 wrapping).
        decompressed = gzip.decompress(headers[TENUO_WARRANT_HEADER])
        assert decompressed == b'{"test": "warrant"}'

    def test_uncompressed_option(self, mock_warrant, mock_signing_key):
        """Can disable compression."""
        headers = tenuo_headers(mock_warrant, "key-123", compress=False)

        assert headers[TENUO_COMPRESSED_HEADER] == b"0"
        # Uncompressed: raw bytes in the warrant header (no base64 wrapping).
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

    def test_resolves_hex_encoded_key(self):
        """EnvKeyResolver auto-detects hex-encoded keys."""
        import asyncio

        async def _test():
            key_hex = ("ab" * 32)  # 64 hex chars = 32 bytes

            with patch.dict(os.environ, {"TENUO_KEY_hexkey": key_hex}):
                with patch("tenuo_core.SigningKey") as MockSigningKey:
                    MockSigningKey.from_bytes.return_value = MagicMock()

                    resolver = EnvKeyResolver()
                    key = await resolver.resolve("hexkey")

                    assert key is not None
                    MockSigningKey.from_bytes.assert_called_once_with(bytes.fromhex(key_hex))

        asyncio.run(_test())

    def test_decode_key_bytes_base64(self):
        """_decode_key_bytes handles base64."""
        raw = b"x" * 32
        encoded = base64.b64encode(raw).decode()
        assert EnvKeyResolver._decode_key_bytes(encoded) == raw

    def test_decode_key_bytes_hex(self):
        """_decode_key_bytes handles hex."""
        raw = bytes(range(32))
        encoded = raw.hex()
        assert EnvKeyResolver._decode_key_bytes(encoded) == raw

    def test_decode_key_bytes_rejects_garbage(self):
        """_decode_key_bytes raises on unrecognized format."""
        with pytest.raises(ValueError, match="Cannot decode"):
            EnvKeyResolver._decode_key_bytes("not-a-valid-key-at-all!!!")


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


class TestTenuoPluginConfig:
    """Tests for TenuoPluginConfig."""

    def test_default_values(self):
        """Config has sensible defaults."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(
            key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS
        )

        assert config.on_denial == "raise"
        assert config.dry_run is False
        assert config.tool_mappings == {}
        assert config.audit_callback is None
        assert config.audit_allow is True
        assert config.audit_deny is True
        assert config.max_chain_depth == 10

    def test_custom_values(self):
        """Can override all config values."""
        resolver = MagicMock(spec=KeyResolver)
        callback = MagicMock()

        config = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            on_denial="log",
            dry_run=True,
            tool_mappings={"fetch": "read_file"},
            audit_callback=callback,
            audit_allow=False,
            audit_deny=True,
            max_chain_depth=5,
        )

        assert config.on_denial == "log"
        assert config.dry_run is True
        assert config.tool_mappings == {"fetch": "read_file"}
        assert config.audit_callback is callback
        assert config.audit_allow is False
        assert config.max_chain_depth == 5

    def test_trusted_roots_required_without_global(self):
        from tenuo.config import reset_config
        from tenuo.exceptions import ConfigurationError

        reset_config()
        try:
            resolver = MagicMock(spec=KeyResolver)
            with pytest.raises(ConfigurationError, match="trusted_roots"):
                TenuoPluginConfig(key_resolver=resolver)
        finally:
            reset_config()

    def test_signing_key_synthesizes_resolver(self):
        from tenuo_core import SigningKey

        sk = SigningKey.generate()
        cfg = TenuoPluginConfig(signing_key=sk, trusted_roots=_TEMPORAL_TRUST_ROOTS)
        assert cfg.key_resolver is not None
        assert cfg.key_resolver.resolve_sync("any-id") is sk

    def test_neither_resolver_nor_signing_key_raises(self):
        from tenuo.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="key_resolver|signing_key"):
            TenuoPluginConfig(trusted_roots=_TEMPORAL_TRUST_ROOTS)

    def test_approval_handler_widens_retry_pop_when_unset(self):
        resolver = MagicMock(spec=KeyResolver)
        cfg = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            approval_handler=lambda _r: None,
        )
        assert cfg.retry_pop_max_windows == 240

    def test_approval_handler_respects_explicit_retry_pop(self):
        resolver = MagicMock(spec=KeyResolver)
        cfg = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            approval_handler=lambda _r: None,
            retry_pop_max_windows=120,
        )
        assert cfg.retry_pop_max_windows == 120

    def test_retry_pop_default_covers_temporal_default_backoff(self):
        """Default ``retry_pop_max_windows`` must survive Temporal's default retry policy.

        Temporal's default exponential backoff (``initial_interval=1s``,
        ``backoff_coefficient=2``, ``max_interval=100s``) places the Nth retry
        at roughly ``1 + 2 + 4 + … + min(2^(N-1), 100)`` seconds. Ten retries
        land at ~800 s and fifteen retries at ~1300 s. With a 30-second
        window, that maps to ceil(800/30)=27 and ceil(1300/30)=44 windows.

        The default must cover at least ten-retry scenarios to prevent
        transient backend failures from becoming permanent via
        ``PopVerificationError(non_retryable=True)``. Fifteen retries is the
        upper tolerance: beyond ~22 minutes the operator should set the field
        explicitly.
        """
        resolver = MagicMock(spec=KeyResolver)
        cfg = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
        )
        # Simulate a 10-retry horizon under Temporal's default policy.
        ten_retry_seconds = 1
        interval = 1
        for _ in range(10):
            interval = min(interval * 2, 100)
            ten_retry_seconds += interval
        windows_needed = (ten_retry_seconds + 29) // 30  # ceil
        assert cfg.retry_pop_max_windows is not None
        assert cfg.retry_pop_max_windows >= windows_needed, (
            f"Default retry_pop_max_windows={cfg.retry_pop_max_windows} "
            f"cannot cover a 10-retry horizon (~{ten_retry_seconds} s, "
            f"~{windows_needed} windows) under Temporal's default policy."
        )

    def test_trusted_approvers_not_accepted_on_config(self):
        """TenuoPluginConfig no longer accepts trusted_approvers — warrant is source of truth."""
        resolver = MagicMock(spec=KeyResolver)
        with pytest.raises(TypeError, match="trusted_approvers"):
            TenuoPluginConfig(
                key_resolver=resolver,
                trusted_roots=_TEMPORAL_TRUST_ROOTS,
                trusted_approvers=["should_fail"],
            )

    def test_approval_threshold_not_accepted_on_config(self):
        """TenuoPluginConfig no longer accepts approval_threshold — warrant is source of truth."""
        resolver = MagicMock(spec=KeyResolver)
        with pytest.raises(TypeError, match="approval_threshold"):
            TenuoPluginConfig(
                key_resolver=resolver,
                trusted_roots=_TEMPORAL_TRUST_ROOTS,
                approval_threshold=2,
            )

    def test_trusted_roots_refresh_preserves_clearance_and_srl(self, monkeypatch):
        """Authorizer refresh must re-apply clearance_requirements and SRL.

        Regression: ``_maybe_refresh_trusted_roots`` used to rebuild the
        Authorizer with only ``trusted_roots=``, silently dropping clearance
        policy and the current revocation list.
        """
        from tenuo import SigningKey
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        import tenuo_core  # type: ignore[import-not-found]

        class _FakeAuthorizer:
            instances: list = []

            def __init__(self, *, trusted_roots, **kwargs):
                self.trusted_roots = list(trusted_roots)
                self.kwargs = kwargs
                self.clearance: dict = {}
                self.srl = None
                type(self).instances.append(self)

            def require_clearance(self, tool, clearance):
                self.clearance[tool] = clearance

            def set_revocation_list(self, srl):
                self.srl = srl

        _FakeAuthorizer.instances.clear()
        monkeypatch.setattr(tenuo_core, "Authorizer", _FakeAuthorizer)

        initial_root = SigningKey.generate().public_key
        rotated_root = SigningKey.generate().public_key
        clearance_requirements = {"read_file": "high"}
        srl = object()

        roots_to_return = [initial_root]

        def provider():
            return list(roots_to_return)

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots_provider=provider,
            trusted_roots_refresh_interval_secs=1.0,
            clearance_requirements=clearance_requirements,
            revocation_list=srl,
        )
        activity_interceptor = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=cfg, version="test"
        )
        assert _FakeAuthorizer.instances[-1].clearance == clearance_requirements
        assert _FakeAuthorizer.instances[-1].srl is srl

        roots_to_return = [rotated_root]
        activity_interceptor._last_trusted_roots_refresh = -1e9
        activity_interceptor._maybe_refresh_trusted_roots()

        rebuilt = _FakeAuthorizer.instances[-1]
        assert rebuilt.trusted_roots == [rotated_root]
        assert rebuilt.clearance == clearance_requirements
        assert rebuilt.srl is srl

    def test_worker_interceptor_accepts_trusted_roots_provider_without_control_plane(self):
        """``TenuoWorkerInterceptor(cfg)`` must not blow up when ``cfg`` uses
        ``trusted_roots_provider=`` and no explicit ``control_plane=``.

        Regression: ``__init__`` used ``dataclasses.replace`` to attach a
        default control plane, which re-ran ``__post_init__`` and tripped the
        "pass either trusted_roots= or trusted_roots_provider=, not both"
        check because the first post-init had already seeded ``trusted_roots``
        from the provider.
        """
        from tenuo import SigningKey

        root = SigningKey.generate().public_key
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots_provider=lambda: [root],
        )
        interceptor = TenuoWorkerInterceptor(cfg)
        assert interceptor._config.trusted_roots_provider is cfg.trusted_roots_provider
        assert interceptor._config.trusted_roots == [root]

    def test_trusted_roots_refresh_ignores_provider_exceptions(self, monkeypatch):
        """When ``trusted_roots_provider`` raises, the existing Authorizer is kept
        and the error is logged but not surfaced — otherwise a transient fetch
        failure would take the whole worker down mid-activity.
        """
        from tenuo import SigningKey
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        import tenuo_core  # type: ignore[import-not-found]

        class _FakeAuthorizer:
            instances: list = []

            def __init__(self, *, trusted_roots, **kwargs):
                self.trusted_roots = list(trusted_roots)
                type(self).instances.append(self)

            def require_clearance(self, tool, clearance):  # pragma: no cover
                pass

            def set_revocation_list(self, srl):  # pragma: no cover
                pass

        _FakeAuthorizer.instances.clear()
        monkeypatch.setattr(tenuo_core, "Authorizer", _FakeAuthorizer)

        root = SigningKey.generate().public_key
        call_count = {"n": 0}

        def flaky_provider():
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [root]
            raise RuntimeError("transient KMS outage")

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots_provider=flaky_provider,
            trusted_roots_refresh_interval_secs=1.0,
        )
        ai = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=cfg, version="test"
        )
        before = _FakeAuthorizer.instances[-1]
        assert before.trusted_roots == [root]

        ai._last_trusted_roots_refresh = -1e9
        ai._maybe_refresh_trusted_roots()

        assert _FakeAuthorizer.instances[-1] is before, (
            "Authorizer must NOT be rebuilt when the provider raises"
        )

    def test_trusted_roots_refresh_ignores_empty_provider_result(self, monkeypatch):
        """An empty ``trusted_roots_provider()`` result must keep the prior Authorizer
        (otherwise a misconfigured provider would silently reject every request).
        """
        from tenuo import SigningKey
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        import tenuo_core  # type: ignore[import-not-found]

        class _FakeAuthorizer:
            instances: list = []

            def __init__(self, *, trusted_roots, **kwargs):
                self.trusted_roots = list(trusted_roots)
                type(self).instances.append(self)

            def require_clearance(self, tool, clearance):  # pragma: no cover
                pass

            def set_revocation_list(self, srl):  # pragma: no cover
                pass

        _FakeAuthorizer.instances.clear()
        monkeypatch.setattr(tenuo_core, "Authorizer", _FakeAuthorizer)

        root = SigningKey.generate().public_key
        roots_to_return = [root]

        def provider():
            return list(roots_to_return)

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots_provider=provider,
            trusted_roots_refresh_interval_secs=1.0,
        )
        ai = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=cfg, version="test"
        )
        before = _FakeAuthorizer.instances[-1]

        roots_to_return = []
        ai._last_trusted_roots_refresh = -1e9
        ai._maybe_refresh_trusted_roots()

        assert _FakeAuthorizer.instances[-1] is before

    def test_revocation_list_refresh_survives_set_revocation_list_exception(
        self, monkeypatch
    ):
        """A failing ``set_revocation_list`` on the Authorizer must not crash
        the refresh loop; the next refresh tick must still fire.
        """
        from tenuo import SigningKey
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        import tenuo_core  # type: ignore[import-not-found]

        class _FakeAuthorizer:
            def __init__(self, *, trusted_roots, **kwargs):
                self.trusted_roots = list(trusted_roots)
                self.srl_attempts = 0

            def require_clearance(self, tool, clearance):  # pragma: no cover
                pass

            def set_revocation_list(self, srl):
                self.srl_attempts += 1
                raise RuntimeError("authorizer rejected SRL")

        monkeypatch.setattr(tenuo_core, "Authorizer", _FakeAuthorizer)

        root = SigningKey.generate().public_key
        srl_value = {"revoked": ["warrant-xyz"]}

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[root],
            revocation_list_provider=lambda: srl_value,
            revocation_refresh_secs=1.0,
        )
        ai = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=cfg, version="test"
        )

        ai._last_srl_refresh = -1e9
        ai._maybe_refresh_revocation_list()

        assert ai._authorizer.srl_attempts == 1
        assert ai._config.revocation_list == srl_value, (
            "config.revocation_list should be updated even if the Authorizer "
            "call failed — the next refresh tick must be able to retry."
        )

    def test_retry_authorizer_selected_on_retry_attempt(self):
        """``_retry_authorizer`` must be used for ``info.attempt > 1``."""
        from tenuo import SigningKey
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[SigningKey.generate().public_key],
            retry_pop_max_windows=120,
        )
        ai = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=cfg, version="test"
        )
        assert ai._authorizer is not None
        assert ai._retry_authorizer is not None
        assert ai._authorizer is not ai._retry_authorizer, (
            "Retry authorizer must be a distinct instance so the wider "
            "pop_max_windows only applies on retry attempts."
        )

    def test_retry_authorizer_not_built_when_disabled(self):
        """Setting ``retry_pop_max_windows=None`` disables retry widening entirely."""
        from tenuo import SigningKey
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[SigningKey.generate().public_key],
            retry_pop_max_windows=None,
        )
        ai = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=cfg, version="test"
        )
        assert ai._retry_authorizer is None

    def test_empty_authorized_signals_rejected_at_config_time(self):
        """``authorized_signals=[]`` is a deny-everything footgun — reject early."""
        from tenuo.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="authorized_signals"):
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                trusted_roots=_TEMPORAL_TRUST_ROOTS,
                authorized_signals=[],
            )

    def test_empty_authorized_updates_rejected_at_config_time(self):
        """``authorized_updates=[]`` is also deny-everything — reject early."""
        from tenuo.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="authorized_updates"):
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                trusted_roots=_TEMPORAL_TRUST_ROOTS,
                authorized_updates=[],
            )


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
        """TemporalConstraintViolation has informative str."""
        exc = TemporalConstraintViolation(
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


class TestTenuoPlugin:
    """Tests for TenuoWorkerInterceptor."""

    def test_creates_activity_interceptor(self):
        """Creates activity inbound interceptor."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS)
        interceptor = TenuoWorkerInterceptor(config)

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


# =============================================================================
# Phase 2: Config Tests
# =============================================================================


class TestPhase2Config:
    """Tests for Phase 2 config options."""

    def test_default_phase2_values(self):
        """Phase 2 config has sensible defaults."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS)

        assert config.block_local_activities is True  # Secure by default

    def test_pop_is_always_mandatory(self):
        """PoP is always mandatory — no config toggle exists."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS)

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

        from tenuo.temporal._resolvers import CompositeKeyResolver

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

        from tenuo.temporal._resolvers import CompositeKeyResolver

        resolver1 = MagicMock(spec=KeyResolver)
        resolver1.resolve = AsyncMock(side_effect=KeyResolutionError("key1"))

        resolver2 = MagicMock(spec=KeyResolver)
        resolver2.resolve = AsyncMock(side_effect=KeyResolutionError("key1"))

        composite = CompositeKeyResolver([resolver1, resolver2])

        with pytest.raises(KeyResolutionError):
            asyncio.run(composite.resolve("key1"))

    def test_requires_at_least_one_resolver(self):
        """CompositeKeyResolver requires at least one resolver."""
        from tenuo.temporal._resolvers import CompositeKeyResolver

        with pytest.raises(ValueError):
            CompositeKeyResolver([])


class TestAWSSecretsManagerKeyResolver:
    """Tests for AWSSecretsManagerKeyResolver."""

    def test_resolves_binary_secret(self):
        """AWSSecretsManagerKeyResolver handles binary secrets."""
        import asyncio
        import sys
        from unittest.mock import patch

        from tenuo.temporal._resolvers import AWSSecretsManagerKeyResolver

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

        from tenuo.temporal._resolvers import AWSSecretsManagerKeyResolver

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

        from tenuo.temporal._resolvers import AWSSecretsManagerKeyResolver

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

        from tenuo.temporal._resolvers import AWSSecretsManagerKeyResolver
        from tenuo.temporal.exceptions import KeyResolutionError

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

        from tenuo.temporal._resolvers import GCPSecretManagerKeyResolver

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

        from tenuo.temporal._resolvers import GCPSecretManagerKeyResolver

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

        from tenuo.temporal._resolvers import GCPSecretManagerKeyResolver

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
        from tenuo.temporal._observability import TenuoMetrics

        metrics = TenuoMetrics(prefix="test")
        metrics.record_authorized("read_file", "MyWorkflow", 0.005)

        stats = metrics.get_stats()
        assert "read_file:MyWorkflow" in stats["authorized"]
        assert stats["authorized"]["read_file:MyWorkflow"] == 1
        assert stats["latency_count"] == 1

    def test_records_denied(self):
        """TenuoMetrics records denied activities."""
        from tenuo.temporal._observability import TenuoMetrics

        metrics = TenuoMetrics(prefix="test")
        metrics.record_denied("write_file", "expired", "MyWorkflow", 0.003)

        stats = metrics.get_stats()
        assert "write_file:expired:MyWorkflow" in stats["denied"]
        assert stats["denied"]["write_file:expired:MyWorkflow"] == 1

    def test_calculates_average_latency(self):
        """TenuoMetrics calculates average latency."""
        from tenuo.temporal._observability import TenuoMetrics

        metrics = TenuoMetrics(prefix="test")
        metrics.record_authorized("read_file", "MyWorkflow", 0.010)
        metrics.record_authorized("read_file", "MyWorkflow", 0.020)

        stats = metrics.get_stats()
        assert stats["latency_avg"] == pytest.approx(0.015, rel=0.01)

    def test_latency_ring_is_bounded(self):
        """Internal latency ring must not grow without bound.

        Regression: ``_latencies`` was a plain list, leaking memory in
        long-lived workers. Prometheus histograms remain the real store.
        """
        from tenuo.temporal._observability import TenuoMetrics

        metrics = TenuoMetrics(prefix="test_bounded")
        cap = TenuoMetrics._LATENCY_RING_SIZE
        for i in range(cap * 3):
            metrics.record_authorized(
                tool="read_file", workflow_type="W", latency_seconds=float(i)
            )
        assert len(metrics._latencies) == cap
        assert metrics.get_stats()["latency_count"] == cap


class TestPhase4Config:
    """Tests for Phase 4 config options."""

    def test_default_phase4_values(self):
        """Phase 4 config defaults are sensible."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS)

        assert config.metrics is None

    def test_can_enable_metrics(self):
        """Can enable metrics in config."""
        from tenuo.temporal._observability import TenuoMetrics

        resolver = MagicMock(spec=KeyResolver)
        metrics = TenuoMetrics(prefix="test")
        config = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            metrics=metrics,
        )

        assert config.metrics is metrics

class TestSecurityConfig:
    """Tests for security hardening config options."""

    def test_require_warrant_defaults_to_true(self):
        """require_warrant defaults to True (fail-closed)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS)

        assert config.require_warrant is True

    def test_can_disable_require_warrant(self):
        """Can disable require_warrant for opt-in mode."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            require_warrant=False,
        )

        assert config.require_warrant is False

    def test_redact_args_defaults_to_true(self):
        """redact_args_in_logs defaults to True (secure by default)."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=_TEMPORAL_TRUST_ROOTS)

        assert config.redact_args_in_logs is True

    def test_can_disable_redact_args(self):
        """Can disable arg redaction for debugging."""
        resolver = MagicMock(spec=KeyResolver)
        config = TenuoPluginConfig(
            key_resolver=resolver,
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            redact_args_in_logs=False,
        )

        assert config.redact_args_in_logs is False


# =============================================================================
# Key Resolver Cache & Failure Tests
# =============================================================================


class TestVaultKeyResolverCache:
    """Tests for VaultKeyResolver cache thread safety and failure paths."""

    def test_cache_returns_cached_key_within_ttl(self):
        """Cached key is returned without Vault fetch when within TTL."""
        import time

        from tenuo.temporal._resolvers import VaultKeyResolver

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

        from tenuo.temporal._resolvers import VaultKeyResolver

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
        from tenuo.temporal.exceptions import KeyResolutionError
        from tenuo.temporal._resolvers import VaultKeyResolver

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

        from tenuo.temporal._resolvers import VaultKeyResolver

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
        from tenuo.temporal._state import _DEDUP_MAX_SIZE
        assert _DEDUP_MAX_SIZE > 0
        assert _DEDUP_MAX_SIZE <= 100_000

    def test_dedup_cache_can_be_filled_and_cleared(self):
        """Basic smoke test: cache supports dict operations."""
        import time

        from tenuo.temporal._dedup import _pop_dedup_cache

        _pop_dedup_cache.clear()

        now = time.time()
        for i in range(100):
            _pop_dedup_cache[f"nonce-{i}"] = now

        assert len(_pop_dedup_cache) == 100
        _pop_dedup_cache.clear()
        assert len(_pop_dedup_cache) == 0


class TestPopDedupStoreHook:
    """Optional PopDedupStore on TenuoPluginConfig."""

    def test_config_rejects_trusted_roots_and_provider_together(self):
        from tenuo import SigningKey
        from tenuo.exceptions import ConfigurationError

        ck = SigningKey.generate()
        with pytest.raises(ConfigurationError, match="trusted_roots_provider"):
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                trusted_roots=[ck.public_key],
                trusted_roots_provider=lambda: [ck.public_key],
            )

    def test_config_requires_interval_with_provider_for_refresh(self):
        from tenuo.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="trusted_roots_provider"):
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                trusted_roots_refresh_interval_secs=30.0,
            )

    def test_custom_pop_dedup_store_used_by_interceptor(self):
        import time

        from tenuo import SigningKey, Warrant
        from tenuo_core import Subpath

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/demo"))
            .ttl(3600)
            .mint(control_key)
        )
        h = tenuo_headers(warrant, "agent1")

        class RecordingDedup:
            def __init__(self) -> None:
                self.calls = []

            def check_pop_replay(self, dedup_key, now, ttl_seconds, *, activity_name):
                self.calls.append((dedup_key, now, ttl_seconds))

        dedup = RecordingDedup()
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            pop_dedup_store=dedup,
        )
        ti = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        pop = warrant.sign(
            agent_key, "read_file", {"path": "/tmp/demo"}, int(time.time())
        )
        act_headers = {}
        for k, v in h.items():
            raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                act_headers[k] = raw_v
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        payload_headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        info = MagicMock()
        info.activity_type = "read_file"
        info.activity_id = "1"
        info.workflow_id = "wf-dedup-hook"
        info.workflow_run_id = "run-1"
        info.workflow_type = "W"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = lambda path: path
        inp.args = ("/tmp/demo",)
        inp.headers = payload_headers

        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        assert len(dedup.calls) == 1
        assert "wf-dedup-hook" in dedup.calls[0][0]


# =============================================================================
# Item 0.2 — PoP signing failure non-retryable test
# =============================================================================


def test_pop_signing_error_is_non_retryable():
    """PoP signing failures must be non-retryable to prevent infinite Temporal retries."""
    from tenuo.temporal._interceptors import _raise_non_retryable
    from tenuo.temporal.exceptions import TenuoContextError
    try:
        from temporalio.exceptions import ApplicationError
    except ImportError:
        pytest.skip("temporalio not installed")

    with pytest.raises(ApplicationError) as exc_info:
        _raise_non_retryable(TenuoContextError("key resolution failed"))

    assert exc_info.value.non_retryable is True


def test_workflow_constraint_violation_is_non_retryable():
    """TemporalConstraintViolation in workflow context must be non-retryable.

    Without this, misconfigured delegation chains (e.g. delegating a tool the
    parent doesn't have) cause the workflow to hang forever because Temporal
    retries the workflow task indefinitely.
    """
    from tenuo.temporal._workflow import _fail_workflow_non_retryable
    from tenuo.temporal.exceptions import TemporalConstraintViolation
    try:
        from temporalio.exceptions import ApplicationError
    except ImportError:
        pytest.skip("temporalio not installed")

    violation = TemporalConstraintViolation(
        tool="nonexistent_tool",
        arguments={},
        constraint="Cannot delegate tools not in parent: {'nonexistent_tool'}",
        warrant_id="wrt_test123",
    )
    wrapped = _fail_workflow_non_retryable(violation)
    assert isinstance(wrapped, ApplicationError)
    assert wrapped.non_retryable is True
    assert "nonexistent_tool" in str(wrapped)
    # Wire contract: ``type`` is the Tenuo ``error_code`` (stable across
    # activity and workflow contexts), not the Python class name.
    assert wrapped.type == TemporalConstraintViolation.error_code
    # Cause is preserved so Temporal's traceback points back at the Tenuo
    # violation, not at the wrapper itself.
    assert wrapped.__cause__ is violation


def test_resolve_client_interceptor_auto_discovers():
    """_resolve_client_interceptor finds TenuoClientInterceptor from client config."""
    from tenuo.temporal._workflow import _resolve_client_interceptor
    from tenuo.temporal._client import TenuoClientInterceptor

    interceptor = TenuoClientInterceptor()

    class FakeClient:
        def config(self, *, active_config=False):
            return {"interceptors": [interceptor]}

    result = _resolve_client_interceptor(FakeClient(), None)
    assert result is interceptor


def test_resolve_client_interceptor_explicit_takes_precedence():
    """Explicit client_interceptor is returned without introspection."""
    from tenuo.temporal._workflow import _resolve_client_interceptor
    from tenuo.temporal._client import TenuoClientInterceptor

    explicit = TenuoClientInterceptor()
    auto = TenuoClientInterceptor()

    class FakeClient:
        def config(self, *, active_config=False):
            return {"interceptors": [auto]}

    result = _resolve_client_interceptor(FakeClient(), explicit)
    assert result is explicit


def test_resolve_client_interceptor_raises_if_not_found():
    """Clear error when no TenuoClientInterceptor is available."""
    from tenuo.temporal._workflow import _resolve_client_interceptor
    from tenuo.temporal.exceptions import TenuoContextError

    class FakeClient:
        def config(self, *, active_config=False):
            return {"interceptors": []}

    with pytest.raises(TenuoContextError, match="No TenuoClientInterceptor found"):
        _resolve_client_interceptor(FakeClient(), None)


# =============================================================================
# Item 1.4 — OpenTelemetry tracing auto-on
# =============================================================================


def test_otel_import_check():
    """OTel tracing module-level flag is always a bool (soft dependency)."""
    from tenuo.temporal._interceptors import _otel_available

    assert isinstance(_otel_available, bool)


def test_otel_span_emitted_on_allow():
    """Verify Tenuo emits a 'tenuo.authorize' OTel span with allow decision on success."""
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from tenuo import SigningKey, Warrant
    from tenuo_core import Subpath
    from tenuo.temporal._constants import TENUO_POP_HEADER
    from tenuo.temporal._interceptors import TenuoWorkerInterceptor
    from tenuo.temporal._config import TenuoPluginConfig
    from tenuo.temporal._resolvers import EnvKeyResolver
    from tenuo.temporal._headers import tenuo_headers

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    # Patch the module-level _otel_trace so the inbound interceptor uses our
    # test provider. The global set_tracer_provider() is blocked by OTel's
    # "Overriding of current TracerProvider is not allowed" guard.
    test_trace = type("_FakeTrace", (), {
        "get_tracer": lambda self, name: provider.get_tracer(name),
        "get_current_span": staticmethod(
            __import__("opentelemetry").trace.get_current_span
        ),
        "Status": __import__("opentelemetry").trace.Status,
        "StatusCode": __import__("opentelemetry").trace.StatusCode,
    })()

    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/tmp/demo"))
        .ttl(3600)
        .mint(control_key)
    )
    h = tenuo_headers(warrant, "agent1")

    cfg = TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[control_key.public_key],
    )
    ti = TenuoWorkerInterceptor(cfg)
    nxt = MagicMock()
    nxt.execute_activity = AsyncMock(return_value="ok")
    nxt.init = MagicMock()
    ai = ti.intercept_activity(nxt)

    import time as _time
    pop = warrant.sign(
        agent_key, "read_file", {"path": "/tmp/demo"}, int(_time.time())
    )

    act_headers = {}
    for k, v in h.items():
        raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
        if k.startswith("x-tenuo-"):
            act_headers[k] = raw_v
    act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

    class FakePayload:
        def __init__(self, data):
            self.data = data

    payload_headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

    info = MagicMock()
    info.activity_type = "read_file"
    info.activity_id = "act-otel-1"
    info.workflow_id = "wf-otel-allow"
    info.workflow_run_id = "run-otel-1"
    info.workflow_type = "OtelWorkflow"
    info.attempt = 1
    info.is_local = False

    inp = MagicMock()
    inp.fn = lambda path: path
    inp.args = ("/tmp/demo",)
    inp.headers = payload_headers

    loop = asyncio.new_event_loop()
    try:
        with patch("tenuo.temporal._interceptors._otel_trace", test_trace), \
             patch("temporalio.activity.info", return_value=info):
            loop.run_until_complete(ai.execute_activity(inp))
    finally:
        loop.close()

    finished = exporter.get_finished_spans()
    tenuo_spans = [s for s in finished if s.name == "tenuo.authorize"]
    assert len(tenuo_spans) >= 1, (
        f"Expected tenuo.authorize span, got: {[s.name for s in finished]}"
    )
    span = tenuo_spans[0]
    attrs = dict(span.attributes or {})
    assert attrs.get("tenuo.tool") == "read_file"
    assert attrs.get("tenuo.decision") == "allow"
    assert "tenuo.warrant_id" in attrs
    assert "tenuo.constraint_violated" in attrs


# =============================================================================
# Phase 1.1 — TenuoWarrantContextPropagator + tenuo_warrant_context
# =============================================================================


def test_tenuo_warrant_context_manager_exists():
    from tenuo.temporal._client import tenuo_warrant_context, TenuoWarrantContextPropagator

    assert tenuo_warrant_context is not None
    assert TenuoWarrantContextPropagator is not None


def test_context_propagator_sets_and_clears():
    from tenuo.temporal._client import TenuoWarrantContextPropagator

    prop = TenuoWarrantContextPropagator()
    assert prop.get() is None
    # Mock a warrant
    mock_warrant = object()
    token = prop.set(mock_warrant, "key1")
    assert prop.get() == (mock_warrant, "key1")
    prop.clear(token)
    assert prop.get() is None


# =============================================================================
# Phase 1.7 — WarrantSource abstraction + implementations
# =============================================================================


def test_literal_warrant_source_wraps_warrant():
    from tenuo.temporal._warrant_source import LiteralWarrantSource
    import inspect
    source = LiteralWarrantSource(object(), "k1")
    assert inspect.iscoroutinefunction(source.resolve)


def test_env_warrant_source_missing_var():
    import os
    from tenuo.temporal._warrant_source import EnvWarrantSource
    from tenuo.temporal.exceptions import TenuoContextError
    os.environ.pop("TENUO_TEST_WARRANT_MISSING", None)
    source = EnvWarrantSource("TENUO_TEST_WARRANT_MISSING", "k1")
    with pytest.raises(TenuoContextError, match="is not set"):
        asyncio.run(source.resolve())


def test_warrant_source_and_literal_mutually_exclusive():
    """Passing both warrant= and warrant_source= to execute_workflow_authorized must raise."""
    from tenuo.temporal._workflow import execute_workflow_authorized
    import inspect
    sig = inspect.signature(execute_workflow_authorized)
    assert "warrant_source" in sig.parameters, "warrant_source kwarg must be present"


def test_cloud_trigger_warrant_source_importable():
    from tenuo.temporal._warrant_source import CloudTriggerWarrantSource
    source = CloudTriggerWarrantSource(
        base_url="https://example.com",
        trigger_id="trig_123",
        api_key="key",
        key_id="agent1",
    )
    import inspect
    assert inspect.iscoroutinefunction(source.resolve)


def test_cloud_trigger_warrant_source_uses_event_mapper():
    from tenuo.temporal._warrant_source import CloudTriggerWarrantSource
    events_captured = []

    def mapper(patient_id, *a, **kw):
        events_captured.append(patient_id)
        return {"patient_id": patient_id}

    source = CloudTriggerWarrantSource(
        base_url="https://example.com",
        trigger_id="trig_123",
        api_key="key",
        key_id="agent1",
        event_mapper=mapper,
    )
    # We can't call resolve() without an httpx mock, but verify event_mapper is stored
    assert source._event_mapper is mapper


# =============================================================================
# Item 3.4 — Dynamic activity per-name tool resolution
# =============================================================================


def test_dynamic_activity_falls_back_to_runtime_name():
    """When fn resolution fails, fall back to input.activity for dynamic activities."""
    from tenuo.temporal._decorators import _warrant_tool_name_for_activity_type

    class MockInput:
        fn = None  # no function reference (dynamic handler)
        activity = "SomeDynamicTool"  # runtime name
        headers = {}

    class MockConfig:
        activity_fns: list = []
        tool_mappings: dict = {}
        _activity_registry: dict = {}

    result = _warrant_tool_name_for_activity_type(MockInput(), MockConfig())
    assert result == "SomeDynamicTool"


def test_dynamic_activity_legacy_call_unchanged():
    """Legacy 3-arg call still works: (config, activity_type, activity_fn)."""
    from tenuo.temporal._decorators import _warrant_tool_name_for_activity_type

    class MockConfig:
        tool_mappings: dict = {}

    result = _warrant_tool_name_for_activity_type(MockConfig(), "MyActivity", None)
    assert result == "MyActivity"


def test_dynamic_activity_legacy_call_with_tool_mapping():
    """tool_mappings override still applies in legacy call."""
    from tenuo.temporal._decorators import _warrant_tool_name_for_activity_type

    class MockConfig:
        tool_mappings = {"MyActivity": "mapped_tool"}

    result = _warrant_tool_name_for_activity_type(MockConfig(), "MyActivity", None)
    assert result == "mapped_tool"


# =============================================================================
# Item 3.5 — Continue-as-new attenuation
# =============================================================================


def test_tenuo_continue_as_new_exists():
    from tenuo.temporal._workflow import tenuo_continue_as_new

    assert tenuo_continue_as_new is not None
    assert callable(tenuo_continue_as_new)


def test_tenuo_continue_as_new_has_attenuation_kwarg():
    from tenuo.temporal._workflow import tenuo_continue_as_new
    import inspect

    sig = inspect.signature(tenuo_continue_as_new)
    assert "tenuo_attenuation" in sig.parameters


def test_tenuo_continue_as_new_in_all():
    from tenuo.temporal._workflow import tenuo_continue_as_new

    assert callable(tenuo_continue_as_new)


def test_create_scheduled_workflow_with_warrant_exists():
    """Verify the scheduled workflow helper is exported."""
    from tenuo.temporal._workflow import create_scheduled_workflow_with_warrant
    import inspect
    assert inspect.iscoroutinefunction(create_scheduled_workflow_with_warrant)


# =============================================================================
# tenuo_complete_async_activity
# =============================================================================


def test_tenuo_complete_async_activity_exists():
    """Verify the async activity completion wrapper is exported."""
    from tenuo.temporal._workflow import tenuo_complete_async_activity
    import inspect
    assert inspect.iscoroutinefunction(tenuo_complete_async_activity)


# =============================================================================
# set_activity_approvals
# =============================================================================


class TestSetActivityApprovals:
    """Tests for the set_activity_approvals workflow helper."""

    def _call_with_mock_wf(self, wf_id, approvals):
        """Call set_activity_approvals while mocking temporalio.workflow.info.

        The internal stores are keyed by ``run_id``; we set both
        ``workflow_id`` and ``run_id`` to the test-supplied string so
        existing assertions that look up ``_pending_activity_approvals[wf_id]``
        continue to function (the string is opaque — the test just needs
        a stable key).
        """
        from tenuo.temporal._workflow import set_activity_approvals

        fake_info = MagicMock()
        fake_info.workflow_id = wf_id
        fake_info.run_id = wf_id

        with patch("temporalio.workflow.info", return_value=fake_info):
            set_activity_approvals(approvals)

    def test_stores_approvals_in_pending_map(self):
        """Approvals are stashed in _pending_activity_approvals keyed by workflow_id."""
        from tenuo.temporal._state import _pending_activity_approvals, _store_lock

        sentinel_a = MagicMock(name="approval_a")
        sentinel_b = MagicMock(name="approval_b")
        self._call_with_mock_wf("wf-approvals-test", [sentinel_a, sentinel_b])

        with _store_lock:
            stored = _pending_activity_approvals.get("wf-approvals-test")

        assert stored is not None
        assert len(stored) == 2
        assert stored[0] is sentinel_a
        assert stored[1] is sentinel_b

        with _store_lock:
            _pending_activity_approvals.pop("wf-approvals-test", None)

    def test_copies_list_defensively(self):
        """set_activity_approvals makes a copy so later mutations don't affect state."""
        from tenuo.temporal._state import _pending_activity_approvals, _store_lock

        original = [MagicMock(name="a1")]
        self._call_with_mock_wf("wf-defensive-copy", original)

        original.append(MagicMock(name="a2"))

        with _store_lock:
            stored = _pending_activity_approvals.get("wf-defensive-copy")

        assert len(stored) == 1

        with _store_lock:
            _pending_activity_approvals.pop("wf-defensive-copy", None)

    def test_overwrites_previous_approvals(self):
        """A second call replaces (not appends to) the stored approvals."""
        from tenuo.temporal._state import _pending_activity_approvals, _store_lock

        self._call_with_mock_wf("wf-overwrite", [MagicMock(name="first")])
        self._call_with_mock_wf("wf-overwrite", [MagicMock(name="second"), MagicMock(name="third")])

        with _store_lock:
            stored = _pending_activity_approvals.get("wf-overwrite")

        assert len(stored) == 2

        with _store_lock:
            _pending_activity_approvals.pop("wf-overwrite", None)

    def test_empty_list_clears_approvals(self):
        """Passing an empty list stores an empty list (no-op on next dispatch)."""
        from tenuo.temporal._state import _pending_activity_approvals, _store_lock

        self._call_with_mock_wf("wf-empty", [MagicMock(name="something")])
        self._call_with_mock_wf("wf-empty", [])

        with _store_lock:
            stored = _pending_activity_approvals.get("wf-empty")

        assert stored == []

        with _store_lock:
            _pending_activity_approvals.pop("wf-empty", None)

    def test_consumed_by_outbound_interceptor(self):
        """Approvals stored by set_activity_approvals are popped by the outbound interceptor."""
        from tenuo.temporal._state import _pending_activity_approvals, _store_lock

        wf_id = "wf-consume-test"
        sentinel = MagicMock(name="approval")

        with _store_lock:
            _pending_activity_approvals[wf_id] = [sentinel]

        with _store_lock:
            consumed = _pending_activity_approvals.pop(wf_id, None)

        assert consumed is not None
        assert consumed[0] is sentinel

        with _store_lock:
            assert wf_id not in _pending_activity_approvals


# =============================================================================
# Constraint-type coverage: UrlSafe, Wildcard
# =============================================================================


class TestConstraintTypesThroughInterceptor:
    """End-to-end interceptor tests for constraint types beyond Subpath.

    Each test mints a warrant with the given constraint, creates a signed PoP,
    sends it through the activity interceptor, and asserts allow/deny.

    Shlex is a Python-only constraint and cannot be embedded in warrants, so it
    is not covered here.
    """

    @staticmethod
    def _build_interceptor_and_run(
        *,
        control_key,
        agent_key,
        warrant,
        activity_name: str,
        activity_args: dict,
    ):
        """Wire up the full interceptor stack and execute a single activity.

        Returns the result from the next interceptor (i.e. "ok" on success).
        Raises on authorization failure.
        """
        import time as _time

        from tenuo.temporal._constants import TENUO_POP_HEADER, TENUO_ARG_KEYS_HEADER
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._resolvers import EnvKeyResolver
        from tenuo.temporal._headers import tenuo_headers

        h = tenuo_headers(warrant, "agent1")

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        pop = warrant.sign(
            agent_key,
            activity_name,
            activity_args,
            int(_time.time()),
        )

        act_headers: dict = {}
        for k, v in h.items():
            raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                act_headers[k] = raw_v
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        act_headers[TENUO_ARG_KEYS_HEADER] = ",".join(activity_args.keys()).encode()

        class FakePayload:
            def __init__(self, data):
                self.data = data

        payload_headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        info = MagicMock()
        info.activity_type = activity_name
        info.activity_id = "1"
        info.workflow_id = "wf-constraint-test"
        info.workflow_run_id = "run-1"
        info.workflow_type = "TestWorkflow"
        info.task_queue = "test-q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = tuple(activity_args.values())
        inp.headers = payload_headers

        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                return loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

    # -- Wildcard --------------------------------------------------------

    def test_wildcard_allows_any_value(self):
        """A Wildcard() constraint allows any string value."""
        from tenuo import SigningKey, Warrant
        from tenuo_core import Wildcard

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("search", query=Wildcard())
            .ttl(3600)
            .mint(control_key)
        )

        result = self._build_interceptor_and_run(
            control_key=control_key,
            agent_key=agent_key,
            warrant=warrant,
            activity_name="search",
            activity_args={"query": "anything at all"},
        )
        assert result == "ok"

    def test_wildcard_allows_empty_string(self):
        """Wildcard() also accepts the empty string."""
        from tenuo import SigningKey, Warrant
        from tenuo_core import Wildcard

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("search", query=Wildcard())
            .ttl(3600)
            .mint(control_key)
        )

        result = self._build_interceptor_and_run(
            control_key=control_key,
            agent_key=agent_key,
            warrant=warrant,
            activity_name="search",
            activity_args={"query": ""},
        )
        assert result == "ok"

    # -- UrlSafe ---------------------------------------------------------

    def test_urlsafe_allows_matching_url(self):
        """UrlSafe constraint allows a URL that matches allowed domains/schemes."""
        from tenuo import SigningKey, Warrant
        from tenuo_core import UrlSafe

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability(
                "fetch_url",
                url=UrlSafe(
                    allow_schemes=["https"],
                    allow_domains=["api.example.com"],
                    block_private=True,
                ),
            )
            .ttl(3600)
            .mint(control_key)
        )

        result = self._build_interceptor_and_run(
            control_key=control_key,
            agent_key=agent_key,
            warrant=warrant,
            activity_name="fetch_url",
            activity_args={"url": "https://api.example.com/v1/data"},
        )
        assert result == "ok"

    def test_urlsafe_denies_wrong_domain(self):
        """UrlSafe constraint denies a URL with a non-allowed domain."""
        from tenuo import SigningKey, Warrant
        from tenuo_core import UrlSafe

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability(
                "fetch_url",
                url=UrlSafe(
                    allow_schemes=["https"],
                    allow_domains=["api.example.com"],
                    block_private=True,
                ),
            )
            .ttl(3600)
            .mint(control_key)
        )

        with pytest.raises(Exception):
            self._build_interceptor_and_run(
                control_key=control_key,
                agent_key=agent_key,
                warrant=warrant,
                activity_name="fetch_url",
                activity_args={"url": "https://evil.com/steal"},
            )

    def test_urlsafe_denies_http_scheme(self):
        """UrlSafe rejects http:// when only https:// is allowed."""
        from tenuo import SigningKey, Warrant
        from tenuo_core import UrlSafe

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability(
                "fetch_url",
                url=UrlSafe(
                    allow_schemes=["https"],
                    allow_domains=["api.example.com"],
                    block_private=True,
                ),
            )
            .ttl(3600)
            .mint(control_key)
        )

        with pytest.raises(Exception):
            self._build_interceptor_and_run(
                control_key=control_key,
                agent_key=agent_key,
                warrant=warrant,
                activity_name="fetch_url",
                activity_args={"url": "http://api.example.com/v1/data"},
            )

    # -- Wildcard + UrlSafe combined capability --------------------------

    def test_combined_wildcard_and_urlsafe_capability(self):
        """A capability with mixed constraint types works end-to-end."""
        from tenuo import SigningKey, Warrant
        from tenuo_core import UrlSafe, Wildcard

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability(
                "web_search",
                query=Wildcard(),
                endpoint=UrlSafe(
                    allow_schemes=["https"],
                    allow_domains=["search.example.com"],
                    block_private=True,
                ),
            )
            .ttl(3600)
            .mint(control_key)
        )

        result = self._build_interceptor_and_run(
            control_key=control_key,
            agent_key=agent_key,
            warrant=warrant,
            activity_name="web_search",
            activity_args={
                "query": "temporal workflow best practices",
                "endpoint": "https://search.example.com/api",
            },
        )
        assert result == "ok"


# =============================================================================
# Workflow inbound interceptor: signal/update denial warrant-id resolution
# =============================================================================


class TestWorkflowInboundWarrantId:
    """Verify signal/update denial events carry the real warrant id.

    Regression: the inbound workflow interceptor used to hard-code
    ``warrant_id="workflow"`` on ``TemporalConstraintViolation`` and its
    logger.warning calls, destroying audit correlation.
    """

    def _make_inbound(self):
        from tenuo.temporal._interceptors import _TenuoWorkflowInboundInterceptor

        return _TenuoWorkflowInboundInterceptor(next_interceptor=MagicMock())

    def test_resolve_warrant_id_returns_real_id_from_headers(self):
        """``_resolve_warrant_id`` decodes the stored warrant and returns its id."""
        from tenuo import SigningKey
        from tenuo_core import Warrant  # type: ignore[import-not-found]
        from tenuo.temporal._interceptors import _store_lock, _workflow_headers_store

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

        inbound = self._make_inbound()
        wf_id = "wf-warrant-id-regression"
        headers = tenuo_headers(warrant, "agent1")
        stored = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in headers.items()
        }
        try:
            with _store_lock:
                _workflow_headers_store[wf_id] = stored
            fake_info = MagicMock()
            fake_info.workflow_id = wf_id
            fake_info.run_id = wf_id
            with patch("temporalio.workflow.info", return_value=fake_info):
                resolved = inbound._resolve_warrant_id()
        finally:
            with _store_lock:
                _workflow_headers_store.pop(wf_id, None)

        assert resolved == expected_id
        assert resolved != "workflow"

    def test_resolve_warrant_id_returns_sentinel_when_no_headers(self):
        """No stored headers → explicit ``<no-warrant>`` sentinel."""
        inbound = self._make_inbound()
        fake_info = MagicMock()
        fake_info.workflow_id = "wf-missing-headers"
        fake_info.run_id = "wf-missing-headers"
        with patch("temporalio.workflow.info", return_value=fake_info):
            assert inbound._resolve_warrant_id() == "<no-warrant>"

    def test_resolve_warrant_id_returns_sentinel_on_malformed_header(self):
        """Malformed warrant bytes → distinct sentinel, never raises."""
        from tenuo.temporal._interceptors import _store_lock, _workflow_headers_store

        inbound = self._make_inbound()
        wf_id = "wf-malformed-warrant"
        try:
            with _store_lock:
                _workflow_headers_store[wf_id] = {
                    TENUO_WARRANT_HEADER: b"not-a-valid-cbor-warrant",
                    TENUO_COMPRESSED_HEADER: b"0",
                }
            fake_info = MagicMock()
            fake_info.workflow_id = wf_id
            fake_info.run_id = wf_id
            with patch("temporalio.workflow.info", return_value=fake_info):
                resolved = inbound._resolve_warrant_id()
        finally:
            with _store_lock:
                _workflow_headers_store.pop(wf_id, None)

        assert resolved == "<undecodable-warrant>"


# =============================================================================
# Approval gates (warrant-gated activities)
# =============================================================================


class TestApprovalGates:
    """End-to-end coverage for approval-gated activities through the interceptor.

    ``_resolve_approval_gate_approvals`` has three paths:

    * ``x-tenuo-approvals`` header present → decode + verify.
    * ``approval_handler`` on the config → invoke handler + verify.
    * Neither → raise ``ApprovalGateTriggered``.

    Prior to this PR only the "nothing available" path had coverage.
    """

    @staticmethod
    def _mint_gated_warrant(control_key, holder_key, *, approver_key):
        from tenuo import Warrant

        return (
            Warrant.mint_builder()
            .holder(holder_key.public_key)
            .capability("deploy")
            .required_approvers([approver_key.public_key])
            .min_approvals(1)
            .approval_gates({"deploy": None})
            .ttl(3600)
            .mint(control_key)
        )

    @staticmethod
    def _sign_approval(warrant, approver_key, tool, args):
        import time as _time

        import tenuo_core

        now = int(_time.time())
        request_hash = tenuo_core.py_compute_request_hash(
            warrant.id, tool, args, warrant.holder_key,
        )
        payload = tenuo_core.ApprovalPayload(
            request_hash=request_hash,
            nonce=bytes(range(16)),
            external_id="admin@test.com",
            approved_at=now,
            expires_at=now + 300,
        )
        return tenuo_core.SignedApproval.create(payload, approver_key)

    @staticmethod
    def _build_activity_inputs(warrant, pop_bytes, approvals_header=None):
        from tenuo.temporal._constants import (
            TENUO_APPROVALS_HEADER,
            TENUO_ARG_KEYS_HEADER,
            TENUO_POP_HEADER,
        )
        from tenuo.temporal._headers import tenuo_headers

        h = tenuo_headers(warrant, "agent1")
        act_headers: dict = {}
        for k, v in h.items():
            raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                act_headers[k] = raw_v
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop_bytes))
        act_headers[TENUO_ARG_KEYS_HEADER] = b""
        if approvals_header is not None:
            act_headers[TENUO_APPROVALS_HEADER] = approvals_header

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "deploy"
        info.activity_id = "1"
        info.workflow_id = "wf-approval-test"
        info.workflow_run_id = "run-1"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = lambda: None
        inp.args = ()
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}
        return info, inp

    def _run(self, plugin, info, inp):
        ai = plugin.intercept_activity(MagicMock(
            execute_activity=AsyncMock(return_value="ok"),
            init=MagicMock(),
        ))
        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                return loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

    def test_approval_handler_happy_path_allows_gated_activity(self):
        """A warrant-gated tool succeeds when ``approval_handler`` returns a valid
        signed approval from one of the warrant's required approvers.
        """
        import time as _time

        from tenuo import SigningKey

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        approver_key = SigningKey.generate()

        warrant = self._mint_gated_warrant(
            control_key, agent_key, approver_key=approver_key,
        )
        signed = self._sign_approval(warrant, approver_key, "deploy", {})
        pop = warrant.sign(agent_key, "deploy", {}, int(_time.time()))

        captured: dict = {}

        def handler(request):
            captured["tool"] = request.tool
            captured["warrant_id"] = request.warrant_id
            return signed

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            approval_handler=handler,
        )
        plugin = TenuoWorkerInterceptor(cfg)
        info, inp = self._build_activity_inputs(warrant, pop)

        result = self._run(plugin, info, inp)

        assert result == "ok"
        assert captured["tool"] == "deploy"
        assert captured["warrant_id"] == warrant.id

    def test_approvals_header_happy_path_allows_gated_activity(self):
        """A warrant-gated tool succeeds when the client attaches valid signed
        approvals via the ``x-tenuo-approvals`` header (the path used by the
        outbound workflow interceptor when ``set_activity_approvals`` ran).
        """
        import json as _json
        import time as _time

        from tenuo import SigningKey

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        approver_key = SigningKey.generate()

        warrant = self._mint_gated_warrant(
            control_key, agent_key, approver_key=approver_key,
        )
        signed = self._sign_approval(warrant, approver_key, "deploy", {})
        pop = warrant.sign(agent_key, "deploy", {}, int(_time.time()))

        approvals_header = _json.dumps(
            [base64.b64encode(signed.to_bytes()).decode("ascii")]
        ).encode("utf-8")

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
        )
        plugin = TenuoWorkerInterceptor(cfg)
        info, inp = self._build_activity_inputs(
            warrant, pop, approvals_header=approvals_header,
        )

        result = self._run(plugin, info, inp)

        assert result == "ok"

    def test_missing_approvals_on_gated_warrant_raises_approval_gate(self):
        """Sanity: no handler and no header → ``ApprovalGateTriggered``."""
        import time as _time

        from tenuo import SigningKey
        from tenuo.exceptions import ApprovalGateTriggered

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        approver_key = SigningKey.generate()

        warrant = self._mint_gated_warrant(
            control_key, agent_key, approver_key=approver_key,
        )
        pop = warrant.sign(agent_key, "deploy", {}, int(_time.time()))

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
        )
        plugin = TenuoWorkerInterceptor(cfg)
        info, inp = self._build_activity_inputs(warrant, pop)

        with pytest.raises((ApprovalGateTriggered, Exception)) as exc_info:
            self._run(plugin, info, inp)
        # ApprovalGateTriggered may be wrapped in Temporal's ApplicationError.
        msg = str(exc_info.value)
        assert "approval" in msg.lower() or "gate" in msg.lower() or \
            isinstance(exc_info.value, ApprovalGateTriggered)


# =============================================================================
# block_local_activities
# =============================================================================


class TestBlockLocalActivities:
    """``block_local_activities=True`` (the default) denies protected local
    activities both on the outbound workflow path and the inbound activity path.
    """

    def _make_outbound(self, *, block=True):
        from tenuo.temporal._interceptors import _TenuoWorkflowOutboundInterceptor

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            block_local_activities=block,
        )
        nxt = MagicMock()
        nxt.start_local_activity = MagicMock(return_value="dispatched")
        return _TenuoWorkflowOutboundInterceptor(nxt, cfg), nxt

    def test_outbound_blocks_protected_local_activity(self):
        """A plain (protected) local activity must raise ``LocalActivityError``."""
        outbound, nxt = self._make_outbound()

        def my_activity(x):
            return x

        inp = MagicMock(fn=my_activity, activity="my_activity")

        with pytest.raises(LocalActivityError):
            outbound.start_local_activity(inp)
        nxt.start_local_activity.assert_not_called()

    def test_outbound_allows_unprotected_local_activity(self):
        """``@unprotected`` local activities must pass through untouched."""
        outbound, nxt = self._make_outbound()

        @unprotected
        def safe_activity(x):
            return x

        inp = MagicMock(fn=safe_activity, activity="safe_activity")

        assert outbound.start_local_activity(inp) == "dispatched"
        nxt.start_local_activity.assert_called_once_with(inp)

    def test_outbound_respects_block_local_activities_false(self):
        """With ``block_local_activities=False`` every local activity passes."""
        outbound, nxt = self._make_outbound(block=False)

        def my_activity(x):
            return x

        inp = MagicMock(fn=my_activity, activity="my_activity")

        assert outbound.start_local_activity(inp) == "dispatched"
        nxt.start_local_activity.assert_called_once_with(inp)

    def test_inbound_blocks_protected_local_activity(self):
        """The activity inbound interceptor also fails-closed when ``is_local=True``."""
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            block_local_activities=True,
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        def my_activity(x):
            return x

        info = MagicMock()
        info.activity_type = "my_activity"
        info.is_local = True
        info.attempt = 1

        inp = MagicMock(fn=my_activity, args=("x",), headers={})

        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                with pytest.raises(Exception):
                    loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        nxt.execute_activity.assert_not_called()


# =============================================================================
# Metrics wiring
# =============================================================================


class TestMetricsWiring:
    """Verify TenuoMetrics.record_authorized/record_denied are called."""

    def test_metrics_record_authorized_on_allow(self):
        """TenuoMetrics.record_authorized is invoked when an activity is allowed."""
        import time as _time

        from tenuo import SigningKey, Warrant
        from tenuo_core import Wildcard
        from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER, TENUO_POP_HEADER
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._resolvers import EnvKeyResolver
        from tenuo.temporal._headers import tenuo_headers
        from tenuo.temporal._observability import TenuoMetrics

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("ping", msg=Wildcard())
            .ttl(3600)
            .mint(control_key)
        )

        metrics = TenuoMetrics()
        h = tenuo_headers(warrant, "agent1")
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            metrics=metrics,
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        pop = warrant.sign(agent_key, "ping", {"msg": "hello"}, int(_time.time()))
        act_headers: dict = {}
        for k, v in h.items():
            raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                act_headers[k] = raw_v
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        act_headers[TENUO_ARG_KEYS_HEADER] = b"msg"

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "ping"
        info.activity_id = "1"
        info.workflow_id = "wf-metrics-test"
        info.workflow_run_id = "run-1"
        info.workflow_type = "MetricsWF"
        info.task_queue = "test-q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ("hello",)
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        stats = metrics.get_stats()
        assert stats["authorized"].get("ping:MetricsWF", 0) >= 1
        assert stats["latency_count"] >= 1

    def test_metrics_record_denied_on_constraint_violation(self):
        """TenuoMetrics.record_denied is invoked when an activity is denied."""
        import time as _time

        from tenuo import SigningKey, Warrant
        from tenuo_core import Subpath
        from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER, TENUO_POP_HEADER
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._resolvers import EnvKeyResolver
        from tenuo.temporal._headers import tenuo_headers
        from tenuo.temporal._observability import TenuoMetrics

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/safe"))
            .ttl(3600)
            .mint(control_key)
        )

        metrics = TenuoMetrics()
        h = tenuo_headers(warrant, "agent1")
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            metrics=metrics,
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        pop = warrant.sign(
            agent_key, "read_file", {"path": "/etc/passwd"}, int(_time.time())
        )
        act_headers: dict = {}
        for k, v in h.items():
            raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                act_headers[k] = raw_v
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        act_headers[TENUO_ARG_KEYS_HEADER] = b"path"

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "read_file"
        info.activity_id = "1"
        info.workflow_id = "wf-metrics-deny"
        info.workflow_run_id = "run-1"
        info.workflow_type = "MetricsDenyWF"
        info.task_queue = "test-q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ("/etc/passwd",)
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                with pytest.raises(Exception):
                    loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        stats = metrics.get_stats()
        assert stats["latency_count"] >= 1


# =============================================================================
# error_code on exception classes
# =============================================================================


class TestExceptionErrorCodes:
    """Verify every Temporal exception has an error_code attribute."""

    def test_all_exceptions_have_error_code(self):
        exc_classes = [
            TemporalConstraintViolation,
            PopVerificationError,
            ChainValidationError,
            WarrantExpired,
            KeyResolutionError,
            LocalActivityError,
        ]
        for cls in exc_classes:
            assert hasattr(cls, "error_code"), f"{cls.__name__} missing error_code"

    def test_context_error_has_error_code(self):
        from tenuo.temporal.exceptions import TenuoContextError
        assert TenuoContextError.error_code == "CONTEXT_MISSING"

    def test_arg_normalization_error_has_error_code(self):
        from tenuo.temporal.exceptions import TenuoArgNormalizationError
        assert TenuoArgNormalizationError.error_code == "ARG_NORMALIZATION_FAILED"

    def test_pre_validation_error_has_error_code(self):
        from tenuo.temporal.exceptions import TenuoPreValidationError
        assert TenuoPreValidationError.error_code == "PRE_VALIDATION_FAILED"


# =============================================================================
# Fourth deep-review fixes — non-retryable wrapping, audit durability,
# client TTL, signal/update runtime denial, dedup retry skip.
# =============================================================================


class TestNonRetryableWrapping:
    """Activity denials must surface as Temporal ``ApplicationError(non_retryable=True)``
    with ``type`` set to the Tenuo ``error_code`` so downstream consumers can
    branch on a stable wire code.
    """

    def test_application_error_type_uses_error_code(self):
        """The ``type=`` attribute on ``ApplicationError`` is the Tenuo
        ``error_code`` (``POP_VERIFICATION_FAILED``, not ``PopVerificationError``).
        """
        from temporalio.exceptions import ApplicationError

        from tenuo.temporal._interceptors import _error_type_for_wire

        exc = PopVerificationError(
            reason="malformed base64",
            activity_name="deploy",
        )
        assert _error_type_for_wire(exc) == "POP_VERIFICATION_FAILED"

        app = ApplicationError(
            str(exc), type=_error_type_for_wire(exc), non_retryable=True,
        )
        assert app.type == "POP_VERIFICATION_FAILED"
        assert app.non_retryable is True

    def test_error_type_falls_back_to_class_name(self):
        """Python exceptions without a ``error_code`` fall back to the class name."""
        from tenuo.temporal._interceptors import _error_type_for_wire

        assert _error_type_for_wire(ValueError("nope")) == "ValueError"

    def test_missing_authorizer_raises_non_retryable(self):
        """A config with no ``trusted_roots`` (and thus no ``Authorizer``) must
        reach the activity path as a **non-retryable** ``ApplicationError``.
        Otherwise Temporal retries the activity every attempt, hitting the
        same broken config every time.
        """
        import time as _time

        from temporalio.exceptions import ApplicationError

        from tenuo import SigningKey, Warrant
        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("noop")
            .ttl(3600)
            .mint(control_key)
        )
        pop = warrant.sign(agent_key, "noop", {}, int(_time.time()))

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
        )
        ai = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(),
            config=cfg,
            version="test",
        )
        # Simulate the "authorizer never got built" branch: a real warrant
        # reaches the interceptor, but the ``Authorizer`` is missing (e.g.
        # misconfigured worker). The path *past* ``require_warrant`` /
        # trusted-roots refresh must still fail closed, non-retryably.
        ai._authorizer = None

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "noop"
        info.activity_id = "1"
        info.workflow_id = "wf"
        info.workflow_run_id = "run"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ()
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                with pytest.raises(ApplicationError) as excinfo:
                    loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        assert excinfo.value.non_retryable is True
        assert "Authorizer" in str(excinfo.value)

    def test_generic_exception_in_auth_block_is_non_retryable(self):
        """An unexpected exception inside the auth try block (e.g. a custom
        ``PopDedupStore`` raising ``RuntimeError``) must be wrapped as
        non-retryable. Leaving it retryable causes Temporal to loop on the
        same failing path until the retry policy gives up.
        """
        import time as _time

        from temporalio.exceptions import ApplicationError

        from tenuo import SigningKey, Warrant
        from tenuo.temporal._dedup import PopDedupStore

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("noop")
            .ttl(3600)
            .mint(control_key)
        )
        pop = warrant.sign(agent_key, "noop", {}, int(_time.time()))

        class BrokenDedupStore(PopDedupStore):
            def check_pop_replay(self, *args, **kwargs):
                raise RuntimeError("simulated dedup backend failure")

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            pop_dedup_store=BrokenDedupStore(),
        )
        plugin = TenuoWorkerInterceptor(cfg)

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "noop"
        info.activity_id = "1"
        info.workflow_id = "wf"
        info.workflow_run_id = "run"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ()
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        ai = plugin.intercept_activity(MagicMock(
            execute_activity=AsyncMock(return_value="ok"),
            init=MagicMock(),
        ))
        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                with pytest.raises(ApplicationError) as excinfo:
                    loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        assert excinfo.value.non_retryable is True


class TestApprovalGateWireType:
    """``ApprovalGateTriggered`` must reach the wire with its own error code
    (``approval_required``) instead of being collapsed into
    ``TemporalConstraintViolation`` / ``CONSTRAINT_VIOLATED``.
    """

    def test_approval_gate_surfaces_with_own_error_code(self):
        import time as _time

        from temporalio.exceptions import ApplicationError

        from tenuo import SigningKey, Warrant

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        approver_key = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("deploy")
            .required_approvers([approver_key.public_key])
            .min_approvals(1)
            .approval_gates({"deploy": None})
            .ttl(3600)
            .mint(control_key)
        )
        pop = warrant.sign(agent_key, "deploy", {}, int(_time.time()))

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
        )
        plugin = TenuoWorkerInterceptor(cfg)

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "deploy"
        info.activity_id = "1"
        info.workflow_id = "wf-gate"
        info.workflow_run_id = "run-1"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = lambda: None
        inp.args = ()
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        ai = plugin.intercept_activity(MagicMock(
            execute_activity=AsyncMock(return_value="ok"),
            init=MagicMock(),
        ))
        loop = asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=info):
                with pytest.raises(ApplicationError) as excinfo:
                    loop.run_until_complete(ai.execute_activity(inp))
        finally:
            loop.close()

        from tenuo.exceptions import ApprovalGateTriggered

        assert excinfo.value.non_retryable is True
        # The wire error_code must reflect *approval required*, not the
        # generic constraint-violation code.
        assert excinfo.value.type == ApprovalGateTriggered.error_code
        assert excinfo.value.type != TemporalConstraintViolation.error_code


class TestDedupRetrySkip:
    """PoP dedup is skipped when Temporal is retrying (``info.attempt > 1``)."""

    def test_second_attempt_does_not_hit_dedup_store(self):
        import time as _time

        from tenuo import SigningKey, Warrant
        from tenuo.temporal._dedup import PopDedupStore

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("noop")
            .ttl(3600)
            .mint(control_key)
        )
        pop = warrant.sign(agent_key, "noop", {}, int(_time.time()))

        calls: list = []

        class RecordingDedupStore(PopDedupStore):
            def check_pop_replay(self, dedup_key, now, ttl_seconds, *, activity_name):
                calls.append(dedup_key)

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            pop_dedup_store=RecordingDedupStore(),
        )
        plugin = TenuoWorkerInterceptor(cfg)

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        def run_with_attempt(attempt: int) -> None:
            info = MagicMock()
            info.activity_type = "noop"
            info.activity_id = f"a-{attempt}"
            info.workflow_id = "wf"
            info.workflow_run_id = "run"
            info.workflow_type = "W"
            info.task_queue = "q"
            info.attempt = attempt
            info.is_local = False
            inp = MagicMock()
            inp.fn = None
            inp.args = ()
            inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

            ai = plugin.intercept_activity(MagicMock(
                execute_activity=AsyncMock(return_value="ok"),
                init=MagicMock(),
            ))
            loop = asyncio.new_event_loop()
            try:
                with patch("temporalio.activity.info", return_value=info):
                    loop.run_until_complete(ai.execute_activity(inp))
            finally:
                loop.close()

        run_with_attempt(1)
        assert len(calls) == 1, "attempt=1 should hit the dedup store"

        run_with_attempt(2)
        assert len(calls) == 1, "attempt=2 (retry) must skip the dedup store"


class TestAuditCallbackFailureSwallowed:
    """``audit_callback`` failures must not crash the activity path, and must
    produce a traceback in logs for both ALLOW and DENY events.
    """

    def _build_cfg(self, *, audit_callback, control_key):
        return TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            audit_callback=audit_callback,
            audit_allow=True,
            audit_deny=True,
        )

    def test_allow_path_swallows_audit_callback_exception(self, caplog):
        import logging
        import time as _time

        from tenuo import SigningKey, Warrant

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("noop")
            .ttl(3600)
            .mint(control_key)
        )
        pop = warrant.sign(agent_key, "noop", {}, int(_time.time()))

        def boom(_event):
            raise RuntimeError("audit sink exploded")

        cfg = self._build_cfg(audit_callback=boom, control_key=control_key)
        plugin = TenuoWorkerInterceptor(cfg)

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "noop"
        info.activity_id = "1"
        info.workflow_id = "wf"
        info.workflow_run_id = "run"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ()
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        ai = plugin.intercept_activity(MagicMock(
            execute_activity=AsyncMock(return_value="ok"),
            init=MagicMock(),
        ))

        with caplog.at_level(logging.ERROR, logger="tenuo.temporal"):
            loop = asyncio.new_event_loop()
            try:
                with patch("temporalio.activity.info", return_value=info):
                    result = loop.run_until_complete(ai.execute_activity(inp))
            finally:
                loop.close()

        assert result == "ok", "audit failure must not break the activity"
        # The log record carries a traceback (exc_info=True).
        allow_records = [
            r for r in caplog.records
            if "Audit callback failed for ALLOW event" in r.getMessage()
        ]
        assert allow_records, "ALLOW-path audit error should be logged"
        assert any(r.exc_info is not None for r in allow_records), (
            "audit-callback error log must include exc_info for diagnosability"
        )

    def test_deny_path_swallows_audit_callback_exception(self, caplog):
        import logging
        import time as _time

        from temporalio.exceptions import ApplicationError

        from tenuo import SigningKey, Warrant
        from tenuo_core import Subpath

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/safe"))
            .ttl(3600)
            .mint(control_key)
        )
        # Sign for a DENIED arg so the activity path hits the deny branch.
        pop = warrant.sign(
            agent_key, "read_file", {"path": "/etc/passwd"}, int(_time.time()),
        )

        def boom(_event):
            raise RuntimeError("audit sink exploded on deny")

        cfg = self._build_cfg(audit_callback=boom, control_key=control_key)
        plugin = TenuoWorkerInterceptor(cfg)

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER
        act_headers[TENUO_ARG_KEYS_HEADER] = b"path"

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "read_file"
        info.activity_id = "1"
        info.workflow_id = "wf"
        info.workflow_run_id = "run"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ("/etc/passwd",)
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        ai = plugin.intercept_activity(MagicMock(
            execute_activity=AsyncMock(return_value="ok"),
            init=MagicMock(),
        ))

        with caplog.at_level(logging.ERROR, logger="tenuo.temporal"):
            loop = asyncio.new_event_loop()
            try:
                with patch("temporalio.activity.info", return_value=info):
                    with pytest.raises(ApplicationError):
                        loop.run_until_complete(ai.execute_activity(inp))
            finally:
                loop.close()

        deny_records = [
            r for r in caplog.records
            if "Audit callback failed for DENY event" in r.getMessage()
        ]
        assert deny_records, "DENY-path audit error should be logged"
        assert any(r.exc_info is not None for r in deny_records), (
            "deny-audit error log must include exc_info — DENY events are "
            "compliance-critical, operators must be able to trace the loss"
        )


class TestClientHeadersPendingMapBound:
    """``TenuoClientInterceptor.set_headers_for_workflow`` must not grow
    unbounded for workflow ids that never start. A TTL + max-size cap keeps
    long-running clients healthy.
    """

    def test_explicit_discard_drops_entry(self):
        from tenuo.temporal._client import TenuoClientInterceptor

        ci = TenuoClientInterceptor()
        ci.set_headers_for_workflow("wf-1", {"x-tenuo-warrant": b"abc"})
        assert ci.discard_headers_for_workflow("wf-1") is True
        assert ci.discard_headers_for_workflow("wf-1") is False

    def test_ttl_evicts_stale_entries_on_next_set(self):
        from tenuo.temporal._client import TenuoClientInterceptor

        ci = TenuoClientInterceptor(pending_headers_ttl_secs=0.01)
        ci.set_headers_for_workflow("stale", {"x-tenuo-warrant": b"old"})
        # Poke in expired-but-not-evicted-yet state:
        import time as _time
        _time.sleep(0.02)
        # Any subsequent set or start_workflow will prune expired entries.
        ci.set_headers_for_workflow("fresh", {"x-tenuo-warrant": b"new"})
        assert "stale" not in ci._headers_by_workflow_id
        assert "fresh" in ci._headers_by_workflow_id

    def test_max_size_evicts_oldest(self, caplog):
        import logging

        from tenuo.temporal._client import TenuoClientInterceptor

        ci = TenuoClientInterceptor(
            pending_headers_max_size=3,
            pending_headers_ttl_secs=None,
        )
        with caplog.at_level(logging.WARNING, logger="tenuo.temporal"):
            for i in range(5):
                ci.set_headers_for_workflow(f"wf-{i}", {"x-tenuo-warrant": b"x"})

        # Only the last 3 remain (oldest were evicted).
        remaining = set(ci._headers_by_workflow_id.keys())
        assert remaining == {"wf-2", "wf-3", "wf-4"}
        assert any(
            "exceeded" in r.getMessage() and "evicting oldest" in r.getMessage()
            for r in caplog.records
        )

    def test_rebinding_refreshes_position_for_ttl(self):
        """Re-binding an existing workflow_id resets its TTL clock."""
        from tenuo.temporal._client import TenuoClientInterceptor

        ci = TenuoClientInterceptor(
            pending_headers_max_size=2,
            pending_headers_ttl_secs=None,
        )
        ci.set_headers_for_workflow("a", {"x-tenuo-warrant": b"1"})
        ci.set_headers_for_workflow("b", {"x-tenuo-warrant": b"2"})
        # Re-bind "a" → becomes the newest entry.
        ci.set_headers_for_workflow("a", {"x-tenuo-warrant": b"1b"})
        # Adding a third entry now evicts "b" (oldest), not "a".
        ci.set_headers_for_workflow("c", {"x-tenuo-warrant": b"3"})
        assert set(ci._headers_by_workflow_id.keys()) == {"a", "c"}


class TestSignalAndUpdateRuntimeDenial:
    """The inbound workflow interceptor rejects signals/updates that aren't
    in the explicit allowlist. Covers the behavioural runtime path, not
    just config-time validation.
    """

    def _stub_inbound(self, *, authorized_signals=None, authorized_updates=None):
        """Build an inbound interceptor and register its config in the
        workflow-config store so ``_resolve_config`` finds it.
        """
        from tenuo.temporal._interceptors import _TenuoWorkflowInboundInterceptor
        from tenuo.temporal._state import _store_lock, _workflow_config_store

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            authorized_signals=authorized_signals,
            authorized_updates=authorized_updates,
        )
        next_interceptor = MagicMock()
        next_interceptor.handle_signal = AsyncMock(return_value=None)
        next_interceptor.handle_update_validator = MagicMock(return_value=None)

        inbound = _TenuoWorkflowInboundInterceptor(next_interceptor=next_interceptor)
        wf_id = "wf-sig"
        with _store_lock:
            _workflow_config_store[wf_id] = cfg
        return inbound, next_interceptor, cfg, wf_id

    def _fake_wf_info(self, wf_id="wf-sig"):
        info = MagicMock()
        info.workflow_id = wf_id
        info.run_id = wf_id
        return info

    @staticmethod
    def _cleanup(wf_id):
        from tenuo.temporal._state import _store_lock, _workflow_config_store

        with _store_lock:
            _workflow_config_store.pop(wf_id, None)

    def test_signal_allowed_passes_through(self):
        inbound, nxt, _, wf_id = self._stub_inbound(authorized_signals=["add"])
        sig_input = MagicMock(signal="add")
        try:
            with patch("temporalio.workflow.info", return_value=self._fake_wf_info(wf_id)):
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(inbound.handle_signal(sig_input))
                finally:
                    loop.close()
        finally:
            self._cleanup(wf_id)
        nxt.handle_signal.assert_called_once_with(sig_input)

    def test_signal_outside_allowlist_denies_and_names_warrant(self):
        inbound, nxt, _, wf_id = self._stub_inbound(authorized_signals=["add"])
        sig_input = MagicMock(signal="drop_tables")
        try:
            with patch("temporalio.workflow.info", return_value=self._fake_wf_info(wf_id)):
                loop = asyncio.new_event_loop()
                try:
                    with pytest.raises(TemporalConstraintViolation) as excinfo:
                        loop.run_until_complete(inbound.handle_signal(sig_input))
                finally:
                    loop.close()
        finally:
            self._cleanup(wf_id)

        assert "drop_tables" in str(excinfo.value)
        nxt.handle_signal.assert_not_called()

    def test_update_allowed_passes_through(self):
        inbound, nxt, _, wf_id = self._stub_inbound(authorized_updates=["retry"])
        upd_input = MagicMock(update="retry")
        try:
            with patch("temporalio.workflow.info", return_value=self._fake_wf_info(wf_id)):
                inbound.handle_update_validator(upd_input)
        finally:
            self._cleanup(wf_id)
        nxt.handle_update_validator.assert_called_once_with(upd_input)

    def test_update_outside_allowlist_denies(self):
        inbound, nxt, _, wf_id = self._stub_inbound(authorized_updates=["retry"])
        upd_input = MagicMock(update="wipe")
        try:
            with patch("temporalio.workflow.info", return_value=self._fake_wf_info(wf_id)):
                with pytest.raises(TemporalConstraintViolation) as excinfo:
                    inbound.handle_update_validator(upd_input)
        finally:
            self._cleanup(wf_id)
        assert "wipe" in str(excinfo.value)
        nxt.handle_update_validator.assert_not_called()


class TestSetActivityApprovalsOverwriteWarning:
    """Two back-to-back ``set_activity_approvals`` calls without an intervening
    dispatch log a warning so users notice the one-shot contract was
    violated (usually a hint of a parallel-gather footgun).
    """

    def test_overwrite_without_dispatch_logs_warning(self, caplog):
        import logging

        from tenuo.temporal._state import _pending_activity_approvals, _store_lock
        from tenuo.temporal._workflow import set_activity_approvals

        wf_id = "wf-approval-overwrite"
        fake_info = MagicMock()
        fake_info.workflow_id = wf_id
        fake_info.run_id = wf_id

        try:
            with caplog.at_level(logging.WARNING, logger="tenuo.temporal"):
                with patch("temporalio.workflow.info", return_value=fake_info):
                    set_activity_approvals(["first"])
                    set_activity_approvals(["second"])
            assert any(
                "overwriting" in r.getMessage() and "asyncio.gather" in r.getMessage()
                for r in caplog.records
            )
            with _store_lock:
                assert _pending_activity_approvals[wf_id] == ["second"]
        finally:
            with _store_lock:
                _pending_activity_approvals.pop(wf_id, None)


class TestManualSetupActivitiesRegistry:
    """``TENUO_TEMPORAL_ACTIVITIES`` is the public handle for the
    Tenuo-owned activities every worker must register.

    The plugin path (``TenuoTemporalPlugin``) injects these automatically;
    manual setups (``TenuoWorkerInterceptor`` wired directly into
    ``Worker(...)``) must splat this tuple into ``activities=[...]`` or
    ``workflow_grant()`` / ``tenuo_execute_child_workflow(constraints=...)``
    have no mint activity to dispatch against.
    """

    def test_tuple_contains_mint_activity(self):
        from tenuo.temporal import TENUO_TEMPORAL_ACTIVITIES
        from tenuo.temporal._workflow import _tenuo_internal_mint_activity

        # Tuple (immutable) — users splat it with ``*TENUO_TEMPORAL_ACTIVITIES``
        # and cannot accidentally mutate the shared registry.
        assert isinstance(TENUO_TEMPORAL_ACTIVITIES, tuple)
        assert _tenuo_internal_mint_activity is not None
        assert _tenuo_internal_mint_activity in TENUO_TEMPORAL_ACTIVITIES

    def test_tuple_is_single_source_of_truth_for_plugin(self):
        """The plugin appends exactly the same set — no duplicate registry to drift."""
        from tenuo.temporal import TENUO_TEMPORAL_ACTIVITIES
        from tenuo.temporal_plugin import TENUO_TEMPORAL_ACTIVITIES as PLUGIN_SIDE

        assert TENUO_TEMPORAL_ACTIVITIES is PLUGIN_SIDE


class TestInMemoryPopDedupStoreWarning:
    """Default ``pop_dedup_store`` (``None`` → in-memory) must log loudly.

    Single-process replay protection is close to no replay protection in
    any horizontally-deployed environment, so the default is logged at
    ``WARNING``. Operators who consciously accept the single-process mode
    can pass an explicit ``InMemoryPopDedupStore()`` to silence it.
    """

    def test_none_default_emits_warning(self, caplog):
        import logging

        from tenuo import SigningKey

        control_key = SigningKey.generate()
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            # pop_dedup_store left None — this is the footgun path
        )

        with caplog.at_level(logging.WARNING, logger="tenuo.temporal"):
            TenuoWorkerInterceptor(cfg)

        messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("in-memory PopDedupStore" in m for m in messages), (
            f"expected a WARNING about the in-memory dedup store, got: {messages}"
        )

    def test_explicit_store_is_silent(self, caplog):
        """Operators who acknowledge the mode explicitly get silence."""
        import logging

        from tenuo import SigningKey
        from tenuo.temporal._dedup import InMemoryPopDedupStore

        control_key = SigningKey.generate()
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            pop_dedup_store=InMemoryPopDedupStore(),
        )

        with caplog.at_level(logging.WARNING, logger="tenuo.temporal"):
            TenuoWorkerInterceptor(cfg)

        messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert not any("in-memory PopDedupStore" in m for m in messages), (
            f"expected no in-memory-dedup WARNING, got: {messages}"
        )


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
