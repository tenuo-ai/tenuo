"""Property tests for config.py resolve_trusted_roots.

Verifies:
- Explicit parameter always wins (precedence)
- None explicit falls through to global config
- Empty list explicit is returned as-is
- None result from resolve means fail-closed at enforce_tool_call
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo import SigningKey
from tenuo.config import resolve_trusted_roots


class TestResolvePrecedence:
    @given(n_keys=st.integers(min_value=1, max_value=5))
    @settings(max_examples=20)
    def test_explicit_always_wins(self, n_keys):
        """When explicit roots are provided, they are returned regardless of global config."""
        keys = [SigningKey.generate().public_key for _ in range(n_keys)]
        result = resolve_trusted_roots(explicit=keys)
        assert result is keys

    def test_explicit_empty_list_returned(self):
        """An explicit empty list is returned as-is (caller decides if that's valid)."""
        result = resolve_trusted_roots(explicit=[])
        assert result == []

    def test_none_explicit_falls_through(self):
        """When explicit is None, resolve looks at global config."""
        result = resolve_trusted_roots(explicit=None)
        # Result depends on global config state; we just verify it doesn't crash
        assert result is None or isinstance(result, list)


class TestFailClosedIntegration:
    def test_none_result_causes_denial(self):
        """When resolve returns None, enforce_tool_call denies (fail-closed)."""
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        warrant = __import__("tenuo").Warrant.issue(
            keypair=key, capabilities={"test": {}},
            ttl_seconds=3600, holder=key.public_key,
        )
        bound = warrant.bind(key)

        with patch("tenuo.config.resolve_trusted_roots", return_value=None):
            result = enforce_tool_call(
                "test", {}, bound,
                trusted_roots=None,
            )
            assert result.allowed is False


class TestDevModeFallback:
    def test_dev_mode_uses_issuer_key(self):
        """In dev_mode with issuer_key set, resolve returns issuer public key."""
        key = SigningKey.generate()

        from tenuo.config import TenuoConfig, _config_context

        dev_config = TenuoConfig()
        dev_config.dev_mode = True
        dev_config.issuer_key = key

        token = _config_context.set(dev_config)
        try:
            result = resolve_trusted_roots(explicit=None)
            assert result is not None
            assert len(result) == 1
            assert result[0] == key.public_key
        finally:
            _config_context.reset(token)
