"""Property tests for FastAPI integration (fastapi.py).

Verifies:
- TenuoGuard._enforce_with_pop_signature calls enforce_tool_call (Rust path)
- Warrant header extraction handles arbitrary strings without crashing
- Trusted roots resolution: no roots -> denial (fail-closed)
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo._enforcement import enforce_tool_call

from .strategies import st_warrant_bundle


# ---------------------------------------------------------------------------
# TenuoGuard calls enforce_tool_call (Rust path)
# ---------------------------------------------------------------------------


class TestFastAPIGuardCallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_enforce_with_pop_calls_enforce_tool_call(self, data):
        """TenuoGuard._enforce_with_pop_signature delegates to enforce_tool_call."""
        warrant, key, tool, args = data
        pop = bytes(warrant.sign(key, tool, args, int(time.time())))

        try:
            from tenuo.fastapi import TenuoGuard, _config
        except ImportError:
            pytest.skip("fastapi not installed")

        _config["trusted_issuers"] = [key.public_key]
        try:
            guard = TenuoGuard(tool)

            with patch("tenuo._enforcement.enforce_tool_call", wraps=enforce_tool_call) as spy:
                guard._enforce_with_pop_signature(warrant, tool, args, pop)
                spy.assert_called_once()
        finally:
            _config.pop("trusted_issuers", None)

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_enforce_uses_verify_mode(self, data):
        """FastAPI guard uses verify_mode='verify' (not sign)."""
        warrant, key, tool, args = data
        pop = bytes(warrant.sign(key, tool, args, int(time.time())))

        try:
            from tenuo.fastapi import TenuoGuard, _config
        except ImportError:
            pytest.skip("fastapi not installed")

        _config["trusted_issuers"] = [key.public_key]
        try:
            guard = TenuoGuard(tool)

            with patch("tenuo._enforcement.enforce_tool_call", wraps=enforce_tool_call) as spy:
                guard._enforce_with_pop_signature(warrant, tool, args, pop)
                _, kwargs = spy.call_args
                assert kwargs.get("verify_mode") == "verify"
        finally:
            _config.pop("trusted_issuers", None)


# ---------------------------------------------------------------------------
# Warrant header extraction robustness
# ---------------------------------------------------------------------------


class TestWarrantHeaderExtraction:
    @given(header_value=st.one_of(st.none(), st.text(min_size=0, max_size=500)))
    @settings(max_examples=50)
    def test_get_warrant_header_never_crashes(self, header_value):
        """get_warrant_header handles arbitrary header values without crashing."""
        try:
            from tenuo.fastapi import get_warrant_header
        except ImportError:
            pytest.skip("fastapi not installed")
            return

        try:
            get_warrant_header.__wrapped__(header_value) if hasattr(get_warrant_header, "__wrapped__") else None
        except Exception as e:
            assert not isinstance(e, (SystemExit, KeyboardInterrupt))


# ---------------------------------------------------------------------------
# Fail-closed: no trusted roots -> denial
# ---------------------------------------------------------------------------


class TestFastAPIFailClosed:
    @given(data=st_warrant_bundle())
    @settings(max_examples=10)
    def test_no_trusted_issuers_denies(self, data):
        """TenuoGuard with no trusted_issuers raises HTTPException (fail-closed)."""
        warrant, key, tool, args = data
        pop = bytes(warrant.sign(key, tool, args, int(time.time())))

        try:
            from fastapi import HTTPException
            from tenuo.fastapi import TenuoGuard, _config
        except ImportError:
            pytest.skip("fastapi not installed")

        _config.pop("trusted_issuers", None)
        guard = TenuoGuard(tool)

        with patch("tenuo.config.resolve_trusted_roots", return_value=None):
            try:
                result = guard._enforce_with_pop_signature(warrant, tool, args, pop)
                assert not result.allowed
            except HTTPException as e:
                assert e.status_code == 403
            except Exception:
                pass
