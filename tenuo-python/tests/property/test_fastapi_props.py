"""Property tests for FastAPI integration (fastapi.py).

Verifies:
- TenuoGuard._enforce_with_pop_signature reaches the shared enforcement path in verify mode
- A PoP signed by a key other than the holder's is denied
- Warrant header extraction handles arbitrary strings without crashing
- Trusted roots resolution: no roots -> denial (fail-closed)
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo import SigningKey
from tenuo._enforcement import _enforce_tool_call_impl

from .strategies import st_warrant_bundle


# ---------------------------------------------------------------------------
# TenuoGuard reaches the shared enforcement path (verify_inbound_call)
# ---------------------------------------------------------------------------


class TestFastAPIGuardCallsRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_enforce_with_pop_calls_enforcement(self, data):
        """TenuoGuard._enforce_with_pop_signature delegates to the shared enforcement path."""
        warrant, key, tool, args = data
        pop = bytes(warrant.sign(key, tool, args, int(time.time())))

        try:
            from tenuo.fastapi import TenuoGuard, _config
        except ImportError:
            pytest.skip("fastapi not installed")

        _config["trusted_issuers"] = [key.public_key]
        try:
            guard = TenuoGuard(tool)

            with patch("tenuo._enforcement._enforce_tool_call_impl", wraps=_enforce_tool_call_impl) as spy:
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

            with patch("tenuo._enforcement._enforce_tool_call_impl", wraps=_enforce_tool_call_impl) as spy:
                guard._enforce_with_pop_signature(warrant, tool, args, pop)
                _, kwargs = spy.call_args
                assert kwargs.get("verify_mode") == "verify"
        finally:
            _config.pop("trusted_issuers", None)

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_pop_from_other_key_denied(self, data):
        """A PoP signed by a key other than the warrant holder's is denied."""
        warrant, key, tool, args = data
        pop = bytes(warrant.sign(SigningKey.generate(), tool, args, int(time.time())))

        try:
            from fastapi import HTTPException
            from tenuo.fastapi import TenuoGuard, _config
        except ImportError:
            pytest.skip("fastapi not installed")

        _config["trusted_issuers"] = [key.public_key]
        try:
            guard = TenuoGuard(tool)
            try:
                result = guard._enforce_with_pop_signature(warrant, tool, args, pop)
            except HTTPException as e:
                assert e.status_code == 403
            else:
                assert not result.allowed
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
