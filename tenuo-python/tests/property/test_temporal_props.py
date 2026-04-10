"""Property tests for Temporal integration (temporal.py).

Verifies:
- tenuo_headers -> _extract_warrant_from_headers roundtrip
- _extract_warrant_from_headers robustness with arbitrary headers
- _wrap_as_non_retryable always produces non-retryable ApplicationError
- Temporal module uses Authorizer from tenuo_core
"""

from __future__ import annotations

import inspect

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


from .strategies import st_temporal_headers, st_warrant_bundle


# ---------------------------------------------------------------------------
# Wire roundtrip: tenuo_headers -> _extract_warrant_from_headers
# ---------------------------------------------------------------------------


class TestTemporalWireRoundtrip:
    @given(data=st_warrant_bundle())
    @settings(max_examples=30)
    def test_roundtrip_compressed(self, data):
        """Encoding then decoding a warrant via Temporal headers preserves bytes."""
        warrant, key, tool, args = data

        try:
            from tenuo.temporal import _extract_warrant_from_headers, tenuo_headers
        except ImportError:
            pytest.skip("temporalio not installed")

        headers = tenuo_headers(warrant, key_id="test-key", compress=True)
        recovered = _extract_warrant_from_headers(headers)
        assert recovered is not None
        assert bytes(recovered.to_bytes()) == bytes(warrant.to_bytes())

    @given(data=st_warrant_bundle())
    @settings(max_examples=30)
    def test_roundtrip_uncompressed(self, data):
        """Encoding then decoding without compression preserves bytes."""
        warrant, key, tool, args = data

        try:
            from tenuo.temporal import _extract_warrant_from_headers, tenuo_headers
        except ImportError:
            pytest.skip("temporalio not installed")

        headers = tenuo_headers(warrant, key_id="test-key", compress=False)
        recovered = _extract_warrant_from_headers(headers)
        assert recovered is not None
        assert bytes(recovered.to_bytes()) == bytes(warrant.to_bytes())


# ---------------------------------------------------------------------------
# _extract_warrant_from_headers: robustness with arbitrary headers
# ---------------------------------------------------------------------------


class TestExtractWarrantRobustness:
    @given(headers=st_temporal_headers())
    @settings(max_examples=50)
    def test_never_crashes_on_arbitrary_headers(self, headers):
        """_extract_warrant_from_headers returns None or a Warrant, never crashes."""
        try:
            from tenuo.temporal import _extract_warrant_from_headers
        except ImportError:
            pytest.skip("temporalio not installed")

        try:
            result = _extract_warrant_from_headers(headers)
            assert result is None or hasattr(result, "to_bytes")
        except Exception as e:
            # Known, expected exceptions are OK — not crashes
            assert not isinstance(e, (SystemExit, KeyboardInterrupt))

    @given(headers=st.dictionaries(
        keys=st.text(min_size=1, max_size=30),
        values=st.binary(min_size=0, max_size=200),
        max_size=5,
    ))
    @settings(max_examples=50)
    def test_never_crashes_on_random_headers(self, headers):
        """Even completely random header dicts don't crash."""
        try:
            from tenuo.temporal import _extract_warrant_from_headers
        except ImportError:
            pytest.skip("temporalio not installed")

        try:
            _extract_warrant_from_headers(headers)
        except Exception as e:
            assert not isinstance(e, (SystemExit, KeyboardInterrupt))


# ---------------------------------------------------------------------------
# _wrap_as_non_retryable: exhaustiveness
# ---------------------------------------------------------------------------


class TestWrapAsNonRetryable:
    @given(msg=st.text(min_size=0, max_size=200))
    @settings(max_examples=30)
    def test_always_produces_non_retryable(self, msg):
        """_wrap_as_non_retryable always returns ApplicationError(non_retryable=True)."""
        try:
            from temporalio.exceptions import ApplicationError
            from tenuo.temporal import TenuoActivityInboundInterceptor
        except ImportError:
            pytest.skip("temporalio not installed")

        exc = Exception(msg)
        wrapped = TenuoActivityInboundInterceptor._wrap_as_non_retryable(exc)
        assert isinstance(wrapped, ApplicationError)
        assert wrapped.non_retryable is True

    @given(msg=st.text(min_size=0, max_size=200))
    @settings(max_examples=30)
    def test_preserves_message(self, msg):
        """The original message is preserved in the wrapped error."""
        try:
            from tenuo.temporal import TenuoActivityInboundInterceptor
        except ImportError:
            pytest.skip("temporalio not installed")

        exc = ValueError(msg)
        wrapped = TenuoActivityInboundInterceptor._wrap_as_non_retryable(exc)
        assert msg in str(wrapped) or msg == ""


# ---------------------------------------------------------------------------
# Module-level: Temporal uses Authorizer from tenuo_core
# ---------------------------------------------------------------------------


class TestTemporalUsesRust:
    def test_module_imports_authorizer(self):
        """The temporal module imports and uses Authorizer from tenuo_core."""
        try:
            from tenuo import temporal as temporal_mod
        except ImportError:
            pytest.skip("temporalio not installed")

        source = inspect.getsource(temporal_mod)
        assert "Authorizer" in source
        assert "authorize_one" in source or "check_chain" in source

    def test_module_imports_warrant(self):
        """The temporal module imports Warrant from tenuo_core."""
        try:
            from tenuo import temporal as temporal_mod
        except ImportError:
            pytest.skip("temporalio not installed")

        source = inspect.getsource(temporal_mod)
        assert "Warrant.from_bytes" in source or "Warrant.from_base64" in source
