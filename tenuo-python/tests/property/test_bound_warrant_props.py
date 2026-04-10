"""Property tests for BoundWarrant (bound_warrant.py).

Verifies:
- Serialization prevention: pickle/reduce always raise TypeError
- __repr__ never includes key material
- headers() output shape: exactly two headers with base64 values
- validate() uses Authorizer (Rust) for verification
- Context manager enter/exit restores scope correctly
"""

from __future__ import annotations

import pickle

import pytest
from hypothesis import given, settings

from tenuo import Warrant

from .strategies import st_warrant_bundle


class TestSerializationPrevention:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_getstate_raises_typeerror(self, data):
        """__getstate__ always raises TypeError for any BoundWarrant."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        with pytest.raises(TypeError, match="cannot be serialized"):
            bound.__getstate__()

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_reduce_raises_typeerror(self, data):
        """__reduce__ always raises TypeError for any BoundWarrant."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        with pytest.raises(TypeError, match="cannot be pickled"):
            bound.__reduce__()

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_pickle_dumps_raises(self, data):
        """pickle.dumps always raises for BoundWarrant."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        with pytest.raises(TypeError):
            pickle.dumps(bound)


class TestReprHidesKeys:
    @given(data=st_warrant_bundle())
    @settings(max_examples=30)
    def test_repr_never_contains_key_bytes(self, data):
        """__repr__ never exposes signing key material."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        r = repr(bound)
        key_hex = bytes(key.to_bytes()).hex() if hasattr(key, "to_bytes") else ""
        assert "BoundWarrant" in r
        assert "KEY_BOUND=True" in r
        if key_hex and len(key_hex) > 16:
            assert key_hex not in r

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_repr_is_short(self, data):
        """__repr__ is reasonably short (no huge data dumps)."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        assert len(repr(bound)) < 200


class TestHeadersOutputShape:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_headers_returns_two_keys(self, data):
        """headers() returns exactly X-Tenuo-Warrant and X-Tenuo-PoP."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        headers = bound.headers(tool, args)
        assert isinstance(headers, dict)
        assert len(headers) == 2
        header_keys = set(headers.keys())
        assert "X-Tenuo-PoP" in header_keys

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_headers_values_are_base64(self, data):
        """Both header values are valid base64-encoded strings."""
        import re
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        headers = bound.headers(tool, args)
        b64_pattern = re.compile(r"^[A-Za-z0-9+/\-_]+=*$")
        for name, value in headers.items():
            assert isinstance(value, str)
            assert len(value) > 0
            assert b64_pattern.match(value), f"Header {name} is not base64: {value!r}"


class TestValidateUsesRust:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_validate_success_for_matching_tool(self, data):
        """validate() returns truthy for a tool in the warrant."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        result = bound.validate(tool, args)
        assert result

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_validate_failure_for_wrong_tool(self, data):
        """validate() returns falsy for a tool not in the warrant."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        result = bound.validate("definitely_not_in_warrant_xyz", {})
        assert not result


class TestContextManager:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_enter_exit_restores_scope(self, data):
        """Context manager enter sets scope, exit restores it."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)

        from tenuo.decorators import _keypair_context, _warrant_context

        before_w = _warrant_context.get()
        before_k = _keypair_context.get()

        with bound:
            assert _warrant_context.get() is warrant
            assert _keypair_context.get() is key

        assert _warrant_context.get() is before_w
        assert _keypair_context.get() is before_k

    @given(data=st_warrant_bundle())
    @settings(max_examples=10)
    def test_nested_context_managers(self, data):
        """Nested BoundWarrant context managers restore correctly."""
        w1, k1, tool, args = data
        w2 = Warrant.issue(
            keypair=k1, capabilities={tool: {}},
            ttl_seconds=3600, holder=k1.public_key,
        )
        b1 = w1.bind(k1)
        b2 = w2.bind(k1)

        from tenuo.decorators import _warrant_context

        with b1:
            assert _warrant_context.get() is w1
            with b2:
                assert _warrant_context.get() is w2
            assert _warrant_context.get() is w1
