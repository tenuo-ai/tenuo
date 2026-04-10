"""Property tests for decorators.py.

Verifies:
- _check_annotated_constraint: unknown types fail closed (return False)
- _check_annotated_constraint: exceptions fail closed (return False)
- is_bypass_enabled: False when TENUO_ENV != 'test'
- Scope context managers: enter/exit/nesting
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo import SigningKey, Warrant
from tenuo.decorators import (
    _check_annotated_constraint,
    _is_tenuo_constraint,
    _keypair_context,
    _warrant_context,
    _chain_context,
    is_bypass_enabled,
    _bypass_context,
)


class TestAnnotatedConstraintFailClosed:
    @given(value=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False)))
    @settings(max_examples=30)
    def test_unknown_type_returns_false(self, value):
        """Unknown constraint types always return False (fail closed)."""
        unknown = MagicMock()
        unknown.__class__.__name__ = "TotallyUnknownConstraint"
        # Remove all known method signatures
        del unknown.contains
        del unknown.matches
        del unknown.is_safe
        del unknown.contains_ip
        del unknown.matches_url
        del unknown.allows
        del unknown.check
        del unknown.value
        result = _check_annotated_constraint(unknown, value)
        assert result is False

    @given(value=st.text(min_size=0, max_size=50))
    @settings(max_examples=30)
    def test_exception_in_constraint_returns_false(self, value):
        """If the constraint method raises, result is False (fail closed)."""

        def _boom(v):
            raise RuntimeError("boom")

        BrokenPattern = type("Pattern", (), {"matches": _boom})
        broken = BrokenPattern()
        result = _check_annotated_constraint(broken, value)
        assert result is False


class TestIsTenuoConstraint:
    def test_known_types_recognized(self):
        """Known constraint type names are recognized."""
        for name in ["Pattern", "Exact", "Range", "OneOf", "Wildcard", "Subpath", "Cidr"]:
            mock = MagicMock()
            mock.__class__.__name__ = name
            assert _is_tenuo_constraint(mock) is True

    @given(name=st.from_regex(r"[a-zA-Z][a-zA-Z0-9]{0,29}", fullmatch=True).filter(
        lambda n: n not in {
            "Pattern", "Exact", "Range", "OneOf", "NotOneOf",
            "Contains", "Subset", "Regex", "Cidr", "UrlPattern",
            "CEL", "All", "AnyOf", "Not", "Subpath", "UrlSafe",
            "Shlex", "Wildcard",
        }
    ))
    @settings(max_examples=30)
    def test_unknown_types_not_recognized(self, name):
        """Arbitrary class names are not recognized as Tenuo constraints."""
        mock = MagicMock()
        mock.__class__.__name__ = name
        assert _is_tenuo_constraint(mock) is False


class TestBypassSecurity:
    def test_bypass_false_when_env_not_test(self):
        """is_bypass_enabled returns False when TENUO_ENV is not 'test'."""
        token = _bypass_context.set(True)
        try:
            with patch.dict(os.environ, {"TENUO_ENV": "production"}, clear=False):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    assert is_bypass_enabled() is False
        finally:
            _bypass_context.reset(token)

    def test_bypass_false_when_env_empty(self):
        """is_bypass_enabled returns False when TENUO_ENV is empty."""
        token = _bypass_context.set(True)
        try:
            with patch.dict(os.environ, {"TENUO_ENV": ""}, clear=False):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    assert is_bypass_enabled() is False
        finally:
            _bypass_context.reset(token)

    def test_bypass_false_when_context_not_set(self):
        """is_bypass_enabled returns False when bypass context is False."""
        token = _bypass_context.set(False)
        try:
            assert is_bypass_enabled() is False
        finally:
            _bypass_context.reset(token)

    @given(env_val=st.text(min_size=1, max_size=30).filter(lambda s: s.lower() != "test"))
    @settings(max_examples=20)
    def test_bypass_false_for_arbitrary_env(self, env_val):
        """is_bypass_enabled returns False for any TENUO_ENV value that isn't 'test'."""
        token = _bypass_context.set(True)
        try:
            with patch.dict(os.environ, {"TENUO_ENV": env_val}, clear=False):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    assert is_bypass_enabled() is False
        finally:
            _bypass_context.reset(token)


class TestScopeContextManagers:
    def test_warrant_scope_enter_exit(self):
        """warrant_scope sets and restores the warrant context."""
        from tenuo import warrant_scope

        key = SigningKey.generate()
        w = Warrant.issue(
            keypair=key, capabilities={"test": {}},
            ttl_seconds=3600, holder=key.public_key,
        )

        before = _warrant_context.get()
        with warrant_scope(w):
            assert _warrant_context.get() is w
        assert _warrant_context.get() is before

    def test_key_scope_enter_exit(self):
        """key_scope sets and restores the key context."""
        from tenuo import key_scope

        key = SigningKey.generate()

        before = _keypair_context.get()
        with key_scope(key):
            assert _keypair_context.get() is key
        assert _keypair_context.get() is before

    def test_chain_scope_enter_exit(self):
        """chain_scope sets and restores the chain context."""
        from tenuo import chain_scope

        chain = [MagicMock()]

        before = _chain_context.get()
        with chain_scope(chain):
            assert _chain_context.get() is chain
        assert _chain_context.get() is before

    def test_nested_scopes_restore_correctly(self):
        """Nested scope context managers restore in correct LIFO order."""
        from tenuo import key_scope, warrant_scope

        k1 = SigningKey.generate()
        k2 = SigningKey.generate()
        w1 = Warrant.issue(keypair=k1, capabilities={"a": {}}, ttl_seconds=3600, holder=k1.public_key)
        w2 = Warrant.issue(keypair=k2, capabilities={"b": {}}, ttl_seconds=3600, holder=k2.public_key)

        with warrant_scope(w1), key_scope(k1):
            assert _warrant_context.get() is w1
            with warrant_scope(w2), key_scope(k2):
                assert _warrant_context.get() is w2
                assert _keypair_context.get() is k2
            assert _warrant_context.get() is w1
            assert _keypair_context.get() is k1
