"""Property tests for BaseGuardBuilder (_builder.py).

Verifies:
- allow() last-write-wins: calling twice replaces constraints
- allow() dict size equals distinct tool count
- with_warrant() requires non-None key
- on_denial() validates mode
- validate_warrant_for_binding: holder mismatch raises
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo import SigningKey, Warrant
from tenuo._builder import BaseGuardBuilder, validate_warrant_for_binding
from tenuo.exceptions import ConfigurationError, MissingSigningKey

from .strategies import st_tool_name, st_warrant_bundle


class TestAllowLastWriteWins:
    @given(tool=st_tool_name)
    @settings(max_examples=30)
    def test_second_allow_replaces_first(self, tool):
        """Calling allow() twice for the same tool replaces constraints."""

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        b.allow(tool, x="first")
        b.allow(tool, y="second")
        assert b._constraints[tool] == {"y": "second"}
        assert "x" not in b._constraints[tool]

    @given(tools=st.lists(st_tool_name, min_size=1, max_size=10))
    @settings(max_examples=30)
    def test_dict_size_equals_distinct_tools(self, tools):
        """Constraint dict size equals the number of distinct tool names."""

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        for t in tools:
            b.allow(t)
        assert len(b._constraints) == len(set(tools))


class TestWithWarrant:
    def test_none_key_raises(self):
        """with_warrant raises MissingSigningKey when key is None."""

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        with pytest.raises(MissingSigningKey):
            b.with_warrant(MagicMock(), None)

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_stores_warrant_and_key(self, data):
        """with_warrant stores both warrant and signing_key."""
        warrant, key, tool, args = data

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        result = b.with_warrant(warrant, key)
        assert result is b
        assert b._warrant is warrant
        assert b._signing_key is key


class TestOnDenial:
    @given(mode=st.sampled_from(["raise", "log", "skip"]))
    def test_valid_modes_accepted(self, mode):
        """Valid denial modes are accepted."""

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        result = b.on_denial(mode)
        assert result is b
        assert b._on_denial == mode

    @given(mode=st.text(min_size=1, max_size=20).filter(
        lambda m: m not in {"raise", "log", "skip"}
    ))
    @settings(max_examples=20)
    def test_invalid_modes_rejected(self, mode):
        """Invalid denial modes raise ValueError."""

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        with pytest.raises(ValueError):
            b.on_denial(mode)


class TestWithTrustedRoots:
    @given(n=st.integers(min_value=1, max_value=5))
    @settings(max_examples=10)
    def test_stores_copy_of_roots(self, n):
        """with_trusted_roots stores a copy, not the original list."""
        keys = [SigningKey.generate().public_key for _ in range(n)]

        class TestBuilder(BaseGuardBuilder["TestBuilder"]):
            def build(self): ...

        b = TestBuilder()
        original = list(keys)
        b.with_trusted_roots(original)
        assert b._trusted_roots == keys
        assert b._trusted_roots is not original


class TestValidateWarrantForBinding:
    def test_none_key_raises(self):
        """validate_warrant_for_binding raises when signing_key is None."""
        with pytest.raises(MissingSigningKey):
            validate_warrant_for_binding(MagicMock(), None)

    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_matching_holder_succeeds(self, data):
        """When key matches holder, validation succeeds."""
        warrant, key, tool, args = data
        result = validate_warrant_for_binding(warrant, key)
        assert result.bound_warrant is not None

    def test_mismatched_holder_raises(self):
        """When key doesn't match holder, validation raises ConfigurationError."""
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        other = SigningKey.generate()
        w = Warrant.issue(
            keypair=issuer, capabilities={"test": {}},
            ttl_seconds=3600, holder=holder.public_key,
        )
        with pytest.raises(ConfigurationError, match="does not match"):
            validate_warrant_for_binding(w, other, check_holder=True)
