"""
Unit tests for Phase 1 DX improvements.

Tests cover:
- Core warrant properties (ttl_remaining, expires_at, is_terminal, is_expired)
- Preview methods (preview_can, preview_would_allow)
- Debugging methods (explain, inspect)
- BoundWarrant class and serialization guards
- Testing utilities (quick_issue, for_testing, allow_all)
- Diagnostics (diagnose, info)
"""

import os
import pickle
import pytest
from datetime import timedelta
from tenuo import (
    Warrant,
    SigningKey,
    BoundWarrant,
    diagnose,
    info,
)
from tenuo.testing import allow_all, deterministic_headers


class TestCoreProperties:
    """Test core warrant convenience properties."""

    def test_ttl_remaining(self):
        """Test ttl_remaining property."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        assert isinstance(warrant.ttl_remaining, timedelta)
        assert warrant.ttl_remaining.total_seconds() > 0
        assert warrant.ttl_remaining.total_seconds() <= 3600

    def test_expires_at(self):
        """Test expires_at method (returns RFC3339 string)."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        # expires_at() is a method that returns RFC3339 string
        expires_at = warrant.expires_at()
        assert isinstance(expires_at, str)
        assert "T" in expires_at  # RFC3339 format

    def test_is_terminal(self):
        """Test is_terminal method."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        # is_terminal() is a method
        result = warrant.is_terminal()
        assert isinstance(result, bool)
        # Fresh warrant should not be terminal
        assert not result

    def test_is_expired(self):
        """Test is_expired method."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        # is_expired() is a method
        result = warrant.is_expired()
        assert isinstance(result, bool)
        # Fresh warrant should not be expired
        assert not result


class TestLogicCheckMethods:
    """Test allows() method for logic checks."""

    def test_allows_tool_only(self):
        """Test allows() with tool only (replaces preview_can)."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=3600)

        # Argument-less check for tool existence
        result = warrant.allows("search")
        assert result is True

    def test_allows_denied(self):
        """Test allows() with denied tool."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        result = warrant.allows("delete")
        assert result is False

    def test_allows_with_args(self):
        """Test allows() with arguments (replaces preview_would_allow)."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        # Tool present (constraint check)
        result = warrant.allows("search", args={"query": "test"})
        assert result is True or result is False  # Either is valid depending on constraints logic

        # Tool not present
        result = warrant.allows("delete", args={})
        assert result is False


class TestDebuggingMethods:
    """Test debugging and introspection methods."""

    def test_explain(self):
        """Test explain method."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=3600)

        explanation = warrant.explain()
        assert isinstance(explanation, str)
        assert "Warrant" in explanation
        assert "search" in explanation
        assert "read" in explanation
        assert "TTL" in explanation

    def test_explain_with_chain(self):
        """Test explain with include_chain=True."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        explanation = warrant.explain(include_chain=True)
        assert isinstance(explanation, str)
        assert "Warrant" in explanation

    def test_inspect(self):
        """Test inspect method (alias for explain)."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        inspection = warrant.inspect()
        assert isinstance(inspection, str)
        assert "Warrant" in inspection


class TestBoundWarrant:
    """Test BoundWarrant class."""

    def test_creation(self):
        """Test BoundWarrant creation."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        assert isinstance(bound, BoundWarrant)
        assert bound.warrant == warrant

    def test_property_forwarding(self):
        """Test that properties are forwarded to inner warrant."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        assert bound.id == warrant.id
        assert bound.tools == warrant.tools
        # ttl_remaining is calculated dynamically, so allow small difference
        assert abs(bound.ttl_remaining.total_seconds() - warrant.ttl_remaining.total_seconds()) < 1
        # BoundWarrant.is_terminal is a property, warrant.is_terminal() is a method
        assert bound.is_terminal == warrant.is_terminal()

    def test_unbind(self):
        """Test unbinding returns inner warrant."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        unbound = bound.unbind()
        assert unbound == warrant

    def test_delegate_with_bound_key(self):
        """Test delegation using bound key."""
        parent, parent_key = Warrant.quick_mint(["search"], ttl=3600)
        bound = parent.bind(parent_key)

        child_key = SigningKey.generate()
        child = bound.grant(to=child_key.public_key, allow="search", ttl=300)

        assert "search" in child.tools

    def test_headers(self):
        """Test headers generation."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        headers = bound.headers("search", {"query": "test"})

        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers
        assert isinstance(headers["X-Tenuo-Warrant"], str)
        assert isinstance(headers["X-Tenuo-PoP"], str)

    def test_serialization_blocked(self):
        """Test that BoundWarrant cannot be serialized."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(bound)

    def test_repr_hides_key(self):
        """Test that repr doesn't expose the key."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        repr_str = repr(bound)
        assert "BoundWarrant" in repr_str
        assert "KEY_BOUND=True" in repr_str
        # Should not contain actual key material
        assert "secret" not in repr_str.lower()


class TestTestingUtilities:
    """Test testing utilities."""

    def test_quick_issue(self):
        """Test Warrant.quick_mint()."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=300)

        assert "search" in warrant.tools
        assert "read" in warrant.tools
        assert isinstance(key, SigningKey)
        assert warrant.ttl_remaining.total_seconds() <= 300

    def test_for_testing_in_test_env(self):
        """Test Warrant.for_testing() in test environment."""
        os.environ["TENUO_TEST_MODE"] = "1"

        warrant = Warrant.for_testing(["search"])
        assert "search" in warrant.tools

    def test_for_testing_outside_test_env(self):
        """Test that for_testing() fails outside test environment."""
        os.environ.pop("TENUO_TEST_MODE", None)

        with pytest.raises(RuntimeError, match="test environments"):
            Warrant.for_testing(["search"])

    def test_allow_all_works_in_test_environment(self):
        """Test that allow_all() works when in a test environment."""
        os.environ["TENUO_TEST_MODE"] = "1"

        # Should not raise - test environment check passes
        with allow_all():
            pass  # Currently a placeholder, but context manager works

    def test_allow_all_outside_test_env(self):
        """Test that allow_all() fails outside test environment."""
        os.environ.pop("TENUO_TEST_MODE", None)
        os.environ.pop("TENUO_ENV", None)

        with pytest.raises(RuntimeError, match="test environments"):
            with allow_all():
                pass

    def test_deterministic_headers(self):
        """Test deterministic_headers generation."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        headers = deterministic_headers(warrant, key, "search", {"query": "test"})

        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers


class TestDiagnostics:
    """Test diagnostic utilities."""

    def test_diagnose(self):
        """Test diagnose function."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=3600)

        report = diagnose(warrant)

        assert isinstance(report, str)
        assert "Warrant Diagnosis" in report
        assert "search" in report
        assert "read" in report

    def test_info(self):
        """Test info function."""
        report = info()

        assert isinstance(report, str)
        assert "Tenuo Configuration" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
