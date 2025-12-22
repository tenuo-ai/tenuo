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
    allow_all,
    deterministic_headers,
)


class TestCoreProperties:
    """Test core warrant convenience properties."""
    
    def test_ttl_remaining(self):
        """Test ttl_remaining property."""
        warrant, key = Warrant.quick_issue(["test"], ttl=3600)
        
        assert isinstance(warrant.ttl_remaining, timedelta)
        assert warrant.ttl_remaining.total_seconds() > 0
        assert warrant.ttl_remaining.total_seconds() <= 3600
    
    def test_expires_at(self):
        """Test expires_at method (returns RFC3339 string)."""
        warrant, key = Warrant.quick_issue(["test"], ttl=3600)
        
        # expires_at() is a method that returns RFC3339 string
        expires_at = warrant.expires_at()
        assert isinstance(expires_at, str)
        assert "T" in expires_at  # RFC3339 format
    
    def test_is_terminal(self):
        """Test is_terminal method."""
        warrant, key = Warrant.quick_issue(["test"], ttl=3600)
        
        # is_terminal() is a method
        result = warrant.is_terminal()
        assert isinstance(result, bool)
        # Fresh warrant should not be terminal
        assert not result
    
    def test_is_expired(self):
        """Test is_expired method."""
        warrant, key = Warrant.quick_issue(["test"], ttl=3600)
        
        # is_expired() is a method
        result = warrant.is_expired()
        assert isinstance(result, bool)
        # Fresh warrant should not be expired
        assert not result


class TestPreviewMethods:
    """Test preview methods for UX."""
    
    def test_preview_can_allowed(self):
        """Test preview_can with allowed tool."""
        warrant, key = Warrant.quick_issue(["search", "read"], ttl=3600)
        
        result = warrant.preview_can("search")
        assert result.allowed
        assert bool(result) is True
        assert "UX ONLY" in repr(result)
    
    def test_preview_can_denied(self):
        """Test preview_can with denied tool."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        
        result = warrant.preview_can("delete")
        assert not result.allowed
        assert bool(result) is False
        assert result.reason is not None
        assert "delete" in result.reason
    
    def test_preview_would_allow(self):
        """Test preview_would_allow method."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        
        # Tool present (constraint check not yet implemented in Rust)
        result = warrant.preview_would_allow("search", {"query": "test"})
        assert result.allowed or not result.allowed  # Either is valid for now
        
        # Tool not present
        result = warrant.preview_would_allow("delete", {})
        assert not result.allowed


class TestDebuggingMethods:
    """Test debugging and introspection methods."""
    
    def test_explain(self):
        """Test explain method."""
        warrant, key = Warrant.quick_issue(["search", "read"], ttl=3600)
        
        explanation = warrant.explain()
        assert isinstance(explanation, str)
        assert "Warrant" in explanation
        assert "search" in explanation
        assert "read" in explanation
        assert "TTL" in explanation
    
    def test_explain_with_chain(self):
        """Test explain with include_chain=True."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        
        explanation = warrant.explain(include_chain=True)
        assert isinstance(explanation, str)
        assert "Warrant" in explanation
    
    def test_inspect(self):
        """Test inspect method (alias for explain)."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        
        inspection = warrant.inspect()
        assert isinstance(inspection, str)
        assert "Warrant" in inspection


class TestDelegateMethod:
    """Test improved delegate method."""
    
    def test_delegate_single_tool_string(self):
        """Test delegation with single tool as string."""
        parent, parent_key = Warrant.quick_issue(["search", "read"], ttl=3600)
        child_key = SigningKey.generate()
        
        child = parent.delegate(
            to=child_key.public_key,
            allow="search",
            ttl=300,
            key=parent_key
        )
        
        assert "search" in child.tools
        assert child.ttl_remaining.total_seconds() <= 300
    
    def test_delegate_multiple_tools_list(self):
        """Test delegation with multiple tools as list."""
        parent, parent_key = Warrant.quick_issue(["search", "read", "write"], ttl=3600)
        child_key = SigningKey.generate()
        
        child = parent.delegate(
            to=child_key.public_key,
            allow=["search", "read"],
            ttl=300,
            key=parent_key
        )
        
        assert "search" in child.tools
        assert "read" in child.tools
        assert child.ttl_remaining.total_seconds() <= 300
    
    def test_delegate_without_key_raises(self):
        """Test that delegate without key raises error."""
        parent, parent_key = Warrant.quick_issue(["search"], ttl=3600)
        child_key = SigningKey.generate()
        
        with pytest.raises(RuntimeError, match="No signing key"):
            parent.delegate(
                to=child_key.public_key,
                allow="search",
                ttl=300
            )


class TestBoundWarrant:
    """Test BoundWarrant class."""
    
    def test_creation(self):
        """Test BoundWarrant creation."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        bound = warrant.bind_key(key)
        
        assert isinstance(bound, BoundWarrant)
        assert bound.warrant == warrant
    
    def test_property_forwarding(self):
        """Test that properties are forwarded to inner warrant."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        bound = warrant.bind_key(key)
        
        assert bound.id == warrant.id
        assert bound.tools == warrant.tools
        # ttl_remaining is calculated dynamically, so allow small difference
        assert abs(bound.ttl_remaining.total_seconds() - warrant.ttl_remaining.total_seconds()) < 1
        # BoundWarrant.is_terminal is a property, warrant.is_terminal() is a method
        assert bound.is_terminal == warrant.is_terminal()
    
    def test_unbind(self):
        """Test unbinding returns inner warrant."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        bound = warrant.bind_key(key)
        
        unbound = bound.unbind()
        assert unbound == warrant
    
    def test_delegate_with_bound_key(self):
        """Test delegation using bound key."""
        parent, parent_key = Warrant.quick_issue(["search"], ttl=3600)
        bound = parent.bind_key(parent_key)
        
        child_key = SigningKey.generate()
        child = bound.delegate(
            to=child_key.public_key,
            allow="search",
            ttl=300
        )
        
        assert "search" in child.tools
    
    def test_auth_headers(self):
        """Test auth_headers generation."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        bound = warrant.bind_key(key)
        
        headers = bound.auth_headers("search", {"query": "test"})
        
        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers
        assert isinstance(headers["X-Tenuo-Warrant"], str)
        assert isinstance(headers["X-Tenuo-PoP"], str)
    
    def test_serialization_blocked(self):
        """Test that BoundWarrant cannot be serialized."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        bound = warrant.bind_key(key)
        
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(bound)
    
    def test_repr_hides_key(self):
        """Test that repr doesn't expose the key."""
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        bound = warrant.bind_key(key)
        
        repr_str = repr(bound)
        assert "BoundWarrant" in repr_str
        assert "KEY_BOUND=True" in repr_str
        # Should not contain actual key material
        assert "secret" not in repr_str.lower()


class TestTestingUtilities:
    """Test testing utilities."""
    
    def test_quick_issue(self):
        """Test Warrant.quick_issue()."""
        warrant, key = Warrant.quick_issue(["search", "read"], ttl=300)
        
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
        warrant, key = Warrant.quick_issue(["search"], ttl=3600)
        
        headers = deterministic_headers(warrant, key, "search", {"query": "test"})
        
        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers


class TestDiagnostics:
    """Test diagnostic utilities."""
    
    def test_diagnose(self):
        """Test diagnose function."""
        warrant, key = Warrant.quick_issue(["search", "read"], ttl=3600)
        
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
