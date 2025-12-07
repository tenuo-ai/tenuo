"""
Tests for Python exception types.
"""

import pytest
from tenuo import (
    Keypair, Warrant, Pattern, Range,
    TenuoError, AuthorizationError, ConstraintError, ConfigurationError
)
from tenuo.decorators import lockdown, set_warrant_context


class TestExceptions:
    """Tests for exception handling."""
    
    def test_authorization_error(self):
        """Test AuthorizationError is raised correctly."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="test")
        def test_function(cluster: str):
            return f"Processing {cluster}"
        
        # Should raise AuthorizationError
        with pytest.raises(AuthorizationError) as exc_info:
            test_function("production-web")
        
        # Check that AuthorizationError was raised (message may vary)
        assert "authorization" in str(exc_info.value).lower() or "warrant" in str(exc_info.value).lower()
    
    def test_exception_hierarchy(self):
        """Test exception inheritance hierarchy."""
        # AuthorizationError should be a subclass of TenuoError
        assert issubclass(AuthorizationError, TenuoError)
        assert issubclass(ConstraintError, TenuoError)
        assert issubclass(ConfigurationError, TenuoError)
    
    def test_no_warrant_error(self):
        """Test error when no warrant in context."""
        @lockdown(tool="test")
        def test_function(cluster: str):
            return f"Processing {cluster}"
        
        # Should raise AuthorizationError when no warrant in context
        with pytest.raises(AuthorizationError) as exc_info:
            test_function("staging-web")
        
        assert "warrant" in str(exc_info.value).lower() or "context" in str(exc_info.value).lower()

