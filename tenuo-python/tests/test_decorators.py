"""
Tests for @lockdown decorator and ContextVar functionality.
"""

import pytest
from tenuo import (
    Keypair, Warrant, Pattern, Range, Exact,
    lockdown, set_warrant_context, get_warrant_context,
    AuthorizationError
)


class TestLockdownDecorator:
    """Tests for @lockdown decorator."""
    
    def test_lockdown_with_explicit_warrant(self):
        """Test @lockdown with explicit warrant."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="upgrade_cluster",
            constraints={
                "cluster": Pattern("staging-*"),
                "budget": Range.max_value(10000.0)
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="upgrade_cluster")
        def upgrade_cluster(cluster: str, budget: float):
            return f"Upgrading {cluster} with ${budget}"
        
        # Should succeed with authorized args
        result = upgrade_cluster("staging-web", 5000.0)
        assert "staging-web" in result
        
        # Should raise AuthorizationError with unauthorized args
        with pytest.raises(AuthorizationError):
            upgrade_cluster("production-web", 5000.0)
        
        with pytest.raises(AuthorizationError):
            upgrade_cluster("staging-web", 15000.0)
    
    def test_lockdown_with_context(self):
        """Test @lockdown with ContextVar (no explicit warrant)."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="upgrade_cluster",
            constraints={
                "cluster": Pattern("staging-*"),
                "budget": Range.max_value(10000.0)
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(tool="upgrade_cluster")
        def upgrade_cluster(cluster: str, budget: float):
            return f"Upgrading {cluster} with ${budget}"
        
        # Should succeed with warrant in context
        with set_warrant_context(warrant):
            result = upgrade_cluster("staging-web", 5000.0)
            assert "staging-web" in result
        
        # Should raise AuthorizationError without warrant in context
        with pytest.raises(AuthorizationError):
            upgrade_cluster("staging-web", 5000.0)
    
    def test_lockdown_with_extract_args(self):
        """Test @lockdown with custom extract_args function."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={"file_path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        def extract_file_path(file_path: str, **kwargs):
            return {"file_path": file_path}
        
        @lockdown(warrant, tool="read_file", extract_args=extract_file_path)
        def read_file(file_path: str):
            return f"Reading {file_path}"
        
        # Should succeed
        result = read_file("/tmp/test.txt")
        assert "/tmp/test.txt" in result
        
        # Should fail
        with pytest.raises(AuthorizationError):
            read_file("/etc/passwd")


class TestContextVar:
    """Tests for ContextVar warrant management."""
    
    def test_set_warrant_context(self):
        """Test setting warrant in context."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Initially no warrant
        assert get_warrant_context() is None
        
        # Set warrant in context
        with set_warrant_context(warrant):
            context_warrant = get_warrant_context()
            assert context_warrant is not None
            assert context_warrant.tool == warrant.tool
        
        # Context should be cleared after exit
        assert get_warrant_context() is None
    
    def test_nested_contexts(self):
        """Test nested warrant contexts."""
        keypair = Keypair.generate()
        warrant1 = Warrant.create(
            tool="test1",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        warrant2 = Warrant.create(
            tool="test2",
            constraints={"cluster": Exact("staging-web")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        with set_warrant_context(warrant1):
            assert get_warrant_context().tool == "test1"
            
            with set_warrant_context(warrant2):
                assert get_warrant_context().tool == "test2"
            
            # Should revert to outer context
            assert get_warrant_context().tool == "test1"

