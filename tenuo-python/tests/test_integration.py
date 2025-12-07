"""
Integration tests demonstrating real-world Tenuo workflows.
"""

import pytest
from tenuo import (
    Keypair, Warrant, Pattern, Exact, Range,
    Authorizer, PublicKey,
    lockdown, set_warrant_context, AuthorizationError
)


class TestDelegationChain:
    """Test multi-level warrant delegation."""
    
    def test_three_level_delegation(self):
        """Test control plane -> orchestrator -> worker delegation."""
        # Control plane
        control_keypair = Keypair.generate()
        root_warrant = Warrant.create(
            tool="manage_infrastructure",
            constraints={
                "cluster": Pattern("*"),  # Any cluster
                "budget": Range.max_value(100000.0)
            },
            ttl_seconds=3600,
            keypair=control_keypair
        )
        
        # Orchestrator
        orchestrator_keypair = Keypair.generate()
        orchestrator_warrant = root_warrant.attenuate(
            constraints={
                "cluster": Pattern("staging-*"),  # Only staging
                "budget": Range.max_value(10000.0)
            },
            keypair=orchestrator_keypair
        )
        
        # Worker
        worker_keypair = Keypair.generate()
        worker_warrant = orchestrator_warrant.attenuate(
            constraints={
                "cluster": Exact("staging-web"),  # Only staging-web
                "budget": Range.max_value(1000.0)
            },
            keypair=worker_keypair
        )
        
        # Verify delegation chain
        assert root_warrant.depth == 0
        assert orchestrator_warrant.depth == 1
        assert worker_warrant.depth == 2
        
        # Worker can only access staging-web with <= $1k
        assert worker_warrant.authorize(
            "manage_infrastructure",
            {"cluster": "staging-web", "budget": 500.0}
        ) is True
        
        # Worker cannot access other clusters
        assert worker_warrant.authorize(
            "manage_infrastructure",
            {"cluster": "staging-db", "budget": 500.0}
        ) is False
        
        # Worker cannot exceed budget
        assert worker_warrant.authorize(
            "manage_infrastructure",
            {"cluster": "staging-web", "budget": 2000.0}
        ) is False


class TestAuthorizer:
    """Test Authorizer for full warrant chain verification."""
    
    def test_authorizer_verify(self):
        """Test Authorizer.verify() method."""
        control_keypair = Keypair.generate()
        control_public_key = control_keypair.public_key()
        
        authorizer = Authorizer.new(control_public_key)
        
        warrant = Warrant.create(
            tool="test",
            constraints={},
            ttl_seconds=3600,
            keypair=control_keypair
        )
        
        # Should verify successfully
        authorizer.verify(warrant)  # Should not raise
    
    def test_authorizer_check(self):
        """Test Authorizer.check() method."""
        control_keypair = Keypair.generate()
        control_public_key = control_keypair.public_key()
        
        authorizer = Authorizer.new(control_public_key)
        
        warrant = Warrant.create(
            tool="test",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=control_keypair
        )
        
        # Should check successfully
        authorizer.check(
            warrant,
            "test",
            {"cluster": "staging-web"},
            None  # No PoP signature
        )  # Should not raise
        
        # Should fail on constraint violation
        with pytest.raises(Exception):  # May raise different exception types
            authorizer.check(
                warrant,
                "test",
                {"cluster": "production-web"},
                None
            )


class TestContextVarWorkflow:
    """Test ContextVar-based workflow (LangChain/FastAPI pattern)."""
    
    def test_context_based_authorization(self):
        """Test authorization using ContextVar pattern."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={"file_path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(tool="read_file")
        def read_file(file_path: str):
            return f"Reading {file_path}"
        
        # Simulate request handler
        def handle_request(file_path: str):
            with set_warrant_context(warrant):
                return read_file(file_path)
        
        # Should succeed
        result = handle_request("/tmp/test.txt")
        assert "/tmp/test.txt" in result
        
        # Should fail
        with pytest.raises(AuthorizationError):
            handle_request("/etc/passwd")

