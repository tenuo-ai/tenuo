"""
Basic functionality tests for Tenuo Python SDK.

Tests core functionality: keypair generation, warrant creation, authorization.
"""

import pytest
from tenuo import Keypair, Warrant, Pattern, Exact, Range, PublicKey


class TestKeypair:
    """Tests for Keypair functionality."""
    
    def test_generate_keypair(self):
        """Test keypair generation."""
        keypair = Keypair.generate()
        assert keypair is not None
        
        # Public key should be accessible
        public_key = keypair.public_key()
        assert public_key is not None
        assert len(public_key.to_bytes()) == 32
    
    def test_keypair_from_bytes(self):
        """Test creating keypair from secret key bytes."""
        keypair1 = Keypair.generate()
        secret_bytes = keypair1.secret_key_bytes()
        
        # Convert list to bytes
        secret_bytes_obj = bytes(secret_bytes)
        keypair2 = Keypair.from_bytes(secret_bytes_obj)
        assert bytes(keypair2.public_key().to_bytes()) == bytes(keypair1.public_key().to_bytes())
    
    def test_keypair_sign_and_verify(self):
        """Test signing and verifying messages."""
        keypair = Keypair.generate()
        message = b"test message"
        
        signature = keypair.sign(message)
        assert signature is not None
        assert len(signature.to_bytes()) == 64
        
        # Verify signature
        public_key = keypair.public_key()
        assert public_key.verify(message, signature) is True
        
        # Wrong message should fail
        assert public_key.verify(b"wrong message", signature) is False


class TestWarrant:
    """Tests for Warrant functionality."""
    
    def test_create_warrant(self):
        """Test creating a warrant."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test_tool",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        assert warrant is not None
        assert warrant.tool == "test_tool"
        assert warrant.depth == 0
    
    def test_warrant_authorize_success(self):
        """Test successful authorization."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test_tool",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        result = warrant.authorize(
            tool="test_tool",
            args={"cluster": "staging-web"}
        )
        assert result is True
    
    def test_warrant_authorize_failure(self):
        """Test failed authorization."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test_tool",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Wrong tool
        result = warrant.authorize(
            tool="wrong_tool",
            args={"cluster": "staging-web"}
        )
        assert result is False
        
        # Constraint violation
        result = warrant.authorize(
            tool="test_tool",
            args={"cluster": "production-web"}
        )
        assert result is False
    
    def test_warrant_verify(self):
        """Test warrant signature verification."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test_tool",
            constraints={},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should verify with correct public key
        public_key = keypair.public_key()
        assert warrant.verify(bytes(public_key.to_bytes())) is True
        
        # Should fail with wrong public key
        wrong_keypair = Keypair.generate()
        wrong_public_key = wrong_keypair.public_key()
        assert warrant.verify(bytes(wrong_public_key.to_bytes())) is False
    
    def test_warrant_serialization(self):
        """Test warrant serialization and deserialization."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test_tool",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Serialize
        base64_str = warrant.to_base64()
        assert base64_str is not None
        assert len(base64_str) > 0
        
        # Deserialize
        deserialized = Warrant.from_base64(base64_str)
        assert deserialized.tool == warrant.tool
        assert deserialized.depth == warrant.depth
    
    def test_warrant_attenuation(self):
        """Test warrant attenuation (delegation)."""
        control_keypair = Keypair.generate()
        worker_keypair = Keypair.generate()
        
        root_warrant = Warrant.create(
            tool="manage_cluster",
            constraints={
                "cluster": Pattern("staging-*"),
                "budget": Range.max_value(10000.0)
            },
            ttl_seconds=3600,
            keypair=control_keypair
        )
        
        # Attenuate to narrower constraints
        worker_warrant = root_warrant.attenuate(
            constraints={
                "cluster": Exact("staging-web"),
                "budget": Range.max_value(1000.0)
            },
            keypair=worker_keypair
        )
        
        assert worker_warrant.depth == 1
        assert worker_warrant.parent_id == root_warrant.id
        
        # Worker can access staging-web with $500
        assert worker_warrant.authorize(
            tool="manage_cluster",
            args={"cluster": "staging-web", "budget": 500.0}
        ) is True
        
        # Worker cannot access staging-db
        assert worker_warrant.authorize(
            tool="manage_cluster",
            args={"cluster": "staging-db", "budget": 500.0}
        ) is False
        
        # Worker cannot exceed $1k budget
        assert worker_warrant.authorize(
            tool="manage_cluster",
            args={"cluster": "staging-web", "budget": 2000.0}
        ) is False

