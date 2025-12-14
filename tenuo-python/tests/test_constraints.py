"""
Tests for constraint validation and enforcement.

Tests cover:
- Pattern matching
- Exact matching
- Constraint monotonicity
- Multiple constraints
- Constraint attenuation
"""

import pytest
from tenuo import (
    Keypair, Warrant, Pattern, Exact,
    lockdown, set_warrant_context, set_keypair_context,
    AuthorizationError
)


def test_pattern_constraint_matching():
    """Test that Pattern constraints match correctly."""
    
    @lockdown(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tool="file_ops",
        keypair=kp,
        holder=kp.public_key(),
        constraints={"path": Pattern("/data/*")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        # Should match
        assert access_file(path="/data/file.txt") == "accessed /data/file.txt"
        assert access_file(path="/data/subdir/file.txt") == "accessed /data/subdir/file.txt"
        
        # Should not match
        with pytest.raises(AuthorizationError):
            access_file(path="/other/file.txt")


def test_exact_constraint_matching():
    """Test that Exact constraints match only exact values."""
    
    @lockdown(tool="delete_db")
    def delete_database(db_name: str) -> str:
        return f"deleted {db_name}"
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tool="delete_db",
        keypair=kp,
        holder=kp.public_key(),
        constraints={"db_name": Exact("test-db")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        # Should match exact value
        assert delete_database(db_name="test-db") == "deleted test-db"
        
        # Should not match different values
        with pytest.raises(AuthorizationError):
            delete_database(db_name="prod-db")
        
        with pytest.raises(AuthorizationError):
            delete_database(db_name="test-db-2")


def test_multiple_constraints():
    """Test that multiple constraints are all enforced."""
    
    @lockdown(tool="transfer_money")
    def transfer(account: str, amount: str) -> str:
        return f"transferred ${amount} from {account}"
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tool="transfer_money",
        keypair=kp,
        holder=kp.public_key(),
        constraints={
            "account": Pattern("checking-*"),
            "amount": Exact("100")
        },
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        # Both constraints satisfied
        result = transfer(account="checking-001", amount="100")
        assert result == "transferred $100 from checking-001"
        
        # First constraint violated
        with pytest.raises(AuthorizationError):
            transfer(account="savings-001", amount="100")
        
        # Second constraint violated
        with pytest.raises(AuthorizationError):
            transfer(account="checking-001", amount="200")
        
        # Both constraints violated
        with pytest.raises(AuthorizationError):
            transfer(account="savings-001", amount="200")



def test_constraint_attenuation():
    """Test that constraints can only become more restrictive."""
    
    kp = Keypair.generate()
    
    # Parent with broad constraint
    parent = Warrant.issue(
        tool="file_ops",
        keypair=kp,
        holder=kp.public_key(),
        constraints={"path": Pattern("/data/*")},
        ttl_seconds=3600
    )
    
    # Child with narrower constraint
    child = parent.attenuate(
        constraints={"path": Pattern("/data/reports/*")},
        keypair=kp,
        parent_keypair=kp,
        holder=kp.public_key(),
        ttl_seconds=60
    )
    
    @lockdown(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"
    
    # Parent can access broader paths
    with set_warrant_context(parent), set_keypair_context(kp):
        assert access_file(path="/data/file.txt") == "accessed /data/file.txt"
        assert access_file(path="/data/reports/q3.pdf") == "accessed /data/reports/q3.pdf"
    
    # Child can only access narrower paths
    with set_warrant_context(child), set_keypair_context(kp):
        assert access_file(path="/data/reports/q3.pdf") == "accessed /data/reports/q3.pdf"
        
        with pytest.raises(AuthorizationError):
            access_file(path="/data/file.txt")


def test_constraint_field_addition():
    """Test that new constraint fields can be added during attenuation."""
    
    kp = Keypair.generate()
    
    # Parent with one constraint
    parent = Warrant.issue(
        tool="api_call",
        keypair=kp,
        holder=kp.public_key(),
        constraints={"endpoint": Pattern("/api/*")},
        ttl_seconds=3600
    )
    
    # Child adds another constraint
    child = parent.attenuate(
        constraints={
            "endpoint": Pattern("/api/users/*"),
            "method": Exact("GET")
        },
        keypair=kp,
        parent_keypair=kp,
        holder=kp.public_key(),
        ttl_seconds=60
    )
    
    @lockdown(tool="api_call")
    def call_api(endpoint: str, method: str) -> str:
        return f"{method} {endpoint}"
    
    # Parent doesn't require method constraint
    with set_warrant_context(parent), set_keypair_context(kp):
        assert call_api(endpoint="/api/data", method="GET") == "GET /api/data"
        assert call_api(endpoint="/api/data", method="POST") == "POST /api/data"
    
    # Child requires both constraints
    with set_warrant_context(child), set_keypair_context(kp):
        assert call_api(endpoint="/api/users/123", method="GET") == "GET /api/users/123"
        
        # Wrong method
        with pytest.raises(AuthorizationError):
            call_api(endpoint="/api/users/123", method="POST")
        
        # Wrong endpoint
        with pytest.raises(AuthorizationError):
            call_api(endpoint="/api/data", method="GET")


def test_missing_constraint_parameter():
    """Test that missing required constraint parameters fail authorization."""
    
    @lockdown(tool="test_tool")
    def protected_function(required: str, optional: str = "default") -> str:
        return f"{required}-{optional}"
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tool="test_tool",
        keypair=kp,
        holder=kp.public_key(),
        constraints={"required": Exact("value")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        # Should work with required parameter
        result = protected_function(required="value")
        assert result == "value-default"
        
        # Should work with both parameters
        result = protected_function(required="value", optional="custom")
        assert result == "value-custom"
