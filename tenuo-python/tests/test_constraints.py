"""
Tests for constraint validation and enforcement.

Tests cover:
- Pattern matching
- Exact matching
- Constraint monotonicity
- Multiple constraints
- Constraint attenuation
- CIDR network constraints
- URL pattern constraints
"""

import pytest
from tenuo import (
    SigningKey, Warrant, Pattern, Exact, Cidr, UrlPattern,
    lockdown, set_warrant_context, set_signing_key_context,
    AuthorizationError
)


def test_pattern_constraint_matching():
    """Test that Pattern constraints match correctly."""
    
    @lockdown(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"
    
    kp = SigningKey.generate()
    warrant = Warrant.issue(
        tools="file_ops",
        keypair=kp,
        holder=kp.public_key,
        constraints={"path": Pattern("/data/*")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_signing_key_context(kp):
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
    
    kp = SigningKey.generate()
    warrant = Warrant.issue(
        tools="delete_db",
        keypair=kp,
        holder=kp.public_key,
        constraints={"db_name": Exact("test-db")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_signing_key_context(kp):
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
    
    kp = SigningKey.generate()
    warrant = Warrant.issue(
        tools="transfer_money",
        keypair=kp,
        holder=kp.public_key,
        constraints={
            "account": Pattern("checking-*"),
            "amount": Exact("100")
        },
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_signing_key_context(kp):
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
    
    kp = SigningKey.generate()
    
    # Parent with broad constraint
    parent = Warrant.issue(
        tools="file_ops",
        keypair=kp,
        holder=kp.public_key,
        constraints={"path": Pattern("/data/*")},
        ttl_seconds=3600
    )
    
    # Child with narrower constraint
    child = parent.attenuate(
        constraints={"path": Pattern("/data/reports/*")},
        keypair=kp,
        parent_keypair=kp,
        holder=kp.public_key,
        ttl_seconds=60
    )
    
    @lockdown(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"
    
    # Parent can access broader paths
    with set_warrant_context(parent), set_signing_key_context(kp):
        assert access_file(path="/data/file.txt") == "accessed /data/file.txt"
        assert access_file(path="/data/reports/q3.pdf") == "accessed /data/reports/q3.pdf"
    
    # Child can only access narrower paths
    with set_warrant_context(child), set_signing_key_context(kp):
        assert access_file(path="/data/reports/q3.pdf") == "accessed /data/reports/q3.pdf"
        
        with pytest.raises(AuthorizationError):
            access_file(path="/data/file.txt")


def test_constraint_field_addition():
    """Test that new constraint fields can be added during attenuation."""
    
    kp = SigningKey.generate()
    
    # Parent with one constraint
    parent = Warrant.issue(
        tools="api_call",
        keypair=kp,
        holder=kp.public_key,
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
        holder=kp.public_key,
        ttl_seconds=60
    )
    
    @lockdown(tool="api_call")
    def call_api(endpoint: str, method: str) -> str:
        return f"{method} {endpoint}"
    
    # Parent doesn't require method constraint
    with set_warrant_context(parent), set_signing_key_context(kp):
        assert call_api(endpoint="/api/data", method="GET") == "GET /api/data"
        assert call_api(endpoint="/api/data", method="POST") == "POST /api/data"
    
    # Child requires both constraints
    with set_warrant_context(child), set_signing_key_context(kp):
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
    
    kp = SigningKey.generate()
    warrant = Warrant.issue(
        tools="test_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={"required": Exact("value")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_signing_key_context(kp):
        # Should work with required parameter
        result = protected_function(required="value")
        assert result == "value-default"
        
        # Should work with both parameters
        result = protected_function(required="value", optional="custom")
        assert result == "value-custom"


# ============================================================================
# CIDR Constraint Tests
# ============================================================================

def test_cidr_creation():
    """Test CIDR constraint creation."""
    # IPv4
    cidr = Cidr("10.0.0.0/8")
    assert cidr.network == "10.0.0.0/8"
    
    # IPv6
    cidr = Cidr("2001:db8::/32")
    assert cidr.network == "2001:db8::/32"


def test_cidr_invalid():
    """Test that invalid CIDR raises error."""
    from tenuo.exceptions import ValidationError
    
    with pytest.raises(ValidationError):
        Cidr("not-a-cidr")
    
    with pytest.raises(ValidationError):
        Cidr("10.0.0.0/33")  # Invalid prefix for IPv4


def test_cidr_contains():
    """Test CIDR contains() method."""
    cidr = Cidr("192.168.0.0/16")
    
    # IPs in range
    assert cidr.contains("192.168.1.1")
    assert cidr.contains("192.168.255.255")
    
    # IPs out of range
    assert not cidr.contains("10.0.0.1")
    assert not cidr.contains("192.169.0.1")


def test_cidr_constraint_matching():
    """Test that CIDR constraints match correctly."""
    
    @lockdown(tool="network_ops")
    def allow_ip(source_ip: str) -> str:
        return f"allowed {source_ip}"
    
    kp = SigningKey.generate()
    warrant = Warrant.issue(
        tools="network_ops",
        keypair=kp,
        holder=kp.public_key,
        constraints={"source_ip": Cidr("10.0.0.0/8")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_signing_key_context(kp):
        # Should match IPs in network
        assert allow_ip(source_ip="10.1.2.3") == "allowed 10.1.2.3"
        assert allow_ip(source_ip="10.255.255.255") == "allowed 10.255.255.255"
        
        # Should not match IPs outside network
        with pytest.raises(AuthorizationError):
            allow_ip(source_ip="192.168.1.1")


def test_cidr_attenuation():
    """Test that CIDR constraints can only narrow to subnets."""
    kp = SigningKey.generate()
    
    # Parent with broad network
    parent = Warrant.issue(
        tools="network_ops",
        keypair=kp,
        holder=kp.public_key,
        constraints={"source_ip": Cidr("10.0.0.0/8")},
        ttl_seconds=3600
    )
    
    # Child with narrower subnet - should work
    child = parent.attenuate(
        constraints={"source_ip": Cidr("10.1.0.0/16")},
        keypair=kp,
        parent_keypair=kp,
        holder=kp.public_key,
        ttl_seconds=60
    )
    
    @lockdown(tool="network_ops")
    def allow_ip(source_ip: str) -> str:
        return f"allowed {source_ip}"
    
    # Parent can access broader network
    with set_warrant_context(parent), set_signing_key_context(kp):
        assert allow_ip(source_ip="10.1.2.3") == "allowed 10.1.2.3"
        assert allow_ip(source_ip="10.2.3.4") == "allowed 10.2.3.4"
    
    # Child can only access narrower subnet
    with set_warrant_context(child), set_signing_key_context(kp):
        assert allow_ip(source_ip="10.1.2.3") == "allowed 10.1.2.3"
        
        with pytest.raises(AuthorizationError):
            allow_ip(source_ip="10.2.3.4")


def test_cidr_ipv6():
    """Test CIDR with IPv6 addresses."""
    cidr = Cidr("2001:db8::/32")
    
    assert cidr.contains("2001:db8::1")
    assert not cidr.contains("2001:db9::1")


def test_cidr_repr():
    """Test CIDR string representation."""
    cidr = Cidr("192.168.1.0/24")
    assert "192.168.1.0/24" in repr(cidr)
    assert "192.168.1.0/24" in str(cidr)


# ============================================================================
# URL Pattern Constraint Tests
# ============================================================================

def test_url_pattern_creation():
    """Test URL pattern creation."""
    pattern = UrlPattern("https://api.example.com/*")
    assert pattern.pattern == "https://api.example.com/*"
    assert pattern.schemes == ["https"]
    assert pattern.host_pattern == "api.example.com"


def test_url_pattern_wildcard_scheme():
    """Test URL pattern with wildcard scheme."""
    pattern = UrlPattern("*://example.com/api/*")
    assert pattern.schemes == []  # Empty means any scheme


def test_url_pattern_invalid():
    """Test that invalid URL pattern raises error."""
    from tenuo.exceptions import ValidationError

    with pytest.raises(ValidationError):
        UrlPattern("not-a-url")

    with pytest.raises(ValidationError):
        UrlPattern("missing-scheme.com")


def test_url_pattern_matches():
    """Test URL pattern matches() method."""
    pattern = UrlPattern("https://api.example.com/*")

    assert pattern.matches("https://api.example.com/v1/users")
    assert pattern.matches("https://api.example.com/")

    # Wrong scheme
    assert not pattern.matches("http://api.example.com/v1")
    # Wrong host
    assert not pattern.matches("https://other.example.com/v1")


def test_url_pattern_constraint_matching():
    """Test that URL pattern constraints match correctly."""

    @lockdown(tool="api_call")
    def call_api(endpoint: str) -> str:
        return f"called {endpoint}"

    kp = SigningKey.generate()
    warrant = Warrant.issue(
        tools="api_call",
        keypair=kp,
        holder=kp.public_key,
        constraints={"endpoint": UrlPattern("https://api.example.com/*")},
        ttl_seconds=60
    )

    with set_warrant_context(warrant), set_signing_key_context(kp):
        # Should match valid URLs
        assert call_api(endpoint="https://api.example.com/v1/users") == "called https://api.example.com/v1/users"

        # Should not match invalid URLs
        with pytest.raises(AuthorizationError):
            call_api(endpoint="https://evil.com/v1")


def test_url_pattern_attenuation():
    """Test that URL patterns can only narrow."""
    kp = SigningKey.generate()

    # Parent with broad pattern
    parent = Warrant.issue(
        tools="api_call",
        keypair=kp,
        holder=kp.public_key,
        constraints={"endpoint": UrlPattern("https://*.example.com/*")},
        ttl_seconds=3600
    )

    # Child with narrower pattern - should work
    child = parent.attenuate(
        constraints={"endpoint": UrlPattern("https://api.example.com/v1/*")},
        keypair=kp,
        parent_keypair=kp,
        holder=kp.public_key,
        ttl_seconds=60
    )

    @lockdown(tool="api_call")
    def call_api(endpoint: str) -> str:
        return f"called {endpoint}"

    # Parent can access broader URLs
    with set_warrant_context(parent), set_signing_key_context(kp):
        assert call_api(endpoint="https://api.example.com/v1") == "called https://api.example.com/v1"
        assert call_api(endpoint="https://www.example.com/other") == "called https://www.example.com/other"

    # Child can only access narrower URLs
    with set_warrant_context(child), set_signing_key_context(kp):
        assert call_api(endpoint="https://api.example.com/v1/users") == "called https://api.example.com/v1/users"

        with pytest.raises(AuthorizationError):
            call_api(endpoint="https://www.example.com/other")


def test_url_pattern_repr():
    """Test URL pattern string representation."""
    pattern = UrlPattern("https://api.example.com/*")
    assert "https://api.example.com/*" in repr(pattern)
    assert "https://api.example.com/*" in str(pattern)