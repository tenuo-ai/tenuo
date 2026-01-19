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
    Warrant,
    SigningKey,
    Pattern,
    guard,
    warrant_scope,
    key_scope,
    Exact,
)
from tenuo.constraints import Constraints
from tenuo.exceptions import ScopeViolation
from tenuo_core import Cidr, UrlPattern


def test_pattern_constraint_matching():
    """Test that Pattern constraints match correctly."""

    @guard(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"

    kp = SigningKey.generate()
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("file_ops", {"path": Pattern("/data/*")}),
        holder=kp.public_key,
        ttl_seconds=60,
    )

    with warrant_scope(warrant), key_scope(kp):
        # Should match
        assert access_file(path="/data/file.txt") == "accessed /data/file.txt"
        assert access_file(path="/data/subdir/file.txt") == "accessed /data/subdir/file.txt"

        # Should not match
        with pytest.raises(ScopeViolation):
            access_file(path="/other/file.txt")


def test_exact_constraint_matching():
    """Test that Exact constraints match only exact values."""

    @guard(tool="delete_db")
    def delete_database(db_name: str) -> str:
        return f"deleted {db_name}"

    kp = SigningKey.generate()
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("delete_db", {"db_name": Exact("test-db")}),
        holder=kp.public_key,
        ttl_seconds=60,
    )

    with warrant_scope(warrant), key_scope(kp):
        # Should match exact value
        assert delete_database(db_name="test-db") == "deleted test-db"

        # Should not match different values
        with pytest.raises(ScopeViolation):
            delete_database(db_name="prod-db")

        with pytest.raises(ScopeViolation):
            delete_database(db_name="test-db-2")


def test_multiple_constraints():
    """Test that multiple constraints are all enforced."""

    @guard(tool="transfer_money")
    def transfer(account: str, amount: str) -> str:
        return f"transferred ${amount} from {account}"

    kp = SigningKey.generate()
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("transfer_money", {"account": Pattern("checking-*"), "amount": Exact("100")}),
        holder=kp.public_key,
        ttl_seconds=60,
    )

    with warrant_scope(warrant), key_scope(kp):
        # Both constraints satisfied
        result = transfer(account="checking-001", amount="100")
        assert result == "transferred $100 from checking-001"

        # First constraint violated
        with pytest.raises(ScopeViolation):
            transfer(account="savings-001", amount="100")

        # Second constraint violated
        with pytest.raises(ScopeViolation):
            transfer(account="checking-001", amount="200")

        # Both constraints violated
        with pytest.raises(ScopeViolation):
            transfer(account="savings-001", amount="200")


def test_constraint_attenuation():
    """Test that constraints can only become more restrictive."""

    kp = SigningKey.generate()

    # Parent with broad constraint
    parent = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("file_ops", {"path": Pattern("/data/*")}),
        holder=kp.public_key,
        ttl_seconds=3600,
    )

    # Child with narrower constraint
    child = parent.attenuate(
        capabilities=Constraints.for_tool("file_ops", {"path": Pattern("/data/reports/*")}),
        signing_key=kp,  # kp signs (they hold parent)
        holder=kp.public_key,
        ttl_seconds=60,
    )

    @guard(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"

    # Parent can access broader paths
    with warrant_scope(parent), key_scope(kp):
        assert access_file(path="/data/file.txt") == "accessed /data/file.txt"
        assert access_file(path="/data/reports/q3.pdf") == "accessed /data/reports/q3.pdf"

    # Child can only access narrower paths
    with warrant_scope(child), key_scope(kp):
        assert access_file(path="/data/reports/q3.pdf") == "accessed /data/reports/q3.pdf"

        with pytest.raises(ScopeViolation):
            access_file(path="/data/file.txt")


def test_constraint_field_addition():
    """Test that new constraint fields can be added during attenuation."""

    kp = SigningKey.generate()

    # Parent with one constraint, allows unknown fields (permissive)
    # Child can then add constraints on those fields (restrictive)
    parent = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool(
            "api_call",
            {
                "endpoint": Pattern("/api/*"),
                "_allow_unknown": True,  # Allow other fields like 'method'
            },
        ),
        holder=kp.public_key,
        ttl_seconds=3600,
    )

    # Child adds another constraint
    child = parent.attenuate(
        capabilities=Constraints.for_tool("api_call", {"endpoint": Pattern("/api/users/*"), "method": Exact("GET")}),
        signing_key=kp,  # kp signs (they hold parent)
        holder=kp.public_key,
        ttl_seconds=60,
    )

    @guard(tool="api_call")
    def call_api(endpoint: str, method: str) -> str:
        return f"{method} {endpoint}"

    # Parent doesn't require method constraint
    with warrant_scope(parent), key_scope(kp):
        assert call_api(endpoint="/api/data", method="GET") == "GET /api/data"
        assert call_api(endpoint="/api/data", method="POST") == "POST /api/data"

    # Child requires both constraints
    with warrant_scope(child), key_scope(kp):
        assert call_api(endpoint="/api/users/123", method="GET") == "GET /api/users/123"

        # Wrong method
        with pytest.raises(ScopeViolation):
            call_api(endpoint="/api/users/123", method="POST")

        # Wrong endpoint
        with pytest.raises(ScopeViolation):
            call_api(endpoint="/api/data", method="GET")


def test_missing_constraint_parameter():
    """Test that missing required constraint parameters fail authorization."""

    @guard(tool="test_tool")
    def protected_function(required: str, optional: str = "default") -> str:
        return f"{required}-{optional}"

    kp = SigningKey.generate()
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool(
            "test_tool",
            {
                "required": Exact("value"),
                "_allow_unknown": True,  # Allow optional parameter
            },
        ),
        holder=kp.public_key,
        ttl_seconds=60,
    )

    with warrant_scope(warrant), key_scope(kp):
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

    @guard(tool="network_ops")
    def allow_ip(source_ip: str) -> str:
        return f"allowed {source_ip}"

    kp = SigningKey.generate()
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("network_ops", {"source_ip": Cidr("10.0.0.0/8")}),
        holder=kp.public_key,
        ttl_seconds=60,
    )

    with warrant_scope(warrant), key_scope(kp):
        # Should match IPs in network
        assert allow_ip(source_ip="10.1.2.3") == "allowed 10.1.2.3"
        assert allow_ip(source_ip="10.255.255.255") == "allowed 10.255.255.255"

        # Should not match IPs outside network
        with pytest.raises(ScopeViolation):
            allow_ip(source_ip="192.168.1.1")


def test_cidr_attenuation():
    """Test that CIDR constraints can only narrow to subnets."""
    kp = SigningKey.generate()

    # Parent with broad network
    parent = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("network_ops", {"source_ip": Cidr("10.0.0.0/8")}),
        holder=kp.public_key,
        ttl_seconds=3600,
    )

    # Child with narrower subnet - should work
    child = parent.attenuate(
        capabilities=Constraints.for_tool("network_ops", {"source_ip": Cidr("10.1.0.0/16")}),
        signing_key=kp,  # kp signs (they hold parent)
        holder=kp.public_key,
        ttl_seconds=60,
    )

    @guard(tool="network_ops")
    def allow_ip(source_ip: str) -> str:
        return f"allowed {source_ip}"

    # Parent can access broader network
    with warrant_scope(parent), key_scope(kp):
        assert allow_ip(source_ip="10.1.2.3") == "allowed 10.1.2.3"
        assert allow_ip(source_ip="10.2.3.4") == "allowed 10.2.3.4"

    # Child can only access narrower subnet
    with warrant_scope(child), key_scope(kp):
        assert allow_ip(source_ip="10.1.2.3") == "allowed 10.1.2.3"

        with pytest.raises(ScopeViolation):
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

    @guard(tool="api_call")
    def call_api(endpoint: str) -> str:
        return f"called {endpoint}"

    kp = SigningKey.generate()
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("api_call", {"endpoint": UrlPattern("https://api.example.com/*")}),
        holder=kp.public_key,
        ttl_seconds=60,
    )

    with warrant_scope(warrant), key_scope(kp):
        # Should match valid URLs
        assert call_api(endpoint="https://api.example.com/v1/users") == "called https://api.example.com/v1/users"

        # Should not match invalid URLs
        with pytest.raises(ScopeViolation):
            call_api(endpoint="https://evil.com/v1")


def test_url_pattern_attenuation():
    """Test that URL patterns can only narrow."""
    kp = SigningKey.generate()

    # Parent with broad pattern
    parent = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("api_call", {"endpoint": UrlPattern("https://*.example.com/*")}),
        holder=kp.public_key,
        ttl_seconds=3600,
    )

    # Child with narrower pattern - should work
    child = parent.attenuate(
        capabilities=Constraints.for_tool("api_call", {"endpoint": UrlPattern("https://api.example.com/v1/*")}),
        signing_key=kp,  # kp signs (they hold parent)
        holder=kp.public_key,
        ttl_seconds=60,
    )

    @guard(tool="api_call")
    def call_api(endpoint: str) -> str:
        return f"called {endpoint}"

    # Parent can access broader URLs
    with warrant_scope(parent), key_scope(kp):
        assert call_api(endpoint="https://api.example.com/v1") == "called https://api.example.com/v1"
        assert call_api(endpoint="https://www.example.com/other") == "called https://www.example.com/other"

    # Child can only access narrower URLs
    with warrant_scope(child), key_scope(kp):
        assert call_api(endpoint="https://api.example.com/v1/users") == "called https://api.example.com/v1/users"

        with pytest.raises(ScopeViolation):
            call_api(endpoint="https://www.example.com/other")


def test_url_pattern_repr():
    """Test URL pattern string representation."""
    pattern = UrlPattern("https://api.example.com/*")
    assert "https://api.example.com/*" in repr(pattern)
    assert "https://api.example.com/*" in str(pattern)


# ============================================================================
# Bidirectional Wildcard Pattern Tests
# ============================================================================


def test_pattern_bidirectional_wildcard_matching():
    """Test that bidirectional wildcard patterns (*mid*) match correctly."""
    # Pattern with wildcards on both sides
    pattern = Pattern("*-prod-*")
    assert pattern.matches("db-prod-primary")
    assert pattern.matches("cache-prod-replica")
    assert pattern.matches("-prod-")  # Minimal match
    assert not pattern.matches("db-staging-primary")
    assert not pattern.matches("prod-only")

    # Another example: *safe*
    pattern = Pattern("*safe*")
    assert pattern.matches("unsafe")
    assert pattern.matches("safeguard")
    assert pattern.matches("is-safe-mode")
    assert not pattern.matches("danger")


def test_pattern_middle_wildcard_matching():
    """Test patterns with wildcard in the middle (prefix-*-suffix)."""
    pattern = Pattern("report-*-2024.pdf")
    assert pattern.matches("report-Q1-2024.pdf")
    assert pattern.matches("report-annual-2024.pdf")
    assert not pattern.matches("report-Q1-2025.pdf")
    assert not pattern.matches("report-2024.pdf")  # Missing middle part


def test_pattern_bidirectional_attenuation():
    """Test that bidirectional patterns require equality for attenuation."""
    from tenuo.exceptions import MonotonicityError

    kp = SigningKey.generate()

    # Parent with bidirectional pattern
    parent = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("resource_ops", {"name": Pattern("*-prod-*")}),
        holder=kp.public_key,
        ttl_seconds=3600,
    )

    # Same pattern: Should work (equality)
    child_same = parent.attenuate(
        capabilities=Constraints.for_tool("resource_ops", {"name": Pattern("*-prod-*")}),
        signing_key=kp,
        holder=kp.public_key,
        ttl_seconds=60,
    )

    @guard(tool="resource_ops")
    def access_resource(name: str) -> str:
        return f"accessed {name}"

    # Child with same pattern works
    with warrant_scope(child_same), key_scope(kp):
        assert access_resource(name="db-prod-primary") == "accessed db-prod-primary"

    # Different pattern: Should fail (even if logically narrower)
    with pytest.raises(MonotonicityError):
        parent.attenuate(
            capabilities=Constraints.for_tool("resource_ops", {"name": Pattern("db-prod-*")}),
            signing_key=kp,
            holder=kp.public_key,
            ttl_seconds=60,
        )

    with pytest.raises(MonotonicityError):
        parent.attenuate(
            capabilities=Constraints.for_tool("resource_ops", {"name": Pattern("*-prod-primary")}),
            signing_key=kp,
            holder=kp.public_key,
            ttl_seconds=60,
        )


def test_pattern_complex_path_matching():
    """Test complex path patterns with multiple wildcards."""
    pattern = Pattern("/data/*/file.txt")
    assert pattern.matches("/data/reports/file.txt")
    assert pattern.matches("/data/x/file.txt")
    assert not pattern.matches("/data/reports/other.txt")
    assert not pattern.matches("/data/file.txt")  # Missing middle segment

    pattern = Pattern("/*/reports/*.pdf")
    assert pattern.matches("/data/reports/q3.pdf")
    assert pattern.matches("/home/reports/annual.pdf")
    assert not pattern.matches("/data/reports/q3.txt")
    assert not pattern.matches("/data/other/q3.pdf")


def test_pattern_complex_attenuation():
    """Test that complex patterns (middle wildcard) require equality."""
    from tenuo.exceptions import MonotonicityError

    kp = SigningKey.generate()

    parent = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("file_ops", {"path": Pattern("/data/*/file.txt")}),
        holder=kp.public_key,
        ttl_seconds=3600,
    )

    # Same pattern: OK
    child_same = parent.attenuate(
        capabilities=Constraints.for_tool("file_ops", {"path": Pattern("/data/*/file.txt")}),
        signing_key=kp,
        holder=kp.public_key,
        ttl_seconds=60,
    )

    @guard(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"

    with warrant_scope(child_same), key_scope(kp):
        assert access_file(path="/data/reports/file.txt") == "accessed /data/reports/file.txt"

    # Different pattern: Rejected
    with pytest.raises(MonotonicityError):
        parent.attenuate(
            capabilities=Constraints.for_tool("file_ops", {"path": Pattern("/data/reports/file.txt")}),
            signing_key=kp,
            holder=kp.public_key,
            ttl_seconds=60,
        )
