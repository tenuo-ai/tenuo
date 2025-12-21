"""
Tests for WarrantBuilder fluent API.

These tests verify that:
1. WarrantBuilder creates valid execution warrants
2. WarrantBuilder creates valid issuer warrants
3. Method chaining works correctly
4. Preview shows correct configuration
5. Validation errors are raised appropriately
"""

import pytest
from tenuo import (
    SigningKey,
    Warrant,
    Pattern,
    Exact,
    Range,
    TrustLevel,
    ValidationError,
    Constraints,
)


class TestWarrantBuilderExecution:
    """Tests for execution warrant creation."""
    
    def test_basic_execution_warrant(self):
        """Basic execution warrant with tools and constraints."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tools(["read_file", "write_file"])
            .constraint("path", Pattern("/data/*"))
            .ttl(3600)
            .issue(kp))
        
        assert warrant.tools == ["read_file", "write_file"]
        assert warrant.depth == 0
        assert not warrant.is_expired()
    
    def test_single_tool(self):
        """Single tool using tool() method."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tool("read_file")
            .issue(kp))
        
        assert warrant.tools == ["read_file"]
    
    def test_multiple_constraints(self):
        """Multiple constraints using chained constraint() calls."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tools(["transfer"])
            .constraint("amount", Range(0, 1000))
            .constraint("recipient", Pattern("*@company.com"))
            .constraint("currency", Exact("USD"))
            .issue(kp))
        
        constraints = warrant.capabilities["transfer"]
        assert "amount" in constraints
        assert "recipient" in constraints
        assert "currency" in constraints
    
    def test_constraints_dict(self):
        """Set all constraints at once."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tools(["read"])
            .constraints({
                "path": Pattern("/data/*"),
                "size": Range(0, 1000000),
            })
            .issue(kp))
        
        constraints = warrant.capabilities["read"]
        assert len(constraints) == 2
    
    def test_with_holder(self):
        """Warrant bound to specific holder."""
        issuer_kp = SigningKey.generate()
        holder_kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tools(["read_file"])
            .holder(holder_kp.public_key)
            .issue(issuer_kp))
        
        # Warrant should be bound to holder
        assert warrant is not None
    
    def test_with_trust_level(self):
        """Warrant with explicit trust level."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tools(["admin_task"])
            .trust_level(TrustLevel.Internal)
            .issue(kp))
        
        assert warrant is not None
    
    def test_with_session_id(self):
        """Warrant with session ID."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .tools(["read_file"])
            .session_id("session-123")
            .issue(kp))
        
        assert warrant is not None
    
    def test_missing_tools_raises(self):
        """Missing tools should raise ValidationError."""
        kp = SigningKey.generate()
        
        with pytest.raises(ValidationError, match="tools"):
            (Warrant.builder()
                .constraint("path", Pattern("/data/*"))
                .issue(kp))


class TestWarrantBuilderIssuer:
    """Tests for issuer warrant creation."""
    
    def test_basic_issuer_warrant(self):
        """Basic issuer warrant with issuable_tools."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .issuer()
            .issuable_tools(["read_file", "write_file"])
            .trust_level(TrustLevel.Internal)
            .issue(kp))
        
        # Issuer warrants have different structure
        assert warrant is not None
        assert warrant.depth == 0
    
    def test_issuer_with_constraint_bounds(self):
        """Issuer warrant with constraint bounds."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .issuable_tools(["read_file"])  # Implicitly sets issuer mode
            .trust_level(TrustLevel.Privileged)
            .constraint_bound("path", Pattern("/data/*"))
            .constraint_bound("size", Range(0, 1000000))
            .issue(kp))
        
        assert warrant is not None
    
    def test_issuer_with_max_depth(self):
        """Issuer warrant with max issue depth."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.builder()
            .issuer()
            .issuable_tools(["read_file"])
            .trust_level(TrustLevel.Internal)
            .max_issue_depth(3)
            .issue(kp))
        
        assert warrant is not None
    
    def test_missing_issuable_tools_raises(self):
        """Missing issuable_tools should raise ValidationError."""
        kp = SigningKey.generate()
        
        with pytest.raises(ValidationError, match="issuable_tools"):
            (Warrant.builder()
                .issuer()
                .trust_level(TrustLevel.Internal)
                .issue(kp))


class TestWarrantBuilderPreview:
    """Tests for preview functionality."""
    
    def test_execution_preview(self):
        """Preview execution warrant configuration."""
        builder = (Warrant.builder()
            .tools(["read_file"])
            .constraint("path", Pattern("/data/*"))
            .ttl(7200))
        
        preview = builder.preview()
        
        assert preview["type"] == "execution"
        assert preview["tools"] == ["read_file"]
        assert preview["ttl_seconds"] == 7200
        assert "path" in preview["constraints"]
    
    def test_issuer_preview(self):
        """Preview issuer warrant configuration."""
        builder = (Warrant.builder()
            .issuer()
            .issuable_tools(["read_file"])
            .trust_level(TrustLevel.Internal)
            .max_issue_depth(5))
        
        preview = builder.preview()
        
        assert preview["type"] == "issuer"
        assert preview["issuable_tools"] == ["read_file"]
        assert preview["max_issue_depth"] == 5


class TestWarrantBuilderMethodChaining:
    """Tests for method chaining and API ergonomics."""
    
    def test_all_methods_return_self(self):
        """All builder methods should return self for chaining."""
        kp = SigningKey.generate()
        builder = Warrant.builder()
        
        # Each method should return the builder
        assert builder.tools(["read"]) is builder
        assert builder.tool("write") is builder
        assert builder.constraint("path", Pattern("*")) is builder
        assert builder.constraints({}) is builder
        assert builder.ttl(3600) is builder
        assert builder.holder(kp.public_key) is builder
        assert builder.session_id("test") is builder
        assert builder.trust_level(TrustLevel.Internal) is builder
        assert builder.issuer() is builder
        assert builder.issuable_tools(["read"]) is builder
        assert builder.constraint_bound("x", Pattern("*")) is builder
        assert builder.constraint_bounds({}) is builder
        assert builder.max_issue_depth(3) is builder
    
    def test_builder_reuse(self):
        """Same builder can be used to create multiple warrants."""
        kp1 = SigningKey.generate()
        kp2 = SigningKey.generate()
        
        # Note: This is a fresh builder each time via Warrant.builder()
        # The builder itself is mutable, so reusing the same instance
        # would create warrants with accumulated state
        w1 = Warrant.builder().tools(["read"]).issue(kp1)
        w2 = Warrant.builder().tools(["write"]).issue(kp2)
        
        assert w1.tools == ["read"]
        assert w2.tools == ["write"]


class TestBackwardCompatibility:
    """Tests that Warrant.issue() still works."""
    
    def test_issue_still_works(self):
        """Warrant.issue() with capabilities."""
        kp = SigningKey.generate()
        
        # New API: capabilities dict
        warrant = Warrant.issue(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
            ttl_seconds=3600,
        )
        
        assert warrant.tools == ["read_file"]
    
    def test_builder_and_issue_equivalent(self):
        """Builder and issue() should create equivalent warrants."""
        kp = SigningKey.generate()
        
        w1 = Warrant.issue(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
            ttl_seconds=3600,
        )
        
        w2 = (Warrant.builder()
            .tool("read_file")
            .constraint("path", Pattern("/data/*"))
            .ttl(3600)
            .issue(kp))
        
        # Both should have the same tools
        assert w1.tools == w2.tools

