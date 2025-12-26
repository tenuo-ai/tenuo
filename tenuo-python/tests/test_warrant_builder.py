"""
Tests for MintBuilder fluent API.

These tests verify that:
1. MintBuilder creates valid execution warrants
2. MintBuilder creates valid issuer warrants
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
)
from tenuo.exceptions import ValidationError
from tenuo_core import Clearance, WarrantType


class TestWarrantBuilderExecution:
    """Tests for execution warrant creation."""
    
    def test_basic_execution_warrant(self):
        """Basic execution warrant with tools and constraints."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tools(["read_file", "write_file"])
            .constraint("path", Pattern("/data/*"))
            .ttl(3600)
            .mint(kp))
        
        assert warrant.tools == ["read_file", "write_file"]
        assert warrant.depth == 0
        assert not warrant.is_expired()
    
    def test_single_tool(self):
        """Single tool using tool() method."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tool("read_file")
            .mint(kp))
        
        assert warrant.tools == ["read_file"]
    
    def test_multiple_constraints(self):
        """Multiple constraints using chained constraint() calls."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tools(["transfer"])
            .constraint("amount", Range(0, 1000))
            .constraint("recipient", Pattern("*@company.com"))
            .constraint("currency", Exact("USD"))
            .mint(kp))
        
        constraints = warrant.capabilities["transfer"]
        assert "amount" in constraints
        assert "recipient" in constraints
        assert "currency" in constraints
    
    def test_constraints_dict(self):
        """Set all constraints at once."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tools(["read"])
            .constraints({
                "path": Pattern("/data/*"),
                "size": Range(0, 1000000),
            })
            .mint(kp))
        
        constraints = warrant.capabilities["read"]
        assert len(constraints) == 2
    
    def test_with_holder(self):
        """Warrant bound to specific holder."""
        issuer_kp = SigningKey.generate()
        holder_kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tools(["read_file"])
            .holder(holder_kp.public_key)
            .mint(issuer_kp))
        
        # Warrant should be bound to holder
        assert warrant.authorized_holder.to_bytes() == holder_kp.public_key.to_bytes()
    
    def test_with_clearance(self):
        """Warrant with explicit clearance."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tools(["admin_task"])
            .clearance(Clearance.INTERNAL)
            .mint(kp))
        
        assert warrant.clearance == Clearance.INTERNAL
    
    def test_with_session_id(self):
        """Warrant with session ID."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .tools(["read_file"])
            .session_id("session-123")
            .mint(kp))
        
        assert warrant.session_id == "session-123"
    
    def test_missing_tools_raises(self):
        """Missing tools should raise ValidationError."""
        kp = SigningKey.generate()
        
        with pytest.raises(ValidationError, match="tools"):
            (Warrant.mint_builder()
                .constraint("path", Pattern("/data/*"))
                .mint(kp))


class TestWarrantBuilderIssuer:
    """Tests for issuer warrant creation."""
    
    def test_basic_issuer_warrant(self):
        """Basic issuer warrant with issuable_tools."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .issuer()
            .issuable_tools(["read_file", "write_file"])
            .clearance(Clearance.INTERNAL)
            .mint(kp))
        
        # Issuer warrants have different structure
        assert warrant.warrant_type == WarrantType.Issuer
        assert warrant.depth == 0
    
    def test_issuer_with_constraint_bounds(self):
        """Issuer warrant with constraint bounds."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .issuable_tools(["read_file"])  # Implicitly sets issuer mode
            .clearance(Clearance.PRIVILEGED)
            .constraint_bound("path", Pattern("/data/*"))
            .constraint_bound("size", Range(0, 1000000))
            .mint(kp))
        
        assert warrant.warrant_type == WarrantType.Issuer
    
    def test_issuer_with_max_depth(self):
        """Issuer warrant with max issue depth."""
        kp = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .issuer()
            .issuable_tools(["read_file"])
            .clearance(Clearance.INTERNAL)
            .max_issue_depth(3)
            .mint(kp))
        
        assert warrant.max_issue_depth == 3
    
    def test_missing_issuable_tools_raises(self):
        """Missing issuable_tools should raise ValidationError."""
        kp = SigningKey.generate()
        
        with pytest.raises(ValidationError, match="issuable_tools"):
            (Warrant.mint_builder()
                .issuer()
                .clearance(Clearance.INTERNAL)
                .mint(kp))


class TestWarrantBuilderPreview:
    """Tests for preview functionality."""
    
    def test_execution_preview(self):
        """Preview execution warrant configuration."""
        builder = (Warrant.mint_builder()
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
        builder = (Warrant.mint_builder()
            .issuer()
            .issuable_tools(["read_file"])
            .clearance(Clearance.INTERNAL)
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
        builder = Warrant.mint_builder()
        
        # Each method should return the builder
        assert builder.tools(["read"]) is builder
        assert builder.tool("write") is builder
        assert builder.constraint("path", Pattern("*")) is builder
        assert builder.constraints({}) is builder
        assert builder.ttl(3600) is builder
        assert builder.holder(kp.public_key) is builder
        assert builder.session_id("test") is builder
        assert builder.clearance(Clearance.INTERNAL) is builder
        assert builder.issuer() is builder
        assert builder.issuable_tools(["read"]) is builder
        assert builder.constraint_bound("x", Pattern("*")) is builder
        assert builder.constraint_bounds({}) is builder
        assert builder.max_issue_depth(3) is builder
    
    def test_builder_reuse(self):
        """Same builder can be used to create multiple warrants."""
        kp1 = SigningKey.generate()
        kp2 = SigningKey.generate()
        
        # Note: This is a fresh builder each time via Warrant.mint_builder()
        # The builder itself is mutable, so reusing the same instance
        # would create warrants with accumulated state
        w1 = Warrant.mint_builder().tools(["read"]).mint(kp1)
        w2 = Warrant.mint_builder().tools(["write"]).mint(kp2)
        
        assert w1.tools == ["read"]
        assert w2.tools == ["write"]


