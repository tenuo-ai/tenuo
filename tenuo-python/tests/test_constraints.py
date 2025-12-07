"""
Tests for constraint types: Pattern, Exact, Range, OneOf, CEL.
"""

import pytest
from tenuo import Keypair, Warrant, Pattern, Exact, Range, OneOf, CEL


class TestPatternConstraint:
    """Tests for Pattern constraints."""
    
    def test_pattern_matching(self):
        """Test pattern matching."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should match
        assert warrant.authorize("test", {"cluster": "staging-web"}) is True
        assert warrant.authorize("test", {"cluster": "staging-db"}) is True
        
        # Should not match
        assert warrant.authorize("test", {"cluster": "production-web"}) is False
        assert warrant.authorize("test", {"cluster": "staging"}) is False  # No wildcard match


class TestExactConstraint:
    """Tests for Exact constraints."""
    
    def test_exact_matching(self):
        """Test exact value matching."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"db_name": Exact("test-db")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should match exactly
        assert warrant.authorize("test", {"db_name": "test-db"}) is True
        
        # Should not match
        assert warrant.authorize("test", {"db_name": "test-db-backup"}) is False
        assert warrant.authorize("test", {"db_name": "prod-db"}) is False


class TestRangeConstraint:
    """Tests for Range constraints."""
    
    def test_range_max_value(self):
        """Test max value constraint."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"budget": Range.max_value(1000.0)},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should allow values <= max
        assert warrant.authorize("test", {"budget": 500.0}) is True
        assert warrant.authorize("test", {"budget": 1000.0}) is True  # At boundary
        
        # Should reject values > max
        assert warrant.authorize("test", {"budget": 1500.0}) is False
    
    def test_range_min_value(self):
        """Test min value constraint."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"memory": Range.min_value(2.0)},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should allow values >= min
        assert warrant.authorize("test", {"memory": 4.0}) is True
        assert warrant.authorize("test", {"memory": 2.0}) is True  # At boundary
        
        # Should reject values < min
        assert warrant.authorize("test", {"memory": 1.0}) is False
    
    def test_range_between(self):
        """Test range between min and max."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"cpu": Range.between(1, 8)},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should allow values in range
        assert warrant.authorize("test", {"cpu": 4}) is True
        assert warrant.authorize("test", {"cpu": 1}) is True  # At min boundary
        assert warrant.authorize("test", {"cpu": 8}) is True  # At max boundary
        
        # Should reject values outside range
        assert warrant.authorize("test", {"cpu": 0}) is False
        assert warrant.authorize("test", {"cpu": 10}) is False


class TestOneOfConstraint:
    """Tests for OneOf constraints."""
    
    def test_oneof_matching(self):
        """Test one-of value matching."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={"action": OneOf(["restart", "stop", "start"])},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should match values in set
        assert warrant.authorize("test", {"action": "restart"}) is True
        assert warrant.authorize("test", {"action": "stop"}) is True
        assert warrant.authorize("test", {"action": "start"}) is True
        
        # Should not match values outside set
        assert warrant.authorize("test", {"action": "delete"}) is False
        assert warrant.authorize("test", {"action": "restart-backup"}) is False


class TestCELConstraint:
    """Tests for CEL constraints."""
    
    def test_cel_constraint(self):
        """Test CEL expression constraints."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={
                # Each CEL constraint evaluates against its own value
                # "cluster" constraint: value is the cluster string
                "cluster": CEL('value.startsWith("staging")'),
                # "budget" constraint: value is the budget number
                "budget": CEL('value <= 1000.0 && value > 0'),
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Should match CEL expressions
        assert warrant.authorize("test", {"cluster": "staging-web", "budget": 500.0}) is True
        
        # Should reject when CEL expression fails
        assert warrant.authorize("test", {"cluster": "production-web", "budget": 500.0}) is False
        assert warrant.authorize("test", {"cluster": "staging-web", "budget": 1500.0}) is False


class TestMixedConstraints:
    """Tests for combining different constraint types."""
    
    def test_mixed_constraints(self):
        """Test warrant with multiple constraint types."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="manage",
            constraints={
                "cluster": Pattern("staging-*"),           # Pattern
                "environment": Exact("staging"),           # Exact
                "budget": Range.max_value(5000.0),         # Range
                "action": OneOf(["scale", "restart"]),     # OneOf
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # All constraints satisfied
        assert warrant.authorize("manage", {
            "cluster": "staging-web",
            "environment": "staging",
            "budget": 3000.0,
            "action": "scale"
        }) is True
        
        # One constraint fails
        assert warrant.authorize("manage", {
            "cluster": "staging-web",
            "environment": "production",  # Wrong environment
            "budget": 3000.0,
            "action": "scale"
        }) is False

