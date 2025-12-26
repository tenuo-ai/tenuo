"""
Capability API Tests

Tests for the Capability-based Tier 1 API:
- Capability.merge() behavior
- grant() boundaries  
- ensure_constraint() behavior
- Capability object handling
"""

import pytest

from tenuo import (
    Capability,
    Pattern,
    Range,
    Exact,
    SigningKey,
    configure,
    reset_config,
    mint_sync,
    grant,
    ConfigurationError,
    MonotonicityError,
)
from tenuo.exceptions import ScopeViolation
from tenuo.constraints import ensure_constraint
from tenuo.decorators import warrant_scope


@pytest.fixture(autouse=True)
def reset_config_fixture():
    """Reset config before and after each test."""
    reset_config()
    yield
    reset_config()


@pytest.fixture
def keypair():
    """Generate a fresh keypair for testing."""
    kp = SigningKey.generate()
    configure(issuer_key=kp, dev_mode=True)
    return kp


class TestCapabilityMerge:
    """Tests for Capability.merge() security."""

    def test_duplicate_tool_last_wins(self, keypair):
        """
        Attack: Merge two Capabilities for same tool with different constraints.
        
        Expected: Last one wins (documented behavior), no security bypass.
        """
        print("\n--- Capability Merge: Duplicate Tool ---")
        
        cap1 = Capability("read_file", path=Pattern("/data/*"))
        cap2 = Capability("read_file", path=Pattern("/etc/*"))  # More permissive
        
        merged = Capability.merge(cap1, cap2)
        
        # Last wins
        assert "read_file" in merged
        assert merged["read_file"]["path"].pattern == "/etc/*"
        
        print("  [Info] Duplicate tools: last Capability wins")
        print("  [Note] This is documented behavior, not a bug")
        print("  [Result] No security bypass (order is explicit)")

    def test_merge_empty_capability(self, keypair):
        """
        Attack: Merge empty Capability to grant unconstrained access.
        
        Expected: Empty constraints = allowed for any args (documented).
        """
        print("\n--- Capability Merge: Empty Constraints ---")
        
        # Empty capability = "tool allowed with any args"
        cap_empty = Capability("admin")
        cap_constrained = Capability("read_file", path=Pattern("/data/*"))
        
        merged = Capability.merge(cap_empty, cap_constrained)
        
        # admin has no constraints
        assert merged["admin"] == {}
        
        # read_file has constraints
        assert "path" in merged["read_file"]
        
        print("  [Info] Empty Capability = unconstrained access to tool")
        print("  [Note] This is intentional for tools like 'ping' or 'health'")
        print("  [Result] Documented behavior, not a bypass")

    def test_merge_preserves_constraint_types(self, keypair):
        """
        Verify: Capability.merge() preserves constraint object types.
        """
        print("\n--- Capability Merge: Type Preservation ---")
        
        cap = Capability(
            "transfer",
            amount=Range(max=1000),
            recipient=Pattern("user-*"),
            status=Exact("approved")
        )
        
        merged = Capability.merge(cap)
        
        # Types should be preserved
        assert isinstance(merged["transfer"]["amount"], Range)
        assert isinstance(merged["transfer"]["recipient"], Pattern)
        assert isinstance(merged["transfer"]["status"], Exact)
        
        print("  [Result] Constraint types preserved through merge")


class TestScopedTaskBoundaries:
    """Tests for grant() authorization boundaries."""

    def test_scoped_task_requires_capabilities(self, keypair):
        """
        Attack: Call grant() without any capabilities.
        
        Expected: ConfigurationError raised.
        """
        print("\n--- grant: No Capabilities ---")
        
        with mint_sync(Capability("read_file", path=Pattern("/data/*"))):
            with pytest.raises(ConfigurationError, match="requires at least one Capability"):
                with grant():  # No capabilities
                    pass
        
        print("  [Result] Empty grant() blocked")

    def test_scoped_task_tool_not_in_parent(self, keypair):
        """
        Attack: grant() for tool not in parent's capabilities.
        
        Expected: ScopeViolation raised.
        """
        print("\n--- grant: Tool Not In Parent ---")
        
        with mint_sync(Capability("read_file", path=Pattern("/data/*"))):
            with pytest.raises(ScopeViolation, match="not in parent"):
                with grant(Capability("write_file", path=Pattern("/data/*"))):
                    pass
        
        print("  [Result] Tool expansion blocked at grant")

    def test_scoped_task_widens_constraint(self, keypair):
        """
        Attack: grant() with wider constraint than parent.
        
        Expected: MonotonicityError raised.
        """
        print("\n--- grant: Constraint Widening ---")
        
        with mint_sync(Capability("read_file", path=Pattern("/data/reports/*"))):
            with pytest.raises(MonotonicityError):
                with grant(Capability("read_file", path=Pattern("/data/*"))):
                    pass
        
        print("  [Result] Constraint widening blocked at grant")

    def test_scoped_task_narrows_correctly(self, keypair):
        """
        Verify: grant() correctly narrows capabilities.
        """
        print("\n--- grant: Correct Narrowing ---")
        
        with mint_sync(
            Capability("read_file", path=Pattern("/data/*")),
            Capability("write_file", path=Pattern("/data/*")),
        ):
            parent = warrant_scope()
            assert sorted(parent.tools) == ["read_file", "write_file"]
            
            with grant(Capability("read_file", path=Pattern("/data/reports/*"))):
                child = warrant_scope()
                
                # Tools narrowed
                assert child.tools == ["read_file"]
                
                # Constraint narrowed
                assert child.capabilities["read_file"]["path"].pattern == "/data/reports/*"
        
        print("  [Result] grant correctly narrows tools and constraints")

    def test_scoped_task_cannot_add_constraint_field(self, keypair):
        """
        Attack: Add new constraint field not in parent.
        
        Expected: Allowed (narrowing), but parent constraints inherited.
        """
        print("\n--- grant: New Constraint Field ---")
        
        with mint_sync(Capability("read_file", path=Pattern("/data/*"))):
            # Add max_size constraint not in parent
            with grant(Capability("read_file", path=Pattern("/data/reports/*"), max_size=Range(max=1000))):
                child = warrant_scope()
                
                # Both constraints present
                assert "path" in child.capabilities["read_file"]
                assert "max_size" in child.capabilities["read_file"]
        
        print("  [Result] New constraint fields allowed (narrowing)")


class TestEnsureConstraint:
    """Tests for ensure_constraint() security."""

    def test_ensure_wraps_strings(self, keypair):
        """
        Verify: ensure_constraint wraps strings in Exact.
        """
        print("\n--- ensure_constraint: String Wrapping ---")
        
        result = ensure_constraint("hello")
        assert isinstance(result, Exact)
        
        # Note: Exact only accepts strings in tenuo_core
        # Integers and booleans must use Range or other types
        
        print("  [Result] Strings wrapped in Exact")

    def test_ensure_preserves_constraints(self, keypair):
        """
        Verify: ensure_constraint passes through constraint objects.
        """
        print("\n--- ensure_constraint: Passthrough ---")
        
        pattern = Pattern("/data/*")
        result = ensure_constraint(pattern)
        assert result is pattern  # Same object
        
        range_c = Range(max=100)
        result = ensure_constraint(range_c)
        assert result is range_c
        
        print("  [Result] Constraint objects passed through unchanged")

    def test_ensure_no_inference(self, keypair):
        """
        Verify: ensure_constraint does NOT infer types.
        
        Security: "foo*" should NOT become Pattern("foo*").
        """
        print("\n--- ensure_constraint: No Type Inference ---")
        
        # String with wildcard should NOT become Pattern
        result = ensure_constraint("foo*")
        assert isinstance(result, Exact)
        assert not isinstance(result, Pattern)
        
        # Verify the value is stored as-is
        assert result.value == "foo*"
        
        print("  [Result] No type inference (explicit is better)")


class TestCapabilityImmutability:
    """Tests for Capability object safety."""

    def test_capability_constraints_isolation(self, keypair):
        """
        Verify: Modifying Capability.constraints after creation
        doesn't affect the warrant.
        """
        print("\n--- Capability: Constraints Isolation ---")
        
        cap = Capability("read_file", path=Pattern("/data/*"))
        
        # Create warrant
        with mint_sync(cap):
            warrant = warrant_scope()
            
            # Mutate capability after creation
            cap.constraints["path"] = Pattern("/*")
            cap.constraints["new_field"] = Exact("hacked")
            
            # Warrant should be unchanged
            assert warrant.capabilities["read_file"]["path"].pattern == "/data/*"
            assert "new_field" not in warrant.capabilities["read_file"]
        
        print("  [Result] Capability mutation doesn't affect issued warrant")

    def test_capability_to_dict_isolation(self, keypair):
        """
        Verify: Capability.to_dict() returns a copy.
        """
        print("\n--- Capability: to_dict() Isolation ---")
        
        cap = Capability("read_file", path=Pattern("/data/*"))
        
        dict1 = cap.to_dict()
        dict2 = cap.to_dict()
        
        # Mutate one
        dict1["read_file"]["path"] = "hacked"
        
        # Other should be unchanged
        assert dict2["read_file"]["path"].pattern == "/data/*"
        
        print("  [Result] to_dict() returns isolated copy")

