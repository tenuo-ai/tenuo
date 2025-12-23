"""
Monotonicity Attacks

Tests verifying:
- Capabilities can only shrink (monotonic attenuation)
- Type changes rejected
- Re-widening blocked (Pattern→Wildcard, Range expansion)
- CEL syntactic monotonicity enforced
- Empty result sets detected
"""

import pytest

from tenuo import (
    Warrant, Pattern, Range, Wildcard, OneOf, NotOneOf,
    Contains, Subset, CEL, Constraints,
    PatternExpanded, WildcardExpansion,
    MonotonicityError, EmptyResultSet
)


@pytest.mark.security
@pytest.mark.monotonicity
class TestMonotonicity:
    """Monotonicity violation attacks."""

    def test_attack_3_constraint_widening(self, keypair):
        """
        Attack: Widen constraint from Pattern("allowed*") to Pattern("*").
        
        Defense: PatternExpanded error blocks re-widening.
        """
        print("\n--- Attack 3A: Constraint Widening ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {"query": Pattern("allowed*")}),
            ttl_seconds=60
        )
        
        print("  [Attack 3A] Attempting to widen constraints...")
        with pytest.raises(PatternExpanded):
            builder = parent.attenuate_builder()
            builder.capability("search", {"query": Pattern("*")})
            builder.delegate(keypair)
            
        print("  [Result] Attack 3A blocked (Monotonicity enforced)")

    def test_attack_3b_add_unauthorized_tool(self, keypair):
        """
        Attack: Add tool not in parent's allowed tools.
        
        Defense: MonotonicityError blocks tool addition.
        """
        print("\n--- Attack 3B: Add Unauthorized Tool ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {"query": Pattern("allowed*")}),
            ttl_seconds=60
        )
        
        print("  [Attack 3B] Attempting to add unauthorized tool via capability...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            # Try to add a capability for a tool not in the parent
            builder.capability("delete", {})
            builder.delegate(keypair)
             
        print("  [Result] Attack 3B blocked (Cannot add tools not in parent)")

    def test_attack_12_constraint_removal(self, keypair):
        """
        Attack: Remove constraint during attenuation.
        
        Defense: Constraints are inherited from parent.
        """
        print("\n--- Attack 12: Constraint Removal ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
            ttl_seconds=3600
        )
        
        # Attenuate inheriting all constraints (POLA)
        builder = parent.attenuate_builder()
        builder.inherit_all()  # POLA: constraints inherited
        child = builder.delegate(keypair)
        
        print(f"  [Check] Parent capabilities: {parent.capabilities}")
        print(f"  [Check] Child capabilities: {child.capabilities}")
        
        # Try to read /etc/passwd (should fail)
        if child.authorize("read_file", {"path": "/etc/passwd"}):
            print("  [CRITICAL] Attack 12 SUCCEEDED: Constraint was removed!")
            assert False, "Constraint should be inherited"
        else:
            print("  [Result] Attack 12 blocked (Constraints inherited)")

    def test_attack_23_cel_injection(self, keypair):
        """
        Attack: Inject CEL expression to bypass parent constraint.
        
        Defense: Child CEL must be (parent) && X format.
        """
        print("\n--- Attack 23: CEL Injection ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("spend", {"budget_check": CEL("budget < 10000")}),
            ttl_seconds=3600
        )
        
        # Attack A: Replace with always-true
        print("  [Attack 23A] Attempting to replace with 'true' expression...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.capability("spend", {"budget_check": CEL("true")})
            builder.delegate(keypair)
        
        print("  [Result] Attack 23A blocked (CEL attenuation enforces conjunction)")
        
        # Attack B: OR to widen
        print("  [Attack 23B] Attempting to OR with broader condition...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.capability("spend", {"budget_check": CEL("budget < 10000 || true")})
            builder.delegate(keypair)
        
        print("  [Result] Attack 23B blocked (Must be (parent) && X format)")

    def test_attack_26_constraint_type_substitution(self, keypair):
        """
        Attack: Change constraint type from Pattern to Range.
        
        Defense: IncompatibleConstraintTypes error.
        """
        print("\n--- Attack 26: Constraint Type Substitution ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
            ttl_seconds=3600
        )
        
        print("  [Attack 26] Attempting to change Pattern to Range...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.capability("read_file", {"path": Range(max=100)})
            builder.delegate(keypair)
        
        print("  [Result] Attack 26 blocked (Incompatible types rejected)")

    def test_attack_27_wildcard_rewidening(self, keypair):
        """
        Attack: Attenuate Pattern back to Wildcard.
        
        Defense: WildcardExpansion error blocks re-widening.
        """
        print("\n--- Attack 27: Wildcard Re-widening ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {"query": Pattern("allowed*")}),
            ttl_seconds=3600
        )
        
        print("  [Attack 27] Attempting to attenuate Pattern to Wildcard...")
        with pytest.raises(WildcardExpansion):
            builder = parent.attenuate_builder()
            builder.capability("search", {"query": Wildcard()})
            builder.delegate(keypair)
        
        print("  [Result] Attack 27 blocked (Cannot attenuate to Wildcard)")

    def test_attack_28_ttl_extension(self, keypair):
        """
        Attack: Extend TTL during attenuation.
        
        Defense: Child TTL is clamped to parent's remaining TTL.
        """
        print("\n--- Attack 28: TTL Extension ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {}),
            ttl_seconds=600
        )
        
        print("  [Attack 28] Attempting to extend TTL from 600s to 3600s...")
        
        builder = parent.attenuate_builder()
        builder.inherit_all()  # POLA: explicit inheritance
        builder.ttl(3600)  # Try to extend
        child = builder.delegate(keypair)
        
        # Child's expiration should not be later than parent's
        parent_exp = parent.expires_at()
        child_exp = child.expires_at()
        
        print(f"  [Check] Parent expires: {parent_exp}")
        print(f"  [Check] Child expires: {child_exp}")
        
        # If TTL was truly extended, child would expire after parent
        # The system should clamp it
        assert child_exp <= parent_exp, "Child TTL should be clamped to parent's"
        print("  [Result] Attack 28 blocked (TTL clamped to parent's remaining time)")

    def test_attack_34_oneof_notoneof_paradox(self, keypair):
        """
        Attack: Create empty result set via OneOf + NotOneOf.
        
        Defense: EmptyResultSet detected and rejected.
        """
        print("\n--- Attack 34: OneOf/NotOneOf Paradox ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("action", {"type": OneOf(["read", "write"])}),
            ttl_seconds=3600
        )
        
        print("  [Attack 34] Attempting to exclude all parent values...")
        with pytest.raises(EmptyResultSet):
            builder = parent.attenuate_builder()
            builder.capability("action", {"type": NotOneOf(["read", "write"])})
            builder.delegate(keypair)
        
        print("  [Result] Attack 34 blocked (Empty result set detected)")

    def test_attack_37_notoneof_without_positive(self, keypair):
        """
        Attack: Create warrant with only NotOneOf (denylist without allowlist).
        
        Note: This is legal but discouraged. Not a Tenuo bug.
        """
        print("\n--- Attack 37: NotOneOf Without Positive Constraint ---")
        
        print("  [Attack 37] Creating warrant with only NotOneOf constraint...")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("query", {"env": NotOneOf(["prod"])}),
            ttl_seconds=3600
        )
        
        # Allows everything except prod
        if warrant.authorize("query", {"env": "staging"}):
            print("  [Info] NotOneOf without positive constraint accepted (Legal but risky)")
        
        if warrant.authorize("query", {"env": "prod"}):
            print("  [CRITICAL] NotOneOf didn't block prod!")
            assert False, "NotOneOf should block excluded values"
        else:
            print("  [Result] NotOneOf correctly blocks excluded values")
        
        print("  [Note] This is allowed but discouraged. Use OneOf (allowlist) instead.")

    def test_attack_38_contains_subset_confusion(self, keypair):
        """
        Attack: Confuse Contains vs Subset semantics.
        
        Defense: Incompatible types rejected.
        """
        print("\n--- Attack 38: Contains/Subset Confusion ---")
        
        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("access", {"permissions": Contains(["read"])}),
            ttl_seconds=3600
        )
        
        print("  [Attack 38A] Attempting to attenuate Contains to Subset...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.capability("access", {"permissions": Subset(["read", "write"])})
            builder.delegate(keypair)
        
        print("  [Result] Attack 38A blocked (Incompatible types)")
        
        # Valid Contains attenuation (adding more required values)
        print("  [Attack 38B] Attenuating Contains to require more values...")
        builder = parent.attenuate_builder()
        builder.capability("access", {"permissions": Contains(["read", "write"])})
        _child = builder.delegate(keypair)
        
        print("  [Result] Attack 38B: Valid attenuation (Contains can add requirements)")

    def test_attack_11_tool_wildcard_exploitation(self, keypair):
        """
        Attack: Exploit tools=["*"] to gain all tools.
        
        Note: Tenuo doesn't support wildcard tool syntax.
        """
        print("\n--- Attack 11: Tool Wildcard Exploitation ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities={
                "search": {},
                "read": {},
                "write": {}
            },
            ttl_seconds=3600
        )
        
        # Attenuation should narrow tools (POLA: inherit_all first, then narrow)
        builder = warrant.attenuate_builder()
        builder.inherit_all()
        builder.tools(["search"])
        child = builder.delegate(keypair)

        assert child.tools == ["search"]
        print("  [Result] Attack 11 N/A (Tenuo doesn't support wildcard tools syntax)")
