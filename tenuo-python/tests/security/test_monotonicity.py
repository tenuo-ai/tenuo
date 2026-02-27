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
from tenuo_core import Cidr, UrlPattern

from tenuo import (
    CEL,
    ConstraintViolation,
    Contains,
    MonotonicityError,
    NotOneOf,
    OneOf,
    Pattern,
    Range,
    Subpath,
    Subset,
    UrlSafe,
    Warrant,
    Wildcard,
)
from tenuo.constraints import Constraints
from tenuo.exceptions import EmptyResultSet, PatternExpanded, WildcardExpansion


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
            keypair=keypair, capabilities=Constraints.for_tool("search", {"query": Pattern("allowed*")}), ttl_seconds=60
        )

        print("  [Attack 3A] Attempting to widen constraints...")
        with pytest.raises(PatternExpanded):
            builder = parent.grant_builder()
            builder.capability("search", {"query": Pattern("*")})
            builder.grant(keypair)

        print("  [Result] Attack 3A blocked (Monotonicity enforced)")

    def test_attack_3b_add_unauthorized_tool(self, keypair):
        """
        Attack: Add tool not in parent's allowed tools.

        Defense: MonotonicityError blocks tool addition.
        """
        print("\n--- Attack 3B: Add Unauthorized Tool ---")

        parent = Warrant.issue(
            keypair=keypair, capabilities=Constraints.for_tool("search", {"query": Pattern("allowed*")}), ttl_seconds=60
        )

        print("  [Attack 3B] Attempting to add unauthorized tool via capability...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            # Try to add a capability for a tool not in the parent
            builder.capability("delete", {})
            builder.grant(keypair)

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
            ttl_seconds=3600,
        )

        # Attenuate inheriting all constraints (POLA)
        builder = parent.grant_builder()
        builder.inherit_all()  # POLA: constraints inherited
        child = builder.grant(keypair)

        print(f"  [Check] Parent capabilities: {parent.capabilities}")
        print(f"  [Check] Child capabilities: {child.capabilities}")

        # Try to read /etc/passwd (should fail)
        if child.check_constraints("read_file", {"path": "/etc/passwd"}) is None:
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
            ttl_seconds=3600,
        )

        # Attack A: Replace with always-true
        print("  [Attack 23A] Attempting to replace with 'true' expression...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("spend", {"budget_check": CEL("true")})
            builder.grant(keypair)

        print("  [Result] Attack 23A blocked (CEL attenuation enforces conjunction)")

        # Attack B: OR to widen
        print("  [Attack 23B] Attempting to OR with broader condition...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("spend", {"budget_check": CEL("budget < 10000 || true")})
            builder.grant(keypair)

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
            ttl_seconds=3600,
        )

        print("  [Attack 26] Attempting to change Pattern to Range...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("read_file", {"path": Range(max=100)})
            builder.grant(keypair)

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
            ttl_seconds=3600,
        )

        print("  [Attack 27] Attempting to attenuate Pattern to Wildcard...")
        with pytest.raises(WildcardExpansion):
            builder = parent.grant_builder()
            builder.capability("search", {"query": Wildcard()})
            builder.grant(keypair)

        print("  [Result] Attack 27 blocked (Cannot attenuate to Wildcard)")

    def test_attack_28_ttl_extension(self, keypair):
        """
        Attack: Extend TTL during attenuation.

        Defense: Child TTL is clamped to parent's remaining TTL.
        """
        print("\n--- Attack 28: TTL Extension ---")

        parent = Warrant.issue(keypair=keypair, capabilities=Constraints.for_tool("search", {}), ttl_seconds=600)

        print("  [Attack 28] Attempting to extend TTL from 600s to 3600s...")

        builder = parent.grant_builder()
        builder.inherit_all()  # POLA: explicit inheritance
        builder.ttl(3600)  # Try to extend
        child = builder.grant(keypair)

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
            ttl_seconds=3600,
        )

        print("  [Attack 34] Attempting to exclude all parent values...")
        with pytest.raises(EmptyResultSet):
            builder = parent.grant_builder()
            builder.capability("action", {"type": NotOneOf(["read", "write"])})
            builder.grant(keypair)

        print("  [Result] Attack 34 blocked (Empty result set detected)")

    def test_attack_37_notoneof_without_positive(self, keypair):
        """
        Attack: Create warrant with only NotOneOf (denylist without allowlist).

        Note: This is legal but discouraged. Not a Tenuo bug.
        """
        print("\n--- Attack 37: NotOneOf Without Positive Constraint ---")

        print("  [Attack 37] Creating warrant with only NotOneOf constraint...")

        warrant = Warrant.issue(
            keypair=keypair, capabilities=Constraints.for_tool("query", {"env": NotOneOf(["prod"])}), ttl_seconds=3600
        )

        # Allows everything except prod
        if warrant.check_constraints("query", {"env": "staging"}) is None:
            print("  [Info] NotOneOf without positive constraint accepted (Legal but risky)")

        if warrant.check_constraints("query", {"env": "prod"}) is None:
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
            ttl_seconds=3600,
        )

        print("  [Attack 38A] Attempting to attenuate Contains to Subset...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("access", {"permissions": Subset(["read", "write"])})
            builder.grant(keypair)

        print("  [Result] Attack 38A blocked (Incompatible types)")

        # Valid Contains attenuation (adding more required values)
        print("  [Attack 38B] Attenuating Contains to require more values...")
        builder = parent.grant_builder()
        builder.capability("access", {"permissions": Contains(["read", "write"])})
        _child = builder.grant(keypair)

        print("  [Result] Attack 38B: Valid attenuation (Contains can add requirements)")

    def test_attack_11_tool_wildcard_exploitation(self, keypair):
        """
        Attack: Exploit tools=["*"] to gain all tools.

        Note: Tenuo doesn't support wildcard tool syntax.
        """
        print("\n--- Attack 11: Tool Wildcard Exploitation ---")

        warrant = Warrant.issue(keypair=keypair, capabilities={"search": {}, "read": {}, "write": {}}, ttl_seconds=3600)

        # Attenuation should narrow tools (POLA: inherit_all first, then narrow)
        builder = warrant.grant_builder()
        builder.inherit_all()
        builder.tools(["search"])
        child = builder.grant(keypair)

        assert child.tools == ["search"]
        print("  [Result] Attack 11 N/A (Tenuo doesn't support wildcard tools syntax)")

    # =========================================================================
    # Subpath Constraint Tests (Path Traversal Protection)
    # =========================================================================

    def test_subpath_valid_narrowing(self, keypair):
        """
        Valid: Subpath('/data') -> Subpath('/data/reports') is allowed.
        """
        print("\n--- Subpath: Valid Narrowing ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {"path": Subpath("/data")}),
            ttl_seconds=3600,
        )

        builder = parent.grant_builder()
        builder.capability("read_file", {"path": Subpath("/data/reports")})
        child = builder.grant(keypair)

        print(f"  [Check] Child path constraint: {child.capabilities['read_file']['path']}")
        # Verify the attenuation was successful
        assert child is not None
        assert "read_file" in child.tools
        print("  [Result] Subpath narrowing works correctly")

    def test_subpath_widening_blocked(self, keypair):
        """
        Attack: Subpath('/data/reports') -> Subpath('/data') widens access.

        Defense: ConstraintViolation blocks widening.
        """
        print("\n--- Attack: Subpath Widening ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {"path": Subpath("/data/reports")}),
            ttl_seconds=3600,
        )

        print("  [Attack] Attempting to widen Subpath('/data/reports') to Subpath('/data')...")
        with pytest.raises((MonotonicityError, ConstraintViolation)):
            builder = parent.grant_builder()
            builder.capability("read_file", {"path": Subpath("/data")})
            builder.grant(keypair)

        print("  [Result] Attack blocked (Subpath widening rejected)")

    def test_subpath_sibling_blocked(self, keypair):
        """
        Attack: Subpath('/data') -> Subpath('/etc') is unrelated path.

        Defense: ConstraintViolation blocks sibling paths.
        """
        print("\n--- Attack: Subpath Sibling ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {"path": Subpath("/data")}),
            ttl_seconds=3600,
        )

        print("  [Attack] Attempting to change Subpath('/data') to Subpath('/etc')...")
        with pytest.raises((MonotonicityError, ConstraintViolation)):
            builder = parent.grant_builder()
            builder.capability("read_file", {"path": Subpath("/etc")})
            builder.grant(keypair)

        print("  [Result] Attack blocked (Sibling path rejected)")

    # =========================================================================
    # UrlSafe Constraint Tests (SSRF Protection)
    # =========================================================================

    def test_urlsafe_add_domain_allowlist(self, keypair):
        """
        Valid: UrlSafe() -> UrlSafe(allow_domains=[...]) is more restrictive.
        """
        print("\n--- UrlSafe: Add Domain Allowlist ---")

        parent = Warrant.issue(
            keypair=keypair, capabilities=Constraints.for_tool("fetch_url", {"url": UrlSafe()}), ttl_seconds=3600
        )

        builder = parent.grant_builder()
        builder.capability("fetch_url", {"url": UrlSafe(allow_domains=["api.github.com"])})
        child = builder.grant(keypair)

        print(f"  [Check] Child url constraint: {child.capabilities['fetch_url']['url']}")
        # Verify the attenuation was successful
        assert child is not None
        assert "fetch_url" in child.tools
        print("  [Result] UrlSafe domain allowlist attenuation works correctly")

    def test_urlsafe_remove_domain_allowlist_blocked(self, keypair):
        """
        Attack: UrlSafe(allow_domains=[...]) -> UrlSafe() removes restriction.

        Defense: MonotonicityError blocks removal.
        """
        print("\n--- Attack: UrlSafe Remove Domain Allowlist ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("fetch_url", {"url": UrlSafe(allow_domains=["api.github.com"])}),
            ttl_seconds=3600,
        )

        print("  [Attack] Attempting to remove domain allowlist...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("fetch_url", {"url": UrlSafe()})
            builder.grant(keypair)

        print("  [Result] Attack blocked (Domain allowlist removal rejected)")

    def test_urlsafe_widen_domain_allowlist_blocked(self, keypair):
        """
        Attack: UrlSafe(allow_domains=['a']) -> UrlSafe(allow_domains=['a', 'b']) widens.

        Defense: MonotonicityError blocks widening.
        """
        print("\n--- Attack: UrlSafe Widen Domain Allowlist ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("fetch_url", {"url": UrlSafe(allow_domains=["api.github.com"])}),
            ttl_seconds=3600,
        )

        print("  [Attack] Attempting to add evil.com to allowed domains...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("fetch_url", {"url": UrlSafe(allow_domains=["api.github.com", "evil.com"])})
            builder.grant(keypair)

        print("  [Result] Attack blocked (Domain allowlist widening rejected)")

    # =========================================================================
    # Cidr Constraint Tests (IP Network Containment)
    # =========================================================================

    def test_cidr_valid_subnet_narrowing(self, keypair):
        """
        Valid: Cidr('10.0.0.0/8') -> Cidr('10.1.0.0/16') is a subnet.
        """
        print("\n--- Cidr: Valid Subnet Narrowing ---")

        parent = Warrant.issue(
            keypair=keypair, capabilities=Constraints.for_tool("connect", {"ip": Cidr("10.0.0.0/8")}), ttl_seconds=3600
        )

        builder = parent.grant_builder()
        builder.capability("connect", {"ip": Cidr("10.1.0.0/16")})
        child = builder.grant(keypair)

        print(f"  [Check] Child ip constraint: {child.capabilities['connect']['ip']}")
        # Verify the attenuation was successful
        assert child is not None
        assert "connect" in child.tools
        print("  [Result] Cidr subnet narrowing attenuation works correctly")

    def test_cidr_widening_blocked(self, keypair):
        """
        Attack: Cidr('10.1.0.0/16') -> Cidr('10.0.0.0/8') widens network.

        Defense: MonotonicityError blocks widening.
        """
        print("\n--- Attack: Cidr Widening ---")

        parent = Warrant.issue(
            keypair=keypair, capabilities=Constraints.for_tool("connect", {"ip": Cidr("10.1.0.0/16")}), ttl_seconds=3600
        )

        print("  [Attack] Attempting to widen Cidr('10.1.0.0/16') to Cidr('10.0.0.0/8')...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("connect", {"ip": Cidr("10.0.0.0/8")})
            builder.grant(keypair)

        print("  [Result] Attack blocked (Cidr widening rejected)")

    # =========================================================================
    # UrlPattern Constraint Tests (URL Pattern Matching)
    # =========================================================================

    def test_urlpattern_valid_narrowing(self, keypair):
        """
        Valid: UrlPattern('https://*.example.com/*') -> UrlPattern('https://api.example.com/*')
        """
        print("\n--- UrlPattern: Valid Narrowing ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("fetch", {"url": UrlPattern("https://*.example.com/*")}),
            ttl_seconds=3600,
        )

        builder = parent.grant_builder()
        builder.capability("fetch", {"url": UrlPattern("https://api.example.com/*")})
        child = builder.grant(keypair)

        print(f"  [Check] Child url constraint: {child.capabilities['fetch']['url']}")
        # Verify the attenuation was successful
        assert child is not None
        assert "fetch" in child.tools
        print("  [Result] UrlPattern narrowing attenuation works correctly")

    def test_urlpattern_widening_blocked(self, keypair):
        """
        Attack: UrlPattern('https://api.example.com/*') -> UrlPattern('https://*.example.com/*')

        Defense: MonotonicityError blocks widening.
        """
        print("\n--- Attack: UrlPattern Widening ---")

        parent = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("fetch", {"url": UrlPattern("https://api.example.com/*")}),
            ttl_seconds=3600,
        )

        print("  [Attack] Attempting to widen UrlPattern...")
        with pytest.raises(MonotonicityError):
            builder = parent.grant_builder()
            builder.capability("fetch", {"url": UrlPattern("https://*.example.com/*")})
            builder.grant(keypair)

        print("  [Result] Attack blocked (UrlPattern widening rejected)")
