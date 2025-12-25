"""
Tests for Tenuo Tier 1 API (3-line API).

Covers:
- Global configuration
- mint and grant context managers
- Tool protection (@guard)
- Containment logic for constraints
"""

import pytest
import asyncio

from tenuo import (
    configure,
    reset_config,
    mint,
    grant,
    guard,
    SigningKey,
    ConfigurationError,
    MonotonicityError,
)
from tenuo.config import get_config
from tenuo.exceptions import ScopeViolation
from tenuo.schemas import ToolSchema, register_schema
from tenuo.scoped import _is_constraint_contained
from tenuo.decorators import warrant_scope

# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def keypair():
    return SigningKey.generate()

@pytest.fixture
def setup_config(keypair):
    """Setup valid configuration for tests."""
    reset_config()
    configure(issuer_key=keypair, dev_mode=True)
    yield
    reset_config()

# =============================================================================
# Configuration Tests
# =============================================================================

def test_configure_sets_global_state(keypair):
    reset_config()
    configure(issuer_key=keypair, dev_mode=True)
    
    config = get_config()
    assert config.issuer_keypair is not None
    assert config.dev_mode is True

def test_configure_validation():
    reset_config()
    
    # Production mode requires trusted_roots
    with pytest.raises(ConfigurationError, match="trusted_roots required"):
        configure(dev_mode=False)
        
    # Passthrough requires dev_mode
    with pytest.raises(ConfigurationError, match="allow_passthrough=True requires dev_mode=True"):
        configure(dev_mode=False, allow_passthrough=True)

# =============================================================================
# Containment Logic Tests - Comprehensive
# =============================================================================

class TestConstraintContainment:
    """Comprehensive tests for _is_constraint_contained used by grant()."""
    
    # -------------------------------------------------------------------------
    # Exact Constraints
    # -------------------------------------------------------------------------
    def test_exact_equality(self):
        from tenuo_core import Exact
        assert _is_constraint_contained(Exact("foo"), Exact("foo"))
        assert not _is_constraint_contained(Exact("foo"), Exact("bar"))
    
    def test_exact_string_fallback(self):
        """Plain strings should work as exact values."""
        assert _is_constraint_contained("foo", "foo")
        assert not _is_constraint_contained("foo", "bar")
    
    # -------------------------------------------------------------------------
    # Wildcard Constraints (Universal Superset)
    # -------------------------------------------------------------------------
    def test_wildcard_contains_anything(self):
        """Wildcard parent contains any child constraint."""
        from tenuo_core import Wildcard, Exact, Pattern, OneOf, Range
        
        wildcard = Wildcard()
        
        # Wildcard contains Exact
        assert _is_constraint_contained(Exact("anything"), wildcard)
        
        # Wildcard contains Pattern
        assert _is_constraint_contained(Pattern("staging-*"), wildcard)
        
        # Wildcard contains OneOf
        assert _is_constraint_contained(OneOf(["a", "b", "c"]), wildcard)
        
        # Wildcard contains Range
        assert _is_constraint_contained(Range(0, 100), wildcard)
        
        # Wildcard contains plain string
        assert _is_constraint_contained("any string", wildcard)
        
        # Wildcard contains another Wildcard
        assert _is_constraint_contained(Wildcard(), wildcard)
    
    def test_wildcard_child_never_contained(self):
        """No parent can contain Wildcard child (would widen permissions)."""
        from tenuo_core import Wildcard, Exact, Pattern, OneOf, Range
        
        wildcard = Wildcard()
        
        # Exact cannot contain Wildcard
        assert not _is_constraint_contained(wildcard, Exact("foo"))
        
        # Pattern cannot contain Wildcard
        assert not _is_constraint_contained(wildcard, Pattern("*"))
        
        # OneOf cannot contain Wildcard
        assert not _is_constraint_contained(wildcard, OneOf(["a", "b"]))
        
        # Range cannot contain Wildcard
        assert not _is_constraint_contained(wildcard, Range(0, 100))
    
    # -------------------------------------------------------------------------
    # Regex Constraints
    # -------------------------------------------------------------------------
    def test_regex_identical_pattern(self):
        """Regex -> Regex: patterns must be identical."""
        from tenuo_core import Regex
        
        parent = Regex(r"^staging-.*$")
        
        # Same pattern is contained
        assert _is_constraint_contained(Regex(r"^staging-.*$"), parent)
        
        # Different pattern is NOT contained (even if semantically narrower)
        assert not _is_constraint_contained(Regex(r"^staging-web$"), parent)
        assert not _is_constraint_contained(Regex(r"^staging-.*-prod$"), parent)
    
    def test_regex_exact_inside(self):
        """Regex -> Exact: exact value must match the regex."""
        from tenuo_core import Regex, Exact
        
        parent = Regex(r"^staging-.*$")
        
        # Matching exact values
        assert _is_constraint_contained(Exact("staging-web"), parent)
        assert _is_constraint_contained(Exact("staging-api-v2"), parent)
        assert _is_constraint_contained(Exact("staging-"), parent)
        
        # Non-matching exact values
        assert not _is_constraint_contained(Exact("production-web"), parent)
        assert not _is_constraint_contained(Exact("dev-staging-web"), parent)
        assert not _is_constraint_contained(Exact("staging"), parent)  # missing dash
    
    def test_regex_string_inside(self):
        """Regex -> string: string must match the regex."""
        from tenuo_core import Regex
        
        parent = Regex(r"^[a-z]+@company\.com$")
        
        # Matching strings
        assert _is_constraint_contained("alice@company.com", parent)
        assert _is_constraint_contained("bob@company.com", parent)
        
        # Non-matching strings
        assert not _is_constraint_contained("Alice@company.com", parent)  # uppercase
        assert not _is_constraint_contained("alice@evil.com", parent)
        assert not _is_constraint_contained("alice123@company.com", parent)  # has numbers
    
    def test_regex_complex_patterns(self):
        """Test regex with complex patterns."""
        from tenuo_core import Regex, Exact
        
        # IP address pattern
        ip_pattern = Regex(r"^192\.168\.\d+\.\d+$")
        assert _is_constraint_contained(Exact("192.168.1.1"), ip_pattern)
        assert _is_constraint_contained(Exact("192.168.255.255"), ip_pattern)
        assert not _is_constraint_contained(Exact("10.0.0.1"), ip_pattern)
        
        # UUID pattern
        uuid_pattern = Regex(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assert _is_constraint_contained(Exact("12345678-1234-1234-1234-123456789abc"), uuid_pattern)
        assert not _is_constraint_contained(Exact("not-a-uuid"), uuid_pattern)
    
    # -------------------------------------------------------------------------
    # Pattern (Glob) Constraints - Suffix Wildcards
    # -------------------------------------------------------------------------
    def test_pattern_suffix_exact_inside(self):
        """Exact value inside suffix wildcard pattern."""
        from tenuo_core import Pattern, Exact
        # /data/* should contain /data/anything
        assert _is_constraint_contained(Exact("/data/reports/q3.pdf"), Pattern("/data/*"))
        assert _is_constraint_contained(Exact("/data/x"), Pattern("/data/*"))
        assert not _is_constraint_contained(Exact("/etc/passwd"), Pattern("/data/*"))
        assert not _is_constraint_contained(Exact("/dataX/file"), Pattern("/data/*"))
    
    def test_pattern_suffix_narrowing(self):
        """Pattern inside pattern - must be more restrictive."""
        from tenuo_core import Pattern
        # /data/reports/* is narrower than /data/*
        assert _is_constraint_contained(Pattern("/data/reports/*"), Pattern("/data/*"))
        assert _is_constraint_contained(Pattern("/data/reports/2024/*"), Pattern("/data/*"))
        # Cannot widen
        assert not _is_constraint_contained(Pattern("/data/*"), Pattern("/data/reports/*"))
        assert not _is_constraint_contained(Pattern("/*"), Pattern("/data/*"))
    
    # -------------------------------------------------------------------------
    # Pattern (Glob) Constraints - Prefix Wildcards
    # -------------------------------------------------------------------------
    def test_pattern_prefix_exact_inside(self):
        """Exact value inside prefix wildcard pattern (e.g., *@company.com)."""
        from tenuo_core import Pattern, Exact
        # *@company.com should contain anything@company.com
        assert _is_constraint_contained(Exact("cfo@company.com"), Pattern("*@company.com"))
        assert _is_constraint_contained(Exact("alice@company.com"), Pattern("*@company.com"))
        assert _is_constraint_contained(Exact("a@company.com"), Pattern("*@company.com"))
        # Should NOT contain
        assert not _is_constraint_contained(Exact("hacker@evil.com"), Pattern("*@company.com"))
        assert not _is_constraint_contained(Exact("cfo@company.com.evil.com"), Pattern("*@company.com"))
        assert not _is_constraint_contained(Exact("@company.comX"), Pattern("*@company.com"))
    
    def test_pattern_prefix_narrowing(self):
        """Prefix pattern narrowing."""
        from tenuo_core import Pattern
        # *-admin@company.com is narrower than *@company.com
        assert _is_constraint_contained(Pattern("*-admin@company.com"), Pattern("*@company.com"))
    
    # -------------------------------------------------------------------------
    # Pattern (Glob) Constraints - Middle Wildcards
    # -------------------------------------------------------------------------
    def test_pattern_middle_exact_inside(self):
        """Exact value inside middle wildcard pattern."""
        from tenuo_core import Pattern, Exact
        # /data/*/file.txt should contain /data/anything/file.txt
        assert _is_constraint_contained(Exact("/data/reports/file.txt"), Pattern("/data/*/file.txt"))
        assert _is_constraint_contained(Exact("/data/x/file.txt"), Pattern("/data/*/file.txt"))
        # Should NOT contain
        assert not _is_constraint_contained(Exact("/data/reports/other.txt"), Pattern("/data/*/file.txt"))
        assert not _is_constraint_contained(Exact("/data/file.txt"), Pattern("/data/*/file.txt"))
    
    # -------------------------------------------------------------------------
    # Pattern (Glob) Constraints - Multiple Wildcards
    # -------------------------------------------------------------------------
    def test_pattern_multiple_wildcards(self):
        """Pattern with multiple wildcards."""
        from tenuo_core import Pattern, Exact
        # /*/reports/*.pdf
        assert _is_constraint_contained(Exact("/data/reports/q3.pdf"), Pattern("/*/reports/*.pdf"))
        assert _is_constraint_contained(Exact("/home/reports/annual.pdf"), Pattern("/*/reports/*.pdf"))
        assert not _is_constraint_contained(Exact("/data/reports/q3.txt"), Pattern("/*/reports/*.pdf"))
    
    # -------------------------------------------------------------------------
    # Range Constraints
    # -------------------------------------------------------------------------
    def test_range_narrowing(self):
        """Child range must be within parent range."""
        from tenuo_core import Range
        parent = Range(0, 100)
        
        # Narrower ranges are contained
        assert _is_constraint_contained(Range(10, 50), parent)
        assert _is_constraint_contained(Range(0, 100), parent)  # Equal is contained
        assert _is_constraint_contained(Range(50, 50), parent)  # Single value
        
        # Wider ranges are NOT contained
        assert not _is_constraint_contained(Range(0, 200), parent)
        assert not _is_constraint_contained(Range(-10, 100), parent)
        assert not _is_constraint_contained(Range(0, 101), parent)
    
    def test_range_max_only(self):
        """Range with only max bound."""
        from tenuo_core import Range
        parent = Range.max_value(100)
        
        assert _is_constraint_contained(Range.max_value(50), parent)
        assert _is_constraint_contained(Range.max_value(100), parent)
        assert not _is_constraint_contained(Range.max_value(150), parent)
    
    def test_range_min_only(self):
        """Range with only min bound."""
        from tenuo_core import Range
        parent = Range.min_value(10)
        
        assert _is_constraint_contained(Range.min_value(20), parent)
        assert _is_constraint_contained(Range.min_value(10), parent)
        assert not _is_constraint_contained(Range.min_value(5), parent)
    
    # -------------------------------------------------------------------------
    # OneOf Constraints
    # -------------------------------------------------------------------------
    def test_oneof_subset(self):
        """Child OneOf must be subset of parent."""
        from tenuo_core import OneOf
        parent = OneOf(["a", "b", "c", "d"])
        
        # Subsets are contained
        assert _is_constraint_contained(OneOf(["a", "b"]), parent)
        assert _is_constraint_contained(OneOf(["a"]), parent)
        assert _is_constraint_contained(OneOf(["a", "b", "c", "d"]), parent)  # Equal
        
        # Supersets or different sets are NOT contained
        assert not _is_constraint_contained(OneOf(["a", "b", "c", "d", "e"]), parent)
        assert not _is_constraint_contained(OneOf(["x", "y"]), parent)
        assert not _is_constraint_contained(OneOf(["a", "x"]), parent)
    
    # -------------------------------------------------------------------------
    # Cross-Type Containment
    # -------------------------------------------------------------------------
    # The following cross-type containments are supported:
    #   Pattern → Exact (exact must match pattern)
    #   OneOf → Exact (exact must be in set)
    #   OneOf → string (string must be in set)
    # -------------------------------------------------------------------------
    
    def test_exact_in_oneof(self):
        """Exact value should be contained if it's in the OneOf set."""
        from tenuo_core import Exact, OneOf
        parent = OneOf(["read", "write", "delete"])
        
        # Exact value that IS in the OneOf set should be contained
        assert _is_constraint_contained(Exact("read"), parent)
        assert _is_constraint_contained(Exact("write"), parent)
        assert _is_constraint_contained(Exact("delete"), parent)
        
        # Exact value NOT in the OneOf set should NOT be contained
        assert not _is_constraint_contained(Exact("execute"), parent)
        assert not _is_constraint_contained(Exact("admin"), parent)
    
    def test_string_in_oneof(self):
        """Plain string value should be contained if it's in the OneOf set."""
        from tenuo_core import OneOf
        parent = OneOf(["staging", "production", "dev"])
        
        # Plain string in set
        assert _is_constraint_contained("staging", parent)
        assert _is_constraint_contained("production", parent)
        
        # Plain string NOT in set
        assert not _is_constraint_contained("local", parent)
        assert not _is_constraint_contained("test", parent)
    
    def test_exact_in_pattern(self):
        """Exact value should be contained if it matches the pattern."""
        from tenuo_core import Pattern, Exact
        
        # Suffix wildcard
        assert _is_constraint_contained(Exact("/data/file.txt"), Pattern("/data/*"))
        assert not _is_constraint_contained(Exact("/etc/passwd"), Pattern("/data/*"))
        
        # Prefix wildcard
        assert _is_constraint_contained(Exact("admin@company.com"), Pattern("*@company.com"))
        assert not _is_constraint_contained(Exact("hacker@evil.com"), Pattern("*@company.com"))
        
        # Middle wildcard
        assert _is_constraint_contained(Exact("/var/log/app.log"), Pattern("/var/*/app.log"))
        assert not _is_constraint_contained(Exact("/var/log/other.log"), Pattern("/var/*/app.log"))
    
    def test_string_in_pattern(self):
        """Plain string value should be contained if it matches the pattern."""
        from tenuo_core import Pattern
        
        # Suffix wildcard
        assert _is_constraint_contained("/data/file.txt", Pattern("/data/*"))
        assert not _is_constraint_contained("/etc/passwd", Pattern("/data/*"))
        
        # Prefix wildcard
        assert _is_constraint_contained("user@company.com", Pattern("*@company.com"))
        assert not _is_constraint_contained("user@other.com", Pattern("*@company.com"))
    
    # -------------------------------------------------------------------------
    # Cross-Type Incompatibilities (should NOT be contained)
    # -------------------------------------------------------------------------
    def test_range_exact_cross_type(self):
        """Range parent CAN contain Exact child if numeric value is within bounds."""
        from tenuo_core import Range, Exact
        # Range parent can contain Exact child with numeric value
        assert _is_constraint_contained(Exact("50"), Range(0, 100))  # In range
        assert not _is_constraint_contained(Exact("200"), Range(0, 100))  # Out of range
        assert not _is_constraint_contained(Exact("abc"), Range(0, 100))  # Non-numeric
    
    def test_incompatible_oneof_pattern(self):
        """OneOf parent cannot contain Pattern child (would need subset check)."""
        from tenuo_core import OneOf, Pattern
        # A Pattern inside OneOf doesn't make semantic sense
        assert not _is_constraint_contained(Pattern("staging-*"), OneOf(["staging-web", "staging-api"]))
    
    def test_incompatible_pattern_oneof(self):
        """Pattern parent with specific pattern won't match OneOf child."""
        from tenuo_core import Pattern, OneOf
        # OneOf child doesn't match specific pattern (not a simple string)
        # Note: Pattern("*") WOULD match because "*" matches anything
        assert not _is_constraint_contained(OneOf(["staging", "prod"]), Pattern("/data/*"))
    
    # -------------------------------------------------------------------------
    # Edge Cases
    # -------------------------------------------------------------------------
    def test_empty_pattern(self):
        """Edge case: empty or minimal patterns."""
        from tenuo_core import Pattern, Exact
        # Single wildcard matches everything
        assert _is_constraint_contained(Exact("anything"), Pattern("*"))
        assert _is_constraint_contained(Exact(""), Pattern("*"))
    
    def test_no_wildcard_pattern(self):
        """Pattern without wildcard is effectively Exact."""
        from tenuo_core import Pattern, Exact
        assert _is_constraint_contained(Exact("/data/file.txt"), Pattern("/data/file.txt"))
        assert not _is_constraint_contained(Exact("/data/other.txt"), Pattern("/data/file.txt"))
    
    # -------------------------------------------------------------------------
    # NotOneOf Constraints
    # -------------------------------------------------------------------------
    def test_notoneof_superset_exclusions(self):
        """NotOneOf child must exclude MORE values (superset of exclusions)."""
        from tenuo_core import NotOneOf
        parent = NotOneOf(["admin", "root"])
        
        # Child excludes MORE - valid narrowing (more restrictive)
        assert _is_constraint_contained(NotOneOf(["admin", "root", "sudo"]), parent)
        assert _is_constraint_contained(NotOneOf(["admin", "root"]), parent)  # Equal
        
        # Child excludes LESS - invalid (would allow more)
        assert not _is_constraint_contained(NotOneOf(["admin"]), parent)
        assert not _is_constraint_contained(NotOneOf(["other"]), parent)
    
    # -------------------------------------------------------------------------
    # Contains Constraints
    # -------------------------------------------------------------------------
    def test_contains_superset_required(self):
        """Contains child must require MORE values (superset of required)."""
        from tenuo_core import Contains
        parent = Contains(["read", "write"])
        
        # Child requires MORE - valid narrowing
        assert _is_constraint_contained(Contains(["read", "write", "execute"]), parent)
        assert _is_constraint_contained(Contains(["read", "write"]), parent)  # Equal
        
        # Child requires LESS - invalid (would accept more inputs)
        assert not _is_constraint_contained(Contains(["read"]), parent)
        assert not _is_constraint_contained(Contains(["other"]), parent)
    
    # -------------------------------------------------------------------------
    # Subset Constraints
    # -------------------------------------------------------------------------
    def test_subset_fewer_allowed(self):
        """Subset child must allow FEWER values (subset of allowed)."""
        from tenuo_core import Subset
        parent = Subset(["a", "b", "c", "d"])
        
        # Child allows FEWER - valid narrowing
        assert _is_constraint_contained(Subset(["a", "b"]), parent)
        assert _is_constraint_contained(Subset(["a"]), parent)
        assert _is_constraint_contained(Subset(["a", "b", "c", "d"]), parent)  # Equal
        
        # Child allows MORE or different - invalid
        assert not _is_constraint_contained(Subset(["a", "b", "c", "d", "e"]), parent)
        assert not _is_constraint_contained(Subset(["x", "y"]), parent)
    
    # -------------------------------------------------------------------------
    # Range -> Exact Cross-Type
    # -------------------------------------------------------------------------
    def test_range_to_exact_numeric(self):
        """Range parent can contain Exact numeric child if within bounds."""
        from tenuo_core import Range, Exact
        parent = Range(0, 100)
        
        # Exact with numeric string within range
        assert _is_constraint_contained(Exact("50"), parent)
        assert _is_constraint_contained(Exact("0"), parent)   # At min
        assert _is_constraint_contained(Exact("100"), parent)  # At max
        
        # Exact outside range
        assert not _is_constraint_contained(Exact("-1"), parent)
        assert not _is_constraint_contained(Exact("101"), parent)
    
    def test_range_to_exact_string_fails(self):
        """Range -> Exact with non-numeric string should fail."""
        from tenuo_core import Range, Exact
        parent = Range(0, 100)
        
        # Non-numeric exact fails
        assert not _is_constraint_contained(Exact("fifty"), parent)
        assert not _is_constraint_contained(Exact("abc"), parent)

# =============================================================================
# Task Context Tests
# =============================================================================

def test_root_task_creates_warrant(setup_config):
    from tenuo_core import Pattern
    from tenuo import Capability
    async def _test():
        async with mint(Capability("read_file", path=Pattern("/data/*"))) as warrant:
            assert warrant is not None
            assert warrant_scope() == warrant
            assert warrant.tools == ["read_file"]
            
            # Check constraints
            constraints = warrant.capabilities["read_file"]
            assert constraints["path"].pattern == "/data/*"
    
    asyncio.run(_test())

def test_scoped_task_narrowing(setup_config):
    from tenuo_core import Pattern
    from tenuo import Capability
    async def _test():
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            parent = warrant_scope()
            
            # Valid narrowing
            async with grant(Capability("read_file", path=Pattern("/data/reports/*"))) as child:
                import hashlib
                ph = hashlib.sha256(parent.payload_bytes).hexdigest()
                assert child.parent_hash == ph
                assert child.depth == parent.depth + 1
    
    asyncio.run(_test())

def test_scoped_task_requires_parent(setup_config):
    from tenuo_core import Pattern
    from tenuo import Capability
    async def _test():
        with pytest.raises(ScopeViolation, match="requires a parent warrant"):
            async with grant(Capability("read_file", path=Pattern("/data/*"))):
                pass
    
    asyncio.run(_test())

def test_scoped_task_enforces_containment(setup_config):
    from tenuo_core import Pattern
    from tenuo import Capability
    async def _test():
        async with mint(Capability("read_file", path=Pattern("/data/reports/*"))):
            # Try to widen scope
            with pytest.raises(MonotonicityError):
                async with grant(Capability("read_file", path=Pattern("/data/*"))):
                    pass
    
    asyncio.run(_test())

def test_scoped_task_preview(setup_config):
    from tenuo_core import Pattern
    from tenuo import Capability
    async def _test():
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            preview = grant(Capability("read_file", path=Pattern("/data/reports/*"))).preview()
            assert preview.error is None
            # Preview returns the constraint object, not string
            assert preview.constraints["path"].pattern == "/data/reports/*"
            assert preview.depth == 1  # 0 (root) + 1
    
    asyncio.run(_test())

# =============================================================================
# Tool Protection Tests (@guard decorator)
# =============================================================================

def test_guard_decorator_async(setup_config):
    from tenuo_core import Pattern
    from tenuo import Capability
    
    @guard(tool="read_file")
    async def read_file(path: str) -> str:
        return f"content of {path}"
    
    async def _test():
        # 1. Call without warrant -> Error
        with pytest.raises(Exception):  # ToolNotAuthorized or similar
            await read_file(path="/data/file.txt")
            
        # 2. Call with valid warrant -> Success
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            result = await read_file(path="/data/file.txt")
            assert result == "content of /data/file.txt"
            
        # 3. Call with path outside allowed pattern -> Error
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            try:
                await read_file(path="/etc/passwd")
                pytest.fail("Should have raised authorization error")
            except Exception:
                pass
    
    asyncio.run(_test())

@pytest.mark.skip(reason="Schema enforcement removed from @guard in API cleanup")
def test_critical_tool_requires_constraint(setup_config):
    from tenuo import Capability
    
    # Register a critical tool schema
    register_schema("delete_file", ToolSchema(
        recommended_constraints=["path"],
        risk_level="critical"
    ))
    
    @guard(tool="delete_file")
    async def delete_file(path: str):
        return "deleted"
    
    async def _test():
        # Create warrant WITHOUT constraints (empty Capability)
        async with mint(Capability("delete_file")):
            with pytest.raises(ConfigurationError, match="requires at least one constraint"):
                await delete_file(path="/data/file.txt")
    
    asyncio.run(_test())

