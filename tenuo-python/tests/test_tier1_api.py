"""
Tests for Tenuo Tier 1 API (3-line API).

Covers:
- Global configuration
- root_task and scoped_task context managers
- Tool protection (protect_tools)
- Containment logic for constraints
"""

import pytest
import asyncio

from tenuo import (
    configure,
    reset_config,
    get_config,
    root_task,
    scoped_task,
    protect_tools,
    SigningKey,
    ConfigurationError,
    ScopeViolation,
    MonotonicityError,
    ToolSchema,
    register_schema,
)
from tenuo.scoped import _is_constraint_contained
from tenuo.decorators import get_warrant_context

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
    """Comprehensive tests for _is_constraint_contained used by scoped_task()."""
    
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
    def test_exact_in_oneof(self):
        """Exact value should be contained if it's in the OneOf set."""
        from tenuo_core import OneOf  # noqa: F401
        _parent = OneOf(["read", "write", "delete"])  # noqa: F841
        
        # Note: Cross-type containment (Exact in OneOf) is not yet implemented
        # in _is_constraint_contained. This test documents expected behavior.
        # TODO: Implement when needed - Exact("read") should be contained in
        # OneOf(["read", "write", "delete"])
    
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

# =============================================================================
# Task Context Tests
# =============================================================================

def test_root_task_creates_warrant(setup_config):
    from tenuo_core import Pattern
    async def _test():
        async with root_task(tools=["read_file"], path=Pattern("/data/*")) as warrant:
            assert warrant is not None
            assert get_warrant_context() == warrant
            assert warrant.tools == ["read_file"]
            
            # Check constraints
            constraints = warrant.constraints_dict()
            assert constraints["path"].pattern == "/data/*"
    
    asyncio.run(_test())

def test_scoped_task_narrowing(setup_config):
    from tenuo_core import Pattern
    async def _test():
        async with root_task(tools=["read_file"], path=Pattern("/data/*")):
            parent = get_warrant_context()
            
            # Valid narrowing
            async with scoped_task(path=Pattern("/data/reports/*")) as child:
                assert child.parent_id == parent.id
                assert child.depth == parent.depth + 1
    
    asyncio.run(_test())

def test_scoped_task_requires_parent(setup_config):
    from tenuo_core import Pattern
    async def _test():
        with pytest.raises(ScopeViolation, match="requires a parent warrant"):
            async with scoped_task(path=Pattern("/data/*")):
                pass
    
    asyncio.run(_test())

def test_scoped_task_enforces_containment(setup_config):
    from tenuo_core import Pattern
    async def _test():
        async with root_task(tools=["read_file"], path=Pattern("/data/reports/*")):
            # Try to widen scope
            with pytest.raises(MonotonicityError):
                async with scoped_task(path=Pattern("/data/*")):
                    pass
    
    asyncio.run(_test())

def test_scoped_task_preview(setup_config):
    from tenuo_core import Pattern
    async def _test():
        async with root_task(tools=["read_file"], path=Pattern("/data/*")):
            preview = scoped_task(path=Pattern("/data/reports/*")).preview()
            assert preview.error is None
            # Preview returns the constraint object, not string
            assert preview.constraints["path"].pattern == "/data/reports/*"
            assert preview.depth == 1  # 0 (root) + 1
    
    asyncio.run(_test())

# =============================================================================
# Tool Protection Tests
# =============================================================================

def test_protect_tools_async(setup_config):
    from tenuo_core import Pattern
    async def _test():
        # Define a dummy async tool
        async def read_file(path: str) -> str:
            return f"content of {path}"
        
        # Protect it
        tools = [read_file]
        protect_tools(tools)
        protected_read_file = tools[0]
        
        # 1. Call without warrant -> Error
        with pytest.raises(Exception): # ToolNotAuthorized or similar
            await protected_read_file(path="/data/file.txt")
            
        # 2. Call with valid warrant -> Success
        async with root_task(tools=["read_file"], path=Pattern("/data/*")):
            result = await protected_read_file(path="/data/file.txt")
            assert result == "content of /data/file.txt"
            
        # 3. Call with invalid constraint -> Error
        async with root_task(tools=["read_file"], path=Pattern("/data/*")):
            try:
                await protected_read_file(path="/etc/passwd")
                pytest.fail("Should have raised authorization error")
            except Exception:
                pass
    
    asyncio.run(_test())

def test_critical_tool_requires_constraint(setup_config):
    async def _test():
        # Register a critical tool schema
        register_schema("delete_file", ToolSchema(
            recommended_constraints=["path"],
            risk_level="critical"
        ))
        
        async def delete_file(path: str):
            return "deleted"
        
        tools = [delete_file]
        protect_tools(tools)
        protected_delete = tools[0]
        
        # Create warrant WITHOUT constraints
        async with root_task(tools=["delete_file"]):
            with pytest.raises(ConfigurationError, match="requires at least one constraint"):
                await protected_delete(path="/data/file.txt")
    
    asyncio.run(_test())

