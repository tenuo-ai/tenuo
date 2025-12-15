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
    Keypair,
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
    return Keypair.generate()

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
# Containment Logic Tests
# =============================================================================

def test_containment_logic():
    from tenuo_core import Pattern, Exact, Range, OneOf  # type: ignore[import-untyped]

    # Exact
    assert _is_constraint_contained("foo", "foo")
    assert not _is_constraint_contained("foo", "bar")
    
    # Glob/Pattern (Must be explicit now)
    assert _is_constraint_contained(Exact("/data/reports/q3.pdf"), Pattern("/data/*"))
    assert _is_constraint_contained(Pattern("/data/reports/*"), Pattern("/data/*"))
    assert not _is_constraint_contained(Pattern("/data/*"), Pattern("/data/reports/*"))  # Parent is narrower
    assert not _is_constraint_contained(Exact("/etc/passwd"), Pattern("/data/*"))
    
    # Range (tuples)
    r_parent = Range(0, 100)
    r_child = Range(10, 50)
    r_wide = Range(0, 200)
    
    assert _is_constraint_contained(r_child, r_parent)
    assert not _is_constraint_contained(r_wide, r_parent)
    
    # OneOf (lists)
    o_parent = OneOf(["a", "b", "c"])
    o_child = OneOf(["a", "b"])
    o_wide = OneOf(["a", "b", "c", "d"])
    
    assert _is_constraint_contained(o_child, o_parent)
    assert not _is_constraint_contained(o_wide, o_parent)

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

