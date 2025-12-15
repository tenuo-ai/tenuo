"""
Tests for Tenuo LangGraph integration.
"""

import pytest
from tenuo import (
    configure,
    reset_config,
    root_task_sync,
    Keypair,
    ScopeViolation,
)
from tenuo.langgraph import tenuo_node, require_warrant
from tenuo.decorators import get_warrant_context


@pytest.fixture(autouse=True)
def reset_config_fixture():
    """Reset config before and after each test."""
    reset_config()
    yield
    reset_config()


class TestTenuoNode:
    """Tests for @tenuo_node decorator."""
    
    def test_decorator_scopes_authority(self):
        """@tenuo_node scopes authority for node execution."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools_seen = []
        
        @tenuo_node(tools=["search"])
        def research_node(state):
            # Capture what tools are allowed
            warrant = get_warrant_context()
            if warrant:
                tools_seen.append(warrant.tool)
            return {"result": "done"}
        
        with root_task_sync(tools=["search", "read_file"]):
            result = research_node({})
            assert result == {"result": "done"}
    
    def test_decorator_with_constraints(self):
        """@tenuo_node applies constraints."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @tenuo_node(tools=["read_file"], path="/data/*")
        def file_reader_node(state):
            return {"content": "file contents"}
        
        with root_task_sync(tools=["read_file"], path="/data/*"):
            result = file_reader_node({})
            assert result == {"content": "file contents"}
    
    def test_decorator_requires_parent_warrant(self):
        """@tenuo_node fails without parent warrant."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @tenuo_node(tools=["search"])
        def search_node(state):
            return {"result": "done"}
        
        # No root_task - should fail
        with pytest.raises(ScopeViolation, match="requires a parent warrant"):
            search_node({})
    
    def test_decorator_narrows_tools(self):
        """@tenuo_node narrows tool allowlist."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @tenuo_node(tools=["search"])
        def narrow_node(state):
            # Inside here, only search should be allowed
            from tenuo.decorators import get_allowed_tools_context
            allowed = get_allowed_tools_context()
            return {"allowed": allowed}
        
        with root_task_sync(tools=["search", "read_file", "write_file"]):
            result = narrow_node({})
            assert result["allowed"] == ["search"]
    
    def test_decorator_preserves_function_metadata(self):
        """@tenuo_node preserves function name and docstring."""
        @tenuo_node(tools=["test"])
        def my_documented_node(state):
            """This is the docstring."""
            return state
        
        assert my_documented_node.__name__ == "my_documented_node"
        assert "docstring" in my_documented_node.__doc__


class TestRequireWarrant:
    """Tests for @require_warrant decorator."""
    
    def test_allows_with_warrant(self):
        """@require_warrant allows execution with warrant."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @require_warrant
        def protected_node(state):
            return {"status": "ok"}
        
        with root_task_sync(tools=["any"]):
            result = protected_node({})
            assert result == {"status": "ok"}
    
    def test_blocks_without_warrant(self):
        """@require_warrant blocks execution without warrant."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @require_warrant
        def protected_node(state):
            return {"status": "ok"}
        
        # No root_task - should fail
        with pytest.raises(ScopeViolation, match="requires warrant"):
            protected_node({})
    
    def test_preserves_function_metadata(self):
        """@require_warrant preserves function metadata."""
        @require_warrant
        def documented_node(state):
            """Node docstring."""
            return state
        
        assert documented_node.__name__ == "documented_node"
        assert "docstring" in documented_node.__doc__


class TestTenuoNodeAsync:
    """Tests for @tenuo_node with async functions."""
    
    def test_async_node_sync_invocation(self):
        """@tenuo_node async function can be set up (invocation tested separately)."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @tenuo_node(tools=["search"])
        async def async_search_node(state):
            return {"async": True}
        
        # Just test that the decorator works - actual async invocation
        # requires pytest-asyncio which may not be installed
        assert callable(async_search_node)
        assert async_search_node.__name__ == "async_search_node"


class TestNestedNodes:
    """Tests for nested @tenuo_node decorators."""
    
    def test_nested_narrowing(self):
        """Nested @tenuo_node further narrows scope."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @tenuo_node(tools=["search"])
        def outer_node(state):
            @tenuo_node(tools=["search"])
            def inner_node(state):
                return {"inner": True}
            
            inner_result = inner_node(state)
            return {"outer": True, **inner_result}
        
        with root_task_sync(tools=["search", "read_file"]):
            result = outer_node({})
            assert result == {"outer": True, "inner": True}
    
    def test_inner_cannot_widen_scope(self):
        """Inner @tenuo_node cannot request tools not in outer scope."""
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @tenuo_node(tools=["search"])
        def outer_node(state):
            @tenuo_node(tools=["read_file"])  # Not in outer's scope!
            def inner_node(state):
                return {"inner": True}
            
            return inner_node(state)
        
        with root_task_sync(tools=["search", "read_file"]):
            from tenuo.exceptions import ConstraintViolation
            with pytest.raises(ConstraintViolation, match="not in parent"):
                outer_node({})
