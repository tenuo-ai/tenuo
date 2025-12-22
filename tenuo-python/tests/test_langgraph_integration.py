"""
Tests for Tenuo LangGraph integration.

Tests the improved API with:
- key_id in config (not state)
- secure() wrapper
- auto_load_keys()
"""

import pytest
from typing import Dict, Any

from tenuo import (
    Warrant,
    SigningKey,
    KeyRegistry,
    ConfigurationError,
    Pattern,
    BoundWarrant,
)
from tenuo.langgraph import (
    tenuo_node,
    secure,
    TenuoToolNode,
    LANGGRAPH_AVAILABLE,
)


def make_config(key_id: str) -> Dict[str, Any]:
    """Create a LangGraph-style config with key_id."""
    return {"configurable": {"tenuo_key_id": key_id}}


@pytest.fixture(autouse=True)
def cleanup_registry():
    """Clear registry after each test."""
    KeyRegistry.reset_instance()
    yield
    KeyRegistry.reset_instance()


class TestKeyRegistry:
    
    def test_singleton(self):
        r1 = KeyRegistry.get_instance()
        r2 = KeyRegistry.get_instance()
        assert r1 is r2
        
    def test_register_and_get(self):
        registry = KeyRegistry.get_instance()
        key = SigningKey.generate()
        registry.register("test-key", key)
        
        retrieved = registry.get("test-key")
        assert str(retrieved.public_key) == str(key.public_key)
        
    def test_get_missing_raises(self):
        registry = KeyRegistry.get_instance()
        with pytest.raises(KeyError):
            registry.get("missing")


class TestSecureWrapper:
    """Tests for secure() wrapper."""
    
    def test_wraps_pure_node(self):
        """secure() wraps a pure node function."""
        key = SigningKey.generate()
        registry = KeyRegistry.get_instance()
        registry.register("worker", key)
        
        warrant = (Warrant.builder()
            .tool("test_tool")
            .issue(key))
        
        def my_node(state: Dict) -> Dict:
            return {"result": "done"}
        
        wrapped = secure(my_node)
        
        state = {"warrant": warrant}
        config = make_config("worker")
        
        result = wrapped(state, config=config)
        assert result == {"result": "done"}
    
    def test_secure_with_explicit_key_id(self):
        """secure() can use explicit key_id."""
        key = SigningKey.generate()
        registry = KeyRegistry.get_instance()
        registry.register("worker", key)
        
        warrant = (Warrant.builder()
            .tool("test_tool")
            .issue(key))
        
        def my_node(state: Dict) -> Dict:
            return {"result": "done"}
        
        wrapped = secure(my_node, key_id="worker")
        
        state = {"warrant": warrant}
        result = wrapped(state)  # No config needed
        assert result == {"result": "done"}


class TestTenuoNodeDecorator:
    
    def test_injects_bound_warrant(self):
        """@tenuo_node injects bound_warrant."""
        key = SigningKey.generate()
        registry = KeyRegistry.get_instance()
        registry.register("worker", key)
        
        warrant = (Warrant.builder()
            .tool("test_tool")
            .issue(key))
        
        state = {"warrant": warrant}
        config = make_config("worker")
        
        @tenuo_node
        def my_node(state: Dict, bound_warrant: BoundWarrant):
            return bound_warrant
            
        bw = my_node(state, config=config)
        
        assert isinstance(bw, BoundWarrant)
        assert bw.warrant.id == warrant.id
    
    def test_uses_config_key_id(self):
        """key_id must be passed via config."""
        key = SigningKey.generate()
        registry = KeyRegistry.get_instance()
        registry.register("worker", key)
        
        warrant = (Warrant.builder()
            .tool("test_tool")
            .issue(key))
        
        state = {"warrant": warrant}
        config = make_config("worker")
        
        @tenuo_node
        def my_node(state: Dict, bound_warrant: BoundWarrant):
            return bound_warrant
            
        bw = my_node(state, config=config)
        assert isinstance(bw, BoundWarrant)
        
    def test_raises_if_missing_warrant(self):
        state = {}
        config = make_config("worker")
        
        @tenuo_node
        def my_node(state: Dict, bound_warrant: BoundWarrant): pass
            
        with pytest.raises(ConfigurationError, match="warrant"):
            my_node(state, config=config)


class TestTenuoToolNode:
    
    @pytest.mark.skipif(not LANGGRAPH_AVAILABLE, reason="LangGraph not installed")
    def test_executes_protected_tools(self):
        """Test that TenuoToolNode wraps and executes tools."""
        key = SigningKey.generate()
        registry = KeyRegistry.get_instance()
        registry.register("worker", key)
        
        warrant = (Warrant.builder()
            .capability("echo", {"msg": Pattern("hello*")})
            .issue(key))
            
        from langchain_core.tools import tool
        
        @tool
        def echo(msg: str) -> str:
            """Echoes the message."""
            return f"Echo: {msg}"
            
        tool_node = TenuoToolNode([echo])
        
        state = {
            "warrant": warrant,
            "messages": [
                type('AIMessage', (), {
                    "tool_calls": [
                        {"name": "echo", "args": {"msg": "hello world"}, "id": "call_1"}
                    ]
                })()
            ]
        }
        config = make_config("worker")
        
        result = tool_node.invoke(state, config=config)
        messages = result["messages"]
        
        assert len(messages) == 1
        assert messages[0].content == "Echo: hello world"
        
    @pytest.mark.skipif(not LANGGRAPH_AVAILABLE, reason="LangGraph not installed")
    def test_blocks_unauthorized_tools(self):
        """Test blocking unauthorized calls."""
        key = SigningKey.generate()
        registry = KeyRegistry.get_instance()
        registry.register("worker", key)
        
        warrant = (Warrant.builder()
            .capability("echo", {"msg": Pattern("hello*")})
            .issue(key))
            
        from langchain_core.tools import tool
        @tool
        def echo(msg: str) -> str:
            """Echoes the message."""
            return f"Echo: {msg}"
            
        tool_node = TenuoToolNode([echo])
        
        state = {
            "warrant": warrant,
            "messages": [
                type('AIMessage', (), {
                    "tool_calls": [
                        {"name": "echo", "args": {"msg": "bye world"}, "id": "call_2"}
                    ]
                })()
            ]
        }
        config = make_config("worker")
        
        result = tool_node.invoke(state, config=config)
        messages = result["messages"]
        
        # Expect error message (constraint violation)
        assert "error" in messages[0].content.lower() or "Authorization" in messages[0].content
