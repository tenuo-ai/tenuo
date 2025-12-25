"""
Tests for Tenuo LangGraph integration.

Tests the improved KeyRegistry pattern where:
- Keys are auto-loaded from env OR registered manually
- Warrant stays in state (it attenuates)
- key_id goes in config (infrastructure concern)
- guard() wrapper OR @tenuo_node decorator
"""

import pytest
import tenuo.testing  # noqa: F401
from typing import Dict, Any, TypedDict, Optional

from tenuo import (
    SigningKey,
    Warrant,
    ConfigurationError,
    BoundWarrant,
)
from tenuo.keys import KeyRegistry
from tenuo.langgraph import (
    tenuo_node,
    require_warrant,
    guard,
    load_tenuo_keys,
)


class MockState(TypedDict, total=False):
    """Test state with warrant (key_id now in config)."""
    messages: list
    warrant: Warrant
    result: str


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    return SigningKey.generate()


@pytest.fixture
def registry():
    """Get a fresh KeyRegistry instance."""
    KeyRegistry.reset_instance()
    return KeyRegistry.get_instance()


@pytest.fixture
def warrant_and_key(registry):
    """Create a test warrant and register the key."""
    warrant, key = Warrant.quick_mint(tools=["search", "read_file"], ttl=3600)
    registry.register("test-key", key)
    return warrant, "test-key"


def make_config(key_id: str) -> Dict[str, Any]:
    """Create a LangGraph-style config with key_id."""
    return {"configurable": {"tenuo_key_id": key_id}}


class TestGuardWrapper:
    """Tests for the guard() wrapper (keeps nodes pure)."""
    
    def test_guard_wraps_node(self, warrant_and_key, registry):
        """guard() wraps a pure node function."""
        warrant, key_id = warrant_and_key
        
        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}
        
        wrapped = guard(my_agent)
        
        state = {"warrant": warrant}
        config = make_config(key_id)
        
        result = wrapped(state, config=config)
        assert result == {"result": "done"}
    
    def test_guard_with_explicit_key_id(self, warrant_and_key, registry):
        """guard() can use explicit key_id."""
        warrant, key_id = warrant_and_key
        
        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}
        
        # Explicit key_id in wrapper
        wrapped = guard(my_agent, key_id=key_id)
        
        state = {"warrant": warrant}
        # No config needed - key_id is explicit
        result = wrapped(state)
        assert result == {"result": "done"}
    
    def test_guard_inject_warrant(self, warrant_and_key, registry):
        """guard(inject_warrant=True) passes bound_warrant."""
        warrant, key_id = warrant_and_key
        
        received_bw = None
        
        def my_agent(state: Dict[str, Any], bound_warrant: Optional[BoundWarrant] = None) -> Dict[str, Any]:
            nonlocal received_bw
            received_bw = bound_warrant
            return {"result": "done"}
        
        wrapped = guard(my_agent, inject_warrant=True)
        
        state = {"warrant": warrant}
        config = make_config(key_id)
        
        wrapped(state, config=config)
        
        assert received_bw is not None
        assert isinstance(received_bw, BoundWarrant)
    
    def test_guard_fails_without_warrant(self, registry):
        """guard() fails if state has no warrant."""
        registry.register("test-key", SigningKey.generate())
        
        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}
        
        wrapped = guard(my_agent)
        
        state = {}  # No warrant
        config = make_config("test-key")
        
        with pytest.raises(ConfigurationError, match="warrant"):
            wrapped(state, config=config)
    
    def test_guard_uses_default_key(self, registry):
        """guard() falls back to 'default' key_id."""
        warrant, key = Warrant.quick_mint(tools=["search"], ttl=3600)
        registry.register("default", key)  # Register as "default"
        
        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}
        
        wrapped = guard(my_agent)
        
        state = {"warrant": warrant}
        # No config - should use "default"
        result = wrapped(state)
        assert result == {"result": "done"}


class TestTenuoNode:
    """Tests for @tenuo_node decorator (explicit access)."""
    
    def test_decorator_injects_bound_warrant(self, warrant_and_key, registry):
        """@tenuo_node injects bound_warrant into function."""
        warrant, key_id = warrant_and_key
        
        received_bw = None
        
        @tenuo_node
        def my_node(state: Dict[str, Any], bound_warrant: BoundWarrant):
            nonlocal received_bw
            received_bw = bound_warrant
            return {"result": "done"}
        
        state = {"warrant": warrant}
        config = make_config(key_id)
        
        result = my_node(state, config=config)
        
        assert result == {"result": "done"}
        assert received_bw is not None
        assert isinstance(received_bw, BoundWarrant)
        assert received_bw.id == warrant.id
    
    def test_decorator_fails_without_warrant(self, registry):
        """@tenuo_node fails if state has no warrant."""
        registry.register("test-key", SigningKey.generate())
        
        @tenuo_node
        def my_node(state: Dict[str, Any], bound_warrant: BoundWarrant):
            return {"result": "done"}
        
        state = {}  # No warrant
        config = make_config("test-key")
        
        with pytest.raises(ConfigurationError, match="warrant"):
            my_node(state, config=config)
    
    def test_decorator_preserves_function_metadata(self):
        """@tenuo_node preserves function name and docstring."""
        @tenuo_node
        def my_documented_node(state, bound_warrant: BoundWarrant):
            """This is the docstring."""
            return state
        
        assert my_documented_node.__name__ == "my_documented_node"
        assert "docstring" in my_documented_node.__doc__

    def test_bound_warrant_can_authorize(self, warrant_and_key, registry):
        """BoundWarrant injected by @tenuo_node can authorize calls."""
        warrant, key_id = warrant_and_key
        
        auth_result = None
        
        @tenuo_node
        def my_node(state: Dict[str, Any], bound_warrant: BoundWarrant):
            nonlocal auth_result
            auth_result = bound_warrant.validate("search", {"query": "test"})
            return {"result": "done"}
        
        state = {"warrant": warrant}
        config = make_config(key_id)
        
        my_node(state, config=config)
        
        assert auth_result


class TestAutoLoadKeys:
    """Tests for load_tenuo_keys()."""
    
    def test_loads_keys_from_env(self, monkeypatch):
        """load_tenuo_keys() loads TENUO_KEY_* env vars."""
        KeyRegistry.reset_instance()
        
        # Create a test key and encode it
        key = SigningKey.generate()
        key_bytes = key.secret_key_bytes()
        import base64
        key_b64 = base64.b64encode(bytes(key_bytes)).decode()
        
        monkeypatch.setenv("TENUO_KEY_WORKER", key_b64)
        
        count = load_tenuo_keys()
        
        assert count >= 1
        
        registry = KeyRegistry.get_instance()
        loaded = registry.get("worker")
        assert loaded is not None
    
    def test_converts_key_names(self, monkeypatch):
        """load_tenuo_keys() converts TENUO_KEY_MY_SERVICE to my-service."""
        KeyRegistry.reset_instance()
        
        key = SigningKey.generate()
        import base64
        key_b64 = base64.b64encode(bytes(key.secret_key_bytes())).decode()
        
        monkeypatch.setenv("TENUO_KEY_MY_SERVICE", key_b64)
        
        load_tenuo_keys()
        
        registry = KeyRegistry.get_instance()
        loaded = registry.get("my-service")
        assert loaded is not None


class TestRequireWarrant:
    """Tests for require_warrant helper."""
    
    def test_returns_bound_warrant(self, warrant_and_key, registry):
        """require_warrant returns BoundWarrant from state + config."""
        warrant, key_id = warrant_and_key
        
        state = {"warrant": warrant}
        config = make_config(key_id)
        
        bw = require_warrant(state, config)
        
        assert isinstance(bw, BoundWarrant)
        assert bw.id == warrant.id
    
    def test_fails_without_warrant(self, registry):
        """require_warrant fails if state has no warrant."""
        registry.register("test-key", SigningKey.generate())
        
        state = {}
        config = make_config("test-key")
        
        with pytest.raises(ConfigurationError, match="warrant"):
            require_warrant(state, config)


class TestKeyRegistry:
    """Tests for KeyRegistry singleton."""
    
    def test_singleton_pattern(self):
        """KeyRegistry is a singleton."""
        KeyRegistry.reset_instance()
        r1 = KeyRegistry.get_instance()
        r2 = KeyRegistry.get_instance()
        assert r1 is r2
    
    def test_register_and_get(self):
        """Can register and retrieve keys."""
        KeyRegistry.reset_instance()
        registry = KeyRegistry.get_instance()
        
        key = SigningKey.generate()
        registry.register("my-key", key)
        
        retrieved = registry.get("my-key")
        assert bytes(retrieved.public_key.to_bytes()) == bytes(key.public_key.to_bytes())
    
    def test_namespaced_keys(self):
        """Keys can be namespaced."""
        KeyRegistry.reset_instance()
        registry = KeyRegistry.get_instance()
        
        key1 = SigningKey.generate()
        key2 = SigningKey.generate()
        
        registry.register("key", key1, namespace="ns1")
        registry.register("key", key2, namespace="ns2")
        
        r1 = registry.get("key", namespace="ns1")
        r2 = registry.get("key", namespace="ns2")
        
        assert bytes(r1.public_key.to_bytes()) != bytes(r2.public_key.to_bytes())
    
    def test_get_nonexistent_raises(self):
        """Getting nonexistent key raises KeyError."""
        KeyRegistry.reset_instance()
        registry = KeyRegistry.get_instance()
        
        with pytest.raises(KeyError):
            registry.get("nonexistent")


