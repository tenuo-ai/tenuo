"""
Tests for Tenuo LangGraph integration.

Tests the improved KeyRegistry pattern where:
- Keys are auto-loaded from env OR registered manually
- Warrant stays in state (it attenuates)
- key_id goes in config (infrastructure concern)
- guard_node() wrapper OR @tenuo_node decorator
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
    guard_node,
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
    """Tests for the guard_node() wrapper (keeps nodes pure)."""

    def test_guard_node_wraps_node(self, warrant_and_key, registry):
        """guard_node() wraps a pure node function."""
        warrant, key_id = warrant_and_key

        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}

        wrapped = guard_node(my_agent)

        state = {"warrant": warrant}
        config = make_config(key_id)

        result = wrapped(state, config=config)
        assert result == {"result": "done"}

    def test_guard_node_with_explicit_key_id(self, warrant_and_key, registry):
        """guard_node() can use explicit key_id."""
        warrant, key_id = warrant_and_key

        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}

        # Explicit key_id in wrapper
        wrapped = guard_node(my_agent, key_id=key_id)

        state = {"warrant": warrant}
        # No config needed - key_id is explicit
        result = wrapped(state)
        assert result == {"result": "done"}

    def test_guard_node_inject_warrant(self, warrant_and_key, registry):
        """guard_node(inject_warrant=True) passes bound_warrant."""
        warrant, key_id = warrant_and_key

        received_bw = None

        def my_agent(state: Dict[str, Any], bound_warrant: Optional[BoundWarrant] = None) -> Dict[str, Any]:
            nonlocal received_bw
            received_bw = bound_warrant
            return {"result": "done"}

        wrapped = guard_node(my_agent, inject_warrant=True)

        state = {"warrant": warrant}
        config = make_config(key_id)

        wrapped(state, config=config)

        assert received_bw is not None
        assert isinstance(received_bw, BoundWarrant)

    def test_guard_node_fails_without_warrant(self, registry):
        """guard_node() fails if state has no warrant."""
        registry.register("test-key", SigningKey.generate())

        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}

        wrapped = guard_node(my_agent)

        state = {}  # No warrant
        config = make_config("test-key")

        with pytest.raises(ConfigurationError, match="warrant"):
            wrapped(state, config=config)

    def test_guard_node_uses_default_key(self, registry):
        """guard_node() falls back to 'default' key_id."""
        warrant, key = Warrant.quick_mint(tools=["search"], ttl=3600)
        registry.register("default", key)  # Register as "default"

        def my_agent(state: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "done"}

        wrapped = guard_node(my_agent)

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


def _middleware_available() -> bool:
    """Check if middleware is available."""
    try:
        from tenuo.langgraph import MIDDLEWARE_AVAILABLE

        return MIDDLEWARE_AVAILABLE
    except ImportError:
        return False


class TestTenuoMiddleware:
    """Tests for TenuoMiddleware (LangChain 1.0+ middleware API)."""

    def test_middleware_available_flag(self):
        """MIDDLEWARE_AVAILABLE flag reflects import status."""
        from tenuo.langgraph import MIDDLEWARE_AVAILABLE

        # Should be a boolean
        assert isinstance(MIDDLEWARE_AVAILABLE, bool)

    @pytest.mark.skipif(
        not _middleware_available(),
        reason="LangChain 1.0+ middleware not installed",
    )
    def test_middleware_init(self, registry):
        """TenuoMiddleware can be initialized."""
        from tenuo.langgraph import TenuoMiddleware

        middleware = TenuoMiddleware()
        assert middleware is not None
        assert middleware._filter_tools is True
        assert middleware._require_constraints is False

    @pytest.mark.skipif(
        not _middleware_available(),
        reason="LangChain 1.0+ middleware not installed",
    )
    def test_middleware_init_with_options(self, registry):
        """TenuoMiddleware accepts configuration options."""
        from tenuo.langgraph import TenuoMiddleware

        middleware = TenuoMiddleware(
            key_id="my-key",
            filter_tools=False,
            require_constraints=True,
        )
        assert middleware._key_id == "my-key"
        assert middleware._filter_tools is False
        assert middleware._require_constraints is True

    @pytest.mark.skipif(
        not _middleware_available(),
        reason="LangChain 1.0+ middleware not installed",
    )
    def test_middleware_debug_mode(self, registry):
        """TenuoMiddleware returns detailed errors in debug mode."""
        from tenuo.langgraph import TenuoMiddleware

        middleware = TenuoMiddleware(debug=True)

        # Mock request with invalid tool call
        class MockRequest:
            state = {"warrant": "invalid-warrant"}  # Will cause config error
            runtime = None
            tool_call = {"name": "test", "id": "123"}

        # Should return detailed error
        response = middleware.wrap_tool_call(MockRequest(), lambda x: x)

        assert response.status == "error"
        # In debug mode, we expect details
        assert "Configuration error" in response.content or "Authorization denied" in response.content


class TestEnforcementModule:
    """Tests for the shared _enforcement module."""

    def test_enforce_tool_call_allowed(self, warrant_and_key, registry):
        """enforce_tool_call returns allowed=True for valid calls."""
        from tenuo._enforcement import enforce_tool_call

        warrant, key_id = warrant_and_key
        key = registry.get(key_id)
        bound = warrant.bind(key)

        result = enforce_tool_call(
            tool_name="search",
            tool_args={"query": "test"},
            bound_warrant=bound,
        )

        assert result.allowed is True
        assert result.tool == "search"

    def test_enforce_tool_call_denied_wrong_tool(self, warrant_and_key, registry):
        """enforce_tool_call returns allowed=False for unauthorized tool."""
        from tenuo._enforcement import enforce_tool_call

        warrant, key_id = warrant_and_key
        key = registry.get(key_id)
        bound = warrant.bind(key)

        result = enforce_tool_call(
            tool_name="delete_file",  # Not in warrant
            tool_args={"path": "/etc/passwd"},
            bound_warrant=bound,
        )

        assert result.allowed is False
        assert result.tool == "delete_file"
        assert "not in warrant" in result.denial_reason

    def test_enforce_tool_call_with_allowlist_override(self, warrant_and_key, registry):
        """enforce_tool_call respects explicit allowed_tools."""
        from tenuo._enforcement import enforce_tool_call

        warrant, key_id = warrant_and_key
        key = registry.get(key_id)
        bound = warrant.bind(key)

        # Tool is in warrant but not in explicit allowlist
        result = enforce_tool_call(
            tool_name="search",
            tool_args={"query": "test"},
            bound_warrant=bound,
            allowed_tools=["read_file"],  # Override
        )

        assert result.allowed is False
        assert "not in allowed list" in result.denial_reason

    def test_enforce_requires_bound_warrant(self, warrant_and_key, registry):
        """enforce_tool_call raises ConfigurationError for plain Warrant."""
        from tenuo._enforcement import enforce_tool_call

        warrant, key_id = warrant_and_key

        # Pass plain warrant instead of BoundWarrant
        with pytest.raises(ConfigurationError) as exc_info:
            enforce_tool_call(
                tool_name="search",
                tool_args={"query": "test"},
                bound_warrant=warrant,  # Not bound!
            )

        assert "Expected BoundWarrant" in str(exc_info.value)
        assert "warrant.bind(signing_key)" in str(exc_info.value)

    def test_filter_tools_by_warrant(self, warrant_and_key, registry):
        """filter_tools_by_warrant filters tool list."""
        from tenuo._enforcement import filter_tools_by_warrant
        from dataclasses import dataclass

        @dataclass
        class MockTool:
            name: str

        warrant, key_id = warrant_and_key
        key = registry.get(key_id)
        bound = warrant.bind(key)

        tools = [
            MockTool(name="search"),
            MockTool(name="read_file"),
            MockTool(name="delete_file"),
        ]

        filtered = filter_tools_by_warrant(tools, bound)

        # Only search and read_file are in warrant
        assert len(filtered) == 2
        assert {t.name for t in filtered} == {"search", "read_file"}

    def test_filter_tools_requires_bound_warrant(self, warrant_and_key, registry):
        """filter_tools_by_warrant raises ConfigurationError for plain Warrant."""
        from tenuo._enforcement import filter_tools_by_warrant
        from dataclasses import dataclass

        @dataclass
        class MockTool:
            name: str

        warrant, key_id = warrant_and_key
        tools = [MockTool(name="search")]

        with pytest.raises(ConfigurationError) as exc_info:
            filter_tools_by_warrant(tools, warrant)  # Not bound!

        assert "Expected BoundWarrant" in str(exc_info.value)

    def test_filter_tools_with_many_tools(self, registry):
        """filter_tools_by_warrant handles warrants with many tools."""
        from tenuo._enforcement import filter_tools_by_warrant
        from dataclasses import dataclass

        @dataclass
        class MockTool:
            name: str

        # Warrant with many tools (all in available list)
        warrant, key = Warrant.quick_mint(
            tools=["search", "delete", "anything"],
            ttl=3600,
        )
        registry.register("many-tools-key", key)
        bound = warrant.bind(key)

        tools = [
            MockTool(name="search"),
            MockTool(name="delete"),
            MockTool(name="anything"),
        ]

        filtered = filter_tools_by_warrant(tools, bound)

        # All tools should be returned since all are in warrant
        assert len(filtered) == 3

    def test_enforcement_result_raise_if_denied(self):
        """EnforcementResult.raise_if_denied raises appropriate exception."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.exceptions import ToolNotAuthorized, ConstraintViolation

        # Allowed - should not raise
        allowed_result = EnforcementResult(
            allowed=True,
            tool="test",
            arguments={},
        )
        allowed_result.raise_if_denied()  # No exception

        # Denied without constraint - ToolNotAuthorized
        denied_result = EnforcementResult(
            allowed=False,
            tool="test",
            arguments={},
            denial_reason="Not authorized",
        )
        with pytest.raises(ToolNotAuthorized):
            denied_result.raise_if_denied()

        # Denied with constraint - ConstraintViolation
        constraint_result = EnforcementResult(
            allowed=False,
            tool="test",
            arguments={},
            denial_reason="Path not allowed",
            constraint_violated="path",
        )
        with pytest.raises(ConstraintViolation):
            constraint_result.raise_if_denied()

    def test_extract_violated_field(self):
        """_extract_violated_field extracts field names from error messages."""
        from tenuo._enforcement import _extract_violated_field

        # Test various error message formats
        assert _extract_violated_field("Constraint 'path' not satisfied") == "path"
        assert _extract_violated_field("Range exceeded for 'amount'") == "amount"
        assert _extract_violated_field("field 'query' invalid") == "query"
        assert _extract_violated_field(None) is None
        assert _extract_violated_field("Generic error") is None

    def test_get_constraints_dict_uses_capabilities(self, registry):
        """_get_constraints_dict properly extracts from capabilities."""
        from tenuo._enforcement import _get_constraints_dict
        from tenuo_core import Pattern

        # Create warrant with capabilities-based constraints
        key = SigningKey.generate()
        registry.register("cap-test-key", key)

        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("test*"))
            .capability("read_file", path=Pattern("/data/*"))
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )

        bound = warrant.bind(key)

        constraints = _get_constraints_dict(bound)

        # Should have flattened constraints from both capabilities
        assert "query" in constraints or "path" in constraints
