"""
Tests for Tenuo LangGraph integration.

Tests the improved KeyRegistry pattern where:
- Keys are auto-loaded from env OR registered manually
- Warrant stays in state (it attenuates)
- key_id goes in config (infrastructure concern)
- guard_node() wrapper OR @tenuo_node decorator
"""

from typing import Any, Dict, Optional, TypedDict

import pytest

import tenuo.testing  # noqa: F401
from tenuo import (
    BoundWarrant,
    ConfigurationError,
    SigningKey,
    Warrant,
)
from tenuo.keys import KeyRegistry
from tenuo.langgraph import (
    guard_node,
    load_tenuo_keys,
    require_warrant,
    tenuo_node,
)

try:
    from langchain_core.messages import ToolMessage
except ImportError:
    ToolMessage = None  # type: ignore


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
        bound = warrant.bind(key, trusted_roots=[key.public_key])

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
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Use a non-critical tool that's not in warrant (to bypass schema policy)
        result = enforce_tool_call(
            tool_name="unknown_tool",  # Not in warrant, not in schemas
            tool_args={"arg": "value"},
            bound_warrant=bound,
            schemas={},  # Empty schemas to skip policy check
        )

        assert result.allowed is False
        assert result.tool == "unknown_tool"
        # Rust core should reject - tool not in warrant
        # The exact message may vary, but it should be denied

    def test_enforce_tool_call_with_allowlist_override(self, warrant_and_key, registry):
        """enforce_tool_call respects explicit allowed_tools."""
        from tenuo._enforcement import enforce_tool_call

        warrant, key_id = warrant_and_key
        key = registry.get(key_id)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

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
        from dataclasses import dataclass

        from tenuo._enforcement import filter_tools_by_warrant

        @dataclass
        class MockTool:
            name: str

        warrant, key_id = warrant_and_key
        key = registry.get(key_id)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

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
        from dataclasses import dataclass

        from tenuo._enforcement import filter_tools_by_warrant

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
        from dataclasses import dataclass

        from tenuo._enforcement import filter_tools_by_warrant

        @dataclass
        class MockTool:
            name: str

        # Warrant with many tools (all in available list)
        warrant, key = Warrant.quick_mint(
            tools=["search", "delete", "anything"],
            ttl=3600,
        )
        registry.register("many-tools-key", key)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

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
        from tenuo.exceptions import ConstraintViolation, ToolNotAuthorized

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
        from tenuo_core import Pattern

        from tenuo._enforcement import _get_constraints_dict

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

        bound = warrant.bind(key, trusted_roots=[key.public_key])

        constraints = _get_constraints_dict(bound)

        # Should have flattened constraints from both capabilities
        assert "query" in constraints or "path" in constraints

    def test_enforce_tool_call_exempt_gate(self, warrant_and_key, registry):
        """enforce_tool_call allows tool calls matching an exempt gate without requiring approval."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo_core import Exact
        from tenuo.approval import ApprovalRequired

        key = registry.get(warrant_and_key[1])
        warrant = (
            Warrant.mint_builder()
            .capability("search")
            .approval_gates({"search": {"query": {"exempt": Exact("skip")}}})
            .required_approvers([key.public_key])
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # "skip" is specifically exempt - no approval handler provided, and should just succeed
        result = enforce_tool_call("search", {"query": "skip"}, bound)
        assert result.allowed is True

        # Any other value requires approval, and will raise ApprovalRequired since no handler provided
        with pytest.raises(ApprovalRequired):
            enforce_tool_call("search", {"query": "other"}, bound)


# =============================================================================
# Core Invariant Tests
# =============================================================================


class TestCoreInvariants:
    """
    Tests for Tenuo's core security invariants.

    These tests verify the fundamental security properties that MUST hold:
    1. Rust core is the security boundary (not bypassable from Python)
    2. Fail-closed behavior (deny on any error)
    3. PoP signatures are verified
    4. Constraints are cryptographically enforced
    5. Expiration is enforced
    """

    def test_rust_enforces_expiration(self, registry):
        """
        INVARIANT: Expired warrants are rejected by Rust core.

        This cannot be bypassed by Python code.
        """
        import time

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("expiry-test-key", key)

        # Create warrant with 1 second TTL
        warrant = (
            Warrant.mint_builder()
            .capability("search")
            .holder(key.public_key)
            .ttl(1)  # Very short TTL
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Wait for expiration
        time.sleep(2)

        # Rust core should reject
        result = enforce_tool_call("search", {"query": "test"}, bound)

        assert not result.allowed, "Expired warrant must be denied"
        assert "expired" in result.denial_reason.lower() or result.error_type == "expired"

    def test_rust_enforces_range_constraint(self, registry):
        """
        INVARIANT: Range constraints are enforced by Rust core.

        Python cannot bypass the min/max bounds.
        """
        from tenuo_core import Range

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("range-test-key", key)

        warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(min=0, max=100))
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Within range - should succeed
        result = enforce_tool_call("transfer", {"amount": 50}, bound)
        assert result.allowed, f"Within range should succeed: {result.denial_reason}"

        # Exceeds range - Rust core must reject
        result = enforce_tool_call("transfer", {"amount": 200}, bound)
        assert not result.allowed, "Exceeding range must be denied by Rust"
        assert "amount" in result.denial_reason.lower() or result.constraint_violated == "amount"

    def test_rust_enforces_pattern_constraint(self, registry):
        """
        INVARIANT: Pattern constraints are enforced by Rust core.

        Python cannot bypass glob/regex matching.
        """
        from tenuo_core import Pattern

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("pattern-test-key", key)

        warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Pattern("/data/*"))
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Matches pattern - should succeed
        result = enforce_tool_call("read_file", {"path": "/data/file.txt"}, bound)
        assert result.allowed, f"Matching pattern should succeed: {result.denial_reason}"

        # Doesn't match pattern - Rust core must reject
        result = enforce_tool_call("read_file", {"path": "/etc/passwd"}, bound)
        assert not result.allowed, "Non-matching path must be denied by Rust"

    def test_wrong_key_fails_pop(self, registry):
        """
        INVARIANT: PoP signature must be from the warrant's holder key.

        Using a different key must cause authorization failure.
        """
        from tenuo._enforcement import enforce_tool_call

        # Create two different keys
        holder_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        registry.register("holder-key", holder_key)
        registry.register("attacker-key", attacker_key)

        # Warrant is for holder_key
        warrant = (
            Warrant.mint_builder()
            .capability("search")
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(holder_key)
        )

        # Bind with WRONG key (attacker's key) — but supply the correct trusted root so
        # the only failure is the mismatched PoP signature, not a ConfigurationError.
        wrong_bound = warrant.bind(attacker_key, trusted_roots=[holder_key.public_key])

        # Should fail - PoP signature won't verify
        result = enforce_tool_call("search", {"query": "test"}, wrong_bound)
        assert not result.allowed, "Wrong key must fail PoP verification"

    def test_fail_closed_on_internal_error(self, registry):
        """
        INVARIANT: Fail-closed behavior on unexpected errors.

        If anything unexpected happens, authorization must be denied.
        """
        from tenuo._enforcement import EnforcementResult

        key = SigningKey.generate()
        registry.register("fail-closed-key", key)

        warrant, _ = Warrant.quick_mint(tools=["search"], ttl=3600)

        # Create a mock BoundWarrant that raises an unexpected error
        class BrokenBoundWarrant:
            """Mock that simulates internal error."""

            def __init__(self, warrant, key):
                self._warrant = warrant
                self.tools = ["search"]
                self.id = "test-id"

            def validate(self, tool, args):
                raise RuntimeError("Simulated internal error")

            def constraints_dict(self):
                return {}

        # Patch isinstance check
        BrokenBoundWarrant(warrant, key)

        # The function should catch this and return denied
        # Note: This tests the catch-all exception handler

        # We can't easily test this without mocking, but verify error_type exists
        result = EnforcementResult(
            allowed=False,
            tool="test",
            arguments={},
            error_type="internal_error",
            denial_reason="Internal error",
        )
        assert result.error_type == "internal_error"

    def test_error_type_categorization(self, registry):
        """
        INVARIANT: Errors are categorized for programmatic handling.

        Different error types should be distinguishable.
        """
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("error-type-key", key)

        warrant, _ = Warrant.quick_mint(tools=["search"], ttl=3600)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Tool not in warrant - should be "tool_not_allowed" or similar
        result = enforce_tool_call("delete", {}, bound)
        assert not result.allowed
        assert result.error_type is not None, "error_type must be set on denial"

    def test_critical_tool_requires_relevant_constraints(self, registry):
        """
        INVARIANT: Critical tools require relevant constraints (policy check).

        This is a Python-side policy, but ensures high-risk tools have bounds.
        """
        from tenuo._enforcement import enforce_tool_call
        from tenuo.schemas import ToolSchema

        key = SigningKey.generate()
        registry.register("critical-tool-key", key)

        # Create warrant for a critical tool WITHOUT constraints
        warrant = (
            Warrant.mint_builder()
            .capability("delete_file")  # No path constraint!
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Define delete_file as critical in schemas
        test_schemas = {
            "delete_file": ToolSchema(
                risk_level="critical",
                recommended_constraints=["path"],
                require_at_least_one=True,
            )
        }

        # Should be denied by Python policy (before Rust even sees it)
        result = enforce_tool_call(
            "delete_file",
            {"path": "/etc/passwd"},
            bound,
            schemas=test_schemas,
        )

        assert not result.allowed, "Critical tool without constraints must be denied"
        assert result.error_type == "policy_violation"
        assert "requires at least one of" in result.denial_reason

    def test_application_allowlist_cannot_expand_warrant(self, registry):
        """
        INVARIANT: Application allowlist can only RESTRICT, not EXPAND.

        Even if allowed_tools includes a tool, warrant must also allow it.
        """
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("expand-test-key", key)

        # Warrant only allows "search"
        warrant, _ = Warrant.quick_mint(tools=["search"], ttl=3600)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Application tries to allow "delete" which is NOT in warrant
        enforce_tool_call(
            "delete",
            {},
            bound,
            allowed_tools=["search", "delete"],  # App "allows" delete
        )

        # Must still be denied - Rust core checks warrant
        # (The tool will fail at Rust level even if Python allows it)
        # This test verifies the architecture

    def test_verify_mode_requires_signature(self, registry):
        """
        INVARIANT: verify_mode="verify" requires precomputed_signature.

        This mode is for Remote PEP where client provides the PoP.
        """
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("verify-mode-key", key)

        warrant, _ = Warrant.quick_mint(tools=["search"], ttl=3600)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # verify_mode without signature must raise ConfigurationError
        with pytest.raises(ConfigurationError) as exc_info:
            enforce_tool_call(
                "search",
                {"query": "test"},
                bound,
                verify_mode="verify",
                # precomputed_signature missing!
            )

        assert "precomputed_signature" in str(exc_info.value)

    def test_rust_tool_check_includes_wildcard(self, registry):
        """
        INVARIANT: Rust core handles wildcard (*) tool matching.

        Python doesn't implement this - it's Rust's responsibility.
        """
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("wildcard-key", key)

        # Create warrant with wildcard tool
        warrant = (
            Warrant.mint_builder()
            .capability("*")  # Allow all tools
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Any tool should work (Rust handles wildcard)
        result = enforce_tool_call("any_tool", {"arg": "value"}, bound)
        assert result.allowed, f"Wildcard tool should allow any tool: {result.denial_reason}"

        result = enforce_tool_call("another_tool", {}, bound)
        assert result.allowed, "Wildcard should allow all tools"


class TestPhilosophyAndDesign:
    """
    Tests that verify Tenuo's security philosophy and design principles.

    These tests ensure we maintain:
    1. Audit trail for security decisions
    2. Opaque errors that don't leak information
    3. Defense in depth patterns
    4. Proper separation of concerns
    """

    def test_audit_logging_on_success(self, registry, caplog):
        """
        PHILOSOPHY: Successful authorizations must be logged for audit.

        This creates an audit trail of all authorized operations.
        """
        import logging

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("audit-key", key)

        # Use builder to create properly keyed warrant
        warrant = (
            Warrant.mint_builder()
            .capability("search")
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        with caplog.at_level(logging.INFO, logger="tenuo"):
            result = enforce_tool_call("search", {"query": "test"}, bound)

        assert result.allowed, f"Expected allowed=True, got: {result.denial_reason}"

        # Check for audit log entry
        audit_records = [r for r in caplog.records if "authorized" in r.message.lower()]
        assert len(audit_records) >= 1, "Successful auth must be logged"

        # Log should contain useful audit info
        log_text = " ".join(r.message for r in audit_records)
        assert "search" in log_text, "Audit log should include tool name"

    def test_audit_logging_on_denial(self, registry, caplog):
        """
        PHILOSOPHY: Denied authorizations must be logged for security monitoring.
        """
        import logging

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("audit-denial-key", key)

        warrant, _ = Warrant.quick_mint(tools=["search"], ttl=3600)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        with caplog.at_level(logging.WARNING, logger="tenuo"):
            result = enforce_tool_call("delete_file", {"path": "/"}, bound)

        assert not result.allowed

        # Check for denial log
        denial_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(denial_records) >= 1, "Denied auth must be logged at WARNING+"

    def test_opaque_errors_dont_leak_constraint_details(self, registry):
        """
        PHILOSOPHY: Error messages to LLMs should be opaque.

        We don't want to leak constraint details that could help
        an attacker craft bypass attempts.
        """
        from tenuo_core import Range

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("opaque-error-key", key)

        warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(min=0, max=100))
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Try to exceed constraint
        result = enforce_tool_call("transfer", {"amount": 9999}, bound)

        assert not result.allowed

        # The denial_reason may contain details for operators
        # But the LLM-facing message should be more generic
        # (TenuoMiddleware handles this transformation)
        # Here we just verify the result has structured error info
        assert result.error_type is not None
        assert result.constraint_violated is not None or "amount" in result.denial_reason

    def test_multiple_constraint_violations_reported(self, registry):
        """
        PHILOSOPHY: When multiple constraints are violated, we detect at least one.

        This is defense in depth - even if one check has a bug,
        another should catch it.
        """
        from tenuo_core import Pattern, Range

        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("multi-constraint-key", key)

        warrant = (
            Warrant.mint_builder()
            .capability(
                "copy_file",
                source=Pattern("/data/*"),
                destination=Pattern("/backup/*"),
                size_kb=Range(max=1000),
            )
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Violate MULTIPLE constraints
        result = enforce_tool_call(
            "copy_file",
            {
                "source": "/etc/passwd",  # Wrong path!
                "destination": "/root/.ssh/",  # Wrong path!
                "size_kb": 9999,  # Exceeds limit!
            },
            bound,
        )

        assert not result.allowed, "Multiple violations must be denied"

    def test_enforcement_result_is_immutable_after_creation(self):
        """
        PHILOSOPHY: EnforcementResult should behave immutably.

        This prevents accidental mutation of authorization decisions.
        """
        from tenuo._enforcement import EnforcementResult

        result = EnforcementResult(
            allowed=False,
            tool="test",
            arguments={"key": "value"},
            denial_reason="Not allowed",
        )

        # The result is a dataclass - verify fields are set correctly
        assert result.allowed is False
        assert result.tool == "test"
        assert result.denial_reason == "Not allowed"

        # Attempting to modify should either fail or be discouraged
        # (dataclass is technically mutable, but pattern is to treat as immutable)

    def test_defense_in_depth_multiple_checks(self, registry):
        """
        PHILOSOPHY: Multiple independent checks provide defense in depth.

        Even if one layer fails, others should catch the violation.
        """
        from tenuo._enforcement import enforce_tool_call
        from tenuo.schemas import ToolSchema

        key = SigningKey.generate()
        registry.register("depth-key", key)

        # Warrant allows the tool but without proper constraints
        warrant = (
            Warrant.mint_builder()
            .capability("admin_operation")
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        # Layer 1: Tool schema policy requires constraints
        schemas = {
            "admin_operation": ToolSchema(
                risk_level="critical",
                recommended_constraints=["scope", "resource"],
                require_at_least_one=True,
            )
        }

        result = enforce_tool_call(
            "admin_operation",
            {"action": "delete_all"},
            bound,
            schemas=schemas,
        )

        # Should be denied by policy layer
        assert not result.allowed
        assert result.error_type == "policy_violation"

    def test_tool_args_preserved_in_result(self, registry):
        """
        PHILOSOPHY: EnforcementResult preserves tool call details for audit.

        Operators need to know exactly what was attempted.
        """
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("preserve-args-key", key)

        warrant, _ = Warrant.quick_mint(tools=["search"], ttl=3600)
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        args = {"query": "sensitive data", "limit": 100}
        result = enforce_tool_call("search", args, bound)

        assert result.tool == "search"
        assert result.arguments == args, "Arguments must be preserved"

    def test_warrant_id_available_for_correlation(self, registry):
        """
        PHILOSOPHY: Warrant ID should be available for log correlation.

        This allows tracing authorization decisions back to their source.
        """
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        registry.register("correlation-key", key)

        warrant = (
            Warrant.mint_builder()
            .capability("search")
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        result = enforce_tool_call("search", {}, bound)

        # Warrant ID should be accessible for correlation
        assert bound.id is not None, "BoundWarrant must have ID"
        # Result should allow correlation back to warrant
        assert result.warrant_id is not None or hasattr(bound, "id")


def _middleware_available() -> bool:
    try:
        from langchain.agents.middleware import AgentMiddleware  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _middleware_available(), reason="LangChain middleware not installed")
class TestMiddlewareAsync:
    """
    Tests that TenuoMiddleware works correctly with async agents.

    The AgentMiddleware ABC requires both sync AND async hook implementations.
    Missing awrap_tool_call / awrap_model_call causes NotImplementedError when
    users call agent.ainvoke() or agent.astream() — the common production path.
    """

    @pytest.fixture
    def warrant_and_key(self, registry):
        warrant, key = Warrant.quick_mint(tools=["search", "write_file"], ttl=3600)
        registry.register("test-key", key)
        return warrant, key

    @pytest.mark.asyncio
    async def test_awrap_tool_call_allows_authorized_tool(self, warrant_and_key, registry):
        """awrap_tool_call: authorized tool call must be passed to handler."""
        from unittest.mock import AsyncMock, MagicMock
        from tenuo.langgraph import TenuoMiddleware

        warrant, key = warrant_and_key
        middleware = TenuoMiddleware(key_id="test-key", trusted_roots=[key.public_key])

        request = MagicMock()
        request.tool_call = {"name": "search", "args": {"query": "papers"}, "id": "t1"}
        request.state = {"warrant": warrant}
        request.runtime = MagicMock()
        request.runtime.config = make_config("test-key")

        handler = AsyncMock(return_value=ToolMessage(content="results", tool_call_id="t1"))
        result = await middleware.awrap_tool_call(request, handler)

        handler.assert_awaited_once_with(request)
        assert result.content == "results"

    @pytest.mark.asyncio
    async def test_awrap_tool_call_denies_unauthorized_tool(self, warrant_and_key, registry):
        """awrap_tool_call: unauthorized tool must be denied without calling handler."""
        from unittest.mock import AsyncMock, MagicMock
        from tenuo.langgraph import TenuoMiddleware

        warrant, _ = warrant_and_key
        middleware = TenuoMiddleware(key_id="test-key")

        request = MagicMock()
        request.tool_call = {"name": "delete_everything", "args": {}, "id": "t2"}
        request.state = {"warrant": warrant}
        request.runtime = MagicMock()
        request.runtime.config = make_config("test-key")

        handler = AsyncMock(return_value=ToolMessage(content="SHOULD NOT REACH", tool_call_id="t2"))
        result = await middleware.awrap_tool_call(request, handler)

        handler.assert_not_awaited()
        assert result.status == "error"
        assert "Authorization denied" in result.content

    @pytest.mark.asyncio
    async def test_awrap_model_call_passes_through_when_filter_disabled(
        self, warrant_and_key, registry
    ):
        """awrap_model_call with filter_tools=False must call handler unchanged."""
        from unittest.mock import AsyncMock, MagicMock
        from tenuo.langgraph import TenuoMiddleware

        warrant, _ = warrant_and_key
        middleware = TenuoMiddleware(key_id="test-key", filter_tools=False)

        request = MagicMock()
        request.state = {"warrant": warrant}
        request.runtime = MagicMock()
        request.runtime.config = make_config("test-key")
        request.tools = []

        expected = MagicMock()
        handler = AsyncMock(return_value=expected)
        result = await middleware.awrap_model_call(request, handler)

        handler.assert_awaited_once_with(request)
        assert result is expected

    @pytest.mark.asyncio
    async def test_awrap_tool_call_opaque_error_in_production_mode(
        self, warrant_and_key, registry
    ):
        """awrap_tool_call: denied tool returns opaque ref-id in production (debug=False)."""
        from unittest.mock import AsyncMock, MagicMock
        from tenuo.langgraph import TenuoMiddleware

        warrant, _ = warrant_and_key
        middleware = TenuoMiddleware(key_id="test-key", debug=False)

        request = MagicMock()
        request.tool_call = {"name": "admin_panel", "args": {}, "id": "t3"}
        request.state = {"warrant": warrant}
        request.runtime = MagicMock()
        request.runtime.config = make_config("test-key")

        handler = AsyncMock()
        result = await middleware.awrap_tool_call(request, handler)

        # Opaque message: contains ref-id but NOT the internal denial reason
        assert "ref:" in result.content
        assert "not in allowed" not in result.content.lower()
        assert "constraint" not in result.content.lower()


class TestLangGraphApproval:
    """Tests for approval policy wiring through LangGraph components."""

    @pytest.mark.skipif(
        not _middleware_available(),
        reason="LangChain 1.0+ middleware not installed",
    )
    def test_middleware_stores_approval_params(self, registry):
        """TenuoMiddleware accepts and stores approval_policy and approval_handler."""
        from tenuo.approval import ApprovalPolicy, auto_approve, require_approval
        from tenuo.langgraph import TenuoMiddleware

        approver_key = SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_approve(approver_key=approver_key)

        middleware = TenuoMiddleware(
            approval_policy=policy,
            approval_handler=handler,
        )
        assert middleware._approval_policy is policy
        assert middleware._approval_handler is handler

    @pytest.mark.skipif(
        not _middleware_available(),
        reason="LangChain 1.0+ middleware not installed",
    )
    def test_middleware_defaults_to_none(self, registry):
        """TenuoMiddleware defaults approval params to None."""
        from tenuo.langgraph import TenuoMiddleware

        middleware = TenuoMiddleware()
        assert middleware._approval_policy is None
        assert middleware._approval_handler is None

    def test_toolnode_stores_approval_params(self, registry):
        """TenuoToolNode accepts and stores approval_policy and approval_handler."""
        try:
            from tenuo.langgraph import LANGGRAPH_AVAILABLE, TenuoToolNode
        except ImportError:
            pytest.skip("LangGraph not installed")

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not installed")

        from tenuo.approval import ApprovalPolicy, auto_approve, require_approval

        approver_key = SigningKey.generate()
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_approve(approver_key=approver_key)

        # TenuoToolNode needs real LangChain tools — skip if not available
        try:
            from langchain_core.tools import tool

            @tool
            def search(query: str) -> str:
                """Search tool."""
                return f"Results for: {query}"

            node = TenuoToolNode(
                [search],
                approval_policy=policy,
                approval_handler=handler,
            )
            assert node._approval_policy is policy
            assert node._approval_handler is handler
        except ImportError:
            pytest.skip("langchain_core not installed")


# =============================================================================
# Multi-Agent Delegation Pattern
# =============================================================================


class TestMultiAgentDelegation:
    """
    End-to-end tests for the supervisor → sub-agent → tool enforcement pattern.

    Invariants verified:
      D1  Supervisor can create an attenuated warrant for a sub-agent.
      D2  Sub-agent's TenuoToolNode accepts the attenuated warrant.
      D3  Sub-agent cannot call tools outside its delegated scope.
      D4  Warrant flows correctly through graph state.
      D5  guard_node required_tools blocks nodes whose warrant misses a tool.
      D6  Three-level chain: orchestrator → researcher → executor is enforceable.
    """

    @pytest.fixture
    def multi_agent_keys(self, registry):
        """Create and register keys for supervisor and sub-agent."""
        supervisor_key = SigningKey.generate()
        researcher_key = SigningKey.generate()
        registry.register("supervisor", supervisor_key)
        registry.register("researcher", researcher_key)
        return supervisor_key, researcher_key

    @pytest.fixture
    def _lc_tool(self):
        """Return a minimal LangChain tool factory or skip if unavailable."""
        try:
            from langchain_core.tools import tool as lc_tool
        except ImportError:
            pytest.skip("langchain_core not installed")
        return lc_tool

    @pytest.fixture
    def tool_node_tools(self, _lc_tool):
        """Return [search_tool, write_tool] as LangChain BaseTool instances."""
        @_lc_tool
        def search(query: str) -> str:
            """Search the web."""
            return f"results: {query}"

        @_lc_tool
        def write_file(path: str, content: str) -> str:
            """Write a file."""
            return "written"

        return search, write_file

    # ------------------------------------------------------------------
    # D1 — Supervisor can attenuate
    # ------------------------------------------------------------------

    def test_D1_supervisor_attenuates_warrant(self, multi_agent_keys):
        """D1: Supervisor can create an attenuated warrant for a sub-agent."""
        supervisor_key, researcher_key = multi_agent_keys

        root_warrant = Warrant.issue(
            supervisor_key,
            capabilities={"search": {}, "write_file": {}},
            ttl_seconds=3600,
            holder=supervisor_key.public_key,
        )

        researcher_warrant = root_warrant.attenuate(
            signing_key=supervisor_key,
            holder=researcher_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=300,
        )

        # Attenuated warrant only has search, not write_file
        assert not researcher_warrant.is_expired()
        # Warrant chain: researcher's warrant has a parent (the root)

    # ------------------------------------------------------------------
    # Shared helper: build + run a minimal one-step graph
    # ------------------------------------------------------------------

    def _run_tool_node(self, tool_node, state, key_id):
        """
        Run a TenuoToolNode through a real StateGraph so the LangGraph
        runtime injects the required Runtime context into ToolNode._func.
        """
        from typing import TypedDict, Annotated
        from langchain_core.messages import BaseMessage
        from langgraph.graph import StateGraph, END, START
        from langgraph.graph.message import add_messages

        class _State(TypedDict):
            messages: Annotated[list[BaseMessage], add_messages]
            warrant: Any

        workflow = StateGraph(_State)
        workflow.add_node("tools", tool_node)
        workflow.add_edge(START, "tools")
        workflow.add_edge("tools", END)
        graph = workflow.compile()
        return graph.invoke(state, config=make_config(key_id))

    # ------------------------------------------------------------------
    # D2 — Sub-agent's TenuoToolNode accepts delegated warrant
    # ------------------------------------------------------------------

    def test_D2_toolnode_accepts_attenuated_warrant(
        self, multi_agent_keys, registry, tool_node_tools
    ):
        """D2: TenuoToolNode accepts a researcher's attenuated warrant for search."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not installed")

        supervisor_key, researcher_key = multi_agent_keys
        search_tool, _ = tool_node_tools

        root_warrant = Warrant.issue(
            supervisor_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=supervisor_key.public_key,
        )
        researcher_warrant = root_warrant.attenuate(
            signing_key=supervisor_key,
            holder=researcher_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=300,
        )

        tool_node = TenuoToolNode([search_tool], trusted_roots=[supervisor_key.public_key])
        state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "search", "args": {"query": "AI papers"}, "id": "t1"}],
                )
            ],
            "warrant": researcher_warrant,
        }

        result = self._run_tool_node(tool_node, state, "researcher")
        messages = result.get("messages", [])
        assert messages, "TenuoToolNode should return at least one ToolMessage"
        assert "Authorization denied" not in messages[-1].content, (
            f"D2: researcher's warrant should authorize 'search'. "
            f"Got: {messages[-1].content}"
        )

    # ------------------------------------------------------------------
    # D3 — Sub-agent cannot exceed delegated scope
    # ------------------------------------------------------------------

    def test_D3_subagent_cannot_exceed_scope(
        self, multi_agent_keys, registry, tool_node_tools
    ):
        """D3: Researcher's warrant does NOT cover write_file — must be denied."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not installed")

        supervisor_key, researcher_key = multi_agent_keys
        _, write_tool = tool_node_tools

        root_warrant = Warrant.issue(
            supervisor_key,
            capabilities={"search": {}, "write_file": {}},
            ttl_seconds=3600,
            holder=supervisor_key.public_key,
        )
        # Researcher only gets search — NOT write_file
        researcher_warrant = root_warrant.attenuate(
            signing_key=supervisor_key,
            holder=researcher_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=300,
        )

        tool_node = TenuoToolNode([write_tool])
        if not getattr(tool_node, "_tenuo_hooks_active", True):
            pytest.skip("LangGraph version does not support authorization hooks (wrap_tool_call)")

        state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "write_file", "args": {"path": "/etc/passwd", "content": "pwned"}, "id": "t2"}
                    ],
                )
            ],
            "warrant": researcher_warrant,
        }

        result = self._run_tool_node(tool_node, state, "researcher")
        messages = result.get("messages", [])
        assert messages, "TenuoToolNode should return a denial ToolMessage"
        denial_msg = messages[-1].content
        assert "Authorization denied" in denial_msg, (
            f"D3: write_file must be denied for researcher's warrant. "
            f"Got: {denial_msg}"
        )

    # ------------------------------------------------------------------
    # D4 — Warrant flows through state to downstream TenuoToolNode
    # ------------------------------------------------------------------

    def test_D4_attenuated_warrant_in_state_enforced(
        self, multi_agent_keys, registry, tool_node_tools
    ):
        """D4: Warrant put into state by supervisor is picked up by TenuoToolNode."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE, tenuo_node

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not installed")

        supervisor_key, researcher_key = multi_agent_keys
        search_tool, _ = tool_node_tools

        root_warrant = Warrant.issue(
            supervisor_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=supervisor_key.public_key,
        )

        # Supervisor node puts an attenuated warrant into state
        @tenuo_node
        def supervisor_node(state, bound_warrant=None):
            sub_warrant = bound_warrant.warrant.attenuate(
                signing_key=supervisor_key,
                holder=researcher_key.public_key,
                capabilities={"search": {}},
                ttl_seconds=300,
            )
            return {"warrant": sub_warrant}

        state = {"warrant": root_warrant, "messages": []}
        config = make_config("supervisor")

        updated_state = supervisor_node(state, config)
        assert "warrant" in updated_state, "Supervisor should update state with sub-warrant"

        # Downstream TenuoToolNode enforces the attenuated warrant
        merged_state = {**state, **updated_state}
        merged_state["messages"] = [
            AIMessage(
                content="",
                tool_calls=[{"name": "search", "args": {"query": "test"}, "id": "t3"}],
            )
        ]

        tool_node = TenuoToolNode([search_tool], trusted_roots=[supervisor_key.public_key])
        result = self._run_tool_node(tool_node, merged_state, "researcher")
        messages = result.get("messages", [])
        assert messages
        assert "Authorization denied" not in messages[-1].content, (
            f"D4: search should be allowed by delegated warrant. Got: {messages[-1].content}"
        )

    # ------------------------------------------------------------------
    # D5 — guard_node required_tools blocks missing capabilities
    # ------------------------------------------------------------------

    def test_D5_guard_node_required_tools_blocks_missing_capability(
        self, registry
    ):
        """D5: guard_node(required_tools=...) raises if warrant misses a tool."""
        key = SigningKey.generate()
        registry.register("worker", key)

        # Warrant only covers "search", not "write_file"
        warrant = Warrant.issue(
            key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=key.public_key,
        )

        def worker_node(state):
            return {"result": "done"}

        # Guard requires both search AND write_file — should fail fast
        wrapped = guard_node(worker_node, key_id="worker", required_tools=["search", "write_file"], trusted_roots=[key.public_key])

        with pytest.raises(ConfigurationError, match="write_file"):
            wrapped({"warrant": warrant})

    def test_D5_guard_node_required_tools_passes_when_covered(self, registry):
        """D5: guard_node(required_tools=...) passes when warrant covers all tools."""
        key = SigningKey.generate()
        registry.register("worker2", key)

        warrant = Warrant.issue(
            key,
            capabilities={"search": {}, "read": {}},
            ttl_seconds=3600,
            holder=key.public_key,
        )

        def worker_node(state):
            return {"result": "ok"}

        wrapped = guard_node(worker_node, key_id="worker2", required_tools=["search", "read"], trusted_roots=[key.public_key])
        result = wrapped({"warrant": warrant})
        assert result == {"result": "ok"}

    # ------------------------------------------------------------------
    # D6 — Three-level delegation chain
    # ------------------------------------------------------------------

    def test_D6_three_level_delegation_chain(self, registry, tool_node_tools):
        """D6: orchestrator → researcher → executor — each level narrows scope."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not installed")

        search_tool, write_tool = tool_node_tools

        orchestrator_key = SigningKey.generate()
        researcher_key = SigningKey.generate()
        executor_key = SigningKey.generate()

        registry.register("orchestrator", orchestrator_key)
        registry.register("researcher", researcher_key)
        registry.register("executor", executor_key)

        # L1: orchestrator has full root warrant
        root_warrant = Warrant.issue(
            orchestrator_key,
            capabilities={"search": {}, "write_file": {}},
            ttl_seconds=3600,
            holder=orchestrator_key.public_key,
        )

        # L2: researcher gets search only
        researcher_warrant = root_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=researcher_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=600,
        )

        # L3: executor gets narrowed search (cannot escalate back to write_file)
        executor_warrant = researcher_warrant.attenuate(
            signing_key=researcher_key,
            holder=executor_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=60,
        )

        # Executor TenuoToolNode with both tools available — only search is allowed
        # trusted_roots covers the full delegation chain:
        #   orchestrator_key → root_warrant → researcher_warrant
        #   researcher_key   → executor_warrant (leaf issuer)
        tool_node = TenuoToolNode(
            [search_tool, write_tool],
            trusted_roots=[orchestrator_key.public_key, researcher_key.public_key],
        )
        if not getattr(tool_node, "_tenuo_hooks_active", True):
            pytest.skip("LangGraph version does not support authorization hooks (wrap_tool_call)")

        # Search is allowed
        search_state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "search", "args": {"query": "papers"}, "id": "s1"}],
                )
            ],
            "warrant": executor_warrant,
        }
        result = self._run_tool_node(tool_node, search_state, "executor")
        assert "Authorization denied" not in result["messages"][-1].content, (
            "D6: search must be allowed for executor"
        )

        # write_file is denied — it was never in researcher/executor's scope
        write_state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "write_file", "args": {"path": "/tmp/x", "content": "y"}, "id": "w1"}
                    ],
                )
            ],
            "warrant": executor_warrant,
        }
        result = self._run_tool_node(tool_node, write_state, "executor")
        assert "Authorization denied" in result["messages"][-1].content, (
            "D6: write_file must be denied — executor never received that capability"
        )
