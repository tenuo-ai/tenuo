"""
Tests for TenuoToolNode and LangGraph DX features.

These tests verify the TenuoToolNode that uses KeyRegistry pattern.
"""

import pytest
from dataclasses import dataclass
from typing import Dict, Any, List

from tenuo import (
    SigningKey,
    Warrant,
    KeyRegistry,
    Pattern,
    Range,
    AuthorizationDenied,
    ConstraintResult,
    LANGCHAIN_AVAILABLE,
)
from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE


# =============================================================================
# Test Fixtures
# =============================================================================

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
    """Create a test warrant and register the key it was issued with."""
    warrant, key = Warrant.quick_issue(tools=["search", "calculator"], ttl=3600)
    registry.register("test-key", key)
    return warrant, "test-key"


def make_config(key_id: str) -> Dict[str, Any]:
    """Create a LangGraph-style config with key_id."""
    return {"configurable": {"tenuo_key_id": key_id}}


# =============================================================================
# Mock LangChain Tools (for testing without actual LangChain)
# =============================================================================

@dataclass
class MockTool:
    """Mock LangChain-like tool for testing."""
    name: str
    description: str = "A mock tool"
    
    def _run(self, **kwargs):
        return f"MockTool({self.name}) called with {kwargs}"
    
    async def _arun(self, **kwargs):
        return self._run(**kwargs)
    
    def invoke(self, input: Dict[str, Any], config=None):
        """LangChain-style invoke."""
        return self._run(**input)


class MockMessage:
    """Mock LangChain message with tool_calls."""
    def __init__(self, tool_calls: List[Dict]):
        self.tool_calls = tool_calls


# =============================================================================
# Test: TenuoToolNode
# =============================================================================

@pytest.mark.skipif(not LANGGRAPH_AVAILABLE, reason="LangGraph not installed")
class TestTenuoToolNode:
    """Tests for TenuoToolNode (requires langgraph)."""
    
    def test_tenuo_tool_node_creation(self, keypair):
        """Test creating a TenuoToolNode."""
        from langchain_core.tools import tool
        
        @tool
        def search(query: str) -> str:
            """Search for something."""
            return f"Results for: {query}"
        
        @tool
        def calculator(expression: str) -> str:
            """Calculate expression."""
            return f"Result: {expression}"
        
        tools = [search, calculator]
        
        # Should create successfully
        node = TenuoToolNode(tools)
        
        # Verify tools are registered
        assert "search" in node.tools_by_name
        assert "calculator" in node.tools_by_name
    
    def test_tenuo_tool_node_execution(self, warrant_and_key, registry):
        """Test TenuoToolNode executes tools with authorization."""
        from langchain_core.tools import tool
        from langchain_core.messages import AIMessage
        
        warrant, key_id = warrant_and_key
        
        @tool
        def search(query: str) -> str:
            """Search for something."""
            return f"Results for: {query}"
        
        node = TenuoToolNode([search])
        
        # Create state with warrant (key_id in config)
        state = {
            "warrant": warrant,
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{
                        "name": "search",
                        "args": {"query": "test"},
                        "id": "call_123"
                    }]
                )
            ]
        }
        config = make_config(key_id)
        
        result = node(state, config=config)
        
        # Should have executed the tool
        assert "messages" in result
        assert len(result["messages"]) == 1
        # Check the result is a ToolMessage with content
        msg = result["messages"][0]
        assert hasattr(msg, 'content')
    
    def test_tenuo_tool_node_missing_warrant(self, registry):
        """TenuoToolNode fails gracefully without warrant in state."""
        from langchain_core.tools import tool
        from langchain_core.messages import AIMessage
        
        @tool
        def search(query: str) -> str:
            """Search."""
            return "results"
        
        node = TenuoToolNode([search])
        
        # State without warrant
        state = {
            "key_id": "test-key",
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "search", "args": {}, "id": "call_1"}]
                )
            ]
        }
        
        result = node(state)
        
        # Should return error message
        assert "Security Error" in result["messages"][0].content or "error" in result["messages"][0].content.lower()
    
    def test_tenuo_tool_node_tool_not_found(self, warrant_and_key, registry):
        """TenuoToolNode handles missing tools gracefully."""
        from langchain_core.tools import tool
        from langchain_core.messages import AIMessage
        
        warrant, key_id = warrant_and_key
        
        @tool
        def search(query: str) -> str:
            """Search."""
            return "results"
        
        node = TenuoToolNode([search])
        
        # Request a tool that doesn't exist
        state = {
            "warrant": warrant,
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "nonexistent", "args": {}, "id": "call_1"}]
                )
            ]
        }
        config = make_config(key_id)
        
        result = node(state, config=config)
        
        assert "not found" in result["messages"][0].content.lower() or "error" in result["messages"][0].content.lower()


# =============================================================================
# Test: AuthorizationDenied (diff-style errors)
# =============================================================================

class TestAuthorizationDenied:
    """Tests for diff-style error messages."""

    def test_authorization_denied_basic(self):
        """Test basic AuthorizationDenied error."""
        error = AuthorizationDenied(
            tool="read_file",
            reason="Tool not in warrant scope",
        )
        
        assert "read_file" in str(error)
        assert "Tool not in warrant scope" in str(error)

    def test_authorization_denied_with_constraint_results(self):
        """Test AuthorizationDenied with constraint results."""
        results = [
            ConstraintResult(
                name="path",
                passed=False,
                constraint_repr="Pattern('/data/*')",
                value="/etc/passwd",
                explanation="Pattern does not match"
            ),
            ConstraintResult(
                name="size",
                passed=True,
                constraint_repr="Range(max=1000)",
                value=500,
            )
        ]
        
        error = AuthorizationDenied(
            tool="read_file",
            constraint_results=results,
            reason="Constraint violation",
        )
        
        error_str = str(error)
        assert "read_file" in error_str

    def test_authorization_denied_to_dict(self):
        """Test that AuthorizationDenied has to_dict method."""
        error = AuthorizationDenied(
            tool="search",
            reason="Rate limit exceeded",
        )
        
        data = error.to_dict()
        # to_dict returns TenuoError base fields
        assert "error_code" in data
        assert data["error_code"] == "authorization_denied"


# =============================================================================
# Test: ConstraintResult
# =============================================================================

class TestConstraintResult:
    """Tests for constraint result types."""

    def test_constraint_result_passed(self):
        """Test successful constraint check."""
        result = ConstraintResult(
            name="path",
            passed=True,
            constraint_repr="Pattern('/data/*')",
            value="/data/file.txt",
        )
        assert result.passed is True
        assert "OK" in str(result)

    def test_constraint_result_failed(self):
        """Test denied constraint check."""
        result = ConstraintResult(
            name="path",
            passed=False,
            constraint_repr="Pattern('/data/*')",
            value="/etc/passwd",
            explanation="Pattern does not match",
        )
        assert result.passed is False
        assert result.explanation == "Pattern does not match"

    def test_constraint_result_str_representation(self):
        """Test constraint result string representation."""
        result = ConstraintResult(
            name="size",
            passed=True,
            constraint_repr="Range(0, 100)",
            value=50,
        )
        
        s = str(result)
        assert "size" in s
        assert "✅" in s or "OK" in s


# =============================================================================
# Test: Pattern and Range Constraints
# =============================================================================

class TestConstraintTypes:
    """Tests for constraint type display."""

    def test_pattern_display(self):
        """Test Pattern constraint display."""
        p = Pattern("/data/*")
        assert "/data/*" in str(p)
        
    def test_range_display(self):
        """Test Range constraint display."""
        r = Range(min=0, max=100)
        assert "0" in str(r) or "100" in str(r)


# =============================================================================
# Test: secure_agent (LangChain)
# =============================================================================

@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
class TestSecureAgent:
    """Tests for the secure_agent() one-liner."""

    def test_secure_agent_basic(self, keypair):
        """Test basic secure_agent usage."""
        from tenuo import reset_config
        from tenuo.langchain import secure_agent, TenuoTool
        
        reset_config()
        
        @dataclass
        class Tool:
            name: str = "search"
            description: str = "Search tool"
            def _run(self, **kwargs): return "result"
        
        tools = [Tool()]
        
        # One-liner to secure tools
        protected = secure_agent(tools, issuer_keypair=keypair)
        
        # Should return wrapped tools
        assert len(protected) == 1
        assert all(isinstance(t, TenuoTool) for t in protected)
        assert protected[0].name == "search"
