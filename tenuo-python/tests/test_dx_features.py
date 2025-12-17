"""
Tests for DX (Developer Experience) features.

These tests verify the simplified APIs for LangChain/LangGraph integration.
"""

import pytest
from dataclasses import dataclass

from tenuo import (
    SigningKey,
    Pattern,
    Range,
    reset_config,
    root_task_sync,
    # DX features
    TenuoToolNode,
    AuthorizationDenied,
    ConstraintResult,
    LANGCHAIN_AVAILABLE,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def keypair():
    """Generate a test keypair."""
    return SigningKey.generate()


@pytest.fixture(autouse=True)
def reset_tenuo_config():
    """Reset Tenuo configuration before each test."""
    reset_config()
    yield
    reset_config()


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


# =============================================================================
# Test: secure_agent()
# =============================================================================

@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
class TestSecureAgent:
    """Tests for the secure_agent() one-liner."""

    def test_secure_agent_basic(self, keypair):
        """Test basic secure_agent usage."""
        from tenuo.langchain import secure_agent, TenuoTool
        
        tools = [MockTool("search"), MockTool("calculator")]
        
        # One-liner to secure tools
        protected = secure_agent(tools, issuer_keypair=keypair)
        
        # Should return wrapped tools
        assert len(protected) == 2
        assert all(isinstance(t, TenuoTool) for t in protected)
        assert protected[0].name == "search"
        assert protected[1].name == "calculator"

    def test_secure_agent_configures_tenuo(self, keypair):
        """Test that secure_agent configures Tenuo globally."""
        from tenuo import is_configured, get_config
        from tenuo.langchain import secure_agent
        
        assert not is_configured()
        
        tools = [MockTool("search")]
        secure_agent(tools, issuer_keypair=keypair)
        
        assert is_configured()
        config = get_config()
        assert config is not None
        assert config.warn_on_missing_warrant is True  # Default

    def test_secure_agent_strict_mode(self, keypair):
        """Test strict_mode parameter."""
        from tenuo import get_config
        from tenuo.langchain import secure_agent
        
        tools = [MockTool("search")]
        secure_agent(tools, issuer_keypair=keypair, strict_mode=True)
        
        config = get_config()
        assert config is not None
        assert config.strict_mode is True

    def test_secure_agent_idempotent(self, keypair):
        """Test that secure_agent is idempotent."""
        from tenuo import is_configured
        from tenuo.langchain import secure_agent
        
        tools = [MockTool("search")]
        
        # First call configures
        secure_agent(tools, issuer_keypair=keypair)
        assert is_configured()
        
        # Second call should not fail
        protected = secure_agent(tools, issuer_keypair=keypair)
        assert len(protected) == 1


# =============================================================================
# Test: TenuoToolNode
# =============================================================================

class TestTenuoToolNode:
    """Tests for TenuoToolNode (requires langgraph)."""
    
    def test_tenuo_tool_node_creation(self, keypair):
        """Test creating a TenuoToolNode."""
        tools = [MockTool("search"), MockTool("calculator")]
        
        # Should create successfully
        node = TenuoToolNode(tools)
        
        assert node._tools == tools
        assert len(node._protected_tools) == 2
        assert node.original_tools == tools

    def test_tenuo_tool_node_strict_mode(self, keypair):
        """Test TenuoToolNode with strict mode."""
        tools = [MockTool("search")]
        
        node = TenuoToolNode(tools, strict=True)
        
        assert node._strict is True


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

    def test_authorization_denied_with_constraints(self):
        """Test AuthorizationDenied with constraint results."""
        results = [
            ConstraintResult(
                name="path",
                passed=False,
                constraint_repr='Pattern("/data/*")',
                value="/etc/passwd",
                explanation="Pattern does not match",
            ),
            ConstraintResult(
                name="size",
                passed=True,
                constraint_repr='Range(max=1000)',
                value=500,
            ),
        ]
        
        error = AuthorizationDenied(
            tool="read_file",
            constraint_results=results,
        )
        
        msg = str(error)
        
        # Check failed constraint appears first with details
        assert "❌ path:" in msg
        assert 'Pattern("/data/*")' in msg
        assert "/etc/passwd" in msg  # Value appears in repr form
        
        # Check passed constraint appears with OK
        assert "✅ size: OK" in msg

    def test_authorization_denied_from_constraint_check(self):
        """Test creating AuthorizationDenied from constraint check."""
        constraints = {
            "path": Pattern("/data/*"),
            "size": Range(max=1000),
        }
        args = {
            "path": "/etc/passwd",
            "size": 500,
        }
        
        error = AuthorizationDenied.from_constraint_check(
            tool="read_file",
            constraints=constraints,
            args=args,
            failed_field="path",
            failed_reason="Pattern does not match",
        )
        
        msg = str(error)
        assert "read_file" in msg
        assert "❌ path" in msg
        assert "✅ size" in msg

    def test_constraint_result_str(self):
        """Test ConstraintResult string representation."""
        passed = ConstraintResult(
            name="path",
            passed=True,
            constraint_repr='Exact("/data/file.txt")',
            value="/data/file.txt",
        )
        assert "✅" in str(passed)
        assert "OK" in str(passed)
        
        failed = ConstraintResult(
            name="path",
            passed=False,
            constraint_repr='Pattern("/data/*")',
            value="/etc/passwd",
            explanation="Pattern mismatch",
        )
        assert "❌" in str(failed)
        assert "Pattern mismatch" in str(failed)

    def test_authorization_denied_to_dict(self):
        """Test converting AuthorizationDenied to dict for logging."""
        error = AuthorizationDenied(
            tool="search",
            constraint_results=[
                ConstraintResult(
                    name="query",
                    passed=False,
                    constraint_repr='Pattern("safe*")',
                    value="DROP TABLE",
                    explanation="Blocked pattern",
                ),
            ],
        )
        
        d = error.to_dict()
        
        assert d["error_code"] == "authorization_denied"
        assert d["details"]["tool"] == "search"
        assert len(d["details"]["constraints"]) == 1
        assert d["details"]["constraints"][0]["name"] == "query"
        assert d["details"]["constraints"][0]["passed"] is False


# =============================================================================
# Test: Integration with root_task
# =============================================================================

@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
class TestDXIntegration:
    """Integration tests for DX features with root_task."""

    def test_secure_agent_with_root_task(self, keypair):
        """Test secure_agent tools work with root_task context."""
        from tenuo.langchain import secure_agent
        
        tools = [MockTool("search")]
        protected = secure_agent(tools, issuer_keypair=keypair)
        
        # Should work within root_task context
        with root_task_sync(tools=["search"]):
            # Tool is accessible
            result = protected[0]._run(query="test")
            assert "search" in result

    def test_secure_agent_blocks_unauthorized(self, keypair):
        """Test secure_agent blocks unauthorized tool access."""
        from tenuo.langchain import secure_agent
        from tenuo.exceptions import ToolNotAuthorized
        
        tools = [MockTool("search"), MockTool("delete")]
        protected = secure_agent(tools, issuer_keypair=keypair)
        
        # Only authorize "search", not "delete"
        with root_task_sync(tools=["search"]):
            # search should work
            protected[0]._run(query="test")
            
            # delete should fail
            with pytest.raises(ToolNotAuthorized):
                protected[1]._run(target="important_file")
