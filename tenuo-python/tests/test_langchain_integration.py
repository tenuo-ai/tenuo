"""
Tests for Tenuo LangChain integration.

Tests both Tier 1 (context-based) and Tier 2 (explicit) APIs.
"""

import pytest
from tenuo import (
    configure,
    reset_config,
    mint_sync,
    SigningKey,
    ConfigurationError,
    LANGCHAIN_AVAILABLE,
    Capability,
)
from tenuo.exceptions import ToolNotAuthorized

# Skip all tests if LangChain is not installed
pytestmark = pytest.mark.skipif(
    not LANGCHAIN_AVAILABLE,
    reason="LangChain not installed"
)


@pytest.fixture(autouse=True)
def reset_config_fixture():
    """Reset config before and after each test."""
    reset_config()
    yield
    reset_config()


# =============================================================================
# Mock LangChain tools for testing
# =============================================================================

if LANGCHAIN_AVAILABLE:
    try:
        from langchain_core.tools import tool
        from tenuo.langchain import guard_tools, TenuoTool
        
        @tool
        def search(query: str) -> str:
            """Search for information."""
            return f"Results for: {query}"
        
        @tool
        def read_file(path: str) -> str:
            """Read a file from disk."""
            return f"Contents of: {path}"
        
        @tool
        def write_file(path: str, content: str) -> str:
            """Write content to a file."""
            return f"Wrote {len(content)} bytes to {path}"
        
        @tool
        def http_request(url: str) -> str:
            """Make an HTTP request."""
            return f"Response from: {url}"
    except Exception:
        # Fallback for Pydantic/LangChain compatibility issues
        LANGCHAIN_AVAILABLE = False


class TestProtectLangchainTools:
    """Tests for guard_tools() - Tier 1 API."""
    
    def test_wraps_tools(self):
        """guard_tools wraps tools in TenuoTool."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search, read_file])
        
        assert len(tools) == 2
        assert all(isinstance(t, TenuoTool) for t in tools)
    
    def test_preserves_tool_names(self):
        """Wrapped tools preserve original names."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search, read_file])
        
        assert tools[0].name == "search"
        assert tools[1].name == "read_file"
    
    def test_preserves_descriptions(self):
        """Wrapped tools preserve original descriptions."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search])
        
        assert "Search" in tools[0].description
    
    def test_allows_authorized_tool(self):
        """Protected tool allows execution with valid warrant."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search])
        
        with mint_sync(Capability("search")):
            result = tools[0].invoke({"query": "test"})
            assert "Results for: test" in result
    
    def test_blocks_without_warrant(self):
        """Protected tool blocks execution without warrant."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search])
        
        # No mint - no warrant in context
        with pytest.raises(ToolNotAuthorized):
            tools[0].invoke({"query": "test"})
    
    def test_blocks_unauthorized_tool(self):
        """Protected tool blocks execution for unauthorized tools."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search, read_file])
        
        # Warrant only allows "search", not "read_file"
        with mint_sync(Capability("search")):
            # search is authorized
            result = tools[0].invoke({"query": "test"})
            assert result is not None
            
            # read_file is NOT authorized
            with pytest.raises(ToolNotAuthorized):
                tools[1].invoke({"path": "/data/test.txt"})
    
    def test_multiple_tools_authorized(self):
        """Multiple tools can be authorized."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search, read_file])
        
        with mint_sync(Capability("search"), Capability("read_file")):
            result1 = tools[0].invoke({"query": "test"})
            result2 = tools[1].invoke({"path": "/data/test.txt"})
            
            assert "Results for" in result1
            assert "Contents of" in result2


class TestTenuoTool:
    """Tests for TenuoTool wrapper class."""
    
    def test_is_langchain_tool(self):
        """TenuoTool is a valid LangChain BaseTool."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        from langchain_core.tools import BaseTool
        
        wrapped = TenuoTool(search)
        assert isinstance(wrapped, BaseTool)
    
    def test_run_method(self):
        """TenuoTool._run executes with authorization."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        wrapped = TenuoTool(search)
        
        with mint_sync(Capability("search")):
            result = wrapped._run(query="test query")
            assert "Results for: test query" in result
    
    def test_invoke_method(self):
        """TenuoTool.invoke executes with authorization."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        wrapped = TenuoTool(search)
        
        with mint_sync(Capability("search")):
            result = wrapped.invoke({"query": "test query"})
            assert "Results for: test query" in result


class TestPassthrough:
    """Tests for passthrough mode with LangChain tools."""
    
    def test_passthrough_blocked_by_default(self):
        """Passthrough is blocked in production mode."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, trusted_roots=[kp.public_key])
        
        tools = guard_tools([search])
        
        with pytest.raises(ToolNotAuthorized):
            tools[0].invoke({"query": "test"})
    
    def test_passthrough_allowed_in_dev_mode(self):
        """Passthrough is allowed in dev mode with allow_passthrough."""
        kp = SigningKey.generate()
        configure(
            issuer_key=kp,
            dev_mode=True,
            allow_passthrough=True,
        )
        
        tools = guard_tools([search])
        
        # No mint - but passthrough is allowed
        result = tools[0].invoke({"query": "test"})
        assert "Results for" in result


class TestStrictMode:
    """Tests for strict mode with LangChain tools."""
    
    def test_strict_mode_requires_constraints(self):
        """Strict mode requires constraints for require_at_least_one tools."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        from tenuo.schemas import ToolSchema, register_schema
        
        # Register a schema that requires constraints
        register_schema("search", ToolSchema(
            recommended_constraints=["query"],
            require_at_least_one=True,
            risk_level="medium",
        ))
        
        tools = guard_tools([search], strict=True)
        
        # Without constraints - should fail in strict mode
        with mint_sync(Capability("search")):
            with pytest.raises(ConfigurationError, match="requires at least one constraint"):
                tools[0].invoke({"query": "test"})
    
    def test_non_strict_allows_without_constraints(self):
        """Non-strict mode allows tools without constraints."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search], strict=False)
        
        with mint_sync(Capability("search")):
            result = tools[0].invoke({"query": "test"})
            assert "Results for" in result


class TestWithScopedTask:
    """Tests for LangChain tools with grant."""
    
    def test_scoped_task_narrows_tools(self):
        """grant narrows available tools."""
        from tenuo import grant
        
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = guard_tools([search, read_file])
        
        with mint_sync(Capability("search"), Capability("read_file")):
            # Both tools work at root level
            assert tools[0].invoke({"query": "test"}) is not None
            assert tools[1].invoke({"path": "/data/test.txt"}) is not None
            
            # Narrow to just search
            with grant(Capability("search")):
                # search still works
                assert tools[0].invoke({"query": "test"}) is not None
                
                # read_file is blocked
                with pytest.raises(ToolNotAuthorized):
                    tools[1].invoke({"path": "/data/test.txt"})
