import sys
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

# Skip entire module if pytest-asyncio isn't available
pytest_asyncio = pytest.importorskip("pytest_asyncio")

# Mock mcp modules before importing tenuo.mcp.client
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.client.stdio"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

# Now we can import (must come after mocking sys.modules)
from tenuo.mcp import client  # noqa: E402
from tenuo.mcp.client import SecureMCPClient, discover_and_protect  # noqa: E402
import tenuo  # noqa: E402

# Force MCP_AVAILABLE to True for testing
client.MCP_AVAILABLE = True
client.ClientSession = MagicMock()
client.StdioServerParameters = MagicMock()
client.MCPTool = MagicMock()

# Mock Tenuo config classes
tenuo.McpConfig = MagicMock()
tenuo.CompiledMcpConfig = MagicMock()

@pytest.mark.asyncio
async def test_init_register_config_defaults():
    """Test register_config defaults logic."""
    # Case 1: No config_path -> register_config should be False (default)
    c1 = SecureMCPClient("python", ["server.py"])
    assert c1.config_path is None
    # Check internal state or side effects - actually we can't easily check 'register_config' local var 
    # but we can check if it attempted to configure tenuo.
    # We'll mock 'tenuo.config.configure'
    
    with patch("tenuo.config.configure") as mock_configure:
        # Case 2: config_path provided, register_config=None -> should register
        SecureMCPClient("python", ["server.py"], config_path="mcp.yaml")
        assert mock_configure.called
        
    with patch("tenuo.config.configure") as mock_configure:
        # Case 3: config_path provided, register_config=False -> should NOT register
        SecureMCPClient("python", ["server.py"], config_path="mcp.yaml", register_config=False)
        assert not mock_configure.called

    with patch("tenuo.config.configure") as mock_configure:
        # Case 4: config_path provided, register_config=True -> should register
        SecureMCPClient("python", ["server.py"], config_path="mcp.yaml", register_config=True)
        assert mock_configure.called

@pytest.mark.asyncio
async def test_discover_and_protect_context_manager():
    """Test discover_and_protect as async context manager."""
    
    # Mock SecureMCPClient to verify context manager usage
    with patch("tenuo.mcp.client.SecureMCPClient") as MockClient:
        instance = MockClient.return_value
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock()
        instance.get_protected_tools = AsyncMock(return_value={"tool": "wrapper"})
        
        # Verify usage
        async with discover_and_protect("python", ["server.py"]) as tools:
            assert tools == {"tool": "wrapper"}
            # Session should be open (aenter called, aexit not yet)
            assert instance.__aenter__.called
            assert not instance.__aexit__.called
            
        # After block, session should be closed
        assert instance.__aexit__.called
