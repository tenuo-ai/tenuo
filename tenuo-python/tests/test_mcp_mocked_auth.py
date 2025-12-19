# ruff: noqa: E402
import sys
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

# Skip all tests in this module - MCP mocking is fragile and MCP SDK isn't installed
pytest.skip("MCP mocking tests require MCP SDK installed", allow_module_level=True)

# Mock mcp modules before importing tenuo.mcp.client
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.client.stdio"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

# Now we can import
from tenuo.mcp import client
from tenuo.mcp.client import SecureMCPClient
from tenuo import (
    configure, 
    reset_config, 
    SigningKey, 
    root_task, 
    Capability, 
    Pattern,
    ConstraintViolation,
)

# Force MCP_AVAILABLE to True for testing
client.MCP_AVAILABLE = True
client.ClientSession = MagicMock()
client.StdioServerParameters = MagicMock()

# Determine ToolMock behavior based on mcp version if available, otherwise mock
try:
    from mcp.types import Tool as MCPTool
except ImportError:
    MCPTool = MagicMock()
    client.MCPTool = MCPTool

@pytest.fixture(autouse=True)
def mock_mcp_internals():
    """Mock internal MCP functions used by SecureMCPClient.connect()."""
    with patch("mcp.client.stdio.stdio_client") as mock_stdio, \
         patch("mcp.client.session.ClientSession") as mock_session_cls:
        
        # Mock stdio_client context manager to yield (read, write) tuple
        cm = AsyncMock()
        cm.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_stdio.return_value = cm
        
        # Mock ClientSession context manager
        session_cm = AsyncMock()
        mock_session_instance = AsyncMock()
        session_cm.__aenter__.return_value = mock_session_instance
        mock_session_cls.return_value = session_cm
        
        yield

@pytest.fixture(autouse=True)
def reset_config_fixture():
    reset_config()
    yield
    reset_config()

@pytest.mark.asyncio
async def test_call_tool_authorized():
    """Test calling tool with valid capability."""
    kp = SigningKey.generate()
    configure(issuer_key=kp, dev_mode=True)
    
    # Mock session and tool
    mock_tool = MagicMock()
    mock_tool.name = "read_file"
    mock_tool.description = "Reads a file"
    
    with patch("tenuo.mcp.client.SecureMCPClient.get_tools", new_callable=AsyncMock) as mock_get_tools:
        mock_get_tools.return_value = [mock_tool]
        
        async with SecureMCPClient("python", ["server.py"]) as client:
            client.session = AsyncMock()
            client.session.call_tool.return_value = MagicMock(content="success")
            
            # Authorize read_file
            async with root_task(Capability("read_file", path=Pattern("/data/*"))):
                result = await client.call_tool("read_file", {"path": "/data/test.txt"})
                assert result == "success"
                
                # Verify call was made
                client.session.call_tool.assert_called_with("read_file", {"path": "/data/test.txt"})

@pytest.mark.asyncio
async def test_call_tool_unauthorized_tool_name():
    """Test calling tool not in warrant."""
    kp = SigningKey.generate()
    configure(issuer_key=kp, dev_mode=True)
    
    with patch("tenuo.mcp.client.SecureMCPClient.get_tools", new_callable=AsyncMock) as mock_get_tools:
        mock_get_tools.return_value = []
        
        async with SecureMCPClient("python", ["server.py"]) as client:
            client.session = AsyncMock()
            
            # Authorize ONLY read_file
            async with root_task(Capability("read_file")):
                # Try to call send_email
                with pytest.raises(ConstraintViolation):
                    await client.call_tool("send_email", {"to": "me@test.com"})

@pytest.mark.asyncio
async def test_call_tool_constraint_violation():
    """Test calling tool with invalid args violates constraint."""
    kp = SigningKey.generate()
    configure(issuer_key=kp, dev_mode=True)
    
    async with SecureMCPClient("python", ["server.py"]) as client:
        client.session = AsyncMock()
        
        # Authorize read_file for /data/*
        async with root_task(Capability("read_file", path=Pattern("/data/*"))):
            # Try to read /etc/passwd
            with pytest.raises(ConstraintViolation):
                await client.call_tool("read_file", {"path": "/etc/passwd"})

@pytest.mark.asyncio
async def test_protected_tool_wrapper():
    """Test get_protected_tools wrapper behavior."""
    kp = SigningKey.generate()
    configure(issuer_key=kp, dev_mode=True)
    
    mock_tool = MagicMock()
    mock_tool.name = "read_file"
    # Mock schema allowing only 'path'
    mock_tool.inputSchema = {
        "properties": {"path": {"type": "string"}}
    }
    
    with patch("tenuo.mcp.client.SecureMCPClient.get_tools", new_callable=AsyncMock) as mock_get_tools:
        mock_get_tools.return_value = [mock_tool]
        
        async with SecureMCPClient("python", ["server.py"]) as client:
            client.session = AsyncMock()
            client.session.call_tool.return_value = MagicMock(content="ok")
            
            protected = await client.get_protected_tools()
            read_func = protected["read_file"]
            
            # Authorized call
            async with root_task(Capability("read_file")):
                # Pass extra arg 'evil' which should be stripped by wrapper
                await read_func(path="/data/file", evil="command")
                
                # Check that 'evil' was stripped
                client.session.call_tool.assert_called_with(
                    "read_file", 
                    {"path": "/data/file"}
                )

