"""
Integration tests for Tenuo + MCP.

Tests SecureMCPClient with a real MCP server.
"""

import pytest
from pathlib import Path

# Check if MCP is available
try:
    from tenuo.mcp import SecureMCPClient, MCP_AVAILABLE
    from tenuo import SigningKey, configure, root_task, Pattern
    pytestmark = pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
except ImportError:
    pytestmark = pytest.mark.skip(reason="MCP integration not available")


@pytest.fixture
def mcp_server_script():
    """Path to test MCP server."""
    return Path(__file__).parent.parent / "examples" / "mcp_server_demo.py"


@pytest.mark.asyncio
async def test_mcp_client_connection(mcp_server_script):
    """Test connecting to MCP server."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    async with SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)]
    ) as client:
        assert client.session is not None
        tools = await client.get_tools()
        assert len(tools) > 0


@pytest.mark.asyncio
async def test_mcp_tool_discovery(mcp_server_script):
    """Test discovering MCP tools."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    async with SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)]
    ) as client:
        tools = await client.get_tools()
        tool_names = [t.name for t in tools]
        
        assert "read_file" in tool_names
        assert "list_directory" in tool_names


@pytest.mark.asyncio
async def test_mcp_tool_call_authorized(mcp_server_script):
    """Test calling MCP tool with authorization."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    # Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    # Create test file
    test_file = Path("/tmp/tenuo_mcp_test.txt")
    test_file.write_text("test content")
    
    try:
        async with SecureMCPClient(
            command="python",
            args=[str(mcp_server_script)]
        ) as client:
            # Get protected tool
            protected_tools = await client.get_protected_tools()
            read_file = protected_tools["read_file"]
            
            # Call with authorization
            async with root_task(tools=["read_file"], path=Pattern("/tmp/*")):
                result = await read_file(path=str(test_file))
                assert result is not None
                assert len(result) > 0
                assert "test content" in result[0].text
    finally:
        if test_file.exists():
            test_file.unlink()


@pytest.mark.asyncio
async def test_mcp_tool_call_blocked(mcp_server_script):
    """Test that unauthorized calls are blocked."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    from tenuo import ConstraintViolation
    
    # Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    async with SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)]
    ) as client:
        protected_tools = await client.get_protected_tools()
        read_file = protected_tools["read_file"]
        
        # Try to read outside allowed path
        async with root_task(tools=["read_file"], path=Pattern("/tmp/*")):
            with pytest.raises(ConstraintViolation):
                await read_file(path="/etc/passwd")


@pytest.mark.asyncio
async def test_mcp_client_without_config(mcp_server_script):
    """Test MCP client without mcp-config.yaml."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    # Should work without config (no constraint extraction)
    async with SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)]
    ) as client:
        tools = await client.get_tools()
        assert len(tools) > 0
