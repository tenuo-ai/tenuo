"""
Integration tests for Tenuo + MCP.

Tests SecureMCPClient with a real MCP server.
"""

import pytest
import tempfile
import os
from pathlib import Path

# Check if MCP is available
try:
    from tenuo.mcp import SecureMCPClient, MCP_AVAILABLE
    from tenuo import SigningKey, configure, root_task, Pattern, Range, McpConfig, CompiledMcpConfig, Capability
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
    
    # Create test file using tempfile for cross-platform support
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
        tf.write("test content")
        test_file_path = tf.name
    test_file = Path(test_file_path)
    
    try:
        async with SecureMCPClient(
            command="python",
            args=[str(mcp_server_script)]
        ) as client:
            # Get protected tool
            protected_tools = await client.get_protected_tools()
            read_file = protected_tools["read_file"]
            
            # Call with authorization
            async with root_task(Capability("read_file", path=Pattern("*"))):
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
        
        # Try to read outside allowed path (Pattern matches nothing effectively or specific file)
        # We allow * but check a specific exclusion or just use a restricted pattern
        async with root_task(Capability("read_file", path=Pattern("*.allowed"))):
            with pytest.raises(ConstraintViolation):
                # This file doesn't match *.allowed
                await read_file(path=str(Path(tempfile.gettempdir()) / "forbidden.txt"))


@pytest.mark.asyncio
async def test_mcp_client_with_config_registration(mcp_server_script):
    """Test that register_config=True works."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    # Create a simple config
    config_yaml = """
version: "1"
tools:
  read_file:
    description: "Read file contents"
    constraints:
      max_size:
        from: body
        path: "max_size"
        type: integer
        default: 1000
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_yaml)
        config_path = f.name
    
    try:
        # Configure Tenuo
        keypair = SigningKey.generate()
        configure(issuer_key=keypair, dev_mode=True)
        
        async with SecureMCPClient(
            command="python",
            args=[str(mcp_server_script)],
            config_path=config_path,
            register_config=True
        ) as client:
            protected_tools = await client.get_protected_tools()
            read_file = protected_tools["read_file"]
            
            # This should work and use the default max_size from config
            async with root_task(Capability("read_file", path=Pattern("*"), max_size=Range.max_value(2000))):
                # Test file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                    tf.write("small")
                    test_file = tf.name
                
                try:
                    result = await read_file(path=test_file)
                    assert "small" in result[0].text
                finally:
                    os.unlink(test_file)
    finally:
        os.unlink(config_path)


@pytest.mark.asyncio
async def test_mcp_warrant_injection(mcp_server_script):
    """Test that warrant injection works."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    # Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    async with SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)]
    ) as client:
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write("injection test")
            test_file_path = tf.name
        test_file = Path(test_file_path)
        
        try:
            async with root_task(Capability("read_file", path=Pattern("*"))):
                # Call tool with injection
                result = await client.call_tool(
                    "read_file",
                    {"path": str(test_file)},
                    inject_warrant=True
                )
                assert "injection test" in result[0].text
        finally:
            if test_file.exists():
                test_file.unlink()


@pytest.mark.asyncio
async def test_mcp_nested_field_extraction():
    """Test extraction of nested fields from MCP arguments."""
    config_yaml = """
version: "1"
tools:
  db_query:
    description: "Execute a database query"
    constraints:
      table:
        from: body
        path: "query.table"
      op:
        from: body
        path: "query.operation"
"""
    # Write to temp file since McpConfig only has from_file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_yaml)
        config_path = f.name
    
    try:
        config = McpConfig.from_file(config_path)
        compiled = CompiledMcpConfig.compile(config)
        
        args = {
            "query": {
                "table": "users",
                "operation": "SELECT"
            }
        }
        
        result = compiled.extract_constraints("db_query", args)
        constraints = dict(result.constraints)
        
        assert constraints["table"] == "users"
        assert constraints["op"] == "SELECT"
    finally:
        os.unlink(config_path)


@pytest.mark.asyncio
async def test_discover_and_protect_usage(mcp_server_script):
    """Test discover_and_protect as context manager."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
    
    from tenuo import SigningKey, configure, root_task, Pattern, Capability
    from tenuo.mcp.client import discover_and_protect
    
    # Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
        tf.write("context_manager_test")
        test_file = tf.name
        
    try:
        async with discover_and_protect("python", [str(mcp_server_script)]) as tools:
            assert "read_file" in tools
            read_file = tools["read_file"]
            
            async with root_task(Capability("read_file", path=Pattern("*"))):
                result = await read_file(path=test_file)
                assert "context_manager_test" in result[0].text
    finally:
        os.unlink(test_file)


@pytest.mark.asyncio
async def test_config_auto_registration(mcp_server_script):
    """Test that config is automatically registered when config_path is provided."""
    if not mcp_server_script.exists():
        pytest.skip("MCP server script not found")
        
    from tenuo import get_config, SigningKey, configure
    
    # Reset config
    from tenuo.config import reset_config
    reset_config()
    
    # Setup minimal config
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    # Ensure no MCP config initially
    assert get_config().mcp_config is None
    
    # Create MCP config file
    config_yaml = """
version: "1"
tools:
  read_file:
    description: "Read file contents"
    constraints:
      max_size:
        from: body
        path: "max_size"
        type: integer
        default: 12345
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_yaml)
        config_path = f.name
        
    try:
        # Initialize client with config_path (no register_config arg)
        # Should default to registering
        async with SecureMCPClient(
            command="python", 
            args=[str(mcp_server_script)],
            config_path=config_path
        ) as _client:  # noqa: F841
            # Check global config
            conf = get_config()
            assert conf.mcp_config is not None
            # Verify it's the right config by checking compiled output or similar
            # Deep inspection might be hard, but presence is good enough for this test
            
    finally:
        os.unlink(config_path)
