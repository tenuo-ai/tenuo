"""
Secure MCP Client with Tenuo Authorization.

Wraps the MCP Python SDK to add cryptographic authorization for tool calls.
"""

from contextlib import AsyncExitStack
from typing import Any, Callable, Dict, List, Optional

from ..config import is_configured
from ..decorators import lockdown
from ..exceptions import ConfigurationError

# Optional MCP import (requires Python 3.10+)
try:
    from mcp import ClientSession, StdioServerParameters  # type: ignore[import-not-found]
    from mcp.client.stdio import stdio_client  # type: ignore[import-not-found]
    from mcp.types import Tool as MCPTool  # type: ignore[import-not-found]
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    ClientSession = object  # type: ignore
    StdioServerParameters = object  # type: ignore
    MCPTool = object  # type: ignore

import sys
if sys.version_info < (3, 10) and MCP_AVAILABLE:
    # Should not happen if installed correctly, but guard anyway
    MCP_AVAILABLE = False


class SecureMCPClient:
    """
    MCP client with Tenuo authorization.
    
    Wraps the MCP Python SDK and automatically protects tool calls with warrants.
    
    Example:
        async with SecureMCPClient("python", ["mcp_server.py"]) as client:
            # Tools are auto-discovered and protected
            tools = await client.get_tools()
            
            # Use with warrant context
            with root_task_sync(tools=["read_file"], path="/data/*"):
                result = await client.call_tool("read_file", {"path": "/data/file.txt"})
    """
    
    def __init__(
        self,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        config_path: Optional[str] = None,
    ):
        """
        Initialize MCP client.
        
        Args:
            command: Command to run MCP server ("python" or "node")
            args: Arguments to pass to server (e.g., ["server.py"])
            env: Environment variables for server process
            config_path: Path to mcp-config.yaml (optional)
        """
        if not MCP_AVAILABLE:
            raise ImportError(
                "MCP SDK not installed. Install with: pip install tenuo[mcp]"
            )
        
        self.command = command
        self.args = args
        self.env = env
        self.config_path = config_path
        
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self._tools: Optional[List[MCPTool]] = None
        self._wrapped_tools: Dict[str, Callable] = {}
        
        # Load MCP config if provided
        self.mcp_config = None
        self.compiled_config = None
        if config_path:
            from tenuo import McpConfig, CompiledMcpConfig
            self.mcp_config = McpConfig.from_file(config_path)
            self.compiled_config = CompiledMcpConfig.compile(self.mcp_config)
    
    async def __aenter__(self):
        """Connect to MCP server."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Disconnect from MCP server."""
        await self.close()
    
    async def connect(self):
        """Connect to the MCP server."""
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env
        )
        
        # Connect via stdio
        stdio_transport = await self.exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        stdio, write = stdio_transport
        
        # Create session
        self.session = await self.exit_stack.enter_async_context(
            ClientSession(stdio, write)
        )
        
        # Initialize protocol
        await self.session.initialize()
        
        # Discover tools
        response = await self.session.list_tools()
        self._tools = response.tools
    
    async def close(self):
        """Close the MCP connection."""
        await self.exit_stack.aclose()
    
    async def get_tools(self) -> List[MCPTool]:
        """
        Get available MCP tools.
        
        Returns list of MCP Tool objects with name, description, inputSchema.
        """
        if self._tools is None:
            response = await self.session.list_tools()  # type: ignore[union-attr]
            self._tools = response.tools
        return self._tools
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        warrant_context: bool = True
    ) -> Any:
        """
        Call an MCP tool with Tenuo authorization.
        
        Args:
            tool_name: Name of the MCP tool to call
            arguments: Tool arguments
            warrant_context: If True, use warrant from context (requires root_task)
        
        Returns:
            Tool result from MCP server
        
        Raises:
            ConfigurationError: If Tenuo not configured and warrant_context=True
            ConstraintViolation: If arguments don't satisfy warrant constraints
        """
        if self.session is None:
            raise RuntimeError("Not connected to MCP server. Call connect() first.")
        
        # Extract constraints if config provided
        extracted_args = arguments
        if self.compiled_config:
            result = self.compiled_config.extract_constraints(tool_name, arguments)
            extracted_args = dict(result.constraints)
        
        # Authorize if warrant context is enabled
        if warrant_context:
            if not is_configured():
                raise ConfigurationError(
                    "Tenuo not configured. Call configure() or use warrant_context=False"
                )
            
            # Create protected wrapper
            @lockdown(tool=tool_name)
            async def _authorized_call(**kwargs):
                # Actually call MCP server
                response = await self.session.call_tool(tool_name, kwargs)
                return response.content
            
            # Call with authorization
            return await _authorized_call(**extracted_args)
        else:
            # Call without authorization
            response = await self.session.call_tool(tool_name, extracted_args)
            return response.content
    
    def create_protected_tool(self, mcp_tool: MCPTool) -> Callable:
        """
        Create a protected Python function wrapper for an MCP tool.
        
        Args:
            mcp_tool: MCP Tool object
        
        Returns:
            Protected async function that calls MCP with Tenuo authorization
        """
        tool_name = mcp_tool.name
        
        @lockdown(tool=tool_name)
        async def protected_tool(**kwargs):
            """Protected MCP tool wrapper."""
            return await self.call_tool(tool_name, kwargs, warrant_context=False)
        
        # Set function metadata
        protected_tool.__name__ = tool_name
        protected_tool.__doc__ = mcp_tool.description or f"MCP tool: {tool_name}"
        
        return protected_tool
    
    async def get_protected_tools(self) -> Dict[str, Callable]:
        """
        Get all MCP tools as protected Python functions.
        
        Returns:
            Dict mapping tool names to protected async functions
        """
        if not self._wrapped_tools:
            tools = await self.get_tools()
            for tool in tools:
                self._wrapped_tools[tool.name] = self.create_protected_tool(tool)
        
        return self._wrapped_tools


async def discover_and_protect(
    command: str,
    args: List[str],
    env: Optional[Dict[str, str]] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Callable]:
    """
    Discover MCP tools and return protected wrappers.
    
    Convenience function for one-liner tool discovery.
    
    Args:
        command: Command to run MCP server
        args: Server arguments
        env: Environment variables
        config_path: Path to mcp-config.yaml
    
    Returns:
        Dict of tool_name -> protected async function
    
    Example:
        tools = await discover_and_protect("python", ["server.py"])
        
        with root_task_sync(tools=["read_file"], path="/data/*"):
            result = await tools["read_file"](path="/data/file.txt")
    """
    async with SecureMCPClient(command, args, env, config_path) as client:
        return await client.get_protected_tools()
