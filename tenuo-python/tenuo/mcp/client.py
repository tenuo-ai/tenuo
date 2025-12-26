"""
Secure MCP Client with Tenuo Authorization.

Wraps the MCP Python SDK to add cryptographic authorization for tool calls.
"""

from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Callable, Dict, List, Optional

from ..config import is_configured
from ..decorators import guard, warrant_scope, key_scope
from ..exceptions import ConfigurationError
from ..validation import ValidationResult

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
            # Use the .tools property for easy access
            
            # Use with warrant context
            async with mint(Capability("read_file", path=Pattern("/data/*"))):
                result = await client.tools["read_file"](path="/data/file.txt")
    """
    
    def __init__(
        self,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        config_path: Optional[str] = None,
        register_config: Optional[bool] = None,
        inject_warrant: bool = False,
    ):
        """
        Initialize MCP client.
        
        Args:
            command: Command to run MCP server ("python" or "node")
            args: Arguments to pass to server (e.g., ["server.py"])
            env: Environment variables for server process
            config_path: Path to mcp-config.yaml (optional)
            register_config: If True, register config globally for @guard. 
                           Defaults to True if config_path is provided, else False.
            inject_warrant: If True, automatically inject warrants into tool calls (default: False)
        
        Note:
            # register_config=True enables global configuration for @guard decorators
            # This allows Tenuo to verify arguments without explicit extraction logic in code
            If register_config=True, this mutates global Tenuo configuration.
            Prefer calling configure(mcp_config=...) explicitly if you need
            fine-grained control.
        """
        if not MCP_AVAILABLE:
            raise ImportError(
                "MCP SDK not installed. Install with: pip install tenuo[mcp]"
            )
        
        self.command = command
        self.args = args
        self.env = env
        self.config_path = config_path
        self.inject_warrant = inject_warrant
        
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self._tools: Optional[List[MCPTool]] = None
        self._wrapped_tools: Dict[str, Callable] = {}
        
        # Load MCP config if provided
        self.mcp_config = None
        self.compiled_config = None
        if config_path:
            from tenuo_core import McpConfig, CompiledMcpConfig
            
            self.mcp_config = McpConfig.from_file(config_path)
            self.compiled_config = CompiledMcpConfig.compile(self.mcp_config)
            
            # Default logic: If config_path provided, we assume you want to register it
            # unless explicitly disabled.
            should_register = register_config if register_config is not None else True
            
            # Optionally register with global config
            if should_register:
                from ..config import get_config, configure as tenuo_configure
                import warnings
                
                existing_config = get_config()
                if existing_config and existing_config.mcp_config is not None:
                    warnings.warn(
                        "Overwriting existing MCP config in global configuration. "
                        "Consider calling configure(mcp_config=...) explicitly.",
                        UserWarning,
                        stacklevel=2
                    )
                
                if existing_config:
                    # Preserve existing settings, just add MCP config
                    tenuo_configure(
                        issuer_key=existing_config.issuer_key,
                        trusted_roots=existing_config.trusted_roots,
                        default_ttl=existing_config.default_ttl,
                        clock_tolerance=existing_config.clock_tolerance,
                        pop_window_secs=existing_config.pop_window_secs,
                        pop_max_windows=existing_config.pop_max_windows,
                        mcp_config=self.compiled_config,
                        dev_mode=existing_config.dev_mode,
                        allow_passthrough=existing_config.allow_passthrough,
                        allow_self_signed=existing_config.allow_self_signed,
                        strict_mode=existing_config.strict_mode,
                        warn_on_missing_warrant=existing_config.warn_on_missing_warrant,
                        max_missing_warrant_warnings=existing_config.max_missing_warrant_warnings,
                    )
                else:
                    # No existing config, just register MCP
                    tenuo_configure(mcp_config=self.compiled_config)
    
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
        
        # Pre-populate protected tools for the .tools property
        self._wrapped_tools = {}
        for tool in self._tools:
            self._wrapped_tools[tool.name] = self.create_protected_tool(tool)
    
    async def close(self):
        """Close the MCP connection."""
        await self.exit_stack.aclose()
    
    async def get_tools(self) -> List[MCPTool]:
        """
        Get available MCP tools.
        
        Returns list of MCP Tool objects with name, description, inputSchema.
        """
        if self.session is None:
            raise RuntimeError(
                "Not connected to MCP server. "
                "Use 'async with SecureMCPClient(...) as client:' or call await client.connect() first."
            )
            
        if self._tools is None:
            response = await self.session.list_tools()  # type: ignore[union-attr]
            self._tools = response.tools
        return self._tools
    
    @property
    def tools(self) -> Dict[str, Callable]:
        """
        Get all MCP tools as protected Python functions.
        
        Returns:
            Dict mapping tool names to protected async functions
        """
        if not self._wrapped_tools and self.session is not None:
            # Fallback for manual calls outside of context manager
            # but usually initialized in connect()
            try:
                # If we're already in a loop and session is active but tools aren't wrapped
                # this is a safety fallback.
                if self._tools:
                    for tool in self._tools:
                        self._wrapped_tools[tool.name] = self.create_protected_tool(tool)
            except Exception:
                pass
                
        return self._wrapped_tools

    async def validate_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> 'ValidationResult':
        """
        Check if a tool call would be authorized under the current warrant.
        
        Args:
            tool_name: Name of the tool
            arguments: Arguments for the tool
            
        Returns:
            ValidationResult
        """
        from ..validation import ValidationResult
        warrant = warrant_scope()
        keypair = key_scope()
        
        if warrant is None:
            return ValidationResult.fail(
                "No active warrant in context",
                suggestions=["Wrap your call in 'async with mint(...):'"]
            )
            
        if keypair is None:
            return ValidationResult.fail(
                "No signing key in context",
                suggestions=["Call configure(issuer_key=...) or use key_scope()"]
            )
            
        # Re-map arguments if we have a config
        extraction_args = arguments
        if self.compiled_config:
            try:
                result = self.compiled_config.extract_constraints(tool_name, arguments)
                extraction_args = result.constraints
            except Exception:
                pass
                
        return warrant.validate(keypair, tool_name, extraction_args)
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        warrant_context: bool = True,
        inject_warrant: Optional[bool] = None,
    ) -> Any:
        """
        Call an MCP tool with Tenuo authorization.
        
        MCP Warrant Transport:
            When injection is enabled, the current warrant and PoP signature are
            injected into arguments._tenuo before sending to the MCP server.
        
        Args:
            tool_name: Name of the MCP tool to call
            arguments: Tool arguments
            warrant_context: If True, authorize locally before sending
            inject_warrant: Override client's inject_warrant setting (default: None)
        
        Returns:
            Tool result from MCP server
        
        Raises:
            ConfigurationError: If Tenuo not configured and warrant_context=True
            ConstraintViolation: If arguments don't satisfy warrant constraints
        """
        if self.session is None:
            raise RuntimeError(
                "Not connected to MCP server. "
                "Use 'async with SecureMCPClient(...) as client:' or call await client.connect() first."
            )
        
        should_inject = self.inject_warrant if inject_warrant is None else inject_warrant
        
        # Helper to perform the actual network call with optional injection
        async def _perform_call(args: Dict[str, Any]) -> Any:
            call_args = args.copy()
            
            if should_inject:
                warrant = warrant_scope()
                keypair = key_scope()
                
                if warrant is not None and keypair is not None:
                    import base64
                    
                    warrant_base64 = warrant.to_base64()
                    # Create PoP signature for this specific call
                    pop_sig = warrant.sign(keypair, tool_name, args)
                    signature_base64 = base64.b64encode(bytes(pop_sig)).decode('utf-8')
                    
                    call_args["_tenuo"] = {
                        "warrant": warrant_base64,
                        "signature": signature_base64
                    }
            
            if self.session is None:
                raise RuntimeError("Not connected to MCP server. Call connect() first.")
                
            response = await self.session.call_tool(tool_name, call_args)
            return response.content

        # Authorize locally if warrant context is enabled
        if warrant_context:
            if not is_configured():
                raise ConfigurationError(
                    "Tenuo not configured. Call configure() first or use warrant_context=False"
                )
            
            # Create protected wrapper for local authorization
            @guard(tool=tool_name, extract_args=lambda **kwargs: kwargs)
            async def wrapper(**kwargs):
                return await _perform_call(kwargs)
            
            # Call with local authorization
            return await wrapper(**arguments)
        else:
            # Call without local authorization (but still with optional injection)
            return await _perform_call(arguments)
    
    def create_protected_tool(self, mcp_tool: MCPTool) -> Callable:
        """
        Create a protected Python function wrapper for an MCP tool.
        
        Args:
            mcp_tool: MCP Tool object
        
        Returns:
            Protected async function that calls MCP with Tenuo authorization
        """
        tool_name = mcp_tool.name
        
        # Extract allowed keys from JSON Schema to prevent "Shadow Parameter" attacks
        # We fail-closed: if it's not in the schema, it doesn't get sent to the server.
        input_schema = getattr(mcp_tool, 'inputSchema', {}) or {}
        properties = input_schema.get('properties', {})
        allowed_keys = set(properties.keys())
        
        def _extract_auth_args(**kwargs):
            if self.compiled_config:
                # Apply defaults and extraction rules from config
                # We do NOT suppress exceptions here (Fail Closed). 
                # If extraction fails, it means the request doesn't match the required configuration.
                result = self.compiled_config.extract_constraints(tool_name, kwargs)
                
                # Merge extracted constraints (which have defaults/types) over raw kwargs
                combined = kwargs.copy()
                combined.update(result.constraints)
                return combined
            return kwargs
        
        @guard(tool=tool_name, extract_args=_extract_auth_args)
        async def protected_tool(**kwargs):
            """Protected MCP tool wrapper."""
            # Filter arguments against schema (Schema-Based Argument Stripping)
            filtered_args = {
                k: v for k, v in kwargs.items() 
                if k in allowed_keys
            }
            
            # Note: We could log dropped arguments here if needed
            
            return await self.call_tool(
                tool_name, 
                filtered_args, 
                warrant_context=False,
                inject_warrant=self.inject_warrant
            )
        
        # Set function metadata
        protected_tool.__name__ = tool_name
        protected_tool.__doc__ = mcp_tool.description or f"MCP tool: {tool_name}"
        
        return protected_tool
    
    # This method is removed in favor of the .tools property
    
    @property
    def get_protected_tools(self) -> Callable:
        """Deprecated alias for .tools property."""
        import warnings
        warnings.warn("get_protected_tools() is deprecated, use .tools property", DeprecationWarning)
        
        async def _compat():
            return self.tools
        return _compat  # type: ignore


@asynccontextmanager
async def discover_and_protect(
    command: str,
    args: List[str],
    env: Optional[Dict[str, str]] = None,
    config_path: Optional[str] = None,
):  # type: ignore[misc]
    """
    Discover MCP tools and return protected wrappers.
    
    Convenience context manager for one-liner tool discovery.
    
    Args:
        command: Command to run MCP server
        args: Server arguments
        env: Environment variables
        config_path: Path to mcp-config.yaml
    
    Yields:
        Dict of tool_name -> protected async function
    
    Example:
        async with discover_and_protect("python", ["server.py"]) as tools:
            async with mint(Capability("read_file", path=Pattern("/data/*"))):
                result = await tools["read_file"](path="/data/file.txt")
    """
    async with SecureMCPClient(command, args, env, config_path) as client:
        yield client.tools
