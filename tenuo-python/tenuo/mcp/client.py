"""
Secure MCP Client with Tenuo Authorization.

Wraps the MCP Python SDK to add cryptographic authorization for tool calls.
"""

import asyncio
import logging
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Callable, Dict, List, Literal, Optional

from .._enforcement import EnforcementResult, enforce_tool_call
from ..config import is_configured
from ..decorators import guard, key_scope, warrant_scope
from ..exceptions import ConfigurationError, ExpiredError
from ..validation import ValidationResult

logger = logging.getLogger(__name__)

# Optional MCP import (requires Python 3.10+)
try:
    from mcp import ClientSession, StdioServerParameters  # type: ignore[import-not-found]
    from mcp.client.sse import sse_client  # type: ignore[import-not-found]
    from mcp.client.stdio import stdio_client  # type: ignore[import-not-found]
    from mcp.client.streamable_http import streamablehttp_client  # type: ignore[import-not-found]
    from mcp.types import Tool as MCPTool  # type: ignore[import-not-found]

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    ClientSession = object  # type: ignore
    StdioServerParameters = object  # type: ignore
    MCPTool = object  # type: ignore


if sys.version_info < (3, 10) and MCP_AVAILABLE:
    # Should not happen if installed correctly, but guard anyway
    MCP_AVAILABLE = False


class SecureMCPClient:
    """
    MCP client with Tenuo authorization.

    Wraps the MCP Python SDK and automatically protects tool calls with warrants.
    Supports stdio (local subprocess), SSE, and StreamableHTTP transports.

    Stdio (local subprocess):
        async with SecureMCPClient("python", ["mcp_server.py"]) as client:
            async with mint(Capability("read_file", path=Pattern("/data/*"))):
                result = await client.tools["read_file"](path="/data/file.txt")

    SSE (remote server, legacy HTTP transport):
        async with SecureMCPClient(
            url="https://mcp.example.com/sse",
            transport="sse",
            inject_warrant=True,
        ) as client:
            async with mint(Capability("read_file", path=Pattern("/data/*"))):
                result = await client.tools["read_file"](path="/data/file.txt")

    StreamableHTTP (remote server, current HTTP transport):
        async with SecureMCPClient(
            url="https://mcp.example.com/mcp",
            transport="http",
            headers={"Authorization": "Bearer <token>"},
            inject_warrant=True,
        ) as client:
            async with mint(Capability("read_file", path=Pattern("/data/*"))):
                result = await client.tools["read_file"](path="/data/file.txt")
    """

    def __init__(
        self,
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        config_path: Optional[str] = None,
        register_config: Optional[bool] = None,
        inject_warrant: bool = False,
        url: Optional[str] = None,
        transport: Literal["stdio", "sse", "http"] = "stdio",
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        sse_read_timeout: float = 300.0,
        auth: Optional[Any] = None,
    ):
        """
        Initialize MCP client.

        Stdio transport (local subprocess):
            command: Command to run MCP server ("python" or "node")
            args: Arguments to pass to server (e.g., ["server.py"])
            env: Environment variables for server process

        HTTP transports (remote server):
            url: MCP server endpoint URL
            transport: "sse" for legacy SSE transport, "http" for StreamableHTTP
            headers: HTTP headers to include in every request (e.g., Authorization)
            timeout: HTTP request timeout in seconds (default 30)
            sse_read_timeout: SSE stream read timeout in seconds (default 300)
            auth: httpx.Auth instance for authentication (e.g., httpx.BasicAuth(...))

        Common:
            config_path: Path to mcp-config.yaml (optional)
            register_config: Register config globally for @guard. Defaults to True
                if config_path is provided.
            inject_warrant: Inject warrants into tool calls for server-side
                verification (default: False). Set True when the server runs
                Tenuo verification.

        Note:
            If register_config=True, this mutates global Tenuo configuration.
            Prefer calling configure(mcp_config=...) explicitly if you need
            fine-grained control.
        """
        if not MCP_AVAILABLE:
            raise ImportError('MCP SDK not installed. Install with: uv pip install "tenuo[mcp]"')

        if transport == "stdio" and command is None:
            raise ValueError(
                "transport='stdio' requires 'command'. "
                "For HTTP transports use transport='sse' or transport='http' with url=."
            )
        if transport in ("sse", "http") and url is None:
            raise ValueError(
                f"transport='{transport}' requires 'url'. "
                "Provide the MCP server endpoint URL."
            )

        self.command = command
        self.args = args or []
        self.env = env
        self.config_path = config_path
        self.inject_warrant = inject_warrant
        self.url = url
        self.transport = transport
        self.headers = headers
        self.timeout = timeout
        self.sse_read_timeout = sse_read_timeout
        self.auth = auth

        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self._tools: Optional[List[MCPTool]] = None
        self._wrapped_tools: Dict[str, Callable] = {}

        # Load MCP config if provided
        self.mcp_config = None
        self.compiled_config = None
        if config_path:
            from tenuo_core import CompiledMcpConfig, McpConfig

            self.mcp_config = McpConfig.from_file(config_path)
            self.compiled_config = CompiledMcpConfig.compile(self.mcp_config)

            # Default logic: If config_path provided, we assume you want to register it
            # unless explicitly disabled.
            should_register = register_config if register_config is not None else True

            # Optionally register with global config
            if should_register:
                import warnings

                from ..config import configure as tenuo_configure
                from ..config import get_config

                existing_config = get_config()
                if existing_config and existing_config.mcp_config is not None:
                    warnings.warn(
                        "Overwriting existing MCP config in global configuration. "
                        "Consider calling configure(mcp_config=...) explicitly.",
                        UserWarning,
                        stacklevel=2,
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
        """Connect to the MCP server using the configured transport."""
        if self.transport == "stdio":
            server_params = StdioServerParameters(
                command=self.command, args=self.args, env=self.env
            )
            stdio_transport = await self.exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            read_stream, write_stream = stdio_transport

        elif self.transport == "sse":
            sse_transport = await self.exit_stack.enter_async_context(
                sse_client(
                    url=self.url,
                    headers=self.headers,
                    timeout=self.timeout,
                    sse_read_timeout=self.sse_read_timeout,
                    auth=self.auth,
                )
            )
            read_stream, write_stream = sse_transport

        elif self.transport == "http":
            http_transport = await self.exit_stack.enter_async_context(
                streamablehttp_client(
                    url=self.url,
                    headers=self.headers,
                    timeout=self.timeout,
                    sse_read_timeout=self.sse_read_timeout,
                    auth=self.auth,
                )
            )
            # streamablehttp_client returns a 3-tuple; third element is session-ID callback
            read_stream, write_stream, _ = http_transport

        else:
            raise ValueError(
                f"Unknown transport: {self.transport!r}. Use 'stdio', 'sse', or 'http'."
            )

        # Create session
        self.session = await self.exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
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

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        """Return True if exc is a recoverable transport/connection error."""
        type_name = type(exc).__name__
        module = getattr(type(exc), "__module__", "") or ""
        # anyio transport errors (checked by name to avoid a hard anyio import)
        if module.startswith("anyio") and type_name in (
            "ClosedResourceError",
            "BrokenResourceError",
            "EndOfStream",
        ):
            return True
        # Standard Python I/O errors
        if isinstance(exc, EOFError):
            return True
        if isinstance(exc, OSError) and exc.errno in (
            32,   # EPIPE  (broken pipe)
            54,   # ECONNRESET (macOS)
            104,  # ECONNRESET (Linux)
            110,  # ETIMEDOUT
        ):
            return True
        return False

    async def _reconnect(self) -> None:
        """Close the current session and reconnect using the same configuration."""
        logger.info("MCP session lost; reconnecting to %s...", self.url or self.command)
        try:
            await self.exit_stack.aclose()
        except Exception:
            pass
        self.exit_stack = AsyncExitStack()
        self.session = None
        self._tools = None
        self._wrapped_tools = {}
        await self.connect()

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
            except Exception as exc:
                logger.warning("Failed to wrap tool '%s': %s", tool.name, exc, exc_info=True)

        return self._wrapped_tools

    async def validate_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> "ValidationResult":
        """
        Check if a tool call would be authorized under the current warrant.

        This is a local dry-run check. It does not supply approvals, so
        approval-gate-protected tools will always appear as unauthorized here.
        Use :meth:`call_tool` with ``approvals=`` for the real invocation.

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
                "No active warrant in context", suggestions=["Wrap your call in 'async with mint(...):'"]
            )

        if keypair is None:
            return ValidationResult.fail(
                "No signing key in context", suggestions=["Call configure(issuer_key=...) or use key_scope()"]
            )

        # Create BoundWarrant for enforcement
        bound_warrant = warrant.bind(keypair)

        # Re-map arguments if we have a config
        extraction_args = arguments
        if self.compiled_config:
            try:
                result = self.compiled_config.extract_constraints(tool_name, arguments)
                extraction_args = result.constraints
            except Exception:
                pass

        # Use unified enforcement logic
        enforcement: EnforcementResult = enforce_tool_call(
            tool_name=tool_name,
            tool_args=extraction_args,
            bound_warrant=bound_warrant,
        )

        if enforcement.allowed:
            return ValidationResult.ok()
        else:
            logger.warning(
                f"MCP tool '{tool_name}' denied: {enforcement.denial_reason}",
                extra={"tool": tool_name, "args_keys": list(arguments.keys())}
            )
            return ValidationResult.fail(
                reason=enforcement.denial_reason or "Authorization denied",
                # TODO: enforcement module could provide suggestions in the future
                suggestions=[],
            )

    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        warrant_context: bool = True,
        inject_warrant: Optional[bool] = None,
        approvals: Optional[List] = None,
        timeout: float = 30.0,
    ) -> Any:
        """
        Call an MCP tool with Tenuo authorization.

        MCP Warrant Transport:
            When injection is enabled, the current warrant and PoP signature are
            injected into arguments._tenuo before sending to the MCP server.
            If ``approvals`` are provided, they are serialized into
            ``_tenuo.approvals`` so the server can satisfy any approval gate on the tool.

        Args:
            tool_name: Name of the MCP tool to call
            arguments: Tool arguments
            warrant_context: If True, authorize locally before sending
            inject_warrant: Override client's inject_warrant setting (default: None)
            approvals: Pre-obtained SignedApproval objects to forward to the server
                via ``_tenuo.approvals``. Required when the tool is approval-gate-protected
                and the server performs Tenuo verification (``inject_warrant=True``).
            timeout: Maximum seconds to wait for the server response (default: 30).
                Raises ``asyncio.TimeoutError`` if exceeded.

        Returns:
            Tool result from MCP server

        Raises:
            ConfigurationError: If Tenuo not configured and warrant_context=True
            ConstraintViolation: If arguments don't satisfy warrant constraints
            ExpiredError: If the active warrant has expired before the call
            asyncio.TimeoutError: If the server does not respond within timeout
        """
        if self.session is None:
            raise RuntimeError(
                "Not connected to MCP server. "
                "Use 'async with SecureMCPClient(...) as client:' or call await client.connect() first."
            )

        should_inject = self.inject_warrant if inject_warrant is None else inject_warrant

        # Pre-flight expiry check — fail fast before touching the network
        _active_warrant = warrant_scope()
        if _active_warrant is not None:
            try:
                if _active_warrant.is_expired():
                    raise ExpiredError("Warrant expired before MCP tool call")
            except AttributeError:
                pass  # is_expired() not available on this warrant type; enforcement will catch it

        # Helper to perform the actual network call with optional injection
        async def _perform_call(args: Dict[str, Any]) -> Any:
            call_args = args.copy()

            if should_inject:
                warrant = warrant_scope()
                keypair = key_scope()

                if warrant is not None and keypair is not None:
                    import base64
                    import time

                    warrant_base64 = warrant.to_base64()
                    # Create PoP signature for this specific call
                    pop_sig = warrant.sign(keypair, tool_name, args, int(time.time()))
                    signature_base64 = base64.b64encode(bytes(pop_sig)).decode("utf-8")

                    tenuo_meta: Dict[str, Any] = {
                        "warrant": warrant_base64,
                        "signature": signature_base64,
                    }
                    if approvals:
                        tenuo_meta["approvals"] = [
                            base64.b64encode(a.to_bytes()).decode("utf-8")
                            for a in approvals
                        ]
                    call_args["_tenuo"] = tenuo_meta

            if self.session is None:
                raise RuntimeError("Not connected to MCP server. Call connect() first.")

            for attempt in range(2):
                try:
                    response = await asyncio.wait_for(
                        self.session.call_tool(tool_name, call_args),
                        timeout=timeout,
                    )
                    return response.content
                except asyncio.TimeoutError:
                    raise
                except Exception as exc:
                    if attempt == 0 and self._is_connection_error(exc):
                        logger.warning(
                            "MCP connection lost during call to '%s'; reconnecting...",
                            tool_name,
                        )
                        await self._reconnect()
                        continue
                    raise

        # Authorize locally if warrant context is enabled
        if warrant_context:
            if not is_configured():
                raise ConfigurationError("Tenuo not configured. Call configure() first or use warrant_context=False")

            # Create protected wrapper for local authorization
            @guard(tool=tool_name, extract_args=lambda **kwargs: kwargs)
            async def wrapper(**kwargs):
                _w = warrant_scope()
                _wid = getattr(_w, "id", None) if _w else None
                logger.info("MCP tool authorised: %s (warrant=%s)", tool_name, _wid)
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
        input_schema = getattr(mcp_tool, "inputSchema", {}) or {}
        properties = input_schema.get("properties", {})
        allowed_keys = set(properties.keys())

        def _extract_auth_args(**kwargs):
            # Strip _approvals — it is a Tenuo transport kwarg, not a tool argument.
            # Passing SignedApproval objects to extract_constraints would fail JSON
            # serialization and is not part of the constraint schema.
            tool_kwargs = {k: v for k, v in kwargs.items() if k != "_approvals"}
            if self.compiled_config:
                # Apply defaults and extraction rules from config
                # We do NOT suppress exceptions here (Fail Closed).
                # If extraction fails, it means the request doesn't match the required configuration.
                result = self.compiled_config.extract_constraints(tool_name, tool_kwargs)

                # Merge extracted constraints (which have defaults/types) over raw kwargs
                combined = tool_kwargs.copy()
                combined.update(result.constraints)
                return combined
            return tool_kwargs

        @guard(tool=tool_name, extract_args=_extract_auth_args)
        async def protected_tool(**kwargs):
            """Protected MCP tool wrapper."""
            # Extract _approvals before schema filtering — it's a transport kwarg,
            # not a tool schema argument and must not be forwarded to the server.
            _approvals = kwargs.pop("_approvals", None)

            # Filter arguments against schema (Schema-Based Argument Stripping)
            filtered_args = {k: v for k, v in kwargs.items() if k in allowed_keys}

            return await self.call_tool(
                tool_name,
                filtered_args,
                warrant_context=False,
                inject_warrant=self.inject_warrant,
                approvals=_approvals,
            )

        # Set function metadata
        protected_tool.__name__ = tool_name
        protected_tool.__doc__ = mcp_tool.description or f"MCP tool: {tool_name}"

        return protected_tool


@asynccontextmanager
async def discover_and_protect(
    command: Optional[str] = None,
    args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
    config_path: Optional[str] = None,
    url: Optional[str] = None,
    transport: Literal["stdio", "sse", "http"] = "stdio",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
    sse_read_timeout: float = 300.0,
    auth: Optional[Any] = None,
    inject_warrant: bool = False,
):  # type: ignore[misc]
    """
    Discover MCP tools and return protected wrappers.

    Convenience context manager for one-liner tool discovery.
    Supports all three transports: stdio, SSE, and StreamableHTTP.

    Stdio:
        async with discover_and_protect("python", ["server.py"]) as tools:
            async with mint(Capability("read_file", path=Pattern("/data/*"))):
                result = await tools["read_file"](path="/data/file.txt")

    HTTP (SSE or StreamableHTTP):
        async with discover_and_protect(
            url="https://mcp.example.com/mcp",
            transport="http",
            inject_warrant=True,
        ) as tools:
            async with mint(Capability("search")):
                result = await tools["search"](query="tenuo")
    """
    async with SecureMCPClient(
        command=command,
        args=args,
        env=env,
        config_path=config_path,
        inject_warrant=inject_warrant,
        url=url,
        transport=transport,
        headers=headers,
        timeout=timeout,
        sse_read_timeout=sse_read_timeout,
        auth=auth,
    ) as client:
        yield client.tools
