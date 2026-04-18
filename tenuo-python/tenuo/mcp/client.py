"""
Secure MCP Client with Tenuo Authorization.

Wraps the MCP Python SDK to add cryptographic authorization for tool calls.
"""

import asyncio
import base64
import logging
import random
import sys
import time
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Callable, Dict, List, Literal, Optional

from .._enforcement import EnforcementResult, enforce_tool_call_async
from ..config import is_configured
from ..decorators import key_scope, warrant_scope
from ..exceptions import (
    AuthorizationDenied,
    ConfigurationError,
    ConstraintViolation,
    ExpiredError,
    MCPToolCallError,
    ToolNotAuthorized,
)
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


def _raise_for_denial(result: "EnforcementResult", tool_name: str) -> None:
    """Raise the appropriate exception for a denied EnforcementResult."""
    reason = result.denial_reason or "Authorization denied"
    etype = result.error_type or ""
    if etype == "constraint_violation":
        field = result.constraint_violated or tool_name
        raise ConstraintViolation(field, reason)
    if etype == "tool_not_allowed":
        raise ToolNotAuthorized(reason)
    if etype == "expired":
        raise ExpiredError(reason)
    raise AuthorizationDenied(reason)


def _extract_tenuo_error_code(structured: Any) -> Optional[int]:
    """Extract the JSON-RPC error code from ``structuredContent.tenuo.code``."""
    if isinstance(structured, dict):
        tenuo_block = structured.get("tenuo")
        if isinstance(tenuo_block, dict):
            code = tenuo_block.get("code")
            if isinstance(code, int):
                return code
    return None


def _safe_mcp_tool_error_message(content: Any, tool_name: str) -> str:
    """Best-effort user-facing text when ``CallToolResult.isError`` is true.

    Avoids assuming non-empty ``content`` or that the first block is text (MCP
    allows empty error payloads and arbitrary content types).
    """
    blocks = content if isinstance(content, list) else []
    for block in blocks:
        if getattr(block, "type", None) == "text":
            text = getattr(block, "text", None)
            if isinstance(text, str) and text.strip():
                return text
    return f"Tool '{tool_name}' returned an error"


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
        approval_handler: Optional[Any] = None,
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
            register_config: If ``True``, register the loaded config into global
                ``TenuoConfig`` so ``@guard`` decorators can use it. Defaults to
                ``False`` — call ``configure(mcp_config=...)`` explicitly if you
                need global registration.
            inject_warrant: Inject warrants into tool calls for server-side
                verification (default: False). Set True when the server runs
                Tenuo verification.
            approval_handler: Optional callable for warrant approval gates.
                Receives an ``ApprovalRequest`` and returns ``SignedApproval``
                (or raises ``ApprovalDenied``). Used during local enforcement
                (``warrant_context=True``).
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
        self._approval_handler = approval_handler

        from ..control_plane import get_or_create
        self._control_plane = get_or_create()

        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self._tools: Optional[List[MCPTool]] = None
        self._wrapped_tools: Dict[str, Callable] = {}
        self._connect_lock = asyncio.Lock()
        self._reconnect_delay: float = 0.0

        # Load MCP config if provided
        self.mcp_config = None
        self.compiled_config = None
        if config_path:
            from tenuo_core import CompiledMcpConfig, McpConfig

            self.mcp_config = McpConfig.from_file(config_path)
            self.compiled_config = CompiledMcpConfig.compile(self.mcp_config)

            should_register = register_config if register_config is not None else False

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
        """Connect to the MCP server using the configured transport.

        Safe to call multiple times; subsequent calls on an already-connected
        client tear down the previous connection first.  Serialized by an
        internal lock so concurrent callers don't race.
        """
        async with self._connect_lock:
            await self._connect_unlocked()

    async def _connect_unlocked(self):
        if self.session is not None:
            logger.debug("Tearing down existing MCP session before reconnecting")
            try:
                await self.exit_stack.aclose()
            except Exception:
                logger.warning("Error closing previous MCP session", exc_info=True)
            self.exit_stack = AsyncExitStack()
            self.session = None
            self._tools = None
            self._wrapped_tools = {}

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
        await asyncio.wait_for(self.session.initialize(), timeout=self.timeout)

        # Discover tools
        response = await asyncio.wait_for(self.session.list_tools(), timeout=self.timeout)
        self._tools = response.tools

        # Pre-populate protected tools for the .tools property
        self._wrapped_tools = {}
        for tool in self._tools:
            self._wrapped_tools[tool.name] = self.create_protected_tool(tool)

    async def close(self):
        """Close the MCP connection and clear all session state."""
        async with self._connect_lock:
            await self.exit_stack.aclose()
            self.session = None
            self._tools = None
            self._wrapped_tools = {}

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        """Return True if exc is a recoverable transport/connection error."""
        try:
            from anyio import ClosedResourceError, BrokenResourceError, EndOfStream
            if isinstance(exc, (ClosedResourceError, BrokenResourceError, EndOfStream)):
                return True
        except ImportError:
            pass
        if isinstance(exc, EOFError):
            return True
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return True
        if isinstance(exc, OSError) and exc.errno in (
            32,   # EPIPE
            54,   # ECONNRESET (macOS)
            104,  # ECONNRESET (Linux)
            110,  # ETIMEDOUT
        ):
            return True
        return False

    _RECONNECT_BASE_DELAY = 0.5
    _RECONNECT_MAX_DELAY = 30.0

    async def _reconnect(self) -> None:
        """Close the current session and reconnect using the same configuration.

        Serialized by the connect lock so that concurrent callers that both
        see a connection error don't race through teardown/setup.  Uses
        exponential backoff with jitter to avoid hammering a down server.
        """
        async with self._connect_lock:
            if self._reconnect_delay > 0:
                jittered = self._reconnect_delay * (0.5 + random.random())
                logger.info(
                    "MCP reconnect backoff: %.1fs before retry to %s",
                    jittered,
                    self.url or self.command,
                )
                await asyncio.sleep(jittered)

            logger.info("MCP session lost; reconnecting to %s...", self.url or self.command)
            try:
                await self.exit_stack.aclose()
            except Exception:
                logger.warning("Error closing MCP session during reconnect", exc_info=True)
            self.exit_stack = AsyncExitStack()
            self.session = None
            self._tools = None
            self._wrapped_tools = {}
            try:
                await self._connect_unlocked()
                self._reconnect_delay = 0.0
            except Exception:
                self._reconnect_delay = min(
                    max(self._reconnect_delay, self._RECONNECT_BASE_DELAY) * 2,
                    self._RECONNECT_MAX_DELAY,
                )
                raise

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

        Returns a snapshot so callers always see a consistent dict even if
        a concurrent ``_reconnect`` is rebuilding ``_wrapped_tools``.
        """
        wrapped = self._wrapped_tools
        if not wrapped and self.session is not None:
            try:
                if self._tools:
                    for tool in self._tools:
                        wrapped[tool.name] = self.create_protected_tool(tool)
                    self._wrapped_tools = wrapped
            except Exception as exc:
                logger.warning("Failed to wrap tool '%s': %s", tool.name, exc, exc_info=True)

        return dict(wrapped)

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
                logger.warning(
                    "Constraint extraction failed for '%s'; falling back to raw arguments",
                    tool_name,
                    exc_info=True,
                )

        # Use unified enforcement logic (async for approval handler support)
        enforcement: EnforcementResult = await enforce_tool_call_async(
            tool_name=tool_name,
            tool_args=extraction_args,
            bound_warrant=bound_warrant,
        )

        if self._control_plane is not None:
            try:
                self._control_plane.emit_for_enforcement(enforcement, chain_result=enforcement.chain_result)
            except Exception:
                logger.warning(
                    "Control plane emission failed for '%s'; audit event lost",
                    tool_name,
                    exc_info=True,
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
        raise_on_tool_error: bool = True,
    ) -> Any:
        """
        Call an MCP tool with Tenuo authorization.

        MCP Warrant Transport:
            When injection is enabled, the current warrant and PoP signature are
            sent via ``params._meta.tenuo`` (the MCP spec extension point).
            If ``approvals`` are provided, they are serialized into
            ``_meta.tenuo.approvals`` so the server can satisfy any approval gate on the tool.

        Args:
            tool_name: Name of the MCP tool to call
            arguments: Tool arguments
            warrant_context: If True, authorize locally before sending
            inject_warrant: Override client's inject_warrant setting (default: None)
            approvals: Pre-obtained SignedApproval objects to forward to the server
                via ``_meta.tenuo.approvals``. Required when the tool is approval-gate-protected
                and the server performs Tenuo verification (``inject_warrant=True``).
            timeout: Maximum seconds to wait for the server response (default: 30).
                Raises ``asyncio.TimeoutError`` if exceeded.
            raise_on_tool_error: If True (default), a server response with
                ``isError=True`` raises :class:`~tenuo.exceptions.MCPToolCallError`
                with a safe message and optional ``structuredContent`` (e.g.
                Tenuo denial metadata). If False, returns ``content`` as for
                success (legacy; callers must inspect the raw MCP session).

        Returns:
            Tool result content blocks from the MCP server (success path).

        Raises:
            ConfigurationError: If Tenuo not configured and warrant_context=True
            ConstraintViolation: If arguments don't satisfy warrant constraints
            ExpiredError: If the active warrant has expired before the call
            MCPToolCallError: If the server returns ``isError=True`` and
                ``raise_on_tool_error`` is True
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
            meta_payload: Optional[Dict[str, Any]] = None

            if should_inject:
                warrant = warrant_scope()
                keypair = key_scope()

                if warrant is not None and keypair is not None:
                    # Encode as WarrantStack when the parent chain is
                    # available via chain_scope(), otherwise single warrant.
                    from ..decorators import chain_scope as _chain_scope
                    _parents = _chain_scope()
                    if _parents:
                        try:
                            from tenuo_core import encode_warrant_stack
                            warrant_base64 = encode_warrant_stack(
                                list(_parents) + [warrant]
                            )
                        except Exception:
                            warrant_base64 = warrant.to_base64()
                    else:
                        warrant_base64 = warrant.to_base64()
                    # PoP must sign the same constraint view the server will
                    # verify against. When a CompiledMcpConfig is loaded, that
                    # means extracted (renamed/coerced) constraints — not raw args.
                    sign_args = args
                    if self.compiled_config:
                        try:
                            extraction = self.compiled_config.extract_constraints(
                                tool_name, args
                            )
                            sign_args = dict(extraction.constraints)
                        except Exception:
                            logger.warning(
                                "Config extraction failed for '%s'; PoP will sign raw "
                                "arguments (server-side verification may reject)",
                                tool_name,
                                exc_info=True,
                            )
                    pop_sig = warrant.sign(keypair, tool_name, sign_args, int(time.time()))
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
                    meta_payload = {"tenuo": tenuo_meta}

            if self.session is None:
                raise RuntimeError("Not connected to MCP server. Call connect() first.")

            for attempt in range(2):
                try:
                    response = await asyncio.wait_for(
                        self.session.call_tool(tool_name, call_args, meta=meta_payload),
                        timeout=timeout,
                    )
                    if getattr(response, "isError", False) is True:
                        raw_content = getattr(response, "content", None)
                        structured = getattr(response, "structuredContent", None)
                        _tenuo_code = _extract_tenuo_error_code(structured)
                        if _tenuo_code == -32002:
                            from .server import MCPApprovalRequired
                            _msg = _safe_mcp_tool_error_message(raw_content, tool_name)
                            _tenuo_block = (structured or {}).get("tenuo") or {}
                            _rh = _tenuo_block.get("request_hash") if isinstance(_tenuo_block, dict) else None
                            raise MCPApprovalRequired(
                                tool_name=tool_name,
                                message=_msg,
                                raw_error=structured,
                                request_hash=_rh,
                            )
                        if raise_on_tool_error:
                            raise MCPToolCallError(
                                _safe_mcp_tool_error_message(raw_content, tool_name),
                                tool_name=tool_name,
                                content=list(raw_content) if raw_content is not None else [],
                                structured_content=structured,
                            )
                        return raw_content
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

            from ..bound_warrant import BoundWarrant
            from ..config import resolve_trusted_roots

            w = warrant_scope()
            k = key_scope()
            if w is None or k is None:
                raise ConfigurationError(
                    "warrant_context=True requires an active warrant and key scope. "
                    "Use `with warrant_scope(w), key_scope(k):` or set warrant_context=False."
                )
            bw = BoundWarrant(w, k)
            result = await enforce_tool_call_async(
                tool_name=tool_name,
                tool_args=arguments,
                bound_warrant=bw,
                trusted_roots=resolve_trusted_roots(),
                approval_handler=self._approval_handler,
                approvals=approvals,
            )
            if self._control_plane is not None:
                try:
                    self._control_plane.emit_for_enforcement(result, chain_result=result.chain_result)
                except Exception:
                    logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)
            if not result.allowed:
                _raise_for_denial(result, tool_name)
            logger.info(
                "MCP tool authorised: %s (warrant=%s)",
                tool_name,
                getattr(w, "id", None),
            )
            return await _perform_call(arguments)
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

        # Extract allowed keys from JSON Schema to prevent "Shadow Parameter" attacks.
        # When the schema declares properties we fail-closed: if a key isn't in
        # the schema it doesn't get sent to the server.  When the schema is
        # absent or has no properties we forward all args — stripping everything
        # would silently break tools that don't publish a schema.
        input_schema = getattr(mcp_tool, "inputSchema", {}) or {}
        properties = input_schema.get("properties", {})
        allowed_keys: Optional[set] = set(properties.keys()) if properties else None

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

        async def protected_tool(**kwargs):
            """Protected MCP tool wrapper."""
            from ..bound_warrant import BoundWarrant
            from ..config import resolve_trusted_roots

            _approvals = kwargs.pop("_approvals", None)

            auth_args = _extract_auth_args(**kwargs)

            w = warrant_scope()
            k = key_scope()
            if w is not None and k is not None:
                bw = BoundWarrant(w, k)
                result = await enforce_tool_call_async(
                    tool_name=tool_name,
                    tool_args=auth_args,
                    bound_warrant=bw,
                    trusted_roots=resolve_trusted_roots(),
                    approval_handler=self._approval_handler,
                    approvals=_approvals,
                )
                if self._control_plane is not None:
                    try:
                        self._control_plane.emit_for_enforcement(result, chain_result=result.chain_result)
                    except Exception:
                        logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)
                if not result.allowed:
                    _raise_for_denial(result, tool_name)
                logger.info(
                    "MCP tool authorised: %s (warrant=%s)",
                    tool_name,
                    getattr(w, "id", None),
                )
            elif w is not None or k is not None:
                raise ConfigurationError(
                    f"Incomplete authorization context for MCP tool '{tool_name}': "
                    f"warrant={'set' if w else 'missing'}, "
                    f"signing_key={'set' if k else 'missing'}. "
                    f"Both must be provided via warrant_scope/key_scope."
                )
            else:
                logger.warning(
                    "MCP tool '%s' executed without authorization context "
                    "(no warrant/key in scope)", tool_name,
                )

            if allowed_keys is not None:
                filtered_args = {k: v for k, v in kwargs.items() if k in allowed_keys}
            else:
                filtered_args = dict(kwargs)

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
