"""
LangChain adapter for MCP tools with Tenuo authorization.

Converts MCP tools to LangChain BaseTool with automatic warrant enforcement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Dict, List

if TYPE_CHECKING:
    from .client import SecureMCPClient


# Optional imports
try:
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, create_model

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    StructuredTool = object  # type: ignore
    BaseModel = object  # type: ignore

try:
    from mcp.types import Tool as MCPTool  # type: ignore[import-not-found]

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    MCPTool = object  # type: ignore


def mcp_tool_to_langchain(
    mcp_tool: Any,  # MCPTool
    protected_func: Callable,
) -> Any:  # StructuredTool
    """
    Convert an MCP tool to a LangChain StructuredTool.

    Args:
        mcp_tool: MCP Tool object with name, description, inputSchema
        protected_func: Protected async function (from SecureMCPClient)

    Returns:
        LangChain StructuredTool with Tenuo protection

    Example:
        tool = mcp_tool_to_langchain(mcp_tool, protected_func)
        agent = create_openai_tools_agent(llm, [tool])
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError('LangChain not installed. Install with: uv pip install "tenuo[langchain]"')

    if not MCP_AVAILABLE:
        raise ImportError('MCP SDK not installed. Install with: uv pip install "tenuo[mcp]"')

    # Extract schema from MCP tool
    tool_name = mcp_tool.name
    description = mcp_tool.description or f"MCP tool: {tool_name}"

    # Convert MCP JSON Schema to Pydantic model
    # MCP uses JSONSchema, LangChain uses Pydantic
    input_schema = getattr(mcp_tool, "inputSchema", None) or {}
    properties = input_schema.get("properties", {})
    required = input_schema.get("required", [])

    # Build Pydantic model fields
    field_definitions = {}
    for field_name, field_schema in properties.items():
        field_type = _json_schema_to_python_type(field_schema)
        default = ... if field_name in required else None
        field_definitions[field_name] = (field_type, default)

    # Create Pydantic model dynamically
    if field_definitions:
        ArgsSchema = create_model(f"{tool_name}Args", **field_definitions)  # type: ignore[call-overload]
    else:
        ArgsSchema = None

    # Create sync wrapper (LangChain sometimes requires it even for async tools)
    def _sync_not_supported(*args, **kwargs):
        raise NotImplementedError(
            f"MCP tool '{tool_name}' only supports async calls. Use await or async agent executor."
        )

    # Create LangChain tool
    return StructuredTool(
        name=tool_name,
        description=description,
        func=_sync_not_supported,  # Sync wrapper (raises error)
        coroutine=protected_func,  # Async version (actual implementation)
        args_schema=ArgsSchema,
    )


def _json_schema_to_python_type(schema: Dict[str, Any]) -> type:
    """
    Convert JSON Schema type to Python type hint.

    Simple mapping for common types. Defaults to Any for unknown types (safe fallback).

    Note: Complex schemas (unions, nested objects) are simplified to their base type.
    This is conservative but prevents Pydantic validation errors. If strict validation
    is needed, users can manually create a Pydantic model.
    """
    schema_type = schema.get("type", "string")

    type_mapping = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    # Fallback to Any for unknown types (e.g., "null", unions, custom types)
    return type_mapping.get(schema_type, Any)


def guard_mcp_client(client: Any) -> List[Any]:
    """
    Wrap all tools from a LangChain MultiServerMCPClient with Tenuo protection.

    Args:
        client: langchain_mcp_adapters.client.MultiServerMCPClient instance

    Returns:
        List of LangChain StructuredTool objects with Tenuo protection
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError('LangChain not installed. Install with: uv pip install "tenuo[langchain]"')

    # This is a bit tricky because the official client is stateless by default.
    # We need to wrap the tool calls it makes.

    # 1. Get tools from the client
    # Note: client.get_tools() is async
    raise NotImplementedError(
        "Direct wrapping of MultiServerMCPClient is coming soon. "
        "Use SecureMCPClient for now which provides the same functionality with native protection."
    )


class MCPToolAdapter:
    """
    Adapter for converting MCP client tools to LangChain tools.

    Example:
        async with SecureMCPClient("python", ["server.py"]) as client:
            adapter = MCPToolAdapter(client)
            langchain_tools = await adapter.to_langchain_tools()

            # Use with LangChain agent
            agent = create_openai_tools_agent(llm, langchain_tools)
    """

    def __init__(self, mcp_client: SecureMCPClient):
        """
        Initialize adapter.

        Args:
            mcp_client: Connected SecureMCPClient instance
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError('LangChain not installed. Install with: uv pip install "tenuo[langchain]"')

        self.client = mcp_client

    async def to_langchain_tools(self) -> List[Any]:  # List[StructuredTool]
        """
        Convert all MCP tools to LangChain tools.

        Returns:
            List of LangChain StructuredTool objects with Tenuo protection
        """
        mcp_tools = await self.client.get_tools()
        protected_funcs = self.client.tools

        langchain_tools = []
        for mcp_tool in mcp_tools:
            protected_func = protected_funcs[mcp_tool.name]
            tool = mcp_tool_to_langchain(mcp_tool, protected_func)
            langchain_tools.append(tool)

        return langchain_tools
