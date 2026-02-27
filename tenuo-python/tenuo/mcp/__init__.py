"""
Tenuo MCP Integration.

Full Model Context Protocol integration with cryptographic authorization.

Example:
    from tenuo import mint, Capability, Pattern

    async with SecureMCPClient("python", ["mcp_server.py"]) as client:
        # Access tools via the convenient sync .tools property

        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            result = await client.tools["read_file"](path="/data/file.txt")
"""

from .client import MCP_AVAILABLE, SecureMCPClient, discover_and_protect

__all__ = [
    "SecureMCPClient",
    "discover_and_protect",
    "MCP_AVAILABLE",
]

# Only export LangChain adapter if both MCP and LangChain are available
try:
    from .langchain import MCPToolAdapter, mcp_tool_to_langchain  # noqa: F401

    __all__.extend(["MCPToolAdapter", "mcp_tool_to_langchain"])
except ImportError:
    pass
