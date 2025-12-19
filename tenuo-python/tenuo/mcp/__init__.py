"""
Tenuo MCP Integration.

Full Model Context Protocol integration with cryptographic authorization.

Example:
    from tenuo import root_task, Capability, Pattern
    
    async with SecureMCPClient("python", ["mcp_server.py"]) as client:
        tools = await client.get_protected_tools()
        
        async with root_task(Capability("read_file", path=Pattern("/data/*"))):
            result = await tools["read_file"](path="/data/file.txt")
"""

from .client import SecureMCPClient, discover_and_protect, MCP_AVAILABLE

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
