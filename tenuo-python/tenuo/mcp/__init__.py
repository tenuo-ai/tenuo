"""
Tenuo MCP Integration.

Full Model Context Protocol integration with cryptographic authorization.

Client-side (connecting to an MCP server):

    from tenuo import mint, Capability, Pattern

    async with SecureMCPClient("python", ["mcp_server.py"]) as client:
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            result = await client.tools["read_file"](path="/data/file.txt")

Server-side (verifying warrants inside an MCP server):

    from tenuo import Authorizer, PublicKey
    from tenuo.mcp import MCPVerifier

    verifier = MCPVerifier(
        authorizer=Authorizer(
            trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
        )
    )

    @mcp.tool()
    async def read_file(path: str, **kwargs) -> str:
        clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
        return open(clean["path"]).read()
"""

from .client import MCP_AVAILABLE, SecureMCPClient, discover_and_protect
from .server import MCPAuthorizationError, MCPVerificationResult, MCPVerifier, verify_mcp_call

__all__ = [
    # Client
    "SecureMCPClient",
    "discover_and_protect",
    "MCP_AVAILABLE",
    # Server
    "MCPVerifier",
    "MCPVerificationResult",
    "MCPAuthorizationError",
    "verify_mcp_call",
]

# Only export LangChain adapter if both MCP and LangChain are available
try:
    from .langchain import MCPToolAdapter, mcp_tool_to_langchain  # noqa: F401

    __all__.extend(["MCPToolAdapter", "mcp_tool_to_langchain"])
except ImportError:
    pass
