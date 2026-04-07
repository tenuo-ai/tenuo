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

    # Optional FastMCP (``tenuo[fastmcp]``): wire ``_meta`` is not passed into
    # ``@mcp.tool()`` — register middleware, then implement slim handlers.
    # from fastmcp import FastMCP
    # from tenuo.mcp import TenuoMiddleware
    # mcp = FastMCP("app", middleware=[TenuoMiddleware(verifier)])
    # @mcp.tool()
    # async def read_file(path: str) -> str:
    #     return open(path).read()
"""

from ..exceptions import MCPToolCallError
from .client import MCP_AVAILABLE, SecureMCPClient, discover_and_protect
from .server import MCPAuthorizationError, MCPVerificationResult, MCPVerifier, verify_mcp_call

__all__ = [
    # Client
    "SecureMCPClient",
    "discover_and_protect",
    "MCP_AVAILABLE",
    "MCPToolCallError",
    # Server
    "MCPVerifier",
    "MCPVerificationResult",
    "MCPAuthorizationError",
    "verify_mcp_call",
]

try:
    from .fastmcp_middleware import TenuoMiddleware, resolve_tool_call_meta_for_verify  # noqa: F401

    __all__.extend(["TenuoMiddleware", "resolve_tool_call_meta_for_verify"])
except ImportError:

    class TenuoMiddleware:  # type: ignore[no-redef]
        """Placeholder: real :class:`TenuoMiddleware` requires ``tenuo[fastmcp]``."""

        def __init__(self, *_a: object, **_kw: object) -> None:
            raise ImportError(
                "TenuoMiddleware requires FastMCP. Install with: pip install \"tenuo[fastmcp]\""
            ) from None

    __all__.append("TenuoMiddleware")

# Only export LangChain adapter if both MCP and LangChain are available
try:
    from .langchain import MCPToolAdapter, mcp_tool_to_langchain  # noqa: F401

    __all__.extend(["MCPToolAdapter", "mcp_tool_to_langchain"])
except ImportError:
    pass
