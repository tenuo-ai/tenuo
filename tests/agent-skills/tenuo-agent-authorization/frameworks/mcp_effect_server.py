"""Real stdio fixture; journal is written only inside the effect body."""

import asyncio
import os
from pathlib import Path


def main():
    from tenuo import Authorizer, PublicKey
    from tenuo.mcp import MCPVerifier

    root_hex = os.environ.get("TENUO_TEST_ROOT")
    native_v2 = False
    try:
        from mcp.server.mcpserver import MCPServer

        native_v2 = True
    except ImportError:
        from fastmcp import FastMCP as MCPServer
    if root_hex:
        verifier = MCPVerifier(
            authorizer=Authorizer(
                trusted_roots=[PublicKey.from_bytes(bytes.fromhex(root_hex))]
            ),
            require_warrant=True,
        )
        if native_v2:
            from tenuo.mcp import TenuoServerMiddleware

            auth = TenuoServerMiddleware(verifier)
        else:
            from tenuo.mcp.fastmcp_middleware import TenuoMiddleware

            auth = TenuoMiddleware(verifier)
        server = MCPServer("skill-effect", middleware=[auth])
        decorate = auth.tool(server) if native_v2 else server.tool()
    else:
        # Agents SDK tests isolate its own MCP interception against a raw server.
        server = MCPServer("skill-effect")
        decorate = server.tool()

    @decorate
    def refund(amount: int) -> str:
        """Refund cents; append to the durable effect journal."""
        with Path(os.environ["TENUO_TEST_JOURNAL"]).open("a") as f:
            f.write(str(amount) + "\n")
        return "refunded"

    if native_v2:
        server.run()
    else:
        asyncio.run(server.run_stdio_async(show_banner=False, log_level="CRITICAL"))


if __name__ == "__main__":
    main()
