#!/usr/bin/env python3
"""
Stdio FastMCP server with :class:`TenuoMiddleware` for integration tests.

Environment:
    TENUO_MCP_E2E_ISSUER_PUB — hex-encoded issuer :class:`~tenuo_core.PublicKey`
    bytes (trusted root for :class:`~tenuo.mcp.MCPVerifier`).
"""
from __future__ import annotations

import asyncio
import os
import sys


def main() -> None:
    pub_hex = os.environ.get("TENUO_MCP_E2E_ISSUER_PUB", "").strip()
    if not pub_hex:
        print("TENUO_MCP_E2E_ISSUER_PUB is required", file=sys.stderr)
        sys.exit(2)

    from fastmcp import FastMCP
    from tenuo import Authorizer, PublicKey
    from tenuo.mcp.fastmcp_middleware import TenuoMiddleware
    from tenuo.mcp.server import MCPVerifier

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(pub_hex))]
    )
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    mcp = FastMCP("tenuo-mw-e2e", middleware=[TenuoMiddleware(verifier)])

    @mcp.tool()
    async def ping() -> str:
        return "pong"

    asyncio.run(mcp.run_stdio_async(show_banner=False, log_level="CRITICAL"))


if __name__ == "__main__":
    main()
