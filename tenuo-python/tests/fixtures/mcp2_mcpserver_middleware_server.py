#!/usr/bin/env python3
"""Stdio ``MCPServer`` (MCP SDK 2.x) guarded by :class:`TenuoServerMiddleware`.

Usage: ``python mcp2_mcpserver_middleware_server.py <root public key hex>``

Every tool is registered with the plain high-level decorator and an ordinary
signature. None of them declares ``_tenuo``; the middleware verifies the
envelope, from ``_meta`` or from the reserved argument, and strips it before
the SDK validates the arguments.
"""

from __future__ import annotations

import sys

try:
    from mcp.server.mcpserver import Context, MCPServer
except ImportError:  # pragma: no cover - exercised only without the SDK
    print("MCP SDK 2.x not installed.", file=sys.stderr)
    sys.exit(1)

from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier
from tenuo.mcp.mcpserver_middleware import TenuoServerMiddleware

root_hex = sys.argv[1]
verifier = MCPVerifier(
    authorizer=Authorizer(trusted_roots=[PublicKey.from_bytes(bytes.fromhex(root_hex))])
)
mcp = MCPServer("guarded", middleware=[TenuoServerMiddleware(verifier)])


@mcp.tool()
def read_file(path: str) -> str:
    """Pretend to read a file."""
    return f"contents of {path}"


@mcp.tool()
def argument_keys(path: str, ctx: Context) -> str:
    """Report the argument keys the handler's request context still carries."""
    params = ctx.request_context.params or {}
    arguments = params.get("arguments") or {}
    meta = ctx.request_context.meta or {}
    return f"arguments={sorted(arguments)} meta={sorted(meta)}"


if __name__ == "__main__":
    mcp.run()
