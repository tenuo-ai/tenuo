#!/usr/bin/env python3
"""
Stdio MCP server for examples/temporal/temporal_mcp_layering.py.

Intentionally minimal for the demo, not a production MCP server layout (no lifecycle
hardening, observability, or multi-tool routing). Do not copy the ``request_handlers``
override into real servers unless you need full ``CallToolRequest`` access and
understand the tradeoffs.

Verifies each tools/call with Tenuo MCPVerifier using warrant + PoP in
params._meta["tenuo"]. We assign ``server.request_handlers[CallToolRequest]`` because
the stock ``@server.call_tool(name, args)`` handler never passes ``params._meta`` to
your function, and MCPVerifier needs it.

Environment:
  TENUO_TEMPORAL_MCP_TRUSTED_ROOT_HEX — hex-encoded Ed25519 issuer public key (64 hex chars)

Run: started automatically by temporal_mcp_layering.py via SecureMCPClient (stdio).
"""

from __future__ import annotations

import asyncio
import os
import sys

try:
    from mcp import types
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
except ImportError:
    print("Install MCP: uv pip install 'tenuo[mcp]'", file=sys.stderr)
    sys.exit(1)

from tenuo import Authorizer, PublicKey
from tenuo.mcp.server import MCPVerifier


def _meta_to_dict(meta: object | None) -> dict | None:
    if meta is None:
        return None
    if hasattr(meta, "model_dump"):
        return meta.model_dump(mode="python")
    if isinstance(meta, dict):
        return meta
    return None


def main() -> None:
    hex_key = os.environ.get("TENUO_TEMPORAL_MCP_TRUSTED_ROOT_HEX", "").strip()
    if not hex_key:
        print("Missing TENUO_TEMPORAL_MCP_TRUSTED_ROOT_HEX", file=sys.stderr)
        sys.exit(1)

    issuer_pk = PublicKey.from_bytes(bytes.fromhex(hex_key))
    authorizer = Authorizer(trusted_roots=[issuer_pk])
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)

    server = Server("tenuo-temporal-mcp-demo")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="safe_echo",
                description="Echo a message (authorized by Tenuo MCPVerifier)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "description": "Message to echo"},
                    },
                    "required": ["message"],
                },
            ),
        ]

    async def handle_call_tool(req: types.CallToolRequest) -> types.ServerResult:
        params = req.params
        tool_name = params.name
        arguments = dict(params.arguments or {})
        meta_dict = _meta_to_dict(params.meta)

        v = verifier.verify(tool_name, arguments, meta=meta_dict)
        if not v.allowed:
            return types.ServerResult(
                types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=v.denial_reason or "MCP authorization denied",
                        )
                    ],
                    isError=True,
                )
            )

        if tool_name == "safe_echo":
            msg = str(v.clean_arguments.get("message", ""))
            return types.ServerResult(
                types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"MCP echo: {msg}")],
                    isError=False,
                )
            )

        return types.ServerResult(
            types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool: {tool_name}")],
                isError=True,
            )
        )

    server.request_handlers[types.CallToolRequest] = handle_call_tool

    async def run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(run())


if __name__ == "__main__":
    main()
