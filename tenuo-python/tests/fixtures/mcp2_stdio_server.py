#!/usr/bin/env python3
"""Stdio MCP server built against the MCP SDK 2.x lowlevel API.

``examples/mcp/mcp_server_demo.py`` drives the 1.x decorator API, which 2.0
restructured, so end-to-end coverage of :class:`~tenuo.mcp.SecureMCPClient`
would otherwise stop at the 1.x line.  2.x registers handlers explicitly via
``Server.add_request_handler`` instead.

Alongside the filesystem tools the 1.x demo exposes, this server can return a
*server-side denial* — a ``CallToolResult`` with the error flag and a Tenuo
``structuredContent`` block.  No fixture did that before, which is why a client
that misread the renamed ``isError`` field went unnoticed: the client treated
the denial as a successful call.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import mcp.types as mt
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
except ImportError:  # pragma: no cover - exercised only without the SDK
    print("MCP SDK not installed. Install with: uv pip install mcp", file=sys.stderr)
    sys.exit(1)

# The decorator API this server deliberately avoids is the 1.x marker; its
# absence is what makes add_request_handler the right entry point.
if hasattr(Server, "list_tools"):  # pragma: no cover - guarded by the caller
    print(
        "This server targets the MCP 2.x lowlevel API; the installed SDK is 1.x. "
        "Use examples/mcp/mcp_server_demo.py instead.",
        file=sys.stderr,
    )
    sys.exit(1)

#: Denial codes the client is expected to map to distinct exceptions.
DENY_TOOL = "always_denied"
APPROVAL_TOOL = "needs_approval"

TOOLS = [
    mt.Tool(
        name="read_file",
        description="Read contents of a file",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
                "max_size": {
                    "type": "integer",
                    "description": "Maximum bytes to read",
                    "default": 1048576,
                },
            },
            "required": ["path"],
        },
    ),
    mt.Tool(
        name="list_directory",
        description="List files in a directory",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory path"}},
            "required": ["path"],
        },
    ),
    mt.Tool(
        name=DENY_TOOL,
        description="Always returns a Tenuo authorization denial",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
    mt.Tool(
        name=APPROVAL_TOOL,
        description="Always returns a Tenuo insufficient-approvals denial",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
]


def _denial(message: str, tenuo_block: dict) -> mt.CallToolResult:
    """Build an error result using whichever field names the SDK defines.

    Constructed by alias so the same call is valid on either line; only the
    *reading* side needed a compatibility shim.
    """
    return mt.CallToolResult.model_validate(
        {
            "content": [{"type": "text", "text": message}],
            "isError": True,
            "structuredContent": {"tenuo": tenuo_block},
        }
    )


def _text(message: str) -> mt.CallToolResult:
    return mt.CallToolResult.model_validate(
        {"content": [{"type": "text", "text": message}]}
    )


async def _list_tools(_ctx: object, _params: object) -> mt.ListToolsResult:
    return mt.ListToolsResult(tools=TOOLS)


async def _call_tool(_ctx: object, params: mt.CallToolRequestParams) -> mt.CallToolResult:
    name = params.name
    arguments = params.arguments or {}

    if name == DENY_TOOL:
        return _denial(
            "Tool 'always_denied' is not authorized by the presented warrant",
            {"code": -32003, "tool": name},
        )

    if name == APPROVAL_TOOL:
        return _denial(
            "Insufficient approvals for 'needs_approval': got 1, need 2",
            {"code": -32002, "tool": name, "got": 1, "need": 2},
        )

    if name == "read_file":
        path = Path(arguments["path"])
        max_size = arguments.get("max_size", 1048576)
        if not path.exists():
            return _text(f"Error: File not found: {path}")
        return _text(path.read_text()[:max_size])

    if name == "list_directory":
        path = Path(arguments["path"])
        if not path.is_dir():
            return _text(f"Error: Not a directory: {path}")
        return _text("\n".join(entry.name for entry in path.iterdir()))

    return _text(f"Unknown tool: {name}")


def build_server() -> Server:
    server: Server = Server("tenuo-mcp2-test-server")
    server.add_request_handler("tools/list", mt.PaginatedRequestParams, _list_tools)
    server.add_request_handler("tools/call", mt.CallToolRequestParams, _call_tool)
    return server


async def main() -> None:
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import anyio

    anyio.run(main)
