#!/usr/bin/env python3
"""
Simple MCP Server for Testing Tenuo Integration.

This is a minimal MCP server that exposes filesystem operations.
Used for testing SecureMCPClient.
"""

import asyncio
import sys
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError:
    print("MCP SDK not installed. Install with: uv pip install mcp", file=sys.stderr)
    sys.exit(1)


# Create MCP server
server = Server("demo-filesystem-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="read_file",
            description="Read contents of a file",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"},
                    "max_size": {"type": "integer", "description": "Maximum bytes to read", "default": 1048576},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="list_directory",
            description="List files in a directory",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Directory path"}},
                "required": ["path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls."""

    if name == "read_file":
        path = arguments["path"]
        max_size = arguments.get("max_size", 1048576)

        try:
            file_path = Path(path)
            if not file_path.exists():
                return [TextContent(type="text", text=f"Error: File not found: {path}")]

            with open(file_path, "r") as f:
                content = f.read(max_size)

            return [TextContent(type="text", text=content)]
        except Exception as e:
            return [TextContent(type="text", text=f"Error reading file: {e}")]

    elif name == "list_directory":
        path = arguments["path"]

        try:
            dir_path = Path(path)
            if not dir_path.is_dir():
                return [TextContent(type="text", text=f"Error: Not a directory: {path}")]

            files = [f.name for f in dir_path.iterdir()]
            return [TextContent(type="text", text="\n".join(files))]
        except Exception as e:
            return [TextContent(type="text", text=f"Error listing directory: {e}")]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
