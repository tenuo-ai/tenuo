#!/usr/bin/env python3
"""
Simple MCP Server for Testing Tenuo Integration.

This is a minimal MCP server that exposes filesystem operations.
Used for testing SecureMCPClient.
"""

import sys
from pathlib import Path

try:
    from mcp.server.mcpserver import MCPServer  # MCP SDK 2.x
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer  # MCP SDK 1.x
    except ImportError:
        print("MCP SDK not installed. Install with: uv pip install mcp", file=sys.stderr)
        sys.exit(1)


# Create MCP server
server = MCPServer("demo-filesystem-server")


@server.tool()
def read_file(path: str, max_size: int = 1048576) -> str:
    """Read contents of a file"""
    try:
        file_path = Path(path)
        if not file_path.exists():
            return f"Error: File not found: {path}"

        with open(file_path, "r") as f:
            return f.read(max_size)
    except Exception as e:
        return f"Error reading file: {e}"


@server.tool()
def list_directory(path: str) -> str:
    """List files in a directory"""
    try:
        dir_path = Path(path)
        if not dir_path.is_dir():
            return f"Error: Not a directory: {path}"

        return "\n".join(f.name for f in dir_path.iterdir())
    except Exception as e:
        return f"Error listing directory: {e}"


if __name__ == "__main__":
    server.run()
