#!/usr/bin/env python3
"""A stdio server on the official MCP SDK (not FastMCP); ``tenuo.mcp.wrap`` must refuse it."""

from __future__ import annotations

try:
    from mcp.server.mcpserver import MCPServer as Server  # mcp >= 2
except ImportError:
    from mcp.server.fastmcp import FastMCP as Server  # mcp 1.x

mcp = Server("plain")


@mcp.tool()
def hello() -> str:
    return "hi"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
