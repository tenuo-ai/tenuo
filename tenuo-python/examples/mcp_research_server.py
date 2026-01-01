#!/usr/bin/env python3
"""
MCP Server for Research Agent Demo

A simple MCP server that exposes web search and file operations.
Used by research_agent_demo.py.

This is a SEPARATE process that the demo connects to via stdio.

Usage:
    # Run directly (for testing):
    python mcp_research_server.py

    # The demo script starts this automatically via SecureMCPClient
"""

import os
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Check for Tavily (optional - will use mock if not available)
try:
    from tavily import TavilyClient
    TAVILY_AVAILABLE = True
except ImportError:
    TAVILY_AVAILABLE = False

# Initialize MCP server
server = Server("research-tools")


@server.list_tools()
async def list_tools():
    """List available tools."""
    return [
        Tool(
            name="web_search",
            description="Search the web for information. Returns search results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Optional: restrict search to this domain (e.g., 'arxiv.org')"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="write_file",
            description="Write content to a file. Paths are mapped to /tmp/research/.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (e.g., /data/research/notes.md → /tmp/research/data/research/notes.md)"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write"
                    }
                },
                "required": ["path", "content"]
            }
        ),
        Tool(
            name="read_file",
            description="Read content from a file. Paths are mapped to /tmp/research/.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (e.g., /data/research/notes.md → /tmp/research/data/research/notes.md)"
                    }
                },
                "required": ["path"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Handle tool calls."""

    if name == "web_search":
        query = arguments.get("query", "")
        domain = arguments.get("domain", "")

        # Build search query with domain filter
        search_query = f"site:{domain} {query}" if domain else query

        if TAVILY_AVAILABLE and os.getenv("TAVILY_API_KEY"):
            try:
                client = TavilyClient(api_key=os.getenv("TAVILY_API_KEY"))
                response = client.search(
                    query=search_query,
                    search_depth="basic",
                    max_results=3
                )

                results = []
                for r in response.get("results", []):
                    results.append(
                        f"• {r.get('title', 'No title')}\n"
                        f"  URL: {r.get('url', '')}\n"
                        f"  {r.get('content', '')[:200]}..."
                    )

                return [TextContent(
                    type="text",
                    text="\n\n".join(results) if results else "No results found."
                )]
            except Exception as e:
                return [TextContent(type="text", text=f"Search error: {e}")]
        else:
            # Mock response for demo without Tavily
            return [TextContent(
                type="text",
                text=f"""[MOCK SEARCH RESULTS for: {search_query}]

• AI Agent Security: A Survey (2024)
  URL: https://arxiv.org/abs/2401.12345
  Recent advances in AI agent security focus on capability control,
  sandboxing, and authorization frameworks. Key challenges include...

• Securing LLM Tool Use with Cryptographic Warrants
  URL: https://arxiv.org/abs/2402.67890
  This paper proposes using capability-based security tokens to
  constrain AI agent actions at the tool level...

• Multi-Agent Systems: Security Considerations
  URL: https://arxiv.org/abs/2403.11111
  As AI agents become more autonomous, security becomes paramount.
  We analyze attack vectors including prompt injection..."""
            )]

    elif name == "write_file":
        path = arguments.get("path", "")
        content = arguments.get("content", "")

        # Security: restrict to /tmp/research/
        base_dir = "/tmp/research"
        os.makedirs(base_dir, exist_ok=True)

        # Normalize and validate path
        full_path = os.path.normpath(os.path.join(base_dir, path.lstrip("/")))
        if not full_path.startswith(base_dir):
            return [TextContent(type="text", text=f"Error: Path must be within {base_dir}")]

        try:
            os.makedirs(os.path.dirname(full_path) or base_dir, exist_ok=True)
            with open(full_path, "w") as f:
                f.write(content)
            return [TextContent(type="text", text=f"Successfully wrote {len(content)} bytes to {full_path}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Write error: {e}")]

    elif name == "read_file":
        path = arguments.get("path", "")

        base_dir = "/tmp/research"
        full_path = os.path.normpath(os.path.join(base_dir, path.lstrip("/")))
        if not full_path.startswith(base_dir):
            return [TextContent(type="text", text=f"Error: Path must be within {base_dir}")]

        try:
            with open(full_path, "r") as f:
                content = f.read()
            return [TextContent(type="text", text=content)]
        except FileNotFoundError:
            return [TextContent(type="text", text=f"File not found: {full_path}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Read error: {e}")]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

