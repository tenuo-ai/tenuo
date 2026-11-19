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

try:
    from mcp.server.mcpserver import MCPServer  # MCP SDK 2.x
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer  # MCP SDK 1.x

# Check for Tavily (optional - will use mock if not available)
try:
    from tavily import TavilyClient

    TAVILY_AVAILABLE = True
except ImportError:
    TAVILY_AVAILABLE = False

# Initialize MCP server
server = MCPServer("research-tools")

BASE_DIR = "/tmp/research"


def _resolve(path: str):
    """Map a path under BASE_DIR; None if it escapes."""
    full_path = os.path.normpath(os.path.join(BASE_DIR, path.lstrip("/")))
    return full_path if full_path.startswith(BASE_DIR) else None


@server.tool()
def web_search(query: str, domain: str = "") -> str:
    """Search the web for information. Returns search results.

    Args:
        query: Search query
        domain: Optional: restrict search to this domain (e.g., 'arxiv.org')
    """
    # Build search query with domain filter
    search_query = f"site:{domain} {query}" if domain else query

    if TAVILY_AVAILABLE and os.getenv("TAVILY_API_KEY"):
        try:
            client = TavilyClient(api_key=os.getenv("TAVILY_API_KEY"))
            response = client.search(query=search_query, search_depth="basic", max_results=3)

            results = []
            for r in response.get("results", []):
                results.append(
                    f"• {r.get('title', 'No title')}\n  URL: {r.get('url', '')}\n  {r.get('content', '')[:200]}..."
                )

            return "\n\n".join(results) if results else "No results found."
        except Exception as e:
            return f"Search error: {e}"

    # Mock response for demo without Tavily
    return f"""[MOCK SEARCH RESULTS for: {search_query}]

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


@server.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file. Paths are mapped to /tmp/research/.

    Args:
        path: File path (e.g., /data/research/notes.md → /tmp/research/data/research/notes.md)
        content: Content to write
    """
    os.makedirs(BASE_DIR, exist_ok=True)
    full_path = _resolve(path)
    if full_path is None:
        return f"Error: Path must be within {BASE_DIR}"

    try:
        os.makedirs(os.path.dirname(full_path) or BASE_DIR, exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {full_path}"
    except Exception as e:
        return f"Write error: {e}"


@server.tool()
def read_file(path: str) -> str:
    """Read content from a file. Paths are mapped to /tmp/research/.

    Args:
        path: File path (e.g., /data/research/notes.md → /tmp/research/data/research/notes.md)
    """
    full_path = _resolve(path)
    if full_path is None:
        return f"Error: Path must be within {BASE_DIR}"

    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"File not found: {full_path}"
    except Exception as e:
        return f"Read error: {e}"


if __name__ == "__main__":
    server.run()
