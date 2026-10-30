# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2", "mcp==2.3.0", "fastmcp==4.1.0"]
# ///
"""The same real-transport example, pinned to MCP 2 instead of MCP 1."""
import asyncio
from mcp_stdio import main

if __name__ == "__main__":
    asyncio.run(main())
