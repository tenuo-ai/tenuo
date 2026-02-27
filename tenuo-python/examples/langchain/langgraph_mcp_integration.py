#!/usr/bin/env python3
"""
LangGraph + Tenuo + MCP Integration Example.

This example demonstrates a secure multi-agent graph where:
1. An orchestrator receives a user request.
2. It delegates to a researcher node with narrowed authority.
3. The researcher node uses MCP tools (discovered and protected by Tenuo).
4. All tool calls are cryptographically authorized and constrained.

Prerequisites:
    uv pip install "tenuo[langgraph,mcp]"
"""

import asyncio
from pathlib import Path
from typing import TypedDict

try:
    from langgraph.graph import END, START, StateGraph

    from tenuo import Capability, Pattern, SigningKey, configure, mint
    from tenuo.mcp import MCP_AVAILABLE, SecureMCPClient
except ImportError:
    print('❌ Prerequisites not met. Install with: uv pip install "tenuo[langgraph,mcp]"')
    import sys

    sys.exit(1)


# 1. Define Graph State
class AgentState(TypedDict):
    query: str
    research_results: str
    final_answer: str


# 2. Setup MCP Server (Simulated)
SERVER_SCRIPT = Path(__file__).parent.parent / "mcp" / "mcp_server_demo.py"


async def main():
    if not MCP_AVAILABLE:
        print("❌ MCP SDK not installed. Skipping demo.")
        return

    if not SERVER_SCRIPT.exists():
        print(f"❌ MCP server script not found at {SERVER_SCRIPT}. Skipping demo.")
        return

    print("=== LangGraph + Tenuo + MCP Integration Demo ===\n")

    # 3. Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    print("   ✓ Tenuo configured")

    # 4. Connect to MCP Server and discover tools
    async with SecureMCPClient("python", [str(SERVER_SCRIPT)], register_config=True) as mcp_client:
        print("   ✓ Connected to MCP server and registered config")

        protected_tools = mcp_client.tools
        print(f"   ✓ Discovered {len(protected_tools)} MCP tools")

        # 5. Define Graph Nodes
        # The MCP tools are already guarded by Tenuo. The mint() context manager
        # sets the warrant in context, and MCP tool calls check it automatically.

        async def researcher_node(state: AgentState):
            """Researcher node — MCP tools enforce authorization via context warrant."""
            print("\n   [Node: Researcher] Executing with restricted warrant...")

            query = state["query"]
            target_file = "/tmp/research_data.txt"
            Path(target_file).write_text(f"Research data for: {query}")

            print(f"   Calling read_file(path='{target_file}')...")

            result = await protected_tools["read_file"](path=target_file)

            content = result[0].text if result else "No content"
            print(f"   ✓ Tool result received: {content}")

            return {"research_results": content}

        async def answer_node(state: AgentState):
            """Simple node to format the final answer."""
            print("\n   [Node: Answer] Formatting result...")
            return {"final_answer": f"Based on research: {state['research_results']}"}

        # 6. Build the Graph
        workflow = StateGraph(AgentState)
        workflow.add_node("researcher", researcher_node)
        workflow.add_node("answer", answer_node)

        workflow.add_edge(START, "researcher")
        workflow.add_edge("researcher", "answer")
        workflow.add_edge("answer", END)

        app = workflow.compile()
        print("   ✓ LangGraph application built")

        # 7. Run with Task Scoping
        # mint() creates a root warrant and sets it in context.
        # The MCP protected tools pick it up automatically.
        print("\n7. Running graph with root task authority...")

        async with mint(
            Capability("read_file", path=Pattern("/tmp/*")),
            Capability("list_directory", path=Pattern("/tmp/*")),
        ):
            input_state = {"query": "Tenuo Security", "research_results": "", "final_answer": ""}
            final_state = await app.ainvoke(input_state)

            print("\n=== Final Graph Output ===")
            print(f"Query: {final_state['query']}")
            print(f"Answer: {final_state['final_answer']}")

        # 8. Test Security (Unauthorized path)
        print("\n8. Testing security boundary...")
        async with mint(Capability("read_file", path=Pattern("/tmp/*"))):
            try:
                print("   Researcher attempting to read /etc/passwd...")
                await protected_tools["read_file"](path="/etc/passwd")
            except Exception as e:
                print(f"   ✓ Blocked by Tenuo: {type(e).__name__}")


if __name__ == "__main__":
    asyncio.run(main())
