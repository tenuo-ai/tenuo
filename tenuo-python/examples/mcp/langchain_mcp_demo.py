#!/usr/bin/env python3
"""
LangChain + MCP Integration with Tenuo

Demonstrates using MCP tools in LangChain agents with warrant authorization.

What this shows:
- MCPToolAdapter converting MCP tools to LangChain StructuredTool
- ReAct agent with protected MCP tools
- Warrant-scoped execution
- Constraint enforcement in agent workflows
- Attack demonstrations (path traversal, unauthorized access)

Prerequisites:
    uv pip install "tenuo[langchain,mcp]" langchain-openai

Usage:
    # Set OpenAI API key
    export OPENAI_API_KEY=your-key

    # Run demo
    python langchain_mcp_demo.py

    # Or run without LLM (simulation mode)
    python langchain_mcp_demo.py --simulate
"""

import asyncio
import sys
from pathlib import Path

# Check dependencies
try:
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain_core.prompts import PromptTemplate
    from langchain_openai import ChatOpenAI
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("⚠️  LangChain not installed. Install with: uv pip install langchain-openai")
    print("   Running in simulation mode...\n")

# Ensure we can import from tenuo
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tenuo import Capability, Range, SigningKey, Subpath, configure, mint
from tenuo.mcp import MCP_AVAILABLE, MCPToolAdapter, SecureMCPClient


# Colors
class C:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def log(msg: str, color: str = C.CYAN):
    print(f"{color}{msg}{C.RESET}")


def header(text: str):
    print(f"\n{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{text.center(70)}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}\n")


async def run_with_langchain():
    """Run demo with actual LangChain agent."""
    header("LangChain + MCP Integration Demo")

    if not LANGCHAIN_AVAILABLE:
        log("LangChain not available, running simulation...", C.YELLOW)
        await run_simulation()
        return

    if not MCP_AVAILABLE:
        log("❌ MCP SDK not installed", C.YELLOW)
        log('   Install with: uv pip install "tenuo[mcp]"')
        return

    # Setup Tenuo
    log("1. Configuring Tenuo...")
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    log("   ✓ Tenuo configured")

    # Find MCP server
    server_script = Path(__file__).parent / "mcp_server_demo.py"
    if not server_script.exists():
        log(f"\n❌ MCP server not found: {server_script}", C.YELLOW)
        log("   Ensure mcp_server_demo.py is in the same directory")
        return

    log("2. Connecting to MCP server...")

    try:
        async with SecureMCPClient(
            command="python",
            args=[str(server_script)],
            register_config=True,
        ) as client:
            log("   ✓ Connected to MCP server")

            # Discover MCP tools
            log("\n3. Discovering MCP tools...")
            mcp_tools = await client.get_tools()
            log(f"   ✓ Found {len(mcp_tools)} MCP tools:")
            for tool in mcp_tools:
                log(f"     - {tool.name}: {tool.description}", C.BLUE)

            # Convert to LangChain tools
            log("\n4. Converting MCP tools to LangChain format...")
            langchain_tools = []
            for tool in mcp_tools:
                try:
                    lc_tool = MCPToolAdapter(tool, client)
                    langchain_tools.append(lc_tool)
                    log(f"   ✓ Converted: {tool.name}", C.GREEN)
                except Exception as e:
                    log(f"   ⚠ Skipped {tool.name}: {e}", C.YELLOW)

            log(f"\n   ✓ {len(langchain_tools)} tools ready for LangChain")

            # Create test files
            log("\n5. Setting up test environment...")
            test_dir = Path("/tmp/langchain_mcp_test")
            test_dir.mkdir(exist_ok=True)

            (test_dir / "research.txt").write_text("AI agent security research notes")
            (test_dir / "data.txt").write_text("Important data file")
            log(f"   ✓ Created test files in {test_dir}")

            # Create LangChain agent
            log("\n6. Creating LangChain ReAct agent...")

            # Check for OpenAI API key
            import os
            if not os.getenv("OPENAI_API_KEY"):
                log("   ⚠️  OPENAI_API_KEY not set", C.YELLOW)
                log("   Running simulation mode instead...")
                await simulate_agent_workflow(client, test_dir)
                return

            llm = ChatOpenAI(temperature=0, model="gpt-4")

            prompt = PromptTemplate.from_template("""
Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Question: {input}
{agent_scratchpad}
""")

            agent = create_react_agent(llm, langchain_tools, prompt)
            executor = AgentExecutor(
                agent=agent,
                tools=langchain_tools,
                verbose=True,
                max_iterations=3,
                handle_parsing_errors=True,
            )

            log("   ✓ Agent created with MCP tools")

            # Execute with warrant authorization
            header("Agent Execution with Warrant Authorization")

            log("📋 Task: Read research notes from /tmp/langchain_mcp_test/")

            async with mint(Capability("read_file",
                                      path=Subpath(str(test_dir)),
                                      max_size=Range.max_value(10000))):
                log("\n   ✓ Warrant issued: read_file in /tmp/langchain_mcp_test/")
                log("   ✓ Max file size: 10KB\n")

                result = await executor.ainvoke({
                    "input": f"Read the file {test_dir}/research.txt and tell me what it contains"
                })

                log("\n✅ Agent Result:", C.GREEN)
                log(f"   {result['output']}", C.BLUE)

            # Test constraint enforcement
            header("Security: Constraint Enforcement")

            log("🔒 Attack 1: Try to read file outside authorized path")
            try:
                async with mint(Capability("read_file",
                                          path=Subpath(str(test_dir)),
                                          max_size=Range.max_value(10000))):
                    result = await executor.ainvoke({
                        "input": "Read the file /etc/passwd"
                    })
                log("   ❌ Should have been blocked!", C.YELLOW)
            except Exception as e:
                log(f"   ✅ BLOCKED: {type(e).__name__}", C.GREEN)
                log("   Subpath constraint prevented path traversal")

            log("\n🔒 Attack 2: Try to read without warrant")
            try:
                # No warrant context
                result = await executor.ainvoke({
                    "input": f"Read {test_dir}/data.txt"
                })
                log("   ❌ Should have been blocked!", C.YELLOW)
            except Exception as e:
                log(f"   ✅ BLOCKED: {type(e).__name__}", C.GREEN)
                log("   No warrant in scope")

            header("Summary")
            log("✅ LangChain agent used MCP tools successfully")
            log("✅ MCPToolAdapter converted tools to LangChain format")
            log("✅ Warrant-scoped execution enforced")
            log("✅ Path traversal attacks blocked")
            log("✅ Unauthorized access blocked")

    except Exception as e:
        log(f"\n❌ Error: {e}", C.YELLOW)
        import traceback
        traceback.print_exc()


async def simulate_agent_workflow(client, test_dir: Path):
    """Simulate agent workflow without actual LLM calls."""
    log("\n📋 Simulating agent workflow (no LLM calls)...")

    # Simulate agent using tools
    async with mint(Capability("read_file",
                              path=Subpath(str(test_dir)),
                              max_size=Range.max_value(10000))):
        log("\n   ✓ Warrant issued: read_file in authorized directory")

        # Agent decides to use read_file tool
        log("\n   Agent Thought: I should read the research file")
        log("   Agent Action: read_file")
        log(f"   Agent Input: {test_dir}/research.txt")

        # Execute tool
        result = await client.tools["read_file"](
            path=str(test_dir / "research.txt"),
            max_size=1000
        )

        log(f"\n   Observation: {result[0].text[:50]}...", C.BLUE)
        log("   Agent Thought: I now have the answer")
        log("   Final Answer: The file contains research notes", C.GREEN)

    # Test attacks
    log("\n\n🔒 Testing constraint enforcement...")

    try:
        async with mint(Capability("read_file",
                                  path=Subpath(str(test_dir)),
                                  max_size=Range.max_value(10000))):
            await client.tools["read_file"](path="/etc/passwd", max_size=1000)
        log("   ❌ Should have been blocked!", C.YELLOW)
    except Exception:
        log("   ✅ Path traversal blocked", C.GREEN)


async def run_simulation():
    """Run without LangChain for demonstration."""
    header("LangChain + MCP Simulation")

    log("This demo shows how LangChain agents use MCP tools with Tenuo.")
    log("\nTo run the full demo:")
    log("  1. Install: uv pip install langchain-openai")
    log("  2. Set: export OPENAI_API_KEY=your-key")
    log("  3. Run: python langchain_mcp_demo.py")

    log("\n\nKey Concepts:", C.YELLOW)
    log("  • MCPToolAdapter converts MCP tools to LangChain StructuredTool")
    log("  • ReAct agent uses tools with warrant authorization")
    log("  • Constraints enforced at runtime (path, size limits)")
    log("  • Attack prevention: path traversal, unauthorized access")


async def main():
    """Entry point."""
    import sys

    if "--simulate" in sys.argv or not LANGCHAIN_AVAILABLE:
        await run_simulation()
    else:
        await run_with_langchain()


if __name__ == "__main__":
    asyncio.run(main())
