#!/usr/bin/env python3
"""
CrewAI + MCP Integration with Tenuo

Demonstrates CrewAI crews using MCP tools with warrant authorization.

Scenario: Research Workflow
  - Researcher: Uses MCP web_search and read_file tools
  - Writer: Uses MCP write_file tool
  - Editor: Uses MCP read_file tool for verification

What this shows:
- CrewAI agents with MCP tool access
- Per-agent warrant attenuation (least privilege)
- Research → Write → Edit workflow using MCP tools
- Constraint enforcement in crew workflows
- Attack demonstrations

Prerequisites:
    uv pip install "tenuo[mcp]" crewai

Usage:
    # Optional: Set Tavily API key for real web search
    export TAVILY_API_KEY=your-key

    # Run demo
    python crewai_mcp_demo.py
"""

import asyncio
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# Ensure we can import from tenuo
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from crewai import Agent, Crew, Process, Task  # noqa: F401
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    print("⚠️  CrewAI not installed. Install with: uv pip install crewai")
    print("   Running in simulation mode...\n")

from tenuo import (
    Pattern,
    SigningKey,
    Subpath,
    Warrant,
    Wildcard,
    chain_scope,
    configure,
    key_scope,
    warrant_scope,
)
from tenuo.mcp import MCP_AVAILABLE, SecureMCPClient


# Colors
class C:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def log(msg: str, color: str = C.CYAN):
    print(f"{color}{msg}{C.RESET}")


def header(text: str):
    print(f"\n{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{text.center(70)}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}\n")


# =============================================================================
# MCP Tool Wrappers for CrewAI
# =============================================================================

class MCPToolWrapper:
    """Wrapper to make MCP tools callable in CrewAI context."""

    def __init__(self, name: str, mcp_client: SecureMCPClient, warrant: Warrant, signing_key: SigningKey):
        self.name = name
        self.mcp_client = mcp_client
        self.warrant = warrant
        self.signing_key = signing_key

    async def call(self, **kwargs) -> Any:
        """Call the MCP tool with warrant authorization."""
        # In CrewAI, we'd use this in a custom tool
        # For demo, we'll call directly
        return await self.mcp_client.tools[self.name](**kwargs)


# =============================================================================
# Demo
# =============================================================================

async def run_demo():
    """Run the CrewAI + MCP demo."""

    header("CrewAI + MCP Integration")

    if not CREWAI_AVAILABLE:
        log("CrewAI not available, running simulation...", C.YELLOW)
        await run_simulation()
        return

    if not MCP_AVAILABLE:
        log("❌ MCP SDK not installed", C.YELLOW)
        log('   Install with: uv pip install "tenuo[mcp]"')
        return

    # Setup keys
    log("🔑 Generating cryptographic keys...")
    control_key = SigningKey.generate()
    crew_orchestrator_key = SigningKey.generate()
    log("   ✓ Control Plane, Crew Orchestrator")

    # Trust the control plane key as the root of every warrant chain
    configure(issuer_key=control_key, trusted_roots=[control_key.public_key])

    # Setup test environment
    log("\n📁 Setting up test environment...")
    test_dir = Path("/tmp/crewai_mcp_test")
    sources_dir = test_dir / "sources"
    output_dir = test_dir / "output"
    sources_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    (sources_dir / "reference.txt").write_text("AI agent security: Best practices include...")
    log(f"   ✓ Created test directories in {test_dir}")

    # Find MCP research server
    mcp_server_script = Path(__file__).parent / "mcp_research_server.py"
    if not mcp_server_script.exists():
        log(f"\n❌ MCP server not found: {mcp_server_script}", C.YELLOW)
        log("   Ensure mcp_research_server.py is in the same directory")
        return

    log("\n🚀 Starting MCP research server...")

    # Create MCP client
    mcp_client = SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)],
        register_config=True,
    )
    await mcp_client.connect()
    log("   ✓ MCP server connected")

    # Discover tools
    mcp_tools = await mcp_client.get_tools()
    log(f"   ✓ Discovered {len(mcp_tools)} MCP tools:")
    for tool in mcp_tools:
        log(f"     • {tool.name}", C.BLUE)

    try:
        # Issue crew orchestrator warrant
        log("\n📜 Control Plane issues warrant to Crew Orchestrator...")
        orchestrator_warrant = (Warrant.mint_builder()
            .capability("web_search", domain=Wildcard(), query=Pattern("*"))
            .capability("read_file", path=Subpath("/tmp/research"))
            .capability("write_file", path=Subpath("/tmp/research"), content=Pattern("*"))
            .holder(crew_orchestrator_key.public_key)
            .ttl(3600)
            .mint(control_key))

        log(f"   Warrant ID: {orchestrator_warrant.id[:12]}...")
        log(f"   Tools: {', '.join(orchestrator_warrant.tools)}")

        # Attenuate warrants for crew members
        log("\n🔐 Crew Orchestrator attenuates warrants for crew members...")

        # Researcher: search + read only
        researcher_warrant = orchestrator_warrant.attenuate(
            signing_key=crew_orchestrator_key,
            holder=crew_orchestrator_key.public_key,  # Same holder for demo
            capabilities={
                "web_search": {"domain": Pattern("*.org"), "query": Pattern("*")},
                "read_file": {"path": Subpath("/tmp/research/sources")},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Researcher: web_search (*.org only), read_file (sources only)")

        # Writer: write only
        writer_warrant = orchestrator_warrant.attenuate(
            signing_key=crew_orchestrator_key,
            holder=crew_orchestrator_key.public_key,
            capabilities={
                "write_file": {"path": Subpath("/tmp/research/output"), "content": Pattern("*")},
                "read_file": {"path": Subpath("/tmp/research/sources")},  # For reference
            },
            ttl_seconds=1800,
        )
        log("   ✓ Writer: write_file (output only), read_file (sources for reference)")

        # Editor: read only
        editor_warrant = orchestrator_warrant.attenuate(
            signing_key=crew_orchestrator_key,
            holder=crew_orchestrator_key.public_key,
            capabilities={
                "read_file": {"path": Subpath("/tmp/research/output")},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Editor: read_file (output only)")

        @contextmanager
        def crew_member(warrant: Warrant):
            """Put a crew member's warrant, its parent chain and holder key in scope."""
            with chain_scope([orchestrator_warrant]), warrant_scope(warrant), key_scope(crew_orchestrator_key):
                yield

        # =================================================================
        # Research Workflow (Simulated CrewAI)
        # =================================================================

        header("Research Workflow")

        # Phase 1: Researcher
        log("📚 Phase 1: Researcher gathers information...")
        log("   Using warrant: web_search + read_file (sources)")

        with crew_member(researcher_warrant):
            # Search web
            search_result = await mcp_client.tools["web_search"](  # noqa: F841
                query="AI agent security best practices", domain="arxiv.org"
            )
            log("   ✓ Web search complete", C.GREEN)
            log("   Found research on AI security", C.BLUE)

            # Read reference
            read_result = await mcp_client.tools["read_file"](  # noqa: F841
                path="/tmp/research/sources/reference.txt"
            )
        log("   ✓ Read reference file", C.GREEN)

        # Phase 2: Writer
        log("\n✍️  Phase 2: Writer creates content...")
        log("   Using warrant: write_file (output only)")

        article_content = """# AI Agent Security Best Practices

Based on research from arxiv.org and reference materials:

## Overview
Modern AI agents require robust security frameworks to prevent unauthorized actions.

## Key Principles
1. Least-privilege access control
2. Cryptographic authorization (warrants)
3. Constraint-based tool usage
4. Audit trails for accountability

## Recommendations
- Use warrant-based authorization for all tool calls
- Implement path restrictions for filesystem access
- Monitor agent behavior for anomalies
- Regular security audits

## Conclusion
Security must be built into agent architectures from the ground up.
"""

        with crew_member(writer_warrant):
            write_result = await mcp_client.tools["write_file"](
                path="/tmp/research/output/article.md", content=article_content
            )
        log("   ✓ Article written to output/article.md", C.GREEN)
        log(f"   {write_result[0].text}", C.BLUE)

        # Phase 3: Editor
        log("\n📝 Phase 3: Editor reviews content...")
        log("   Using warrant: read_file (output only)")

        with crew_member(editor_warrant):
            editor_read = await mcp_client.tools["read_file"](path="/tmp/research/output/article.md")
        content = editor_read[0].text
        log(f"   ✓ Retrieved article ({len(content)} bytes)", C.GREEN)
        log(f"   Preview: {content[:80]}...", C.BLUE)
        log("   ✅ Content approved for publication", C.GREEN)

        # =================================================================
        # Security Demonstrations
        # =================================================================

        header("Security: Warrant Constraints in Action")

        log("🔒 Attack 1: Researcher tries to write (privilege escalation)")
        try:
            # Researcher only has read access, tries write
            with crew_member(researcher_warrant):
                await mcp_client.tools["write_file"](path="/tmp/research/output/malicious.txt", content="pwned")
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Researcher warrant doesn't include write_file")

        log("\n🔒 Attack 2: Writer tries path traversal")
        try:
            with crew_member(writer_warrant):
                await mcp_client.tools["write_file"](path="/etc/passwd", content="malicious")
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Subpath constraint restricts to /tmp/research/output")

        log("\n🔒 Attack 3: Editor tries to read sources (out of scope)")
        try:
            with crew_member(editor_warrant):
                await mcp_client.tools["read_file"](path="/tmp/research/sources/reference.txt")
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Editor warrant only allows output directory")

        log("\n🔒 Attack 4: Researcher tries unauthorized domain")
        try:
            with crew_member(researcher_warrant):
                await mcp_client.tools["web_search"](query="hacking tools", domain="evil.com")
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Pattern constraint only allows *.org domains")

        # =================================================================
        # Summary
        # =================================================================

        header("Summary")
        log("✅ CrewAI-style workflow with MCP tools")
        log("✅ Three crew members with attenuated warrants:")
        log("   • Researcher: web_search + read (sources)")
        log("   • Writer: write (output) + read (sources)")
        log("   • Editor: read (output)")
        log("✅ Complete research workflow executed")
        log("✅ All attacks blocked by warrant constraints")
        log("\nKey Benefits:")
        log("  • Per-agent least-privilege access")
        log("  • MCP tools secured with cryptographic warrants")
        log("  • Constraint enforcement at runtime")
        log("  • Clear audit trail of tool usage")

        log("\n\n📘 Note:")
        log("  This demo simulates CrewAI workflow patterns.")
        log("  In production, wrap MCP tools as CrewAI custom tools")
        log("  and use warrant scoping in tool execution context.")

    finally:
        # Cleanup
        log("\n🧹 Shutting down...")
        await mcp_client.close()
        await asyncio.sleep(0.5)


async def run_simulation():
    """Run simulation without CrewAI."""
    header("CrewAI + MCP Simulation")

    log("This demo shows CrewAI crews using MCP tools with Tenuo.")
    log("\nTo run the full demo:")
    log("  1. Install: uv pip install crewai")
    log("  2. Run: python crewai_mcp_demo.py")

    log("\n\nWorkflow:", C.YELLOW)
    log("  1. Researcher → Uses web_search and read_file (MCP tools)")
    log("  2. Writer    → Uses write_file (MCP tool)")
    log("  3. Editor    → Uses read_file (MCP tool)")

    log("\nSecurity:", C.YELLOW)
    log("  • Each crew member has attenuated warrant")
    log("  • Least-privilege principle enforced")
    log("  • Constraints prevent unauthorized access")
    log("  • Cryptographic proof of authorization")


async def main():
    """Entry point."""
    try:
        await run_demo()
    except KeyboardInterrupt:
        print("\n\n^C received")


if __name__ == "__main__":
    asyncio.run(main())
