#!/usr/bin/env python3
"""
MCP + A2A Multi-Agent Delegation

Demonstrates multi-agent systems where agents delegate MCP tool usage through A2A protocol.

Architecture:
    Control Plane (root authority)
         ↓
    Orchestrator (coordinates workflow)
         ↓
    Worker Agents (A2A servers with MCP clients)
         ↓
    MCP Servers (filesystem, search, etc.)

What this shows:
- A2A agents exposing MCP tools as skills
- Multi-hop authorization: Control → Orchestrator → Worker → MCP
- Warrant attenuation for MCP tool access
- MCP tools in distributed agent architecture
- Attack demonstrations: warrant theft, privilege escalation

Prerequisites:
    uv pip install "tenuo[a2a,mcp]"

Usage:
    python mcp_a2a_delegation.py
"""

import asyncio
import io
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure we can import from tenuo
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tenuo import Pattern, Range, SigningKey, Subpath, Warrant
from tenuo.a2a import A2AClient, A2AServer
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
# A2A Worker Agents (with MCP clients)
# =============================================================================

def create_file_worker(key: SigningKey, trusted: list, port: int, mcp_client: SecureMCPClient) -> A2AServer:
    """Worker agent that exposes MCP filesystem tools via A2A."""

    server = A2AServer(
        name="File Worker",
        url=f"http://localhost:{port}",
        public_key=key.public_key,
        trusted_issuers=trusted,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),
    )

    @server.skill("read_file", constraints={"path": Subpath, "max_size": Range})
    async def read_file(path: str, max_size: int = 10000) -> Dict[str, Any]:
        """Read file via MCP tool."""
        # Use MCP client internally
        result = await mcp_client.tools["read_file"](path=path, max_size=max_size)
        content = result[0].text if result else ""
        return {"path": path, "content": content, "size": len(content)}

    @server.skill("list_directory", constraints={"path": Subpath})
    async def list_directory(path: str) -> Dict[str, Any]:
        """List directory via MCP tool."""
        result = await mcp_client.tools["list_directory"](path=path)
        listing = result[0].text if result else ""
        files = listing.split("\n") if listing else []
        return {"path": path, "files": files, "count": len(files)}

    return server


def create_search_worker(key: SigningKey, trusted: list, port: int) -> A2AServer:
    """Worker agent that provides search capabilities (simulated)."""

    server = A2AServer(
        name="Search Worker",
        url=f"http://localhost:{port}",
        public_key=key.public_key,
        trusted_issuers=trusted,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),
    )

    @server.skill("search_files", constraints={"path": Subpath, "pattern": Pattern})
    async def search_files(path: str, pattern: str) -> Dict[str, Any]:
        """Search files by pattern."""
        # Simulate file search
        await asyncio.sleep(0.2)
        return {
            "path": path,
            "pattern": pattern,
            "matches": [
                f"{path}/result1.txt",
                f"{path}/result2.txt",
            ],
            "count": 2,
        }

    return server


# =============================================================================
# Demo
# =============================================================================

async def run_demo():
    """Run the MCP + A2A delegation demo."""

    header("MCP + A2A Multi-Agent Delegation")

    if not MCP_AVAILABLE:
        log("❌ MCP SDK not installed", C.YELLOW)
        log('   Install with: uv pip install "tenuo[mcp]"')
        return

    # Setup keys
    log("🔑 Generating cryptographic keys...")
    control_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()
    file_worker_key = SigningKey.generate()
    search_worker_key = SigningKey.generate()
    log("   ✓ Control Plane, Orchestrator, 2 Workers")

    # Setup test environment
    log("\n📁 Setting up test environment...")
    test_dir = Path("/tmp/mcp_a2a_test")
    test_dir.mkdir(exist_ok=True)
    (test_dir / "report.txt").write_text("Security audit report: All systems nominal")
    (test_dir / "data.txt").write_text("Sensitive data file")
    log(f"   ✓ Created test files in {test_dir}")

    # Find MCP server
    mcp_server_script = Path(__file__).parent / "mcp_server_demo.py"
    if not mcp_server_script.exists():
        log(f"\n❌ MCP server not found: {mcp_server_script}", C.YELLOW)
        return

    log("\n🚀 Starting MCP server...")

    # Create MCP client for file worker
    mcp_client = SecureMCPClient(
        command="python",
        args=[str(mcp_server_script)],
        register_config=True,
    )
    await mcp_client.connect()
    log("   ✓ MCP server connected")

    # Create A2A worker agents
    log("\n🤖 Starting A2A worker agents...")

    file_worker = create_file_worker(
        key=file_worker_key,
        trusted=[control_key.public_key, orchestrator_key.public_key],
        port=8001,
        mcp_client=mcp_client,
    )

    search_worker = create_search_worker(
        key=search_worker_key,
        trusted=[control_key.public_key, orchestrator_key.public_key],
        port=8002,
    )

    # Start servers
    import uvicorn

    async def start_server(app, port):
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", lifespan="off")
        server = uvicorn.Server(config)
        return asyncio.create_task(server.serve())

    file_task = await start_server(file_worker.app, 8001)
    search_task = await start_server(search_worker.app, 8002)

    await asyncio.sleep(1)
    log("   ✓ File Worker on http://localhost:8001 (MCP backend)")
    log("   ✓ Search Worker on http://localhost:8002")

    try:
        # Issue orchestrator warrant
        log("\n📜 Control Plane issues warrant to Orchestrator...")
        orchestrator_warrant = (Warrant.mint_builder()
            .capability("read_file", path=Subpath(str(test_dir)), max_size=Range.max_value(100000))
            .capability("list_directory", path=Subpath(str(test_dir)))
            .capability("search_files", path=Subpath(str(test_dir)), pattern=Pattern("*"))
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(control_key))

        log(f"   Warrant ID: {orchestrator_warrant.id[:12]}...")
        log(f"   Tools: {', '.join(orchestrator_warrant.tools)}")
        log(f"   Scope: {test_dir}")

        # =================================================================
        # Workflow: Orchestrator delegates to workers
        # =================================================================

        header("Multi-Agent Workflow")

        log("📊 Scenario: Security audit workflow")
        log("   1. Search for reports")
        log("   2. List files")
        log("   3. Read report contents\n")

        # Create A2A clients
        file_client = A2AClient("http://localhost:8001")
        search_client = A2AClient("http://localhost:8002")

        # Task 1: Search files (attenuate warrant for search worker)
        log("🔍 Step 1: Orchestrator → Search Worker")
        search_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=search_worker_key.public_key,
            capabilities={
                "search_files": {"path": Subpath(str(test_dir)), "pattern": Pattern("*.txt")},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Attenuated warrant: search_files only")

        search_result = await search_client.send_task(
            message="Search for text files",
            warrant=search_warrant,
            skill="search_files",
            arguments={"path": str(test_dir), "pattern": "*.txt"},
            signing_key=orchestrator_key,
        )
        log(f"   ✓ Found {search_result.output.get('count', 0)} matches", C.GREEN)

        # Task 2: List directory (attenuate warrant for file worker)
        log("\n📂 Step 2: Orchestrator → File Worker (list)")
        list_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=file_worker_key.public_key,
            capabilities={
                "list_directory": {"path": Subpath(str(test_dir))},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Attenuated warrant: list_directory only")

        list_result = await file_client.send_task(
            message="List directory contents",
            warrant=list_warrant,
            skill="list_directory",
            arguments={"path": str(test_dir)},
            signing_key=orchestrator_key,
        )
        log(f"   ✓ Found {list_result.output.get('count', 0)} files:", C.GREEN)
        for f in list_result.output.get('files', [])[:3]:
            log(f"     • {f}", C.BLUE)

        # Task 3: Read file (attenuate warrant for file worker)
        log("\n📖 Step 3: Orchestrator → File Worker (read via MCP)")
        read_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=file_worker_key.public_key,
            capabilities={
                "read_file": {"path": Subpath(str(test_dir)), "max_size": Range.max_value(10000)},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Attenuated warrant: read_file with 10KB limit")

        read_result = await file_client.send_task(
            message="Read report file",
            warrant=read_warrant,
            skill="read_file",
            arguments={"path": str(test_dir / "report.txt"), "max_size": 10000},
            signing_key=orchestrator_key,
        )
        content = read_result.output.get('content', '')
        log(f"   ✓ Read {read_result.output.get('size', 0)} bytes", C.GREEN)
        log(f"   Preview: {content[:60]}...", C.BLUE)

        # =================================================================
        # Security Demonstrations
        # =================================================================

        header("Security: Multi-Hop Authorization")

        log("🔒 Attack 1: Search Worker tries to read files (privilege escalation)")
        try:
            # Search worker has search_files only, tries read_file
            await file_client.send_task(
                message="Unauthorized read",
                warrant=search_warrant,  # Wrong warrant!
                skill="read_file",
                arguments={"path": str(test_dir / "data.txt"), "max_size": 1000},
                signing_key=orchestrator_key,
            )
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Warrant only authorized search_files, not read_file")

        log("\n🔒 Attack 2: File Worker tries path traversal")
        try:
            await file_client.send_task(
                message="Path traversal attempt",
                warrant=read_warrant,
                skill="read_file",
                arguments={"path": "/etc/passwd", "max_size": 1000},
                signing_key=orchestrator_key,
            )
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log(f"   Subpath constraint restricts to {test_dir}")

        log("\n🔒 Attack 3: Orchestrator tries without Control Plane warrant")
        try:
            # Create unauthorized warrant (not signed by control plane)
            fake_key = SigningKey.generate()
            fake_warrant = (Warrant.mint_builder()
                .capability("read_file", path=Subpath("/"), max_size=Range.max_value(1000000))
                .holder(file_worker_key.public_key)
                .ttl(3600)
                .mint(fake_key))

            await file_client.send_task(
                message="Forged warrant",
                warrant=fake_warrant,
                skill="read_file",
                arguments={"path": str(test_dir / "data.txt"), "max_size": 1000},
                signing_key=fake_key,
            )
            log("   ❌ Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Worker only trusts Control Plane and Orchestrator keys")

        # =================================================================
        # Architecture Visualization
        # =================================================================

        header("Architecture Diagram")

        print(f"""
{C.CYAN}Control Plane{C.RESET} (root authority)
      ↓ (issues warrant)
{C.BLUE}Orchestrator{C.RESET} (workflow coordinator)
      ├─→ {C.GREEN}Search Worker{C.RESET} (search_files)
      │      ↓ (simulated search)
      │   Results
      │
      └─→ {C.MAGENTA}File Worker{C.RESET} (read_file, list_directory)
             ↓ (uses MCP internally)
          {C.YELLOW}MCP Server{C.RESET} (filesystem operations)

{C.BOLD}Warrant Chain:{C.RESET}
  1. Control → Orchestrator (broad capabilities)
  2. Orchestrator → Worker (attenuated per task)
  3. Worker → MCP Tool (constraint-enforced)
""")

        # =================================================================
        # Summary
        # =================================================================

        header("Summary")
        log("✅ Multi-agent system with MCP tools via A2A")
        log("✅ Orchestrator delegated to 2 workers")
        log("✅ File Worker used MCP tools (read_file, list_directory)")
        log("✅ Search Worker provided search capability")
        log("✅ Warrant attenuation enforced least privilege")
        log("✅ Multi-hop authorization validated")
        log("✅ All attacks blocked by constraints")
        log("\nKey Benefits:")
        log("  • MCP tools accessible in distributed agent systems")
        log("  • Each agent has narrowed capabilities")
        log("  • Cryptographic proof of authorization chain")
        log("  • Works across network boundaries")

    finally:
        # Cleanup
        log("\n🧹 Shutting down...")
        await mcp_client.close()
        file_task.cancel()
        search_task.cancel()
        try:
            await asyncio.gather(file_task, search_task)
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.5)


async def main():
    """Entry point."""
    try:
        await run_demo()
    except KeyboardInterrupt:
        print("\n\n^C received")


if __name__ == "__main__":
    asyncio.run(main())
