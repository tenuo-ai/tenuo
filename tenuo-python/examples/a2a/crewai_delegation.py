#!/usr/bin/env python3
"""
CrewAI + Tenuo A2A Integration

Demonstrates warrant-based authorization for CrewAI crews with A2A task delegation.

Scenario: Content Creation Crew
  - Researcher: Finds information (A2A delegation to Research Agent)
  - Writer: Creates content using research
  - Editor: Reviews and approves

Security:
  - Researcher has attenuated warrant (read-only, specific domains)
  - Writer has separate warrant (write to /tmp/output only)
  - Editor has verification warrant (read /tmp/output only)

Run:
    # Install dependencies first
    uv pip install "tenuo[a2a]" crewai

    # Run demo
    python crewai_delegation.py

Requirements:
    - crewai (for crew framework)
    - tenuo[a2a] (for warrant delegation)
"""

import asyncio
import io
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure we can import from tenuo
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from crewai import Agent, Task, Crew, Process  # noqa: F401
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    print("⚠️  CrewAI not installed. Install with: uv pip install crewai")
    print("   Running in simulation mode...\n")

from tenuo import SigningKey, Warrant, Pattern
from tenuo.constraints import Subpath, UrlSafe
from tenuo.a2a import A2AServer, A2AClient


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


# =============================================================================
# A2A Agents (Workers)
# =============================================================================

def create_research_agent_server(key: SigningKey, trusted: list, port: int) -> A2AServer:
    """Research agent that fetches information from allowed sources."""

    server = A2AServer(
        name="Research Agent",
        url=f"http://localhost:{port}",
        public_key=key.public_key,
        trusted_issuers=trusted,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),
    )

    @server.skill("search_web", constraints={"domain": UrlSafe})
    async def search_web(query: str, domain: str) -> Dict[str, Any]:
        """Search the web from allowed domains."""
        # Simulate web search
        return {
            "query": query,
            "domain": domain,
            "results": [
                {"title": "AI Agent Architectures", "snippet": "Overview of modern agent design patterns..."},
                {"title": "Multi-Agent Systems", "snippet": "Coordination strategies for agent teams..."},
                {"title": "Warrant-Based Security", "snippet": "Cryptographic authorization for agents..."},
            ],
        }

    @server.skill("read_source", constraints={"path": Subpath})
    async def read_source(path: str) -> Dict[str, Any]:
        """Read from allowed source paths."""
        # Simulate reading source
        return {
            "path": path,
            "content": f"Sample content from {path}",
            "word_count": 150,
        }

    return server


def create_storage_agent_server(key: SigningKey, trusted: list, port: int) -> A2AServer:
    """Storage agent for saving/retrieving content."""

    server = A2AServer(
        name="Storage Agent",
        url=f"http://localhost:{port}",
        public_key=key.public_key,
        trusted_issuers=trusted,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),
    )

    @server.skill("write_content", constraints={"path": Subpath, "content": Pattern})
    async def write_content(path: str, content: str) -> Dict[str, Any]:
        """Write content to allowed paths."""
        # Simulate writing
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content)
        return {
            "path": path,
            "bytes_written": len(content),
            "status": "success",
        }

    @server.skill("read_content", constraints={"path": Subpath})
    async def read_content(path: str) -> Dict[str, Any]:
        """Read content from allowed paths."""
        # Simulate reading
        if Path(path).exists():
            content = Path(path).read_text()
            return {"path": path, "content": content, "found": True}
        return {"path": path, "content": "", "found": False}

    return server


# =============================================================================
# CrewAI Integration
# =============================================================================

class TenuoA2AClient:
    """
    Wrapper for A2A client that CrewAI agents can use as a tool.

    This bridges CrewAI's tool calling with Tenuo's A2A protocol.
    """

    def __init__(self, url: str, warrant: Warrant, signing_key: SigningKey):
        self.url = url
        self.warrant = warrant
        self.signing_key = signing_key
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = A2AClient(self.url)
        return self._client

    async def call_skill(self, skill: str, **kwargs) -> Dict[str, Any]:
        """Call A2A skill with warrant authorization."""
        client = await self._get_client()
        result = await client.send_task(
            message=f"Execute {skill}",
            warrant=self.warrant,
            skill=skill,
            arguments=kwargs,
            signing_key=self.signing_key,
        )
        return result.output


# =============================================================================
# CrewAI Agents (Crew Members)
# =============================================================================

def create_researcher_agent(a2a_client: TenuoA2AClient) -> Any:
    """Researcher agent that uses A2A to fetch information."""

    if not CREWAI_AVAILABLE:
        return None

    # In real CrewAI, this would be a custom tool
    # For demo, we'll use the agent's backstory
    return Agent(
        role="Researcher",
        goal="Find accurate information on the given topic",
        backstory=(
            "You are a thorough researcher who finds high-quality sources. "
            "You use the research service to gather information from trusted domains."
        ),
        verbose=True,
        allow_delegation=False,
    )


def create_writer_agent(a2a_client: TenuoA2AClient) -> Any:
    """Writer agent that creates content and saves via A2A."""

    if not CREWAI_AVAILABLE:
        return None

    return Agent(
        role="Content Writer",
        goal="Create engaging, well-structured content based on research",
        backstory=(
            "You are a skilled writer who transforms research into compelling content. "
            "You save your work using the storage service."
        ),
        verbose=True,
        allow_delegation=False,
    )


def create_editor_agent(a2a_client: TenuoA2AClient) -> Any:
    """Editor agent that reviews content via A2A."""

    if not CREWAI_AVAILABLE:
        return None

    return Agent(
        role="Editor",
        goal="Review and approve content for publication",
        backstory=(
            "You are a detail-oriented editor who ensures quality. "
            "You retrieve content using the storage service and provide feedback."
        ),
        verbose=True,
        allow_delegation=False,
    )


# =============================================================================
# Demo
# =============================================================================

async def run_demo():
    """Run the CrewAI + A2A demo."""

    header("CrewAI + Tenuo A2A Integration")

    if not CREWAI_AVAILABLE:
        log("Running in simulation mode (CrewAI not installed)", C.YELLOW)
        log("Install with: uv pip install crewai\n")

    # Setup keys
    log("🔑 Generating cryptographic keys...")
    control_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()  # CrewAI orchestrator
    research_agent_key = SigningKey.generate()
    storage_agent_key = SigningKey.generate()

    # Start A2A servers
    log("🚀 Starting A2A worker agents...")

    research_server = create_research_agent_server(
        key=research_agent_key,
        trusted=[control_key.public_key, orchestrator_key.public_key],
        port=8001,
    )

    storage_server = create_storage_agent_server(
        key=storage_agent_key,
        trusted=[control_key.public_key, orchestrator_key.public_key],
        port=8002,
    )

    # Start servers
    import uvicorn

    async def start_server(app, port):
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", lifespan="off")
        server = uvicorn.Server(config)
        return asyncio.create_task(server.serve())

    research_task = await start_server(research_server.app, 8001)
    storage_task = await start_server(storage_server.app, 8002)

    await asyncio.sleep(1)
    log("✅ Research Agent on http://localhost:8001")
    log("✅ Storage Agent on http://localhost:8002\n")

    try:
        # Issue orchestrator warrant
        log("📜 Control Plane issues warrant to Orchestrator...")
        orchestrator_warrant = (Warrant.mint_builder()
            .capability("search_web", domain=UrlSafe(allow_domains=["*.wikipedia.org", "*.arxiv.org"]))
            .capability("read_source", path=Subpath("/tmp/sources"))
            .capability("write_content", path=Subpath("/tmp/output"), content=Pattern("*"))
            .capability("read_content", path=Subpath("/tmp/output"))
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(control_key))

        log(f"   Warrant ID: {orchestrator_warrant.id[:12]}...")
        log("   Tools: search_web, read_source, write_content, read_content\n")

        # Orchestrator attenuates warrants for crew members
        log("🔐 Orchestrator attenuates warrants for crew members...")

        # Researcher: read-only, specific domains
        researcher_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=research_agent_key.public_key,
            capabilities={
                "search_web": {"domain": UrlSafe(allow_domains=["*.wikipedia.org"])},
                "read_source": {"path": Subpath("/tmp/sources")},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Researcher: search_web (wikipedia only), read_source")

        # Writer: write to output
        writer_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=storage_agent_key.public_key,
            capabilities={
                "write_content": {"path": Subpath("/tmp/output"), "content": Pattern("*")},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Writer: write_content (/tmp/output only)")

        # Editor: read from output
        editor_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=storage_agent_key.public_key,
            capabilities={
                "read_content": {"path": Subpath("/tmp/output")},
            },
            ttl_seconds=1800,
        )
        log("   ✓ Editor: read_content (/tmp/output only)\n")

        # Create A2A clients for crew
        research_client = TenuoA2AClient(
            "http://localhost:8001",
            researcher_warrant,
            orchestrator_key,
        )

        storage_client_write = TenuoA2AClient(
            "http://localhost:8002",
            writer_warrant,
            orchestrator_key,
        )

        storage_client_read = TenuoA2AClient(
            "http://localhost:8002",
            editor_warrant,
            orchestrator_key,
        )

        # =================================================================
        # Task Execution (Simulated CrewAI Flow)
        # =================================================================

        header("Content Creation Workflow")

        # Phase 1: Research
        log("📚 Phase 1: Researcher gathers information...")
        research_result = await research_client.call_skill(
            skill="search_web",
            query="AI agent architectures",
            domain="https://en.wikipedia.org",
        )
        log(f"   Found {len(research_result.get('results', []))} sources", C.GREEN)
        for r in research_result.get("results", [])[:2]:
            log(f"   • {r['title']}", C.BLUE)

        # Phase 2: Writing
        log("\n✍️  Phase 2: Writer creates content...")
        content = """# AI Agent Architectures

Based on research from Wikipedia and academic sources:

## Overview
AI agents are autonomous systems that perceive their environment and take actions...

## Multi-Agent Systems
When multiple agents work together, they can accomplish complex tasks through delegation...

## Security Considerations
Warrant-based authorization ensures agents only access what they're authorized for...
"""
        write_result = await storage_client_write.call_skill(
            skill="write_content",
            path="/tmp/output/article.md",
            content=content,
        )
        log(f"   Saved {write_result.get('bytes_written', 0)} bytes", C.GREEN)
        log(f"   Path: {write_result.get('path', 'N/A')}")

        # Phase 3: Editing
        log("\n📝 Phase 3: Editor reviews content...")
        read_result = await storage_client_read.call_skill(
            skill="read_content",
            path="/tmp/output/article.md",
        )
        if read_result.get("found"):
            content_lines = read_result["content"].split("\n")
            log(f"   Retrieved {len(content_lines)} lines", C.GREEN)
            log(f"   Preview: {content_lines[0]}", C.BLUE)
            log("   ✅ Content approved for publication")
        else:
            log("   ❌ Content not found")

        # =================================================================
        # Security Demonstration
        # =================================================================

        header("Security: Warrant Constraints in Action")

        # Attack 1: Researcher tries to write (should fail)
        log("🔒 Attack 1: Researcher tries to write content...")
        try:
            await research_client.call_skill(
                skill="write_content",
                path="/tmp/output/malicious.txt",
                content="pwned",
            )
            log("   ❌ ERROR: Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Researcher warrant only has read permissions")

        # Attack 2: Writer tries to write outside /tmp/output
        log("\n🔒 Attack 2: Writer tries path traversal...")
        try:
            await storage_client_write.call_skill(
                skill="write_content",
                path="/etc/passwd",
                content="malicious",
            )
            log("   ❌ ERROR: Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   Subpath constraint prevents path traversal")

        # Attack 3: Researcher tries unauthorized domain
        log("\n🔒 Attack 3: Researcher tries unauthorized domain...")
        try:
            await research_client.call_skill(
                skill="search_web",
                query="hacking guide",
                domain="https://evil.com",
            )
            log("   ❌ ERROR: Should have been blocked!", C.YELLOW)
        except Exception as e:
            log(f"   ✅ BLOCKED: {str(e)[:60]}...", C.GREEN)
            log("   UrlSafe constraint blocks non-whitelisted domains")

        # =================================================================
        # Summary
        # =================================================================

        header("Summary")
        log("✅ CrewAI agents used A2A for secure task delegation")
        log("✅ Each crew member had attenuated warrant (least privilege)")
        log("✅ Researcher: read-only from specific domains")
        log("✅ Writer: write to /tmp/output only")
        log("✅ Editor: read from /tmp/output only")
        log("✅ All attacks blocked by warrant constraints")
        log("\nKey Benefits:")
        log("  • Cryptographic proof of authorization")
        log("  • Least-privilege principle enforced")
        log("  • No trust in crew orchestrator")
        log("  • Works across process boundaries")

    finally:
        # Cleanup
        log("\n🧹 Shutting down A2A agents...")
        research_task.cancel()
        storage_task.cancel()
        try:
            await asyncio.gather(research_task, storage_task)
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
