#!/usr/bin/env python3
"""
Tenuo A2A Demo: Research Pipeline

Demonstrates multi-agent delegation with warrant-based authorization.

Architecture:
    User → Orchestrator → Paper Search Agent → Summarizer Agent

Each delegation attenuates the warrant. Attacks are blocked by constraints.

Run:
    # Default: run both normal and attack scenarios
    python a2a_demo.py

    # Non-interactive (for CI/testing)
    python a2a_demo.py --non-interactive

    # Just normal flow
    python a2a_demo.py run

    # Just attack simulation
    python a2a_demo.py attack

Requires:
    uv pip install tenuo[a2a]
    # This installs: tenuo, starlette, httpx, uvicorn
"""

from __future__ import annotations

import argparse
import asyncio
import io
import sys
import time
from typing import Any, Dict

# =============================================================================
# Check Dependencies
# =============================================================================

try:
    from tenuo_core import SigningKey, Warrant
    from tenuo.constraints import Subpath, UrlSafe
    from tenuo.a2a import A2AServer, A2AClient
    import uvicorn
    import httpx  # noqa: F401 - imported to verify availability
except ImportError as e:
    print(f"Error: Missing dependency - {e}")
    print("\nInstall with: uv pip install tenuo[a2a] uvicorn")
    sys.exit(1)


# =============================================================================
# Demo Colors
# =============================================================================


class C:
    """ANSI colors for output."""

    GRAY = "\033[90m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def header(text: str):
    print(f"\n{C.BOLD}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD}  {text}{C.RESET}")
    print(f"{C.BOLD}{'=' * 70}{C.RESET}\n")

# Global delay for demo pacing
DELAY_SECONDS = 0.0


def step(num: int, text: str):
    if DELAY_SECONDS > 0 and num > 0:
        time.sleep(DELAY_SECONDS)
    print(f"{C.CYAN}[Step {num}]{C.RESET} {text}")


def success(text: str):
    print(f"{C.GREEN}  ✓ {text}{C.RESET}")


def blocked(text: str):
    print(f"{C.RED}  ✗ BLOCKED: {text}{C.RESET}")


def info(text: str):
    print(f"{C.GRAY}    {text}{C.RESET}")


def warrant_info(name: str, tools: list[str], constraints: Dict[str, Any]):
    print(f"\n{C.YELLOW}  Warrant: {name}{C.RESET}")
    print(f"    Tools: {', '.join(tools)}")
    for param, constraint in constraints.items():
        print(f"    {param}: {constraint}")


# =============================================================================
# Agent Servers
# =============================================================================


def create_paper_search_server(
    signing_key: SigningKey,
    trusted_issuers: list,
    port: int = 8001,
    real_skills: bool = False,
) -> A2AServer:
    """Create the Paper Search agent server."""

    server = A2AServer(
        name="Paper Search Agent",
        url=f"http://localhost:{port}",
        public_key=signing_key.public_key,
        trusted_issuers=trusted_issuers,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),  # Suppress audit output for demo
    )

    @server.skill("fetch_url", constraints={"url": UrlSafe(allow_domains=["arxiv.org", "scholar.google.com"])})
    async def fetch_url(url: str) -> Dict[str, Any]:
        """Fetch content from a URL."""
        if real_skills:
            import httpx

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(url)
                    return {
                        "status": "success",
                        "url": url,
                        "status_code": response.status_code,
                        "content": response.text[:500] + "..." if len(response.text) > 500 else response.text,
                    }
            except Exception as e:
                return {"status": "error", "url": url, "error": str(e)}
        else:
            return {
                "status": "success",
                "url": url,
                "content": f"[Simulated paper content from {url}]",
            }

    return server


def create_summarizer_server(
    signing_key: SigningKey,
    trusted_issuers: list,
    port: int = 8002,
    real_skills: bool = False,
) -> A2AServer:
    """Create the Summarizer agent server."""

    server = A2AServer(
        name="Summarizer Agent",
        url=f"http://localhost:{port}",
        public_key=signing_key.public_key,
        trusted_issuers=trusted_issuers,
        require_warrant=True,
        require_audience=False,
        require_pop=False,
        check_replay=False,
        audit_log=io.StringIO(),  # Suppress audit output for demo
    )

    @server.skill("read_file", constraints={"path": Subpath("/tmp/papers")})
    async def read_file(path: str) -> Dict[str, Any]:
        """Read a file from allowed paths."""
        if real_skills:
            import os

            try:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        content = f.read()
                    return {
                        "status": "success",
                        "path": path,
                        "content": content[:500] + "..." if len(content) > 500 else content,
                    }
                else:
                    return {"status": "error", "path": path, "error": "File not found"}
            except Exception as e:
                return {"status": "error", "path": path, "error": str(e)}
        else:
            return {
                "status": "success",
                "path": path,
                "content": f"[Simulated file content from {path}]",
            }

    return server


# =============================================================================
# Server Runner
# =============================================================================


class ServerRunner:
    """Manages running A2A servers in the background."""

    def __init__(self):
        self.servers: Dict[str, asyncio.Task] = {}
        self._shutdown_events: Dict[str, asyncio.Event] = {}

    async def start(self, name: str, server: A2AServer, port: int):
        """Start a server in the background."""
        shutdown_event = asyncio.Event()
        self._shutdown_events[name] = shutdown_event

        config = uvicorn.Config(
            server.app,
            host="127.0.0.1",
            port=port,
            log_level="critical",  # Suppress all but critical errors
            lifespan="off",  # Disable lifespan to avoid spurious errors
        )
        uv_server = uvicorn.Server(config)

        async def run_server():
            await uv_server.serve()

        task = asyncio.create_task(run_server())
        self.servers[name] = task

        # Wait for server to be ready
        await asyncio.sleep(0.5)
        info(f"Started {name} on port {port}")

    async def stop_all(self):
        """Stop all running servers."""
        for name, task in self.servers.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.servers.clear()
        self._shutdown_events.clear()
        # Allow ports to be released before next demo run
        await asyncio.sleep(0.5)


# =============================================================================
# Demo Scenarios
# =============================================================================


async def run_demo(inject_attack: bool = False, port_offset: int = 0, real_skills: bool = False):
    """Run the full demo scenario."""
    port1 = 8001 + port_offset
    port2 = 8002 + port_offset

    if inject_attack:
        header("DEMO: Research Pipeline (WITH ATTACK)")
        print("  This run simulates a prompt injection attack.")
        print("  Watch how Tenuo warrants block the malicious actions.\n")
    else:
        header("DEMO: Research Pipeline (Normal Flow)")
        print("  This run shows normal operation without attacks.\n")

    # -------------------------------------------------------------------------
    # Setup: Generate keys for all parties
    # -------------------------------------------------------------------------

    step(0, "Generating cryptographic keys for all parties")

    # Control plane (root authority)
    control_key = SigningKey.generate()

    # Agent keys
    orchestrator_key = SigningKey.generate()
    paper_search_key = SigningKey.generate()
    summarizer_key = SigningKey.generate()

    success("Keys generated for: Control Plane, Orchestrator, Paper Search, Summarizer")

    # -------------------------------------------------------------------------
    # Setup: Start A2A servers
    # -------------------------------------------------------------------------

    step(1, "Starting A2A agent servers")

    runner = ServerRunner()

    try:
        # Paper Search trusts: Control Plane and Orchestrator
        paper_search_server = create_paper_search_server(
            signing_key=paper_search_key,
            trusted_issuers=[control_key.public_key, orchestrator_key.public_key],
            port=port1,
            real_skills=real_skills,
        )
        await runner.start("Paper Search", paper_search_server, port1)

        # Summarizer trusts: Control Plane and Orchestrator
        summarizer_server = create_summarizer_server(
            signing_key=summarizer_key,
            trusted_issuers=[control_key.public_key, orchestrator_key.public_key],
            port=port2,
            real_skills=real_skills,
        )
        await runner.start("Summarizer", summarizer_server, port2)

        success(f"A2A servers running on ports {port1} and {port2}")

        # Ensure sample paper exists for real_skills mode
        if real_skills:
            import os

            os.makedirs("/tmp/papers", exist_ok=True)
            paper_path = "/tmp/papers/toctou.pdf"
            if not os.path.exists(paper_path):
                with open(paper_path, "w") as f:
                    f.write(
                        "Time-Of-Check to Time-Of-Use Vulnerabilities in LLM Tool Execution\n"
                        "===================================================================\n\n"
                        "Abstract\n--------\n"
                        "This paper presents a systematic analysis of TOCTOU vulnerabilities...\n"
                        "(Sample content created by Tenuo Demo)\n"
                    )
                print(f"  {C.YELLOW}Created sample paper at {paper_path}{C.RESET}")

        # ---------------------------------------------------------------------
        # Step 2: Create root warrant for Orchestrator
        # ---------------------------------------------------------------------

        step(2, "Control Plane issues root warrant to Orchestrator")

        root_warrant = Warrant.issue(
            keypair=control_key,
            holder=orchestrator_key.public_key,
            capabilities={
                "fetch_url": {"url": UrlSafe(allow_domains=["arxiv.org", "scholar.google.com"])},
                "read_file": {"path": Subpath("/tmp/papers")},
            },
            ttl_seconds=3600,
        )

        warrant_info(
            "Root (Orchestrator)",
            ["fetch_url", "read_file"],
            {
                "url": "UrlSafe(allow_domains=['arxiv.org', 'scholar.google.com'])",
                "path": "Subpath('/tmp/papers')",
            },
        )
        success(f"Root warrant issued (depth={root_warrant.depth})")

        # ---------------------------------------------------------------------
        # Step 3: Orchestrator attenuates for Paper Search
        # ---------------------------------------------------------------------

        step(3, "Orchestrator attenuates warrant for Paper Search agent")

        search_warrant = root_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=paper_search_key.public_key,
            capabilities={
                "fetch_url": {"url": UrlSafe(allow_domains=["arxiv.org", "scholar.google.com"])},
            },
            ttl_seconds=1800,
        )

        warrant_info(
            "Attenuated (Paper Search)",
            ["fetch_url"],
            {"url": "UrlSafe(allow_domains=['arxiv.org', 'scholar.google.com'])"},
        )
        info(f"Chain depth: {search_warrant.depth}")
        success("Attenuated warrant created - Paper Search can ONLY fetch from arxiv.org/scholar")

        # ---------------------------------------------------------------------
        # Step 4: Call Paper Search via A2A
        # ---------------------------------------------------------------------

        step(4, "Calling Paper Search agent via A2A")

        # Choose URL based on attack mode
        if inject_attack:
            # Simulated prompt injection: LLM tries to access cloud metadata
            target_url = "http://169.254.169.254/latest/meta-data/iam/credentials"
            info(f"[ATTACK] LLM wants to fetch: {target_url}")
        else:
            target_url = "https://arxiv.org/abs/2310.17419"  # Real paper: "Hype, Sustainability, and the Price of the Bigger-is-Better Paradigm"
            info(f"LLM wants to fetch: {target_url}")

        async with A2AClient(f"http://localhost:{port1}") as client:
            try:
                result = await client.send_task(
                    message="Find papers about TOCTOU vulnerabilities",
                    warrant=search_warrant,
                    skill="fetch_url",
                    arguments={"url": target_url},
                )
                success(f"Paper Search completed: {result.output}")
            except Exception as e:
                error_msg = str(e)
                blocked(error_msg)

                if inject_attack:
                    print(f"\n{C.GREEN}  ╔══════════════════════════════════════════════════════════════╗{C.RESET}")
                    print(f"{C.GREEN}  ║  SSRF ATTACK BLOCKED BY WARRANT CONSTRAINT                   ║{C.RESET}")
                    print(f"{C.GREEN}  ╚══════════════════════════════════════════════════════════════╝{C.RESET}")

                    print(f"\n{C.YELLOW}  What happened:{C.RESET}")
                    print("    1. Attacker injected prompt to fetch cloud credentials")
                    print("    2. LLM tried to call fetch_url('http://169.254.169.254/...')")
                    print("    3. Warrant only allows arxiv.org and scholar.google.com")
                    print("    4. Request BLOCKED at the A2A server before any network call")

        print()

        # ---------------------------------------------------------------------
        # Step 5: Orchestrator attenuates for Summarizer
        # ---------------------------------------------------------------------

        step(5, "Orchestrator attenuates warrant for Summarizer agent")

        summarize_warrant = root_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=summarizer_key.public_key,
            capabilities={
                "read_file": {"path": Subpath("/tmp/papers")},
            },
            ttl_seconds=1800,
        )

        warrant_info(
            "Attenuated (Summarizer)",
            ["read_file"],
            {"path": "Subpath('/tmp/papers')"},
        )
        info(f"Chain depth: {summarize_warrant.depth}")
        success("Attenuated warrant created - Summarizer can ONLY read /tmp/papers/*")

        # ---------------------------------------------------------------------
        # Step 6: Call Summarizer via A2A
        # ---------------------------------------------------------------------

        step(6, "Calling Summarizer agent via A2A")

        # Choose path based on attack mode
        if inject_attack:
            # Simulated prompt injection: LLM tries to read system files
            target_path = "/etc/passwd"
            info(f"[ATTACK] LLM wants to read: {target_path}")
        else:
            target_path = "/tmp/papers/toctou.pdf"
            info(f"LLM wants to read: {target_path}")

        async with A2AClient(f"http://localhost:{port2}") as client:
            try:
                result = await client.send_task(
                    message="Summarize the downloaded paper",
                    warrant=summarize_warrant,
                    skill="read_file",
                    arguments={"path": target_path},
                )
                success(f"Summarizer completed: {result.output}")
            except Exception as e:
                error_msg = str(e)
                blocked(error_msg)

                if inject_attack:
                    print(f"\n{C.GREEN}  ╔══════════════════════════════════════════════════════════════╗{C.RESET}")
                    print(f"{C.GREEN}  ║  PATH TRAVERSAL ATTACK BLOCKED BY WARRANT CONSTRAINT         ║{C.RESET}")
                    print(f"{C.GREEN}  ╚══════════════════════════════════════════════════════════════╝{C.RESET}")

                    print(f"\n{C.YELLOW}  What happened:{C.RESET}")
                    print("    1. Attacker injected prompt to read /etc/passwd")
                    print("    2. Warrant only allows reading from /tmp/papers")
                    print("    3. Subpath constraint normalized and checked containment")
                    print("    4. Request BLOCKED at the A2A server before any file access")

        print()

        # ---------------------------------------------------------------------
        # Step 7: Demonstrate Escalation Prevention
        # ---------------------------------------------------------------------

        step(7, "Demonstrating Privilege Escalation Prevention")

        print(f"\n  {C.YELLOW}Scenario:{C.RESET} Paper Search tries to delegate 'read_file' (which it doesn't have)")

        try:
            # Paper Search only has fetch_url, not read_file
            # This attenuation should fail
            _escalated = search_warrant.attenuate(
                signing_key=paper_search_key,
                holder=SigningKey.generate().public_key,  # Some other agent
                capabilities={
                    "read_file": {"path": Subpath("/")},  # Full filesystem access!
                },
                ttl_seconds=300,
            )
            print(f"  {C.RED}ERROR: Escalation should have been prevented!{C.RESET}")
        except Exception as e:
            blocked(f"Escalation prevented: {e}")
            print(f"\n{C.GREEN}  ╔══════════════════════════════════════════════════════════════╗{C.RESET}")
            print(f"{C.GREEN}  ║  PRIVILEGE ESCALATION BLOCKED - MONOTONICITY ENFORCED        ║{C.RESET}")
            print(f"{C.GREEN}  ╚══════════════════════════════════════════════════════════════╝{C.RESET}")

        # ---------------------------------------------------------------------
        # Summary
        # ---------------------------------------------------------------------

        header("DEMO COMPLETE")

        print(f"  {C.BOLD}Security Properties Demonstrated:{C.RESET}")
        print()
        print(f"  {C.CYAN}1. Cryptographic Authority{C.RESET}")
        print("     Warrants are Ed25519 signed - can't be forged")
        print()
        print(f"  {C.CYAN}2. Monotonic Attenuation{C.RESET}")
        print("     Child warrants can only REDUCE capabilities")
        print()
        print(f"  {C.CYAN}3. Constraint Enforcement{C.RESET}")
        print("     Subpath and UrlSafe validate at the A2A server")
        print()
        print(f"  {C.CYAN}4. Chain Validation{C.RESET}")
        print("     Each server validates the full delegation chain")

        if inject_attack:
            print(f"\n  {C.GREEN}Both attacks were blocked:{C.RESET}")
            print("    • SSRF to cloud metadata → blocked by UrlSafe")
            print("    • Path traversal to /etc/passwd → blocked by Subpath")
            print(f"\n{C.YELLOW}  ╔══════════════════════════════════════════════════════════════╗{C.RESET}")
            print(f"  {C.YELLOW}║  The LLM was 'compromised'. The system was protected.       ║{C.RESET}")
            print(f"  {C.YELLOW}╚══════════════════════════════════════════════════════════════╝{C.RESET}")

        print()

    finally:
        # Cleanup: stop all servers
        await runner.stop_all()
        info("Servers stopped")


async def run_comparison(interactive: bool = True):
    """Run both normal and attack scenarios for comparison."""

    header("TENUO A2A DEMO")
    print("  Architecture:")
    print("    User → Orchestrator → Paper Search")
    print("                       → Summarizer")
    print()
    print("  Scenarios:")
    print("    1. Normal operation")
    print("    2. Simulated attacks (SSRF + path traversal)")
    print()

    if interactive:
        input("  Press Enter to start...\n")
    else:
        print("  [non-interactive mode]\n")

    # Normal run
    await run_demo(inject_attack=False, port_offset=0)

    if interactive:
        input("\n  Press Enter to run with attack simulation...\n")
    else:
        print("\n  --- Running attack simulation ---\n")

    # Attack run (use different ports to avoid conflicts)
    await run_demo(inject_attack=True, port_offset=10)


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Tenuo A2A Demo - Multi-agent delegation with warrant-based authorization"
    )
    parser.add_argument(
        "command",
        choices=["run", "attack", "compare"],
        nargs="?",
        default="compare",
        help="run=normal, attack=with injection, compare=both (default)",
    )
    parser.add_argument(
        "--non-interactive",
        "-n",
        action="store_true",
        help="Skip interactive prompts (for CI/testing)",
    )
    parser.add_argument(
        "--real-skills",
        "-r",
        action="store_true",
        help="Make skills perform real operations (fetch URLs, read files)",
    )
    parser.add_argument(
        "--slow",
        "-s",
        action="store_true",
        help="Run demo slower for presentations (1.5s delay between steps)",
    )
    args = parser.parse_args()

    # Set delay if requested
    if args.slow:
        global DELAY_SECONDS
        DELAY_SECONDS = 1.5

    if args.command == "run":
        asyncio.run(run_demo(inject_attack=False, real_skills=args.real_skills))
    elif args.command == "attack":
        asyncio.run(run_demo(inject_attack=True, real_skills=args.real_skills))
    else:
        asyncio.run(run_comparison(interactive=not args.non_interactive))


if __name__ == "__main__":
    main()
