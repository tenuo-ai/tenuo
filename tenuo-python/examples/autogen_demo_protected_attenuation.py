#!/usr/bin/env python3
"""
AutoGen AgentChat demo: research pipeline (PROTECTED - attenuation).

Architecture:
    User -> Orchestrator -> Paper Search Agent -> Summarizer Agent

This mirrors the flow in examples/a2a_demo.py and adds Tenuo protections.
In this version, URL access is restricted by an allowlist, file reads are
restricted to a safe subpath, and delegation is attenuated per-agent.

Run:
    # Default: run both normal and attack scenarios
    python autogen_demo_protected_attenuation.py

    # Just normal flow
    python autogen_demo_protected_attenuation.py run

    # Just attack simulation
    python autogen_demo_protected_attenuation.py attack

Requires:
    pip install "tenuo[autogen]"
    # Set OPENAI_API_KEY
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from typing import Any

try:
    from dotenv import load_dotenv  # type: ignore[reportMissingImports]
except Exception as e:  # pragma: no cover - import guard for optional deps
    print(f"Error: Missing dependency - {e}")
    print('Install with: pip install "python-dotenv"')
    raise

try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient
except Exception as e:  # pragma: no cover - import guard for optional deps
    print(f"Error: Missing dependency - {e}")
    print('Install with: pip install "tenuo[autogen]"')
    raise

from tenuo import SigningKey, Subpath, UrlSafe, Warrant
from tenuo.autogen import guard_tool
from tenuo.constraints import Constraints


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


def header(text: str) -> None:
    print(f"\n{C.BOLD}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD}  {text}{C.RESET}")
    print(f"{C.BOLD}{'=' * 70}{C.RESET}\n")


DELAY_SECONDS = 0.0


def step(num: int, text: str) -> None:
    if DELAY_SECONDS > 0 and num > 0:
        time.sleep(DELAY_SECONDS)
    print(f"{C.CYAN}[Step {num}]{C.RESET} {text}")


def success(text: str) -> None:
    print(f"{C.GREEN}  ✓ {text}{C.RESET}")


def warn(text: str) -> None:
    print(f"{C.YELLOW}  ! {text}{C.RESET}")


def info(text: str) -> None:
    print(f"{C.GRAY}    {text}{C.RESET}")


def blocked(text: str) -> None:
    print(f"{C.RED}  ✗ BLOCKED: {text}{C.RESET}")


SAMPLE_PAPER_CONTENT = (
    "Time-Of-Check to Time-Of-Use Vulnerabilities in LLM Tool Execution\n"
    "===================================================================\n\n"
    "Abstract\n--------\n"
    "This paper presents a systematic analysis of TOCTOU vulnerabilities in\n"
    "tool-using LLM systems, including common failure modes, attack vectors,\n"
    "and mitigation strategies.\n"
    "(Sample content created by AutoGen demo)\n"
)


def _result_to_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    messages = getattr(result, "messages", None)
    if isinstance(messages, list) and messages:
        last = messages[-1]
        content = getattr(last, "content", None)
        if content is not None:
            return str(content)
    return str(result)


def _ensure_sample_paper(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(SAMPLE_PAPER_CONTENT)


# =============================================================================
# Demo Scenario
# =============================================================================


async def run_demo(
    inject_attack: bool = False,
    model: str = "gpt-4o",
    real_tools: bool = False,
) -> None:
    if inject_attack:
        header("DEMO: AutoGen Research Pipeline (PROTECTED, WITH ATTACK)")
        print(
            "  This run simulates prompt injection with URL allowlist, "
            "subpath, and attenuation protections.\n"
        )
    else:
        header("DEMO: AutoGen Research Pipeline (Protected Flow)")
        print(
            "  This run shows URL allowlist, subpath, and attenuation enforcement.\n"
        )

    # ---------------------------------------------------------------------
    # Setup: Tools (URL allowlist enforced by Tenuo)
    # ---------------------------------------------------------------------
    sample_path = "/tmp/papers/toctou.txt"
    if real_tools:
        _ensure_sample_paper(sample_path)
        warn("Real tools enabled: URL fetching and file reads are live.")
    else:
        info("Using simulated tools (no real network or filesystem access).")

    def fetch_url(url: str) -> dict[str, Any]:
        """Fetch content from a URL (simulated by default)."""
        if real_tools:
            try:
                import httpx

                response = httpx.get(url, timeout=10.0)
                content = response.text
                if len(content) > 500:
                    content = content[:500] + "..."
                return {
                    "status": "success",
                    "url": url,
                    "status_code": response.status_code,
                    "content": content,
                }
            except Exception as e:
                return {"status": "error", "url": url, "error": str(e)}
        return {
            "status": "success",
            "url": url,
            "content": f"[Simulated paper content from {url}]",
        }

    def read_file(path: str) -> dict[str, Any]:
        """Read a file from disk (simulated by default)."""
        if real_tools:
            try:
                with open(path, "r") as f:
                    content = f.read()
                if len(content) > 500:
                    content = content[:500] + "..."
                return {"status": "success", "path": path, "content": content}
            except Exception as e:
                return {"status": "error", "path": path, "error": str(e)}
        content = (
            SAMPLE_PAPER_CONTENT
            if path == sample_path
            else f"[Simulated file content from {path}]"
        )
        return {"status": "success", "path": path, "content": content}

    # ---------------------------------------------------------------------
    # Setup: Keys and root warrant (attenuation)
    # ---------------------------------------------------------------------
    step(1, "Generating keys and root warrant")
    control_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()
    paper_search_key = SigningKey.generate()
    summarizer_key = SigningKey.generate()

    root_capabilities: dict[str, dict[str, Any]] = {}
    root_capabilities.update(
        Constraints.for_tool(
            "fetch_url",
            {
                "url": UrlSafe(
                    allow_domains=["arxiv.org", "scholar.google.com"]
                )
            },
        )
    )
    root_capabilities.update(
        Constraints.for_tool("read_file", {"path": Subpath("/tmp/papers")})
    )

    root_warrant = Warrant.mint(
        keypair=control_key,
        capabilities=root_capabilities,
        ttl_seconds=3600,
        holder=orchestrator_key.public_key,
    )
    success("Root warrant issued to Orchestrator")

    # ---------------------------------------------------------------------
    # Setup: Attenuate per-agent warrants
    # ---------------------------------------------------------------------
    step(2, "Attenuating warrant for Paper Search")
    search_warrant = root_warrant.attenuate(
        capabilities=Constraints.for_tool(
            "fetch_url",
            {
                "url": UrlSafe(
                    allow_domains=["arxiv.org", "scholar.google.com"]
                )
            },
        ),
        signing_key=orchestrator_key,
        holder=paper_search_key.public_key,
    )
    guarded_fetch_url = guard_tool(
        fetch_url, search_warrant.bind(paper_search_key), tool_name="fetch_url"
    )
    success("Paper Search can only fetch allowlisted URLs")

    step(3, "Attenuating warrant for Summarizer")
    summarize_warrant = root_warrant.attenuate(
        capabilities=Constraints.for_tool(
            "read_file", {"path": Subpath("/tmp/papers")}
        ),
        signing_key=orchestrator_key,
        holder=summarizer_key.public_key,
    )
    guarded_read_file = guard_tool(
        read_file,
        summarize_warrant.bind(summarizer_key),
        tool_name="read_file",
    )
    success("Summarizer can only read within /tmp/papers")

    # ---------------------------------------------------------------------
    # Setup: Agents
    # ---------------------------------------------------------------------
    step(4, "Creating AutoGen agents")
    load_dotenv()
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        raise RuntimeError("OPENAI_API_KEY not found in .env file")
    model_client = OpenAIChatCompletionClient(
        model=model,
        api_key=openai_api_key,
        tool_choice="required",
    )

    paper_search_agent = AssistantAgent(
        "paper_search",
        model_client,
        tools=[guarded_fetch_url],
        max_tool_iterations=1,
        system_message=(
            "You are the Paper Search agent. Always use the fetch_url tool to "
            "retrieve paper content. Return the tool result."
        ),
    )

    summarizer_agent = AssistantAgent(
        "summarizer",
        model_client,
        tools=[guarded_read_file],
        max_tool_iterations=1,
        system_message=(
            "You are the Summarizer agent. Use read_file to load the paper "
            "content, then summarize it concisely."
        ),
    )

    async def call_agent(agent: str, task: str) -> str:
        """Delegate a task to another agent and return its final response."""
        try:
            if agent == "paper_search":
                result = await paper_search_agent.run(task=task)
            elif agent == "summarizer":
                result = await summarizer_agent.run(task=task)
            else:
                return f"Unknown agent: {agent}"
            return _result_to_text(result)
        except Exception as e:
            return f"ERROR: {e}"

    orchestrator = AssistantAgent(
        "orchestrator",
        model_client,
        tools=[call_agent],
        max_tool_iterations=1,
        system_message=(
            "You are the Orchestrator. Delegate tasks to other agents using "
            "the call_agent tool. Choose the best agent for each task and "
            "do not solve tasks yourself. Available agents: "
            "paper_search (fetches URLs), summarizer (reads and summarizes files)."
        ),
    )

    success("Agents created: Orchestrator, Paper Search, Summarizer")

    # ---------------------------------------------------------------------
    # Step 2: Orchestrator delegates (model chooses agent)
    # ---------------------------------------------------------------------
    step(5, "Orchestrator delegates task to the best agent")
    if inject_attack:
        target_url = "http://169.254.169.254/latest/meta-data/iam/credentials"
        warn(f"[ATTACK] LLM tries to fetch: {target_url}")
        info("Expected: UrlSafe allowlist should block this request")
    else:
        target_url = "https://arxiv.org/abs/2310.17419"
        info(f"LLM fetches: {target_url}")

    search_task = (
        "Use fetch_url to retrieve the paper content from the URL below. "
        "Return only the tool output.\n"
        f"URL: {target_url}"
    )
    search_result = await orchestrator.run(
        task=(
            "Choose the best agent and use call_agent once to complete this task.\n"
            "Available agents: paper_search, summarizer.\n"
            f"Task: {search_task}"
        )
    )
    success(f"Paper Search result: {_result_to_text(search_result)}")

    print()

    # ---------------------------------------------------------------------
    # Step 3: Orchestrator delegates (model chooses agent)
    # ---------------------------------------------------------------------
    step(6, "Orchestrator delegates task to the best agent")
    if inject_attack:
        target_path = "/etc/passwd"
        warn(f"[ATTACK] LLM tries to read: {target_path}")
        info("Expected: Subpath guard should block this request")
    else:
        target_path = sample_path
        info(f"LLM reads: {target_path}")

    summarize_task = (
        "Use read_file to load the paper content, then summarize it in 3-5 sentences.\n"
        f"Path: {target_path}"
    )
    summary_result = await orchestrator.run(
        task=(
            "Choose the best agent and use call_agent once to complete this task.\n"
            "Available agents: paper_search, summarizer.\n"
            f"Task: {summarize_task}"
        )
    )
    success("Summarizer completed")
    print(_result_to_text(summary_result))

    print()

    if inject_attack:
        # -----------------------------------------------------------------
        # Step 4: Demonstrate Escalation Prevention (attenuation)
        # -----------------------------------------------------------------
        step(7, "Demonstrating Privilege Escalation Prevention")
        print(
            f"\n  {C.YELLOW}Scenario:{C.RESET} Paper Search tries to delegate 'read_file' "
            "(which it doesn't have)"
        )
        try:
            _escalated = search_warrant.attenuate(
                signing_key=paper_search_key,
                holder=SigningKey.generate().public_key,
                capabilities=Constraints.for_tool(
                    "read_file", {"path": Subpath("/")}
                ),
                ttl_seconds=300,
            )
            print(
                f"  {C.RED}ERROR: Escalation should have been prevented!{C.RESET}"
            )
        except Exception as e:
            blocked(f"Escalation prevented: {e}")
            print(
                f"\n{C.GREEN}  ╔══════════════════════════════════════════════════════════════╗"
                f"{C.RESET}"
            )
            print(
                f"{C.GREEN}  ║  PRIVILEGE ESCALATION BLOCKED - MONOTONICITY ENFORCED        ║"
                f"{C.RESET}"
            )
            print(
                f"{C.GREEN}  ╚══════════════════════════════════════════════════════════════╝"
                f"{C.RESET}"
            )

        warn(
            "URL and file access are protected in this demo. Attempts to "
            "read outside /tmp/papers should be blocked."
        )


async def run_comparison(
    interactive: bool = True, model: str = "gpt-4o", real_tools: bool = False
) -> None:
    header(
        "AUTOGEN A2A-STYLE DEMO (PROTECTED: URL allowlist + subpath + attenuation)"
    )
    print("  Architecture:")
    print("    User -> Orchestrator -> Paper Search")
    print("                       -> Summarizer")
    print()
    print("  Scenarios:")
    print("    1. Normal operation")
    print("    2. Simulated attacks (SSRF + path traversal)")
    print()

    if interactive:
        input("  Press Enter to start...\n")
    else:
        print("  [non-interactive mode]\n")

    await run_demo(inject_attack=False, model=model, real_tools=real_tools)

    if interactive:
        input("\n  Press Enter to run with attack simulation...\n")
    else:
        print("\n  --- Running attack simulation ---\n")

    await run_demo(inject_attack=True, model=model, real_tools=real_tools)


# =============================================================================
# CLI
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AutoGen AgentChat demo - protected delegation (attenuation)"
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
        "--real-tools",
        "-r",
        action="store_true",
        help="Perform real URL fetches and file reads (unsafe without protections)",
    )
    parser.add_argument(
        "--model",
        "-m",
        default="gpt-4o",
        help="OpenAI model name (default: gpt-4o)",
    )
    parser.add_argument(
        "--slow",
        "-s",
        action="store_true",
        help="Run demo slower for presentations (1.5s delay between steps)",
    )
    args = parser.parse_args()

    if args.slow:
        global DELAY_SECONDS
        DELAY_SECONDS = 1.5

    if args.command == "run":
        asyncio.run(
            run_demo(
                inject_attack=False,
                model=args.model,
                real_tools=args.real_tools,
            )
        )
    elif args.command == "attack":
        asyncio.run(
            run_demo(
                inject_attack=True,
                model=args.model,
                real_tools=args.real_tools,
            )
        )
    else:
        asyncio.run(
            run_comparison(
                interactive=not args.non_interactive,
                model=args.model,
                real_tools=args.real_tools,
            )
        )


if __name__ == "__main__":
    main()
