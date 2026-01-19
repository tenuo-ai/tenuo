#!/usr/bin/env python3
"""
AutoGen AgentChat demo: GuardBuilder (Tier 1 constraints-only) using the SAME
three-agent flow as the protected/attenuation demos:

    User -> Orchestrator -> Paper Search (fetch_url) -> Summarizer (read_file)

Protection:
- UrlSafe allowlist for fetch_url (arxiv.org, scholar.google.com)
- Subpath("/tmp/papers") for read_file
- No warrants/PoP (Tier 1), on_denial = raise (default)

Run:
    python autogen_demo_guardbuilder_tier1.py
    python autogen_demo_guardbuilder_tier1.py run
    python autogen_demo_guardbuilder_tier1.py attack
    python autogen_demo_guardbuilder_tier1.py compare

Requires:
    pip install "tenuo[autogen]" "python-dotenv"
    # Set OPENAI_API_KEY (env or .env file)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from typing import Any

try:
    from dotenv import load_dotenv  # type: ignore[reportMissingImports]
except Exception as e:  # pragma: no cover - optional dep guard
    print(f"Error: Missing dependency - {e}")
    print('Install with: pip install "python-dotenv"')
    raise

try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient
except Exception as e:  # pragma: no cover - optional dep guard
    print(f"Error: Missing dependency - {e}")
    print('Install with: pip install "tenuo[autogen]"')
    raise

from tenuo import Subpath, UrlSafe
from tenuo.autogen import GuardBuilder


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


async def run_demo(
    inject_attack: bool = False,
    model: str = "gpt-4o",
    real_tools: bool = False,
) -> None:
    sample_path = "/tmp/papers/toctou.txt"
    if real_tools:
        _ensure_sample_paper(sample_path)

    def fetch_url(url: str) -> dict[str, Any]:
        if real_tools:
            import httpx

            try:
                r = httpx.get(url, timeout=10.0)
                content = r.text
                if len(content) > 500:
                    content = content[:500] + "..."
                return {"status": "success", "url": url, "status_code": r.status_code, "content": content}
            except Exception as e:
                return {"status": "error", "url": url, "error": str(e)}
        return {"status": "success", "url": url, "content": f"[Simulated paper content from {url}]"}

    def read_file(path: str) -> dict[str, Any]:
        if real_tools:
            try:
                with open(path, "r") as f:
                    content = f.read()
                if len(content) > 500:
                    content = content[:500] + "..."
                return {"status": "success", "path": path, "content": content}
            except Exception as e:
                return {"status": "error", "path": path, "error": str(e)}
        content = SAMPLE_PAPER_CONTENT if path == sample_path else f"[Simulated file content from {path}]"
        return {"status": "success", "path": path, "content": content}

    guard = (
        GuardBuilder()
        .allow("fetch_url", url=UrlSafe(allow_domains=["arxiv.org", "scholar.google.com"]))
        .allow("read_file", path=Subpath("/tmp/papers"))
        .build()
    )
    guarded_fetch_url = guard.guard_tool(fetch_url, tool_name="fetch_url")
    guarded_read_file = guard.guard_tool(read_file, tool_name="read_file")

    load_dotenv()
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        raise RuntimeError("OPENAI_API_KEY not found in .env file")

    model_client = OpenAIChatCompletionClient(model=model, api_key=openai_api_key, tool_choice="required")

    paper_search_agent = AssistantAgent(
        "paper_search",
        model_client,
        tools=[guarded_fetch_url],
        system_message=(
            "You are the Paper Search agent. Always use the fetch_url tool to "
            "retrieve paper content. Return the tool result."
        ),
    )

    summarizer_agent = AssistantAgent(
        "summarizer",
        model_client,
        tools=[guarded_read_file],
        system_message=(
            "You are the Summarizer agent. Use read_file to load the paper "
            "content, then summarize it concisely."
        ),
    )

    async def call_agent(agent: str, task: str) -> str:
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
        system_message=(
            "You are the Orchestrator. Delegate tasks to other agents using "
            "the call_agent tool. Choose the best agent for each task and "
            "do not solve tasks yourself. Available agents: "
            "paper_search (fetches URLs), summarizer (reads and summarizes files)."
        ),
    )

    if inject_attack:
        target_url = "http://169.254.169.254/latest/meta-data/iam/credentials"
        target_path = "/etc/passwd"
    else:
        target_url = "https://arxiv.org/abs/2310.17419"
        target_path = sample_path

    search_task = (
        "Use fetch_url to retrieve the paper content from the URL below. "
        "Return only the tool output.\n"
        f"URL: {target_url}"
    )
    summarize_task = (
        "Use read_file to load the paper content, then summarize it in 3-5 sentences.\n"
        f"Path: {target_path}"
    )

    search_result = await orchestrator.run(
        task=(
            "Choose the best agent and use call_agent once to complete this task.\n"
            "Available agents: paper_search, summarizer.\n"
            f"Task: {search_task}"
        )
    )
    print("Paper Search result:", _result_to_text(search_result))

    summary_result = await orchestrator.run(
        task=(
            "Choose the best agent and use call_agent once to complete this task.\n"
            "Available agents: paper_search, summarizer.\n"
            f"Task: {summarize_task}"
        )
    )
    print("Summarizer result:", _result_to_text(summary_result))


async def run_comparison(
    interactive: bool = True, model: str = "gpt-4o", real_tools: bool = False
) -> None:
    print("AUTOGEN GUARD BUILDER (TIER 1, CONSTRAINTS ONLY)")
    print("Scenario: User -> Orchestrator -> Paper Search (fetch_url) -> Summarizer (read_file)")
    if interactive:
        input("Press Enter to run normal flow...\n")
    await run_demo(inject_attack=False, model=model, real_tools=real_tools)

    if interactive:
        input("\nPress Enter to run with attack simulation...\n")
    await run_demo(inject_attack=True, model=model, real_tools=real_tools)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AutoGen AgentChat demo - GuardBuilder Tier 1 (constraints only)"
    )
    parser.add_argument("command", choices=["run", "attack", "compare"], nargs="?", default="compare")
    parser.add_argument("--non-interactive", "-n", action="store_true", help="Skip interactive prompts")
    parser.add_argument("--real-tools", "-r", action="store_true", help="Use real HTTP/file access")
    parser.add_argument("--model", "-m", default="gpt-4o", help="OpenAI model name")
    args = parser.parse_args()

    if args.command == "run":
        asyncio.run(run_demo(inject_attack=False, model=args.model, real_tools=args.real_tools))
    elif args.command == "attack":
        asyncio.run(run_demo(inject_attack=True, model=args.model, real_tools=args.real_tools))
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
