#!/usr/bin/env python3
"""
Just-in-Time Warrant Demo with Orchestrator-Worker Pattern

Demonstrates a production-realistic pattern where:
1. Orchestrator (LLM) analyzes tasks and proposes capabilities
2. Control Plane + Human approve with cryptographic signatures
3. Orchestrator delegates ATTENUATED warrants to specialized workers
4. Workers execute with Proof-of-Possession
5. Shows temporal mismatch scenarios
"""

import asyncio

import config
import display
import requests
import tools as tool_module
from control_plane import ControlPlane
from executor import WarrantExecutor, simulate_compromised_execution
from human_approval import HumanApprover, MultiSigApprovalFlow
from orchestrator import (
    Orchestrator,
    extract_urls,
    propose_capabilities_sync,
    propose_capabilities_with_llm,
)

LM_STUDIO_API_URL = config.LM_STUDIO_URL + "/v1/models"


def pre_flight_check():
    """Check if LM Studio is running and has models."""
    if config.LM_STUDIO_MODEL_ID:
        display.print_verdict(True, "Using Configured Model", f"Model: {config.LM_STUDIO_MODEL_ID}")
        return config.LM_STUDIO_MODEL_ID

    try:
        resp = requests.get(LM_STUDIO_API_URL, timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("data", [])
            if models:
                model_id = models[0]["id"]
                display.print_verdict(True, "LM Studio Connected", f"Model: {model_id}")
                return model_id
    except requests.exceptions.ConnectionError:
        pass

    return None


def run_delegation_demo(orchestrator: Orchestrator, urls: list):
    """
    Demonstrate warrant attenuation during delegation.

    The orchestrator delegates subsets of its authority to specialized workers.
    """
    from tenuo import Exact

    display.print_header("DELEGATION DEMO: Orchestrator -> Workers")
    display.print_attenuation_demo()

    # Create specialized workers
    fetcher = orchestrator.create_worker("Fetcher", "URL fetching")
    summarizer = orchestrator.create_worker("Summarizer", "Text summarization")

    # Delegate attenuated warrants
    display.print_step(6, "Delegate to Workers", "Orchestrator gives each worker ONLY what it needs (monotonicity).")

    target_url = urls[0] if urls else "https://docs.python.org"

    # Fetcher gets only fetch_url for specific URLs
    # Use Exact constraint for the URL
    orchestrator.delegate_to_worker(
        fetcher,
        tools=["fetch_url"],
        constraints={"fetch_url": {"url": Exact(target_url)}},
        ttl=60,
    )

    # Summarizer gets only summarize
    orchestrator.delegate_to_worker(
        summarizer,
        tools=["summarize"],
        constraints={},
        ttl=60,
    )

    # Show worker execution
    display.print_step(7, "Worker Execution", "Each worker operates within its attenuated warrant.")

    tools_dict = {
        "fetch_url": tool_module.fetch_url,
        "summarize": tool_module.summarize,
        "write_file": tool_module.write_file,
    }

    content = ""

    # Fetcher worker execution
    if fetcher.warrant:
        display.print_worker_execution(fetcher.name, fetcher.specialty)
        fetcher_executor = WarrantExecutor(fetcher.warrant, fetcher.signing_key)

        fetch = fetcher_executor.wrap(tools_dict["fetch_url"])
        content = fetch(url=target_url)

        # Fetcher tries to summarize (should fail - not in its warrant)
        display.console.print("\n[dim]Fetcher tries to use summarize (not in its warrant)...[/dim]")
        summarize = fetcher_executor.wrap(tools_dict["summarize"])
        summarize(content="test")
    else:
        display.console.print("[dim]Fetcher delegation failed, skipping...[/dim]")

    # Summarizer worker execution
    if summarizer.warrant:
        display.print_worker_execution(summarizer.name, summarizer.specialty)
        summarizer_executor = WarrantExecutor(summarizer.warrant, summarizer.signing_key)

        summarize = summarizer_executor.wrap(tools_dict["summarize"])
        if content and not content.startswith("BLOCKED"):
            summarize(content=content)

        # Summarizer tries to fetch (should fail - not in its warrant)
        display.console.print("\n[dim]Summarizer tries to use fetch_url (not in its warrant)...[/dim]")
        fetch = summarizer_executor.wrap(tools_dict["fetch_url"])
        fetch(url="https://evil.com")
    else:
        display.console.print("[dim]Summarizer delegation failed, skipping...[/dim]")

    # Summary
    display.print_learning(
        "Monotonicity",
        "Each worker only received the tools it needed. "
        "The Fetcher couldn't summarize, the Summarizer couldn't fetch. "
        "This is LEAST PRIVILEGE through delegation.",
    )


def run_temporal_mismatch_demo(orchestrator: Orchestrator, urls: list):
    """
    Demonstrate temporal mismatch - when a valid warrant becomes stale.

    This shows what happens when:
    1. A warrant was correctly issued for resource A
    2. Requirements change - now we need resource B
    3. The old warrant can't access the new resource
    """
    from tenuo import Exact

    display.print_header("TEMPORAL MISMATCH DEMO")
    display.print_temporal_mismatch_intro()

    # Scenario: Worker was given warrant for v1 API, but now we need v2 API
    display.print_step(
        8, "Stale Warrant Scenario", "A worker has a warrant from an earlier task. Requirements have changed."
    )

    # Simulate: Earlier, we issued a warrant for the OLD API
    old_api_url = "https://api.example.com/v1/data"
    new_api_url = "https://api.example.com/v2/data"

    display.print_temporal_timeline(old_api_url, new_api_url)

    # Create a "stale" worker that has a warrant from the old task
    # We need to create this warrant from a separate orchestrator that had the old permissions
    stale_worker = orchestrator.create_worker("StaleWorker", "Has warrant from earlier task")

    # Give the worker a warrant for the OLD API (simulating it was issued earlier)
    # We'll mint this directly to simulate it came from a previous session
    from control_plane import ControlPlane

    old_control_plane = ControlPlane()

    display.console.print("\n[bold yellow]T0 (Earlier):[/bold yellow] Warrant issued for v1 API")
    old_warrant = old_control_plane.mint_warrant_silent(
        agent_key=stale_worker.signing_key,
        capabilities=[{"tool": "fetch_url"}],
        allowed_urls=[old_api_url],
        ttl=300,
    )
    stale_worker.warrant = old_warrant

    display.print_stale_warrant_issued(stale_worker.name, old_api_url)

    # Now show that the current task needs the NEW API
    display.console.print("\n[bold yellow]T1 (Now):[/bold yellow] Task requires v2 API")
    display.print_current_requirement(new_api_url)

    # Worker tries to access the NEW API with its OLD warrant
    display.console.print("\n[bold yellow]T2 (Execution):[/bold yellow] Worker attempts to use stale warrant")

    tools_dict = {"fetch_url": tool_module.fetch_url}
    stale_executor = WarrantExecutor(stale_worker.warrant, stale_worker.signing_key)
    fetch = stale_executor.wrap(tools_dict["fetch_url"])

    display.console.print(f"\n[dim]Worker tries to fetch NEW API: {new_api_url}[/dim]")
    fetch(url=new_api_url)

    # Also show that the OLD API still works (warrant is valid, just stale)
    display.console.print(f"\n[dim]Worker CAN still access OLD API: {old_api_url}[/dim]")
    fetch(url=old_api_url)

    display.print_learning(
        "Temporal Mismatch",
        "The warrant was VALID when issued, but requirements changed. "
        "The worker can still access the OLD resource (v1 API), but NOT the new one (v2 API). "
        "Solution: Short TTLs + JIT minting ensure warrants match current requirements.",
    )

    # Now show monotonicity as a separate concept
    display.print_header("MONOTONICITY ENFORCEMENT")
    display.print_monotonicity_intro()

    display.print_step(
        9, "Attempted Privilege Escalation", "What if orchestrator tries to delegate BROADER access than it has?"
    )

    escalation_worker = orchestrator.create_worker("EscalationWorker", "Attempts broader access")

    display.console.print("\n[dim]Orchestrator attempts to delegate for unauthorized URL...[/dim]")

    result = orchestrator.delegate_to_worker(
        escalation_worker,
        tools=["fetch_url"],
        constraints={"fetch_url": {"url": Exact("https://admin.internal.corp/secrets")}},
        ttl=60,
    )

    if not result:
        display.print_learning(
            "Monotonicity",
            "Delegation FAILED - you cannot grant what you don't have. "
            "The orchestrator only has access to docs.python.org, "
            "so it cannot create a child warrant for admin.internal.corp. "
            "Authority can only DECREASE through delegation.",
        )


async def run_demo_with_llm(
    task: str, model_id: str, simulate_attack: bool = True, show_delegation: bool = False, interactive: bool = True
):
    """
    Run the full demo with LLM capability analysis and human approval.
    """
    import lmstudio as lms

    display.print_demo_intro()
    display.print_user_task(task)

    # Extract URLs for constraint building (source of truth, not LLM)
    urls = extract_urls(task)
    if not urls:
        display.console.print("[yellow]No URLs found. Using example URL.[/yellow]")
        urls = ["https://docs.python.org"]

    async with lms.AsyncClient() as client:
        model = await client.llm.model(model_id)
        display.console.print(f"[dim]Connected to: {model_id}[/dim]\n")

        # Create the Orchestrator
        orchestrator = Orchestrator()

        # Phase 1: LLM proposes capabilities
        proposed_caps = await propose_capabilities_with_llm(model, task)

        # Phase 2: Control plane reviews against policy
        control_plane = ControlPlane()
        approved_caps = control_plane.review_proposal(proposed_caps, auto_approve=True)

        if not approved_caps:
            display.print_verdict(False, "All capabilities rejected", "The control plane rejected the entire proposal.")
            return

        # Phase 3: Mint warrant
        # First create the warrant, then get approvals for its use
        warrant = control_plane.mint_warrant(
            agent_key=orchestrator.signing_key,
            capabilities=approved_caps,
            allowed_urls=urls,
            ttl=300,
        )
        orchestrator.receive_warrant(warrant)

        # Phase 4: Multi-sig approval (System + Human)
        # Approvals are bound to specific tool calls on this warrant
        human = HumanApprover(name="Security Reviewer")
        approval_flow = MultiSigApprovalFlow(
            system_key=control_plane.signing_key,
            human_approver=human,
        )

        # Get approvals for the first expected tool call
        first_tool = approved_caps[0]["tool"] if approved_caps else "fetch_url"
        first_args = {"url": urls[0]} if urls else {}

        approvals = approval_flow.execute_approval_flow(
            warrant=warrant,
            tool=first_tool,
            args=first_args,
            holder_key=orchestrator.signing_key.public_key,
            task=task,
            proposed_capabilities=approved_caps,
            allowed_urls=urls,
            interactive=interactive,
        )

        if approvals is None:
            display.print_verdict(False, "Approval rejected", "Human reviewer did not approve the warrant.")
            return

        # Phase 5: Execute with cryptographic authorization
        display.print_step(
            5,
            "Orchestrator Executes",
            "Orchestrator runs with warrant. Each call is cryptographically signed with PoP.",
        )

        # Pass approvals to executor for multi-sig verification
        executor = WarrantExecutor(warrant, orchestrator.signing_key, approvals=approvals)

        tools_dict = {
            "fetch_url": tool_module.fetch_url,
            "summarize": tool_module.summarize,
            "write_file": tool_module.write_file,
            "http_request": tool_module.http_request,
            "send_email": tool_module.send_email,
        }

        if simulate_attack:
            simulate_compromised_execution(executor, tools_dict, urls)
        else:
            fetch = executor.wrap(tools_dict["fetch_url"])
            summarize = executor.wrap(tools_dict["summarize"])

            all_content = []
            for url in urls:
                content = fetch(url=url)
                if not content.startswith("BLOCKED"):
                    all_content.append(content)

            if all_content:
                summarize(content="\n".join(all_content))

        # Summary
        blocked, allowed = executor.get_stats()
        display.print_demo_summary(blocked, allowed)

        # Optional: Show delegation demos
        if show_delegation:
            run_delegation_demo(orchestrator, urls)
            run_temporal_mismatch_demo(orchestrator, urls)


def run_demo_simulate(task: str, show_delegation: bool = False, interactive: bool = True):
    """
    Run demo in simulation mode (no LLM required).
    """
    display.print_demo_intro()
    display.print_user_task(task)

    urls = extract_urls(task)
    if not urls:
        urls = ["https://docs.python.org"]

    # Create the Orchestrator
    orchestrator = Orchestrator()

    # Phase 1: Simulated capability analysis
    proposed_caps = propose_capabilities_sync(task)

    # Phase 2: Control plane reviews against policy
    control_plane = ControlPlane()
    approved_caps = control_plane.review_proposal(proposed_caps, auto_approve=True)

    if not approved_caps:
        display.print_verdict(False, "All capabilities rejected", "The control plane rejected the entire proposal.")
        return

    # Phase 3: Mint warrant
    warrant = control_plane.mint_warrant(
        agent_key=orchestrator.signing_key,
        capabilities=approved_caps,
        allowed_urls=urls,
        ttl=300,
    )
    orchestrator.receive_warrant(warrant)

    # Phase 4: Multi-sig approval (System + Human)
    human = HumanApprover(name="Security Reviewer")
    approval_flow = MultiSigApprovalFlow(
        system_key=control_plane.signing_key,
        human_approver=human,
    )

    # Get approvals for the first expected tool call
    first_tool = approved_caps[0]["tool"] if approved_caps else "fetch_url"
    first_args = {"url": urls[0]} if urls else {}

    approvals = approval_flow.execute_approval_flow(
        warrant=warrant,
        tool=first_tool,
        args=first_args,
        holder_key=orchestrator.signing_key.public_key,
        task=task,
        proposed_capabilities=approved_caps,
        allowed_urls=urls,
        interactive=interactive,
    )

    if approvals is None:
        display.print_verdict(False, "Approval rejected", "Human reviewer did not approve the warrant.")
        return

    # Phase 5: Execute with cryptographic authorization
    display.print_step(
        5, "Orchestrator Executes", "Orchestrator runs with warrant. Each call is cryptographically signed with PoP."
    )

    executor = WarrantExecutor(warrant, orchestrator.signing_key, approvals=approvals)

    tools_dict = {
        "fetch_url": tool_module.fetch_url,
        "summarize": tool_module.summarize,
        "write_file": tool_module.write_file,
        "http_request": tool_module.http_request,
        "send_email": tool_module.send_email,
    }

    # Run attack simulation
    simulate_compromised_execution(executor, tools_dict, urls)

    # Summary
    blocked, allowed = executor.get_stats()
    display.print_demo_summary(blocked, allowed)

    # Optional: Show delegation demos
    if show_delegation:
        run_delegation_demo(orchestrator, urls)
        run_temporal_mismatch_demo(orchestrator, urls)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Just-in-Time Warrant Demo with Orchestrator-Worker Pattern",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo.py                    # Full demo with LLM + human approval
  python demo.py --simulate         # Simulation mode (no LLM)
  python demo.py --delegation       # Include delegation + temporal mismatch demos
  python demo.py --auto-approve     # Skip interactive approval prompt
  python demo.py --slow 2           # Add 2-second pauses for presentations
  python demo.py --task "Summarize https://example.com"
        """,
    )
    parser.add_argument(
        "--task", "-t", default="Summarize this URL: https://docs.python.org", help="The task to perform"
    )
    parser.add_argument("--simulate", "-s", action="store_true", help="Run in simulation mode (no LLM required)")
    parser.add_argument("--delegation", "-d", action="store_true", help="Show delegation and temporal mismatch demos")
    parser.add_argument("--auto-approve", action="store_true", help="Auto-approve without interactive prompt")
    parser.add_argument("--no-attack", action="store_true", help="Skip the attack simulation")
    parser.add_argument(
        "--slow",
        type=float,
        default=0,
        metavar="SECONDS",
        help="Add delay between steps for presentations (e.g., --slow 2)",
    )

    args = parser.parse_args()
    config.setup_workspace()

    # Set step delay for presentations
    if args.slow > 0:
        display.set_step_delay(args.slow)

    interactive = not args.auto_approve

    if args.simulate:
        run_demo_simulate(args.task, show_delegation=args.delegation, interactive=interactive)
    else:
        # Check for LM Studio
        display.print_header("PRE-FLIGHT CHECK")
        model_id = pre_flight_check()

        if not model_id:
            display.print_verdict(False, "LM Studio not available", "Run with --simulate for demo without LLM")
            return

        asyncio.run(
            run_demo_with_llm(
                args.task,
                model_id,
                simulate_attack=not args.no_attack,
                show_delegation=args.delegation,
                interactive=interactive,
            )
        )


if __name__ == "__main__":
    main()
