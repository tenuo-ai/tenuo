"""Rich console display for JIT Warrant Demo."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich import box
import json
import time

console = Console()

# Configurable delay between steps (set via --slow flag)
STEP_DELAY = 0.0


def set_step_delay(seconds: float):
    """Set the delay between demo steps."""
    global STEP_DELAY
    STEP_DELAY = seconds


def pause():
    """Pause between steps if delay is configured."""
    if STEP_DELAY > 0:
        time.sleep(STEP_DELAY)

def print_header(title: str):
    pause()
    console.print()
    console.print(Panel(
        f"[bold white]{title}[/bold white]",
        style="bold blue",
        box=box.DOUBLE
    ))

def print_step(number: int, title: str, description: str = ""):
    """Print a numbered step in the demo flow."""
    pause()
    content = f"[bold cyan]Step {number}:[/bold cyan] [bold]{title}[/bold]"
    if description:
        content += f"\n[dim]{description}[/dim]"
    console.print(Panel(content, box=box.ROUNDED, border_style="cyan"))

def print_user_task(task: str):
    """Display the user's task."""
    console.print(Panel(
        f"[bold]{task}[/bold]",
        title="📝 User Task",
        border_style="white"
    ))

def print_capability_proposal(capabilities: list):
    """Display the LLM's proposed capabilities."""
    table = Table(title="Proposed Capabilities", box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Constraints", style="yellow")
    
    for cap in capabilities:
        tool = cap.get("tool", "unknown")
        constraints = cap.get("constraints", {})
        constraint_str = ", ".join(f"{k}={v}" for k, v in constraints.items())
        table.add_row(tool, constraint_str or "(none)")
    
    console.print(Panel(
        table,
        title="🤖 LLM Capability Proposal",
        subtitle="[dim]The LLM analyzed the task and proposes these permissions[/dim]",
        border_style="blue"
    ))

def print_approval_prompt():
    """Show that approval is needed."""
    console.print(Panel(
        "[bold yellow]Review the proposed capabilities above.[/bold yellow]\n\n"
        "The LLM is requesting these permissions to complete the task.\n"
        "You can approve, modify, or reject.",
        title="🔐 Control Plane: Approval Required",
        border_style="yellow"
    ))

def print_warrant_minted(capabilities: list, ttl: int):
    """Show the minted warrant."""
    content = f"[bold]TTL:[/bold] {ttl} seconds\n\n"
    content += "[bold]Capabilities:[/bold]\n"
    for cap in capabilities:
        tool = cap.get("tool", "unknown")
        constraints = cap.get("constraints", {})
        content += f" [green]✓[/green] [cyan]{tool}[/cyan]"
        if constraints:
            content += "\n    " + ", ".join(f"[yellow]{k}[/yellow]: {v}" for k, v in constraints.items())
        content += "\n"
    
    console.print(Panel(
        content,
        title="📋 Warrant Minted",
        subtitle="[dim]Agent can now execute with these exact permissions[/dim]",
        border_style="green"
    ))

def print_execution_start():
    """Indicate execution phase."""
    console.print(Panel(
        "[bold]The agent now executes with cryptographic authorization.[/bold]\n\n"
        "Each tool call is:\n"
        " 1. [cyan]Signed[/cyan] with the agent's private key (Proof-of-Possession)\n"
        " 2. [cyan]Verified[/cyan] against the warrant's constraints\n\n"
        "[dim]Even if an attacker obtains the warrant, they can't use it without the key.[/dim]",
        title="⚡ Execution Phase (PoP Authorization)",
        border_style="magenta"
    ))

def print_tool_call(tool: str, args: dict):
    """Show what tool the agent is calling."""
    args_json = json.dumps(args, indent=2)
    console.print(Panel(
        Syntax(args_json, "json", theme="monokai", background_color="default"),
        title=f"🔧 Agent calls: [bold]{tool}[/bold]",
        border_style="blue",
        expand=False
    ))

def print_verdict(allowed: bool, reason: str, details: str = "", explorer_link: str = None):
    """Show Tenuo's authorization decision."""
    if allowed:
        style = "bold green"
        title = "✅ AUTHORIZED"
    else:
        style = "bold red"
        title = "⛔ BLOCKED"
    
    content = f"[bold]{reason}[/bold]"
    if details:
        content += f"\n\n{details}"
    
    if not allowed:
        content += "\n\n[dim italic]The warrant doesn't allow this action.[/dim italic]"
        
    console.print(Panel(
        content,
        title=title,
        border_style=style,
        expand=False
    ))
    
    # Print explorer link on a single line (copyable, no wrapping)
    if explorer_link:
        # Use print() directly to avoid Rich's wrapping
        print(f"\033[2mDebug: {explorer_link}\033[0m")
    
    pause()

def print_injection_detected():
    """Alert about prompt injection in content."""
    console.print(Panel(
        "[bold red]⚠️  PROMPT INJECTION DETECTED IN FETCHED CONTENT[/bold red]\n\n"
        "The fetched page contains hidden instructions trying to trick the LLM:\n"
        " [red]•[/red] Fetch unauthorized URLs\n"
        " [red]•[/red] Exfiltrate data\n"
        " [red]•[/red] Exceed granted permissions\n\n"
        "[dim]Watch how the warrant blocks these attempts...[/dim]",
        title="🎭 ATTACK IN PROGRESS",
        border_style="red",
        box=box.HEAVY
    ))

def print_learning(title: str, text: str):
    """Highlight a security concept."""
    console.print(Panel(
        f"[italic]{text}[/italic]",
        title=f"🎓 KEY INSIGHT: {title}",
        border_style="yellow",
        box=box.ROUNDED
    ))
    pause()

def print_demo_intro():
    """Print introduction explaining the demo."""
    console.print(Panel(
        "[bold]Just-in-Time Warrants with Multi-Sig Human Approval[/bold]\n\n"
        "This demo shows a production-realistic security pattern:\n"
        "1. LLM analyzes the task and proposes needed capabilities\n"
        "2. System (Control Plane) validates against security policy\n"
        "3. [yellow]Human cryptographically signs approval[/yellow]\n"
        "4. Multi-sig warrant is minted (requires both signatures)\n"
        "5. Even if compromised, the LLM is bound by the warrant\n\n"
        "[yellow]Key security:[/yellow] Both system AND human must approve with their private keys.",
        title="🎯 DEMO: Multi-Sig Just-in-Time Warrants",
        border_style="magenta",
        box=box.DOUBLE
    ))

def print_llm_reasoning(response: str):
    """Show the LLM's reasoning about capabilities."""
    # Try to extract just the reasoning part if it's JSON
    import json
    import re
    
    reasoning = response
    try:
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            data = json.loads(json_match.group())
            if "reasoning" in data:
                reasoning = data["reasoning"]
    except (json.JSONDecodeError, KeyError):
        pass
    
    console.print(Panel(
        f"[italic]{reasoning}[/italic]",
        title="🧠 LLM Reasoning",
        subtitle="[dim]The LLM analyzed what capabilities it needs[/dim]",
        border_style="blue"
    ))


def print_human_approval_request(approver_name: str, task: str, capabilities: list, urls: list):
    """Show the approval request to the human."""
    # Build capability list with constraints
    cap_lines = []
    for cap in capabilities:
        tool = cap.get('tool', 'unknown')
        constraints = cap.get('constraints', {})
        if constraints:
            constraint_str = ", ".join(f"{k}={v}" for k, v in constraints.items())
            cap_lines.append(f" [cyan]•[/cyan] [bold]{tool}[/bold]\n      {constraint_str}")
        else:
            cap_lines.append(f" [cyan]•[/cyan] [bold]{tool}[/bold] [dim](no constraints)[/dim]")
    tools_list = "\n".join(cap_lines)
    
    # URL constraints that will be applied
    urls_list = "\n".join(f" [yellow]•[/yellow] {url}" for url in urls)
    
    console.print(Panel(
        f"[bold]Task:[/bold] {task}\n\n"
        f"[bold]Requested Capabilities:[/bold]\n{tools_list}\n\n"
        f"[bold]URL Constraints (will be enforced):[/bold]\n{urls_list}\n\n"
        "[dim]The LLM is requesting these permissions. Review carefully.[/dim]",
        title=f"🔐 APPROVAL REQUIRED: {approver_name}",
        border_style="yellow",
        box=box.HEAVY
    ))


def print_system_approval(system_key):
    """Show system (control plane) approval."""
    console.print(Panel(
        f"[bold green]✓[/bold green] Policy check passed\n"
        f"[bold green]✓[/bold green] No dangerous tools requested\n"
        f"[bold green]✓[/bold green] System signed with key: {str(system_key)[:20]}...\n\n"
        "[dim]Waiting for human approval...[/dim]",
        title="🤖 SYSTEM APPROVAL",
        border_style="green"
    ))


def print_human_approval_signed(approver_name: str, public_key):
    """Show that human has signed approval."""
    console.print(Panel(
        f"[bold green]✓[/bold green] {approver_name} reviewed the proposal\n"
        f"[bold green]✓[/bold green] Cryptographically signed with key: {str(public_key)[:20]}...\n\n"
        "[bold]Human approval recorded on warrant.[/bold]",
        title=f"✍️  HUMAN SIGNATURE: {approver_name}",
        border_style="green"
    ))


def print_human_rejection(approver_name: str):
    """Show that human rejected the proposal."""
    console.print(Panel(
        f"[bold red]✗[/bold red] {approver_name} rejected the proposal\n\n"
        "[bold]Warrant will NOT be issued.[/bold]",
        title=f"🚫 REJECTED: {approver_name}",
        border_style="red"
    ))


def print_approval_complete():
    """Show that multi-sig approval is complete."""
    console.print(Panel(
        "[bold green]Both signatures collected:[/bold green]\n"
        " [green]✓[/green] System (Control Plane)\n"
        " [green]✓[/green] Human Approver\n\n"
        "[bold]The warrant is now valid and can be used.[/bold]",
        title="✅ MULTI-SIG APPROVAL COMPLETE",
        border_style="green",
        box=box.DOUBLE
    ))


def print_demo_summary(blocked: int, allowed: int):
    """Print summary at end of demo."""
    console.print(Panel(
        f"[bold green]✅ Allowed actions:[/bold green] {allowed}\n"
        f"[bold red]⛔ Blocked actions:[/bold red] {blocked}\n\n"
        "[bold]The task-specific warrant enforced boundaries.[/bold]\n"
        "Even with prompt injection in fetched content, unauthorized actions were blocked.\n\n"
        "Learn more: https://tenuo.dev",
        title="📊 DEMO SUMMARY",
        border_style="magenta"
    ))


def print_delegation(
    from_key,
    worker_name: str,
    to_key,
    tools: list,
    constraints: dict,
    ttl: int
):
    """Show warrant delegation from orchestrator to worker."""
    tools_str = ", ".join(f"[cyan]{t}[/cyan]" for t in tools)
    constraint_str = ""
    if constraints:
        constraint_str = "\n[bold]Constraints:[/bold]\n"
        for tool, cons in constraints.items():
            constraint_str += f" [yellow]{tool}[/yellow]: {cons}\n"
    
    console.print(Panel(
        f"[bold]From:[/bold] Orchestrator ({str(from_key)[:16]}...)\n"
        f"[bold]To:[/bold] {worker_name} ({str(to_key)[:16]}...)\n"
        f"[bold]Tools:[/bold] {tools_str}\n"
        f"[bold]TTL:[/bold] {ttl}s{constraint_str}\n\n"
        "[dim]The worker receives an ATTENUATED subset of authority.[/dim]",
        title=f"📤 DELEGATION: Orchestrator -> {worker_name}",
        border_style="blue"
    ))


def print_stale_warrant_warning(worker_name: str):
    """Warn about stale/mismatched warrant assignment."""
    console.print(Panel(
        f"[bold red]⚠️  TEMPORAL MISMATCH DETECTED[/bold red]\n\n"
        f"Worker '{worker_name}' has been given a warrant that:\n"
        " [red]•[/red] May have different constraints than expected\n"
        " [red]•[/red] May grant access to wrong resources\n"
        " [red]•[/red] Represents stale authorization state\n\n"
        "[dim]This demonstrates what happens when warrants are mismanaged.[/dim]",
        title="⏰ STALE WARRANT WARNING",
        border_style="red",
        box=box.HEAVY
    ))


def print_worker_execution(worker_name: str, specialty: str):
    """Show a worker beginning execution."""
    console.print(Panel(
        f"[bold]{worker_name}[/bold] ({specialty})\n\n"
        "[dim]Worker executes with its delegated (attenuated) warrant.[/dim]",
        title=f"👷 WORKER: {worker_name}",
        border_style="cyan"
    ))


def print_attenuation_demo():
    """Explain the attenuation concept."""
    console.print(Panel(
        "[bold]MONOTONICITY: Authority can only decrease, never increase.[/bold]\n\n"
        "When the Orchestrator delegates to Workers:\n"
        " [green]✓[/green] Orchestrator: fetch_url(*.python.org), summarize, write_file\n"
        " [cyan]→[/cyan] Fetcher Worker: fetch_url(docs.python.org) [dim]# subset[/dim]\n"
        " [cyan]→[/cyan] Summarizer Worker: summarize [dim]# subset[/dim]\n"
        " [cyan]→[/cyan] Writer Worker: write_file(/tmp/summary.txt) [dim]# subset[/dim]\n\n"
        "[yellow]Each worker gets ONLY what it needs.[/yellow]",
        title="📉 ATTENUATION: Least Privilege Delegation",
        border_style="yellow",
        box=box.DOUBLE
    ))


def print_temporal_mismatch_intro():
    """Explain temporal mismatch concept."""
    console.print(Panel(
        "[bold]TEMPORAL MISMATCH: When a valid warrant becomes stale.[/bold]\n\n"
        "Scenario:\n"
        " 1. [green]T0[/green]: Warrant issued for Resource A (v1 API)\n"
        " 2. [yellow]T1[/yellow]: Requirements change - now need Resource B (v2 API)\n"
        " 3. [red]T2[/red]: Worker tries to use old warrant for new resource\n\n"
        "The warrant is still cryptographically VALID, but:\n"
        " [red]•[/red] It grants access to the WRONG resource\n"
        " [red]•[/red] It doesn't match current requirements\n"
        " [red]•[/red] The task will fail or access stale data\n\n"
        "[yellow]Solution: Short TTLs + Just-in-Time minting[/yellow]",
        title="⏰ TEMPORAL MISMATCH",
        border_style="yellow",
        box=box.DOUBLE
    ))


def print_monotonicity_intro():
    """Explain monotonicity enforcement."""
    console.print(Panel(
        "[bold]MONOTONICITY: Authority can only DECREASE, never increase.[/bold]\n\n"
        "When delegating warrants:\n"
        " [green]✓[/green] Grant a SUBSET of your capabilities (attenuation)\n"
        " [green]✓[/green] Add MORE constraints (tightening)\n"
        " [green]✓[/green] Reduce TTL (shorter lifetime)\n\n"
        "You CANNOT:\n"
        " [red]✗[/red] Grant capabilities you don't have\n"
        " [red]✗[/red] Relax constraints\n"
        " [red]✗[/red] Extend TTL beyond parent\n\n"
        "[yellow]This prevents privilege escalation through delegation.[/yellow]",
        title="🔒 MONOTONICITY",
        border_style="blue",
        box=box.DOUBLE
    ))


def print_temporal_timeline(old_url: str, new_url: str):
    """Show the temporal timeline of the mismatch."""
    console.print(Panel(
        f"[bold green]T0 - Earlier:[/bold green]\n"
        f"   Worker received warrant for: [cyan]{old_url}[/cyan]\n\n"
        f"[bold yellow]T1 - Now:[/bold yellow]\n"
        f"   Current task requires: [cyan]{new_url}[/cyan]\n\n"
        f"[bold red]T2 - Problem:[/bold red]\n"
        f"   Worker's warrant doesn't match current requirements!",
        title="📅 TIMELINE",
        border_style="yellow"
    ))


def print_stale_warrant_issued(worker_name: str, url: str):
    """Show that a stale warrant was issued."""
    console.print(Panel(
        f"[bold]{worker_name}[/bold] received warrant for:\n"
        f" [cyan]fetch_url[/cyan]({url})\n\n"
        "[dim]This warrant was valid at the time...[/dim]",
        title="📜 WARRANT ISSUED (Earlier)",
        border_style="dim"
    ))


def print_current_requirement(url: str):
    """Show the current requirement."""
    console.print(Panel(
        f"Current task needs access to:\n"
        f" [yellow]{url}[/yellow]\n\n"
        "[dim]But the worker has a warrant for the OLD resource![/dim]",
        title="📋 CURRENT REQUIREMENT",
        border_style="yellow"
    ))

