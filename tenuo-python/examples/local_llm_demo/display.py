from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box
import json

console = Console()


def print_header(title: str):
    console.print()
    console.print(Panel(f"[bold white]{title}[/bold white]", style="bold blue", box=box.DOUBLE))


def print_step(number: int, title: str, description: str = ""):
    """Print a numbered step in the demo flow"""
    content = f"[bold cyan]Step {number}:[/bold cyan] [bold]{title}[/bold]"
    if description:
        content += f"\n[dim]{description}[/dim]"
    console.print(Panel(content, box=box.ROUNDED, border_style="cyan"))


def print_warrant_details(warrant, role: str):
    """Pretty print a warrant with educational context"""
    content = f"[bold]Issuer:[/bold] {warrant.issuer}\n"
    content += f"[bold]Holder:[/bold] {role} ({warrant.authorized_holder})\n"
    content += f"[bold]TTL:[/bold] {warrant.ttl_remaining}\n\n"
    content += "[bold]Capabilities (what this agent CAN do):[/bold]\n"

    if hasattr(warrant, "capabilities"):
        caps = warrant.capabilities
        for tool, constraints in caps.items():
            content += f" [green]✓[/green] [cyan]{tool}[/cyan]"
            if constraints:
                content += "\n    " + ", ".join(f"[yellow]{k}[/yellow]: {v}" for k, v in constraints.items())
            content += "\n"
    else:
        content += f" {warrant.tools}"

    content += "\n[bold red]NOT in warrant (will be BLOCKED):[/bold red]\n"
    content += " [red]✗[/red] http_request (no network access)\n"
    content += " [red]✗[/red] Files outside allowed paths"

    console.print(Panel(content, title=f"📋 Active Warrant: {role}", border_style="green", expand=False))


def print_llm_intent(tool: str, args: dict):
    """Show what the LLM wants to do"""
    args_json = json.dumps(args, indent=2)
    console.print(
        Panel(
            Syntax(args_json, "json", theme="monokai", background_color="default"),
            title=f"🤖 LLM wants to call: [bold]{tool}[/bold]",
            border_style="blue",
            expand=False,
        )
    )


def print_verdict(allowed: bool, reason: str, details: str = "", debug_link: str = None):
    """Show Tenuo's decision with educational context"""
    if allowed:
        style = "bold green"
        title = "✅ TENUO: AUTHORIZED"
    else:
        style = "bold red"
        title = "⛔ TENUO: BLOCKED"

    content = f"[bold]{reason}[/bold]"
    if details:
        content += f"\n\n{details}"

    # Add educational context for blocks
    if not allowed:
        content += "\n\n[dim italic]The warrant doesn't allow this action.[/dim italic]"

    console.print(Panel(content, title=title, border_style=style, expand=False))

    # Print debug link on its own line for easy copying
    if debug_link:
        console.print(f"[dim]Debug: {debug_link}[/dim]")


def print_injection_warning():
    """Alert that malicious content was injected"""
    console.print(
        Panel(
            "[bold red]⚠️  MALICIOUS PAYLOAD DETECTED IN SEARCH RESULTS[/bold red]\n\n"
            "The 'search results' contain hidden instructions trying to trick the LLM into:\n"
            " • Sending data to http://evil.example.com (exfiltration)\n"
            " • Reading /etc/passwd and SSH keys (path traversal)\n"
            " • Granting excessive permissions when delegating (escalation)\n\n"
            "[dim]Watch what happens when the LLM tries to follow these instructions...[/dim]",
            title="🎭 PROMPT INJECTION ATTACK",
            border_style="red",
            box=box.HEAVY,
        )
    )


def print_learning(title: str, text: str):
    """Highlight a security concept"""
    console.print(
        Panel(f"[italic]{text}[/italic]", title=f"🎓 KEY INSIGHT: {title}", border_style="yellow", box=box.ROUNDED)
    )


def print_agent_thought(text: str):
    console.print(f"[dim]💭 Agent:[/dim] {text}")


def print_demo_intro():
    """Print introduction explaining what the demo shows"""
    console.print(
        Panel(
            "[bold]This demo shows how Tenuo protects AI agents from prompt injection attacks.[/bold]\n\n"
            "The scenario:\n"
            "1. A Research Agent searches for papers (search results contain hidden malicious instructions)\n"
            "2. The LLM may try to follow these malicious instructions\n"
            "3. Tenuo's warrant system BLOCKS any unauthorized actions\n\n"
            "[yellow]Key concept:[/yellow] Even if the LLM is 'jailbroken', it can only do what the warrant allows.",
            title="🎯 DEMO: Capability-Based Security vs Prompt Injection",
            border_style="magenta",
            box=box.DOUBLE,
        )
    )


def print_demo_summary(blocked_count: int, allowed_count: int):
    """Print summary at the end of the demo"""
    console.print(
        Panel(
            f"[bold green]✅ Allowed actions:[/bold green] {allowed_count}\n"
            f"[bold red]⛔ Blocked actions:[/bold red] {blocked_count}\n\n"
            "[bold]The warrant enforced security boundaries regardless of what the LLM tried to do.[/bold]\n\n"
            "Learn more: https://tenuo.ai",
            title="📊 DEMO SUMMARY",
            border_style="magenta",
        )
    )
