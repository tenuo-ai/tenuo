"""
Tenuo Google ADK - Developer Experience Helpers

Utilities for debugging, visualization, and easier integration.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from tenuo_core import Warrant


# =============================================================================
# Internal Helpers
# =============================================================================


def _suggest_similar(name: str, candidates: List[str], threshold: int = 3) -> Optional[str]:
    """
    Suggest a similar name from candidates using edit distance.

    Returns the closest match if edit distance <= threshold, else None.
    """
    if not candidates:
        return None

    def edit_distance(s1: str, s2: str) -> int:
        """Simple Levenshtein distance."""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    best_match = None
    best_distance = threshold + 1

    for candidate in candidates:
        dist = edit_distance(name.lower(), candidate.lower())
        if dist < best_distance:
            best_distance = dist
            best_match = candidate

    return best_match if best_distance <= threshold else None


# =============================================================================
# chain_callbacks - Compose multiple ADK callbacks
# =============================================================================


def chain_callbacks(*callbacks: Callable) -> Callable:
    """
    Chain multiple before_tool_callbacks. First non-None return wins.

    ADK only allows one callback per hook. This utility lets you compose multiple.
    Supports both sync and async callbacks.

    Usage:
        from tenuo.google_adk import TenuoGuard, chain_callbacks

        guard = TenuoGuard(warrant=w, signing_key=k)

        agent = Agent(
            tools=[...],
            before_tool_callback=chain_callbacks(
                guard.before_tool,
                my_custom_logger,
                rate_limiter.check,
            ),
        )

    Args:
        *callbacks: Functions with signature (tool, args, tool_context) -> Optional[Dict]
                   Can be sync or async functions.

    Returns:
        Combined callback that runs each in order, short-circuiting on first denial.
        Returns async function if any callback is async.
    """
    import inspect

    # Check if any callback is async
    has_async = any(inspect.iscoroutinefunction(cb) for cb in callbacks)

    if has_async:

        async def chained_async(tool: Any, args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
            for cb in callbacks:
                if inspect.iscoroutinefunction(cb):
                    result = await cb(tool, args, tool_context)
                else:
                    result = cb(tool, args, tool_context)
                if result is not None:
                    return result  # Short-circuit on first denial
            return None

        return chained_async
    else:

        def chained_sync(tool: Any, args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
            for cb in callbacks:
                result = cb(tool, args, tool_context)
                if result is not None:
                    return result  # Short-circuit on first denial
            return None

        return chained_sync


# =============================================================================
# explain_denial - Rich denial explanations
# =============================================================================


def explain_denial(
    result: Dict[str, Any],
    *,
    file: Any = None,
    color: bool = True,
) -> None:
    """
    Print a rich, human-readable explanation of a denial.

    Usage:
        result = guard.before_tool(tool, args, ctx)
        if result:
            explain_denial(result)

    Args:
        result: The denial dict returned by TenuoGuard.before_tool()
        file: Output file (default: sys.stderr)
        color: Whether to use ANSI colors (default: True if terminal)
    """
    if file is None:
        file = sys.stderr

    # Detect if we should use colors
    use_color = color and hasattr(file, "isatty") and file.isatty()

    def red(s: str) -> str:
        return f"\033[91m{s}\033[0m" if use_color else s

    def yellow(s: str) -> str:
        return f"\033[93m{s}\033[0m" if use_color else s

    def dim(s: str) -> str:
        return f"\033[90m{s}\033[0m" if use_color else s

    def bold(s: str) -> str:
        return f"\033[1m{s}\033[0m" if use_color else s

    error = result.get("error", "unknown")
    message = result.get("message", "No message")
    details = result.get("details")
    hints = result.get("hints", [])

    print(file=file)
    print(red("❌ Authorization Denied"), file=file)
    print(file=file)
    print(f"  {bold('Error:')} {error}", file=file)
    print(f"  {bold('Message:')} {message}", file=file)

    if details:
        print(file=file)
        print(f"  {bold('Details:')}", file=file)
        print(f"    {details}", file=file)

    if hints:
        print(file=file)
        print(f"  {yellow('💡 Suggestions:')}", file=file)
        for hint in hints:
            print(f"    • {hint}", file=file)

    print(file=file)


# =============================================================================
# visualize_warrant - Display warrant capabilities
# =============================================================================


def visualize_warrant(
    warrant: "Warrant",
    *,
    file: Any = None,
    show_constraints: bool = True,
) -> None:
    """
    Print a visual representation of warrant capabilities.

    Usage:
        from tenuo.google_adk import visualize_warrant
        visualize_warrant(my_warrant)

    Args:
        warrant: The warrant to visualize
        file: Output file (default: sys.stdout)
        show_constraints: Whether to show constraint details
    """
    if file is None:
        file = sys.stdout

    # Extract warrant info
    jti: Any = getattr(warrant, "jti", None) or getattr(warrant, "id", "unknown")
    if jti is not None and hasattr(jti, "hex"):
        jti = jti.hex()[:16] + "..."
    elif len(str(jti)) > 20:
        jti = str(jti)[:16] + "..."

    exp = getattr(warrant, "exp", None)
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        remaining = exp_dt - now
        if remaining.total_seconds() > 0:
            mins = int(remaining.total_seconds() // 60)
            exp_str = f"{exp_dt.strftime('%Y-%m-%d %H:%M:%S')} ({mins}m left)"
        else:
            exp_str = f"{exp_dt.strftime('%Y-%m-%d %H:%M:%S')} (EXPIRED)"
    else:
        exp_str = "No expiry"

    # Get skills
    skills = {}

    # Try capabilities first (new format)
    caps = getattr(warrant, "capabilities", {})
    if caps:
        for skill, constraints in caps.items():
            skills[skill] = constraints if isinstance(constraints, dict) else {}

    # Try grants (intermediate format)
    grants = getattr(warrant, "grants", [])
    for grant in grants:
        if isinstance(grant, dict):
            skill = grant.get("skill")
            if skill:
                skills[skill] = grant.get("constraints", {})
        elif isinstance(grant, str):
            skills[grant] = {}

    # Try tools (legacy format)
    tools_attr = getattr(warrant, "tools", [])
    for tool in tools_attr:
        if tool not in skills:
            skills[tool] = {}

    # Print
    width = 50
    print("┌" + "─" * width + "┐", file=file)
    print(f"│ {'Warrant: ' + str(jti):<{width}} │", file=file)
    print(f"│ {'Expires: ' + exp_str:<{width}} │", file=file)
    print("├" + "─" * width + "┤", file=file)
    print(f"│ {'Skills:':<{width}} │", file=file)

    if skills:
        for skill, constraints in skills.items():
            print(f"│   ✓ {skill:<{width - 5}} │", file=file)
            if show_constraints and constraints:
                for param, constraint in constraints.items():
                    if param.startswith("_"):
                        continue
                    constraint_str = _format_constraint(constraint)
                    line = f"└─ {param}: {constraint_str}"
                    if len(line) > width - 5:
                        line = line[: width - 8] + "..."
                    print(f"│     {line:<{width - 5}} │", file=file)
    else:
        print(f"│   {'(no skills granted)':<{width - 3}} │", file=file)

    print("└" + "─" * width + "┘", file=file)


def _format_constraint(constraint: Any) -> str:
    """Format a constraint for display."""
    name = type(constraint).__name__

    # Try common attribute patterns
    if hasattr(constraint, "root"):
        return f'{name}("{constraint.root}")'
    if hasattr(constraint, "allow_domains"):
        domains = getattr(constraint, "allow_domains", [])
        if len(domains) <= 2:
            return f"{name}({domains})"
        return f"{name}([{domains[0]!r}, ...+{len(domains) - 1}])"
    if hasattr(constraint, "pattern"):
        return f'{name}("{constraint.pattern}")'
    if hasattr(constraint, "values"):
        vals = list(constraint.values)[:2]
        return f"{name}({vals}...)"
    if hasattr(constraint, "min") or hasattr(constraint, "max"):
        min_v = getattr(constraint, "min", None)
        max_v = getattr(constraint, "max", None)
        return f"{name}({min_v}, {max_v})"

    return name


# =============================================================================
# suggest_skill_mapping - Safe skill inference with warnings
# =============================================================================


def suggest_skill_mapping(
    tools: List[Callable],
    warrant: "Warrant",
    *,
    verbose: bool = True,
) -> Dict[str, str]:
    """
    Suggest skill mappings based on tool names.

    ⚠️ SECURITY WARNING: This is a SUGGESTION ONLY. Always review the mapping
    before using it. Auto-mapping could allow unintended access if tool names
    happen to match skill names.

    Usage:
        suggested = suggest_skill_mapping(tools, warrant)
        # Review the mapping!
        print(suggested)
        # Then use it explicitly:
        guard = TenuoGuard(warrant=w, signing_key=k, skill_map=suggested)

    Args:
        tools: List of tool functions to analyze
        warrant: The warrant to match against
        verbose: Print suggestions to stderr

    Returns:
        Dict mapping tool names to suggested skill names
    """
    granted_skills: set[str] = set()

    # Extract skills from warrant
    caps = getattr(warrant, "capabilities", {})
    if caps:
        granted_skills.update(caps.keys())

    grants = getattr(warrant, "grants", [])
    for grant in grants:
        if isinstance(grant, dict):
            skill = grant.get("skill")
            if skill:
                granted_skills.add(skill)
        elif isinstance(grant, str):
            granted_skills.add(grant)

    tools_attr = getattr(warrant, "tools", [])
    granted_skills.update(tools_attr)

    # Generate suggestions
    suggestions: Dict[str, str] = {}
    unmatched: List[str] = []

    for tool in tools:
        tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))

        # Try exact match first
        if tool_name in granted_skills:
            suggestions[tool_name] = tool_name
            continue

        # Try common suffix patterns
        candidates = []
        for suffix in ["_tool", "_func", "_action", "_handler"]:
            if tool_name.endswith(suffix):
                base = tool_name[: -len(suffix)]
                if base in granted_skills:
                    candidates.append(base)

        # Try common prefix patterns
        for prefix in ["tool_", "func_", "do_", "handle_"]:
            if tool_name.startswith(prefix):
                base = tool_name[len(prefix) :]
                if base in granted_skills:
                    candidates.append(base)

        if candidates:
            # Use first match (most specific)
            suggestions[tool_name] = candidates[0]
        else:
            unmatched.append(tool_name)

    if verbose:
        import sys

        print("\n⚠️  SKILL MAPPING SUGGESTIONS (review before using!)\n", file=sys.stderr)

        if suggestions:
            print("Matched:", file=sys.stderr)
            for tool_name, skill_name in suggestions.items():
                print(f"  {tool_name} → {skill_name}", file=sys.stderr)

        if unmatched:
            print("\nUnmatched (need manual mapping):", file=sys.stderr)
            for tool_name in unmatched:
                print(f"  {tool_name} → ???", file=sys.stderr)

        print("\nAvailable skills in warrant:", file=sys.stderr)
        for skill in sorted(granted_skills):
            print(f"  - {skill}", file=sys.stderr)

        print(
            "\n🔒 Security Note: Always verify mappings before use.\n"
            "   Incorrect mappings could grant unintended access.\n",
            file=sys.stderr,
        )

    return suggestions


# =============================================================================
# ScopedWarrantContext - Context manager for dynamic warrants
# =============================================================================


@contextmanager
def scoped_warrant(
    state: Dict[str, Any],
    warrant: "Warrant",
    *,
    key: str = "tenuo_warrant",
    agent_name: Optional[str] = None,
):
    """
    Context manager for temporary warrant injection.

    Automatically cleans up the warrant from state when done.
    Optionally wraps in ScopedWarrant for multi-agent safety.

    Usage:
        with scoped_warrant(session.state, my_warrant, agent_name="researcher"):
            result = await agent.run(query)
        # Warrant automatically removed from state

    Args:
        state: The state dict to inject warrant into
        warrant: The warrant to inject
        key: State key to use (default: "tenuo_warrant")
        agent_name: If provided, wraps in ScopedWarrant for multi-agent safety
    """
    from .plugin import ScopedWarrant

    try:
        if agent_name:
            state[key] = ScopedWarrant(warrant, agent_name)
        else:
            state[key] = warrant
        yield
    finally:
        state.pop(key, None)


# =============================================================================
# generate_hints - Generate recovery hints for denials
# =============================================================================


def generate_hints(
    tool_name: str,
    args: Dict[str, Any],
    warrant: Optional["Warrant"] = None,
    constraint_param: Optional[str] = None,
    constraint: Optional[Any] = None,
) -> List[str]:
    """
    Generate helpful hints for recovering from a denial.

    Args:
        tool_name: The denied tool name
        args: The arguments that were denied
        warrant: Optional warrant for context
        constraint_param: The parameter that violated the constraint
        constraint: The constraint that was violated

    Returns:
        List of hint strings
    """
    hints = []

    if constraint_param and constraint:
        constraint_type = type(constraint).__name__

        if constraint_type == "Subpath":
            root = getattr(constraint, "root", "/data")
            hints.append(f"Path must be under {root}/")
            hints.append(f"Try: {root}/your_file.txt")

        elif constraint_type == "UrlSafe":
            domains = getattr(constraint, "allow_domains", [])
            if domains:
                hints.append(f"URL must be from allowed domains: {domains[:3]}")
                hints.append(f"Try: https://{domains[0]}/path")
            else:
                hints.append("URL must not target private IPs or metadata endpoints")

        elif constraint_type == "Shlex":
            bins = getattr(constraint, "allowed_bins", [])
            if bins:
                hints.append(f"Only these binaries are allowed: {list(bins)[:5]}")
            hints.append("Shell operators (;, |, &) are not allowed")

        elif constraint_type == "Pattern":
            pattern = getattr(constraint, "pattern", "*")
            hints.append(f"Value must match pattern: {pattern}")

        elif constraint_type == "Range":
            min_v = getattr(constraint, "min", None)
            max_v = getattr(constraint, "max", None)
            if min_v is not None and max_v is not None:
                hints.append(f"Value must be between {min_v} and {max_v}")
            elif max_v is not None:
                hints.append(f"Value must be at most {max_v}")
            elif min_v is not None:
                hints.append(f"Value must be at least {min_v}")

        elif constraint_type == "OneOf":
            values = getattr(constraint, "values", [])
            hints.append(f"Value must be one of: {list(values)[:5]}")

    if warrant:
        # Suggest what IS allowed
        granted: list[str] = []
        caps = getattr(warrant, "capabilities", {})
        if caps:
            granted.extend(caps.keys())
        tools_attr = getattr(warrant, "tools", [])
        granted.extend(tools_attr)

        if granted and tool_name not in granted:
            hints.append(f"Warrant has skills: {granted[:5]}")
            # Try to suggest similar skill name
            suggestion = _suggest_similar(tool_name, granted)
            if suggestion:
                hints.append(f"Did you mean '{suggestion}'?")
                hints.append(f'Fix: .map_skill("{tool_name}", "{suggestion}")')
        elif not granted:
            hints.append("Warrant has no tools granted")

    if not hints:
        hints.append("Contact your administrator for elevated permissions")

    return hints


# =============================================================================
# Zero-Config Entry Point
# =============================================================================


def protect_agent(
    agent: Any,
    *,
    allow: Optional[List[str]] = None,
) -> Any:
    """
    Add Tenuo protection to a Google ADK agent. Zero configuration required.

    This is the simplest way to add Tenuo to your ADK agent.
    It provides "fail-closed" security: only explicitly allowed tools can run.

    Args:
        agent: Google ADK Agent instance
        allow: List of allowed tool names.
               If not provided, ALL tools are denied by default.

    Returns:
        The same agent, now protected by Tenuo

    Example - Quick Start::

        from google.adk import Agent
        from tenuo.google_adk import protect_agent

        agent = protect_agent(
            Agent(tools=[search, read_file, shell]),
            allow=["search", "read_file"]  # shell is denied
        )

    Example - With Constraints::

        from tenuo.google_adk import GuardBuilder
        from tenuo.constraints import Subpath

        # For constraints, use GuardBuilder:
        guard = (GuardBuilder()
            .allow("search")
            .allow("read_file", path=Subpath("/data"))
            .build())

        agent = Agent(
            tools=[search, read_file],
            before_tool_callback=guard.before_tool,
        )

    Next Steps:
        - Add constraints: GuardBuilder().allow("tool", param=Constraint)
        - Add warrants: GuardBuilder().with_warrant(warrant, key)
        - See docs: https://tenuo.ai/docs/google-adk
    """
    from .guard import GuardBuilder

    if allow is None:
        allow = []

    # Build guard with allowlist
    builder = GuardBuilder()
    for tool_name in allow:
        builder.allow(tool_name)

    guard = builder.build()

    # Attach to agent
    # ADK agents have before_tool_callback attribute
    existing_callback = getattr(agent, "before_tool_callback", None)

    if existing_callback:
        # Chain with existing callback
        agent.before_tool_callback = chain_callbacks(guard.before_tool, existing_callback)
    else:
        agent.before_tool_callback = guard.before_tool

    return agent
