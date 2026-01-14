"""
A2A Developer Experience Helpers.

This module provides debugging, visualization, and diagnostic tools
for working with A2A warrants and delegation chains.

Usage:
    from tenuo.a2a import explain, visualize_chain, dry_run

    # Explain an A2A error
    try:
        await client.send_task(...)
    except A2AError as e:
        explain(e)

    # Visualize a delegation chain
    print(visualize_chain([root_warrant, delegated_warrant, leaf_warrant]))

    # Test authorization without executing
    result = await server.dry_run(warrant, "read_file", {"path": "/tmp/test"})
"""

from typing import Any, Dict, List, Optional, TextIO
import sys


# =============================================================================
# Error Explanation
# =============================================================================


def explain(
    error: Exception,
    *,
    file: Optional[TextIO] = None,
    show_context: bool = True,
) -> None:
    """
    Print a detailed, actionable explanation of an A2A error.

    Provides human-readable diagnostics with fix suggestions.

    Args:
        error: The A2AError to explain
        file: Output file (defaults to sys.stderr)
        show_context: Whether to show error context dict

    Example:
        from tenuo.a2a import A2AClient, explain

        try:
            await client.send_task(...)
        except Exception as e:
            explain(e)
            # Output:
            # ❌ Constraint Violation
            #
            # Parameter 'path' failed Subpath constraint.
            #
            # Suggestions:
            #   - Ensure path is under the allowed root directory
            #   - Check warrant constraints match your request
    """
    from .errors import (
        A2AError,
        MissingWarrantError,
        InvalidSignatureError,
        UntrustedIssuerError,
        WarrantExpiredError,
        AudienceMismatchError,
        ReplayDetectedError,
        SkillNotFoundError,
        SkillNotGrantedError,
        ConstraintViolationError,
        ChainValidationError,
        PopRequiredError,
        PopVerificationError,
    )

    out = file or sys.stderr

    if not isinstance(error, A2AError):
        # Try the core tenuo explain for non-A2A errors
        try:
            from tenuo.explain import explain as core_explain

            core_explain(error, file=out, show_context=show_context)
        except ImportError:
            out.write(f"❌ Error: {error}\n")
        return

    # Header
    out.write(f"\n❌ {type(error).__name__}\n")
    out.write("=" * 50 + "\n\n")

    # Error-specific explanations
    if isinstance(error, MissingWarrantError):
        out.write("The server requires a warrant but none was provided.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Add X-Tenuo-Warrant header to your request\n")
        out.write("  - Pass warrant= parameter to send_task()\n")
        out.write("  - Check if the server has require_warrant=False for open endpoints\n")

    elif isinstance(error, InvalidSignatureError):
        out.write("The warrant's cryptographic signature is invalid.\n\n")
        out.write("This could mean:\n")
        out.write("  - The warrant was tampered with\n")
        out.write("  - The warrant was issued by a different key\n")
        out.write("  - The warrant is corrupted or truncated\n")

    elif isinstance(error, UntrustedIssuerError):
        out.write("The warrant's issuer is not in the server's trusted list.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Add the issuer's public key to trusted_issuers=[...]\n")
        out.write("  - Verify you're using the correct warrant for this server\n")

    elif isinstance(error, WarrantExpiredError):
        out.write("The warrant has expired.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Request a new warrant with a longer TTL\n")
        out.write("  - Check clock synchronization between client and server\n")

    elif isinstance(error, AudienceMismatchError):
        out.write("The warrant was issued for a different server.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Ensure the warrant's 'aud' field matches the server URL\n")
        out.write("  - Check for HTTP/HTTPS or port mismatches\n")

    elif isinstance(error, ReplayDetectedError):
        out.write("This warrant (jti) was already used.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Generate a new warrant with a unique jti\n")
        out.write("  - Don't retry requests with the same warrant\n")

    elif isinstance(error, SkillNotFoundError):
        out.write(f"The skill '{error.data.get('skill', '?')}' doesn't exist on this server.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Use client.discover() to list available skills\n")
        out.write("  - Check for typos in the skill name\n")

    elif isinstance(error, SkillNotGrantedError):
        out.write(f"The warrant doesn't grant access to skill '{error.data.get('skill', '?')}'.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Request a warrant that includes this skill\n")
        out.write("  - Check the warrant's grants/capabilities\n")

    elif isinstance(error, ConstraintViolationError):
        param = error.data.get("param", "?")
        constraint = error.data.get("constraint_type", "?")
        reason = error.data.get("reason", "")
        out.write(f"Parameter '{param}' failed {constraint} constraint.\n")
        if reason:
            out.write(f"Reason: {reason}\n")
        out.write("\nSuggestions:\n")
        out.write("  - Check the value satisfies the constraint\n")
        out.write("  - Use explain_constraint() for detailed analysis\n")
        out.write("  - Verify warrant constraints match your request\n")

    elif isinstance(error, ChainValidationError):
        out.write(f"Delegation chain validation failed: {error.message}\n\n")
        out.write("Suggestions:\n")
        out.write("  - Verify chain order is parent-first\n")
        out.write("  - Check each child's issuer matches parent's holder\n")
        out.write("  - Ensure child grants don't exceed parent grants\n")

    elif isinstance(error, PopRequiredError):
        out.write("This server requires Proof-of-Possession (PoP) signatures.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Pass signing_key= to send_task()\n")
        out.write("  - Ensure tenuo_core is installed for PoP support\n")

    elif isinstance(error, PopVerificationError):
        out.write("Proof-of-Possession signature verification failed.\n\n")
        out.write("Suggestions:\n")
        out.write("  - Ensure you're using the correct signing key\n")
        out.write("  - Verify arguments match what was signed\n")

    else:
        out.write(f"{error.message}\n")

    # Show context if requested
    if show_context and hasattr(error, "data") and error.data:
        out.write("\nContext:\n")
        for k, v in error.data.items():
            out.write(f"  {k}: {v}\n")

    out.write("\n")


def explain_str(error: Exception, show_context: bool = True) -> str:
    """
    Return explanation as a string instead of printing.

    Args:
        error: The A2AError to explain
        show_context: Whether to include error context

    Returns:
        Human-readable explanation string
    """
    import io

    buf = io.StringIO()
    explain(error, file=buf, show_context=show_context)
    return buf.getvalue()


# =============================================================================
# Chain Visualization
# =============================================================================


def visualize_chain(
    warrants: List[Any],
    *,
    use_rich: bool = True,
) -> str:
    """
    Visualize a delegation chain as a readable tree.

    Args:
        warrants: List of warrants in parent-first order
        use_rich: Try to use rich library for pretty output

    Returns:
        String representation of the chain

    Example:
        from tenuo.a2a import visualize_chain

        print(visualize_chain([root, orchestrator, agent]))
        # Output:
        # === Delegation Chain (3 warrants) ===
        #
        # 🌳 ROOT: a1b2c3d4... ✅ VALID
        #   Type: root
        #   Tools: delegate_search, fetch_url, read_file
        #   ↓ delegates to ↓
        #
        # 📄 LEVEL 1: e5f6g7h8... ✅ VALID
        #   Type: delegated
        #   Tools: fetch_url, read_file
        #   ↓ delegates to ↓
        #
        # 🍃 LEAF: i9j0k1l2... ✅ VALID
        #   Type: delegated
        #   Tools: read_file
        #   Constraints: path=Subpath('/tmp/papers')
    """
    if not warrants:
        return "Empty chain"

    # Try rich visualization first
    if use_rich:
        try:
            return _visualize_chain_rich(warrants)
        except ImportError:
            pass

    # Plain text fallback
    lines = [f"=== Delegation Chain ({len(warrants)} warrants) ===", ""]

    for i, warrant in enumerate(warrants):
        if i == 0:
            prefix = "🌳 ROOT"
        elif i == len(warrants) - 1:
            prefix = "🍃 LEAF"
        else:
            prefix = f"📄 LEVEL {i}"

        # Get warrant ID (handle different warrant types)
        warrant_id = _get_warrant_id(warrant)
        is_expired = _is_expired(warrant)

        status = "❌ EXPIRED" if is_expired else "✅ VALID"
        lines.append(f"{prefix}: {warrant_id[:16]}... {status}")

        # Type
        warrant_type = getattr(warrant, "warrant_type", getattr(warrant, "type", "unknown"))
        lines.append(f"  Type: {warrant_type}")

        # Tools
        tools = getattr(warrant, "tools", [])
        if tools:
            lines.append(f"  Tools: {', '.join(tools)}")

        # Grants (for leaf, show constraints)
        if i == len(warrants) - 1:
            grants = getattr(warrant, "grants", [])
            if grants:
                for grant in grants:
                    if isinstance(grant, dict) and "constraints" in grant:
                        skill = grant.get("skill", "?")
                        constraints = grant.get("constraints", {})
                        if constraints:
                            const_str = ", ".join(f"{k}={v}" for k, v in constraints.items())
                            lines.append(f"  Constraints ({skill}): {const_str}")

        if i < len(warrants) - 1:
            lines.append("  ↓ delegates to ↓")
        lines.append("")

    lines.append(f"Active warrant: {_get_warrant_id(warrants[-1])[:16]}...")
    return "\n".join(lines)


def _visualize_chain_rich(warrants: List[Any]) -> str:
    """Visualize chain using rich library."""
    from rich.console import Console
    from rich.tree import Tree
    from rich.text import Text
    import io

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True)

    root_warrant = warrants[0]
    root_id = _get_warrant_id(root_warrant)
    is_expired = _is_expired(root_warrant)

    root_status = "❌" if is_expired else "✅"
    root_text = Text(
        f"{root_status} ROOT: {root_id[:8]}...",
        style="bold green" if not is_expired else "bold red",
    )
    warrant_type = getattr(root_warrant, "warrant_type", "?")
    root_text.append(f" ({warrant_type})", style="yellow")

    tree = Tree(root_text)
    current = tree

    for i, warrant in enumerate(warrants[1:], 1):
        warrant_id = _get_warrant_id(warrant)
        is_exp = _is_expired(warrant)
        is_leaf = i == len(warrants) - 1
        prefix = "🍃 LEAF" if is_leaf else f"Level {i}"

        status = "❌ EXPIRED" if is_exp else "✅ VALID"
        node_text = Text(f"{prefix}: {warrant_id[:8]}... ", style="bold cyan" if is_leaf else "cyan")
        node_text.append(status, style="green" if not is_exp else "red")

        wtype = getattr(warrant, "warrant_type", "?")
        node_text.append(f" ({wtype})", style="yellow")

        current = current.add(node_text)

        # Add tools for leaf
        if is_leaf:
            tools = getattr(warrant, "tools", [])
            if tools:
                current.add(f"Tools: {', '.join(tools)}")

    console.print(tree)
    return buf.getvalue()


def _get_warrant_id(warrant: Any) -> str:
    """Get warrant ID from various warrant types."""
    for attr in ["id", "jti", "warrant_id"]:
        val = getattr(warrant, attr, None)
        if val:
            return str(val)
    return "unknown"


def _is_expired(warrant: Any) -> bool:
    """Check if warrant is expired."""
    is_expired = getattr(warrant, "is_expired", None)
    if callable(is_expired):
        return is_expired()
    if isinstance(is_expired, bool):
        return is_expired
    return False


# =============================================================================
# Dry Run
# =============================================================================


async def dry_run(
    server: "A2AServer",  # noqa: F821
    warrant: Any,
    skill: str,
    arguments: Optional[Dict[str, Any]] = None,
    *,
    warrant_chain: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Test if a warrant would authorize a skill call without executing.

    This is useful for:
    - Debugging authorization issues
    - Pre-flight checks before making real requests
    - Testing constraint configurations

    Args:
        server: The A2AServer instance
        warrant: The warrant to test (Warrant object or base64 string)
        skill: The skill to test
        arguments: Arguments to test against constraints
        warrant_chain: Optional delegation chain (semicolon-separated JWTs)

    Returns:
        Dict with 'allowed' bool and optional 'reason' on failure

    Example:
        from tenuo.a2a import A2AServer, dry_run

        server = A2AServer(...)

        result = await dry_run(
            server,
            warrant=my_warrant,
            skill="read_file",
            arguments={"path": "/tmp/test.txt"}
        )

        if result["allowed"]:
            print("✅ Would be authorized")
        else:
            print(f"❌ Denied: {result['reason']}")
    """
    from .errors import A2AError

    # Convert string warrant to base64 token
    if hasattr(warrant, "to_base64"):
        warrant_token = warrant.to_base64()
    else:
        warrant_token = str(warrant)

    args = arguments or {}

    try:
        # Use the server's validate_warrant method
        await server.validate_warrant(
            warrant_token=warrant_token,
            skill_id=skill,
            arguments=args,
            warrant_chain=warrant_chain,
        )
        return {"allowed": True}
    except A2AError as e:
        return {
            "allowed": False,
            "reason": str(e),
            "error_type": type(e).__name__,
            "data": e.data,
        }
    except Exception as e:
        return {
            "allowed": False,
            "reason": str(e),
            "error_type": type(e).__name__,
        }


# =============================================================================
# Simulate with Trace
# =============================================================================


class SimulationStep:
    """A step in the simulation trace."""

    def __init__(self, name: str, passed: bool, detail: str = ""):
        self.name = name
        self.passed = passed
        self.detail = detail
        self.children: List["SimulationStep"] = []

    def add(self, name: str, passed: bool, detail: str = "") -> "SimulationStep":
        child = SimulationStep(name, passed, detail)
        self.children.append(child)
        return child


class SimulationTrace:
    """Detailed trace of a simulation run."""

    def __init__(self, skill: str, arguments: Dict[str, Any]):
        self.skill = skill
        self.arguments = arguments
        self.steps: List[SimulationStep] = []
        self.result: Optional[str] = None
        self.error_type: Optional[str] = None

    def step(self, name: str, passed: bool, detail: str = "") -> SimulationStep:
        s = SimulationStep(name, passed, detail)
        self.steps.append(s)
        return s

    def __str__(self) -> str:
        """Render the trace as a tree."""
        args_str = ", ".join(f'{k}="{v}"' for k, v in self.arguments.items())
        lines = [f"Simulation: {self.skill}({args_str})"]

        for i, step in enumerate(self.steps):
            is_last = i == len(self.steps) - 1
            prefix = "└──" if is_last else "├──"
            icon = "✓" if step.passed else "✗"
            status = "" if step.passed else " FAILED"

            line = f"{prefix} [{icon}] {step.name}{status}"
            if step.detail:
                line += f": {step.detail}"
            lines.append(line)

            # Render children
            for j, child in enumerate(step.children):
                child_is_last = j == len(step.children) - 1
                indent = "    " if is_last else "│   "
                child_prefix = "└──" if child_is_last else "├──"

                cline = f"{indent}{child_prefix} {child.name}"
                if child.detail:
                    cline += f": {child.detail}"
                lines.append(cline)

        # Result
        lines.append("")
        if self.result == "ALLOWED":
            lines.append("└── Result: ✅ ALLOWED")
        else:
            lines.append(f"└── Result: ❌ DENIED ({self.error_type})")

        return "\n".join(lines)


async def simulate(
    server: "A2AServer",  # noqa: F821
    warrant: Any,
    skill: str,
    arguments: Optional[Dict[str, Any]] = None,
    *,
    warrant_chain: Optional[str] = None,
) -> SimulationTrace:
    """
    Simulate authorization with a detailed trace.

    Unlike dry_run() which returns pass/fail, simulate() returns a
    detailed trace showing exactly which step passed or failed.

    Args:
        server: The A2AServer instance
        warrant: The warrant to test (Warrant object or base64 string)
        skill: The skill to test
        arguments: Arguments to test against constraints
        warrant_chain: Optional delegation chain (semicolon-separated JWTs)

    Returns:
        SimulationTrace with detailed step-by-step results

    Example:
        trace = await simulate(server, warrant, "read_file", {"path": "/tmp/test"})
        print(trace)
        # Output:
        # Simulation: read_file(path="/tmp/test")
        # ├── [✓] Warrant signature valid
        # ├── [✓] Issuer trusted: did:key:z6Mk...
        # ├── [✓] Audience matches: https://research.example.com
        # ├── [✓] Not expired (4h 23m remaining)
        # ├── [✓] JTI not replayed
        # ├── [✓] Skill 'read_file' granted
        # ├── [✗] Constraint 'path' FAILED
        # │   ├── Server constraint: Subpath("/data/papers")
        # │   ├── Value: "/tmp/test"
        # │   └── Reason: Path not under root
        #
        # └── Result: ❌ DENIED (constraint_violation)
    """

    args = arguments or {}
    trace = SimulationTrace(skill, args)

    # Convert warrant to token
    if hasattr(warrant, "to_base64"):
        warrant_token = warrant.to_base64()
    else:
        warrant_token = str(warrant)

    # Step 1: Parse and verify signature
    try:
        from tenuo_core import Warrant as CoreWarrant

        parsed_warrant = CoreWarrant(warrant_token)
        trace.step("Warrant signature valid", True)
    except Exception as e:
        trace.step("Warrant signature valid", False, str(e))
        trace.result = "DENIED"
        trace.error_type = "invalid_signature"
        return trace

    # Step 2: Check issuer trust
    warrant_issuer = getattr(parsed_warrant, "issuer", None)
    trusted = False
    if hasattr(server, "_is_trusted_issuer"):
        try:
            trusted = server._is_trusted_issuer(warrant_issuer)
        except Exception:
            pass
    else:
        # Fallback: check trusted_issuers list
        trusted_issuers = getattr(server, "trusted_issuers", [])
        trusted = warrant_issuer in trusted_issuers if warrant_issuer else False

    issuer_str = str(warrant_issuer)[:20] + "..." if warrant_issuer else "unknown"
    trace.step("Issuer trusted", trusted, issuer_str)
    if not trusted:
        trace.result = "DENIED"
        trace.error_type = "untrusted_issuer"
        return trace

    # Step 3: Check audience
    server_url = getattr(server, "url", "")
    warrant_aud = getattr(parsed_warrant, "audience", None)
    aud_matches = not warrant_aud or warrant_aud == server_url
    trace.step("Audience matches", aud_matches, server_url if aud_matches else f"expected {warrant_aud}")
    if not aud_matches:
        trace.result = "DENIED"
        trace.error_type = "audience_mismatch"
        return trace

    # Step 4: Check expiry
    is_expired = False
    ttl_info = ""
    if hasattr(parsed_warrant, "is_expired"):
        is_expired = parsed_warrant.is_expired() if callable(parsed_warrant.is_expired) else parsed_warrant.is_expired
    if hasattr(parsed_warrant, "ttl_remaining"):
        ttl_info = f"{parsed_warrant.ttl_remaining} remaining"

    trace.step("Not expired", not is_expired, ttl_info if not is_expired else "expired")
    if is_expired:
        trace.result = "DENIED"
        trace.error_type = "expired"
        return trace

    # Step 5: Check replay (if enabled)
    if getattr(server, "check_replay", True):
        getattr(parsed_warrant, "id", getattr(parsed_warrant, "jti", None))
        # We can't actually check replay without modifying state, so assume pass for simulation
        trace.step("JTI not replayed", True, "simulation mode - no actual check")

    # Step 6: Check skill granted
    tools = getattr(parsed_warrant, "tools", [])
    skill_granted = skill in tools
    trace.step(f"Skill '{skill}' granted", skill_granted, f"tools: {', '.join(tools)}" if tools else "no tools")
    if not skill_granted:
        trace.result = "DENIED"
        trace.error_type = "skill_not_granted"
        return trace

    # Step 7: Check constraints
    skill_def = server._skills.get(skill) if hasattr(server, "_skills") else None
    if skill_def and hasattr(skill_def, "constraints") and skill_def.constraints:
        for param, constraint in skill_def.constraints.items():
            value = args.get(param)
            if value is None:
                continue

            # Check constraint
            passed = False
            reason = ""
            try:
                if hasattr(constraint, "contains"):
                    passed = constraint.contains(value)
                    reason = "Subpath check"
                elif hasattr(constraint, "is_safe"):
                    passed = constraint.is_safe(value)
                    reason = "UrlSafe check"
                elif hasattr(constraint, "matches"):
                    passed = constraint.matches(value)
                    reason = "Shlex check"
                else:
                    passed = True
                    reason = "Unknown constraint type"
            except Exception as e:
                passed = False
                reason = str(e)

            step = trace.step(f"Constraint '{param}'", passed)
            step.add("Server constraint", True, str(constraint))
            step.add("Value", True, str(value))
            if not passed:
                step.add("Reason", False, reason if reason else "Constraint failed")
                trace.result = "DENIED"
                trace.error_type = "constraint_violation"
                return trace

    # All checks passed
    trace.result = "ALLOWED"
    return trace


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "explain",
    "explain_str",
    "visualize_chain",
    "dry_run",
    "simulate",
    "SimulationTrace",
]
