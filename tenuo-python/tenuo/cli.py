"""
Tenuo CLI Tools.

Commands:
    tenuo init        - Initialize a new Tenuo project
    tenuo mint        - Create a test warrant
    tenuo decode      - Decode and inspect a warrant
    tenuo validate    - Check if a tool call would be authorized
    tenuo discover    - Analyze logs and generate capability definitions

Usage:
    tenuo init
    tenuo mint --tool read_file --tool search --ttl 1h
    tenuo decode <warrant_base64>
    tenuo validate <warrant> --tool read_file --args '{"path": "/data/x.txt"}'
    tenuo discover --input audit.log --output capabilities.yaml
"""

import argparse
import json
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from pathlib import Path


def discover_capabilities(
    log_file: Optional[str] = None,
    log_lines: Optional[List[str]] = None,
    output_format: str = "yaml",
) -> str:
    """
    Analyze audit logs and generate capability definitions.

    Reads structured JSON audit logs and infers the minimal set of
    capabilities needed to authorize all observed tool calls.

    Args:
        log_file: Path to audit log file (JSON lines format)
        log_lines: List of log lines (alternative to file)
        output_format: "yaml" or "python"

    Returns:
        Generated capability definitions
    """
    # Collect all tool calls
    tool_calls: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    lines = log_lines or []
    if log_file:
        with open(log_file, 'r') as f:
            lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Look for authorization events
        tool = entry.get('tool')
        constraints = entry.get('constraints', {})
        event_type = entry.get('event_type', '')

        if tool and 'authorization' in event_type.lower():
            tool_calls[tool].append(constraints)

    # Analyze and generate capabilities
    capabilities = _analyze_tool_calls(tool_calls)

    if output_format == "yaml":
        return _format_as_yaml(capabilities)
    else:
        return _format_as_python(capabilities)


def _analyze_tool_calls(tool_calls: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """
    Analyze tool calls and infer minimal constraints.

    Strategy:
    - If all values for a field are the same -> Exact
    - If values follow a pattern (e.g., "/data/*") -> Pattern
    - If values are from a small set -> OneOf
    - If values are numeric with a range -> Range
    - Otherwise -> Pattern("*") (permissive)
    """
    capabilities: Dict[str, Dict[str, Any]] = {}

    for tool, calls in tool_calls.items():
        if not calls:
            capabilities[tool] = {}
            continue

        # Collect all values for each field
        field_values: Dict[str, Set[Any]] = defaultdict(set)
        for call in calls:
            for field, value in call.items():
                if value is not None:
                    field_values[field].add(_normalize_value(value))

        # Infer constraints for each field
        constraints = {}
        for field, values in field_values.items():
            constraint = _infer_constraint(field, values)
            if constraint:
                constraints[field] = constraint

        capabilities[tool] = constraints

    return capabilities


def _normalize_value(value: Any) -> Any:
    """Normalize value for comparison."""
    if isinstance(value, (list, dict)):
        return str(value)
    return value


def _infer_constraint(field: str, values: Set[Any]) -> Optional[str]:
    """
    Infer the best constraint for a set of values.

    Returns constraint as a string representation.
    """
    if not values:
        return None

    values_list = list(values)

    # Single value -> Exact
    if len(values_list) == 1:
        val = values_list[0]
        if isinstance(val, str):
            return f'Exact("{val}")'
        return f'Exact({val})'

    # All strings
    if all(isinstance(v, str) for v in values_list):
        # Check for common prefix pattern
        prefix = _find_common_prefix(values_list)
        if prefix and len(prefix) > 3:
            return f'Pattern("{prefix}*")'

        # Small set -> OneOf
        if len(values_list) <= 10:
            quoted = [f'"{v}"' for v in sorted(values_list)]
            return f'OneOf([{", ".join(quoted)}])'

        # Default to wildcard
        return 'Pattern("*")'

    # All numbers
    if all(isinstance(v, (int, float)) for v in values_list):
        min_val = min(values_list)
        max_val = max(values_list)
        return f'Range({min_val}, {max_val})'

    # Mixed types - use wildcard
    return 'Pattern("*")'


def _find_common_prefix(strings: List[str]) -> str:
    """Find the longest common prefix among strings."""
    if not strings:
        return ""

    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""

    # Don't return partial words - find last separator
    for sep in ['/', '_', '-', '.']:
        if sep in prefix:
            idx = prefix.rfind(sep)
            if idx > 0:
                return prefix[:idx + 1]

    return prefix


def _format_as_yaml(capabilities: Dict[str, Dict[str, Any]]) -> str:
    """Format capabilities as YAML."""
    lines = ["# Generated by: tenuo discover", "# Review and adjust constraints as needed", "", "capabilities:"]

    for tool, constraints in sorted(capabilities.items()):
        lines.append(f"  - tool: {tool}")
        if constraints:
            lines.append("    constraints:")
            for field, constraint in sorted(constraints.items()):
                lines.append(f"      {field}: {constraint}")
        lines.append("")

    return "\n".join(lines)


def _format_as_python(capabilities: Dict[str, Dict[str, Any]]) -> str:
    """Format capabilities as Python code."""
    lines = [
        "# Generated by: tenuo discover",
        "# Review and adjust constraints as needed",
        "",
        "from tenuo import Capability, Pattern, Exact, OneOf, Range",
        "",
        "capabilities = [",
    ]

    for tool, constraints in sorted(capabilities.items()):
        if constraints:
            constraint_strs = [f"{k}={v}" for k, v in sorted(constraints.items())]
            lines.append(f'    Capability("{tool}", {", ".join(constraint_strs)}),')
        else:
            lines.append(f'    Capability("{tool}"),')

    lines.append("]")
    return "\n".join(lines)


def parse_kv_args(args: List[str]) -> Dict[str, Any]:
    """
    Parse key=value arguments.

    Args:
        args: List of "key=value" strings

    Returns:
        Dict of parsed arguments with auto-typed values
    """
    result: Dict[str, Any] = {}

    for arg in args:
        if '=' not in arg:
            continue
        key, value = arg.split('=', 1)

        # Auto-type conversion
        if value.lower() == 'true':
            result[key] = True
        elif value.lower() == 'false':
            result[key] = False
        elif value.isdigit():
            result[key] = int(value)
        else:
            try:
                result[key] = float(value)
            except ValueError:
                result[key] = value

    return result


def verify_warrant(warrant_str: str, tool: str, args: Dict[str, Any]) -> bool:
    """
    Verify if a warrant authorizes a tool call.

    Prints verification result and details.

    Args:
        warrant_str: Base64-encoded warrant
        tool: Tool name to verify
        args: Tool arguments

    Returns:
        True if authorized, False otherwise
    """
    try:
        from tenuo_core import Warrant

        warrant = Warrant(warrant_str)

        print(f"Verifying warrant for tool: {tool}")
        print(f"  Warrant ID: {warrant.id}")
        print(f"  Tools: {', '.join(warrant.tools)}")

        # Check expiry
        if warrant.is_expired():
            print("  ❌ DENIED: Warrant has expired")
            return False

        # Check tool in warrant
        if tool not in warrant.tools:
            print(f"  ❌ DENIED: Tool '{tool}' not in allowed tools: {warrant.tools}")
            return False

        # Check allows
        if hasattr(warrant, 'allows'):
            if not warrant.allows(tool, args):
                print("  ❌ DENIED: Arguments do not satisfy constraints")
                if hasattr(warrant, 'why_denied'):
                    why = warrant.why_denied(tool, args)
                    if hasattr(why, 'suggestion'):
                        print(f"  Suggestion: {why.suggestion}")
                return False

        print("  ✅ AUTHORIZED")
        return True

    except Exception as e:
        print(f"  ❌ ERROR: {e}")
        return False



def print_rich_warrant(warrant) -> bool:
    """
    Print warrant using rich if available.
    Returns True if rich output was used, False otherwise.
    """
    try:
        from rich.console import Console  # type: ignore[import-not-found]
        from rich.tree import Tree  # type: ignore[import-not-found]
        from rich.table import Table  # type: ignore[import-not-found]
        from rich.panel import Panel  # type: ignore[import-not-found]
        from rich.text import Text  # type: ignore[import-not-found]
    except ImportError:
        return False

    console = Console()

    # Root node
    status_icon = "❌" if warrant.is_expired() else "✅"
    term_icon = "🛑" if warrant.is_terminal() else "➡️"  # noqa: F841

    root_text = Text(f"{status_icon} Warrant {warrant.id[:8]}... ", style="bold green" if not warrant.is_expired() else "bold red")
    root_text.append(f"({warrant.warrant_type}) ", style="yellow")
    if warrant.is_expired():
        root_text.append("[EXPIRED] ", style="red reverse")
    if warrant.is_terminal():
        root_text.append("[TERMINAL]", style="blue reverse")

    tree = Tree(root_text)

    # Tools Table
    table = Table(title="Authorized Tools", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Constraints", style="green")

    # Try to get capabilities if available (property or manual)
    capabilities = getattr(warrant, 'capabilities', {})
    if not capabilities and warrant.tools:
        # Fallback if capabilities property not ready/populated
        for tool in warrant.tools:
             table.add_row(tool, "All allowed (or unknown)")
    else:
        for tool, constraints in capabilities.items():
            const_str = ", ".join([f"{k}={v}" for k, v in constraints.items()]) if constraints else "*"
            table.add_row(tool, const_str)

    tree.add(table)

    # Metadata
    meta = tree.add("Metadata")
    if hasattr(warrant, 'ttl_remaining'):
         meta.add(f"TTL: {warrant.ttl_remaining}")
    meta.add(f"Expires: {warrant.expires_at()}")
    if warrant.parent_hash:
        meta.add(f"Parent: {warrant.parent_hash[:16]}...")

    console.print(Panel(tree, title="Tenuo Authority Inspector", border_style="green"))
    return True


def print_warrant_stack(warrants) -> None:
    """
    Print a warrant chain with delegation flow (plain text).
    """
    print(f"=== Warrant Chain ({len(warrants)} warrants) ===\n")

    for i, warrant in enumerate(warrants):
        if i == 0:
            prefix = "🌳 ROOT"
        elif i == len(warrants) - 1:
            prefix = "🍃 LEAF"
        else:
            prefix = f"📄 LEVEL {i}"

        status = "❌ EXPIRED" if warrant.is_expired() else "✅ VALID"
        print(f"{prefix}: {warrant.id[:16]}... {status}")
        print(f"  Type: {warrant.warrant_type}")
        print(f"  Tools: {', '.join(warrant.tools)}")

        if i < len(warrants) - 1:
            print("  ↓ delegates to ↓")
        print()

    print(f"Active warrant: {warrants[-1].id[:16]}...")
    print("\n(Tip: Install 'rich' for a nicer visualization: pip install rich)")


def print_rich_warrant_stack(warrants) -> bool:
    """
    Print warrant stack using rich if available.
    Returns True if rich output was used, False otherwise.
    """
    try:
        from rich.console import Console  # type: ignore[import-not-found]
        from rich.tree import Tree  # type: ignore[import-not-found]
        from rich.panel import Panel  # type: ignore[import-not-found]
        from rich.text import Text  # type: ignore[import-not-found]
    except ImportError:
        return False

    console = Console()

    # Build tree from root to leaf
    root_warrant = warrants[0]
    root_status = "❌" if root_warrant.is_expired() else "✅"
    root_text = Text(f"{root_status} ROOT: {root_warrant.id[:8]}...",
                     style="bold green" if not root_warrant.is_expired() else "bold red")
    root_text.append(f" ({root_warrant.warrant_type})", style="yellow")

    tree = Tree(root_text)
    current = tree

    for i, warrant in enumerate(warrants[1:], 1):
        status = "❌ EXPIRED" if warrant.is_expired() else "✅ VALID"
        is_leaf = (i == len(warrants) - 1)
        prefix = "🍃 LEAF" if is_leaf else f"Level {i}"

        node_text = Text(f"{prefix}: {warrant.id[:8]}... ",
                        style="bold cyan" if is_leaf else "cyan")
        node_text.append(status, style="green" if not warrant.is_expired() else "red")
        node_text.append(f" ({warrant.warrant_type})", style="yellow")

        current = current.add(node_text)

    console.print(Panel(tree, title=f"Warrant Chain ({len(warrants)} warrants)",
                       border_style="green"))
    return True


def inspect_warrant(warrant_str: str) -> None:
    """
    Inspect a warrant or warrant stack and print human-readable details.

    Auto-detects whether the input is a single warrant or a stack.
    """
    try:
        from tenuo_core import Warrant, decode_warrant_stack_base64

        # Try to decode as stack first
        try:
            warrants = decode_warrant_stack_base64(warrant_str)
            if len(warrants) > 1:
                # It's a multi-warrant stack
                if print_rich_warrant_stack(warrants):
                    return
                print_warrant_stack(warrants)
                return
            elif len(warrants) == 1:
                # Single warrant in stack format, extract it
                warrant = warrants[0]
            else:
                raise ValueError("Empty warrant stack")
        except Exception:
            # Not a stack, try single warrant
            warrant = Warrant(warrant_str)

        # Display single warrant
        if print_rich_warrant(warrant):
            return

        # Fallback to plain text
        print("=== Warrant Inspection ===")
        print(f"ID: {warrant.id}")
        print(f"Type: {warrant.warrant_type}")
        print(f"Tools: {', '.join(warrant.tools)}")
        print(f"Expired: {warrant.is_expired()}")
        print(f"Terminal: {warrant.is_terminal()}")

        if hasattr(warrant, 'ttl_remaining'):
            print(f"TTL Remaining: {warrant.ttl_remaining}")

        if hasattr(warrant, 'explain'):
            print("")
            print("Explanation:")
            print(warrant.explain(include_chain=True))

        print("\n(Tip: Install 'rich' for a nicer visualization: pip install rich)")

    except Exception as e:
        print(f"Error inspecting warrant: {e}")


def decode_warrant(warrant_str: str) -> str:
    """Decode and display a warrant's contents."""
    # This function returns string, mainly used by 'decode' command which prints it.
    # Refactoring 'decode' command to use inspect_warrant instead for rich output.
    inspect_warrant(warrant_str)
    return ""  # Return empty string to satisfy signature or caller expect printing handled inside


def mint_warrant(tools: List[str], ttl: str = "1h") -> str:
    """
    Create a simple test warrant.

    Uses TENUO_ROOT_KEY from environment (set by `tenuo init`).

    Args:
        tools: List of tool names to authorize
        ttl: Time-to-live (e.g., "1h", "30m", "300s")

    Returns:
        Base64-encoded warrant string
    """
    import os
    import base64

    # Get key from environment
    key_b64 = os.environ.get("TENUO_ROOT_KEY")
    if not key_b64:
        print("❌ TENUO_ROOT_KEY not set. Run 'tenuo init' first or set manually.")
        sys.exit(1)

    try:
        from tenuo_core import SigningKey, Warrant

        # Decode key
        key_bytes = base64.b64decode(key_b64)
        key = SigningKey.from_bytes(key_bytes)

        # Parse TTL
        ttl_seconds = _parse_ttl(ttl)

        # Build warrant
        builder = Warrant.mint_builder()
        for tool in tools:
            builder = builder.tool(tool)
        builder = builder.ttl(ttl_seconds)
        builder = builder.holder(key.public_key)

        warrant = builder.mint(key)
        warrant_b64 = warrant.to_base64()

        return warrant_b64

    except Exception as e:
        print(f"❌ Failed to mint warrant: {e}")
        sys.exit(1)


def _parse_ttl(ttl: str) -> int:
    """Parse TTL string like '1h', '30m', '300s' to seconds."""
    ttl = ttl.strip().lower()

    if ttl.endswith('h'):
        return int(ttl[:-1]) * 3600
    elif ttl.endswith('m'):
        return int(ttl[:-1]) * 60
    elif ttl.endswith('s'):
        return int(ttl[:-1])
    else:
        # Assume seconds if no suffix
        return int(ttl)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Tenuo CLI Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # discover command
    discover_parser = subparsers.add_parser(
        "discover",
        help="Analyze audit logs and generate capability definitions",
    )
    discover_parser.add_argument(
        "--input", "-i",
        help="Path to audit log file (JSON lines format)",
        required=True,
    )
    discover_parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)",
    )
    discover_parser.add_argument(
        "--format", "-f",
        choices=["yaml", "python"],
        default="yaml",
        help="Output format (default: yaml)",
    )

    # decode command
    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode and inspect a warrant",
    )
    decode_parser.add_argument(
        "warrant",
        help="Base64-encoded warrant string",
    )

    # mint command
    mint_parser = subparsers.add_parser(
        "mint",
        help="Create a test warrant (uses TENUO_ROOT_KEY from env)",
    )
    mint_parser.add_argument(
        "--tool", "-t",
        action="append",
        dest="tools",
        required=True,
        help="Tool to authorize (repeatable)",
    )
    mint_parser.add_argument(
        "--ttl",
        default="1h",
        help="Time-to-live (default: 1h). Examples: 1h, 30m, 300s",
    )

    # validate command
    validate_parser = subparsers.add_parser(
        "validate",
        help="Check if a tool call would be authorized",
    )
    validate_parser.add_argument(
        "warrant",
        help="Base64-encoded warrant string",
    )
    validate_parser.add_argument(
        "--tool", "-t",
        required=True,
        help="Tool name to check",
    )
    validate_parser.add_argument(
        "--args", "-a",
        default="{}",
        help="Tool arguments as JSON (default: {})",
    )

    # init command
    subparsers.add_parser(
        "init",
        help="Initialize a new Tenuo project",
    )

    args = parser.parse_args()

    if args.command == "discover":
        result = discover_capabilities(
            log_file=args.input,
            output_format=args.format,
        )
        if args.output:
            Path(args.output).write_text(result)
            print(f"Wrote capabilities to {args.output}")
        else:
            print(result)

    elif args.command == "decode":
        decode_warrant(args.warrant)

    elif args.command == "mint":
        warrant = mint_warrant(args.tools, args.ttl)
        print(warrant)

    elif args.command == "validate":
        try:
            tool_args = json.loads(args.args)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON for --args: {e}")
            sys.exit(1)
        success = verify_warrant(args.warrant, args.tool, tool_args)
        sys.exit(0 if success else 1)

    elif args.command == "init":
        init_project()

    else:
        parser.print_help()
        sys.exit(1)


def init_project() -> None:
    """
    Initialize a new Tenuo project.

    Generates:
    - .env with TENUO_ROOT_KEY
    - tenuo_config.py with basics
    """
    import base64
    from tenuo_core import SigningKey

    print("🚀 Initializing Tenuo project (development mode)...")

    # 1. Generate Root Key
    key = SigningKey.generate()
    key_b64 = base64.b64encode(key.to_string()).decode('ascii')

    # 2. Create .env
    env_content = f"TENUO_ROOT_KEY={key_b64}\nTENUO_ENV=dev\n"
    if Path(".env").exists():
        print("ℹ️  .env already exists, skipping.")
    else:
        Path(".env").write_text(env_content, encoding='utf-8')
        print("✅ Received root_key (ed25519) -> .env")

    # 3. Create tenuo_config.py
    config_content = """# Tenuo Configuration
# Run this once to setup your environment

import os
import sys
from dotenv import load_dotenv
from tenuo import configure, PublicKey

# Load keys from .env
load_dotenv()

def setup():
    root_key = os.getenv("TENUO_ROOT_KEY")
    if not root_key:
        print("[ERROR] Missing TENUO_ROOT_KEY in .env")
        sys.exit(1)

    # In a real app, you would load the issuer's public key
    # For dev, we just checking configuration
    print(f"[OK] Tenuo configured locally.")
    print(f"[KEY] Root Key present: {root_key[:10]}...")

if __name__ == "__main__":
    setup()
"""
    if Path("tenuo_config.py").exists():
        print("ℹ️  tenuo_config.py already exists, skipping.")
    else:
        Path("tenuo_config.py").write_text(config_content, encoding='utf-8')
        print("✅ Created tenuo_config.py with sensible defaults")

    print("\n🎉 Ready! Next steps:")
    print("   tenuo mint --tool read_file --ttl 1h   # Create a test warrant")
    print("   tenuo decode <warrant>                 # Inspect it")
    print("\n💡 Tip: Root keys grant unlimited authority—protect them with a secrets manager in production.")


if __name__ == "__main__":
    main()
