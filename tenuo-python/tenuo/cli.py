"""
Tenuo CLI.

Provides command-line utilities for inspecting warrants and verifying authorization.
Usage:
    python -m tenuo.cli inspect <warrant_base64>
    python -m tenuo.cli verify <warrant_base64> <tool> <arg1=val1> <arg2=val2> ...
"""

import sys
import argparse
import json
from typing import List, Dict, Any

from tenuo_core import Warrant  # type: ignore[import-untyped]


def verify_warrant(warrant_str: str, tool: str, args: Dict[str, Any]) -> None:
    """Check if a warrant authorizes a tool call (no PoP check, just logic)."""
    try:
        warrant = Warrant.from_base64(warrant_str)
    except Exception as e:
        print(f"Error: Invalid warrant format: {e}")
        sys.exit(1)

    print(f"Verifying warrant {warrant.id} for tool '{tool}' with args {args}...")
    
    # Check if tool is authorized
    if warrant.tools and tool not in warrant.tools:
        print(f"❌ DENIED: Tool '{tool}' is not in allowed tools: {warrant.tools}")
        return

    # Check expiration
    if warrant.is_expired():
        print(f"❌ DENIED: Warrant is expired (expired at {warrant.expires_at()})")
        return

    # Check constraints
    # Note: We can't easily execute the full constraint check without the PoP signature
    # because authorize() requires a signature.
    # However, we can inspect constraints manually or use a "dry run" if available.
    # Currently, authorize() is the only way to check constraints fully.
    # But authorize() needs a valid signature matching the args.
    # Since CLI user doesn't have the private key, we can't sign.
    # We can only INSPECT constraints.
    
    constraints = warrant.constraints_dict()
    print("Constraints present:")
    if not constraints:
        print("  (None)")
    else:
        for k, v in constraints.items():
            print(f"  {k}: {v}")
            
    print("\n⚠️  Note: Full verification requires a valid PoP signature signed by the holder key.")
    print("This CLI tool currently only checks static properties (expiry, tool allowance).")


def inspect_warrant(warrant_str: str) -> None:
    """Print human-readable warrant details."""
    try:
        warrant = Warrant.from_base64(warrant_str)
    except Exception as e:
        print(f"Error: Invalid warrant format: {e}")
        sys.exit(1)
        
    print("=== Warrant Inspection ===")
    print(f"ID:           {warrant.id}")
    print(f"Holder Key:   {warrant.holder}")
    print(f"Expires At:   {warrant.expires_at()}")
    print(f"TTL Remain:   {warrant.ttl_remaining}")
    print(f"Tools:        {warrant.tools if warrant.tools else '*'}")
    print(f"Is Terminal:  {warrant.is_terminal()}")
    print(f"Max Depth:    {warrant.max_depth()}")
    
    print("\n[Constraints]")
    constraints = warrant.constraints_dict()
    if not constraints:
        print("  (None)")
    else:
        print(json.dumps(constraints, indent=2))
        
    print("\n[Base64]")
    print(warrant.to_base64())


def parse_kv_args(args_list: List[str]) -> Dict[str, Any]:
    """Parse key=value arguments into a dictionary."""
    args = {}
    for item in args_list:
        if "=" in item:
            k, v = item.split("=", 1)
            # Try to infer type
            if v.lower() == "true":
                v_box = True
            elif v.lower() == "false":
                v_box = False
            else:
                try:
                    v_box = int(v)
                except ValueError:
                    try:
                        v_box = float(v)
                    except ValueError:
                        v_box = v
            args[k] = v_box
    return args


def main():
    parser = argparse.ArgumentParser(description="Tenuo CLI Utility")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a warrant")
    inspect_parser.add_argument("warrant", help="Base64 encoded warrant string")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify tool authorization logic")
    verify_parser.add_argument("warrant", help="Base64 encoded warrant string")
    verify_parser.add_argument("tool", help="Tool name to verify")
    verify_parser.add_argument("args", nargs="*", help="Arguments in key=value format (e.g. query=foo)")
    
    args = parser.parse_args()
    
    if args.command == "inspect":
        inspect_warrant(args.warrant)
    elif args.command == "verify":
        kv_args = parse_kv_args(args.args)
        verify_warrant(args.warrant, args.tool, kv_args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
