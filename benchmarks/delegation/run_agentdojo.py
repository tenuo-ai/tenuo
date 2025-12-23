#!/usr/bin/env python3
"""
Run delegation benchmark with AgentDojo's scenarios.

Compares attack success rates between:
- Manager with full suite constraints  
- Assistant with delegated (narrower) constraints

Usage:
    python -m benchmarks.delegation.run_agentdojo --suite workspace
    python -m benchmarks.delegation.run_agentdojo --suite banking --limit 5
"""

import argparse
from pathlib import Path
from datetime import datetime

from .agentdojo_delegated import run_delegation_comparison


def main():
    parser = argparse.ArgumentParser(
        description="Run delegation comparison benchmark with AgentDojo scenarios",
    )
    parser.add_argument(
        "--suite",
        default="workspace",
        choices=["workspace", "banking", "slack", "travel"],
        help="AgentDojo task suite (default: workspace)",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenAI model (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Limit number of tasks (default: 3)",
    )
    
    args = parser.parse_args()
    
    results = run_delegation_comparison(
        suite=args.suite,
        model=args.model,
        limit=args.limit,
    )
    
    print("\n" + "=" * 60)
    print("KEY INSIGHT")
    print("=" * 60)
    print("Same LLM, same attacks, same tools.")
    print("Only difference: Assistant has DELEGATED warrant (narrower scope).")
    print()
    if results.delegation_prevented > 0:
        print(f"→ Delegation prevented {results.delegation_prevented} attacks that")
        print("  would have succeeded with manager's broader warrant.")
    print()
    print("This is Tenuo's value: delegation mathematically bounds damage.")


if __name__ == "__main__":
    main()

