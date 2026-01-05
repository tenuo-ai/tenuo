#!/usr/bin/env python3
"""
Evaluate AgentDojo benchmarks with and without capability enforcement.

Usage:
    python evaluate.py --suite workspace --baseline-only
    python evaluate.py --suite banking --with-tenuo
    python evaluate.py --suite email --compare
    python evaluate.py --suite workspace --dry-run  # No API calls

The difference is mechanical, not heuristic: constraints are cryptographically
enforced at the tool boundary. The LLM cannot consent to actions the warrant
doesn't allow.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime

# Note: TenuoAgentDojoHarness imported inside main() to allow dry-run
# without openai/agentdojo installed
from .warrant_templates import get_constraints_for_suite
from .tool_wrapper import AuthorizationMetrics


def run_dry_run(suite_name: str) -> None:
    """
    Validate benchmark setup without making any API calls.

    Checks:
    - All modules import correctly
    - Constraint templates are defined for the suite
    - Tenuo warrant creation works
    - Tool wrapper can be instantiated

    No OpenAI API calls are made, so this is free to run.
    """
    from tenuo import SigningKey, Warrant

    print("=" * 60)
    print("DRY RUN: Validating benchmark setup (no API calls)")
    print("=" * 60)
    print()

    # Check 1: Imports
    print("✓ All modules imported successfully")

    # Check 2: Constraint templates
    constraints = get_constraints_for_suite(suite_name)
    print(f"✓ Loaded {len(constraints)} tool constraints for '{suite_name}'")
    for tool_name, tool_constraints in list(constraints.items())[:5]:
        print(f"  - {tool_name}: {len(tool_constraints)} constraint(s)")
    if len(constraints) > 5:
        print(f"  ... and {len(constraints) - 5} more tools")
    print()

    # Check 3: Warrant creation
    issuer_key = SigningKey.generate()
    holder_key = SigningKey.generate()

    warrants_created = 0
    for tool_name, tool_constraints in constraints.items():
        # Verify warrant creation succeeds (variable unused intentionally)
        _ = (
            Warrant.mint_builder()
            .capability(tool_name.lower(), tool_constraints)
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )
        warrants_created += 1

    print(f"✓ Created {warrants_created} warrants successfully")
    print()

    # Check 4: Metrics tracker
    metrics = AuthorizationMetrics()
    print(
        f"✓ AuthorizationMetrics instantiated (allowed={metrics.allowed}, denied={metrics.denied})"
    )
    print()

    # Summary
    print("=" * 60)
    print("DRY RUN COMPLETE: All checks passed!")
    print("=" * 60)
    print()
    print("Ready to run real benchmarks with:")
    print(f"  python -m benchmarks.agentdojo.evaluate --suite {suite_name} --compare")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run AgentDojo benchmarks with Tenuo protection"
    )
    parser.add_argument(
        "--suite",
        type=str,
        required=True,
        choices=["workspace", "banking", "travel", "slack"],
        help="Task suite to evaluate",
    )
    parser.add_argument(
        "--tasks",
        type=str,
        default="all",
        help="Comma-separated task IDs or 'all' (default: all)",
    )
    parser.add_argument(
        "--user-tasks",
        type=int,
        default=None,
        help="Limit number of user tasks to run (example: --user-tasks 3)",
    )
    parser.add_argument(
        "--injection-tasks",
        type=int,
        default=None,
        help="Limit number of injection tasks to run (example: --injection-tasks 2)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4o-mini",
        help="LLM model to use (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--baseline-only", action="store_true", help="Only run baseline (no Tenuo)"
    )
    parser.add_argument(
        "--with-tenuo", action="store_true", help="Only run with Tenuo protection"
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run both baseline and Tenuo for comparison",
    )
    parser.add_argument(
        "--no-attacks", action="store_true", help="Skip attack scenarios (benign only)"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="OpenAI API key (if not set, uses OPENAI_API_KEY env var)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Output directory for results (default: results/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate setup without making API calls (no cost)",
    )
    parser.add_argument(
        "--jit",
        action="store_true",
        help="Enable JIT (Just-in-Time) warrants - task-specific constraints",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Handle dry-run mode first
    if args.dry_run:
        run_dry_run(args.suite)
        return

    # Parse task IDs
    if args.tasks == "all":
        task_ids = None  # Will use all tasks from suite
    else:
        task_ids = args.tasks.split(",")

    # Determine what to run
    run_baseline = args.baseline_only or args.compare
    run_tenuo = args.with_tenuo or args.compare

    if not (run_baseline or run_tenuo):
        # Default: run comparison
        run_baseline = run_tenuo = True

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suite_dir = args.output_dir / args.suite / timestamp
    suite_dir.mkdir(parents=True, exist_ok=True)

    print(f"Running AgentDojo benchmark: {args.suite}")
    print(f"Model: {args.model}")
    print(f"Tasks: {args.tasks}")
    print(f"Attacks: {'No' if args.no_attacks else 'Yes'}")
    print(f"Output: {suite_dir}")
    print()

    # Import harness here (requires openai/agentdojo)
    from .harness import TenuoAgentDojoHarness

    # Create harness
    harness = TenuoAgentDojoHarness(
        suite_name=args.suite,
        model=args.model,
        api_key=args.api_key,
        jit_warrants=args.jit,
    )

    def take_first_task_ids(task_map: dict, limit: int) -> list:
        # AgentDojo task maps are dict-like. Sort keys for stable ordering.
        keys = sorted(task_map.keys(), key=lambda k: str(k))
        return list(keys[:limit])

    if args.user_tasks is not None:
        if task_ids is not None:
            raise SystemExit("Use either --tasks or --user-tasks, not both")
        task_ids = take_first_task_ids(harness.suite.user_tasks, args.user_tasks)

    injection_task_ids = None
    if args.injection_tasks is not None:
        injection_task_ids = take_first_task_ids(
            harness.suite.injection_tasks, args.injection_tasks
        )

    baseline_results = None
    tenuo_results = None

    # Run baseline
    if run_baseline:
        print("Running baseline (no Tenuo)...")
        baseline_results = harness.run_benchmark(
            with_tenuo=False,
            with_attacks=not args.no_attacks,
            user_tasks=task_ids,
            injection_tasks=injection_task_ids,
            logdir=suite_dir / "baseline",
        )

        # Save results
        with open(suite_dir / "baseline.json", "w") as f:
            json.dump(baseline_results, f, indent=2, default=str)

        print("Baseline complete")
        print()

    # Run with capability enforcement
    if run_tenuo:
        print("Running with capability enforcement (Tenuo)...")
        tenuo_results = harness.run_benchmark(
            with_tenuo=True,
            with_attacks=not args.no_attacks,
            user_tasks=task_ids,
            injection_tasks=injection_task_ids,
            logdir=suite_dir / "with_tenuo",
        )

        # Save results and metrics
        with open(suite_dir / "with_tenuo.json", "w") as f:
            json.dump(tenuo_results, f, indent=2, default=str)

        with open(suite_dir / "authorization_metrics.json", "w") as f:
            json.dump(tenuo_results["metrics"], f, indent=2)

        metrics = tenuo_results["metrics"]
        print("Capability enforcement complete")
        print(
            f"Blocked by physics: {metrics['denied']} denied, {metrics['allowed']} allowed"
        )
        print()

    # Summary
    print(f"Results saved to: {suite_dir}")
    print()
    print("To analyze results:")
    print(f"  python -m benchmarks.agentdojo.analyze {suite_dir}")


if __name__ == "__main__":
    main()
