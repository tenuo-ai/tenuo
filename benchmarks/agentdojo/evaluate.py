#!/usr/bin/env python3
"""
Evaluate AgentDojo benchmarks with and without capability enforcement.

Usage:
    python evaluate.py --suite workspace --baseline-only
    python evaluate.py --suite banking --with-tenuo
    python evaluate.py --suite email --compare

The difference is mechanical, not heuristic: constraints are cryptographically
enforced at the tool boundary. The LLM cannot consent to actions the warrant
doesn't allow.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime

from .harness import TenuoAgentDojoHarness


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run AgentDojo benchmarks with Tenuo protection"
    )
    parser.add_argument(
        "--suite",
        type=str,
        required=True,
        choices=["workspace", "banking", "travel", "slack"],
        help="Task suite to evaluate"
    )
    parser.add_argument(
        "--tasks",
        type=str,
        default="all",
        help="Comma-separated task IDs or 'all' (default: all)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4o-mini",
        help="LLM model to use (default: gpt-4o-mini)"
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Only run baseline (no Tenuo)"
    )
    parser.add_argument(
        "--with-tenuo",
        action="store_true",
        help="Only run with Tenuo protection"
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run both baseline and Tenuo for comparison"
    )
    parser.add_argument(
        "--no-attacks",
        action="store_true",
        help="Skip attack scenarios (benign only)"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="OpenAI API key (if not set, uses OPENAI_API_KEY env var)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Output directory for results (default: results/)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    
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
    
    # Create harness
    harness = TenuoAgentDojoHarness(
        suite_name=args.suite,
        model=args.model,
        api_key=args.api_key,
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
            logdir=suite_dir / "baseline",
        )
        
        # Save results
        with open(suite_dir / "baseline.json", 'w') as f:
            json.dump(baseline_results, f, indent=2, default=str)
        
        print(f"Baseline complete")
        print()
    
    # Run with capability enforcement
    if run_tenuo:
        print("Running with capability enforcement (Tenuo)...")
        tenuo_results = harness.run_benchmark(
            with_tenuo=True,
            with_attacks=not args.no_attacks,
            user_tasks=task_ids,
            logdir=suite_dir / "with_tenuo",
        )
        
        # Save results and metrics
        with open(suite_dir / "with_tenuo.json", 'w') as f:
            json.dump(tenuo_results, f, indent=2, default=str)
        
        with open(suite_dir / "authorization_metrics.json", 'w') as f:
            json.dump(tenuo_results["metrics"], f, indent=2)
        
        metrics = tenuo_results["metrics"]
        print(f"Capability enforcement complete")
        print(f"Blocked by physics: {metrics['denied']} denied, {metrics['allowed']} allowed")
        print()
    
    # Summary
    print(f"Results saved to: {suite_dir}")
    print()
    print("To analyze results:")
    print(f"  python -m benchmarks.agentdojo.analyze {suite_dir}")


if __name__ == "__main__":
    main()
