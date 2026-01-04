#!/usr/bin/env python3
"""
CLI for running delegation benchmarks.

Usage:
    python -m benchmarks.delegation.evaluate --scenario temporal_scoping
    python -m benchmarks.delegation.evaluate --all
"""

import argparse
from pathlib import Path
from datetime import datetime

from .harness import DelegationHarness, run_all_scenarios


def main():
    parser = argparse.ArgumentParser(
        description="Run Tenuo delegation benchmarks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run single scenario
  python -m benchmarks.delegation.evaluate --scenario temporal_scoping
  
  # Run all scenarios
  python -m benchmarks.delegation.evaluate --all
  
  # Save results to file
  python -m benchmarks.delegation.evaluate --all --output results/delegation/
""",
    )

    parser.add_argument(
        "--scenario",
        choices=["temporal_scoping", "range_limit", "pattern_match", "tool_scoping"],
        help="Scenario to run",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all scenarios",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Directory to save results",
    )

    args = parser.parse_args()

    if not args.scenario and not args.all:
        parser.error("Must specify --scenario or --all")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.all:
        results = run_all_scenarios()

        if args.output:
            output_dir = args.output / timestamp
            for name, metrics in results.items():
                harness = DelegationHarness(name)
                harness.metrics = metrics
                harness.save_results(output_dir / f"{name}.json")

        # Print combined summary
        print("\n" + "=" * 60)
        print("COMBINED RESULTS")
        print("=" * 60)
        total_tests = sum(m.total_tests for m in results.values())
        total_passed = sum(m.passed for m in results.values())
        total_false_neg = sum(m.false_negatives for m in results.values())

        print(f"Total tests:     {total_tests}")
        print(
            f"Total passed:    {total_passed} ({100 * total_passed / total_tests:.0f}%)"
        )
        print(f"False negatives: {total_false_neg}")

        if total_false_neg > 0:
            print("\n⚠️  WARNING: False negatives indicate delegation bypass!")
        else:
            print("\n✓ All delegation constraints correctly enforced")

    else:
        harness = DelegationHarness(args.scenario)
        harness.setup()
        harness.run()
        harness.print_summary()

        if args.output:
            output_path = args.output / timestamp / f"{args.scenario}.json"
            harness.save_results(output_path)


if __name__ == "__main__":
    main()
