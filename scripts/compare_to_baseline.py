#!/usr/bin/env python3
"""
Compare benchmark results to baseline for regression detection.

Usage:
    python scripts/compare_to_baseline.py results/my_run.json benchmarks/results/baseline/escalation_summary.json
    python scripts/compare_to_baseline.py results/my_run.json --benchmark escalation
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(path) as f:
        return json.load(f)


def compare_escalation(current: Dict, baseline: Dict) -> List[Tuple[str, str, Any, Any]]:
    """Compare escalation benchmark results."""
    diffs = []

    # Check enforcement rate
    current_rate = current.get("enforcement_rate", 0.0)
    baseline_rate = baseline.get("enforcement_rate", 0.0)

    if abs(current_rate - baseline_rate) > 0.05:  # 5% tolerance
        diffs.append((
            "enforcement_rate",
            "REGRESSION" if current_rate < baseline_rate else "IMPROVEMENT",
            current_rate,
            baseline_rate
        ))

    # Check total attacks
    if current.get("total_attacks") != baseline.get("total_attacks"):
        diffs.append((
            "total_attacks",
            "CHANGED",
            current.get("total_attacks"),
            baseline.get("total_attacks")
        ))

    return diffs


def compare_cryptographic(current: Dict, baseline: Dict) -> List[Tuple[str, str, Any, Any]]:
    """Compare cryptographic benchmark results."""
    diffs = []

    # All metrics should be 1.0
    critical_metrics = [
        "wrong_key_detection",
        "replay_detection",
        "escalation_detection",
        "delegation_enforcement",
        "key_separation",
        "stolen_warrant_protection",
        "fresh_acceptance",
        "expired_rejection",
    ]

    for metric in critical_metrics:
        current_val = current.get(metric, 0.0)
        baseline_val = baseline.get(metric, 1.0)

        if current_val < 1.0:
            diffs.append((
                metric,
                "CRITICAL REGRESSION",
                current_val,
                baseline_val
            ))

    return diffs


def compare_adversarial(current: Dict, baseline: Dict) -> List[Tuple[str, str, Any, Any]]:
    """Compare adversarial benchmark results."""
    diffs = []

    scenarios = [
        "email_exfil",
        "financial_limit",
        "path_traversal",
        "url_restriction",
        "multi_recipient",
        "api_key_exfil",
        "tool_confusion",
        "unicode_homoglyph",
    ]

    for scenario in scenarios:
        current_result = current.get(scenario, {})
        baseline_result = baseline.get(scenario, {})

        current_mean = current_result.get("mean", 0.0)
        baseline_mean = baseline_result.get("mean", 1.0)

        if current_mean < 0.95:  # Below 95% defense rate
            diffs.append((
                scenario,
                "REGRESSION" if current_mean < baseline_mean else "WARNING",
                f"{current_mean:.2%}",
                f"{baseline_mean:.2%}"
            ))

    return diffs


def compare_delegation(current: Dict, baseline: Dict) -> List[Tuple[str, str, Any, Any]]:
    """Compare delegation benchmark results."""
    diffs = []

    current_rate = current.get("overall_pass_rate", 0.0)
    baseline_rate = baseline.get("overall_pass_rate", 1.0)

    if current_rate < 1.0:
        diffs.append((
            "overall_pass_rate",
            "REGRESSION",
            current_rate,
            baseline_rate
        ))

    return diffs


def main():
    parser = argparse.ArgumentParser(description="Compare benchmark results to baseline")
    parser.add_argument("current", type=Path, help="Current results JSON file")
    parser.add_argument(
        "baseline",
        type=Path,
        nargs="?",
        help="Baseline results JSON file (or use --benchmark)"
    )
    parser.add_argument(
        "--benchmark",
        choices=["escalation", "cryptographic", "adversarial", "delegation"],
        help="Auto-detect baseline from benchmark type"
    )
    args = parser.parse_args()

    # Load current results
    current = load_json(args.current)

    # Determine baseline path
    if args.baseline:
        baseline_path = args.baseline
    elif args.benchmark:
        baseline_path = Path("benchmarks/results/baseline") / f"{args.benchmark}_*.json"
        # Find matching file
        matches = list(Path("benchmarks/results/baseline").glob(f"{args.benchmark}_*.json"))
        if not matches:
            print(f"❌ No baseline found for {args.benchmark}")
            print(f"   Expected: benchmarks/results/baseline/{args.benchmark}_*.json")
            sys.exit(1)
        baseline_path = matches[0]
    else:
        parser.error("Either provide baseline path or use --benchmark")

    # Load baseline
    baseline = load_json(baseline_path)

    # Detect benchmark type from current results structure
    if "enforcement_rate" in current:
        benchmark_type = "escalation"
        diffs = compare_escalation(current, baseline)
    elif "wrong_key_detection" in current:
        benchmark_type = "cryptographic"
        diffs = compare_cryptographic(current, baseline)
    elif any(k in current for k in ["email_exfil", "financial_limit"]):
        benchmark_type = "adversarial"
        diffs = compare_adversarial(current, baseline)
    elif "overall_pass_rate" in current:
        benchmark_type = "delegation"
        diffs = compare_delegation(current, baseline)
    else:
        print("❌ Could not detect benchmark type from results structure")
        sys.exit(1)

    # Print results
    print(f"\n{'='*70}")
    print(f"Comparing {benchmark_type.upper()} benchmark results")
    print(f"{'='*70}\n")
    print(f"Current:  {args.current}")
    print(f"Baseline: {baseline_path}\n")

    if not diffs:
        print("✅ All metrics match baseline (within tolerance)")
        print("\nNo regressions detected.")
        sys.exit(0)

    # Print differences
    print(f"{'Metric':<30} {'Status':<20} {'Current':<15} {'Baseline':<15}")
    print("-" * 80)

    has_regression = False
    for metric, status, current_val, baseline_val in diffs:
        print(f"{metric:<30} {status:<20} {current_val!s:<15} {baseline_val!s:<15}")
        if "REGRESSION" in status or "CRITICAL" in status:
            has_regression = True

    print()

    if has_regression:
        print("❌ REGRESSIONS DETECTED")
        print("\nAction required:")
        print("1. Investigate the regression")
        print("2. Fix the issue")
        print("3. Re-run the benchmark")
        sys.exit(1)
    else:
        print("⚠️  Changes detected but within tolerance")
        sys.exit(0)


if __name__ == "__main__":
    main()
