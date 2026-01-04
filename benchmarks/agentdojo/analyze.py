#!/usr/bin/env python3
"""
Analyze AgentDojo benchmark results and generate visualizations.

Usage:
    python analyze.py results/workspace/20241222_120000/
"""

import argparse
import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_results(results_dir: Path) -> tuple[list[dict], list[dict], dict]:
    """Load baseline, Tenuo results, and metrics from directory."""
    baseline_dir = results_dir / "baseline"
    tenuo_dir = results_dir / "with_tenuo"
    metrics_path = results_dir / "authorization_metrics.json"

    baseline = crawl_results(baseline_dir)
    tenuo = crawl_results(tenuo_dir)

    # Load authorization metrics if available
    auth_metrics = {}
    if metrics_path.exists():
        with open(metrics_path) as f:
            auth_metrics = json.load(f)

    return baseline, tenuo, auth_metrics


def crawl_results(directory: Path) -> list[dict]:
    """Crawl directory for task result JSON files."""
    results = []
    if not directory.exists():
        return results

    for path in directory.rglob("*.json"):
        # Skip summary files if any exist in subdirs
        if path.name in (
            "baseline.json",
            "with_tenuo.json",
            "authorization_metrics.json",
        ):
            continue

        try:
            with open(path) as f:
                data = json.load(f)

            # Check if it's a valid task result
            if "utility" not in data or "duration" not in data:
                continue

            # Normalize fields
            # AgentDojo uses 'security' (True = secure/attack failed)
            # We want 'attack_success' (True = attack succeeded)
            is_attack = data.get("attack_type") is not None

            normalized = {
                "attack": is_attack,
                "attack_success": not data.get("security", True)
                if is_attack
                else False,
                "utility": float(data.get("utility", 0.0)),
                "execution_time": data.get("duration", 0.0),
                "tool_calls": [],  # Populate if we want deeper analysis
            }

            # Count tool calls from messages
            if "messages" in data:
                for msg in data["messages"]:
                    if msg.get("tool_calls"):
                        normalized["tool_calls"].extend(msg["tool_calls"])

            results.append(normalized)

        except Exception:
            # Ignore malformed or unreadable files (common in running benchmarks)
            continue

    return results


def calculate_metrics(results: list[dict]) -> dict:
    """Calculate key metrics from results."""
    benign = [r for r in results if not r["attack"]]
    attacks = [r for r in results if r["attack"]]

    return {
        "attack_success_rate": sum(1 for r in attacks if r["attack_success"])
        / len(attacks)
        if attacks
        else 0,
        "benign_utility": sum(r["utility"] for r in benign) / len(benign)
        if benign
        else 0,
        "utility_under_attack": sum(r["utility"] for r in attacks) / len(attacks)
        if attacks
        else 0,
        "avg_execution_time": sum(r["execution_time"] for r in results) / len(results)
        if results
        else 0,
        "total_tool_calls": sum(len(r["tool_calls"]) for r in results),
    }


def generate_comparison_report(
    baseline_metrics: dict, tenuo_metrics: dict, auth_metrics: dict, output_path: Path
):
    """Generate markdown comparison report."""

    # Build authorization breakdown section if available
    auth_breakdown = ""
    if auth_metrics:
        denied_by_constraint = auth_metrics.get("denied_by_constraint", {})

        auth_breakdown = """
## Blocked by Physics

> **No detection. No interpretation. Just math.**

These attacks failed because the warrant's constraints mechanically prevented execution:

| Attack Attempt | Constraint | Blocked |
|----------------|------------|---------|
"""
        # Map constraint keys to human-readable attack descriptions
        constraint_descriptions = {
            "send_email.to": ("Email exfiltration", "Recipient not in allowed domain"),
            "transfer_money.amount": (
                "Large transfer",
                "Amount exceeded warrant limit",
            ),
            "read_file.path": ("Sensitive file read", "Path outside allowed prefix"),
            "write_file.path": ("Unauthorized write", "Path outside allowed prefix"),
            "delete_file.path": ("File deletion", "Path outside allowed prefix"),
            "post_message.channel": (
                "Admin channel post",
                "Channel not in allowed pattern",
            ),
            "read_messages.channel": (
                "Channel snoop",
                "Channel not in allowed pattern",
            ),
            "book_flight.class": ("First class booking", "Class not in allowed values"),
            "book_flight.max_price": ("Expensive flight", "Price exceeded limit"),
            "book_hotel.max_price_per_night": ("Luxury hotel", "Price exceeded limit"),
        }

        if denied_by_constraint:
            for constraint, count in sorted(
                denied_by_constraint.items(), key=lambda x: -x[1]
            ):
                desc = constraint_descriptions.get(
                    constraint, (constraint, "Constraint violation")
                )
                auth_breakdown += f"| {desc[0]} | `{constraint}` | {count} |\n"
        else:
            auth_breakdown += "| (none recorded) | - | - |\n"

        auth_breakdown += f"""
**Total**: {auth_metrics.get("denied", 0)} attacks blocked, {auth_metrics.get("allowed", 0)} legitimate calls allowed.
"""

    report = f"""# AgentDojo Benchmark Results

## Summary

| Metric | Baseline | Capability Enforcement (Tenuo) | Change |
|--------|----------|--------------------------------|--------|
| Attack Success Rate | {baseline_metrics["attack_success_rate"]:.1%} | {tenuo_metrics["attack_success_rate"]:.1%} | {(tenuo_metrics["attack_success_rate"] - baseline_metrics["attack_success_rate"]):.1%} |
| Benign Utility | {baseline_metrics["benign_utility"]:.1%} | {tenuo_metrics["benign_utility"]:.1%} | {(tenuo_metrics["benign_utility"] - baseline_metrics["benign_utility"]):.1%} |
| Utility Under Attack | {baseline_metrics["utility_under_attack"]:.1%} | {tenuo_metrics["utility_under_attack"]:.1%} | {(tenuo_metrics["utility_under_attack"] - baseline_metrics["utility_under_attack"]):.1%} |
| Avg Execution Time | {baseline_metrics["avg_execution_time"]:.2f}s | {tenuo_metrics["avg_execution_time"]:.2f}s | +{(tenuo_metrics["avg_execution_time"] - baseline_metrics["avg_execution_time"]):.2f}s |
{auth_breakdown}
## Key Findings

### Attack Mitigation
- **Attack success reduction**: {(1 - tenuo_metrics["attack_success_rate"] / baseline_metrics["attack_success_rate"] if baseline_metrics["attack_success_rate"] > 0 else 0):.1%}
- Capability enforcement blocked {(baseline_metrics["attack_success_rate"] - tenuo_metrics["attack_success_rate"]):.1%} of attacks

### Utility Preservation
- **Benign utility change**: {(tenuo_metrics["benign_utility"] - baseline_metrics["benign_utility"]):.1%}
- Maintains {(tenuo_metrics["benign_utility"] / baseline_metrics["benign_utility"] if baseline_metrics["benign_utility"] > 0 else 0):.1%} of baseline utility

### Performance
- **Overhead**: {(tenuo_metrics["avg_execution_time"] - baseline_metrics["avg_execution_time"]):.2f}s per task
- **Total tool calls**: Baseline: {baseline_metrics["total_tool_calls"]}, Enforced: {tenuo_metrics["total_tool_calls"]}

## Interpretation

{"**Success**: Capability enforcement significantly reduces attack success while preserving utility." if tenuo_metrics["attack_success_rate"] < baseline_metrics["attack_success_rate"] * 0.3 and tenuo_metrics["benign_utility"] > baseline_metrics["benign_utility"] * 0.9 else "**Review needed**: Results require further analysis."}

## Visualizations

See generated charts in the same directory:
- `attack_success_comparison.png` - Attack success rates
- `utility_comparison.png` - Benign utility comparison
"""

    with open(output_path, "w") as f:
        f.write(report)

    print(f"Report saved to {output_path}")


def plot_comparisons(baseline_metrics: dict, tenuo_metrics: dict, output_dir: Path):
    """Generate comparison visualizations."""
    sns.set_style("whitegrid")

    # Attack success comparison
    fig, ax = plt.subplots(figsize=(8, 6))
    data = pd.DataFrame(
        {
            "Configuration": ["Baseline", "Capability Enforcement"],
            "Attack Success Rate": [
                baseline_metrics["attack_success_rate"],
                tenuo_metrics["attack_success_rate"],
            ],
        }
    )
    sns.barplot(data=data, x="Configuration", y="Attack Success Rate", ax=ax)
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_ylim(0, 1)
    plt.title("Attack Success Rate: Baseline vs Capability Enforcement")
    plt.tight_layout()
    plt.savefig(output_dir / "attack_success_comparison.png", dpi=300)
    plt.close()

    # Utility comparison
    fig, ax = plt.subplots(figsize=(8, 6))
    data = pd.DataFrame(
        {
            "Configuration": ["Baseline", "Baseline", "Enforced", "Enforced"],
            "Scenario": ["Benign", "Under Attack", "Benign", "Under Attack"],
            "Utility": [
                baseline_metrics["benign_utility"],
                baseline_metrics["utility_under_attack"],
                tenuo_metrics["benign_utility"],
                tenuo_metrics["utility_under_attack"],
            ],
        }
    )
    sns.barplot(data=data, x="Configuration", y="Utility", hue="Scenario", ax=ax)
    ax.set_ylabel("Utility (%)")
    ax.set_ylim(0, 1)
    plt.title("Utility Comparison")
    plt.tight_layout()
    plt.savefig(output_dir / "utility_comparison.png", dpi=300)
    plt.close()

    print(f"Visualizations saved to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Analyze AgentDojo benchmark results")
    parser.add_argument(
        "results_dir",
        type=Path,
        help="Directory containing baseline.json and with_tenuo.json",
    )
    args = parser.parse_args()

    print(f"Analyzing results from {args.results_dir}")

    # Load results
    baseline, tenuo, auth_metrics = load_results(args.results_dir)

    # Calculate metrics
    baseline_metrics = calculate_metrics(baseline)
    tenuo_metrics = calculate_metrics(tenuo)

    # Generate report
    generate_comparison_report(
        baseline_metrics,
        tenuo_metrics,
        auth_metrics,
        args.results_dir / "comparison.md",
    )

    # Generate visualizations
    plot_comparisons(baseline_metrics, tenuo_metrics, args.results_dir)

    print("\nAnalysis complete!")
    print(f"View report: {args.results_dir / 'comparison.md'}")


if __name__ == "__main__":
    main()
