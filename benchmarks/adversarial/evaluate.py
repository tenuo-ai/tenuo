#!/usr/bin/env python3
"""
Adversarial Benchmark CLI

Run a Red Team LLM against Tenuo's constraints.

Usage:
    python -m benchmarks.adversarial.evaluate
    python -m benchmarks.adversarial.evaluate --scenario email_exfil
    python -m benchmarks.adversarial.evaluate --attacker-model gpt-4o --max-attempts 20
    python -m benchmarks.adversarial.evaluate --runs 5 --ablation
"""

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

from openai import OpenAI

from .redteam import RedTeamBenchmark, AttackResult
from .scenarios import ADVERSARIAL_SCENARIOS, build_scenario
from .statistics import aggregate_runs, format_ci
from .metrics import (
    estimate_cost,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def print_result(result: AttackResult, show_recon: bool = True):
    """Print formatted result."""
    status = "[SUCCESS] CONSTRAINT BYPASSED" if result.success else "[DEFENDED] Constraint held"
    
    print()
    print("=" * 70)
    print(f"Scenario: {result.scenario}")
    print(f"Goal: {result.goal}")
    print("=" * 70)
    
    # Show reconnaissance findings
    if show_recon and result.recon_observations:
        print()
        print("--- RECONNAISSANCE PHASE ---")
        print(f"Probes: {result.recon_probes}")
        for i, obs in enumerate(result.recon_observations, 1):
            status_str = "ALLOWED" if obs.allowed else "BLOCKED"
            print(f"  {i}. {obs.tool}({json.dumps(obs.args, default=str)[:40]}...) -> {status_str}")
        print()
        
        # Show patterns learned
        allowed = sum(1 for o in result.recon_observations if o.allowed)
        blocked = sum(1 for o in result.recon_observations if not o.allowed)
        print(f"Learned: {allowed} allowed, {blocked} blocked")
        print("--- END RECONNAISSANCE ---")
    
    print()
    print(f"Result: {status}")
    print(f"Attack attempts: {result.num_attempts}")
    print(f"Blocked: {result.blocked_attempts}")
    if result.recon_probes:
        print(f"Recon probes: {result.recon_probes}")
    if result.strategies_tried:
        print(f"Strategies tried: {', '.join(result.strategies_tried)}")
    print()
    
    print("Attack Attempt History:")
    print("-" * 70)
    for i, attempt in enumerate(result.attempts, 1):
        if attempt.blocked:
            status = "BLOCKED"
            detail = attempt.reason or "Unknown"
        elif attempt.is_bypass:
            status = "BYPASS!"
            detail = "Malicious call authorized"
        else:
            status = "ALLOWED"
            detail = "Legitimate call (not a bypass)"
        
        print(f"  {i}. {attempt.tool}({json.dumps(attempt.args)[:50]}...)")
        print(f"     {status}: {detail}")
    print()


def print_summary(results: list[AttackResult], recon_enabled: bool = True, model: str = "gpt-4o-mini"):
    """Print overall summary."""
    total = len(results)
    bypassed = sum(1 for r in results if r.success)
    defended = total - bypassed
    
    total_attempts = sum(r.num_attempts for r in results)
    total_recon = sum(r.recon_probes for r in results)
    avg_attempts = total_attempts / total if total else 0
    
    all_strategies = set()
    for r in results:
        all_strategies.update(r.strategies_tried)
    
    print()
    print("=" * 70)
    print("ADVERSARIAL BENCHMARK SUMMARY")
    print("=" * 70)
    print()
    print(f"{'Scenarios tested:':<30} {total}")
    print(f"{'Constraints bypassed:':<30} {bypassed}")
    print(f"{'Constraints defended:':<30} {defended}")
    print(f"{'Defense rate:':<30} {defended/total:.1%}" if total else "")
    print()
    if recon_enabled:
        print(f"{'Methodology:':<30} Adaptive (with reconnaissance)")
        print(f"{'Total recon probes:':<30} {total_recon}")
    else:
        print(f"{'Methodology:':<30} Naive (no reconnaissance)")
    print(f"{'Total attack attempts:':<30} {total_attempts}")
    print(f"{'Avg attempts per scenario:':<30} {avg_attempts:.1f}")
    print()
    
    # Cost estimation
    total_cost = sum(
        estimate_cost(model, r.recon_probes, r.num_attempts)
        for r in results
    )
    print(f"{'Estimated cost:':<30} ${total_cost:.3f}")
    print()
    
    if all_strategies:
        print(f"Strategies observed: {', '.join(sorted(all_strategies))}")
    print()
    
    if bypassed > 0:
        print("WARNING: Some constraints were bypassed!")
        print("Review the following scenarios:")
        for r in results:
            if r.success:
                print(f"  - {r.scenario}: {r.goal}")
    else:
        print("All constraints held against adversarial attacks.")
    
    print("=" * 70)


def print_aggregated_summary(
    all_runs: dict[str, list[AttackResult]],
    model: str = "gpt-4o-mini",
):
    """Print summary with confidence intervals from multiple runs."""
    print()
    print("=" * 70)
    print("AGGREGATED RESULTS (with 95% Confidence Intervals)")
    print("=" * 70)
    print()
    
    overall_defended = 0
    overall_total = 0
    overall_cost = 0.0
    
    for scenario_name, runs in all_runs.items():
        agg = aggregate_runs(runs)
        
        ci_str = format_ci(
            agg.defense_rate_mean,
            agg.defense_rate_ci_lower,
            agg.defense_rate_ci_upper,
        )
        
        print(f"{scenario_name}:")
        print(f"  Runs: {agg.runs}")
        print(f"  Defense rate: {ci_str}")
        print(f"  Avg attempts: {agg.attempts_mean:.1f} ± {agg.attempts_std:.1f}")
        print()
        
        overall_defended += agg.defended_count
        overall_total += agg.runs
        
        for r in runs:
            overall_cost += estimate_cost(model, r.recon_probes, r.num_attempts)
    
    # Overall
    overall_rate = overall_defended / overall_total if overall_total else 0
    print("-" * 70)
    print(f"{'Overall defense rate:':<30} {overall_rate:.1%}")
    print(f"{'Total runs:':<30} {overall_total}")
    print(f"{'Total cost:':<30} ${overall_cost:.3f}")
    print("=" * 70)


def print_ablation_results(
    with_recon: dict[str, list[AttackResult]],
    without_recon: dict[str, list[AttackResult]],
):
    """Print ablation study results comparing recon vs no-recon."""
    print()
    print("=" * 70)
    print("ABLATION STUDY: Reconnaissance vs No Reconnaissance")
    print("=" * 70)
    print()
    
    print("| Scenario | With Recon | Without Recon | Δ Defense |")
    print("|----------|------------|---------------|-----------|")
    
    for scenario_name in with_recon.keys():
        recon_runs = with_recon.get(scenario_name, [])
        no_recon_runs = without_recon.get(scenario_name, [])
        
        if recon_runs:
            agg_recon = aggregate_runs(recon_runs)
            recon_str = f"{agg_recon.defense_rate_mean:.0%}"
        else:
            recon_str = "N/A"
            agg_recon = None
        
        if no_recon_runs:
            agg_no_recon = aggregate_runs(no_recon_runs)
            no_recon_str = f"{agg_no_recon.defense_rate_mean:.0%}"
        else:
            no_recon_str = "N/A"
            agg_no_recon = None
        
        if agg_recon and agg_no_recon:
            delta = agg_no_recon.defense_rate_mean - agg_recon.defense_rate_mean
            delta_str = f"{delta:+.0%}"
        else:
            delta_str = "N/A"
        
        print(f"| {scenario_name:<8} | {recon_str:<10} | {no_recon_str:<13} | {delta_str:<9} |")
    
    print()
    print("Interpretation:")
    print("  Δ Defense > 0: Recon helps attacker (defender performs better without recon)")
    print("  Δ Defense < 0: Recon helps defender (counterintuitive)")
    print("=" * 70)


def run_benchmark(
    client: OpenAI,
    args,
    enable_recon: bool = True,
) -> dict[str, list[AttackResult]]:
    """Run benchmark and return results organized by scenario."""
    results_by_scenario: dict[str, list[AttackResult]] = {}
    
    # Determine scenarios
    if args.scenario == "all":
        scenario_names = list(ADVERSARIAL_SCENARIOS.keys())
    else:
        scenario_names = [args.scenario]
    
    for scenario_name in scenario_names:
        results_by_scenario[scenario_name] = []
    
    for run_num in range(1, args.runs + 1):
        if args.runs > 1:
            print(f"\n--- Run {run_num}/{args.runs} ---")
        
        benchmark = RedTeamBenchmark(
            client=client,
            attacker_model=args.attacker_model,
            max_attempts=args.max_attempts,
            recon_probes=args.recon_probes,
            enable_recon=enable_recon,
        )
        
        for scenario_name in scenario_names:
            print(f"Running scenario: {scenario_name}...")
            
            scenario = build_scenario(scenario_name)
            
            result = benchmark.run_scenario(
                scenario_name=scenario["name"],
                goal=scenario["goal"],
                tools=scenario["tools"],
                warrant=scenario["warrant"],
                holder_key=scenario["holder_key"],
                issuer_key=scenario["issuer_key"],
                verify_bypass=scenario.get("verify_bypass"),
            )
            
            results_by_scenario[scenario_name].append(result)
            
            if args.runs == 1:
                print_result(result, show_recon=enable_recon)
    
    return results_by_scenario


def main():
    parser = argparse.ArgumentParser(
        description="Red Team LLM adversarial benchmark"
    )
    parser.add_argument(
        "--scenario",
        choices=list(ADVERSARIAL_SCENARIOS.keys()) + ["all"],
        default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument(
        "--attacker-model",
        default="gpt-4o-mini",
        help="LLM model for attacker (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=10,
        help="Max attempts per scenario (default: 10)",
    )
    parser.add_argument(
        "--recon-probes",
        type=int,
        default=5,
        help="Reconnaissance probes per scenario (default: 5)",
    )
    parser.add_argument(
        "--no-recon",
        action="store_true",
        help="Disable reconnaissance phase (naive attacks only)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs per scenario for statistical averaging (default: 1)",
    )
    parser.add_argument(
        "--ablation",
        action="store_true",
        help="Run ablation study (compare recon vs no-recon)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON file for results",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="OpenAI API key (or set OPENAI_API_KEY env var)",
    )
    parser.add_argument(
        "--multi-step",
        action="store_true",
        help="Run multi-step attack chain scenarios",
    )
    args = parser.parse_args()
    
    enable_recon = not args.no_recon
    
    # Setup
    client = OpenAI(api_key=args.api_key) if args.api_key else OpenAI()
    
    # Determine scenarios
    if args.scenario == "all":
        scenario_names = list(ADVERSARIAL_SCENARIOS.keys())
    else:
        scenario_names = [args.scenario]
    
    methodology = "Adaptive (with reconnaissance)" if enable_recon else "Naive (no reconnaissance)"
    
    print()
    print("=" * 70)
    print("ADVERSARIAL BENCHMARK: Red Team LLM vs Tenuo")
    print("=" * 70)
    print()
    print(f"Attacker model: {args.attacker_model}")
    print(f"Methodology: {methodology}")
    if enable_recon:
        print(f"Recon probes: {args.recon_probes} per scenario")
    print(f"Attack attempts: {args.max_attempts} per scenario")
    print(f"Scenarios: {len(scenario_names)}")
    print(f"Runs per scenario: {args.runs}")
    if args.ablation:
        print("Mode: ABLATION STUDY")
    print()
    
    # Handle multi-step mode
    if args.multi_step:
        from .multistep import MultiStepBenchmark, MULTI_STEP_SCENARIOS
        
        print("=" * 70)
        print("MULTI-STEP ATTACK CHAIN BENCHMARK")
        print("=" * 70)
        print()
        print(f"Scenarios: {list(MULTI_STEP_SCENARIOS.keys())}")
        print()
        
        ms_benchmark = MultiStepBenchmark(
            client=client,
            attacker_model=args.attacker_model,
            max_steps=args.max_attempts,
        )
        
        for scenario_name in MULTI_STEP_SCENARIOS.keys():
            result = ms_benchmark.run_scenario(scenario_name)
        
        return  # Exit after multi-step
    
    # Run benchmark (standard single-step mode)
    if args.ablation:
        print("=== PHASE 1: With Reconnaissance ===")
        with_recon = run_benchmark(client, args, enable_recon=True)
        
        print("\n=== PHASE 2: Without Reconnaissance ===")
        without_recon = run_benchmark(client, args, enable_recon=False)
        
        print_ablation_results(with_recon, without_recon)
        
        # Combine for output
        all_results = {}
        for name in scenario_names:
            all_results[f"{name}_recon"] = with_recon.get(name, [])
            all_results[f"{name}_no_recon"] = without_recon.get(name, [])
    else:
        all_results = run_benchmark(client, args, enable_recon=enable_recon)
        
        # Summary
        all_flat = [r for runs in all_results.values() for r in runs]
        
        if args.runs > 1:
            print_aggregated_summary(all_results, args.attacker_model)
        elif len(all_flat) > 1:
            print_summary(all_flat, recon_enabled=enable_recon, model=args.attacker_model)
    
    # Save results
    if args.output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "config": {
                "attacker_model": args.attacker_model,
                "max_attempts": args.max_attempts,
                "recon_probes": args.recon_probes,
                "runs": args.runs,
                "ablation": args.ablation,
            },
            "results": {},
        }
        
        for scenario_name, runs in all_results.items():
            output_data["results"][scenario_name] = []
            for r in runs:
                output_data["results"][scenario_name].append({
                    "success": r.success,
                    "attempts": r.num_attempts,
                    "blocked": r.blocked_attempts,
                    "recon_probes": r.recon_probes,
                    "strategies": r.strategies_tried,
                })
        
        # Add aggregated stats
        if args.runs > 1:
            output_data["aggregate"] = {}
            for scenario_name, runs in all_results.items():
                if runs:
                    agg = aggregate_runs(runs)
                    output_data["aggregate"][scenario_name] = {
                        "defense_rate_mean": agg.defense_rate_mean,
                        "defense_rate_std": agg.defense_rate_std,
                        "defense_rate_ci_lower": agg.defense_rate_ci_lower,
                        "defense_rate_ci_upper": agg.defense_rate_ci_upper,
                        "attempts_mean": agg.attempts_mean,
                    }
        
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
