#!/usr/bin/env python3
"""
Escalation Prevention Benchmark CLI.

Measures how delegation bounds damage from compromised AI agents.
Runs Layer 1 (policy enforcement) and Layer 2 (cryptographic integrity).

Usage:
    python -m benchmarks.escalation.evaluate
    python -m benchmarks.escalation.evaluate --scenario email_exfil
    python -m benchmarks.escalation.evaluate --output results/report.json
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

from .scenarios import (
    SCENARIOS, run_scenario, run_all_scenarios,
    run_policy_scenarios, run_crypto_scenarios,
    run_holder_binding_scenario, run_crypto_integrity_scenario,
    run_chain_manipulation_scenario, ScenarioResult,
)


def print_result(result: ScenarioResult, verbose: bool = True):
    """Print formatted result for a single scenario."""
    width = 75

    print()
    print("+" + "-" * (width - 2) + "+")
    print(f"| {'ESCALATION PREVENTION BENCHMARK':<{width-4}} |")
    print("+" + "-" * (width - 2) + "+")
    print(f"| Scenario: {result.name:<{width-14}} |")
    print(f"| {result.description:<{width-4}} |")
    print(f"| Attacks tested: {len(result.attacks):<{width-20}} |")
    print("+" + "-" * 25 + "+" + "-" * 18 + "+" + "-" * (width - 47) + "+")
    print(f"| {'Metric':<23} | {'p-agent (broad)':<16} | {'q-agent (delegated)':<{width-49}} |")
    print("+" + "-" * 25 + "+" + "-" * 18 + "+" + "-" * (width - 47) + "+")
    print(f"| {'Attacks allowed':<23} | {result.p_allowed:<16} | {result.q_allowed:<{width-49}} |")
    print(f"| {'Attacks blocked':<23} | {result.p_blocked:<16} | {result.q_blocked:<{width-49}} |")
    print("+" + "-" * 25 + "+" + "-" * 18 + "+" + "-" * (width - 47) + "+")

    enforce_str = f"{result.escalation_prevented}/{result.expected_violations} ({result.enforcement_rate:.0%})"
    legit_str = f"{result.both_allowed} calls passed through correctly"
    print(f"| {'CAUGHT:':<26} {enforce_str:<{width-31}} |")
    print(f"| {'LEGITIMATE PRESERVED:':<26} {legit_str:<{width-31}} |")
    print("+" + "-" * (width - 2) + "+")

    if verbose:
        print()
        print("Attack Details:")
        print("-" * width)

        for i, attack in enumerate(result.attacks, 1):
            p_status = "allowed" if attack.p_allowed else "BLOCKED"
            q_status = "allowed" if attack.q_allowed else "BLOCKED"
            prevented = " [CAUGHT]" if attack.escalation_prevented else ""

            if attack.label:
                print(f"  {i:2}. [{attack.label}]")
                args_str = ", ".join(f"{k}={v!r}" for k, v in list(attack.args.items())[:3])
                print(f"      {attack.tool}({args_str})")
            else:
                args_str = ", ".join(f"{k}={v!r}" for k, v in list(attack.args.items())[:2])
                if len(attack.args) > 2:
                    args_str += ", ..."
                print(f"  {i:2}. {attack.tool}({args_str})")

            print(f"      p-agent: {p_status:<8} | q-agent: {q_status}{prevented}")


def _print_layer_summary(title: str, results: list[ScenarioResult]):
    total_prevented = sum(r.escalation_prevented for r in results)
    total_expected = sum(r.expected_violations for r in results)
    total_legitimate = sum(r.both_allowed for r in results)
    enforcement = total_prevented / total_expected if total_expected else 1.0

    print()
    print("=" * 75)
    print(title)
    print("=" * 75)
    print(f"  Scenarios: {len(results)}")
    print(f"  Attacks:   {sum(len(r.attacks) for r in results)}")
    print(f"  Caught:    {total_prevented}/{total_expected} ({enforcement:.0%})")
    print(f"  Legit:     {total_legitimate} preserved")
    print("=" * 75)


def main():
    parser = argparse.ArgumentParser(
        description="Escalation prevention benchmark (Layers 1+2)"
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["holder_binding", "crypto_integrity", "chain_manipulation", "all"],
        default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON file for results",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print summary",
    )
    args = parser.parse_args()

    if args.scenario == "all":
        policy = run_policy_scenarios()
        crypto = run_crypto_scenarios()

        print("\n--- Layer 1: Policy Enforcement ---")
        for r in policy:
            print_result(r, verbose=not args.quiet)
        _print_layer_summary("LAYER 1: POLICY ENFORCEMENT", policy)

        print("\n--- Layer 2: Cryptographic Integrity ---")
        for r in crypto:
            print_result(r, verbose=not args.quiet)
        _print_layer_summary("LAYER 2: CRYPTOGRAPHIC INTEGRITY", crypto)

        results = policy + crypto
    elif args.scenario == "holder_binding":
        results = [run_holder_binding_scenario()]
        for r in results:
            print_result(r, verbose=not args.quiet)
    elif args.scenario == "crypto_integrity":
        results = [run_crypto_integrity_scenario()]
        for r in results:
            print_result(r, verbose=not args.quiet)
    elif args.scenario == "chain_manipulation":
        results = [run_chain_manipulation_scenario()]
        for r in results:
            print_result(r, verbose=not args.quiet)
    else:
        results = [run_scenario(args.scenario)]
        for r in results:
            print_result(r, verbose=not args.quiet)

    if args.output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "scenarios": [
                {
                    "name": r.name,
                    "description": r.description,
                    "attacks": len(r.attacks),
                    "violations_caught": r.escalation_prevented,
                    "expected_violations": r.expected_violations,
                    "enforcement_rate": r.enforcement_rate,
                    "legitimate_preserved": r.both_allowed,
                }
                for r in results
            ],
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)

        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
