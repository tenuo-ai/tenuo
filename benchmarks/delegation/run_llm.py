#!/usr/bin/env python3
"""
Run real LLM-based delegation benchmark with prompt injections.

Usage:
    python -m benchmarks.delegation.run_llm --model gpt-4o-mini
    python -m benchmarks.delegation.run_llm --scenario multi_agent
    python -m benchmarks.delegation.run_llm --scenario chain_attack
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

from .llm_scenarios import (
    MultiAgentDelegationScenario,
    DelegationChainScenario,
    INJECTION_PAYLOADS,
)


def run_multi_agent(model: str, output_dir: Optional[Path] = None) -> dict:
    """Run multi-agent injection scenario."""
    
    print("=" * 60)
    print("MULTI-AGENT DELEGATION BENCHMARK")
    print(f"Model: {model}")
    print(f"Injection payloads: {len(INJECTION_PAYLOADS)}")
    print("=" * 60)
    
    scenario = MultiAgentDelegationScenario(model=model)
    results = scenario.run_all_injections()
    
    # Summary
    total = len(results)
    blocked = sum(1 for r in results if not r.attack_succeeded)
    succeeded = sum(1 for r in results if r.attack_succeeded)
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Total injections: {total}")
    print(f"Attacks blocked:  {blocked} ({100*blocked//total}%)")
    print(f"Attacks succeeded: {succeeded}")
    
    if succeeded > 0:
        print("\n⚠️  WARNING: Some attacks escaped delegation constraints!")
        for r in results:
            if r.attack_succeeded:
                print(f"  - {r.payload[:50]}...")
    else:
        print("\n✓ All attacks bounded by delegation constraints")
    
    # Save results
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "multi_agent_results.json"
        with open(output_file, "w") as f:
            json.dump({
                "model": model,
                "total": total,
                "blocked": blocked,
                "succeeded": succeeded,
                "results": [
                    {
                        "payload": r.payload,
                        "tool_calls": r.tool_calls,
                        "blocked_calls": r.blocked_calls,
                        "allowed_calls": r.allowed_calls,
                        "attack_succeeded": r.attack_succeeded,
                    }
                    for r in results
                ],
            }, f, indent=2)
        print(f"\nResults saved to {output_file}")
    
    return {
        "total": total,
        "blocked": blocked,
        "succeeded": succeeded,
    }


def run_chain_attack(model: str, output_dir: Optional[Path] = None) -> dict:
    """Run delegation chain attack demo."""
    
    print("=" * 60)
    print("DELEGATION CHAIN ATTACK DEMO")
    print("=" * 60)
    print("Testing that each level can only transfer up to its limit:")
    print("  - Bot: max $50")
    print("  - Assistant: max $1,000")
    print("  - Manager: max $100,000")
    print("=" * 60)
    
    scenario = DelegationChainScenario(model=model)
    results = scenario.run_chain_attack_demo()
    
    # Summary
    blocked = sum(1 for r in results if r["blocked"])
    allowed = sum(1 for r in results if not r["blocked"])
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Attacks blocked: {blocked}/{len(results)}")
    
    if allowed > 0:
        print("\n⚠️  WARNING: Some over-limit transfers were allowed!")
    else:
        print("\n✓ All over-limit transfers blocked by delegation chain")
    
    return {
        "total": len(results),
        "blocked": blocked,
        "allowed": allowed,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run LLM-based delegation benchmarks with prompt injection",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenAI model to use (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--scenario",
        choices=["multi_agent", "chain_attack", "all"],
        default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Directory to save results",
    )
    
    args = parser.parse_args()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / timestamp if args.output else None
    
    if args.scenario in ("multi_agent", "all"):
        run_multi_agent(args.model, output_dir)
    
    if args.scenario in ("chain_attack", "all"):
        print("\n")
        run_chain_attack(args.model, output_dir)


if __name__ == "__main__":
    main()

