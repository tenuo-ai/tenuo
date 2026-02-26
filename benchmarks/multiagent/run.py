#!/usr/bin/env python3
"""
CLI for the multi-agent delegation benchmark.

Usage:
    python -m benchmarks.multiagent.run
    python -m benchmarks.multiagent.run --mode deterministic
    python -m benchmarks.multiagent.run --mode llm --model gpt-4o-mini --runs 5
    python -m benchmarks.multiagent.run --mode both --scenario config_review
"""

import argparse
import os
import time

from .tasks import ALL_SCENARIOS
from .policies import CONDITIONS
from .harness import run_all_deterministic, run_all_llm, run_deterministic, run_llm, TrialResult
from .report import save_report


def _print_trial(r: TrialResult):
    asr = "ATTACK" if r.attack_succeeded else "safe"
    tcr = "TASK OK" if r.task_succeeded else "task FAIL"
    print(f"  [{r.condition:<12}] {asr:<7} | {tcr:<9} | "
          f"{r.calls_allowed} allowed, {r.calls_blocked} blocked")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-agent delegation benchmark"
    )
    parser.add_argument(
        "--mode",
        choices=["deterministic", "llm", "both"],
        default="deterministic",
    )
    parser.add_argument(
        "--scenario",
        choices=list(ALL_SCENARIOS.keys()) + ["all"],
        default="all",
    )
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--runs", type=int, default=5,
                        help="Runs per cell in LLM mode (default: 5)")
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    scenarios = (
        ALL_SCENARIOS if args.scenario == "all"
        else {args.scenario: ALL_SCENARIOS[args.scenario]}
    )

    print("=" * 70)
    print("MULTI-AGENT DELEGATION BENCHMARK")
    print("=" * 70)
    print()

    all_results: list[TrialResult] = []

    # ── Deterministic mode ──
    if args.mode in ("deterministic", "both"):
        print("--- Deterministic Mode ---")
        print()
        t0 = time.perf_counter()

        for name, scenario in scenarios.items():
            print(f"Scenario: {name}")
            for cond in CONDITIONS:
                r = run_deterministic(scenario, cond)
                all_results.append(r)
                _print_trial(r)
            print()

        elapsed = time.perf_counter() - t0
        det_results = [r for r in all_results if True]  # all so far
        scoped = [r for r in det_results if r.condition == "task_scoped"]
        baseline = [r for r in det_results if r.condition == "no_warrant"]
        scoped_asr = sum(1 for r in scoped if r.attack_succeeded) / len(scoped) if scoped else 0
        baseline_asr = sum(1 for r in baseline if r.attack_succeeded) / len(baseline) if baseline else 0
        print(f"Deterministic: baseline ASR={baseline_asr:.0%} → task_scoped ASR={scoped_asr:.0%} "
              f"({elapsed:.2f}s)")
        print()

    # ── LLM mode ──
    if args.mode in ("llm", "both"):
        api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            print("LLM mode: Skipped (no OPENAI_API_KEY)")
        else:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)

            print(f"--- LLM Mode ({args.model}, {args.runs} runs/cell) ---")
            print()
            t0 = time.perf_counter()

            for name, scenario in scenarios.items():
                print(f"Scenario: {name}")
                for cond in CONDITIONS:
                    for run_i in range(args.runs):
                        r = run_llm(scenario, cond, args.model, client)
                        all_results.append(r)
                    trials = [r for r in all_results
                              if r.scenario == name and r.condition == cond and r.mode == "llm"]
                    asr = sum(1 for t in trials if t.attack_succeeded) / len(trials)
                    tcr = sum(1 for t in trials if t.task_succeeded) / len(trials)
                    print(f"  [{cond:<12}] ASR={asr:.0%} TCR={tcr:.0%} ({len(trials)} runs)")
                print()

            elapsed = time.perf_counter() - t0
            print(f"LLM mode complete ({elapsed:.1f}s)")
            print()

    # ── Report ──
    if all_results:
        model = args.model if args.mode in ("llm", "both") else None
        out_path = save_report(all_results, model=model)
        print(f"Report saved to: {out_path}")
    else:
        print("No results to report.")

    print("=" * 70)


if __name__ == "__main__":
    main()
