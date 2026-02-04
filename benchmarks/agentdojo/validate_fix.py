#!/usr/bin/env python3
"""
Validate that the utility measurement fix works correctly.

This script runs a minimal benchmark (1 user task, 1 injection task) to verify:
1. Baseline and Tenuo write to different directories
2. Per-task results are persisted correctly
3. Utility metrics can be calculated

Cost: ~$0.10 (minimal tasks)
"""

import sys
import json
from pathlib import Path
from datetime import datetime


def main():
    print("=" * 70)
    print("VALIDATING UTILITY MEASUREMENT FIX")
    print("=" * 70)
    print()

    # Import harness
    try:
        from benchmarks.agentdojo.harness import TenuoAgentDojoHarness
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        print()
        print("Install dependencies:")
        print("  uv pip install -r benchmarks/agentdojo/requirements.txt")
        sys.exit(1)

    # Check OpenAI API key
    import os
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ OPENAI_API_KEY environment variable not set")
        sys.exit(1)

    print("✓ Dependencies OK")
    print("✓ API key found")
    print()

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("results") / "validation" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output: {output_dir}")
    print()

    # Create harness
    print("Creating harness...")
    harness = TenuoAgentDojoHarness(
        suite_name="workspace",
        model="gpt-4o-mini",
    )

    # Get first user task
    task_ids = [list(harness.suite.user_tasks.keys())[0]]
    print(f"Testing with task: {task_ids[0]}")
    print()

    # Test 1: Baseline pipeline name
    print("=" * 70)
    print("TEST 1: Baseline Pipeline Name")
    print("=" * 70)
    baseline_pipeline = harness._create_pipeline(with_tenuo=False)
    baseline_name = baseline_pipeline.name
    print(f"Pipeline name: {baseline_name}")

    if "baseline" not in baseline_name.lower():
        print("❌ FAILED: Baseline pipeline should contain 'baseline' in name")
        sys.exit(1)
    else:
        print("✓ PASS: Baseline pipeline has correct name")
    print()

    # Test 2: Tenuo pipeline name
    print("=" * 70)
    print("TEST 2: Tenuo Pipeline Name")
    print("=" * 70)
    tenuo_pipeline = harness._create_pipeline(with_tenuo=True)
    tenuo_name = tenuo_pipeline.name
    print(f"Pipeline name: {tenuo_name}")

    if "tenuo" not in tenuo_name.lower():
        print("❌ FAILED: Tenuo pipeline should contain 'tenuo' in name")
        sys.exit(1)

    if tenuo_name == baseline_name:
        print(f"❌ FAILED: Pipeline names are identical: {tenuo_name}")
        sys.exit(1)
    else:
        print("✓ PASS: Tenuo pipeline has unique name")
    print()

    # Test 3: Run baseline
    print("=" * 70)
    print("TEST 3: Baseline Execution")
    print("=" * 70)
    print("Running baseline (1 user task, no attacks)...")

    baseline_results = harness.run_benchmark(
        with_tenuo=False,
        with_attacks=False,
        user_tasks=task_ids,
        logdir=output_dir / "baseline",
    )

    baseline_dir = output_dir / "baseline" / baseline_name
    if not baseline_dir.exists():
        print(f"❌ FAILED: Baseline directory not created: {baseline_dir}")
        sys.exit(1)

    baseline_files = list(baseline_dir.rglob("*.json"))
    if not baseline_files:
        print(f"❌ FAILED: No result files in {baseline_dir}")
        sys.exit(1)

    print(f"✓ PASS: Baseline wrote {len(baseline_files)} result file(s)")
    print(f"  Location: {baseline_dir}")
    print()

    # Test 4: Run with Tenuo
    print("=" * 70)
    print("TEST 4: Tenuo Execution")
    print("=" * 70)
    print("Running with Tenuo (1 user task, no attacks)...")

    tenuo_results = harness.run_benchmark(
        with_tenuo=True,
        with_attacks=False,
        user_tasks=task_ids,
        logdir=output_dir / "with_tenuo",
    )

    tenuo_dir = output_dir / "with_tenuo" / tenuo_name
    if not tenuo_dir.exists():
        print(f"❌ FAILED: Tenuo directory not created: {tenuo_dir}")
        sys.exit(1)

    tenuo_files = list(tenuo_dir.rglob("*.json"))
    if not tenuo_files:
        print(f"❌ FAILED: No result files in {tenuo_dir}")
        sys.exit(1)

    print(f"✓ PASS: Tenuo wrote {len(tenuo_files)} result file(s)")
    print(f"  Location: {tenuo_dir}")
    print()

    # Test 5: Verify directory separation
    print("=" * 70)
    print("TEST 5: Directory Separation")
    print("=" * 70)

    if baseline_dir == tenuo_dir:
        print(f"❌ FAILED: Directories are identical: {baseline_dir}")
        sys.exit(1)

    print("✓ PASS: Baseline and Tenuo wrote to different directories")
    print(f"  Baseline: {baseline_dir.name}")
    print(f"  Tenuo:    {tenuo_dir.name}")
    print()

    # Test 6: Verify result format
    print("=" * 70)
    print("TEST 6: Result Format")
    print("=" * 70)

    baseline_file = baseline_files[0]
    with open(baseline_file) as f:
        baseline_data = json.load(f)

    required_fields = ["utility", "duration"]
    missing = [f for f in required_fields if f not in baseline_data]

    if missing:
        print(f"❌ FAILED: Missing fields: {missing}")
        print(f"  File: {baseline_file}")
        sys.exit(1)

    print("✓ PASS: Result files have correct format")
    print(f"  Utility: {baseline_data.get('utility')}")
    print(f"  Duration: {baseline_data.get('duration')}s")
    print()

    # Summary
    print("=" * 70)
    print("ALL TESTS PASSED ✓")
    print("=" * 70)
    print()
    print("The utility measurement fix is working correctly!")
    print()
    print("Next steps:")
    print("  1. Run full benchmark:")
    print("     python -m benchmarks.agentdojo.evaluate --suite workspace --compare")
    print()
    print("  2. Analyze results:")
    print("     python -m benchmarks.agentdojo.analyze results/workspace/<timestamp>/")
    print()
    print(f"Validation results saved to: {output_dir}")


if __name__ == "__main__":
    main()
