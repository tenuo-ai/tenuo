#!/usr/bin/env python3
"""
Run AgentDojo benchmarks in batches to avoid rate limits.

This script runs tasks one at a time with configurable delays to stay within
OpenAI API rate limits.
"""

import subprocess
import time
import sys
import argparse


RATE_LIMITED = "rate_limited"


def run_task(
    suite: str, task: str, api_key: str, python_path: str, model: str = None
) -> bool | str:
    """Run a single benchmark task. Returns True, False, or RATE_LIMITED."""
    print(f"\n{'=' * 60}")
    print(f"Running task: {task}")
    print(f"Model: {model if model else 'default'}")
    print(f"{'=' * 60}")

    cmd = [
        python_path,
        "-m",
        "benchmarks.agentdojo.evaluate",
        "--suite",
        suite,
        "--compare",
        "--tasks",
        task,
    ]

    if model:
        cmd.extend(["--model", model])

    env = {"OPENAI_API_KEY": api_key}

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout per task
        )

        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr, file=sys.stderr)

        if result.returncode == 0:
            print(f"✓ Task {task} completed successfully")
            return True
        else:
            print(f"✗ Task {task} failed with exit code {result.returncode}")

            if "rate_limit" in result.stderr.lower() or "429" in result.stderr:
                print("⚠ Rate limit detected!")
                return RATE_LIMITED

            return False

    except subprocess.TimeoutExpired:
        print(f"✗ Task {task} timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"✗ Task {task} failed with error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Run AgentDojo benchmarks in batches")
    parser.add_argument(
        "--suite",
        default="workspace",
        choices=["workspace", "banking", "travel", "slack"],
        help="Benchmark suite to run",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=30,
        help="Delay between tasks in seconds (default: 30)",
    )
    parser.add_argument(
        "--rate-limit-delay",
        type=int,
        default=5,
        help="Extra delay after rate limit in seconds (default: 5)",
    )
    parser.add_argument(
        "--tasks", nargs="+", default=None, help="Specific tasks to run (default: all)"
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Path to Python interpreter (default: current interpreter)",
    )
    parser.add_argument(
        "--model", default=None, help="Model to use (e.g. gpt-4o, gpt-5.1)"
    )

    args = parser.parse_args()

    # Get API key from environment
    import os

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        sys.exit(1)

    # Default tasks for workspace suite
    if args.tasks is None:
        args.tasks = [
            "user_task_0",
            "user_task_1",
            "user_task_3",
            "user_task_4",
            "user_task_5",
            "user_task_6",
            "user_task_7",
            "user_task_8",
            "user_task_9",
        ]

    print("Running AgentDojo benchmarks")
    print(f"Suite: {args.suite}")
    print(f"Tasks: {len(args.tasks)}")
    print(f"Delay: {args.delay}s")
    print(f"Rate limit delay: {args.rate_limit_delay}s")

    successful = 0
    failed = 0

    for i, task in enumerate(args.tasks):
        result = run_task(args.suite, task, api_key, args.python, args.model)

        if result is True:
            successful += 1
        else:
            failed += 1
            if result == RATE_LIMITED:
                print(f"Waiting {args.rate_limit_delay}s for rate limit...")
                time.sleep(args.rate_limit_delay)
                continue

        # Wait before next task (except for last one)
        if i < len(args.tasks) - 1:
            print(f"\nWaiting {args.delay}s before next task...")
            time.sleep(args.delay)

    print(f"\n{'=' * 60}")
    print("Batch complete!")
    print(f"Successful: {successful}/{len(args.tasks)}")
    print(f"Failed: {failed}/{len(args.tasks)}")
    print(f"Results saved to: results/{args.suite}/")
    print(f"{'=' * 60}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
