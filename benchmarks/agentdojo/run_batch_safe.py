#!/usr/bin/env python3
"""
Run AgentDojo benchmarks in batches with rate limit handling.

This script runs tasks sequentially with delays to stay within OpenAI rate limits.
"""

import subprocess
import time
import sys
import argparse
from pathlib import Path


def run_single_task(suite: str, task: str, model: str, output_dir: Path) -> bool:
    """Run a single benchmark task."""
    print(f"\n{'='*60}")
    print(f"Running task: {task}")
    print(f"Model: {model}")
    print(f"{'='*60}")
    
    cmd = [
        "python", "-m", "benchmarks.agentdojo.evaluate",
        "--suite", suite,
        "--compare",
        "--tasks", task,
        "--model", model,
        "--output-dir", str(output_dir),
    ]
    
    try:
        result = subprocess.run(
            cmd,
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
            print(f"✗ Task {task} failed with code {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"✗ Task {task} timed out")
        return False
    except Exception as e:
        print(f"✗ Task {task} failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Run AgentDojo benchmarks in batches with rate limit handling"
    )
    parser.add_argument("--suite", required=True, help="Suite to run")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model to use")
    parser.add_argument("--output-dir", default="benchmarks/agentdojo/results/batch", help="Output directory")
    parser.add_argument("--delay", type=int, default=5, help="Delay between tasks (seconds)")
    parser.add_argument("--start-task", type=int, default=0, help="Start from task N")
    parser.add_argument("--max-tasks", type=int, default=None, help="Max tasks to run")
    
    args = parser.parse_args()
    
    # Get all tasks for the suite
    # For now, hardcode workspace tasks (0-39)
    all_tasks = [f"user_task_{i}" for i in range(40)]
    
    # Filter tasks
    tasks = all_tasks[args.start_task:]
    if args.max_tasks:
        tasks = tasks[:args.max_tasks]
    
    print(f"Running {len(tasks)} tasks from suite '{args.suite}'")
    print(f"Model: {args.model}")
    print(f"Delay: {args.delay}s between tasks")
    print(f"Output: {args.output_dir}")
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run tasks
    completed = 0
    failed = 0
    
    for i, task in enumerate(tasks):
        print(f"\n[{i+1}/{len(tasks)}] Running {task}...")
        
        success = run_single_task(args.suite, task, args.model, output_dir)
        
        if success:
            completed += 1
        else:
            failed += 1
        
        # Delay between tasks to avoid rate limits
        if i < len(tasks) - 1:  # Don't delay after last task
            print(f"Waiting {args.delay}s before next task...")
            time.sleep(args.delay)
    
    # Summary
    print(f"\n{'='*60}")
    print("BATCH RUN COMPLETE")
    print(f"{'='*60}")
    print(f"Completed: {completed}/{len(tasks)}")
    print(f"Failed: {failed}/{len(tasks)}")
    print(f"Results: {output_dir}")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
