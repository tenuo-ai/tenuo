"""
Parse AgentDojo benchmark results from JSON log files.

Extracts attack success/failure, utility scores, and tool call metrics
from AgentDojo's output directory structure.
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TaskResult:
    """Single task result from AgentDojo."""

    task_id: str
    injection_task_id: Optional[str]
    is_attack: bool
    attack_success: bool  # True = attack succeeded (security failure)
    utility: float  # 0.0 to 1.0
    duration: float
    tool_calls: int
    error: Optional[str] = None


@dataclass
class BenchmarkResults:
    """Aggregated results from a benchmark run."""

    task_results: list[TaskResult]

    @property
    def attack_tasks(self) -> list[TaskResult]:
        """Get only attack (injection) tasks."""
        return [t for t in self.task_results if t.is_attack]

    @property
    def benign_tasks(self) -> list[TaskResult]:
        """Get only benign (non-injection) tasks."""
        return [t for t in self.task_results if not t.is_attack]

    @property
    def attack_success_count(self) -> int:
        """Number of attacks that succeeded."""
        return sum(1 for t in self.attack_tasks if t.attack_success)

    @property
    def attack_blocked_count(self) -> int:
        """Number of attacks that were blocked."""
        return sum(1 for t in self.attack_tasks if not t.attack_success)

    @property
    def attack_success_rate(self) -> float:
        """Percentage of attacks that succeeded."""
        attacks = self.attack_tasks
        return self.attack_success_count / len(attacks) if attacks else 0.0

    @property
    def mean_utility(self) -> float:
        """Average utility across all tasks."""
        if not self.task_results:
            return 0.0
        return sum(t.utility for t in self.task_results) / len(self.task_results)

    @property
    def mean_benign_utility(self) -> float:
        """Average utility on benign tasks only."""
        benign = self.benign_tasks
        if not benign:
            return 0.0
        return sum(t.utility for t in benign) / len(benign)

    @property
    def mean_attack_utility(self) -> float:
        """Average utility on attack tasks (should be low if blocked)."""
        attacks = self.attack_tasks
        if not attacks:
            return 0.0
        return sum(t.utility for t in attacks) / len(attacks)


def parse_agentdojo_result_file(path: Path) -> Optional[TaskResult]:
    """
    Parse a single AgentDojo result JSON file.

    Args:
        path: Path to result JSON file

    Returns:
        TaskResult if parsing succeeds, None otherwise
    """
    try:
        with open(path) as f:
            data = json.load(f)

        # Check if it's a valid task result
        if "utility" not in data or "duration" not in data:
            return None

        # Determine if this is an attack task
        is_attack = data.get("attack_type") is not None

        # AgentDojo's 'security' field:
        #   True = injection task completed successfully (attack succeeded)
        #   False = injection task failed (attack failed, system secure)
        # So attack_success = security (NOT inverted!)
        attack_success = data.get("security", False) if is_attack else False

        # Count tool calls
        tool_calls = 0
        if "messages" in data:
            for msg in data["messages"]:
                if msg.get("tool_calls"):
                    tool_calls += len(msg["tool_calls"])

        return TaskResult(
            task_id=data.get("user_task_id", "unknown"),
            injection_task_id=data.get("injection_task_id"),
            is_attack=is_attack,
            attack_success=attack_success,
            utility=float(data.get("utility", 0.0)),
            duration=data.get("duration", 0.0),
            tool_calls=tool_calls,
            error=data.get("error"),
        )

    except Exception as e:
        logger.warning(f"Failed to parse {path}: {e}")
        return None


def parse_benchmark_directory(logdir: Path) -> BenchmarkResults:
    """
    Parse all result files in an AgentDojo log directory.

    Args:
        logdir: Root directory containing benchmark results
                (e.g., results/workspace/20260218_120000/baseline/)

    Returns:
        BenchmarkResults with aggregated data
    """
    results = []

    # AgentDojo creates nested directories: logdir/pipeline_name/suite_name/...
    # Find all JSON files recursively
    if not logdir.exists():
        logger.warning(f"Log directory not found: {logdir}")
        return BenchmarkResults(task_results=[])

    json_files = list(logdir.rglob("*.json"))
    logger.info(f"Found {len(json_files)} JSON files in {logdir}")

    # Skip summary files
    skip_files = {"baseline.json", "with_tenuo.json", "authorization_metrics.json"}

    for path in json_files:
        if path.name in skip_files:
            continue

        result = parse_agentdojo_result_file(path)
        if result:
            results.append(result)

    logger.info(f"Parsed {len(results)} task results")
    logger.info(f"  Benign tasks: {len([r for r in results if not r.is_attack])}")
    logger.info(f"  Attack tasks: {len([r for r in results if r.is_attack])}")

    return BenchmarkResults(task_results=results)


def compare_paired_results(
    baseline_dir: Path,
    treatment_dir: Path,
) -> tuple[list[tuple[TaskResult, TaskResult]], list[str]]:
    """
    Match tasks between baseline and treatment runs for paired analysis.

    Args:
        baseline_dir: Directory with baseline results
        treatment_dir: Directory with treatment (Tenuo) results

    Returns:
        Tuple of (paired_results, unmatched_task_ids)
        - paired_results: List of (baseline_task, treatment_task) tuples
        - unmatched_task_ids: Task IDs that appear in only one condition
    """
    baseline_results = parse_benchmark_directory(baseline_dir)
    treatment_results = parse_benchmark_directory(treatment_dir)

    # Create lookup by task ID (user_task_id + injection_task_id)
    def task_key(task: TaskResult) -> str:
        base = task.task_id
        if task.injection_task_id:
            return f"{base}_{task.injection_task_id}"
        return base

    baseline_map = {task_key(t): t for t in baseline_results.task_results}
    treatment_map = {task_key(t): t for t in treatment_results.task_results}

    # Find matched pairs
    paired = []
    for key in baseline_map:
        if key in treatment_map:
            paired.append((baseline_map[key], treatment_map[key]))

    # Find unmatched
    all_keys = set(baseline_map.keys()) | set(treatment_map.keys())
    matched_keys = set(baseline_map.keys()) & set(treatment_map.keys())
    unmatched = list(all_keys - matched_keys)

    logger.info(f"Matched {len(paired)} paired tasks")
    if unmatched:
        logger.warning(f"{len(unmatched)} tasks appear in only one condition")

    return paired, unmatched


def extract_mcnemar_data(
    baseline_dir: Path,
    treatment_dir: Path,
) -> tuple[int, int, int, int]:
    """
    Extract contingency table for McNemar's test.

    Args:
        baseline_dir: LLM-only results
        treatment_dir: LLM + Tenuo results

    Returns:
        Tuple of (both_blocked, llm_only_blocked, tenuo_only_blocked, both_failed)
    """
    paired, unmatched = compare_paired_results(baseline_dir, treatment_dir)

    both_blocked = 0
    llm_only_blocked = 0
    tenuo_only_blocked = 0
    both_failed = 0

    for baseline_task, treatment_task in paired:
        # Only count attack tasks
        if not baseline_task.is_attack:
            continue

        # Invert: attack_success=True means security failed
        llm_blocked = not baseline_task.attack_success
        tenuo_blocked = not treatment_task.attack_success

        if llm_blocked and tenuo_blocked:
            both_blocked += 1
        elif llm_blocked and not tenuo_blocked:
            llm_only_blocked += 1
        elif not llm_blocked and tenuo_blocked:
            tenuo_only_blocked += 1
        else:
            both_failed += 1

    logger.info("McNemar contingency table:")
    logger.info(f"  Both blocked: {both_blocked}")
    logger.info(f"  LLM only blocked: {llm_only_blocked}")
    logger.info(f"  Tenuo only blocked: {tenuo_only_blocked}")
    logger.info(f"  Both failed: {both_failed}")

    return both_blocked, llm_only_blocked, tenuo_only_blocked, both_failed


def extract_utility_scores(
    baseline_dir: Path,
    treatment_dir: Path,
) -> tuple[list[float], list[float]]:
    """
    Extract paired utility scores for t-test.

    Args:
        baseline_dir: Results without warrants
        treatment_dir: Results with warrants

    Returns:
        Tuple of (baseline_scores, treatment_scores) - paired and aligned
    """
    paired, _ = compare_paired_results(baseline_dir, treatment_dir)

    baseline_scores = []
    treatment_scores = []

    for baseline_task, treatment_task in paired:
        # Only use benign tasks for utility comparison
        if baseline_task.is_attack:
            continue

        baseline_scores.append(baseline_task.utility)
        treatment_scores.append(treatment_task.utility)

    logger.info(f"Extracted {len(baseline_scores)} paired utility scores")

    return baseline_scores, treatment_scores
