"""
Delegation benchmark harness.

Runs delegation scenarios and collects metrics.
"""

from dataclasses import dataclass, field
import time
import json
from pathlib import Path

from tenuo import Warrant, Authorizer, ScopeViolation

from .scenarios import (
    BaseDelegationScenario,
    DelegationResult,
    TemporalScopingScenario,
    RangeLimitScenario,
    PatternMatchScenario,
    ToolScopingScenario,
)


@dataclass
class DelegationMetrics:
    """Metrics collected during delegation benchmark."""

    total_tests: int = 0
    passed: int = 0
    failed: int = 0

    # Breakdown by attack type
    delegation_violations_caught: int = 0  # Attacks correctly denied
    false_positives: int = 0  # Legitimate actions incorrectly denied
    false_negatives: int = 0  # Attacks incorrectly allowed

    # Performance
    total_auth_time_ms: float = 0.0
    auth_calls: int = 0

    results: list[DelegationResult] = field(default_factory=list)

    @property
    def avg_auth_time_ms(self) -> float:
        return self.total_auth_time_ms / self.auth_calls if self.auth_calls > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": f"{100 * self.passed / self.total_tests:.1f}%"
            if self.total_tests > 0
            else "N/A",
            "delegation_violations_caught": self.delegation_violations_caught,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "avg_auth_time_ms": round(self.avg_auth_time_ms, 3),
            "results": [
                {
                    "scenario": r.scenario,
                    "chain": r.delegation_chain,
                    "attack_point": r.attack_point,
                    "action": r.attempted_action,
                    "expected": r.expected,
                    "actual": r.actual,
                    "passed": r.passed,
                }
                for r in self.results
            ],
        }


class DelegationHarness:
    """
    Harness for running delegation benchmarks.

    Tests that warrant constraints are correctly enforced.
    """

    SCENARIOS = {
        "temporal_scoping": TemporalScopingScenario,
        "range_limit": RangeLimitScenario,
        "pattern_match": PatternMatchScenario,
        "tool_scoping": ToolScopingScenario,
    }

    def __init__(self, scenario_name: str = "temporal_scoping", **kwargs):
        """
        Args:
            scenario_name: Which scenario to run
            **kwargs: Passed to scenario constructor
        """
        if scenario_name not in self.SCENARIOS:
            raise ValueError(
                f"Unknown scenario: {scenario_name}. Available: {list(self.SCENARIOS.keys())}"
            )

        self.scenario: BaseDelegationScenario = self.SCENARIOS[scenario_name](**kwargs)
        self.metrics = DelegationMetrics()
        self.warrants: dict[str, Warrant] = {}

    def _get_holder_key(self, role: str):
        """Get the signing key for a role (for PoP signing).

        All scenarios use the same agent_key for all warrants.
        """
        if hasattr(self.scenario, "agent_key"):
            return self.scenario.agent_key

        raise ValueError(f"No key found for role: {role}")

    def setup(self) -> None:
        """Initialize warrants for the scenario."""
        self.warrants = self.scenario.setup()
        print(
            f"[Delegation] Created {len(self.warrants)} warrants: {list(self.warrants.keys())}"
        )

    def run(self) -> DelegationMetrics:
        """
        Run all attacks in the scenario.

        Returns:
            Metrics with results
        """
        if not self.warrants:
            self.setup()

        attacks = self.scenario.get_attacks()
        print(f"[Delegation] Running {len(attacks)} attack vectors...")

        for attack in attacks:
            self._run_attack(attack)

        return self.metrics

    def _run_attack(self, attack: dict) -> None:
        """Execute a single attack and record result."""
        attack_point = attack["attack_point"]
        action = attack["action"]
        expected = attack["expected"]

        # Get the warrant for the attack point
        warrant = self.warrants.get(attack_point)
        if warrant is None:
            print(f"[Delegation] Warning: No warrant for {attack_point}, skipping")
            return

        # Get the corresponding key for PoP
        holder_key = self._get_holder_key(attack_point)

        # Create authorizer with issuer as trusted root
        authorizer = Authorizer(trusted_roots=[self.scenario.issuer_key.public_key])

        # Attempt authorization
        tool = action["tool"]
        args = action["args"]

        start = time.perf_counter()
        try:
            # Create PoP signature for the tool call
            pop = warrant.sign(holder_key, tool, args)

            # authorize() raises exceptions on failure
            authorizer.authorize(
                warrant,
                tool,
                args,
                signature=bytes(pop),
                approvals=[],
            )
            actual = "allowed"
        except ScopeViolation:
            actual = "denied"
        except Exception:
            # Any other exception also means denied
            actual = "denied"
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.metrics.total_auth_time_ms += elapsed_ms
            self.metrics.auth_calls += 1

        # Record result
        result = DelegationResult(
            scenario=self.scenario.name,
            delegation_chain=list(self.warrants.keys()),
            attack_point=attack_point,
            attempted_action=action,
            expected=expected,
            actual=actual,
        )

        self.metrics.results.append(result)
        self.metrics.total_tests += 1

        if result.passed:
            self.metrics.passed += 1
            if expected == "denied":
                self.metrics.delegation_violations_caught += 1
        else:
            self.metrics.failed += 1
            if expected == "denied" and actual == "allowed":
                self.metrics.false_negatives += 1
                print(f"[Delegation] FALSE NEGATIVE: {attack_point} -> {tool}({args})")
            elif expected == "allowed" and actual == "denied":
                self.metrics.false_positives += 1
                print(f"[Delegation] FALSE POSITIVE: {attack_point} -> {tool}({args})")

        status = "✓" if result.passed else "✗"
        print(
            f"[Delegation] {status} {attack_point}: {tool}({args}) = {actual} (expected {expected})"
        )

    def save_results(self, path: Path) -> None:
        """Save results to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.metrics.to_dict(), f, indent=2)
        print(f"[Delegation] Results saved to {path}")

    def print_summary(self) -> None:
        """Print human-readable summary."""
        m = self.metrics
        print("\n" + "=" * 60)
        print(f"DELEGATION BENCHMARK: {self.scenario.name}")
        print("=" * 60)
        print(f"Total tests:     {m.total_tests}")
        print(
            f"Passed:          {m.passed} ({100 * m.passed / m.total_tests:.0f}%)"
            if m.total_tests > 0
            else "N/A"
        )
        print(f"Failed:          {m.failed}")
        print()
        print(f"Attacks blocked: {m.delegation_violations_caught}")
        print(f"False positives: {m.false_positives}")
        print(f"False negatives: {m.false_negatives}")
        print()
        print(f"Avg auth time:   {m.avg_auth_time_ms:.3f} ms")
        print("=" * 60)


def run_all_scenarios() -> dict[str, DelegationMetrics]:
    """Run all delegation scenarios and return combined results."""
    results = {}

    for name in DelegationHarness.SCENARIOS:
        print(f"\n{'=' * 60}")
        print(f"Running scenario: {name}")
        print("=" * 60)

        harness = DelegationHarness(name)
        harness.setup()
        metrics = harness.run()
        harness.print_summary()

        results[name] = metrics

    return results
