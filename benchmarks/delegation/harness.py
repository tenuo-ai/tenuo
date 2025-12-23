"""
Delegation benchmark harness.

Runs delegation scenarios and collects metrics.
"""

from dataclasses import dataclass, field
from typing import Optional
import time
import json
from pathlib import Path

from tenuo import Warrant, ScopeViolation

from .scenarios import (
    BaseDelegationScenario,
    DelegationResult,
    ManagerAssistantScenario,
    ChainDepthScenario,
    MixedAttackScenario,
    TTLBoundedScenario,
    TemporalScopingScenario,
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
            "pass_rate": f"{100 * self.passed / self.total_tests:.1f}%" if self.total_tests > 0 else "N/A",
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
    
    Tests that warrant chains correctly enforce attenuation.
    """
    
    SCENARIOS = {
        "manager_assistant": ManagerAssistantScenario,
        "chain_depth": ChainDepthScenario,
        "mixed_attack": MixedAttackScenario,
        "ttl_bounded": TTLBoundedScenario,
        "temporal_scoping": TemporalScopingScenario,
    }
    
    def __init__(self, scenario_name: str = "manager_assistant", **kwargs):
        """
        Args:
            scenario_name: Which scenario to run
            **kwargs: Passed to scenario constructor (e.g., depth=5 for chain_depth)
        """
        if scenario_name not in self.SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario_name}. Available: {list(self.SCENARIOS.keys())}")
        
        self.scenario: BaseDelegationScenario = self.SCENARIOS[scenario_name](**kwargs)
        self.metrics = DelegationMetrics()
        self.warrants: dict[str, Warrant] = {}
    
    def _get_holder_key(self, role: str):
        """Get the signing key for a role (for PoP signing).
        
        The holder key must match the warrant's authorized holder for PoP to work.
        """
        # Access scenario's keys based on role
        scenario = self.scenario
        
        if hasattr(scenario, 'manager_key') and role == "manager":
            return scenario.manager_key
        if hasattr(scenario, 'assistant_key') and role == "assistant":
            return scenario.assistant_key
        if hasattr(scenario, 'bot_key') and role == "bot":
            return scenario.bot_key
        
        # For temporal scoping scenario: all warrants use the same agent key
        if hasattr(scenario, 'agent_key'):
            return scenario.agent_key
        
        # For chain depth scenario:
        # - Root warrant's holder is keys[1]
        # - level_N warrant's holder is keys[N+1] (or keys[N] at final level)
        if hasattr(scenario, 'keys'):
            if role == "root":
                return scenario.keys[1]  # Root's holder is keys[1]
            if role.startswith("level_"):
                level = int(role.split("_")[1])
                # level_N's holder is keys[N+1], capped at len(keys)-1
                holder_idx = min(level + 1, len(scenario.keys) - 1)
                return scenario.keys[holder_idx]
        
        raise ValueError(f"No key found for role: {role}")
    
    def setup(self) -> None:
        """Initialize warrant chain for the scenario."""
        self.warrants = self.scenario.setup()
        print(f"[Delegation] Created warrant chain: {list(self.warrants.keys())}")
    
    def run(self) -> DelegationMetrics:
        """
        Run all attacks in the scenario.
        
        Returns:
            Metrics with results
        """
        if not self.warrants:
            self.setup()
        
        # Check if this is a TTL scenario with special handling
        if hasattr(self.scenario, 'get_ttl_attack_sequence'):
            return self._run_ttl_scenario()
        
        attacks = self.scenario.get_attacks()
        print(f"[Delegation] Running {len(attacks)} attack vectors...")
        
        for attack in attacks:
            self._run_attack(attack)
        
        return self.metrics
    
    def _run_ttl_scenario(self) -> DelegationMetrics:
        """
        Run TTL-based scenario with timed phases.
        
        Tests that short TTL limits attack window even with same capabilities.
        """
        import time
        
        sequence = self.scenario.get_ttl_attack_sequence()
        print(f"[TTL Scenario] Running {len(sequence)} phases...")
        
        for phase in sequence:
            phase_name = phase["phase"]
            delay = phase["delay"]
            attacks = phase["attacks"]
            
            if delay > 0:
                print(f"\n[TTL] Waiting {delay}s for TTL expiry...")
                time.sleep(delay)
            
            print(f"\n[TTL] Phase: {phase_name}")
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
        
        # Attempt authorization
        tool = action["tool"]
        args = action["args"]
        
        start = time.perf_counter()
        try:
            # Create PoP signature for the tool call
            pop = warrant.create_pop_signature(holder_key, tool, args)
            
            # authorize() returns True/False, not exceptions
            result = warrant.authorize(tool, args, signature=bytes(pop))
            actual = "allowed" if result else "denied"
        except ScopeViolation:
            actual = "denied"
        except Exception as e:
            print(f"[Delegation] Unexpected error: {e}")
            actual = "error"
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
                print(f"[Delegation] ❌ FALSE NEGATIVE: {attack_point} -> {tool}({args})")
            elif expected == "allowed" and actual == "denied":
                self.metrics.false_positives += 1
                print(f"[Delegation] ❌ FALSE POSITIVE: {attack_point} -> {tool}({args})")
        
        status = "✓" if result.passed else "✗"
        print(f"[Delegation] {status} {attack_point}: {tool}({args}) = {actual} (expected {expected})")
    
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
        print(f"Passed:          {m.passed} ({100 * m.passed / m.total_tests:.0f}%)" if m.total_tests > 0 else "N/A")
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
        
        kwargs = {}
        if name == "chain_depth":
            kwargs["depth"] = 5
        
        harness = DelegationHarness(name, **kwargs)
        harness.setup()
        metrics = harness.run()
        harness.print_summary()
        
        results[name] = metrics
    
    return results

