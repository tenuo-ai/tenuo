"""
AgentDojo benchmark with delegation.

Runs AgentDojo's full benchmark but with a delegated warrant chain:
- Manager gets full suite constraints
- Assistant gets attenuated (narrowed) warrant via delegation
- Attacks that work against manager should fail against assistant

This demonstrates Tenuo's core value: delegation bounds damage.
"""

from typing import Optional, Sequence
from pathlib import Path
from dataclasses import dataclass

from openai import OpenAI
from agentdojo.benchmark import get_suite, benchmark_suite_with_injections
from agentdojo.agent_pipeline import (
    BasePipelineElement,
    AgentPipeline,
    OpenAILLM,
    InitQuery,
    ToolsExecutor,
    ToolsExecutionLoop,
    SystemMessage,
)
from agentdojo.attacks.baseline_attacks import DirectAttack
import agentdojo.logging as adlog

from tenuo import SigningKey, Warrant

from ..agentdojo.warrant_templates import (
    get_constraints_for_suite,
    DELEGATION_NARROWING,
)
from ..agentdojo.tool_wrapper import wrap_tools, AuthorizationMetrics


@dataclass
class DelegationComparisonResults:
    """Results comparing manager vs assistant."""

    suite: str
    model: str

    # Manager (broad scope) results
    manager_allowed: int = 0
    manager_blocked: int = 0
    manager_attacks_succeeded: int = 0

    # Assistant (delegated, narrow scope) results
    assistant_allowed: int = 0
    assistant_blocked: int = 0
    assistant_attacks_succeeded: int = 0

    # Key metric: attacks that worked on manager but failed on assistant
    delegation_prevented: int = 0


class DelegatedPipeline(BasePipelineElement):
    """
    Pipeline with delegated warrant (narrower than manager).
    """

    def __init__(
        self,
        base_pipeline: BasePipelineElement,
        suite_name: str,
        manager_warrant: Warrant,
        manager_key: SigningKey,
        assistant_key: SigningKey,
        metrics: AuthorizationMetrics,
    ):
        super().__init__()
        self.base_pipeline = base_pipeline
        self.suite_name = suite_name
        self.manager_key = manager_key
        self.assistant_key = assistant_key
        self.metrics = metrics

        # Create delegated warrant with narrower scope
        self.assistant_warrant = self._delegate_warrant(manager_warrant)
        self.warrants = self._create_tool_warrants()

    def _delegate_warrant(self, manager_warrant: Warrant) -> Warrant:
        """Create assistant warrant by delegating from manager with narrowing."""

        # Get narrowing rules for this suite
        narrowing = DELEGATION_NARROWING.get(self.suite_name, {})

        if not narrowing:
            # No narrowing defined - just delegate with same constraints
            # (still demonstrates delegation chain even without attenuation)
            return (
                manager_warrant.attenuate_builder()
                .inherit_all()
                .holder(self.assistant_key.public_key)
                .ttl(1800)
                .delegate(self.manager_key)
            )

        # Build attenuated warrant with narrowed constraints
        builder = manager_warrant.attenuate_builder()
        builder.inherit_all()

        for tool_name, constraints in narrowing.items():
            builder.capability(tool_name.lower(), constraints)

        builder.holder(self.assistant_key.public_key)
        builder.ttl(1800)

        return builder.delegate(self.manager_key)

    def _create_tool_warrants(self) -> dict[str, Warrant]:
        """Create per-tool warrants from assistant's capabilities."""
        warrants = {}
        for tool in self.assistant_warrant.tools:
            warrants[tool.lower()] = self.assistant_warrant
        return warrants

    def query(self, query, runtime, env=None, messages=None, extra_args=None):
        """Execute with delegated warrant constraints."""
        if messages is None:
            messages = []
        if extra_args is None:
            extra_args = {}

        if hasattr(runtime, "functions"):
            original_functions = runtime.functions.copy()

            protected_tools, _ = wrap_tools(
                tools=original_functions,
                warrants=self.warrants,
                holder_key=self.assistant_key,
                metrics=self.metrics,
            )

            runtime.functions.clear()
            runtime.functions.update(protected_tools)

        try:
            return self.base_pipeline.query(query, runtime, env, messages, extra_args)
        finally:
            if hasattr(runtime, "functions"):
                runtime.functions.clear()
                runtime.functions.update(original_functions)


class DelegationBenchmark:
    """
    Run AgentDojo benchmark comparing manager vs delegated assistant.

    This demonstrates that delegation bounds damage:
    - Same attacks, same LLM
    - Manager: broader warrant, more attacks succeed
    - Assistant: delegated warrant, attacks bounded
    """

    def __init__(
        self,
        suite_name: str = "workspace",
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
    ):
        self.suite_name = suite_name
        self.model = model
        self.client = OpenAI(api_key=api_key) if api_key else OpenAI()
        self.suite = get_suite("v1", suite_name)

        # Key hierarchy
        self.org_key = SigningKey.generate()
        self.manager_key = SigningKey.generate()
        self.assistant_key = SigningKey.generate()

        # Create manager warrant with full suite constraints
        self.manager_warrant = self._create_manager_warrant()

    def _create_manager_warrant(self) -> Warrant:
        """Create manager warrant with full suite constraints."""
        constraints = get_constraints_for_suite(self.suite_name)

        builder = Warrant.builder()
        for tool_name, tool_constraints in constraints.items():
            builder.capability(tool_name.lower(), tool_constraints)

        builder.holder(self.manager_key.public_key)
        builder.ttl(3600)

        return builder.issue(self.org_key)

    def run_comparison(
        self,
        user_tasks: Optional[Sequence[str]] = None,
        injection_tasks: Optional[Sequence[str]] = None,
        logdir: Optional[Path] = None,
    ) -> DelegationComparisonResults:
        """
        Run benchmark with both manager and assistant warrants.

        Compares results to show delegation's protective effect.
        """
        if logdir is None:
            logdir = Path("results/delegation_comparison") / self.suite_name

        results = DelegationComparisonResults(
            suite=self.suite_name,
            model=self.model,
        )

        # Run with manager warrant (broader scope)
        print("\n" + "=" * 60)
        print("PHASE 1: Running with MANAGER warrant (full scope)")
        print("=" * 60)
        manager_metrics = self._run_benchmark(
            role="manager",
            warrant=self.manager_warrant,
            holder_key=self.manager_key,
            user_tasks=user_tasks,
            injection_tasks=injection_tasks,
            logdir=logdir / "manager",
        )
        results.manager_allowed = manager_metrics.allowed
        results.manager_blocked = manager_metrics.denied

        # Run with delegated assistant warrant (narrower scope)
        print("\n" + "=" * 60)
        print("PHASE 2: Running with ASSISTANT warrant (delegated, narrower)")
        print("=" * 60)
        assistant_metrics = self._run_benchmark(
            role="assistant",
            warrant=self.manager_warrant,  # Will be delegated internally
            holder_key=self.assistant_key,
            user_tasks=user_tasks,
            injection_tasks=injection_tasks,
            logdir=logdir / "assistant",
            use_delegation=True,
        )
        results.assistant_allowed = assistant_metrics.allowed
        results.assistant_blocked = assistant_metrics.denied

        # Calculate delegation's protective effect
        results.delegation_prevented = (
            results.assistant_blocked - results.manager_blocked
        )

        return results

    def _run_benchmark(
        self,
        role: str,
        warrant: Warrant,
        holder_key: SigningKey,
        user_tasks: Optional[Sequence[str]],
        injection_tasks: Optional[Sequence[str]],
        logdir: Path,
        use_delegation: bool = False,
    ) -> AuthorizationMetrics:
        """Run single benchmark with specified warrant."""

        logdir.mkdir(parents=True, exist_ok=True)
        metrics = AuthorizationMetrics()

        # Create LLM
        llm = OpenAILLM(self.client, model=self.model)

        # Create base pipeline
        tools_loop = ToolsExecutionLoop([ToolsExecutor(), llm])
        base_pipeline = AgentPipeline(
            [
                SystemMessage(f"You are a helpful assistant ({role})."),
                InitQuery(),
                llm,
                tools_loop,
            ]
        )
        base_pipeline.name = f"delegation-{role}"

        # Wrap with Tenuo
        if use_delegation:
            pipeline = DelegatedPipeline(
                base_pipeline=base_pipeline,
                suite_name=self.suite_name,
                manager_warrant=warrant,
                manager_key=self.manager_key,
                assistant_key=holder_key,
                metrics=metrics,
            )
        else:
            # Direct warrant (manager)
            from ..agentdojo.harness import TenuoProtectedPipeline

            pipeline = TenuoProtectedPipeline(
                base_pipeline=base_pipeline,
                suite_name=self.suite_name,
                issuer_key=self.org_key,
                holder_key=holder_key,
                metrics=metrics,
            )

        # Run with attacks
        attack = DirectAttack(task_suite=self.suite, target_pipeline=pipeline)
        attack.name = "direct"

        with adlog.OutputLogger(logdir=str(logdir)):
            benchmark_suite_with_injections(
                agent_pipeline=pipeline,
                suite=self.suite,
                attack=attack,
                logdir=logdir,
                force_rerun=True,
                user_tasks=user_tasks,
                injection_tasks=injection_tasks,
            )

        print(f"[{role}] Allowed: {metrics.allowed}, Blocked: {metrics.denied}")
        return metrics


def run_delegation_comparison(
    suite: str = "workspace",
    model: str = "gpt-4o-mini",
    limit: int = 3,
) -> DelegationComparisonResults:
    """
    Run full delegation comparison benchmark.

    Compares attack success rates between:
    - Manager with full suite constraints
    - Assistant with delegated (narrower) constraints
    """

    print("=" * 60)
    print("DELEGATION COMPARISON BENCHMARK")
    print("=" * 60)
    print(f"Suite: {suite}")
    print(f"Model: {model}")
    print("=" * 60)

    benchmark = DelegationBenchmark(suite_name=suite, model=model)

    # Get task IDs
    user_task_ids = list(benchmark.suite.user_tasks.keys())[:limit]
    injection_task_ids = list(benchmark.suite.injection_tasks.keys())[:limit]

    results = benchmark.run_comparison(
        user_tasks=user_task_ids,
        injection_tasks=injection_task_ids,
    )

    # Print summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print("Manager (full scope):")
    print(f"  Allowed: {results.manager_allowed}")
    print(f"  Blocked: {results.manager_blocked}")
    print()
    print("Assistant (delegated):")
    print(f"  Allowed: {results.assistant_allowed}")
    print(f"  Blocked: {results.assistant_blocked}")
    print()
    print(f"Delegation prevented: {results.delegation_prevented} additional attacks")

    if results.delegation_prevented > 0:
        print("\n✓ Delegation provided additional protection!")
    elif results.delegation_prevented == 0:
        print("\n= Same protection (delegation may not narrow relevant constraints)")
    else:
        print("\n⚠️ Unexpected: delegation blocked fewer than manager")

    return results
