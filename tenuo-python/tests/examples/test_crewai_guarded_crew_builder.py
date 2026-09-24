"""
Unit and integration tests for examples/crewai/guarded_crew_builder.py (#656).

Verifies:
1. Public GuardedCrew builder constructs properly configured agents, tasks, and guards.
2. Authorized role tool calls succeed and execute tool bodies.
3. Constraint violations are blocked before tool execution, ensuring tool bodies never run.
4. Cross-role unauthorized tool calls fail closed without executing tool bodies.
5. Strict mode and unguarded call reporting behavior.
6. The example main() runs cleanly end-to-end without requiring external LLM API keys.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

from tenuo.crewai import (
    CrewAIGuard,
    _guarded_zone,
    get_unguarded_calls,
)

pytest.importorskip("crewai", reason="GuardedCrew requires crewai")

EXAMPLE_PATH = (
    Path(__file__).resolve().parents[2] / "examples" / "crewai" / "guarded_crew_builder.py"
)


@pytest.fixture
def example():
    """Load the guarded_crew_builder example freshly with cleared execution tracking."""
    spec = importlib.util.spec_from_file_location("guarded_crew_builder", EXAMPLE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.executed_tools.clear()
    yield module
    module.executed_tools.clear()


def simulate_tool_call(
    hook: Any,
    tool: Any,
    tool_args: Dict[str, Any],
    agent: Any,
) -> Optional[Any]:
    """Simulate CrewAI before_tool_call hook interception.

    In CrewAI, if the before_tool_call hook returns False, the runner blocks
    and skips tool execution, preventing the tool body from running.
    """
    context = SimpleNamespace(
        tool_name=tool.name,
        tool_input=tool_args,
        agent=agent,
    )
    hook_result = hook(context)
    if hook_result is not False:
        # Tool call is allowed (hook returned None or True)
        return tool._run(**tool_args)
    # Tool call was blocked by Tenuo hook
    return None


def test_crew_builder_instantiation(example):
    """GuardedCrew builder initializes agents and per-agent guards correctly."""
    crew, researcher, writer = example.build_guarded_crew()

    assert crew is not None
    assert researcher.role == "Researcher"
    assert writer.role == "Writer"

    # Guards property provides per-agent CrewAIGuard introspection
    guards = crew.guards
    assert "Researcher" in guards
    assert "Writer" in guards
    assert isinstance(guards["Researcher"], CrewAIGuard)
    assert isinstance(guards["Writer"], CrewAIGuard)


def test_authorized_tool_execution(example):
    """Authorized tools with valid constraints execute successfully."""
    crew, researcher, writer = example.build_guarded_crew()
    crew._protect_agents()
    hook = crew._create_combined_hook()

    search_tool = example.SearchTool()
    report_tool = example.WriteReportTool()

    # Researcher executes search within constraint "topic:*"
    search_args = {"query": "topic:model_safety"}
    res = simulate_tool_call(hook, search_tool, search_args, researcher)

    assert res == "Research results for: topic:model_safety"
    assert ("search", search_args) in example.executed_tools

    # Writer executes write_report within constraint "topic:*"
    report_args = {"topic": "topic:model_safety"}
    res = simulate_tool_call(hook, report_tool, report_args, writer)

    assert res == "Report published for: topic:model_safety"
    assert ("write_report", report_args) in example.executed_tools


def test_constraint_violation_denied_and_never_runs(example):
    """Arguments violating constraints are blocked and tool bodies never execute."""
    crew, researcher, writer = example.build_guarded_crew()
    crew._protect_agents()
    hook = crew._create_combined_hook()

    search_tool = example.SearchTool()
    invalid_args = {"query": "unapproved_query"}  # does not match Pattern("topic:*")

    res = simulate_tool_call(hook, search_tool, invalid_args, researcher)

    assert res is None
    assert example.executed_tools == []


def test_cross_role_tool_denied_and_never_runs(example):
    """Tools attempted by unauthorized agent roles are blocked without running."""
    crew, researcher, writer = example.build_guarded_crew()
    crew._protect_agents()
    hook = crew._create_combined_hook()

    report_tool = example.WriteReportTool()
    search_tool = example.SearchTool()

    # Researcher trying to call Writer's tool
    res1 = simulate_tool_call(hook, report_tool, {"topic": "topic:model_safety"}, researcher)
    assert res1 is None
    assert example.executed_tools == []

    # Writer trying to call Researcher's tool
    res2 = simulate_tool_call(hook, search_tool, {"query": "topic:model_safety"}, writer)
    assert res2 is None
    assert example.executed_tools == []


def test_closed_world_unlisted_argument_denied(example):
    """Extra unlisted parameters trigger closed-world denial."""
    crew, researcher, _ = example.build_guarded_crew()
    crew._protect_agents()
    hook = crew._create_combined_hook()

    search_tool = example.SearchTool()
    injected_args = {"query": "topic:model_safety", "extra_param": "injection"}

    res = simulate_tool_call(hook, search_tool, injected_args, researcher)

    assert res is None
    assert example.executed_tools == []


def test_unguarded_tool_reporting(example):
    """Unguarded tool calls report their invocation to Tenuo strict tracking."""
    crew, researcher, _ = example.build_guarded_crew()
    guard = crew.guards["Researcher"]
    admin_tool = example.UnguardedAdminTool()

    with _guarded_zone(guard, strict=True):
        assert get_unguarded_calls() == []
        admin_tool._run(target="cluster_config")
        assert ("admin_reset", {"target": "cluster_config"}) in example.executed_tools
        assert "admin_reset" in get_unguarded_calls()


def test_main_runs_end_to_end(example, capsys):
    """Example entrypoint runs cleanly without external dependencies or API keys."""
    example.main()

    captured = capsys.readouterr().out
    assert "=== Tenuo GuardedCrew Builder Quickstart ===" in captured
    assert "Researcher search('topic:ai_safety'): True" in captured
    assert "Writer write_report('topic:ai_safety'): True" in captured
    assert "Researcher search('unapproved_query'): False" in captured
    assert "Researcher write_report('topic:ai_safety'): False" in captured
    assert "Writer search('topic:ai_safety'): False" in captured
    assert "GuardedCrew successfully configured with strict enforcement." in captured
