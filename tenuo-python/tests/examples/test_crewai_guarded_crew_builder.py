"""
Unit and integration tests for examples/crewai/guarded_crew_builder.py (#656).

Verifies:
1. Public GuardedCrew builder constructs properly configured agents, tasks, and process.
2. Authorized role tool calls succeed and execute tool bodies via public kickoff().
3. Constraint violations are blocked by the authorization hook; tool bodies never run.
4. Cross-role unauthorized tool calls fail closed without executing tool bodies.
5. Closed-world semantics block unlisted arguments from executing tool bodies.
6. Strict mode detects unguarded calls after kickoff and raises UnguardedToolError.
7. Per-agent guard introspection provides accurate policy evaluation via .allows().
8. The example main() runs cleanly end-to-end without requiring external LLM API keys.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from tenuo.crewai import CrewAIGuard, UnguardedToolError

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


def test_crew_builder_instantiation(example):
    """GuardedCrew builder initializes agents and tasks correctly."""
    crew, researcher, writer = example.build_guarded_crew()

    assert crew is not None
    assert researcher.role == "Researcher"
    assert writer.role == "Writer"


def test_authorized_tool_execution(example):
    """Authorized tools with valid constraints execute successfully via kickoff()."""
    crew, _, _ = example.build_guarded_crew()

    result = crew.kickoff()
    assert result is not None

    # Both authorized tools should have executed their underlying bodies
    assert ("search", {"query": "topic:model_safety"}) in example.executed_tools
    assert ("write_report", {"topic": "topic:model_safety"}) in example.executed_tools

    # Per-agent guards are accessible after kickoff for introspection
    guards = crew.guards
    assert "Researcher" in guards
    assert "Writer" in guards
    assert isinstance(guards["Researcher"], CrewAIGuard)
    assert isinstance(guards["Writer"], CrewAIGuard)


def test_constraint_violation_denied_and_never_runs(example):
    """Arguments violating constraints are blocked and tool bodies never execute."""
    # Researcher requests an unapproved query that does not match Pattern("topic:*")
    crew, _, _ = example.build_guarded_crew(
        researcher_responses=[
            'Thought: Search unapproved\nAction: search\nAction Input: {"query": "unapproved_query"}\n',
            'Thought: Final response\nFinal Answer: Done without unapproved tools.',
        ],
        writer_responses=[
            'Thought: Done\nFinal Answer: Task complete.',
        ],
    )

    crew.kickoff()

    # The tool body must never have been called with the disallowed argument
    assert ("search", {"query": "unapproved_query"}) not in example.executed_tools
    assert example.executed_tools == []


def test_cross_role_tool_denied_and_never_runs(example):
    """Tools attempted by unauthorized agent roles are blocked without running."""
    # Researcher attempting to invoke Writer's tool (write_report)
    crew, _, _ = example.build_guarded_crew(
        researcher_responses=[
            'Thought: Try writer tool\nAction: write_report\nAction Input: {"topic": "topic:model_safety"}\n',
            'Thought: Conclude\nFinal Answer: Complete.',
        ],
        writer_responses=[
            'Thought: Conclude\nFinal Answer: Complete.',
        ],
    )

    crew.kickoff()

    # Researcher cannot call write_report; tool body must never run
    assert ("write_report", {"topic": "topic:model_safety"}) not in example.executed_tools
    assert example.executed_tools == []


def test_cross_role_writer_denied_researcher_tool(example):
    """Writer attempting to invoke Researcher's search tool is blocked without running."""
    crew, _, _ = example.build_guarded_crew(
        researcher_responses=[
            'Thought: Conclude\nFinal Answer: Done.',
        ],
        writer_responses=[
            'Thought: Try search\nAction: search\nAction Input: {"query": "topic:model_safety"}\n',
            'Thought: Conclude\nFinal Answer: Complete.',
        ],
    )

    crew.kickoff()

    # Writer cannot call search; tool body must never run
    assert ("search", {"query": "topic:model_safety"}) not in example.executed_tools
    assert example.executed_tools == []


def test_closed_world_unlisted_argument_denied(example):
    """Extra unlisted parameters trigger closed-world denial; tool body never runs."""
    crew, _, _ = example.build_guarded_crew(
        researcher_responses=[
            'Thought: Injected args\nAction: search\nAction Input: {"query": "topic:model_safety", "extra_param": "injection"}\n',
            'Thought: Conclude\nFinal Answer: Done.',
        ],
        writer_responses=[
            'Thought: Conclude\nFinal Answer: Complete.',
        ],
    )

    crew.kickoff()

    # Injected argument triggers UnlistedArgument denial; tool body never executes
    assert example.executed_tools == []


def test_strict_mode_unguarded_tool_raises_on_kickoff(example):
    """Strict mode detects unguarded calls and raises UnguardedToolError on kickoff."""
    crew, _, _ = example.build_guarded_crew(
        include_unguarded_tool=True,
        researcher_responses=[
            'Thought: Reset\nAction: admin_reset\nAction Input: {}\n',
            'Thought: Done\nFinal Answer: Done.',
        ],
        writer_responses=[
            'Thought: Done\nFinal Answer: Done.',
        ],
    )

    with pytest.raises(UnguardedToolError) as exc_info:
        crew.kickoff()

    assert "admin_reset" in str(exc_info.value)
    assert "GuardedCrew.kickoff" in str(exc_info.value)
    # Tool body executed before strict mode detected the bypass after kickoff
    assert ("admin_reset", {}) in example.executed_tools


def test_guard_allows_policy_evaluation(example):
    """Guard allows() provides accurate boolean policy evaluation for CI checks."""
    crew, _, _ = example.build_guarded_crew()
    crew.kickoff()

    res_guard = crew.guards["Researcher"]
    writer_guard = crew.guards["Writer"]

    # Allowed calls
    assert res_guard.allows("search", {"query": "topic:ai_safety"}) is True
    assert writer_guard.allows("write_report", {"topic": "topic:ai_safety"}) is True

    # Constraint violations
    assert res_guard.allows("search", {"query": "unapproved_query"}) is False

    # Cross-role denials
    assert res_guard.allows("write_report", {"topic": "topic:ai_safety"}) is False
    assert writer_guard.allows("search", {"query": "topic:ai_safety"}) is False


def test_main_runs_end_to_end(example, capsys):
    """Example entrypoint runs cleanly without external dependencies or API keys."""
    example.main()

    captured = capsys.readouterr().out
    assert "=== Tenuo GuardedCrew Builder Quickstart ===" in captured
    assert "Kickoff Result: Safety report published." in captured
    assert "- [ALLOWED] search({'query': 'topic:model_safety'})" in captured
    assert "- [ALLOWED] write_report({'topic': 'topic:model_safety'})" in captured
    assert "Researcher search('topic:ai_safety'): True" in captured
    assert "Writer write_report('topic:ai_safety'): True" in captured
    assert "Researcher search('unapproved_query'): False" in captured
    assert "Researcher write_report('topic:ai_safety'): False" in captured
    assert "Writer search('topic:ai_safety'): False" in captured
    assert "[STRICT] Unguarded call detected after kickoff" in captured
    assert "GuardedCrew successfully executed with strict audit." in captured
