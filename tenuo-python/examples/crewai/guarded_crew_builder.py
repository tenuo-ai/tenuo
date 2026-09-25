"""
GuardedCrew Builder Quickstart Example

Demonstrates the public Tenuo 0.3.0 GuardedCrew() builder API for CrewAI:
- Role-based policy: map CrewAI agent roles to permitted tools
- Granular constraints: restrict argument values per agent and tool
- Strict mode: fail closed if any unguarded tool calls occur
- Deterministic double: execute end-to-end offline without LLM API keys
"""

import os
from typing import Any, List, Optional, Tuple
from crewai import Agent, Process, Task

try:
    from crewai.tools import BaseTool
    from crewai.llms.base_llm import BaseLLM
except ImportError:
    class BaseTool:  # type: ignore[no-redef]
        pass

    class BaseLLM:  # type: ignore[no-redef]
        pass

from tenuo.crewai import (
    GuardedCrew,
    Pattern,
    UnguardedToolError,
    report_unguarded_call,
)

# Global execution tracker to verify which tool bodies execute
executed_tools: List[Tuple[str, dict]] = []


class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search for research topics"

    def _run(self, query: str, **kwargs: Any) -> str:
        call_args = {"query": query}
        if kwargs:
            call_args.update(kwargs)
        executed_tools.append(("search", call_args))
        return f"Research results for: {query}"


class WriteReportTool(BaseTool):
    name: str = "write_report"
    description: str = "Write a report based on research"

    def _run(self, topic: str, **kwargs: Any) -> str:
        call_args = {"topic": topic}
        if kwargs:
            call_args.update(kwargs)
        executed_tools.append(("write_report", call_args))
        return f"Report published for: {topic}"


class UnguardedAdminTool(BaseTool):
    name: str = "admin_reset"
    description: str = "Unguarded maintenance tool"

    def _run(self) -> str:
        report_unguarded_call(self.name)
        executed_tools.append(("admin_reset", {}))
        return "System reset performed"


class DeterministicDoubleLLM(BaseLLM):
    """Deterministic LLM test double for offline execution without API keys."""

    model: str = "custom/deterministic-double"
    responses: List[str] = []
    _step_index: int = 0

    def call(self, messages: Any, **kwargs: Any) -> str:
        if self._step_index < len(self.responses):
            resp = self.responses[self._step_index]
            self._step_index += 1
            return resp
        return "Thought: Task is complete\nFinal Answer: Completed successfully."


def build_guarded_crew(
    researcher_responses: Optional[List[str]] = None,
    writer_responses: Optional[List[str]] = None,
    include_unguarded_tool: bool = False,
):
    """Construct a GuardedCrew with researcher and writer agents.

    Uses deterministic LLM doubles so execution is reproducible, offline,
    and requires no LLM provider API keys.
    """
    if researcher_responses is None:
        researcher_responses = [
            'Thought: Search for safety topic\nAction: search\nAction Input: {"query": "topic:model_safety"}\n',
            'Thought: I have verified notes\nFinal Answer: Verified safety parameters documented.',
        ]
    if writer_responses is None:
        writer_responses = [
            'Thought: Draft final report\nAction: write_report\nAction Input: {"topic": "topic:model_safety"}\n',
            'Thought: Report is written\nFinal Answer: Safety report published.',
        ]

    researcher_tools = [SearchTool()]
    policy = {
        "Researcher": ["search"],
        "Writer": ["write_report"],
    }

    if include_unguarded_tool:
        researcher_tools.append(UnguardedAdminTool())
        policy["Researcher"].append("admin_reset")

    researcher_llm = DeterministicDoubleLLM(
        model="custom/researcher-double",
        responses=list(researcher_responses),
    )
    writer_llm = DeterministicDoubleLLM(
        model="custom/writer-double",
        responses=list(writer_responses),
    )

    researcher = Agent(
        role="Researcher",
        goal="Discover facts on approved safety topics",
        backstory="An AI safety researcher who only searches verified sources.",
        allow_delegation=False,
        llm=researcher_llm,
        tools=researcher_tools,
    )

    writer = Agent(
        role="Writer",
        goal="Produce summaries for approved topics",
        backstory="A technical writer who summarizes approved research findings.",
        allow_delegation=False,
        llm=writer_llm,
        tools=[WriteReportTool()],
    )

    research_task = Task(
        description="Search for topic:model_safety and analyze findings.",
        agent=researcher,
        expected_output="Key notes on model safety.",
    )

    writing_task = Task(
        description="Write a summary report for topic:model_safety.",
        agent=writer,
        expected_output="Final published report document.",
    )

    crew = (
        GuardedCrew(
            agents=[researcher, writer],
            tasks=[research_task, writing_task],
            process=Process.sequential,
        )
        .policy(policy)
        .constraints({
            "Researcher": {
                "search": {"query": Pattern("topic:*")},
            },
            "Writer": {
                "write_report": {"topic": Pattern("topic:*")},
            },
        })
        .strict()
        .build()
    )

    return crew, researcher, writer


def main():
    os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "true"
    os.environ["OTEL_SDK_DISABLED"] = "true"

    print("=== Tenuo GuardedCrew Builder Quickstart ===")
    executed_tools.clear()
    crew, researcher, writer = build_guarded_crew()

    print("\n1. Running GuardedCrew via kickoff() with deterministic LLM double...")
    result = crew.kickoff()
    print(f"Kickoff Result: {getattr(result, 'raw', result)}")
    print(f"Executed Tools ({len(executed_tools)} calls reached tool bodies):")
    for tool_name, args in executed_tools:
        print(f" - [ALLOWED] {tool_name}({args})")

    print("\n2. Guard Introspection & Policy Verification (post-kickoff):")
    res_guard = crew.guards.get("Researcher")
    writer_guard = crew.guards.get("Writer")
    if res_guard and writer_guard:
        print(f" - Researcher search('topic:ai_safety'): {res_guard.allows('search', {'query': 'topic:ai_safety'})}")
        print(f" - Writer write_report('topic:ai_safety'): {writer_guard.allows('write_report', {'topic': 'topic:ai_safety'})}")
        print(f" - Researcher search('unapproved_query'): {res_guard.allows('search', {'query': 'unapproved_query'})}")
        print(f" - Researcher write_report('topic:ai_safety'): {res_guard.allows('write_report', {'topic': 'topic:ai_safety'})}")
        print(f" - Writer search('topic:ai_safety'): {writer_guard.allows('search', {'query': 'topic:ai_safety'})}")

    print("\n3. Strict Mode Enforcement Demonstration:")
    strict_crew, _, _ = build_guarded_crew(
        include_unguarded_tool=True,
        researcher_responses=[
            'Thought: Run reset\nAction: admin_reset\nAction Input: {}\n',
            'Thought: Done\nFinal Answer: Done.',
        ],
    )
    try:
        strict_crew.kickoff()
        print("Strict mode check: unexpected pass")
    except UnguardedToolError as e:
        print(f" - [FAIL-CLOSED] Caught UnguardedToolError as expected: {e}")

    print("\nGuardedCrew successfully executed with strict enforcement.")


if __name__ == "__main__":
    main()
