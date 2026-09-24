"""
GuardedCrew Builder Quickstart Example

Demonstrates the public Tenuo 0.3.0 GuardedCrew() builder API for CrewAI:
- Role-based policy: map CrewAI agent roles to permitted tools
- Granular constraints: restrict argument values per agent and tool
- Strict mode: fail closed if any unguarded tool calls occur
"""

from typing import List, Tuple
from crewai import Agent, Process, Task

try:
    from crewai.tools import BaseTool
except ImportError:
    class BaseTool:  # type: ignore[no-redef]
        pass

from tenuo.crewai import (
    GuardedCrew,
    Pattern,
    TenuoCrewAIError,
    UnguardedToolError,
    report_unguarded_call,
)

# Global execution tracker to verify that denied tools never execute
executed_tools: List[Tuple[str, dict]] = []


class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search for research topics"

    def _run(self, query: str) -> str:
        executed_tools.append(("search", {"query": query}))
        return f"Research results for: {query}"


class WriteReportTool(BaseTool):
    name: str = "write_report"
    description: str = "Write a report based on research"

    def _run(self, topic: str) -> str:
        executed_tools.append(("write_report", {"topic": topic}))
        return f"Report published for: {topic}"


class UnguardedAdminTool(BaseTool):
    name: str = "admin_reset"
    description: str = "Unguarded tool that demonstrates strict mode fail-closed behavior"

    def _run(self, target: str) -> str:
        report_unguarded_call(self.name)
        executed_tools.append(("admin_reset", {"target": target}))
        return f"Reset target: {target}"


def build_guarded_crew(include_unguarded_tool: bool = False):
    """Construct a GuardedCrew with researcher and writer agents."""
    search_tool = SearchTool()
    report_tool = WriteReportTool()

    researcher_tools = [search_tool]
    if include_unguarded_tool:
        researcher_tools.append(UnguardedAdminTool())

    researcher = Agent(
        role="Researcher",
        goal="Discover facts on approved safety topics",
        backstory="An AI safety researcher who only searches verified sources.",
        allow_delegation=False,
        tools=researcher_tools,
    )

    writer = Agent(
        role="Writer",
        goal="Produce summaries for approved topics",
        backstory="A technical writer who summarizes approved research findings.",
        allow_delegation=False,
        tools=[report_tool],
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
        .policy({
            "Researcher": ["search"],
            "Writer": ["write_report"],
        })
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
    print("=== Tenuo GuardedCrew Builder Quickstart ===")
    crew, researcher, writer = build_guarded_crew()

    print("\n1. Policy & Constraint Verification:")
    res_guard = crew.guards["Researcher"]
    writer_guard = crew.guards["Writer"]

    # Allowed calls
    print(f" - Researcher search('topic:ai_safety'): {res_guard.allows('search', {'query': 'topic:ai_safety'})}")
    print(f" - Writer write_report('topic:ai_safety'): {writer_guard.allows('write_report', {'topic': 'topic:ai_safety'})}")

    # Constraint violations
    print(f" - Researcher search('unapproved_query'): {res_guard.allows('search', {'query': 'unapproved_query'})}")

    # Cross-role denials
    print(f" - Researcher write_report('topic:ai_safety'): {res_guard.allows('write_report', {'topic': 'topic:ai_safety'})}")
    print(f" - Writer search('topic:ai_safety'): {writer_guard.allows('search', {'query': 'topic:ai_safety'})}")

    print("\nGuardedCrew successfully configured with strict enforcement.")


if __name__ == "__main__":
    main()
