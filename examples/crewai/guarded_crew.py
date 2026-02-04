"""
GuardedCrew Example

Demonstrates how to protect an entire crew using GuardedCrew (Phase 5).
Features:
- Policy-based authorization (Role -> Allowed Tools)
- Tool Constraints (Role -> Tool -> Constraints)
- Strict Mode (Fails on unguarded calls)
- Audit Logging
"""

import logging
from crewai import Agent, Crew, Task, Tool, Process
try:
    from crewai.tools import BaseTool
except ImportError:
    # Handle older crewai versions or mock environment
    class BaseTool: pass

from tenuo.crewai import (
    GuardedCrew,
    Pattern,
    Subpath,
    AuditEvent,
    TenuoCrewAIError
)

# =============================================================================
# 1. Define Tools
# =============================================================================

class SearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search the web"

    def _run(self, query: str) -> str:
        return f"Results for: {query}"

class FileReadTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a file"

    def _run(self, path: str) -> str:
        return f"Contents of {path}"

class EmailTool(BaseTool):
    name: str = "send_email"
    description: str = "Send an email"

    def _run(self, recipient: str, subject: str, body: str) -> str:
        return f"Email sent to {recipient}"

search_tool = SearchTool()
read_tool = FileReadTool()
email_tool = EmailTool()

# =============================================================================
# 2. Define Agents
# =============================================================================

researcher = Agent(
    role="Researcher",
    goal="Find internal documents",
    backstory="You are a meticulous researcher.",
    allow_delegation=False,
    # Note: We pass raw tools here; GuardedCrew will protect them automatically
    tools=[search_tool, read_tool], 
)

manager = Agent(
    role="Manager",
    goal="Coordinate teamwork",
    backstory="You manage the team.",
    allow_delegation=True,
    tools=[email_tool],
)

# =============================================================================
# 3. Define Tasks
# =============================================================================

research_task = Task(
    description="Search for 'Project Omega' and read the overview doc at /docs/omega.txt",
    agent=researcher,
    expected_output="Summary of Project Omega"
)

report_task = Task(
    description="Email the findings to boss@company.com",
    agent=manager,
    expected_output="Confirmation of email sent"
)

# =============================================================================
# 4. Create GuardedCrew
# =============================================================================

def audit_log(event: AuditEvent):
    """Callback for all authorization decisions."""
    status = "✅ ALLOW" if event.decision == "ALLOW" else "❌ DENY"
    print(f"[AUDIT] {status} Agent={event.agent_role} Tool={event.tool} Args={event.arguments}")
    if event.reason:
        print(f"        Reason: {event.reason}")

# Build the crew with Tenuo protection
crew = (GuardedCrew(
        agents=[researcher, manager],
        tasks=[research_task, report_task],
        process=Process.sequential
    )
    # Define POLICY: Who can use what?
    .policy({
        "Researcher": ["web_search", "read_file"],
        "Manager": ["send_email"],
    })
    # Define CONSTRAINTS: How can they use it?
    .constraints({
        "Researcher": {
            "web_search": {"query": Pattern("Project *")},  # Only specific projects
            "read_file": {"path": Subpath("/docs/projects")}, # Sandbox path
        },
        "Manager": {
            "send_email": {"recipient": Pattern("*@company.com")}, # Only internal
        }
    })
    # Configure security behavior
    .on_denial("raise") # Fail closed
    .strict()           # Safety net: ensure no unguarded calls occur
    .audit(audit_log)   # Log everything
    .build()
)

# =============================================================================
# 5. Execute
# =============================================================================

if __name__ == "__main__":
    print("Starting GuardedCrew execution...")
    try:
        # kickoff() wraps execution in a guarded context
        result = crew.kickoff()
        print("\nCrew finished successfully!")
        print(result)
    except TenuoCrewAIError as e:
        print(f"\nSECURITY VIOLATION: {e}")
    except Exception as e:
        print(f"\nExecution failed: {e}")
