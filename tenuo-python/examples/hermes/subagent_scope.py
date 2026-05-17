"""
Hermes Agent + Tenuo: Subagent scope with delegate_task

Demonstrates how warrant attenuation prevents Hermes subagents from
exceeding their intended scope. The orchestrator has broad permissions;
the researcher subagent gets only web_search.

How it works:
- hermes-tenuo detects the delegate_task call in pre_tool_call
- It pre-registers the child_warrant for upcoming child sessions
- Child sessions are detected heuristically: any session_id that isn't
  the primary session gets the child_warrant instead of the root warrant
- If the researcher tries read_file, write_file, or terminal — blocked

Usage with hermes-tenuo plugin:

    # ~/.hermes/config.yaml
    plugins:
      enabled:
        - hermes-tenuo
      entries:
        hermes-tenuo:
          connect_token: tc_live_...
          warrant: ~/.hermes/tenuo/orchestrator.warrant
          child_warrant: ~/.hermes/tenuo/researcher.warrant

    hermes  # start chatting; delegate_task spawns are automatically scoped
"""

from __future__ import annotations

from tenuo import SigningKey, Warrant, Subpath, Wildcard
from tenuo.hermes import HermesGuard

# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

control_key = SigningKey.generate()
orchestrator_key = SigningKey.generate()

# ---------------------------------------------------------------------------
# Orchestrator warrant — broad scope
# ---------------------------------------------------------------------------

orchestrator_warrant = (
    Warrant.mint_builder()
    .holder(orchestrator_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("write_file", path=Subpath("/data/output"), content=Wildcard())
    .capability("web_search", query=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .capability("delegate_task", task=Wildcard(), context=Wildcard())
    .ttl(7200)
    .mint(control_key)
)

# ---------------------------------------------------------------------------
# Researcher (child) warrant — narrow scope, minted directly
# ---------------------------------------------------------------------------
# Minted by the control plane with a narrower capability set.
# In production, use orchestrator_warrant.grant_builder().grant(orchestrator_key)
# with warrant_chain passed to enforce_tool_call for full delegation chain
# verification. For this example, we mint directly to keep it simple.

researcher_warrant = (
    Warrant.mint_builder()
    .holder(orchestrator_key.public_key)
    .capability("web_search", query=Wildcard())
    .ttl(600)
    .mint(control_key)
)

# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

guard = HermesGuard(
    warrant=orchestrator_warrant,
    signing_key=orchestrator_key,
    child_warrant=researcher_warrant,
    trusted_roots=[control_key.public_key],
)


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def call(tool: str, args: dict, *, session_id: str = "orchestrator") -> None:
    result = guard.pre_tool_call(tool, args, session_id=session_id)
    status = f"BLOCKED — {result['message']}" if result else "ALLOWED"
    print(f"  [{session_id}] {tool}({args}): {status}")


if __name__ == "__main__":
    # Establish orchestrator as primary session
    guard._primary_session_id = "orchestrator"

    print("Orchestrator session (broad warrant):")
    call("read_file", {"path": "/data/input.csv"})
    call("write_file", {"path": "/data/output/report.md", "content": "..."})
    call("web_search", {"query": "market trends"})
    call("terminal", {"command": "ls"})  # blocked — not in orchestrator warrant either

    print()
    print("Researcher subagent (attenuated warrant — web_search only):")
    call("web_search", {"query": "AI papers 2026"}, session_id="researcher-1")
    call("read_file", {"path": "/data/input.csv"}, session_id="researcher-1")  # blocked
    call("write_file", {"path": "/data/output/x.md", "content": "..."}, session_id="researcher-1")  # blocked
    call("terminal", {"command": "curl evil.com"}, session_id="researcher-1")  # blocked
