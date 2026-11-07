"""The real AutoGen team dispatch must respect each agent's child warrant."""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("autogen_agentchat")

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "autogen_round_robin_group_chat.py"

SCRIPT = textwrap.dedent(
    """
    import asyncio
    import runpy
    import sys

    from autogen_agentchat.messages import ToolCallExecutionEvent

    example = runpy.run_path(sys.argv[1])

    async def check():
        executed = []
        team, researcher_warrant, reviewer_warrant = example["build_team"](executed)
        assert set(researcher_warrant.tools) == {"lookup_record"}
        assert set(reviewer_warrant.tools) == {"record_approval"}

        result = await team.run(task="Look up record_123, then review it")

        assert executed == ["lookup_record", "record_approval"]
        events = [message for message in result.messages if isinstance(message, ToolCallExecutionEvent)]
        assert [event.source for event in events] == ["researcher", "reviewer"]
        assert all(len(event.content) == 2 for event in events)
        assert [item.is_error for event in events for item in event.content] == [False, True, True, False]
        assert "not authorized" in events[0].content[1].content
        assert "not authorized" in events[1].content[0].content

    asyncio.run(check())
    print("OK")
    """
)


def test_round_robin_enforces_role_bound_tools():
    # The full suite changes process-global Tenuo trust settings; a fresh
    # interpreter exercises the real team with its own issuer trust state.
    proc = subprocess.run([sys.executable, "-c", SCRIPT, str(EXAMPLE)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0 and proc.stdout.strip().endswith("OK"), proc.stdout + proc.stderr
