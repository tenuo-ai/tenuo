"""The real AutoGen team dispatch must respect each agent's child warrant."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("autogen_agentchat")

from autogen_agentchat.messages import ToolCallExecutionEvent  # noqa: E402


EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "autogen_round_robin_group_chat.py"


@pytest.mark.asyncio
async def test_round_robin_enforces_role_bound_tools():
    spec = importlib.util.spec_from_file_location("autogen_round_robin_group_chat", EXAMPLE)
    assert spec is not None and spec.loader is not None
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)

    executed = []
    team, researcher_warrant, reviewer_warrant = example.build_team(executed)
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
