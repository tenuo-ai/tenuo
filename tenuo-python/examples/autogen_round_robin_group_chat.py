"""Offline AutoGen RoundRobinGroupChat with separate Tenuo tool authority.

Install ``tenuo[autogen]`` and run this file. No API key or network is needed.
The researcher may look up a record; the reviewer may record approval. Both
agents see both tool names so cross-role attempts exercise Tenuo's denial.
"""

import asyncio

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_core import FunctionCall
from autogen_core.models import CreateResult, ModelFamily, RequestUsage
from autogen_ext.models.replay import ReplayChatCompletionClient

from tenuo import SigningKey, Warrant
from tenuo.autogen import guard_tools


MODEL_INFO = {
    "vision": False,
    "function_calling": True,
    "json_output": False,
    "family": ModelFamily.UNKNOWN,
    "structured_output": False,
}


def _tool_calls(*names):
    return CreateResult(
        finish_reason="function_calls",
        content=[FunctionCall(id=str(index), name=name, arguments="{}") for index, name in enumerate(names)],
        usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
        cached=False,
    )


def build_team(executed):
    """Build a two-turn team using holder-bound, role-specific child warrants."""
    issuer = SigningKey.generate()
    orchestrator = SigningKey.generate()
    researcher_key = SigningKey.generate()
    reviewer_key = SigningKey.generate()
    parent = (
        Warrant.mint_builder()
        .capability("lookup_record")
        .capability("record_approval")
        .holder(orchestrator.public_key)
        .ttl(300)
        .mint(issuer)
    )
    researcher_warrant = (
        parent.grant_builder()
        .capability("lookup_record")
        .holder(researcher_key.public_key)
        .ttl(120)
        .grant(orchestrator)
    )
    reviewer_warrant = (
        parent.grant_builder()
        .capability("record_approval")
        .holder(reviewer_key.public_key)
        .ttl(120)
        .grant(orchestrator)
    )

    def lookup_record() -> str:
        """Look up the sample record."""
        executed.append("lookup_record")
        return "record_123 is ready for review"

    def record_approval() -> str:
        """Record approval for the sample record."""
        executed.append("record_approval")
        return "record_123 approved"

    tools = [lookup_record, record_approval]
    researcher = AssistantAgent(
        "researcher",
        ReplayChatCompletionClient([_tool_calls("lookup_record", "record_approval")], model_info=MODEL_INFO),
        tools=guard_tools(
            tools,
            researcher_warrant.bind(researcher_key, trusted_roots=[issuer.public_key]),
            warrant_chain=[parent],
        ),
    )
    reviewer = AssistantAgent(
        "reviewer",
        ReplayChatCompletionClient([_tool_calls("lookup_record", "record_approval")], model_info=MODEL_INFO),
        tools=guard_tools(
            tools,
            reviewer_warrant.bind(reviewer_key, trusted_roots=[issuer.public_key]),
            warrant_chain=[parent],
        ),
    )
    team = RoundRobinGroupChat([researcher, reviewer], max_turns=2)
    return team, researcher_warrant, reviewer_warrant


async def main():
    executed = []
    team, _, _ = build_team(executed)
    await team.run(task="Look up record_123, then review it")
    print(f"Tool bodies executed: {executed}")
    print("Both cross-role calls were denied before their tool bodies ran.")


if __name__ == "__main__":
    asyncio.run(main())
