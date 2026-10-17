"""Real Agents Runner dispatch; no hosted model or provider credentials."""

import json
import os
import sys
from pathlib import Path

import pytest
from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)
from tenuo import Range, SigningKey, Warrant
from tenuo.openai import OpenAIConfigurationError, guard_agent

set_tracing_disabled(True)


class Scripted(Model):
    def __init__(self, calls):
        self.calls = iter(calls)
        self.turn = 0

    async def get_response(self, *args, **kwargs):
        call = next(self.calls, None)
        self.turn += 1
        call_id = f"call-{self.turn}"
        output = (
            [
                ResponseFunctionToolCall(
                    type="function_call",
                    name=call[0],
                    arguments=json.dumps(call[1]),
                    call_id=call_id,
                    id=call_id,
                )
            ]
            if call
            else [
                ResponseOutputMessage(
                    id="msg",
                    type="message",
                    role="assistant",
                    status="completed",
                    content=[
                        ResponseOutputText(
                            type="output_text", text="done", annotations=[]
                        )
                    ],
                )
            ]
        )
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError


@pytest.mark.asyncio
@pytest.mark.parametrize("amount,expected", [(200, [200]), (4900, [])])
async def test_function_tool(amount, expected):
    effects = []

    @function_tool
    def refund(amount: int) -> str:
        """Refund cents."""
        effects.append(amount)
        return "refunded"

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("refund", amount=Range(max=500))
        .ttl(300)
        .mint(issuer)
    )
    agent = guard_agent(
        Agent(
            name="refund",
            model=Scripted([("refund", {"amount": amount})]),
            tools=[refund],
        ),
        warrant=warrant,
        signing_key=holder,
        trusted_roots=[issuer.public_key],
    )
    await Runner.run(agent, "refund")
    assert effects == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed,expected", [(True, ["200"]), (False, [])])
async def test_mcp_tool_through_runner(allowed, expected, tmp_path):
    from agents.mcp import MCPServerStdio

    journal = tmp_path / "effects"
    env = {**os.environ, "TENUO_TEST_JOURNAL": str(journal)}
    # No server guard: an Agents dispatch regression really would execute it.
    env.pop("TENUO_TEST_ROOT", None)
    server = MCPServerStdio(
        params={
            "command": sys.executable,
            "args": [str(Path(__file__).with_name("mcp_effect_server.py"))],
            "env": env,
        }
    )
    if not hasattr(server, "tool_input_guardrails"):
        with pytest.raises(OpenAIConfigurationError) as exc:
            guard_agent(Agent(name="a", mcp_servers=[server]), allow_tools=["refund"])
        assert exc.value.code == "CFG_006"
        assert not journal.exists()
        print(
            "MCP interception unavailable in this Agents SDK: refused before dispatch"
        )
        return
    async with server:
        agent = guard_agent(
            Agent(
                name="a",
                model=Scripted([("refund", {"amount": 200})]),
                mcp_servers=[server],
            ),
            allow_tools=["refund"] if allowed else ["search"],
        )
        await Runner.run(agent, "refund")
    assert (journal.read_text().splitlines() if journal.exists() else []) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed,expected", [(True, [200]), (False, [])])
async def test_handoff_target_tool(allowed, expected):
    effects = []

    @function_tool
    def refund(amount: int) -> str:
        """Refund cents."""
        effects.append(amount)
        return "refunded"

    model = Scripted([("transfer_to_specialist", {}), ("refund", {"amount": 200})])
    specialist = Agent(name="specialist", model=model, tools=[refund])
    agent = guard_agent(
        Agent(name="triage", model=model, handoffs=[specialist]),
        allow_tools=["refund"] if allowed else ["search"],
    )
    await Runner.run(agent, "refund")
    assert effects == expected


def test_hosted_tool_refused_before_run():
    from agents import WebSearchTool

    with pytest.raises(OpenAIConfigurationError) as exc:
        guard_agent(Agent(name="a", tools=[WebSearchTool()]), allow_tools=["search"])
    assert exc.value.code == "CFG_006"
