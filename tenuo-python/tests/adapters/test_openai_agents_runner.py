"""guard_agent() under a real Agents SDK run loop.

These tests drive ``agents.Runner`` with a scripted model, so every tool call
goes through the SDK's own dispatch, not a direct call to the guardrail.
"""

import json
from typing import Any, List

import pytest

agents = pytest.importorskip("agents")
pytest.importorskip("agents.tool_guardrails")

from agents import Agent, Runner, function_tool  # noqa: E402
from agents.exceptions import ToolInputGuardrailTripwireTriggered  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from tenuo import Range, SigningKey, Subpath, Warrant  # noqa: E402
from tenuo.openai import OpenAIConfigurationError, TenuoToolGuardrail, guard_agent  # noqa: E402


def _call(name: str, args: dict, call_id: str) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        type="function_call", name=name, arguments=json.dumps(args), call_id=call_id, id=call_id
    )


def _text(text: str) -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id="msg",
        type="message",
        role="assistant",
        status="completed",
        content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
    )


class ScriptedModel(Model):
    """Returns a fixed sequence of model turns and records what it was sent."""

    def __init__(self, turns: List[List[Any]]):
        self.turns = list(turns)
        self.inputs: List[Any] = []

    async def get_response(self, system_instructions, input, *args, **kwargs):
        self.inputs.append(input)
        output = self.turns.pop(0) if self.turns else [_text("done")]
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):  # pragma: no cover - not used
        raise NotImplementedError


def _tool_outputs(model: ScriptedModel) -> List[str]:
    """Tool results the model saw on its later turns."""
    outputs = []
    for item in model.inputs[-1] if model.inputs else []:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            outputs.append(str(item.get("output")))
    return outputs


@pytest.fixture
def ran():
    return []


@pytest.fixture
def tools(ran):
    @function_tool
    def search(query: str) -> str:
        """Search the knowledge base."""
        ran.append(("search", query))
        return "no results"

    @function_tool
    def delete_account(customer_id: str) -> str:
        """Permanently delete a customer account."""
        ran.append(("delete_account", customer_id))
        return f"deleted {customer_id}"

    @function_tool
    def refund(amount: int) -> str:
        """Refund an amount in cents."""
        ran.append(("refund", amount))
        return f"refunded {amount}"

    return {"search": search, "delete_account": delete_account, "refund": refund}


@pytest.mark.asyncio
async def test_forbidden_tool_never_runs(tools, ran):
    model = ScriptedModel([[_call("delete_account", {"customer_id": "cus_123"}, "c1")]])
    agent = guard_agent(
        Agent(name="a", model=model, tools=[tools["search"], tools["delete_account"]]),
        allow_tools=["search"],
    )
    await Runner.run(agent, "delete cus_123")
    assert ran == []
    assert any("blocked by Tenuo" in o for o in _tool_outputs(model))


@pytest.mark.asyncio
async def test_allowed_tool_runs(tools, ran):
    model = ScriptedModel([[_call("search", {"query": "refunds"}, "c1")]])
    agent = guard_agent(Agent(name="a", model=model, tools=[tools["search"]]), allow_tools=["search"])
    await Runner.run(agent, "search")
    assert ran == [("search", "refunds")]


@pytest.mark.asyncio
async def test_warrant_constrains_arguments(tools, ran):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("refund", amount=Range(max=100))
        .ttl(300)
        .mint(issuer)
    )
    model = ScriptedModel([[_call("refund", {"amount": 500}, "c1")], [_call("refund", {"amount": 50}, "c2")]])
    agent = guard_agent(
        Agent(name="a", model=model, tools=[tools["refund"], tools["delete_account"]]),
        warrant=warrant,
        signing_key=holder,
        trusted_roots=[issuer.public_key],
    )
    await Runner.run(agent, "refund")
    assert ran == [("refund", 50)]


@pytest.mark.asyncio
async def test_raise_mode_halts_the_run(tools, ran):
    model = ScriptedModel([[_call("delete_account", {"customer_id": "cus_1"}, "c1")]])
    agent = guard_agent(
        Agent(name="a", model=model, tools=[tools["delete_account"]]),
        allow_tools=["search"],
        on_denial="raise",
    )
    with pytest.raises(ToolInputGuardrailTripwireTriggered):
        await Runner.run(agent, "delete")
    assert ran == []


@pytest.mark.asyncio
async def test_handoff_target_tools_are_guarded(tools, ran):
    model = ScriptedModel(
        [
            [_call("transfer_to_specialist", {}, "h1")],
            [_call("delete_account", {"customer_id": "cus_9"}, "c1")],
        ]
    )
    specialist = Agent(name="specialist", model=model, tools=[tools["delete_account"]])
    triage = Agent(name="triage", model=model, handoffs=[specialist])
    guard_agent(triage, allow_tools=["search"])
    await Runner.run(triage, "please delete")
    assert ran == []


@pytest.mark.asyncio
async def test_input_guardrail_misuse_fails_loudly(tools):
    model = ScriptedModel([[_call("search", {"query": "x"}, "c1")]])
    agent = Agent(
        name="a",
        model=model,
        tools=[tools["search"]],
        input_guardrails=[TenuoToolGuardrail(allow_tools=["search"])],
    )
    with pytest.raises(OpenAIConfigurationError, match="guard_agent") as exc:
        await Runner.run(agent, "hi")
    assert exc.value.code == "CFG_006"


def test_hosted_tools_are_refused():
    from agents import WebSearchTool

    with pytest.raises(OpenAIConfigurationError, match="can't be checked") as exc:
        guard_agent(Agent(name="a", tools=[WebSearchTool()]), allow_tools=["search"])
    assert exc.value.code == "CFG_006"


def test_invalid_denial_mode_has_agents_configuration_code():
    with pytest.raises(OpenAIConfigurationError, match="on_denial") as exc:
        guard_agent(Agent(name="a"), on_denial="continue")
    assert exc.value.code == "CFG_006"


def test_mcp_servers_receive_the_guardrail():
    class FakeServer:
        name = "fake"
        tool_input_guardrails = None

    server = FakeServer()
    agent = Agent(name="a")
    agent.mcp_servers = [server]
    guard_agent(agent, allow_tools=["search"])
    assert [g.name for g in server.tool_input_guardrails] == ["tenuo"]


def test_guarding_twice_does_not_stack(tools):
    agent = Agent(name="a", tools=[tools["search"]])
    guard_agent(agent, allow_tools=["search"])
    guard_agent(agent, allow_tools=["search"])
    assert [g.name for g in tools["search"].tool_input_guardrails] == ["tenuo"]


@pytest.mark.asyncio
async def test_agents_sharing_tools_keep_their_own_policy(tools, ran):
    """The policy belongs to the agent: sharing tool objects must not merge policies."""
    writer_model = ScriptedModel([[_call("delete_account", {"customer_id": "cus_1"}, "c1")]])
    reader_model = ScriptedModel([[_call("delete_account", {"customer_id": "cus_2"}, "c2")]])
    shared = [tools["search"], tools["delete_account"]]
    writer = guard_agent(Agent(name="writer", model=writer_model, tools=shared), allow_tools=["delete_account"])
    reader = guard_agent(Agent(name="reader", model=reader_model, tools=shared), allow_tools=["search"])
    await Runner.run(writer, "delete")
    await Runner.run(reader, "delete")
    assert ran == [("delete_account", "cus_1")]


@pytest.mark.asyncio
async def test_guarding_again_replaces_the_policy(tools, ran):
    model = ScriptedModel([[_call("delete_account", {"customer_id": "cus_1"}, "c1")]])
    agent = Agent(name="a", model=model, tools=[tools["delete_account"]])
    guard_agent(agent, allow_tools=["delete_account"])
    guard_agent(agent, allow_tools=["search"])
    await Runner.run(agent, "delete")
    assert ran == []


@pytest.mark.asyncio
async def test_unguarded_agent_using_a_guarded_tool_is_denied(tools, ran):
    guard_agent(Agent(name="guarded", tools=[tools["search"]]), allow_tools=["search"])
    model = ScriptedModel([[_call("search", {"query": "x"}, "c1")]])
    other = Agent(name="other", model=model, tools=[tools["search"]])
    await Runner.run(other, "search")
    assert ran == []


@pytest.mark.asyncio
async def test_clone_of_a_guarded_agent_needs_its_own_policy(tools, ran):
    model = ScriptedModel([[_call("search", {"query": "x"}, "c1")]])
    agent = guard_agent(Agent(name="a", model=model, tools=[tools["search"]]), allow_tools=["search"])
    clone = agent.clone(name="a-copy")
    await Runner.run(clone, "search")
    assert ran == []
    model.turns = [[_call("search", {"query": "y"}, "c2")]]
    await Runner.run(guard_agent(clone, allow_tools=["search"]), "search")
    assert ran == [("search", "y")]


@pytest.mark.asyncio
async def test_guarding_a_parent_keeps_the_policy_of_a_handoff_target(tools, ran):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("refund", amount=Range(max=100))
        .ttl(300)
        .mint(issuer)
    )
    refunds = guard_agent(
        Agent(name="refunds", model=ScriptedModel([]), tools=[tools["refund"]]),
        warrant=warrant,
        signing_key=holder,
        trusted_roots=[issuer.public_key],
    )
    # The parent's looser policy must not replace the refunds agent's warrant.
    guard_agent(
        Agent(name="triage", model=ScriptedModel([]), tools=[tools["search"]], handoffs=[refunds]),
        allow_tools=["search", "refund"],
    )
    refunds.model = ScriptedModel([[_call("refund", {"amount": 99999}, "c1")]])
    await Runner.run(refunds, "refund")
    assert ran == []

    # Calling guard_agent on the agent itself still replaces its policy.
    guard_agent(refunds, allow_tools=["refund"])
    refunds.model = ScriptedModel([[_call("refund", {"amount": 5}, "c2")]])
    await Runner.run(refunds, "refund")
    assert ran == [("refund", 5)]


@pytest.mark.asyncio
async def test_omitted_constrained_argument_never_runs_with_the_tool_default(ran):
    @function_tool
    def read_file(path: str = "/etc/shadow") -> str:
        """Read a file."""
        ran.append(path)
        return "ok"

    model = ScriptedModel([[_call("read_file", {}, "c1")], [_call("read_file", {"path": "/data/x"}, "c2")]])
    agent = guard_agent(
        Agent(name="reader", model=model, tools=[read_file]),
        allow_tools=["read_file"], constraints={"read_file": {"path": Subpath("/data")}},
    )
    await Runner.run(agent, "read")
    assert ran == ["/data/x"]
    assert any("blocked by Tenuo" in output for output in _tool_outputs(model))


@pytest.mark.asyncio
async def test_argument_the_sdk_would_convert_never_runs(tools, ran):
    # refund(amount: int): the SDK would turn "50" into 50 after the guardrail.
    model = ScriptedModel([[_call("refund", {"amount": "50"}, "c1")], [_call("refund", {"amount": 50}, "c2")]])
    agent = guard_agent(Agent(name="a", model=model, tools=[tools["refund"]]), allow_tools=["refund"])
    await Runner.run(agent, "refund")
    assert ran == [("refund", 50)]
    assert any("blocked by Tenuo" in o for o in _tool_outputs(model))


@pytest.mark.asyncio
async def test_concurrent_parent_registration_cannot_replace_a_target_policy(tools, ran, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import tenuo.openai as adapter

    target = Agent(name="refunds", model=ScriptedModel([]), tools=[tools["refund"]])
    parent = Agent(name="triage", model=ScriptedModel([]), tools=[tools["search"]], handoffs=[target])
    reached, proceed = threading.Event(), threading.Event()
    main_thread = threading.current_thread()
    register = adapter._register_agent_policy

    def pause_parent(agent, *args, **kwargs):
        if agent is target and threading.current_thread() is not main_thread:
            reached.set()
            assert proceed.wait(timeout=5)
        return register(agent, *args, **kwargs)

    monkeypatch.setattr(adapter, "_register_agent_policy", pause_parent)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(guard_agent, parent, allow_tools=["search", "refund"])
        try:
            assert reached.wait(timeout=5)
            guard_agent(target, allow_tools=["search"])
        finally:
            proceed.set()
        pending.result(timeout=5)
    target.model = ScriptedModel([[_call("refund", {"amount": 50}, "c1")]])
    await Runner.run(target, "refund")
    assert ran == []
    assert any("blocked by Tenuo" in output for output in _tool_outputs(target.model))
