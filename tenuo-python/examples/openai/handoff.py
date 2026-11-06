"""Native Agents SDK handoff with a narrower Tenuo specialist warrant.

Run with ``python handoff.py`` after installing ``tenuo[openai]``. The model
is scripted, so this needs no API key or network access. The Agents SDK routes
the handoff; Tenuo checks each specialist tool call before it runs.
"""

import asyncio
import json

from agents import Agent, Runner, function_tool, handoff, set_tracing_disabled
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from tenuo import Range, SigningKey, Warrant
from tenuo.openai import create_tier2_guardrail, guard_agent


def _call(name, args, call_id):
    return ResponseFunctionToolCall(
        type="function_call", name=name, arguments=json.dumps(args), call_id=call_id, id=call_id
    )


def _text(value):
    return ResponseOutputMessage(
        id="msg",
        type="message",
        role="assistant",
        status="completed",
        content=[ResponseOutputText(type="output_text", text=value, annotations=[])],
    )


class ScriptedModel(Model):
    """Return fixed model turns to exercise the real SDK handoff and tools."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.inputs = []

    async def get_response(self, system_instructions, input, *args, **kwargs):
        self.inputs.append(input)
        return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError


def build_agents(model, executed):
    """Return the triage agent, warrants, and specialist guardrail."""
    issuer = SigningKey.generate()
    triage_key = SigningKey.generate()
    specialist_key = SigningKey.generate()
    parent = (
        Warrant.mint_builder()
        .capability("lookup_order")
        .capability("issue_refund")
        .capability("delete_all_orders")
        .holder(triage_key.public_key)
        .ttl(300)
        .mint(issuer)
    )
    child = (
        parent.grant_builder()
        .capability("lookup_order")
        .capability("issue_refund", amount=Range(max=100))
        .holder(specialist_key.public_key)
        .ttl(120)
        .grant(triage_key)
    )

    @function_tool
    def lookup_order() -> str:
        """Look up the sample order."""
        executed.append("lookup_order")
        return "order_123: refundable"

    @function_tool
    def issue_refund(amount: int) -> str:
        """Refund the sample order by an amount in cents."""
        executed.append("issue_refund")
        return f"refunded {amount} cents"

    @function_tool
    def delete_all_orders() -> str:
        """Delete every order (included only to demonstrate denial)."""
        executed.append("delete_all_orders")
        return "deleted"

    specialist = Agent(
        name="refund_specialist",
        model=model,
        tools=[lookup_order, issue_refund, delete_all_orders],
    )
    guard_agent(
        specialist,
        warrant=child,
        signing_key=specialist_key,
        trusted_roots=[issuer.public_key],
        warrant_chain=[parent],
    )
    guardrail = create_tier2_guardrail(
        warrant=child,
        signing_key=specialist_key,
        trusted_roots=[issuer.public_key],
        warrant_chain=[parent],
    )
    triage = Agent(name="triage", model=model, handoffs=[handoff(specialist)])
    return triage, parent, child, guardrail


async def main():
    set_tracing_disabled(True)
    model = ScriptedModel(
        [
            [_call("transfer_to_refund_specialist", {}, "h1")],
            [_call("lookup_order", {}, "c1")],
            [_call("issue_refund", {"amount": 50}, "c2")],
            [_call("delete_all_orders", {}, "c3")],
            [_text("done")],
        ]
    )
    executed = []
    triage, _, _, _ = build_agents(model, executed)
    await Runner.run(triage, "Check the sample order and refund 50 cents")
    print(f"Tool bodies executed: {executed}")
    print("The deletion was denied before its body ran.")


if __name__ == "__main__":
    asyncio.run(main())
