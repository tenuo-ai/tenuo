"""Refund assistant. amount_cents is an integer count of USD cents."""
import json
from agents import Agent, Runner, function_tool, InputGuardrail, set_tracing_disabled
from agents.models.interface import Model
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
from tenuo import Exact, Range
from tenuo.openai import create_tier1_guardrail

set_tracing_disabled(True)
effects = []

@function_tool
def refund_order(order_id: str, amount_cents: int) -> str:
    """Refund an order; amount_cents is USD cents."""
    effects.append((order_id, amount_cents))
    return "refunded"

class ScriptedModel(Model):
    def __init__(self, calls):
        self.calls = iter(calls)
        self.turn = 0
    async def get_response(self, *args, **kwargs):
        self.turn += 1
        call = next(self.calls, None)
        output = [ResponseFunctionToolCall(type="function_call", name="refund_order", arguments=json.dumps(call), call_id=f"c{self.turn}", id=f"c{self.turn}")] if call else [ResponseOutputMessage(id="msg", type="message", role="assistant", status="completed", content=[ResponseOutputText(type="output_text", text="done", annotations=[])])]
        return ModelResponse(output=output, usage=Usage(), response_id=None)
    def stream_response(self, *args, **kwargs):
        raise NotImplementedError

def make_agent(calls):
    policy = create_tier1_guardrail(allow_tools=["refund_order"], constraints={"refund_order": {"order_id": Exact("123"), "amount_cents": Range(max=50000)}})
    return Agent(name="refund assistant", model=ScriptedModel(calls), tools=[refund_order], input_guardrails=[InputGuardrail(guardrail_function=policy, name="tenuo")])

async def run_agent(calls):
    return await Runner.run(make_agent(calls), "Process the requested refund.")
