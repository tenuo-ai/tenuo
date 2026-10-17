"""Refund assistant. amount_cents is an integer count of USD cents."""
import json
import time
from dataclasses import dataclass
from agents.tool_context import ToolContext
from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.models.interface import Model
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
from tenuo import Exact, Range, SigningKey, Warrant, parse_strict_json
from refund_service import Presentation, RefundDenied, RefundService

set_tracing_disabled(True)
effects = []

@dataclass(frozen=True)
class RefundSession:
    service: RefundService
    chain: tuple[str, ...]
    holder: SigningKey

    def present(self, args):
        leaf = Warrant.from_base64(self.chain[-1])
        return Presentation(self.chain, leaf.sign(self.holder, "refund_order", args, int(time.time())))


def development_session():
    """Local demo issuance only; never production key provisioning."""
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    scope = {"order_id": Exact("123"), "amount_cents": Range(min=1, max=50000)}
    parent = Warrant.mint(keypair=issuer, capabilities={"refund_order": scope},
                          holder=holder.public_key, ttl_seconds=300)
    leaf = (parent.grant_builder().capability("refund_order", scope)
            .holder(holder.public_key).ttl(240).terminal().grant(holder))
    service = RefundService([issuer.public_key], effects)
    return RefundSession(service, (parent.to_base64(), leaf.to_base64()), holder)


@function_tool(failure_error_function=None)
def refund_order(ctx: ToolContext[RefundSession], order_id: str, amount_cents: int) -> str:
    """Refund an order; amount_cents is an integer count of USD cents."""
    if not isinstance(ctx.context, RefundSession):
        raise RefundDenied("missing session authority")
    # This SDK strips Annotated strictness while building its schema. Validate
    # the original JSON rather than trusting its coercive Pydantic conversion.
    args = parse_strict_json(ctx.tool_arguments)
    if (type(args) is not dict or set(args) != {"order_id", "amount_cents"}
            or type(args["order_id"]) is not str or type(args["amount_cents"]) is not int):
        raise RefundDenied("invalid argument types")
    order_id, amount_cents = args["order_id"], args["amount_cents"]
    return ctx.context.service.refund_order(order_id, amount_cents, ctx.context.present(args))

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
    return Agent(name="refund assistant", model=ScriptedModel(calls), tools=[refund_order])

async def run_agent(calls, *, session=None):
    session = development_session() if session is None else session
    return await Runner.run(make_agent(calls), "Process the requested refund.", context=session)
