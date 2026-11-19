# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2", "openai-agents==0.22.0"]
# ///
"""Generic service enforcement through a real Agents Runner; no guard_agent API."""
import asyncio
import json
from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.tool_context import ToolContext
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
from tenuo import parse_strict_json
from common import Task, demonstrate

set_tracing_disabled(True)


class ScriptedModel(Model):
    """A model already fooled into requesting the supplied tool arguments."""
    def __init__(self, arguments):
        self.arguments = arguments
        self.done = False

    async def get_response(self, *args, **kwargs):
        if not self.done:
            self.done = True
            output = [ResponseFunctionToolCall(type="function_call", name="pay_invoice",
                      arguments=json.dumps(self.arguments), call_id="call", id="call")]
        else:
            output = [ResponseOutputMessage(id="done", type="message", role="assistant",
                      status="completed", content=[ResponseOutputText(type="output_text",
                      text="done", annotations=[])])]
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError("This example uses non-streaming Runner.run")


async def main():
    task = Task()

    @function_tool(failure_error_function=None)
    def pay_invoice(ctx: ToolContext, invoice_id: str, bank_account: str, amount_cents: int) -> str:
        """Pay the invoice in integer cents."""
        # This SDK coerces typed parameters. Use its original JSON, so the
        # verified values are exactly those used by the effect owner.
        return task.pay(parse_strict_json(ctx.tool_arguments))

    async def dispatch(args):
        agent = Agent(name="invoice specialist", model=ScriptedModel(args), tools=[pay_invoice])
        await Runner.run(agent, "Pay the assigned invoice.")

    await demonstrate(dispatch, lambda: task.service.effect_count)


if __name__ == "__main__":
    asyncio.run(main())
