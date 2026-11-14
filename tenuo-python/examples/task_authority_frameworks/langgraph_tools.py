# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2", "langgraph==1.2.11", "langchain-core==1.6.12"]
# ///
"""Generic service enforcement through compiled LangGraph ToolNode dispatch."""
import asyncio
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from pydantic import StrictInt, StrictStr
from common import Task, demonstrate


async def main():
    task = Task()

    @tool
    def pay_invoice(invoice_id: StrictStr, bank_account: StrictStr, amount_cents: StrictInt) -> str:
        """Pay the invoice in integer cents."""
        return task.pay(dict(invoice_id=invoice_id, bank_account=bank_account, amount_cents=amount_cents))

    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([pay_invoice], handle_tool_errors=False))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile()

    async def dispatch(args):
        # A scripted model tool request; the compiled graph invokes the tool.
        await app.ainvoke({"messages": [AIMessage(content="", tool_calls=[
            {"name": "pay_invoice", "args": args, "id": "call", "type": "tool_call"}])]})

    await demonstrate(dispatch, lambda: task.service.effect_count)


if __name__ == "__main__":
    asyncio.run(main())
