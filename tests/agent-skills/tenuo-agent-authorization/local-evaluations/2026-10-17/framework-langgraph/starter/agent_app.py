"""Compiled refund agent. amount_cents is USD cents."""
from typing import Any, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langchain_core.tools import tool
from langchain_core.messages import AIMessage
from tenuo import Exact, Range, SigningKey, Warrant
from tenuo.keys import KeyRegistry

effects = []

@tool
def refund_order(order_id: str, amount_cents: int) -> str:
    """Refund an order; amount_cents is USD cents."""
    effects.append((order_id, amount_cents))
    return "refunded"

class State(TypedDict):
    messages: list
    warrant: Any
    warrant_chain: list

def task_authority():
    issuer, parent_holder, worker = [SigningKey.generate() for _ in range(3)]
    root = Warrant.mint_builder().holder(parent_holder.public_key).capability("refund_order", order_id=Exact("123"), amount_cents=Range(max=50000)).ttl(300).mint(issuer)
    child = root.grant_builder().holder(worker.public_key).capability("refund_order", order_id=Exact("123"), amount_cents=Range(max=50000)).ttl(120).grant(parent_holder)
    registry = KeyRegistry.get_instance()
    registry.register("default", SigningKey.generate())
    registry.register("refund-worker", worker)
    return issuer, root, child

def make_graph(roots):
    builder = StateGraph(State)
    builder.add_node("tools", ToolNode([refund_order]))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()

def run_refund(graph, warrant, parents, order_id, amount_cents):
    state = {"messages": [AIMessage(content="", tool_calls=[{"name": "refund_order", "args": {"order_id": order_id, "amount_cents": amount_cents}, "id": "call"}])], "warrant": warrant, "warrant_chain": parents}
    return graph.invoke(state, config={"configurable": {"tenuo_key_id": "refund-worker"}})
