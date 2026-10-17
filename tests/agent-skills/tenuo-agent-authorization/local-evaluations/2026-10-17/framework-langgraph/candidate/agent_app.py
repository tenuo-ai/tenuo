"""Local scripted refund agent; all effects are fake, amounts are USD cents.

The handler verifies public presentations. Only the caller makes holder proof.
This process-local development example is not a sandbox for arbitrary Python.
"""
import time
from typing import Any, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langchain_core.tools import tool
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from pydantic import StrictInt, StrictStr
from tenuo import Authorizer, Exact, Range, SigningKey, Warrant
from tenuo.keys import KeyRegistry

effects = []


@tool
def refund_order(order_id: StrictStr, amount_cents: StrictInt) -> str:
    """Retired direct refund route: use a configured graph with public proof."""
    raise PermissionError("Direct refund route disabled: authorization required")


class State(TypedDict):
    messages: list
    warrant: Any
    warrant_chain: list


def task_authority():
    """Development issuance entrypoint; keep these issuer keys outside agents in production."""
    issuer, parent_holder, worker = [SigningKey.generate() for _ in range(3)]
    scope = {"order_id": Exact("123"), "amount_cents": Range(min=1, max=50000)}
    root = Warrant.mint_builder().holder(parent_holder.public_key).capability("refund_order", **scope).ttl(300).mint(issuer)
    child = root.grant_builder().holder(worker.public_key).capability("refund_order", **scope).ttl(120).terminal().grant(parent_holder)
    registry = KeyRegistry.get_instance()
    # A different default key makes config-forwarding mistakes detectable.
    registry.register("default", SigningKey.generate())
    registry.register("refund-worker", worker)
    return issuer, root, child


def make_graph(roots):
    # Trust is pinned at graph construction, never supplied by a tool request.
    if not roots:
        raise ValueError("Explicit trusted issuer roots required")
    verifier = Authorizer(trusted_roots=list(roots), clock_tolerance_secs=0)

    @tool("refund_order")
    def protected_refund(order_id: StrictStr, amount_cents: StrictInt, config: RunnableConfig) -> str:
        """Refund order 123 for 1..50000 integer USD cents with caller proof."""
        # Strict schema avoids framework coercion before this final boundary.
        if type(order_id) is not str or type(amount_cents) is not int:
            raise PermissionError("Invalid refund argument types")
        if order_id != "123" or not 1 <= amount_cents <= 50000:
            raise PermissionError("Refund exceeds local order/amount ceiling")
        args = {"order_id": order_id, "amount_cents": amount_cents}
        presentation = config.get("configurable", {}).get("refund_presentation")
        if not isinstance(presentation, dict):
            raise PermissionError("Missing public authorization presentation")
        try:
            tokens, signature = presentation["chain"], presentation["signature"]
            if not isinstance(tokens, list) or not tokens or not isinstance(signature, bytes) or len(signature) != 64:
                raise ValueError("Malformed chain or proof")
            chain = [Warrant.from_base64(token) for token in tokens]
            verifier.check_chain(chain, "refund_order", args, signature)
        except Exception as exc:
            raise PermissionError(f"Authorization denied: {exc}") from exc
        # No unguarded refund function/client exists behind this check.
        effects.append((args["order_id"], args["amount_cents"]))
        return "refunded"

    builder = StateGraph(State)
    builder.add_node("tools", ToolNode([protected_refund], handle_tool_errors=True))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()


def run_refund(graph, warrant, parents, order_id, amount_cents):
    """Caller-side scripted dispatcher; private key never reaches the verifier."""
    presentation = None
    if warrant is not None:
        key = KeyRegistry.get_instance().get("refund-worker")
        args = {"order_id": order_id, "amount_cents": amount_cents}
        presentation = {"chain": [w.to_base64() for w in [*parents, warrant]],
                        "signature": warrant.sign(key, "refund_order", args, int(time.time()))}
    state = {"messages": [AIMessage(content="", tool_calls=[{"name": "refund_order", "args": {"order_id": order_id, "amount_cents": amount_cents}, "id": "call"}])], "warrant": warrant, "warrant_chain": parents}
    return graph.invoke(state, config={"configurable": {"tenuo_key_id": "refund-worker", "refund_presentation": presentation}})
