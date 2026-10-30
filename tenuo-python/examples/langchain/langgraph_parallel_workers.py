"""Parallel LangGraph workers with separate, attenuated Tenuo warrants.

Run with ``python examples/langchain/langgraph_parallel_workers.py`` after
installing ``tenuo[langgraph]``. No LLM, credentials, or server is needed.
"""

import asyncio
import operator
from typing import Annotated, Awaitable, Callable, List, Optional, TypedDict
from uuid import uuid4

from langchain_core.messages import AIMessage, AnyMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.types import Send

from tenuo import SigningKey, Warrant
from tenuo.keys import KeyRegistry
from tenuo.langgraph import TenuoToolNode, guard_node


class State(TypedDict):
    messages: Annotated[List[AnyMessage], operator.add]
    warrant: str
    warrant_chain: List[str]
    dispatches: List[dict]


def build_graph(
    on_execute: Optional[Callable[[], Awaitable[None]]] = None,
):
    """Build a graph; ``on_execute`` lets tests synchronize the tool bodies."""
    issuer = SigningKey.generate()
    orchestrator = SigningKey.generate()
    researcher = SigningKey.generate()
    writer = SigningKey.generate()
    prefix = str(uuid4())
    registry = KeyRegistry.get_instance()
    registry.register(f"{prefix}-orchestrator", orchestrator)
    registry.register(f"{prefix}-researcher", researcher)
    registry.register(f"{prefix}-writer", writer)

    root = (
        Warrant.mint_builder()
        .holder(orchestrator.public_key)
        .capability("search")
        .capability("write_report")
        .ttl(300)
        .mint(issuer)
    )
    executed: List[str] = []

    @tool
    async def search(query: str) -> str:
        """Search for material for a report."""
        executed.append("search")
        if on_execute is not None:
            await on_execute()
        return f"Found material for {query}"

    @tool
    async def write_report(report: str) -> str:
        """Write a report from research material."""
        executed.append("write_report")
        if on_execute is not None:
            await on_execute()
        return f"Wrote {report}"

    def prepare_workers(state: State, bound_warrant) -> dict:
        # Each Send payload carries only that worker's warrant and the parent
        # chain. Private signing keys stay in the registry, outside graph state.
        researcher_warrant = bound_warrant.grant(to=researcher.public_key, allow=["search"], ttl=120)
        writer_warrant = bound_warrant.grant(to=writer.public_key, allow=["write_report"], ttl=120)
        chain = [state["warrant"]]
        return {
            "dispatches": [
                {
                    "worker": "researcher",
                    "warrant": str(researcher_warrant),
                    "warrant_chain": chain,
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {"name": "search", "args": {"query": "AI agents"}, "id": "research-search"},
                                {"name": "write_report", "args": {"report": "wrong"}, "id": "research-write"},
                            ],
                        )
                    ],
                },
                {
                    "worker": "writer",
                    "warrant": str(writer_warrant),
                    "warrant_chain": chain,
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {"name": "write_report", "args": {"report": "AI agents"}, "id": "writer-write"},
                                {"name": "search", "args": {"query": "wrong"}, "id": "writer-search"},
                            ],
                        )
                    ],
                },
            ]
        }

    def fan_out(state: State):
        return [Send(item["worker"], item) for item in state["dispatches"]]

    graph = StateGraph(State)
    graph.add_node(
        "orchestrator",
        guard_node(
            prepare_workers,
            key_id=f"{prefix}-orchestrator",
            inject_warrant=True,
            trusted_roots=[issuer.public_key],
        ),
    )
    for name in ("researcher", "writer"):
        graph.add_node(
            name,
            TenuoToolNode(
                [search, write_report],
                key_id=f"{prefix}-{name}",
                trusted_roots=[issuer.public_key],
            ),
        )
        graph.add_edge(name, END)
    graph.set_entry_point("orchestrator")
    graph.add_conditional_edges("orchestrator", fan_out)
    return graph.compile(), str(root), executed


async def main() -> None:
    graph, root, executed = build_graph()
    result = await graph.ainvoke({"messages": [], "warrant": root, "warrant_chain": [], "dispatches": []})
    for message in result["messages"]:
        if isinstance(message, ToolMessage):
            print(f"{message.tool_call_id}: {message.status}: {message.content}")
    print(f"Tool bodies executed: {executed}")


if __name__ == "__main__":
    asyncio.run(main())
