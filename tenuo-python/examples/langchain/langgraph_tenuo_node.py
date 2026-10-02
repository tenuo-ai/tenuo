"""Explicit authority delegation inside a LangGraph node.

The planner receives its authority through ``@tenuo_node`` instead of reading
private-key material from graph state. It narrows that authority to a worker
and stores only the serializable child warrant in state.

Run with::

    pip install "tenuo[langgraph]"
    python examples/langchain/langgraph_tenuo_node.py

The example is fully local: it does not call a model, an API, or the network.
"""

from typing import TypedDict

from tenuo import BoundWarrant, SigningKey, Warrant
from tenuo.keys import KeyRegistry
from tenuo.langgraph import tenuo_node

try:
    from langgraph.graph import END, START, StateGraph
except ImportError as exc:  # pragma: no cover - exercised by users without the extra
    raise SystemExit('Install the LangGraph extra first: pip install "tenuo[langgraph]"') from exc


PLANNER_KEY_ID = "langgraph-planner"
RESEARCH_TOPIC = "agent authorization patterns"


class DelegationState(TypedDict, total=False):
    """Serializable state shared by the planner and worker nodes."""

    warrant: Warrant
    planner_checked_research: bool
    research_result: str
    denied_action_body_ran: bool


def run_demo() -> DelegationState:
    """Run a planner-to-worker delegation graph and return its final state."""
    KeyRegistry.reset_instance()
    registry = KeyRegistry.get_instance()

    planner_key = SigningKey.generate()
    worker_key = SigningKey.generate()
    registry.register(PLANNER_KEY_ID, planner_key)

    root_warrant = (
        Warrant.mint_builder()
        .holder(planner_key.public_key)
        .capability("research")
        .capability("publish")
        .ttl(300)
        .mint(planner_key)
    )

    @tenuo_node
    def planner(state: DelegationState, bound_warrant: BoundWarrant) -> DelegationState:
        """Check the root warrant and delegate only research to the worker."""
        if not bound_warrant.allows("research", {"topic": RESEARCH_TOPIC}):
            raise RuntimeError("Planner was not granted research authority")

        worker_warrant = bound_warrant.grant(
            to=worker_key.public_key,
            allow=["research"],
            ttl=60,
        )
        return {
            "warrant": worker_warrant,
            "planner_checked_research": True,
        }

    def worker(state: DelegationState) -> DelegationState:
        """Run an allowed action and prove a broader action is never invoked."""
        worker_warrant = state["warrant"]
        if not worker_warrant.allows("research", {"topic": RESEARCH_TOPIC}):
            raise RuntimeError("Worker did not receive research authority")

        research_result = f"Research notes for: {RESEARCH_TOPIC}"
        denied_action_body_ran = False

        # The child only grants ``research``, so this branch must stay unreachable.
        if worker_warrant.allows("publish", {"destination": "public"}):
            denied_action_body_ran = True
            research_result = "This must never be published"

        return {
            "research_result": research_result,
            "denied_action_body_ran": denied_action_body_ran,
        }

    graph = StateGraph(DelegationState)
    graph.add_node("planner", planner)
    graph.add_node("worker", worker)
    graph.add_edge(START, "planner")
    graph.add_edge("planner", "worker")
    graph.add_edge("worker", END)

    app = graph.compile()
    return app.invoke(
        {"warrant": root_warrant},
        config={"configurable": {"tenuo_key_id": PLANNER_KEY_ID}},
    )


def main() -> None:
    """Print the local result and the denied-action safety check."""
    result = run_demo()
    print(result["research_result"])
    print(f"Planner checked research: {result['planner_checked_research']}")
    print(f"Denied action body ran: {result['denied_action_body_ran']}")


if __name__ == "__main__":
    main()
