"""Explicit authority delegation inside a LangGraph node.

A planner node receives its authority through ``@tenuo_node``: the decorator
reads the warrant from graph state, looks up the planner's signing key by the
``tenuo_key_id`` in the LangGraph config, and injects a ``BoundWarrant``. No
private-key material ever lives in graph state.

The planner checks that research is allowed, then grants the worker a
short-lived child warrant that covers ``research`` only. The worker runs under
its own key and tries two tools. Every call goes through
``enforce_tool_call``, which verifies the delegation chain back to the trusted
issuer and the worker's proof-of-possession. ``research`` runs. ``publish``
is denied, and its body never executes.

Run with::

    pip install "tenuo[langgraph]"
    python examples/langchain/langgraph_tenuo_node.py

The example is fully local: it does not call a model, an API, or the network.
"""

from typing import Any, Callable, Dict, List, TypedDict

from tenuo import BoundWarrant, ScopeViolation, SigningKey, Warrant, enforce_tool_call
from tenuo.keys import KeyRegistry
from tenuo.langgraph import guard_node, tenuo_node

try:
    from langgraph.graph import END, START, StateGraph
except ImportError as exc:  # pragma: no cover - exercised by users without the extra
    raise SystemExit('Install the LangGraph extra first: pip install "tenuo[langgraph]"') from exc


PLANNER_KEY_ID = "langgraph-planner"
WORKER_KEY_ID = "langgraph-worker"
RESEARCH_TOPIC = "agent authorization patterns"


class DelegationState(TypedDict, total=False):
    """Serializable state shared by the planner and worker nodes."""

    warrant: Warrant
    # Parents of ``warrant``, root-first. A delegated warrant is only
    # verifiable together with the path back to the trusted issuer.
    warrant_chain: List[Warrant]
    planner_checked_research: bool
    research_result: str
    publish_denial: str
    executed_tools: List[str]


def run_demo() -> DelegationState:
    """Run a planner-to-worker delegation graph and return its final state."""
    # In production the issuer key lives in your control plane and the agent
    # keys come from a secret store (see ``load_tenuo_keys()``).
    issuer_key = SigningKey.generate()
    planner_key = SigningKey.generate()
    worker_key = SigningKey.generate()

    registry = KeyRegistry.get_instance()
    registry.register(PLANNER_KEY_ID, planner_key)
    registry.register(WORKER_KEY_ID, worker_key)

    root_warrant = (
        Warrant.mint_builder()
        .holder(planner_key.public_key)
        .capability("research")
        .capability("publish")
        .ttl(300)
        .mint(issuer_key)
    )

    # Tool bodies record that they ran, so we can prove the denied one did not.
    executed_tools: List[str] = []

    def research(topic: str) -> str:
        executed_tools.append("research")
        return f"Research notes for: {topic}"

    def publish(destination: str) -> str:
        executed_tools.append("publish")
        return f"Published to {destination}"

    def call_tool(
        bound_warrant: BoundWarrant,
        chain: List[Warrant],
        tool: Callable[..., str],
        args: Dict[str, Any],
    ) -> str:
        """Authorize first; run the tool body only if the call is allowed."""
        result = enforce_tool_call(
            tool.__name__,
            args,
            bound_warrant,
            trusted_roots=[issuer_key.public_key],
            warrant_chain=chain,
        )
        result.raise_if_denied()
        return tool(**args)

    @tenuo_node
    def planner(state: DelegationState, bound_warrant: BoundWarrant) -> DelegationState:
        """Check the root warrant and delegate only research to the worker."""
        # allows() is a fast local pre-check, handy for routing decisions.
        # Enforcement happens in the worker, at the tool call.
        if not bound_warrant.allows("research", {"topic": RESEARCH_TOPIC}):
            raise RuntimeError("Planner was not granted research authority")

        worker_warrant = bound_warrant.grant(
            to=worker_key.public_key,
            allow=["research"],
            ttl=60,
        )
        return {
            "warrant": worker_warrant,
            "warrant_chain": [bound_warrant.warrant],
            "planner_checked_research": True,
        }

    def worker(state: DelegationState, bound_warrant: BoundWarrant) -> DelegationState:
        """Run an allowed tool, then attempt one outside the delegated scope."""
        chain = state["warrant_chain"]
        research_result = call_tool(bound_warrant, chain, research, {"topic": RESEARCH_TOPIC})

        try:
            call_tool(bound_warrant, chain, publish, {"destination": "public"})
            publish_denial = ""
        except ScopeViolation as exc:  # the child warrant does not cover publish
            publish_denial = f"{type(exc).__name__}: {exc}"

        return {
            "research_result": research_result,
            "publish_denial": publish_denial,
            "executed_tools": list(executed_tools),
        }

    graph = StateGraph(DelegationState)
    graph.add_node("planner", planner)
    # The worker holds a different key than the planner. ``tenuo_key_id`` in
    # the config names the planner's key for the whole run, so the worker
    # names its own key explicitly with ``guard_node(key_id=...)``.
    graph.add_node("worker", guard_node(worker, key_id=WORKER_KEY_ID, inject_warrant=True))
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
    print(f"Publish denied: {result['publish_denial']}")
    print(f"Tool bodies that ran: {result['executed_tools']}")


if __name__ == "__main__":
    main()
