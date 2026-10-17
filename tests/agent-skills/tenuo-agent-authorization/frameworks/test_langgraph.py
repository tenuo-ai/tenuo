"""Compiled graph and create_agent dispatch, including root-only delegation."""

from typing import Any, TypedDict

import pytest
from langchain.agents import create_agent
from langchain.agents.middleware import AgentState
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from tenuo import Range, SigningKey, Warrant
from tenuo.keys import KeyRegistry
from tenuo.langgraph import TenuoMiddleware, TenuoToolNode, guard_node


class State(TypedDict):
    messages: list
    warrant: Any
    warrant_chain: list


class AgentStateWithAuthority(AgentState):
    warrant: Any
    warrant_chain: list


class Scripted(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


@pytest.fixture
def authority():
    KeyRegistry.reset_instance()
    issuer, holder, worker = [SigningKey.generate() for _ in range(3)]
    # A wrong default makes dropped config/key selection visible.
    KeyRegistry.get_instance().register("default", SigningKey.generate())
    KeyRegistry.get_instance().register("holder", holder)
    KeyRegistry.get_instance().register("worker", worker)
    root = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("refund", amount=Range(max=500))
        .ttl(300)
        .mint(issuer)
    )
    child = (
        root.grant_builder()
        .holder(worker.public_key)
        .capability("refund", amount=Range(max=300))
        .ttl(120)
        .grant(holder)
    )
    yield issuer, root, child
    KeyRegistry.reset_instance()


@pytest.mark.parametrize("dispatch", ["toolnode", "middleware"])
@pytest.mark.parametrize("case", ["allow", "deny", "delegated", "missing-chain"])
def test_dispatch(dispatch, case, authority):
    issuer, root, child = authority
    effects = []

    @tool
    def refund(amount: int) -> str:
        """Refund cents."""
        effects.append(amount)
        return "refunded"

    delegated = case in ("delegated", "missing-chain")
    amount = 4900 if case == "deny" else 200
    state = {
        "warrant": child if delegated else root,
        "warrant_chain": [root] if case == "delegated" else [],
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "refund", "args": {"amount": amount}, "id": "call"}
                ],
            )
        ],
    }
    config = {"configurable": {"tenuo_key_id": "worker" if delegated else "holder"}}
    if dispatch == "toolnode":
        b = StateGraph(State)
        b.add_node("tools", TenuoToolNode([refund], trusted_roots=[issuer.public_key]))
        b.add_edge(START, "tools")
        b.add_edge("tools", END)
        graph = b.compile()
    else:
        model = Scripted(
            messages=iter([state["messages"][0], AIMessage(content="done")])
        )
        graph = create_agent(
            model,
            tools=[refund],
            middleware=[
                TenuoMiddleware(trusted_roots=[issuer.public_key], filter_tools=False)
            ],
            state_schema=AgentStateWithAuthority,
        )
        state["messages"] = []
    result = graph.invoke(state, config=config)
    allowed = case in ("allow", "delegated")
    assert effects == ([200] if allowed else [])
    messages = result["messages"]
    tools = [m for m in messages if m.type == "tool"]
    assert len(tools) == 1
    assert tools[0].status == ("success" if allowed else "error")


def test_guard_node_compiled_config_is_forwarded(authority):
    issuer, root, _ = authority
    seen = []

    def node(state: State, bound_warrant):
        seen.append(bound_warrant.holder_key.to_bytes())
        return {}

    b = StateGraph(State)
    b.add_node(
        "guarded",
        guard_node(node, inject_warrant=True, trusted_roots=[issuer.public_key]),
    )
    b.add_edge(START, "guarded")
    b.add_edge("guarded", END)
    b.compile().invoke(
        {"messages": [], "warrant": root, "warrant_chain": []},
        config={"configurable": {"tenuo_key_id": "holder"}},
    )
    assert seen == [root.authorized_holder.to_bytes()]


def test_original_handler_is_a_real_bypass(authority):
    """Negative control: graph interception cannot protect this callable."""
    effects = []

    @tool
    def refund(amount: int) -> str:
        """Refund cents."""
        effects.append(amount)
        return "refunded"

    TenuoToolNode([refund], trusted_roots=[authority[0].public_key])
    refund.invoke({"amount": 4900})
    assert effects == [4900]  # document the bypass, never claim zero here
