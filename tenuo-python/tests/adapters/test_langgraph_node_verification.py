"""guard_node and TenuoToolNode driven through real StateGraph runs.

Each test records which node and tool bodies actually ran.
"""

import logging
import time
from typing import Annotated, Any, List, Optional, TypedDict

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.graph import END, START, StateGraph  # noqa: E402
from langgraph.graph.message import add_messages  # noqa: E402

from tenuo import Pattern, SigningKey, Warrant, configure  # noqa: E402
from tenuo.config import reset_config  # noqa: E402
from tenuo.exceptions import ConfigurationError  # noqa: E402
from tenuo.keys import KeyRegistry  # noqa: E402
from tenuo.langgraph import WRAP_TOOL_CALL_SUPPORTED, TenuoToolNode, guard_node  # noqa: E402

RAN: List[tuple] = []

issuer = SigningKey.generate()
holder = SigningKey.generate()
rogue = SigningKey.generate()


class State(TypedDict, total=False):
    messages: Annotated[list, add_messages]
    warrant: Any
    warrant_chain: list
    result: str


@tool
def search(query: str) -> str:
    """Search customer records."""
    RAN.append(("search", query))
    return f"results for {query}"


def mint(*, holder_key=holder, issuer_key=issuer, ttl=3600, tools=("search",)) -> Warrant:
    builder = Warrant.mint_builder().holder(holder_key.public_key)
    for name in tools:
        builder = builder.capability(name, query=Pattern("customers:*"))
    return builder.ttl(ttl).mint(issuer_key)


def researcher(state: State) -> dict:
    RAN.append(("researcher",))
    return {"result": "done"}


def run_guarded(warrant: Any, *, chain: Optional[list] = None, **guard_kwargs: Any) -> Any:
    g = StateGraph(State)
    g.add_node("researcher", guard_node(researcher, **guard_kwargs))
    g.add_edge(START, "researcher")
    g.add_edge("researcher", END)
    state: dict = {"messages": [], "warrant": warrant}
    if chain is not None:
        state["warrant_chain"] = chain
    return g.compile().invoke(state)


@pytest.fixture(autouse=True)
def _setup():
    reset_config()
    KeyRegistry.reset_instance()
    KeyRegistry.get_instance().register("default", holder)
    configure(trusted_roots=[issuer.public_key], mode="enforce")
    RAN.clear()
    yield
    reset_config()
    KeyRegistry.reset_instance()
    RAN.clear()


# --- guard_node verifies the warrant before the node runs --------------------


def test_guard_node_runs_for_valid_warrant():
    assert run_guarded(mint())["result"] == "done"
    assert RAN == [("researcher",)]


@pytest.mark.parametrize(
    "warrant_factory, reason",
    [
        (lambda: mint(issuer_key=rogue), "not trusted"),
        (lambda: mint(holder_key=rogue), "not the warrant holder"),
        (lambda: mint(ttl=1), "expired"),
    ],
    ids=["untrusted-issuer", "wrong-holder", "expired"],
)
def test_guard_node_blocks_unverified_warrant(warrant_factory, reason):
    warrant = warrant_factory()
    if reason == "expired":
        time.sleep(1.5)
    with pytest.raises(ConfigurationError, match=reason):
        run_guarded(warrant)
    assert RAN == []


def test_guard_node_without_trusted_roots_fails_closed():
    reset_config()
    with pytest.raises(ConfigurationError, match="no trusted roots"):
        run_guarded(mint())
    assert RAN == []


def test_guard_node_required_tools_accepts_constrained_capability():
    # search is granted with a query constraint; the node check must not
    # evaluate a call with empty arguments.
    assert run_guarded(mint(), required_tools=["search"])["result"] == "done"
    assert RAN == [("researcher",)]


def test_guard_node_required_tools_accepts_wildcard_grant():
    warrant = Warrant.mint_builder().holder(holder.public_key).capability("*").ttl(600).mint(issuer)
    assert run_guarded(warrant, required_tools=["search", "delete_record"])["result"] == "done"


def test_guard_node_required_tools_blocks_missing_tool():
    with pytest.raises(ConfigurationError, match="delete_record"):
        run_guarded(mint(), required_tools=["search", "delete_record"])
    assert RAN == []


def test_guard_node_delegated_warrant_needs_its_chain():
    parent_holder = SigningKey.generate()
    parent = mint(holder_key=parent_holder)
    child = parent.grant_builder().holder(holder.public_key).capability(
        "search", query=Pattern("customers:a*")
    ).ttl(600).grant(parent_holder)

    assert run_guarded(child, chain=[parent])["result"] == "done"
    assert RAN == [("researcher",)]
    RAN.clear()

    with pytest.raises(ConfigurationError, match="not trusted"):
        run_guarded(child)
    assert RAN == []


def test_guard_node_observe_mode_logs_and_runs(caplog):
    configure(trusted_roots=[issuer.public_key], mode="observe")
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        run_guarded(mint(issuer_key=rogue))
    assert RAN == [("researcher",)]
    assert any(r.getMessage().startswith("OBSERVE: would deny researcher") for r in caplog.records)


# --- TenuoToolNode -----------------------------------------------------------


needs_hooks = pytest.mark.skipif(
    not WRAP_TOOL_CALL_SUPPORTED, reason="langgraph-prebuilt >= 1.0.2 required for TenuoToolNode"
)


def run_tool_node(node: Any, state_extra: dict) -> dict:
    g = StateGraph(State)
    g.add_node("tools", node)
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    call = {"name": "search", "args": {"query": "customers:acme"}, "id": "c0", "type": "tool_call"}
    return g.compile().invoke({"messages": [AIMessage("", tool_calls=[call])], **state_extra})


class RecordingControlPlane:
    def __init__(self) -> None:
        self.events: List[Any] = []

    def emit_for_enforcement(self, result: Any, **_: Any) -> None:
        self.events.append(result)


@needs_hooks
def test_tool_node_emits_to_default_control_plane(monkeypatch):
    cp = RecordingControlPlane()
    monkeypatch.setattr("tenuo.control_plane.get_or_create", lambda: cp)

    run_tool_node(TenuoToolNode([search]), {"warrant": mint()})
    run_tool_node(TenuoToolNode([search]), {"warrant": mint(issuer_key=rogue)})

    assert RAN == [("search", "customers:acme")]
    assert [e.allowed for e in cp.events] == [True, False]


@needs_hooks
def test_tool_node_without_warrant_blocks_in_enforce_mode():
    out = run_tool_node(TenuoToolNode([search]), {})
    assert RAN == []
    assert out["messages"][-1].status == "error"


@needs_hooks
def test_tool_node_without_warrant_observe_mode_logs_and_runs(caplog):
    configure(trusted_roots=[issuer.public_key], mode="observe")
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        run_tool_node(TenuoToolNode([search]), {})
    assert RAN == [("search", "customers:acme")]
    assert any(r.getMessage().startswith("OBSERVE: would deny search") for r in caplog.records)
