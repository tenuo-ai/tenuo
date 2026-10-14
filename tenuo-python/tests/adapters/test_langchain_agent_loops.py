"""guard_agent / auto_protect / SecureAgentExecutor driven through real LangChain loops.

Each test records which tool bodies actually ran, so a wrapper that reports
protected tools while the agent keeps its originals fails here.
"""

import json
import logging
from typing import Any, List

import pytest

pytest.importorskip("langchain_core")
pytest.importorskip("langchain_classic")

from langchain_classic.agents import AgentExecutor, create_tool_calling_agent  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, AIMessageChunk  # noqa: E402
from langchain_core.outputs import ChatGenerationChunk  # noqa: E402
from langchain_core.prompts import ChatPromptTemplate  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from tenuo import Capability, Pattern, SigningKey, configure, mint_sync  # noqa: E402
from tenuo.config import reset_config  # noqa: E402
from tenuo.exceptions import ConfigurationError, ToolNotAuthorized  # noqa: E402
from tenuo.langchain import SecureAgentExecutor, auto_protect, guard_agent  # noqa: E402

RAN: List[tuple] = []


@tool
def search(query: str) -> str:
    """Search customer records."""
    RAN.append(("search", query))
    return f"results for {query}"


@tool
def delete_record(record_id: str) -> str:
    """Delete a customer record."""
    RAN.append(("delete_record", record_id))
    return f"deleted {record_id}"


TOOLS = [search, delete_record]
CALLS = [("search", {"query": "customers:acme"}), ("delete_record", {"record_id": "42"})]
SEARCH_ONLY = [Capability("search", query=Pattern("customers:*"))]


class ScriptedModel(GenericFakeChatModel):
    """Replays scripted AI messages; tool binding is a no-op."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedModel":
        return self

    def _stream(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
        # AgentExecutor streams; emit each scripted message whole so its tool calls survive.
        msg = next(self.messages)
        yield ChatGenerationChunk(
            message=AIMessageChunk(
                content=msg.content,
                tool_call_chunks=[
                    {"name": t["name"], "args": json.dumps(t["args"]), "id": t["id"], "index": i}
                    for i, t in enumerate(msg.tool_calls)
                ],
            )
        )


def scripted(calls) -> ScriptedModel:
    tool_calls = [{"name": n, "args": a, "id": f"c{i}", "type": "tool_call"} for i, (n, a) in enumerate(calls)]
    return ScriptedModel(messages=iter([AIMessage("", tool_calls=tool_calls), AIMessage("Done.")]))


def classic_executor(calls=CALLS) -> AgentExecutor:
    prompt = ChatPromptTemplate.from_messages(
        [("system", "You help."), ("human", "{input}"), ("placeholder", "{agent_scratchpad}")]
    )
    return AgentExecutor(agent=create_tool_calling_agent(scripted(calls), TOOLS, prompt), tools=TOOLS)


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    RAN.clear()
    yield
    reset_config()
    RAN.clear()


# --- guard_agent on langchain_classic.AgentExecutor -------------------------


def test_guard_agent_routes_classic_executor_through_guarded_tools():
    protected = guard_agent(classic_executor(), issuer_key=SigningKey.generate(), capabilities=SEARCH_ONLY)

    with pytest.raises(ToolNotAuthorized):
        protected.invoke({"input": "look up acme"})

    assert RAN == [("search", "customers:acme")]
    assert ("delete_record", "42") not in RAN


def test_auto_protect_enforce_executor_without_warrant_runs_nothing():
    protected = auto_protect(classic_executor(), mode="enforce")

    with pytest.raises(ToolNotAuthorized):
        protected.invoke({"input": "look up acme"})

    assert RAN == []


def test_secure_agent_executor_works_with_classic_agent():
    issuer = SigningKey.generate()
    configure(issuer_key=issuer, dev_mode=True, trusted_roots=[issuer.public_key])
    prompt = ChatPromptTemplate.from_messages(
        [("system", "You help."), ("human", "{input}"), ("placeholder", "{agent_scratchpad}")]
    )
    executor = SecureAgentExecutor(agent=create_tool_calling_agent(scripted(CALLS), TOOLS, prompt), tools=TOOLS)

    with mint_sync(*SEARCH_ONLY):
        with pytest.raises(ToolNotAuthorized):
            executor.invoke({"input": "look up acme"})

    assert RAN == [("search", "customers:acme")]


# --- create_agent graphs are refused, never returned unprotected ------------


def test_guard_agent_refuses_create_agent_graph():
    from langchain.agents import create_agent

    graph = create_agent(model=scripted(CALLS), tools=TOOLS)
    with pytest.raises(ConfigurationError, match="TenuoMiddleware"):
        guard_agent(graph, capabilities=SEARCH_ONLY)
    assert RAN == []


def test_auto_protect_refuses_create_agent_graph():
    from langchain.agents import create_agent

    graph = create_agent(model=scripted(CALLS), tools=TOOLS)
    with pytest.raises(ConfigurationError, match="TenuoMiddleware"):
        auto_protect(graph, mode="enforce")


def test_guard_agent_refuses_unknown_agent_type():
    class LooksLikeAnAgent:
        tools = TOOLS

        def invoke(self, *_: Any, **__: Any) -> Any:
            return search.invoke({"query": "anything"})

    with pytest.raises(ConfigurationError, match="expects an AgentExecutor"):
        guard_agent(LooksLikeAnAgent())


# --- observe mode: no warrant is logged and allowed -------------------------


def test_auto_protect_observe_runs_without_warrant_and_logs(caplog):
    from langchain.agents import create_agent

    tools = auto_protect(TOOLS)  # unconfigured -> observe
    agent = create_agent(model=scripted(CALLS), tools=tools)

    with caplog.at_level(logging.WARNING, logger="tenuo"):
        agent.invoke({"messages": [("human", "go")]})

    assert sorted(RAN) == [("delete_record", "42"), ("search", "customers:acme")]
    observed = [r.getMessage() for r in caplog.records if r.getMessage().startswith("OBSERVE: would deny")]
    assert len(observed) == 2


def test_auto_protect_enforce_tools_without_warrant_run_nothing():
    from langchain.agents import create_agent

    tools = auto_protect(TOOLS, mode="enforce")
    agent = create_agent(model=scripted(CALLS), tools=tools)

    with pytest.raises(ToolNotAuthorized):
        agent.invoke({"messages": [("human", "go")]})
    assert RAN == []
