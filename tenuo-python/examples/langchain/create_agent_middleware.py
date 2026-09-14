"""
LangChain create_agent() + TenuoMiddleware quickstart.

The shortest current-generation LangChain agent with Tenuo: a warrant in agent
state decides which tool calls run.

Demonstrates:
1. Minting a warrant for a holder key, signed by an issuer key.
2. Registering the holder key in KeyRegistry (no environment variables).
3. Installing TenuoMiddleware with trusted_roots on create_agent().
4. An authorized `search` call running, and `delete_record` (not in the warrant)
   being denied without its body executing.

Requires LangChain >= 1.0 (for create_agent and agent middleware):

    uv pip install "tenuo[langchain,langgraph]" "langchain>=1.0"
    python create_agent_middleware.py

A deterministic fake chat model scripts the tool calls, so no provider
credentials or network access are needed. Swap in a real model (for example
``model="openai:gpt-4.1"``) to let the LLM choose tools.
"""

from typing import Any, Dict, Iterable, List

from langchain.agents import create_agent
from langchain.agents.middleware import AgentState
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool

from tenuo import Pattern, SigningKey, Warrant
from tenuo.keys import KeyRegistry
from tenuo.langgraph import TenuoMiddleware

HOLDER_KEY_ID = "support-agent"

# Records every tool body that actually runs, so the denial is observable.
executed: List[str] = []


@tool
def search(query: str) -> str:
    """Search customer records."""
    executed.append(f"search:{query}")
    return f"3 records match {query!r}"


@tool
def delete_record(record_id: str) -> str:
    """Delete a customer record."""
    executed.append(f"delete_record:{record_id}")
    return f"record {record_id} deleted"


class TenuoAgentState(AgentState):
    """Agent state with the documented ``warrant`` field TenuoMiddleware reads."""

    warrant: Any


class ScriptedChatModel(GenericFakeChatModel):
    """Fake chat model that replays scripted messages, including tool calls."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedChatModel":
        return self


def scripted_model(tool_name: str, args: Dict[str, Any]) -> ScriptedChatModel:
    """A model that calls one tool, then answers."""
    return ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[{"name": tool_name, "args": args, "id": "call-1", "type": "tool_call"}],
                ),
                AIMessage(content="Done."),
            ]
        )
    )


def setup_keys_and_warrant() -> tuple:
    """Create keys, register the holder key, and mint a search-only warrant."""
    issuer_key = SigningKey.generate()  # The authority that issues warrants.
    holder_key = SigningKey.generate()  # The agent's own key, used for proof of possession.

    # The middleware looks the holder key up by id; nothing is read from the environment.
    KeyRegistry.get_instance().register(HOLDER_KEY_ID, holder_key)

    # Allow `search` only for customer queries. `delete_record` is simply not granted.
    warrant = (
        Warrant.mint_builder()
        .holder(holder_key.public_key)
        .capability("search", query=Pattern("customers:*"))
        .ttl(3600)
        .mint(issuer_key)
    )
    return issuer_key, warrant


def build_agent(model: Any, issuer_key: SigningKey) -> Any:
    """Build a create_agent() agent protected by TenuoMiddleware."""
    return create_agent(
        model=model,
        tools=[search, delete_record],
        state_schema=TenuoAgentState,
        middleware=[
            TenuoMiddleware(
                key_id=HOLDER_KEY_ID,
                # Only warrants issued by this key are accepted.
                trusted_roots=[issuer_key.public_key],
            )
        ],
    )


def run(tool_name: str, args: Dict[str, Any], issuer_key: SigningKey, warrant: Warrant) -> List[ToolMessage]:
    """Invoke the agent with the warrant in state and return its tool messages."""
    agent = build_agent(scripted_model(tool_name, args), issuer_key)
    result = agent.invoke({"messages": [HumanMessage("Handle the request.")], "warrant": warrant})
    return tool_messages(result["messages"])


def tool_messages(messages: Iterable[Any]) -> List[ToolMessage]:
    return [message for message in messages if isinstance(message, ToolMessage)]


def main() -> None:
    issuer_key, warrant = setup_keys_and_warrant()

    print("1. Authorized: search customers")
    for message in run("search", {"query": "customers:acme"}, issuer_key, warrant):
        print(f"   {message.status}: {message.content}")

    print("2. Not in the warrant: delete_record")
    for message in run("delete_record", {"record_id": "42"}, issuer_key, warrant):
        print(f"   {message.status}: {message.content}")

    print(f"Tool bodies that ran: {executed}")


if __name__ == "__main__":
    main()
