"""
LangGraph Tenuo Integration Example.

Demonstrates:
1. Secure Agent with NO private keys in state (Checkpointing safe).
2. TenuoToolNode for authorized tool execution.
3. guard_node() wrapper for pure nodes.
4. BoundWarrant dynamic injection.

Run with:
    python examples/langgraph_protected.py
"""

import operator
from typing import Annotated, TypedDict, List, Dict, Any
from uuid import uuid4

# Tenuo Imports
from tenuo import Warrant, SigningKey
from tenuo.keys import KeyRegistry
from tenuo.langgraph import (
    guard_node,
    TenuoToolNode,
    require_warrant,
)

# LangGraph / LangChain Imports
try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.memory import MemorySaver
    from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
    from langchain_core.tools import tool
    from langchain_core.runnables import RunnableConfig  # noqa: F401
except ImportError:
    print("Please install langgraph and langchain-core to run this example.")
    print("uv pip install langgraph langchain-core")
    exit(1)


# =============================================================================
# 1. Setup Infrastructure (Keys & Registry)
# =============================================================================

# In production, keys come from env vars (e.g., K8s secrets)
# We simulate this by setting env vars and using load_tenuo_keys()
worker_key = SigningKey.generate()
# Export as hex/base64 (Tenuo keys have .to_hex() or similar?)
# SigningKey string repr is usually redacted.
# For this example, we manually register to keep it simple,
# but we show the pattern.

print("🔒 Registering keys...")
registry = KeyRegistry.get_instance()
registry.register("worker-1", worker_key)

# Creates an ISSUER warrant (usually done by an authority service)
# Here we just self-issue for the demo
print("📜 issuing warrant...")
root_warrant = Warrant.mint_builder().tool("echo").tool("search").mint(worker_key)

print(f"   Warrant ID: {root_warrant.id}")


# =============================================================================
# 2. Define Tools
# =============================================================================


@tool
def echo(msg: str) -> str:
    """Echoes the input message."""
    return f"Echo: {msg}"


@tool
def search(query: str) -> str:
    """Searches the database."""
    return f"Results for: {query}"


@tool
def delete_database() -> str:
    """Dangerous tool!"""
    return "Database deleted!"


# We only authorize 'echo' and 'search' in the warrant above.
tools = [echo, search, delete_database]


# =============================================================================
# 3. Define State
# =============================================================================


class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    warrant: str  # Storing as string/token prevents serialization issues with checkpointers
    # key_id is passed via config, NOT stored here


# =============================================================================
# 4. Define Nodes
# =============================================================================


def agent_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Simulates an agent decision.

    We use `require_warrant` manually here to check permissions BEFORE
    calling tools (acting as a policy layer).
    """
    messages = state["messages"]
    last_msg = messages[-1]

    # Get secure context
    bw = require_warrant(state, config)

    if isinstance(last_msg, HumanMessage):
        content = last_msg.content.lower()

        # Simulating LLM decision
        if "delete" in content:
            # Check permission explicitly (Logic check)
            if not bw.allows("delete_database"):
                return {"messages": [HumanMessage(content="I cannot delete the database (unauthorized warrant).")]}

            return {
                "messages": [
                    AIMessage(
                        content="Deleting...", tool_calls=[{"name": "delete_database", "args": {}, "id": str(uuid4())}]
                    )
                ]
            }

        elif "search" in content:
            return {
                "messages": [
                    AIMessage(
                        content="Searching...",
                        tool_calls=[{"name": "search", "args": {"query": "something"}, "id": str(uuid4())}],
                    )
                ]
            }

        else:
            return {
                "messages": [
                    AIMessage(
                        content="Echoing...",
                        tool_calls=[{"name": "echo", "args": {"msg": content}, "id": str(uuid4())}],
                    )
                ]
            }

    return {"messages": []}


# Wrap agent node if we wanted automatic injection, but here we used require_warrant manually.
# Let's wrap it securely anyway to ensure key binding is possible.
secure_agent = guard_node(agent_node)


# =============================================================================
# 5. Build Graph
# =============================================================================

workflow = StateGraph(AgentState)

workflow.add_node("agent", secure_agent)
workflow.add_node("tools", TenuoToolNode(tools))

workflow.set_entry_point("agent")


def should_continue(state: AgentState):
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        return "tools"
    return END


workflow.add_conditional_edges("agent", should_continue)
workflow.add_edge("tools", "agent")

# Enable Checkpointing (The ultimate test of serialization safety)
checkpointer = MemorySaver()

app = workflow.compile(checkpointer=checkpointer)


# =============================================================================
# 6. Run Demo
# =============================================================================

if __name__ == "__main__":
    print("\n🚀 Starting Secure Agent...")

    # Session ID for checkpointing
    thread_id = "thread-1"
    config = {
        "configurable": {
            "thread_id": thread_id,
            "tenuo_key_id": "worker-1",  # Pass infrastructure key ID here
        }
    }

    # Initial input
    initial_state = {"messages": [HumanMessage(content="Hello world")], "warrant": root_warrant.to_base64()}

    print("\n--- TURN 1: Allowed Action (Echo) ---")
    for event in app.stream(initial_state, config=config):
        for key, value in event.items():
            if key == "agent":
                if value.get("messages"):
                    msg = value["messages"][0]
                    print(f"🤖 Agent: {msg.content}")
                else:
                    print("🤖 Agent: (No output)")
            elif key == "tools":
                if value.get("messages"):
                    print(f"🛠️  Tool Output: {value['messages'][0].content}")

    print("\n--- TURN 2: Denied Action (Delete) ---")
    # Agent should refuse because it checks allows
    # OR if it tried, TenuoToolNode would block it.

    next_input = {"messages": [HumanMessage(content="Please delete the database")]}

    for event in app.stream(next_input, config=config):
        for key, value in event.items():
            print(f"[{key}] {value}")

    print("\n✅ Demo Complete. Checkpointing worked (no PickleErrors).")
