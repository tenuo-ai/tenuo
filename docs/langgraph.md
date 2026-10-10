---
title: LangGraph Integration
description: Secure LangGraph workflows with Tenuo
---

# Tenuo LangGraph Integration

Tenuo stops LangChain agents from doing more than the task requires. A warrant defines which tools the agent may call, the allowed argument values (paths, URLs, shell commands, amounts), and when it expires. Tenuo checks every call before the tool runs and blocks anything outside the warrant, even when the model has been prompt-injected. Warrants are bound to the agent holding them, so a copied warrant can't be used, and authority can only shrink as it passes to sub-agents. With signed receipt collection enabled, each decision over a presented warrant produces verifiable evidence.

See [tenuo.ai](https://tenuo.ai) for the full docs, or the source on [GitHub](https://github.com/tenuo-ai/tenuo).

---

## Why Tenuo for LangGraph?

**Scenario**: You're building a customer support system with tiered agents. Tier 1 agents can refund up to $50. Tier 2 agents can refund up to $500. How do you enforce this?

Without Tenuo, you'd hardcode limits in your tools or add if-statements. But when a prompt injection says "Override the limit and refund $10,000", the LLM might believe it and try.

With Tenuo, the constraint is cryptographically enforced:

```python
from typing import Annotated, Any, TypedDict

from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.message import add_messages
from tenuo import KeyRegistry, Pattern, SigningKey, Warrant, Range
from tenuo.langgraph import TenuoToolNode

# Keys: control plane issues warrants, agents hold them
control_plane_key = SigningKey.generate()
tier1_agent_key = SigningKey.generate()
KeyRegistry.get_instance().register("default", tier1_agent_key)  # never in state

# Tier 1 agent: can only refund up to $50
tier1_warrant = (Warrant.mint_builder()
    .capability("lookup_order")
    .capability("process_refund", order_id=Pattern("*"), amount=Range(min=0, max=50))
    .holder(tier1_agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Tools
@tool
def lookup_order(order_id: str) -> str:
    """Look up an order by ID."""
    return f"Order {order_id}: $120 widget"

@tool
def process_refund(order_id: str, amount: float) -> str:
    """Process a refund for an order."""
    return f"Refunded ${amount} for order {order_id}"

class State(TypedDict):
    messages: Annotated[list, add_messages]
    warrant: Any  # MessagesState has no warrant field, so declare one

# Build graph with TenuoToolNode (drop-in replacement for ToolNode)
graph_builder = StateGraph(State)
# ... add your agent node here ...
graph_builder.add_node("tools", TenuoToolNode(
    [lookup_order, process_refund],
    trusted_roots=[control_plane_key.public_key],  # only the root
))
graph = graph_builder.compile()

# Run with warrant in state
result = graph.invoke({
    "messages": [HumanMessage("refund order 123 for $75")],
    "warrant": str(tier1_warrant),
})
```

**What happens when the LLM calls `process_refund(amount=75)`?**

```
1. LLM decides to call process_refund(order_id="123", amount=75)
         ↓
2. TenuoToolNode intercepts the tool call
         ↓
3. Extracts warrant from state, binds signing key from KeyRegistry
         ↓
4. Checks: Does the warrant chain to a trusted root? Is process_refund in it?
   Does amount=75 satisfy Range(min=0, max=50)?
         ↓
5. NO → Returns error ToolMessage. The refund never executes.
```

The warrant is the authority, not the LLM's judgment. Even if the model is tricked into calling `process_refund(amount=10000)`, the warrant says `Range(min=0, max=50)` and the call fails. Period.

---

## Quick Start

For a LangGraph `StateGraph`, use `TenuoToolNode` as a drop-in replacement for `ToolNode`. For LangChain 1.x `create_agent()`, use `TenuoMiddleware` below.

```python
from typing import Annotated, Any, TypedDict

from langgraph.graph import StateGraph
from langgraph.graph.message import add_messages
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from tenuo import KeyRegistry, Pattern, SigningKey, Subpath, Warrant
from tenuo.langgraph import TenuoToolNode

# 1. Keys: the issuer is the trusted root; the agent key signs PoP.
#    In production, load agent keys with load_tenuo_keys() (TENUO_KEY_*).
issuer = SigningKey.generate()
agent_key = SigningKey.generate()
KeyRegistry.get_instance().register("default", agent_key)

# 2. Define tools
@tool
def search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

@tool
def read_file(path: str) -> str:
    """Read a file."""
    return open(path).read()

# 3. Build graph with TenuoToolNode (replaces ToolNode).
#    The state must declare a `warrant` field.
class State(TypedDict):
    messages: Annotated[list, add_messages]
    warrant: Any

graph_builder = StateGraph(State)
# ... add your agent node here ...
graph_builder.add_node("tools", TenuoToolNode([search, read_file], trusted_roots=[issuer.public_key]))
graph = graph_builder.compile()

# 4. Mint a warrant and invoke
warrant = (Warrant.mint_builder()
    .capability("search", query=Pattern("*"))
    .capability("read_file", path=Subpath("/data"))
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(issuer))

result = graph.invoke({
    "messages": [HumanMessage("search for AI papers")],
    "warrant": str(warrant),
})
```

> **Declare `warrant` in your state.** LangGraph drops input keys that are not in the state schema, and `MessagesState` has no `warrant` field. With `StateGraph(MessagesState)`, every tool call comes back as `Security configuration error (ref: ...)` and the log says `State is missing 'warrant' field`.

> **Trusted roots are required.** Pass `trusted_roots=[...]` (root issuer keys only) or call `tenuo.configure(trusted_roots=[...])` at startup. Without either, every call is denied.

### TenuoToolNode vs TenuoMiddleware

| Feature | TenuoToolNode | TenuoMiddleware |
|---------|---------------|-----------------|
| **Use when** | Existing `StateGraph` / `ToolNode` | LangChain 1.x `create_agent()` |
| **Status** | Stable | Stable |
| **Integration** | Drop-in replacement for `ToolNode` | Native LangChain middleware API |
| **Tool filtering** | No | Auto-hides unauthorized tools from LLM |
| **Requires** | langgraph | `langchain>=1.0` |

Both use the same `enforce_tool_call` path.

---

## TenuoMiddleware (LangChain 1.x `create_agent()`)

> Recommended for `create_agent()`. Requires `langchain>=1.0`. For a custom `StateGraph`, use `TenuoToolNode`.

A runnable example is [`create_agent_middleware.py`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/langchain/create_agent_middleware.py).

```python
from typing import Any

from langchain.agents import create_agent
from langchain.agents.middleware import AgentState
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from tenuo import HolderIdentity, Pattern, Runtime, SigningKey, Warrant
from tenuo.keys import KeyRegistry
from tenuo.langgraph import TenuoMiddleware


@tool
def search(query: str) -> str:
    """Search customer records. Use the query format ``customers:<term>``."""
    return f"3 records match {query!r}"


@tool
def delete_record(record_id: str) -> str:
    """Delete a customer record."""
    return f"record {record_id} deleted"


class TenuoAgentState(AgentState):
    warrant: Any  # TenuoMiddleware reads the warrant from agent state


issuer_key = SigningKey.generate()  # issues warrants
holder = HolderIdentity.generate()  # the agent's key, used for proof of possession
KeyRegistry.get_instance().register("support-agent", holder.signing_key)

# Collect signed receipts for authorization decisions made over the warrant.
runtime = Runtime(
    identity=holder,
    trusted_roots=[issuer_key.public_key],
    receipts="collect",
)

agent = create_agent(
    model="openai:gpt-4.1",
    tools=[search, delete_record],
    state_schema=TenuoAgentState,
    middleware=[
        TenuoMiddleware(
            key_id="support-agent",
            trusted_roots=[issuer_key.public_key],  # only accept warrants from this issuer
        )
    ],
)

# search is allowed only for customer queries; delete_record is not granted
warrant = (
    Warrant.mint_builder()
    .holder(holder.public_key)
    .capability("search", query=Pattern("customers:*"))
    .ttl(3600)
    .mint(issuer_key)
)

with runtime.bind():
    result = agent.invoke({
        "messages": [HumanMessage("Search customer records for customers:acme")],
        "warrant": str(warrant),  # base64 token; safe to checkpoint
    })

signed_receipts = runtime.peek_receipts()
```

Calls outside the warrant (an ungranted tool, or `search` with a query that does not match `customers:*`) come back to the model as an error `ToolMessage`, and the tool body never runs. The linked example is the deterministic run: it allows `search("customers:acme")`, denies `delete_record`, and verifies the signed allow and deny receipts. This snippet calls a live model, which may choose a different tool call, so `signed_receipts` can be empty.

---

## Key Concepts

### Keys Stay Out of State

**The Problem**: LangGraph checkpoints state to databases (Redis, Postgres, etc.). If you put a `SigningKey` in state, your private key gets persisted --a serious security risk.

**The Solution**: Warrants travel in state (they're just signed claims, no secrets). Keys stay in `KeyRegistry` (in-memory only). Only a string `key_id` flows through config.

```python
# CORRECT: Warrant as string in state, key_id in config
state = {"warrant": str(warrant), "messages": [...]}  # str() = base64, safe for JSON
config = {"configurable": {"tenuo_key_id": "worker"}}  # Just a string ID
graph.invoke(state, config=config)

# At execution, TenuoToolNode looks up the key from KeyRegistry
# Key never leaves memory, never hits the checkpoint database

# WRONG: Key in state (gets persisted to database!)
state = {"warrant": warrant, "key": signing_key}  # Security risk!
```

### Convention Over Configuration

Load keys automatically from environment variables:

```python
from tenuo.langgraph import load_tenuo_keys

# Before app startup, set env vars:
# TENUO_KEY_DEFAULT=base64encodedkey...
# TENUO_KEY_WORKER_1=base64encodedkey...
# TENUO_KEY_ORCHESTRATOR=base64encodedkey...

load_tenuo_keys()  # Registers all TENUO_KEY_* vars

# Keys are now available:
# - "default" (from TENUO_KEY_DEFAULT)
# - "worker-1" (from TENUO_KEY_WORKER_1)
# - "orchestrator" (from TENUO_KEY_ORCHESTRATOR)
```

---

## API Reference

### `TenuoToolNode`

**Recommended**: drop-in replacement for LangGraph's `ToolNode` with automatic authorization:

```python
from tenuo.langgraph import TenuoToolNode
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    return f"Results for {query}"

@tool
def calculator(expression: str) -> str:
    # Use a sandboxed arithmetic parser (e.g. `simpleeval`) in real code.
    # Never pass LLM-provided strings to eval() / exec() / compile().
    from simpleeval import simple_eval
    return str(simple_eval(expression))

# Create secure tool node
tool_node = TenuoToolNode([search, calculator])

# With constraint requirement
tool_node = TenuoToolNode([search, calculator], require_constraints=True)

graph.add_node("tools", tool_node)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tools` | `List[BaseTool]` | required | Tools to make available |
| `require_constraints` | `bool` | `False` | Require constraints for sensitive tools |
| `trusted_roots` | `List[PublicKey]` | `None` | Root issuer keys to anchor verification on (falls back to `tenuo.configure`) |
| `warrant_chain` | `List[Warrant]` | `None` | Default parents for graphs without a `warrant_chain` state field |
| `key_id` | `str` | `None` | Signing key to use, overriding the config value |
| `approval_handler` | callable | `None` | Called when an approval gate fires (see [Human Approval](#human-approval)) |
| `approvals` | `List[SignedApproval]` | `None` | Pre-collected approvals |
| `control_plane` | `ControlPlaneClient` | `None` | Where to send authorization events |

**How it works:**
1. Extracts warrant from state (a single warrant, or a WarrantStack token / root-first list), plus any parents in `warrant_chain`
2. Gets key from registry (via `key_id` in config or "default")
3. Authorizes each tool call via shared enforcement logic
4. Returns error ToolMessage if authorization fails

### `TenuoMiddleware`

Recommended for LangChain 1.x `create_agent()`. Requires `langchain>=1.0`.

```python
from tenuo.langgraph import TenuoMiddleware

# Basic usage (roots from tenuo.configure(trusted_roots=[...]))
middleware = TenuoMiddleware()

# With configuration
middleware = TenuoMiddleware(
    trusted_roots=[issuer_key.public_key],
    key_id="worker",      # Explicit key (default: from config or "default")
    filter_tools=True,    # Hide unauthorized tools from LLM (default: True)
    require_constraints=False,  # Require constraints for sensitive tools
)

# Use with create_agent()
from langchain.agents import create_agent

agent = create_agent(
    model="gpt-4.1",
    tools=[search, calculator],
    middleware=[middleware],
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key_id` | `str` | `None` | Key ID to use (overrides config) |
| `filter_tools` | `bool` | `True` | Filter tools shown to LLM based on warrant |
| `require_constraints` | `bool` | `False` | Require constraints for sensitive tools |
| `trusted_roots` | `List[PublicKey]` | `None` | Root issuer keys (falls back to `tenuo.configure`) |
| `warrant_chain` | `List[Warrant]` | `None` | Default parents when state has no `warrant_chain` |
| `approval_handler` | callable | `None` | Called when an approval gate fires |
| `approvals` | `List[SignedApproval]` | `None` | Pre-collected approvals |
| `debug` | `bool` | `False` | Verbose logging |

**Hooks:**

| Hook | Purpose |
|------|---------|
| `wrap_model_call` | Filters tools to only those in warrant |
| `wrap_tool_call` | Authorizes each tool call with PoP |

### `load_tenuo_keys()`

Load signing keys from environment variables matching `TENUO_KEY_*`.

```python
from tenuo.langgraph import load_tenuo_keys

# Naming convention: TENUO_KEY_{NAME} -> key_id="{name}" (lowercase, underscores to hyphens)
# TENUO_KEY_WORKER_1 -> "worker-1"
# TENUO_KEY_DEFAULT -> "default"

load_tenuo_keys()
```

### `KeyRegistry`

Thread-safe in-memory singleton for key management. **Essential for LangGraph** because it keeps private keys out of checkpointed state.

```python
from tenuo import KeyRegistry, SigningKey

registry = KeyRegistry.get_instance()

# At startup: register keys (keys live in memory only)
registry.register("worker", SigningKey.from_env("WORKER_KEY"))
registry.register("orchestrator", SigningKey.from_env("ORCH_KEY"))

# At execution: lookup by ID (the ID is just a string, safe anywhere)
key = registry.get("worker")

# Multi-tenant: namespace keys per tenant
registry.register("worker", key1, namespace="tenant-a")
registry.register("worker", key2, namespace="tenant-b")
```

> See [API Reference](./api-reference#keyregistry) for full method documentation.

### `guard_node(node, key_id=None, inject_warrant=False, required_tools=None, trusted_roots=None)`

Wrap a pure node function with a warrant check. By default it only checks that state carries a warrant and that a key is registered for it; it does **not** authorize anything the node does. Per-call authorization happens in `TenuoToolNode` / `TenuoMiddleware`. Pass `required_tools=[...]` to fail fast when the warrant does not grant those tools.

```python
from tenuo.langgraph import guard_node

# Basic usage - key_id from config or "default"
def my_node(state):
    return {"result": "done"}

graph.add_node("my_node", guard_node(my_node))

# Explicit key_id
graph.add_node("worker", guard_node(worker_node, key_id="worker-1"))

# Inject BoundWarrant for advanced use. The injected warrant carries the roots
# from tenuo.configure(trusted_roots=[...]); validate() fails closed without one.
def node_with_warrant(state, bound_warrant):
    if bound_warrant.validate("search", {"query": "test"},
                              warrant_chain=state.get("warrant_chain")):
        return {"authorized": True}
    return {"authorized": False}

graph.add_node("checker", guard_node(node_with_warrant, inject_warrant=True))
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `node` | `Callable` | The node function to wrap |
| `key_id` | `str` | Key ID to use (default: from config or "default") |
| `inject_warrant` | `bool` | If True, inject `bound_warrant` parameter |
| `required_tools` | `List[str]` | Tools the warrant must grant, verified against the trusted roots before the node runs; raises `ConfigurationError` otherwise |
| `trusted_roots` | `List[PublicKey]` | Roots for the `required_tools` check |

### `@tenuo_node`

Decorator for nodes that need explicit BoundWarrant access:

```python
from tenuo.langgraph import tenuo_node

@tenuo_node
def my_agent(state, bound_warrant):
    # Check permissions
    if bound_warrant.allows("search"):
        # ...
        pass

    # Delegate to sub-agent, and carry the chain (see Pattern 4)
    child = bound_warrant.grant(
        to=worker_pubkey,
        allow=["search"],
        ttl=60
    )
    return {
        "messages": [...],
        "warrant": str(child),
        "warrant_chain": [*state.get("warrant_chain", []), bound_warrant.warrant],
    }

graph.add_node("agent", my_agent)
```

---

## Patterns

### Pattern 1: TenuoToolNode (Recommended)

The cleanest integration for any LangGraph graph:

```python
from typing import Annotated, Any, TypedDict

from langgraph.graph import StateGraph
from langgraph.graph.message import add_messages
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from tenuo import KeyRegistry, SigningKey, Subpath, Pattern, Warrant
from tenuo.langgraph import TenuoToolNode

issuer = SigningKey.generate()
agent_key = SigningKey.generate()
KeyRegistry.get_instance().register("default", agent_key)

class State(TypedDict):
    messages: Annotated[list, add_messages]
    warrant: Any

@tool
def search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

@tool
def read_file(path: str) -> str:
    """Read a file."""
    return open(path).read()

@tool
def write_file(path: str, content: str) -> str:
    """Write a file."""
    open(path, "w").write(content)
    return f"Wrote {path}"

# Build graph with TenuoToolNode
graph_builder = StateGraph(State)
# ... add your agent node here ...
graph_builder.add_node("tools", TenuoToolNode(
    [search, read_file, write_file],
    trusted_roots=[issuer.public_key],
))
graph = graph_builder.compile()

# Run with different warrants for different access levels
readonly_warrant = (Warrant.mint_builder()
    .capability("search", query=Pattern("*"))
    .capability("read_file", path=Subpath("/data"))
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(issuer))

readwrite_warrant = (Warrant.mint_builder()
    .capability("search", query=Pattern("*"))
    .capability("read_file", path=Subpath("/data"))
    .capability("write_file", path=Subpath("/tmp"), content=Pattern("*"))
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(issuer))

# Read-only user
result = graph.invoke({
    "messages": [HumanMessage("read config.yaml")],
    "warrant": str(readonly_warrant),
})

# Read-write user
result = graph.invoke({
    "messages": [HumanMessage("write to /tmp/output.txt")],
    "warrant": str(readwrite_warrant),
})
```

### Pattern 2: Pure Nodes with `guard_node()`

Keep your node functions pure (no Tenuo imports):

```python
# nodes.py - Pure business logic
def researcher(state):
    query = state["messages"][-1].content
    results = web_search(query)
    return {"results": results}

def writer(state):
    content = generate_content(state["results"])
    return {"output": content}

# graph.py - Wire up with security
from tenuo.langgraph import guard_node

graph.add_node("researcher", guard_node(researcher, key_id="worker", required_tools=["web_search"]))
graph.add_node("writer", guard_node(writer, key_id="worker"))
```

`guard_node` refuses to run the node when state has no warrant or no key is registered, and, with `required_tools`, when the warrant does not grant those tools. Calls the node makes itself (like `web_search` above) are **not** authorized by `guard_node`; route tool calls through `TenuoToolNode` to enforce arguments.

### Pattern 3: Nodes that Need Warrant Access

Use `inject_warrant=True` or `@tenuo_node`:

```python
from tenuo.langgraph import guard_node

def smart_router(state, bound_warrant):
    # Route based on available permissions
    if bound_warrant.allows("write_file"):
        return {"next": "writer"}
    elif bound_warrant.allows("search"):
        return {"next": "researcher"}
    else:
        return {"next": "fallback"}

graph.add_node("router", guard_node(smart_router, inject_warrant=True))
```

### Pattern 4: Delegation

A delegated warrant is signed by the agent that delegated it, not by a trusted
root. Presented on its own it is denied with **`Root warrant issuer is not
trusted`**, because the only warrant the verifier sees was issued by a key it
has no reason to trust. The sub-agent must also present the path back to a
trusted root.

Carry that path in a `warrant_chain` state field, root-first and **excluding**
the leaf in `warrant`:

```python
from typing import Annotated, Any, TypedDict
from langgraph.graph.message import add_messages

class State(TypedDict):
    messages: Annotated[list, add_messages]
    warrant: Any        # the agent's own (possibly delegated) warrant
    warrant_chain: list # its parents, root-first, excluding `warrant`
```

Each delegating node appends its own warrant to the chain it received:

```python
from tenuo import Pattern
from tenuo.langgraph import tenuo_node

@tenuo_node
def orchestrator(state, bound_warrant):
    worker_warrant = bound_warrant.grant(
        to=worker_pubkey,
        allow=["search"],
        ttl=60,
        query=Pattern("safe*"),
    )
    return {
        "messages": [...],
        "warrant": worker_warrant,
        "warrant_chain": [*state.get("warrant_chain", []), bound_warrant.warrant],
    }
```

`TenuoToolNode` and `TenuoMiddleware` read the field automatically and verify
the full chain. Entries may be `Warrant` objects or base64 tokens.

Alternatively, put the whole chain in `warrant` itself, as a WarrantStack token
(`encode_warrant_stack([root, ..., leaf])`) or a root-first list ending in the
leaf. Use one form or the other: a stack in `warrant` together with a
`warrant_chain` is rejected as a configuration error. A chain that
does not hash-link to the leaf, or that does not root in one of
`trusted_roots`, is denied: supplying a chain cannot widen authority, only
prove it.

You only get away without a chain when the delegating agent is itself a trusted
root, which stops being true as soon as a third level appears.

#### Supplying the chain outside state

When a graph cannot thread the field through state, set a default once at
construction:

```python
researcher_tools = TenuoToolNode([search_tool], warrant_chain=[root_warrant])
```

Or wrap the invocation in a chain scope:

```python
from tenuo import SigningKey, Warrant, chain_scope, warrant_scope, key_scope

issuer = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()

root = (Warrant.mint_builder()
    .capability("search").capability("read_file")
    .holder(orchestrator.public_key).ttl(3600).mint(issuer))

child = (root.grant_builder()
    .capability("search")
    .holder(worker.public_key).ttl(1800).grant(orchestrator))

with chain_scope([root]):
    with warrant_scope(child):
        with key_scope(worker):
            # Tool calls here use check_chain for full chain verification
            pass
```

The state field takes precedence over the constructor default, which takes
precedence over `chain_scope()`.

### Pattern 5: Multi-Tenant Key Isolation

Use namespaced keys for tenant isolation:

```python
from tenuo import KeyRegistry

registry = KeyRegistry.get_instance()

# Register tenant-specific keys
registry.register("worker", tenant_a_key, namespace="tenant-a")
registry.register("worker", tenant_b_key, namespace="tenant-b")

# In your node, determine namespace from state/context
def tenant_aware_node(state):
    tenant_id = state.get("tenant_id", "default")
    key = registry.get("worker", namespace=tenant_id)
    # ...
```

`TenuoToolNode`, `TenuoMiddleware` and `guard_node` look keys up by `key_id` only and do not apply a namespace. Namespaced keys are reachable only from your own code, as above; to give each tenant its own key in a tool node, register it under a distinct `key_id` and pass that ID in config.

---

## Error Handling

`TenuoToolNode` and `TenuoMiddleware` do not raise on a denial. The tool body does not run, and the model gets a `ToolMessage` with `status="error"` and an opaque message carrying a reference ID. The reason is logged under the same ID:

```python
result = graph.invoke(state)

for msg in result["messages"]:
    if getattr(msg, "status", None) == "error":
        print(msg.content)  # "Authorization denied (ref: c5d12bc0-...)"
```

| `ToolMessage` content | Logged reason (same ref) | Fix |
|-----------------------|--------------------------|-----|
| `Security configuration error (ref: ...)` | `State is missing 'warrant' field` | Declare `warrant` in the state schema and pass it in (see [Quick Start](#quick-start)) |
| `Security configuration error (ref: ...)` | `Key '<id>' not found in KeyRegistry` | Register the key or use `load_tenuo_keys()` |
| `Security configuration error (ref: ...)` | `State has both a multi-warrant stack in 'warrant' and an explicit 'warrant_chain'` | Send the chain one way only |
| `Authorization denied (ref: ...)` | `enforce_tool_call requires trusted_roots ...` | Pass `trusted_roots=[...]` or call `tenuo.configure(trusted_roots=[...])` |
| `Authorization denied (ref: ...)` | `Root warrant issuer is not trusted` | Delegated warrant sent without its parents: add `warrant_chain` (see [Pattern 4](#pattern-4-delegation)) |
| `Authorization denied (ref: ...)` | `chain broken: child parent_hash mismatch` | Present the real parents, root-first, excluding the leaf |
| `Authorization denied (ref: ...)` | `Constraint '<field>' not satisfied: ...` | Request within bounds, or check the warrant with `why_denied()` |
| `Authorization denied (ref: ...)` | tool not in warrant | Grant the tool, or let `TenuoMiddleware(filter_tools=True)` hide it |

`guard_node` is the exception: it raises `ConfigurationError` before the node runs.

---

## Observe Mode

To learn what a graph needs before enforcing it, run in observe mode:

```python
from tenuo import configure

configure(trusted_roots=[issuer.public_key], mode="observe")
# or TENUO_MODE=observe via tenuo.auto_configure(); "audit" and "permissive" are aliases
```

`TenuoToolNode` and `TenuoMiddleware` still run every check. A call that would be denied runs anyway, and the process logs `OBSERVE: would deny <tool>: <reason>` at warning level. Observe mode lets every would-deny through, including chain and signature failures, so use it only while discovering policy. Configuration errors (no `warrant` in state, no key) still return an error `ToolMessage`.

---

## Security Notes

### Error Messages are Opaque

By default, authorization errors don't reveal constraint details:

```python
# Model sees: "Authorization denied (ref: c5d12bc0-...)"
# Logs show:  "[c5d12bc0-...] Tool 'process_refund' denied: Constraint 'amount' not satisfied: ..."
```

This prevents attackers from learning your constraint boundaries.

### BoundWarrant is Never Serialized

`BoundWarrant` contains a private key and will raise `TypeError` if serialization is attempted:

```python
# This will fail
state["bound_warrant"] = bound_warrant  # TypeError on checkpoint

# Correct: unbind before storing
state["warrant"] = bound_warrant.warrant  # Just the warrant (serializable)
```

### `allows()` is Not Authorization
 
 `allows()` is for UX hints only:
 
 ```python
 # OK for UI hints
 if bound_warrant.allows("delete"):
     show_delete_button()
 
 # WRONG: Not a security check!
 if bound_warrant.allows("delete"):
     delete_database()  # No PoP verification, no issuer check!
 
 # Correct: validate() checks issuer trust, PoP, and constraints
 if bound_warrant.validate("delete", args,
                           warrant_chain=state.get("warrant_chain")):
     delete_database()
 ```
### Lazy Key Binding

`BoundWarrant.bind(key)` performs **lazy validation**. It does not verify that the key matches the warrant's `holder` at binding time.

Instead, validation happens at **usage time** (inside `validate()`). The `validate()` method generates a Proof-of-Possession signature using the bound key. If the key is incorrect, the core Rust logic will reject the signature, and `validate()` will return a failed `ValidationResult`. This ensures security without requiring stateful validation during graph transitions.

`validate()` also checks that the warrant's issuer chains back to a trusted root, so it needs an anchor: the `trusted_roots` argument, the roots given at bind time, `tenuo.configure(trusted_roots=[...])`, or the active `Runtime`. With none of those it raises `ConfigurationError` rather than trusting the warrant's own issuer. Warrants injected by `guard_node` and `@tenuo_node` inherit the configured roots.

---

## Migration from Context-Based API

If you were using `@tenuo_node(Capability(...))` with `mint()`:

```python
# OLD (context-based)
@tenuo_node(Capability("search"))
async def researcher(state):
    ...

async with mint(Capability("search")):
    await graph.ainvoke(state)

# NEW (state-based)
from tenuo.langgraph import guard_node

def researcher(state):
    ...

graph.add_node("researcher", guard_node(researcher))
graph.invoke({"warrant": str(warrant), "messages": [...]})
```

---

## Human Approval

Add human-in-the-loop approval for sensitive tool calls. Approval gates are defined in the warrant, and `approval_handler` is passed to the adapter. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo import cli_prompt

# Approval gates are in the warrant:
#   .approval_gates({"delete_database": None})
#   .required_approvers([approver_key.public_key])

# TenuoToolNode (StateGraph)
tool_node = TenuoToolNode(
    tools,
    approval_handler=cli_prompt(approver_key=approver_key),
)

# TenuoMiddleware (create_agent)
middleware = TenuoMiddleware(
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

---

## See Also

- [LangChain Integration](./langchain)  -- Tool protection for LangChain
- [Human Approvals](./approvals)  -- Approval gates and handlers guide
- [FastAPI Integration](./fastapi)  -- Zero-boilerplate API protection
- [Security](./security)  -- Threat model, best practices
- [API Reference](./api-reference)  -- Full Python API documentation
