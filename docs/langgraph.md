---
title: LangGraph Integration
description: Secure LangGraph workflows with Tenuo
---

# Tenuo LangGraph Integration

> **Status**: ✅ Implemented (v0.1)

---

## Why Tenuo for LangGraph?

**Scenario**: You're building a customer support system with tiered agents. Tier 1 agents can refund up to $50. Tier 2 agents can refund up to $500. How do you enforce this?

Without Tenuo, you'd hardcode limits in your tools or add if-statements. But when a prompt injection says "Override the limit and refund $10,000", the LLM might believe it and try.

With Tenuo, the constraint is cryptographically enforced:

```python
from langchain.agents import create_agent
from tenuo import Warrant, Range
from tenuo.langgraph import TenuoMiddleware, load_tenuo_keys

# Load keys from environment
load_tenuo_keys()

# Tier 1 agent: can only refund up to $50
tier1_warrant = (Warrant.mint_builder()
    .capability("lookup_order")
    .capability("process_refund", amount=Range(min=0, max=50))
    .holder(tier1_agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Tools
@tool
def process_refund(order_id: str, amount: float) -> str:
    return f"Refunded ${amount} for order {order_id}"

# Create agent with TenuoMiddleware
agent = create_agent(
    model="gpt-4.1",
    tools=[lookup_order, process_refund],
    middleware=[TenuoMiddleware()],  # ← All authorization handled here
)

# Run with warrant in state
result = agent.invoke({
    "messages": [HumanMessage("refund order 123 for $75")],
    "warrant": tier1_warrant,
})
```

**What happens when the LLM calls `process_refund(amount=75)`?**

```
1. LLM decides to call process_refund(order_id="123", amount=75)
         ↓
2. TenuoMiddleware.wrap_tool_call() intercepts
         ↓
3. Extracts warrant from state, binds signing key from KeyRegistry
         ↓
4. Checks: Is process_refund in warrant? Does amount=75 satisfy Range(min=0, max=50)?
         ↓
5. NO → Returns error ToolMessage. The refund never executes.
```

The warrant is the authority, not the LLM's judgment. Even if the model is tricked into calling `process_refund(amount=10000)`, the warrant says `Range(min=0, max=50)` and the call fails. Period.

---

## Quick Start (Middleware)

The recommended approach uses `TenuoMiddleware` with LangChain's `create_agent()`:

```python
from langchain.agents import create_agent
from langchain.messages import HumanMessage
from tenuo import Warrant
from tenuo.langgraph import TenuoMiddleware, load_tenuo_keys

# 1. Load keys from environment
load_tenuo_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER_1, etc.

# 2. Define tools
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

@tool
def read_file(path: str) -> str:
    """Read a file."""
    return open(path).read()

# 3. Create agent with middleware
agent = create_agent(
    model="gpt-4.1",
    tools=[search, read_file],
    middleware=[TenuoMiddleware()],
)

# 4. Create warrant and invoke
warrant, key = Warrant.quick_mint(tools=["search", "read_file"], ttl=3600)
from tenuo import KeyRegistry
KeyRegistry.get_instance().register("default", key)

result = agent.invoke({
    "messages": [HumanMessage("search for AI papers")],
    "warrant": warrant,
})
```

### Why Middleware?

| Feature | TenuoMiddleware | TenuoToolNode |
|---------|-----------------|---------------|
| **Integration** | Native LangChain middleware API | Custom node replacement |
| **Tool filtering** | ✅ Auto-hides unauthorized tools from LLM | ❌ |
| **New graphs** | ✅ Recommended | Legacy support |
| **Existing graphs** | Requires migration to `create_agent()` | ✅ Drop-in |

**Middleware benefits:**
- **Framework-agnostic pattern**: Same middleware concept as FastAPI, MCP
- **Tool filtering**: LLM only sees authorized tools (improves accuracy)
- **Cleaner code**: No custom node types, just configuration

---

## Alternative: TenuoToolNode (Legacy Graphs)

For existing LangGraph graphs that use `ToolNode`, use `TenuoToolNode` as a drop-in replacement:

```python
from tenuo.langgraph import TenuoToolNode, guard_node, load_tenuo_keys

load_tenuo_keys()

# Create secure tool node (replaces ToolNode)
tool_node = TenuoToolNode([search, read_file])

# Wrap pure nodes
def my_agent(state):
    return {"messages": [...]}

graph.add_node("agent", guard_node(my_agent))
graph.add_node("tools", tool_node)

# Run with warrant in state
state = {"warrant": str(warrant), "messages": [...]}
result = graph.invoke(state, config={"configurable": {"tenuo_key_id": "worker"}})
```

---

## Key Concepts

### Keys Stay Out of State

**The Problem**: LangGraph checkpoints state to databases (Redis, Postgres, etc.). If you put a `SigningKey` in state, your private key gets persisted—a serious security risk.

**The Solution**: Warrants travel in state (they're just signed claims, no secrets). Keys stay in `KeyRegistry` (in-memory only). Only a string `key_id` flows through config.

```python
# ✅ CORRECT: Warrant as string in state, key_id in config
state = {"warrant": str(warrant), "messages": [...]}  # str() = base64, safe for JSON
config = {"configurable": {"tenuo_key_id": "worker"}}  # Just a string ID
graph.invoke(state, config=config)

# At execution, TenuoToolNode looks up the key from KeyRegistry
# Key never leaves memory, never hits the checkpoint database

# ❌ WRONG: Key in state (gets persisted to database!)
state = {"warrant": warrant, "key": signing_key}  # 💀 Security risk!
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

### `TenuoMiddleware`

**Recommended** — Middleware for securing LangGraph agents with automatic authorization.

```python
from tenuo.langgraph import TenuoMiddleware

# Basic usage
middleware = TenuoMiddleware()

# With configuration
middleware = TenuoMiddleware(
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

### `guard_node(node, key_id=None, inject_warrant=False)`

Wrap a pure node function with Tenuo authorization.

```python
from tenuo.langgraph import guard_node

# Basic usage - key_id from config or "default"
def my_node(state):
    return {"result": "done"}

graph.add_node("my_node", guard_node(my_node))

# Explicit key_id
graph.add_node("worker", guard_node(worker_node, key_id="worker-1"))

# Inject BoundWarrant for advanced use
def node_with_warrant(state, bound_warrant):
    if bound_warrant.validate("search", {"query": "test"}):
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

### `@tenuo_node`

Decorator for nodes that need explicit BoundWarrant access:

```python
from tenuo.langgraph import tenuo_node
from tenuo import BoundWarrant

@tenuo_node
def my_agent(state, bound_warrant: BoundWarrant):
    # Check permissions
    if bound_warrant.allows("search"):
        # ...
    
    # Delegate to sub-agent
    child = bound_warrant.grant(
        to=worker_pubkey,
        allow=["search"],
        ttl=60
    )
    return {"messages": [...], "warrant": child.warrant}

graph.add_node("agent", my_agent)
```

### `TenuoToolNode`

> **Note**: For new projects, prefer `TenuoMiddleware`. `TenuoToolNode` is provided for backward compatibility with existing graphs.

Drop-in replacement for LangGraph's `ToolNode` with automatic authorization:

```python
from tenuo.langgraph import TenuoToolNode
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    return f"Results for {query}"

@tool
def calculator(expression: str) -> str:
    return str(eval(expression))

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

**How it works:**
1. Extracts warrant from state
2. Gets key from registry (via `key_id` in config or "default")
3. Authorizes each tool call via shared enforcement logic
4. Returns error ToolMessage if authorization fails

---

## Patterns

### Pattern 1: Middleware with `create_agent()` (Recommended)

The cleanest integration uses middleware:

```python
from langchain.agents import create_agent
from langchain.messages import HumanMessage
from tenuo import Warrant, Range
from tenuo.langgraph import TenuoMiddleware, load_tenuo_keys

load_tenuo_keys()

# Create agent with Tenuo middleware
agent = create_agent(
    model="gpt-4.1",
    tools=[search, read_file, write_file],
    middleware=[
        TenuoMiddleware(filter_tools=True),  # Authorization + tool filtering
        # Other middleware can go here (logging, caching, etc.)
    ],
)

# Run with different warrants for different access levels
readonly_warrant, key = Warrant.quick_mint(tools=["search", "read_file"], ttl=3600)
readwrite_warrant, _ = Warrant.quick_mint(
    tools=["search", "read_file", "write_file"],
    constraints={"path": "/tmp/*"},
    ttl=3600,
)

# Read-only user
result = agent.invoke({
    "messages": [HumanMessage("read config.yaml")],
    "warrant": readonly_warrant,
})

# Read-write user
result = agent.invoke({
    "messages": [HumanMessage("write to /tmp/output.txt")],
    "warrant": readwrite_warrant,
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

graph.add_node("researcher", guard_node(researcher, key_id="worker"))
graph.add_node("writer", guard_node(writer, key_id="worker"))
```

### Pattern 2: Nodes that Need Warrant Access

Use `inject_warrant=True` or `@tenuo_node`:

```python
from tenuo.langgraph import guard_node
from tenuo import BoundWarrant

def smart_router(state, bound_warrant: BoundWarrant):
    # Route based on available permissions
    if bound_warrant.allows("write_file"):
        return {"next": "writer"}
    elif bound_warrant.allows("search"):
        return {"next": "researcher"}
    else:
        return {"next": "fallback"}

graph.add_node("router", guard_node(smart_router, inject_warrant=True))
```

### Pattern 3: Delegation in Nodes

Attenuate warrants for sub-agents:

```python
from tenuo.langgraph import tenuo_node
from tenuo import BoundWarrant, Pattern

@tenuo_node
def orchestrator(state, bound_warrant: BoundWarrant):
    # Create narrower warrant for worker
    worker_warrant = bound_warrant.grant(
        to=worker_pubkey,
        allow=["search"],
        ttl=60,
        query=Pattern("safe*")
    )
    
    # Pass delegated warrant in state
    return {
        "messages": [...],
        "warrant": worker_warrant.warrant  # Unbind for serialization
    }
```

### Pattern 4: Multi-Tenant Key Isolation

Use namespaced keys for tenant isolation:

```python
from tenuo import KeyRegistry

registry = KeyRegistry.get_instance()

# Register tenant-specific keys
registry.register("worker", tenant_a_key, namespace="tenant-a")
registry.register("worker", tenant_b_key, namespace="tenant-b")

# In your node, determine namespace from state/context
def tenant_aware_node(state, bound_warrant):
    tenant_id = state.get("tenant_id", "default")
    key = registry.get("worker", namespace=tenant_id)
    # ...
```

---

## Error Handling

Authorization errors return `ToolMessage` with `status="error"` and canonical wire codes:

```python
# TenuoToolNode returns error messages, not exceptions
result = graph.invoke(state)

for msg in result["messages"]:
    if hasattr(msg, "status") and msg.status == "error":
        print(f"Authorization denied: {msg.content}")
        # Content includes request_id for log correlation
        # Parse wire code from content if needed for programmatic handling
```

### Wire Code Support

For direct exception handling in nodes (using `@authorize_node`), all `TenuoError` exceptions include canonical wire codes:

```python
from tenuo.exceptions import TenuoError, ConstraintViolation

@authorize_node(tool="transfer_funds")
def transfer(state: State):
    # Raises ConstraintViolation, ExpiredError, etc.
    # These include wire codes:
    pass

try:
    result = transfer(state)
except ConstraintViolation as e:
    print(f"Wire code: {e.get_wire_code()}")  # 1501
    print(f"Wire name: {e.get_wire_name()}")  # "constraint-violation"
    print(f"HTTP status: {e.get_http_status()}")  # 403
```

### Common Errors

| Error | Wire Code | Cause | Fix |
|-------|-----------|-------|-----|
| `ConfigurationError` | 1201 | Missing 'warrant' field in state | Add warrant to state: `{"warrant": str(warrant), ...}` |
| `ConfigurationError` | 1201 | Key not registered | Register key or use `load_tenuo_keys()` |
| `ToolNotAuthorized` | 1500 | Tool not in warrant | Check warrant constraints with `why_denied()` |
| `ConstraintViolation` | 1501 | Argument violates constraint | Request within bounds |
| `ExpiredError` | 1300 | TTL exceeded | Request fresh warrant |

See [wire format specification](/docs/spec/wire-format-v1#appendix-a-error-codes) for the complete list.

---

## Security Notes

### Error Messages are Opaque

By default, authorization errors don't reveal constraint details:

```python
# Client sees: "Authorization denied (ref: abc123)"
# Logs show: "[abc123] Tool 'search' denied: query=/etc/passwd, expected=Pattern(/data/*)"
```

This prevents attackers from learning your constraint boundaries.

### BoundWarrant is Never Serialized

`BoundWarrant` contains a private key and will raise `TypeError` if serialization is attempted:

```python
# ❌ This will fail
state["bound_warrant"] = bound_warrant  # TypeError on checkpoint

# ✅ Correct: unbind before storing
state["warrant"] = bound_warrant.warrant  # Just the warrant (serializable)
```

### `allows()` is Not Authorization
 
 `allows()` is for UX hints only:
 
 ```python
 # ✅ OK for UI hints
 if bound_warrant.allows("delete"):
     show_delete_button()
 
 # ❌ WRONG: Not a security check!
 if bound_warrant.allows("delete"):
     delete_database()  # No PoP verification happened!
 
 # ✅ Correct: Use validate()
 if bound_warrant.validate("delete", args):
     delete_database()
 ```
### Lazy Key Binding

`BoundWarrant.bind(key)` performs **lazy validation**. It does not verify that the key matches the warrant's `holder` at binding time.

Instead, validation happens at **usage time** (inside `validate()`). The `validate()` method generates a Proof-of-Possession signature using the bound key. If the key is incorrect, the core Rust logic will reject the signature, and `validate()` will return a failed `ValidationResult`. This ensures security without requiring stateful validation during graph transitions.

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

Add human-in-the-loop approval for sensitive tool calls. Both `TenuoMiddleware` and `TenuoToolNode` accept `approval_policy` and `approval_handler` parameters. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo.approval import ApprovalPolicy, require_approval, cli_prompt

policy = ApprovalPolicy(
    require_approval("delete_database"),
    trusted_approvers=[approver_key.public_key],
)

# Middleware pattern
middleware = TenuoMiddleware(
    approval_policy=policy,
    approval_handler=cli_prompt(approver_key=approver_key),
)

# Or TenuoToolNode pattern
tool_node = TenuoToolNode(
    tools,
    approval_policy=policy,
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

---

## See Also

- [LangChain Integration](./langchain) — Tool protection for LangChain
- [Human Approvals](./approvals) — Approval policy guide
- [FastAPI Integration](./fastapi) — Zero-boilerplate API protection
- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
