---
title: LangGraph Integration
description: Secure LangGraph workflows with Tenuo
---

# Tenuo LangGraph Integration

> **Status**: ✅ Implemented (v0.1)

---

## Quick Start

```python
from tenuo import Warrant, SigningKey, KeyRegistry
from tenuo.langgraph import secure, TenuoToolNode, auto_load_keys

# 1. Load keys from environment
auto_load_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER_1, etc.

# 2. Define tools
from langchain_core.tools import tool

@tool
def search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

# 3. Create secure tool node
tool_node = TenuoToolNode([search])

# 4. Wrap pure nodes with secure()
def my_agent(state):
    return {"messages": [...]}

graph.add_node("agent", secure(my_agent))
graph.add_node("tools", tool_node)

# 5. Run with warrant in state
state = {"warrant": warrant, "messages": [...]}
result = graph.invoke(state, config={"configurable": {"tenuo_key_id": "worker"}})
```

---

## Key Concepts

### Keys Stay Out of State

**The fundamental principle**: Warrants travel in state, keys stay in the registry.

```python
# ✅ CORRECT: Warrant in state, key_id in config
state = {"warrant": warrant, "messages": [...]}
config = {"configurable": {"tenuo_key_id": "worker"}}
graph.invoke(state, config=config)

# ❌ WRONG: Key in state (security risk, serialization fails)
state = {"warrant": warrant, "key": signing_key}  # Never do this!
```

### Convention Over Configuration

Load keys automatically from environment variables:

```python
from tenuo.langgraph import auto_load_keys

# Before app startup, set env vars:
# TENUO_KEY_DEFAULT=base64encodedkey...
# TENUO_KEY_WORKER_1=base64encodedkey...
# TENUO_KEY_ORCHESTRATOR=base64encodedkey...

auto_load_keys()  # Registers all TENUO_KEY_* vars

# Keys are now available:
# - "default" (from TENUO_KEY_DEFAULT)
# - "worker-1" (from TENUO_KEY_WORKER_1)
# - "orchestrator" (from TENUO_KEY_ORCHESTRATOR)
```

---

## API Reference

### `auto_load_keys()`

Load signing keys from environment variables matching `TENUO_KEY_*`.

```python
from tenuo.langgraph import auto_load_keys

# Naming convention: TENUO_KEY_{NAME} -> key_id="{name}" (lowercase, underscores to hyphens)
# TENUO_KEY_WORKER_1 -> "worker-1"
# TENUO_KEY_DEFAULT -> "default"

auto_load_keys()
```

### `KeyRegistry`

Thread-safe singleton for key management:

```python
from tenuo import KeyRegistry, SigningKey

registry = KeyRegistry.get_instance()

# Register keys manually
registry.register("worker", SigningKey.generate())
registry.register("orchestrator", SigningKey.from_env("ORCH_KEY"))

# Retrieve
key = registry.get("worker")

# Namespaced (multi-tenant)
registry.register("worker", key1, namespace="tenant-a")
registry.register("worker", key2, namespace="tenant-b")
```

### `secure(node, key_id=None, inject_warrant=False)`

Wrap a pure node function with Tenuo authorization.

```python
from tenuo.langgraph import secure

# Basic usage - key_id from config or "default"
def my_node(state):
    return {"result": "done"}

graph.add_node("my_node", secure(my_node))

# Explicit key_id
graph.add_node("worker", secure(worker_node, key_id="worker-1"))

# Inject BoundWarrant for advanced use
def node_with_warrant(state, bound_warrant):
    if bound_warrant.authorize("search", {"query": "test"}):
        return {"authorized": True}
    return {"authorized": False}

graph.add_node("checker", secure(node_with_warrant, inject_warrant=True))
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
    if bound_warrant.preview_can("search"):
        # ...
    
    # Delegate to sub-agent
    child = bound_warrant.delegate(
        to=worker_pubkey,
        allow=["search"],
        ttl=60
    )
    return {"messages": [...], "warrant": child.warrant}

graph.add_node("agent", my_agent)
```

### `TenuoToolNode`

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

graph.add_node("tools", tool_node)
```

**How it works:**
1. Extracts warrant from state
2. Gets key from registry (via `key_id` in config or "default")
3. Wraps each tool with authorization check
4. Returns error ToolMessage if authorization fails

---

## Patterns

### Pattern 1: Pure Nodes with `secure()`

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
from tenuo.langgraph import secure

graph.add_node("researcher", secure(researcher, key_id="worker"))
graph.add_node("writer", secure(writer, key_id="worker"))
```

### Pattern 2: Nodes that Need Warrant Access

Use `inject_warrant=True` or `@tenuo_node`:

```python
from tenuo.langgraph import secure
from tenuo import BoundWarrant

def smart_router(state, bound_warrant: BoundWarrant):
    # Route based on available permissions
    if bound_warrant.preview_can("write_file"):
        return {"next": "writer"}
    elif bound_warrant.preview_can("search"):
        return {"next": "researcher"}
    else:
        return {"next": "fallback"}

graph.add_node("router", secure(smart_router, inject_warrant=True))
```

### Pattern 3: Delegation in Nodes

Attenuate warrants for sub-agents:

```python
from tenuo.langgraph import tenuo_node
from tenuo import BoundWarrant, Pattern

@tenuo_node
def orchestrator(state, bound_warrant: BoundWarrant):
    # Create narrower warrant for worker
    worker_warrant = bound_warrant.delegate(
        to=worker_pubkey,
        allow={"search": {"query": Pattern("safe*")}},
        ttl=60
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

Authorization errors return `ToolMessage` with `status="error"`:

```python
# TenuoToolNode returns error messages, not exceptions
result = graph.invoke(state)

for msg in result["messages"]:
    if hasattr(msg, "status") and msg.status == "error":
        print(f"Authorization denied: {msg.content}")
        # Content includes request_id for log correlation
```

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `State is missing 'warrant' field` | No warrant in state | Add warrant to state: `{"warrant": warrant, ...}` |
| `Key 'worker' not found` | Key not registered | Register key or use `auto_load_keys()` |
| `Authorization denied` | Warrant doesn't allow action | Check warrant constraints with `why_denied()` |

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

### preview_can() is Not Authorization

`preview_can()` and `preview_would_allow()` are for UX hints only:

```python
# ✅ OK for UI hints
if bound_warrant.preview_can("delete"):
    show_delete_button()

# ❌ WRONG: Not a security check!
if bound_warrant.preview_can("delete"):
    delete_database()  # No PoP verification happened!

# ✅ Correct: Use authorize() for security decisions
if bound_warrant.authorize("delete", {"target": "users"}):
    delete_database()
```

---

## Migration from Context-Based API

If you were using `@tenuo_node(Capability(...))` with `root_task()`:

```python
# OLD (context-based)
@tenuo_node(Capability("search"))
async def researcher(state):
    ...

async with root_task(Capability("search")):
    await graph.ainvoke(state)

# NEW (state-based)
from tenuo.langgraph import secure

def researcher(state):
    ...

graph.add_node("researcher", secure(researcher))
graph.invoke({"warrant": warrant, "messages": [...]})
```

---

## See Also

- [LangChain Integration](./langchain) — Tool protection for LangChain
- [FastAPI Integration](./fastapi) — Zero-boilerplate API protection
- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
