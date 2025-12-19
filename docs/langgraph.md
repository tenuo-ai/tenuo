---
title: LangGraph Integration
description: Node scoping for LangGraph workflows
---

# Tenuo LangGraph Integration

> **Status**: ✅ Implemented (v0.1)  
> **Future**: SecureGraph (v0.2)

---

## Quick Start

```python
from langgraph.graph import StateGraph
from tenuo import configure, SigningKey, lockdown, root_task, Capability
from tenuo.langgraph import tenuo_node

# Setup
kp = SigningKey.generate()
configure(issuer_key=kp)

# 1. Protect your tools (ENFORCEMENT layer)
@lockdown(tool="search")
async def search(query: str) -> list:
    return [f"Result for {query}"]

# 2. Scope your nodes (SCOPING layer)
@tenuo_node(Capability("search"))
async def researcher(state):
    return {"results": await search(state["query"])}

# 3. Build and run with root authority
graph = StateGraph(dict)
graph.add_node("researcher", researcher)
graph.set_entry_point("researcher")
graph.set_finish_point("researcher")

async with root_task(Capability("search")):
    result = await graph.compile().ainvoke({"query": "test"})
```

---

## Problem

In multi-agent systems, manually managing warrant attenuation is error-prone:

```python
# Without Tenuo: Manual attenuation at every delegation
researcher_warrant = root_warrant.attenuate() \
    .with_capability("search", {"file_path": Pattern("/tmp/research/*")}) \
    .build(researcher_keypair, root_keypair)

with set_warrant_context(researcher_warrant):
    researcher_node(state)
```

This becomes unmanageable as graphs grow.

---

## Solution: Two-Layer Security Model

Tenuo uses a **two-layer model** for LangGraph security:

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: SCOPING (@tenuo_node)                             │
│  - Narrows what tools/constraints are ALLOWED               │
│  - Creates attenuated warrant for node's duration           │
│  - Does NOT enforce - just narrows scope                    │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: ENFORCEMENT (@lockdown / protect_tools)           │
│  - Checks warrant against actual tool invocation            │
│  - Raises AuthorizationError if tool/constraints don't match│
│  - The actual security gate                                 │
└─────────────────────────────────────────────────────────────┘
```

**Both layers are required for security:**
- `@tenuo_node` without `@lockdown` = scoping with no enforcement
- `@lockdown` without `@tenuo_node` = enforcement with no scoping

---

## Example

```python
from langgraph.graph import StateGraph
from tenuo import configure, SigningKey, lockdown, root_task, Capability
from tenuo.langgraph import tenuo_node

# Setup (once at startup)
kp = SigningKey.generate()
configure(issuer_key=kp)

# LAYER 2: Tool wrapper (ENFORCEMENT)
# This is where authorization is actually checked
@lockdown(tool="search")
async def search_tool(query: str) -> list:
    return [f"Result for {query}"]

@lockdown(tool="write_file")
async def write_file(path: str, content: str) -> None:
    print(f"Writing to {path}")

# LAYER 1: Node decorator (SCOPING)
# Narrows the warrant for this node's execution
@tenuo_node(Capability("search", query=Pattern("*public*")))
async def researcher(state):
    # Warrant is scoped to: tools=["search"], query must match "*public*"
    # But enforcement happens when search_tool() is called
    results = await search_tool(query=state["query"])
    return {"results": results}

@tenuo_node(Capability("write_file", path=Pattern("/output/*")))
async def writer(state):
    # Warrant is scoped to: tools=["write_file"], path must match "/output/*"
    await write_file(path="/output/report.txt", content=state["content"])
    return {"done": True}

# Build graph
graph = StateGraph(dict)
graph.add_node("researcher", researcher)
graph.add_node("writer", writer)

# Run with root authority (async)
async with root_task(
    Capability("search", query="*"), 
    Capability("write_file", path="/*")
):
    result = await graph.compile().ainvoke({"query": "public data"})

# For sync code, use root_task_sync:
# with root_task_sync(Capability("search", query="*"), Capability("write_file", path="/*")):
#     result = graph.compile().invoke({"query": "public data"})
```

---

## Why Two Layers?

| Scenario | @tenuo_node | @lockdown | Result |
|----------|-------------|-----------|--------|
| Both | ✅ | ✅ | **Secure**: Scoped AND enforced |
| Node only | ✅ | ❌ | ⚠️ Scoped but not enforced |
| Tool only | ❌ | ✅ | ⚠️ Enforced but not scoped per-node |
| Neither | ❌ | ❌ | ❌ No protection |

---

## Context vs State

> **Important**: Context (`set_warrant_context`) is a **convenience layer** for tool protection. For distributed workflows, checkpointing, or serialized state, authority must travel in the graph state (e.g., `tenuo_warrant` field).
>
> **Context is convenience; state is the security boundary.**

For v0.1, `@tenuo_node` uses context internally. For advanced use cases requiring serialization (v0.2 SecureGraph), warrants will be carried in state.

---

## Error Handling & Troubleshooting

### Common Errors

```python
# Missing parent warrant context
@tenuo_node(Capability("search"))
async def researcher(state):
    ...
    
# ERROR: "No parent warrant in context. @tenuo_node requires root_task() or parent scoped_task()"
```

**Fix**: Wrap graph invocation in `root_task()`:

```python
async with root_task(Capability("search"), Capability("write_file")):
    await app.ainvoke(initial_state)
```

### Error Messages Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `No parent warrant in context` | `@tenuo_node` called outside `root_task()` | Wrap graph invocation in `root_task()` |
| `Tool 'write_file' not in parent warrant` | Node requests tool parent doesn't have | Add tool to parent scope, or remove from node |
| `Constraint 'path' failed` | Tool argument violates constraint | Request within allowed constraint bounds |
| `MonotonicityViolation` | Trying to expand scope | Scopes can only narrow, not expand |

### Debugging a Node

```python
from tenuo import get_warrant_context
from tenuo.langgraph import tenuo_node

@tenuo_node(Capability("read_file", path=Pattern("/data/*")))
async def my_node(state):
    warrant = get_warrant_context()
    
    # Inspect active warrant
    print(f"Node has tools: {warrant.tools}")
    print(f"Node has constraints: {warrant.constraints}")
    
    # ... rest of node
```

---

## Important Notes

1. **Raw calls bypass Tenuo**: `await http_client.get(...)` is not protected.
   All tools you want governed MUST use `@lockdown` or `protect_tools()`.

2. **Constraints are for scoping, not enforcement**: When you write
   `@tenuo_node(query="*public*")`, this narrows the warrant. But if
   `@lockdown` doesn't check the `query` parameter, it won't be enforced.

3. **The tool wrapper is the gate**: Even if a node has a narrow scope,
   the tool wrapper is what actually blocks unauthorized calls.

4. **Async/Sync**: Use `root_task` (async) with `ainvoke()`, use `root_task_sync` (sync) with `invoke()`. The `@lockdown` decorator works with both sync and async functions.

5. **Use Capability objects for constraints**:
   ```python
   @tenuo_node(Capability("search", query=Pattern("*public*")))
   ```
   For other constraint types, use explicit constructors:
   ```python
   from tenuo import Range, Exact, Capability
   @tenuo_node(Capability("search", max_results=Range(max=100), env=Exact("prod")))
   ```

---

## Coming in v0.2: SecureGraph

Declarative authority policy with automatic attenuation at graph edges. Stay tuned!

---

## See Also

- [MCP Integration](./mcp) — Secure your AI agent interaction with MCP tools
- [LangChain Integration](./langchain) — Tool protection for LangChain
- [Protocol](./protocol) — Protocol fundamentals and cycle protection
- [API Reference](./api-reference) — Full Python API documentation
