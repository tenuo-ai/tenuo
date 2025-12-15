---
title: LangGraph Integration
description: Node scoping for LangGraph workflows
---

# Tenuo LangGraph Integration

> **Status**: ✅ Implemented (v0.1)  
> **Future**: SecureGraph (v0.2)

---

## Problem

In multi-agent systems, manually managing warrant attenuation is error-prone:

```python
# Without Tenuo: Manual attenuation at every delegation
researcher_warrant = root_warrant.attenuate(
    constraints={"file_path": Pattern("/tmp/research/*")},
    keypair=researcher_keypair
)

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
from tenuo import lockdown, root_task_sync
from tenuo.langgraph import tenuo_node

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
@tenuo_node(tools=["search"], query="*public*")
async def researcher(state):
    # Warrant is scoped to: tools=["search"], query must match "*public*"
    # But enforcement happens when search_tool() is called
    results = await search_tool(query=state["query"])
    return {"results": results}

@tenuo_node(tools=["write_file"], path="/output/*")
async def writer(state):
    # Warrant is scoped to: tools=["write_file"], path must match "/output/*"
    await write_file(path="/output/report.txt", content=state["content"])
    return {"done": True}

# Build graph
graph = StateGraph(AgentState)
graph.add_node("researcher", researcher)
graph.add_node("writer", writer)

# Run with root authority
with root_task_sync(tools=["search", "write_file"], query="*", path="/*"):
    result = graph.compile().invoke({"query": "public data"})
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

## Important Notes

1. **Raw calls bypass Tenuo**: `await http_client.get(...)` is not protected.
   All tools you want governed MUST use `@lockdown` or `protect_tools()`.

2. **Constraints are for scoping, not enforcement**: When you write
   `@tenuo_node(query="*public*")`, this narrows the warrant. But if
   `@lockdown` doesn't check the `query` parameter, it won't be enforced.

3. **The tool wrapper is the gate**: Even if a node has a narrow scope,
   the tool wrapper is what actually blocks unauthorized calls.

---

## Coming in v0.2: SecureGraph

Declarative authority policy with automatic attenuation at graph edges. Stay tuned!

---

## See Also

- [LangChain Integration](./langchain.md) — Tool protection for LangChain
- [Protocol](./protocol.md) — Protocol fundamentals and cycle protection
- [API Reference](./api-reference.md) — Full Python API documentation
