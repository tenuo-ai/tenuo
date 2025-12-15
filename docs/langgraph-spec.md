# SecureGraph: Multi-Agent Warrant Management

> **Status**: 📋 Design Specification - Not Implemented  
> **Purpose**: Future direction for LangGraph integration  
> **Current Workaround**: Use `@lockdown` decorator with LangGraph nodes

---

## Problem

In multi-agent systems, manually managing warrant attenuation is error-prone:
```python
# Current: Manual attenuation at every delegation
researcher_warrant = root_warrant.attenuate(
    constraints={"file_path": Pattern("/tmp/research/*")},
    keypair=researcher_keypair
)

with set_warrant_context(researcher_warrant):
    researcher_node(state)
```

This becomes unmanageable as graphs grow.

---

## Proposed Solution: SecureGraph

`SecureGraph` wraps LangGraph's `StateGraph` and automatically attenuates warrants based on a configuration file.
```python
from tenuo.langgraph import SecureGraph

secure = SecureGraph(
    graph=graph,
    config="tenuo-graph.yaml",
    root_warrant=root_warrant,
    keypair=keypair
)

app = secure.compile()
result = app.invoke({"input": "Research Q3 results"})
# Warrants automatically attenuated at each node transition
```

---

## Configuration

Security rules defined in YAML, separate from code:
```yaml
version: "1"

defaults:
  # Fail-closed: unlisted nodes are denied
  deny_unlisted: true
  
  # Require validation on all interpolated values
  require_validation: true

nodes:
  supervisor:
    role: supervisor
    # No attenuation - inherits root warrant

  researcher:
    attenuate:
      tools:
        - search
        - read_file
      constraints:
        file_path:
          pattern: "/tmp/research/*"

  writer:
    attenuate:
      tools:
        - write_file
      constraints:
        file_path:
          pattern: "/tmp/output/*"
```

---

## Behavior

### Warrant Stack

SecureGraph maintains a stack to handle nested delegations:

1. **Entry**: Push current warrant, activate attenuated warrant
2. **Execution**: Node runs with attenuated warrant
3. **Exit**: Pop stack, restore previous warrant
```
Supervisor (root warrant)
    │
    ├─► Researcher (attenuated: search, read_file)
    │       │
    │       └─► Fact Checker (further attenuated: read_file only)
    │
    └─► Writer (attenuated: write_file)
```

### State Interpolation

Dynamic constraints from runtime state:
```yaml
researcher:
  attenuate:
    constraints:
      file_path:
        pattern: "/tmp/${state.project_id}/*"
        validate: "^[a-zA-Z0-9_-]+$"  # Required
```

**Validation is mandatory.** Without it, `${state.project_id}` could be `../../../etc/passwd`.

If validation regex is omitted, SecureGraph rejects the configuration at compile time.

---

## Tool Protection

Tools must be wrapped with `protect_tool` to read warrants from graph state:
```python
from tenuo.langgraph import protect_tool

# Wrap tools
search = protect_tool(search_func, name="search")
read_file = protect_tool(read_file_func, name="read_file")
```

Unwrapped tools bypass security - this is the user's responsibility.

---

## Audit Events

All transitions and authorizations logged:

| Event | Description |
|-------|-------------|
| `node.enter` | Warrant attenuated for node |
| `node.exit` | Warrant restored from stack |
| `tool.authorized` | Tool call permitted |
| `tool.denied` | Tool call blocked |
| `interpolation.validated` | State variable passed validation |
| `interpolation.rejected` | State variable failed validation |

---

## Known Limitations

### Parallel Execution

LangGraph copies state for parallel branches. This causes:

- Each branch has independent warrant stack
- Merge may lose stack state (depends on reducer)

**Recommendation**: Avoid complex delegation chains in parallel branches. Simple fan-out/fan-in patterns work correctly.

### No Cross-Graph Delegation

SecureGraph manages warrants within a single graph. Delegation to external services or subgraphs requires manual warrant passing.

---

## Open Questions

1. **Keypair per node?** Should each node have its own keypair, or share the parent's?
2. **Revocation integration**: How does SRL checking integrate with graph execution?
3. **Subgraph support**: How do compiled subgraphs inherit warrant context?

---

## Current Implementation (v0.1)

Until SecureGraph is implemented, use the **two-layer model**:

### Two-Layer Architecture

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

### Example

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

### Important Notes

1. **Raw calls bypass Tenuo**: `await http_client.get(...)` is not protected.
   All tools you want governed MUST use `@lockdown` or `protect_tools()`.

2. **Constraints are for scoping, not enforcement**: When you write
   `@tenuo_node(query="*public*")`, this narrows the warrant. But if
   `@lockdown` doesn't check the `query` parameter, it won't be enforced.

3. **The tool wrapper is the gate**: Even if a node has a narrow scope,
   the tool wrapper is what actually blocks unauthorized calls.

### Why Two Layers?

| Scenario | @tenuo_node | @lockdown | Result |
|----------|-------------|-----------|--------|
| Both | ✅ | ✅ | **Secure**: Scoped AND enforced |
| Node only | ✅ | ❌ | ⚠️ Scoped but not enforced |
| Tool only | ❌ | ✅ | ⚠️ Enforced but not scoped per-node |
| Neither | ❌ | ❌ | ❌ No protection |

---

## Timeline

| Milestone | Target |
|-----------|--------|
| Design finalized | v0.2 |
| Prototype | v0.3 |
| Production ready | v0.4 |

---

## See Also

- [LangChain Integration](./langchain-spec.md) (implemented)
- [Security Review](./langgraph-security-review.md)
- [CLI Specification](./cli-spec.md)
- [Core Specification](./spec.md)
