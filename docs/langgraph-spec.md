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

## Current Workaround

Until SecureGraph is implemented, use `@lockdown` directly:
```python
from langgraph.graph import StateGraph
from tenuo import lockdown, set_warrant_context

@lockdown(tool="process")
def process_node(state):
    return {"result": "processed"}

graph = StateGraph(AgentState)
graph.add_node("process", process_node)

with set_warrant_context(warrant):
    result = graph.compile().invoke(initial_state)
```

This works but requires manual attenuation for delegation.

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
