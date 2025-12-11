# Tenuo LangChain Integration: v1 Technical Spec

## Core Invariant

**Attenuation is monotonic.** A child warrant can never exceed its parent's scope. This is enforced cryptographically — the signature chain proves the narrowing at each step.

---

## Security Properties (All Required for v1)

| Property | What It Means | How It's Enforced |
|----------|---------------|-------------------|
| **Scoped** | Warrant permits specific tools + constraints | Constraint matching at call time |
| **Temporal** | Authority expires in seconds/minutes | TTL in warrant, checked on every call |
| **Delegatable** | Parent can issue narrower child warrants | `warrant.attenuate()` with signature chain |
| **Bound** | Credential theft is useless without key | PoP signature over (tool, args, timestamp) |
| **Dynamic** | Scope adapts to runtime context | State interpolation in constraints |

---

## Architectural Patterns

### 1. Single Agent: `protect_tools()`

Wraps LangChain tools with warrant checks. One warrant for entire execution.

```python
from tenuo.langchain import protect_tools

# Tools are vanilla LangChain
@tool
def search(query: str) -> str: ...

@tool
def read_file(path: str) -> str: ...

# Wrap once at setup
secure_tools = protect_tools(
    tools=[search, read_file],
    config="tenuo.yaml",
    warrant=warrant,
    keypair=keypair,
)

agent = AgentExecutor(agent=base_agent, tools=secure_tools)
```

**Tool code is unchanged.** Authorization is configuration.

---

### 2. Multi-Agent: `SecureGraph`

Wraps LangGraph with automatic warrant flow. Push on delegation, pop on return.

```python
from tenuo.langgraph import SecureGraph

# Graph is vanilla LangGraph
graph = StateGraph(AgentState)
graph.add_node("supervisor", supervisor_fn)
graph.add_node("researcher", researcher_fn)
...

# Wrap once
secure = SecureGraph(
    graph=graph,
    config="tenuo-graph.yaml",
    root_warrant=warrant,
    keypair=keypair,
)

result = secure.invoke({"input": "..."})
```

**Node code is unchanged.** Warrant state flows automatically.

---

### 3. Dynamic Attenuation (Required for v1)

Constraints interpolate from runtime state.

```yaml
# tenuo-graph.yaml
nodes:
  file_analyzer:
    attenuate:
      tools: [read_file]
      constraints:
        path:
          pattern: "/uploads/${state.user_id}/${state.filename}"
          validate: "^[a-zA-Z0-9_/-]+$"
```

On node entry:

1. Resolve `${state.*}` references
2. Validate against regex (reject traversal attacks)
3. Verify result still satisfies parent constraints (monotonic)
4. Mint attenuated warrant

**This is what differentiates Tenuo from per-node IAM.**

---

## State Management

```python
# Injected by SecureGraph
state["__tenuo_warrant__"]  # Current node's warrant
state["__tenuo_stack__"]    # Parent warrants for restoration
```

| Transition | Stack Operation |
|------------|-----------------|
| Supervisor → Worker | Push parent, attenuate for child |
| Worker → Supervisor | Pop stack, restore parent |
| Parallel fork | Copy state (LangGraph handles isolation) |
| Parallel join | Discard branch warrants, restore parent |

---

## Config Schema

```yaml
# tenuo-graph.yaml
version: "1"

settings:
  max_stack_depth: 10          # Cycle protection
  allow_unlisted_nodes: false  # Fail-closed

nodes:
  supervisor:
    role: supervisor  # Receives root warrant

  researcher:
    attenuate:
      tools: [search, read_file]
      constraints:
        path:
          pattern: "/data/${state.project_id}/*"
          validate: "^[a-zA-Z0-9_/-]+$"
        max_results:
          max: 100

  writer:
    attenuate:
      tools: [write_file]
      constraints:
        path:
          pattern: "/output/${state.session_id}/*"
          validate: "^[a-zA-Z0-9_/-]+$"
```

---

## v1 Scope

| In | Out |
|----|-----|
| `protect_tools()` for single agent | Checkpoint rehydration |
| `SecureGraph` for LangGraph | Cycle rotation optimization |
| Dynamic constraints via `${state.*}` | Parallel branch warrant differentiation |
| Stack-based delegation/restoration | Cross-graph warrant federation |
| Depth limit for cycles | |
| PoP signature generation | |
| Audit logging | |

---

## Integration Points

```
┌─────────────────────────────────────────────────────────┐
│                    User Code                            │
│          (Tools, Nodes, Graph structure)                │
│                 NO TENUO IMPORTS                        │
└─────────────────────────────┬───────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────┐
│                 Tenuo LangChain SDK                     │
│                                                         │
│   protect_tools()    SecureGraph    SecureToolNode      │
└─────────────────────────────┬───────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────┐
│                     Tenuo Core                          │
│                                                         │
│   Warrant    Authorizer    Keypair    PoP    Config     │
└─────────────────────────────────────────────────────────┘
```

---

## Success Criteria

1. **Zero Tenuo imports in user code** — tools and nodes are pure business logic
2. **Dynamic scope** — warrant constraints adapt to `state.*` at runtime
3. **Monotonic proof** — signature chain verifiable from root to leaf
4. **Sub-minute TTL** — warrants expire before they can be exfiltrated and reused