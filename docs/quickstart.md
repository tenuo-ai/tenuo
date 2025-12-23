---
title: Quick Start
description: Get started with Tenuo in 5 minutes
---

# Quick Start

Get Tenuo running in 5 minutes. For a visual walkthrough, see the [Demo](./demo.html).

## What is Tenuo?

Tenuo is a capability-based authorization library for AI agent workflows. It uses signed tokens called **warrants** to control what actions agents can perform.

**Core invariant**: When a warrant is delegated, its capabilities can only **shrink**. 15 replicas becomes 10. Access to `staging-*` narrows to `staging-web`.

```
┌─────────────────────────────────────────────────────────┐
│  Agent Request: "restart staging-web"                   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Tenuo Layer                                            │
│  ✓ Does this warrant allow "restart" on "staging-web"?  │
│  ✓ Is the delegation chain valid?                       │
│  ✓ Is the holder's signature correct?                   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Infrastructure IAM (AWS / K8s / etc.)                  │
│  ✓ Does this service account have permission?           │
└─────────────────────────────────────────────────────────┘
```

Tenuo adds a **delegation layer** on top of your existing IAM. It tracks *who* delegated authority, *what limits* apply, and *why* an agent is acting.

## Installation

**Python**
```bash
pip install tenuo
```

**With framework support**
```bash
pip install tenuo[langchain]   # LangChain integration
pip install tenuo[langgraph]   # LangGraph integration (includes LangChain)
pip install tenuo[fastapi]     # FastAPI integration
```

**Rust**
```toml
[dependencies]
tenuo = "0.1"
```

---

## Python Quick Start

### Option A: The Safe Path (Recommended)

The primary API keeps keys separate from warrants:

```python
from tenuo import Warrant, SigningKey, Pattern

# Warrant in state/storage - serializable, no secrets
warrant = receive_warrant_from_orchestrator()

# Explicit key at call site - keys never in state
key = SigningKey.from_env("MY_SERVICE_KEY")
headers = warrant.auth_headers(key, "search", {"query": "test"})

# Explicit key in delegation
child = warrant.delegate(
    to=worker_pubkey,
    allow={"search": {"query": Pattern("safe*")}},
    ttl=300,
    key=key
)
```

### Option B: BoundWarrant (For Repeated Operations)

When you need to make many calls with the same warrant+key:

```python
from tenuo import Warrant, SigningKey

warrant = receive_warrant()
key = SigningKey.from_env("MY_KEY")

# Bind key for repeated use
bound = warrant.bind_key(key)

for item in items:
    headers = bound.auth_headers("process", {"item": item})
    # Make API call with headers...

# ⚠️ BoundWarrant should NOT be stored in state/cache (contains key)
```

### Option C: Context-Based (Simple Prototyping)

For quick prototyping with `@lockdown` decorators:

```python
from tenuo import configure, root_task, scoped_task, Capability, Pattern, SigningKey

# 1. Configure once at startup
configure(issuer_key=SigningKey.generate(), dev_mode=True)

# 2. Protect tools with @lockdown
from tenuo import lockdown

@lockdown(tool="read_file")
def read_file(path: str):
    return open(path).read()

# 3. Scope authority to tasks
async with root_task(
    Capability("read_file", path=Pattern("/data/*")),
):
    # Inner scope narrows further
    async with scoped_task(
        Capability("read_file", path=Pattern("/data/reports/*"))
    ):
        result = read_file("/data/reports/q3.pdf")  # ✅ Allowed
        result = read_file("/etc/passwd")           # ❌ Blocked
```

---

## Framework Integrations

### FastAPI

```python
from fastapi import FastAPI, Depends
from tenuo.fastapi import TenuoGuard, SecurityContext, configure_tenuo

app = FastAPI()
configure_tenuo(app, trusted_issuers=[issuer_pubkey])

@app.get("/search")
async def search(
    query: str,
    ctx: SecurityContext = Depends(TenuoGuard("search"))
):
    # ctx.warrant is verified, ctx.args contains extracted arguments
    return {"results": [...]}
```

### LangChain

```python
from tenuo import Warrant, SigningKey
from tenuo.langchain import protect

# Create warrant and bind key
keypair = SigningKey.generate()
warrant = (Warrant.builder()
    .tool("search")
    .tool("calculator")
    .issue(keypair))
bound = warrant.bind_key(keypair)

# Protect your tools
from langchain_community.tools import DuckDuckGoSearchRun
protected_tools = protect([DuckDuckGoSearchRun()], bound_warrant=bound)

# Use in your agent
agent = create_openai_tools_agent(llm, protected_tools, prompt)
```

### LangGraph

```python
from tenuo import Warrant, SigningKey, KeyRegistry
from tenuo.langgraph import secure, TenuoToolNode, auto_load_keys

# 1. Load keys from environment (convention: TENUO_KEY_*)
auto_load_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER, etc.

# 2. Define your tools
@tool
def search(query: str) -> str:
    return f"Results for {query}"

# 3. Create secure tool node
tool_node = TenuoToolNode([search])

# 4. Wrap pure nodes with secure()
def my_agent(state):
    # Pure function - no Tenuo imports needed
    return {"messages": [...]}

graph.add_node("agent", secure(my_agent, key_id="worker"))
graph.add_node("tools", tool_node)

# 5. Run with warrant in state, key_id in config
state = {"warrant": warrant, "messages": [...]}
config = {"configurable": {"tenuo_key_id": "worker"}}
result = graph.invoke(state, config=config)
```

---

## Low-Level API (Full Control)

For production deployments with explicit keypair management.

### 1. Create a Warrant

```python
from tenuo import SigningKey, Warrant, Pattern, Range

keypair = SigningKey.generate()

warrant = (Warrant.builder()
    .capability("manage_infrastructure", {
        "cluster": Pattern("staging-*"),
        "replicas": Range.max_value(15),
    })
    .holder(keypair.public_key)
    .ttl(3600)
    .issue(keypair))
```

### 2. Delegate with Attenuation

```python
worker_keypair = SigningKey.generate()

# Child warrant has narrower scope
worker_warrant = warrant.delegate(
    to=worker_keypair.public_key,
    allow={"manage_infrastructure": {
        "cluster": Pattern("staging-web"),  # Narrowed
        "replicas": Range.max_value(10),    # Reduced
    }},
    ttl=300,
    key=keypair  # Parent signs
)
```

### 3. Authorize an Action

```python
# Worker signs Proof-of-Possession
args = {"cluster": "staging-web", "replicas": 5}
pop_sig = worker_warrant.create_pop_signature(
    worker_keypair, "manage_infrastructure", args
)

# Verify authorization
authorized = worker_warrant.authorize(
    tool="manage_infrastructure",
    args=args,
    signature=bytes(pop_sig)
)
print(f"Authorized: {authorized}")  # True
```

---

## Debugging Authorization Failures

Use `why_denied()` for detailed diagnostics:

```python
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})
if result.denied:
    print(f"Denied: {result.deny_code}")
    print(f"Field: {result.field}")
    print(f"Suggestion: {result.suggestion}")
```

Or use `diagnose()` for a full warrant inspection:

```python
from tenuo import diagnose
diagnose(warrant)  # Prints warrant details, TTL, constraints, etc.
```

**Interactive Debugging**: Paste your warrant in the [Explorer Playground](https://tenuo.dev/explorer/) to decode it, inspect constraints, and test authorization - warrants contain only signed claims, not secrets, so they're safe to share.

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Warrant** | Signed token granting specific capabilities |
| **Attenuation** | Creating a child warrant with narrower scope |
| **Constraints** | Rules limiting what a warrant can authorize (`Pattern`, `Range`, `Exact`, etc.) |
| **PoP** | Proof-of-Possession: signature proving holder identity |
| **BoundWarrant** | Warrant + SigningKey for convenience (non-serializable) |

## Constraint Types

| Type | Example | Matches |
|------|---------|---------|
| `Exact` | `Exact("prod")` | Only "prod" |
| `Pattern` | `Pattern("staging-*")` | "staging-web", "staging-db" |
| `OneOf` | `OneOf(["a", "b"])` | "a" or "b" |
| `Range` | `Range(min=0, max=1000)` | 0 to 1000 |
| `Regex` | `Regex(r"^user_\d+$")` | "user_123", "user_456" |

See [Constraints](./constraints) for the full list.

---

## Next Steps

- **[AI Agent Patterns](./ai-agents)** — P-LLM/Q-LLM, prompt injection defense
- **[Concepts](./concepts)** — Why Tenuo? Threat model, core invariants
- **[LangChain](./langchain)** — Protect LangChain tools
- **[LangGraph](./langgraph)** — Scope LangGraph nodes
- **[FastAPI](./fastapi)** — Zero-boilerplate API protection
- **[Security](./security)** — Threat model, best practices
