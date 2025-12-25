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
headers = warrant.headers(key, "search", {"query": "test"})

# Explicit key in delegation
child = warrant.grant(
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
bound = warrant.bind(key)

for item in items:
    headers = bound.headers("process", {"item": item})
    # Make API call with headers...

# ⚠️ BoundWarrant should NOT be stored in state/cache (contains key)
```

### Option C: Auto-Configure (Zero Setup)

For maximum speed, let Tenuo configure from environment:

```python
from tenuo import auto_configure

# Reads TENUO_* environment variables automatically:
# TENUO_ISSUER_KEY, TENUO_MODE, TENUO_TRUSTED_ROOTS, etc.
auto_configure()
```

**Environment variables:**
| Variable | Description |
|----------|-------------|
| `TENUO_ISSUER_KEY` | Base64-encoded signing key |
| `TENUO_MODE` | `enforce` (default), `audit`, or `permissive` |
| `TENUO_TRUSTED_ROOTS` | Comma-separated public keys |
| `TENUO_DEV_MODE` | `1` for development mode |

### Option D: Context-Based (Simple Prototyping)

For quick prototyping with `@guard` decorators:

```python
from tenuo import configure, mint, grant, Capability, Pattern, SigningKey

# 1. Configure once at startup
configure(issuer_key=SigningKey.generate(), dev_mode=True, mode="audit")

# 2. Protect tools with @guard
from tenuo import guard

@guard(tool="delete_user")
def delete_user(user_id: str):
    print(f"Deleting {user_id}...")

# 3. Scope authority to tasks
async with mint(
    Capability("read_file", path=Pattern("/data/*")),
):
    # Inner scope narrows further
    async with grant(
        Capability("read_file", path=Pattern("/data/reports/*"))
    ):
        result = read_file("/data/reports/q3.pdf")  # ✅ Allowed
        result = read_file("/etc/passwd")           # ❌ Blocked
```

---

## Enforcement Modes

Tenuo supports three enforcement modes for gradual adoption:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `enforce` | Block unauthorized requests | Production (default) |
| `audit` | Log violations but allow execution | Gradual adoption, discovery |
| `permissive` | Log + warn header, allow execution | Development, testing |

```python
from tenuo import configure, SigningKey

# Audit mode - deploy without breaking anything
configure(
    issuer_key=SigningKey.generate(),
    mode="audit",  # Log violations, don't block
    dev_mode=True,
)

# After analyzing logs, switch to enforce
configure(
    issuer_key=issuer_keypair,
    mode="enforce",  # Block violations
    trusted_roots=[control_plane_pubkey],
)
```

Check current mode programmatically:
```python
from tenuo import is_audit_mode, is_enforce_mode, should_block_violation

if is_audit_mode():
    print("Running in audit mode - violations logged but not blocked")
```

---

## Framework Integrations

### FastAPI

**Option 1: `SecureAPIRouter` (Drop-in Replacement)**

```python
from fastapi import FastAPI
from tenuo.fastapi import SecureAPIRouter, configure_tenuo

app = FastAPI()
configure_tenuo(app, trusted_issuers=[issuer_pubkey])

# Drop-in replacement for APIRouter - auto-protects routes
router = SecureAPIRouter(tool_prefix="api")

@router.get("/users/{user_id}")  # Auto-protected as "api_users_read"
async def get_user(user_id: str):
    return {"user_id": user_id}

@router.post("/users", tool="create_user")  # Explicit tool name
async def create_user(name: str):
    return {"name": name}

app.include_router(router)
```

**Option 2: `TenuoGuard` Dependency (Fine Control)**

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

**Option 1: `auto_protect()` (Zero Config)**

```python
from tenuo.langchain import auto_protect

# Wrap your executor - defaults to audit mode
protected_executor = auto_protect(executor)

# Run normally
result = protected_executor.invoke({"input": "Search for AI news"})
```

**Option 2: `SecureAgentExecutor` (Drop-in Replacement)**

```python
from tenuo.langchain import SecureAgentExecutor
from tenuo import configure, mint, Capability, SigningKey

configure(issuer_key=SigningKey.generate(), dev_mode=True)

# Drop-in replacement for AgentExecutor
executor = SecureAgentExecutor(agent=agent, tools=tools)

# Run with authorization context
async with mint(Capability("search"), Capability("calculator")):
    result = await executor.ainvoke({"input": "Calculate 2+2"})
```

**Option 3: `guard_tools()` and `guard_agent()` (Fine Control)**

```python
from tenuo import Warrant, SigningKey, Capability
from tenuo.langchain import guard_tools, guard_agent

keypair = SigningKey.generate()

# guard_tools: wrap tools, manage context yourself
protected_tools = guard_tools([search_tool, calculator], issuer_keypair=keypair)

# guard_agent: wrap entire executor with built-in context
protected_executor = guard_agent(
    executor,
    issuer_keypair=keypair,
    capabilities=[Capability("search"), Capability("calculator")],
)

# Now authorization is automatic
result = protected_executor.invoke({"input": "Search for AI news"})
```

**Option 4: Explicit BoundWarrant**

```python
from tenuo import Warrant, SigningKey
from tenuo.langchain import guard

keypair = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .tool("search")
    .mint(keypair))
bound = warrant.bind(keypair)

# Pass bound warrant explicitly
protected_tools = guard([DuckDuckGoSearchRun()], bound)
```

### LangGraph

```python
from tenuo import Warrant, SigningKey, KeyRegistry
from tenuo.langgraph import guard, TenuoToolNode, load_tenuo_keys

# 1. Load keys from environment (convention: TENUO_KEY_*)
load_tenuo_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER, etc.

# 2. Define your tools
@tool
def search(query: str) -> str:
    return f"Results for {query}"

# 3. Create secure tool node
tool_node = TenuoToolNode([search])

# 4. Wrap pure nodes with guard()
def my_agent(state):
    # Pure function - no Tenuo imports needed
    return {"messages": [...]}

graph.add_node("agent", guard(my_agent, key_id="worker"))
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
# ── CONTROL PLANE ──
from tenuo import SigningKey, Warrant, Pattern, Range, PublicKey

issuer_key = SigningKey.from_env("ISSUER_KEY")       # From secure storage
orchestrator_pubkey = PublicKey.from_env("ORCH_PUBKEY")  # Orchestrator's public key

warrant = (Warrant.mint_builder()
    .capability("manage_infrastructure", {
        "cluster": Pattern("staging-*"),
        "replicas": Range.max_value(15),
    })
    .holder(orchestrator_pubkey)
    .ttl(3600)
    .mint(issuer_key))
```

### 2. Delegate with Attenuation

```python
# ── ORCHESTRATOR ──
# Has its own key, only needs worker's PUBLIC key
from tenuo import PublicKey
worker_pubkey = PublicKey.from_env("WORKER_PUBKEY")

# Child warrant has narrower scope
worker_warrant = warrant.grant(
    to=worker_pubkey,
    allow={"manage_infrastructure": {
        "cluster": Pattern("staging-web"),  # Narrowed
        "replicas": Range.max_value(10),    # Reduced
    }},
    ttl=300,
    key=keypair  # Parent signs
)

# Send to worker: send_to_worker(str(worker_warrant))
```

### 3. Authorize an Action

```python
# ── WORKER ──
# Worker signs Proof-of-Possession with their private key
args = {"cluster": "staging-web", "replicas": 5}
pop_sig = worker_warrant.sign(
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

**Interactive Debugging**: Paste your warrant in the [Explorer Playground](https://tenuo.dev/explorer) to decode it, inspect constraints, and test authorization - warrants contain only signed claims, not secrets, so they're safe to share.

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
