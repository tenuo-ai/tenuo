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

```bash
pip install tenuo
```

**With framework support:**
```bash
pip install "tenuo[langchain]"   # LangChain integration
pip install "tenuo[langgraph]"   # LangGraph integration (includes LangChain)
pip install "tenuo[fastapi]"     # FastAPI integration
```

> **Note:** Quotes are required in zsh (default macOS shell) since `[]` are glob characters.

> **Rust SDK**: If you're using Rust directly, add `tenuo = "0.1.0-beta.3"` to your `Cargo.toml`. See the [crates.io documentation](https://crates.io/crates/tenuo) for Rust-specific examples. This guide focuses on Python.

---

## Core Model

Three things to understand:

| Concept | What it is | Why it matters |
|---------|-----------|----------------|
| **Warrant** | Signed token listing allowed tools + constraints | Authority is explicit, not ambient |
| **Constraints** | Rules on arguments (`path=/data/*`, `amount<100`) | Scopes *what* an action can do, not just *if* it can happen |
| **PoP** | Proof-of-Possession signature | Stolen warrants are useless without the private key |

**The flow:**
```
mint(Capability(...)) → agent calls tool → @guard checks warrant → ✅ or ❌
```

If the LLM is prompt-injected, it can request anything. But the warrant only allows what you scoped. The injection succeeds at the LLM level; authorization stops the action.

---

## Python Quick Start

### Copy-Paste Example (Works Immediately)

This example runs without any setup—just copy and paste:

```python
from tenuo import configure, mint_sync, Capability, Pattern, SigningKey, guard
from tenuo.exceptions import AuthorizationDenied

# 1. Configure once at startup
configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

# 2. Protect tools with @guard
@guard(tool="read_file")
def read_file(path: str) -> str:
    return f"Contents of {path}"

# 3. Scope authority to tasks
with mint_sync(Capability("read_file", path=Pattern("/data/*"))):
    print(read_file("/data/reports/q3.pdf"))  # ✅ Allowed
    
    try:
        read_file("/etc/passwd")  # ❌ Blocked
    except AuthorizationDenied as e:
        print(f"Blocked: {e}")
```

**What just happened?**
- `@guard(tool="read_file")` marks the function as requiring authorization
- `mint_sync(...)` creates a warrant scoped to `/data/*` files
- The second call fails because `/etc/passwd` doesn't match the pattern

---

### Production Patterns

The examples above use `dev_mode=True` which auto-generates keys. In production, you'll separate concerns:

#### Pattern 1: Keys Separate from Warrants (Recommended)

```python
from tenuo import Warrant, SigningKey, Pattern

# Create a warrant (in production: receive from orchestrator)
key = SigningKey.generate()  # Or SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .tool("search")
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Key stays explicit at call sites - never stored in state
headers = warrant.headers(key, "search", {"query": "test"})

# Delegation with attenuation
worker_key = SigningKey.generate()
child = warrant.grant(
    to=worker_key.public_key,
    allow="search",
    ttl=300,
    key=key,  # Parent signs
    query=Pattern("safe*")  # Constraint as kwarg
)
```

#### Pattern 2: BoundWarrant (For Repeated Operations)

```python
from tenuo import Warrant, SigningKey

# warrant = receive_warrant_from_orchestrator()  # In real code
warrant = (Warrant.mint_builder().tool("process").holder(key.public_key).ttl(3600).mint(key))
key = SigningKey.from_env("MY_KEY")

# Bind key for repeated use
bound = warrant.bind(key)

items = ["a", "b", "c"]
for item in items:
    headers = bound.headers("process", {"item": item})
    # Make API call with headers...

# ⚠️ BoundWarrant should NOT be stored in state/cache (contains key)
```

#### Pattern 3: Environment-Based Setup

For 12-factor apps, configure via environment variables:

```python
from tenuo import auto_configure, guard, mint_sync, Capability

auto_configure()  # Reads TENUO_* environment variables

@guard(tool="search")
def search(query: str) -> str:
    return f"Results for {query}"

with mint_sync(Capability("search")):
    print(search("hello"))  # ✅ Works
```

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `TENUO_ISSUER_KEY` | Base64-encoded signing key |
| `TENUO_MODE` | `enforce` (default), `audit`, or `permissive` |
| `TENUO_TRUSTED_ROOTS` | Comma-separated public keys |
| `TENUO_DEV_MODE` | `1` for development mode |

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
    issuer_key=issuer_key,
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

## Adopting Gradually

For existing applications, roll out Tenuo without breaking production:

**Step 1: Deploy in audit mode**
```python
configure(issuer_key=SigningKey.generate(), mode="audit", dev_mode=True)
```
All tool calls are logged but never blocked. Analyze logs to see what would be denied.

**Step 2: Add `@guard` to critical tools**
```python
@guard(tool="delete_file")
def delete_file(path: str): ...
```
In audit mode, this still allows execution but logs authorization checks.

**Step 3: Test with scoped warrants**
```python
with mint_sync(Capability("delete_file", path=Pattern("/tmp/*"))):
    delete_file("/tmp/test.txt")  # ✅ Would be allowed
    delete_file("/etc/passwd")    # ⚠️ Logged as violation
```

**Step 4: Enable enforce mode**
```python
configure(mode="enforce", trusted_roots=[control_plane_pubkey])
```
Now violations are blocked. Roll out to a subset of traffic first if needed.

> **Tip:** Use `why_denied(tool, args)` to debug specific failures during rollout.

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
protected_tools = guard_tools([search_tool, calculator], issuer_key=keypair)

# guard_agent: wrap entire executor with built-in context
protected_executor = guard_agent(
    executor,
    issuer_key=keypair,
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
from tenuo.langgraph import guard_node, TenuoToolNode, load_tenuo_keys
from langchain_core.tools import tool  # LangChain tool decorator

# 1. Load keys from environment (convention: TENUO_KEY_*)
load_tenuo_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER, etc.

# 2. Define your tools
@tool
def search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

# 3. Create secure tool node
tool_node = TenuoToolNode([search])

# 4. Wrap pure nodes with guard()
def my_agent(state):
    # Pure function - no Tenuo imports needed
    return {"messages": [...]}

graph.add_node("agent", guard_node(my_agent, key_id="worker"))
graph.add_node("tools", tool_node)

# 5. Run with warrant in state (str() = base64, safe for JSON serialization)
state = {"warrant": str(warrant), "messages": [...]}
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
    .capability("manage_infrastructure",
        cluster=Pattern("staging-*"),
        replicas=Range.max_value(15))
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
    allow="manage_infrastructure",
    ttl=300,
    key=key,  # Parent signs
    cluster=Pattern("staging-web"),  # Narrowed (constraint as kwarg)
    replicas=Range.max_value(10),    # Reduced
)

# Send to worker: send_to_worker(str(worker_warrant))
```

### 3. Authorize an Action

```python
# ── WORKER ──
# Worker signs Proof-of-Possession with their private key
worker_key = SigningKey.from_env("WORKER_KEY")
args = {"cluster": "staging-web", "replicas": 5}
pop_sig = worker_warrant.sign(
    worker_key, "manage_infrastructure", args
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
result = warrant.why_denied("read_file", path="/etc/passwd")
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

> [!WARNING]
> **Trust Cliff**: Once you add **any** constraint, unknown arguments are rejected.
> Use `_allow_unknown=True` to opt out, or use `Wildcard()` to explicitly allow specific fields.
> See [Closed-World Mode](./constraints#closed-world-mode-trust-cliff) for details.

---

## Next Steps

- **[AI Agent Patterns](./ai-agents)** — P-LLM/Q-LLM, prompt injection defense
- **[Concepts](./concepts)** — Why Tenuo? Threat model, core invariants
- **[LangChain](./langchain)** — Protect LangChain tools
- **[LangGraph](./langgraph)** — Scope LangGraph nodes
- **[FastAPI](./fastapi)** — Zero-boilerplate API protection
- **[Security](./security)** — Threat model, best practices
