---
title: Quick Start
description: Get started with Tenuo in 5 minutes
---

# Quick Start

## What is Tenuo?

Tenuo is a warrant-based authorization library for AI agent workflows. A **warrant** is a signed token specifying which tools an agent can call, under what constraints, and for how long.

**Core invariant**: When a warrant is delegated, its capabilities can only **narrow**. 15 replicas becomes 10. Access to `staging-*` narrows to `staging-web`. Enforced cryptographically.

```
┌─────────────────────────────────────────────────────────┐
│  Agent Request: "restart staging-web"                   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Tenuo Layer                                            │
│  - Does this warrant allow "restart" on "staging-web"?  │
│  - Is the delegation chain valid?                       │
│  - Is the holder's signature correct?                   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Infrastructure IAM (AWS / K8s / etc.)                  │
│  - Does this service account have permission?           │
└─────────────────────────────────────────────────────────┘
```

Tenuo adds a **delegation layer** on top of your existing IAM. It tracks *who* delegated authority, *what limits* apply, and *why* an agent is acting.

## Installation

```bash
uv pip install tenuo
```

**With framework support:**
```bash
uv pip install "tenuo[openai]"      # OpenAI Agents SDK
uv pip install "tenuo[google_adk]"  # Google ADK
uv pip install "tenuo[langchain]"   # LangChain (langchain-core ≥0.2)
uv pip install "tenuo[langgraph]"   # LangGraph (includes LangChain)
uv pip install "tenuo[crewai]"      # CrewAI
uv pip install "tenuo[temporal]"    # Temporal workflows
uv pip install "tenuo[autogen]"     # AutoGen AgentChat (Python ≥3.10)
uv pip install "tenuo[a2a]"         # A2A inter-agent delegation
uv pip install "tenuo[mcp]"         # MCP client & server verification (Python ≥3.10)
uv pip install "tenuo[fastapi]"     # FastAPI
```

> **Note:** Quotes are required in zsh (default macOS shell) since `[]` are glob characters.

> **Rust SDK**: If you're using Rust directly, add `tenuo = "0.1.0-beta.22"` to your `Cargo.toml`. See the [crates.io documentation](https://crates.io/crates/tenuo) for Rust-specific examples. This guide focuses on Python.

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
mint(Capability(...)) → agent calls tool → @guard checks warrant → allowed or denied
```

If the LLM is prompt-injected, it can request anything. But the warrant only allows what you scoped. The injection succeeds at the LLM level; authorization stops the action.

---

## Python Quick Start

### Copy-Paste Example (Works Immediately)

This example runs without any setup -- just copy and paste:

```python
from tenuo import configure, mint_sync, Capability, Subpath, SigningKey, guard
from tenuo.exceptions import AuthorizationDenied

# 1. Configure once at startup
configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

# 2. Protect tools with @guard
@guard(tool="read_file")
def read_file(path: str) -> str:
    return f"Contents of {path}"

# 3. Scope authority to tasks
with mint_sync(Capability("read_file", path=Subpath("/data"))):
    print(read_file("/data/reports/q3.pdf"))  # Allowed
    
    try:
        read_file("/etc/passwd")  # Blocked
    except AuthorizationDenied as e:
        print(f"Blocked: {e}")
```

**What just happened?**
- `@guard(tool="read_file")` marks the function as requiring authorization
- `mint_sync(...)` creates a warrant scoped to `/data/` directory (using `Subpath` for path traversal protection)
- The second call fails because `/etc/passwd` is not under `/data/`

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
child = (warrant.grant_builder()
    .capability("search", query=Pattern("safe*"))
    .holder(worker_key.public_key)
    .ttl(300)
    .grant(key))  # Parent signs
```

#### Pattern 2: BoundWarrant (For Repeated Operations)

```python
from tenuo import Warrant, SigningKey

key = SigningKey.from_env("MY_KEY")

# warrant = receive_warrant_from_orchestrator()  # In real code
warrant = (Warrant.mint_builder().tool("process").holder(key.public_key).ttl(3600).mint(key))

# Bind key for repeated use
bound = warrant.bind(key)

items = ["a", "b", "c"]
for item in items:
    headers = bound.headers("process", {"item": item})
    # Make API call with headers...

# BoundWarrant should NOT be stored in state/cache (contains key)
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
    print(search("hello"))  # Works
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

Start with audit mode, then switch to enforce after analyzing logs:

```python
from tenuo import configure, SigningKey

# Stage 1: Audit mode - deploy without breaking anything
configure(
    issuer_key=SigningKey.generate(),
    mode="audit",  # Log violations, don't block
    dev_mode=True,
)
```

```python
# Stage 2: After analyzing logs, switch to enforce
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
with mint_sync(Capability("delete_file", path=Subpath("/tmp"))):
    delete_file("/tmp/test.txt")  # Would be allowed
    delete_file("/etc/passwd")    # Logged as violation
```

**Step 4: Enable enforce mode**
```python
configure(mode="enforce", trusted_roots=[control_plane_pubkey])
```
Now violations are blocked. Roll out to a subset of traffic first if needed.

> **Tip:** Use `why_denied(tool, args)` to debug specific failures during rollout.

---

## Choosing Your Integration

### Quick Decision Tree

**1. What runtime/framework are you using?**

- **OpenAI SDK** (`openai.OpenAI`, `openai.AsyncOpenAI`) --> Use [`tenuo.openai`](./openai)
- **CrewAI** (`crewai.Crew`, `crewai.Agent`) --> Use [`tenuo.crewai`](./crewai)
- **Google ADK** (`google.adk.agents.Agent`) --> Use [`tenuo.google_adk`](./google-adk)
- **Temporal** (durable workflows) --> Use [`tenuo.temporal`](./temporal)
- **MCP** (Model Context Protocol) --> Use [`tenuo.mcp`](./mcp)
- **LangChain / LangGraph / AutoGen** --> See [Framework Integrations](#framework-integrations) below
- **Custom/other** --> Use [API Reference](./api-reference) directly

**2. Do you have multiple agents communicating across processes?**

- **Yes**, agents are separate services (microservices, distributed system):
  - Use [`tenuo.a2a`](./a2a) **in addition to** your runtime integration
- **No**, single process or same-process multi-agent:
  - Just use your runtime integration

**3. Do you need cryptographic verifiability?**

- **Yes** (distributed, untrusted executor, audit requirements): Use **Tier 2** (Warrant + PoP)
- **No** (single-process, trusted environment, prototyping): Use **Tier 1** (Guardrails)

### Comparison

| Feature | OpenAI | CrewAI | ADK | Temporal | MCP | A2A |
|---------|--------|--------|-----|---------|-----|-----|
| **Runtime** | OpenAI SDK | CrewAI | Google ADK | Temporal SDK | MCP protocol | Any (HTTP) |
| **Deployment** | Single/multi process | Single/multi process | Single/multi process | Distributed workers | Client/server | Distributed |
| **Tier 1 (Guardrails)** | Yes | Yes | Yes | N/A | N/A | N/A |
| **Tier 2 (Warrant + PoP)** | Yes | Yes | Yes | Yes | Yes | Yes |
| **Delegation** | No | Yes `WarrantDelegator` | No | Yes (child workflows) | No | Yes (discovery) |
| **Streaming** | Yes | No | Yes | N/A | No | No |
| **Learning Curve** | Easy | Easy | Medium | Medium | Easy | Steep |

### Migration Paths

**Tier 1 --> Tier 2 (Adding Crypto):**

```python
# Before (Guardrails):
client = guard(openai.OpenAI(), allow_tools=[...], constraints={...})

# After (Warrant + PoP) - minimal change:
client = guard(openai.OpenAI(), warrant=my_warrant, signing_key=agent_key)
```

**Single-Process --> Distributed (Adding A2A):**

```python
# Before (Direct function calls):
result = worker.search_papers(query, sources)

# After (A2A - worker runs as separate service):
client = A2AClient("https://worker.svc", signing_key=orchestrator_key)
result = await client.send_task("search_papers", {...}, warrant=task_warrant)
```

**Combining integrations:**

| Combination | Use When |
|-------------|----------|
| **OpenAI + A2A** | Workers are separate OpenAI services |
| **ADK + A2A** | ADK orchestrator --> various worker services |
| **Temporal + MCP** | Durable workflows calling MCP tool servers |
| **OpenAI + ADK + A2A** | Mixed runtimes in distributed system |

**Rule of thumb**: Same language + same process --> runtime integration only. Cross-service --> add A2A.

---

## Framework Integrations

### OpenAI

Protect OpenAI tool calls with the `guard()` wrapper:

```python
from tenuo import SigningKey, Warrant, Subpath
from tenuo.openai import guard
import openai

# Create warrant
key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data"))
    .holder(key.public_key)
    .ttl(300)
    .mint(key))

# Wrap OpenAI client
client = guard(openai.OpenAI(), warrant=warrant, signing_key=key)

# Tools are automatically protected
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Read /data/report.txt"}],
    tools=[...]
)
```

See [OpenAI Integration](./openai) for full documentation.

### LangChain

**Option 1: `auto_protect()` (Zero Config)**

```python
from tenuo.langchain import auto_protect

# Wrap your executor - defaults to audit mode
protected_executor = auto_protect(executor)
result = protected_executor.invoke({"input": "Search for AI news"})
```

**Option 2: `SecureAgentExecutor` (Drop-in Replacement)**

```python
from tenuo.langchain import SecureAgentExecutor
from tenuo import configure, mint, Capability, SigningKey

configure(issuer_key=SigningKey.generate(), dev_mode=True)

executor = SecureAgentExecutor(agent=agent, tools=tools)

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

protected_tools = guard([DuckDuckGoSearchRun()], bound)
```

See [LangChain Integration](./langchain) for full documentation.

### Google ADK

Use `TenuoGuard` to protect Google ADK tools:

```python
from google import genai
from tenuo import SigningKey, Warrant, Subpath
from tenuo.google_adk import TenuoGuard, GuardBuilder

key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data"))
    .holder(key.public_key)
    .ttl(300)
    .mint(key))

# Create guard
guard = TenuoGuard(warrant=warrant, signing_key=key)

# Wrap client
client = genai.Client(middleware=[guard.before_tool])

# Or use builder for Tier 1 only
guard = (GuardBuilder()
    .allow("search")
    .with_constraints("read_file", path=Subpath("/data"))
    .build())
```

See [Google ADK Integration](./google-adk) for full documentation.

### LangGraph

**Option 1: `TenuoToolNode` + `guard_node()` (Recommended)**

```python
from tenuo import Warrant, SigningKey, KeyRegistry
from tenuo.langgraph import guard_node, TenuoToolNode, load_tenuo_keys
from langchain_core.tools import tool

load_tenuo_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER, etc.

@tool
def search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

tool_node = TenuoToolNode([search])

def my_agent(state):
    return {"messages": [...]}

graph.add_node("agent", guard_node(my_agent, key_id="worker"))
graph.add_node("tools", tool_node)

state = {"warrant": str(warrant), "messages": [...]}
config = {"configurable": {"tenuo_key_id": "worker"}}
result = graph.invoke(state, config=config)
```

**Option 2: `warrant_scope()` (Manual Narrowing)**

```python
from tenuo import warrant_scope, key_scope, Pattern

async def researcher_node(state, warrant, signing_key):
    node_warrant = (warrant.grant_builder()
        .capability("search", query=Pattern("*public*"))
        .grant(signing_key))

    with warrant_scope(node_warrant), key_scope(signing_key):
        results = await search(state["query"])
    return {"results": results}
```

See [LangGraph Integration](./langgraph) for full documentation.

---

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
from tenuo import SigningKey, PublicKey
orchestrator_key = SigningKey.from_env("ORCH_KEY")
worker_pubkey = PublicKey.from_env("WORKER_PUBKEY")

# Child warrant has narrower scope
worker_warrant = (warrant.grant_builder()
    .capability("manage_infrastructure",
        cluster=Pattern("staging-web"),
        replicas=Range.max_value(10))
    .holder(worker_pubkey)
    .ttl(300)
    .grant(orchestrator_key))

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
authorized = worker_warrant.allows("manage_infrastructure", args)
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

**Interactive Debugging**: Paste your warrant in the [Explorer Playground](https://tenuo.ai/explorer/) to decode it, inspect constraints, and test authorization - warrants contain only signed claims, not secrets, so they're safe to share.

---

## Next Steps

- **[AI Agent Patterns](./ai-agents)** — P-LLM/Q-LLM, prompt injection defense
- **[Concepts](./concepts)** — Why Tenuo? Threat model, core invariants
- **[OpenAI](./openai)** — Direct API protection with streaming
- **[Google ADK](./google-adk)** — ADK agent tool protection
- **[CrewAI](./crewai)** — Multi-agent crew protection
- **[LangChain](./langchain)** — Protect LangChain tools
- **[LangGraph](./langgraph)** — Scope LangGraph nodes
- **[AutoGen](./autogen)** — Protect AutoGen AgentChat tools
- **[Temporal](./temporal)** — Durable workflow authorization
- **[MCP](./mcp)** — Model Context Protocol client & server verification
- **[A2A](./a2a)** — Inter-agent delegation
- **[FastAPI](./fastapi)** — Zero-boilerplate API protection
- **[Security](./security)** — Threat model, best practices
