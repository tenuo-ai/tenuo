# Choosing Your Integration

Tenuo provides three main integrations. This guide helps you choose the right one.

---

## TL;DR

- **Using OpenAI?** → [`tenuo.openai`](./openai.md)
- **Using CrewAI?** → [`tenuo.crewai`](./crewai.md)
- **Using Google ADK?** → [`tenuo.google_adk`](./google-adk.md)
- **Agents in separate services?** → Add [`tenuo.a2a`](./a2a.md)
- **Need crypto?** → Use Tier 2

Read below for details.

---

## Quick Decision Tree

### 1. What runtime/framework are you using?

- **OpenAI SDK** (`openai.OpenAI`, `openai.AsyncOpenAI`) → Use [`tenuo.openai`](./openai.md)
- **CrewAI** (`crewai.Crew`, `crewai.Agent`) → Use [`tenuo.crewai`](./crewai.md)
- **Google ADK** (`google.adk.agents.Agent`) → Use [`tenuo.google_adk`](./google-adk.md)
- **LangChain, Autogen, etc.** → See [Framework Integrations](./integrations.md)
- **Custom/other** → Use [Warrant API](./warrants.md) directly

### 2. Do you have multiple agents communicating across processes?

- **Yes**, agents are separate services (microservices, distributed system):
  - Use [`tenuo.a2a`](./a2a.md) **in addition to** your runtime integration
  - Example: Orchestrator (ADK) → Worker (OpenAI) via HTTP

- **No**, single process or same-process multi-agent:
  - Just use your runtime integration (OpenAI or ADK)
  - Each agent gets its own warrant

### 3. Do you need cryptographic verifiability?

- **Yes** (distributed, untrusted executor, audit requirements):
  - Use **Tier 2** (Warrant + PoP) in your integration

- **No** (single-process, trusted environment, prototyping):
  - Use **Tier 1** (Guardrails) in your integration

---

## Common Scenarios

### Single OpenAI Agent (Internal Tool)

**Use**: `tenuo.openai` Tier 1

```python
from tenuo.openai import guard, Subpath

client = guard(
    openai.OpenAI(),
    allow_tools=["read_file", "search"],
    constraints={"read_file": {"path": Subpath("/data")}}
)
```

**Why**: Simplest setup. No warrants needed for single trusted agent.

---

### Multi-Agent OpenAI (Same Process)

**Use**: `tenuo.openai` Tier 2 (each agent has its own warrant)

```python
# Orchestrator gets issuer warrant
orchestrator_warrant = Warrant.mint_builder()...mint(control_plane_key)

# Workers get execution warrants delegated from orchestrator
researcher_warrant = orchestrator_warrant.grant_builder()...grant(orchestrator_key)

# Each has its own guarded client
researcher_client = guard(openai.OpenAI(), warrant=researcher_warrant, signing_key=researcher_key)
analyst_client = guard(openai.OpenAI(), warrant=analyst_warrant, signing_key=analyst_key)
```

**Why**: Each agent has different permissions. Warrants enforce least privilege.

---

### Google ADK Workflow

**Use**: `tenuo.google_adk` Tier 2

```python
from tenuo.google_adk import GuardBuilder

guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .build())

agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, search]),
    before_tool_callback=guard.before_tool,
)
```

**Why**: ADK-specific integration with tool filtering and callback hooks.

---

### Microservices (Orchestrator → Workers)

**Use**: `tenuo.a2a` + runtime integration

**Orchestrator** (Google ADK):
```python
from tenuo.a2a import A2AClient
from tenuo.google_adk import GuardBuilder

# Orchestrator has its own guard
orchestrator_guard = GuardBuilder().with_warrant(orchestrator_warrant, key).build()

# Delegate to worker via A2A
client = A2AClient("https://worker.example.com", signing_key=orchestrator_key)

# Attenuate warrant for specific task
task_warrant = orchestrator_warrant.grant_builder()
    .capability("search_papers", sources=UrlSafe(allow_domains=["arxiv.org"]))
    .holder(worker_public_key)
    .grant(orchestrator_key)

# Send task with attenuated warrant
result = await client.send_task("search_papers", {...}, warrant=task_warrant)
```

**Worker** (OpenAI):
```python
from tenuo.a2a import A2AServer

server = A2AServer(
    name="ResearchWorker",
    public_key=worker_key,
    trusted_issuers=[orchestrator_public_key],
)

@server.skill("search_papers")
async def search_papers(query: str, sources: list[str]) -> list[dict]:
    # Warrant is validated automatically by server
    return await do_search(query, sources)
```

**Why**: A2A handles cross-process authorization. Each service uses its own runtime integration.

---

| Feature | OpenAI | CrewAI | ADK | A2A |
|---------|--------|--------|-----|-----|
| **Runtime** | OpenAI SDK | CrewAI | Google ADK | Any (HTTP) |
| **Deployment** | Single/multi process | Single/multi process | Single/multi process | Distributed |
| **Tier 1 (Guardrails)** | ✅ | ✅ | ✅ | N/A (Tier 2 required) |
| **Tier 2 (Warrant + PoP)** | ✅ | ✅ | ✅ | ✅ |
| **Delegation** | ❌ | ✅ `WarrantDelegator` | ❌ | ✅ (discovery) |
| **Agent Namespacing** | ❌ | ✅ `role::tool` | ❌ | N/A |
| **Streaming** | ✅ | ❌ | ✅ | ❌ |
| **Seal Mode** | ❌ | ✅ | ❌ | N/A |
| **Learning Curve** | Easy | Easy | Medium | Steep |

---

## Migration Paths

###  Tier 1 → Tier 2 (Adding Crypto)

**Before** (Guardrails):
```python
client = guard(openai.OpenAI(), allow_tools=[...], constraints={...})
```

**After** (Warrant + PoP):
```python
# Add warrant and signing_key
client = guard(
    openai.OpenAI(),
    warrant=my_warrant,
    signing_key=agent_key,
)
```

**Impact**: Minimal code change. Constraints move into warrant (issued by control plane).

---

### Single-Process → Distributed (Adding A2A)

**Before** (Direct function calls):
```python
# Orchestrator calls worker functions directly
result = worker.search_papers(query, sources)
```

**After** (A2A):
```python
# Worker runs as separate service
# Orchestrator delegates via HTTP + warrant

client = A2AClient("https://worker.svc", signing_key=orchestrator_key)
result = await client.send_task("search_papers", {...}, warrant=task_warrant)
```

**Impact**: Architecture change (multi-process). Requires service deployment.

---

### OpenAI → ADK (Changing Runtime)

**Constraints stay the same**:
```python
# Both use same constraint API
from tenuo.constraints import Subpath, UrlSafe, Pattern
```

**Integration changes**:
```python
# OpenAI
client = guard(openai.OpenAI(), allow_tools=[...], constraints={...})

# ADK (equivalent)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
agent = Agent(tools=guard.filter_tools([...]), before_tool_callback=guard.before_tool)
```

**Impact**: Integration API differs, but constraint logic is portable.

---

## When to Combine Integrations

| Combination | Use When | Pattern |
|-------------|----------|---------|
| **OpenAI + A2A** | Workers are separate OpenAI services | Each service has `tenuo.openai` guard + orchestrator uses `A2AClient` |
| **ADK + A2A** | ADK orchestrator → various worker services | ADK uses `GuardBuilder` + `A2AClient` for delegation |
| **OpenAI + ADK + A2A** | Mixed runtimes in distributed system | Each agent uses its runtime integration, A2A is network layer |

---

## Still Unsure?

**Start simple**:
1. Use your runtime integration (OpenAI or ADK)
2. Start with Tier 1 (guardrails) for prototyping
3. Upgrade to Tier 2 when you need warrants
4. Add A2A only when distributing to separate services

**Rule of thumb**:
- Same language + same process → Runtime integration only
- Cross-service → Add A2A

**Get help**:
- [Discord](https://discord.gg/tenuo)
- [GitHub Discussions](https://github.com/tenuo-ai/tenuo/discussions)
- [Examples](https://github.com/tenuo-ai/tenuo/tree/main/examples)
