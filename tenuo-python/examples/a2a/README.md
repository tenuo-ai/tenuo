# Tenuo A2A Examples

Agent-to-Agent (A2A) communication with warrant-based authorization.

## What is A2A?

A2A enables secure task delegation between agents with cryptographic warrants that specify exactly what each agent is allowed to do.

```
┌─────────────┐                     ┌─────────────┐
│   Agent A   │   Task + Warrant    │   Agent B   │
│ (Orchestrator)│──────────────────▶│  (Worker)   │
│             │                     │             │
│             │◀──────────────────  │             │
│             │      Result         │             │
└─────────────┘                     └─────────────┘

Warrant says: "Agent B can only search arxiv.org for this task"
```

**Use A2A when:**
- Multiple agents delegate tasks to each other
- You need cryptographic proof of authorization
- Least-privilege access control is required
- Agents run in separate processes/services

**Don't use A2A when:**
- Single-agent tool enforcement (use `tenuo.openai` or `tenuo.langchain`)
- All tools run in the same process as the LLM

---

## Examples in This Directory

### 1. [`demo.py`](demo.py) - Research Pipeline (Intro)

Multi-agent research system with attack demonstrations.

**What it shows:**
- Paper Search agent with UrlSafe constraint (blocks SSRF)
- Summarizer agent with Subpath constraint (blocks path traversal)
- Warrant attenuation for least-privilege delegation
- Attack scenarios: prompt injection, warrant replay, privilege escalation

**Run:**
```bash
# Default: normal + attack scenarios
python demo.py

# Just normal flow
python demo.py run

# Just attack simulation
python demo.py attack

# Non-interactive (for CI)
python demo.py --non-interactive
```

**Architecture:**
```
User → Orchestrator → Paper Search Agent (fetch_url)
                   → Summarizer Agent (read_file)
```

### 2. [`streaming_demo.py`](streaming_demo.py) - Streaming Responses

Long-running tasks with real-time progress updates via Server-Sent Events (SSE).

**What it shows:**
- Streaming task execution with `send_task_streaming()`
- Progress updates as Server-Sent Events
- Generator skills that yield intermediate results
- Stream timeout protection (DoS prevention)
- Comparison: streaming vs non-streaming tasks

**Run:**
```bash
python streaming_demo.py
```

**Use cases:**
- Data analysis with progress bars
- File processing with chunk updates
- Long-running computations
- Real-time monitoring

### 3. [`crewai_delegation.py`](crewai_delegation.py) - CrewAI Integration

Content creation crew with warrant-based A2A delegation.

**What it shows:**
- CrewAI agents using A2A for secure task delegation
- Researcher, Writer, and Editor with separate warrants
- Warrant attenuation for least-privilege access
- Integration pattern: CrewAI + A2A servers
- Security: Each crew member has narrowed capabilities

**Run:**
```bash
# Install CrewAI first
uv pip install crewai

# Run demo
python crewai_delegation.py
```

**Architecture:**
```
Content Crew (CrewAI)
├─ Researcher → Research Agent (A2A)
├─ Writer     → Storage Agent (A2A)
└─ Editor     → Storage Agent (A2A)
```

### 4. [`multi_hop_delegation.py`](multi_hop_delegation.py) - Multi-Hop Chains

3-hop delegation chain: Orchestrator → Analyst → Responder.

**What it shows:**
- Multi-hop warrant chain validation
- Monotonic privilege attenuation at each hop
- Chain depth: Control Plane → Orchestrator → Analyst → Responder
- Constraint narrowing: Cidr(0.0.0.0/0) → Exact(203.0.113.5)
- TTL reduction: 3600s → 1800s → 600s
- Attack demonstrations: privilege escalation, forged warrants, broken chains

**Run:**
```bash
python multi_hop_delegation.py
```

**Architecture:**
```
Control Plane (root authority)
      │
      ├─ Orchestrator (broad warrant)
      │     │
      │     └─ Analyst (read + query + delegate block)
      │           │
      │           └─ Responder (block single IP only)
```

---

## When to Use Which Pattern?

| Pattern | Use When | Example |
|---------|----------|---------|
| **A2A** | Multi-agent delegation across network | Orchestrator → Research Agent → Analyst Agent |
| **Temporal** | Durable workflows with multi-step authorization | ETL pipeline with warrant rotation per stage |
| **LangChain** | Single-agent tool authorization | Chatbot with constrained tool access |
| **Google ADK** | Google's agent framework + constraints | ADK agent with Subpath/UrlSafe constraints |
| **OpenAI** | OpenAI SDK with function calling | GPT-4 with warrant-enforced tools |

---

## Comparison: A2A vs Direct HTTP

### Before (Direct HTTP with API Keys)

```python
# Orchestrator calls worker with API key
import httpx

async def delegate_task():
    response = await httpx.post(
        "https://worker.example.com/api/search",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={"query": "papers on AI safety"},
    )
    return response.json()
```

**Problems:**
- ❌ API key gives full access (no per-task constraints)
- ❌ Can't prove what was authorized after the fact
- ❌ Worker trusts orchestrator to enforce constraints
- ❌ No protection if API key leaks

### After (A2A with Warrants)

```python
# Orchestrator delegates with warrant
from tenuo.a2a import A2AClient
from tenuo.constraints import UrlSafe

async def delegate_task(my_warrant, my_key):
    # Attenuate warrant for this specific task
    task_warrant = my_warrant.attenuate(
        signing_key=my_key,
        holder=worker_public_key,
        capabilities={
            "search": {"url": UrlSafe(allow_domains=["arxiv.org"])}
        },
        ttl_seconds=300,
    )

    client = A2AClient("https://worker.example.com")
    return await client.send_task(
        warrant=task_warrant,
        skill="search",
        arguments={"query": "papers on AI safety", "url": "https://arxiv.org"},
        signing_key=my_key,
    )
```

**Benefits:**
- ✅ Warrant scoped to single task with constraints
- ✅ Cryptographic proof of authorization (Ed25519 signatures)
- ✅ Worker validates constraints (doesn't trust orchestrator)
- ✅ Stolen warrant only works for approved URLs + TTL

---

## Quick Start (5 minutes)

### 1. Install

```bash
uv pip install "tenuo[a2a]"
```

### 2. Create Server (Worker)

```python
# worker.py
from tenuo.a2a import A2AServerBuilder
from tenuo.constraints import UrlSafe

server = (A2AServerBuilder()
    .name("Research Worker")
    .url("http://localhost:8000")
    .key(worker_key)
    .accept_warrants_from(orchestrator_key.public_key)
    .build())

@server.skill("search", constraints={"url": UrlSafe})
async def search(query: str, url: str) -> dict:
    # Only allowed URLs pass through
    return await fetch_papers(query, url)

# Run: uvicorn worker:server.app
```

### 3. Create Client (Orchestrator)

```python
# orchestrator.py
from tenuo.a2a import A2AClient
from tenuo import Warrant
from tenuo.constraints import UrlSafe

# Issue warrant for this task
task_warrant = (Warrant.mint_builder()
    .capability("search", url=UrlSafe(allow_domains=["arxiv.org"]))
    .holder(worker_key.public_key)
    .ttl(300)
    .mint(orchestrator_key))

# Call worker
client = A2AClient("http://localhost:8000")
result = await client.send_task(
    warrant=task_warrant,
    skill="search",
    arguments={"query": "AI safety", "url": "https://arxiv.org"},
    signing_key=orchestrator_key,
)
```

---

## Example Progression

These examples build on each other:

| Example | Complexity | Concepts |
|---------|-----------|----------|
| **demo.py** | ⭐ Basic | Single-hop delegation, constraints, attacks |
| **streaming_demo.py** | ⭐⭐ Intermediate | SSE streaming, progress updates, timeouts |
| **crewai_delegation.py** | ⭐⭐ Intermediate | Framework integration, crew workflows |
| **multi_hop_delegation.py** | ⭐⭐⭐ Advanced | Warrant chains, multi-hop validation, deep attenuation |

**Recommended learning path:**
1. Start with `demo.py` to understand basic A2A patterns
2. Try `streaming_demo.py` to see long-running tasks
3. Explore `crewai_delegation.py` for framework integration
4. Study `multi_hop_delegation.py` for production-grade delegation

## Coming Soon

**Planned examples:**
- **LangChain + A2A**: LangGraph agents using A2A for sub-tasks
- **OpenAI Swarm + A2A**: Swarm framework with warrant delegation
- **Performance benchmark**: Latency and throughput measurements

**Want to contribute?** See [CONTRIBUTING.md](../../CONTRIBUTING.md)

---

## Framework Integrations

### With Google ADK

See [`examples/google_adk_a2a_incident/`](../google_adk_a2a_incident/) for incident response demo with:
- Multi-process architecture (3 separate agents)
- Real HTTP calls between agents
- Warrant chain validation
- Attack demonstrations

### With Temporal

See [`examples/temporal/`](../temporal/) for durable workflow patterns:
- Per-stage warrant rotation
- Inline attenuation with child workflows
- Transparent PoP computation

---

## Documentation

- **[A2A Integration Guide](../../../docs/a2a.md)** - Complete API reference
- **[Constraints Reference](../../../docs/constraints.md)** - Available constraint types
- **[Security Model](../../../docs/security.md)** - Threat model and mitigations

---

## Testing Your A2A Server

### Discovery

```bash
# Check agent capabilities
curl http://localhost:8000/.well-known/agent.json
```

### Send Task (with curl)

```bash
# Create warrant (use tenuo CLI or Python)
WARRANT="..."  # Base64-encoded JWT

# Send task
curl -X POST http://localhost:8000/a2a \
  -H "Content-Type: application/json" \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -d '{
    "jsonrpc": "2.0",
    "method": "task/send",
    "params": {
      "task": {
        "id": "task_123",
        "message": "Search for papers",
        "skill": "search",
        "arguments": {"query": "AI safety"}
      }
    },
    "id": 1
  }'
```

---

## Common Issues

### Q: "Skill not found in warrant"

**Problem:** Tool name doesn't match warrant skill name.

**Fix:** Use skill mapping:
```python
guard = (GuardBuilder()
    .with_warrant(warrant, key)
    .map_skill("search_tool", "search")  # tool_name -> skill_name
    .build())
```

### Q: "Constraint violation" but warrant looks correct

**Problem:** Argument values don't satisfy constraint.

**Debug:**
```python
from tenuo.a2a import dry_run

result = await dry_run(
    server, warrant, "search",
    arguments={"url": "https://evil.com"}
)
print(result)  # Shows which constraint failed
```

### Q: Server returns "Untrusted issuer"

**Problem:** Warrant issuer not in server's `trusted_issuers` list.

**Fix:** Add issuer's public key to server config:
```python
server = A2AServer(
    ...,
    trusted_issuers=[orchestrator_key.public_key],  # Add all trusted issuers
)
```

---

## Need Help?

- **Issues**: [GitHub Issues](https://github.com/tenuo-ai/tenuo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tenuo-ai/tenuo/discussions)
- **Docs**: [docs.tenuo.ai](https://docs.tenuo.ai)
