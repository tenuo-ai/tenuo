# Tenuo: Capability-Based Authorization for AI Agents

## System Specification v1

---

## Executive Summary

Tenuo provides **stateless, flow-aware authorization** for agentic AI systems. Authority is bound to **tasks**, not **compute**. Warrants are self-contained capability tokens that travel with requests, require proof-of-possession to use, and are verified locally without control plane calls at runtime.

---

## Core Model

### The Problem

IAM binds authority to compute:

```
Pod starts → Gets role → Role for pod lifetime → Static scope
```

An agent processing Task A and Task B has the same permissions for both, even if Task A requires read-only access and Task B requires write access. The permission that enables one task becomes liability in another.

### The Solution

Tenuo binds authority to tasks:

```
Task submitted → Warrant minted (scoped to task) → Agent executes → Warrant expires
```

Each task carries exactly the authority it needs. No more, no less.

---

## Invariants

| Invariant | Description |
|-----------|-------------|
| **Mandatory PoP** | Every warrant bound to a public key. Usage requires proof-of-possession. |
| **Warrant per task** | Authority scoped to task, not compute. |
| **Stateless verification** | Authorization is local. No control plane calls during execution. |
| **Monotonic attenuation** | Child scope ⊆ parent scope. Always. |
| **Self-contained** | Warrant carries everything needed for verification. |

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Scoped** | Warrant specifies allowed tools and constraints |
| **Temporal** | TTL checked on every authorization |
| **Bound** | PoP required; stolen warrant useless without private key |
| **Delegatable** | Parent mints narrower children; signature chain proves lineage |
| **Revocable** | Signed revocation list checked locally |

---

## Threat Model

### Protected

| Threat | Protection |
|--------|------------|
| **Prompt injection** | LLM invokes tools through wrappers; attenuated scope limits damage |
| **Confused deputy** | Node can only use tools in its warrant |
| **Credential theft** | Warrant useless without private key (PoP) |
| **Stale permissions** | TTL forces expiration |
| **Privilege escalation** | Monotonic attenuation; child cannot exceed parent |

### Not Protected

| Threat | Why |
|--------|-----|
| **Container compromise** | Attacker has keypair + warrant; can bypass wrappers |
| **Malicious node code** | Same trust boundary as authorization logic |
| **Control plane compromise** | Can mint arbitrary warrants |

For container compromise, Tenuo limits damage to current warrant's scope and TTL. For stronger isolation, deploy nodes as separate containers with separate keypairs.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CONTROL PLANE                                   │
│                                                                              │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│   │  Issuer Keys    │    │   Policy        │    │  Revocation     │         │
│   │  (sign warrants)│    │   Engine        │    │  Manager (SRL)  │         │
│   └────────┬────────┘    └─────────────────┘    └────────┬────────┘         │
└────────────┼─────────────────────────────────────────────┼───────────────────┘
             │ (task submission)                           │ (periodic sync)
             ▼                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GATEWAY                                         │
│                                                                              │
│   1. Authenticate user                                                       │
│   2. Authorize request                                                       │
│   3. Mint warrant (scoped to task, bound to agent key)                       │
│   4. Forward with X-Tenuo-Warrant header                                     │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AGENT POD                                       │
│                                                                              │
│   Volume: /var/run/secrets/tenuo/keypair  (identity only, no authority)      │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Middleware: Extract warrant → Set ContextVar → Call handler        │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ ContextVar                            │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │  Application Code (NO TENUO IMPORTS)                                │   │
│   │  async def process(req): return await agent.invoke(req.prompt)      │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ ContextVar                            │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │  SecureGraph: Attenuate per node → Set ContextVar                   │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ ContextVar                            │
│   ┌──────────────────────────────────▼──────────────────────────────────┐   │
│   │  Protected Tools: PoP signature → Authorize → Execute               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Warrant

Self-contained capability token.

```
┌─────────────────────────────────────────────────┐
│                    WARRANT                       │
├─────────────────────────────────────────────────┤
│  id: "wrt_abc123"                               │
│  tool: "search,read_file"                       │
│  constraints:                                    │
│    path: Pattern("/data/project-alpha/*")       │
│    max_results: Range(1, 100)                   │
│  ttl_seconds: 300                               │
│  issued_at: 1705312200                          │
│  expires_at: 1705312500                         │
│  issuer: <public_key>                           │
│  authorized_holder: <public_key>  ← Mandatory   │
│  session_id: "sess_xyz789"        ← Audit only  │
│  signature: <issuer_signature>                  │
└─────────────────────────────────────────────────┘
```

**Operations:**
```python
# Create (at gateway)
warrant = Warrant.create(
    tool="search,read_file",
    constraints={"path": Pattern("/data/*")},
    ttl_seconds=300,
    keypair=issuer_keypair,
    authorized_holder=agent_public_key,  # Mandatory PoP
    session_id="sess_xyz789",
)

# Attenuate (local)
child = warrant.attenuate(
    tool="read_file",
    constraints={"path": Pattern("/data/project-1/*")},
    keypair=agent_keypair,
)

# Authorize (local)
pop_sig = warrant.create_pop_signature(keypair, tool, args)
authorized = warrant.authorize(tool, args, signature=pop_sig)
```

---

### 2. Middleware

Extracts warrant from transport, sets ContextVar.

**FastAPI:**
```python
from tenuo import Warrant, Keypair
from tenuo.decorators import set_warrant_context, set_keypair_context

KEYPAIR = Keypair.from_file("/var/run/secrets/tenuo/keypair")

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        return await call_next(request)
    
    warrant = Warrant.from_base64(warrant_b64)
    
    if not warrant.is_bound_to(KEYPAIR.public_key()):
        raise HTTPException(403, "Warrant not bound to this agent")
    if warrant.is_expired:
        raise HTTPException(403, "Warrant expired")
    
    with set_warrant_context(warrant), set_keypair_context(KEYPAIR):
        return await call_next(request)
```

**Queue:**
```python
async def process_message(message: QueueMessage):
    warrant = Warrant.from_base64(message.metadata["tenuo_warrant"])
    
    if not warrant.is_bound_to(KEYPAIR.public_key()):
        raise AuthorizationError("Warrant not bound to this agent")
    if warrant.is_expired:
        raise AuthorizationError("Warrant expired")
    
    with set_warrant_context(warrant), set_keypair_context(KEYPAIR):
        return await handler(message.body)
```

---

### 3. SecureGraph (Future)

See [SecureGraph Design Spec](./langgraph-spec.md).

---

### 4. LangChain Integration

See [LangChain Integration Spec](./langchain-spec.md).

def read_file(path: str) -> str: ...

# Wrap at setup
secure_tools = protect_tools(
    tools=[search, read_file],
    config="tenuo.yaml",
)

# Use in agent
agent = AgentExecutor(agent=base_agent, tools=secure_tools)
```

---

### 5. Revocation (Optional)

Async SRL sync:

```python
# Sidecar or background task
async def srl_sync_loop():
    while True:
        response = await http.get(SRL_URL)
        srl = SignedRevocationList.from_bytes(response.content)
        atomic_write("/var/run/tenuo/srl", srl.to_bytes())
        await asyncio.sleep(30)
```

---

## Data Flow

### Per-Request

```
Gateway                          Agent
   │                               │
   │ 1. Authenticate user          │
   │ 2. Mint warrant               │
   │                               │
   │ POST /process                 │
   │ X-Tenuo-Warrant: <warrant>    │
   │──────────────────────────────►│
   │                               │
   │                    Middleware │ Extract, verify, set ContextVar
   │                               │
   │                   Application │ agent.invoke() - no Tenuo code
   │                               │
   │                   SecureGraph │ Attenuate per node
   │                               │
   │                        Tools  │ PoP + authorize + execute
   │                               │
   │◄──────────────────────────────│
```

---

## API Surface

### Core (`tenuo`)

```python
Warrant, Keypair, PublicKey, Authorizer
Pattern, Regex, Exact, OneOf, Range
SignedRevocationList, RevocationManager
```

### Decorators (`tenuo.decorators`)

```python
set_warrant_context(warrant) -> ContextManager
set_keypair_context(keypair) -> ContextManager
get_warrant_context() -> Optional[Warrant]
get_keypair_context() -> Optional[Keypair]
```

### LangChain (`tenuo.langchain`)

```python
protect_tools(tools, config=None) -> list[Callable]
protect_tool(tool, name=None) -> Callable
```

### LangGraph (`tenuo.langgraph`)

```python
SecureGraph(graph, config)
TENUO_WARRANT, TENUO_STACK  # State keys
```

---

## Configuration

### SecureGraph

```yaml
version: "1"

settings:
  max_stack_depth: 16
  allow_unlisted_nodes: false

nodes:
  supervisor:
    role: supervisor
    
  researcher:
    attenuate:
      tools: [search, read_file]
      constraints:
        path:
          pattern: "/data/${state.project_id}/*"
          validate: "^[a-zA-Z0-9_-]+$"
```

### Constraints

| Type | Config | Description |
|------|--------|-------------|
| Pattern | `pattern: "/data/*"` | Glob |
| Regex | `regex: "^[a-z]+$"` | Regex |
| Exact | `exact: "production"` | Exact match |
| OneOf | `enum: [a, b, c]` | Allowed values |
| Range | `min: 0, max: 100` | Numeric range |

### Dynamic Interpolation

```yaml
path:
  pattern: "/data/${state.project_id}/*"
  validate: "^[a-zA-Z0-9_-]+$"
```

State values validated before interpolation.

---

## Deployment

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: research-agent
spec:
  template:
    spec:
      containers:
      - name: agent
        image: myorg/research-agent:v1
        env:
        - name: TENUO_KEYPAIR_PATH
          value: /var/run/secrets/tenuo/keypair
        volumeMounts:
        - name: keypair
          mountPath: /var/run/secrets/tenuo
          readOnly: true
      
      volumes:
      - name: keypair
        secret:
          secretName: research-agent-keypair
```

### What's NOT Needed

| Component | Why |
|-----------|-----|
| Init container | Warrant comes with task |
| Refresh sidecar | No renewal; warrant expires with task |
| Control plane (runtime) | All authorization local |

---

## Checkpointing

Tenuo works with LangGraph checkpointing. The warrant is stored in checkpoint state and restored on resume.

**With mandatory PoP, this is safe:** Leaked checkpoint = leaked warrant bytes, but warrant requires private key to use.

### Limitation

If warrant TTL expires while checkpointed, resume fails:

```python
# On resume
warrant = state.get("__tenuo_warrant__")
if warrant.is_expired:
    raise AuthorizationError(
        "Cannot resume: warrant expired. Resubmit task for fresh warrant."
    )
```

### Recommendations

| Task Duration | TTL | Checkpointing |
|---------------|-----|---------------|
| < 5 min | 5-10 min | Not needed |
| 5-30 min | 30-60 min | Works if resumed quickly |
| > 1 hour | N/A | Break into subtasks |

For long workflows, decompose into subtasks. Each subtask gets its own warrant from gateway.

---

## Audit Logging

All authorization events logged as structured JSON:

```json
{
  "event_type": "authorization_success",
  "warrant_id": "wrt_xyz789",
  "session_id": "sess_task123",
  "tool": "read_file",
  "constraints": {"path": "/data/alpha/report.csv"},
  "@timestamp": "2024-01-15T10:30:00Z"
}
```

Event types:
- `authorization_success` / `authorization_failure`
- `warrant_attenuated`
- `pop_verified` / `pop_failed`

---

## v0.1 Scope

### Included

| Component | Status |
|-----------|--------|
| Warrant + mandatory PoP | ✅ |
| Middleware (FastAPI) | ✅ (Pattern) |
| SecureGraph | ❌ Future |
| protect_tools | ❌ Removed |
| Dynamic constraints `${state.*}` | ❌ Future |
| Audit logging | ❌ Future |
| SRL sync | ✅ Optional |

### Not Included (Future)

| Component | Reason | When |
|-----------|--------|------|
| TenuoCheckpointer | Most tasks < TTL | v0.2 if requested |
| Session management | Stateless model | Not planned |
| Control plane re-auth | Violates stateless | Not planned |
| Warrant renewal | Violates security model | Not planned |
| Human-in-the-loop | Requires orchestration | v0.2 |

---

## Summary

| Principle | Implementation |
|-----------|----------------|
| Authority bound to task | Warrant minted per-request at gateway |
| Stateless | Local verification, no runtime control plane |
| Mandatory PoP | Stolen warrant is useless |
| Clean application code | ContextVar injection |
| Honest threat model | Protects LLM, not shell access |

**The agent has identity (keypair), not authority. Authority arrives with each task.**