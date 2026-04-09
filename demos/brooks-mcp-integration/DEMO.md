# Tenuo + FastMCP Integration Demo

**Audience:** Brooks McMillin — `task-mcp-resource` maintainer
**Goal:** Server-side warrant enforcement on a FastMCP server, closing the
gap where a valid OAuth token + flat scope can bypass tool-level restrictions.

---

## Architecture Overview

```
                           Brooks's stack today
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  Agent (k8s Job)                                                 │
  │  ┌────────────────────┐                                          │
  │  │ PermissionSet      │  OAuth token                             │
  │  │ (READ, WRITE, …)   │──────────┐                              │
  │  │ AgentIdentity      │          │                               │
  │  └────────────────────┘          ▼                               │
  │                         ┌─────────────────┐    tools/call        │
  │                         │ RemoteMCPClient  │──────────────────┐  │
  │                         └─────────────────┘                   │  │
  │                                                               ▼  │
  │                         ┌─────────────────────────────────────┐  │
  │                         │ task-mcp-resource  (FastMCP)        │  │
  │                         │                                     │  │
  │                         │   OAuth / introspection             │  │
  │                         │          │                          │  │
  │                         │          ▼                          │  │
  │                         │   ┌──────────────┐                  │  │
  │  THE GAP ─────────────► │   │  (no tool-   │  Flat scope:    │  │
  │                         │   │   level       │  ["read"]       │  │
  │                         │   │   enforcement)│                  │  │
  │                         │   └──────┬───────┘                  │  │
  │                         │          ▼                          │  │
  │                         │   Tool handler runs                 │  │
  │                         └─────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────────┘

                        With Tenuo warrant middleware
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  Agent (k8s Job)                                                 │
  │  ┌────────────────────┐                                          │
  │  │ PermissionSet      │  OAuth token + warrant in _meta          │
  │  │ AgentIdentity      │──────────┐                               │
  │  └────────────────────┘          │                               │
  │                         ┌────────▼────────┐   tools/call         │
  │                         │ RemoteMCPClient  │──────────────────┐  │
  │                         │ (adds _meta with │                  │  │
  │                         │  warrant + PoP)  │                  │  │
  │                         └─────────────────┘                   │  │
  │                                                               ▼  │
  │                         ┌─────────────────────────────────────┐  │
  │                         │ task-mcp-resource  (FastMCP)        │  │
  │                         │                                     │  │
  │                         │   OAuth / introspection             │  │
  │                         │          │                          │  │
  │                         │          ▼                          │  │
  │                         │   ┌──────────────────────────┐      │  │
  │                         │   │ TenuoMiddleware           │      │  │
  │  CLOSED ────────────►   │   │  • verify warrant chain  │      │  │
  │                         │   │  • check PoP signature   │      │  │
  │                         │   │  • enforce tool + args   │      │  │
  │                         │   │  • strip _meta.tenuo     │      │  │
  │                         │   └──────────┬───────────────┘      │  │
  │                         │          allowed?                   │  │
  │                         │        ╱         ╲                  │  │
  │                         │      YES          NO                │  │
  │                         │       │            │                │  │
  │                         │       ▼            ▼                │  │
  │                         │   Tool runs    isError + deny msg   │  │
  │                         └─────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────────┘

                        Delegation chain (stretch goal)
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │   Issuer (control plane)                                         │
  │      │                                                           │
  │      │ mint root warrant                                         │
  │      │  tools: [get_tasks, search_tasks, create_task, ...]       │
  │      ▼                                                           │
  │   Orchestrator agent                                             │
  │      │                                                           │
  │      │ attenuate (narrow)                                        │
  │      │  tools: [get_tasks, search_tasks]   ← read-only subset   │
  │      ▼                                                           │
  │   Worker agent (k8s Job)                                         │
  │      │                                                           │
  │      │ uses narrowed warrant to call MCP server                  │
  │      ▼                                                           │
  │   task-mcp-resource verifies full chain                          │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

```bash
pip install "tenuo[fastmcp]"
```

This installs `tenuo`, `mcp`, and `fastmcp>=3.2.1`.

---

## Step 1: Generate keys

One issuer key for the demo. In production this lives in a secret store.

```python
from tenuo import SigningKey

# The issuer (control plane) key — mints warrants
issuer_key = SigningKey.generate()
print("Issuer public key (hex):", issuer_key.public_key.to_hex())

# The agent's key — proves holder identity via PoP signatures
agent_key = SigningKey.generate()
print("Agent public key (hex):", agent_key.public_key.to_hex())
```

---

## Step 2: Set up the MCP server with TenuoMiddleware

This is the server-side integration point Brooks described: between
token introspection and tool execution.

```python
# server.py
from fastmcp import FastMCP
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware

ISSUER_PUB_HEX = "..."  # from step 1

# --- Tenuo setup (once at startup) ---
authorizer = Authorizer(
    trusted_roots=[PublicKey.from_hex(ISSUER_PUB_HEX)]
)
verifier = MCPVerifier(authorizer=authorizer)

# --- FastMCP app with Tenuo middleware ---
mcp = FastMCP(
    "task-mcp-resource",
    middleware=[
        # Existing: OAuth / introspection middleware (Brooks's stack)
        # ...
        # New: warrant enforcement — sits after auth, before tools
        TenuoMiddleware(verifier),
    ],
)


# --- Read tools ---
@mcp.tool()
async def get_tasks(project: str) -> str:
    return f"Tasks for {project}: [task-1, task-2, task-3]"


@mcp.tool()
async def search_tasks(query: str) -> str:
    return f"Search results for '{query}': [task-2]"


@mcp.tool()
async def get_wiki_page(slug: str) -> str:
    return f"Wiki page: {slug}"


@mcp.tool()
async def list_articles(category: str = "all") -> str:
    return f"Articles in '{category}': [article-1, article-2]"


# --- Write tools ---
@mcp.tool()
async def create_task(title: str, project: str) -> str:
    return f"Created task '{title}' in {project}"


@mcp.tool()
async def update_task(task_id: str, status: str) -> str:
    return f"Updated {task_id} → {status}"


@mcp.tool()
async def delete_task(task_id: str) -> str:
    return f"Deleted {task_id}"
```

The middleware runs `MCPVerifier.verify` on every `tools/call`. If the
request has no `_meta.tenuo` or the warrant doesn't cover the tool, the
call is **denied** with a structured `isError` result. The tool handler
**never runs**.

---

## Step 3: Mint a read-only warrant

```python
# mint_warrant.py
from tenuo import SigningKey, Warrant, Capability, Pattern

issuer_key = SigningKey.from_hex("...")  # from step 1
agent_key = SigningKey.from_hex("...")   # agent's key

# Read-only warrant: only these four tools, 1 hour TTL
read_warrant = (
    Warrant.mint_builder()
    .capability("get_tasks")
    .capability("search_tasks")
    .capability("get_wiki_page")
    .capability("list_articles")
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(issuer_key)
)

print("Warrant minted, tools:", [c.action for c in read_warrant.capabilities])
```

---

## Step 4: Call with a warrant (allowed)

The agent signs a Proof-of-Possession per call and sends the warrant
in `params._meta.tenuo`. For a root warrant (minted directly by a
trusted issuer, depth 0), a single-warrant encoding is sufficient —
the server can verify the issuer against its trust anchors in one step.

```python
# client_demo.py
import asyncio, time, base64
from tenuo import SigningKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

agent_key = SigningKey.from_hex("...")
read_warrant = ...  # from step 3


async def call_with_warrant(tool_name: str, arguments: dict) -> str:
    """Call an MCP tool with a Tenuo warrant in _meta."""
    # PoP signature: proves the caller holds the warrant's private key
    timestamp = int(time.time())
    pop = read_warrant.sign(agent_key, tool_name, arguments, timestamp=timestamp)

    # Wire format: single warrant + PoP travel in _meta.tenuo.
    # This works for root warrants (depth 0, issuer = trusted root).
    # For delegation chains see Step 7 — use WarrantStack encoding.
    meta = {
        "tenuo": {
            "warrant": read_warrant.to_base64(),
            "signature": base64.b64encode(bytes(pop)).decode(),
        }
    }

    server_params = StdioServerParameters(command="python", args=["server.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments, meta=meta)
            return result


async def main():
    # --- Allowed: read tools ---
    print("=== get_tasks (should PASS) ===")
    r = await call_with_warrant("get_tasks", {"project": "demo"})
    print(r)

    print("\n=== search_tasks (should PASS) ===")
    r = await call_with_warrant("search_tasks", {"query": "urgent"})
    print(r)


asyncio.run(main())
```

Expected: both calls succeed — the warrant covers `get_tasks` and
`search_tasks`.

---

## Step 5: Scope break — write tool denied

Same warrant, call a write tool:

```python
async def scope_break():
    print("=== create_task (should DENY) ===")
    r = await call_with_warrant(
        "create_task",
        {"title": "hacked task", "project": "demo"},
    )
    print(r)
    # → isError: true
    # → "Authorization denied: tool 'create_task' not in warrant capabilities"
```

The server **rejects** the call. The tool handler **never executes**.
Same OAuth token, different tool — blocked at the MCP boundary.

---

## Step 6: (Optional) Mint a constrained write warrant

```python
write_warrant = (
    Warrant.mint_builder()
    .capability("create_task", project=Pattern("demo-*"))
    .holder(agent_key.public_key)
    .ttl(600)  # 10 min
    .mint(issuer_key)
)
```

- `create_task(title="x", project="demo-app")` → **allowed**
- `create_task(title="x", project="production")` → **denied** (Pattern
  mismatch)
- `delete_task(task_id="1")` → **denied** (not in capabilities)

---

## Step 7: Delegation / attenuation

This is the core story for Brooks's orchestrator → worker architecture.
Today he does `AgentIdentity.delegate_to()` with `PermissionSet`
intersection in Python. With warrants, delegation is **cryptographic**
and enforced **at the MCP server**, not in agent code.

### How delegation works

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                    KEY SETUP (once per identity)                    │
 │                                                                    │
 │  issuer_key       = SigningKey.generate()   ← control plane        │
 │  orchestrator_key = SigningKey.generate()   ← orchestrator agent   │
 │  worker_key       = SigningKey.generate()   ← worker agent (Job)   │
 │                                                                    │
 │  MCP server trusts only:  issuer_key.public_key                    │
 │  (configured in Authorizer trusted_roots)                          │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────┐
 │                    STEP A: Issuer mints root warrant                │
 │                                                                    │
 │  issuer_key ──mint──► root_warrant                                 │
 │                        │                                           │
 │                        ├─ holder: orchestrator_key.public_key      │
 │                        ├─ tools:  get_tasks, search_tasks,         │
 │                        │          create_task, update_task          │
 │                        ├─ ttl:    1 hour                           │
 │                        └─ issuer: issuer_key.public_key            │
 │                                                                    │
 │  The orchestrator receives this warrant and can use ALL four tools. │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────┐
 │                    STEP B: Orchestrator attenuates for worker       │
 │                                                                    │
 │  orchestrator_key ──grant──► worker_warrant                        │
 │                                │                                   │
 │                                ├─ holder: worker_key.public_key    │
 │                                ├─ tools:  get_tasks, search_tasks  │
 │                                │          (ONLY read tools)        │
 │                                ├─ ttl:    30 min (≤ parent)        │
 │                                ├─ issuer: orchestrator_key.pub     │
 │                                └─ parent: root_warrant.id          │
 │                                                                    │
 │  The child warrant is SIGNED by the orchestrator's key.            │
 │  It can only NARROW — never add tools or widen constraints.        │
 │  Rust enforces: child.capabilities ⊆ parent.capabilities           │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────┐
 │                    STEP C: Worker calls MCP server                  │
 │                                                                    │
 │  Worker signs a PoP with worker_key and sends a WarrantStack       │
 │  — the FULL delegation chain [root, worker] as a CBOR array:       │
 │                                                                    │
 │    tools/call                                                      │
 │    ├─ name: "get_tasks"                                            │
 │    ├─ arguments: { "project": "demo" }                             │
 │    └─ _meta:                                                       │
 │         └─ tenuo:                                                  │
 │              ├─ warrant:   <WarrantStack([root, worker]) base64>   │
 │              └─ signature: <PoP signature as base64>               │
 │                                                                    │
 │  The child warrant contains parent_hash = SHA-256(root.payload)    │
 │  as a cryptographic commitment. But the full parent CBOR is NOT    │
 │  embedded inside the child — instead the full chain is sent as     │
 │  a WarrantStack (ordered CBOR array) so the server can verify      │
 │  every link independently.                                         │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────┐
 │                    STEP D: Server verifies the chain                │
 │                                                                    │
 │  Authorizer.check_chain([root, worker], tool, args, pop)           │
 │                                                                    │
 │  Rust checks (all must pass):                                      │
 │                                                                    │
 │    1. Decode WarrantStack → [root_warrant, worker_warrant]         │
 │    2. Root trust:                                                  │
 │         root_warrant.issuer == issuer_key.pub                      │
 │         issuer_key.pub ∈ trusted_roots                  ✓          │
 │    3. Chain linkage:                                               │
 │         worker_warrant.issuer == root.holder (orch_pub)  ✓         │
 │         worker_warrant.parent_hash == SHA-256(root)      ✓         │
 │    4. Monotonic attenuation:                                       │
 │         worker tools ⊆ root tools                       ✓          │
 │         worker constraints ≥ root constraints            ✓          │
 │    5. TTL not expired on any link                        ✓          │
 │    6. PoP signature valid for worker_key.pub             ✓          │
 │    7. Tool "get_tasks" ∈ worker_warrant.capabilities     ✓          │
 │                                                                    │
 │  → ALLOWED                                                         │
 │                                                                    │
 │  If the worker tries "create_task":                                │
 │    7. Tool "create_task" ∈ worker_warrant.capabilities   ✗         │
 │  → DENIED  (tool not in child warrant, even though parent has it)  │
 └─────────────────────────────────────────────────────────────────────┘
```

### Code: full delegation lifecycle

```python
# delegation_demo.py
import time, base64
from tenuo import SigningKey, Warrant, Capability, Pattern, Authorizer
from tenuo_core import encode_warrant_stack

# === KEY SETUP ===

issuer_key       = SigningKey.generate()   # control plane
orchestrator_key = SigningKey.generate()   # orchestrator agent
worker_key       = SigningKey.generate()   # worker agent (k8s Job)


# === STEP A: Issuer mints root warrant for orchestrator ===

root_warrant = (
    Warrant.mint_builder()
    .capability("get_tasks")
    .capability("search_tasks")
    .capability("create_task")
    .capability("update_task")
    .holder(orchestrator_key.public_key)
    .ttl(3600)
    .mint(issuer_key)
)

print(f"Root warrant: {root_warrant.id}")
print(f"  holder:  orchestrator")
print(f"  tools:   {[c.action for c in root_warrant.capabilities]}")
print(f"  issuer:  issuer (trusted root)")
print()


# === STEP B: Orchestrator attenuates for worker ===
# This is the equivalent of AgentIdentity.delegate_to() +
# PermissionSet intersection, but cryptographic.

worker_warrant = (
    root_warrant.grant_builder()
    .capability("get_tasks")        # keep
    .capability("search_tasks")     # keep
    # create_task, update_task: NOT granted → dropped
    .holder(worker_key.public_key)
    .ttl(1800)                      # 30 min (must be ≤ parent's remaining)
    .grant(orchestrator_key)        # orchestrator signs (proves they hold parent)
)

print(f"Worker warrant: {worker_warrant.id}")
print(f"  holder:  worker")
print(f"  tools:   {[c.action for c in worker_warrant.capabilities]}")
print(f"  issuer:  orchestrator")
print(f"  parent:  {root_warrant.id}")
print()


# === STEP C: Worker calls the MCP server ===

def build_meta(chain, signing_key, tool_name, arguments):
    """Build the _meta.tenuo envelope for a delegation chain.

    chain: list of Warrant objects from root to leaf (e.g. [root, worker]).
           For a root warrant with no delegation, pass [root_warrant].
    signing_key: the leaf warrant holder's key (for PoP).
    """
    leaf = chain[-1]
    timestamp = int(time.time())
    pop = leaf.sign(signing_key, tool_name, arguments, timestamp=timestamp)

    # WarrantStack: encodes the full chain as a single base64 CBOR array.
    # The server decodes this, walks root→leaf verifying every link.
    stack_b64 = encode_warrant_stack(chain)

    return {
        "tenuo": {
            "warrant": stack_b64,
            "signature": base64.b64encode(bytes(pop)).decode(),
        }
    }


# Full chain: [root_warrant, worker_warrant]  (root first, leaf last)
chain = [root_warrant, worker_warrant]

meta = build_meta(chain, worker_key, "get_tasks", {"project": "demo"})


# === STEP D: Server verifies (simulated here) ===

# Server only trusts the issuer key — not orchestrator, not worker
authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

# check_chain verifies the full delegation path:
#   root.issuer ∈ trusted_roots, chain linkage, monotonic attenuation,
#   TTLs, PoP, and tool capabilities — all in one call.

# Allowed: get_tasks is in worker_warrant
from tenuo_core import decode_warrant_stack_base64
decoded_chain = decode_warrant_stack_base64(meta["tenuo"]["warrant"])
pop_bytes = base64.b64decode(meta["tenuo"]["signature"])

try:
    result = authorizer.check_chain(
        decoded_chain, "get_tasks", {"project": "demo"}, signature=pop_bytes
    )
    print(f"get_tasks:    allowed=True  (chain_length={result.chain_length})")
except Exception as e:
    print(f"get_tasks:    denied  reason={e}")

# Denied: create_task is NOT in worker_warrant (only in parent)
meta_write = build_meta(chain, worker_key, "create_task",
                        {"title": "test", "project": "demo"})
decoded_chain2 = decode_warrant_stack_base64(meta_write["tenuo"]["warrant"])
pop_bytes2 = base64.b64decode(meta_write["tenuo"]["signature"])

try:
    authorizer.check_chain(
        decoded_chain2, "create_task", {"title": "test", "project": "demo"},
        signature=pop_bytes2
    )
    print(f"create_task:  allowed=True")
except Exception as e:
    print(f"create_task:  denied  reason={e}")
```

Expected output:

```
Root warrant: tnu_wrt_...
  holder:  orchestrator
  tools:   ['get_tasks', 'search_tasks', 'create_task', 'update_task']
  issuer:  issuer (trusted root)

Worker warrant: tnu_wrt_...
  holder:  worker
  tools:   ['get_tasks', 'search_tasks']
  issuer:  orchestrator
  parent:  tnu_wrt_...

get_tasks:    allowed=True  (chain_length=2)
create_task:  denied  reason=...tool 'create_task' not in warrant...
```

> **Note:** The code above uses `Authorizer.check_chain()` directly to show
> the delegation verification path clearly. In a real FastMCP deployment,
> `MCPVerifier` + `TenuoMiddleware` will handle WarrantStack decoding
> automatically (chain support is being added to `MCPVerifier` — see the
> A2A server adapter for the pattern already shipping).

### What happens under the hood

```
  Worker's tools/call request
        │
        ▼
  ┌─────────────────────────────────────────────────┐
  │ _meta.tenuo.warrant (base64 CBOR WarrantStack)  │
  │                                                 │
  │   CBOR array of warrants, root-first:           │
  │                                                 │
  │   [0] root_warrant                              │
  │       capabilities: [get_, search_,             │
  │                      create_, update_tasks]     │
  │       holder: orchestrator_pub                  │
  │       issuer: issuer_pub  ◄──── trust anchor    │
  │                                                 │
  │   [1] worker_warrant                            │
  │       capabilities: [get_tasks, search_tasks]   │
  │       holder: worker_pub                        │
  │       issuer: orchestrator_pub                  │
  │       parent_hash: SHA-256(root.payload) ──┐    │
  │                                            │    │
  │       The parent_hash cryptographically    │    │
  │       binds this warrant to its parent.    │    │
  │       Tampering with root breaks the hash. │    │
  │                                                 │
  │ _meta.tenuo.signature (base64)                  │
  │   = PoP signed by worker_key over               │
  │     (tool_name, arguments, timestamp)           │
  └─────────────────────────────────────────────────┘
        │
        ▼
  Authorizer.check_chain([root, worker], tool, args, pop):
        │
        ├── root.issuer ∈ trusted_roots?          ✓
        ├── root signature valid?                 ✓
        ├── worker.issuer == root.holder?          ✓  (delegation authority)
        ├── worker.parent_hash == SHA-256(root)?   ✓  (chain integrity)
        ├── worker signature valid?               ✓
        ├── worker capabilities ⊆ root?            ✓  (monotonic attenuation)
        ├── TTL valid on all links?               ✓
        ├── PoP valid for worker_pub?             ✓
        └── tool in worker's capabilities?        ✓ or ✗
```

### Mapping to Brooks's delegation model

| Brooks today | Tenuo warrant chain |
|---|---|
| `AgentIdentity.delegate_to(worker)` | `root_warrant.grant_builder().holder(worker_pub).grant(orch_key)` |
| `PermissionSet` intersection (READ ∩ WRITE = READ) | `.capability("get_tasks").capability("search_tasks")` — only list what the child gets; omitting tools drops them |
| Enforcement: agent Python checks before call | Enforcement: `Authorizer.check_chain` on the **server** verifies the full chain — works even if something calls the server outside the agent framework |
| Trust: implicit (agent code is correct) | Trust: **cryptographic** — each link is signed; the full chain travels as a WarrantStack; server walks root→leaf to the trust anchor |
| Revocation: redeploy agent code | Revocation: warrant TTL expires; or revoke via signed revocation list (SRL) |

### Why this matters for the k8s Job architecture

Brooks's worker agents run as k8s Jobs and connect to MCP via
`RemoteMCPClient`. Today, if a Job is compromised or misconfigured, it
has the OAuth token's full scope. With delegation:

1. The orchestrator issues a **task-scoped, short-lived** warrant to
   each Job — only the tools needed for that specific task.
2. The worker sends the full **WarrantStack** (chain from root to leaf)
   with each call, so the MCP server can verify it **without calling
   back** to any auth service.
3. Even if the Job is compromised, the attacker can only use the tools
   in the narrowed warrant, and only until the TTL expires.

---

## Step 8: (Optional) Defense in depth with Lakera

This is a narrative point, not code:

```
                       ┌───────────────────────────────────┐
                       │         Defense in depth           │
                       │                                   │
  Incoming tool call ──┤                                   │
                       │  Layer 1: Tenuo warrant           │
                       │    "Can this agent call this      │
                       │     tool with these arguments?"   │
                       │           │                       │
                       │           ▼                       │
                       │  Layer 2: Lakera Guard            │
                       │    "Is the content within the     │
                       │     allowed scope an injection    │
                       │     attempt?"                     │
                       │           │                       │
                       │           ▼                       │
                       │  Tool executes                    │
                       └───────────────────────────────────┘
```

- **Warrant** prevents **scope escalation** — an agent can't call
  tools it wasn't granted, even if prompt-injected.
- **Lakera Guard** catches **injection within scope** — malicious
  content inside arguments that the warrant structurally allows.
- Neither alone is complete. Together they cover both capability
  boundaries and content-level abuse.

---

## Key concept mapping

| Brooks's stack               | Tenuo equivalent                                    |
|------------------------------|-----------------------------------------------------|
| `PermissionSet` (READ, …)   | Capabilities on the warrant (tool allowlist + args)  |
| `AgentIdentity.delegate_to` | `warrant.grant_builder()` (attenuation chain)        |
| `PermissionSet` intersection | Attenuation: child ⊆ parent, enforced in Rust        |
| OAuth scope `["read"]`       | Warrant: fine-grained per-tool + per-argument         |
| Enforcement in agent Python  | `TenuoMiddleware` on FastMCP server                   |
| Lakera Guard                 | Complements warrant — content abuse inside scope      |

---

## What this session does NOT cover

- Migrating all 40 tools (pick 4–6 representative ones)
- Rewriting `mcp-auth-framework` (keep OAuth; add warrant sidecar)
- Production k8s key management (follow-up)
- Tenuo Cloud telemetry setup (follow-up if interested)
