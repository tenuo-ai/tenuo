---
title: A2A Integration
description: Warrant-based authorization for inter-agent communication
---

# Tenuo A2A Integration

## Overview

Tenuo A2A adds **warrant-based authorization** to agent-to-agent communication. When Agent A sends a task to Agent B, it presents a warrant that specifies exactly which skills, with which arguments, A may invoke on B. B verifies the warrant back to a root it trusts before running the skill.

```
┌─────────────┐                     ┌─────────────┐
│   Agent A   │   Task + Warrant    │   Agent B   │
│ (Orchestrator)│──────────────────▶│  (Worker)   │
│             │                     │             │
│             │◀──────────────────  │             │
│             │      Result         │             │
└─────────────┘                     └─────────────┘

Warrant says: "Agent A may ask for search_papers, sources on arxiv.org only"
```

**Use cases:**
- Multi-agent systems where agents delegate tasks
- Orchestrators that dispatch work to specialized workers
- Agent networks with least-privilege access control

**Not for:** Single-agent tool enforcement (use `tenuo.openai` or `tenuo.langchain` instead)

---

## Installation

```bash
uv pip install "tenuo[a2a]"
```

---

## Quick Start (Minimal Example)

**Server (Worker Agent):**

```python
from tenuo.a2a import A2AServerBuilder

# Build server with fluent API
server = (A2AServerBuilder()
    .name("Worker")
    .url("https://worker.example.com")
    .key(worker_key)                                    # Your identity
    .accept_warrants_from(orchestrator_key.public_key)  # Trusted root: who can give you tasks
    .build())

@server.skill("echo")
async def echo(msg: str) -> str:
    return f"Echo: {msg}"

# uvicorn server:server.app --port 8000
```

Or use the direct constructor:

```python
from tenuo.a2a import A2AServer

server = A2AServer(
    name="Worker",
    url="https://worker.example.com",
    public_key=worker_key.public_key,
    trusted_issuers=[orchestrator_key.public_key],
)
```

`trusted_issuers` holds **root** keys only. A delegated warrant is accepted when the caller sends the full chain back to one of these roots (see [Delegation Chains](#delegation-chains)). Never add an intermediate agent's key here to make a bare delegated warrant verify: that promotes the intermediate to a root and skips the attenuation checks against the real root.

**Client (Orchestrator):**

```python
from tenuo.a2a import A2AClientBuilder
from tenuo import Warrant

# Create a warrant for this task. The holder is the caller: the
# orchestrator signs the Proof-of-Possession with its own key.
task_warrant = (Warrant.mint_builder()
    .capability("echo")
    .holder(orchestrator_key.public_key)
    .ttl(300)
    .mint(orchestrator_key))

# Build client with a default warrant and PoP key
client = (A2AClientBuilder()
    .url("http://localhost:8000")
    .warrant(task_warrant, orchestrator_key)
    .build())

# Send task (warrant already configured)
result = await client.send_task(
    "hello",
    skill="echo",
    arguments={"msg": "hello"},
)
print(result.output)  # "Echo: hello"
```

Or use the direct constructor:

```python
from tenuo.a2a import A2AClient

client = A2AClient("http://localhost:8000")
result = await client.send_task(
    "hello",
    skill="echo",
    arguments={"msg": "hello"},
    warrant=task_warrant,
    signing_key=orchestrator_key,
)
```

That's it. The warrant proves the orchestrator authorized this specific task, and the PoP signature proves the caller holds the warrant.

> **One warrant per task.** With the default `check_replay=True`, the server remembers each warrant's ID for `replay_window` seconds (default 3600) and rejects a second task with the same warrant as `replay_detected`. Mint or attenuate a fresh warrant for each task, including when you pre-configure one on `A2AClientBuilder`.

---

## Full Example (With Constraints)

### Server (Worker)

```python
from tenuo.a2a import A2AServerBuilder
from tenuo.constraints import Subpath, UrlSafe

server = (A2AServerBuilder()
    .name("Research Agent")
    .url("https://research-agent.example.com")
    .key(worker_key)
    .accept_warrants_from(control_plane_key.public_key)  # root only
    .build())

# Register skills with constraint bindings. Instances are enforced on every
# call, on top of whatever the warrant allows.
@server.skill("search_papers", constraints={"sources": UrlSafe()})
async def search_papers(query: str, sources: list[str]) -> list[dict]:
    return await do_search(query, sources)

@server.skill("read_file", constraints={"path": Subpath("/data")})
async def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

# uvicorn server:server.app --host 0.0.0.0 --port 8000
```

### Client (Orchestrator)

The control plane is the trusted root. It mints the orchestrator a broad warrant; the orchestrator attenuates it for each task and sends the parent along with the task warrant, so the worker can verify back to the root.

```python
from tenuo import Warrant
from tenuo.a2a import A2AClient
from tenuo.constraints import Subpath, UrlSafe

# Issued by the control plane (the worker's trusted root), held by the orchestrator
orchestrator_warrant = (Warrant.mint_builder()
    .capability("search_papers", sources=UrlSafe(allow_domains=["arxiv.org", "openreview.net"]))
    .capability("read_file", path=Subpath("/data"))
    .holder(orchestrator_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

client = A2AClient("https://research-agent.example.com")
card = await client.discover()  # skills and x-tenuo-constraints

# Narrow the warrant for this one task. The orchestrator still holds it,
# because it is the caller that signs the PoP.
task_warrant = (orchestrator_warrant
    .grant_builder()
    .capability("search_papers", sources=UrlSafe(allow_domains=["arxiv.org"]))
    .holder(orchestrator_key.public_key)
    .ttl(300)
    .grant(orchestrator_key))

result = await client.send_task(
    message="Find papers on capability-based security",
    warrant=task_warrant,
    warrant_chain=[orchestrator_warrant],  # parents, root first, leaf excluded
    signing_key=orchestrator_key,
    skill="search_papers",
    arguments={"query": "capability-based security", "sources": ["https://arxiv.org"]},
)
```

### Streaming Tasks

For long-running tasks, use streaming to receive incremental updates:

```python
# Stream results as they arrive
async for update in client.send_task_streaming(
    message="Analyze these papers",
    warrant=analysis_warrant,          # a fresh warrant per task
    warrant_chain=[orchestrator_warrant],
    signing_key=orchestrator_key,
    skill="analyze_papers",
    arguments={"paper_ids": ["arxiv:2401.12345"]},
):
    if update.type.value == "status":
        print(f"Status: {update.data.get('status')}")
    elif update.type.value == "message":
        print(f"Chunk: {update.data.get('content')}")
    elif update.type.value == "complete":
        print(f"Done: {update.data.get('output')}")
```

The server emits SSE events for status updates, intermediate messages, and final completion.

**Stream timeout (DoS protection):**

```python
# Default timeout is 300 seconds (5 minutes)
async for update in client.send_task_streaming(
    ...,
    stream_timeout=600.0,  # 10 minute timeout
):
    ...
```

If the stream exceeds `stream_timeout`, a `TimeoutError` is raised. This prevents slow-drip DoS attacks where a malicious server holds connections indefinitely.

---

## Automated Registration (CSR Handshake)

A2A supports an automated handshake for agent registration, eliminating the need for out-of-band key sharing. This follows the Certificate Signing Request (CSR) pattern.

The connecting agent dynamically generates a self-signed challenge token to cryptographically prove key ownership. The server verifies this signature and uses a registered handler to decide what capabilities to grant, minting a fresh delegation warrant on the fly. 

**Server (Control Plane / Parent Agent):**

```python
from tenuo.a2a import A2AServerBuilder, RegistrationDeniedError
from tenuo.a2a.types import VerifiedWarrantRequest

# The handler decides whether to grant the requested capabilities
async def registration_handler(req: VerifiedWarrantRequest, issue):
    if req.verified_key_hex not in ALLOWLIST:
        raise RegistrationDeniedError("Agent not approved")
    
    # Issue a new warrant bound to the requested capabilities
    await issue(capabilities=req.capabilities, ttl=86400) # 24 hrs

server = (A2AServerBuilder()
    .name("Control Plane")
    .url("https://control.example.com")
    .key(server_signing_key) # MUST be a SigningKey to issue warrants
    .trust(server_signing_key.public_key)
    .registration_handler(registration_handler) # Enable handshake
    .build())
```

**Client (Child Agent):**

```python
from tenuo.a2a import A2AClient
from tenuo import SigningKey

client = A2AClient("https://control.example.com")
worker_key = SigningKey.generate() 

# Request a warrant with specific capabilities
# The client automatically generates the self-signed challenge token
warrant = await client.request_warrant(
    signing_key=worker_key,
    capabilities={"search_papers": {}}
)

# You can now immediately use this warrant (and key) for tasks
result = await client.send_task(
    "Search for AI Agents papers",
    skill="search_papers",
    arguments={"query": "AI Agents"},
    warrant=warrant,
    signing_key=worker_key,
)
```

**Note:** Extension data (like AWS Nitro Enclaves or SGX TEE quotes) can be attached to the request via the `extensions` parameter in `request_warrant()` and inspected in the server handler via `req.extensions`.

---

## Proof-of-Possession (PoP)

Proof-of-Possession adds an additional security layer by requiring the client to prove they control the private key associated with the warrant's holder.

### When to Use PoP

**Require PoP when:**
- Agents communicate over untrusted networks (Internet, shared infrastructure)
- Compliance requires cryptographic proof of authorization
- Protection against warrant theft is critical
- Multi-hop delegation across organizational boundaries

**PoP is optional when:**
- All agents run on trusted infrastructure (same data center, VPC)
- Network isolation provides security (private network, mTLS)
- Performance is critical and risk is low (every extra signature operation matters)

**Never skip PoP when:**
- Agents are on the public Internet
- Warrants have long TTLs (hours/days)
- Untrusted intermediaries exist in the call chain

### How PoP Works

PoP signatures prove that the caller holds the private key for the warrant's holder (`warrant.authorized_holder`). The holder is therefore the **caller**, not the agent being called:

```
┌──────────────────────────────────────────────────────┐
│ Warrant (CBOR, signed):                              │
│   holder: orchestrator public key                    │
│   capabilities: {"search": {...}}                    │
│   expires_at: 1234567890                             │
│   signed by: control plane (trusted root)            │
└──────────────────────────────────────────────────────┘
                       +
┌──────────────────────────────────────────────────────┐
│ PoP Signature (X-Tenuo-PoP):                         │
│   sign(orchestrator_private_key, "search", args, ts) │
│   → Proves the caller controls the holder key        │
└──────────────────────────────────────────────────────┘
                       =
               Authorization Proof
```

**What PoP Prevents:**
- **Warrant Theft**: If an attacker intercepts a warrant, they can't use it without the private key
- **Man-in-the-Middle**: Modified arguments invalidate the PoP signature

Replay protection is separate: with `check_replay=True` (default) the server accepts each warrant ID once per `replay_window`.

### Client Usage

Pass `signing_key` to `send_task()`, or pre-configure it with `A2AClientBuilder().warrant(warrant, key)`. The server rejects tasks without PoP by default (`require_pop=True`):

```python
from tenuo.a2a import A2AClient

client = A2AClient("https://worker.example.com")

result = await client.send_task(
    "search for papers",
    warrant=my_warrant,
    skill="search",
    arguments={"query": "papers"},
    signing_key=orchestrator_key,  # holder key: proves possession
)
```

Omitting `signing_key` only works against a server configured with `require_pop=False`.

### Server Configuration

Control PoP requirements on the server:

```python
server = A2AServer(
    name="Worker",
    url="https://worker.example.com",
    public_key=worker_key.public_key,
    trusted_issuers=[control_plane_key.public_key],  # Required: root keys only

    # PoP configuration
    require_pop=True,          # Reject requests without PoP (default: True)
)
```

> **Important:** Always configure `trusted_issuers`. The builder raises `ValueError` without at least one `.trust()` / `.accept_warrants_from()`. Only warrants that chain back to these keys are accepted.

**Security Defaults:**
- `trusted_issuers` is **required** (fail-closed)
- `require_pop=True` by default (fail-safe)
- Can be disabled via `TENUO_A2A_REQUIRE_POP=false` environment variable
- If `require_pop=True` and the client sends no PoP, the server returns `pop_required` (`-32015`)

### Performance Impact

Enabling PoP adds two extra Ed25519 signature operations per request on top of warrant verification:

- **Without PoP:** warrant verification only.
- **With PoP:** warrant verification + client-side PoP signing + server-side PoP verification.

All three operations are local and offline. See [Performance Benchmarks](./api-reference#performance-benchmarks) for measured timings.

**Recommendation:** Always use PoP in production unless you have network-level security (mTLS + VPC).

### Error Handling

The client raises `A2AError` for every JSON-RPC error the server returns. `e.message` is the error name and `e.data` carries the details, including `tenuo_code` (see [Error Handling](#error-handling-1)):

```python
from tenuo.a2a import A2AError

try:
    result = await client.send_task("search", warrant=warrant, skill="search", arguments={}, signing_key=key)
except A2AError as e:
    if e.message == "pop_required":
        print("Server requires PoP: pass signing_key")
    elif e.message == "pop_failed":
        print(f"PoP signature invalid: {e.data.get('reason')}")
        # Possible causes:
        #   - Signing key is not the warrant holder's key
        #   - Arguments modified after signing
        #   - Clock skew between client/server
```

### Debugging PoP Issues

**Issue:** `pop_failed` with reason `Signature verification failed`

**Causes:**
1. **Wrong signing key**: Key doesn't match the warrant's holder
2. **Modified arguments**: Arguments changed after PoP computation
3. **Clock skew**: Client/server clocks differ significantly

**Debug:**
```python
# Verify signing key matches warrant holder
assert warrant.authorized_holder == signing_key.public_key

# Log PoP computation
import logging
logging.getLogger("tenuo.a2a.client").setLevel(logging.DEBUG)
# Shows: "Generated PoP signature for skill 'search'"
```

---

## Server Configuration

```python
server = A2AServer(
    # Required
    name="Agent Name",                    # Display name
    url="https://agent.example.com",      # Public URL (for audience validation)
    public_key=my_public_key,             # This agent's public key
    trusted_issuers=[...],                # Trusted root public keys (never intermediates)
    
    # Optional (shown with defaults)
    trust_delegated=True,                 # Accept delegated warrants that chain back to a root
    require_warrant=True,                 # Reject tasks without warrants
    require_pop=True,                     # Require a Proof-of-Possession signature
    require_audience=False,               # See note below
    check_replay=True,                    # Accept each warrant ID once per replay_window
    replay_window=3600,                   # Seconds to remember warrant IDs
    max_chain_depth=10,                   # Maximum delegation chain length
    
    # Audit
    audit_log=sys.stderr,                 # Destination (file, callable, or stderr)
    audit_format="json",                  # "json" or "text"
)
```

Each boolean option can also be set with an environment variable (`TENUO_A2A_REQUIRE_WARRANT`, `TENUO_A2A_REQUIRE_POP`, `TENUO_A2A_REQUIRE_AUDIENCE`, `TENUO_A2A_CHECK_REPLAY`); explicit arguments win.

**`require_audience`** defaults to `False`. Tenuo warrants carry no audience claim, so turning it on rejects every warrant unless your warrant objects expose an `aud`/`audience` value that matches the server URL.

### Trust Model

The server trusts warrants based on `trusted_issuers`, which should hold **root** keys only:

1. **Direct Trust**: Warrant issued by a trusted root → accepted
2. **Delegated Trust** (if `trust_delegated=True`): the caller sends the full chain (root first) and every link verifies back to a trusted root → accepted

With `trust_delegated=False`, every delegated warrant is rejected as `untrusted_issuer`, whether the chain arrives as a WarrantStack or in the legacy chain header. A delegated warrant sent **without** its chain is always rejected (`untrusted_issuer`): the server never looks up parents, it only verifies the chain it is given.

```
┌─────────────────────┐
│    Trusted Root     │  ← In trusted_issuers
│   (Control Plane)   │
└──────────┬──────────┘
           │ delegates
           ▼
┌─────────────────────┐
│   Orchestrator A    │  ← Holds a warrant issued by the root
└──────────┬──────────┘
           │ delegates
           ▼
┌─────────────────────┐
│     Agent B         │  ← Calls the server, sends [root→A, A→B], signs PoP with B's key
└─────────────────────┘
```

### Skill Constraints

Constraints bind warrant parameters to skill parameters:

```python
@server.skill("read_file", constraints={"path": Subpath("/data")})
async def read_file(path: str) -> str:
    # Blocked if arg is "/etc/passwd", even when the warrant allows Subpath("/")
    ...
```

Pass constraint instances such as `Subpath("/data")`: the server checks them on
every call, on top of the warrant, whether or not `require_pop` is set. A
violation returns `constraint_violation` (`-32008`). A bare class such as `Subpath` only advertises
the parameter's constraint type in the AgentCard, enforces no bound, and emits a
`UserWarning` at registration.

**Constraint binding validation** happens at startup:

```python
# This raises ConstraintBindingError at startup:
@server.skill("read_file", constraints={"file_path": Subpath("/data")})  # "file_path" not a param
async def read_file(path: str) -> str:  # param is "path"
    ...
```

---

## Client Configuration

```python
client = A2AClient(
    url="https://agent.example.com",
    
    # Optional
    pin_key="z6Mk...",    # Expected public key (raises KeyMismatchError if different)
    timeout=30.0,          # Request timeout in seconds
)
```

### Key Pinning

Pin the expected public key to prevent TOFU (Trust On First Use) attacks:

```python
# If agent returns different key, raises KeyMismatchError
client = A2AClient(
    "https://research-agent.example.com",
    pin_key="z6MkResearchAgentKey123"  # From your config/secrets
)

card = await client.discover()  # Fails if key doesn't match
```

### Key Format Compatibility

A2A accepts public keys in multiple formats:

```python
# All of these work:
server = (A2AServerBuilder()
    .key(signing_key)  # PublicKey object
    .accept_warrants_from("a1b2c3...")  # Hex (64 chars)
    .accept_warrants_from("z6MkpT...")  # Multibase (base58btc)
    .accept_warrants_from("did:key:z6MkpT...")  # W3C DID
    .build())
```

All formats are automatically normalized for comparison. Multibase and DID support requires `uv pip install base58`.

---

## Agent Card (Discovery)

Agents expose their capabilities via `/.well-known/agent.json`:

```json
{
  "name": "Research Agent",
  "url": "https://research-agent.example.com",
  "skills": [
    {
      "id": "search_papers",
      "name": "search_papers",
      "x-tenuo-constraints": {
        "sources": {"type": "UrlSafe", "required": true}
      }
    }
  ],
  "x-tenuo": {
    "version": "0.1.0",
    "required": true,
    "public_key": "a5afc4f3...",
    "previous_keys": []
  }
}
```

A skill registered with a bare constraint class (`constraints={"sources": UrlSafe}`) appears here with the same shape, but the server does not enforce it (see [Skill Constraints](#skill-constraints)).

---

## Delegation Chains

When delegating through multiple agents, the caller sends the **full chain** with the task: every parent warrant, root first, followed by the leaf it presents. The server never fetches parents; it only verifies what it receives. Pass the parents with `warrant_chain=`:

```python
result = await client.send_task(
    "Search",
    warrant=leaf_warrant,                          # held by this caller
    warrant_chain=[root_warrant, middle_warrant],  # parents, root first, leaf excluded
    signing_key=my_key,                            # leaf holder's key
    skill="search_papers",
    arguments={"query": "capabilities"},
)
```

The server validates:
1. Root warrant is from a trusted issuer
2. Each link: child issuer = parent holder
3. Skills narrow monotonically (no privilege escalation)
4. Chain depth ≤ `max_chain_depth`

### WarrantStack Transport

`A2AClient` packs the chain and the leaf into a **single** `X-Tenuo-Warrant` header using WarrantStack encoding. The server still accepts the legacy two-header form (`X-Tenuo-Warrant` + `X-Tenuo-Warrant-Chain`), which the client only falls back to if stack encoding fails.

If you build requests yourself, encode the same stack:

```python
from tenuo import encode_warrant_stack

# Full chain, root first, leaf last
stack_b64 = encode_warrant_stack([root_warrant, child_warrant])
# stack_b64 goes in the X-Tenuo-Warrant header
```

This simplifies proxy and load-balancer configurations (one header to forward instead of two) and avoids ordering ambiguities in multi-hop chains.

---

## Human Approval

Define gates and approvers on the warrant. When a gate fires, the server returns `approval_required` (`-32019`) with the `request_hash` to sign. On retry, attach the `SignedApproval` objects in the `X-Tenuo-Approvals` header (or an `x-tenuo-approvals` JSON-RPC param). See [Human Approvals](approvals.md) for minting and signing.

```python
from tenuo.a2a import A2AError

try:
    result = await client.send_task("transfer", warrant=w, signing_key=key,
                                    skill="transfer", arguments={"amount": 5000})
except A2AError as e:
    if e.message == "approval_required":
        request_hash = e.data["request_hash"]       # hand to your approval flow
        min_approvals = e.data["min_approvals"]
    elif e.message == "insufficient_approvals":
        ...  # compare e.data["required"] and e.data["received"]
```

`A2AClient.send_task()` has no `approvals=` parameter yet, so send the retry with your own HTTP client and set the header:

```python
import base64, json

approvals_header = base64.b64encode(json.dumps(
    [base64.b64encode(a.to_bytes()).decode() for a in signed_approvals]
).encode()).decode()
# headers["X-Tenuo-Approvals"] = approvals_header
```

**Wire encoding:** `X-Tenuo-Approvals` = `base64(JSON(["base64(CBOR SignedApproval)", ...]))`. Same outer wrapper as FastAPI.

| A2A JSON-RPC | Wire code | When | Key `data` fields |
|--------------|-----------|------|-------------------|
| **-32019** | 1707 | Gate fired, no approvals | `request_hash`, `min_approvals`, `skill` |
| **-32020** | 1700 | Partial multi-sig | `required`, `received` |
| **-32021** | 1701 | Invalid / malformed approval | `reason` |

> **Note:** A2A `-32002` is **invalid signature** (1100), not approval. Do not reuse MCP's `-32002` semantics on A2A.

---

## Error Handling

The server maps every rejection to a JSON-RPC error with an A2A code, a short error name as `message`, and details in `data`, including the canonical Tenuo wire code as `data["tenuo_code"]`.

On the client side, `A2AClient.send_task()` raises the base `A2AError` for every error response. The typed classes in `tenuo.a2a` (`SkillNotGrantedError`, `ConstraintViolationError`, ...) are what the **server** raises internally; the client does not re-create them, and `e.code` on the client is not the server's JSON-RPC code. Branch on `e.message` or `e.data["tenuo_code"]`:

```python
from tenuo.a2a import A2AError

try:
    result = await client.send_task(...)
except A2AError as e:
    if e.message == "skill_not_granted":
        print(f"Skill {e.data['skill']} is not in the warrant")
    elif e.message == "constraint_violation":
        print(f"{e.data['param']} rejected: {e.data['reason']}")
    else:
        print(f"A2A error {e.message} (tenuo_code={e.data.get('tenuo_code')})")
```

The granted skill list is intentionally left out of `skill_not_granted` responses, to prevent capability enumeration.

### Wire Code Support

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32008,
    "message": "constraint_violation",
    "data": {
      "param": "path",
      "constraint_type": "Subpath",
      "reason": "Value does not satisfy server constraint",
      "tenuo_code": 1501
    }
  },
  "id": 1
}
```

| A2A JSON-RPC Code | `message` | Canonical Wire Code |
|-------------------|-----------|---------------------|
| -32001 | `missing_warrant` | — (A2A-specific) |
| -32002 | `invalid_signature` | 1100 |
| -32003 | `untrusted_issuer` | 1406 |
| -32004 | `expired` | 1300 |
| -32005 | `audience_mismatch` | — (A2A-specific) |
| -32006 | `replay_detected` | — (A2A-specific) |
| -32007 | `skill_not_granted` | 1500 |
| -32008 | `constraint_violation` | 1501 |
| -32009 | `revoked` | 1800 |
| -32010 | `chain_invalid` | 1405 |
| -32012 | `key_mismatch` | — (A2A-specific) |
| -32013 | `skill_not_found` | 1500 |
| -32014 | `unknown_constraint` | 1504 |
| -32015 | `pop_required` | 1600 |
| -32016 | `pop_failed` | 1600 |
| -32017 | `registration_disabled` | — (A2A-specific) |
| -32018 | `registration_denied` | — (A2A-specific) |
| -32019 | `approval_required` | 1707 |
| -32020 | `insufficient_approvals` | 1700 |
| -32021 | `invalid_approval` | 1701 |

A delegated warrant sent without its chain is rejected as `untrusted_issuer` (`-32003`): send the parents with `warrant_chain=`.

See [wire format specification](./spec/wire-format-v1#appendix-a-error-code-reference) for the complete list.

---

## Accessing the Warrant

Inside a skill, access the current warrant via context:

```python
from tenuo.a2a import current_task_warrant

@server.skill("my_skill")
async def my_skill(query: str) -> str:
    warrant = current_task_warrant.get()
    if warrant:
        print(f"Warrant issuer: {warrant.issuer}")
        print(f"Warrant holder: {warrant.authorized_holder}")
    return "done"
```

---

## Audit Logging

The server writes a structured event to `audit_log` for each task it lets through:

```python
# JSON format (default)
{"timestamp": "...", "event": "warrant_validated", "skill": "search", "outcome": "allowed", "observed": false, ...}

# Text format
[warrant_validated] search: allowed
```

Rejected tasks are returned to the caller as JSON-RPC errors (see [Error Handling](#error-handling-1)); in enforce mode they are not written to `audit_log`.

Custom audit handler:

```python
from tenuo.a2a import AuditEvent

async def my_audit_handler(event: AuditEvent):
    await send_to_siem(event.to_dict())

server = A2AServer(..., audit_log=my_audit_handler)
```

### Observe Mode

Use observe mode to find out what policy you need before enforcing it. Set it globally:

```python
from tenuo import configure

configure(trusted_roots=[control_plane_key.public_key], mode="observe")
# or: TENUO_MODE=observe  ("audit" and "permissive" are accepted aliases)
```

On the PoP path (`require_pop=True`, the default), the server still runs full verification. A task it would have denied runs anyway and is written to `audit_log` as the denial it was:

```json
{"event": "warrant_rejected", "outcome": "denied", "observed": true,
 "reason": "Constraint 'path' not satisfied: value does not match constraint", ...}
```

The server also logs `OBSERVE: would deny <skill>: <reason>` at warning level.

Observe mode does not yet apply when `require_pop=False`: those servers keep blocking would-deny tasks. Server-level skill constraints (`@server.skill(constraints=...)`) and replay checks also keep blocking in observe mode.

---

## Example: Full Multi-Agent System

```python
# control_plane.py
from tenuo import SigningKey, Warrant
from tenuo.constraints import Subpath, UrlSafe

control_key = SigningKey.from_env("CONTROL_PLANE_KEY")

def issue_orchestrator_warrant(orchestrator_pubkey):
    return (Warrant.mint_builder()
        .capability("search_papers", sources=UrlSafe(allow_domains=["arxiv.org", "openreview.net"]))
        .capability("read_file", path=Subpath("/data"))
        .holder(orchestrator_pubkey)
        .ttl(86400)  # 24 hours
        .mint(control_key))
```

```python
# orchestrator.py
from tenuo.a2a import A2AClient
from tenuo.constraints import UrlSafe

async def delegate_research(topic: str, my_warrant, my_key):
    client = A2AClient("https://research-agent.example.com")

    # Attenuate a fresh warrant for this task. The orchestrator stays the
    # holder because it is the caller that signs the PoP.
    task_warrant = (my_warrant
        .grant_builder()
        .capability("search_papers", sources=UrlSafe(allow_domains=["arxiv.org"]))
        .holder(my_key.public_key)
        .ttl(300)
        .grant(my_key))

    return await client.send_task(
        message=f"Research: {topic}",
        warrant=task_warrant,
        warrant_chain=[my_warrant],  # lets the worker verify back to the control plane
        signing_key=my_key,
        skill="search_papers",
        arguments={"query": topic, "sources": ["https://arxiv.org"]},
    )
```

```python
# research_agent.py
from tenuo.a2a import A2AServer
from tenuo.constraints import UrlSafe

server = A2AServer(
    name="Research Agent",
    url="https://research-agent.example.com",
    public_key=my_public_key,
    trusted_issuers=[control_plane_public_key],  # the root only
)

@server.skill("search_papers", constraints={"sources": UrlSafe(allow_domains=["arxiv.org"])})
async def search_papers(query: str, sources: list[str]) -> list[dict]:
    # Only allowed URLs pass through
    return await search_arxiv(query, sources)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="0.0.0.0", port=8000)
```

---

## API Reference

See [API Reference](./api-reference) for complete type signatures.

## Protocol Specification

For the wire format and protocol details, see the [Protocol Spec](./spec/protocol-spec-v1) and [Wire Format](./spec/wire-format-v1).

