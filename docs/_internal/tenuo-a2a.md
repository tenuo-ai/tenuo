# tenuo[a2a]

Inter-agent delegation over the A2A protocol.

```bash
pip install tenuo[a2a]
```

---

## What This Is

A2A handles agent-to-agent communication. This package adds warrant-based authorization to that communication.

```
Agent A                              Agent B
┌──────────────┐                     ┌──────────────┐
│              │   A2A Task          │              │
│              │   + Warrant         │              │
│              │────────────────────▶│              │
│              │                     │              │
│              │◀────────────────────│              │
│              │   Result            │              │
└──────────────┘                     └──────────────┘

Warrant says: "Agent B can only search arxiv.org for this task"
```

For tool enforcement *within* an agent, see `tenuo[openai]` or `tenuo[vertex]`.

---

## Client

Send tasks with warrants attached.

```python
from tenuo import Warrant, Grant
from tenuo.constraints import UrlSafe
from tenuo.a2a import A2AClient

client = A2AClient("https://research-agent.example.com")

# Attenuate your warrant for this delegation
task_warrant = (my_warrant.grant_builder()
    .grant("search_papers", sources=UrlSafe(allow_domains=["arxiv.org"]))
    .audience("https://research-agent.example.com")  # Bind to target
    .build(my_private_key)
)

result = await client.send_task(
    message="Find papers on capability-based security",
    warrant=task_warrant,
)
```

### API

```python
class A2AClient:
    def __init__(
        self,
        url: str,
        auth: AuthConfig | None = None,
        pin_key: str | None = None,  # Expected public key (fail if mismatch)
    ): ...
    
    async def discover(self) -> AgentCard:
        """Fetch agent card. Check x-tenuo.required to see if warrants needed.
        
        If pin_key was provided, raises KeyMismatchError if the agent's
        public key doesn't match. This prevents TOFU attacks where a
        compromised server swaps its key.
        """
    
    async def send_task(
        self,
        message: str | Message,
        warrant: Warrant,
        *,
        skill: str,
        arguments: dict[str, Any] | None = None,
    ) -> TaskResult: ...
    
    async def send_task_streaming(
        self,
        message: str | Message,
        warrant: Warrant,
        *,
        skill: str,
        arguments: dict[str, Any] | None = None,
    ) -> AsyncIterator[TaskUpdate]: ...
```

### Streaming and Warrant Expiry

For long-running streaming tasks, the warrant may expire mid-stream.

**Server behavior:**
- Server checks warrant expiry at task start
- Server SHOULD check expiry periodically during streaming (e.g., every 60s)
- If warrant expires mid-stream, server terminates with error:

```json
{"type": "error", "code": -32004, "message": "expired", "data": {"mid_stream": true}}
```

**Client guidance:**
- For streaming tasks, use warrants with TTLs longer than expected task duration
- If task duration is unpredictable, implement reconnection with fresh warrant:

```python
async def resilient_stream(client, message, skill, get_warrant):
    while True:
        warrant = get_warrant()  # Fresh warrant
        try:
            async for update in client.send_task_streaming(message, warrant, skill=skill):
                yield update
                if update.type == "complete":
                    return
        except WarrantExpiredError:
            continue  # Get new warrant and reconnect
```

> **Note:** There is no mid-stream warrant refresh mechanism. This is intentional — it would complicate the protocol and create ambiguity about which warrant governs which part of the response. Use appropriate TTLs instead.

### Delegation Helper

```python
from tenuo.a2a import delegate

result = await delegate(
    to="https://research-agent.example.com",
    parent=my_warrant,
    grants=[Grant(skill="search", constraints={"url": UrlSafe(["arxiv.org"])})],
    message="Find TOCTOU papers",
    key=my_private_key,
)
```

---

## Server

Receive tasks, enforce warrants.

```python
from tenuo.a2a import A2AServer
from tenuo.constraints import UrlSafe, Subpath

server = A2AServer(
    name="Research Agent",
    url="https://research-agent.example.com",
    public_key=my_public_key,
    trusted_issuers=[          # Who can issue warrants we accept
        orchestrator_public_key,
        root_ca_public_key,
    ],
)

@server.skill("search_papers", constraints={"sources": UrlSafe})
async def search_papers(query: str, sources: list[str]) -> list[dict]:
    # Warrant already validated sources before we get here
    return await do_search(query, sources)

@server.skill("read_file", constraints={"path": Subpath})
async def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

# Run
uvicorn.run(server.app, port=8000)
```

### Trust Model

The server must know which issuers to trust. Configure via `trusted_issuers`:

```python
server = A2AServer(
    ...,
    trusted_issuers=[
        "z6Mkf5rGMoatrSj1f...",   # Public key (multibase)
        "did:key:z6Mkf5rG...",    # DID
    ],
    trust_delegated=True,  # Also trust warrants attenuated from trusted issuers
)
```

**Trust modes:**

| Mode | Behavior |
|------|----------|
| `trusted_issuers` only | Only accept warrants signed directly by listed keys |
| `trust_delegated=True` | Accept warrants with valid chain back to trusted issuer |

For delegation chains, the server validates:
1. Root warrant signed by trusted issuer
2. Each child properly attenuated from parent
3. Chain ≤ `max_chain_depth`

### How `@server.skill` Works

1. Task arrives with warrant in `X-Tenuo-Warrant` header
2. Server verifies signature against `trusted_issuers`
3. Server checks `aud` matches this server's URL (if present)
4. Server checks `jti` not already used (if replay protection enabled)
5. When skill is invoked, server checks arguments against warrant constraints
6. If valid → execute function
7. If invalid → return error, function never runs

**Constraint binding validation:**

At server startup, `@server.skill` validates that constraint keys match function parameters:

```python
@server.skill("read_file", constraints={"path": Subpath})
async def read_file(path: str) -> str:  # ✓ 'path' exists as parameter
    ...

@server.skill("read_file", constraints={"file_path": Subpath})
async def read_file(path: str) -> str:
    # ✗ Raises at startup:
    # ConstraintBindingError: Constraint 'file_path' does not match any
    # parameter of skill 'read_file'. Available: ['path']
```

This catches configuration errors before the server accepts traffic.

### Server Options

```python
server = A2AServer(
    name="Research Agent",
    url="https://research-agent.example.com",
    public_key=my_public_key,
    trusted_issuers=[...],           # Required: who to trust
    trust_delegated=True,            # Trust attenuated warrants (default: True)
    require_warrant=True,            # Reject tasks without warrant (default: True)
    require_audience=True,           # Require aud claim matches our URL (default: True)
    check_replay=True,               # Enforce jti uniqueness (default: True)
    replay_window=3600,              # Seconds to remember jti (default: 3600)
    max_chain_depth=10,              # Max delegation hops (default: 10)
    audit_log=sys.stderr,            # Where to log (default: stderr)
    audit_format="json",             # "json" or "text" (default: json)
)
```

### Audit Log Schema

When `audit_format="json"`, events are structured for compliance and analysis:

```json
{
  "timestamp": "2026-01-13T10:30:00.000Z",
  "event": "skill_invoked",
  "task_id": "task_abc123",
  "skill": "search_papers",
  "warrant": {
    "jti": "wrt_xyz789",
    "iss": "did:key:z6MkClient...",
    "sub": "did:key:z6MkAgent...",
    "exp": 1736647200,
    "chain_depth": 2
  },
  "outcome": "allowed",
  "constraints_checked": {
    "sources": {"type": "UrlSafe", "value": ["arxiv.org"], "result": "pass"}
  },
  "latency_ms": 12
}
```

**Event types:**

| Event | Description |
|-------|-------------|
| `warrant_received` | Warrant arrived with task |
| `warrant_validated` | Signature and claims verified |
| `warrant_rejected` | Validation failed (with reason) |
| `skill_invoked` | Skill called with constraints checked |
| `skill_denied` | Constraint violation blocked execution |
| `warrant_expired` | Warrant expired mid-stream |

```python
# Custom audit handler
async def my_audit_handler(event: AuditEvent):
    await send_to_siem(event.to_dict())

server = A2AServer(..., audit_log=my_audit_handler)
```

### Accessing Warrant in Skill

```python
from tenuo.a2a import current_task_warrant

@server.skill("custom", constraints={})
async def custom(data: str) -> str:
    warrant = current_task_warrant.get()
    # Custom logic based on warrant.subject, etc.
```

---

## Wire Format

### AgentCard Extension

```json
{
  "name": "Research Agent",
  "url": "https://research.example.com/",
  "skills": [
    {
      "id": "search_papers",
      "name": "Search Papers",
      "x-tenuo-constraints": {
        "sources": {"type": "UrlSafe", "required": true}
      }
    },
    {
      "id": "read_file",
      "name": "Read File",
      "x-tenuo-constraints": {
        "path": {"type": "Subpath", "required": true}
      }
    }
  ],
  
  "x-tenuo": {
    "version": "0.1.0",
    "required": true,
    "public_key": "z6Mkf5rGMoatrSj1f...",
    "previous_keys": []
  }
}
```

**Skill constraint discovery:** The `x-tenuo-constraints` field in each skill tells clients what constraints are required. Clients can use this to construct valid warrants:

```python
card = await client.discover()
for skill in card.skills:
    constraints = skill.get("x-tenuo-constraints", {})
    # Now client knows: search_papers needs UrlSafe constraint on 'sources'
```

**Key authentication:** The AgentCard is fetched over HTTPS. TLS authenticates the domain; the key at that domain is trusted.

> **⚠️ TOFU Warning:** This is Trust-On-First-Use. An attacker who compromises the server can swap the key. For high-security deployments, use key pinning:

```python
# Pin the expected key — fails if agent serves a different key
client = A2AClient(
    "https://research-agent.example.com",
    pin_key="z6Mkf5rGMoatrSj1f...",  # Known good key
)

# On mismatch:
# KeyMismatchError: Expected z6Mkf5rG..., got z6MkXYZ...
```

**Key rotation:** When agents rotate keys, clients with pinned keys will fail. Coordinate rotation:
1. Agent adds new key to `x-tenuo.previous_keys` in AgentCard
2. Clients update their pinned keys
3. After transition period, agent removes old key

### Warrant Transport

**Primary: HTTP Header (recommended)**

```
POST /a2a HTTP/1.1
Host: research-agent.example.com
Content-Type: application/json
X-Tenuo-Warrant: eyJhbGciOiJFZERTQSJ9...

{"jsonrpc": "2.0", "method": "task/send", "params": {"task": {...}}}
```

**Fallback: Extension field in params**

```json
{
  "jsonrpc": "2.0",
  "method": "task/send",
  "params": {
    "task": {...},
    "x-tenuo-warrant": "eyJhbGciOiJFZERTQSJ9..."
  }
}
```

Header is preferred:
- Middleware won't strip it
- Won't appear in JSON-RPC logs
- Can be processed before parsing body

Servers MUST accept header. Servers SHOULD accept params fallback.

### Warrant Claims

Standard JWT claims with Tenuo extensions:

| Claim | Required | Description |
|-------|----------|-------------|
| `jti` | Yes | Unique warrant ID |
| `iss` | Yes | Issuer public key or DID |
| `sub` | Yes | Subject (who can use this warrant) |
| `aud` | Recommended | Audience (target server URL) |
| `iat` | Yes | Issued at |
| `exp` | Yes | Expires at |
| `grants` | Yes | Array of skill grants with constraints |
| `parent` | If attenuated | Parent warrant ID |

Example payload:
```json
{
  "jti": "wrt_abc123",
  "iss": "did:key:z6MkClient...",
  "sub": "did:key:z6MkAgent...",
  "aud": "https://research-agent.example.com",
  "iat": 1736643600,
  "exp": 1736647200,
  "grants": [
    {"skill": "search_papers", "constraints": {"sources": {"type": "UrlSafe", "allow_domains": ["arxiv.org"]}}}
  ],
  "parent": null
}
```

### Replay Protection

Servers SHOULD enforce `jti` uniqueness within the warrant lifetime:

```python
# Pseudocode
def validate_warrant(warrant):
    if replay_cache.has(warrant.jti):
        raise ReplayError()
    replay_cache.set(warrant.jti, ttl=warrant.exp - now())
```

This prevents a captured warrant from being reused.

### Audience Binding

If `aud` is present, server MUST reject warrants where `aud` doesn't match:

```python
def validate_audience(warrant, server_url):
    if warrant.aud and warrant.aud != server_url:
        raise AudienceMismatch()
```

This prevents warrants issued for Agent B from being used at Agent C.

### Errors

| Code | Reason | Description |
|------|--------|-------------|
| -32001 | `missing_warrant` | Warrant required but not provided |
| -32002 | `invalid_signature` | Signature verification failed |
| -32003 | `untrusted_issuer` | Issuer not in trusted_issuers |
| -32004 | `expired` | Warrant expired |
| -32005 | `audience_mismatch` | aud doesn't match server URL |
| -32006 | `replay_detected` | jti already used |
| -32007 | `skill_not_granted` | Skill not in warrant |
| -32008 | `constraint_violation` | Argument fails constraint |
| -32009 | `revoked` | Warrant or issuer revoked |
| -32010 | `chain_invalid` | Delegation chain validation failed |
| -32011 | `chain_missing` | Chain header required but not provided |
| -32012 | `key_mismatch` | Agent key doesn't match pinned key |

**Error detail for chain failures:**

```json
{
  "code": -32010,
  "message": "chain_invalid",
  "data": {
    "depth": 2,
    "reason": "issuer_mismatch",
    "expected_issuer": "did:key:z6MkParent...",
    "actual_issuer": "did:key:z6MkAttacker...",
    "warrant_jti": "wrt_child123"
  }
}
```

| Chain reason | Description |
|--------------|-------------|
| `issuer_mismatch` | `child.iss != parent.sub` |
| `not_attenuated` | Child grants exceed parent grants |
| `untrusted_root` | Chain root not in `trusted_issuers` |
| `max_depth_exceeded` | Chain longer than `max_chain_depth` |
| `parent_expired` | Parent warrant expired before child |
| `signature_invalid` | Signature verification failed at depth N |

### Skill Matching

Skills are matched **exactly** by ID. Wildcards and patterns are not supported.

```python
# Warrant grants:
{"skill": "search_papers", ...}

# These match:
@server.skill("search_papers")  # ✓ Exact match

# These do NOT match:
@server.skill("search")          # ✗ Partial
@server.skill("search_*")        # ✗ Wildcards not supported
```

> **Rationale:** Wildcards introduce ambiguity in security boundaries. Grant specific skills explicitly.

---

## Delegation Chains

Agent A delegates to Agent B, which delegates to Agent C:

```python
# Agent B receives warrant from A
incoming_warrant = current_task_warrant.get()

# B attenuates for C (can only narrow, not expand)
c_warrant = (incoming_warrant.grant_builder()
    .grant("fetch", url=UrlSafe(allow_domains=["api.example.com"]))
    .audience("https://agent-c.example.com")  # Bind to C
    .build(b_private_key)
)

# Delegate to C
result = await delegate(
    to="https://agent-c.example.com",
    warrant=c_warrant,  # Send the attenuated warrant
    message="Fetch the data",
)
```

### Chain Validation

When `trust_delegated=True`, server validates the full chain:

1. Fetch parent warrant (from `X-Tenuo-Warrant-Chain` header or issuer's well-known endpoint)
2. Verify parent signature
3. **Verify `child.iss == parent.sub`** (the child issuer must be the parent's intended subject)
4. Verify child grants are a subset of parent grants (attenuation only narrows)
5. Recurse until reaching a trusted issuer
6. Reject if chain > `max_chain_depth`

> **Critical: Subject chain validation.** Step 3 prevents "warrant theft" where an attacker who obtains a warrant could re-sign it and claim to be the delegator. The issuer of each child warrant MUST be the subject of its parent.

**Chain transport:**

Clients SHOULD include the full chain in headers (preferred for offline validation):

```
X-Tenuo-Warrant: <child_jwt>
X-Tenuo-Warrant-Chain: <parent_jwt>; <grandparent_jwt>; <root_jwt>
```

**Chain header format:**
- **Separator:** Semicolon (`;`) — safe in base64url, unlike comma
- **Order:** Parent-first (immediate parent, then grandparent, then root)
- **Size limit:** If chain exceeds ~6KB, use params fallback or shorter TTLs instead of deep chains

```json
{
  "params": {
    "task": {...},
    "x-tenuo-warrant": "<child_jwt>",
    "x-tenuo-warrant-chain": ["<parent_jwt>", "<grandparent_jwt>", "<root_jwt>"]
  }
}
```

> **Note:** Servers MUST NOT fetch missing parents from remote endpoints. This would introduce latency, availability dependencies, and potential SSRF vectors. Clients MUST include the full chain. If chain is missing, server returns `chain_invalid` error.

---

## With Framework Adapters

A2A handles delegation *between* agents. Framework adapters handle tool calls *within* agents. Use both:

```python
from tenuo.a2a import A2AServer, current_task_warrant
from tenuo.vertex import tenuo_tool
from tenuo.context import use_warrant

server = A2AServer(
    name="Analysis Agent",
    url="https://analysis.example.com",
    public_key=key,
    trusted_issuers=[orchestrator_key],
)

@server.skill("analyze", constraints={"path": Subpath})
async def analyze(path: str) -> str:
    # A2A validated the path against the incoming warrant
    # Now use the same warrant for internal tool calls
    warrant = current_task_warrant.get()
    
    with use_warrant(warrant):
        # Vertex tools are now constrained by the same warrant
        result = await run_vertex_agent(f"Analyze {path}")
    
    return result
```

---

## Security Considerations

| Concern | Mitigation |
|---------|------------|
| Untrusted issuer | `trusted_issuers` allowlist |
| MITM on AgentCard | TLS authenticates domain; pin key for high-security |
| Warrant replay | `jti` uniqueness check within expiry window |
| Warrant misdirection | `aud` claim binds to specific server |
| Warrant theft | `child.iss == parent.sub` validation in chain |
| Warrant in logs | Use header transport, not params |
| Excessive delegation | `max_chain_depth` limit |
| Revoked warrant/key | Integrate with THI revocation registry (see below) |
| Flood attack | Per-warrant rate limiting (see below) |

### Revocation Integration (Optional)

A2A servers MAY integrate with the [THI revocation registry](./thi-spec.md#23-revocation-registry) for real-time revocation checks:

```python
server = A2AServer(
    ...,
    revocation_check=True,        # Enable revocation checks
    revocation_registry=thi_host, # THI-compliant host
)
```

When enabled, the server checks:
1. Warrant ID not revoked
2. Issuer key not revoked
3. (If `trust_delegated`) All delegator keys in chain not revoked

> **Trade-off:** Revocation checks add latency (THI host round-trip). Use short TTLs as an alternative for latency-sensitive deployments.

### Rate Limiting (Optional)

A2A servers MAY enforce per-warrant rate limits via THI or external gateway:

```python
server = A2AServer(
    ...,
    rate_limit={
        "per_warrant": 100,    # Max 100 tasks per warrant
        "per_holder": 1000,    # Max 1000 tasks per holder public key
        "window_secs": 3600,   # Per hour
    },
)
```

> **Rationale:** If an attacker obtains a valid warrant, rate limiting bounds the damage. This is defense-in-depth; short TTLs remain the primary control.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TENUO_A2A_REQUIRE_WARRANT` | `true` | Require warrants |
| `TENUO_A2A_REQUIRE_AUDIENCE` | `true` | Require aud claim |
| `TENUO_A2A_CHECK_REPLAY` | `true` | Check jti uniqueness |
| `TENUO_A2A_REPLAY_WINDOW` | `3600` | Seconds to remember jti |
| `TENUO_A2A_MAX_CHAIN_DEPTH` | `10` | Max delegation depth |
| `TENUO_A2A_AUDIT_LOG` | `stderr` | Audit log destination |

---

## See Also

- [A2A User Guide](../a2a.md) — Public documentation and quick start
- [tenuo core](./README.md) — Warrant, Grant, Constraint, attenuate()
- [tenuo[vertex]](./vertex.md) — Gemini tool enforcement
- [tenuo[openai]](./openai.md) — OpenAI tool enforcement
- [A2A Protocol](https://google.github.io/A2A/) — Underlying protocol
