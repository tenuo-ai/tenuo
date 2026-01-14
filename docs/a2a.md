---
title: A2A Integration
description: Warrant-based authorization for inter-agent communication
---

# Tenuo A2A Integration

> **Status**: Implemented (MVP)

## Overview

Tenuo A2A adds **warrant-based authorization** to agent-to-agent communication. When Agent A delegates a task to Agent B, the warrant specifies exactly what Agent B is allowed to do.

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

**Use cases:**
- Multi-agent systems where agents delegate tasks
- Orchestrators that dispatch work to specialized workers
- Agent networks with least-privilege access control

**Not for:** Single-agent tool enforcement (use `tenuo.openai` or `tenuo.langchain` instead)

---

## Installation

```bash
pip install tenuo[a2a]
```

This installs Tenuo with A2A dependencies (starlette, httpx).

---

## Quick Start

### Server (Agent B - Worker)

```python
from tenuo.a2a import A2AServer
from tenuo.constraints import Subpath, UrlSafe

# Create server with trusted issuer(s)
server = A2AServer(
    name="Research Agent",
    url="https://research-agent.example.com",
    public_key=my_public_key,
    trusted_issuers=[orchestrator_public_key],
)

# Register skills with constraints
@server.skill("search_papers", constraints={"sources": UrlSafe})
async def search_papers(query: str, sources: list[str]) -> list[dict]:
    """Search academic papers. URLs constrained by warrant."""
    return await do_search(query, sources)

@server.skill("read_file", constraints={"path": Subpath})
async def read_file(path: str) -> str:
    """Read a file. Path constrained by warrant."""
    with open(path) as f:
        return f.read()

# Run with uvicorn
import uvicorn
uvicorn.run(server.app, host="0.0.0.0", port=8000)
```

### Client (Agent A - Orchestrator)

```python
from tenuo.a2a import A2AClient
from tenuo import Warrant, SigningKey
from tenuo.constraints import UrlSafe

# Discover agent capabilities
client = A2AClient("https://research-agent.example.com")
card = await client.discover()
print(f"Agent: {card.name}")
print(f"Requires warrant: {card.requires_warrant}")

# Create a scoped warrant for this delegation
task_warrant = (my_warrant
    .grant_builder()
    .skill("search_papers")
    .constraint("sources", UrlSafe(allow_domains=["arxiv.org"]))
    .audience("https://research-agent.example.com")
    .ttl(300)
    .build(my_signing_key))

# Send task with warrant
result = await client.send_task(
    message="Find papers on capability-based security",
    warrant=task_warrant,
    skill="search_papers",
    arguments={"query": "capability-based security", "sources": ["https://arxiv.org"]},
)

print(f"Found {len(result.output)} papers")
```

### Streaming Tasks

For long-running tasks, use streaming to receive incremental updates:

```python
# Stream results as they arrive
async for update in client.send_task_streaming(
    message="Analyze these papers",
    warrant=task_warrant,
    skill="analyze_papers",
    arguments={"paper_ids": ["arxiv:2401.12345"]},
):
    if update.type.value == "status":
        print(f"Status: {update.status}")
    elif update.type.value == "message":
        print(f"Chunk: {update.content}")
    elif update.type.value == "complete":
        print(f"Done: {update.output}")
```

The server emits SSE events for status updates, intermediate messages, and final completion.

---

## Server Configuration

```python
server = A2AServer(
    # Required
    name="Agent Name",                    # Display name
    url="https://agent.example.com",      # Public URL (for audience validation)
    public_key=my_public_key,             # This agent's public key
    trusted_issuers=[...],                # List of trusted issuer public keys
    
    # Optional (shown with defaults)
    trust_delegated=True,                 # Accept warrants delegated from trusted issuers
    require_warrant=True,                 # Reject tasks without warrants
    require_audience=True,                # Require warrant audience matches our URL
    check_replay=True,                    # Enforce jti uniqueness
    replay_window=3600,                   # Seconds to remember jti values
    max_chain_depth=10,                   # Maximum delegation chain length
    
    # Audit
    audit_log=sys.stderr,                 # Destination (file, callable, or stderr)
    audit_format="json",                  # "json" or "text"
)
```

### Trust Model

The server trusts warrants based on `trusted_issuers`:

1. **Direct Trust**: Warrant signed by a trusted issuer → accepted
2. **Delegated Trust** (if `trust_delegated=True`): Warrant with valid chain back to trusted issuer → accepted

```
┌─────────────────────┐
│    Trusted Root     │  ← In trusted_issuers
│   (Control Plane)   │
└──────────┬──────────┘
           │ delegates
           ▼
┌─────────────────────┐
│   Orchestrator A    │  ← Warrant signed by root
└──────────┬──────────┘
           │ delegates
           ▼
┌─────────────────────┐
│     Worker B        │  ← Warrant with chain [root → A → B]
└─────────────────────┘
```

### Skill Constraints

Constraints bind warrant parameters to skill parameters:

```python
@server.skill("read_file", constraints={"path": Subpath})
async def read_file(path: str) -> str:
    # "path" constraint checked against warrant's path constraint
    # Blocked if: warrant allows Subpath("/data") but arg is "/etc/passwd"
    ...
```

**Constraint binding validation** happens at startup:

```python
# This raises ConstraintBindingError at startup:
@server.skill("read_file", constraints={"file_path": Subpath})  # ❌ "file_path" not a param
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
      "name": "Search Papers",
      "x-tenuo-constraints": {
        "sources": {"type": "UrlSafe", "required": true}
      }
    }
  ],
  "x-tenuo": {
    "version": "0.1.0",
    "required": true,
    "public_key": "z6Mk..."
  }
}
```

---

## Delegation Chains

When delegating through multiple agents, include the warrant chain:

```python
# Orchestrator delegates to Worker A, who delegates to Worker B
# Worker B receives:
#   X-Tenuo-Warrant: <worker_b_warrant>
#   X-Tenuo-Warrant-Chain: <root>;...;<worker_a_warrant>
```

The server validates:
1. Root warrant is from a trusted issuer
2. Each link: child issuer = parent holder
3. Skills narrow monotonically (no privilege escalation)
4. Chain depth ≤ `max_chain_depth`

---

## Error Handling

All A2A errors inherit from `A2AError` and map to JSON-RPC error codes:

```python
from tenuo.a2a import (
    A2AError,
    MissingWarrantError,      # -32001: Warrant required but not provided
    InvalidSignatureError,     # -32002: Signature verification failed
    UntrustedIssuerError,      # -32003: Issuer not in trusted_issuers
    WarrantExpiredError,       # -32004: Warrant has expired
    AudienceMismatchError,     # -32005: Audience doesn't match server URL
    ReplayDetectedError,       # -32006: jti already used
    SkillNotGrantedError,      # -32007: Skill not in warrant grants
    ConstraintViolationError,  # -32008: Argument violates constraint
    ChainInvalidError,         # -32010: Delegation chain validation failed
    KeyMismatchError,          # -32012: Public key doesn't match pinned key
)

try:
    result = await client.send_task(...)
except SkillNotGrantedError as e:
    print(f"Skill {e.data['skill']} not in granted: {e.data['granted_skills']}")
except A2AError as e:
    print(f"A2A error {e.code}: {e.message}")
```

---

## Accessing the Warrant

Inside a skill, access the current warrant via context:

```python
from tenuo.a2a import current_task_warrant

@server.skill("my_skill")
async def my_skill(query: str) -> str:
    warrant = current_task_warrant.get()
    if warrant:
        print(f"Warrant issuer: {warrant.iss}")
        print(f"Warrant subject: {warrant.sub}")
    return "done"
```

---

## Audit Logging

Server emits structured audit events:

```python
# JSON format (default)
{"timestamp": "...", "event": "warrant_validated", "skill": "search", "outcome": "allowed", ...}

# Text format
[WARRANT_VALIDATED] search: allowed
```

Custom audit handler:

```python
async def my_audit_handler(event: AuditEvent):
    await send_to_siem(event.to_dict())

server = A2AServer(..., audit_log=my_audit_handler)
```

---

## Example: Full Multi-Agent System

```python
# control_plane.py
from tenuo import SigningKey, Warrant

control_key = SigningKey.from_env("CONTROL_PLANE_KEY")

def issue_orchestrator_warrant(orchestrator_pubkey):
    return (Warrant.mint_builder()
        .capability("search_papers", {})
        .capability("read_file", {"path": Subpath("/data")})
        .holder(orchestrator_pubkey)
        .ttl(86400)  # 24 hours
        .mint(control_key))
```

```python
# orchestrator.py
from tenuo.a2a import A2AClient

async def delegate_research(topic: str, my_warrant, my_key):
    client = A2AClient("https://research-agent.example.com")
    
    # Attenuate warrant for this specific task
    task_warrant = (my_warrant
        .grant_builder()
        .skill("search_papers")
        .constraint("sources", UrlSafe(allow_domains=["arxiv.org"]))
        .audience("https://research-agent.example.com")
        .ttl(300)
        .build(my_key))
    
    return await client.send_task(
        message=f"Research: {topic}",
        warrant=task_warrant,
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
    trusted_issuers=[control_plane_public_key],
)

@server.skill("search_papers", constraints={"sources": UrlSafe})
async def search_papers(query: str, sources: list[str]) -> list[dict]:
    # Only allowed URLs pass through
    return await search_arxiv(query, sources)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="0.0.0.0", port=8000)
```

---

## API Reference

See [API Reference](/api-reference) for complete type signatures.

## Protocol Specification

For the wire format and protocol details, see the [internal spec](/docs/_internal/tenuo-a2a.md).

