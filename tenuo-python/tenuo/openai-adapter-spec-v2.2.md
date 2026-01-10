# Tenuo Adapter Specification: OpenAI

**Version:** 2.2  
**Status:** Draft  
**Date:** 2025-01-09  
**Author:** Niki Niyikiza  

**Target SDKs:**
- `openai-python` ≥1.50
- OpenAI Agents SDK ≥0.1

**Supported Endpoints:**
- `client.chat.completions.create()` — ✅ Full support
- `client.responses.create()` — ✅ Full support  
- `client.beta.assistants.*` — ⚠️ Planned (v2.3)
- OpenAI Agents SDK `agent.run()` — ✅ Full support

---

## Abstract

This specification defines how Tenuo integrates with OpenAI's APIs. The adapter provides **two tiers** of protection:

| Tier | Complexity | Use Case |
|------|------------|----------|
| **Tier 1: Guardrails** | 3 lines of code | Single-process agents, quick hardening |
| **Tier 2: Warrants** | Full crypto | Multi-agent delegation, audit trails |

Tier 1 is a stepping stone to Tier 2 — same API, opt-in cryptography.

---

## Quick Start

**Tier 1** (5 minutes):

```python
from tenuo.openai import guard, Pattern

client = guard(
    openai.OpenAI(),
    allow_tools=["search_web", "read_file"],
    constraints={
        "read_file": {"path": Pattern("/data/*")}
    }
)

# Use normally — unauthorized tool calls are blocked
response = client.chat.completions.create(...)
```

**Tier 2** (when you need cryptographic guarantees):

```python
from tenuo.openai import guard, Pattern, Keypair, Warrant

# Same API, add warrant + keypair
client = guard(
    openai.OpenAI(),
    warrant=my_warrant,
    keypair=my_keypair,
    trusted_roots=[control_plane_pubkey]
)
```

---

# Part I: Tier 1 — Guardrails

## 1. Overview

Tier 1 provides runtime constraint checking with zero cryptography. It catches:

- ✅ Hallucinated tool calls
- ✅ Argument constraint violations  
- ✅ Prompt injection tool abuse
- ✅ Streaming TOCTOU attacks

It does NOT provide:

- ❌ Cryptographic proof of authorization
- ❌ Cross-process trust boundaries
- ❌ Audit trails with signatures
- ❌ Delegation chains

**When Tier 1 is enough:** All agents run in the same process, you trust the runtime, you just want to prevent LLM mistakes.

---

## 2. API Reference

### 2.1 The `guard()` Wrapper

```python
def guard(
    client: openai.OpenAI,
    *,
    allow_tools: list[str] | None = None,
    deny_tools: list[str] | None = None,
    constraints: dict[str, dict[str, Constraint]] | None = None,
    on_denial: Literal["raise", "skip", "log"] = "raise",
) -> GuardedClient:
    """
    Wrap an OpenAI client with Tenuo guardrails.
    
    Args:
        client: OpenAI client instance
        allow_tools: Allowlist of tool names (default: allow all)
        deny_tools: Denylist of tool names (default: deny none)
        constraints: Per-tool argument constraints
        on_denial: Behavior when tool call is denied
        
    Returns:
        Wrapped client that enforces constraints
    """
```

### 2.2 Constraints

Reuses core Tenuo constraint types:

| Type | Example | Matches |
|------|---------|---------|
| `Exact(v)` | `Exact("/data/report.pdf")` | Exact value only |
| `Pattern(p)` | `Pattern("/data/*.pdf")` | Glob pattern |
| `Regex(r)` | `Regex(r"^[a-z]+$")` | Regular expression |
| `OneOf([...])` | `OneOf(["dev", "staging"])` | Set membership |
| `Range(min, max)` | `Range(0, 100)` | Numeric bounds |

```python
from tenuo import Exact, Pattern, Regex, OneOf, Range

client = guard(
    openai.OpenAI(),
    allow_tools=["read_file", "search", "calculate"],
    constraints={
        "read_file": {
            "path": Pattern("/data/**/*.pdf"),
        },
        "search": {
            "query": Regex(r"^[a-zA-Z0-9 ]+$"),  # No special chars
            "max_results": Range(1, 20),
        },
        "calculate": {
            "operation": OneOf(["add", "subtract", "multiply"]),
        },
    }
)
```

### 2.3 Denial Handling

| Mode | Behavior |
|------|----------|
| `"raise"` | Raise `ToolDenied` exception |
| `"skip"` | Silently skip the tool call, continue |
| `"log"` | Log warning, skip the tool call |

**Mode: `raise` (default)**

```python
from tenuo.openai import guard, ToolDenied

client = guard(
    openai.OpenAI(),
    allow_tools=["search"],
    on_denial="raise"
)

try:
    response = client.chat.completions.create(...)
except ToolDenied as e:
    print(f"Blocked: {e.tool_name} — {e.reason}")
    # Blocked: send_email — Tool not in allowlist
```

**Mode: `skip`**

```python
client = guard(
    openai.OpenAI(),
    allow_tools=["search"],
    on_denial="skip"
)

# Unauthorized tool calls silently removed from response
response = client.chat.completions.create(...)
# response.choices[0].message.tool_calls contains only allowed calls
```

**Mode: `log`**

```python
import logging

logging.basicConfig(level=logging.WARNING)

client = guard(
    openai.OpenAI(),
    allow_tools=["search"],
    on_denial="log"
)

response = client.chat.completions.create(...)
# WARNING:tenuo.openai:Tool denied: send_email — Tool not in allowlist
# (tool call skipped, execution continues)
```

---

## 3. Streaming Protection

### 3.1 The Problem

Streaming responses arrive in chunks. A naive check-then-execute approach is vulnerable:

```
Chunk 1: {"name": "read_file", "arguments": "{\"path\": \"/data/..."}
         ↓ Check passes
Chunk 2: {"arguments": "...secret.pdf\"}"}
         ↓ Final path: /data/secret.pdf — NOT what was checked!
```

### 3.2 Buffer-Verify-Emit

Tier 1 buffers tool call chunks until complete, then verifies:

```
┌─────────────────────────────────────────────────────────┐
│                    OpenAI Stream                        │
│  chunk[0] ──► chunk[1] ──► ... ──► chunk[n] ──► done   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Tenuo Guardrail                        │
│                                                         │
│  1. BUFFER: Accumulate tool_call chunks silently        │
│  2. VERIFY: On completion, check tool + constraints     │
│  3. EMIT: Yield verified call OR denial                 │
└─────────────────────────────────────────────────────────┘
```

```python
# Streaming just works
async for chunk in client.chat.completions.create(..., stream=True):
    # Tool calls only emitted after verification
    print(chunk)
```

---

## 4. Responses API Support

```python
client = guard(openai.OpenAI(), allow_tools=["search"])

# Works with Responses API
async for event in client.responses.create(..., stream=True):
    if event.type == "response.tool_call.done":
        # Already verified by guardrail
        execute(event.tool_call)
```

---

## 5. OpenAI Agents SDK Support

The adapter integrates with OpenAI's Agents SDK for multi-agent workflows.

### 5.1 Guarding Agent Runs

```python
from openai import Agent
from tenuo.openai import guard_agent, Pattern

# Define agent
researcher = Agent(
    name="Researcher",
    model="gpt-4o",
    tools=[search_tool, read_file_tool],
)

# Apply guardrails
guarded_researcher = guard_agent(
    researcher,
    allow_tools=["search"],
    constraints={
        "search": {"max_results": Range(1, 10)}
    }
)

# Run with protection
result = guarded_researcher.run("Find Python tutorials")
```

### 5.2 Guarding Handoff Loops

```python
from openai import Agent, Swarm
from tenuo.openai import guard_swarm

# Define agents
triage = Agent(name="Triage", ...)
researcher = Agent(name="Researcher", ...)
writer = Agent(name="Writer", ...)

# Define allowed handoffs and constraints per agent
swarm = Swarm(agents=[triage, researcher, writer])

guarded_swarm = guard_swarm(
    swarm,
    agent_constraints={
        "Triage": {
            "allow_tools": ["handoff_to_researcher", "handoff_to_writer"],
        },
        "Researcher": {
            "allow_tools": ["search", "read_file"],
            "constraints": {
                "read_file": {"path": Pattern("/data/*")}
            }
        },
        "Writer": {
            "allow_tools": ["write_file"],
            "constraints": {
                "write_file": {"path": Pattern("/output/*")}
            }
        },
    }
)

# Run multi-agent loop with per-agent guardrails
result = guarded_swarm.run("Research and write a report on AI safety")
```

### 5.3 Agent-Level vs Swarm-Level Guards

| Scope | Use Case |
|-------|----------|
| `guard_agent()` | Single agent, simple workflows |
| `guard_swarm()` | Multi-agent, different constraints per agent |

---

## 6. Simple Handoffs

Tier 1 supports basic handoff restrictions (no cryptography):

```python
from tenuo.openai import guard, Agent, handoff

manager = Agent(name="Manager")
researcher = Agent(name="Researcher")

client = guard(
    openai.OpenAI(),
    allow_tools=["search", "handoff_to_researcher"],
    handoffs={
        "handoff_to_researcher": {
            "target": researcher,
            "allow_tools": ["search"],  # Researcher can only search
            "constraints": {
                "search": {"query": Pattern("*python*")}
            }
        }
    }
)
```

**Limitation:** No cryptographic proof that restrictions were enforced. For auditable delegation, use Tier 2.

---

## 7. Limitations

| Threat | Tier 1 Protection |
|--------|-------------------|
| LLM hallucinates tool call | ✅ Blocked by allowlist |
| Prompt injection changes args | ✅ Blocked by constraints |
| Streaming TOCTOU | ✅ Buffer-verify-emit |
| Attacker steals tool call | ❌ No protection (same process) |
| Compromised sub-agent | ❌ No cryptographic boundary |
| Need audit proof | ❌ No signatures |

**If you need the ❌ protections → Tier 2**

---

# Part II: Tier 2 — Cryptographic Warrants

## 8. Overview

Tier 2 adds cryptographic guarantees on top of Tier 1:

- ✅ Proof-of-Possession (stolen warrants are useless)
- ✅ Delegation chains with attenuation
- ✅ Cross-process/network trust boundaries
- ✅ Signed audit trails

**When you need Tier 2:**
- Agents in separate containers/services
- Regulatory audit requirements
- Zero-trust agent architectures
- Provable delegation chains

---

## 9. Activation

Same `guard()` API, add cryptographic parameters:

```python
from tenuo.openai import guard
from tenuo import Keypair, Warrant

# Generate or load keypair
agent_keypair = Keypair.generate()

# Receive warrant from control plane
warrant = Warrant.from_base64(os.environ["TENUO_WARRANT"])

# Same guard() call, now with crypto
client = guard(
    openai.OpenAI(),
    warrant=warrant,
    keypair=agent_keypair,
    trusted_roots=[control_plane_pubkey],
)
```

**What changes:**

| Behavior | Tier 1 | Tier 2 |
|----------|--------|--------|
| Tool allowlist | From `allow_tools` param | From `warrant.tools` |
| Constraints | From `constraints` param | From `warrant.constraints` |
| Verification | Local check | Chain verification + PoP |
| Handoffs | Config-based | Warrant attenuation |

---

## 10. Warrant-Based Authorization

### 10.1 How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Control Plane  │     │     Agent       │     │   Tool Call     │
│                 │     │                 │     │                 │
│  Issues warrant │────►│  Holds warrant  │────►│  Verified by    │
│  to agent       │     │  + keypair      │     │  guardrail      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │
                                ▼
                        Signs PoP for each
                        tool invocation
```

### 10.2 Verification Flow

Enforces invariants I1-I6 from [protocol-spec-v1.md](../spec/protocol-spec-v1.md#4-attenuation):

```python
def verify_tool_call(tool_name, args, warrant, pop_signature):
    # 1. Verify warrant chain
    #    - I1: child.issuer == parent.holder
    #    - I2: depth monotonicity
    #    - I3: TTL monotonicity
    #    - I4: capability monotonicity
    #    - I5: cryptographic linkage (parent_hash)
    leaf = tenuo.verify_chain(warrant.stack, trusted_roots)
    
    # 2. Check tool in warrant
    if tool_name not in leaf.tools:
        raise ToolNotAllowed(tool_name)
    
    # 3. Check constraints
    for param, constraint in leaf.tools[tool_name].items():
        if not constraint.check(args.get(param)):
            raise ConstraintViolation(param)
    
    # 4. Verify Proof-of-Possession
    #    - I6: holder binding
    verify_pop(leaf.holder, tool_name, args, pop_signature)
```

### 10.3 PoP Generation

The adapter automatically signs PoP for each tool execution:

```python
# Automatic — no code change needed
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[...],
    tools=[...]
)

# Internally:
# 1. LLM returns tool_call
# 2. Adapter signs PoP with agent's keypair
# 3. Adapter verifies warrant + PoP
# 4. If valid, tool_call is returned to app
```

---

## 11. Secure Handoffs

### 11.1 The Problem

When Agent A hands off to Agent B, how do we constrain B's authority?

**Tier 1:** Config says B can only use certain tools. No proof.

**Tier 2:** A cryptographically delegates a subset of its authority to B.

### 11.2 Delegation as Attenuation

```
┌──────────────────┐                    ┌──────────────────┐
│     Agent A      │                    │     Agent B      │
│    (Manager)     │                    │   (Researcher)   │
│                  │   handoff()        │                  │
│  Warrant W₀:     │ ─────────────────► │  Warrant W₁:     │
│  - search        │                    │  - search        │
│  - read_file     │   A signs W₁       │    (python only) │
│  - send_email    │   W₁ ⊂ W₀          │                  │
└──────────────────┘                    └──────────────────┘
```

**Invariants enforced (see [protocol-spec-v1.md §4](../spec/protocol-spec-v1.md#4-attenuation)):**
- I1: W₁.issuer = W₀.holder (A authorized the delegation)
- I3: W₁.expires_at ≤ W₀.expires_at (can't extend time)
- I4: W₁.tools ⊆ W₀.tools (can't add capabilities)
- I5: W₁.parent_hash = SHA256(W₀.payload) (chain linkage)

### 11.3 API

**Decorator syntax:**

```python
from tenuo.openai import secure_handoff, Pattern

@secure_handoff(
    source=manager,
    target=researcher,
    capabilities={
        "search": {"query": Pattern("*python*")}
    },
    ttl=300
)
def transfer_to_researcher():
    """Researcher can only search for Python topics."""
    return researcher
```

**Explicit syntax:**

```python
# Manager attenuates warrant for Researcher
child_warrant = (manager.warrant
    .grant_builder()
    .capability("search", query=Pattern("*python*"))
    .ttl(300)
    .holder(researcher.public_key)
    .build(manager.keypair))

researcher.set_warrant(child_warrant)
```

### 11.4 Runtime Flow

```
1. INTERCEPT
   Adapter sees handoff tool call

2. VALIDATE
   Manager's warrant allows delegation (depth < max_depth)

3. MINT
   Manager's keypair signs child warrant:
   - child.issuer = manager.warrant.holder
   - child.holder = researcher.public_key
   - child.tools = handoff config
   - child.parent_hash = SHA256(manager.warrant.payload)

4. INJECT
   Child warrant injected into researcher's context

5. CONTINUE
   Researcher runs with attenuated authority
```

---

## 12. Async/Queue Patterns

### 12.1 The Problem

Tool calls that spawn background jobs need PoP that survives queueing:

```
Agent ──► Queue ──► Worker (minutes later)
           │
           └── PoP must still be valid
```

### 12.2 Extended PoP Window

```python
client = guard(
    openai.OpenAI(),
    warrant=warrant,
    keypair=keypair,
    pop_ttl=300,  # 5 minutes for async patterns
)
```

### 12.3 Job Payload

```python
# Enqueue
job = {
    "tool_call": tool_call,
    "warrant_stack": warrant.stack.to_base64(),
    "pop_signature": pop.to_hex(),
    "pop_valid_until": int(time.time()) + 300,
}
queue.put(job)

# Worker
def process(job):
    if time.time() > job["pop_valid_until"]:
        raise PopExpired()
    
    warrant = WarrantStack.from_base64(job["warrant_stack"])
    verify_tool_call(
        job["tool_call"],
        warrant,
        bytes.fromhex(job["pop_signature"])
    )
    execute(job["tool_call"])
```

### 12.4 Idempotency

Warrants provide built-in deduplication keys for retry-safe execution:

```python
def process(job):
    # Generate deterministic dedup key from warrant + tool + args
    dedup_key = warrant.dedup_key(
        tool=job["tool_call"]["name"],
        args=job["tool_call"]["arguments"]
    )
    # Returns: SHA256(warrant.id || tool || canonical_args)
    
    # Check if already processed
    if redis.sismember("processed_calls", dedup_key):
        logger.info(f"Duplicate call skipped: {dedup_key}")
        return
    
    # Process and mark as done
    execute(job["tool_call"])
    redis.sadd("processed_calls", dedup_key)
```

**Note:** `dedup_key` is deterministic — same warrant + tool + args always produces the same key, enabling safe retries without duplicate execution.

---

## 13. Revocation

### 13.1 Signed Revocation List (SRL)

Tier 2 supports optional warrant revocation via SRL (see [protocol-spec-v1.md §16](../spec/protocol-spec-v1.md)):

```python
from tenuo import SignedRevocationList

# Load SRL from control plane
srl = SignedRevocationList.fetch("https://cp.example.com/srl")

client = guard(
    openai.OpenAI(),
    warrant=warrant,
    keypair=keypair,
    trusted_roots=[control_plane_pubkey],
    revocation_list=srl,  # Optional
)
```

### 13.2 Dynamic Revocation Checker

For real-time revocation checks:

```python
async def check_revocation(warrant_id: str) -> bool:
    """Return True if warrant is revoked."""
    return await redis.sismember("revoked_warrants", warrant_id)

client = guard(
    openai.OpenAI(),
    warrant=warrant,
    keypair=keypair,
    trusted_roots=[control_plane_pubkey],
    revocation_checker=check_revocation,  # Called on each tool execution
)
```

### 13.3 Revocation Tradeoffs

| Approach | Latency | Freshness |
|----------|---------|-----------|
| No revocation | 0ms | N/A (rely on short TTL) |
| Static SRL | 0ms (cached) | Minutes (refresh interval) |
| Dynamic checker | +1-5ms | Real-time |

**Recommendation:** Use short TTL warrants (5-15 min) instead of revocation when possible.

---

## 14. Configuration Reference

### 14.1 Full `guard()` Signature

```python
def guard(
    client: openai.OpenAI,
    *,
    # Tier 1: Guardrails
    allow_tools: list[str] | None = None,
    deny_tools: list[str] | None = None,
    constraints: dict[str, dict[str, Constraint]] | None = None,
    handoffs: dict[str, HandoffConfig] | None = None,
    on_denial: Literal["raise", "skip", "log"] = "raise",
    
    # Tier 2: Cryptographic (all optional, enables Tier 2 when present)
    warrant: Warrant | None = None,
    keypair: Keypair | None = None,
    trusted_roots: list[PublicKey] | None = None,
    pop_ttl: int = 120,  # seconds
    revocation_list: SignedRevocationList | None = None,
    revocation_checker: Callable[[str], Awaitable[bool]] | None = None,
    
    # Common
    stream_buffer_limit: int = 65536,  # bytes
) -> GuardedClient:
```

### 14.2 Environment Variables

| Variable | Description | Tier | Example |
|----------|-------------|------|---------|
| `TENUO_ALLOW_TOOLS` | Comma-separated allowlist | 1 | `search,read_file,calculate` |
| `TENUO_DENY_TOOLS` | Comma-separated denylist | 1 | `send_email,delete_file` |
| `TENUO_ON_DENIAL` | Denial handling mode | 1 | `raise` / `skip` / `log` |
| `TENUO_WARRANT` | Base64-encoded warrant | 2 | `gwFYnKo...` |
| `TENUO_PRIVATE_KEY` | Hex-encoded private key | 2 | `0a1b2c3d...` |
| `TENUO_TRUSTED_ROOTS` | Comma-separated public keys (hex) | 2 | `8a88e3dd...,8139770e...` |
| `TENUO_POP_TTL` | PoP validity (seconds) | 2 | `120` |

**Parsing examples:**

```python
# TENUO_ALLOW_TOOLS="search,read_file,calculate"
allow_tools = os.environ.get("TENUO_ALLOW_TOOLS", "").split(",")
# Result: ["search", "read_file", "calculate"]

# TENUO_TRUSTED_ROOTS="8a88e3dd7409f195...,8139770ea87d175f..."
trusted_roots = [
    PublicKey.from_hex(k.strip())
    for k in os.environ.get("TENUO_TRUSTED_ROOTS", "").split(",")
    if k.strip()
]
```

---

## 15. Error Reference

| Error | Code | Tier | Meaning |
|-------|------|------|---------|
| `ToolNotAllowed` | `T1_001` | 1+ | Tool not in allowlist/warrant |
| `ConstraintViolation` | `T1_002` | 1+ | Argument fails constraint |
| `HandoffDenied` | `T1_003` | 1+ | Handoff not permitted |
| `ChainNotAnchored` | `T2_001` | 2 | Root issuer not trusted |
| `SignatureInvalid` | `T2_002` | 2 | Warrant signature invalid |
| `WarrantExpired` | `T2_003` | 2 | Warrant past expiration |
| `WarrantRevoked` | `T2_004` | 2 | Warrant ID in revocation list |
| `PopInvalid` | `T2_005` | 2 | PoP signature invalid |
| `PopExpired` | `T2_006` | 2 | PoP outside time window |
| `DepthExceeded` | `T2_007` | 2 | Cannot delegate (terminal) |

---

## 16. Testing

### 16.1 Unit Testing Tier 1

```python
import pytest
from unittest.mock import Mock, patch
from tenuo.openai import guard, ToolDenied, Pattern

class TestTier1Guardrails:
    
    def test_allowed_tool_passes(self):
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = Mock(
            choices=[Mock(message=Mock(tool_calls=[
                Mock(function=Mock(name="search", arguments='{"query": "python"}'))
            ]))]
        )
        
        client = guard(mock_client, allow_tools=["search"])
        response = client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(response.choices[0].message.tool_calls) == 1
    
    def test_denied_tool_raises(self):
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = Mock(
            choices=[Mock(message=Mock(tool_calls=[
                Mock(function=Mock(name="send_email", arguments='{}'))
            ]))]
        )
        
        client = guard(mock_client, allow_tools=["search"], on_denial="raise")
        
        with pytest.raises(ToolDenied) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "send_email"
    
    def test_constraint_violation(self):
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = Mock(
            choices=[Mock(message=Mock(tool_calls=[
                Mock(function=Mock(
                    name="read_file",
                    arguments='{"path": "/etc/passwd"}'
                ))
            ]))]
        )
        
        client = guard(
            mock_client,
            allow_tools=["read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}},
            on_denial="raise"
        )
        
        with pytest.raises(ToolDenied) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert "constraint" in exc.value.reason.lower()
```

### 16.2 Unit Testing Tier 2

Use test vectors from [test-vectors.md](../spec/test-vectors.md):

```python
from tenuo import Keypair, Warrant, WarrantStack
from tenuo.openai import guard

# Deterministic keys from test vectors
CONTROL_PLANE_SEED = bytes.fromhex("01" * 32)
WORKER_SEED = bytes.fromhex("03" * 32)

class TestTier2Warrants:
    
    @pytest.fixture
    def control_plane_kp(self):
        return Keypair.from_seed(CONTROL_PLANE_SEED)
    
    @pytest.fixture
    def worker_kp(self):
        return Keypair.from_seed(WORKER_SEED)
    
    def test_valid_warrant_chain(self, control_plane_kp, worker_kp):
        # Create warrant matching test vector A.1
        warrant = (Warrant.mint_builder()
            .capability("read_file")
            .holder(worker_kp.public_key)
            .ttl(3600)
            .mint(control_plane_kp))
        
        mock_client = Mock()
        client = guard(
            mock_client,
            warrant=warrant,
            keypair=worker_kp,
            trusted_roots=[control_plane_kp.public_key],
        )
        
        # Should not raise
        assert client is not None
    
    def test_chain_not_anchored(self, worker_kp):
        # Warrant signed by unknown issuer
        rogue_kp = Keypair.generate()
        warrant = (Warrant.mint_builder()
            .capability("read_file")
            .holder(worker_kp.public_key)
            .mint(rogue_kp))  # Not trusted
        
        mock_client = Mock()
        
        with pytest.raises(ChainNotAnchored):
            guard(
                mock_client,
                warrant=warrant,
                keypair=worker_kp,
                trusted_roots=[],  # Empty trusted roots
            )
```

### 16.3 Testing Streaming Edge Cases

```python
class TestStreamingEdgeCases:
    
    @pytest.mark.asyncio
    async def test_malformed_chunk_rejected(self):
        """Chunks with invalid JSON should be rejected."""
        mock_stream = AsyncMock()
        mock_stream.__aiter__.return_value = [
            Mock(type="tool_call.chunk", arguments="{invalid json"),
            Mock(type="tool_call.done"),
        ]
        
        client = guard(Mock(), allow_tools=["search"])
        
        with pytest.raises(MalformedToolCall):
            async for _ in client._guard_stream(mock_stream):
                pass
    
    @pytest.mark.asyncio
    async def test_oversized_buffer_rejected(self):
        """Tool calls exceeding buffer limit should be rejected."""
        # Generate chunks totaling > 64KB
        large_arg = "x" * 100_000
        mock_stream = AsyncMock()
        mock_stream.__aiter__.return_value = [
            Mock(type="tool_call.chunk", arguments=f'{{"data": "{large_arg}"}}'),
            Mock(type="tool_call.done"),
        ]
        
        client = guard(
            Mock(),
            allow_tools=["search"],
            stream_buffer_limit=65536  # 64KB
        )
        
        with pytest.raises(BufferOverflow):
            async for _ in client._guard_stream(mock_stream):
                pass
    
    @pytest.mark.asyncio
    async def test_toctou_attack_blocked(self):
        """Argument changes across chunks should use final value."""
        mock_stream = AsyncMock()
        mock_stream.__aiter__.return_value = [
            # First chunk: looks safe
            Mock(type="tool_call.chunk", 
                 name="read_file",
                 arguments='{"path": "/data/'),
            # Second chunk: completes to unsafe path
            Mock(type="tool_call.chunk",
                 arguments='../../../etc/passwd"}'),
            Mock(type="tool_call.done"),
        ]
        
        client = guard(
            Mock(),
            allow_tools=["read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}},
            on_denial="raise"
        )
        
        # Should reject based on FINAL assembled path
        with pytest.raises(ToolDenied):
            async for _ in client._guard_stream(mock_stream):
                pass
```

---

## 17. Migration Path

### 17.1 Start with Tier 1

```python
# Day 1: Basic protection
client = guard(
    openai.OpenAI(),
    allow_tools=["search", "read_file"],
    constraints={
        "read_file": {"path": Pattern("/data/*")}
    }
)
```

### 17.2 Add Tier 2 When Needed

```python
# Later: Add cryptographic guarantees
# No code restructure — just add parameters

client = guard(
    openai.OpenAI(),
    # Tier 1 config still works (as fallback/documentation)
    allow_tools=["search", "read_file"],
    constraints={
        "read_file": {"path": Pattern("/data/*")}
    },
    # Tier 2 additions
    warrant=warrant,        # Overrides allow_tools/constraints
    keypair=keypair,
    trusted_roots=[root_key],
)
```

### 17.3 Precedence Rules

When both Tier 1 and Tier 2 parameters are present:

| Parameter | Behavior |
|-----------|----------|
| `allow_tools` | Ignored if `warrant` present (warrant is authoritative) |
| `constraints` | Ignored if `warrant` present |
| `on_denial` | Applies to both tiers |
| `handoffs` | Config-based if no warrant, crypto-based if warrant |

---

## 18. Security Considerations

### 18.1 Tier 1

- **Trust boundary:** Same process. If attacker has code execution, game over anyway.
- **Replay:** Not applicable — no tokens to replay.
- **Audit:** Logs only, no cryptographic proof.

### 18.2 Tier 2

- **Key storage:** Private keys MUST NOT be logged or serialized to disk unencrypted.
- **Clock sync:** PoP requires synchronized clocks (±30s tolerance).
- **Warrant refresh:** Short-lived warrants preferred; refresh from control plane.

### 18.3 Streaming

Both tiers use buffer-verify-emit. Memory bounded by `stream_buffer_limit` (default 64KB).

---

## Appendix A: Complete Example

```python
import openai
from tenuo.openai import guard, guard_agent, secure_handoff, Agent, Pattern, Range, OneOf
from tenuo import Keypair, Warrant

# ============================================================
# TIER 1: Quick Start (no crypto)
# ============================================================

client_simple = guard(
    openai.OpenAI(),
    allow_tools=["search", "calculate"],
    constraints={
        "search": {"max_results": Range(1, 10)},
        "calculate": {"operation": OneOf(["add", "sub"])},
    }
)

response = client_simple.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Search for Python tutorials"}],
    tools=[SEARCH_TOOL, CALCULATE_TOOL],
)

# ============================================================
# TIER 2: Full Crypto (when you need it)
# ============================================================

# Setup keys
control_plane_kp = Keypair.from_env("CONTROL_PLANE_KEY")
manager_kp = Keypair.generate()
researcher_kp = Keypair.generate()

# Control plane issues warrant to manager
manager_warrant = (Warrant.mint_builder()
    .capability("search")
    .capability("read_file", path=Pattern("/data/*"))
    .capability("send_email")
    .holder(manager_kp.public_key)
    .ttl(3600)
    .max_depth(3)
    .mint(control_plane_kp))

# Manager agent
manager = Agent(
    name="Manager",
    keypair=manager_kp,
    warrant=manager_warrant,
)

# Researcher agent (no warrant yet)
researcher = Agent(
    name="Researcher",
    keypair=researcher_kp,
)

# Secure handoff: Manager delegates subset to Researcher
@secure_handoff(
    source=manager,
    target=researcher,
    capabilities={
        "search": {"query": Pattern("*python*")}
    },
    ttl=300
)
def transfer_to_researcher():
    return researcher

# Guarded client with full crypto
client_secure = guard(
    openai.OpenAI(),
    warrant=manager_warrant,
    keypair=manager_kp,
    trusted_roots=[control_plane_kp.public_key],
)

# Use exactly like Tier 1
response = client_secure.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Research Python async patterns"}],
    tools=[SEARCH_TOOL, HANDOFF_TOOL],
)
```

---

## Appendix B: Comparison with Alternatives

| Feature | Tier 1 | Tier 2 | LangChain Guardrails | Guardrails AI |
|---------|--------|--------|---------------------|---------------|
| Tool allowlist | ✅ | ✅ | ✅ | ✅ |
| Argument constraints | ✅ | ✅ | ⚠️ Limited | ✅ |
| Streaming protection | ✅ | ✅ | ❌ | ❌ |
| Cryptographic PoP | ❌ | ✅ | ❌ | ❌ |
| Delegation chains | ❌ | ✅ | ❌ | ❌ |
| Cross-process trust | ❌ | ✅ | ❌ | ❌ |
| Signed audit trail | ❌ | ✅ | ❌ | ❌ |
| Revocation | ❌ | ✅ | ❌ | ❌ |
| Setup complexity | 3 lines | 20 lines | 10 lines | 15 lines |

---

## References

- [Tenuo Protocol Specification](../spec/protocol-spec-v1.md)
- [Tenuo Wire Format](../spec/wire-format-v1.md)
- [Tenuo Test Vectors](../spec/test-vectors.md)
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) — JSON Canonicalization Scheme
- [OpenAI API Reference](https://platform.openai.com/docs/api-reference)
- [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)

---

## Changelog

- **2.2 (2025-01-09):** Added testing section, Agents SDK support, revocation, idempotency
- **2.1:** Two-tier architecture (Guardrails + Warrants)
- **2.0:** Responses API, secure handoffs, JCS
- **1.0:** Initial specification
