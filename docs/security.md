---
title: Security
description: Threat model, PoP, integration safety, and best practices
---

# Tenuo Security Model

This page covers what Tenuo protects against, how Proof-of-Possession works, integration safety mechanisms, and deployment best practices.

## Core Security Properties

| Property | How It Works |
|----------|--------------|
| **Scoped** | Warrants specify exactly which tools and constraints are allowed |
| **Temporal** | TTL checked on every authorization; expired warrants are rejected |
| **Bound** | Proof-of-Possession (PoP) required; stolen warrant is useless without private key |
| **Delegatable** | Parent warrants mint narrower children; signature chain proves lineage |
| **Revocable** | Signed revocation lists (SRL) checked locally |

---

## Proof-of-Possession (PoP)

Warrants are **bound to keypairs**. To use a warrant, you must prove you hold the private key.

```python
# Attenuate with explicit capability (POLA)
warrant = (root_warrant.attenuate()
    .capability("protected_tool", {"path": Pattern("/data/*")})
    .holder(worker_keypair.public_key)
    .grant(root_keypair))  # Root keypair signs (they hold the parent warrant)

with warrant_scope(warrant), key_scope(worker_keypair):
    await protected_tool(...)
```

If an attacker steals the warrant token alone, they can't use it without the private key.

### Replay Protection & Statelessness

Tenuo uses time-windowed PoP signatures (~2 minutes) to allow for **stateless verification** and distributed clock skew. 

> [!IMPORTANT]
> **Residual Replay Risk**: Because the scheme is stateless (no nonce tracking in core), a valid PoP signature can be replayed **within the ~2 minute window**.

This is an intentional design trade-off for scalability. The protection prevents an attacker from using a stolen warrant *after* the window closes, but does not prevent immediate replay of the exact same request.

**Mitigation**: For sensitive tools, implement **application-level deduplication**:

```python
# Use the built-in helper to generate a deterministic cache key
dedup_key = warrant.dedup_key(tool, args)

if cache.exists(dedup_key):  # Redis, memcached, or in-memory
    raise ReplayError("Duplicate request")
    
authorizer.check(warrant, tool, args)
cache.set(dedup_key, "1", ttl=120)  # 120s covers the ~2min window
```

**When to implement deduplication:**
- High-value operations (payments, deletions, privilege escalation)
- Environments where network interception is possible
- Multi-step workflows where replay could cause inconsistency

**When you can skip:**
- Read-only operations (replaying a "read" is usually harmless)
- Idempotent operations (replaying has no additional effect)
- Very short-lived warrants (TTL < 2 min makes PoP window irrelevant)

---

## Monotonic Attenuation

Authority can only **shrink**, never expand:

| What | Rule |
|------|------|
| **Tools** | Child can only use a subset of parent's tools |
| **Constraints** | Child constraints must be tighter than parent's |
| **TTL** | Child cannot outlive parent |
| **Depth** | `max_depth` can only decrease |

```python
# Parent has broad capabilities
parent = (Warrant.mint_builder()
    .capability("read", {"path": Pattern("/*")})
    .capability("write", {"path": Pattern("/*")})
    .capability("delete", {"path": Pattern("/*")})
    .holder(keypair.public_key)
    .ttl(3600)
    .mint(keypair))

# Child can only narrow
child = (parent.attenuate()
    .capability("read", {"path": Pattern("/data/*")})
    .grant(keypair))  # Keypair signs (they hold the parent warrant)

# This would FAIL:
child = (parent.attenuate()
    .capability("execute", {})  # FAILS (parent doesn't have "execute")
    .grant(keypair))
```

---

## Threat Model

### What Tenuo Protects Against

**Prompt injection**: Even if the LLM is tricked, attenuated scope limits damage.

**Confused deputy**: A node can only use tools in its warrant.

**Credential theft**: Warrant is useless without the private key (PoP).

**Stale permissions**: TTL forces expiration.

**Privilege escalation**: Monotonic attenuation means a child can never exceed its parent.

**Replay attacks**: Timestamp windows (~2 min) prevent signature reuse.

### What Tenuo Does NOT Protect Against

**Container compromise**: If an attacker has both keypair and warrant, they have full access within that scope. Use separate containers with separate keypairs.

**Malicious node code**: Same trust boundary as auth logic. Use code review and sandboxing.

**Control plane compromise**: Can mint arbitrary warrants. Secure your control plane.

**Raw API calls**: Bypass Tenuo entirely. 1. **Wrapper usage** - All tools must be protected with `@guard` or `guard()`. Use Network Policies.

#### Defense in Depth: Network Policies

Tenuo handles **authorization** - what an agent is *allowed* to do. For **exfiltration prevention**, use Kubernetes Network Policies:

```yaml
# Restrict agent egress to only approved services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
spec:
  podSelector:
    matchLabels:
      app: agent
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: tool-proxy  # Only allow calls to protected tool proxy
```

**Tenuo + Network Policies = complete coverage:**
- Tenuo: Prevents unauthorized tool usage *through* your API
- Network Policies: Prevents bypassing your API entirely

---

## Cost Containment

Prompt injection attacks can cause financial damage by tricking agents into making expensive API calls. Tenuo provides **stateless** mechanisms to contain costs while your infrastructure handles rate limiting.

### Parameter-Level Budget Constraints

Constrain cost-driving parameters directly in the warrant:

```python
warrant = (Warrant.mint_builder()
    .capability("call_llm", {
        "max_tokens": Range.max_value(1000),      # Cap output tokens
        "model": OneOf(["gpt-3.5-turbo"]),        # No expensive models
    })
    .capability("search_api", {
        "max_results": Range.max_value(10),       # Limit results per call
    })
    .ttl(60)  # 1 minute window
    .mint(keypair))
```

### Single-Use Warrants for Expensive Operations

Issue terminal warrants (cannot be delegated) for each expensive call:

```python
async def safe_expensive_call(tool_name: str, params: dict):
    # One warrant per operation - orchestrator controls issuance
    single_use = (Warrant.mint_builder()
        .capability(tool_name, params)
        .ttl(30)        # 30 second window
        .terminal()     # max_depth=0, cannot delegate
        .mint(keypair))
    
    async with grant(single_use):
        return await execute_tool(tool_name, params)
```

### Orchestrator-Level Budget Tracking

Track call counts in your orchestrator:

```python
class BudgetedOrchestrator:
    def __init__(self, max_calls: int = 10):
        self.remaining_calls = max_calls
    
    async def execute_with_budget(self, task):
        if self.remaining_calls <= 0:
            raise BudgetExhausted("Call limit reached")
        
        self.remaining_calls -= 1
        
        # Fresh short-lived warrant for this call
        warrant = (Warrant.mint_builder()
            .capability(task.tool, task.constraints)
            .ttl(30)
            .terminal()
            .mint(self.keypair))
        
        async with grant(warrant):
            return await task.execute()
```

### Gateway-Side Rate Limiting

Your API gateway should enforce call counts per warrant:

```yaml
# Kong rate limiting example
plugins:
  - name: rate-limiting
    config:
      minute: 10                    # 10 calls per minute per warrant
      policy: local
      header_name: X-Tenuo-Warrant-Id
```

### Strategy Summary

| Strategy | Where | Stateful? | Best For |
|----------|-------|-----------|----------|
| Parameter constraints | Warrant | ❌ No | Limiting per-call cost |
| Short TTLs + terminal | Warrant | ❌ No | Time-boxing exposure |
| Orchestrator budget | Application | ✅ In-memory | Task-level budgets |
| Gateway rate limiting | Infrastructure | ✅ Yes | Hard call limits |

**Design principle:** Tenuo handles **authorization** (what CAN be done). Your infrastructure handles **rate limiting** (how MANY times). This keeps warrant verification fast (~27μs), offline, and stateless.

---

## Integration Safety

> **The Primary Attack Surface: Integration Mistakes**

Tenuo's core is cryptographically secure. But **integration bugs** are the primary attack surface:
- Forgetting to add `@guard` to a tool
- Missing `warrant_scope()` or `mint()`
- Dynamic nodes without wrappers
- Wrapper that checks tool names but skips `validate()`

### Strict Mode

**Fail-closed enforcement**: Panic if a tool is called without warrant context.

```python
from tenuo import configure, SigningKey

configure(
    issuer_key=SigningKey.generate(),
    strict_mode=True,  # Enforce warrant presence
)
```

**Behavior:**

```python
@guard(tool="read_file")
def read_file(path: str):
    return open(path).read()

# Called without warrant context
read_file("/data/test.txt")
# RuntimeError: [MISSING_CONTEXT] No warrant context available for tool 'read_file'.
```

**When to use:**
- ✅ **Development/staging** - Catch integration bugs early
- ✅ **CI/CD** - Fail tests if warrant context is missing  
- ⚠️ **Production** - Only if you want hard failures

### Warning Mode

**Loud warnings**: Log and warn (but don't crash) when tools are called without warrants.

```python
configure(
    issuer_key=SigningKey.generate(),
    issuer_key=SigningKey.generate(),
    warn_on_missing_warrant=True,
)
```

> [!CAUTION]
> **Production Safety**: Never set `TENUO_ENV="test"` in production environments.
> This environment variable enables special test-only bypass modes (like `allow_any()`) which
> completely disable authorization checks. Tenuo will emit warnings if this is detected,
> but for defense-in-depth, ensure your production manifests (Helm, Terraform) strictly avoid this variable.

### Mode Comparison

| Mode | Missing Warrant Behavior | Use Case |
|------|-------------------------|----------|
| **Default** | Raises `Unauthorized` | Production (minimal overhead) |
| **`warn_on_missing_warrant=True`** | Warns + raises | Development/staging |
| **`strict_mode=True`** | Panics with `RuntimeError` | CI/CD, strict production |

### Common Integration Bugs

| Bug | Detection |
|-----|-----------|
| Missing `@guard` decorator | Code review, linting |
| Missing `warrant_scope()` | Strict mode catches |
| Dynamic node without wrapper | Strict mode (if tools decorated) |
| Wrapper skips `validate()` | Integration tests |

### Async Context Sharp Edges

```python
# ✅ Works correctly
async with mint(Capability("search")):
    result = await search("query")

# ❌ Context not propagated (task created BEFORE context)
task = asyncio.create_task(search("query"))
async with mint(Capability("search")):
    await task  # Task runs without context

# ✅ Fix: create task INSIDE context
async with mint(Capability("search")):
    task = asyncio.create_task(search("query"))
    await task
```

---

## Control Plane Deployment Models

The control plane holds the **root signing key** and issues the initial warrant for each agent network.

### Level 1: Embedded (Development)

```python
root_key = SigningKey.from_env("TENUO_ROOT_KEY")
warrant = (Warrant.mint_builder()...mint(root_key))
```

| | |
|---|---|
| **Pros** | Zero infrastructure overhead |
| **Cons** | RCE on orchestrator exposes root key |
| **Use case** | Local dev, CI/CD, non-critical agents |

### Level 2: Isolated Signing Service (Production)

```
Orchestrator  →  gRPC/mTLS  →  Signing Service (holds key)
```

| | |
|---|---|
| **Pros** | Key isolation; RCE can only request warrants |
| **Cons** | One additional service to run |
| **Use case** | Production Kubernetes, standard SaaS |

### Level 3: Hardware Root of Trust (High Assurance)

```
Orchestrator  →  AWS KMS / GCP KMS / HSM  →  Signed warrant
```

| | |
|---|---|
| **Pros** | Key is non-exportable; instant revocation via IAM |
| **Cons** | ~50-100ms issuance latency |
| **Use case** | FinTech, HealthTech, regulated industries |

---

## Cycle Protection

Tenuo prevents infinite delegation cycles through multiple layers:

1. **Warrant ID Tracking**: Same ID twice → fail
2. **Depth Limits**: `MAX_DELEGATION_DEPTH = 16`
3. **Monotonic Attenuation**: Each warrant strictly weaker
4. **Self-Issuance Prevention**: Issuer warrants cannot grant execution to themselves

---

## Protocol Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_DELEGATION_DEPTH` | 16 | Prevents unbounded delegation chains |
| `MAX_WARRANT_TTL_SECS` | 90 days | Protocol ceiling for warrant lifetime |
| `MAX_WARRANT_SIZE` | 64 KB | Prevents memory exhaustion |
| `MAX_CONSTRAINT_DEPTH` | 16 | Prevents stack overflow in nested constraints |
| PoP Timestamp Window | ~2 min | Replay attack protection |

**TTL Note**: 90 days is the protocol maximum. Deployments should configure stricter limits (e.g., 24 hours for production). Default TTL is 5 minutes.

---

## Best Practices

### 1. Wrap All Tools

```python
# Good
@guard(tool="delete_file")
def delete_file(path: str): ...

# Bad: bypasses Tenuo
await http_client.delete(url)
```

### 2. Use Short TTLs

```python
# Good: 5 minute TTL
warrant = (Warrant.mint_builder()...ttl(300).mint(keypair))

# Risky: 24 hour TTL
warrant = (Warrant.mint_builder()...ttl(86400).mint(keypair))
```

### 3. Principle of Least Privilege

```python
# Good: only what's needed
with mint(Capability("read_file", path="/data/reports/*")):
    ...

# Risky: overly broad
with mint(
    Capability("read_file", path="/*"),
    Capability("write_file", path="/*"),
    Capability("delete_file", path="/*")
):
    ...
```

### 4. Separate SigningKeys per Trust Boundary

- Control plane: One keypair
- Each worker: Own keypair
- Don't share keypairs across trust boundaries

### 5. Use Strict Mode in Tests

```python
# conftest.py
@pytest.fixture(scope="session", autouse=True)
def tenuo_strict():
    configure(
        issuer_key=SigningKey.generate(),
        dev_mode=True,
        strict_mode=True,  # Fail tests if warrant missing
    )
```

---

## See Also

- [AI Agent Patterns](./ai-agents) — P-LLM/Q-LLM, prompt injection defense, multi-agent security
- [Enforcement Models](./enforcement) — In-process, sidecar, gateway deployment patterns
- [Argument Extraction](./argument-extraction) — How tool arguments are extracted and validated
- [Protocol](./protocol) — Full protocol details
- [Proxy Configs](./proxy-configs) — Envoy, Istio, nginx integration
- [API Reference](./api-reference) — Function signatures
- [Constraints](./constraints) — Constraint types and usage
