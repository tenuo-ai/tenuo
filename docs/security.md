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

Warrants are **bound to keys**. To use a warrant, you must prove you hold the private key.

```python
# Attenuate with explicit capability (POLA)
warrant = (root_warrant.grant_builder()
    .capability("protected_tool", path=Subpath("/data"))
    .holder(worker_key.public_key)
    .grant(root_key))  # Root key signs (they hold the parent warrant)

with warrant_scope(warrant), key_scope(worker_key):
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

> [!NOTE]
> **Performance & Responsibility**: You are responsible for provisioning and maintaining the storage backend (e.g., Redis). Tenuo provides the deterministic key but does not manage the statestore. The latency and availability of this check depend entirely on your storage infrastructure.

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
    .capability("read", path=Subpath("/"))
    .capability("write", path=Subpath("/"))
    .capability("delete", path=Subpath("/"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Child can only narrow
child = (parent.grant_builder()
    .capability("read", path=Subpath("/data"))
    .grant(key))  # Key signs (they hold the parent warrant)

# This would FAIL:
child = (parent.grant_builder()
    .capability("execute")  # FAILS (parent doesn't have "execute")
    .grant(key))
```

---

## Revocation

Tenuo's wire format includes support for signed revocation lists (SRLs) for emergency warrant cancellation. The revocation system allows the Control Plane, issuers, or warrant holders to revoke warrants before they expire.

> [!NOTE]
> **Development Status**: Revocation is supported in the protocol specification but full integration with the SDK is being finalized for v0.2. The wire format types (`RevocationRequest`, `SignedRevocationList`) are available but end-to-end workflows are still under development.

**Design philosophy**: Tenuo favors **short TTLs (5-15 minutes) over revocation**. A warrant that expires naturally is simpler than one that requires emergency cancellation. Use revocation only when TTL alone cannot meet your security requirements (e.g., long-lived sessions where key compromise must be handled mid-session).

For technical details, see the [wire format specification](spec/wire-format-v1.md#17-signed-revocation-list-srl-wire-format).

---

## Production Deployment Policy

> [!IMPORTANT]
> **Tier 2 (Warrant + PoP) is the recommended pattern for production systems.**
>
> While Tier 1 guardrails provide effective protection against prompt injection and accidental misuse, they can be modified or bypassed by anyone with code access. For production environments where insider threats or container compromise are concerns, use Tier 2 with cryptographic warrants.

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

**Container compromise**: If an attacker has both signing key and warrant, they have full access within that scope. Use separate containers with separate keys.

**Malicious node code**: Same trust boundary as auth logic. Use code review and sandboxing.

**Control plane compromise**: Can mint arbitrary warrants. Secure your control plane.

**Raw API calls**: Bypass Tenuo entirely.
    
**Mitigations:**
1.  **Wrapper usage** - All tools must be protected with `@guard` or `guard()`.
2.  **Network Policies** - Restrict egress to prevent data exfiltration.

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

## Denial-of-Service (DoS) Protection

Tenuo is designed to protect validation services from CPU exhaustion attacks.

### Fail-Fast Cryptography
The authorization flow is strictly ordered to reject unauthorized requests before performing expensive logic:

1. **Expiration Check** (Values comparison): $\mathcal{O}(1)$ - Fails instantly if expired.
2. **Proof-of-Possession** (Ed25519 Verify): $\mathcal{O}(1)$ - Verifies the request signature. Fails fast if signature is invalid or missing.
3. **Constraint Matching** (Regex/Looping): $\mathcal{O}(N)$ - Only executed **after** the request is cryptographically authenticated.

**Why this matters**: An attacker cannot force the server to evaluate complex regex or deep constraint trees by sending 100k requests, because looking up constraints happens *after* the signature check. If they don't have a valid private key, the request is dropped with minimal CPU cost.

### Fail-Closed Validation (Zero Trust Data)
Tenuo extends Zero Trust beyond identity (keys) to **data validation**.

**Philosophy**: Ambiguity is a vulnerability. If Tenuo encounters data it doesn't strictly understand or expect, it fails closed (denies).

1.  **Closed-World Arguments**: If you confine a tool with constraints, *any* unmentioned argument triggers a denial. Zero Trust means no "shadow arguments" can sneak past validation.
2.  **Unknown Constraints**: If the runtime encounters a constraint type it doesn't recognize (e.g., mismatched version), it defaults to **DENY**. It never fails open.
3.  **Parser Safety**: URL and Path parsers are hardened against polyglot payloads (e.g., JSON-in-URL). If a payload looks malformed or ambiguous, it is rejected.

---

## Cost Containment

Prompt injection attacks can cause financial damage by tricking agents into making expensive API calls. Tenuo provides **stateless** mechanisms to contain costs while your infrastructure handles rate limiting.

### Parameter-Level Budget Constraints

Constrain cost-driving parameters directly in the warrant:

```python
warrant = (Warrant.mint_builder()
    .capability("call_llm",
        max_tokens=Range.max_value(1000),      # Cap output tokens
        model=OneOf(["gpt-3.5-turbo"]))        # No expensive models
    .capability("search_api",
        max_results=Range.max_value(10))       # Limit results per call
    .ttl(60)  # 1 minute window
    .mint(key))
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
        .mint(key))
    
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
            .mint(self.key))
        
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
      header_name: X-Tenuo-Warrant-Id  # Custom header for rate limiting (distinct from auth)
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
2. **Depth Limits**: `MAX_DELEGATION_DEPTH = 64`
3. **Monotonic Attenuation**: Each warrant strictly weaker
4. **Self-Issuance Prevention**: Issuer warrants cannot grant execution to themselves

---

## Protocol Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_DELEGATION_DEPTH` | 64 | Prevents unbounded delegation chains |
| `MAX_WARRANT_TTL_SECS` | 90 days | Protocol ceiling for warrant lifetime |
| `MAX_WARRANT_SIZE` | 64 KB | Prevents memory exhaustion (single warrant) |
| `MAX_STACK_SIZE` | 256 KB | Max WarrantStack encoded size (chain) |
| `MAX_CONSTRAINT_DEPTH` | 32 | Prevents stack overflow in nested constraints |
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
warrant = (Warrant.mint_builder()...ttl(300).mint(key))

# Risky: 24 hour TTL
warrant = (Warrant.mint_builder()...ttl(86400).mint(key))
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

- Control plane: One signing key
- Each worker: Own signing key
- Don't share keys across trust boundaries

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
- [Protocol Specification](./spec/protocol-spec-v1) — Full protocol details
- [Proxy Configs](./proxy-configs) — Envoy, Istio, nginx integration
- [API Reference](./api-reference) — Function signatures
- [Constraints](./constraints) — Constraint types and usage
