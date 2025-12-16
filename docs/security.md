---
title: Security
description: Threat model, PoP requirements, best practices
---

# Tenuo Security Model

> Understanding what Tenuo protects against and how it works.

---

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
# The warrant is bound to worker_keypair.public_key
warrant = root_warrant.attenuate(
    holder=worker_keypair.public_key,  # Bound to this key
    ...
)

# To use it, you need the private key
with set_warrant_context(warrant), set_keypair_context(worker_keypair):
    # PoP signature generated automatically
    await protected_tool(...)
```

**Why this matters**: If an attacker steals just the warrant token, they can't use it without the private key.

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
# Parent allows: tools=["read", "write", "delete"], path="/*"
parent = Warrant.issue(tools=["read", "write", "delete"], path=Pattern("/*"), ...)

# Child can only narrow:
child = parent.attenuate(
    tools=["read"],           # ✅ Subset
    path=Pattern("/data/*"),  # ✅ Tighter
    ...
)

# This would FAIL:
child = parent.attenuate(
    tools=["read", "execute"],  # ❌ "execute" not in parent
    ...
)
```

---

## Threat Model

### What Tenuo Protects Against

| Threat | Protection |
|--------|------------|
| **Prompt injection** | Even if LLM is tricked, attenuated scope limits damage |
| **Confused deputy** | Node can only use tools in its warrant |
| **Credential theft** | Warrant useless without private key (PoP) |
| **Stale permissions** | TTL forces expiration |
| **Privilege escalation** | Monotonic attenuation; child cannot exceed parent |
| **Replay attacks** | Timestamp windows (~2 min) prevent signature reuse |

### What Tenuo Does NOT Protect Against

| Threat | Why | Mitigation |
|--------|-----|------------|
| **Container compromise** | Attacker has both keypair + warrant | Use separate containers with separate keypairs |
| **Malicious node code** | Same trust boundary as auth logic | Code review, sandboxing |
| **Control plane compromise** | Can mint arbitrary warrants | Secure control plane infrastructure |
| **Raw API calls** | Bypass Tenuo entirely | Wrap ALL tools with `@lockdown` + Network Policies |

#### Defense in Depth: Network Policies

Tenuo handles **authorization** — what an agent is *allowed* to do. For **exfiltration prevention** (stopping agents from making raw API calls that bypass Tenuo), use Kubernetes Network Policies:

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

## Cycle Protection

Tenuo prevents infinite delegation cycles through multiple layers:

### 1. Warrant ID Tracking
Each warrant has a unique ID. If the same ID appears twice during chain verification → fail.

### 2. Chain Length Limits
- `MAX_ISSUER_CHAIN_LENGTH = 8` — Max embedded chain links
- `MAX_DELEGATION_DEPTH = 64` — Max payload depth counter

### 3. Monotonic Attenuation
Even if A→B→A happens (holder cycling), each warrant is strictly weaker. The third warrant has less authority than the first.

### 4. Self-Issuance Prevention
Issuer warrants cannot grant execution capabilities to themselves.

---

## Protocol Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_DELEGATION_DEPTH` | 64 | Prevents unbounded delegation chains |
| `MAX_ISSUER_CHAIN_LENGTH` | 8 | Prevents DoS during verification |
| `MAX_WARRANT_SIZE` | 1 MB | Prevents memory exhaustion |
| `MAX_CONSTRAINT_DEPTH` | 16 | Prevents stack overflow in nested constraints |
| PoP Timestamp Window | ~2 min | Replay attack protection |

---

## Best Practices

### 1. Wrap All Tools
```python
# ✅ Good: Tool is protected
@lockdown(tool="delete_file")
def delete_file(path: str): ...

# ❌ Bad: Raw call bypasses Tenuo
await http_client.delete(url)
```

### 2. Use Short TTLs
```python
# ✅ Good: 5 minute TTL for task
warrant = Warrant.issue(..., ttl_seconds=300)

# ⚠️ Risky: 24 hour TTL
warrant = Warrant.issue(..., ttl_seconds=86400)
```

### 3. Principle of Least Privilege
```python
# ✅ Good: Only what's needed
with root_task(tools=["read_file"], path="/data/reports/*"):
    ...

# ⚠️ Risky: Overly broad
with root_task(tools=["read_file", "write_file", "delete_file"], path="/*"):
    ...
```

### 4. Separate Keypairs per Trust Boundary
- Control plane: One keypair
- Each worker: Own keypair
- Don't share keypairs across trust boundaries

---

## See Also

- [Argument Extraction](./argument-extraction) — How tool arguments are extracted and validated
- [Protocol](./protocol) — Full protocol details
- [Deployment Patterns](./deployment) — Envoy, Istio, nginx integration
- [API Reference](./api-reference) — Function signatures
- [Constraints](./constraints) — Constraint types and usage
