---
title: Security
description: Threat model, PoP requirements, best practices
---

# Tenuo Security Model

This page covers what Tenuo protects against, how Proof-of-Possession works, and deployment best practices.

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
warrant = root_warrant.attenuate(
    holder=worker_keypair.public_key,
    ...
)

with set_warrant_context(warrant), set_keypair_context(worker_keypair):
    await protected_tool(...)
```

If an attacker steals the warrant token alone, they can't use it without the private key.

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
    tools=["read"],
    path=Pattern("/data/*"),
    ...
)

# This would FAIL:
child = parent.attenuate(
    tools=["read", "execute"],  # FAILS
    ...
)
```

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

**Raw API calls**: Bypass Tenuo entirely. Wrap ALL tools with `@lockdown` and use Network Policies.

#### Defense in Depth: Network Policies

Tenuo handles **authorization**—what an agent is *allowed* to do. For **exfiltration prevention**, use Kubernetes Network Policies:

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

## Control Plane Deployment Models

The control plane holds the **root signing key** and issues the initial warrant for each agent network. It is *not* in the data path. Ttool execution never touches it, so it can be secured with high-latency/high-security patterns without affecting agent performance.

Choose a model based on your threat model.

### Level 1: Embedded (Development)

The orchestrator holds the root key directly.
```python
# Development only
root_key = Keypair.from_env("TENUO_ROOT_KEY")
warrant = Warrant.issue(..., keypair=root_key)
```

| | |
|---|---|
| **Architecture** | Orchestrator process holds key |
| **Pros** | Zero infrastructure overhead |
| **Cons** | RCE on orchestrator exposes root key |
| **Use case** | Local dev, CI/CD, non-critical agents |

---

### Level 2: Isolated Signing Service (Production)

Root key held by a dedicated service. Orchestrator authenticates (mTLS, IAM) to request warrants.
```
Orchestrator  →  gRPC/mTLS  →  Signing Service (holds key)
```

| | |
|---|---|
| **Architecture** | Separate service holds key |
| **Pros** | Key isolation; RCE can only request warrants (rate-limited, logged), not exfiltrate key |
| **Cons** | One additional service to run |
| **Use case** | Production Kubernetes, standard SaaS |

---

### Level 3: Hardware Root of Trust (High Assurance)

Root key never leaves HSM or Cloud KMS. Signing requests go to KMS API.
```
Orchestrator  →  AWS KMS / GCP KMS / HSM  →  Signed warrant
```

| | |
|---|---|
| **Architecture** | Cloud KMS or on-prem HSM |
| **Pros** | Key is non-exportable; instant revocation via IAM |
| **Cons** | ~50-100ms issuance latency (verification still ~27μs) |
| **Use case** | FinTech, HealthTech, multi-tenant, regulated industries |

> **Note:** Tenuo doesn't call KMS directly. You implement a signing service that uses KMS internally and exposes `Warrant.issue()` semantics.

---

### Summary

| Threat | Recommended | Why |
|--------|-------------|-----|
| Prompt injection | Level 2+ | Key isolated from agent memory |
| Container breakout | Level 3 | Key in hardware/cloud provider |
| Rogue insider | Level 3 | Audit logs in KMS, no key export |
| Dev/test | Level 1 | Speed over security |

## Cycle Protection

Tenuo prevents infinite delegation cycles through multiple layers.

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

## Best Practices

### 1. Wrap All Tools

```python
# Good
@lockdown(tool="delete_file")
def delete_file(path: str): ...

# Bad: bypasses Tenuo
await http_client.delete(url)
```

### 2. Use Short TTLs

```python
# Good: 5 minute TTL
warrant = Warrant.issue(..., ttl_seconds=300)

# Risky: 24 hour TTL
warrant = Warrant.issue(..., ttl_seconds=86400)
```

### 3. Principle of Least Privilege

```python
# Good: only what's needed
with root_task(tools=["read_file"], path="/data/reports/*"):
    ...

# Risky: overly broad
with root_task(tools=["read_file", "write_file", "delete_file"], path="/*"):
    ...
```

### 4. Separate Keypairs per Trust Boundary
- Control plane: One keypair
- Each worker: Own keypair
- Don't share keypairs across trust boundaries

## See Also

- [Integration Safety](./integration-safety) — **Fail-safe mechanisms for integration bugs** 
- [Argument Extraction](./argument-extraction) — How tool arguments are extracted and validated
- [Protocol](./protocol) — Full protocol details
- [Proxy Configs](./proxy-configs) — Envoy, Istio, nginx integration
- [API Reference](./api-reference) — Function signatures
- [Constraints](./constraints) — Constraint types and usage
