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
# Attenuate with explicit capability (POLA)
warrant = (root_warrant.attenuate()
    .with_capability("protected_tool", {"path": Pattern("/data/*")})
    .holder(worker_keypair.public_key)
    .build(worker_keypair, root_keypair))

with set_warrant_context(warrant), set_signing_key_context(worker_keypair):
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

## Monotonic Attenuation

Authority can only **shrink**, never expand:

| What | Rule |
|------|------|
| **Tools** | Child can only use a subset of parent's tools |
| **Constraints** | Child constraints must be tighter than parent's |
| **TTL** | Child cannot outlive parent |
| **Depth** | `max_depth` can only decrease |

```python
# Parent allows: capabilities={"read": path="/*", "write": path="/*", "delete": path="/*"}
parent = Warrant.issue(
    capabilities=Constraints.for_tools(["read", "write", "delete"], {"path": Pattern("/*")}),
    ...
)

# Child can only narrow:
child = parent.attenuate() \
    .with_capability("read", {"path": Pattern("/data/*")}) \
    .build(...)

# This would FAIL:
child = parent.attenuate() \
    .with_capability("execute", {}) \
    .build(...)  # FAILS (parent doesn't have "execute")
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

## Control Plane Deployment Models

The control plane holds the **root signing key** and issues the initial warrant for each agent network. It is *not* in the data path. Ttool execution never touches it, so it can be secured with high-latency/high-security patterns without affecting agent performance.

Choose a model based on your threat model.

### Level 1: Embedded (Development)

The orchestrator holds the root key directly.
```python
# Development only
root_key = SigningKey.from_env("TENUO_ROOT_KEY")
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

### 2. Depth Limits
- `MAX_DELEGATION_DEPTH = 16` — Max delegation depth (typical chains are 3-5 levels)

### 3. Monotonic Attenuation
Even if A→B→A happens (holder cycling), each warrant is strictly weaker. The third warrant has less authority than the first.

### 4. Self-Issuance Prevention
Issuer warrants cannot grant execution capabilities to themselves.

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

## Production Deployment Security

### Control Plane (`tenuo-control`)

The reference control plane binary requires explicit configuration in production:

| Requirement | Environment Variable | Notes |
|-------------|---------------------|-------|
| **Secret Key** | `TENUO_SECRET_KEY` | **Required in release builds**. Hex-encoded Ed25519 seed. If missing, the server fails to start. |
| **Enrollment Token** | `TENUO_ENROLLMENT_TOKEN` | Shared secret for agent enrollment. Use a cryptographically random value. |

> **Why fail-fast?** In debug builds, an ephemeral key is generated for convenience. In release builds, this would cause all warrants to become invalid on restart, so the server refuses to start without an explicit key.

Generate a secret key:
```bash
openssl rand -hex 32
```

### Authorizer (`tenuo-authorizer`)

The authorizer exposes unauthenticated health endpoints for Kubernetes probes:

> [!WARNING]
> **Statelessness & Replay Risk**: The provided `tenuo-authorizer` binary is stateless for infinite horizontal scaling. It does **not** implement the [optional PoP deduplication cache](#replay-protection--statelessness) by default. If your threat model requires strict replay protection within the ~2 minute window, you must modify the binary to use a shared cache (Redis/Memcached) or implement deduplication at your API gateway.

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness probe |
| `GET /healthz` | Liveness probe (alias) |
| `GET /ready` | Readiness probe |

Configure Kubernetes probes:
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /ready
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10
```

**Error Sanitization**: The authorizer sanitizes error responses to prevent information leakage. Internal error details are logged but not returned to clients.

---

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
with root_task(Capability("read_file", path="/data/reports/*")):
    ...

# Risky: overly broad
with root_task(
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

## See Also

- [Enforcement Models](./enforcement) — In-process, sidecar, gateway deployment patterns
- [Integration Safety](./integration-safety) — Fail-safe mechanisms for integration bugs 
- [Argument Extraction](./argument-extraction) — How tool arguments are extracted and validated
- [Protocol](./protocol) — Full protocol details
- [Proxy Configs](./proxy-configs) — Envoy, Istio, nginx integration
- [API Reference](./api-reference) — Function signatures
- [Constraints](./constraints) — Constraint types and usage
