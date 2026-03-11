---
title: Kubernetes Integration
description: Deployment patterns and operations for Kubernetes
---

# Kubernetes Integration

This guide covers how to deploy and operate Tenuo in Kubernetes.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           YOUR CLUSTER                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────────┐      ┌──────────────────────────────────────────┐    │
│   │              │      │              AGENT POD                    │    │
│   │   CONTROL    │      │  ┌─────────────────┐  ┌───────────────┐  │    │
│   │    PLANE     │◄────►│  │ tenuo-authorizer│  │  Your Agent   │  │    │
│   │              │      │  │   (sidecar)     │◄─┤               │  │    │
│   │ • Issues     │      │  │                 │  │ • LangChain   │  │    │
│   │   warrants   │      │  │ • Verifies      │  │ • LangGraph   │  │    │
│   │ • Holds root │      │  │   warrants      │  │ • Your code   │  │    │
│   │   key        │      │  │ • Checks PoP    │  │               │  │    │
│   │              │      │  │ • ~27μs         │  │ • Holds       │  │    │
│   │  (you build  │      │  │                 │  │   keypair     │  │    │
│   │   this)      │      │  │(tenuo/authorizer)│ │               │  │    │
│   └──────────────┘      │  └─────────────────┘  └───────────────┘  │    │
│                         └──────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | What It Does | Who Provides It |
|-----------|--------------|-----------------|
| **Control Plane** | Issues warrants, holds root signing key | You build this |
| **tenuo-authorizer** | Verifies warrants, checks PoP, returns allow/deny | Tenuo (`tenuo/authorizer` image) |
| **Agent** | Executes tasks, holds keypair for PoP signatures | You build this |

### Authorizer Deployment Options

| Option | Description | Best For |
|--------|-------------|----------|
| **Sidecar** | Per-pod container | Fine-grained control |
| **Gateway** | Cluster-wide via Envoy/Istio | Centralized policy |
| **SDK only** | No separate container | Simple deployments |

---

## Quickstarts

Get a working setup in 5 minutes:

- [Envoy Quickstart](./quickstart/envoy/) - Standalone proxy
- [Istio Quickstart](./quickstart/istio/) - Service mesh

---

## Helm Chart

For production deployments, use the official Helm chart:

```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --namespace tenuo-system --create-namespace \
  --set config.trustedRoots[0]="YOUR_CONTROL_PLANE_PUBLIC_KEY"
```

The chart includes:
- **High Availability**: Pod anti-affinity, PodDisruptionBudget
- **Autoscaling**: HPA support with sensible defaults
- **Security**: Non-root, read-only filesystem, minimal capabilities
- **Gateway Config**: Full tool/route extraction via ConfigMap

See [charts/tenuo-authorizer/README.md](https://github.com/tenuo-ai/tenuo/tree/main/charts/tenuo-authorizer) for full configuration options.

---

## Choosing a Pattern

| Pattern | Warrant Scope | Complexity | Best For |
|---------|---------------|------------|----------|
| **Control Plane Fetch** | Per-task | Medium | Task-scoped authority ✅ |
| **Request Header** | Per-request | Medium | Ingress injects warrants |
| **Environment Variable** | Per-pod | Low | Batch jobs, prototyping |

### Decision Flowchart

```
Is warrant scope static for the pod lifetime?
├── Yes → Environment Variable (simple, but loses task-scoping)
└── No  → Does your ingress/mesh inject warrants?
          ├── Yes → Request Header
          └── No  → Control Plane Fetch ✅ (recommended)
```

---

## Pattern: Control Plane Fetch (Recommended)

Fetch a warrant from your control plane when each task starts. This is the canonical pattern that Tenuo was designed for.

**When to use:** Production systems where you want task-scoped, short-lived authority.

```python
async def handle_task(user_request: str):
    # Fetch warrant scoped to this task
    warrant = await control_plane.get_warrant(
        tools=["read_file"],
        constraints={"path": "/data/reports/*"},
        ttl=60
    )
    
    with warrant_scope(warrant), key_scope(keypair):
        result = await agent.invoke(user_request)
    
    # Warrant expires, no cleanup needed
```

📄 **Full code:** [proxy-configs.md#control-plane-fetch](./proxy-configs.md#control-plane-fetch)

---

## Pattern: Request Header

Warrant passed per-request via `X-Tenuo-Warrant` header. Your ingress or mesh injects the warrant.

**When to use:** You have infrastructure that can inject warrants (API gateway, service mesh).

```python
@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    warrant = Warrant.from_base64(request.headers["X-Tenuo-Warrant"])
    with warrant_scope(warrant), key_scope(keypair):
        return await call_next(request)
```

📄 **Full code:** [proxy-configs.md#request-header](./proxy-configs.md#request-header)

---

## Pattern: Environment Variable

Warrant loaded at pod startup from a Secret.

**When to use:** Batch jobs, static workloads, or initial prototyping.

```yaml
env:
- name: TENUO_WARRANT_BASE64
  valueFrom:
    secretKeyRef:
      name: tenuo-credentials
      key: WARRANT_BASE64
```

📄 **Full code:** [proxy-configs.md#environment-variable](./proxy-configs.md#environment-variable)

### ⚠️ Anti-Pattern Warning

Long-lived warrants in environment variables defeat Tenuo's purpose:

```yaml
# ❌ 24-hour warrant in env var = IAM with extra steps
env:
  - name: TENUO_WARRANT_BASE64
    value: "eyJ..."  # TTL: 86400s

# ✅ Short-lived, per-task warrants from control plane
```

---

## Deploying the Authorizer

### As Sidecar

```yaml
containers:
- name: tenuo-authorizer
  image: tenuo/authorizer:0.1
  ports:
  - name: metrics
    containerPort: 9090
  env:
  - name: TRUSTED_ISSUERS
    value: "<control-plane-public-key-hex>"
  resources:
    requests: { memory: "32Mi", cpu: "10m" }
    limits: { memory: "64Mi", cpu: "100m" }
- name: agent
  # Your agent container
```

### As Gateway

See [Envoy config](./proxy-configs.md#envoy) or [Istio config](./proxy-configs.md#istio).

---

## Key Rotation

Rotate signing keys without downtime.

### Steps

1. **Add new key to trusted issuers**
   ```yaml
   env:
   - name: TRUSTED_ISSUERS
     value: "OLD_KEY_HEX,NEW_KEY_HEX"
   ```

2. **Roll out authorizer**
   ```bash
   kubectl rollout restart deployment/tenuo-authorizer
   ```

3. **Update control plane to sign with new key**

4. **Wait for old warrants to expire** (max TTL window)

5. **Remove old key**
   ```yaml
   env:
   - name: TRUSTED_ISSUERS
     value: "NEW_KEY_HEX"
   ```

**Rollback:** Re-add old key to `TRUSTED_ISSUERS`.

---

## Security Checklist

| Practice | Why |
|----------|-----|
| K8s Secrets, not ConfigMaps | Secrets can be encrypted at rest |
| SigningKey per workload | Limits blast radius |
| Short TTLs (60-300s) | Stolen warrants expire quickly |
| Network policies | Restrict control plane access |
| Verify SA tokens in control plane | Prevent warrant spoofing |

### SigningKey Strategy

| Strategy | Security | Complexity |
|----------|----------|------------|
| Per-pod | Best | High |
| Per-deployment | Good | Medium ✅ |
| Shared | Weak | Low |

---

## Debugging Denials

### Structured Logs

```json
{
  "level": "warn",
  "event": "authorization_denied",
  "reason": "constraint_violation",
  "tool": "read_file",
  "constraint": "path",
  "expected": "Pattern(/data/*)",
  "actual": "/etc/passwd"
}
```

### Tail Denials

```bash
# All denials
kubectl logs -l app=tenuo-authorizer -f | \
  jq 'select(.event == "authorization_denied")'

# By tool
kubectl logs -l app=tenuo-authorizer -f | \
  jq 'select(.tool == "read_file")'

# Count by reason (last hour)
kubectl logs -l app=tenuo-authorizer --since=1h | \
  jq -r 'select(.event == "authorization_denied") | .reason' | \
  sort | uniq -c | sort -rn
```

### Debug Headers (Non-Production)

```yaml
env:
- name: DEBUG_MODE
  value: "true"  # ⚠️ Non-production only
```

Denied responses include `X-Tenuo-Deny-Reason`:

```http
HTTP/1.1 403 Forbidden
X-Tenuo-Deny-Reason: constraint_violation: path=/etc/passwd not in Pattern(/data/*)
```

### Common Denial Reasons

| Reason | Cause | Fix |
|--------|-------|-----|
| `tool_not_in_warrant` | Tool not authorized | Issue warrant with correct tools |
| `constraint_violation` | Argument out of bounds | Check constraints or widen warrant |
| `warrant_expired` | TTL passed | Issue new warrant or increase TTL |
| `missing_pop` | No PoP signature | Ensure keypair is set in context |
| `invalid_pop` | Wrong keypair | Check keypair matches warrant holder |
| `chain_invalid` | Broken delegation chain | Verify issuer chain |

### CLI Debugging

```bash
# Decode and inspect warrant contents
tenuo decode $WARRANT

# Output shows: ID, issuer, holder, tools, TTL, constraints
```

---

## Metrics

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: tenuo-authorizer
spec:
  selector:
    matchLabels:
      app: tenuo-authorizer
  podMetricsEndpoints:
  - port: metrics
```

| Metric | Description |
|--------|-------------|
| `tenuo_authz_total{result,tool}` | Decision counts |
| `tenuo_authz_duration_seconds` | Latency histogram |
| `tenuo_warrant_ttl_remaining_seconds` | Time until expiry |

---

## See Also

- [Proxy Configs Reference](./proxy-configs.md): Full Envoy, Istio, nginx configs
- [Envoy Quickstart](https://github.com/tenuo-ai/tenuo/tree/main/quickstart/envoy)
- [Istio Quickstart](https://github.com/tenuo-ai/tenuo/tree/main/quickstart/istio)
- [Enforcement Models](./enforcement): In-process, sidecar, gateway, MCP patterns