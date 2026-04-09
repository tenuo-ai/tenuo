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
| **Control Plane Fetch** | Per-task | Medium | Task-scoped authority |
| **Request Header** | Per-request | Medium | Ingress injects warrants |
| **Environment Variable** | Per-pod | Low | Batch jobs, prototyping |

### Decision Flowchart

```
Is warrant scope static for the pod lifetime?
├── Yes → Environment Variable (simple, but loses task-scoping)
└── No  → Does your ingress/mesh inject warrants?
          ├── Yes → Request Header
          └── No  → Control Plane Fetch (recommended)
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

**Full code:** [Enforcement: Proxy Configurations](./enforcement#proxy-configurations)

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

**Full code:** [Enforcement: Proxy Configurations](./enforcement#proxy-configurations)

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

**Full code:** [Enforcement: Proxy Configurations](./enforcement#proxy-configurations)

### Anti-Pattern Warning

Long-lived warrants in environment variables defeat Tenuo's purpose:

```yaml
# 24-hour warrant in env var = IAM with extra steps
env:
  - name: TENUO_WARRANT_BASE64
    value: "eyJ..."  # TTL: 86400s

# Short-lived, per-task warrants from control plane
```

---

## Deploying the Authorizer

### As Sidecar

```yaml
containers:
- name: tenuo-authorizer
  image: tenuo/authorizer:0.1
  args: ["serve", "--config", "/etc/tenuo/gateway.yaml"]
  ports:
  - name: http
    containerPort: 9090
  env:
  - name: TENUO_TRUSTED_KEYS
    value: "<control-plane-public-key-hex>"
  resources:
    requests: { memory: "32Mi", cpu: "10m" }
    limits: { memory: "64Mi", cpu: "100m" }
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
    initialDelaySeconds: 3
    periodSeconds: 5
- name: agent
  # Your agent container
```

> The authorizer binary reads trusted keys from `TENUO_TRUSTED_KEYS` (comma-separated hex). When using the Helm chart, keys are set via `config.trustedRoots` in `values.yaml` instead.

### As Gateway

See [Proxy Configurations](./enforcement#proxy-configurations) for Envoy and Istio configs.

---

## Key Rotation

Rotate signing keys without downtime.

### Steps

1. **Add new key to trusted keys**
   ```yaml
   env:
   - name: TENUO_TRUSTED_KEYS
     value: "OLD_KEY_HEX,NEW_KEY_HEX"
   ```
   Or, if using the Helm chart:
   ```bash
   helm upgrade tenuo-authorizer ./charts/tenuo-authorizer \
     --set config.trustedRoots[0]="OLD_KEY_HEX" \
     --set config.trustedRoots[1]="NEW_KEY_HEX"
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
   - name: TENUO_TRUSTED_KEYS
     value: "NEW_KEY_HEX"
   ```

**Rollback:** Re-add old key to `TENUO_TRUSTED_KEYS`.

---

## Delegation Chains (Multi-Hop)

When agents delegate to sub-agents across pods, the full delegation chain must travel with the request so each hop can be independently verified.

### How It Works

```
Control Plane                Agent A (Pod 1)              Agent B (Pod 2)
     │                            │                            │
     │  root warrant (depth=0)    │                            │
     │ ──────────────────────────>│                            │
     │                            │  grant child warrant       │
     │                            │  (depth=1, parent_hash)    │
     │                            │                            │
     │                            │  X-Tenuo-Warrant: [root, child]  (WarrantStack)
     │                            │  X-Tenuo-PoP: <sig>        │
     │                            │ ──────────────────────────>│
     │                            │                            │  authorizer verifies
     │                            │                            │  full chain via check_chain
```

The `X-Tenuo-Warrant` header carries a **WarrantStack** — a base64-encoded CBOR array of warrants ordered root-first, leaf-last. The authorizer's `check_chain` verifies:

1. The root warrant's issuer is in `TENUO_TRUSTED_KEYS`
2. Each child's `parent_hash` matches its parent
3. Capabilities are monotonically attenuated (child ⊆ parent)
4. The leaf's PoP signature is valid

### Client-Side (Python SDK)

```python
from tenuo import Warrant, SigningKey, encode_warrant_stack

root = Warrant.mint_builder().tool("search").tool("summarize").mint(control_plane_key)

child = (
    Warrant.grant_builder(root)
    .tool("search")           # attenuate: drop summarize
    .holder(agent_b_key.public_key)
    .ttl(60)
    .grant(agent_a_key)
)

stack_b64 = encode_warrant_stack([root, child])

headers = {
    "X-Tenuo-Warrant": stack_b64,
    "X-Tenuo-PoP": pop_signature_b64,
}
```

### Authorizer Behavior

The authorizer auto-detects whether `X-Tenuo-Warrant` contains a single warrant or a `WarrantStack`. No configuration change is needed — `check_chain` is always used.

If a delegated warrant (depth > 0) arrives without its parent chain, the authorizer logs a warning:

```
WARN Received orphaned delegated warrant (depth > 0) without parent chain.
     Zero-Trust best practice is to send full WarrantStack.
```

### Helm Chart: Trusted Roots for Chains

Only the **root** issuer needs to be in `trustedRoots`. Intermediate agents don't need to be pre-registered — their authority is proven by the chain itself:

```yaml
config:
  trustedRoots:
    - "f32e74b5..."   # Control plane key only
```

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
| Per-deployment | Good | Medium |
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

Enable via the gateway config file (not an env var):

```yaml
# gateway.yaml (or Helm: config.debugMode: true)
settings:
  debug_mode: true   # Non-production only!
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

## Monitoring

### Structured Logs (Primary)

The authorizer emits structured JSON logs for every authorization decision. Use these as your primary observability signal:

```bash
# Count allow/deny decisions per tool (last hour)
kubectl logs -l app=tenuo-authorizer --since=1h | \
  jq -r 'select(.event | test("authorization_")) | "\(.event) \(.tool)"' | \
  sort | uniq -c | sort -rn
```

### `/status` Endpoint

The authorizer exposes a `/status` endpoint (no auth required) for debugging:

```bash
# From the agent container in the same pod (distroless authorizer has no shell):
kubectl exec deploy/your-agent -c agent -- curl -s localhost:9090/status | jq

# Or port-forward and query from your machine:
kubectl port-forward deploy/your-agent 9090:9090 &
curl -s localhost:9090/status | jq
```

```json
{
  "version": "0.1.0-beta.16",
  "uptime_secs": 42,
  "cp": {
    "enabled": true,
    "status": "registered",
    "authorizer_id": "tnu_auth_..."
  }
}
```

Use `cp.status` to verify control plane registration in readiness checks.

### Helm ServiceMonitor (Optional)

The Helm chart includes a `ServiceMonitor` template for the Prometheus Operator. Enable it in `values.yaml`:

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus   # match your Prometheus selector
    interval: 30s
```

> **Note:** The authorizer currently reports metrics to the Tenuo control plane via heartbeat rather than exposing a Prometheus `/metrics` endpoint. The `ServiceMonitor` monitors the `/health` endpoint for up/down status. For detailed authorization metrics (allow/deny counts, latency percentiles), use structured logs or the control plane dashboard.

---

## See Also

- [Proxy Configurations](./enforcement#proxy-configurations): Full Envoy, Istio, nginx configs
- [Envoy Quickstart](./quickstart/envoy/): Get your first 403 in under 5 minutes
- [Istio Quickstart](./quickstart/istio/): Service mesh integration
- [Enforcement Architecture](./enforcement): In-process, sidecar, gateway, MCP patterns
- [Helm Chart README](https://github.com/tenuo-ai/tenuo/tree/main/charts/tenuo-authorizer): Full configuration reference