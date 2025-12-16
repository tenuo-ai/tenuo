---
title: Kubernetes Integration
description: Deployment patterns for Kubernetes
---

# Kubernetes Integration

Tenuo provides primitives. You build the integration that fits your setup.

## Quickstart Guides

Get started in 5 minutes with one of these quickstart guides:

### 🚀 [Istio Quickstart](https://github.com/horkosdev/tenuo/tree/main/quickstart/istio)
**Best for:** Teams already using Istio service mesh

- Uses Istio's `ExtensionProvider` + `AuthorizationPolicy`
- Declarative policy-based configuration
- Integrates with existing Istio setup
- **Time to first 403:** 5 minutes

### 🚀 [Envoy Quickstart](https://github.com/horkosdev/tenuo/tree/main/quickstart/envoy)
**Best for:** Standalone Envoy proxy without service mesh

- Direct Envoy `ext_authz` filter configuration
- No service mesh required
- Full control over Envoy config
- **Time to first 403:** 5 minutes

---

## Primitives

```python
from tenuo import Warrant, Keypair, set_warrant_context, set_keypair_context

# Load warrant from any source
warrant = Warrant.from_base64(data)

# Load keypair (required for PoP)
keypair = Keypair.from_pem(pem_string)

# Set in context
with set_warrant_context(warrant), set_keypair_context(keypair):
    await agent.invoke(...)
```

---

## Choosing a Pattern

| Pattern | Granularity | Complexity | Best For |
|---------|-------------|------------|----------|
| **Environment Variable** | Per-pod | Low | Static workloads, batch jobs |
| **Request Header** | Per-request | Medium | Ingress/mesh with warrant injection |
| **Control Plane Fetch** | Per-request | High | Task-scoped authority (recommended) |

### Decision Guide
```
Is warrant scope static for the pod lifetime?
├── Yes → Environment Variable
└── No → Does your mesh/ingress inject warrants?
    ├── Yes → Request Header
    └── No → Control Plane Fetch
```

### Warning: Environment Variable Anti-Pattern

Using env var warrants with long TTLs defeats Tenuo's task-scoped authority model:
```yaml
# ❌ Anti-pattern: 24-hour warrant in env var
env:
  - name: TENUO_WARRANT
    value: "eyJ..." # TTL: 86400s

# ✅ Better: Short-lived, per-request warrants
# Fetched from control plane at task start
```

---

## Pattern: Environment Variable

Warrant and keypair loaded at pod startup from K8s Secret.

```yaml
# kubernetes/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-credentials
type: Opaque
stringData:
  WARRANT_BASE64: <base64-encoded-warrant>
  KEYPAIR_PEM: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

```yaml
# kubernetes/deployment.yaml
env:
- name: TENUO_WARRANT_BASE64
  valueFrom:
    secretKeyRef:
      name: tenuo-credentials
      key: WARRANT_BASE64
- name: TENUO_KEYPAIR_PEM
  valueFrom:
    secretKeyRef:
      name: tenuo-credentials
      key: KEYPAIR_PEM
```

```python
import os
from tenuo import Warrant, Keypair, set_warrant_context, set_keypair_context

warrant = Warrant.from_base64(os.getenv("TENUO_WARRANT_BASE64"))
keypair = Keypair.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

with set_warrant_context(warrant), set_keypair_context(keypair):
    result = agent.invoke({"input": prompt})
```

---

## Pattern: Request Header

Warrant passed per-request, keypair loaded at startup.

```python
from fastapi import FastAPI, Request
from tenuo import Warrant, Keypair, set_warrant_context, set_keypair_context
import os

app = FastAPI()
keypair = Keypair.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    if header := request.headers.get("X-Tenuo-Warrant"):
        warrant = Warrant.from_base64(header)
        with set_warrant_context(warrant), set_keypair_context(keypair):
            return await call_next(request)
    return await call_next(request)
```

---

## Pattern: Control Plane (Per-Request)

Fetch warrant from control plane for each task.

```python
import httpx
from tenuo import Warrant

async def get_warrant(tools: list, constraints: dict, ttl: int = 60) -> Warrant:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://control-plane.tenuo.svc.cluster.local:8080/v1/warrants",
            json={
                "tools": tools,
                "constraints": constraints,
                "ttl_seconds": ttl,
                "holder": keypair.public_key.to_bytes().hex(),
            }
        )
        return Warrant.from_base64(resp.json()["warrant"])

# Usage
warrant = await get_warrant(
    tools=["read_file"],
    constraints={"path": "/data/reports/*"},
)
```

---

## Pattern: Hybrid

Default warrant from environment, override per-request.

```python
import os
from tenuo import Warrant

class WarrantManager:
    def __init__(self):
        base64 = os.getenv("TENUO_WARRANT_BASE64")
        self.default = Warrant.from_base64(base64) if base64 else None
    
    def for_request(self, headers: dict) -> Warrant:
        if h := headers.get("X-Tenuo-Warrant"):
            return Warrant.from_base64(h)
        return self.default

# Usage
manager = WarrantManager()

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    warrant = manager.for_request(dict(request.headers))
    if warrant:
        with set_warrant_context(warrant), set_keypair_context(keypair):
            return await call_next(request)
    return await call_next(request)
```

---

## Pattern: Init Container

Fetch warrant during pod initialization.

```yaml
spec:
  serviceAccountName: agent-sa  # Required for authentication
  initContainers:
  - name: fetch-warrant
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      # Authenticate using K8s Service Account Token
      TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
      curl -s http://control-plane:8080/v1/warrants \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"agent_id": "'$HOSTNAME'"}' \
        -o /tenuo/warrant.b64
    volumeMounts:
    - name: tenuo
      mountPath: /tenuo
  containers:
  - name: agent
    volumeMounts:
    - name: tenuo
      mountPath: /tenuo
      readOnly: true
  volumes:
  - name: tenuo
    emptyDir: {}
```

> ⚠️ **Production Note**: The control plane MUST verify the Kubernetes Service Account Token 
> to authenticate the request. Without this, any pod could claim to be any agent.
> Use [TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
> or a service mesh (Istio, Linkerd) for mTLS-based identity.

```python
# Read warrant from init container output
with open("/tenuo/warrant.b64") as f:
    warrant = Warrant.from_base64(f.read().strip())
```

---

## Key Rotation

Rotate control plane signing keys without downtime by maintaining multiple trusted issuers during the transition.

### 1. Add new key to trusted roots
```yaml
settings:
  trusted_issuers:
    - "OLD_KEY_HEX"
    - "NEW_KEY_HEX"  # Add new key
```

### 2. Roll out config change
```bash
kubectl rollout restart deployment/tenuo-authorizer
```

### 3. Start issuing warrants with new key
Update control plane to sign with new key.

### 4. Wait for old warrants to expire
Monitor for warrants signed by old key (max TTL window).

### 5. Remove old key
```yaml
settings:
  trusted_issuers:
    - "NEW_KEY_HEX"  # Old key removed
```

### Rollback
If issues arise, re-add old key to `trusted_issuers`.

---

## Security Notes

| Practice | Why |
|----------|-----|
| Use K8s Secrets, not ConfigMaps | Secrets are base64 encoded and can be encrypted at rest |
| Keypair per pod | Compromise of one pod doesn't affect others |
| Short TTLs | Limits blast radius of stolen warrants |
| Network policies | Restrict which pods can reach control plane |

---

## Troubleshooting

```python
import os

# Check if warrant is loaded
warrant_b64 = os.getenv("TENUO_WARRANT_BASE64")
if not warrant_b64:
    raise RuntimeError("TENUO_WARRANT_BASE64 not set")

warrant = Warrant.from_base64(warrant_b64)

# Check if expired
if warrant.is_expired():
    raise RuntimeError(f"Warrant expired at {warrant.expires_at}")

# Check tools
print(f"Authorized tools: {warrant.tools}")
```

---

## Debugging Denials

When authorization fails, understanding *why* is critical for debugging. Tenuo provides structured denial logging and optional debug headers.

### Structured Denial Logs

The authorizer outputs JSON-formatted denial logs:

```json
{
  "level": "warn",
  "event": "authorization_denied",
  "reason": "constraint_violation",
  "tool": "scale_cluster",
  "constraint": "replicas",
  "expected": "Range(max=10)",
  "actual": 50,
  "warrant_id": "tnu_wrt_abc123",
  "request_id": "req_xyz789"
}
```

### Tailing Authorization Denials

```bash
# Tail authorizer logs and filter for denials
kubectl logs -l app=tenuo-authorizer -f | jq 'select(.event == "authorization_denied")'

# Filter by specific tool
kubectl logs -l app=tenuo-authorizer -f | jq 'select(.event == "authorization_denied" and .tool == "scale_cluster")'

# Count denials by reason
kubectl logs -l app=tenuo-authorizer --since=1h | \
  jq -r 'select(.event == "authorization_denied") | .reason' | \
  sort | uniq -c | sort -rn
```

### Debug Mode (Non-Production Only)

Enable debug mode to get detailed deny reasons in HTTP response headers:

```yaml
# gateway-config.yaml
settings:
  debug_mode: true  # ⚠️ Only in non-production!
  warrant_header: "X-Tenuo-Warrant"
  pop_header: "X-Tenuo-PoP"
```

When enabled, denied requests include the `X-Tenuo-Deny-Reason` header:

```http
HTTP/1.1 403 Forbidden
X-Tenuo-Deny-Reason: constraint_violation: replicas=50 exceeds Range(max=10)
```

### Enabling Debug Mode Temporarily

```bash
# Option 1: Via environment variable
kubectl set env deployment/tenuo-authorizer DEBUG=true
# ... reproduce issue ...
kubectl set env deployment/tenuo-authorizer DEBUG-

# Option 2: Via ConfigMap (requires restart)
kubectl patch configmap tenuo-config -p '{"data":{"debug_mode":"true"}}'
kubectl rollout restart deployment/tenuo-authorizer
# ... reproduce issue ...
kubectl patch configmap tenuo-config -p '{"data":{"debug_mode":"false"}}'
kubectl rollout restart deployment/tenuo-authorizer
```

### Common Denial Reasons

| Reason | Description | Fix |
|--------|-------------|-----|
| `constraint_violation` | Request value exceeds warrant constraints | Attenuate warrant with wider constraints |
| `warrant_expired` | Warrant TTL has passed | Issue new warrant or increase TTL |
| `missing_pop` | PoP signature not provided | Ensure client sends X-Tenuo-PoP header |
| `signature_invalid` | PoP signature doesn't match | Check keypair matches warrant holder |
| `unauthorized` | Tool not in warrant's allowed list | Issue warrant with correct tools |
| `chain_verification_failed` | Delegation chain is invalid | Check issuer chain integrity |

### Testing Authorization Locally

```bash
# Test a specific warrant against the authorizer
export WARRANT=$(cat warrant.b64)
curl -X POST http://localhost:9090/api/v1/clusters/prod/scale \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "Content-Type: application/json" \
  -d '{"spec": {"replicas": 5}}' \
  -v 2>&1 | grep -E "(X-Tenuo-|HTTP/)"

# Verify warrant without making a request
echo $WARRANT | tenuo-authorizer check
```

### Prometheus Metrics

The authorizer exposes metrics for monitoring:

```yaml
# PodMonitor for scraping
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
    path: /metrics
```

Key metrics:
- `tenuo_authorization_total{result="allowed|denied",tool="..."}` — Total authorization decisions
- `tenuo_authorization_duration_seconds` — Authorization latency histogram
- `tenuo_warrant_expiry_seconds` — Time until warrant expiration

---

## See Also

- [**Istio Quickstart (5 min)**](https://github.com/horkosdev/tenuo/tree/main/quickstart/istio) — Service mesh integration
- [**Envoy Quickstart (5 min)**](https://github.com/horkosdev/tenuo/tree/main/quickstart/envoy) — Standalone proxy setup
- [Deployment Patterns](./deployment) — Envoy, Istio, nginx integration
- [Gateway Configuration](./gateway-config) — YAML config reference
- [LangChain Integration](./langchain)
- [API Reference](./api-reference)
- [Protocol](./protocol)
