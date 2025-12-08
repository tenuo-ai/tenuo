# Tenuo + LangChain Kubernetes Integration Guide

This guide shows how to deploy Tenuo-protected LangChain agents in Kubernetes.

## Architecture Overview

### Simple Agent Pattern

```
┌─────────────────────────────────────────────────────────────────────┐
│  Control Plane (Issuer)                                             │
│  - Issues warrants at ENROLLMENT (once)                             │
│  - Signs with root keypair                                          │
│  - Warrant PoP-bound to agent's public key                          │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       │ Stores warrant in K8s Secret
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Kubernetes Secret                                                  │
│  - TENUO_WARRANT_BASE64 (warrant)                                   │
│  - Agent's keypair (for PoP)                                        │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       │ Mounted to pod at startup
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Agent Pod                                                          │
│  - Loads warrant and keypair at startup                             │
│  - Uses keypair to prove identity (PoP)                             │
│  - All @lockdown functions protected                                │
│  - Verification is OFFLINE (no Control Plane calls)                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Orchestrator → Worker Delegation

When an orchestrator needs to delegate tasks to workers, it **attenuates** its warrant locally (offline) and binds it to the worker's public key.

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. ENROLLMENT (one-time, online)                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Orchestrator ──────────────────────────► Control Plane            │
│       │         "Enroll me"                     │                   │
│       │         (PoP signature)                 │                   │
│       │                                         │                   │
│       │◄────────────────────────────────────────┘                   │
│       │         Root Warrant                                        │
│       │         (broad scope, PoP-bound to Orchestrator)            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ 2. TASK ASSIGNMENT (per-task, OFFLINE)                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Orchestrator receives task: "Process batch-123"                   │
│       │                                                             │
│       │ Orchestrator decides: "Delegate to Worker-A"                │
│       │                                                             │
│       │ Orchestrator knows Worker-A's public key                    │
│       │ (from service discovery, K8s API, or pre-registered)        │
│       │                                                             │
│       ▼                                                             │
│   orchestrator_warrant.attenuate(                                   │
│       constraints={"file_path": "/data/batch-123/*"},  # narrower   │
│       keypair=orchestrator_keypair,                    # signs it   │
│       ttl_seconds=300,                                 # shorter    │
│       authorized_holder=worker_A_pubkey                # PoP-bound  │
│   )                                                                 │
│       │                                                             │
│       │ This is LOCAL crypto - no Control Plane call!               │
│       │                                                             │
│       ▼                                                             │
│   Attenuated warrant created                                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ 3. WARRANT DELIVERY (Orchestrator → Worker)                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Orchestrator ──────────────────────────► Worker-A                 │
│                  HTTP request with:                                 │
│                  - Task details (batch-123)                         │
│                  - X-Tenuo-Warrant header (attenuated warrant)      │
│                                                                     │
│   OR                                                                │
│                                                                     │
│   Orchestrator creates K8s Job with:                                │
│                  - TENUO_WARRANT_BASE64 env var                     │
│                  - Task config                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ 4. WORKER USES WARRANT (offline verification)                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Worker-A receives warrant                                         │
│       │                                                             │
│       │ Worker has its own private key (from K8s Secret)            │
│       │                                                             │
│       ▼                                                             │
│   Worker calls @lockdown protected tool:                            │
│       process_file("/data/batch-123/file.csv")                      │
│       │                                                             │
│       │ Tenuo checks:                                               │
│       │   ✓ Warrant signature chain valid?                          │
│       │   ✓ Constraints match? (/data/batch-123/* allows this)      │
│       │   ✓ PoP valid? (Worker signs with private key)              │
│       │   ✓ Not expired?                                            │
│       │                                                             │
│       ▼                                                             │
│   Tool executes (or blocked if checks fail)                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- **Orchestrator initiates** - Worker never asks for a warrant
- **Attenuation is OFFLINE** - pure crypto, no Control Plane involved
- **Warrant pushed to worker** - via HTTP header or K8s env var
- **Worker proves identity** - uses its private key for PoP
- **Principle of least privilege** - Worker gets only what it needs

## Deployment Patterns

### Pattern 1: Pod-Level Warrant (Static)

Warrant is loaded once at pod startup and used for all requests.

**Use Case:** Agent has fixed capabilities, warrant doesn't change per-request.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-warrant
type: Opaque
stringData:
  WARRANT_BASE64: <base64-encoded-warrant>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: langchain-agent
spec:
  template:
    spec:
      containers:
      - name: agent
        image: langchain-agent:latest
        env:
        - name: TENUO_WARRANT_BASE64
          valueFrom:
            secretKeyRef:
              name: tenuo-warrant
              key: WARRANT_BASE64
```

**Python Code:**
```python
from tenuo import load_warrant_from_env, set_warrant_context

# Load warrant at startup
warrant = load_warrant_from_env()

# Use for all requests
with set_warrant_context(warrant):
    agent_executor.invoke({"input": prompt})
```

### Pattern 2: Per-Request Warrant (Dynamic)

Warrant is passed in request headers, different per request.

**Use Case:** Capabilities vary by user/tenant/request context.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: langchain-agent
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      # Forward warrant header from client
      proxy_set_header X-Tenuo-Warrant $http_x_tenuo_warrant;
```

**Python Code (FastAPI):**
```python
from fastapi import FastAPI, Request, Header
from tenuo import set_warrant_context, Warrant

app = FastAPI()

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    # Get warrant from header
    warrant_header = request.headers.get("X-Tenuo-Warrant")
    if warrant_header:
        warrant = Warrant.from_base64(warrant_header)
        with set_warrant_context(warrant):
            return await call_next(request)
    return await call_next(request)
```

### Pattern 3: Orchestrator Delegation

Orchestrator attenuates its warrant for workers. See [Orchestrator → Worker Delegation](#orchestrator--worker-delegation) above.

**Use Case:** Orchestrator delegates tasks to workers with narrowed, time-limited warrants.

```python
# Orchestrator attenuates warrant for worker
worker_warrant = orchestrator_warrant.attenuate(
    constraints={"file_path": f"/data/{batch_id}/*"},  # narrower scope
    keypair=orchestrator_keypair,
    ttl_seconds=300,  # 5 minutes
    authorized_holder=worker_pubkey  # PoP-bound to this worker
)

# Send to worker via HTTP or K8s Job
response = httpx.post(
    "http://worker:8000/process",
    headers={"X-Tenuo-Warrant": worker_warrant.to_base64()}
)
```

## Control Plane Integration

### Option 1: Init Container

Fetch warrant from control plane during pod startup.

```yaml
spec:
  initContainers:
  - name: fetch-warrant
    image: tenuo/fetch-warrant:latest
    env:
    - name: AGENT_ID
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
    - name: CONTROL_PLANE_URL
      value: "https://control-plane.tenuo.svc.cluster.local"
    volumeMounts:
    - name: warrant
      mountPath: /etc/tenuo
  containers:
  - name: agent
    volumeMounts:
    - name: warrant
      mountPath: /etc/tenuo
      readOnly: true
```

### Option 2: Operator Pattern

Kubernetes operator watches agent deployments and updates warrants.

```yaml
apiVersion: tenuo.io/v1
kind: AgentWarrant
metadata:
  name: langchain-agent-warrant
spec:
  agentId: langchain-agent
  constraints:
    file_path: "/tmp/*"
    user_id: "user-*"
  ttl: 3600
```

### Option 3: Admission Webhook

Mutating webhook injects warrant into pod spec at creation time.

## FastAPI Integration

Complete FastAPI example for Kubernetes:

```python
from fastapi import FastAPI
from tenuo import set_warrant_context, Warrant, AuthorizationError
from contextlib import asynccontextmanager
import os

def load_warrant():
    """Load warrant from K8s environment."""
    warrant_b64 = os.getenv("TENUO_WARRANT_BASE64")
    if warrant_b64:
        return Warrant.from_base64(warrant_b64)
    return None

# Load warrant ONCE at startup
warrant = load_warrant()
if not warrant:
    raise RuntimeError("No warrant - agent cannot start")

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"Agent started with warrant: {warrant.id[:8]}...")
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/agent/run")
async def run_agent(prompt: str):
    """Run LangChain agent with Tenuo protection."""
    with set_warrant_context(warrant):
        # All @lockdown functions are automatically protected
        from langchain_agent import agent_executor
        
        try:
            response = agent_executor.invoke({"input": prompt})
            return {"output": response["output"]}
        except AuthorizationError as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail=str(e))
```

## Security Considerations

### 1. Secret Management

- **Use K8s Secrets** for warrant storage (not ConfigMaps)
- **Rotate warrants** regularly (via TTL or manual updates)
- **Use sealed-secrets** or external secret operators for production

### 2. Network Security

- **Control plane** should be in separate namespace with network policies
- **Agent pods** should not have direct access to control plane
- **Use service mesh** (Istio/Linkerd) for mTLS between services

### 3. Warrant Distribution

- **Init containers** fetch warrants before agent starts
- **Operators** manage warrant lifecycle
- **Admission webhooks** inject warrants at pod creation

### 4. Revocation

- **Signed Revocation Lists (SRLs)** distributed via ConfigMap
- **Authorizer** checks revocation list before authorizing
- **Update SRL** to revoke compromised warrants

## Monitoring and Observability

### Metrics

- Warrant load failures
- Authorization failures (by tool, by constraint)
- Warrant expiration warnings
- Revocation list updates

### Logging

```python
import logging

logger = logging.getLogger("tenuo")

@lockdown(tool="read_file")
def read_file(file_path: str) -> str:
    logger.info(f"Authorized read_file: {file_path}")
    # ... implementation
```

### Tracing

- Add warrant ID to trace context
- Track warrant chain depth
- Monitor constraint violations

## Example: Complete Deployment

See `examples/kubernetes_integration.py` for a complete working example.

## Best Practices

1. **Load warrant at startup** - Don't fetch on every request
2. **Bind warrants to holder's public key** - Always use `authorized_holder` for PoP
3. **Orchestrators attenuate, workers consume** - Workers never request warrants
4. **Attenuation is offline** - No Control Plane calls after enrollment
5. **Short TTL for delegated warrants** - Task-scoped warrants should be minutes, not hours
6. **Handle errors gracefully** - Return 403, not 500
7. **Monitor warrant expiration** - Alert before TTL expires
8. **Use separate namespaces** - Control plane vs data plane
9. **Enable network policies** - Restrict pod-to-pod communication

## Troubleshooting

### Warrant Not Loading

```python
# Check environment
warrant = load_warrant_from_env()
if not warrant:
    warrant = load_warrant_from_file()
if not warrant:
    raise RuntimeError("No warrant available")
```

### Authorization Failures

```python
# Enable debug logging
import logging
logging.getLogger("tenuo").setLevel(logging.DEBUG)
```

### Context Not Propagating

- Ensure `set_warrant_context` is called before async operations
- Use `ContextVar` which propagates through `await` boundaries
- Check that middleware is applied correctly

## See Also

- [LangChain Integration Examples](../examples/langchain_simple.py)
- [ContextVar Pattern](../examples/context_pattern.py)
- [Kubernetes Integration Example](../examples/kubernetes_integration.py)

