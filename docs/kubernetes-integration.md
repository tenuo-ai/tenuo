# Tenuo + LangChain Kubernetes Integration Guide

This guide shows how to deploy Tenuo-protected LangChain agents in Kubernetes.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Control Plane (Issuer)                                      │
│  - Issues warrants for agents                                │
│  - Signs with root keypair                                    │
│  - Updates K8s Secrets/ConfigMaps                             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ Updates Secret
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Kubernetes Secret / ConfigMap                              │
│  - Stores base64-encoded warrant                             │
│  - Mounted to agent pods                                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ Mounted at /etc/tenuo/warrant.b64
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  LangChain Agent Pods (Replicas)                            │
│  - Load warrant at startup                                   │
│  - Set warrant in context per-request                        │
│  - All @lockdown functions protected                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ Request with warrant header
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Ingress / API Gateway                                      │
│  - Validates warrant (optional)                              │
│  - Forwards X-Tenuo-Warrant header                          │
└─────────────────────────────────────────────────────────────┘
```

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

### Pattern 3: Hybrid (Pod + Request)

Pod-level warrant as fallback, request header for override.

**Use Case:** Default capabilities from pod warrant, enhanced capabilities per-request.

```python
class KubernetesWarrantManager:
    def __init__(self):
        # Load pod-level warrant at startup
        self.pod_warrant = load_warrant_from_env() or load_warrant_from_file()
    
    def get_warrant_for_request(self, headers: Dict[str, str]) -> Optional[Warrant]:
        # Try request header first (most specific)
        if "X-Tenuo-Warrant" in headers:
            return Warrant.from_base64(headers["X-Tenuo-Warrant"])
        
        # Fall back to pod-level warrant
        return self.pod_warrant
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
from fastapi import FastAPI, Request
from tenuo import set_warrant_context, Warrant, AuthorizationError
from kubernetes_warrant_manager import KubernetesWarrantManager

app = FastAPI()
warrant_manager = KubernetesWarrantManager()

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    """Set warrant in context for each request."""
    headers = dict(request.headers)
    warrant = warrant_manager.get_warrant_for_request(headers)
    
    if not warrant:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="No warrant available")
    
    with set_warrant_context(warrant):
        return await call_next(request)

@app.post("/agent/run")
async def run_agent(prompt: str):
    """Run LangChain agent with Tenuo protection."""
    # Warrant is already in context from middleware
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
2. **Use request headers** - For dynamic per-request capabilities
3. **Set context once** - In middleware, not in each route
4. **Handle errors gracefully** - Return 403, not 500
5. **Monitor warrant expiration** - Alert before TTL expires
6. **Rotate warrants regularly** - Update secrets periodically
7. **Use separate namespaces** - Control plane vs data plane
8. **Enable network policies** - Restrict pod-to-pod communication

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

