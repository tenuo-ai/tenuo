---
title: Proxy Configurations
description: Reference configurations for Envoy, Istio, nginx, and direct SDK
---

# Proxy Configurations

Copy-paste- **Application Layer**: Python SDK (`@guard` decorator)
- **Network Layer**: Envoy Proxy (Sidecar)
- **Infrastructure Layer**: Kubernetes Network Policies

### Application Layer (`@guard`)

The `@guard` decorator validates requests at the application layer.

For guidance on which pattern to use, see [Kubernetes Integration](./kubernetes.md).

---

## Envoy External Authorization

Tenuo integrates with Envoy as an external authorization service via `ext_authz`.

### Architecture

```
┌─────────┐     ┌─────────┐     ┌─────────────┐     ┌─────────┐
│ Client  │────▶│  Envoy  │────▶│ Tenuo Authz │     │ Backend │
│         │     │         │     │   (9090)    │     │         │
└─────────┘     │         │◀────│ 200 or 403  │     │         │
                │         │     └─────────────┘     │         │
                │         │────────────────────────▶│         │
                │         │  (only if 200)          │         │
                └─────────┘                         └─────────┘
```

### Full Envoy Config

```yaml
# envoy.yaml
static_resources:
  listeners:
  - name: main
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress
          route_config:
            name: local_route
            virtual_hosts:
            - name: backend
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: backend }
          http_filters:
          # Tenuo authorization filter
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              grpc_service:
                envoy_grpc:
                  cluster_name: tenuo-authorizer
                timeout: 0.25s
              include_peer_certificate: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: tenuo-authorizer
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    http2_protocol_options: {}  # Required for gRPC
    load_assignment:
      cluster_name: tenuo-authorizer
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: tenuo-authorizer
                port_value: 9090

  - name: backend
    connect_timeout: 0.5s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: backend
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: backend
                port_value: 8080
```

### HTTP Mode (Alternative)

If you prefer HTTP over gRPC:

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    http_service:
      server_uri:
        uri: http://tenuo-authorizer:9090
        cluster: tenuo-authorizer
        timeout: 0.25s
      authorization_request:
        allowed_headers:
          patterns:
          - exact: x-tenuo-warrant
          - exact: x-tenuo-pop
          - exact: content-type
      authorization_response:
        allowed_upstream_headers:
          patterns:
          - exact: x-tenuo-warrant-id
```

---

## Istio Integration

### Step 1: Configure ExtensionProvider

Add Tenuo as an external authorization provider in Istio's mesh config:

```yaml
# istio-config.yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    extensionProviders:
    - name: tenuo-ext-authz
      envoyExtAuthzGrpc:
        service: tenuo-authorizer.tenuo-system.svc.cluster.local
        port: 9090
```

Or patch an existing installation:

```bash
kubectl edit configmap istio -n istio-system
```

```yaml
data:
  mesh: |
    extensionProviders:
    - name: tenuo-ext-authz
      envoyExtAuthzGrpc:
        service: tenuo-authorizer.tenuo-system.svc.cluster.local
        port: 9090
```

### Step 2: Apply AuthorizationPolicy

```yaml
# authz-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: tenuo-authz
  namespace: default
spec:
  selector:
    matchLabels:
      app: my-agent  # Apply to pods with this label
  action: CUSTOM
  provider:
    name: tenuo-ext-authz
  rules:
  - to:
    - operation:
        paths: ["/api/*"]  # Paths requiring authorization
```

### Selective Enforcement

Apply to specific methods:

```yaml
rules:
- to:
  - operation:
      methods: ["POST", "PUT", "DELETE"]
      paths: ["/api/tools/*"]
```

Exclude health checks:

```yaml
rules:
- to:
  - operation:
      notPaths: ["/health", "/ready", "/metrics"]
```

---

## nginx Integration

Use the `auth_request` directive:

```nginx
# nginx.conf
upstream backend {
    server localhost:8080;
}

upstream tenuo {
    server localhost:9090;
}

server {
    listen 80;

    # Internal auth endpoint
    location = /_tenuo_auth {
        internal;
        proxy_pass http://tenuo/authorize;
        proxy_pass_request_body on;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Tenuo-Warrant $http_x_tenuo_warrant;
        proxy_set_header X-Tenuo-PoP $http_x_tenuo_pop;
    }

    # Protected routes
    location /api/ {
        auth_request /_tenuo_auth;
        error_page 401 403 = @denied;
        proxy_pass http://backend;
    }
    
    location @denied {
        return 403 '{"error": "authorization_denied"}';
        add_header Content-Type application/json;
    }
    
    # Unprotected routes
    location /health {
        proxy_pass http://backend;
    }
}
```

---

## Control Plane Fetch

Full implementation for fetching warrants per-task.

### Agent Code

```python
import os
import httpx
from tenuo import Warrant, SigningKey, warrant_scope, key_scope

# Load keypair once at startup
keypair = SigningKey.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

def get_k8s_token() -> str:
    """Read the pod's service account token."""
    with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
        return f.read()

async def get_warrant(
    tools: list[str],
    constraints: dict,
    ttl: int = 60
) -> Warrant:
    """Fetch a task-scoped warrant from the control plane."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://control-plane.tenuo-system.svc.cluster.local:8080/v1/warrants",
            headers={"Authorization": f"Bearer {get_k8s_token()}"},
            json={
                "tools": tools,
                "constraints": constraints,
                "ttl_seconds": ttl,
                "holder": keypair.public_key.to_hex(),
            },
            timeout=5.0
        )
        resp.raise_for_status()
        return Warrant.from_base64(resp.json()["warrant"])


async def handle_task(user_request: str):
    """Example: handle a task with scoped authority."""
    # Fetch warrant scoped to this specific task
    warrant = await get_warrant(
        tools=["read_file", "search"],
        constraints={"path": "/data/reports/*"},
        ttl=60
    )
    
    with warrant_scope(warrant), key_scope(keypair):
        result = await agent.invoke({"input": user_request})
    
    # Warrant expires automatically — no cleanup needed
    return result
```

### Kubernetes Manifests

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: agent-keypair
type: Opaque
stringData:
  KEYPAIR_PEM: |
    -----BEGIN PRIVATE KEY-----
    ... generate with: tenuo keygen --format pem ...
    -----END PRIVATE KEY-----
---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
spec:
  template:
    spec:
      serviceAccountName: agent-sa  # For control plane auth
      containers:
      - name: agent
        image: your-agent:latest
        env:
        - name: TENUO_KEYPAIR_PEM
          valueFrom:
            secretKeyRef:
              name: agent-keypair
              key: KEYPAIR_PEM

> [!CAUTION]
> **Production Safety**: Do NOT set `TENUO_ENV="test"` in your production manifests.
> This variable enables development-only bypass modes that disable authorization checks.
```

---

## Request Header

Warrant passed via HTTP header, validated in middleware.

```python
from fastapi import FastAPI, Request, HTTPException
from tenuo import Warrant, SigningKey, warrant_scope, key_scope
import os

app = FastAPI()

# Load keypair once at startup
keypair = SigningKey.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    # Skip unprotected paths
    if request.url.path in ["/health", "/ready"]:
        return await call_next(request)
    
    # Require warrant header
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        raise HTTPException(401, "Missing X-Tenuo-Warrant header")
    
    try:
        warrant = Warrant.from_base64(warrant_b64)
    except Exception as e:
        raise HTTPException(400, f"Invalid warrant: {e}")
    
    if warrant.is_expired():
        raise HTTPException(401, "Warrant expired")
    
    with warrant_scope(warrant), key_scope(keypair):
        return await call_next(request)
```

---

## Environment Variable

Warrant loaded from Secret at pod startup.

### Kubernetes Manifests

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-credentials
type: Opaque
stringData:
  WARRANT_BASE64: |
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...
  KEYPAIR_PEM: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
spec:
  template:
    spec:
      containers:
      - name: agent
        image: your-agent:latest
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

### Agent Code

```python
import os
from tenuo import Warrant, SigningKey, warrant_scope, key_scope

# Load once at startup
warrant = Warrant.from_base64(os.getenv("TENUO_WARRANT_BASE64"))
keypair = SigningKey.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

def run_agent(prompt: str):
    with warrant_scope(warrant), key_scope(keypair):
        return agent.invoke({"input": prompt})
```

---

## Docker Compose (Local Development)

```yaml
# docker-compose.yaml
version: '3.8'

services:
  agent:
    build: .
    environment:
      - TENUO_KEYPAIR_PEM=${TENUO_KEYPAIR_PEM}
    depends_on:
      - tenuo-authorizer

  tenuo-authorizer:
    image: tenuo/authorizer:0.1
    ports:
      - "9090:9090"
    environment:
      - TRUSTED_ISSUERS=${CONTROL_PLANE_PUBLIC_KEY}
    volumes:
      - ./gateway.yaml:/etc/tenuo/gateway.yaml:ro

  control-plane:
    image: tenuo/demo-control-plane:0.1
    ports:
      - "8080:8080"
    environment:
      - SIGNING_KEY=${CONTROL_PLANE_PRIVATE_KEY}

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - agent
      - tenuo-authorizer
```

### .env file

```bash
# Generate with: tenuo keygen
CONTROL_PLANE_PRIVATE_KEY=...
CONTROL_PLANE_PUBLIC_KEY=...
TENUO_KEYPAIR_PEM="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

---

## Direct SDK (No Proxy)

For simple deployments without a sidecar or gateway.

```python
from fastapi import FastAPI, Request, HTTPException
from tenuo import (
    Authorizer, Warrant, SigningKey, PublicKey,
    warrant_scope, key_scope, guard
)
import os

app = FastAPI()

# Initialize authorizer with trusted root
control_plane_key = PublicKey.from_hex(os.getenv("TRUSTED_ISSUER_KEY"))
authorizer = Authorizer(trusted_roots=[control_plane_key])

# Load service keypair
keypair = SigningKey.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))


@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        raise HTTPException(401, "Missing warrant")
    
    try:
        warrant = Warrant.from_base64(warrant_b64)
        authorizer.verify(warrant)  # Checks signature + expiry
    except Exception as e:
        raise HTTPException(403, f"Authorization failed: {e}")
    
    with warrant_scope(warrant), key_scope(keypair):
        return await call_next(request)


@app.post("/api/files/read")
@guard(tool="read_file")
async def read_file(path: str):
    # @guard checks: tool in warrant, path matches constraints
    return {"content": open(path).read()}


@app.post("/api/files/write")
@guard(tool="write_file")
async def write_file(path: str, content: str):
    open(path, "w").write(content)
    return {"status": "ok"}
```

---

## Gateway Configuration

See [Gateway Configuration Reference](./gateway-config.md) for the full YAML schema.

---

## See Also

- [Kubernetes Integration](./kubernetes) - Patterns, decisions, debugging
- [Envoy Quickstart](./quickstart/envoy/)
- [Istio Quickstart](./quickstart/istio/)
- [API Reference](./api-reference)
