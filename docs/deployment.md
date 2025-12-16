---
title: Deployment Patterns
description: Production deployment with Envoy, Istio, and nginx
---

# Deployment Patterns

Tenuo is an **authorization service**, not a proxy. It integrates with your existing infrastructure.

---

## Recommended: Envoy External Authorization

Tenuo integrates with Envoy/Istio as an external authorization service:

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

### Envoy Configuration

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
          # Tenuo external authorization
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              http_service:
                server_uri:
                  uri: http://tenuo-authz:9090
                  cluster: tenuo-authz
                  timeout: 0.25s
                authorization_request:
                  # Forward warrant headers to Tenuo
                  allowed_headers:
                    patterns:
                    - exact: x-tenuo-warrant
                    - exact: x-tenuo-pop
                    - exact: content-type
                authorization_response:
                  # Pass Tenuo headers to backend
                  allowed_upstream_headers:
                    patterns:
                    - exact: x-tenuo-warrant-id
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: tenuo-authz
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: tenuo-authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: tenuo-authz
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

### Flow

1. Request arrives at Envoy with `X-Tenuo-Warrant` header (base64 warrant)
2. Envoy calls Tenuo sidecar with warrant headers
3. Tenuo verifies warrant, extracts constraints, authorizes
4. Tenuo returns `200` (allow) or `403` (deny)
5. Envoy forwards to backend **only if 200**

---

## Istio Integration

### AuthorizationPolicy with External Provider

First, configure Istio to use Tenuo as an external authorization provider:

```yaml
# istio-config.yaml (MeshConfig)
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    extensionProviders:
    - name: tenuo-ext-authz
      envoyExtAuthzHttp:
        service: tenuo-authz.default.svc.cluster.local
        port: 9090
        includeRequestHeadersInCheck:
        - x-tenuo-warrant
        - x-tenuo-pop
        - content-type
        headersToUpstreamOnAllow:
        - x-tenuo-warrant-id
```

Then apply an AuthorizationPolicy:

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
      app: my-api  # Apply to pods with this label
  action: CUSTOM
  provider:
    name: tenuo-ext-authz
  rules:
  - to:
    - operation:
        paths: ["/api/*"]  # Paths requiring authorization
```

### What This Does

- All requests to `/api/*` are sent to Tenuo for authorization
- Tenuo checks the warrant in `X-Tenuo-Warrant` header
- Only authorized requests reach your backend

---

## Kubernetes Sidecar Deployment

Deploy Tenuo as a sidecar container:

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-api
  template:
    metadata:
      labels:
        app: my-api
    spec:
      containers:
      # Your application
      - name: app
        image: your-app:latest
        ports:
        - containerPort: 8080
        
      # Tenuo authorization sidecar
      - name: tenuo-authz
        image: tenuo/authorizer:0.1
        args:
        - serve
        - --config=/etc/tenuo/gateway.yaml
        - --bind=0.0.0.0
        - --port=9090
        ports:
        - containerPort: 9090
        env:
        - name: TENUO_TRUSTED_KEYS
          valueFrom:
            secretKeyRef:
              name: tenuo-secrets
              key: trusted_keys
        volumeMounts:
        - name: tenuo-config
          mountPath: /etc/tenuo
        resources:
          limits:
            memory: "64Mi"
            cpu: "100m"
          requests:
            memory: "32Mi"
            cpu: "50m"
            
      volumes:
      - name: tenuo-config
        configMap:
          name: tenuo-gateway-config
---
# ConfigMap for gateway configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: tenuo-gateway-config
data:
  gateway.yaml: |
    version: "1"
    settings:
      warrant_header: "X-Tenuo-Warrant"
      pop_header: "X-Tenuo-PoP"
      clock_tolerance_secs: 30
    
    tools:
      read_file:
        description: "Read a file"
        constraints:
          path:
            from: body
            path: "path"
            required: true
      
      query_database:
        description: "Query database"
        constraints:
          query:
            from: body
            path: "query"
            required: true
          database:
            from: header
            path: "X-Database"
    
    routes:
      - pattern: "/api/files/{action}"
        method: ["GET", "POST"]
        tool: "read_file"
      
      - pattern: "/api/db/query"
        method: ["POST"]
        tool: "query_database"
---
# Secret for trusted keys
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-secrets
type: Opaque
stringData:
  trusted_keys: "f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f"
```

---

## nginx Integration

For nginx, use the `auth_request` directive:

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

    # Internal location for Tenuo authorization
    location = /_tenuo_auth {
        internal;
        proxy_pass http://tenuo;
        proxy_pass_request_body on;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        # Forward warrant headers
        proxy_set_header X-Tenuo-Warrant $http_x_tenuo_warrant;
        proxy_set_header X-Tenuo-PoP $http_x_tenuo_pop;
    }

    # Protected API routes
    location /api/ {
        auth_request /_tenuo_auth;
        
        # On auth failure, return 403
        error_page 401 403 = @auth_failed;
        
        # On success, proxy to backend
        proxy_pass http://backend;
    }
    
    location @auth_failed {
        return 403 '{"error": "authorization_failed"}';
        add_header Content-Type application/json;
    }
}
```

---

## Docker Compose (Development)

For local development without Kubernetes:

```yaml
# docker-compose.yaml
version: '3.8'

services:
  # Your API
  api:
    build: .
    environment:
      - PORT=8080
  
  # Tenuo authorization service
  tenuo-authz:
    image: tenuo/authorizer:0.1
    command:
      - serve
      - --config=/etc/tenuo/gateway.yaml
      - --port=9090
    volumes:
      - ./gateway.yaml:/etc/tenuo/gateway.yaml:ro
    environment:
      - TENUO_TRUSTED_KEYS=${TENUO_TRUSTED_KEYS}
  
  # nginx as the entry point
  nginx:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
      - tenuo-authz
```

---

## Direct SDK Integration (No Sidecar)

For simpler deployments, use the Python SDK directly:

```python
from fastapi import FastAPI, Request, HTTPException
from tenuo import (
    Authorizer, Warrant, Keypair,
    set_warrant_context, set_keypair_context,
    lockdown, Pattern
)

app = FastAPI()

# Initialize authorizer with trusted root
control_plane_key = PublicKey.from_hex(os.getenv("TENUO_TRUSTED_KEY"))
authorizer = Authorizer(trusted_roots=[control_plane_key])

# Load service keypair
keypair = Keypair.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    # Extract warrant from header
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        raise HTTPException(401, "Missing X-Tenuo-Warrant header")
    
    try:
        warrant = Warrant.from_base64(warrant_b64)
        authorizer.verify(warrant)
    except Exception as e:
        raise HTTPException(403, f"Invalid warrant: {e}")
    
    # Set context for downstream handlers
    with set_warrant_context(warrant), set_keypair_context(keypair):
        return await call_next(request)

# Protected endpoint
@app.post("/api/files/read")
@lockdown("read_file")
async def read_file(path: str):
    # Authorization handled by @lockdown
    return {"content": open(path).read()}
```

---

## Choosing a Pattern

| Scenario | Recommended Pattern |
|----------|---------------------|
| **Kubernetes + Istio** | Istio AuthorizationPolicy |
| **Kubernetes + Envoy** | Envoy ext_authz |
| **Kubernetes (bare)** | Sidecar deployment |
| **nginx frontend** | auth_request directive |
| **Direct Python app** | SDK middleware |
| **Local development** | Docker Compose + nginx |

---

## See Also

- [Gateway Configuration](./gateway-config) — YAML config reference
- [Kubernetes Integration](./kubernetes) — K8s-specific patterns
- [API Reference](./api-reference) — Python SDK documentation
