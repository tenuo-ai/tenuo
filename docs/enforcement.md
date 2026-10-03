---
title: "Enforcement Architecture"
description: "Warrants, proof-of-possession, attenuation, and where checks run."
---

# Enforcement Architecture

> [!NOTE]
> **Key terms:**
> - **Warrant**: A short-lived, cryptographically signed token that says "this agent may call these tools with these constraints"
> - **Proof-of-Possession (PoP)**: A signature proving the requester holds the warrant's private key (stolen warrants are useless without it)
> - **Attenuation**: Delegating a warrant with *narrower* permissions: authority can only shrink, never expand
> - **Control Plane**: The trusted service that issues root warrants (you build this, or use Tenuo Cloud)
>
> See [Concepts](./concepts) for a full introduction.

This page covers how Tenuo deploys into production infrastructure: the five enforcement points, how they compose for defense in depth, and the security architecture of the Rust core. For the problem/solution overview and how warrants work, see [Concepts](./concepts).

---

## Deployment Models

Tenuo deploys at five enforcement points. Choose based on your threat model, or combine them for defense in depth.

Every model verifies warrants, so **all five block unauthorized tool calls** -- including prompt injection and confused deputy attacks. The difference is where the enforcement point sits and what additional threats it covers.

| Model | Where It Runs | Additional Threat Coverage | Trust Boundary |
|-------|---------------|---------------------------|----------------|
| **In-Process** | Inside the agent (Python decorator) | Fastest path; framework-native integration | Agent process |
| **Sidecar** | Separate container, same pod | Agent compromise (RCE) | Pod network |
| **Gateway** | Cluster ingress (Envoy/Istio `ext_authz`) | Centralized policy across multiple services | Gateway |
| **MCP Proxy** | Between agent and MCP server | Unauthorized tool discovery | Proxy |
| **A2A** | Between agents (JSON-RPC) | Unconstrained inter-agent delegation | Receiving agent |

### In-Process: Drop-In Agent Protection

The fastest path to production. Tenuo wraps tool functions inside the agent process. If the LLM is tricked by prompt injection into calling `delete_file("/etc/passwd")`, the warrant blocks it before the function body runs.

```python
@guard(tool="delete_file")
def delete_file(path: str):
    os.remove(path)  # Never reached without a valid warrant
```

Integrates with the frameworks teams already use:

| Framework | Module | Integration |
|-----------|--------|-------------|
| LangGraph | `tenuo.langgraph` | `TenuoToolNode` / `TenuoMiddleware` |
| OpenAI | `tenuo.openai` | `verify_tool_call()` |
| CrewAI | `tenuo.crewai` | `@guard` decorator |
| Google ADK | `tenuo.google_adk` | `TenuoPlugin` |
| AutoGen | `tenuo.autogen` | `@guard` decorator |
| Temporal | `tenuo.temporal` | Workflow-level warrants |
| FastAPI | `tenuo.fastapi` | Middleware / dependency injection |
| MCP | `tenuo.mcp` | Proxy or server-side verifier |
| A2A | `tenuo.a2a` | Client / server |

All integrations share a single enforcement code path through the Rust core: same behavior, same audit log, same security guarantees regardless of framework.

### Human Approvals

After PoP and constraint checks, the Rust core evaluates **approval gates** on the warrant. If a gate fires:

1. Collect `SignedApproval`(s) from `required_approvers` (via handler or pre-supplied approvals).
2. Verify signatures, request-hash binding, expiry, and m-of-n threshold.
3. Proceed or return a typed retry signal (`approval_required` vs `insufficient_approvals`).

Gates, approvers, and threshold are defined on the warrant — not in adapter config. See [Human Approvals](approvals.md) for quick start and per-integration retry codes.

> [!NOTE]
> **Limitation**: In-process enforcement cannot survive agent compromise (RCE). If an attacker gets code execution inside the agent, they can call tools directly. For that threat, add a sidecar.

### Sidecar: Surviving Agent Compromise

Tenuo runs as a separate container in the same Kubernetes pod. All tool traffic routes through the sidecar first. Even if the agent process is fully compromised, unauthorized calls never reach the tool service.

```
┌─────────────────┐       Network        ┌──────────────────────────┐
│  Agent (Client) │ ───────────────────► │ Tool Service Pod         │
└─────────────────┘      (HTTP/gRPC)     │ ┌──────────────────────┐ │
                                         │ │   Tenuo Sidecar      │ │
                                         │ └─────────┬────────────┘ │
                                         │           ▼              │
                                         │ ┌──────────────────────┐ │
                                         │ │   Tool API           │ │
                                         │ └──────────────────────┘ │
                                         └──────────────────────────┘
```

```yaml
# Standard Kubernetes sidecar pattern
spec:
  containers:
    - name: tenuo-authorizer
      image: tenuo/authorizer:0.3.1
      ports:
        - { name: http, containerPort: 9090 }     # authorization API
        - { name: health, containerPort: 9091 }   # /health, /ready, /status
      readinessProbe:
        httpGet: { path: /ready, port: health }
    - name: tool-api
      image: your-tool:latest
      # Only accepts traffic from localhost (sidecar)
```

#### Serving over a Unix domain socket

When the agent and the authorizer share a pod or host, the sidecar can serve the
**same HTTP API over a Unix domain socket** instead of a localhost TCP port. This
keeps authorization traffic off the network stack entirely and lets you gate access
with filesystem permissions.

```bash
tenuo-authorizer serve \
  --config /etc/tenuo/authorizer.yaml \
  --socket /var/run/tenuo/authorizer.sock \
  --socket-mode 0660 \
  --socket-group tenuo
```

- `--socket PATH` — serve over `AF_UNIX` at `PATH`. Mutually exclusive with `--port` / `--bind` (the CLI rejects combining them).
- `--socket-mode` — octal bits controlling who may *connect* (default `0660` = owner + group). Use `0600` for owner-only or `0666` for any local user.
- `--socket-group` — group name or numeric gid the socket is `chgrp`'d to after bind. With the default `0660`, this lets a **non-root client** (e.g. an app user in a shared `tenuo` group) reach an authorizer running as root.
- `--health-port`: health endpoints (`/health`, `/healthz`, `/ready`, `/status`) are not served on the socket. In socket mode no TCP listener is opened unless you set `--health-port`, which serves them on `--health-bind` (default `127.0.0.1`).

Clients connect with any HTTP-over-UDS client, e.g.:

```bash
curl --unix-socket /var/run/tenuo/authorizer.sock -X POST http://localhost/api/v1/clusters/staging/deploy \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $POP"
```

**Security:** the socket's trust rests on its *parent directory*. The authorizer
refuses to bind if that directory is group- or world-writable, refuses a symlink or
non-socket file at the path, and removes a stale socket left by a previous crash.
Place the socket in a directory only the authorizer's own user can write to (for
example `/var/run/tenuo`).

### Gateway: Centralized Enforcement for Multiple Services

One Tenuo instance protects many backend services. Plugs into existing service mesh infrastructure via Envoy's HTTP `ext_authz` protocol (gRPC `ext_authz` is not supported yet). No new proxy to deploy if you already run Envoy or Istio.

```
                                    ┌─────────────────────────┐
                                    │  Service A (database)   │
                              ┌────▶│                         │
┌──────────────┐              │     └─────────────────────────┘
│   Agents     │──▶ Tenuo Gateway (ext_authz) ──┤
└──────────────┘              │     ┌─────────────────────────┐
                              └────▶│  Service B (storage)    │
                                    └─────────────────────────┘
```

Authorization is stateless and local: no runtime network call, no shared database, no token introspection endpoint. See [Performance Benchmarks](./api-reference#performance-benchmarks) for measured timings.

### MCP Proxy: Securing the Model Context Protocol

Tenuo sits between the agent and MCP servers. The agent never talks to raw MCP endpoints. Every `call_tool` request is authorized against the warrant before forwarding.

For teams that prefer server-side verification, `MCPVerifier` runs inside the MCP server itself with no separate proxy needed. See [MCP Integration](./mcp) for both patterns.

### A2A: Cryptographic Inter-Agent Delegation

When an orchestrator delegates a task to a worker agent, the warrant travels with it, attenuated to only the permissions the worker needs. The worker cannot exceed its delegated scope, even if compromised.

```
┌──────────────┐  attenuated warrant  ┌──────────────┐
│ Orchestrator │─────────────────────▶│   Worker     │
│              │◀─────────────────────│              │
└──────────────┘       result         └──────────────┘
```

This is cryptographic least privilege for multi-agent systems. The orchestrator narrows the scope; the worker proves it holds the key; the Rust core verifies the chain. See [A2A Integration](./a2a) for details.

---

## Defense in Depth: Layered Enforcement

These models compose. A production deployment can layer in-process enforcement (catches prompt injection at the source) with a sidecar (catches anything that slips past a compromised agent):

```
┌─────────────────────────────────────────────────────┐
│  Agent Process                                      │
│    @guard ─────────────────────────────────┐     │
│    (catches confused deputy)                  │     │
└───────────────────────────────────────────────┼─────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────┐
│  Tenuo Sidecar                                      │
│  (catches compromised agent)                        │
└───────────────────────────────────────────────┬─────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────┐
│  Tool Service (protected by both layers)            │
└─────────────────────────────────────────────────────┘
```

Combine with Kubernetes Network Policies for complete coverage: Tenuo prevents unauthorized tool usage *through* your API; network policies prevent bypassing your API entirely.

---

## Production Hardening

### `TENUO_REQUIRE_EXTENSION=1`

The tenuo Python SDK depends on a native Rust extension (`tenuo_core`) compiled for each platform. If the extension wheel is missing — for example, after a Docker image rebuild with the wrong `manylinux` tag or a missing `arm64` wheel — enforcement silently degrades: tool calls succeed unconditionally with no warrant attached and no error logged.

Set `TENUO_REQUIRE_EXTENSION=1` in production to make this a hard failure at process startup instead:

```bash
# In your Dockerfile or deployment environment
ENV TENUO_REQUIRE_EXTENSION=1
```

With this flag, if `tenuo_core` cannot be imported, the process exits immediately with a clear error message that identifies the missing wheel as the cause. Without the flag, the missing extension is logged as a warning but does not halt the process.

**Verify the extension is present in your container:**
```bash
python -c "import tenuo_core; print('ok')"
```

---

## Security Architecture

### What's in the Rust Core (the Security Boundary)

All security-critical logic runs in a single Rust library (`tenuo_core`), compiled to both native and WASM:

| Check | Guarantee |
|-------|-----------|
| **Ed25519 signature verification** | Warrants cannot be forged or tampered with |
| **Proof-of-Possession** | Stolen warrants are useless without the private key |
| **Expiration enforcement** | TTL checked on every call; expired warrants are rejected |
| **Constraint evaluation** | Every argument validated against the warrant's constraints |
| **Chain validation** | Full delegation chain verified from root to leaf |
| **Attenuation enforcement** | Child warrants cannot exceed parent's scope |

Authorization (signature + expiration + tool lookup) runs locally with no runtime external dependencies. Constraint evaluation adds variable time depending on complexity. No database, no auth server, no token introspection endpoint. A warrant is entirely self-contained. See [Performance Benchmarks](./api-reference#performance-benchmarks) for measured timings.

### What's in the Python Layer (Defense in Depth)

The Python SDK adds an additional enforcement layer via `@guard` with `Annotated[]` type hints:

```python
@guard(tool="fetch_data")
def fetch_data(url: Annotated[str, UrlSafe(allow_domains=["*.example.com"])]):
    return requests.get(url).text
```

This checks constraints at the Python level *before* the Rust core. Even if a warrant is overly broad, the annotation catches it. This is a defense-in-depth measure. The Rust core is the trust boundary; the Python layer is a safety net.

---

## Summary

Every deployment model verifies warrants, so each one blocks unauthorized tool calls regardless of how the call originated. The difference is where the enforcement point sits and what additional threats it covers:

| Deployment Model | Blocks prompt injection | Also covers |
|------------------|:-----------------------:|-------------|
| In-Process (`@guard`) | Yes | Fastest integration, framework-native |
| Sidecar | Yes | Agent compromise (RCE) |
| Gateway (Envoy `ext_authz`) | Yes | Centralized multi-service policy |
| MCP Proxy / server-side verifier | Yes | Unauthorized tool discovery |
| A2A | Yes | Unconstrained inter-agent delegation |
| In-Process + Sidecar + Network Policy | Yes | Maximum coverage (defense in depth) |

---

## Proxy Configurations

Copy-paste-ready configurations for integrating Tenuo authorization at the network layer.

### Envoy External Authorization

Tenuo integrates with Envoy as an HTTP external authorization service
(`ext_authz` with `http_service`). For each client request Envoy sends a check
request with the same method, the original path (prefixed with `path_prefix`),
the allow-listed headers and, optionally, the body. The authorizer answers 200
to allow; any other status is a deny and is returned to the client.

> [!NOTE]
> The authorizer speaks **HTTP** ext_authz only. gRPC ext_authz
> (`grpc_service`, Istio `envoyExtAuthzGrpc`) is not supported yet; configured
> that way, every request fails at the authorization call.

```
+---------+     +---------+  check: /ext_authz/<path>  +-------------+     +---------+
| Client  |---->|  Envoy  |--------------------------->| Tenuo Authz |     | Backend |
|         |     |         |<---------------------------|   (9090)    |     |         |
+---------+     |         |   200, or 401/403/404      +-------------+     |         |
                |         |--------------------------------------------->|         |
                |         |  (only if 200)                                |         |
                +---------+                                               +---------+
```

```yaml
# envoy.yaml (complete, tested file: docs/quickstart/envoy/envoy.yaml)
static_resources:
  listeners:
  - name: main
    address:
      socket_address: { address: 0.0.0.0, port_value: 8080 }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress
          normalize_path: true
          merge_slashes: true
          route_config:
            name: local_route
            virtual_hosts:
            - name: backend
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: backend }
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              failure_mode_allow: false        # fail closed
              with_request_body:               # only needed for `from: body` extraction
                max_request_bytes: 65536
                allow_partial_message: false
              allowed_headers:                 # copied into the check request
                patterns:
                - exact: x-tenuo-warrant
                - exact: x-tenuo-pop
                - exact: x-tenuo-approvals
                - exact: content-type
              http_service:
                server_uri:
                  uri: http://tenuo-authorizer:9090
                  cluster: tenuo-authorizer
                  timeout: 0.25s
                path_prefix: /ext_authz        # gateway.yaml route patterns start with this
                authorization_response:
                  allowed_client_headers:      # returned to the client on deny
                    patterns:
                    - exact: x-tenuo-deny-reason
                    - exact: content-type
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: tenuo-authorizer
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: tenuo-authorizer
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: tenuo-authorizer, port_value: 9090 }

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
              socket_address: { address: backend, port_value: 8080 }
```

Matching `gateway.yaml` routes include the prefix:

```yaml
routes:
  - pattern: "/ext_authz/api/v1/clusters/{cluster}/{action}"
    method: ["POST"]
    tool: manage_infrastructure
```

**Always set a `path_prefix`.** The authorizer serves its health and status
endpoints (`/health`, `/healthz`, `/ready`, `/status`) only on the separate
health port (`--health-port`, default 9091), so on the ext_authz port those
paths go through route matching like any other request and are denied without
a warrant. Older authorizers (and `--legacy-health-on-main-port`) answered them
with 200 on the ext_authz port; with a raw client path, Envoy treated that 200
as ALLOW and forwarded the request to the backend unauthenticated. The prefix
keeps you safe against that and keeps authorization routes distinct from
backend paths.

Response codes from the authorizer: 200 allow; 401 `missing_warrant`; 400
`invalid_warrant` (undecodable, or the warrant signature does not verify) and
`extraction_failed`; 404 `no_route` (no route for this method and path); 403
for every authorization failure (`untrusted_root`, `missing_pop`,
`signature_invalid`, `tool_not_allowed`, `constraint_violation`, expiry,
revocation). With `debug_mode: true` the reason is also in
`x-tenuo-deny-reason`.

A runnable Docker Compose version with an end-to-end test lives in
[`docs/quickstart/envoy`](./quickstart/envoy/).

### Istio Integration

Register Tenuo as an **HTTP** ext_authz extension provider in the mesh config:

```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    extensionProviders:
    - name: tenuo-ext-authz
      envoyExtAuthzHttp:
        service: tenuo-authorizer.tenuo-system.svc.cluster.local
        port: 9090
        timeout: 1s
        failOpen: false
        pathPrefix: /ext_authz
        includeRequestHeadersInCheck: [x-tenuo-warrant, x-tenuo-pop, x-tenuo-approvals, content-type]
        includeRequestBodyInCheck:
          maxRequestBytes: 65536
          allowPartialMessage: false
        headersToDownstreamOnDeny: [x-tenuo-deny-reason, content-type]
```

Then apply an AuthorizationPolicy:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: tenuo-authz
  namespace: default
spec:
  selector:
    matchLabels:
      app: my-tool-api
  action: CUSTOM
  provider:
    name: tenuo-ext-authz
  rules:
  - to:
    - operation:
        paths: ["/api/*"]
```

The workload must have an Istio sidecar (or a waypoint in ambient mode).
Requests that skip the proxy, such as `kubectl port-forward`, skip the policy
too. See the [Istio quickstart](./quickstart/istio/).

### nginx Integration

```nginx
upstream backend {
    server localhost:8080;
}

upstream tenuo {
    server localhost:9090;
}

server {
    listen 80;

    location = /_tenuo_auth {
        internal;
        # The authorizer matches routes on the method and path it receives,
        # so forward both. Routes in gateway.yaml start with /ext_authz.
        proxy_pass http://tenuo/ext_authz$request_uri;
        proxy_method $request_method;
        # auth_request cannot forward the body: `from: body` extraction is
        # not available behind nginx.
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Tenuo-Warrant $http_x_tenuo_warrant;
        proxy_set_header X-Tenuo-PoP $http_x_tenuo_pop;
    }

    location /api/ {
        auth_request /_tenuo_auth;
        error_page 401 403 = @denied;
        proxy_pass http://backend;
    }

    location @denied {
        return 403 '{"error": "authorization_denied"}';
        add_header Content-Type application/json;
    }

    location /health {
        proxy_pass http://backend;
    }
}
```

The `proxy_method $request_method` line matters: without it nginx sends the
auth subrequest as `GET`, so a `DELETE` or `POST` would be authorized as a
`GET` and then proxied with its real method. nginx turns any auth status other
than 2xx, 401 and 403 (for example the authorizer's 404 `no_route`) into a 500,
which still blocks the request.

### Docker Compose (Local Development)

[`docs/quickstart/envoy/docker-compose.yaml`](./quickstart/envoy/docker-compose.yaml)
runs Envoy, the authorizer and httpbin together. The authorizer part:

```yaml
services:
  tenuo-authorizer:
    image: tenuo/authorizer:0.3.1
    command: ["serve", "--port", "9090", "--config", "/etc/tenuo/gateway.yaml"]
    # Health and status: http://tenuo-authorizer:9091/health (--health-port)
    environment:
      TENUO_TRUSTED_KEYS: ${TENUO_TRUSTED_KEYS}   # hex public key(s) of trusted issuers, comma separated
    volumes:
      - ./gateway.yaml:/etc/tenuo/gateway.yaml:ro
```

---

## See Also

- [Concepts](./concepts): Problem/solution, warrants, threat model, why Tenuo
- [Constraints](./constraints): Complete constraint type reference and argument extraction
- [Security](./security): Full threat model, PoP, key management, best practices
- [MCP Integration](./mcp): MCP proxy and server-side verification
- [A2A Integration](./a2a): Agent-to-agent delegation
- [Kubernetes Deployment](./kubernetes): Sidecar and gateway patterns
