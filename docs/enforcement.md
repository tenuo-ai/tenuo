# Enforcement Models

## Overview

Tenuo provides **Action-Level Security** for AI Agents. But where exactly does that security live?

Unlike network firewalls (which block IPs) or IAM (which blocks identities), Tenuo blocks **specific tool calls** based on cryptographic warrants.

IAM Policies answer “may this identity do X?”
Warrants answer “was this specific action authorized by a specific delegator?”

You can deploy Tenuo in four enforcement models, ranging from "Drop-in Safety" to "Zero Trust Infrastructure."

| Model | Enforcement Point | Protects Against |
|-------|-------------------|------------------|
| In-Process | Inside your Python agent | Prompt injection (confused deputy) |
| Sidecar | Separate process, same pod | Compromised agent (RCE) |
| Gateway | Cluster ingress (Envoy/Istio) | Centralized policy |
| MCP Proxy | Between agent and MCP server | Unauthorized tool discovery |

Choose based on your threat model. They can be combined for defense in depth.

---

## Model 1: Advisory Enforcement (The Library)

*Best for: Preventing Prompt Injection in Monolithic Agents, LangChain/LangGraph, quick integration*

In this model, Tenuo runs **inside** your agent's process as a Python library / decorator.

* **Architecture:**
    ```python
    Agent (Python)
      └─ @guard decorator (Tenuo SDK)
           └─ Tool Implementation (Function)
    ```

**How it works:**

```python
@guard(tool="delete_file")
def delete_file(path: str):
    os.remove(path)  # Never reached if unauthorized

with warrant_scope(warrant), key_scope(keypair):
    delete_file("/etc/passwd")  # Raises ScopeViolation
```

1. LLM generates a tool call: `delete_file("/etc/passwd")`
2. The `@guard` decorator serves as the primary enforcement point.
It checks:
1. Warrant existence
2. Warrant validity (expiration)
3. Tool authorization
4. Argument constraints
5. Proof-of-Possession signature. If the warrant says `path: /data/*`, Tenuo raises `ScopeViolation`. The tool code never runs.

**Security Guarantee:** Blocks confused deputy attacks. If prompt injection tricks the LLM into calling unauthorized tools, Tenuo stops it.

**Limitation:** If an attacker gets remote code execution (RCE) on the agent process, they can bypass Tenuo by calling tools directly. The agent process is the trust boundary. For RCE protection, use Model 2 (Sidecar).

**Variant: Web Framework Middleware**

*Best for: Agents exposed as APIs (e.g., LangServe, Flask apps)*

If your agent exposes tools as HTTP endpoints, you can enforce warrants globally using middleware. This is cleaner than decorating every single route.

**FastAPI / Starlette:**

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from tenuo import Authorizer, Warrant, ScopeViolation

app = FastAPI()

# Initialize with your control plane's public key
authorizer = Authorizer(trusted_roots=[control_plane_public_key])

@app.middleware("http")
async def tenuo_guard(request: Request, call_next):
    # Skip health checks
    if request.url.path in ["/health", "/ready"]:
        return await call_next(request)
    
    # 1. Extract Warrant from header
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        return JSONResponse(status_code=401, content={"error": "Missing warrant"})
    
    try:
        warrant = Warrant.from_base64(warrant_b64)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid warrant"})
    
    # 2. Identify the Tool (Endpoint) & Arguments
    tool_name = request.url.path  # e.g., "/tools/read_file"
    
    # Parse body as JSON dict (check() requires a dict)
    try:
        args = await request.json() if request.method in ["POST", "PUT"] else {}
    except:
        args = {}

    # 3. Enforce
    try:
        authorizer.check(warrant, tool_name, args)
    except ScopeViolation:
        return JSONResponse(status_code=403, content={"error": "Access denied"})
    
    return await call_next(request)
```

**Flask:**

```python
from flask import Flask, request, abort
from tenuo import Authorizer, Warrant, ScopeViolation

app = Flask(__name__)
authorizer = Authorizer(trusted_roots=[control_plane_public_key])

@app.before_request
def check_warrant():
    # Skip health checks
    if request.path in ["/health", "/ready"]:
        return

    # Extract and validate warrant
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        abort(401, description="Missing warrant")
    
    try:
        warrant = Warrant.from_base64(warrant_b64)
        args = request.get_json() or {}
        authorizer.check(warrant, request.path, args)
    except ScopeViolation:
        abort(403, description="Access denied")
```

**FastAPI Dependency Injection (Recommended)**

For more control over which routes require warrants, use FastAPI's dependency injection:

```python
from fastapi import FastAPI, Depends, Request, HTTPException
from tenuo import (
    Warrant, guard,
    warrant_scope, key_scope,
    ScopeViolation
)

app = FastAPI()

async def require_warrant(request: Request) -> Warrant:
    """Dependency that extracts and validates warrant."""
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        raise HTTPException(status_code=401, detail="Missing warrant")
    return Warrant.from_base64(warrant_b64)

@guard(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

@app.get("/files/{path:path}")
async def get_file(path: str, warrant: Warrant = Depends(require_warrant)):
    # Context ensures @guard can access warrant in async handlers
    with warrant_scope(warrant), key_scope(AGENT_KEYPAIR):
        try:
            return {"content": read_file(path)}
        except ScopeViolation as e:
            raise HTTPException(status_code=403, detail=str(e))
```

This pattern is preferred when:
- Only some routes need authorization
- You want per-route warrant requirements  
- You need proper async context propagation

See [examples/fastapi_integration.py](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/fastapi_integration.py) for a complete example.

---

## Model 2: Sidecar Enforcement

*Best for: Microservices, Kubernetes, and High-Value Tools, zero-trust architectures*

In this model, Tenuo runs **alongside** your application as a separate process (Sidecar). The Tool is not just a function; it is an API endpoint and Tenuo sits in front of it.

* **Architecture:**
    ```
    ┌─────────────────┐       Network        ┌──────────────────────────┐
    │  Agent (Client) │ ───────────────────► │ Tool Service Pod         │
    └─────────────────┘      (HTTP/gRPC)     │ ┌──────────────────────┐ │
                                             │ │   Tenuo Sidecar      │ │
                                             │ └─────────┬────────────┘ │
                                             │           ▼              │
                                             │ ┌──────────────────────┐ │
                                             │ │   Actual API Logic   │ │
                                             │ └──────────────────────┘ │
                                             └──────────────────────────┘
    ```
* **The Flow:**
    1. Agent sends HTTP request with warrant in header (`POST /api/delete?file=/etc/passwd` + `X-Tenuo-Warrant`).
    2. Request hits Tenuo sidecar first (via Kubernetes networking or reverse proxy) 
    3. Sidecar validates warrant against parameters (path/body).
    4. If denied: returns `403 Forbidden`. The request never reaches tool
    5. If allowed: forwards request to actual tool API

* **Security Guarantee:** 
    Even if the agent is fully compromised (RCE), it cannot force unauthorized actions. The tool service is the trust boundary, not the agent.

**Kubernetes deployment:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: tool-service
spec:
  containers:
    - name: tenuo-authorizer
      image: tenuo/authorizer:0.1
      ports:
        - containerPort: 9090
    - name: tool-api
      image: your-tool:latest
      # Only accepts traffic from localhost (sidecar)
```

**Note:** This model can also be deployed as a **Gateway**, where a single Tenuo instance protects multiple services. This simplifies management but can introduce a bottleneck.


---

## Model 3: Gateway Enforcement

*Best for: Protecting multiple services, centralized policy, API gateway patterns*

Like sidecar, but one Tenuo instance protects many services.

```
                                    ┌─────────────────────────┐
                                    │  Service A              │
                              ┌────▶│  (database)             │
┌──────────────┐              │     └─────────────────────────┘
│              │   ┌──────────┴───────────┐
│   Agents     │──▶│   Tenuo Gateway      │
│              │   │   (ext_authz)        │
└──────────────┘   └──────────┬───────────┘
                              │     ┌─────────────────────────┐
                              └────▶│  Service B              │
                                    │  (file storage)         │
                                    └─────────────────────────┘
```

**Envoy integration:**

Tenuo implements Envoy's `ext_authz` protocol. If you already run Envoy or Istio, no sidecar container needed.

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: tenuo-authorizer
```

**How it works:**

1. Request hits Envoy proxy
2. Envoy pauses and asks Tenuo: "Is this warrant valid for `POST /admin`?"
3. Tenuo verifies (stateless, ~27μs)
4. Tenuo returns allow/deny
5. Envoy forwards or blocks

**Security guarantee:**

Same as sidecar: tool services are protected regardless of agent compromise. Centralized enforcement simplifies management but introduces a single point of configuration.

---


## Model 4: The "MCP" Pattern (Model Context Protocol)

*Best for: MCP-based tool integrations, standardized agent-tool interfaces*

MCP standardizes how agents talk to tools. Tenuo acts as the "Middleware" that secures this channel.

* **Architecture:**

```
┌──────────────┐       ┌──────────────────┐       ┌──────────────┐
│              │       │                  │       │              │
│    Agent     │──MCP─▶│   Tenuo Proxy    │──MCP─▶│  MCP Server  │
│              │       │                  │       │  (filesystem,│
│              │       │  Validates       │       │   database)  │
│              │◀──────│  warrant before  │◀──────│              │
│              │       │  forwarding      │       │              │
└──────────────┘       └──────────────────┘       └──────────────┘
```

**How it works:**

```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient("python", ["mcp_server.py"]) as client:
    tools = client.tools
    
    # Every call goes through Tenuo authorization
    with warrant_scope(warrant), key_scope(keypair):
        await tools["read_file"](path="/data/report.txt")  # Checked
        await tools["read_file"](path="/etc/passwd")       # Denied
```

1. Agent connects to Tenuo proxy (not raw MCP server)
2. Agent sends MCP `call_tool` request
3. Proxy extracts arguments, verifies warrant
4. If valid: forwards to real MCP server
5. If denied: returns error, MCP server never sees request

**Security guarantee:**

Protects MCP tool access. The proxy is the trust boundary.

---

## Combining Models (Defense in Depth)

Enforcement Models aren't mutually exclusive. Layer them:

```
┌─────────────────────────────────────────────────────┐
│  Agent Process                                      │
│                                                     │
│    @guard ──────────────────────────────────┐    │
│    (Model 1: catches confused deputy)          │    │
│                                                │    │
└────────────────────────────────────────────────┼────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────┐
│  Tenuo Sidecar                                      │
│  (Model 2: catches compromised agent)               │
└────────────────────────────────────────────────┬────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────┐
│  Tool Service                                       │
│  (Protected by both layers)                         │
└─────────────────────────────────────────────────────┘
```

- Model 1 catches prompt injection before it leaves the agent
- Model 2 catches anything that gets past a compromised agent

Belt and suspenders.


---

## Summary

| Goal | Model |
|------|-------|
| Protect LangChain/LangGraph agent from prompt injection | Model 1 (In-Process) |
| Protect internal APIs from any caller | Model 2 (Sidecar) |
| Centralized auth for multiple services | Model 3 (Gateway) |
| Secure MCP tool access | Model 4 (MCP Proxy) |
| Maximum security | Combine Model 1 + Model 2 |

---

## See Also

- [Kubernetes Deployment](./kubernetes) — Full sidecar and gateway patterns
- [Proxy Configs](./proxy-configs) — Envoy, Istio, nginx configurations
- [Security](./security) — Threat model and best practices
- [LangChain Integration](./langchain) — Tool protection for LangChain