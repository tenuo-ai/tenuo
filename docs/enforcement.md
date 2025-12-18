# Enforcement Models

## Overview

Tenuo provides **Action-Level Security** for AI Agents. But where exactly does that security live?

Unlike network firewalls (which block IPs) or IAM (which blocks identities), Tenuo blocks **specific tool calls** based on cryptographic warrants.

IAM Policies answer “may this identity do X?”
Warrants answer “was this specific action authorized by a specific delegator?”

You can deploy Tenuo in three enforcement models, ranging from "Drop-in Safety" to "Zero Trust Infrastructure."

| Model | Enforcement Point | Protects Against |
|-------|-------------------|------------------|
| In-Process | Inside your Python agent | Prompt injection (confused deputy) |
| Sidecar/Gateway | Separate process, same pod or cluster | Compromised agent (RCE) |
| MCP Proxy | Between agent and MCP server | Unauthorized tool discovery and use |

Choose based on your threat model. They can be combined for defense in depth.

---

## Model 1: Advisory Enforcement (The Library)

*Best for: Preventing Prompt Injection in Monolithic Agents, LangChain/LangGraph, quick integration*

In this model, Tenuo runs **inside** your agent's process as a Python library / decorator.

* **Architecture:**
    ```python
    Agent (Python)
      └─ @lockdown decorator (Tenuo SDK)
           └─ Tool Implementation (Function)
    ```
* **The Flow:**
    1.  LLM generates a tool call: `delete_file("/etc/passwd")`
    2.  The `@lockdown` decorator intercepts the call.
    3.  It checks the current `Warrant` in the context.
    4.  **Action:** If the warrant says `path: /data/*`, Tenuo raises an exception. The tool code never runs.
* **Security Guarantee:** 

Constrains Confused Deputy attacks. If prompt injection tricks the  LLM into calling unauthorized tools, Tenuo blocks it.

However, if attacker gets remote code execution (RCE) on the agent server process, they can remove the decorator or call tools directly to bypass Tenuo. The agent process is the trust boundary.

>> ***This model Prevents confused deputy attacks caused by prompt injection inside a trusted process.***

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
    tools = await client.get_protected_tools()
    
    # Every call goes through Tenuo authorization
    with set_warrant_context(warrant), set_keypair_context(keypair):
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
│    @lockdown ──────────────────────────────────┐    │
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