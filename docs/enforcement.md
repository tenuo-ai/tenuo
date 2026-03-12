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

Every model verifies warrants, so **all five block unauthorized tool calls** — including prompt injection and confused deputy attacks. The difference is where the enforcement point sits and what additional threats it covers.

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
      image: tenuo/authorizer:0.1
      ports: [{ containerPort: 9090 }]
    - name: tool-api
      image: your-tool:latest
      # Only accepts traffic from localhost (sidecar)
```

### Gateway: Centralized Enforcement for Multiple Services

One Tenuo instance protects many backend services. Plugs into existing service mesh infrastructure via Envoy's `ext_authz` gRPC protocol. No new proxy to deploy if you already run Envoy or Istio.

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

Authorization is stateless (~27μs) with no external dependencies. Tenuo adds negligible latency to the request path.

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

Authorization (signature + expiration + tool lookup) takes ~27μs, with **zero external dependencies**. Constraint evaluation adds variable time depending on complexity. No database, no auth server, no token introspection endpoint. A warrant is entirely self-contained.

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

## See Also

- [Concepts](./concepts): Problem/solution, warrants, threat model, why Tenuo
- [Constraints](./constraints): Complete constraint type reference
- [Security](./security): Full threat model, PoP, key management, best practices
- [MCP Integration](./mcp): MCP proxy and server-side verification
- [A2A Integration](./a2a): Agent-to-agent delegation
- [Kubernetes Deployment](./kubernetes): Sidecar and gateway patterns
- [Proxy Configs](./proxy-configs): Envoy, Istio, nginx configurations
