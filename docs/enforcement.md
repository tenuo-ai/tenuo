# Enforcement Architecture

> [!NOTE]
> **Key terms:**
> - **Warrant**: A short-lived, cryptographically signed token that says "this agent may call these tools with these constraints"
> - **Proof-of-Possession (PoP)**: A signature proving the requester holds the warrant's private key (stolen warrants are useless without it)
> - **Attenuation**: Delegating a warrant with *narrower* permissions: authority can only shrink, never expand
> - **Control Plane**: The trusted service that issues root warrants (you build this, or use Tenuo Cloud)
>
> See [Core Concepts](./concepts.md) for a full introduction.

Tenuo provides **action-level authorization** for AI agents. Unlike IAM (which gates identities) or LLM guardrails (which filter prompts), Tenuo gates **individual tool calls**, every argument, every invocation, using short-lived, cryptographically signed warrants.

This page explains how Tenuo fits into production infrastructure, what threats each deployment model addresses, and how the layers compose.

---

## How It Works (30-Second Version)

1. A control plane issues a **warrant**: a signed CBOR token that says *"this agent may call `search` and `read_file` where `path` is under `/data/reports`, for the next 5 minutes."*
2. The agent presents this warrant when calling tools.
3. Tenuo verifies: valid signature, unexpired, tool authorized, every argument satisfies its constraint. **Stateless, no network call.** Authorization alone takes ~27μs; constraint evaluation adds variable time depending on complexity.
4. If any check fails, the tool call is blocked before it executes.

Warrants are **delegatable**: an orchestrator can attenuate (narrow) its warrant and hand it to a worker agent. Authority only shrinks, never expands. The entire delegation chain is cryptographically verifiable.

---

## Deployment Models

Tenuo deploys at five enforcement points. Choose based on your threat model, or combine them for defense in depth.

| Model | Where It Runs | Threat Addressed | Trust Boundary |
|-------|---------------|------------------|----------------|
| **In-Process** | Inside the agent (Python decorator) | Prompt injection, confused deputy | Agent process |
| **Sidecar** | Separate container, same pod | Agent compromise (RCE) | Pod network |
| **Gateway** | Cluster ingress (Envoy/Istio `ext_authz`) | Centralized policy, multi-service | Gateway |
| **MCP Proxy** | Between agent and MCP server | Unauthorized tool access | Proxy |
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

## The Constraint Layer

Warrants don't just authorize tool names. They constrain every argument. A few examples:

```python
# SSRF-safe URL validation: blocks private IPs, metadata endpoints,
# ambiguous IP representations, with explicit domain allow/deny lists
url = UrlSafe(allow_domains=["api.github.com"], deny_domains=["*.evil.com"])

# Filesystem path containment (symlink-safe)
path = Subpath("/data/reports")

# Shell command safety: binary allowlist + injection prevention
cmd = Shlex(allow=["npm", "docker"])

# Composable value constraints
model = OneOf(["gpt-4o", "gpt-4o-mini"])
max_tokens = Range(0, 1000)
```

18 built-in constraint types cover values, numeric ranges, network addresses, filesystem paths, shell commands, URL patterns, regex, CIDR ranges, and composable boolean logic (`All`, `AnyOf`, `Not`). An extension range (type IDs 128-255) allows custom constraints without protocol changes.

Every constraint supports **monotonic attenuation**: delegated warrants can only tighten constraints, never loosen them. And the runtime is **fail-closed**: unrecognized constraint types are denied, never silently dropped.

See [Constraints](./constraints) for the full reference.

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

## Why Tenuo

| | Tenuo | Token-Based IAM | LLM Guardrails |
|---|-------|-----------------|----------------|
| **Granularity** | Per-tool, per-argument | Per-identity | Per-prompt |
| **Delegation** | Monotonic attenuation (cryptographic chain) | Static roles | N/A |
| **Authorization latency** | ~27μs (stateless, offline) | Requires auth server roundtrip | Requires LLM inference |
| **Tamper resistance** | Ed25519 signatures + Proof-of-Possession | Bearer token (stealable) | None |
| **Audit trail** | Cryptographic proof of who authorized what | Log-based | None |
| **Infrastructure fit** | K8s sidecar, Envoy `ext_authz`, MCP, A2A | Framework-specific | Framework-specific |
| **Runtime targets** | Native (Rust) + WASM (browser/edge) | Server-only | Server-only |

**Stateless verification** means horizontal scaling without coordination. No shared state, no cache invalidation, no token introspection endpoints. Each verifier is independent.

**WASM support** means the same Rust core runs in browsers, edge functions, and serverless environments. Warrants can be built and validated anywhere WebAssembly runs.

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

- [Security](./security): Full threat model, PoP, key management, best practices
- [Constraints](./constraints): Complete constraint type reference
- [MCP Integration](./mcp): MCP proxy and server-side verification
- [A2A Integration](./a2a): Agent-to-agent delegation
- [Kubernetes Deployment](./kubernetes): Sidecar and gateway patterns
- [Proxy Configs](./proxy-configs): Envoy, Istio, nginx configurations
