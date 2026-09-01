<p align="center">
  <img src="docs/images/tenuo-logo.svg" alt="tenuo" width="200">
</p>

<p align="center">
  <strong>Task-scoped authorization for AI agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml"><img src="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/tenuo"><img src="https://img.shields.io/crates/v/tenuo.svg" alt="Crates.io"></a>
  <a href="https://pypi.org/project/tenuo/"><img src="https://img.shields.io/pypi/v/tenuo.svg" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/tenuo/authorizer"><img src="https://img.shields.io/docker/v/tenuo/authorizer?label=docker" alt="Docker"></a>
  <a href="https://tenuo.ai"><img src="https://img.shields.io/badge/docs-tenuo.ai-blue" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
</p>

Tenuo gives each task only the authority it needs. That authority travels across agents, tools, and workflows, can only narrow when delegated, and is verified where the action executes. It complements the identity and policy systems you already have.

A **warrant** is a signed grant of which tools an agent can call, under what constraints, and for how long. It works like a prepaid card for one task. Sensitive actions can also require a [signed human approval](./docs/approvals.md). Deploy in-process or at a sidecar/gateway; the warrant semantics are the same.

> **Status: v0.2 - Production/Stable.** Core semantics are stable. See [CHANGELOG](./CHANGELOG.md).
>
> **Tenuo Cloud: Early Access.** Managed control plane with revocation, observability, and multi-tenant warrant issuance. [Request access →](https://tenuo.ai/early-access.html)

## Install

```bash
# Using uv (recommended)
uv pip install tenuo

# Or standard pip
pip install tenuo

# TypeScript SDK (beta, Node 20+)
npm i @tenuo/core@beta

# Rust (core crate)
cargo add tenuo
```

TypeScript details: [`tenuo-ts/README.md`](tenuo-ts/README.md). Rust details: the [Rust section](#rust) below.

Or try it without installing:

<a href="https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open In Colab"></a>
<a href="https://tenuo.ai/explorer/"><img src="https://img.shields.io/badge/Explorer-decode_warrants-1a1a1a" alt="Explorer"></a>
<a href="https://tenuo.ai/demo.html"><img src="https://img.shields.io/badge/Docker_Demo-delegation_chain-333333" alt="Docker Demo"></a>
<a href="https://niyikiza.com/posts/tenuo-launch/"><img src="https://img.shields.io/badge/Blog-Why_Tenuo%3F-ff6b6b" alt="Blog"></a>

## Quick Start: From One Tool to Delegated Work

### 1. Protect One Tool

Start with a normal Python function. The warrant limits both which tool can run and the arguments it can receive.

```python
from tenuo import Capability, Pattern, Range, SigningKey, configure, guard, mint_sync
from tenuo.exceptions import AuthorizationDenied

configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

@guard(tool="scale_cluster")
def scale_cluster(cluster: str, replicas: int) -> str:
    return f"Scaled {cluster} to {replicas} replicas"

authority = Capability(
    "scale_cluster",
    cluster=Pattern("staging-*"),
    replicas=Range.max_value(10),
)

with mint_sync(authority):
    print(scale_cluster("staging-web", 3))
    try:
        scale_cluster("production-web", 20)
    except AuthorizationDenied:
        print("Blocked before the function ran")
```

```text
Scaled staging-web to 3 replicas
Blocked before the function ran
```

`dev_mode=True` is for local development only: it relaxes trust-root and audit-log requirements so the snippet is copy-paste-runnable. For production, follow the [Production Guide](./docs/production-guide.md).

Even if the agent is prompt-injected, it cannot scale a production cluster or exceed ten replicas through this tool. The check happens before the function runs.

When the `mint_sync` block exits, that task no longer has a warrant in scope. The warrant's own TTL is separate. Short TTLs are still the production default. A task that ended needs no revocation flow.

### 2. Enforce Across a Real Boundary

Run the same check on the MCP server. The server trusts the issuer's public key; the agent only presents a warrant and a proof of possession. Verification is local.

```python
# pip install "tenuo[fastmcp]"
from fastmcp import FastMCP
from tenuo import Authorizer
from tenuo.mcp import MCPVerifier, TenuoMiddleware

authorizer = Authorizer(trusted_roots=[issuer_public_key])  # trust the issuer's key
verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
mcp = FastMCP("infrastructure", middleware=[TenuoMiddleware(verifier)])

@mcp.tool()
async def scale_cluster(cluster: str, replicas: int) -> str:
    return f"Scaled {cluster} to {replicas}"
```

The caller attaches the warrant with `SecureMCPClient(..., inject_warrant=True)`. See the [MCP walkthrough](./docs/mcp.md) for runnable server and client files.

### 3. Delegate Without Expanding Authority

An orchestrator can give a worker less authority, never more.

```python
from tenuo import Pattern, Range, SigningKey, Warrant
from tenuo.exceptions import MonotonicityError

platform = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()

root = (Warrant.mint_builder()
    .capability(
        "scale_cluster",
        cluster=Pattern("staging-*"),
        replicas=Range.max_value(10),
    )
    .holder(orchestrator.public_key)
    .ttl(300)
    .mint(platform))

# Narrower child: staging only, cap 5, shorter TTL.
worker_warrant = (root.grant_builder()
    .capability(
        "scale_cluster",
        cluster=Pattern("staging-*"),
        replicas=Range.max_value(5),
    )
    .holder(worker.public_key)
    .ttl(60)
    .grant(orchestrator))

try:
    (root.grant_builder()
        .capability(
            "scale_cluster",
            cluster=Pattern("staging-*"),
            replicas=Range.max_value(50),
        )
        .holder(worker.public_key)
        .ttl(60)
        .grant(orchestrator))
except MonotonicityError:
    print("Rejected: child cannot raise the replica cap")
```

Adding tools or widening constraints fails the same way. A child TTL longer than the parent's remaining lifetime is clamped to the parent's expiry. The chain can travel over MCP, A2A, HTTP, or a workflow engine and is verified at the final tool boundary.

Runnable end-to-end: [MCP delegation demo](./tenuo-python/examples/mcp/mcp_delegation_demo.py).

---

## How It Works

Tenuo is capability-based authorization. A warrant is a capability: a signed grant that lists the tools an agent may call, the argument values it may pass, the key that may use it, and when it expires. The warrant travels with the request. Whoever verifies the request only needs the issuer's public key.

Four things follow from that design.

**Holder-bound.** Every warrant names a public key. Every call carries a signature from that key over the warrant, the tool, the exact arguments, and a short time window. A copied warrant is useless without the key.

**Verified offline.** The warrant carries its own authority and signature. Checking it needs no lookup and no network. Checks run in under 50 μs, and enforcement keeps working when the control plane is down.

**Attenuates monotonically.** Delegation mints a child warrant signed by the parent's holder. The verifier walks the whole chain from a trusted root to the leaf. Each link may drop tools, tighten constraints, or shorten expiry. Nothing in the protocol can add authority. Tenuo calls this **Subtractive Delegation**.

**Holds under prompt injection.** The model never sees the warrant. The check runs at the tool boundary, on the real arguments, after the model has chosen what to call. A hijacked agent can only make the calls its warrant already allowed.

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Control Plane   │     │  Orchestrator    │     │  Worker          │
│                  │     │                  │     │                  │
│  Issues root     │────▶│  Attenuates      │────▶│  Executes with   │
│  warrant         │     │  for task        │     │  proof           │
└──────────────────┘     └──────────────────┘     └──────────────────┘
     Full scope     -->     Narrower      -->      Narrowest
```

1. **Control plane** issues a root warrant with broad capabilities
2. **Orchestrator** attenuates it for a specific task; scope can only shrink
3. **Worker** proves possession of the bound key and executes
4. **Warrant expires**; no cleanup needed

Tenuo builds on Macaroons and UCAN and implements the capability primitive from [CaMeL](https://arxiv.org/abs/2503.18813). See [Concepts](https://tenuo.ai/concepts) for the model and [Related Work](./docs/related-work.md) for comparisons with Biscuit, Macaroons, and UCAN.

---

## Why Tenuo?

IAM answers "who are you?" Tenuo adds "what can this workload do right now for this task?" That gives teams a deterministic authorization boundary at agent speed, without reducing useful agents to a static menu of pre-baked behaviors.

| Failure mode in agent systems | Tenuo strength | Practical outcome |
|------------------------------|----------------|-------------------|
| Session roles outlive individual tasks | Task-scoped warrants with TTL | Authority is scoped to the task and expires with it |
| Delegation chains increase blast radius | Monotonic attenuation at every hop | Scope only narrows, never expands |
| Bearer credentials can be replayed | Holder-bound proofs (PoP) | Stolen warrants are unusable without the key |
| Runtime policy calls add latency and dependency risk | Offline verification (under 50 μs) | Enforcement holds under load without network round-trips |
| Teams need defensible audit evidence | Signed authorization receipts (opt-in) | Each decision is attributable and reviewable |

Constraints parse inputs the way the target system will. There are [11 types](https://tenuo.ai/constraints), including `Subpath`, `UrlSafe`, `Shlex`, and `CEL` ([why this matters](https://niyikiza.com/posts/cve-2025-66032/)).

---

## What Tenuo Is Not

- **Not a sandbox**: Tenuo authorizes actions, it doesn't isolate execution. Pair with containers/sandboxes/VMs for defense in depth.
- **Not prompt engineering**: Tenuo does not rely on model instructions for security decisions.
- **Not an LLM filter**: Tenuo checks tool calls when they execute. It never reads model text.
- **Not a replacement for IAM**: Tenuo *complements* IAM by adding task-scoped, attenuating capabilities on top of identity.

---

## Integrate at the Boundary You Control

Tenuo uses the same warrant format and attenuation rules everywhere. Choose the enforcement point that fits your architecture; authority can cross these boundaries without being translated into a new policy model.

| Enforcement point | Use it when | Integrations | Start here |
|-------------------|-------------|--------------|------------|
| **Inside the agent runtime** | You own the application and want the shortest path to enforcement | Python functions, OpenAI, LangChain, LangGraph, Google ADK, CrewAI, AutoGen | [`@guard`](./docs/quickstart.md), [OpenAI](./docs/openai.md), [framework guides](#documentation) |
| **At the MCP tool server** | Agents call tools across a process or vendor boundary | FastMCP, official MCP SDK, custom MCP servers | [MCP guide](./docs/mcp.md) |
| **At an API or service edge** | Multiple agent runtimes share the same downstream services | FastAPI, authorizer sidecar, gateway, Kubernetes | [FastAPI](./docs/fastapi.md), [Kubernetes](./docs/kubernetes.md) |
| **Inside a durable workflow** | Authority must survive retries, queues, and long-running execution | Temporal | [Temporal guide](./docs/temporal-reference.md) |
| **At an agent handoff** | One agent delegates part of a task to another agent | A2A, MCP warrant stacks | [A2A guide](./docs/a2a.md), [delegation demo](./tenuo-python/examples/mcp/mcp_delegation_demo.py) |

These are all deployment choices for one authorization system. A warrant issued in one identity domain remains verifiable when execution moves into another, and every delegated warrant must stay within its parent authority.

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[Quickstart](https://tenuo.ai/quickstart)** | Get running in 5 minutes |
| **[Concepts](https://tenuo.ai/concepts)** | How warrants and attenuation work |
| **[Constraints](https://tenuo.ai/constraints)** | All 11 constraint types explained |
| **[Security](https://tenuo.ai/security)** | Threat model and guarantees |
| **[OpenAI](https://tenuo.ai/openai)** | Direct API protection with streaming |
| **[Google ADK](https://tenuo.ai/google-adk)** | ADK agent tool protection |
| **[AutoGen](https://tenuo.ai/autogen)** | AgentChat tool protection |
| **[A2A](https://tenuo.ai/a2a)** | Inter-agent delegation |
| **[FastAPI](https://tenuo.ai/fastapi)** | Zero-boilerplate API protection |
| **[LangChain](https://tenuo.ai/langchain)** | Tool protection |
| **[LangGraph](https://tenuo.ai/langgraph)** | Multi-agent graph security |
| **[CrewAI](https://tenuo.ai/crewai)** | Multi-agent crew protection |
| **[Temporal](https://tenuo.ai/temporal)** | Durable workflow authorization |
| **[MCP](https://tenuo.ai/mcp)** | Model Context Protocol client + server verification |

---

## Requirements

| Component | Supported |
|-----------|-----------|
| **Python** | 3.9 - 3.14 |
| **Node.js** | **Beta** — Node 20+ (`npm i @tenuo/core@beta`) |
| **OS** | Linux, macOS, Windows |
| **Rust** | Not required (binary wheels for macOS, Linux, Windows) |

### Optional Dependencies

```bash
uv pip install tenuo                  # Core only
uv pip install "tenuo[openai]"        # + OpenAI Agents SDK
uv pip install "tenuo[google_adk]"    # + Google ADK
uv pip install "tenuo[a2a]"           # + A2A (inter-agent delegation)
uv pip install "tenuo[fastapi]"       # + FastAPI integration
uv pip install "tenuo[langchain]"     # + LangChain (langchain-core ≥0.2)
uv pip install "tenuo[langgraph]"     # + LangGraph (includes LangChain)
uv pip install "tenuo[crewai]"        # + CrewAI
uv pip install "tenuo[temporal]"      # + Temporal workflows
uv pip install "tenuo[autogen]"       # + AutoGen AgentChat (Python ≥3.10)
uv pip install "tenuo[mcp]"           # + official MCP SDK, client & server verification (Python ≥3.10)
uv pip install "tenuo[fastmcp]"       # + FastMCP (TenuoMiddleware / FastMCP servers)
uv pip install "tenuo[cloud]"         # + Tenuo Cloud SDK (proprietary control-plane client)
```

---

## Docker & Kubernetes

**Try the Demo**: See the full delegation chain in action:

```bash
docker compose up
```

This runs the [orchestrator -> worker -> authorizer demo](https://tenuo.ai/demo.html) showing warrant issuance, delegation, and verification.

**Official Images** on [Docker Hub](https://hub.docker.com/u/tenuo):

```bash
docker pull tenuo/authorizer:0.2.4  # Sidecar for warrant verification
docker pull tenuo/control:0.2.4     # Control plane (demo/reference)
```

**Helm Chart**:

```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --set config.trustedRoots[0]="YOUR_CONTROL_PLANE_PUBLIC_KEY"
```

See [Helm chart README](./charts/tenuo-authorizer) and [Kubernetes guide](https://tenuo.ai/kubernetes).

---

## Deploying to Production

Self-hosted Tenuo is free forever. The core library and sidecar run entirely in your infrastructure, with no external calls at verification time.

**Self-hosted checklist:**

- Store signing keys in a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager). Keep them out of environment variables
- Configure `trusted_roots` with your control plane's public keys
- Ensure `dry_run` is disabled and warrants are required in all enforcement points
- Enable audit callbacks and metrics for observability

See [Security Model](https://tenuo.ai/security) for the full threat model and production hardening guidance.

Self-hosted Tenuo already verifies warrants and signed revocation lists (SRLs) locally. **[Tenuo Cloud](https://tenuo.ai/early-access.html)** adds managed issuance, key rotation, hosted SRL distribution, observability dashboards, and multi-tenant isolation.

---

## Rust

Building an authorizer sidecar, gateway, or high-throughput service in
Rust? Use the core crate directly.

What you get in Rust:

- Warrant minting, derivation, and verification
- Monotonic attenuation enforcement across delegation hops
- Typed constraint evaluation at execution time
- Holder Proof of Possession (PoP) verification
- Signed receipt generation for allow/deny decisions (opt-in `receipts` feature)

```toml
[dependencies]
tenuo = "0.2.4"
```

Use the Rust API when you need a language-native enforcement boundary
without Python runtime dependencies.

- API docs: [docs.rs/tenuo](https://docs.rs/tenuo)
- Security model: [tenuo.ai/security](https://tenuo.ai/security)
- Constraints reference: [tenuo.ai/constraints](https://tenuo.ai/constraints)

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

The token format and delegation protocol are being standardized as [draft-niyikiza-oauth-attenuating-agent-tokens-01](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/01/) in the IETF OAuth Working Group. The core attenuation rules are formally verified with [Alloy](docs/formal_verification/aat_constraints.als) (capability and argument-key monotonicity) and [Z3](docs/formal_verification/z3_bounds.py) (constraint-type subsumption bounds).

See [Related Work](https://tenuo.ai/related-work) for detailed comparison.

---

## Featured In

- [TLDR InfoSec](https://tldr.tech/infosec/2026-01-13) - "The Map is not the Territory: The Agent-Tool Trust Boundary"
- [TLDR InfoSec](https://tldr.tech/infosec/2025-12-15) - "Capabilities Are the Only Way to Secure Agent Delegation"
- [Awesome Object Capabilities](https://github.com/dckc/awesome-ocap) - Curated list of capability-based security resources
- [Awesome LangChain](https://github.com/kyrolabs/awesome-langchain)
- [Awesome LLM Agent Security](https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security)
- [Awesome LLMSecOps](https://github.com/wearetyomsmnv/Awesome-LLMSecOps)

---

## Etymology

**Tenuo** (/tɛn-ju-oʊ/ • *Ten-YOO-oh*)

From Latin *tenuare*: "to make thin; to attenuate."
Authority starts broad at the root and is **attenuated** as it flows down the delegation chain.

---

## Contributing

Tenuo is Apache-2.0 and built in the open. The core is Rust, with Python and TypeScript SDKs on top. Good places to start:

- **Framework integrations.** Adapters live in `tenuo-python/tenuo/`. The [integration guide](tenuo-python/docs/integration-guide.md) covers the required API patterns and invariant tests. [OpenAI](tenuo-python/tenuo/openai.py) and [Google ADK](tenuo-python/tenuo/google_adk/guard.py) are good templates.
- **Constraint types.** There are 11 today. A new one has to parse input the same way the target system does.
- **The TypeScript SDK.** It is in beta and needs real-world use.
- **Docs and examples.** If a guide confused you, that is a bug worth filing.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, and the PR process.

**Security issues**: Email security@tenuo.ai with PGP ([key](./SECURITY_PUBKEY.asc)). Please do not open public issues for these.

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
