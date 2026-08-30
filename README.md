<p align="center">
  <img src="docs/images/tenuo-logo.svg" alt="tenuo" width="200">
</p>

<p align="center">
  <strong>Capability tokens for AI agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml"><img src="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/tenuo"><img src="https://img.shields.io/crates/v/tenuo.svg" alt="Crates.io"></a>
  <a href="https://pypi.org/project/tenuo/"><img src="https://img.shields.io/pypi/v/tenuo.svg" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/tenuo/authorizer"><img src="https://img.shields.io/docker/v/tenuo/authorizer?label=docker" alt="Docker"></a>
  <a href="https://tenuo.ai"><img src="https://img.shields.io/badge/docs-tenuo.ai-blue" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
</p>

Tenuo is cryptographic authorization infrastructure for AI agents. A useful mental model is a prepaid card instead of a corporate Amex: scoped capability tokens that expire with the task.

Agents stay flexible without turning security into prompt engineering: they can still read across systems, call tools, and delegate work, while sensitive actions remain bounded by deterministic checks at runtime.

The token is called a **warrant**: a signed grant of which tools an agent can call, under what constraints, and for how long.

- **Holder-bound**: a warrant is tied to a cryptographic key, and the caller must prove possession of it (PoP). A stolen warrant is useless without the key.
- **Verified offline**: checks run in under 50 μs, with no network calls.
- **Attenuates monotonically**: delegated authority can narrow but never expand.
- **Holds under prompt injection**: even a hijacked agent is still limited by its warrant's constraints.

Tenuo is designed for teams running tool-calling and multi-agent workflows where authorization must hold at runtime, not just at session start. For sensitive actions, warrants can also require signed human approvals before execution. See the [approvals guide](./docs/approvals.md).

It can be deployed in-process or at boundary enforcement points (sidecar/gateway), with the same warrant semantics and enforcement behavior.

> **Status: v0.2 - Production/Stable.** Core semantics are stable. See [CHANGELOG](./CHANGELOG.md).
>
> **Tenuo Cloud: Early Access.** Managed control plane with revocation, observability, and multi-tenant warrant issuance. [Request access →](https://tenuo.ai/early-access.html)

## Install

```bash
# Using uv (recommended)
uv pip install tenuo

# Or standard pip
pip install tenuo
```

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

When the `mint_sync` block exits, the warrant expires naturally. No manual cleanup or revocation flow is required.

### 2. Enforce Across a Real Boundary

Move the same check into an MCP server. The agent sends its warrant and proof with the tool call; the server verifies both locally before invoking the handler.

```python
# server.py
from fastmcp import FastMCP
from tenuo import Authorizer
from tenuo.mcp import MCPVerifier, TenuoMiddleware

authorizer = Authorizer(trusted_roots=[control_plane_public_key])
verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
mcp = FastMCP("infrastructure", middleware=[TenuoMiddleware(verifier)])

@mcp.tool()
async def scale_cluster(cluster: str, replicas: int) -> str:
    # Runs only after the warrant, proof, tool, and arguments are verified.
    return await infrastructure.scale(cluster, replicas)
```

```python
# agent.py
import asyncio

from tenuo import Capability, Pattern, Range, mint
from tenuo.mcp import SecureMCPClient

async def run() -> None:
    # Application startup configures a local issuer or Tenuo Cloud client.
    async with SecureMCPClient(
        url="https://tools.example.com/mcp",
        transport="http",
        inject_warrant=True,
    ) as tools:
        async with mint(Capability(
            "scale_cluster",
            cluster=Pattern("staging-*"),
            replicas=Range.max_value(10),
        )):
            await tools.tools["scale_cluster"](
                cluster="staging-web",
                replicas=3,
            )

asyncio.run(run())
```

The MCP server trusts the warrant issuer, not the agent process. Verification is offline and does not depend on a policy service being available. See the [complete MCP walkthrough](./docs/mcp.md) for runnable server and client files.

### 3. Delegate Without Expanding Authority

When an orchestrator delegates work, it can give the worker less authority, never more.

```python
from tenuo import Pattern, Range, SigningKey, Warrant

platform = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()

# The platform allows the orchestrator to scale staging up to 10 replicas.
root = (Warrant.mint_builder()
    .capability(
        "scale_cluster",
        cluster=Pattern("staging-*"),
        replicas=Range.max_value(10),
    )
    .holder(orchestrator.public_key)
    .ttl(300)
    .mint(platform))

# The orchestrator delegates a smaller task to a worker.
worker_warrant = (root.grant_builder()
    .capability(
        "scale_cluster",
        cluster=Pattern("staging-*"),
        replicas=Range.max_value(5),
    )
    .holder(worker.public_key)
    .ttl(60)
    .grant(orchestrator))
```

Tenuo rejects any attempted child warrant that adds tools, widens constraints, or outlives its parent. The full chain can travel over MCP, A2A, HTTP, or a workflow engine and be verified at the final tool boundary.

Try the [end-to-end MCP delegation demo](./tenuo-python/examples/mcp/mcp_delegation_demo.py) to see an issuer, orchestrator, worker, and MCP verifier exercise the complete chain.

---

## Why Tenuo?

IAM answers "who are you?" Tenuo adds "what can this workload do right now for this task?" That gives teams a deterministic authorization boundary at agent speed, without reducing useful agents to a static menu of pre-baked behaviors.

| Failure mode in agent systems | Tenuo strength | Practical outcome |
|------------------------------|----------------|-------------------|
| Session roles outlive individual tasks | Task-scoped warrants with TTL | Authority disappears when the task ends |
| Delegation chains increase blast radius | Monotonic attenuation at every hop | Scope only narrows, never expands |
| Bearer credentials can be replayed | Holder-bound proofs (PoP) | Stolen warrants are unusable without the key |
| Runtime policy calls add latency and dependency risk | Offline verification (under 50 μs) | Enforcement holds under load without network round-trips |
| Teams need defensible audit evidence | Signed authorization receipts | Each decision is attributable and reviewable |

---

## What Tenuo Is Not

- **Not a sandbox**: Tenuo authorizes actions, it doesn't isolate execution. Pair with containers/sandboxes/VMs for defense in depth.
- **Not prompt engineering**: Tenuo does not rely on model instructions for security decisions.
- **Not an LLM filter**: Tenuo gates tool calls at execution time rather than filtering model text.
- **Not a replacement for IAM**: Tenuo *complements* IAM by adding task-scoped, attenuating capabilities on top of identity.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Offline verification** | No network calls, under 50 μs |
| **Holder binding** | Stolen tokens are useless without the key |
| **Semantic constraints** | [11 constraint types](https://tenuo.ai/constraints) including `Subpath`, `UrlSafe`, `Shlex`, `CEL`. They parse inputs the way the target system will ([why this matters](https://niyikiza.com/posts/cve-2025-66032/)) |
| **Monotonic attenuation** | Capabilities only shrink, never expand |
| **Framework integrations** | OpenAI, Google ADK, CrewAI, Temporal, LangChain, LangGraph, FastAPI, MCP, A2A, AutoGen |

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

These are deployment choices, not separate authorization systems. A warrant issued in one identity domain remains verifiable when execution moves into another, and every delegated warrant must stay within its parent authority.

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[Quickstart](https://tenuo.ai/quickstart)** | Get running in 5 minutes |
| **[Concepts](https://tenuo.ai/concepts)** | Why capability tokens? |
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
| **Node.js** | *Planned (TypeScript SDK - [help wanted](#contributing))* |
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
docker pull tenuo/authorizer:0.2.3  # Sidecar for warrant verification
docker pull tenuo/control:0.2.3     # Control plane (demo/reference)
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

- Store signing keys in a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager), not environment variables
- Configure `trusted_roots` with your control plane's public keys
- Ensure `dry_run` is disabled and warrants are required in all enforcement points
- Enable audit callbacks and metrics for observability

See [Security Model](https://tenuo.ai/security) for the full threat model and production hardening guidance.

**[Tenuo Cloud](https://tenuo.ai/early-access.html)** adds managed warrant issuance, key rotation, revocation via signed revocation lists (SRL), observability dashboards, and multi-tenant isolation for teams that prefer a hosted control plane.

---

## Rust

Building an authorizer sidecar, gateway, or high-throughput service in
Rust? Use the core crate directly.

What you get in Rust:

- Warrant minting, derivation, and verification
- Monotonic attenuation enforcement across delegation hops
- Typed constraint evaluation at execution time
- Holder Proof of Possession (PoP) verification
- Signed receipt generation for allow/deny decisions

```toml
[dependencies]
tenuo = "0.2.3"
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

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

### TypeScript SDK (Help Wanted)

We're planning a TypeScript/Node SDK. If you're interested in leading or contributing to this effort, open an issue or email us at [dev@tenuo.ai](mailto:dev@tenuo.ai).

**Security issues**: Email security@tenuo.ai with PGP ([key](./SECURITY_PUBKEY.asc), not public issues).

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
