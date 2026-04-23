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
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License"></a>
</p>

> **Tenuo Cloud: Early Access**
>
> Managed control plane with revocation, observability, and multi-tenant warrant issuance.
>
> [Request access →](https://tenuo.ai/early-access.html)

Tenuo is cryptographic authorization infrastructure for AI agents. A useful mental model is a prepaid card instead of a corporate Amex: scoped capability tokens that expire with the task.

A **warrant** is a signed token specifying which tools an agent can call, under what constraints, and for how long. It is bound to a cryptographic key, and the caller must prove possession of that key (PoP). Verification is offline (under 50 μs), and delegation attenuates monotonically: authority can narrow but not expand. If an agent is prompt-injected, execution is still limited by warrant constraints.

Tenuo is designed for teams running tool-calling and multi-agent workflows where authorization must hold at runtime, not just at session start.

It can be deployed in-process or at boundary enforcement points (sidecar/gateway), with the same warrant semantics and enforcement behavior.

> **Status: v0.1 Beta** - Core semantics are stable. APIs may evolve. See [CHANGELOG](./CHANGELOG.md).

```bash
# Using uv (recommended)
uv pip install tenuo

# Or standard pip
pip install tenuo
```

<a href="https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open In Colab"></a>
<a href="https://tenuo.ai/explorer/"><img src="https://img.shields.io/badge/Explorer-decode_warrants-00d4ff" alt="Explorer"></a>
<a href="https://tenuo.ai/demo.html"><img src="https://img.shields.io/badge/Docker_Demo-delegation_chain-a855f7" alt="Docker Demo"></a>
<a href="https://niyikiza.com/posts/tenuo-launch/"><img src="https://img.shields.io/badge/Blog-Why_Tenuo%3F-ff6b6b" alt="Blog"></a>

## Quick Start

```python
from tenuo import configure, SigningKey, mint_sync, guard, Capability, Pattern
from tenuo.exceptions import AuthorizationDenied

# 1. One-time setup: generate a key and configure Tenuo
configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

# 2. Protect a function. Calls are blocked unless a warrant allows them.
@guard(tool="send_email")
def send_email(to: str) -> str:
    return f"Sent to {to}"

# 3. Mint a warrant that only allows sending to @company.com
with mint_sync(Capability("send_email", to=Pattern("*@company.com"))):
    print(send_email(to="alice@company.com"))  # -> "Sent to alice@company.com"
    
    try:
        send_email(to="attacker@evil.com")
    except AuthorizationDenied:
        print("Blocked: attacker@evil.com")  # -> "Blocked: attacker@evil.com"
```

`dev_mode=True` is for local development only: it relaxes trust-root and audit-log requirements so the snippet is copy-paste-runnable. For production, follow the [Production Guide](./docs/production-guide.md).

Even if the agent is prompt-injected, enforcement still happens at the tool boundary. The warrant allows `*@company.com`; `attacker@evil.com` is denied.

When the `mint_sync` block exits, the warrant expires naturally. No manual cleanup or revocation flow is required.

30-second architecture:

1. **Issuer** mints a root warrant for a task.
2. **Delegator** attenuates scope for downstream agents/tools.
3. **Authorizer** verifies warrant + PoP at the tool-call boundary.
4. **Signed receipt** records the authorization decision and execution context.

---

## Why Tenuo?

IAM answers "who are you?" Tenuo adds "what can this workload do right now for this task?" That gives teams a deterministic authorization boundary at agent speed.

| Failure mode in agent systems | Tenuo strength | Practical outcome |
|------------------------------|----------------|-------------------|
| Session roles outlive individual tasks | Task-scoped warrants with TTL | Authority disappears when the task ends |
| Delegation chains increase blast radius | Monotonic attenuation at every hop | Scope only narrows, never expands |
| Bearer credentials can be replayed | Holder-bound proofs (PoP) | Stolen warrants are unusable without the key |
| Runtime policy calls add latency and dependency risk | Offline verification (under 50 μs) | Enforcement holds under load without network round-trips |
| Teams need defensible audit evidence | Signed authorization receipts | Each decision is attributable and reviewable |

---

## How It Works

Tenuo implements **Subtractive Delegation**: each step in the chain can only reduce authority, never expand it.

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
2. **Orchestrator** attenuates it for a specific task (scope can only shrink)
3. **Worker** proves possession of the bound key and executes
4. **Warrant expires**: no cleanup needed

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

## Integrations

**OpenAI**: Tool-call enforcement with streaming TOCTOU protection
```python
from tenuo.openai import GuardBuilder, Subpath, UrlSafe, Range, Pattern

client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))        # Path traversal protection
    .allow("fetch_url", url=UrlSafe())                # SSRF protection
    .allow("transfer", amount=Range(max=1000))        # Value boundary enforcement
    .allow("send_email", to=Pattern("*@company.com"))
    .build())
# Out-of-scope recipient is denied at execution time
```

**LangChain / LangGraph**
```python
from tenuo.langchain import guard_tools
from tenuo.langgraph import TenuoToolNode

protected = guard_tools([search_tool, email_tool])      # LangChain
graph.add_node("tools", TenuoToolNode([search, email])) # LangGraph
```

**MCP**: Model Context Protocol client and server-side verification
```python
from tenuo.mcp import SecureMCPClient, MCPVerifier

# Client: injects warrant proofs into tool arguments
async with SecureMCPClient("python", ["server.py"]) as client:
    async with mint(Capability("read_file", path=Subpath("/data"))):
        result = await client.tools["read_file"](path="/data/file.txt")

# Server: verifies tool constraints offline before execution
verifier = MCPVerifier(...)
@mcp.tool()
async def read_file(path: str, **kwargs) -> str:
    clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
    return open(clean["path"]).read()
```

<details>
<summary><strong>More integrations: Google ADK, CrewAI, A2A, Temporal, FastAPI</strong></summary>

**Google ADK**
```python
from tenuo.google_adk import GuardBuilder
from tenuo.constraints import Subpath, UrlSafe

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("web_search", url=UrlSafe(allow_domains=["*.google.com"]))
    .build())

agent = Agent(name="assistant", before_tool_callback=guard.before_tool)
```

**CrewAI**: Multi-agent crews with warrant-based authorization
```python
from tenuo.crewai import GuardBuilder

guard = (GuardBuilder()
    .allow("search", query=Pattern("*"))
    .allow("write_file", path=Subpath("/workspace"))
    .build())

crew = guard.protect(my_crew)  # Enforces constraints across crew tools
```

**A2A (Agent-to-Agent)**: Warrant-based inter-agent delegation
```python
from tenuo.a2a import A2AServerBuilder

server = A2AServerBuilder().name("Search Agent").url("https://...").key(my_key).trust(orchestrator_key).build()
@server.skill("search", constraints={"url": UrlSafe})
async def search(query: str, url: str) -> dict:
    return await do_search(query, url)

client = A2AClient("https://...")
warrant = await client.request_warrant(signing_key=worker_key, capabilities={"search": {}})
result = await client.send_task(skill="search", warrant=warrant, signing_key=worker_key)
```

**Temporal**: Durable workflows with warrant-based activity authorization
```python
from tenuo.temporal import (
    TenuoTemporalPlugin, TenuoPluginConfig, EnvKeyResolver,
    AuthorizedWorkflow, execute_workflow_authorized,
)

plugin = TenuoTemporalPlugin(
    TenuoPluginConfig(key_resolver=EnvKeyResolver(), trusted_roots=[issuer_public_key])
)
client = await Client.connect("localhost:7233", plugins=[plugin])

@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        return await self.execute_authorized_activity(
            read_file, args=[path], start_to_close_timeout=timedelta(seconds=30),
        )

result = await execute_workflow_authorized(
    client=client,
    workflow_run_fn=MyWorkflow.run,
    workflow_id="wf-123",
    warrant=warrant,
    key_id="agent1",
    args=["/data/report.txt"],
    task_queue="my-queue",
)
```

See full Temporal examples: [`demo.py`](tenuo-python/examples/temporal/demo.py) | [`multi_warrant.py`](tenuo-python/examples/temporal/multi_warrant.py) | [`delegation.py`](tenuo-python/examples/temporal/delegation.py)

**FastAPI**: Extracts warrant from headers, verifies PoP offline
```python
@app.get("/search")
async def search(query: str, ctx: SecurityContext = Depends(TenuoGuard("search"))):
    return {"results": do_search(query)}
```

**Kubernetes**: See [Kubernetes guide](https://tenuo.ai/kubernetes)

</details>

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
| **Python** | 3.9 – 3.14 |
| **Node.js** | *Coming v0.2* |
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
docker pull tenuo/authorizer:0.1.0-beta.22  # Sidecar for warrant verification
docker pull tenuo/control:0.1.0-beta.22     # Control plane (demo/reference)
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

**[Tenuo Cloud](https://tenuo.ai/early-access.html)** adds managed warrant issuance, key rotation, revocation (SRL), observability dashboards, and multi-tenant isolation for teams that prefer a hosted control plane.

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
tenuo = "0.1.0-beta.22"
```

Use the Rust API when you need a language-native enforcement boundary
without Python runtime dependencies.

- API docs: [docs.rs/tenuo](https://docs.rs/tenuo)
- Security model: [tenuo.ai/security](https://tenuo.ai/security)
- Constraints reference: [tenuo.ai/constraints](https://tenuo.ai/constraints)

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

The token format and delegation protocol are being standardized as [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/) in the IETF OAuth Working Group. The core attenuation rules are formally verified with [Alloy](docs/formal_verification/aat_constraints.als) (capability and argument-key monotonicity) and [Z3](docs/formal_verification/z3_bounds.py) (constraint-type subsumption bounds).

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

We're planning a TypeScript/Node SDK for v0.2. If you're interested in leading or contributing to this effort, open an issue or email us at [dev@tenuo.ai](mailto:dev@tenuo.ai).

**Security issues**: Email security@tenuo.ai with PGP ([key](./SECURITY_PUBKEY.asc), not public issues).

---

## License

MIT OR Apache-2.0, at your option.
