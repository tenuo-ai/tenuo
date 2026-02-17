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

Tenuo is a cryptographic authorization primitive for AI agents. **Think prepaid debit card, as opposed to corporate Amex**: ephemeral, scoped capability tokens that expire when the task ends.

It constrains ambient identity-based permissions with task-scoped capabilities that attenuate as they delegate. Offline verification in ~27μs.
If an agent is prompt-injected, the authority still can't escape its bounds.

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

configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

@guard(tool="send_email")
def send_email(to: str) -> str:
    return f"Sent to {to}"

with mint_sync(Capability("send_email", to=Pattern("*@company.com"))):
    print(send_email(to="alice@company.com"))  # -> "Sent to alice@company.com"
    
    try:
        send_email(to="attacker@evil.com")
    except AuthorizationDenied:
        print("Blocked: attacker@evil.com")  # -> "Blocked: attacker@evil.com"
```

The agent can be prompt-injected. The authorization layer doesn't care. The warrant says `*@company.com`. The request says `attacker@evil.com`. **Denied.**

---

## Why Tenuo?

IAM answers "who are you?" Tenuo answers "what can you do right now?"

| Problem | Tenuo's Answer |
|---------|----------------|
| Static IAM roles outlive tasks | Warrants expire with the task (TTL) |
| Broad permissions, big blast radius | Constraints narrow on every delegation |
| Tokens can be stolen and replayed | Proof-of-possession binds warrants to keys |
| Central policy servers add latency | Offline verification in ~27μs |

---

## What Tenuo Is Not

- **Not a sandbox** - Tenuo authorizes actions, it doesn't isolate execution. Pair with containers/sandboxes/VMs for defense in depth.
- **Not prompt engineering** - No "please don't do bad things" instructions. Cryptographic enforcement, not behavioral.
- **Not an LLM filter** - We don't parse model outputs. We gate tool calls at execution time.
- **Not a replacement for IAM** - Tenuo *complements* IAM by adding task-scoped, attenuating capabilities on top of identity.

---

## How It Works

Tenuo implements **Subtractive Delegation**.

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Control Plane   │     │  Orchestrator    │     │  Worker          │
│                  │     │                  │     │                  │
│  Issues root     │────▶│  Attenuates      │────▶│  Executes with   │
│  warrant         │     │  for task        │     │  proof           │
└──────────────────┘     └──────────────────┘     └──────────────────┘
     Full scope     -->     Narrower      -->      Narrowest
```

1. **Control plane** issues a root warrant
2. **Orchestrator** attenuates it (scope can only shrink)
3. **Worker** proves possession and executes
4. **Warrant expires** - no revocation needed

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Offline verification** | No network calls, ~27μs |
| **Holder binding** | Stolen tokens are useless without the key |
| **Constraint types** | `Exact`, `Pattern`, `Range`, `OneOf`, `Regex`, `Cidr`, `UrlPattern`, `Subpath`, `UrlSafe`, `Shlex`, `CEL` |
| **Monotonic attenuation** | Capabilities only shrink, never expand |
| **Framework integrations** | OpenAI, CrewAI, Temporal, LangChain, LangGraph, FastAPI, MCP |

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
uv pip install "tenuo[mcp]"           # + MCP client (Python ≥3.10 required)
```

---

## Integrations

> **Why semantic constraints?** [CVE-2025-66032](https://niyikiza.com/posts/cve-2025-66032/) showed allowlists fail when shells interpret strings differently than validators. Tenuo's `Shlex`, `Subpath`, and `UrlSafe` parse inputs the way the system will. [Full analysis](https://niyikiza.com/posts/map-territory/).

**OpenAI** - Direct API protection with streaming TOCTOU defense
```python
from tenuo.openai import GuardBuilder, Subpath, UrlSafe, Shlex, Pattern

client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data"))        # Path traversal protection
    .allow("fetch_url", url=UrlSafe())                # SSRF protection
    .allow("run_command", cmd=Shlex(allow=["ls"]))    # Shell injection protection
    .allow("send_email", to=Pattern("*@company.com"))
    .build())
# Prompt injection -> send_email(to="attacker@evil.com") -> DENIED
```

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

**A2A (Agent-to-Agent)** - Warrant-based inter-agent delegation
```python
from tenuo.a2a import A2AServer

@server.skill("search", constraints={"url": UrlSafe})
async def search(query: str, url: str) -> dict:
    return await do_search(query, url)
```

**LangChain / LangGraph**
```python
from tenuo.langchain import guard_tools
from tenuo.langgraph import TenuoToolNode

protected = guard_tools([search_tool, email_tool])      # LangChain
graph.add_node("tools", TenuoToolNode([search, email])) # LangGraph
```

**CrewAI** - Multi-agent crews with capability-based authorization
```python
from tenuo.crewai import GuardBuilder

guard = (GuardBuilder()
    .allow("search", query=Pattern("*"))
    .allow("write_file", path=Subpath("/workspace"))
    .build())

crew = guard.protect(my_crew)  # All agents get enforced constraints
```

**Temporal** - Durable workflows with warrant-based activity authorization + Proof-of-Possession
```python
from tenuo.temporal import (
    AuthorizedWorkflow, TenuoInterceptor, TenuoInterceptorConfig,
    TenuoClientInterceptor, EnvKeyResolver, tenuo_headers,
)
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

# Workflow: inherit AuthorizedWorkflow for automatic PoP
@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        return await self.execute_authorized_activity(
            read_file, args=[path], start_to_close_timeout=timedelta(seconds=30),
        )

# Client: inject warrant into workflow headers
client_interceptor = TenuoClientInterceptor()
client = await Client.connect("localhost:7233", interceptors=[client_interceptor])
client_interceptor.set_headers(tenuo_headers(warrant, "agent-1", signing_key))

# Worker: authorize activities with full PoP verification
worker = Worker(client, task_queue="queue",
    workflows=[MyWorkflow], activities=[read_file],
    interceptors=[TenuoInterceptor(TenuoInterceptorConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[control_key.public_key],
    ))],
    workflow_runner=SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core",  # Required for PoP
        )
    ),
)
```

**Examples:** [`authorized_workflow_demo.py`](tenuo-python/examples/temporal/authorized_workflow_demo.py) — AuthorizedWorkflow (recommended) | [`demo.py`](tenuo-python/examples/temporal/demo.py) — Lower-level API | [`multi_warrant.py`](tenuo-python/examples/temporal/multi_warrant.py) — Multi-tenant isolation | [`delegation.py`](tenuo-python/examples/temporal/delegation.py) — Pipeline delegation

**FastAPI** - Extracts warrant from headers, verifies PoP offline
```python
@app.get("/search")
async def search(query: str, ctx: SecurityContext = Depends(TenuoGuard("search"))):
    return {"results": do_search(query)}
```

**More:** [MCP](https://tenuo.ai/mcp) | [Kubernetes](https://tenuo.ai/kubernetes)

---

## Docker & Kubernetes

**Try the Demo** - See the full delegation chain in action:

```bash
docker compose up
```

This runs the [orchestrator -> worker -> authorizer demo](https://tenuo.ai/demo.html) showing warrant issuance, delegation, and verification.

**Official Images** on [Docker Hub](https://hub.docker.com/u/tenuo):

```bash
docker pull tenuo/authorizer:0.1.0-beta.9  # Sidecar for warrant verification
docker pull tenuo/control:0.1.0-beta.9     # Control plane (demo/reference)
```

**Helm Chart**:

```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --set config.trustedRoots[0]="YOUR_CONTROL_PLANE_PUBLIC_KEY"
```

See [Helm chart README](./charts/tenuo-authorizer) and [Kubernetes guide](https://tenuo.ai/kubernetes).

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[Quickstart](https://tenuo.ai/quickstart)** | Get running in 5 minutes |
| **[Concepts](https://tenuo.ai/concepts)** | Why capability tokens? |
| **[OpenAI](https://tenuo.ai/openai)** | Direct API protection with streaming |
| **[Google ADK](https://tenuo.ai/google-adk)** | ADK agent tool protection |
| **[AutoGen](https://tenuo.ai/autogen)** | AgentChat tool protection |
| **[A2A](https://tenuo.ai/a2a)** | Inter-agent delegation |
| **[FastAPI](https://tenuo.ai/fastapi)** | Zero-boilerplate API protection |
| **[LangChain](https://tenuo.ai/langchain)** | Tool protection |
| **[LangGraph](https://tenuo.ai/langgraph)** | Multi-agent graph security |
| **[CrewAI](https://tenuo.ai/crewai)** | Multi-agent crew protection |
| **[Temporal](https://tenuo.ai/temporal)** | Durable workflow authorization |
| **[MCP](https://tenuo.ai/mcp)** | Model Context Protocol client |
| **[Security](https://tenuo.ai/security)** | Threat model |

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

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

## Roadmap

| Feature | Status |
|---------|--------|
| A2A integration | Implemented (`uv pip install tenuo[a2a]`) |
| AutoGen integration | Implemented (`uv pip install tenuo[autogen]`) |
| Google ADK integration | Implemented (`uv pip install tenuo[google_adk]`) |
| Multi-sig approvals | Partial (notary in v0.2) |
| TypeScript/Node SDK | Planned for v0.2 |
| Context-aware constraints | Spec under development |
| Revocation service | Planned for v0.2 |

---

## Rust

Building a sidecar or gateway? Use the core directly:

```toml
[dependencies]
tenuo = "0.1.0-beta.9"
```

See [docs.rs/tenuo](https://docs.rs/tenuo) for Rust API.

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

## Deploying to Production?

Self-hosted is free forever. For a managed control plane with observability and revocation management, [request early access](https://tenuo.ai/pricing.html) to Tenuo Cloud.

---

## License

MIT OR Apache-2.0, at your option.
