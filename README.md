<p align="center">
  <img src="docs/images/tenuo-logo.svg" alt="tenuo" width="200">
</p>

<p align="center">
  <strong>Capability tokens for AI agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml"><img src="https://github.com/tenuo-ai/tenuo/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/tenuo-ai/tenuo"><img src="https://codecov.io/gh/tenuo-ai/tenuo/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://crates.io/crates/tenuo"><img src="https://img.shields.io/crates/v/tenuo.svg" alt="Crates.io"></a>
  <a href="https://pypi.org/project/tenuo/"><img src="https://img.shields.io/pypi/v/tenuo.svg" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/tenuo/authorizer"><img src="https://img.shields.io/docker/v/tenuo/authorizer?label=docker" alt="Docker"></a>
  <a href="https://tenuo.dev"><img src="https://img.shields.io/badge/docs-tenuo.dev-blue" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License"></a>
</p>

Tenuo is a cryptographic authorization primitive for AI agents. **Think prepaid debit card, as opposed to corporate Amex**: ephemeral, scoped capability tokens that expire when the task ends.

It constrains ambient identity-based permissions with task-scoped capabilities that attenuate as they delegate. Offline verification in ~27μs.
If an agent is prompt-injected, the authority still can't escape its bounds.

> **Status: v0.1 Beta** - Core semantics are stable. APIs may evolve. See [CHANGELOG](./CHANGELOG.md).

```bash
pip install tenuo
```

<a href="https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open In Colab"></a>
<a href="https://tenuo.dev/explorer/"><img src="https://img.shields.io/badge/Explorer-decode_warrants-00d4ff" alt="Explorer"></a>
<a href="https://tenuo.dev/demo.html"><img src="https://img.shields.io/badge/Docker_Demo-delegation_chain-a855f7" alt="Docker Demo"></a>
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

**Real-world validation:** String-based validation keeps failing. [CVE-2025-66032 in Claude Code](https://niyikiza.com/posts/cve-2025-66032/) showed that allowlists can't secure command execution when shells interpret strings differently than validators. Tenuo's semantic constraints (`Shlex`, `Subpath`, `UrlSafe`) operate at the right layer. See [The Map is not the Territory](https://niyikiza.com/posts/map-territory/) for the full analysis.

---

## What Tenuo Is Not

- **Not a sandbox** - Tenuo authorizes actions, it doesn't isolate execution. Pair with containers/VMs for defense in depth.
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
| **Framework integrations** | OpenAI, FastAPI, LangChain, LangGraph, MCP |

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
pip install tenuo                  # Core only
pip install "tenuo[openai]"        # + OpenAI Agents SDK
pip install "tenuo[google_adk]"    # + Google ADK
pip install "tenuo[a2a]"           # + A2A (inter-agent delegation)
pip install "tenuo[fastapi]"       # + FastAPI integration
pip install "tenuo[langchain]"     # + LangChain (langchain-core ≥0.2)
pip install "tenuo[langgraph]"     # + LangGraph (includes LangChain)
pip install "tenuo[mcp]"           # + MCP client (Python ≥3.10 required)
```

---

## Integrations

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

**FastAPI** - Extracts warrant from headers, verifies PoP offline
```python
@app.get("/search")
async def search(query: str, ctx: SecurityContext = Depends(TenuoGuard("search"))):
    return {"results": do_search(query)}
```

**More:** [MCP](https://tenuo.dev/mcp) | [Kubernetes](https://tenuo.dev/kubernetes)

---

## Docker & Kubernetes

**Try the Demo** - See the full delegation chain in action:

```bash
docker compose up
```

This runs the [orchestrator -> worker -> authorizer demo](https://tenuo.dev/demo.html) showing warrant issuance, delegation, and verification.

**Official Images** on [Docker Hub](https://hub.docker.com/u/tenuo):

```bash
docker pull tenuo/authorizer:0.1.0-beta.6  # Sidecar for warrant verification
docker pull tenuo/control:0.1.0-beta.6     # Control plane (demo/reference)
```

**Helm Chart**:

```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --set config.trustedRoots[0]="YOUR_CONTROL_PLANE_PUBLIC_KEY"
```

See [Helm chart README](./charts/tenuo-authorizer) and [Kubernetes guide](https://tenuo.dev/kubernetes).

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[Quickstart](https://tenuo.dev/quickstart)** | Get running in 5 minutes |
| **[Concepts](https://tenuo.dev/concepts)** | Why capability tokens? |
| **[OpenAI](https://tenuo.dev/openai)** | Direct API protection with streaming |
| **[Google ADK](https://tenuo.dev/google-adk)** | ADK agent tool protection |
| **[A2A](https://tenuo.dev/a2a)** | Inter-agent delegation |
| **[FastAPI](https://tenuo.dev/fastapi)** | Zero-boilerplate API protection |
| **[LangChain](https://tenuo.dev/langchain)** | Tool protection |
| **[LangGraph](https://tenuo.dev/langgraph)** | Multi-agent graph security |
| **[MCP](https://tenuo.dev/mcp)** | Model Context Protocol client |
| **[Security](https://tenuo.dev/security)** | Threat model |

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

See [Related Work](https://tenuo.dev/related-work) for detailed comparison.

---

## Featured In

- [TLDR InfoSec](https://tldr.tech/infosec/2025-12-15) - "Capabilities Are the Only Way to Secure Agent Delegation"
- [Awesome Object Capabilities](https://github.com/dckc/awesome-ocap) - Curated list of capability-based security resources
- [Awesome LangChain](https://github.com/kyrolabs/awesome-langchain)
- [Awesome LLM Agent Security](https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security)
- [Awesome LLMSecOps](https://github.com/wearetyomsmnv/Awesome-LLMSecOps)

---

## Roadmap

| Feature | Status |
|---------|--------|
| A2A integration | Implemented (`pip install tenuo[a2a]`) |
| Google ADK integration | Implemented (`pip install tenuo[google_adk]`) |
| Multi-sig approvals | Partial (notary in v0.2) |
| TypeScript/Node SDK | Planned for v0.2 |
| Context-aware constraints | Spec under development |
| Revocation service | Basic revocation via Authorizer; distributed revocation in v0.3 |

---

## Rust

Building a sidecar or gateway? Use the core directly:

```toml
[dependencies]
tenuo = "0.1.0-beta.6"
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

We're planning a TypeScript/Node SDK for v0.2. If you're interested in leading or contributing to this effort, open an issue or email us at [dev@tenuo.dev](mailto:dev@tenuo.dev).

**Security issues**: Email security@tenuo.dev with PGP ([key](./SECURITY_PUBKEY.asc), not public issues).

---

## License

MIT OR Apache-2.0, at your option.
