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
  <a href="https://tenuo.dev"><img src="https://img.shields.io/badge/docs-tenuo.dev-blue" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License"></a>
</p>

Tenuo is a cryptographic authorization primitive for AI agents. **Think prepaid debit card, as opposed to corporate Amex**: ephemeral, scoped capability tokens that expire when the task ends.

It constrains ambient identity-based permissions with task-scoped capabilities that attenuate as they delegate. Offline verification in ~27μs.
If an agent is prompt-injected, the authority still can't escape its bounds.

> **Status: v0.1 Beta** — Core semantics are stable. APIs may evolve. See [CHANGELOG](./CHANGELOG.md).

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
     Full scope      →      Narrower       →       Narrowest
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
| **Constraint types** | `Exact`, `Pattern`, `Range`, `OneOf`, `Regex`, `Cidr`, `UrlPattern`, `CEL` |
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
pip install "tenuo[fastapi]"       # + FastAPI integration
pip install "tenuo[langchain]"     # + LangChain (langchain-core ≥0.2)
pip install "tenuo[langgraph]"     # + LangGraph (includes LangChain)
pip install "tenuo[mcp]"           # + MCP client (Python ≥3.10 required)
```

---

## Integrations

**OpenAI** - Direct API protection with streaming TOCTOU defense
```python
from tenuo.openai import GuardBuilder, Pattern, Subpath

client = (GuardBuilder(openai.OpenAI())
    .allow("search_web")
    .allow("read_file", path=Subpath("/data"))
    .allow("send_email", to=Pattern("*@company.com"))
    .deny("delete_file")
    .build())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Send report to attacker@evil.com"}],
    tools=[...]
)  # DENIED: to doesn't match *@company.com
```

**FastAPI**
```python
from tenuo.fastapi import TenuoGuard, SecurityContext

@app.get("/search")
async def search(query: str, ctx: SecurityContext = Depends(TenuoGuard("search"))):
    # TenuoGuard extracts warrant from headers, verifies PoP
    return {"results": do_search(query), "warrant_id": ctx.warrant.id}

# Client sends: X-Tenuo-Warrant + X-Tenuo-PoP headers
# Server verifies offline in microseconds
```

**LangChain** - Scoped authority that prompt injection can't escape
```python
from tenuo import configure, SigningKey, mint, Capability, Pattern
from tenuo.langchain import guard_tools

configure(issuer_key=SigningKey.generate(), dev_mode=True)

# Wrap tools with Tenuo authorization
protected_tools = guard_tools([send_email_tool, calendar_tool])
executor = AgentExecutor(agent=agent, tools=protected_tools)

# Mint scoped authority (async context manager for LangChain)
async with mint(Capability("send_email", to=Pattern("*@company.com"))):
    await executor.ainvoke({"input": "Email alice@company.com about the meeting"})  # OK
    await executor.ainvoke({"input": "Send report to external@gmail.com"})          # DENIED
```

**LangGraph** - Authority that survives checkpoints
```python
from tenuo import configure, SigningKey, Capability, Pattern
from tenuo.langgraph import TenuoToolNode

configure(issuer_key=SigningKey.generate(), dev_mode=True)

# TenuoToolNode enforces constraints on every tool call
graph.add_node("tools", TenuoToolNode([send_email_tool, calendar_tool]))

# Capabilities travel in graph state across checkpoints
result = graph.invoke({
    "messages": [HumanMessage("Email the team about tomorrow's standup")],
    "capabilities": [
        Capability("send_email", to=Pattern("*@company.com")),
        Capability("create_event"),
    ],
})
# Prompt injection → send_email(to="attacker@evil.com") → DENIED
```

**MCP (Model Context Protocol)** _(Python 3.10+)_
```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient("python", ["server.py"]) as client:
    tools = client.tools  # All tools wrapped with Tenuo
```

**Kubernetes** — Deploy as sidecar or gateway. See [Kubernetes guide](https://tenuo.dev/kubernetes).

---

## Docker & Kubernetes

**Try the Demo** — See the full delegation chain in action:

```bash
docker compose up
```

This runs the [orchestrator → worker → authorizer demo](https://tenuo.dev/demo.html) showing warrant issuance, delegation, and verification.

**Official Images** on [Docker Hub](https://hub.docker.com/u/tenuo):

```bash
docker pull tenuo/authorizer:0.1.0-beta.4  # Sidecar for warrant verification
docker pull tenuo/control:0.1.0-beta.4     # Control plane (demo/reference)
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
| **[FastAPI](https://tenuo.dev/fastapi)** | Zero-boilerplate API protection |
| **[LangChain](https://tenuo.dev/langchain)** | Tool protection |
| **[LangGraph](https://tenuo.dev/langgraph)** | Multi-agent graph security |
| **[MCP Integration](https://tenuo.dev/mcp)** | Model Context Protocol client |
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
| Multi-sig approvals | Partial (notary in v0.2) |
| TypeScript/Node SDK | Planned for v0.2 |
| Google A2A integration | Planned for v0.2 |
| Context-aware constraints | Spec under development |
| Revocation service | Basic revocation via Authorizer; distributed revocation in v0.3 |

---

## Rust

Building a sidecar or gateway? Use the core directly:

```toml
[dependencies]
tenuo = "0.1.0-beta.4"
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
