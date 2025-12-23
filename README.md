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
  <a href="./charts/tenuo-authorizer"><img src="https://img.shields.io/badge/helm-0.1.0-blue?logo=helm" alt="Helm"></a>
  <a href="https://tenuo.ai"><img src="https://img.shields.io/badge/docs-tenuo.ai-blue" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License"></a>
</p>

Tenuo is a cryptographic authorization primitive for AI agents. **Think prepaid debit card, as opposed to corporate Amex**: ephemeral, scoped capability tokens that expire when the task ends.

It constrains ambient identity-based permissions with task-scoped capabilities that attenuate as they delegate. Offline verification in ~27μs.
If an agent is prompt-injected, the authority still can't escape its bounds.

> **v0.1.0-alpha.8** - Early release. Cryptographic core is stable; integration APIs are evolving. See [CHANGELOG](./CHANGELOG.md).

```bash
pip install tenuo
```

<a href="https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open In Colab"></a>
<a href="https://tenuo.ai/explorer/"><img src="https://img.shields.io/badge/🔬_Explorer-decode_warrants-00d4ff" alt="Explorer"></a>

## Quick Start

```python
from tenuo import Warrant, SigningKey, Pattern

# Warrant in state - serializable, no secrets
warrant = receive_warrant_from_orchestrator()

# Explicit key at call site - keys never in state
key = SigningKey.from_env("MY_SERVICE_KEY")
headers = warrant.auth_headers(key, "search", {"query": "test"})

# Delegation with attenuation
child = warrant.delegate(
    to=worker_pubkey,
    allow={"search": {"query": Pattern("safe*")}},
    ttl=300,
    key=key
)
```

The agent can be prompt-injected. The authorization layer doesn't care. The warrant says `safe*`. The request says `dangerous`. **Denied.**

<details>
<summary><strong>Context-based API (for prototyping)</strong></summary>

```python
from tenuo import configure, root_task, Capability, Pattern, SigningKey, lockdown

configure(issuer_key=SigningKey.generate(), dev_mode=True)

@lockdown(tool="read_file")
def read_file(path: str):
    return open(path).read()

async with root_task(Capability("read_file", path=Pattern("/data/*"))):
    read_file("/data/report.txt")  # ✅ Allowed
    read_file("/etc/passwd")       # ❌ Blocked
```

</details>

**[Read the launch post →](https://tenuo.ai/blog/introducing-tenuo)**

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
| **Holder binding (PoP)** | Stolen tokens are useless without the key |
| **Constraint types** | `Exact`, `Pattern`, `Range`, `OneOf`, `Regex`, `Cidr`, `UrlPattern`, `CEL` |
| **Monotonic attenuation** | Capabilities only shrink, never expand |
| **Framework integrations** | FastAPI, LangChain, LangGraph, MCP |

---

## Requirements

| Component | Supported |
|-----------|-----------|
| **Python** | 3.9, 3.10, 3.11, 3.12 |
| **OS** | Linux, macOS, Windows |
| **Rust** | Not required (binary wheels provided) |

### Optional Dependencies

```bash
pip install tenuo                # Core only
pip install tenuo[fastapi]       # + FastAPI integration
pip install tenuo[langchain]     # + LangChain (langchain-core ≥0.2)
pip install tenuo[langgraph]     # + LangGraph (includes LangChain)
pip install tenuo[mcp]           # + MCP client (Python ≥3.10 required)
```

---

## Integrations

**FastAPI**
```python
from fastapi import FastAPI, Depends
from tenuo.fastapi import TenuoGuard, SecurityContext, configure_tenuo

app = FastAPI()
configure_tenuo(app, trusted_issuers=[issuer_pubkey])

@app.get("/search")
async def search(query: str, ctx: SecurityContext = Depends(TenuoGuard("search"))):
    return {"results": [...]}
```

**LangChain**
```python
from tenuo import Warrant, SigningKey
from tenuo.langchain import protect

warrant = Warrant.builder().tool("search").issue(keypair)
bound = warrant.bind_key(keypair)

protected_tools = protect([search_tool], bound_warrant=bound)
```

**LangGraph**
```python
from tenuo import KeyRegistry
from tenuo.langgraph import secure, TenuoToolNode, auto_load_keys

# Load keys from TENUO_KEY_* env vars
auto_load_keys()

# Wrap pure nodes with security
graph.add_node("agent", secure(my_agent, key_id="worker"))
graph.add_node("tools", TenuoToolNode([search, calculator]))

# Run with warrant in state
graph.invoke({"warrant": warrant, ...})
```

**MCP (Model Context Protocol)** _(Requires Python 3.10+)_
```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient("python", ["mcp_server.py"]) as client:
    tools = await client.get_protected_tools()
```

**Kubernetes** — Deploy as sidecar or gateway. See [quickstart](https://github.com/tenuo-ai/tenuo/tree/main/docs/quickstart).

---

## Docker & Kubernetes

Official images on [Docker Hub](https://hub.docker.com/u/tenuo):

```bash
docker pull tenuo/authorizer:latest  # Sidecar for warrant verification
docker pull tenuo/control:latest     # Control plane (demo/reference)
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
| **[FastAPI](https://tenuo.ai/fastapi)** | Zero-boilerplate API protection |
| **[LangChain](https://tenuo.ai/langchain)** | Tool protection |
| **[LangGraph](https://tenuo.ai/langgraph)** | Multi-agent graph security |
| **[MCP Integration](https://tenuo.ai/mcp)** | Model Context Protocol client |
| **[Security](https://tenuo.ai/security)** | Threat model |

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

See [Related Work](https://tenuo.ai/related-work) for detailed comparison.

---

## Rust

Building a sidecar or gateway? Use the core directly:

```toml
[dependencies]
tenuo = "0.1"
```

See [docs.rs/tenuo](https://docs.rs/tenuo) for Rust API.

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Security issues**: Email security@tenuo.ai (not public issues).

---

## License

MIT OR Apache-2.0, at your option.
