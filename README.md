<p align="center">
  <img src="docs/images/tenuo-logo.svg" alt="tenuo" width="200">
</p>

<p align="center">
  <strong>Capability tokens for AI agents.</strong>
</p>

Tenuo is a cryptographic authorization primitive for AI agents. **Think prepaid debit card, not corporate Amex**: ephemeral, scoped capability tokens that expire when the task ends.

It constrains ambient identity-based permissions with task-scoped capabilities that attenuate as they delegate. Offline verification in ~27μs.
If an agent is prompt-injected, the authority still can't escape its bounds.

[![Crates.io](https://img.shields.io/crates/v/tenuo-core.svg)](https://crates.io/crates/tenuo-core)
[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Docs](https://img.shields.io/badge/docs-tenuo.ai-blue)](https://tenuo.ai)

> **v0.1** - Early release. Cryptographic core is stable; integration APIs are evolving.

```bash
pip install tenuo
```

## Quick Start

```python
from tenuo import SigningKey, Warrant, Pattern, lockdown, set_warrant_context, set_signing_key_context

# Issue a warrant with fluent builder
keypair = SigningKey.generate()
warrant = (Warrant.builder()
    .tool("read_file")
    .constraint("path", Pattern("/data/*"))
    .holder(keypair.public_key)
    .ttl(300)
    .issue(keypair))

# Protect a tool
@lockdown(tool="read_file")
def read_file(path: str):
    return open(path).read()

# Execute with authorization
with set_warrant_context(warrant), set_signing_key_context(keypair):
    read_file("/data/report.txt")  # Allowed
    read_file("/etc/passwd")       # Blocked
```

The agent can be prompt-injected. The authorization layer doesn't care. The warrant says `/data/*`. The request says `/etc/passwd`. Denied.

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
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Control      │     │ Orchestrator │     │ Worker       │
│ Plane        │     │              │     │              │
│              │     │              │     │              │
│ Issues root  │────▶│ Attenuates   │────▶│ Executes     │
│ warrant      │     │ for task     │     │ with proof   │
└──────────────┘     └──────────────┘     └──────────────┘
     Full scope    →    Narrower     →    Narrowest
     (all tools)       (some tools)      (one tool, one path)
```

1. **Control plane** issues a root warrant
2. **Orchestrator** attenuates it (scope can only shrink)
3. **Worker** proves possession and executes
4. **Warrant expires** - no revocation needed

Warrants can only **shrink** when delegated: 15 replicas becomes 10, access to `staging-*` narrows to `staging-web`. Verification is 100% offline in ~27μs on commodity hardware (benchmarks in repo).

---

## Warrant Types

Tenuo supports two types of warrants for separation of concerns:

### ISSUER Warrants (Planners)
- **Purpose**: Issue EXECUTION warrants to workers
- **Use Case**: Orchestrators, P-LLMs that decide capabilities
- **Capabilities**: Can issue warrants, cannot execute tools
- **Security**: Prevents planning components from directly invoking tools

### EXECUTION Warrants (Workers)
- **Purpose**: Invoke specific tools with specific constraints
- **Use Case**: Workers that execute actions
- **Capabilities**: Can execute tools, cannot issue new warrants
- **Security**: Prevents execution components from escalating privileges

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Offline verification** | No network calls, ~27μs |
| **Holder binding (PoP)** | Stolen tokens are useless without the key |
| **Constraint types** | `Exact`, `Pattern`, `Range`, `OneOf`, `Regex` |
| **Monotonic attenuation** | Capabilities only shrink, never expand |
| **Framework integrations** | LangChain, LangGraph, MCP (full client) |

---

## Requirements

| Component | Supported |
|-----------|-----------|
| **Python** | 3.9, 3.10, 3.11, 3.12 |
| **OS** | Linux, macOS, Windows |
| **Rust** | Not required (binary wheels provided). 1.70+ only if building from source. |

### Optional Dependencies

```bash
pip install tenuo                # Core only
pip install tenuo[langchain]     # + LangChain (langchain-core ≥0.2)
pip install tenuo[langgraph]     # + LangGraph (includes LangChain)
pip install tenuo[mcp]           # + MCP client (Python ≥3.10 required)
```

LangChain/LangGraph are optional to keep the core package lightweight. MCP integration requires Python ≥3.10 (MCP SDK limitation).

---

## Integrations

**LangChain**
```python
from tenuo.langchain import protect_tools
# Wrap tools so every invocation requires a valid warrant
secure_tools = protect_tools([search_tool, file_tool])
```

**LangGraph**
```python
from tenuo.langgraph import TenuoToolNode
tool_node = TenuoToolNode(tools)
```

**MCP (Model Context Protocol)**
```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient("python", ["mcp_server.py"]) as client:
    tools = await client.get_protected_tools()
```

**Kubernetes** — Deploy as sidecar or gateway. See [quickstart](https://github.com/tenuo-ai/tenuo/tree/main/docs/quickstart).

---

## Try It

```bash
docker compose up orchestrator worker
```

See the [examples](./tenuo-python/examples) for LangChain, LangGraph, and multi-agent patterns.

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[Quickstart](https://tenuo.ai/quickstart)** | Get running in 5 minutes |
| **[Concepts](https://tenuo.ai/concepts)** | Why capability tokens? |
| **[LangChain](https://tenuo.ai/langchain)** | Tool protection |
| **[MCP Integration](https://tenuo.ai/mcp)** | Model Context Protocol client |
| **[Kubernetes](https://tenuo.ai/kubernetes)** | Deployment patterns |
| **[Security](https://tenuo.ai/security)** | Threat model |
| **[API Reference](https://tenuo.ai/api-reference)** | Full SDK docs |

---

## Prior Art

Tenuo builds on capability token ideas described in [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). Inspired by [Macaroons](https://research.google/pubs/pub41892/), [Biscuit](https://www.biscuitsec.org/), and [UCAN](https://ucan.xyz/).

See [Related Work](https://tenuo.ai/related-work) for detailed comparison.

---

## Rust

Building a sidecar or gateway? Use the core directly:

```toml
[dependencies]
tenuo-core = "0.1"
```

See [docs.rs/tenuo-core](https://docs.rs/tenuo-core) for Rust API and the [Kubernetes Integration Guide](https://tenuo.ai/kubernetes) for sidecar/gateway deployment patterns.

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Security issues**: Email security@tenuo.ai (not public issues).

---

## License

MIT OR Apache-2.0, at your option.
