# Tenuo

**Agent Capability Flow Control.**

Identity is dead for Agents. Standard IAM answers "Who are you?" Tenuo answers "Do you have a warrant for this specific action?"

It is a cryptographically verifiable, offline authorization engine for AI Agents. Built in Rust, consumed in Python.

[![Crate](https://img.shields.io/crates/v/tenuo-core.svg)](https://crates.io/crates/tenuo-core)
[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Docs](https://docs.rs/tenuo-core/badge.svg)](https://docs.rs/tenuo-core)

## The 5-Second Hook

Stop your agent from deleting production data with one line of code.

**Python**

```python
from tenuo import lockdown

# 1. Protect dangerous tools
@lockdown(tool="delete_database")
def delete_database(db_name: str, reason: str):
    print(f"Deleting {db_name}...")

# 2. Your Agent Logic
# If the agent tries to call this without a valid Warrant for 'prod',
# Tenuo blocks it instantly (Offline).
delete_database(db_name="prod", reason="hallucinated")
# ❌ PermissionError: Tenuo Authorization Failed: 'db_name' constraint violation
```

## Installation

**Bash**

```bash
pip install tenuo
```

## Why Tenuo?

AI Agents are non-deterministic. Giving them static access (like `S3FullAccess`) creates a massive blast radius if they get prompt-injected.

Tenuo implements **Subtractive Delegation**:

- **Orchestrator** holds a Root Warrant
- **Worker** receives an attenuated Warrant (narrower scope) for a specific task
- **Verification** happens offline using Ed25519 signatures. No central bottleneck.

Warrants can only **shrink** when delegated: a $1000 budget becomes $500, access to `staging-*` narrows to `staging-web`. Verification is 100% offline in ~25μs.

## Integration Patterns

### Python SDK (The Easy Way)

Perfect for LangChain, AutoGPT, and CrewAI tools.

```python
from tenuo import Warrant, Pattern, set_warrant_context, lockdown

# Create a restricted warrant for a sub-agent
worker_warrant = root_warrant.attenuate(
    constraints={"db_name": Pattern("test-*")},
    keypair=worker_keypair
)

# Use with ContextVar (LangChain/FastAPI)
@lockdown(tool="delete_database")
def delete_database(db_name: str, reason: str):
    # Warrant retrieved from context automatically
    print(f"Deleting {db_name}...")

with set_warrant_context(worker_warrant):
    delete_database(db_name="test-users", reason="cleanup")
    # ✅ Authorized: matches Pattern("test-*")
```

**Features:**
- `@lockdown` decorator for function-level authorization
- ContextVar support for LangChain/FastAPI integration
- Pythonic exceptions and error handling

See [tenuo-python/](tenuo-python/) for full documentation and examples.

### Rust Core (The Performance Way)

Building a high-performance sidecar or gateway? Use the engine directly.

**Latency:** ~20μs verification. **Stack:** Pure Rust, `no_std` compatible core.

```toml
[dependencies]
tenuo-core = "0.1"
```

```rust
use tenuo_core::{Warrant, Keypair, Pattern, Range};
use std::time::Duration;

let keypair = Keypair::generate();
let warrant = Warrant::builder()
    .tool("manage_infrastructure")
    .constraint("cluster", Pattern::new("staging-*")?)
    .constraint("budget", Range::max(10000.0))
    .ttl(Duration::from_secs(3600))
    .build(&keypair)?;

// Attenuate for a worker (capabilities shrink)
let worker_warrant = warrant.attenuate()
    .constraint("cluster", Exact::new("staging-web"))
    .constraint("budget", Range::max(1000.0))
    .authorized_holder(worker_keypair.public_key())
    .build(&keypair)?;
```

See [API Reference](https://docs.rs/tenuo-core) for full Rust documentation.

## How it Works

1. **Control Plane** issues a Root Warrant (Genesis)
2. **Orchestrator** attenuates it for Workers (Delegation)
3. **Authorizer** verifies the chain at runtime (Enforcement)

See the [Architecture Deep Dive](https://tenuo.github.io/tenuo/guide/) for details on the Protocol, CBOR format, and Cryptography.

### Try the Multi-Agent Demo

Want to see the full architecture in action? Run the Docker demo to explore how orchestrators delegate to workers with attenuated warrants:

```bash
# Run the multi-agent demo
docker compose up orchestrator worker
```

This demonstrates the complete flow: warrant issuance, attenuation, delegation, and offline verification. Perfect for understanding the architecture and protocol details.

## Key Features

| Feature | Description |
|---------|-------------|
| **Monotonic attenuation** | Capabilities only shrink, never expand |
| **Offline verification** | No network calls, ~25μs latency |
| **Holder binding** | Warrants bound to keys, stolen tokens useless |
| **Multi-sig approvals** | M-of-N approval for sensitive actions |
| **Cascading revocation** | Surgical (one warrant) or nuclear (entire agent swarm) |
| **Depth limits** | Configurable delegation depth (max 64) |
| **MCP integration** | Native support for Model Context Protocol (AI agent tool calling) |

## MCP (Model Context Protocol) Integration

**Native AI Agent Support**: Tenuo integrates directly with [MCP](https://modelcontextprotocol.io), the standard protocol for AI agent tool calling. No custom middleware needed.

```
┌─────────────────┐
│  AI Agent       │
│  (Claude/GPT)   │
└────────┬────────┘
         │ MCP tool call
         ▼
┌─────────────────┐      ┌──────────────────┐
│  Tenuo          │─────▶│  Authorizer      │
│  extract_constraints() │  check()         │
└─────────────────┘      └──────────────────┘
         │                        │
         │ Extracted values       │ ✓ Authorized
         │                        │   or ✗ Denied
         ▼                        ▼
┌─────────────────┐      ┌──────────────────┐
│  Tool Execution │      │  Response        │
│  (if authorized)│      │  (to agent)      │
└─────────────────┘      └──────────────────┘
```

**Why MCP + Tenuo?**
- **Tool-centric**: MCP tools map directly to Tenuo tool configurations
- **Cryptographic provenance**: Every tool call is authorized by a warrant chain
- **Multi-agent workflows**: Perfect for orchestrators delegating to specialized workers

See the [MCP module documentation](https://docs.rs/tenuo-core/latest/tenuo_core/mcp/index.html) and [Python SDK examples](examples/mcp_integration.py) for details.

## Where Tenuo Fits

Tenuo sits **above** your infrastructure IAM. It doesn't replace it.

```
┌────────────────────────────────────────────────┐
│  Tenuo (Application Layer)                     │
│  "Who delegated this, what context, what       │
│   bounds?"                                     │
└──────────────────────┬─────────────────────────┘
                       ▼
┌────────────────────────────────────────────────┐
│  Infrastructure IAM (AWS / K8s / etc.)         │
│  "Can this service call this API?"             │
└────────────────────────────────────────────────┘
```

Your services keep their existing IAM. Tenuo adds a **delegation layer** that tracks *who* authorized the action, *what task context* it carries, and *what limits* apply.

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and infographics
- **[Guide](https://tenuo.github.io/tenuo/guide/)**: Concepts, examples, and constraint types
- **[Python SDK](tenuo-python/)**: Full Python documentation and examples
- **[Rust API](https://docs.rs/tenuo-core)**: Complete Rust API reference

## License

MIT OR Apache-2.0
