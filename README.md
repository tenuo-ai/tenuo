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

AI Agents are non-deterministic. Giving them static API keys (like `S3FullAccess`) creates a massive blast radius if they get prompt-injected.

Tenuo implements **Subtractive Delegation**:

- **Orchestrator** holds a Root Warrant
- **Worker** receives an attenuated Warrant (narrower scope) for a specific task
- **Verification** happens offline using Ed25519 signatures. No central bottleneck.

Warrants can only **shrink** when delegated: a $1000 budget becomes $500, access to `staging-*` narrows to `staging-web`. Verification is 100% offline in ~25μs.

## Integration Patterns

### 1. Python SDK (The Easy Way)

Perfect for LangChain, AutoGPT, and CrewAI tools.

**Python**

```python
from tenuo import Warrant, Pattern, Exact, set_warrant_context

# Create a restricted warrant for a sub-agent
worker_warrant = root_warrant.attenuate(
    constraints={
        "db_name": Pattern("test-*"),  # Only test databases
        "budget": 100.0                # Max $100
    },
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

**Full Example:**

```python
from tenuo import Keypair, Warrant, Pattern, Exact, Range

# Generate a keypair
keypair = Keypair.generate()

# Issue a warrant with constraints
warrant = Warrant.create(
    tool="manage_infrastructure",
    constraints={
        "cluster": Pattern("staging-*"),
        "budget": Range.max_value(10000.0)
    },
    ttl_seconds=3600,
    keypair=keypair
)

# Attenuate for a worker (capabilities shrink)
worker_keypair = Keypair.generate()
worker_warrant = warrant.attenuate(
    constraints={
        "cluster": Exact("staging-web"),
        "budget": Range.max_value(1000.0)
    },
    keypair=worker_keypair
)

# Authorize an action
authorized = worker_warrant.authorize(
    tool="manage_infrastructure",
    args={"cluster": "staging-web", "budget": 500.0}
)
print(f"Authorized: {authorized}")  # True
```

**Pythonic features:**
- `@lockdown` decorator for function-level authorization
- ContextVar support for LangChain/FastAPI integration
- Pythonic exceptions and error handling

See [tenuo-python/](tenuo-python/) for full documentation and examples.

### 2. Rust Core (The Performance Way)

Building a high-performance sidecar or gateway? Use the engine directly.

**Latency:** ~20μs verification.

**Stack:** Pure Rust, `no_std` compatible core.

**Cargo.toml**

```toml
[dependencies]
tenuo-core = "0.1"
```

**Rust**

```rust
use tenuo_core::{Warrant, Keypair, Pattern, Range};
use std::time::Duration;

let keypair = Keypair::generate();

// Issue a warrant
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

// Worker authorizes action (~25μs, no network)
worker_warrant.authorize("upgrade", &args, Some(&pop_signature))?;
```

## How it Works

1. **Control Plane** issues a Root Warrant (Genesis)
2. **Orchestrator** attenuates it for Workers (Delegation)
3. **Authorizer** verifies the chain at runtime (Enforcement)

See the [Architecture Deep Dive](https://tenuo.github.io/tenuo/guide/) for details on the Protocol, CBOR format, and Cryptography.

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

## Constraint Types

| Type | Example | Description |
|------|---------|-------------|
| `Wildcard` | `*` | Matches anything, can narrow to any type |
| `Pattern` | `staging-*` | Glob matching |
| `Exact` | `staging-web` | Exact string match |
| `OneOf` | `["a", "b"]` | Value must be in set |
| `Range` | `0..10000` | Numeric bounds |
| `NotOneOf` | `!["prod"]` | Exclude specific values |
| `CEL` | `amount < limit` | Complex expressions |

## MCP (Model Context Protocol) Integration

**Native AI Agent Support**: Tenuo integrates directly with [MCP](https://modelcontextprotocol.io), the standard protocol for AI agent tool calling. No custom middleware needed.

```
┌─────────────────┐
│  AI Agent       │
│  (Claude/GPT)   │
└────────┬────────┘
         │ MCP tool call
         │ {tool: "filesystem_read", arguments: {...}}
         ▼
┌─────────────────┐
│  MCP Server     │
│  (Tool Handler) │
└────────┬────────┘
         │ Extract + Authorize
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

**Python Example:**

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, PublicKey

# Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# Initialize authorizer
control_plane_key = PublicKey.from_bytes(bytes.fromhex("f32e74b5..."))
authorizer = Authorizer.new(control_plane_key)

# Extract constraints from MCP tool call
arguments = {"path": "/var/log/app.log", "maxSize": 1024}
result = compiled.extract_constraints("filesystem_read", arguments)

# Authorize (with warrant chain and PoP signature)
warrant = Warrant.from_base64(warrant_chain_base64)
authorized = authorizer.check(
    warrant,
    "filesystem_read",
    result.constraints,
    pop_signature
)
```

**Why MCP + Tenuo?**
- **Tool-centric**: MCP tools map directly to Tenuo tool configurations (no HTTP routing complexity)
- **Cryptographic provenance**: Every tool call is authorized by a warrant chain proving who delegated authority
- **Multi-agent workflows**: Perfect for orchestrators delegating to specialized workers with bounded capabilities

See the [MCP module documentation](https://docs.rs/tenuo-core/latest/tenuo_core/mcp/index.html) for details.

## Revocation

Warrants can be revoked using **Signed Revocation Lists (SRLs)**. The Control Plane signs the list; authorizers verify before trusting.

**Cascading Revocation:**
- **Surgical**: Revoke a specific warrant ID to stop one task
- **Nuclear**: Revoke an agent's key to instantly invalidate every warrant they ever issued (kill 10,000 sub-agents with one switch)

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

Your services keep their existing IAM. Tenuo adds a **delegation layer** that tracks *who* authorized the action, *what task context* it carries, and *what limits* apply. Constraints can depend on actions earlier in the workflow.

## Architecture

```
Control Plane (secure)     Data Plane (distributed)
┌──────────────────┐       ┌──────────────────────────┐
│ Issue warrants   │       │ Gateway / Sidecar        │
│ Manage keys      │──────▶│ Verify chains offline    │
│ Policy config    │       │ Enforce constraints      │
└──────────────────┘       └──────────────────────────┘
```

The Control Plane issues root warrants. Agents attenuate and delegate. 
The Data Plane (gateway or sidecar) verifies locally with no round-trips.

## Security

| Property | Protection |
|----------|------------|
| Domain separation | Signatures include context prefix |
| Canonical encoding | Deterministic serialization |
| Constraint depth | Max 16 nesting levels |
| Payload size | Max 1MB per warrant |
| PoP replay | Signatures valid ~2 minutes |
| ID validation | Prefix enforced on deserialize |

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and infographics
- **[Guide](https://tenuo.github.io/tenuo/guide/)**: Concepts and examples
- **[API Reference](https://docs.rs/tenuo-core)**: Rustdoc API documentation
- **[Python SDK](tenuo-python/)**: Full Python documentation and examples

## Quick Start (Docker Demo)

```bash
# Run the multi-agent demo
docker compose up orchestrator worker
```

## License

MIT OR Apache-2.0
