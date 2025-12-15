# Tenuo

**Agent Capability Flow Control.**

Identity is dead for Agents. Standard IAM answers "Who are you?" Tenuo answers "Do you have a warrant for this specific action?"

It is a cryptographically verifiable, offline authorization engine for AI Agents. Built in Rust, consumed in Python.

[![Crate](https://img.shields.io/crates/v/tenuo-core.svg)](https://crates.io/crates/tenuo-core)
[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Docs](https://docs.rs/tenuo-core/badge.svg)](https://docs.rs/tenuo-core)

## Quick Start
 
Protect your agent's tools with a single decorator.
 
**Python**
 
```python
from tenuo import Keypair, Warrant, Pattern, lockdown, set_warrant_context, set_keypair_context

# 1. Setup (normally done by control plane)
keypair = Keypair.generate()
warrant = Warrant.issue(
    tool="delete_database",
    keypair=keypair,
    holder=keypair.public_key(),
    constraints={"db_name": Pattern("test-*")},
    ttl_seconds=300,
)

# 2. Protect tools
@lockdown(tool="delete_database")
def delete_database(db_name: str, reason: str):
    print(f"Deleting {db_name}...")

# 3. Execute with authorization
# Keypair required to sign the PoP challenge (proving you own the warrant)
with set_warrant_context(warrant), set_keypair_context(keypair):
    delete_database(db_name="test-users", reason="cleanup")  # [OK] Allowed
    # delete_database(db_name="prod", reason="oops")         # [ERR] Blocked (AuthorizationError)
```

## Installation

**Bash**

```bash
pip install tenuo
```

## Design Principles

### Security Invariants

1. **Authority is Delegated, Not Inherent**: Identity proves *who* you are; a warrant proves *what* you can do.
2. **Monotonic Attenuation**: Scope only shrinks. A child warrant can never exceed its parent's authority.
3. **Mandatory Proof-of-Possession**: Warrants are useless without the corresponding private key. Theft of the token alone grants no access.
4. **Stateless Verification**: Verification is local. It does not require a "phone home" to a control plane.
5. **Ephemeral by Design**: Authority is bound to a task's lifecycle (TTL), not the compute's uptime.
6. **Verifiable Lineage**: Every capability can be cryptographically traced back to a root trust anchor.

### Architectural Boundaries

7. **No Agent Runtime**: Tenuo authorizes actions; it does not execute code, manage state, or orchestrate workflows.
8. **Model Agnostic**: No assumptions about LLMs, prompt structures, or embeddings.
9. **Infrastructure Neutral**: Works in containers, serverless functions, or local scripts.

### Scope

**Tenuo Provides:**

- Key generation
- Warrant issuance, attenuation, and verification
- A constraint language for fine-grained scoping
- Delegation diff tracking and audit receipts
- Builder pattern for warrant attenuation with preview

**Tenuo Does NOT Require:**

- Phone home for verification
- Central authority at runtime
- Network access to validate warrants

**Tenuo Does NOT Provide:**

- Agent frameworks or orchestration (use LangGraph, CrewAI, etc.)
- Tool execution or routing
- Network enforcement (Tenuo is an authorization primitive, not a firewall)

## Why Tenuo?

AI Agents are non-deterministic. Giving them static access (like `S3FullAccess`) creates a massive blast radius if they get prompt-injected.

Tenuo implements **Subtractive Delegation**:

- **Orchestrator** holds a Root Warrant
- **Worker** receives an attenuated Warrant (narrower scope) for a specific task
- **Verification** happens offline using Ed25519 signatures. No central bottleneck.

Warrants can only **shrink** when delegated: a $1000 budget becomes $500, access to `staging-*` narrows to `staging-web`. Verification is 100% offline in ~25μs.

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

### Trust Levels

Warrants have hierarchical trust levels that enforce organizational boundaries:

| Level | Value | Use Case |
|-------|-------|----------|
| **Untrusted** | 0 | Anonymous/unauthenticated entities |
| **External** | 10 | Authenticated external users |
| **Partner** | 20 | Third-party integrations |
| **Internal** | 30 | Internal services |
| **Privileged** | 40 | Admin operations |
| **System** | 50 | Control plane |

Trust levels can only **decrease** during delegation, preventing privilege escalation.

**Best Practice**: Use ISSUER warrants for planners, EXECUTION warrants for workers. See [`issuer_execution_pattern.py`](tenuo-python/examples/issuer_execution_pattern.py) for the recommended pattern.

## Integration Patterns

### Python SDK (The Easy Way)

Perfect for LangChain, AutoGPT, and CrewAI tools.

```python
from tenuo import Warrant, Keypair, Pattern, set_warrant_context, set_keypair_context, lockdown

# Generate keys
root_keypair = Keypair.generate()
worker_keypair = Keypair.generate()

# Issue a root warrant (Control Plane)
root_warrant = Warrant.issue(
    tool="delete_database",
    keypair=root_keypair,
    holder=root_keypair.public_key(),
    constraints={"db_name": Pattern("*")},
    ttl_seconds=3600
)

# Create a restricted warrant for a sub-agent (Orchestrator)
# Option 1: Direct attenuation
worker_warrant = root_warrant.attenuate(
    constraints={"db_name": Pattern("test-*")},
    keypair=worker_keypair,       # Subject keypair
    parent_keypair=root_keypair,  # Issuer keypair
    holder=worker_keypair.public_key()
)

# Option 2: Builder pattern with diff preview (recommended for audit trails)
builder = root_warrant.attenuate_builder()
builder.with_constraint("db_name", Pattern("test-*"))
builder.with_holder(worker_keypair.public_key())
builder.with_intent("Test database cleanup")
print(builder.diff())  # Preview changes before delegation
worker_warrant = builder.delegate_to(root_keypair, root_keypair)

# Use with ContextVar (LangChain/FastAPI)
@lockdown(tool="delete_database")
def delete_database(db_name: str, reason: str):
    # Warrant retrieved from context automatically
    print(f"Deleting {db_name}...")

# Set BOTH warrant and keypair in context (required for PoP)
with set_warrant_context(worker_warrant), set_keypair_context(worker_keypair):
    delete_database(db_name="test-users", reason="cleanup")
    # [OK] Authorized: matches Pattern("test-*")
```

**Features:**
- `@lockdown` decorator for function-level authorization
- ContextVar support for LangChain/FastAPI integration
- Pythonic exceptions and error handling
- Delegation diff tracking with `attenuate_builder()` and audit receipts
- SIEM-compatible JSON export

See [tenuo-python/README.md](tenuo-python/README.md) and [examples](tenuo-python/examples/) for full documentation and examples.

**Delegation Diff & Audit**: See [`delegation_receipts.py`](tenuo-python/examples/delegation_receipts.py) for a comprehensive example of diff tracking, receipts, and SIEM integration.

### CLI Usage (The Manual Way)

Manage keys and issue warrants directly from your terminal.

```bash
# 1. Generate keys
tenuo keygen issuer
tenuo keygen agent

# 2. Issue a root warrant (Control Plane)
WARRANT=$(tenuo issue \
    --signing-key issuer.key \
    --holder agent.pub \
    --tool "read_file" \
    --constraint "path=pattern:/data/*" \
    --ttl 1h \
    --quiet)

# 3. Attenuate for a worker (Orchestrator)
WORKER_WARRANT=$(echo "$WARRANT" | tenuo attenuate - \
    --signing-key agent.key \
    --holder worker.pub \
    --constraint "path=exact:/data/readme.md" \
    --ttl 10m \
    --quiet)

# 4. Inspect the chain
echo "$WORKER_WARRANT" | tenuo inspect - --chain
```

See the [CLI Specification](docs/cli-spec.md) for full reference.

### Rust Core (The Performance Way)

Building a high-performance sidecar or gateway? Use the engine directly.

**Latency:** ~20μs verification. **Stack:** Pure Rust, `no_std` compatible core.

```toml
[dependencies]
tenuo-core = "0.1"
```

```rust
use tenuo_core::{Warrant, Keypair, Pattern, Range, Exact};
use std::time::Duration;

let keypair = Keypair::generate();
let warrant = Warrant::builder()
    .tool("manage_infrastructure")
    .constraint("cluster", Pattern::new("staging-*")?)
    .constraint("budget", Range::max(10000.0))  // Note: Rust uses max(), Python uses max_value()
    .ttl(Duration::from_secs(3600))
    .build(&keypair)?;

// Attenuate for a worker (capabilities shrink)
let worker_warrant = warrant.attenuate()
    .constraint("cluster", Exact::new("staging-web"))
    .constraint("budget", Range::max(1000.0))  // Note: Rust uses max(), Python uses max_value()
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
| **Depth limits** | Configurable delegation depth (max 64) |
| **Audit logging** | SIEM-compatible structured JSON events for all authorization decisions |
| **MCP integration** | Native support for Model Context Protocol (AI agent tool calling) |

## Roadmap

The following features are implemented in the core engine but not yet fully exposed in the CLI or Python SDK:

- **Multi-sig approvals**: M-of-N approval for sensitive actions
- **Cascading revocation**: Surgical (one warrant) or nuclear (entire agent swarm) revocation
- **LangGraph SecureGraph**: Automatic warrant attenuation in multi-agent graphs
- **Framework packages**: `tenuo-langchain`, `tenuo-fastapi`, `tenuo-mcp` (based on demand)

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
         │ Extracted values       │ [OK] Authorized
         │                        │   or [ERR] Denied
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

See the [MCP module documentation](https://docs.rs/tenuo-core/latest/tenuo_core/mcp/index.html) and [Python SDK examples](tenuo-python/examples/mcp_integration.py) for details.

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
- **[CLI Specification](docs/cli-spec.md)**: Complete CLI reference and examples
- **[Python SDK](tenuo-python/)**: Full Python documentation and examples
- **[Rust API](https://docs.rs/tenuo-core)**: Complete Rust API reference

## License

MIT OR Apache-2.0
