# Tenuo

**Capability tokens for AI agents**

[![Crate](https://img.shields.io/crates/v/tenuo-core.svg)](https://crates.io/crates/tenuo-core)
[![Docs](https://docs.rs/tenuo-core/badge.svg)](https://docs.rs/tenuo-core)

Tenuo provides cryptographically-enforced capability attenuation for AI agent workflows. Warrants can only **shrink** when delegated : a $1000 budget becomes $500, access to `staging-*` narrows to `staging-web`. Verification is 100% offline in ~25μs.

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

## Quick Start

```bash
# Run the multi-agent demo
docker compose up orchestrator worker
```

Or add to your Rust project:

```toml
[dependencies]
tenuo-core = "0.1"
```

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

### Revocation

Warrants can be revoked using **Signed Revocation Lists (SRLs)**. The Control Plane signs the list; authorizers verify before trusting.

```rust
// Request revocation (issuer, holder, or admin)
let request = RevocationRequest::new(warrant.id(), "Compromised", &keypair)?;

// Control Plane validates and builds SRL
let srl = SignedRevocationList::builder()
    .revoke(warrant.id())
    .version(1)
    .build(&control_plane_keypair)?;

// Authorizer loads (verifies signature)
authorizer.set_revocation_list(srl, &control_plane_key)?;
```

**Cascading Revocation:**
- **Surgical**: Revoke a specific warrant ID to stop one task
- **Nuclear**: Revoke an agent's key to instantly invalidate every warrant they ever issued (kill 10,000 sub-agents with one switch)

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

### Gateway Configuration

Tenuo provides a YAML-based configuration system for extracting constraint values from HTTP requests:

```yaml
tools:
  manage_infrastructure:
    constraints:
      cluster:
        from: path
        path: "cluster"
        required: true
      cost:
        from: body
        path: "metadata.estimatedCost"
        type: float
```

The authorizer HTTP server automatically:
1. Matches routes using radix trees (O(log n))
2. Extracts values from path, query, headers, and JSON body
3. Verifies warrant chains
4. Authorizes actions using extracted constraints

See [examples/gateway-config.yaml](examples/gateway-config.yaml) for a complete example.

### MCP (Model Context Protocol) Integration

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

```yaml
# mcp-config.yaml
version: "1"
settings:
  trusted_issuers:
    - "f32e74b5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8"

tools:
  filesystem_read:
    description: "Read files from the filesystem"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576
```

**Why MCP + Tenuo?**
- **Tool-centric**: MCP tools map directly to Tenuo tool configurations (no HTTP routing complexity)
- **Cryptographic provenance**: Every tool call is authorized by a warrant chain proving who delegated authority
- **Multi-agent workflows**: Perfect for orchestrators delegating to specialized workers with bounded capabilities

```rust
use tenuo_core::{Authorizer, CompiledMcpConfig, McpConfig, PublicKey};
use serde_json::json;
use std::collections::HashMap;

// Load MCP configuration
let config = McpConfig::from_file("mcp-config.yaml")?;
let compiled = CompiledMcpConfig::compile(config);

// Initialize authorizer with trusted Control Plane key
let control_plane_key_bytes: [u8; 32] = hex::decode("f32e74b5...")?.try_into().unwrap();
let control_plane_key = PublicKey::from_bytes(&control_plane_key_bytes)?;
let authorizer = Authorizer::new(control_plane_key);

// MCP tool call arrives
let arguments = json!({ "path": "/var/log/app.log", "maxSize": 1024 });

// 1. Extract constraints from MCP arguments
let result = compiled.extract_constraints("filesystem_read", &arguments)?;

// 2. Decode warrant chain (from MCP request metadata)
let warrant = wire::decode_base64(&warrant_chain_base64)?;

// 3. Authorize the action
authorizer.check(
    &warrant,
    "filesystem_read",
    &result.constraints,
    pop_signature.as_ref()
)?;

// 4. If authorized, execute the tool
// execute_filesystem_read(arguments);
```

See the [MCP module documentation](https://docs.rs/tenuo-core/latest/tenuo_core/mcp/index.html) for details.

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and infographics
- **[Guide](https://tenuo.github.io/tenuo/guide/)**: Concepts and examples
- **[API Reference](https://docs.rs/tenuo-core)**: Rustdoc API documentation

## Security

| Property | Protection |
|----------|------------|
| Domain separation | Signatures include context prefix |
| Canonical encoding | Deterministic serialization |
| Constraint depth | Max 16 nesting levels |
| Payload size | Max 1MB per warrant |
| PoP replay | Signatures valid ~2 minutes |
| ID validation | Prefix enforced on deserialize |

## Python SDK

Python bindings are available via PyO3:

```bash
pip install tenuo
```

```python
from tenuo import Keypair, Warrant, Pattern, Range

# Generate a keypair
keypair = Keypair.generate()

# Issue a warrant
warrant = Warrant.create(
    tool="manage_infrastructure",
    constraints={
        "cluster": Pattern("staging-*"),
        "budget": Range.max_value(10000.0)
    },
    ttl_seconds=3600,
    keypair=keypair
)

# Attenuate for a worker
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
```

**Pythonic features:**
- `@lockdown` decorator for function-level authorization
- ContextVar support for LangChain/FastAPI integration
- Pythonic exceptions and error handling

See [tenuo-python/](tenuo-python/) for full documentation and examples.

## License

MIT OR Apache-2.0
