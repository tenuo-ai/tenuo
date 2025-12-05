# Tenuo

**Capability tokens for AI agents**

[![Crate](https://img.shields.io/crates/v/tenuo-core.svg)](https://crates.io/crates/tenuo-core)
[![Docs](https://docs.rs/tenuo-core/badge.svg)](https://docs.rs/tenuo-core)

Tenuo provides cryptographically-enforced capability attenuation for AI agent workflows. Warrants can only **shrink** when delegated — a $1000 budget becomes $500, access to `staging-*` narrows to `staging-web`. Verification is 100% offline in ~25μs.

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

## Key Features

| Feature | Description |
|---------|-------------|
| **Monotonic attenuation** | Capabilities only shrink, never expand |
| **Offline verification** | No network calls, ~25μs latency |
| **Holder binding** | Warrants bound to keys, stolen tokens useless |
| **Multi-sig approvals** | M-of-N approval for sensitive actions |
| **Depth limits** | Configurable delegation depth (max 64) |

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
The Data Plane (gateway or sidecar) verifies locally — no round-trips.

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)** — Landing page and infographics
- **[Docs](https://tenuo.github.io/tenuo/reference/)** — Concepts, guides, and examples
- **[API Reference](https://docs.rs/tenuo-core)** — Full Rust API documentation

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

Coming soon: [tenuo-python](https://github.com/tenuo/tenuo-python)

## License

MIT OR Apache-2.0
