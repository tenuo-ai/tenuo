# tenuo

Cryptographic authorization primitive for AI agents.

[![Crates.io](https://img.shields.io/crates/v/tenuo.svg)](https://crates.io/crates/tenuo)
[![docs.rs](https://docs.rs/tenuo/badge.svg)](https://docs.rs/tenuo)

> **Status: v0.2 — Production/Stable.** Core semantics are stable. See [CHANGELOG](../CHANGELOG.md).

## Overview

Tenuo implements **capability tokens** (Warrants) for AI agent authorization:

- **Offline verification** in under 50 μs - no network calls
- **Monotonic attenuation** - delegated tokens can only shrink in scope
- **Proof-of-possession** - stolen tokens are useless without the private key
- **Constraint types** - `Exact`, `Pattern`, `Range`, `OneOf`, `Regex`, `Wildcard`, `CEL`, `UrlPattern`, `Cidr`
- **Multi-sig approvals** - M-of-N cryptographic approval requirements

## Quick Start

```rust
use tenuo::{SigningKey, Warrant, Constraint, ConstraintSet, Authorizer};

// Generate keys
let issuer_key = SigningKey::generate();
let holder_key = SigningKey::generate();

// Issue a warrant
let warrant = Warrant::builder()
    .capability("read_file", ConstraintSet::new().insert("path", Constraint::pattern("/data/*")))
    .holder(holder_key.public_key())
    .ttl_secs(300)
    .build(&issuer_key)?;

// Verify and authorize
let authorizer = Authorizer::new(vec![issuer_key.public_key()]);
authorizer.verify_and_authorize(
    &warrant,
    "read_file",
    &[("path", "/data/report.txt")],
    Some(&holder_key.create_pop(&warrant, "read_file", &args)?),
)?;
```

## Rust SDK (`sdk` feature)

Default-off. `Guard` enforces; `ObservingGuard` only assesses and is not a substitute.

```rust
use tenuo::{args, Call, RevocationMode, Tenuo};
use std::time::Duration;

let (guard, authority) = Tenuo::local()
    .trusted_root(root)
    .chain(chain)
    .signer(holder_key)
    .revocation(RevocationMode::TtlOnly { max_lifetime: Duration::from_secs(300) })
    .build()?;

let args = args! { "path" => "/data/report.txt" };
let call = Call::borrowed("read_file", &args);
guard.guard(&authority, &call, |_authorized| do_read())?;
```

An enforcement point uses `Tenuo::enforcement()` and `Guard::guard_received` on a `ReceivedAuthorization` decoded from `_meta.tenuo` or HTTP headers. The holder path always signs; the received path never does.

| Feature | Description |
|---------|-------------|
| `sdk` | Guard, Call, delegation, observe |
| `mcp-transport` | `params._meta.tenuo` encode/decode |
| `http-transport` | Signed header binding |
| `receipts` | Authorization receipts (draft `receipt-v1`) |
| `async` | Async Guard methods and `AttemptControl` |
| `otel` | OpenTelemetry API spans only; no exporter |
| `test-utils` | `FixedClock` and `sdk::test_utils` scaffolding — not for production |

Run the MCP hop demo:

```bash
cd tenuo-core && cargo run --example sdk_mcp_demo --features sdk,mcp-transport
```

## Features

| Feature | Description |
|---------|-------------|
| `control-plane` | Warrant issuance (default) |
| `data-plane` | Warrant verification (default) |
| `python` | PyO3 bindings |
| `server` | HTTP server dependencies |

## Use Cases

- **Sidecar authorizer** - Verify warrants at the edge
- **Gateway integration** - Envoy/Istio external authorization
- **Embedded verification** - In-process authorization checks

## Documentation

- [tenuo.ai](https://tenuo.ai) - Full documentation
- [docs.rs/tenuo](https://docs.rs/tenuo) - API reference
- [GitHub](https://github.com/tenuo-ai/tenuo) - Source code

## License

Apache-2.0. See [LICENSE](../LICENSE) for details.
