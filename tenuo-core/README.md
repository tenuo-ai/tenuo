# tenuo

Cryptographic authorization primitive for AI agents.

[![Crates.io](https://img.shields.io/crates/v/tenuo.svg)](https://crates.io/crates/tenuo)
[![docs.rs](https://docs.rs/tenuo/badge.svg)](https://docs.rs/tenuo)

## Overview

Tenuo implements **capability tokens** (Warrants) for AI agent authorization:

- **Offline verification** in ~27μs - no network calls
- **Monotonic attenuation** - delegated tokens can only shrink in scope
- **Proof-of-possession** - stolen tokens are useless without the private key
- **Constraint types** - `Exact`, `Pattern`, `Range`, `OneOf`, `Regex`, `Wildcard`

## Quick Start

```rust
use tenuo_core::{SigningKey, Warrant, Constraint, Authorizer};

// Generate keys
let issuer_key = SigningKey::generate();
let holder_key = SigningKey::generate();

// Issue a warrant
let warrant = Warrant::builder()
    .tool("read_file")
    .constraint("path", Constraint::pattern("/data/*"))
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

MIT OR Apache-2.0
