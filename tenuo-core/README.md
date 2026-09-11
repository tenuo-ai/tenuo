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
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    Authorizer, Constraint, ConstraintSet, ConstraintValue, Pattern, SigningKey, Warrant,
};

let issuer_key = SigningKey::generate();
let holder_key = SigningKey::generate();

let mut constraints = ConstraintSet::new();
constraints.insert(
    "path",
    Constraint::Pattern(Pattern::new("/data/*").expect("pattern")),
);
let warrant = Warrant::builder()
    .capability("read_file", constraints)
    .holder(holder_key.public_key())
    .ttl(Duration::from_secs(300))
    .build(&issuer_key)
    .expect("mint");

let mut authorizer = Authorizer::new();
authorizer.add_trusted_root(issuer_key.public_key());
let mut args = HashMap::new();
args.insert(
    "path".into(),
    ConstraintValue::String("/data/report.txt".into()),
);
let pop = warrant
    .sign(&holder_key, "read_file", &args)
    .expect("pop");
authorizer
    .authorize_one(&warrant, "read_file", &args, Some(&pop), &[])
    .expect("authorize");
```

## Rust SDK (`sdk` feature)

Default-off. `Guard` enforces; `ObservingGuard` only assesses and is not a substitute.

```rust
# #[cfg(feature = "sdk")]
# {
use std::collections::HashMap;
use std::time::Duration;
use tenuo::sdk::prelude::*;
use tenuo::{ConstraintSet, Warrant};

let issuer = SigningKey::generate();
let holder = SigningKey::generate();
let warrant = Warrant::builder()
    .capability("read_file", ConstraintSet::new())
    .holder(holder.public_key())
    .ttl(Duration::from_secs(300))
    .build(&issuer)
    .expect("mint");

let runtime = Runtime::builder()
    .holder(holder)
    .trusted_root(issuer.public_key())
    .revocation(RevocationMode::TtlOnly {
        max_lifetime: Duration::from_secs(600),
    })
    .build()
    .expect("runtime");
let session = runtime.session_from_warrant(warrant).expect("session");
let args = HashMap::new();
let call = Call::borrowed("read_file", &args);
let out = session
    .guard(&call, |_| Ok::<_, &str>("read"))
    .expect("allow");
assert_eq!(out.into_inner(), "read");
# }
```

An enforcement point uses `Tenuo::enforcement()` and `Guard::guard_received` on a `ReceivedAuthorization` decoded from `_meta.tenuo` or HTTP headers. The holder path always signs; the received path never does.

A long-lived process that receives warrants over time uses `Runtime`: persist
the holder key, apply signed revocation lists as they arrive, and bind each
warrant into a `Session`. `Tenuo::local` is deprecated.

```rust
# #[cfg(feature = "sdk")]
# {
use std::collections::HashMap;
use std::time::Duration;
use tenuo::sdk::prelude::*;
use tenuo::{ConstraintSet, Warrant};

let issuer = SigningKey::generate();
let holder = SigningKey::generate();
let warrant = Warrant::builder()
    .capability("read", ConstraintSet::new())
    .holder(holder.public_key())
    .ttl(Duration::from_secs(300))
    .build(&issuer)
    .expect("mint");
let runtime = Runtime::builder()
    .holder(holder)
    .trusted_root(issuer.public_key())
    .ttl_fallback(Duration::from_secs(600))
    .build()
    .expect("runtime");
let session = runtime.session_from_warrant(warrant).expect("session");
let args = HashMap::new();
assert!(session
    .diagnostics()
    .why_denied(&Call::borrowed("write", &args))
    .is_some());
# }
```
```

Receipt collection needs the `receipts` feature: set
`evidence_policy(EvidencePolicy::BestEffort)`, then `peek_receipts` /
`drain_receipts` (same snapshot) and `acknowledge_receipts` to drop uploaded
items.

Callers that obtain warrants and SRLs over the network should not assemble `Authorizer`, `PresentedAuthority`, `LocalReceiptSigner`, or `MemoryReceiptSink`.

| Feature | Description |
|---------|-------------|
| `sdk` | Guard, Call, delegation, observe, Runtime / Session |
| `mcp-transport` | `params._meta.tenuo` encode/decode |
| `http-transport` | Signed header binding |
| `receipts` | Authorization receipts (draft `receipt-v1`) |
| `async` | Async Guard methods and `AttemptControl` |
| `otel` | OpenTelemetry API spans only; no exporter |
| `test-utils` | `FixedClock` and `sdk::test_utils` scaffolding — not for production |

Run the MCP hop and runtime demos:

```bash
cd tenuo-core && cargo run --example sdk_mcp_demo --features sdk,mcp-transport
cd tenuo-core && cargo run --example sdk_runtime --features sdk,receipts
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
