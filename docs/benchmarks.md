---
title: Benchmarks
description: Performance characteristics and methodology
---

# Performance Benchmarks

> **TL;DR:** Full authorization (verify + constraints + PoP) takes **~55μs**. Denials fail in **~200ns**. Tenuo will never be your bottleneck.

Tenuo is designed to sit on the critical path of every agent tool call. To ensure it never becomes a bottleneck, we track performance using [Criterion.rs](https://github.com/bheisler/criterion.rs).

## Methodology

Benchmarks measure the core operations of the lifecycle:
1. **Minting:** Creating and signing a warrant.
2. **Attenuation:** Cryptographically deriving a child warrant.
3. **Verification:** Checking signatures, expiration, and chain integrity.
4. **Authorization:** Validating tool arguments against constraints.

Tests were run on **Apple M3 Max** using the code in [`tenuo-core/benches/warrant_benchmarks.rs`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-core/benches/warrant_benchmarks.rs).

> **Note:** These are **microbenchmarks** measuring individual Rust operations in isolation. They represent the theoretical lower bound of Tenuo's performance. End-to-end benchmarks including Python bindings, network overhead, and integration with real agent frameworks will be published separately.

---

## Representative Results

### The Hot Path (Verification + Authorization)

This is the most critical metric. It runs on every single tool call.

| Operation | Time (mean) | Description |
|-----------|-------------|-------------|
| `warrant_verify` | **26.6 µs** | Full crypto signature check + TTL validation |
| `warrant_authorize` | **28.0 µs** | Constraint logic + Proof-of-Possession (PoP) verification |
| **Total Overhead** | **~54.6 µs** | End-to-end authorization latency (verify + authorize) |

> **Note:** The `warrant_authorize` time (~28.0µs) includes regex compilation and full argument validation. Simple checks are significantly faster.

### Denial Performance (Security-Critical)

**Fast denials prevent DoS attacks.** If authorization failures are slow, attackers can exhaust resources with invalid requests.

| Denial Type | Time (mean) | Code Path |
|-------------|-------------|-----------|
| `authorize_deny_wrong_tool` | **114 ns** | Early rejection (tool name check) |
| `authorize_deny_constraint_violation` | **192 ns** | Pattern matching failure |
| `authorize_deny_missing_pop` | **192 ns** | Missing signature check |
| `authorize_deny_invalid_pop` | **109 µs** | Cryptographic verification failure |

**Key Insights:**

1. **Wrong tool/missing PoP: ~190ns** - Fails before expensive crypto operations.
2. **Constraint violations: ~190ns** - Pattern matching is extremely fast.
3. **Invalid PoP: ~109µs** - Must verify signature to detect forgery (unavoidable crypto cost).

**Security Property:** Most attacks fail in **sub-microsecond** time, making DoS via invalid requests impractical. Only sophisticated forgery attempts (invalid PoP) trigger expensive crypto verification.

### The Control Plane (Issuance)

These operations happen asynchronously in your control plane and do not block agent execution.

| Operation | Time (mean) | Description |
|-----------|-------------|-------------|
| `warrant_create_minimal` | **13.5 µs** | Ed25519 signing (minimal warrant) |
| `warrant_create_with_constraints` | **15.5 µs** | Warrant with Pattern + Range constraints |
| `warrant_attenuate` | **30.8 µs** | Parent verification + Child signing |

### Wire Format (Serialization)

| Operation | Time (mean) | Description |
|-----------|-------------|-------------|
| `wire_encode` | **1.12 µs** | Serialization to CBOR binary format |
| `wire_decode` | **8.53 µs** | Deserialization from CBOR |
| `wire_encode_base64` | **1.42 µs** | CBOR + Base64 encoding |
| `wire_decode_base64` | **8.85 µs** | Base64 + CBOR decoding |

---

## Scaling Characteristics

### Delegation Depth

Tenuo validates the entire delegation chain. Performance cost scales linearly with chain depth.

| Chain Depth | Measured Time | Notes |
|-------------|---------------|-------|
| 1 (Root) | ~27 µs | Single warrant verification |
| 8 (Max) | **~251 µs** | Maximum allowed chain (measured) |

> **Note:** Tenuo enforces a **maximum chain length of 8** to prevent DoS attacks. The benchmark `delegation_chain_depth_8` measures the worst-case scenario at **251µs**. Performance scales approximately linearly with chain depth (~31µs per additional delegation level).

### Constraint Complexity

The `warrant_authorize` benchmark tests complex constraint sets (Patterns, Ranges).
* **Cryptographic Overhead:** ~27µs (PoP verification, unavoidable)
* **Logic Overhead:** ~1µs (Argument parsing + Constraint evaluation)

Even with complex regex constraints, the total authorization time (~28.0µs) remains negligible compared to the network latency of the tool call itself (10-100ms).

---

## Run It Yourself

We believe in reproducible benchmarks. You can run the suite on your own hardware:

```bash
# Clone the repo
git clone https://github.com/tenuo-ai/tenuo
cd tenuo/tenuo-core

# Run benchmarks
cargo bench --bench warrant_benchmarks
```

Criterion will output an HTML report at `target/criterion/report/index.html`. Open that file to see detailed performance analysis, including:
- Mean execution time
- Standard deviation
- Outlier detection
- Performance regression detection

Full benchmark source code is available in [`warrant_benchmarks.rs`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-core/benches/warrant_benchmarks.rs).

---

## Performance Considerations

### What's Fast

- **Verification:** ~27µs for signature + TTL check
- **Authorization:** ~28µs for constraints + PoP verification
- **Denials:** **~190ns** for most rejection paths (wrong tool, missing PoP, constraint violations)
- **Wire encoding:** ~1µs (CBOR is efficient)

### What's Slower (But Still Fast)

- **Invalid PoP denial:** ~109µs (must verify signature to detect forgery)
- **Attenuation:** ~31µs (parent verification + child signing)
- **Wire decoding:** ~9µs (CBOR parsing + validation)
- **Deep delegation chains:** ~251µs for max depth of 8

### DoS Resistance

**Tenuo is designed to resist denial-of-service attacks:**

1. **Fast-fail on invalid requests:** Wrong tool names and missing PoP signatures are rejected in **~200 nanoseconds**, before expensive crypto operations.
2. **Constraint violations are cheap:** Pattern matching failures cost ~200ns, making it impractical to DoS via constraint violations.
3. **Only sophisticated attacks are expensive:** Invalid PoP signatures (forgery attempts) cost ~113µs to detect, but this is unavoidable—you must verify the signature to know it's invalid.

**Attack cost analysis:**
- Sending 1 million invalid tool names: ~200ms total (negligible)
- Sending 1 million forged PoP signatures: ~113 seconds (expensive for attacker, but still manageable for defender)

### Design Tradeoffs

Tenuo prioritizes **security over raw speed**:

1. **Mandatory PoP:** Every tool call requires proof-of-possession, adding ~28µs of cryptographic overhead. This prevents warrant theft attacks.
2. **Full chain validation:** We verify the entire delegation chain, not just the leaf warrant. This ensures cryptographic integrity at every level.
3. **Canonical CBOR:** We enforce deterministic serialization to prevent TOCTOU attacks, adding validation overhead during deserialization.

Even with these security measures, **~55µs total latency** is negligible compared to:
- LLM inference: **100-1000ms** (1,400x - 14,000x slower)
- Network I/O: **10-100ms** (140x - 1,400x slower)
- Database queries: **1-10ms** (14x - 140x slower)

Tenuo will never be your bottleneck.

---

## Hardware Notes

These benchmarks were run on **Apple M3 Max** (ARM64 architecture). Performance on x86_64 (Intel/AMD) should be comparable, as Ed25519 signature verification is highly optimized on both architectures.

For production deployments, we recommend:
- **Cloud:** AWS Graviton3 (c7g), GCP T2A, Azure Dpsv5
- **On-prem:** Any modern CPU (2020+)

Tenuo's Rust core is `no_std` compatible and can run in resource-constrained environments (embedded systems, WASM, etc.).

---

## See Also

- [Architecture](./protocol.md) — How warrants work
- [Security Model](./security.md) — Why PoP is mandatory
- [Integration Guide](./quickstart.md) — Getting started
