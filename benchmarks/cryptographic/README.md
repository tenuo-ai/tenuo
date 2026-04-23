# Cryptographic Security Benchmark

This benchmark suite validates Tenuo's cryptographic properties - essential
for distributed systems where trust must cross boundaries.

## Core Question

**In a distributed system, how do you verify authority without calling the
issuer's API?**

| Approach | Tradeoff |
|----------|----------|
| API call to issuer | Latency, availability dependency, coupling |
| Shared database | Consistency issues, tight coupling |
| Trust headers blindly | Insecure |
| **Tenuo warrants** | Self-contained, offline-verifiable, cryptographically bound |

## What Cryptography Provides

### 1. Cross-Boundary Verification
When Service A receives a warrant from Service B, A can verify it without
calling B's backend. The warrant is self-proving.

### 2. Portable Trust
The same warrant can be verified by any party that trusts the issuer's
public key. No shared database, no API calls, works across regions/clouds.

### 3. Holder Binding
Stolen warrants are useless. Even if an attacker intercepts a warrant in
transit, they cannot use it without the holder's private key.

### 4. Non-Repudiation
Signatures prove intent. A valid PoP signature proves the holder authorized
that specific action with those specific parameters.

### 5. Monotonic Delegation
When a warrant is delegated, the child mathematically cannot exceed the
parent's authority. Cryptographically enforced.

## Benchmark Scenarios

### 1. Warrant Forgery Resistance (`test_forgery.py`)
- Tampered warrants fail signature verification
- Stolen warrants are useless without holder key
- Cross-boundary verification works offline

### 2. Delegation Monotonicity (`test_delegation.py`)
- Child warrants cannot exceed parent's constraints
- Cannot add capabilities parent doesn't have
- Cannot extend TTL beyond parent's expiry

### 3. Key Separation (`test_key_separation.py`)
- Holder key cannot issue new warrants
- Issuer key cannot use warrants as holder
- Verifier needs no secrets (only public keys)

### 4. Temporal Enforcement (`test_temporal.py`)
- Expired warrants are rejected
- TTL cannot be extended by tampering
- Just-in-time warrants for sensitive operations

### 5. Multi-Sig Requirements (`test_multisig.py`)
- M-of-N approval thresholds are cryptographically enforced
- Each approval is signed, cannot be forged
- Supports separation of duties patterns

## Running the Benchmarks

```bash
# Run all cryptographic benchmarks
python -m pytest benchmarks/cryptographic/ -v

# Run with timing analysis
python -m pytest benchmarks/cryptographic/ -v --durations=0

# Generate security report
python -m benchmarks.cryptographic.report
```

## Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| Forgery Detection | 100% | All tampered warrants rejected |
| Delegation Enforcement | 100% | All escalation attempts blocked |
| Key Separation | 100% | All wrong-key operations rejected |
| Temporal Accuracy | 100% | All expired/future warrants rejected |
| Multi-Sig Enforcement | 100% | All threshold violations rejected |

## Performance

### Running Rust Benchmarks

Authoritative performance numbers come from the Rust Criterion benchmarks:

```bash
# From repository root
cd tenuo-core

# Run all benchmarks
cargo bench

# Run a subset (e.g. just the hot-path)
cargo bench --bench warrant_benchmarks -- warrant_verify warrant_authorize

# Generate HTML report (opens in browser)
cargo bench -- --save-baseline my-baseline
open target/criterion/report/index.html
```

### Performance Numbers (Apple M3 Max, ARM64)

| Operation | Time (mean) | What it measures |
|-----------|-------------|------------------|
| `warrant_verify` | ~36 μs | Ed25519 signature check (`verify_strict`) + TTL validation |
| `warrant_authorize` | ~36 μs | Constraint evaluation + PoP signature verification |
| `check_constraints` (no crypto) | ~138 ns (1 constraint), ~308 ns (2), ~1.54 μs (10) | Policy evaluation only: tool lookup + `ConstraintSet::matches` |
| Denial: wrong tool | ~105 ns | Early short-circuit before any crypto |
| Denial: missing PoP | ~61 ns | Absent-signature short-circuit |

Verification cost tracks the Ed25519 primitive. The switch to `verify_strict` closes signature malleability and cofactor-attack gaps that default `ed25519-dalek::verify` leaves open, at the cost of a small additional subgroup and canonical-scalar check on each verify. Over 99% of `warrant_authorize` latency is cryptography; policy evaluation itself is sub-microsecond on this hardware. Expect ~40 to 55 μs for `verify` on x86_64 server hardware. Python callers pay an additional PyO3 boundary cost on top of these Rust numbers.

**Benchmark source:** [`tenuo-core/benches/warrant_benchmarks.rs`](../../tenuo-core/benches/warrant_benchmarks.rs).

**Full benchmark suite with denial tables, delegation-depth scaling, and wire-format numbers:** [`docs/api-reference.md#performance-benchmarks`](../../docs/api-reference.md#performance-benchmarks).

## When to Use Tenuo

| Use Case | Recommendation |
|----------|----------------|
| Single service, single trust domain | Input validation sufficient |
| Cross-service calls within same org | Tenuo for audit trail |
| Cross-organization trust | Tenuo recommended |
| Offline/disconnected agents | Tenuo required |
| Compliance requiring non-repudiation | Tenuo provides cryptographic proof |

Tenuo and input validation are **complementary**: input validation for local
checks, Tenuo for distributed trust and audit trails.
