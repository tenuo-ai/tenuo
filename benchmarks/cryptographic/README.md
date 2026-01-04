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

Core cryptographic operations are benchmarked in Rust using Criterion:

```bash
cd tenuo-core && cargo bench
```

Typical results:

| Operation | Latency |
|-----------|---------|
| Full verification (PoP + constraints) | ~27μs |
| Constraint evaluation only | ~100ns |
| Denial (wrong tool) | ~150ns |
| Wire encode/decode | ~5μs |

The ~27μs verification time is the end-to-end cost including signature verification,
constraint matching, and TTL checks. Denials are faster because they short-circuit.

Quick Python timing:

```python
import time
from tenuo import SigningKey, Warrant, Range

key = SigningKey.generate()
w = Warrant.mint_builder().capability("test", x=Range(0, 100)).ttl(60).mint(key)
sig = w.sign(key, "test", {"x": 50})

start = time.perf_counter()
for _ in range(1000):
    w.authorize("test", {"x": 50}, bytes(sig))
elapsed = (time.perf_counter() - start) / 1000 * 1_000_000
print(f"Verification: {elapsed:.1f}μs")
```

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
