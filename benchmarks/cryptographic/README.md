# Cryptographic Security Benchmark

This benchmark suite demonstrates Tenuo's **cryptographic value proposition** - 
properties that input validation alone cannot provide.

## Why This Matters

Traditional "if statement" validation can be:
- Bypassed if the validation code is compromised
- Tampered with at runtime
- Inconsistent across distributed systems
- Subject to race conditions with mutable state

Tenuo's cryptographic approach provides:
- **Unforgeable constraints** - tampered warrants fail signature verification
- **Key separation** - different principals, different keys
- **Monotonic delegation** - child warrants can't exceed parent
- **Stateless verification** - no database, no race conditions
- **Portable trust** - any party can verify independently

## Benchmark Scenarios

### 1. Warrant Forgery Resistance (`test_forgery.py`)
Attacker attempts to:
- Modify constraints in a valid warrant
- Create warrants with unauthorized keys
- Replay warrants with altered capabilities

Expected: 100% detection rate

### 2. Delegation Monotonicity (`test_delegation.py`)
Tests that delegated warrants:
- Cannot exceed parent's constraints
- Cannot add new capabilities
- Cannot extend TTL beyond parent
- Cannot change holder without re-signing

Expected: 100% enforcement

### 3. Key Separation (`test_key_separation.py`)
Tests that:
- Holder key cannot issue new warrants
- Wrong key PoP signatures are rejected
- Stolen warrants are useless without holder key

Expected: 100% rejection of invalid keys

### 4. Temporal Enforcement (`test_temporal.py`)
Tests that:
- Expired warrants are rejected
- Future-dated warrants are rejected
- TTL cannot be extended by tampering

Expected: 100% temporal enforcement

### 5. Multi-Sig Requirements (`test_multisig.py`)
Tests that:
- M-of-N approval requirements are enforced
- Partial approvals are rejected
- Approval signatures are verified

Expected: 100% threshold enforcement

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
| Verification Latency | <1ms | P99 verification time |

## Comparison with Input Validation

This benchmark includes a "baseline" that uses Python if-statements for the same
checks. The key difference:

| Property | If-Statements | Tenuo |
|----------|---------------|-------|
| Tamper-proof | ❌ Code can be modified | ✅ Cryptographic |
| Portable | ❌ Each service reimplements | ✅ Verify anywhere |
| Auditable | ❌ Logs can be forged | ✅ Signatures prove intent |
| Stateless | ❌ Often needs DB lookup | ✅ Self-contained |
| Delegation | ❌ Trust hierarchy unclear | ✅ Monotonic by design |

