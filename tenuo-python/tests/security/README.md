# Security Test Suite

Adversarial tests verifying Tenuo's security properties.

## Quick Verification

```bash
# Verify all security properties in 30 seconds
pytest tests/security/ -v --tb=short

# Expected: 39 passed, 0 failed
```

## Running

```bash
# Run all security tests
pytest tests/security/ -v

# Run specific category
pytest tests/security/test_signature_trust.py -v

# Run with verbose output
pytest tests/security/ -v -s

# Run only integration responsibility tests (expected to document, not fail)
pytest tests/security/ -m integration_responsibility -v
```

## Categories

| Category | File | Tests | Status |
|----------|------|-------|--------|
| Signature/Trust | `test_signature_trust.py` | 5 | ✅ All pass |
| Monotonicity | `test_monotonicity.py` | 11 | ✅ All pass |
| PoP Binding | `test_pop_binding.py` | 5 | ✅ All pass |
| Delegation Limits | `test_delegation_limits.py` | 6 | ✅ All pass |
| Implementation | `test_implementation.py` | 7 | ✅ All pass |
| Edge Cases | `test_edge_cases.py` | 5 | ✅ All pass |

## Test Markers

```python
@pytest.mark.security           # All security tests
@pytest.mark.signature          # Signature/trust verification
@pytest.mark.monotonicity       # Capability attenuation rules  
@pytest.mark.pop                # Proof-of-Possession binding
@pytest.mark.delegation         # Delegation depth/chain limits
@pytest.mark.implementation     # Implementation-level bypasses
@pytest.mark.integration_responsibility  # App responsibilities (not Tenuo bugs)
```

## Critical Security Properties Verified

### ✅ Cryptographic Guarantees
1. **Signature verification** - Warrants signed by attacker keys rejected
2. **Root trust** - Only trusted roots accepted by Authorizer
3. **Holder binding** - PoP signature requires correct keypair
4. **PoP binding** - Signature covers (tool, args, timestamp)

### ✅ Monotonicity Guarantees  
1. **Tool narrowing** - Cannot add tools not in parent
2. **Constraint narrowing** - Cannot widen Pattern, Range, OneOf
3. **Type safety** - Cannot change constraint types
4. **TTL shrinking** - Cannot extend expiration
5. **No re-widening** - Cannot attenuate back to Wildcard

### ✅ Delegation Limits
1. **Depth limit** - MAX_DELEGATION_DEPTH (64) enforced
2. **Chain limit** - MAX_ISSUER_CHAIN_LENGTH (8) enforced
3. **Terminal warrants** - Cannot delegate further
4. **Issuer/Execution separation** - Each type has distinct capabilities

### ✅ Extraction Security
1. **Default inclusion** - Default parameter values always checked
2. **Complete extraction** - All parameters extracted automatically
3. **Fail-closed** - Extraction failures deny authorization

### ⚠️ Application Responsibilities

These are documented by `@pytest.mark.integration_responsibility` tests:

1. **Wrapper usage** - Must call `warrant.authorize()` 
2. **Root trust** - Must use Authorizer with trusted_roots
3. **Path canonicalization** - Must resolve `..` before authorization
4. **Node coverage** - Must wrap ALL nodes in LangGraph
5. **Nonce/idempotency** - App-level for replay prevention

## Contributing

Found an attac scenario we missed? Please:

1. Open an issue with `[SECURITY]` prefix
2. Or submit a PR with a failing test

See [SECURITY.md](../../SECURITY.md) for responsible disclosure.

## Expected Results

- **Most tests should PASS** (attacks are blocked by Tenuo)
- **`integration_responsibility` tests** document app-level concerns
- **Info messages** explain expected behavior or limitations

## Adding New Attack Scenarios

1. Create test in appropriate category file
2. Add `@pytest.mark.security` and category marker
3. Print attack description and result
4. Use `pytest.raises()` for expected failures
5. Document in this README

## Rust-Level Tests

Some attacks require binary manipulation and are tested at the Rust level:

- **ChainLink tampering** - `tenuo-core/tests/red_team.rs`
- **CBOR payload tampering** - `tenuo-core/tests/red_team.rs`

See [tenuo-core/tests/red_team.rs](../../tenuo-core/tests/red_team.rs) for those tests.
