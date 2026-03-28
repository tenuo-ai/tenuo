# Security Test Suite

Adversarial tests verifying Tenuo's security properties.

## Quick Verification

```bash
# Verify all security properties in ~60 seconds
pytest tests/security/ -v --tb=short

# Expected: 155 passed, ~14 skipped, 0 failed
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
| PoP Binding | `test_pop_binding.py` | 6 | ✅ All pass |
| Delegation Limits | `test_delegation_limits.py` | 6 | ✅ All pass |
| Implementation | `test_implementation.py` | 9 | ✅ All pass |
| Edge Cases | `test_edge_cases.py` | 6 | ✅ All pass |
| **Integration Invariants** | **`test_integration_invariants.py`** | **~130** | **✅ All pass** |
| **Security Contracts** | **`test_security_contracts.py`** | **17** | **✅ All pass** |

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

### ✅ Integration-Level Invariants (test_integration_invariants.py)

These tests exercise the **full integration stack** with real `tenuo_core` cryptographic
objects — no mocked signing keys or fake warrants.  Every bug found in a post-mortem
must produce a failing test here before the fix is merged.

| Invariant | Description | Integrations covered |
|-----------|-------------|----------------------|
| I1 | No warrant → always denied | All 10 integrations (cross-matrix) |
| I2 | Expired warrant → always denied | All 10 integrations (cross-matrix) |
| I3 | Untrusted issuer → denied | A2A, FastAPI |
| I4 | Self-signed warrant → denied | A2A, CrewAI, Google ADK |
| I5 | Delegation chain + PoP → **ALLOWED** | A2A, FastAPI |
| I6 | Broken chain linkage → denied | A2A |
| I7 | Wrong tool → denied | All 10 integrations (cross-matrix), Temporal (dedicated) |
| I8 | Constraint violation → denied | A2A, CrewAI, FastAPI, LangChain |
| I9 | No trusted_issuers → SecurityWarning | FastAPI (regression Bug 1) |

### ✅ Security Contracts (test_security_contracts.py)

Tests that verify **configuration knob contracts** — what happens when you change
`on_denial`, `require_warrant`, or `dry_run`.  Prevents silent security degradation
from misconfiguration.

| Contract | Description | Integrations covered |
|----------|-------------|----------------------|
| C2 | `on_denial=log/skip`: tool NOT executed, denial returned | CrewAI, AutoGen, Google ADK, Temporal |
| C3a | `require_warrant=False` + bad warrant → still denied | A2A, MCP |
| C3b | Safe defaults: zero-config is fail-closed | A2A, MCP, CrewAI, AutoGen |
| C3c | `dry_run=False` by default; shadow mode must be explicit | Temporal |

**Regression tests** (`TestRegressions`): one test per production bug, named after
the bug.  If a regression test fails it means a previously-fixed security issue was
re-introduced.

**Adding a new integration**: append its `_XxxAdapter` class to `_ADAPTERS` in
`TestCrossIntegrationMatrix` and it automatically runs I7 (wrong tool / correct tool).
Add integration-specific invariants as a new `TestXxxInvariants` class.

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
2. **Terminal warrants** - Cannot delegate further (max_depth=0)
3. **Issuer/Execution separation** - Each type has distinct capabilities

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

For core warrant invariants:

1. Create test in appropriate category file
2. Add `@pytest.mark.security` and category marker
3. Use `pytest.raises()` for expected failures
4. Document in this README

For integration-level invariants (use this workflow for every new integration bug):

1. **Write the failing test first** in `test_integration_invariants.py` under `TestRegressions`
2. Name the test `test_regression_bugN_short_description`
3. The test body must reproduce the exact attack scenario using real `tenuo_core` objects
4. **Commit the failing test** — this proves the test actually catches the bug
5. Fix the implementation, verify the test now passes
6. Optionally promote the invariant to the appropriate `TestXxxInvariants` class

## Rust-Level Tests

Some attacks require binary manipulation and are tested at the Rust level:

- **ChainLink tampering** - `tenuo-core/tests/red_team.rs`
- **CBOR payload tampering** - `tenuo-core/tests/red_team.rs`

See [tenuo-core/tests/red_team.rs](../../tenuo-core/tests/red_team.rs) for those tests.
