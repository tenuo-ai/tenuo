# Red Team Test Suite Summary

## Overview

The `red_team.py` file contains **38 adversarial security tests** designed to break Tenuo's authorization model. Each test simulates a real attack scenario and verifies that Tenuo's defenses hold.

## Test Coverage by Category

### 1. Signature/Trust Attacks (6 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_1` | State tampering (swap warrant) | Signature verification fails |
| `test_attack_1b` | Replay expired warrant | TTL enforcement blocks |
| `test_attack_4` | Untrusted root acceptance | Root trust check fails |
| `test_attack_4b` | Self-verification bypass | Application must check trusted roots |
| `test_attack_33` | Self-signed warrant as root | Authorizer rejects untrusted root |
| `test_attack_36` | Session ID reuse | Session is metadata only, not authorization |

**Critical Properties Tested:**
- ✅ Signatures must be verified against trusted roots
- ✅ Self-signed warrants rejected without explicit trust
- ✅ Expired warrants rejected

---

### 2. Isolation Attacks (2 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_2` | Context leak to threads | ContextVar isolation (threads don't inherit) |
| `test_attack_8` | Dynamic node bypass | Integration responsibility (fail-closed design) |

**Critical Properties Tested:**
- ✅ ContextVars don't leak across threads by default
- ⚠️ Applications must wrap ALL nodes (integration security)

---

### 3. Monotonicity Attacks (11 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_3` | Constraint widening (Pattern) | PatternExpanded error |
| `test_attack_3b` | Add unauthorized tools | MonotonicityError |
| `test_attack_12` | Constraint removal | Constraints inherited |
| `test_attack_23` | CEL injection (bypass parent) | Must be `(parent) && X` format |
| `test_attack_26` | Change constraint type | IncompatibleConstraintTypes |
| `test_attack_27` | Revert to Wildcard | WildcardExpansion error |
| `test_attack_28` | Extend TTL | MonotonicityError |
| `test_attack_34` | OneOf→NotOneOf paradox | EmptyResultSet detected |
| `test_attack_37` | NotOneOf without positive | Legal but discouraged |
| `test_attack_38` | Contains/Subset confusion | Incompatible types |
| `test_attack_11` | Tool wildcard exploitation | Not applicable (no wildcard syntax) |

**Critical Properties Tested:**
- ✅ Capabilities can only shrink (monotonic attenuation)
- ✅ Type changes rejected
- ✅ Re-widening blocked (Pattern→Wildcard, Range expansion)
- ✅ CEL syntactic monotonicity enforced
- ✅ Empty result sets detected

---

### 4. PoP (Proof-of-Possession) Attacks (5 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_6` | Replay PoP signature | Short TTL + nonce (app-level) |
| `test_attack_7` | Stolen warrant (wrong holder) | PoP signature fails for wrong keypair |
| `test_attack_13` | PoP tool swap | Signature binds to tool name |
| `test_attack_14` | PoP args swap | Signature binds to args |
| `test_attack_35` | Replay after window expires | ~120s timestamp window enforced |

**Critical Properties Tested:**
- ✅ PoP binds warrant to holder (stolen warrants useless)
- ✅ Signature covers (tool, args, timestamp window)
- ✅ Replay prevented within window via timestamp

**Note:** Tests 13-14 now use `create_pop_signature()` API to verify binding.

---

### 5. Delegation Limit Attacks (5 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_9` | Delegate-to-self amplification | DepthExceeded at MAX_DELEGATION_DEPTH (64) |
| `test_attack_18` | Chain length DoS | Depth limit enforced |
| `test_attack_25` | Depth vs chain confusion | Separate limits for execution/issuer |
| `test_attack_29` | Execution warrant issues | ValidationError (only issuer can issue) |
| `test_attack_30` | Issuer warrant executes | ValidationError (issuer cannot execute) |
| `test_attack_31` | Terminal warrant delegates | DepthExceeded (max_depth reached) |

**Critical Properties Tested:**
- ✅ MAX_DELEGATION_DEPTH = 64 enforced
- ✅ MAX_ISSUER_CHAIN_LENGTH = 8 enforced
- ✅ Issuer/Execution warrant separation
- ✅ Terminal warrants cannot delegate

---

### 6. Implementation Bypass Attacks (7 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_10` | Buggy wrapper (skip authorize) | Demo vulnerability if wrapper bypasses |
| `test_attack_15` | Type coercion (string vs int) | Type-safe comparison |
| `test_attack_16` | Serialization injection | Signature covers full payload |
| `test_attack_22` | TOCTOU (payload_bytes) | Rust binds payload_bytes to payload |
| `test_attack_24` | Path traversal in constraints | Pattern is literal (apps must canonicalize paths) |
| `test_attack_32` | Default value bypass | Defaults ALWAYS included in extraction |
| `test_attack_19` | Constraint key injection | Keys matched exactly (safe for Tenuo) |

**Critical Properties Tested:**
- ✅ Automatic extraction includes defaults
- ✅ Authorization checks all parameters
- ⚠️ Applications must use `authorize()` correctly
- ⚠️ Applications must canonicalize paths before checking

---

### 7. Edge Case Attacks (3 tests)
| Test | Attack | Expected Defense |
|------|--------|------------------|
| `test_attack_17` | Clock skew exploitation | Strict expiry (no tolerance in v0.1) |
| `test_attack_20` | Unicode normalization | Byte-wise comparison (no normalization) |
| `test_attack_5` | Issuer warrant abuse | Cannot authorize execution |

**Critical Properties Tested:**
- ✅ Expiration strictly enforced
- ℹ️ Unicode: Byte-wise comparison (safe but strict)

---

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
1. **Wrapper usage** - Must call `warrant.authorize()` 
2. **Root trust** - Must use Authorizer with trusted_roots
3. **Path canonicalization** - Must resolve .. before authorization
4. **Nonce/idempotency** - App-level for replay prevention

---

## Missing Tests (Would Require Binary Manipulation)

1. **ChainLink tampering** - Modify embedded issuer scope without breaking signature
2. **CBOR payload tampering** - Craft payload where payload_bytes ≠ canonical(payload)

These are tested at the Rust level but hard to test from Python without binary serialization access.

---

## How to Run

```bash
# Run all red team tests
pytest tenuo-python/red_team.py -v -s

# Run specific attack
pytest tenuo-python/red_team.py::TestRedTeam::test_attack_7_holder_mismatch -v -s

# Run with coverage
pytest tenuo-python/red_team.py --cov=tenuo --cov-report=html
```

## Expected Results

- **Most tests should PASS** (attacks are blocked)
- **Warnings indicate potential vulnerabilities** that need review
- **Info messages** explain expected behavior or limitations

## Adding New Attack Scenarios

1. Create test method: `test_attack_N_description`
2. Print attack category and description
3. Simulate attack using Tenuo API
4. Use `pytest.raises()` for expected failures
5. Print result with ✅/⚠️/ℹ️ emoji
6. Document in this summary

---

## Attack Scenarios Not Covered (Intentional)

1. **Network-level attacks** - Tenuo is authorization, not networking (use TLS)
2. **Side-channel attacks** - Timing, cache (low priority for v0.1)
3. **Model prompt injection** - Tenuo authorizes actions, not prompts (see CaMeL)
4. **Supply chain attacks** - Dependency verification (use cargo audit)
