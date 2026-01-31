# Tenuo Core Tests

Comprehensive security and correctness tests for the Tenuo protocol implementation.

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test test_vectors
cargo test --test red_team
cargo test --test security

# With output
cargo test --test red_team -- --nocapture
```

---

## Test Files

| File | Tests | Description |
|------|-------|-------------|
| `test_vectors.rs` | 28 | Normative protocol test vectors (A.1-A.23) |
| `red_team.rs` | 27+ | Binary-level adversarial attacks |
| `security.rs` | 14+ | Multi-sig, approval, and authorization security |
| `chain_verification_invariants.rs` | 20+ | Chain linkage and verification invariants |
| `constraint_types.rs` | 15+ | Constraint matching and attenuation |
| `invariants.rs` | 10+ | Property-based invariant testing |
| `integration.rs` | 12+ | End-to-end integration scenarios |
| `revocation.rs` | 8+ | Revocation list and cascading revocation |
| `parental_revocation.rs` | 4 | Parent-child revocation semantics |
| `delegation_semantics.rs` | 6+ | Delegation depth and attenuation |
| `limits.rs` | 5+ | Protocol limits enforcement |
| `wire_format_compliance.rs` | 5+ | CBOR serialization compliance |
| `wire_compatibility.rs` | 4+ | Wire format backward compatibility |
| `canonicalization.rs` | 4+ | Deterministic serialization |
| `enrollment_flow.rs` | 3+ | Enrollment and onboarding flows |
| `cel_stdlib.rs` | 3+ | CEL expression evaluation |
| `test_object_extraction.rs` | 2 | Test helper utilities |

---

## Test Categories

### Normative Test Vectors (`test_vectors.rs`)

Protocol-defined test vectors ensuring cross-implementation compatibility:

| Vector | Description |
|--------|-------------|
| A.1 | Minimal valid Execution warrant |
| A.2 | Minimal valid Issuer warrant |
| A.3 | 3-level delegation chain |
| A.4 | Invalid chain (I1 violation - holder ≠ issuer) |
| A.5 | Expired warrant rejection |
| A.6 | Proof-of-Possession verification |
| A.7 | Extensions with CBOR payload |
| A.8 | WarrantStack serialization |
| A.10 | Invalid depth monotonicity |
| A.11 | Invalid capability monotonicity |
| A.12 | Invalid parent hash |
| A.13 | TTL extension attack |
| A.14 | Invalid signature |
| A.15 | Issuer constraint violation |
| A.16 | Self-issuance (builder rejection) |
| A.17 | Clearance violation |
| A.18 | Multi-sig configuration |
| A.19.1-3 | Constraint types (Range, OneOf, CIDR) |
| A.20.1-2 | PoP failures (wrong key, window) |
| A.21.1-2 | Multi-sig approvals |
| A.22 | Cascading revocation |
| A.23 | Session mismatch (strict mode) |

### Red Team Tests (`red_team.rs`)

Binary-level adversarial attacks requiring direct CBOR/signature manipulation:

| Category | Tests | Description |
|----------|-------|-------------|
| Parent Hash Linkage | 1 | Verify parent_hash links child to parent |
| CBOR Payload Binding | 3 | payload_bytes vs payload mismatch |
| Signature Reuse | 1 | Cross-warrant signature attacks |
| Cycle Detection | 1 | Parent-child relationship integrity |
| Trust Violations | 2 | Trust ceiling and root trust |
| PoP Timestamp | 3 | Future/old/concurrent window attacks |
| Depth Limits | 1 | MAX_DELEGATION_DEPTH enforcement |
| Tool Narrowing | 2 | Execution and issuer tool addition |
| Holder Binding | 1 | Wrong keypair PoP failure |
| Constraint DoS | 2 | Depth and size limits |
| Chain Verification | 3 | Wrong order, mixed chains, WarrantStack |
| PoP Args Binding | 2 | Tool and args swap attacks |
| Trust Level | 1 | Amplification prevention |
| Terminal Warrants | 1 | Delegation after max_depth |
| Serialization | 1 | Non-deterministic CBOR |
| Constraint Bypass | 2 | Unicode lookalike, case sensitivity |

---

## Why Rust-Level Tests?

Some attacks require:
- Raw CBOR manipulation
- Direct signature construction  
- Internal API access (payload_bytes, parent_hash)
- Binary-level tampering

These can't be tested from Python bindings which only expose the safe API.

---

## Test Output

Tests print status with emoji prefixes:
- `✅` Attack blocked (security property verified)
- `⚠️` Expected behavior documented (not a vulnerability)

---

## Intentional Design Choices

Some tests document **intentional behavior**, not vulnerabilities:

### Parent Hash Linkage
Child warrants use `parent_hash` (SHA256 of parent payload) for cryptographic linkage.
Full chain verification requires a `WarrantStack` containing the ancestry.

### Large Warrants
Warrants under `MAX_WARRANT_SIZE` are allowed regardless of tool count.
There's no security reason to limit tool count below the size limit.

### Self-Issuance (`test_vector_a16_self_issuance_violation`)
Self-issuance is **only blocked for Issuer → Execution** transitions.
This enforces P-LLM ≠ Q-LLM separation: the entity that plans/issues warrants
should not be the same entity that executes them.

Self-issuance in **Execution → Execution** chains is NOT blocked because
monotonicity invariants (I2-I4) ensure self-delegation can only attenuate,
never escalate capabilities. It's harmless (if weird).

### Session ID Inheritance
`session_id` is inherited during attenuation and cannot be changed.
`verify_chain_strict()` enforces session consistency across the chain.

---

## See Also

- [Protocol test vectors](../../docs/spec/test-vectors.md) - Byte-exact CBOR vectors
- [Python security tests](../../tenuo-python/tests/security/) - Higher-level attack scenarios
- [Security policy](../../SECURITY.md) - Vulnerability reporting
