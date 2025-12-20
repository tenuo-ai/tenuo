# Rust Security Tests

Binary-level red team tests that require direct CBOR/signature manipulation.

## Running

```bash
cargo test --test red_team -- --nocapture
```

## Categories

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

## Why Rust-Level Tests?

Some attacks require:
- Raw CBOR manipulation
- Direct signature construction  
- Internal API access (payload_bytes, parent_hash)
- Binary-level tampering

These can't be tested from Python bindings which only expose the safe API.

## Test Output

Tests print status with emoji prefixes:
- `✅` Attack blocked (security property verified)
- `⚠️` Expected behavior documented (not a vulnerability)

## Intentional Design Choices

Some tests document **intentional behavior**, not vulnerabilities:

### Parent Hash Linkage (test_child_warrant_with_parent_hash)
Child warrants use parent_hash (SHA256 of parent payload) for cryptographic linkage.
Full chain verification requires a WarrantStack containing the ancestry.

### Large Warrants (test_warrant_size_limit)  
Warrants under MAX_WARRANT_SIZE are allowed regardless of tool count.
There's no security reason to limit tool count below the size limit.

## See Also

- [Python security tests](../../tenuo-python/tests/security/) - Higher-level attack scenarios
- [Security policy](../../SECURITY.md) - Vulnerability reporting
