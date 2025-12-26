# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please email **security@tenuo.dev** instead of opening a public issue.

**PGP Key:** [keys.openpgp.org](https://keys.openpgp.org/search?q=security%40tenuo.dev)  
**Fingerprint:** `A5EC 5FE8 E816 8869 62CC  998C 2E98 D3E4 F5F8 0771`

We will:
- Acknowledge within 48 hours
- Provide an estimated fix timeline within 7 days
- Credit you in the release notes (unless you prefer anonymity)

## Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Remote code execution, warrant forgery | Chain verification bypass |
| **High** | Privilege escalation, constraint bypass | Monotonicity violation |
| **Medium** | Information disclosure | Timing side-channel |
| **Low** | Minor issues, hardening | Missing best practice |

## Scope

| In Scope | Out of Scope |
|----------|--------------|
| Warrant forgery | Denial of service |
| Constraint bypass | Social engineering |
| PoP bypass | Physical attacks |
| Privilege escalation | Attacks requiring root access |
| Monotonicity violations | Client-side misconfigurations |
| Chain verification bypass | Network-level attacks (use TLS) |
| Serialization attacks | Side-channel attacks |

## Known Limitations

See [tests/security/README.md](./tenuo-python/tests/security/README.md) for documented attack scenarios and application responsibilities.

### Application Responsibilities

Tenuo provides cryptographic authorization primitives. Applications are responsible for:

1.  **Wrapper usage** - All tools must be protected with `@guard` or `guard()`
2.  **Root trust** - Must use `Authorizer` with explicit `trusted_roots`
3.  **Fail-Closed Authorization**
    Tenuo operates on a fail-closed basis.
    *   **Missing Warrants**: If no warrant is present in the context, `@guard` protected functions will raise `AuthorizationError` and block execution.
    *   **Invalid Warrants**: If a warrant is expired, has an invalid signature, or is for the wrong tool, access is denied.
4.  **Path canonicalization** - Must resolve `..` before authorization checks
5.  **Node coverage** - All LangGraph nodes must use `@tenuo_node` or wrap their tools
6.  **Nonce/idempotency** - App-level replay prevention within PoP window

### Security Tests

We maintain comprehensive red team test suites:

- **Rust tests**: `cargo test --test red_team`

These cover:
- Signature/trust attacks
- Monotonicity violations
- PoP binding bypasses
- Delegation limit evasion
- Implementation-level attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Security updates |
| < 0.1   | ❌ No support |

## Security Advisories

Security advisories will be published via:
- GitHub Security Advisories
- Email to registered users (opt-in)
- Release notes

## Recognition

We gratefully acknowledge all valid security reports in our Hall of Fame and release notes. We do not currently offer monetary rewards.

