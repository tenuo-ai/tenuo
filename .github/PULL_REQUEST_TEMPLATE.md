## Related Issue

Closes #<!-- issue number -->

> PRs without a linked issue will not be reviewed. See [CONTRIBUTING.md](../CONTRIBUTING.md#before-you-start).
> Small typo/doc fixes may skip this requirement.

## Summary

<!-- What does this PR do? 1-3 bullet points. -->

-

## Test Plan

<!-- How did you verify the change? -->

- [ ] Tests added/updated
- [ ] `./scripts/check.sh` passes

## Security Invariants

<!-- Mark N/A only with a short explanation. Protocol/security-boundary changes
must be called out on the linked issue before implementation. -->

- [ ] Authorization decisions still run in the Rust core; adapters only validate configuration and transport data.
- [ ] Missing, malformed, expired, untrusted, or denied authority fails closed and never invokes the protected handler.
- [ ] Delegation only narrows authority, holder secrets do not cross process boundaries, and wire/canonicalization behavior is unchanged or explicitly reviewed.
- [ ] Security-sensitive behavior has negative tests and, when shared across SDKs, cross-runtime compatibility coverage.
