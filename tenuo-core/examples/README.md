# Tenuo SDK examples

## `sdk_mcp_demo`

Section 16 validation target: a holder process signs, encodes `params._meta.tenuo` from `AuthorizedCall` (no second signature), and an enforcement process verifies through `Guard::guard_received`.

This is the MCP hop. It does not embed `rmcp`; MCP protocol handling stays in the caller.

```bash
cargo run --example sdk_mcp_demo --features sdk,mcp-transport
```

What it shows:

1. Allow: client `guard` → encode → server `guard_received`
2. Constraint deny: the operation does not run, and nothing is encoded
3. Missing `_meta`: `ObservingGuard` records a finding and still runs the tool
4. Approval retry: first attempt returns the core `ApprovalRequest`, `resolve_approvals` signs it, the retry carries approvals on the wire

`ObservingGuard` is an assessment window. It is not enforcement.
