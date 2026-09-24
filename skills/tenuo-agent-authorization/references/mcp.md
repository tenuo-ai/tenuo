# End-to-end MCP integration

Use this workflow when adding or repairing Tenuo authorization across an MCP caller and server. Read [Integration trust levels](trust-levels.md) before reporting the result, and read the applicable language reference before selecting APIs.

## Required outcome

Leave at least one effectful MCP tool protected by a complete, tested path:

```text
issuer -> holder-bound warrant -> PoP-signed MCP call -> verifier -> effect
```

Prefer one secure vertical slice over broad, unverified edits.

## Inspect the repository

Run the read-only inventory helper (the path is relative to this skill's directory; it scans Python, TypeScript, JavaScript, and Rust sources):

```bash
python scripts/inspect_mcp_project.py --root <project>
```

Confirm every finding in source. Locate:

- MCP server construction and tool registration.
- The caller's `tools/call` path.
- Effectful handlers and the operation performed after dispatch.
- Existing OAuth, service-account, workload-identity, or task context.
- Issuer and holder key ownership.
- Warrant minting or delegation.
- Warrant propagation through MCP metadata or the verified fallback carrier.
- Server verification and independently configured trusted roots.
- Tests proving denied calls cannot reach the effect.

Write a compact trust-path map before editing:

```text
Issuer:    missing | file:line
Holder:    missing | file:line
Transport: stdio | HTTP | SSE | unknown
Verifier:  missing | file:line
Effect:    tool -> external mutation at file:line
```

If the client or server is outside the repository, state the limitation. Do not invent the missing half.

## Choose one effectful tool

Choose a tool with a visible, safely testable effect, such as a database write, filesystem mutation, deployment, message send, or external API action. Record the tool name, exact effect boundary, minimum allowed arguments, and a clearly out-of-scope argument or tool for the denial test.

Do not start with a read-only health check merely because it is easy to test.

## Resolve issuance before verification

Prefer issuance in this order:

1. An existing orchestrator or control plane that authenticates the task or principal.
2. An existing service that selects a reviewed warrant template from authenticated task context.
3. Tenuo Cloud when already configured or explicitly requested.
4. An ephemeral local issuer for a development demonstration.

Never silently put production root signing material in the agent process. An agent-controlled issuer demonstrates the protocol but cannot bound a compromised agent, because that agent can mint replacement authority.

If only the server is available, adding observation and producing an issuer/verifier interface contract may still be useful. Report the result as incomplete and do not enable fail-closed enforcement for real callers until a legitimate minting path exists.

## Implement the vertical slice

Verify APIs against the Tenuo version pinned by the target project. For the current Python package, inspect the installed definitions and tests for `Authorizer`, `MCPVerifier`, `TenuoMiddleware`, `SecureMCPClient`, warrant/key scopes, and the supported metadata carrier before using them.

Preserve these invariants across languages and frameworks:

- The verifier runs before handler dispatch.
- Trusted roots are explicit and provisioned independently in production.
- The warrant is short-lived and bound to the caller's holder public key.
- Proof-of-possession covers the effective wire arguments, with the caller and verifier agreeing on canonicalization.
- Authorization metadata is not exposed as an ordinary tool argument after verification.
- Missing authorization fails closed for the protected caller population.
- Development keys are visibly labeled and cannot be mistaken for production configuration.

If existing human or service clients cannot yet present warrants, prefer a scoped rollout keyed by existing authenticated identity. Do not weaken every call with an optional-warrant mode and describe the system as enforced.

## Prove behavior through the real path

At minimum, test:

1. A valid warrant and in-scope arguments reach the handler.
2. A missing warrant is denied.
3. An out-of-scope tool or argument is denied.
4. A denied call does not reach the protected effect.

When supported by the integration, also test wrong-holder proof, tampering, expiry, an untrusted issuer, caller/verifier argument canonicalization, and the selected carrier across the real transport.

Use an observable effect sentinel, mock, transaction boundary, or temporary resource. An exception assertion alone does not prove denial occurred before the effect. Exercise the same middleware and transport path used by the application; do not replace this with a direct unit test of the core authorizer.

## Report the result

Use one of the labels in [Integration trust levels](trust-levels.md):

```text
Authorization result: observation only | development loop | production boundary

Issuer owner:
Holder:
Verifier:
Protected effect:
Transport and carrier:

Verified:
- allowed call reaches effect
- denied call cannot reach effect

Remaining bypasses or production blockers:
- ...
```

Do not claim success when a verifier exists but legitimate callers have no warrant source. Do not call an in-process guard an independent boundary. Do not call a development issuer production-ready.
