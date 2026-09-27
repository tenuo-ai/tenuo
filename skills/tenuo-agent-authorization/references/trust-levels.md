# Integration trust levels

Use these labels when reporting an integration. They describe the guarantee actually achieved, not the intended future architecture.

Choose a label only when its conditions are evidenced. A missing or unverified production requirement rules out "production boundary"; use "development loop" only if its complete allow/deny flow is demonstrated, "observation only" when no authorization is enforced, and "incomplete integration" otherwise.

## SDK tiers are distinct from deployment trust

Tier 1 rejects out-of-policy tool and argument calls in trusted application code, including calls a manipulated prompt induces. Issuer, holder, and delegation signatures are Tier 2. Describe an enforcing local policy as enforcement. It is a production control when trusted code is the boundary.

Tier 2 keeps those policy checks and adds cryptographically verifiable, holder-bound authority and delegation that can only narrow scope. An independently configured verifier checks that authority locally. Warrants may come from an application-owned issuer or a control plane. Signed receipts, when signing and collection are configured, are proof of the presented authority and the verifier's decision, including denials.

Report both what is checked and where it runs. When the agent can skip the guard, enforce that same tier in the component that performs the effect, outside the agent's control. In ADK, `require_pop=False` is Tier 1 even when a warrant supplies the constraints; `require_pop=True` is what checks issuer, holder, and delegation. For a user-requested local-policy integration, report those checks directly. The issuer-to-effect labels below describe warrant-based integrations. An in-process guardrail can accompany either mode.

## Incomplete integration

Some enforcement or issuance exists, but a complete, usable issuer-to-effect path has not been demonstrated. For example, a fail-closed verifier with no known legitimate warrant source is incomplete, not observation-only and not a production boundary.

Report the components and denial behavior that are verified, the missing issuer, holder, transport, key-management, or test evidence, and what must be completed. Do not disable existing enforcement to fit another label, infer deployment evidence from tests, or claim production readiness for architecture alone.

## Observation only

The application inventories or logs tool calls but does not require valid authority before an effect.

Report that:

- no authorization boundary is enforced;
- calls may still reach the handler without a warrant; and
- the output is suitable for policy discovery, not protection.

## Development loop

A working issuer, holder, propagation path, and verifier exist, and behavioral tests prove allow and deny behavior. However, the issuer is ephemeral, stored with the application, or controlled by the same agent process whose authority it is supposed to bound.

Identify the actual development issuance and invocation entrypoints. Minting fixtures in tests alone do not make a verifier-only application a development loop; report incomplete integration until a legitimate caller path exists. A retained original raw-effect route also prevents claiming the protected workflow is complete, even when its preferred entrypoint passes tests.

Report that:

- the cryptographic flow is functional;
- the agent or application can still mint replacement authority; and
- issuance and root signing material must move outside the agent boundary before production.

## Production boundary

Require repository or deployment evidence for all of the following:

- An issuer outside the untrusted agent process decides what authority to grant.
- The warrant is bound to the caller's holder key and has a task-appropriate TTL.
- The caller attaches the warrant and proof-of-possession to the protected request.
- The effecting component trusts explicit issuer roots and verifies before dispatch.
- Missing, invalid, expired, tampered, wrong-holder, and out-of-scope calls fail closed.
- A denial-before-effect test proves the protected effect is not reached.
- Production keys come from an appropriate secret or key-management boundary, not process-start key generation or committed fixtures.

Do not infer a production boundary merely because the code contains a verifier, middleware, trusted roots, or `require_warrant=True`. Issuer and key ownership determine whether the agent can mint itself broader authority.

## In-process guardrail

Report this property separately from the states above when enforcement runs inside the same mutable process as the agent:

- It can prevent accidental or model-driven calls through the protected path.
- It does not constrain a process that can bypass, replace, or disable the guard.
- Use an independently operated server, sidecar, gateway, or worker when the threat model includes compromise of the agent process.
