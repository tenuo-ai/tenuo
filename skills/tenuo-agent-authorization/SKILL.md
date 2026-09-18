---
name: tenuo-agent-authorization
description: Add or retrofit Tenuo authorization for AI-agent tools and effects. Use when implementing Tenuo, protecting an MCP or framework tool, choosing a gateway, sidecar, or embedded enforcement boundary, or testing that an agent cannot exceed delegated authority. Do not use for a review-only audit of an existing warrant.
---

# Tenuo Agent Authorization

Implement the smallest end-to-end Tenuo integration that enforces the user's intended authority at the component that performs the effect. Treat prompts and agent instructions as coordination, not authorization.

## Establish the security boundary

Before editing code, identify:

- the process that chooses an action;
- the component that performs the external effect;
- every path to that effect, including direct SDK, HTTP, queue, and fallback paths;
- who issues authority, who holds it, and which roots the enforcement point trusts.

Distinguish these deployment modes in the final explanation:

1. **In-process guardrail:** a wrapper checks calls in the same process as the agent. This limits ordinary tool use but is not an independent boundary if that process can bypass the wrapper or reach the resource directly.
2. **Effect-boundary enforcement:** a server, sidecar, gateway, worker, or tool host outside the agent's authority verifies the call before performing it. Use this for security claims against a compromised or adversarial agent.

If the agent still has an unguarded route to the effect, say so and either close that route within scope or describe the residual risk. Do not imply that installing an SDK alone creates containment.

Read [Architectural patterns](references/architectural-patterns.md) when choosing or changing the enforcement topology. Select based on the actual trust boundary and bypass paths, not deployment fashion.

## Ground the implementation

Inspect the project before choosing an API:

1. Determine the language, framework, package manager, and resolved Tenuo version from manifests and lockfiles.
2. Search for existing Tenuo setup, tool wrappers, warrant transport, trust-root configuration, and effect handlers.
3. Read the API and examples shipped with that resolved version. Repository source and tests take precedence over remembered syntax.
4. Preserve the project's existing identity, secret-management, logging, and dependency conventions.

For this repository's current SDKs:

- Read [TypeScript integration](references/typescript.md) for `@tenuo/core` or `@tenuo/mcp`.
- Read [Python integration](references/python.md) for `tenuo` and its framework adapters.
- Read [Rust integration](references/rust.md) for the `tenuo` crate, embedded verification, or Rust enforcement services.
- Read [Framework-neutral integration](references/framework-integration.md) when the project uses a framework without an official Tenuo adapter or verified recipe.

If the installed version differs from these references, adapt to its shipped API and state that the reference was not copied verbatim.

API examples belong in the SDK's normal example directories, where CI compiles or exercises them. Do not add copied Python or TypeScript API snippets to this skill. Use the canonical examples linked from the language references, then inspect the installed version before adapting them.

## Implement a vertical slice

Protect one real effect end to end before broadening the integration:

1. Define a capability named for the effect, not for an agent persona or vague purpose.
2. Constrain the arguments that materially determine the effect. Keep the policy closed-world; explicitly allow fields that are intentionally unconstrained.
3. Issue short-lived authority to the holder's public key. Keep issuer and holder private keys out of source control, prompts, model-visible state, logs, and serialized workflow state.
4. Configure the enforcement point with an explicit trusted-root set. Never trust a root supplied by the same untrusted request as the warrant.
5. Verify immediately before the effect and use the verified arguments for the effect. Do not authorize one representation and execute another.
6. Fail closed on missing, expired, malformed, untrusted, wrong-holder, wrong-capability, or constraint-violating authority.
7. Remove or protect alternate routes to the same effect.

Delegate only when the architecture requires it. Bind the child to the recipient's public key, choose the shortest useful TTL, narrow capabilities or arguments where the work is narrower, and mark leaf authority terminal. Do not claim that every hop must be strictly narrower: equal authority can be valid delegation when it remains within the parent's envelope.

## Apply security checks

Use [Security model and limits](references/security-model.md) while designing the integration and [Common footguns](references/common-footguns.md) before considering it complete. In particular:

- **Path effects:** canonicalize or resolve the actual target at the trusted boundary and authorize the same target used for I/O. A lexical prefix check is not a complete filesystem sandbox.
- **Network effects:** constrain scheme, host, port, method, and relevant path where the API exposes them. Treat URL validation as one control; also account for redirects, DNS resolution changes, proxies, and network egress policy.
- **Command effects:** prefer structured APIs. Do not present command token validation as a complete shell sandbox.
- **Replay-sensitive effects:** PoP binds a call to a holder and request, but does not by itself make the call exactly once. Use a nonce store or application-level idempotency at the enforcement point.
- **Mutable resources:** avoid time-of-check/time-of-use gaps. Authorization of a name or path does not freeze the referenced resource.
- **Approvals and receipts:** an approval authorizes a request; it is not evidence that the effect occurred. An authorization receipt records a decision unless the application transactionally couples it to execution.

Do not enable migration, shadow, audit-only, optional-warrant, unknown-argument, or development modes without making the resulting weaker guarantee explicit. Never silently substitute one of these modes for enforcement.

## Prove observable behavior

Add tests at the effect boundary, not only unit tests of policy construction. At minimum prove:

- an allowed test call invokes the effect once;
- a missing warrant is denied and the effect does not run;
- an untrusted issuer is denied;
- the wrong holder or invalid PoP is denied when PoP is part of the selected integration;
- an expired warrant is denied;
- a wrong capability is denied;
- every important argument boundary has allowed and denied cases;
- an attempted wider child delegation is rejected;
- an alternate or direct route cannot bypass verification;
- replay is rejected when the application claims one-use or exactly-once behavior.

Instrument the fake effect with a counter or durable test record so denial tests prove non-execution. A thrown authorization error alone is insufficient evidence if the effect may already have occurred.

Run the narrow tests first, then the relevant package suite and type checker. Do not claim first-attempt correctness, complete mediation, replay resistance, or production readiness unless the tests actually establish it.

## Report the resulting guarantee

Summarize:

- where verification occurs and what effect it mediates;
- which issuer roots are trusted and how the holder key is supplied;
- the capability and argument envelope;
- TTL, delegation depth, terminal status, and replay handling;
- tests run and their results;
- remaining bypasses or operational dependencies.

Use precise language. A sound statement is:

> Calls reaching this effect boundary execute only after the configured Tenuo verifier accepts the warrant, holder proof, capability, and constrained arguments.

Do not claim that Tenuo proves the agent understood or fulfilled human intent, that every action in the application is covered, or that an authorization decision proves the downstream effect completed.
