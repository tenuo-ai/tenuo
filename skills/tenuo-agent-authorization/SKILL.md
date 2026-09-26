---
name: tenuo-agent-authorization
description: Add or retrofit Tenuo authorization for AI-agent tools and effects. Use when implementing Tenuo, protecting an MCP or framework tool, choosing a gateway, sidecar, or embedded enforcement boundary, or testing that an agent cannot exceed delegated authority. Do not use for a review-only audit of an existing warrant.
---

# Tenuo Agent Authorization

Implement the smallest end-to-end integration that enforces approved authority at the component performing the effect. Prompts and instructions coordinate an agent; they are not authorization.

## Locate the boundary

Identify the action-selecting process, the effecting component, every direct or fallback route to the effect, and who issues, holds, and verifies authority.

- An **in-process guardrail** limits calls reaching a wrapper. It is not an independent boundary when the agent process can bypass it or reach the resource directly.
- **Effect-boundary enforcement** verifies in a server, gateway, sidecar, worker, or tool host outside the agent's authority before performing the effect.

If an original unguarded application route remains, close it or report the integration as incomplete; a residual-risk disclaimer does not make that route protected. Read [Architectural patterns](references/architectural-patterns.md) only when the enforcement location is undecided or the task changes deployment topology.

For an MCP integration, run `scripts/inspect_mcp_project.py --root .`, confirm its findings in source, then read [End-to-end MCP integration](references/mcp.md). Do not add a verifier in isolation: identify how legitimate callers receive holder-bound warrants and send proof with each protected call. If issuance is missing, observation and policy discovery may still be useful, but report that enforcement is incomplete.

For native function, shell, computer-use, or framework tools, run `scripts/inspect_native_tools.py --root .`, confirm its findings in source, then read [Native agent tool integration](references/native-tools.md). Determine whether the framework hook actually runs for every selected tool type; when it does not, enforce in the handler or downstream service that owns the effect.

## Resolve the actual API

1. Read manifests and lockfiles to determine the resolved Tenuo version.
2. Inspect that installed package's README, declarations, importable source, and packaged examples. Not every package ships examples.
3. If those artifacts are insufficient, inspect an immutable repository release tag whose package manifest matches the resolved version.
4. Use `main` only for an unreleased checkout or as an explicit fallback. Never silently mix `main` examples with a released dependency.
5. Find existing wrappers, authority transport, trust-root configuration, identity, secrets, logs, and effect handlers before editing.

Read exactly the applicable language reference:

- [Python integration](references/python.md) for `tenuo` and its framework adapters.
- [TypeScript integration](references/typescript.md) for `@tenuo/core` or `@tenuo/mcp`.
- [Rust integration](references/rust.md) for the `tenuo` crate or a Rust enforcement service.

For MCP, also read [End-to-end MCP integration](references/mcp.md). It defines the issuer-to-effect completion gate and reporting levels shared across languages.

For native tools, also read [Native agent tool integration](references/native-tools.md). Ordinary application functions count as native tools even without a framework. It covers function-tool dispatch, built-in execution tools, handoffs, and framework hook bypasses.

Read [Framework-neutral integration](references/framework-integration.md) only when no official adapter or verified recipe covers the framework. The linked examples are pinned to the release represented by this skill; use another version's installed API or matching tag rather than adapting them by guesswork.

## Implement one vertical slice

1. Name a capability for the effect and constrain every argument that materially changes it.
2. Issue short-lived authority to the holder's public key. The holder creates proof; the verifier-facing API accepts a presentation or public transport data, never a private signing key.
3. Configure trusted roots, verification time, and local policy ceilings independently of request data. A test clock belongs in private test code or trusted verifier construction, not a caller-selectable execution argument.
4. Verify immediately before the effect and execute with the returned or identically normalized verified arguments. Reject values that cannot be represented losslessly in both authorization and effect types; unchecked numeric casts can authorize a different value than the one executed.
5. Fail closed for missing, malformed, expired, untrusted, wrong-holder, wrong-capability, or constraint-violating authority.
6. Make the effect client private to or owned by the enforcement component, or guard every effecting method.

Delegate only when required. Bind the child to its recipient, use the shortest useful TTL, narrow authority when the work is narrower, and make leaf authority terminal. Equal delegation can be valid when it remains within the parent envelope.

API examples belong in normal SDK example directories where CI exercises them. Do not copy Python, TypeScript, or Rust API snippets into this skill.

## Pass the completion gate

Read [Common footguns](references/common-footguns.md) before finalizing. Read [Security model and limits](references/security-model.md) when claiming replay resistance, exactly-once effects, revocation, execution evidence, or complete mediation.

Do not finish until:

- a test attempts the original direct route at its original module/import and method, not just a top-level re-export, and proves it is inaccessible or produces zero effects; removing an export or adding an underscore is not sufficient if the callable still works;
- the verifier does not receive or use a holder or issuer private key to manufacture caller proof;
- verification covers the final material arguments and the effect uses the verified values;
- missing and invalid authority fail before the effect;
- development, observation, shadow, optional-warrant, and unknown-argument modes are disabled or reported as weaker modes;
- replay, idempotency, revocation, approvals, receipts, and execution evidence are not conflated with authorization.

## Prove behavior

Instrument a fake effect with an invocation counter or durable test record. Prove one allowed invocation and zero invocations for missing authority, untrusted issuer, wrong holder or PoP, expiry, wrong capability, each important argument boundary, wider child delegation, and the original bypass route. Test replay only when one-use behavior is claimed.

Exercise denials at the receiving boundary, not only in the caller's presentation helper. Check the denial reason: setup errors, missing signer keys, and malformed test fixtures do not prove policy enforcement. For delegation, first prove a valid narrower child works with the correct holder key, then change only the envelope to prove widening is rejected. For compiled APIs, a bypass test must actually attempt the forbidden access and expect compilation failure; a successful test importing only the new API proves nothing about the old route.

Run the narrow tests, then the relevant package suite and type checker. A thrown error is insufficient evidence if the effect may already have happened.

## Report the guarantee

State where verification occurs, what effect it mediates, trusted roots, holder transport, capability and argument envelope, TTL/delegation/replay behavior, tests run, and remaining bypasses or operational dependencies.

Prefer a bounded statement:

> Calls reaching this effect boundary execute only after the configured Tenuo verifier accepts the warrant, holder proof, capability, and constrained arguments.

Do not claim that Tenuo proves human intent, covers every application action, or proves that an authorized downstream effect completed.

Before reporting any integration, read [Integration trust levels](references/trust-levels.md) and name its evidenced label: incomplete integration, observation only, development loop, or production boundary. Test-only minting does not establish an application issuance path. Report an in-process guardrail separately when it can be bypassed by the agent process.
