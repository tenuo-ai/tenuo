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

If an unguarded route remains, close it or report the residual risk. Read [Architectural patterns](references/architectural-patterns.md) only when the enforcement location is undecided or the task changes deployment topology.

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

Read [Framework-neutral integration](references/framework-integration.md) only when no official adapter or verified recipe covers the framework. The linked examples are pinned to the release represented by this skill; use another version's installed API or matching tag rather than adapting them by guesswork.

## Implement one vertical slice

1. Name a capability for the effect and constrain every argument that materially changes it.
2. Issue short-lived authority to the holder's public key. The holder creates proof; the verifier-facing API accepts a presentation or public transport data, never a private signing key.
3. Configure trusted roots and local policy ceilings independently of request data.
4. Verify immediately before the effect and execute with the returned or identically normalized verified arguments.
5. Fail closed for missing, malformed, expired, untrusted, wrong-holder, wrong-capability, or constraint-violating authority.
6. Make the effect client private to or owned by the enforcement component, or guard every effecting method.

Delegate only when required. Bind the child to its recipient, use the shortest useful TTL, narrow authority when the work is narrower, and make leaf authority terminal. Equal delegation can be valid when it remains within the parent envelope.

API examples belong in normal SDK example directories where CI exercises them. Do not copy Python, TypeScript, or Rust API snippets into this skill.

## Pass the completion gate

Read [Common footguns](references/common-footguns.md) before finalizing. Read [Security model and limits](references/security-model.md) when claiming replay resistance, exactly-once effects, revocation, execution evidence, or complete mediation.

Do not finish until:

- a test attempts the original direct route and proves it is inaccessible or produces zero effects;
- the verifier does not receive or use a holder or issuer private key to manufacture caller proof;
- verification covers the final material arguments and the effect uses the verified values;
- missing and invalid authority fail before the effect;
- development, observation, shadow, optional-warrant, and unknown-argument modes are disabled or reported as weaker modes;
- replay, idempotency, revocation, approvals, receipts, and execution evidence are not conflated with authorization.

## Prove behavior

Instrument a fake effect with an invocation counter or durable test record. Prove one allowed invocation and zero invocations for missing authority, untrusted issuer, wrong holder or PoP, expiry, wrong capability, each important argument boundary, wider child delegation, and the original bypass route. Test replay only when one-use behavior is claimed.

Run the narrow tests, then the relevant package suite and type checker. A thrown error is insufficient evidence if the effect may already have happened.

## Report the guarantee

State where verification occurs, what effect it mediates, trusted roots, holder transport, capability and argument envelope, TTL/delegation/replay behavior, tests run, and remaining bypasses or operational dependencies.

Prefer a bounded statement:

> Calls reaching this effect boundary execute only after the configured Tenuo verifier accepts the warrant, holder proof, capability, and constrained arguments.

Do not claim that Tenuo proves human intent, covers every application action, or proves that an authorized downstream effect completed.
