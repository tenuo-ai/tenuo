---
name: tenuo-agent-authorization
description: Add or retrofit Tenuo authorization for AI-agent tools and effects. Use when implementing Tenuo, protecting an MCP or framework tool, choosing a gateway, sidecar, or embedded enforcement boundary, or testing that an agent cannot exceed delegated authority. Do not use for a review-only audit of an existing warrant.
---

# Tenuo Agent Authorization

Implement the smallest end-to-end integration that enforces approved authority at the component performing the effect. Prompts and instructions coordinate an agent; they are not authorization.

## Start with the project

For “Secure this agent with Tenuo”, inspect the project before explaining concepts. Your first substantive output should be a compact proposal: effects found, recommended effect boundary, minimum task authority (capabilities and material argument limits), integration mode, resolved Tenuo source/version, and why this boundary covers the actual execution path. For example: refund service handler; warrant for the current order, amount at most $500. Resolve the boundary and authority before wiring it. Do not add authority merely to make a failing example pass.

For getting started with an existing project, read [Project onboarding](references/project-onboarding.md). Translate the user's task into useful autonomous actions and bounded authority, then produce a project-specific warrant or supported template and one working integration. Infer implementation details from source; ask only about material business authority that the project and user have not established. A list of SDK concepts or read/write permissions is not an onboarding result.

Start with local Tenuo: the installed SDK, locally verified task authority, and the smallest useful integration in the user's project. Use local CLI/templates when the resolved runtime supports them; otherwise use SDK issuance. No Cloud account is needed to get started, and self-managed local verification can also be a production deployment.

Use [Deployment choices](references/deployment-choices.md) when choosing issuance ownership, working with an existing Cloud setup, or migrating to Cloud. Keep a configured Cloud workflow when it fits the request; propose Cloud management when its managed issuance or fleet operations solve an actual need. Choose who issues/manages authority separately from where calls are verified and effects run. Ground core and adapter choices in the matching tenuo runtime, Cloud choices in the matching tenuo-cloud runtime/service, and use demos to illustrate topology.

## Freshness contract

These sources have different authority. Follow this order before choosing an API:

1. Determine the target's actual runtime: installed distribution, lockfile and package-manager resolution, editable checkout, vendored source, or git dependency. Locate what the application imports, including the native extension/WASM artifact and framework versions. Record paths and versions or commit IDs; a manifest version alone cannot distinguish a release from an unreleased checkout with the same version string.
2. Inspect that exact imported code, exports, signatures, and dispatch path.
3. If needed, inspect docs/tests at the matching immutable release. Confirm package manifests at the tag, including language-specific prereleases.
4. Consult merged `main` for known differences and fixes. It supplies implementation APIs only if the project actually runs that checkout or the user explicitly requests an unreleased evaluation; an evaluation does not upgrade the target implicitly.
5. Consult [framework status](references/framework-status.md) for known gaps and compatibility notes. It is dated information about a reviewed release, not installed API documentation; open pull requests can likewise reveal a known gap without making a fix available.
6. Choose only APIs present in the target. Verify constraint syntax and wire semantics there too. If a known gap affects the path, protect the effect handler/service directly, or propose a version change and test it explicitly.

**An open PR may invalidate a recommendation without making its replacement API available.** Never recommend checking out a PR stack as an implicit production upgrade. A framework hook's existence, a compatibility-table “Stable” label, or a green structural validator does not prove authorization.

In particular, released OpenAI Agents examples using `Agent(input_guardrails=[...])` do not intercept later model tool calls. Merged `guard_agent()` must not be supplied to a release lacking that export. Pending LangChain, Temporal, CrewAI, ADK, FastAPI, constraint, and protocol fixes require the same source check. Read the framework status before recommending an adapter.

## Locate the boundary

Identify the action-selecting process, the effecting component, every direct or fallback route to the effect, and who issues, holds, and verifies authority.

- An **in-process guardrail** limits calls reaching a wrapper. It is not an independent boundary when the agent process can bypass it or reach the resource directly.
- **Effect-boundary enforcement** verifies in a server, gateway, sidecar, worker, or tool host outside the agent's authority before performing the effect.

Tier 1 rejects out-of-policy calls in trusted code, including calls a manipulated prompt induces. Tier 2 keeps those checks and adds signed, holder-bound authority and delegation that can only narrow, which an independent verifier can check. Describe a requested local-policy integration by those checks, as enforcement. Read [Integration trust levels](references/trust-levels.md). When the agent can skip the guard, identify the effecting component outside the agent's control where enforcement must run. Do not invent a warrant-issuance requirement for a local-policy request.

If an original unguarded application route remains, close it or report the integration as incomplete; a residual-risk disclaimer does not make that route protected. Read [Architectural patterns](references/architectural-patterns.md) only when the enforcement location is undecided or the task changes deployment topology.

For an MCP integration, run `scripts/inspect_mcp_project.py --root .`, confirm its findings in source, then read [End-to-end MCP integration](references/mcp.md). Do not add a verifier in isolation: identify how legitimate callers receive holder-bound warrants and send proof with each protected call. If issuance is missing, observation and policy discovery may still be useful, but report that enforcement is incomplete.

For native function, shell, computer-use, or framework tools, run `scripts/inspect_native_tools.py --root .`, confirm its findings in source, then read [Native agent tool integration](references/native-tools.md). Determine whether the framework hook actually runs for every selected tool type; when it does not, enforce in the handler or downstream service that owns the effect.

## Resolve the actual API

1. Read manifests and lockfiles to determine the resolved Tenuo version.
2. Inspect that installed package's README, declarations, importable source, and packaged examples. Not every package ships examples.
3. If those artifacts are insufficient, inspect an immutable repository release tag whose package manifest matches the resolved version.
4. Follow the freshness contract above; `main` is never an API fallback for a released dependency.
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

Trust the independently configured root. Present the complete parent chain with a delegated leaf, in the representation/order the installed adapter expects. Never repair missing transport by trusting every intermediate delegator directly. Test a valid child against root-only trust, then omit the chain and prove zero effects.

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

Use the real framework dispatcher, including relevant config forwarding, key selection, MCP transport, handoffs, retries/resume, and injected arguments. Direct verifier tests cannot establish adapter correctness. In observe mode, decision=DENY can coexist with enforcement not applied and an executed effect. Report the decision and effect count separately; never call an observed denial blocked. Check whether the target actually implements the selected mode.

End with a visible task demonstration, for example:

```text
Task warrant: refund(order=123, amount<=500)
Allowed: refund(order=123, amount=200) -> effect executes once
Denied: refund(order=123, amount=4900) -> Tenuo denies -> effect executes zero times
```

Show actual measured results from the target integration, with its scope and remaining gaps. Do not substitute this illustrative output for a test.

Choose a useful action the agent can complete without further intervention inside its task authority. Pair it with an attacker-induced change to a material argument, or an attempted expansion beyond a delegated child's authority. Use the same tool for both calls so a tool allowlist alone cannot explain the result. Keep the user-facing example short and runnable with one documented command; keep framework plumbing in tested SDK examples. A scripted bad tool call demonstrates enforcement after model failure, not a measured live-model prompt-injection success rate.

## Report the guarantee

State where verification occurs, what effect it mediates, trusted roots, holder transport, capability and argument envelope, TTL/delegation/replay behavior, tests run, and remaining bypasses or operational dependencies.

Prefer a bounded statement:

> Calls reaching this effect boundary execute only after the configured Tenuo verifier accepts the warrant, holder proof, capability, and constrained arguments.

Do not claim that Tenuo proves human intent, covers every application action, or proves that an authorized downstream effect completed.

Before reporting any integration, read [Integration trust levels](references/trust-levels.md) and name its evidenced label: incomplete integration, observation only, development loop, or production boundary. Test-only minting does not establish an application issuance path. Report an in-process guardrail separately when it can be bypassed by the agent process.
