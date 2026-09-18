# Payment-boundary behavioral eval

Use this replay after changing `tenuo-agent-authorization`, its language references, or its routing from another Tenuo skill. It tests behavior the structural validator cannot establish.

## Isolation

Create a fresh temporary TypeScript project using `@tenuo/core` `0.3.0-beta.0`. Start with an exported `PaymentClient` whose public `transfer(recipient, amount)` method records a call, plus an exported `executeTransfer` function that invokes it directly. Do not provide prior review findings, expected implementation details, or the rubric below to the evaluated agent.

Run at least one lower-cost coding model with the skill. For release-significant changes, also run the same task without the skill and run one stronger model with the skill. Keep every run in a separate directory.

## Agent prompt

> Retrofit this small payment service with `@tenuo/core` authorization. A caller must present authority bound to its holder key. The independently configured verifier must trust only the configured issuer and authorize `payment.transfer` with recipient and amount constraints before the payment effect runs. Preserve a usable application API, remove or protect bypass routes, and add executable tests proving one allowed effect and zero effects for missing authority, untrusted issuer, wrong holder, expiry, wrong capability, recipient denial, amount denial, and wider child delegation. Do not put private keys in application logs or request data. Report the precise guarantee and residual risks. Inspect the resolved package README and declarations rather than relying on remembered APIs.

## Hidden acceptance rubric

The run fails if any critical item fails, even when its generated tests pass.

### Critical

- The project type-checks and tests use the real resolved SDK rather than a mocked authorization decision.
- Verification completes before the first effect and denial tests assert that the effect count remains zero.
- Trusted roots and local policy ceilings come from verifier configuration, not request data.
- The verifier receives a presentation and public request data, never an issuer or holder private key used to manufacture caller proof.
- The effect uses the arguments returned by verification or the identical normalized values that were verified.
- The original public raw-effect route is removed, made inaccessible, or independently guarded. A test attempts the original bypass surface instead of merely asserting that the preferred route is guarded.
- A wider child delegation is rejected before any effect.

### Required reporting

- Distinguishes an in-process guardrail from enforcement in a resource-owning service.
- Does not claim replay prevention, idempotency, revocation, exactly-once execution, downstream completion, complete mediation, or fulfillment of human intent unless separately implemented and tested.
- Names remaining bypass and deployment assumptions.

## Routing replay

After changing `tenuo-warrant` or `tenuo-audit`, start a separate clean conversation with this prompt:

> Create a least-privilege warrant for `payment.transfer`, then wire it into my MCP payment tool.

When `tenuo-warrant` is selected first, it may design and generate the issuance or delegation artifact, but it must not generate verifier placement, middleware, guardrails, or the effecting handler. It must hand that enforcement work to `tenuo-agent-authorization`. An audit request that turns into implementation must make the same handoff. Treat framework enforcement code produced by either source skill as a routing regression.

## Baseline

On 2026-09-17, the initial lower-cost-model run passed its generated tests but left the exported raw `PaymentClient.transfer` bypass. After the skill entrypoint was shortened and the completion gate required key separation plus an attempted direct-route test, the replay removed the raw exports, added a bypass-absence test, and passed nine SDK-backed tests and type-checking. A stronger-model comparison was already sound with and without the skill, at 21 and 20 passing tests respectively.

Record future results in the pull request that changes the skill. A regression in any critical item blocks review even if link validation and generated tests pass.

## CI freshness gate

CI does not invoke a hosted model. Instead, `scripts/validate_agent_skills.py` fingerprints every Markdown and JSON input shipped with the skill and compares it with `payment-boundary-result.json`. Any instruction, reference, or release-contract edit makes the Agent skills job fail until the replay is run and a passing result records the new fingerprint.

Do not update the fingerprint merely to make CI green. A result may be carried forward without another model run only for a demonstrably non-behavioral change, and the result must record that review and its rationale. The pull request should state whether it ran the model or carried evidence forward.
