# Payment-boundary behavioral eval

Use this replay after changing `tenuo-agent-authorization`, its language references, or its routing from another Tenuo skill. It tests behavior the structural validator cannot establish.

## Isolation

Create a fresh temporary project per language with the released SDK pinned to the version in the skill's `release.json`, installed from the registry rather than from this checkout. Copy the skill directory to `.claude/skills/tenuo-agent-authorization/` in that project so the agent reads the installed shape. Start from a service with an exported `PaymentClient` whose public `transfer(recipient, amount)` method records a call, plus an exported `execute_transfer` (`executeTransfer` in TypeScript) that invokes it directly, and two passing tests for that starter. Do not provide prior review findings, expected implementation details, or the rubric below to the evaluated agent.

| Language | Starter | SDK |
| --- | --- | --- |
| TypeScript | `src/payment.ts` with `PaymentClient` and `executeTransfer` | `@tenuo/core` from npm |
| Python | `payment_service/client.py` with `PaymentClient`, a module-level client, and `execute_transfer` | `tenuo` from PyPI in a project `.venv` |
| Rust | `src/lib.rs` with `PaymentClient` and `execute_transfer` | `tenuo` from crates.io with the `sdk` feature |

Run at least one lower-cost coding model with the skill per language. For release-significant changes, also run the same task without the skill and run one stronger model with the skill. Keep every run in a separate directory. Ask the agent to end its report with the exact list of skill files it read; that list becomes the result file's `inputs`.

## Agent prompt

Substitute the package name for the language under test.

> Retrofit this small payment service with `<package>` authorization. A caller must present authority bound to its holder key. The independently configured verifier must trust only the configured issuer and authorize `payment.transfer` with recipient and amount constraints before the payment effect runs. Preserve a usable application API, remove or protect bypass routes, and add executable tests proving one allowed effect and zero effects for missing authority, untrusted issuer, wrong holder, expiry, wrong capability, recipient denial, amount denial, and wider child delegation. Do not put private keys in application logs or request data. Report the precise guarantee and residual risks. Inspect the resolved package README and declarations rather than relying on remembered APIs.

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

On 2026-09-17, a single Claude Sonnet 5 run against the Python starter with `tenuo` 0.3.0 from PyPI passed every critical item on the first attempt: the verifier accepts only a base64 warrant chain and a PoP signature, trusted issuers come from configuration or injection, `PaymentClient.transfer` requires a matching verified value, and sixteen SDK-backed tests assert zero effects for every denial and for both original bypass shapes. The grader added a `mypy` pass, which reported no issues. The one soft spot is that wider delegation is proven at grant time through the SDK's monotonicity error rather than by presenting a forged wider chain to the verifier.

On 2026-09-17, a single Claude Sonnet 5 run against the Rust starter with the `tenuo` crate 0.3.0 from crates.io passed every critical item: the effect client became crate-private, the bypass function was removed and a `compile_fail` doctest attempts it, the boundary verifies a received authorization built only from public transport data against one configured root, and nine SDK-backed tests assert zero effects for every denial. Its weakness is that five denial cases were proven at the caller's own guard rather than at the boundary, because the presentation type cannot be constructed from outside the crate. The grader added in-crate tests that forge presentations with a raw PoP signature and submit them directly; the boundary denied all four forged cases with zero effects and ran a valid raw presentation once. Future Rust runs should be asked to expose a test-only constructor or an in-crate test so boundary-side denial is part of the agent's own evidence.

Record future results in the pull request that changes the skill. A regression in any critical item blocks review even if link validation and generated tests pass.

## CI freshness gate

CI does not invoke a hosted model. Instead, `scripts/validate_agent_skills.py` reads every `payment-boundary-result.<language>.json` file in this directory, fingerprints the skill files each one lists under `inputs`, and compares the digest with that file's `skill_fingerprint`. Each result must name its `language`, and its inputs must include `SKILL.md` and that language's reference. Editing a listed file makes the Agent skills job fail until the replay for every result that lists it is rerun and records the new fingerprint. Skill files that no result lists are reported as uncovered in the job log rather than gated.

Each result records `evidence_kind`: `fresh` for a model run against the recorded fingerprint, or `carried_forward` for a non-behavioral change reviewed without a model run. A carried-forward result must keep a `carried_forward_review` rationale, and the pull request should state which kind it ships. Do not update a fingerprint merely to make CI green.

## Release re-pinning

`release.json` must name a tag that already exists, so a version-bump pull request cannot update it before the release is tagged. The validator warns whenever the pinned versions differ from the manifests at HEAD; after tagging, open a follow-up that updates `release.json`, the pinned reference links, and this evidence, and run `python3 scripts/validate_agent_skills.py --require-current-release` to turn that warning into a failure.
