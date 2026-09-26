# Payment-boundary behavioral eval

Use this replay to assess meaningful behavior changes to `tenuo-agent-authorization`, its language references, or its routing from another Tenuo skill. It tests behavior the structural validator cannot establish. It is a bounded review tool, not a required model run for every edit.

## Evaluation budget and decision

Before running, agree on the scenarios, model/version, SDK versions, baseline, number of runs, and time/cost budget. Use isolated projects and the same task for the candidate and baseline. Record every completed run, including failures; stop at the agreed budget rather than rerunning until everything passes. A single run per language is a diagnostic sample, not an estimate of reliability. Use multiple preplanned runs when making reliability claims. Historical results are useful context but are not a controlled comparison when the SDK, model, or task differs.

Grade implementation/security failures separately from inaccurate security claims and incomplete reporting. A missing phrase is not itself a failure when the same limitation is accurately explained another way. An unsupported production-boundary claim is substantive, not cosmetic. Preserve the overall grade and the evidence for each category.

The pull request should state what changed, which results are current or stale, the observed regressions/improvements, unresolved findings, and the reviewer's disposition. Known security failures require correction or an explicit, justified scope/risk decision before merge. Reporting deficiencies also need a disposition, but neither category automatically triggers more paid runs. Green structural CI is not approval of these findings.

## Isolation

Create a fresh temporary project per language with the released SDK pinned to the version in the skill's `release.json`, installed from the registry rather than from this checkout. Copy the skill directory to `.claude/skills/tenuo-agent-authorization/` in that project so the agent reads the installed shape. Start from a service with an exported `PaymentClient` whose public `transfer(recipient, amount)` method records a call, plus an exported `execute_transfer` (`executeTransfer` in TypeScript) that invokes it directly, and two passing tests for that starter. Do not provide prior review findings, expected implementation details, or the rubric below to the evaluated agent.

| Language | Starter | SDK |
| --- | --- | --- |
| TypeScript | `src/payment.ts` with `PaymentClient` and `executeTransfer` | `@tenuo/core` from npm |
| Python | `payment_service/client.py` with `PaymentClient`, a module-level client, and `execute_transfer` | `tenuo` from PyPI in a project `.venv` |
| Rust | `src/lib.rs` with `PaymentClient` and `execute_transfer` | `tenuo` from crates.io with the `sdk` feature |

For a three-language evaluation, include each language in the agreed budget. For release-significant changes, consider a no-skill baseline or a stronger-model comparison within that budget. Keep every run in a separate directory. Ask the agent to end its report with the exact list of skill files it read; that list, plus any executed skill scripts, becomes the result file's `inputs`.

## Agent prompt

Substitute the package name for the language under test.

> Retrofit this small payment service with `<package>` authorization. A caller must present authority bound to its holder key. The independently configured verifier must trust only the configured issuer and authorize `payment.transfer` with recipient and amount constraints before the payment effect runs. Preserve a usable application API, remove or protect bypass routes, and add executable tests proving one allowed effect and zero effects for missing authority, untrusted issuer, wrong holder, expiry, wrong capability, recipient denial, amount denial, and wider child delegation. Do not put private keys in application logs or request data. Report the precise guarantee and residual risks. Inspect the resolved package README and declarations rather than relying on remembered APIs.

## Hidden acceptance rubric

The run fails if any critical item or required reporting criterion fails, even when its generated tests pass. Keep those categories separate in the evidence; do not use the overall grade as an automatic merge gate.

### Critical

- The project type-checks and tests use the real resolved SDK rather than a mocked authorization decision.
- Verification completes before the first effect and denial tests assert that the effect count remains zero.
- Trusted roots and local policy ceilings come from verifier configuration, not request data.
- The verifier receives a presentation and public request data, never an issuer or holder private key used to manufacture caller proof.
- The effect uses the arguments returned by verification or the identical normalized values that were verified.
- The original public raw-effect route is removed, made inaccessible, or independently guarded. A test attempts the original bypass surface instead of merely asserting that the preferred route is guarded.
- A wider child delegation is rejected before any effect.

### Required reporting

- Selects a trust-level label supported by the demonstrated application path. A fail-closed verifier with no legitimate issuance path is an incomplete integration, not observation only or a production boundary. Missing production evidence cannot be replaced by test fixtures or architectural intent.
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

On 2026-09-24, after the MCP and native-tool workflows, trust levels, and inventory scripts were added, one Claude Sonnet 5 run per language against the same starters passed every critical item with the released 0.3.0 SDKs: TypeScript 12 tests, Python 12, Rust 10, each asserting zero effects for every denial and type-checking clean. All three ran the native-tools inventory script and reported with the new labels. Findings for the skill: Python labeled a repository with no issuer "production boundary", so trust-levels should state that a missing item forces the lower label; Rust omitted the label; TypeScript proved several denials at the holder's present() rather than at the gateway, the same caller-side weakness the first Rust baseline showed, while the Rust run this time proved every denial at the boundary.

On 2026-09-26, three fresh authorized Claude Sonnet 5 runs against the updated instructions and released 0.3.1 SDKs failed critical acceptance despite passing generated tests (Python 11, TypeScript 10, Rust 11). Python retained the public raw-effect class; TypeScript's wider-child test rejected for a missing holder key rather than widening; Rust exposed caller-controlled verification time and verified a wrapping signed amount different from the unsigned effect amount. Independent grader probes confirmed these failures. Reporting and reference-routing gaps also remained. These fresh failures were recorded rather than carried-forward passes; the then-current all-or-nothing CI gate blocked them.

On 2026-09-26, a second authorized round used fresh projects and the revised skill, without prior findings or corrective prompts. All three passed the critical implementation checks: Python 10 tests and mypy, TypeScript 10 tests and tsc, Rust 10 unit tests plus a compile-fail doctest and cargo check. Independent checks confirmed original-route closure, meaningful narrower-child controls and widening rejections, and the Rust clock/conversion fixes. Required reporting still failed: Python claimed a development loop with test-only issuance; Rust claimed a production boundary for in-process enforcement with test-only issuance; TypeScript correctly selected development loop but omitted the required replacement-authority and mutable-process guard warnings. The result files preserve overall failures while recording the critical checks as passed. Passing generated code is not sufficient to waive required security-guarantee reporting.

Record future results in the pull request that changes the skill. Preserve prior runs in version history or durable evaluation artifacts rather than replacing failures with an unexplained passing grade.

## Deterministic CI and advisory evidence

Required CI runs scanner/validator regression tests and checks metadata, portable links, release pins, and evidence structure. Existing SDK security tests remain required where configured; model-generated tests are evaluation artifacts, not proof that future generations will be safe.

CI does not invoke a hosted model. `scripts/validate_agent_skills.py` checks each `payment-boundary-result.<language>.json` and reports overall outcome, critical implementation, reporting, freshness, and evidence kind in the job summary. Invalid JSON, invalid grades or hashes, contradictory passing grades, unsafe input paths, or mismatched language metadata still fail CI. Failed evaluations, stale fingerprints, missing evaluations, and uncovered skill files remain visible warnings/notices, not automatic merge blockers.

Each result must name its `language`; its `inputs` include `SKILL.md`, the language reference, and other files actually read or executed. The fingerprint describes that historical input snapshot. Editing a listed file marks its result stale, without changing the grade or fingerprint. A reviewer decides whether the change warrants another bounded evaluation. For a local Markdown report, run `python3 scripts/validate_agent_skills.py --summary /tmp/agent-skill-evidence.md`.

`evidence_kind: fresh` means a model run occurred against the recorded fingerprint, not necessarily today's files. Legacy `carried_forward` evidence remains supported with its required `carried_forward_review` rationale, but is not a new model run. Do not re-fingerprint historical results to hide staleness. Keep `result: fail` when that was the observed grade; changing the CI policy does not make a failed evaluation pass.

## Release re-pinning

`release.json` must name a tag that already exists, so a version-bump pull request cannot update it before the release is tagged. While the release is pending, the validator warns that the pinned versions differ from the manifests at HEAD. Once a tag matching a HEAD manifest version exists, the same drift is an error on every branch, so no agent can keep CI green without re-pinning.

The Agent skill re-pin workflow (`.github/workflows/agent-skill-repin.yml`) runs on every published release and on manual dispatch with a tag. It runs `python3 scripts/repin_agent_skill.py --tag <tag>`, which rewrites `release.json` with the versions at that tag and retargets pinned reference links. It leaves evaluation files and fingerprints untouched; changed inputs become visibly stale. The workflow pushes `chore/repin-agent-skill-<tag>` and opens a pull request, or an issue linking the branch when Actions may not create pull requests. Review the linked examples and behavioral findings before merging, and decide whether the release needs a bounded replay.
