# Authorization skill distribution audit

**Promotion remains blocked by stale/incomplete coding-agent evidence.** Draft
PR [#955](https://github.com/tenuo-ai/tenuo/pull/955) is open. Daniel waived personal
manual review and requested thorough agent review. No marketplace submission.

The skill now defaults to local SDK or supported CLI onboarding, proposes
project-specific task authority and effect/credential ownership, and supports
existing Cloud workflows or a staged migration. Cloud is optional management;
verification remains at the actual effect boundary. Private Cloud source was
reviewed for design, not copied or used as an invented installed API.

## Source and freshness

Installed runtime is authoritative, followed by matching release docs/tests.
Main and the open-PR overlay expose known differences/hazards; neither supplies
missing APIs. Released 0.3.2 lacks OpenAI guard_agent; merged main has it. Agents
0.22 lacks its required MCP hook, so main refuses that unsupported path. Temporal
plugin minimum is 1.33 despite older compatibility prose claiming 1.23.

The latest snapshot reviewed 124 open PRs from Daniel and Niki, including local
CLI #942–#952, FastMCP guidance #953 and wrapper #956, and this skill PR #955.
All categories, no-impact assessments, source identities and stack relationships
are retained. The local CLI stack moved while testing: ebdfb291 was executed;
cb440d2's workspace-placement/docs delta was inspected separately. Pending
commands remain unavailable to released integrations. Refresh live before use.

Human generated references change with hazards/facts, not timestamp/head-only
provenance. JSON retains exact provenance. The explicitly designated self-PR
uses full-tree identity excluding only generated horizon outputs and its own
review entry; source and other review changes still invalidate its assessment.

## Independent checks

[Latest artifacts](local-evaluations/2026-10-18-review/README.md) preserve commands,
inputs, outputs and limits. SDK/runtime behavior was not rewritten.

| Check | Result and limit |
| --- | --- |
| Script unit tests | 72 passed; source/review invalidation, truncation, stacks, scanner exclusions, exact native provenance and per-case readiness |
| Main OpenAI Runner | 7 passed: function/handoff allow and deny, unsupported hosted/MCP refusal |
| Main LangChain/LangGraph | 10 passed: real ToolNode/middleware, delegated chain, compiled key selection and raw-handler bypass negative control |
| Main Temporal | 7 live passed: activity ingress, chain, retry/resume/replay and injected arguments |
| Main MCP 1 / MCP 2 | 7 each passed: real stdio metadata, root/holder/proof/constraint/chain cases with durable effect journal |
| Short released examples | 8 methods passed, including five real framework commands; each one allowed/three denied with zero effects |
| Warrant guidance | Actual Markdown Python example/probes: 11 passed; installed TypeScript diagnostics: 5 passed |
| Unreleased local CLI leaf | 89 focused tests plus 3 live Temporal cases passed at ebdfb291; independent CLI-to-LangChain workflow passed typed denials with zero effects |

All 38 merged-main dispatch cases were rerun after rebuilding exact source and
recording native attestation. An initial concurrent-build wheel decompression
failure is preserved; sequential rebuild passed. Independent PR-leaf history
remains separate: Temporal #883/#916 pass; raw #915 fails missing merged config
forwarding, separate main+leaf overlay passes with a documented merge conflict.
No giant merge of pending stacks was attempted.

The local CLI Temporal check explicitly uses an unsandboxed runner, so it does
not establish sandbox/Replayer safety. Local shared-user files are a development
loop; moving keys outside a project does not protect against an unrestricted
same-user shell. No live Cloud issuance, production migration or full repository
scripts/check.sh pass is claimed.

## Behavioral evidence

The [seven-project round](local-evaluations/2026-10-17/README.md) passed independent
implementation/reporting review against copied skill abe73aab: Python payment 26,
TypeScript 21, Rust 11 plus 2 compile-fail; OpenAI 40, LangGraph 21, Temporal 27,
MCP 27 on each major. The [onboarding round](local-evaluations/2026-10-17-onboarding/README.md)
passed 23 real-HTTP cases and produced supported task issuance and an accurate
existing-worker deployment recommendation. These are diagnostic samples, not a
reliability estimate. Exact old inputs, prior failures and model-identity limits
remain preserved; subsequent skill changes leave them visibly stale.

Fresh issuance/review routing attempts selected the appropriate skills, then
hit the account usage limit before completing. No pass is claimed. Current
strict readiness must remain NOT READY until fresh payment/framework/onboarding
and routing evidence is reviewed. Warrant/audit/denial-triage skills also retain
separate behavioral limitations; authorization's strict gate does not certify
all four skills. See [handoff](handoff.md) for the remaining evaluation work.
