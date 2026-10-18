# Authorization skill handoff

Branch: `skill/authorization-readiness`, draft PR
[#955](https://github.com/tenuo-ai/tenuo/pull/955), tracking issue
[#954](https://github.com/tenuo-ai/tenuo/issues/954).

Daniel requested PRs and waived his personal manual-review requirement in favor
of thorough agent review. The skill should primarily help with local Tenuo,
while supporting existing Cloud projects and a deliberate migration. Marketplace
publication is a later discussion. **Distribution readiness remains NOT READY.**

## Current implementation

- Runtime-first API selection separates installed artifacts, matching release,
  merged main and pending PR hazards. Native/WASM provenance matters too.
- Generated inventory covers every open PR from Daniel and Niki, retaining
  reviewed categories, stack edges, alternatives and external prerequisites.
- Framework facts cover MCP, LangChain/LangGraph, OpenAI Agents, Temporal, CrewAI,
  ADK, AutoGen, FastAPI, A2A and Hermes without certifying untested paths.
- Project-first onboarding proposes useful autonomy, minimum task authority and
  actual effect/credential owners. Local SDK or supported CLI is the default;
  Cloud migration preserves authority and receiving-boundary tests.
- Short released-SDK examples run through OpenAI Agents, LangGraph, Temporal,
  MCP 1 and MCP 2 with one command each. No Cloud/model key or real payment.
- Scanners report candidate boundaries; they prune installed skill/environment
  trees and cannot certify mediation. Warrant/audit routing follows requested
  work, not the developer's job title.
- Structural validation stays advisory about model quality. Strict promotion
  additionally requires reviewed freshness, exact native builds, green dispatch
  and current individual coding-agent cases plus project-onboarding evidence.

## Executable evidence

See [latest independent review](local-evaluations/2026-10-18-review/README.md)
and its results.json for exact inputs/provenance and commands:

- 72 script unit tests; structural validation and whitespace check.
- 38 freshly rebuilt-main dispatch cases: OpenAI 7, LangGraph 10, Temporal 7,
  MCP 1 and MCP 2 7 each. Build attestations bind native hashes to selected code.
- 8 short-example test methods, including all five real framework commands.
  Each command allows one effect and denies three material-argument attacks
  with zero effects. Generic service recipes are not adapter certification.
- 11 released Python warrant snippet/probes and 5 installed TypeScript probes.
- Local CLI PR951 leaf ebdfb291: 89 focused cases plus 3 live Temporal cases;
  independent actual CLI YAML/issuance/verification to LangChain workflow passes.
  Its newer cb440d2 delta was inspected; these tests do not certify that delta.
  Workspace default changed from .tenuo to ~/.tenuo; placement alone is not
  isolation from an unrestricted same-user agent process.
- Latest snapshot reviewed 124 PRs (refresh before relying on the count).

Historical leaf experiments remain in horizon-regression-results.json: raw
LangChain #915 lacks merged config forwarding, while a separate main+leaf overlay
passes with a recorded CHANGELOG conflict. Temporal #883 and #916 were tested
independently. None of these branches was merged into adapter implementation.

## Behavioral evidence and remaining work

The preserved [seven-project diagnostic](local-evaluations/2026-10-17/README.md)
and [onboarding diagnostic](local-evaluations/2026-10-17-onboarding/README.md)
passed independent probes against their actual older copied skill inputs.
Their fingerprints and earlier failures remain unchanged. Later edits make them
stale; they are not renewed by rerunning candidate code.

Two fresh routing agents selected the appropriate issuance/review skills in
first responses, then stopped at the account usage limit. Neither completed;
no behavioral pass is claimed. When coding-agent execution is available:

1. Freeze current guidance and reviewed human horizon references. Run bounded
   fresh payment diagnostics in Python/TypeScript/Rust, individual framework
   diagnostics (OpenAI, LangGraph, Temporal, MCP 1/2), and project onboarding.
   Keep the original starters, exact inputs, candidate/probes and all outcomes.
2. Record per-framework case evidence/artifacts, not just aggregate pass. Run
   independent receiving-boundary probes; exceptions alone are insufficient.
3. Finish fresh routing cases: standalone issuance, review-only, mixed MCP
   onboarding, and audit-to-implementation. Exercise an actual local-CLI-present
   project separately from the released SDK code-first fallback.
4. Refresh live PRs and inspect changed sources before renewing classifications.
   Explicit self-PR refresh identity avoids recursive generated-snapshot drift;
   changing source or other hazard reviews still invalidates the assessment.
   Human refs keep semantic changes visible while JSON retains exact timestamps
   and head/tree provenance. Never edit historical model fingerprints.
5. Run required checks and strict readiness. Update the PR from draft only when
   actual evidence supports it. Discuss skill marketplaces/plugins afterwards.

No live Cloud service compatibility or production migration was tested. Source
review supports the migration design; a real Cloud grant must pass the same
receiving boundary before claiming service integration. Full repository
scripts/check.sh is not claimed green.

## Commands

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/validate_agent_skills.py --summary /tmp/agent-skill-evidence.md
python3 scripts/refresh_agent_skill_horizon.py --check
python3 scripts/validate_agent_skills.py --readiness --summary /tmp/agent-skill-readiness.md
uv run --no-project tenuo-python/examples/task_authority_frameworks/tests/test_examples.py
git diff --check
```

See skill references/maintenance.md for rebuilding each exact native runtime and
running real dispatch lanes. Normal CI does not require a hosted-model eval.
