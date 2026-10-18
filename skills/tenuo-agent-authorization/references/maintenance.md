# Refresh and promotion checks

For repository maintainers, the checks are deliberately separate:

| Level | Command | What it establishes |
| --- | --- | --- |
| Structural and release pin | `python3 scripts/validate_agent_skills.py --summary /tmp/agent-skill-evidence.md` | Metadata, portable links, immutable release manifests, evidence schema and generated-artifact consistency. Model quality remains advisory. |
| Release refresh | `python3 scripts/repin_agent_skill.py --tag <released-tag>` | Changes pins/links only; does not certify examples, framework facts or behavioral results. Re-review them. |
| Live horizon | `python3 scripts/refresh_agent_skill_horizon.py` | Queries every open PR for both required authors, checks file-list completeness, captures main and SDK source fingerprints; never executes PR code. |
| Snapshot comparison | `python3 scripts/refresh_agent_skill_horizon.py --check` | Online, read-only comparison with current PR content and SDK sources; ignores timestamp and unrelated-main commit changes. |
| Real dispatch | `python3 scripts/run_agent_skill_frameworks.py --python <isolated-env-python> --source <checkout> --suite <openai,langgraph,temporal,mcp> --lane <name> --rebuild-native --output <evidence.json>` | Rebuilds native code for the selected source, runs real framework paths and records versions, source/harness fingerprints, native artifact hash and effect-counter assertions. Skips and zero tests fail. Run MCP in separate 1.x and 2.x environments. |
| Promotion | `python3 scripts/validate_agent_skills.py --readiness --summary /tmp/agent-skill-readiness.md` | Strict offline gate for reviewed fresh horizon, framework facts, current green dispatch lanes, and fresh passing generic/framework coding-agent evidence. No hosted model invocation. |

The refresh preserves assessments in `unreleased-reviews.json` only when a PR's
head, base, title, body, files and status fingerprint still match. Review all new
or changed PRs, including no-impact category I, then update that file's fingerprint,
categories, impact booleans, summary, dependency/supersedes/related edges and merge
notes. Rerun refresh. Do not classify every mention as a dependency: references
include issues, alternatives and external repository PRs. Base/head matching gives
a stack edge; closed prerequisites remain explicit reviewed edges.

`framework-status.json` contains reviewed implementation facts. When SDK sources
or the release pin change, inspect the affected source/tag/tests before updating
its review identity. The generated `references/framework-status.md` combines
those facts with relevant PRs; updating the PR list cannot certify a framework.
The seven-day horizon window is a promotion policy, not a guarantee that GitHub
has stayed unchanged. Always run the online comparison before promotion.

Evaluate leaf stacks independently in detached worktrees. Build the native SDK
for that checkout, run the corresponding dispatch suite, and retain evidence
with its PR SHA. Check additional prerequisites/merge order first. `git merge-tree`
can identify textual conflicts but cannot prove semantic compatibility. Do not
invent a combined end state for alternatives such as competing parser/observe
proposals. PR-lane evidence never substitutes for released/main lane evidence.

The framework facts also retain a `guidance_review`: a fingerprint of SKILL.md and
handwritten references, plus a reviewed consistency decision. Re-check guidance
against known gaps before updating it. Refresh and release re-pinning never
automatically renew this assessment.

Rebuild once per source/environment, then reuse the same output file without
`--rebuild-native` for subsequent suites only while its build attestation still
matches. An editable package path alone does not establish native provenance.

Framework coding-agent evidence must record individual passing cases for OpenAI,
LangGraph, Temporal, MCP 1 and MCP 2 with preserved artifacts, in addition to its
aggregate result. The project-onboarding evaluation separately checks proposal,
issuance ownership and a usable project-specific authority artifact. Local-first
onboarding is the default; Cloud service compatibility requires a separate real
service test and must not be inferred from a no-account local run.

Historical coding-agent results keep their original fingerprints and failures.
The repository's payment and framework boundary evaluation scenarios define
independent model probes; promotion must remain NOT READY until those actually
pass. Green structural CI or four framework suites alone is insufficient.
