# Authorization skill handoff

Branch: `skill/authorization-readiness` in `tenuo-ai/tenuo`.

**Daniel's instruction: do not open a PR yet. Finish the remaining testing and
allow Daniel to test locally by hand before opening one.** Pushing this branch
is a handoff, not promotion approval.

## Start here

Read [audit.md](audit.md), [payment-boundary-eval.md](payment-boundary-eval.md),
and [framework-boundary-eval.md](framework-boundary-eval.md). The skill's
`references/maintenance.md` explains refresh, evidence and readiness commands.

The implementation is committed in three reviewable parts: source/freshness
architecture; framework dispatch coverage and readiness; heuristic scanners and
audit. The handoff adds no adapter implementation changes.

## Verified so far

- 62 script unit tests pass.
- 38 new real-framework cases pass across five merged-main lanes: OpenAI Agents,
  LangChain/LangGraph, live Temporal, MCP 1 and MCP 2. Tests use scripted models;
  no provider API key is needed for those deterministic suites.
- Structural/release validation, live inventory comparison and whitespace checks
  pass. All 120 open PRs from both required authors are classified after the
  final refresh (including ten new local CLI stack PRs); refresh against GitHub before relying on that inventory.
- Independently built PR leaves were tested separately. The raw #915 leaf lacks
  merged #813 config forwarding and fails compiled key selection; the separate
  main-plus-leaf code overlay passes, with a CHANGELOG merge conflict recorded.
- The strict readiness gate passes structure and current deterministic framework
  dispatch evidence. It still requires guidance review and refreshed coding-agent
  evidence after the local CLI edit and live horizon refresh; see below.

Committed JSON beside this file records actual source/harness fingerprints,
package versions, native artifact hashes and outputs. Historical PR-lane runs
retain their old fingerprints after harness refinements. They do not establish
released functionality or substitute for current merged-main results.

## Local diagnostic round completed

See [the preserved seven-project run](local-evaluations/2026-10-17/README.md) for
original starters, candidate code, exact skill inputs, reports, independent probes
and logs. Payment implementation/reporting passed in all three languages;
OpenAI, LangGraph and both MCP-major independent reruns passed. Temporal's
independent full rerun now passes 27 cases including live workflow/retry/resume
and Replayer. Its first attempt could not start because approval review hit an
account usage limit; a subsequent normally approved invocation passed. Both the
first-blocked note and successful output are preserved.

The round evaluated copied skill `abe73aab`, before the local CLI change below.
Historical payment failures and all evaluated fingerprints are retained. The
Python result is consequently stale for today's Python reference. The subsequent
horizon refresh also marks affected inputs stale in all runs. The aggregate
framework result records the completed four-case round with its original
fingerprint. These seven diagnostics do not establish a reliability rate.

## Remaining work

1. Review/replay `78819f03` Python/local CLI guidance and warrant/audit routing.
   Do not re-fingerprint the older run to certify unseen instructions.
2. Refresh/review changed live PRs and SDK facts, rerun strict readiness, and
   preserve source/stack distinctions and root-only trust throughout.
3. Daniel must test locally by hand before any PR. No PR has been opened.

## Commands

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/validate_agent_skills.py --summary /tmp/agent-skill-evidence.md
python3 scripts/refresh_agent_skill_horizon.py --check
python3 scripts/repin_agent_skill.py --tag v0.3.2 --check
python3 scripts/validate_agent_skills.py --readiness --summary /tmp/agent-skill-readiness.md
git diff --check origin/main...HEAD
```

The readiness command still exits nonzero for guidance
review/freshness blockers. Do not change historical grades/fingerprints merely to make it green.
For dispatch suites, build/install the exact selected checkout in isolated
Python 3.12 environments and use `scripts/run_agent_skill_frameworks.py` as
specified in maintenance.md; MCP major versions need separate environments.

## Local CLI alignment follow-up

The local follow-up branch `skill/local-cli-alignment` adds a version-gated
`references/local-cli.md`, linked from the Python reference. It describes the
unreleased common CLI and explicitly does not add those helpers to the pinned
release contract. Warrant/audit guidance now recognizes local SRLs and receipts,
distinguishes reissuance, attachment and revocation, and preserves intentionally
authorized private endpoints. Warrant creation asks only about material unknowns
instead of requiring confirmation of every constraint.

Validation: all 62 script tests passed, all four skills and 58 portable links
validated, and the three edited skill entrypoints passed skill-creator's
frontmatter validation. No new coding-agent evaluation was run. Historical
fingerprints and grades remain unchanged; the additional guidance-review
freshness warning is expected until that review/evaluation is performed. This
follow-up does not confer promotion approval or authorize a push/PR.
