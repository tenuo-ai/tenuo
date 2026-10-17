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
  pass. All 110 open PRs from both required authors were classified at the
  recorded snapshot; refresh against GitHub before relying on that inventory.
- Independently built PR leaves were tested separately. The raw #915 leaf lacks
  merged #813 config forwarding and fails compiled key selection; the separate
  main-plus-leaf code overlay passes, with a CHANGELOG merge conflict recorded.
- The strict readiness gate passes structure, reviewed horizon/framework facts
  and current framework dispatch evidence. It deliberately fails coding-agent
  evidence requirements.

Committed JSON beside this file records actual source/harness fingerprints,
package versions, native artifact hashes and outputs. Historical PR-lane runs
retain their old fingerprints after harness refinements. They do not establish
released functionality or substitute for current merged-main results.

## Remaining work

1. Run blind coding-agent evaluations in fresh external-style projects. Fresh
   in-session subagents with no inherited conversation are suitable for an
   initial diagnostic pass; no separate OpenAI API key is required for that
   route. Record the inherited model identity as far as exposed, scenario,
   resolved SDK source, run count, limits and every outcome. Do not claim a
   pinned backend revision if the session does not expose one.
2. The proposed full first round is three payment runs (Python, TypeScript,
   Rust) plus four framework projects (OpenAI Agents, LangChain/LangGraph,
   Temporal, MCP exercised against both SDK majors). It has not been executed.
   A disposable Python starter with two passing baseline tests was prepared
   locally, but no evaluating subagent was started and no fresh result exists.
   Recreate starters from the scenario documents; temporary paths are not
   portable handoff artifacts.
3. Give evaluating agents only the starter, installed skill and task. Keep the
   hidden rubric and prior failures out of their context. Independently inspect
   generated patches and run receiving-boundary/bypass probes; generated green
   tests alone do not establish a pass. Preserve failed runs and reporting
   failures. A diagnostic sample is not a reliability estimate.
4. Refresh/review changed PRs and SDK facts without borrowing pending APIs into
   released code. Do not merge all PR stacks together. Preserve root-only trust,
   complete delegated chains, observe/enforce distinctions and measured zero
   protected effects for denials.
5. Update evidence and rerun the strict gate. Complete Daniel's local manual
   testing before opening a PR. No PR has been opened for this branch.

## Commands

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/validate_agent_skills.py --summary /tmp/agent-skill-evidence.md
python3 scripts/refresh_agent_skill_horizon.py --check
python3 scripts/repin_agent_skill.py --tag v0.3.2 --check
python3 scripts/validate_agent_skills.py --readiness --summary /tmp/agent-skill-readiness.md
git diff --check origin/main...HEAD
```

The readiness command currently exits nonzero for the expected coding-agent
blockers. Do not change historical grades/fingerprints merely to make it green.
For dispatch suites, build/install the exact selected checkout in isolated
Python 3.12 environments and use `scripts/run_agent_skill_frameworks.py` as
specified in maintenance.md; MCP major versions need separate environments.
