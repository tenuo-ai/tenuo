# Local blind coding-agent diagnostics, 2026-10-17

One fresh in-session coding subagent per project, seven projects, no provider
API key and no additional external API spend. The inherited session model's
exact backend revision is not exposed. This is a diagnostic sample, not a
reliability estimate or a controlled skill/no-skill comparison.

Each agent received an isolated starter, copied skill, installed dependencies
and the scenario request. Framework task: “Secure this agent with Tenuo. Allow
refunds for order 123 up to $500.” Payment tasks followed the payment scenario's
public agent prompt. Agents were instructed to inspect the resolved SDK, use
fake effects, record files read and report their guarantee; they were not given
the hidden acceptance rubric, previous results, other starters or parent review.
The isolated agent reports record their own inspection/validation history.
Full turn transcripts and first-response proposal timing are not exposed by the
collaboration interface; those procedural details are not independently graded.

The copied skill is from `abe73aab4df50a7044ab8b0d560b061c2b57d650`.
`skill-inputs/` contains the exact union of instruction/script inputs reported
read/executed. Per-project JSON has its actual input list and fingerprint.
Reading only an applicable section of a large reference still fingerprints the
whole file; scanner search hits are not counted as separate instruction reads.
Agents reported truncated initial combined reference output where applicable.

| Project | SDK source | Independent rerun | Disposition |
| --- | --- | --- | --- |
| Python payment | PyPI 0.3.2 | 26 pass; mypy pass | Implementation/reporting pass; usable development issuer/caller APIs |
| TypeScript payment | npm 0.3.2-beta.0 | 21 pass; tsc pass; 3 expected negative compile diagnostics | Implementation/reporting pass; accurately labels test-only issuance incomplete |
| Rust payment | crates.io 0.3.2 | 11 behavioral + 2 compile-fail pass; check/fmt pass | Implementation/reporting pass; development example |
| OpenAI Agents | PyPI 0.3.2; Agents 0.22.0 | 40 pass | Direct service enforcement; no unavailable guard_agent API |
| LangGraph | Editable main SDK; LangGraph 1.2.11 | 21 pass | Compiled ToolNode with guarded handler and public chain/proof transport |
| Temporal | Editable main SDK; Temporal 1.34.0 | 1 independent receiver probe pass | Agent reports 25 live tests pass; additional independent live/replay probe pending |
| MCP | Editable main SDK; MCP 1.30.0 / 2.3.0 | 27 pass on each major | Actual stdio metadata, root-only chain, zero journal writes on denials |

Parent review inspected verification/effect ordering, final argument identity,
root configuration, public transport, original bypasses, negative test reasons,
and reporting. Independent probes test altered signed arguments, a narrower
warrant than local policy, wrong holder, deny-then-allow and original routes.
Payment wider-child cases present correctly signed forged widening to the
receiver with a successful narrower-child positive control. Framework reports
accurately distinguish grant-time widening tests from receiving-boundary proof.

All four framework candidates chose effect-handler/service enforcement. These
runs test the skill's integration selection and guarded dispatch, not universal
correctness of each Tenuo framework adapter. The separate deterministic adapter
matrix remains necessary. No production boundary, replay prevention, cumulative
budget, revocation, idempotency or exactly-once behavior is established here.

## Preserved evidence and limitations

- Raw patches and terminal logs retain their original bytes, including blank
  diff context markers and terminal padding. Local .gitattributes excludes only
  those artifact formats from whitespace lint; candidate source stays checked.
- Each directory has original `starter/`, full `candidate/` (including untracked
  implementation files), `tracked.patch`, parent `grader-output/` and `result.json`.
  A tracked patch alone omits new files; review the candidate tree too.
- Dependency locks, source/runtime probes where generated, reports, and MCP's
  initial failing MCP2 result-field assertions are retained. Agent reports name
  other initial fixture/API mistakes. Their full raw command history is not
  available; do not describe this archive as a full transcript.
- Parent OpenAI/LangGraph probes initially omitted explicit child capabilities;
  those grader fixtures failed before dispatch. Corrected fixtures passed;
  candidate authorization code was unchanged. OpenAI wraps service denials in
  Runner `UserError`; the corrected assertion checks the constraint reason.
- The Temporal live workflow/retry/resume/Replayer probe is preserved as
  `framework-temporal/candidate/grader_probes/test_independent.py` but **NOT RUN**.
  Automatic approval review could not complete due to an account usage limit;
  this was not a safety finding. The additional receiver-only test ran normally.
  Its pass is not a substitute for independent live dispatch evidence.
- MCP agent completion was interrupted by the same usage limit after its report
  and final logs were written. Both parent reruns completed successfully.
- TypeScript's actual packaged WASM reports `sourceClean:false` and
  `wasmMatchesCommit:false`. Its measured artifact hash is preserved; clean
  source provenance is not established. An exploratory tool printed a discarded
  generated test seed; that output/seed is not included here or in application
  requests/logs. Diagnostic hygiene remains a review finding.
- Scanner noise: all agents saw matches in their installed skill metadata (and
  MCP noted virtual environment matches). They treated these as heuristics and
  inspected actual application source. Consider pruning these paths in a later
  scanner change with its own bounded replay; this run does not certify it.
- The remote branch advanced during testing with Python/local CLI guidance in
  `78819f03`. That commit was fast-forwarded after these runs. Fingerprints remain
  those actually evaluated; Python evidence is therefore visibly stale. The
  new local CLI and warrant/audit routing guidance were **not evaluated** here.
- Earlier failed payment results are preserved in `historical/`, unchanged.
  New canonical payment results point to these fresh runs. No aggregate framework
  pass is emitted until the pending independent Temporal probe completes.

## Reproduce and finish

These are development fixtures with fake effects, not production integrations.
Copy a candidate to a disposable directory; do not run its tests in a real app.
Temporary absolute editable paths in locks and SDK_SOURCE.json describe the
measured run, not portable installation instructions. For editable-main lanes,
replace them with the exact audited SDK checkout and build/install its matching
native extension. Preserve the reported artifact provenance when comparing.

Use each candidate REPORT.md for setup/runtime versions and commands. Payment
Python uses pytest and mypy, TypeScript npm ci/test/typecheck, Rust cargo test
--locked --offline and cargo check --locked --offline --all-targets. Framework
Python runs `python -m pytest -q tests grader_probes`; MCP needs separate MCP1
and MCP2 environments. Temporal additionally needs permission to launch the
local server; its pending replay probe should be included when available.

Next: finish that Temporal probe, review/replay the changed Python/local CLI and
warrant/audit routing guidance, refresh live PR inventory, rerun readiness, and
allow Daniel's local manual testing. No PR until testing and manual review are
finished. `sha256.json` records file digests for detecting accidental changes; it is not
a signed attestation.
