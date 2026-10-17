# Authorization skill distribution audit

The skill now separates imported runtime source, matching release, merged main,
and the open-PR horizon. **Promotion remains blocked.** Seven local coding-agent
diagnostics now have preserved source/reports and independent probes; the
Temporal live replay probe now passes; evaluation of subsequent guidance
changes remains pending. Daniel’s local manual testing is also required.

The audit started at main `28305436`. The final live snapshot records main
`ba1efb55`; intervening TypeScript examples do not change the reviewed SDK source
fingerprint. The initial **110** open PRs were classified (94 `d8joseph`, 16 `aimable100`,
including seven reviewed no-impact entries). A final live check found ten new
local CLI PRs #942–#951; all were reviewed/classified, bringing the current
inventory to **120** (104 Daniel, 16 Niki). Their full stack order and mandatory
final hardening are recorded without adopting pending factories. Bodies, files, head commits, base/head branches, dependency edges, alternatives,
supersedes and external merge order are retained in the overlay/reviews.
Changed PR content invalidates its assessment; refresh never grants readiness.

The independently installed PyPI wheel confirms `tenuo==0.3.2` lacks
`tenuo.openai.guard_agent`. Main exports it. Current Agents SDK 0.22.0 supports
function-tool tests but lacks the MCP hook required by that helper; Tenuo refuses
that configuration. No successful Agents-to-MCP interception is claimed there.
Temporal's declared plugin floor is 1.33.0; the matrix's 1.23.0 claim is stale.

| Evidence | Result / limit |
| --- | --- |
| Script unit tests | 62 pass; review invalidation, truncation, stack edges, freshness, guidance drift, scanner heuristics and readiness failure behavior |
| Main OpenAI Runner | 7 pass: function allow/deny, handoff target allow/deny, unsupported hosted refusal, MCP refusal where SDK hook is absent |
| Main LangChain/LangGraph | 10 pass: ToolNode/middleware allow, argument denial, root-only delegation, missing chain, compiled key selection, explicit raw-handler bypass negative control |
| Main Temporal | 7 live cases: activity allow/deny, delegation, missing chain, retry, signal resume/replay, injected-argument rejection; deny/chain cases assert receiver DENY and zero body entries |
| Main MCP 1 and MCP 2 | 7 each over stdio metadata: allow, constraint, missing proof, wrong holder/root, delegated chain, missing parents; durable journal proves zero effects |
| Independent PR leaves | Temporal #883: 7 pass; #916: 7 pass plus 2 dedicated sandbox/Replayer cases. These are not merged functionality. |
| LangChain leaf #915 | Raw leaf: 9 pass/1 fail because newer merged config fix #813 is absent. Separate main-plus-leaf code overlay: 10 pass; merge-tree reports a CHANGELOG conflict. Its 21 dedicated node/executor tests also pass on the raw leaf. |

Versioned JSON records package versions, native artifact hashes, source and
harness fingerprints and output. Historical horizon runs retain their original
fingerprints after harness refinements. No PRs were merged into the implementation
branch. Textually clean merge previews are not semantic compatibility proof.
Core/protocol, CrewAI, ADK, FastAPI and A2A pending fixes were reviewed as hazards;
their entire alternative/stacked end states have not been exhaustively executed.

The first local diagnostic round ran one blind in-session coding subagent in each
of seven external-style starters. [Evidence and limits](local-evaluations/2026-10-17/README.md)
include exact copied skill inputs, original starters, candidates, locks, reports,
parent probes and logs. Python payment: 26 pass; TypeScript: 21 pass; Rust: 11
behavioral plus 2 compile-fail pass. All three pass implementation and reporting
review; historical failures remain archived. OpenAI: 40 pass; LangGraph: 21 pass;
MCP: 27 pass on each major. These framework candidates chose direct effect
handlers/services; they do not replace adapter regression coverage.

Temporal's agent reports 25 live tests passing. The independent full rerun now
passes 27 cases, including real workflow retry/resume with zero activity-body
entries on denial and history Replayer without additional effects. The first
attempt could not start because automatic approval review hit an account usage
limit; review later responded and a normally approved invocation passed. The
framework aggregate is now recorded against the actual evaluated skill inputs.
No separate OpenAI API key or paid external API was used. One run per starter is
a diagnostic sample, not a reliability estimate or controlled comparison.

The branch advanced with local CLI guidance in `78819f03` during these runs.
The runs used the copied skill at `abe73aab`; fingerprints are preserved. The
Python/local CLI edit and later refreshed horizon now make affected evidence
visibly stale rather than silently renewed. New
local CLI and warrant/audit routing behavior still needs review/replay. Scanner
self-matches and the packaged TypeScript WASM's imperfect build provenance are
recorded findings. Daniel's manual testing remains pending. No PR is open.

Use `python3 scripts/validate_agent_skills.py --readiness --summary
/tmp/agent-skill-readiness.md` for the explicit promotion gate. Ordinary CI remains
structural/advisory. The separate manual/weekly workflow checks the live horizon
and real dispatch without invoking a hosted model. A future release or changed
SDK/PR source requires source review and refreshed evidence before promotion.
