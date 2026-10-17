# Authorization skill distribution audit

The skill now separates imported runtime source, matching release, merged main,
and the open-PR horizon. **Promotion remains blocked on fresh coding-agent
evidence.** Structural success and passing dispatch suites do not waive that.

The audit started at main `28305436`. The final live snapshot records main
`ba1efb55`; intervening TypeScript examples do not change the reviewed SDK source
fingerprint. All **110** open PRs from the required authors were classified:
94 `d8joseph`, 16 `aimable100`, including seven explicitly reviewed no-impact
entries. Bodies, files, head commits, base/head branches, dependency edges, alternatives,
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

The existing payment coding-agent evaluations remain failed and stale, including
reporting failures despite previously passing generated implementation tests.
Fresh framework coding-agent evidence is absent. Its scenario now specifies
external-style release/main starters and independent bypass probes. Fresh coding-agent evaluations can use isolated in-session subagents; a separate
OpenAI API key or external model spend is not required for that route. External
paid replays still need an agreed model/run/time/cost budget. No fresh coding-agent
run has completed, and no historical grades or fingerprints were renewed.

Use `python3 scripts/validate_agent_skills.py --readiness --summary
/tmp/agent-skill-readiness.md` for the explicit promotion gate. Ordinary CI remains
structural/advisory. The separate manual/weekly workflow checks the live horizon
and real dispatch without invoking a hosted model. A future release or changed
SDK/PR source requires source review and refreshed evidence before promotion.
