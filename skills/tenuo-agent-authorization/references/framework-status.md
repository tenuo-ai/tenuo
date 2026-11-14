# Framework status by source

Reviewed against SDK sources; re-review these facts when SDK sources or the release pin change.

Release reviewed: `v0.3.2`. These are historical comparisons, never an override of target runtime source. The repository compatibility matrix mixes released and main claims; its Stable label is not deny-before-effect evidence.

No row certifies an integration. Existing test locations below describe coverage to inspect, not proof that they ran against your target. Run the target's own tests for dispatch and effect-count evidence.

## MCP

Interception: Server middleware before decorated handler; verify normalized arguments and execute those values.

Released: Released client/middleware exist; client could call without a warrant in scope. SDK major, decorator shape, metadata and canonicalization must match.

Main: Client now fails closed without warrant; SDK 2 server middleware verifies decorator defaults/validators. Main remains authoritative only for its checkout.

Framework floor: mcp>=1.9.4; FastMCP>=3.2.1; separate MCP 1/FastMCP 3 and MCP 2/FastMCP 4 environments.

Known gaps: Client-only checks do not secure a raw server; optional-warrant/observe paths permit effects. Do not adopt proposed envelope v2.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/mcp/client.py`, `tenuo-python/tenuo/mcp/server.py`, `tenuo-python/tenuo/mcp/fastmcp_middleware.py`, `tenuo-python/tenuo/mcp/mcpserver_middleware.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_mcp_fastmcp_e2e.py`, `tenuo-python/tests/adapters/test_mcp_mcpserver_middleware.py`. Real dispatch/effect-counter coverage exists in tests/agent-skills/tenuo-agent-authorization/frameworks/test_mcp.py; versioned runs and native artifact hashes are recorded separately. This covers the named paths only.

## LangChain

Interception: create_agent middleware from tenuo.langgraph; legacy executors need verified guarded tool rebuilding.

Released: TenuoMiddleware supports create_agent when available. guard_agent fallback can keep original unguarded tools; never infer protection from wrapped .tools.

Main: No merged adapter change since pin; pending enforcement stack still matters.

Framework floor: langchain>=1 for create_agent middleware; legacy extra langchain/core>=0.2 does not provide that API.

Known gaps: guard_agent/auto_protect fallback, global mode changes and original handler access; use middleware/effect guard with actual dispatch tests.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/langchain.py`, `tenuo-python/tenuo/langgraph.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/examples/test_langchain_create_agent_middleware.py`. Real dispatch/effect-counter coverage exists in tests/agent-skills/tenuo-agent-authorization/frameworks/test_langgraph.py; versioned runs and native artifact hashes are recorded separately. This covers the named paths only.

## LangGraph

Interception: TenuoToolNode per tool call with state schema retaining warrant and parent chain.

Released: ToolNode hook is feature detected. guard_node binds state/key and optional capability check; it is not full node authorization. @tenuo_node config injection is broken.

Main: guard_node config forwarding merged; @tenuo_node fix, stack-token parsing and full guard_node verification remain pending.

Framework floor: Other APIs extra langgraph>=0.2/core>=0.2.27; TenuoToolNode actually needs langgraph-prebuilt>=1.0.2 hook. Verify features; pending floor changes.

Known gaps: Raw handlers/effect clients bypass ToolNode; node binding alone does not check trust/expiry/arguments. Do not use node wrapper as effect boundary.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/langgraph.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_langgraph_toolnode.py`, `tenuo-python/tests/adapters/test_langgraph.py`. Real dispatch/effect-counter coverage exists in tests/agent-skills/tenuo-agent-authorization/frameworks/test_langgraph.py; versioned runs and native artifact hashes are recorded separately. This covers the named paths only.

## OpenAI Agents

Interception: Per-function tool input guardrail through guard_agent when exported; protect downstream handlers otherwise.

Released: Agent input_guardrails guidance cannot intercept later tool calls; guard_agent is absent in the matching tag.

Main: guard_agent mediates function/MCP tools and reachable handoff target tools; refuses unsupported hosted tools. Handoff transition itself is not a separately scoped capability.

Framework floor: openai extra declares agents>=0.1; guard_agent requires function tool guardrails (source says >=0.3.3). Runner tested at 0.22.0, whose MCPServerStdio lacks the required MCP hook and is refused. Check features per tool type.

Known gaps: Agent input guardrail is not tool authorization; local hooks do not isolate raw handlers. MCP attachment tests alone do not prove dispatch.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/openai.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_openai_agents_runner.py`. Real dispatch/effect-counter coverage exists in tests/agent-skills/tenuo-agent-authorization/frameworks/test_openai.py; versioned runs and native artifact hashes are recorded separately. This covers the named paths only.

## Temporal

Interception: Activity inbound interceptor before body, with workflow outbound signing and public chain headers.

Released: Transport/interceptors exist; helper chain conventions differ. Start helper cannot accept pending warrant_chain option. dry_run and replayer need path-specific checks.

Main: Adapter fixes include mapping/constraint validation, bounded key cache and native changes; main plugin extra floors temporalio at 1.33.0 despite stale matrix/docs.

Framework floor: Current pyproject temporalio>=1.33.0 for plugin SimplePlugin. Matrix claims 1.23.0; do not use that as evidence.

Known gaps: Missing workflow parents, mixed-worker sandbox extension replacement and replay key resolution; internal/injected argument exemptions and observe are pending.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/temporal/_interceptors.py`, `tenuo-python/tenuo/temporal/_headers.py`, `tenuo-python/tenuo/temporal/_config.py`, `tenuo-python/tenuo/temporal_plugin.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/e2e/test_temporal_live.py`, `tenuo-python/tests/e2e/test_temporal_replay.py`. Real dispatch/effect-counter coverage exists in tests/agent-skills/tenuo-agent-authorization/frameworks/test_temporal.py; versioned runs and native artifact hashes are recorded separately. This covers the named paths only.

## CrewAI

Interception: Before-tool hook must return framework terminal denial; prefer effect service until real kickoff/Flow proof.

Released: GuardedCrew/hooks exist; hook exceptions and async hooks may allow execution; per-agent parent transport gaps.

Main: No merged CrewAI adapter change since pin; pending fail-closed leaf is material.

Framework floor: crewai>=1.5 for hooks; dependency constraints keep MCP 1/OpenAI<3 in separate environment.

Known gaps: Unexpected hook exceptions/coroutines, async Flow guard lifetime, raw effect route, missing parent chain.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/crewai.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_crewai_integration.py`. Existing adapter tests are not a replacement for real kickoff/async Flow effect counts; those gap-specific tests are on the pending fail-closed stack.

## Google ADK

Interception: before_tool/plugin with full argument mapping and scope; downstream handler for unresolved gaps.

Released: Guard/plugin exist; closed-world local constraints and ScopedWarrant scope have pending gaps.

Main: No merged ADK guard change since pin; observe/approval/scope fixes remain open.

Framework floor: google-adk>=0.1 declared; verify installed runner/callback API, tested matrix reports 2.8.

Known gaps: ScopedWarrant scope without plugin, unlisted/runtime arguments, approval errors; require_pop=False does not verify holder proof.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/google_adk/guard.py`, `tenuo-python/tenuo/google_adk/plugin.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_google_adk_runner.py`. An existing InMemoryRunner test exercises dispatch; pending scope/closed-world/approval fixes need their own real-runner proof.

## AutoGen

Interception: Guard each dispatched tool, including async/stream paths; service boundary for process compromise.

Released: GuardBuilder/tool wrappers exist; configure independent roots and pass delegated parents.

Main: Merged audit hardening and audit callback error isolation; explicit entrypoint roots/observe records remain pending.

Framework floor: autogen-agentchat/autogen-ext>=0.7.0; avoid unrelated 0.0.x packages.

Known gaps: Retained original tool and unguarded stream/direct routes; log/skip denial evidence differs across versions.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/autogen.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_autogen_integration.py`. Existing tests require inspection and execution; no blanket certification. See adapter regression results for exact cases.

## FastAPI

Interception: Dependency at every effecting HTTP route, verified final typed arguments.

Released: Guard/router exist; strict=True ignored and add_api_route/include_router may bypass SecureAPIRouter decorators.

Main: Merged typed argument/transport fixes do not fix router coverage; strict audit and all-route leaf remain open.

Framework floor: fastapi>=0.100 declared; inspect Starlette/route dispatch in target.

Known gaps: Included/late-added routes, mounts, websockets and direct endpoint calls need coverage; router symbol is no certificate.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/fastapi.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_fastapi_integration.py`. Existing tests require inspection and execution; no blanket certification. See adapter regression results for exact cases.

## A2A

Interception: Receiving ASGI task/skill handler with root trust, full chain, PoP and server constraints before effect.

Released: Audience default, server constraints under PoP and trust_delegated stack path have pending corrections.

Main: Client compatibility with latest Starlette merged; server gaps remain.

Framework floor: In-repo A2A uses httpx>=0.24 and starlette>=0.27, not an upstream A2A SDK.

Known gaps: Server ceiling skipped under PoP; JTI consumed before authorization; missing chain must not be fixed with intermediate roots.

Source paths to inspect in the matching checkout: `tenuo-python/tenuo/a2a/server.py`, `tenuo-python/tenuo/a2a/client.py`.

Dispatch-test evidence to inspect: `tenuo-python/tests/adapters/test_a2a.py`. Existing tests require inspection and execution; no blanket certification. See adapter regression results for exact cases.

## Hermes

Interception: Plugin pre_tool_call for covered user tools; independently guard ctx.dispatch_tool effects.

Released: Separately shipped hermes-tenuo; this repository release does not pin its installed source.

Main: No in-repo adapter; external plugin version/commit and dispatch tests required.

Framework floor: Matrix: Hermes>=0.20, hermes-tenuo 0.1.3 requires tenuo>=0.3.2; verify external packaging.

Known gaps: Plugin ctx.dispatch_tool calls bypass pre_tool_call; external nightly compatibility is not this skill regression proof.

Source paths to inspect in the matching checkout: external hermes-tenuo repository.

Dispatch-test evidence to inspect: external plugin CI; not established here. Existing tests require inspection and execution; no blanket certification. See adapter regression results for exact cases.
