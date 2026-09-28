---
title: Tenuo for the Temporal Agent Harness
description: Native Tenuo authorization for temporal-agent-harness activity tools, internal activities, and MCP tool calls
---

# Tenuo for the Temporal Agent Harness

> The [Temporal Agent Harness](https://pypi.org/project/temporal-agent-harness/)
> (`temporal-agent-harness`) runs agent tool calls, model invocations, and MCP
> servers as ordinary Temporal Activities on the same Workflow/Activity
> primitives [`tenuo.temporal`](./temporal.md) already protects. This page
> covers the harness-specific presets in `tenuo.temporal.harness`; for the
> base integration (keys, PoP, constraints, production checklist), start with
> [Temporal Integration](./temporal.md) and the
> [Reference](./temporal-reference.md).

The harness is **Pre-Alpha** upstream (APIs will change) as of this writing.
Everything below targets its OpenAI Agents SDK integration
(`temporal_agent_harness.ai_sdks.openai_agents`), the path the harness's own
examples use.

## Why a separate module

A worker built from `TenuoTemporalPlugin` + `TenuoPluginConfig` already
authorizes any Temporal Activity. Three harness-specific shapes need a
little help, and all three are answered by opt-in `TenuoPluginConfig`
fields — `tenuo.temporal.harness` just ships the harness's own values
pre-filled:

| Gap | Field | Preset |
|---|---|---|
| `@agent.activity_tool_defn` tools receive a trailing `tool_ctx: AgentToolContext` the outbound interceptor cannot normalize for PoP | `pop_exclude_args` | `HARNESS_TOOL_CTX_EXCLUDE_ARGS` |
| The harness's own internal activities (model calls, approval routing, sandbox lifecycle) are not effects and shouldn't need a warrant | `unwarranted_activities` | `HARNESS_INTERNAL_ACTIVITIES` |
| MCP tool calls run as one activity per server, wrapping `{tool_name, arguments, meta}` — the warrant should name the inner tool, not the wrapper | `mcp_call_tool_activities` | `HARNESS_MCP_CALL_TOOL_ACTIVITIES` |

Every one of these is off by default: an ordinary `TenuoPluginConfig()` with
none of these fields set behaves exactly as it does today, byte-for-byte —
nothing here changes wire format or PoP canonicalization unless you opt in.

## Install

```bash
pip install 'tenuo[temporal-harness]'
```

This installs `temporalio` and `temporal-agent-harness` together. Importing
`tenuo.temporal.harness` itself never requires the harness package —
`temporal_agent_harness` types are only imported inside `warrant_evaluator()`,
and only when you call it, so the presets and `harness_plugin_config()` work
in a process that has Tenuo but not the harness installed (e.g. a shared
library module, or a test).

## Quick start

Build one config and use it for both the workflow worker (outbound PoP
signing) and the activity/effects worker (inbound verification) — the three
harness fields must agree on both sides or verification fails closed (see
[Fails closed on asymmetry](#fails-closed-on-asymmetry) below):

```python
from temporalio.client import Client
from temporalio.worker import Worker

from tenuo.temporal.harness import harness_plugin_config
from tenuo.temporal_plugin import TenuoTemporalPlugin

config = harness_plugin_config(
    key_resolver=my_key_resolver,       # or signing_key=... for a single-key worker
    trusted_roots=[control_key.public_key],
    require_warrant=True,               # the harness's own activities are still exempt
    activity_fns=[refund_agent_tools...],  # needed to resolve tool_ctx by name — see below
)

plugin = TenuoTemporalPlugin(config)
client = await Client.connect("localhost:7233", plugins=[plugin])

worker = Worker(
    client,
    task_queue="refund-agent",
    workflows=[RefundAgentWorkflow],
    activities=[...],  # includes the @agent.activity_tool_defn tool activities
)
await worker.run()
```

A single worker running both the agent workflow and its `@agent.
activity_tool_defn` tool activities under `require_warrant=True` — the
production pattern this module was built to make unnecessary to split —
now needs no separate "effects worker" and no inline-tool workaround: the
harness's internal activities are exempt via `HARNESS_INTERNAL_ACTIVITIES`,
and every real tool call is verified with `tool_ctx` excluded from the
signed payload.

## `pop_exclude_args` — the `tool_ctx` argument

`@agent.activity_tool_defn` activities receive the model's own arguments
plus a trailing `tool_ctx: AgentToolContext` the harness uses to publish
`tool_start`/`tool_end`/`tool_error` events from inside the running
activity. `AgentToolContext` is a pydantic model (a stream context plus a
call id) — not a primitive, dataclass, dict, or list — so without exclusion
the outbound interceptor fails PoP signing outright:

```
ARG_NORMALIZATION_FAILED: Activity argument 'tool_ctx' has type
'AgentToolContext' which cannot be normalized for PoP signing.
```

`HARNESS_TOOL_CTX_EXCLUDE_ARGS` (`frozenset({"tool_ctx"})`) drops it from
the signed/verified payload entirely, on both sides:

```python
from tenuo.temporal import TenuoPluginConfig
from tenuo.temporal.harness import HARNESS_TOOL_CTX_EXCLUDE_ARGS

config = TenuoPluginConfig(
    ...,
    pop_exclude_args=HARNESS_TOOL_CTX_EXCLUDE_ARGS,
    activity_fns=[my_tool_1, my_tool_2, ...],  # required — see below
)
```

`pop_exclude_args` excludes by **parameter name**, resolved from the
activity function's own signature — so, exactly like named warrant
constraints, it requires `activity_fns=` (the same list you pass to
`Worker(activities=...)`) on **both** the workflow worker and the activity
worker. Without a resolvable function reference, PoP computation for that
activity fails closed with `TenuoContextError` rather than silently leaving
`tool_ctx` in the signed payload.

A warrant can never gain a constraint on `tool_ctx` back door: if a
capability in the warrant still declares a field constraint on an excluded
name, the excluded value is missing from the args dict Tenuo builds, and
zero-trust pre-validation denies the call as a **missing required field**
— it does not silently ignore the constraint.

## `unwarranted_activities` — the harness's internal plumbing

With Tenuo headers on the workflow, the outbound interceptor signs *every*
activity the workflow schedules by default — including the harness's own
internal activities, none of which touch a customer system: model calls,
the Jev auto-mode tool-approval activity, Code Mode batches, MCP
list/session/prompt activities, and sandbox lifecycle. Today's alternative
is `require_warrant=False` on the whole worker (which also stops enforcing
your own tools) or a second, unwarranted worker just for these — a good
production pattern for some deployments, but it should be a choice, not a
requirement.

```python
from tenuo.temporal.harness import HARNESS_INTERNAL_ACTIVITIES

config = TenuoPluginConfig(
    ...,
    unwarranted_activities=HARNESS_INTERNAL_ACTIVITIES,
    require_warrant=True,  # your own tools stay strictly enforced
)
```

`HARNESS_INTERNAL_ACTIVITIES` is a tuple of exact names and anchored glob
patterns (`*` matches any run of characters; there is no substring
matching) taken from the harness's own source, not guessed:

```python
(
    "invoke_model_activity", "invoke_model_activity_streaming",
    "gemini_*",                      # Google GenAI SDK integration
    "jev_tool_approval",
    "code_start_batch", "code_resume_batch",
    "run_subagent_turn",
    "*-list-tools", "*-list-prompts", "*-get-prompt", "*-get-prompt-v2",
    "*-server-session",
    "*-sandbox_*",
)
```

Two things this does **not** do:

- **It is not a bypass for a presented warrant.** An activity on this list
  that arrives *with* warrant/PoP headers anyway — a caller attached one,
  correctly or not — is verified exactly like any other activity. The
  allowlist only waives the "no warrant provided" denial; it never weakens
  verification of a warrant that *is* there.
- **It can never swallow a real effect.** `<server>-call-tool-v2` (the MCP
  tool-call activity — see below) is deliberately absent from this preset,
  and `TenuoPluginConfig.__post_init__` rejects, at construction time, any
  `unwarranted_activities` pattern — yours or an extension of the preset —
  that would match an MCP call-tool-v2-shaped name (or the bare wildcard
  `"*"`). A typo like `"*-call-tool*"` fails fast at startup instead of
  silently exempting every tool call in production.

## `mcp_call_tool_activities` — MCP tool calls

The harness runs MCP tools as one activity per server,
`<server>-call-tool-v2`, with a single argument shaped like:

```python
@dataclasses.dataclass
class _StatefulCallToolsArguments:  # _StatelessCallToolsArguments is the same shape
    tool_name: str
    arguments: dict[str, Any] | None
    meta: dict[str, Any] | None = None
```

These calls **are** effects and must stay protected — but the warrant
should name the MCP tool the model asked for (`scale_cluster`) and
constrain `arguments`, not the per-server wrapper activity or its opaque
envelope:

```python
from tenuo.temporal.harness import HARNESS_MCP_CALL_TOOL_ACTIVITIES

config = TenuoPluginConfig(
    ...,
    mcp_call_tool_activities=HARNESS_MCP_CALL_TOOL_ACTIVITIES,  # ("*-call-tool-v2",)
)
```

With this set, both the outbound signer and the inbound verifier unwrap the
wrapper: `arguments.tool_name` becomes the signed/verified tool name, and
`arguments.arguments` becomes the signed/verified argument dict. A warrant
capability of `scale_cluster` with a constraint on `env` authorizes (or
denies) the *inner* call, not `acme-call-tool-v2` as a whole.

**`meta` is never authority.** It is transport metadata (tracing, routing)
that a caller could attach freely; the unwrap step never reads it to make
an authorization decision, so tampering with `meta` cannot smuggle a
warrant, bypass a constraint, or otherwise influence the outcome.

**Fails closed on a malformed wrapper.** An activity matching this list
that does not receive exactly one argument, or whose argument has a
missing/non-string `tool_name`, or a non-dict/non-`None` `arguments`, is
denied (`TenuoActivityMappingError`, wire error code
`ACTIVITY_MAPPING_FAILED`) rather than falling back to signing/verifying
the wrapper activity as a whole — which would let a malformed or spoofed
wrapper dodge the inner tool's argument-level constraints entirely.

The harness's older, deprecated `<server>-call-tool` activity (two loose
`tool_name`/`arguments` parameters, no wrapper, no `meta`) is intentionally
out of scope for this preset.

## Fails closed on asymmetry

`pop_exclude_args` and `mcp_call_tool_activities` are **symmetric**
settings: the outbound workflow-worker config and the inbound
activity-worker config must make the same decision for the same activity.
This is enforced by construction, not by a separate check — if only one
side excludes an argument or unwraps a wrapper, the two sides compute
different views of "what was signed," so the recomputed PoP bytes at
verification time do not match what was actually signed, and the call is
denied (`PopVerificationError`), never silently authorized against the
wrong payload. In practice: build both configs from the **same**
`harness_plugin_config(...)` call (or the same explicit preset values), not
two independently-assembled ones.

## `harness_plugin_config` — one call, extendable

```python
from tenuo.temporal.harness import harness_plugin_config

config = harness_plugin_config(
    key_resolver=my_key_resolver,
    trusted_roots=[control_key.public_key],
    require_warrant=True,
    activity_fns=[...],
    # Extend the presets — these ADD to the harness defaults, they don't replace them:
    unwarranted_activities=["my_own_internal_activity"],
    pop_exclude_args=["extra_framework_context"],
)
```

Every other `TenuoPluginConfig` field (`on_denial`, `audit_callback`,
`clearance_requirements`, ...) passes straight through.

## `warrant_evaluator` — auto mode, gated by the task warrant

The harness's [auto mode](https://pypi.org/project/temporal-agent-harness/)
gives every gated tool call a durable seam: the call pauses in the
workflow, an evaluator may approve, deny, or escalate it, and anything
escalated waits for a human. `warrant_evaluator` puts the task warrant at
the front of that seam:

```python
from tenuo.temporal.harness import warrant_evaluator

evaluator = warrant_evaluator(
    get_warrant=lambda: workflow.instance().task_warrant,
    next_evaluator=agent.jev_evaluator(),  # or None to approve everything in-warrant
    review_above={"issue_refund": ("amount_cents", 5_000_00)},
)
```

1. **Outside the warrant: DENY**, with a reason the model can act on — the
   call never reaches `next_evaluator` or a human.
2. **Inside the warrant, above `review_above`'s threshold: ESCALATE** to
   the harness's human gate. This is operator policy about who looks at a
   call, not a widening of what the call may do.
3. **Inside the warrant, below the threshold:** delegate to
   `next_evaluator` (pass a real evaluator, e.g. the harness's Jev
   built-in, in production) for the judgment call the warrant cannot make
   — is this refund a *good* idea, not just an *allowed* one.

This is the *early* check, for the model's sake — the binding check still
runs on the effects worker, where the Tenuo plugin verifies the warrant and
a Proof-of-Possession signature over the exact arguments before the
activity body starts. A call that reaches the worker by another route (a
pre-approved tool, a human approval, a bug in an evaluator) is still held
to the same bounds.

## Delivering a warrant that didn't arrive as a header

A workflow started through the harness's own entry points (its session
manager, web app, or chat server) receives no Tenuo headers today — nothing
in the harness forwards them yet (see the gap below). Until it does, a
common pattern is a custom `@workflow.update` that hands the agent its
warrant as an ordinary argument (e.g. a base64 string), the way the refund
example's `open_ticket` does:

```python
@workflow.update
def open_ticket(self, warrant_b64: str) -> str:
    self.ticket_warrant = Warrant.from_base64(warrant_b64)
    tenuo_install_warrant(self.ticket_warrant, HOLDER_KEY_ID)
    return self.ticket_warrant.id
```

`tenuo_install_warrant(warrant, key_id)` installs it into the same ambient,
per-run context a header-carried warrant would have populated at workflow
start — so every later `workflow.execute_activity()` call, including a
harness tool's own dispatcher, is transparently signed against it. It is a
security boundary, not a passthrough: it validates the warrant's chain
against this worker's `trusted_roots` and confirms `key_id` actually
resolves to the warrant's own holder key before installing anything,
failing closed (`TenuoContextError`) otherwise.

## What's still a harness gap, not a Tenuo one

Some parts of the harness integration need a small hook from the harness
side before Tenuo can close them without a workaround. Confirmed by reading
the actual call sites, not inferred:

- **Warrant delivery through the session manager / web app / chat server.**
  `SessionManagerWorkflow.create_session` starts the child agent workflow
  with a plain `workflow.start_child_workflow(...)` — no header
  passthrough — and `AgentConfig` has no metadata/headers field for a
  caller to populate one. The web app's HTTP handlers call `create_session`
  through the *web app's own* Temporal client, not the original caller's,
  so there is no channel today for an HTTP caller to attach a warrant at
  all. The concrete ask: a generic passthrough field on `AgentConfig` that
  `create_session` forwards, unchanged, into the child workflow start's own
  headers. A caller with direct Temporal client access (this doc's own
  examples, and the refund example) already has no such gap — see above.
- **Narrower per-subagent warrants at spawn.** `TenuoPluginConfig.
  child_warrant_policy` (this SDK) mints a narrower warrant for a *plain*
  `workflow.start_child_workflow()` call, which is exactly what
  `AgentWorkflowRunner.start_subagent()` uses — no harness hook needed for
  the mechanism itself. What's not done is wiring it into an actual
  `subagent_toolset`-based demo.
- **Carrying a cryptographic approval through the harness's own gate
  resolution.** `TenuoClientInterceptor.set_approvals_for_update()` (this
  SDK) already lets a signed approval ride on the *update* that resolves a
  harness gate (e.g. `approve_tool`) — no harness hook needed for that
  either. A tighter integration (`ToolApprovalDecision` gaining an optional
  opaque `attestation` field) is a further harness-side option, not a
  requirement.

See `HARNESS_SUPPORT.md` in the Tenuo monorepo for the full investigation
and status.

## See also

- [Temporal Integration](./temporal.md) — the base integration this module
  builds on: keys, PoP, constraints, production checklist.
- [Temporal Integration Reference](./temporal-reference.md) — deep
  reference for `activity_fns`, sandbox passthrough, PoP mechanics, and the
  full threat model.
- [Temporal Nexus Authorization](./temporal-nexus.md) — for the harness's
  Nexus-brokered agents and MCP servers.
