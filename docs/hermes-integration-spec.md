# Hermes Agent Integration — Implementation & Strategy Spec

## Overview

This spec covers building a first-class Tenuo integration for [Hermes Agent](https://github.com/NousResearch/hermes-agent) (NousResearch), the open-source self-improving agent with 154k stars. The integration targets Hermes's autonomous-execution use cases — cron-scheduled agents, `delegate_task` sub-agents, and multi-user gateway deployments — where cryptographic authorization provides genuine value that Hermes's existing human-in-the-loop approval system cannot.

**Positioning:** *Give your Hermes agents a permission slip.* Before you send an agent to do a task unattended, you hand it a cryptographically-signed warrant that says what it can touch, for how long, and nothing else.

### Relationship to Tenuo Cloud

The integration's primary job is being the **telemetry pipe**: getting real Hermes tool calls (tool name, arguments, session context) into Cloud so Cloud's warrant builder has real behavior to learn from. Warrant authoring — audit learning, natural language minting, templates, tightening from observed call patterns — is Cloud's responsibility and is already built. The `hermes-tenuo` plugin does not need to solve warrant authoring friction; Cloud solves it.

**The on-ramp is audit-first:**

1. Install `hermes-tenuo`, set `TENUO_CONNECT_TOKEN` — tool calls start flowing to Cloud immediately
2. Cloud's warrant builder observes real call patterns across sessions
3. Cloud generates a tight warrant for the operator to review and activate
4. Operator activates enforcement — `pre_tool_call` now blocks anything outside the warrant
5. Ongoing: Cloud audit log records every authorized and denied call with full attribution

The operator goes from zero to cryptographically-authorized without writing a single capability by hand. This means steps 1–2 must be as frictionless as possible: one config token, no warrant required to start, audit events flowing immediately.

**Implementation priority order follows directly from this:**

| Priority | What | Why |
|---|---|---|
| 1 | `post_tool_call` → `emit_for_enforcement()` → Cloud | Feeds warrant builder; delivers value before enforcement is configured |
| 2 | `pre_tool_call` block enforcement | The payoff once Cloud has generated and activated a warrant |
| 3 | `TENUO_CONNECT_TOKEN` as the only required config | One token, everything else flows from Cloud |

---

## Architecture

### How Hermes tool dispatch works

Every tool call in Hermes flows through one function:

```
LLM output → handle_function_call(tool_name, args) → registry.dispatch(name, args) → handler
```

Hermes has a documented plugin hook system that fires **before** dispatch:

```python
# hermes_cli/plugins.py — fires for every tool call
invoke_hook("pre_tool_call", tool_name=name, args=args, task_id=..., session_id=..., tool_call_id=...)
```

A plugin blocks a call by returning `{"action": "block", "message": "reason"}`. The docstring for this hook explicitly lists "security restrictions, approval workflows" as its intended use cases. There are also `post_tool_call` (observer, with `duration_ms`) and `transform_tool_result` hooks.

### Delivery model — two packages

```
┌─────────────────────────────┐     ┌─────────────────────────────────┐
│  tenuo (PyPI)               │     │  hermes-tenuo (PyPI)             │
│  tenuo/hermes.py            │◄────│  hermes_tenuo/__init__.py        │
│                             │     │  hermes_tenuo/plugin.yaml        │
│  HermesGuard                │     │  entry_points:                   │
│  - pre_tool_call()          │     │    hermes_agent.plugins =        │
│  - post_tool_call()         │     │      hermes_tenuo                │
│  - set_session_warrant()    │     │                                  │
└─────────────────────────────┘     └─────────────────────────────────┘
```

**`tenuo/hermes.py`** — the Tenuo-side adapter: `HermesGuard` class, session warrant registry, enforcement logic. Follows the same pattern as `tenuo/crewai.py` and `tenuo/google_adk/`.

**`hermes-tenuo`** — a separate PyPI package that is a Hermes plugin. Users install it, enable it in `config.yaml`, and it auto-discovers the warrant configuration. It imports `tenuo` as a dependency. This is the distribution unit Hermes users actually install.

Users do not need to know that there are two packages — from their perspective they `pip install hermes-tenuo` and enable a plugin.

---

## Implementation Plan

### Confirmed: plugin config schema

Plugin-specific configuration in Hermes lives at `plugins.entries.<plugin-key>.*` in `config.yaml`. This is a first-class documented pattern used by bundled plugins. The plugin reads it via `load_config()["plugins"]["entries"]["tenuo-guard"]`. The complete install experience:

```bash
pip install hermes-tenuo
```

```yaml
# ~/.hermes/config.yaml
plugins:
  enabled:
    - tenuo-guard
  entries:
    tenuo-guard:
      connect_token: tc_live_...        # required: paste from Cloud dashboard
      warrant: ~/.hermes/tenuo/warrant  # optional: path or base64, activates enforcement
      signing_key_env: TENUO_SIGNING_KEY # optional: env var name holding signing key
```

All three keys fall back to env vars (`TENUO_CONNECT_TOKEN`, `TENUO_WARRANT`, `TENUO_SIGNING_KEY`) so CI/container deployments need no config file changes. `connect_token` is the only required field to start flowing telemetry. `warrant` activates enforcement — absent means audit-only.

---

### Phase 1 — Full working integration (week 1)

**`tenuo/hermes.py` — `HermesGuard` class**

```python
from tenuo.hermes import HermesGuard

guard = HermesGuard(
    warrant=my_warrant,
    signing_key=agent_key,
    trusted_roots=[issuer_public_key],
    on_denial="block",       # "block" | "log" (audit-only mode)
    audit_callback=None,
)

# Register as a Hermes plugin hook manually (or use hermes-tenuo package)
guard.pre_tool_call(tool_name, args, session_id=session_id)   # → dict | None
guard.post_tool_call(tool_name, args, result, duration_ms=ms) # → None
```

Internal design mirrors `CrewAIGuard`:
- `_authorize(tool_name, args, session_id)` calls `enforce_tool_call()` from `tenuo._enforcement`
- Returns `{"action": "block", "message": "..."}` on denial, `None` on allow
- `on_denial="log"` emits audit event but returns `None` (audit-only mode for phased rollout)
- `_session_warrants: dict[str, BoundWarrant]` for session-scoped warrants (gateway use case)

**`hermes-tenuo` plugin package**

Directory layout:
```
hermes-tenuo/
  hermes_tenuo/
    __init__.py          # setup(ctx) entry point, hook registration
    _config.py           # load warrant from env / file / config.yaml
    _guard.py            # thin wrapper delegating to tenuo.hermes.HermesGuard
  plugin.yaml
  pyproject.toml
  README.md
```

`plugin.yaml`:
```yaml
name: tenuo-guard
version: 0.1.0
description: Warrant-based authorization for Hermes tool calls. Scopes sub-agents
  and unattended cron jobs to least-privilege warrants.
author: Tenuo
kind: standalone
provides_hooks:
  - pre_tool_call
  - post_tool_call
requires_env:
  - name: TENUO_WARRANT
    description: Base64-encoded warrant (or path to .warrant file)
    required: false
  - name: TENUO_SIGNING_KEY
    description: Base64-encoded signing key for Proof-of-Possession
    required: false
```

`__init__.py` entry point:
```python
def setup(ctx):
    """Called by Hermes plugin loader at startup."""
    from hermes_tenuo._guard import build_guard
    guard = build_guard(ctx)
    if guard is None:
        return  # No warrant configured — silently no-op
    ctx.register_hook("pre_tool_call", guard.pre_tool_call_hook)
    ctx.register_hook("post_tool_call", guard.post_tool_call_hook)
```

`pyproject.toml` entry point:
```toml
[project.entry-points."hermes_agent.plugins"]
tenuo-guard = "hermes_tenuo"
```

**Warrant resolution priority** (in `_config.py`):
1. `TENUO_WARRANT` env var (base64 or file path)
2. `~/.hermes/tenuo/warrant.json` (default file location)
3. Hermes `config.yaml` key `plugins.tenuo-guard.warrant_path`
4. Not configured → plugin loads but does nothing (fail-open at startup, fail-closed per call)

**pyproject.toml addition** (in main `tenuo` package):
```toml
hermes = [
    "tenuo>=0.1; python_version >= '3.10'",  # hermes requires 3.10+
]
```

**Phase 1 deliverables:**
- `tenuo/hermes.py` — `HermesGuard`, `HermesGuardBuilder`, `AuditEvent`
- `tenuo/_version_compat.py` addition — `check_hermes_compat()`
- `control_plane.py` — add `("hermes_agent", "framework_hermes")` to framework detection
- `hermes-tenuo/` package — `plugin.yaml`, `setup()`, hook wiring, config resolution
  - `post_tool_call` → `emit_for_enforcement()` → Cloud (audit-only mode when no warrant)
  - `pre_tool_call` block enforcement (passthrough when no warrant present)
  - `pre_tool_call` for `delegate_task` — attenuated child warrant pre-registration
  - `on_session_start` child warrant lookup by `(parent_session_id, task_index)`
  - `connect_token` / `TENUO_CONNECT_TOKEN` as the only required config
  - `warrant` / `TENUO_WARRANT` activates enforcement (top-level sessions only — never children)
  - `child_warrant` / config field for uniform child attenuation (V1 fallback)
  - `TENUO_SIGNING_KEY` for Tier 2 PoP
- `on_session_start` / `on_session_end` hook wiring for session warrant registry
- `hermes-tenuo mint` CLI — Cloud-backed warrant minting to stdout for cron/script use
- `tenuo-python/examples/hermes/subagent_scope.py` — delegate_task with attenuated warrant
- `tenuo-python/examples/hermes/cron_warrant.py` — cron job with TTL-bounded warrant
- `tenuo-python/examples/hermes/gateway_multiuser.py` — per-session warrant injection
- `tenuo[hermes]` extra in `pyproject.toml`

### Phase 2 — Tests, docs, release (week 2)

**Test suite** (`tenuo-python/tests/adapters/test_hermes.py`):
```
test_hermes_post_tool_call_emits_to_cloud_when_no_warrant
test_hermes_pre_tool_call_passthrough_when_no_warrant
test_hermes_pre_tool_call_allows_authorized_call
test_hermes_pre_tool_call_blocks_unauthorized_tool
test_hermes_pre_tool_call_blocks_constraint_violation
test_hermes_pre_tool_call_blocks_expired_warrant
test_hermes_session_warrant_isolation
test_hermes_log_mode_does_not_block
test_hermes_audit_callback_fires_on_allow_and_deny
test_hermes_post_tool_call_audit_includes_duration_ms
test_hermes_connect_token_only_config_works
test_hermes_no_crash_on_missing_tenuo_core
```

**Documentation** (`docs/hermes.md`) — mirrors structure of `docs/temporal.md`:
- What is Hermes Agent
- How Tenuo fits (the autonomy gap narrative)
- Install and enable (`pip install hermes-tenuo` + two config lines)
- Audit-first: connect to Cloud, observe call patterns
- Activate enforcement once Cloud generates a warrant
- The three use cases with runnable examples
- Security section
- Reference

**Phase 2 deliverables:**
- Full test suite
- `docs/hermes.md`
- `hermes-tenuo` published to PyPI
- `tenuo[hermes]` extra published

---

## API Reference

### `tenuo.hermes.HermesGuard`

```python
class HermesGuard:
    def __init__(
        self,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        *,
        trusted_roots: Optional[list] = None,
        on_denial: Literal["block", "log"] = "block",
        on_no_warrant: Literal["block", "passthrough"] = "block",
        audit_callback: Optional[Callable[[HermesAuditEvent], None]] = None,
    ): ...

    # Hook implementations — wired directly into Hermes plugin hooks
    def pre_tool_call_hook(
        self, tool_name: str, args: dict, *,
        task_id: str = "", session_id: str = "", tool_call_id: str = ""
    ) -> Optional[dict]: ...
    # Returns {"action": "block", "message": "..."} or None

    def post_tool_call_hook(
        self, tool_name: str, args: dict, result: str, *,
        task_id: str = "", session_id: str = "",
        tool_call_id: str = "", duration_ms: int = 0,
    ) -> None: ...

    # Session management (gateway multi-user)
    def set_session_warrant(self, session_id: str, warrant: Warrant, signing_key: Optional[SigningKey] = None) -> None: ...
    def clear_session_warrant(self, session_id: str) -> None: ...

    # Introspection
    def explain(self, tool_name: str, args: dict, *, session_id: str = "") -> ExplanationResult: ...
```

### `tenuo.hermes.HermesGuardBuilder`

```python
class HermesGuardBuilder:
    def allow(self, tool_name: str, **constraints) -> "HermesGuardBuilder": ...
    def with_warrant(self, warrant: Warrant, signing_key: SigningKey) -> "HermesGuardBuilder": ...
    def trusted_roots(self, roots: list) -> "HermesGuardBuilder": ...
    def on_denial(self, mode: Literal["block", "log"]) -> "HermesGuardBuilder": ...
    def on_no_warrant(self, policy: Literal["block", "passthrough"]) -> "HermesGuardBuilder": ...
    def audit(self, callback: Callable[[HermesAuditEvent], None]) -> "HermesGuardBuilder": ...
    def build(self) -> HermesGuard: ...
```

---

## Examples

### 1. Sub-agent scope (the primary pitch)

```python
# orchestrator.py
from tenuo import SigningKey, Warrant, Subpath, Wildcard
from tenuo.hermes import HermesGuardBuilder

# Control plane mints the orchestrator's warrant
control_key = SigningKey.generate()
orchestrator_warrant = (
    Warrant.mint_builder()
    .holder(orchestrator_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("web_search", query=Wildcard())
    .capability("write_file", path=Subpath("/tmp/reports"), content=Wildcard())
    .capability("delegate_task", task=Wildcard(), context=Wildcard())
    .ttl(3600)
    .mint(control_key)
)

# Before spawning a sub-agent via delegate_task, attenuate the warrant.
# The sub-agent only gets web_search — not file access.
researcher_warrant = (
    orchestrator_warrant.grant_builder()
    .holder(researcher_key.public_key)
    .capability("web_search", query=Wildcard())
    .ttl(600)
    .grant(orchestrator_key)
)

# The sub-agent runs with the attenuated warrant in its session.
# Any attempt to call read_file, write_file, or terminal is blocked
# at the pre_tool_call hook — even if the model hallucinates those calls.
```

### 2. Cron job with expiring warrant

```python
# In hermes config.yaml or cron definition
from tenuo import Warrant, Subpath, Wildcard

nightly_warrant = (
    Warrant.mint_builder()
    .holder(cron_agent_key.public_key)
    .capability("read_file", path=Subpath("/data/reports"))
    .capability("write_file", path=Subpath("/tmp/nightly"), content=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .ttl(3600)   # Expires after 1 hour — if the job runs long, it stops
    .mint(control_key)
)
# Write warrant to TENUO_WARRANT env before the cron fires.
# If the cron job exceeds 1 hour or tries to touch anything outside
# /data/reports or /tmp/nightly, the call is blocked.
```

### 3. Multi-user gateway

```python
# In gateway setup (hermes-tenuo plugin _guard.py)
from tenuo.hermes import HermesGuard

guard = HermesGuard(
    signing_key=gateway_signing_key,
    trusted_roots=[control_plane_public_key],
    on_denial="block",
    on_no_warrant="block",  # Unknown users get nothing
)

def on_session_start(ctx, session_id, platform, user_id, **kwargs):
    user_warrant = warrant_store.get(platform, user_id)   # Your policy layer
    if user_warrant:
        guard.set_session_warrant(session_id, user_warrant)

def on_session_end(ctx, session_id, **kwargs):
    guard.clear_session_warrant(session_id)
```

---

## Distribution & Release Strategy

### Package naming

| Package | PyPI name | Import |
|---|---|---|
| Tenuo adapter | `tenuo[hermes]` | `from tenuo.hermes import HermesGuard` |
| Hermes plugin | `hermes-tenuo` | installed as Hermes plugin, no user imports |

`hermes-tenuo` is the user-facing distribution unit. `tenuo[hermes]` is for developers embedding the guard directly.

### Install flow for Hermes users

```bash
pip install hermes-tenuo
# Then in ~/.hermes/config.yaml:
plugins:
  enabled:
    - tenuo-guard
```

Because `hermes-tenuo` registers the `hermes_agent.plugins` entry point, Hermes auto-discovers it after pip install. No path configuration, no copying files into `~/.hermes/plugins/`.

### Release sequence

**Week 3 — soft launch:**
- Publish `hermes-tenuo` 0.1.0 to PyPI
- Open PR to `NousResearch/hermes-agent` adding `hermes-tenuo` to the optional-skills / plugin docs
- Post in Hermes Discord with the sub-agent scoping example as the hook

**Week 4 — content:**
- Blog post: "Giving your Hermes sub-agents a permission slip" — lead with the `delegate_task` story, avoid auth jargon in the first 500 words
- Hermes Skills Hub entry: a skill that teaches the agent how to help the user configure Tenuo warrants for their own cron jobs

**Ongoing:**
- Monitor `hermes-agent` releases for plugin API changes (version compat check covers breaking changes)
- The `post_tool_call` hook already provides `duration_ms` — use this for a latency dashboard demo (shows Tenuo as observability, not just restriction)

---

## Security Invariants

These are non-negotiable constraints that must be reflected in every layer of the implementation and all documentation.

### Agents are warrant consumers, never warrant requesters

The warrant constrains the agent. If the agent can fetch, refresh, or request its own warrant, the constraint is circular and meaningless — a compromised agent or a successful prompt injection could request a broader warrant, extend an expired one, or enumerate capabilities to pick the most permissive.

**The trust flow is strictly one-directional:**

```
Cloud / control plane
    ↓  mints warrant (operator or gateway orchestration)
Gateway / scheduler / parent agent
    ↓  injects warrant into session context at startup
Agent (read-only consumer)
    ↓  presents warrant; cannot modify, refresh, or re-request it
```

The `hermes-tenuo` plugin must never expose warrant fetching, issuance, or refresh to agent tool context. `TENUO_API_KEY` (the Cloud credential) lives in gateway orchestration — never in agent process scope.

**Concretely:**
- Cron: the scheduler mints and injects the warrant before the job starts. When the warrant TTL expires, the job cannot make new tool calls. It does not auto-renew.
- Subagents: the parent attenuates its warrant and injects before spawning via `delegate_task`. The child never calls home for a new warrant.
- Gateway multi-user: the `on_session_start` hook (gateway orchestration context, unreachable by agent tools) fetches the user's warrant from the policy store and calls `guard.set_session_warrant()`. The agent never touches this.

```python
# Fires in gateway infrastructure BEFORE the agent processes any message.
# Not callable by any agent tool — prompt injection cannot reach this.
def on_session_start(ctx, session_id, platform, user_id, **kwargs):
    warrant = warrant_store.get_warrant_for_user(platform, user_id)
    guard.set_session_warrant(session_id, warrant)

def on_session_end(ctx, session_id, **kwargs):
    guard.clear_session_warrant(session_id)
```

This is not a limitation of the current SDK — it is a deliberate design invariant. Any future Cloud warrant distribution API must be documented as an **orchestration-layer call only**, not an agent-callable endpoint.

**Runtime human approval via approval gates (not warrant expansion)**

For scenarios where certain capabilities need a human sign-off at runtime, the correct pattern is approval gates on a sufficiently broad top-level warrant — not dynamic warrant expansion. The operator sets the full scope at deploy time; Cloud gates execution on sensitive capabilities until the operator approves. The warrant never mutates.

```python
# Top agent: broad warrant with approval gates on sensitive capabilities
warrant = (
    Warrant.mint_builder()
    .holder(agent_key.public_key)
    .capability("read_file", path=Subpath("/data"))    # always allowed
    .capability("web_search", query=Wildcard())         # always allowed
    .capability("write_file", path=Wildcard(),          # approval-gated
                content=Wildcard())
    .capability("terminal", command=Wildcard())         # approval-gated
    .ttl(3600)
    .mint(control_key)
)
```

When an approval-gated capability fires, `enforce_tool_call()` submits to Cloud via the existing `cp_approval.py` infrastructure. Cloud notifies the operator, operator approves or denies, tool call proceeds or is blocked. No new warrant is issued — the existing warrant already authorizes the capability, conditional on human sign-off.

This collapses the design space to three clean tiers:
- **Always allowed** — operator is comfortable with autonomous use
- **Approval-gated** — within scope but requires per-call human sign-off
- **Outside the warrant** — hard blocked, no approval path

There is no `request_capability_expansion()` API. Dynamic warrant mutation at runtime re-introduces the circular trust problem: the agent cannot be both the constrained party and an initiator of constraint relaxation. Starting with a broad warrant and gating sensitive parts is both simpler and more auditable — the full scope is visible at deploy time.

### `execute_code` sandbox boundary

Hermes's `execute_code` tool runs arbitrary Python inside a sandbox that can itself call tools via RPC. The `pre_tool_call` hook intercepts `execute_code` as a tool call (so unauthorized calls to `execute_code` are blocked). However, Python code running **inside** the sandbox executes with the sandbox's own tool-call path, which may bypass the hook depending on how the sandbox bridges to the registry.

Document this boundary explicitly. Do not imply Tenuo covers the sandbox interior in V1. Investigate the sandbox RPC path before making coverage claims.

---

## Resolved & Open Questions

### Resolved

**1. `delegate_task` warrant threading — confirmed vulnerability, V1 solution defined**

The child's `subagent_id` is `f"sa-{task_index}-{uuid4().hex[:8]}"` — random, unknowable in advance from `pre_tool_call`. However, children receive `parent_session_id` from their constructor (confirmed in `delegate_tool.py`). This is the linkage.

`TENUO_WARRANT` env var leaks across all subagents in the same process. Children must never source their warrant from env vars — the plugin must use the session warrant registry exclusively for child warrant delivery.

**V1 solution:**
- In `pre_tool_call` for `tool_name == "delegate_task"`: parse `tasks`, generate per-task attenuated warrants, store as `_pending_child_warrants[(parent_session_id, task_index)]`
- In the child's `on_session_start`: look up warrant by `(parent_session_id, task_index)` using a per-parent counter
- V1 fallback: single `child_warrant` config field — all children get the same attenuated warrant, simpler but less granular

```yaml
plugins:
  entries:
    hermes-tenuo:
      connect_token: tc_live_...
      warrant: ~/.hermes/tenuo/parent.warrant
      child_warrant: ~/.hermes/tenuo/child.warrant  # attenuated, all children
```

**2. `hermes-tenuo mint` CLI — confirmed necessary, in Phase 1**

```bash
export TENUO_WARRANT=$(hermes-tenuo mint \
  --connect-token $TENUO_CONNECT_TOKEN \
  --ttl 1h \
  --allow read_file:path=/data/reports \
  --allow write_file:path=/tmp/nightly \
  --allow memory)
hermes run --task nightly_cleanup
```

Cloud handles signing; operator never touches key material. Output is base64 warrant to stdout.

**3. Package naming — entry-point plugins don't hit Issue #18005**

For pip entry-point installs, Hermes sets `manifest.name` and `manifest.key` from `ep.name` (the pyproject.toml entry point key) — `plugin.yaml` is NOT read during entry-point discovery. Issue #18005 (directory name must match `plugin.yaml` name) affects filesystem plugins only.

Required naming consistency:

| Location | Value |
|---|---|
| `pyproject.toml` entry point key | `hermes-tenuo` |
| `config.yaml` `plugins.enabled` | `hermes-tenuo` |
| `config.yaml` `plugins.entries` key | `hermes-tenuo` |
| `plugin.yaml` `name` field | `hermes-tenuo` |
| Python package directory | `hermes_tenuo` |

```toml
[project.entry-points."hermes_agent.plugins"]
hermes-tenuo = "hermes_tenuo"   # key = manifest name; value = Python module
```

**4. `execute_code` sandbox — V1 boundary confirmed, V2 design specified**

V1: `pre_tool_call` intercepts `execute_code` as a tool call (blocking unauthorized invocations). Code running inside the sandbox communicates back to the parent via RPC/MCP and may bypass the hook. Document this boundary explicitly; do not claim coverage of the sandbox interior.

V2: Inject the attenuated warrant into the sandbox's environment block as a mandatory transport header on every upstream RPC call. A prompt-injection RCE inside the sandbox would still be bounded by the warrant attached to those RPC calls.

### Open

**5. Hermes ACP toolset**: The `hermes-acp` toolset targets editor integrations (VS Code, Zed). Second distribution channel worth targeting post-launch — ACP users are developers who think about tool scoping.
