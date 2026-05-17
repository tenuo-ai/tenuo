---
title: Hermes Agent Integration
description: Warrant-based authorization for Hermes Agent tool calls
---

# Hermes Agent Integration

## What is Hermes Agent?

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (NousResearch) is an open-source self-improving AI agent with a built-in learning loop. It supports 40+ tools, multi-platform gateways (Telegram, Discord, Slack, etc.), cron scheduling, and `delegate_task` for parallel sub-agents — all running on infrastructure you own.

## How Tenuo fits

Hermes already has a human-in-the-loop approval system for interactive use. What it lacks is authorization for **unattended operation**: cron jobs that run at 3am, sub-agents spawned by `delegate_task`, and gateways serving multiple users with different permission levels.

Tenuo provides cryptographic warrant enforcement at Hermes's `pre_tool_call` plugin hook. Every tool call is checked against a signed warrant that specifies exactly what tools the agent may call, with what arguments, before execution. Tenuo Cloud observes your agent's real call patterns and generates tight warrants — you review and activate them.

**The on-ramp is audit-first:**

1. Install `hermes-tenuo`, paste `TENUO_CONNECT_TOKEN` → tool calls stream to Cloud immediately
2. Cloud's warrant builder learns your agent's real call patterns across sessions
3. Cloud generates a tight warrant for you to review and activate
4. Activate enforcement — `pre_tool_call` now blocks anything outside the warrant
5. Ongoing: every authorized and denied call is recorded with full attribution

## Prerequisites

- [Hermes Agent](https://github.com/NousResearch/hermes-agent) installed (`hermes --version`)
- Python 3.10+
- A [Tenuo Cloud](https://cloud.tenuo.ai) account (for the audit-first flow) or self-managed keys

## Install

```bash
pip install hermes-tenuo
```

## Enable

Add two lines to `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - hermes-tenuo
  entries:
    hermes-tenuo:
      connect_token: tc_live_...   # paste from Tenuo Cloud dashboard → Quick Connect
```

Restart `hermes`. Tool calls immediately start flowing to Cloud. The plugin logs `hermes-tenuo: active (audit-only)` at startup.

To verify:

```bash
hermes-tenuo status
```

## Activate enforcement

Once Cloud has generated a warrant for your agent:

```yaml
plugins:
  entries:
    hermes-tenuo:
      connect_token: tc_live_...
      warrant: ~/.hermes/tenuo/warrant   # path to warrant file, or base64 string
      # signing_key_env: TENUO_SIGNING_KEY  # env var holding Ed25519 signing key
```

The plugin logs `hermes-tenuo: active (enforcing)` at startup. Any tool call outside the warrant scope is blocked with a structured error before the tool handler runs.

> **Note:** Enforcement requires both `warrant` and a signing key (`TENUO_SIGNING_KEY` env var or `signing_key_env` config). Without a signing key, the plugin passes through and logs a warning — it does not silently enforce or silently no-op.

## Use cases

### 1. Cron agents with expiring warrants

A cron agent that runs at 2am should not have the same permission surface as an interactive session. Mint a warrant scoped to exactly the paths and tools the job needs, with a TTL that expires after it should be done.

```python
from tenuo import SigningKey, Warrant, Subpath, Wildcard

control_key = SigningKey.generate()   # your control plane key
cron_agent_key = SigningKey.generate()

nightly_warrant = (
    Warrant.mint_builder()
    .holder(cron_agent_key.public_key)
    .capability("read_file", path=Subpath("/data/reports"))
    .capability("write_file", path=Subpath("/tmp/nightly"), content=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .ttl(3600)   # expires after 1 hour
    .mint(control_key)
)
```

In crontab or a Docker entrypoint:

```bash
export TENUO_WARRANT=$(hermes-tenuo mint --ttl 1h --allow read_file:path=/data/reports ...)
hermes run --task nightly_cleanup
```

If the job runs over an hour, or tries to touch anything outside `/data/reports` or `/tmp/nightly`, the call is blocked — even if the model hallucinates a broader action.

See [`examples/hermes/cron_warrant.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/hermes/cron_warrant.py) for a full runnable example.

### 2. Sub-agent scope with `delegate_task`

When Hermes's orchestrator spawns sub-agents via `delegate_task`, child sessions automatically receive the `child_warrant` rather than the parent's root warrant. The orchestrator can read and write files; the researcher sub-agent can only search the web.

```yaml
# config.yaml
plugins:
  entries:
    hermes-tenuo:
      connect_token: tc_live_...
      warrant: ~/.hermes/tenuo/orchestrator.warrant
      child_warrant: ~/.hermes/tenuo/researcher.warrant
```

How it works: `pre_tool_call` intercepts `delegate_task` calls and pre-registers the `child_warrant` for upcoming child sessions. Child sessions are detected by session ID — the first session seen is the primary (orchestrator); all subsequent different session IDs receive the `child_warrant`.

See [`examples/hermes/subagent_scope.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/hermes/subagent_scope.py) for a full runnable example.

### 3. Multi-user gateway

When a Hermes gateway (Telegram, Discord, Slack, etc.) serves multiple users, each user session gets a different warrant from your policy store. Sessions are isolated: one user's warrant cannot influence another's.

```python
from tenuo.hermes import HermesGuard

guard = HermesGuard(
    signing_key=gateway_signing_key,
    trusted_roots=[control_key.public_key],
)

# In your gateway session handler:
def on_message(session_id: str, user_id: str):
    warrant = policy_store.get_warrant(user_id)
    if warrant:
        guard.set_session_warrant(session_id, warrant, gateway_signing_key)

def on_session_end(session_id: str):
    guard.clear_session_warrant(session_id)
```

See [`examples/hermes/gateway_multiuser.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/hermes/gateway_multiuser.py) for a full runnable example.

## Security

**Agents are warrant consumers, never warrant requesters.** The warrant constrains the agent. If the agent could fetch or refresh its own warrant, a compromised agent or a successful prompt injection could request broader authority. `TENUO_WARRANT` must never be set from within agent tool context — it must be injected by orchestration code (gateway setup, cron scheduler, parent agent) before the agent runs.

**Child warrants for `delegate_task`.** Child sessions inherit `child_warrant`, not the parent's root warrant. The primary session (the first session seen by the plugin) uses the root warrant; all other sessions use `child_warrant`. For gateways where each user has an explicit warrant registered via `set_session_warrant()`, that warrant takes precedence.

**Fail-closed.** Missing or malformed warrants with enforcement enabled block all tool calls. A warrant present without a signing key logs a warning and passes through — it does not silently enforce partial constraints.

**`execute_code` sandbox boundary.** The `pre_tool_call` hook intercepts the `execute_code` tool call itself (blocking unauthorized invocations). Python code running inside the execute_code sandbox communicates back to the parent via an internal RPC path that bypasses the hook. Do not rely on Tenuo to constrain what happens inside the sandbox interior.

| Check | Behavior |
|---|---|
| No warrant, audit-only | All calls pass through; every call logged to Cloud |
| Warrant present, no signing key | Warning logged; calls pass through |
| Tool not in warrant | `{"action": "block", "message": "..."}` |
| Argument outside constraint | `{"action": "block", "message": "..."}` |
| Warrant expired | `{"action": "block", "message": "..."}` |
| `on_denial="log"` | Denial logged; call not blocked |

## API reference

### `HermesGuard`

```python
from tenuo.hermes import HermesGuard

guard = HermesGuard(
    warrant=None,          # Warrant object; None = audit-only
    signing_key=None,      # SigningKey for PoP; required for enforcement
    child_warrant=None,    # Warrant for delegate_task sub-agent sessions
    trusted_roots=None,    # List of trusted issuer PublicKeys
    on_denial="block",     # "block" | "log"
    audit_callback=None,   # Callable[[HermesAuditEvent], None]
)
```

**Hook methods** (wired by hermes-tenuo plugin automatically):

```python
# Returns {"action": "block", "message": "..."} or None
guard.pre_tool_call(tool_name, args, *, task_id="", session_id="", tool_call_id="")

# Emits audit event to Cloud
guard.post_tool_call(tool_name, args, result, *, session_id="", duration_ms=0, ...)

# Session lifecycle (for gateway use)
guard.set_session_warrant(session_id, warrant, signing_key=None)
guard.clear_session_warrant(session_id)
guard.on_session_end(session_id)
```

### `HermesAuditEvent`

```python
@dataclass
class HermesAuditEvent:
    tool: str
    args: dict
    decision: str      # "ALLOW" | "DENY" | "AUDIT"
    reason: str
    session_id: str
    task_id: str
    tool_call_id: str
    duration_ms: int
    timestamp: str
```

## Configuration reference

All settings fall back to environment variables if not set in `config.yaml`.

| `config.yaml` key | Environment variable | Required | Description |
|---|---|---|---|
| `connect_token` | `TENUO_CONNECT_TOKEN` | For Cloud | Quick Connect token from Tenuo Cloud dashboard |
| `warrant` | `TENUO_WARRANT` | For enforcement | Path to warrant file or base64-encoded warrant |
| `child_warrant` | `TENUO_CHILD_WARRANT` | No | Warrant for sub-agent sessions (delegate_task) |
| `signing_key_env` | — | For enforcement | Name of env var holding the signing key (default: `TENUO_SIGNING_KEY`) |

## Known limitations

**`on_session_start` is not fired by Hermes.** The hook is declared in Hermes's `VALID_HOOKS` but has no `invoke_hook` call in the current codebase. Child warrant injection therefore uses a heuristic: the first `session_id` seen by the plugin is the primary session; all other session IDs receive `child_warrant`. Explicit registrations via `set_session_warrant()` always take precedence.

**`execute_code` sandbox interior.** Code running inside the `execute_code` sandbox may call tools via an internal RPC path that bypasses `pre_tool_call`. This is documented above and will be addressed in a future version by injecting the warrant as a mandatory RPC transport header.

## Next steps

- [Tenuo Core Concepts](./concepts.md)
- [Constraint Types](./constraints.md)
- [Security Model](./security.md)
- [Tenuo Cloud](https://cloud.tenuo.ai) — warrant builder, audit dashboard, key management
- [hermes-tenuo on GitHub](https://github.com/tenuo-ai/hermes-tenuo)
- [Example code](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/hermes)
