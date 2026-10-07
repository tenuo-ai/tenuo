---
title: Hermes Agent Integration
description: Signed, expiring permission for every Hermes Agent tool call
---

# Tenuo Hermes Agent Integration

## Overview

[hermes-tenuo](https://github.com/tenuo-ai/hermes-tenuo) is a [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin. It checks every tool call against a Tenuo warrant before the handler runs: the tool name and each argument. A warrant is signed and it expires. When a call falls outside it, the handler never runs, and the model gets the reason back as the tool result.

```text
ALLOW  read_file  path=/data/reports/q3.csv
DENY   read_file  path=/opt/private/payroll.csv
       Constraint 'path' not satisfied: value does not match constraint
DENY   terminal   command=ls
       Tool 'terminal' is not authorized
```

The plugin is listed in the [Hermes plugin catalog](https://hermes-agent.nousresearch.com/docs/plugins/hermes-tenuo) as `hermes-tenuo`. Keys and decisions stay on your machine unless you connect a control plane.

| Hermes feature | What the warrant gives you |
|---|---|
| Cron and scheduled jobs | A TTL that matches the job window. The job cannot act after it should be done. |
| `delegate_task` subagents | The child gets only what the parent granted, verified as a chain. |
| Multi-user gateways | One warrant per session, cleared when the session ends. |
| Kanban workers | A per-task warrant. A denial blocks the task on the board. |
| Fleets | Pin the warrant and trust anchor in `/etc/hermes/config.yaml` so users cannot loosen them. |

---

## See it first

No Hermes install, no API key:

```bash
uvx hermes-tenuo demo
```

It prints the allow and deny decisions for a cron job, a subagent handoff, and two gateway users.

---

## Installation

Requires Hermes Agent 0.20 or newer.

```bash
hermes plugins install hermes-tenuo
hermes plugins enable hermes-tenuo
```

`install` shows the catalog entry and its disclosure, clones the reviewed commit, and asks for `TENUO_WARRANT` and `TENUO_SIGNING_KEY`. You do not have them yet, so leave both empty and continue. `enable` installs the `tenuo` dependency into the Hermes runtime.

If you manage the Hermes venv yourself, `pip install hermes-tenuo` into that venv instead. That route also puts the `hermes-tenuo` command on your path.

---

## Quick Start

### 1. Mint a warrant

```bash
uvx hermes-tenuo mint --ttl 1h \
  --allow read_file:path=/data \
  --allow web_search
```

This generates a key pair and a warrant, and prints the config block to paste:

```yaml
# ~/.hermes/config.yaml
plugins:
  entries:
    hermes-tenuo:
      warrant: <base64>            # or a path to a .warrant file
      trusted_root: <base64>       # the public key that signed it
      signing_key_env: TENUO_SIGNING_KEY
```

Put the printed `TENUO_SIGNING_KEY` in `~/.hermes/.env`, or export it before you start Hermes. Keep it out of `config.yaml`.

### 2. Check the wiring

```bash
hermes plugins doctor hermes-tenuo   # Hermes loads the plugin and its hooks
uvx hermes-tenuo doctor              # config, warrant, expiry, signing key
```

The second command reads the signing key from your shell, so export it first if it only lives in `~/.hermes/.env`.

### 3. Run Hermes

```bash
hermes
```

Ask the agent to read a file outside `/data`. The call is denied, and the agent tells you why.

---

## Scoping arguments

Each `--allow` names a tool and, optionally, constraints on its arguments. A tool with no constraints is allowed with any arguments. A tool not named in the warrant is denied.

| Syntax | Meaning | Example |
|---|---|---|
| `tool` | any arguments | `--allow web_search` |
| `tool:arg=/path` | that path or under it (traversal-safe) | `--allow read_file:path=/data` |
| `tool:arg=glob*` | matches the glob | `--allow web_search:query=acme*` |
| `tool:arg=a\|b\|c` | one of the choices | `--allow git:action=status\|diff\|log` |
| `tool:arg=value` | exact match | `--allow write_file:mode=w` |
| `tool:a=..,b=..` | several constraints on one tool | `--allow write_file:path=/tmp/out,mode=w` |

For numeric ranges and the rest of the [constraint types](./constraints), mint in Python:

```python
from tenuo import SigningKey, Warrant, Subpath, Range

control_key = SigningKey.generate()   # its public key is trusted_root
agent_key = SigningKey.generate()     # its secret is TENUO_SIGNING_KEY

warrant = (
    Warrant.mint_builder()
    .holder(agent_key.public_key)
    .capability("read_file", path=Subpath("/data"))
    .capability("scale_cluster", replicas=Range.max_value(10))
    .ttl(3600)
    .mint(control_key)
)
```

The [hermes-tenuo README](https://github.com/tenuo-ai/hermes-tenuo#scoping-arguments) shows how to write that warrant to a file and wire it in.

---

## Audit log

Every decision is appended to `$HERMES_HOME/tenuo/audit.jsonl`. No account needed.

```bash
uvx hermes-tenuo audit --last 20
uvx hermes-tenuo audit --denied
```

Not sure what to allow yet? Set `on_denial: log` under `plugins.entries.hermes-tenuo`. Every call is still checked and recorded, but nothing is blocked. Run the agent, read the denied lines, tighten the warrant, then remove the setting.

---

## How it works

| Hermes hook | What the plugin does |
|---|---|
| `pre_tool_call` | Verifies the tool name and arguments against the session's warrant. On denial it blocks the call and returns the reason as the tool result. |
| `post_tool_call` | Records timing and writes the audit record. |
| `subagent_start` | Hands the child warrant to the new `delegate_task` session. |
| `on_session_end` | Clears the session's warrant, so gateway users never share one. |

The check runs in Tenuo's Rust core: signature, expiry, holder [proof-of-possession](./concepts), and every argument constraint. The plugin holds only the issuer's public key.

A plugin with a configured warrant that is missing, empty, or fails to load blocks every call. It does not fall back to allowing them.

### Coverage

`pre_tool_call` runs on tool calls from the agent loop, including tools Hermes handles before the tool registry (`todo`, `memory`, `session_search`, `delegate_task`) and tool calls made from inside `execute_code` scripts.

It does not run when another plugin calls a tool directly through `ctx.dispatch_tool()`. Only install plugins you trust alongside it. The plugin also does not inspect what an `execute_code` script does on its own, such as starting a subprocess. Use a container terminal backend (Docker, Modal, Daytona) for that.

---

## Configuration reference

All keys live under `plugins.entries.hermes-tenuo` in `~/.hermes/config.yaml`.

| Key | Env | Meaning |
|---|---|---|
| `warrant` | `TENUO_WARRANT` | Base64 warrant, or a path to a file containing one. Required for enforcement. |
| `trusted_root` | `TENUO_TRUSTED_ROOT` | Base64 public key of the issuer. Warrants signed by anything else are rejected. |
| `signing_key_env` | | Name of the env var holding the agent's signing key. Default `TENUO_SIGNING_KEY`. |
| `child_warrant` | `TENUO_CHILD_WARRANT` | Warrant handed to `delegate_task` children. |
| `on_denial` | | `block` (default) or `log`. |
| `audit_log` | `TENUO_AUDIT_LOG` | Path of the audit log, or `false` to disable it. |

Without a `warrant`, the plugin loads, logs a warning, and enforces nothing. `doctor` reports that.

---

## Connecting a control plane

Everything above runs from files on one machine. Set `TENUO_CONNECT_TOKEN` and the plugin streams every decision to a Tenuo control plane. That adds revocation before a warrant expires, central issuance and key rotation, human approval for sensitive tools, and one audit trail across agents. See [Going to production](./production-guide).

---

## More

- [hermes-tenuo on GitHub](https://github.com/tenuo-ai/hermes-tenuo): full README, runnable examples, and a recorded session where a prompt injection meets a warrant
- [Hermes catalog entry](https://hermes-agent.nousresearch.com/docs/plugins/hermes-tenuo)
- [Constraints](./constraints) and [Concepts](./concepts)
