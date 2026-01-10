---
title: OpenAI Integration
description: Tool protection for OpenAI agents and the Agents SDK
---

# Tenuo OpenAI Integration

> **Status**: Implemented

## Overview

Tenuo integrates with OpenAI's APIs using a **two-tier** protection model:

| Tier | Complexity | Use Case |
|------|------------|----------|
| **Tier 1: Guardrails** | 3 lines of code | Single-process agents, quick hardening |
| **Tier 2: Warrants** | Full crypto | Multi-agent delegation, audit trails |

Tier 1 is a stepping stone to Tier 2 - same API, opt-in cryptography.

---

## Installation

```bash
pip install tenuo
```

---

## Quick Start

### Tier 1: Guardrails (5 minutes)

```python
from tenuo.openai import guard, Pattern

client = guard(
    openai.OpenAI(),
    allow_tools=["search_web", "read_file"],
    constraints={
        "read_file": {"path": Pattern("/data/*")}
    }
)

# Use normally - unauthorized tool calls are blocked
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Read /data/report.txt"}],
    tools=[...]
)
```

**What gets blocked?**
- Tools not in `allow_tools`
- Arguments violating constraints (e.g., `/etc/passwd` blocked by `Pattern("/data/*")`)
- Streaming TOCTOU attacks (buffer-verify-emit)

### Tier 2: Warrants (when you need crypto)

```python
from tenuo.openai import guard
from tenuo import SigningKey, Warrant, Pattern

# Agent holds warrant and signing key
agent_key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("read_file", {"path": Pattern("/data/*")})
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Same guard() API, add warrant + signing_key
client = guard(
    openai.OpenAI(),
    warrant=warrant,
    signing_key=agent_key,
)

# Each tool call is now cryptographically authorized
response = client.chat.completions.create(...)
```

---

## Constraints

Reuses core Tenuo constraint types:

| Type | Example | Matches |
|------|---------|---------|
| `Exact(v)` | `Exact("report.pdf")` | Exact value only |
| `Pattern(p)` | `Pattern("/data/*.pdf")` | Glob pattern |
| `Regex(r)` | `Regex(r"^[a-z]+$")` | Regular expression |
| `OneOf([...])` | `OneOf(["dev", "staging"])` | Set membership |
| `Range(min, max)` | `Range(0, 100)` | Numeric bounds |
| `Subpath(root)` | `Subpath("/data")` | Secure path containment |

```python
from tenuo.openai import guard, Pattern, Range, OneOf, Subpath

client = guard(
    openai.OpenAI(),
    allow_tools=["read_file", "search", "calculate"],
    constraints={
        "read_file": {
            "path": Subpath("/data"),  # Blocks path traversal attacks
        },
        "search": {
            "query": Pattern("*"),
            "max_results": Range(1, 20),
        },
        "calculate": {
            "operation": OneOf(["add", "subtract", "multiply"]),
        },
    }
)
```

### Subpath: Secure Path Containment

`Subpath` blocks path traversal attacks that `Pattern` cannot catch:

```python
# Pattern is vulnerable to traversal:
Pattern("/data/*").matches("/data/../etc/passwd")  # True (BAD!)

# Subpath normalizes first:
Subpath("/data").matches("/data/../etc/passwd")    # False (SAFE!)
```

For maximum security, combine `Subpath` with [path_jail](https://github.com/tenuo-ai/path_jail) at execution time.

---

## Denial Handling

| Mode | Behavior |
|------|----------|
| `"raise"` (default) | Raise `ToolDenied` exception |
| `"skip"` | Silently skip the tool call |
| `"log"` | Log warning, skip the tool call |

```python
from tenuo.openai import guard, ToolDenied

client = guard(
    openai.OpenAI(),
    allow_tools=["search"],
    on_denial="raise"
)

try:
    response = client.chat.completions.create(...)
except ToolDenied as e:
    print(f"Blocked: {e.tool_name}")
```

---

## Streaming Protection

Tenuo uses **buffer-verify-emit** to prevent TOCTOU attacks in streaming:

```
1. BUFFER: Accumulate tool_call chunks silently
2. VERIFY: On completion, check tool + constraints
3. EMIT: Yield verified call OR raise denial
```

```python
# Streaming just works - no code change needed
async for chunk in client.chat.completions.create(..., stream=True):
    print(chunk)  # Tool calls only emitted after verification
```

---

## OpenAI Agents SDK Integration

Tenuo integrates with the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) via guardrails.

### Basic Usage

```python
from agents import Agent, Runner
from tenuo.openai import create_tool_guardrail, Pattern

# Create guardrail
guardrail = create_tool_guardrail(
    constraints={"send_email": {"to": Pattern("*@company.com")}}
)

# Attach to agent
agent = Agent(
    name="Assistant",
    instructions="Help the user with email tasks",
    input_guardrails=[guardrail],
)

# Run - unauthorized tool calls trigger tripwire
result = await Runner.run(agent, "Send email to alice@company.com")
```

### Tier 2: Warrant-Based Guardrails

```python
from tenuo.openai import create_warrant_guardrail
from tenuo import SigningKey, Warrant, Pattern

# Control plane issues warrant to agent
agent_key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("send_email", {"to": Pattern("*@company.com")})
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Create Tier 2 guardrail with PoP
guardrail = create_warrant_guardrail(
    warrant=warrant,
    signing_key=agent_key,
)

agent = Agent(
    name="Authorized Assistant",
    input_guardrails=[guardrail],
)
```

### Guardrail Options

| Parameter | Description |
|-----------|-------------|
| `allow_tools` | Allowlist of permitted tool names |
| `deny_tools` | Denylist of forbidden tool names |
| `constraints` | Per-tool argument constraints |
| `warrant` | Tier 2 warrant (optional) |
| `signing_key` | Required if warrant provided |
| `tripwire` | If True, halt agent on violation (default: True) |
| `audit_callback` | Optional callback for audit events |

---

## Audit Logging

Track all authorization decisions:

```python
from tenuo.openai import guard, AuditEvent

def audit_callback(event: AuditEvent):
    print(f"{event.decision}: {event.tool_name}")
    print(f"  Session: {event.session_id}")
    print(f"  Tier: {event.tier}")

client = guard(
    openai.OpenAI(),
    constraints={"read_file": {"path": Pattern("/data/*")}},
    audit_callback=audit_callback,
)
```

### AuditEvent Fields

| Field | Description |
|-------|-------------|
| `session_id` | Unique session identifier |
| `timestamp` | Unix timestamp |
| `tool_name` | Tool being called |
| `arguments` | Tool arguments |
| `decision` | "ALLOW" or "DENY" |
| `reason` | Why decision was made |
| `tier` | "tier1" or "tier2" |
| `constraint_hash` | Hash of Tier 1 config |
| `warrant_id` | Warrant ID (Tier 2 only) |

---

## Developer Experience

### Debug Mode

```python
from tenuo.openai import enable_debug

enable_debug()  # Verbose logging to stderr
```

### Pre-flight Validation

```python
client = guard(openai.OpenAI(), warrant=warrant, signing_key=key)

# Check configuration before making calls
client.validate()  # Raises ConfigurationError if misconfigured
```

---

## Error Reference

| Error | Tier | Meaning |
|-------|------|---------|
| `ToolDenied` | 1+ | Tool not in allowlist |
| `ConstraintViolation` | 1+ | Argument fails constraint |
| `WarrantDenied` | 2 | Warrant doesn't allow tool/args |
| `MissingSigningKey` | 2 | Warrant provided without signing_key |
| `ConfigurationError` | 1+ | Invalid guard() configuration |
| `MalformedToolCall` | 1+ | Invalid JSON in tool arguments |
| `BufferOverflow` | 1+ | Streaming buffer limit exceeded |

---

## Responses API

```python
client = guard(openai.OpenAI(), allow_tools=["search"])

# Works with Responses API
response = client.responses.create(...)
```

---

## Full Example

```python
import openai
from tenuo.openai import guard, Pattern, Range, Subpath
from tenuo import SigningKey, Warrant

# ============================================================
# TIER 1: Quick Start (no crypto)
# ============================================================

client_simple = guard(
    openai.OpenAI(),
    allow_tools=["search", "read_file"],
    constraints={
        "search": {"max_results": Range(1, 10)},
        "read_file": {"path": Subpath("/data")},
    }
)

response = client_simple.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Read /data/report.txt"}],
    tools=[SEARCH_TOOL, READ_FILE_TOOL],
)

# ============================================================
# TIER 2: Full Crypto (when you need it)
# ============================================================

# Setup keys
control_plane_key = SigningKey.generate()
agent_key = SigningKey.generate()

# Control plane issues warrant
warrant = (Warrant.mint_builder()
    .capability("search")
    .capability("read_file", {"path": Subpath("/data")})
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Agent uses warrant
client_secure = guard(
    openai.OpenAI(),
    warrant=warrant,
    signing_key=agent_key,
)

# Use exactly like Tier 1
response = client_secure.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Read /data/report.txt"}],
    tools=[SEARCH_TOOL, READ_FILE_TOOL],
)
```

---

## See Also

- [LangChain Integration](./langchain) - Tool protection for LangChain
- [LangGraph Integration](./langgraph) - Multi-agent graph security
- [Security](./security) - Threat model, best practices
- [Quickstart](./quickstart) - Getting started guide

