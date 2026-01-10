---
title: OpenAI Integration
description: Tool protection for OpenAI agents and the Agents SDK
---

# Tenuo OpenAI Integration

> **Status**: Implemented

## Overview

Tenuo integrates with OpenAI's APIs using a **two-tier** protection model:

| Tier | Setup | Best For |
|------|-------|----------|
| **Tier 1: Guardrails** | Inline constraints | Quick hardening, prototyping, single-process agents |
| **Tier 2: Warrants** | Warrant + signing key | Production systems, multi-agent, audit requirements |

**Tier 1** catches LLM mistakes and prompt injection with minimal setup. Constraints are defined inline in your code. Good for getting started, but constraints can drift from tool definitions.

**Tier 2** adds cryptographic proof. Constraints live in the warrant (issued by a control plane), ensuring they're defined once and enforced everywhere. Required when agents run in separate processes or you need audit trails.

---

## Installation

```bash
pip install tenuo
```

---

## Quick Start

### Tier 1: Guardrails (5 minutes)

Use the **builder pattern** for clean, fluent constraint definition:

```python
from tenuo.openai import GuardBuilder, Pattern, Subpath

client = (GuardBuilder(openai.OpenAI())
    .allow("search_web")
    .allow("read_file", path=Subpath("/data"))
    .allow("send_email", to=Pattern("*@company.com"))
    .deny("delete_file")
    .build())

# Use normally - unauthorized tool calls are blocked
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Read /data/report.txt"}],
    tools=[...]
)
```

The builder accepts:
- **Strings**: `"search"`
- **OpenAI tool dicts**: `{"type": "function", "function": {"name": "search"}}`
- **Callables**: `my_search_function` (extracts `__name__`)

**Alternative: dict style** (less ergonomic, same functionality):

```python
from tenuo.openai import guard, Subpath

client = guard(
    openai.OpenAI(),
    allow_tools=["search_web", "read_file"],
    constraints={"read_file": {"path": Subpath("/data")}}
)
```

**What gets blocked?**
- Tools not in allow list
- Arguments violating constraints (e.g., `/etc/passwd` blocked by `Subpath("/data")`)
- Streaming TOCTOU attacks (buffer-verify-emit)

### Tier 2: Warrants (when you need crypto)

```python
from tenuo.openai import GuardBuilder
from tenuo import SigningKey, Warrant, Subpath

# Agent holds warrant and signing key
agent_key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("read_file", {"path": Subpath("/data")})
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Builder with warrant
client = (GuardBuilder(openai.OpenAI())
    .with_warrant(warrant, agent_key)
    .build())

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
| `UrlSafe(...)` | `UrlSafe()` | SSRF-safe URL validation |

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

### UrlSafe: SSRF Protection

`UrlSafe` blocks Server-Side Request Forgery (SSRF) attacks:

```python
from tenuo.openai import UrlSafe

# Default: blocks private IPs, loopback, cloud metadata
constraint = UrlSafe()
constraint.is_safe("https://api.github.com/")     # True
constraint.is_safe("http://169.254.169.254/")     # False (AWS metadata)
constraint.is_safe("http://127.0.0.1/")           # False (loopback)
constraint.is_safe("http://10.0.0.1/")            # False (private IP)

# Strict: domain allowlist
constraint = UrlSafe(allow_domains=["api.github.com", "*.googleapis.com"])
```

**Blocked attack vectors:**
- Private IPs (10.x, 172.16.x, 192.168.x)
- Loopback (127.x, ::1, localhost)
- Cloud metadata (169.254.169.254)
- IP encoding bypasses (decimal, hex, octal, IPv6-mapped)
- URL-encoded hostnames

See [Constraints documentation](./constraints.md#urlsafe) for full options.

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
from tenuo.openai import guard, AuditEvent, Subpath

def audit_callback(event: AuditEvent):
    print(f"{event.decision}: {event.tool_name}")
    print(f"  Session: {event.session_id}")
    print(f"  Tier: {event.tier}")

client = guard(
    openai.OpenAI(),
    constraints={"read_file": {"path": Subpath("/data")}},
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

