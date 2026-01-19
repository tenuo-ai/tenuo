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

> [!IMPORTANT]
> **Production Recommendation**: Use **Tier 2** for production deployments. Tier 1 guardrails can be modified or bypassed by anyone with code access, making them unsuitable for environments where insider threats or container compromise are concerns.

---

## Installation

```bash
uv pip install tenuo
```

---

## Which Pattern Should I Use?

**Answer these questions:**

1. **Are your tools running in the same process as the LLM client?**
   - Yes -> Tier 1 (GuardBuilder with inline constraints)
   - No -> Tier 2 (Warrant + Proof-of-Possession)

2. **Do you need protection against insider threats or code tampering?**
   - Yes -> Tier 2 (constraints in cryptographic warrant)
   - No -> Tier 1 is sufficient

3. **Are you using the OpenAI Agents SDK?**
   - Yes -> Use `create_tier1_guardrail()` or `create_tier2_guardrail()`
   - No -> Use `guard()` or `GuardBuilder()`

**TL;DR:** Start with Tier 1. Move to Tier 2 when you need crypto.

---

## Quick Start

### Tier 1: Guardrails (5 minutes)

Use the **builder pattern** for semantic constraints that block attacks:

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

**Simple allowlist only?** Use `protect()` for basic protection without constraints:

```python
from tenuo.openai import protect

client = protect(openai.OpenAI(), tools=["search", "read_file"])
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

## Tier 1 Security Model

### What Tier 1 Protects Against

**Trust Boundary**: Code access

Tier 1 enforces constraints at runtime, protecting against:

| Threat | Protection | Example |
|--------|------------|---------|
| **Prompt Injection** | Strong | Attacker manipulates LLM to call `read_file("/etc/passwd")` - blocked by `Subpath("/data")` |
| **LLM Hallucinations** | Strong | Model invents tool call with invalid args - blocked by constraints |
| **SSRF Attempts** | Strong | LLM tries `http://169.254.169.254/` - blocked by `UrlSafe()` |
| **Path Traversal** | Strong | `../../../etc/passwd` - normalized and blocked by `Subpath` |
| **Development Bugs** | Strong | Accidental misconfiguration caught before production |

**Key Insight**: Tier 1 is effective because **constraints are outside the LLM's control**. Even if an attacker fully manipulates the prompt, they cannot bypass Python-enforced guardrails.

### What Tier 1 Does NOT Protect Against

| Threat | Protection | Why Not |
|--------|------------|---------|
| **Insider Threats** | None | Developer can modify code to bypass guards |
| **Container Compromise** | None | Attacker with code execution can disable guards |
| **Tampering** | None | No cryptographic proof of enforcement |
| **Multi-Process Delegation** | Limited | Downstream service must trust caller's honesty |

**Example Bypass**:
```python
# Production code with guard
client = guard(openai.OpenAI(), allow_tools=[...])

# Insider threat: Just remove the guard
client = openai.OpenAI()  # Bypassed
```

### When to Use Tier 1

**Good for**:
- Single-process agents (LLM and tools in same Python runtime)
- Trusted execution environment (your laptop, internal servers)
- Prototyping and development
- Defense against external attackers (via prompt injection)

**Not suitable for**:
- Untrusted execution environment (shared infrastructure)
- Zero-trust security model
- Compliance requirements for audit trails
- Multi-process systems with untrusted intermediaries

### When to Upgrade to Tier 2

Upgrade when you need:

1. **Cryptographic Proof**: Verifiable evidence of what was authorized
2. **Delegation Chains**: Multi-agent systems where agents delegate to each other
3. **Untrusted Callers**: Cannot trust calling agent to honestly report tool calls
4. **Audit Requirements**: Need non-repudiable logs of authorization decisions

**Tier 2 adds**:
- Warrant signatures (cryptographic authorization)
- Proof-of-Possession (PoP) per tool call
- Tamper-evident audit trail
- Cross-process verification

**Migration is simple**:
```python
# Tier 1
client = guard(openai.OpenAI(), allow_tools=[...], constraints={...})

# Tier 2 (add warrant + signing key)
client = guard(openai.OpenAI(), warrant=my_warrant, signing_key=agent_key)
```

### Bottom Line

Tier 1 stops prompt injection, LLM hallucinations, and SSRF attacks. It enforces constraints at runtime within a single Python process.

Tier 2 adds cryptographic verification for distributed systems and untrusted execution environments.

**Choose based on your threat model:**
- Single-process, trusted execution: Tier 1
- Multi-process, delegation, or untrusted execution: Tier 2

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
| `Shlex(allow)` | `Shlex(allow=["ls", "cat"])` | Safe shell command validation |

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

### Closed-World Constraints (Zero Trust)
> [!IMPORTANT]
> **Tenuo enforces Zero Trust for arguments.**
> Once you add **any** constraint to a tool, Tenuo switches to a "closed-world" model for that tool.
>
> This means **ANY argument not explicitly listed in your constraints will be REJECTED**.
> Tenuo does not silently ignore extra arguments—it blocks them to prevent "shadow argument" attacks.
>
> ```python
> # ❌ Blocks call with 'timeout' arg because it's unknown
> constraints={"api_call": {"url": UrlSafe()}}
>
> # ✅ Explicitly allow unknown args (less secure)
> constraints={"api_call": {"url": UrlSafe(), "_allow_unknown": True}}
>
> # ✅ Or allow specific field with Wildcard
> constraints={"api_call": {"url": UrlSafe(), "timeout": Wildcard()}}
> ```

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

## Development vs Production

### Development: Log violations, don't block

During development, use `on_denial="log"` to see what would be blocked without interrupting your workflow:

```python
client = guard(
    openai.OpenAI(),
    allow_tools=["search", "read_file"],
    constraints={"read_file": {"path": Subpath("/data")}},
    on_denial="log"  # Log violations but allow calls through
)

# Violations are logged to stderr but calls proceed
response = client.chat.completions.create(...)
# WARNING: Tool 'delete_file' not in allowlist (would be blocked in production)
```

### Production: Raise exceptions

In production, use `on_denial="raise"` (the default) to block unauthorized calls:

```python
client = guard(
    openai.OpenAI(),
    allow_tools=["search"],
    on_denial="raise"  # Raise exception on violation
)

try:
    response = client.chat.completions.create(...)
except ToolDenied as e:
    print(f"Blocked: {e.tool_name}")
```

### Denial Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `"raise"` (default) | Raise `ToolDenied` exception | Production |
| `"log"` | Log warning, allow the call | Development/testing |
| `"skip"` | Silently skip the tool call | Legacy compatibility |


---

## Development vs Production

Configure behavior per environment:

```python
from tenuo.openai import guard, Subpath

client = guard(
    openai.OpenAI(),
    allow_tools=["read_file", "search"],
    constraints={"read_file": {"path": Subpath("/data")}},
    on_denial="raise",  # Production (default) - raises exception
    # on_denial="log",  # Development - logs but allows through
    # dry_run=True,     # Testing - logs denials, never blocks
)

try:
    response = client.chat.completions.create(...)
except ToolDenied as e:
    logger.error(f"Tool blocked: {e.tool_name}")
except ConstraintViolation as e:
    logger.error(f"Constraint failed: {e}")
```

| Mode | Setting | Behavior |
|------|---------|----------|
| **Production** | `on_denial="raise"` (default) | Raise exception on violation |
| **Development** | `on_denial="log"` | Log warning, allow call through |
| **Testing** | `dry_run=True` | Log with "DRY RUN" prefix, never block |

---

## Testing Your Configuration

Before making API calls, validate your setup:

```python
from tenuo.openai import guard, ConfigurationError

client = guard(
    openai.OpenAI(),
    warrant=warrant,
    signing_key=agent_key,
)

# Pre-flight check - catch config errors before production
try:
    client.validate()
    print("Configuration valid")
except ConfigurationError as e:
    print(f"Config error: {e}")
```

The `validate()` method checks:
- Constraint parameter names match tool schemas
- Warrant holder matches signing key (Tier 2)
- No conflicting allow/deny rules
- All constraint types are supported

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

### Tier 1: Constraint-Based Guardrails

```python
from agents import Agent, Runner
from tenuo.openai import create_tier1_guardrail, Pattern

# Create guardrail with inline constraints
guardrail = create_tier1_guardrail(
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
from tenuo.openai import create_tier2_guardrail
from tenuo import SigningKey, Warrant, Pattern

# Control plane issues warrant to agent
agent_key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("send_email", {"to": Pattern("*@company.com")})
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Create Tier 2 guardrail with PoP
guardrail = create_tier2_guardrail(
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

The OpenAI integration uses custom exception types for API consistency:

```python
from tenuo.openai import (
    TenuoOpenAIError,
    ToolDenied,
    ConstraintViolation,
    ConfigurationError,
)

try:
    response = client.chat.completions.create(...)
except ToolDenied as e:
    print(f"Tool denied: {e}")
    print(f"Error code: {e.code}")  # e.g., "T1_001"
    if e.quick_fix:
        print(f"Quick fix: {e.quick_fix}")
except ConstraintViolation as e:
    print(f"Constraint failed: {e}")
    print(f"Param: {e.param}")
    print(f"Value: {e.value}")
except TenuoOpenAIError as e:
    # Catch-all for Tenuo OpenAI errors
    print(f"Error: {e} (code: {e.code})")
```

### Error Types

| Error | Tier | Code | Meaning |
|-------|------|------|---------|
| `ToolDenied` | 1+ | T1_001 | Tool not in allowlist |
| `ConstraintViolation` | 1+ | T1_002 | Argument fails constraint |
| `WarrantDenied` | 2 | T2_001 | Warrant doesn't allow tool/args |
| `MissingSigningKey` | 2 | T2_002 | Warrant provided without signing_key |
| `ConfigurationError` | 1+ | CONFIG | Invalid guard() configuration |
| `MalformedToolCall` | 1+ | MALFORMED | Invalid JSON in tool arguments |
| `BufferOverflow` | 1+ | BUFFER | Streaming buffer limit exceeded |

### Wire Code Support

The OpenAI integration uses its own error codes (T1_001, T2_001, etc.) for API consistency with OpenAI's patterns. However, the underlying authorization logic uses Tenuo's canonical wire codes (1000-2199) internally.

**Note**: For direct access to canonical wire codes, use `tenuo.langchain` or raw `Warrant.authorize()` calls. The OpenAI integration prioritizes OpenAI-style error handling for better developer experience.

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

