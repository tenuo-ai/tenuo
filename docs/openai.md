---
title: OpenAI Integration
description: Tool protection for OpenAI agents and the Agents SDK
---

# Tenuo OpenAI Integration

## Overview

Tenuo integrates with OpenAI's APIs using a **two-tier** protection model:

| Tier | Setup | Best For |
|------|-------|----------|
| **Tier 1: Guardrails** | Inline constraints | Application-owned local policy, quick hardening |
| **Tier 2: Warrants** | Warrant + signing key | Verifiable delegated authority, distributed enforcement |

**Tier 1** enforces application-defined tool and argument policies with minimal setup. It blocks out-of-policy calls on the guarded path, including calls induced by prompt injection, without relying on the model to obey instructions.

**Tier 2** adds verifiable authority: signed warrants, holder proof, and delegation that can only narrow authority. An independently configured verifier can check that authority locally without trusting the caller's account of its permissions. Warrants can come from your own issuer or a control plane.

> [!IMPORTANT]
> **Production Recommendation**: Use **Tier 2** when tools must verify issuer-granted authority independently of the caller. For either tier, enforcement must cover the actual effect path. This client wrapper checks returned tool calls; it is not a sandbox or a substitute for verification at a separate tool service. If the agent can modify the wrapper or call the resource directly, place enforcement and resource credentials outside its control.

---

## Installation

```bash
uv pip install tenuo
```

---

## Which Pattern Should I Use?

**Answer these questions:**

1. **Do you need application-owned local policy checks?**
   - Tier 1 provides tool allowlists and argument constraints in trusted application code.

2. **Do you need independently verifiable issuer authority, holder proof, or delegation?**
   - Use Tier 2, whether the workflow is single-process or distributed.
   - If the agent can modify its runtime, also enforce at an effect boundary outside its control.

3. **Are you using the OpenAI Agents SDK?**
   - Yes -> Use `create_tier1_guardrail()` or `create_tier2_guardrail()`
   - No -> Use `guard()` or `GuardBuilder()`

**TL;DR:** Tier 1 enforces local policy. Tier 2 adds verifiable delegated authority. Neither choice alone determines whether the agent can bypass the enforcement boundary.

---

## Quick Start

### Tier 1: Guardrails (5 minutes)

Use the **builder pattern** for semantic constraints that block attacks:

```python
import openai
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

### Tier 2: Warrants (verifiable authority)

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

### Human Approval

Define gates and approvers on the warrant, then pass `.on_approval()`. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo.approval import cli_prompt

client = (GuardBuilder(openai.OpenAI())
    .allow("transfer_funds")
    .with_warrant(warrant, agent_key)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())
```

---

## Tier 1 Security Model

### What Tier 1 Protects Against

**Trust boundary:** the model proposes calls; trusted application code enforces policy before dispatch.

Tier 1 provides deterministic allowlist and argument checks, not another prompt asking the model to behave. Calls that violate the configured policy are blocked on the guarded path, whether they originated from prompt injection, a model mistake, or application logic.

| Attempt | Enforced check | Example |
|---------|----------------|---------|
| Out-of-policy tool call | Tool allowlist and argument constraints | A model-selected recipient outside the permitted set is rejected |
| Invalid or unexpected arguments | Configured constraints and closed-world argument checking | An unlisted argument is rejected |
| Disallowed URL | URL constraints | `UrlSafe()` rejects a literal metadata-service URL such as `http://169.254.169.254/` |
| Path traversal | Path constraints | `Subpath("/data")` rejects traversal outside the permitted root |

**Why this matters:** changing the prompt does not change a policy held in trusted code. Tier 1 can contain the consequences of a manipulated model by rejecting out-of-policy calls. It does not detect every prompt injection or reject harmful actions that are still within policy.

The checks must cover the path that actually performs the effect and the values it uses. Filesystem symlinks and races, URL redirects and DNS resolution, and shell program behavior still require resource-appropriate controls. A wrapper does not protect alternate paths that bypass it.

### What Tier 1 Does NOT Protect Against

| Threat | Protection | Why Not |
|--------|------------|---------|
| **Insider Threats** | None | Developer can modify code to bypass guards |
| **Container Compromise** | None | Attacker with code execution can disable guards |
| **Forged or modified authority** | Not checked | Local policy checks do not authenticate a warrant issuer or holder |
| **Verifiable delegation** | Not provided | Tier 1 does not verify a chain of delegated authority |

**Example Bypass**:
```python
# Production code with guard
client = guard(openai.OpenAI(), allow_tools=[...])

# Insider threat: Just remove the guard
client = openai.OpenAI()  # Bypassed
```

### When to Use Tier 1

**Good for**:

- Application-owned policies enforced in a trusted runtime, including production deployments that need local checks rather than delegated credentials.
- Blocking model-selected calls outside a tool or argument policy.
- Prototyping and defense in depth alongside other access controls.

**Not a substitute for**:

- Verifying who issued authority, which holder may exercise it, or whether delegation narrowed it.
- An independent enforcement boundary when the agent can execute arbitrary code or access the resource directly.
- Signed authorization evidence when that is an audit requirement. Tier 1 can still produce ordinary audit events.

### When to Upgrade to Tier 2

Upgrade when you need:

1. **Cryptographic Proof**: Verifiable evidence of what was authorized
2. **Delegation Chains**: Multi-agent systems where agents delegate to each other
3. **Untrusted Callers**: Cannot trust calling agent to honestly report tool calls
4. **Audit Requirements**: Need verifiable authority and, with receipt signing configured, signed records of authorization decisions

**Tier 2 adds**:
- Warrant signatures (cryptographic authorization)
- Proof-of-Possession (PoP) per tool call
- Cross-process verification against independently configured trusted roots
- Signed authorization receipts when receipt signing and collection are configured

A warrant proves the scope of issued authority; a signed receipt records an authorization decision. Neither alone proves that the downstream effect completed. Tier 2 does not require a hosted control plane: an application-owned issuer can mint warrants.

**Migration is simple**:
```python
# Tier 1
client = guard(openai.OpenAI(), allow_tools=[...], constraints={...})

# Tier 2 (add warrant + signing key)
client = guard(openai.OpenAI(), warrant=my_warrant, signing_key=agent_key)
```

### Bottom Line

**Tier 1 enforces local policy. Tier 2 verifies delegated authority.** Both can reject out-of-policy calls on their protected paths; Tier 2 additionally authenticates signed authority, checks holder proof, and verifies delegation back to trusted roots.

Choose the verification mode separately from the enforcement location:

- Use Tier 1 when trusted application code owns and enforces the policy.
- Use Tier 2 when the effecting component must independently verify issuer-granted, holder-bound authority, including across agents or processes.
- If the agent process may be compromised, put enforcement and resource credentials outside its control and close alternate effect paths. Adding a warrant to a bypassable wrapper does not create that isolation.

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
> Tenuo does not silently ignore extra arguments --it blocks them to prevent "shadow argument" attacks.
>
> ```python
> # Blocks call with 'timeout' arg because it's unknown
> constraints={"api_call": {"url": UrlSafe()}}
>
> # Explicitly allow unknown args (less secure)
> constraints={"api_call": {"url": UrlSafe(), "_allow_unknown": True}}
>
> # Or allow specific field with Wildcard
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

### Development: Log violations, skip denied calls

During development, use `on_denial="log"` to see what would be blocked. Denied tool calls are removed from the response (same as `"skip"`) and a warning is logged:

```python
client = guard(
    openai.OpenAI(),
    allow_tools=["search", "read_file"],
    constraints={"read_file": {"path": Subpath("/data")}},
    on_denial="log"  # Remove denied tool calls + log warning
)

# Denied tool calls are removed; warnings logged to stderr
response = client.chat.completions.create(...)
# WARNING: Tool 'delete_file' not in allowlist - removed from response
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
| `"log"` | Remove denied tool call + log warning | Development/testing |
| `"skip"` | Silently remove the denied tool call | Legacy compatibility |


---

## Testing Your Configuration

Before making API calls, validate your setup:

```python
from tenuo.openai import guard, OpenAIConfigurationError

client = guard(
    openai.OpenAI(),
    warrant=warrant,
    signing_key=agent_key,
)

# Pre-flight check - catch config errors before production
try:
    client.validate()
    print("Configuration valid")
except OpenAIConfigurationError as e:
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
for chunk in client.chat.completions.create(..., stream=True):
    print(chunk)  # Tool calls only emitted after verification
```

> [!NOTE]
> Use a regular `for` loop with sync `OpenAI()` clients. If you need `async for`, use `AsyncOpenAI()` instead.

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
client.validate()  # Raises OpenAIConfigurationError if misconfigured
```

---

## Error Reference

The OpenAI integration uses custom exception types for API consistency:

```python
from tenuo.openai import (
    TenuoOpenAIError,
    ToolDenied,
    OpenAIConstraintViolation,
    OpenAIConfigurationError,
)

try:
    response = client.chat.completions.create(...)
except ToolDenied as e:
    print(f"Tool denied: {e}")
    print(f"Error code: {e.code}")  # e.g., "T1_001"
    if e.quick_fix:
        print(f"Quick fix: {e.quick_fix}")
except OpenAIConstraintViolation as e:
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
| `OpenAIConstraintViolation` | 1+ | T1_002 | Argument fails constraint |
| `WarrantDenied` | 2 | T2_001 | Warrant doesn't allow tool/args |
| `MissingSigningKey` | 2 | T2_002 | Warrant provided without signing_key |
| `OpenAIConfigurationError` | 1+ | CFG_002, CFG_003, C1_003 | Invalid guard() configuration |
| `MalformedToolCall` | 1+ | T1_003 | Invalid JSON in tool arguments |
| `BufferOverflow` | 1+ | T1_004 | Streaming buffer limit exceeded |

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
# TIER 2: Verifiable, holder-bound authority
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

## Delegation

Warrants can be attenuated (narrowed) and delegated to downstream agents. The child warrant can only contain a subset of the parent's capabilities:

```python
from tenuo import SigningKey, Warrant
from tenuo.openai import guard

issuer = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()

root = (Warrant.mint_builder()
    .capability("search").capability("read_file").capability("delete_file")
    .holder(orchestrator.public_key).ttl(3600).mint(issuer))

# Attenuate: worker can only search
child = (root.grant_builder()
    .capability("search")
    .holder(worker.public_key).ttl(1800).grant(orchestrator))

# Use child warrant with worker's key
client = guard(openai.OpenAI(), warrant=child, signing_key=worker)
```

---

## See Also

- [LangChain Integration](./langchain) - Tool protection for LangChain
- [LangGraph Integration](./langgraph) - Multi-agent graph security
- [Security](./security) - Threat model, best practices
- [Quickstart](./quickstart) - Getting started guide
