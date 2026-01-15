# Google ADK Integration

Tenuo provides first-class support for [Google's Agent Development Kit (ADK)](https://github.com/google/adk-toolkit), enabling warrant-based authorization and constraint validation for ADK agents.

---

## Overview

Tenuo integrates with Google ADK using a **two-tier** protection model:

| Tier | Setup | Best For |
|------|-------|----------|
| **Tier 1: Direct Constraints** | Inline constraints via builder | Quick hardening, prototyping, single-process agents |
| **Tier 2: Warrants** | Warrant + signing key | Production systems, multi-agent, audit requirements |

**Tier 1** catches LLM mistakes and prompt injection with minimal setup. Constraints are defined inline using the builder pattern. Good for getting started, but constraints can be modified by anyone with code access.

**Tier 2** adds cryptographic proof. Constraints live in the warrant (issued by a control plane), ensuring they're defined once and enforced everywhere. Required when agents run in separate processes or you need protection against insider threats.

> [!IMPORTANT]
> **Production Recommendation**: Use **Tier 2** for production deployments. Tier 1 constraints can be modified or bypassed by anyone with code access, making them unsuitable for environments where insider threats or container compromise are concerns.

---

## Installation

```bash
pip install tenuo google-genai
```

---

## Quick Start

### Tier 1: Direct Constraints (5 minutes)

Use the **builder pattern** for clean, fluent constraint definition:

```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo.constraints import Subpath, UrlSafe, Pattern

# Define your tools
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

def web_search(query: str, url: str) -> str:
    # ... search implementation
    pass

# Build guard with inline constraints
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("web_search", url=UrlSafe(allow_domains=["*.google.com"]))
    .build())

# Create agent with filtered tools and callback
agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
)
```

**What gets blocked?**
- Tools not explicitly allowed via `.allow()`
- Arguments violating constraints (e.g., `/etc/passwd` blocked by `Subpath("/data")`)
- Unknown arguments (Zero Trust - must be explicitly constrained)

### Alternative: Decorator Pattern (Convenience)

For simple, static tool definitions, you can use the `@guard_tool` decorator:

```python
from google.adk.agents import Agent
from tenuo.google_adk import guard_tool, GuardBuilder
from tenuo.constraints import Subpath, Pattern

@guard_tool(path=Subpath("/data"))
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

@guard_tool(query=Pattern("*"))
def web_search(query: str) -> str:
    # ... search implementation
    pass

# Extract constraints from decorated tools
guard = GuardBuilder.from_tools([read_file, web_search]).build()

agent = Agent(
    name="assistant",
    tools=[read_file, web_search],
    before_tool_callback=guard.before_tool,
)
```

> [!WARNING]
> **Decorator Limitations**
>
> Decorators are convenient but have important limitations:
> - ❌ **Static only** - Can't change constraints per-user or at runtime
> - ❌ **Not for Tier 2** - Can't be used with warrants (no crypto at decoration time)
> - ❌ **No third-party tools** - Can't decorate functions you don't control
> - ❌ **Testing friction** - Harder to test raw function without guard
>
> **Use decorators for**: Prototyping, self-documenting simple tools
>
> **Use GuardBuilder for**: Production systems, dynamic authorization, Tier 2

### Tier 2: Warrants (when you need crypto)

For production systems with distributed agents or insider threat protection:

```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo import SigningKey, Warrant
from tenuo.constraints import Subpath

# Agent's signing key (proves possession)
agent_key = SigningKey.generate()

# Control plane issues warrant
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data"))
    .capability("web_search")
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Build guard with warrant + PoP
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .build())

agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
)
```

---

## Closed-World Constraints (Zero Trust)

> [!IMPORTANT]
> **Tenuo enforces Zero Trust for arguments.**
> Once you add **any** constraint to a tool, Tenuo switches to a "closed-world" model for that tool.
>
> This means **ANY argument not explicitly listed in your constraints will be REJECTED**.
> Tenuo does not silently ignore extra arguments—it blocks them to prevent "shadow argument" attacks.
>
> ```python
> # ❌ Blocks call with 'timeout' arg because it's unknown
> guard = GuardBuilder().allow("api_call", url=UrlSafe()).build()
>
> # ✅ Explicitly allow unknown args (less secure)
> guard = GuardBuilder().allow("api_call", url=UrlSafe(), _allow_unknown=True).build()
>
> # ✅ Or allow specific field with Wildcard
> from tenuo.constraints import Wildcard
> guard = GuardBuilder().allow("api_call", url=UrlSafe(), timeout=Wildcard()).build()
> ```

---

## Constraint Types

Tenuo provides production-ready constraints for common attack vectors:

### Subpath: Secure Path Containment

`Subpath` blocks path traversal attacks that `Pattern` cannot catch:

```python
from tenuo.constraints import Subpath

# Secure: Normalizes paths before checking
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

# Blocks: /data/../etc/passwd → normalizes to /etc/passwd → outside /data
# Blocks: /data/./../../etc/passwd → same
# Allows: /data/reports/file.txt → inside /data
```

### UrlSafe: SSRF Protection

`UrlSafe` blocks Server-Side Request Forgery (SSRF) attempts:

```python
from tenuo.constraints import UrlSafe

# Block private IPs, localhost, cloud metadata
guard = GuardBuilder().allow("fetch", url=UrlSafe()).build()

# Blocks: http://169.254.169.254/ (AWS metadata)
# Blocks: http://127.0.0.1/ (localhost)
# Blocks: http://10.0.0.1/ (private network)
# Blocks: http://2130706433/ (decimal IP encoding)

# With domain allowlist
strict = UrlSafe(allow_domains=["api.example.com", "*.googleapis.com"])
# Allows: https://api.example.com/v1
# Allows: https://storage.googleapis.com/bucket
# Blocks: https://evil.com/
```

### Pattern: Glob Matching

Simple glob-style matching for strings:

```python
from tenuo.constraints import Pattern

# Email domain restriction
guard = GuardBuilder().allow("send_email", to=Pattern("*@company.com")).build()

# Query filtering
guard = GuardBuilder().allow("search", query=Pattern("product:*")).build()
```

### Range: Numeric Bounds

Enforce min/max values for numeric arguments:

```python
from tenuo.constraints import Range

guard = GuardBuilder().allow("set_volume", level=Range(0, 100)).build()
guard = GuardBuilder().allow("api_call", timeout=Range(1, 60)).build()
```

### OneOf: Enumerated Values

Restrict to specific allowed values:

```python
from tenuo.constraints import OneOf

guard = GuardBuilder().allow(
    "set_mode",
    mode=OneOf(["read-only", "read-write", "admin"])
).build()
```

---

## Integration Patterns

### Tool Filtering

`filter_tools()` removes unauthorized tools before agent creation:

```python
all_tools = [read_file, write_file, delete_file, web_search]

# Only read_file and web_search will be visible to the agent
filtered = guard.filter_tools(all_tools)

agent = Agent(
    name="assistant",
    tools=filtered,  # Reduced tool set
    before_tool_callback=guard.before_tool,
)
```

**Why filter?** Don't waste tokens showing tools the LLM can't use.

### ScopedWarrant (Multi-Agent Isolation)

When multiple agents share the same session, use `ScopedWarrant` to prevent cross-agent warrant leaks:

```python
from tenuo.google_adk import TenuoPlugin, ScopedWarrant

# At agent creation time, scope the warrant
plugin = TenuoPlugin(warrant_key="my_warrant")
scoped = ScopedWarrant(warrant, agent_name="research_agent")

# Store in session state
session_state["my_warrant"] =scoped

# Before each turn, plugin validates the warrant belongs to this agent
agent = Agent(
    name="research_agent",
    before_agent_callback=plugin.before_agent_callback,
)
```

### Argument Remapping

Map ADK tool argument names to warrant constraint names:

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file", file_path="path")
    .build())

# Tool called with {"file_path": "/data/report.txt"}
# Validated against warrant's "path" constraint
```

### Denial Handling

Control what happens when a tool call is denied:

```python
# Raise exception (stops execution)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("raise").build()

# Return error dict (agent sees denial reason)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("return").build()

# Silent skip (not recommended - can confuse LLM)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("skip").build()
```

---

## Audit Logging

Every tool call decision is logged with context:

```python
def audit_callback(event):
    print(f"[AUDIT] {event.decision} tool={event.tool_name} agent={event.agent_name}")
    # Send to your logging system

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .audit_callback(audit_callback)
    .build())
```

**Event fields**:
- `decision`: "allowed" or "denied"
- `tool_name`: Name of the tool
- `agent_name`: From ToolContext (if available)
- `arguments`: Tool arguments
- `session_id`: Unique session identifier
- `timestamp`: When the decision was made

---

## Builder API Reference

### `.allow(tool_name, **constraints)`

Allow a tool with optional constraints (Tier 1):

```python
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("search", query=Pattern("*"))
    .build())
```

### `.with_warrant(warrant, signing_key)`

Use cryptographic warrant (Tier 2):

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .build())
```

### `.map_skill(tool_name, skill_name, **arg_mappings)`

Map tool/argument names to warrant skills:

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file", file_path="path")
    .build())
```

### `.on_denial(mode)`

Control denial behavior (`"raise"`, `"return"`, `"skip"`):

```python
guard = GuardBuilder().allow("read_file").on_denial("raise").build()
```

### `.audit_callback(callback)`

Register audit logging callback:

```python
def log_audit(event):
    logger.info(f"{event.decision}: {event.tool_name}")

guard = GuardBuilder().allow("read_file").audit_callback(log_audit).build()
```

---

## Advanced: Dynamic Warrants

For per-request warrants (e.g., user-specific capabilities):

```python
# Configure guard to look up warrant from session state
guard = (GuardBuilder()
    .with_warrant_key("user_warrant")  # Key in ToolContext.session_state
    .build())

# At runtime, inject user-specific warrant
def handle_request(user_id):
    warrant = issue_warrant_for_user(user_id)
    session_state["user_warrant"] = warrant
    
    # Agent uses the injected warrant
    agent.run(...)
```

---

## Tier 1 vs Tier 2 Comparison

| Feature | Tier 1 (Direct) | Tier 2 (Warrant + PoP) |
|---------|-----------------|------------------------|
| **Setup** | `.allow()` builder | Warrant issuance + signing key |
| **Cryptographic proof** | ❌ No | ✅ Yes (Ed25519 signatures) |
| **Protection against insider threats** | ❌ No | ✅ Yes |
| **Multi-agent delegation** | ❌ No | ✅ Yes (attenuation chains) |
| **Audit trail** | ✅ Events only | ✅ Cryptographic receipts |
| **Performance** | Fast (no crypto) | Slightly slower (signature checks) |
| **Use case** | Prototyping, single-process | Production, distributed agents |

---

## Examples

**Tier 1 - Research Agent**:
```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo.constraints import Subpath, UrlSafe

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/research/papers"))
    .allow("web_search", url=UrlSafe(allow_domains=["*.arxiv.org", "*.scholar.google.com"]))
    .build())

agent = Agent(
    name="research_agent",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
)
```

**Tier 2 - Multi-Agent System**:
```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder, TenuoPlugin, ScopedWarrant
from tenuo import SigningKey, Warrant
from tenuo.constraints import Subpath

# Control plane issues warrants
orchestrator_key = SigningKey.generate()
researcher_key = SigningKey.generate()

researcher_warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/research"))
    .capability("web_search")
    .holder(researcher_key.public_key)
    .ttl(3600)
    .mint(orchestrator_key))

# Create scoped warrant for session isolation
plugin = TenuoPlugin(warrant_key="agent_warrant")
scoped = ScopedWarrant(researcher_warrant, "researcher")

# Build guard
guard = (GuardBuilder()
    .with_warrant(researcher_warrant, researcher_key)
    .build())

# Create agent
researcher = Agent(
    name="researcher",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
    before_agent_callback=plugin.before_agent_callback,
)

# Run with scoped warrant in session state
session_state = {"agent_warrant": scoped}
# ... use session_state in agent execution
```

---

## See Also

- [Constraints Reference](./constraints.md) - Full list of available constraints
- [Security Model](./security.md) - Threat model and mitigations
- [OpenAI Integration](./openai.md) - Similar integration for OpenAI SDK
- [API Reference](./api-reference.md) - Complete Python API docs
