---
title: CrewAI Integration
description: Tool protection for CrewAI multi-agent workflows
---

# Tenuo CrewAI Integration

## Overview

Tenuo integrates with [CrewAI](https://crewai.com) using a **two-tier** protection model designed for multi-agent workflows:

| Tier | Setup | Best For |
|------|-------|----------|
| **Tier 1: Guardrails** | Inline constraints | Quick hardening, prototyping, single-crew agents |
| **Tier 2: Warrants** | Warrant + signing key | Hierarchical crews, distributed execution, audit requirements |

**Tier 1** catches LLM mistakes and prompt injection with minimal setup. Constraints are defined inline in your code.

**Tier 2** adds cryptographic proof. Warrants are issued by a control plane and include Proof-of-Possession (PoP) for each tool call. Required for hierarchical crews and delegation.

> [!IMPORTANT]
> **Production Recommendation**: Use **Tier 2** with `guard.register()` for production deployments. The hooks API intercepts all tool calls at the framework level—no wrapping needed.

---

## Installation

```bash
uv pip install tenuo crewai
```

---

## Quick Start

### Tier 1: Guardrails (5 minutes)

Use the **builder pattern** for semantic constraints, then register as a hook:

```python
from crewai import Agent, Task, Crew, Tool
from tenuo.crewai import GuardBuilder, Pattern, Subpath

# Define tools
search_tool = Tool(
    name="search",
    description="Search the web",
    func=lambda query: f"Results for: {query}"
)

read_tool = Tool(
    name="read_file",
    description="Read a file",
    func=lambda path: f"Contents of: {path}"
)

# Create guard with constraints
guard = (GuardBuilder()
    .allow("search", query=Pattern("*"))
    .allow("read_file", path=Subpath("/data"))
    .on_denial("raise")
    .build())

# Register as a global hook — ALL tool calls go through this guard
guard.register()

# Use tools in agent (no wrapping needed)
agent = Agent(
    role="Researcher",
    goal="Find and read research data",
    tools=[search_tool, read_tool],
)

# Unauthorized calls are blocked
# agent.execute("Read /etc/passwd") -- CrewAIConstraintViolation!
```

### Crew-Scoped Hook

For crew-scoped authorization (instead of global), use `as_hook()` with CrewAI's `@before_tool_call_crew` decorator:

```python
from crewai import CrewBase
from crewai.hooks import before_tool_call_crew
from tenuo import Pattern
from tenuo.crewai import GuardBuilder, Subpath

@CrewBase
class MyProjCrew:
    def __init__(self):
        self.guard = (GuardBuilder()
            .allow("read_file", path=Subpath("/data"))
            .allow("search", query=Pattern("*"))
            .on_denial("raise")
            .build())

    @before_tool_call_crew
    def authorize(self, context):
        return self.guard.authorize_hook(context)
```

### Tier 2: Warrants

For hierarchical crews with cryptographic authorization:

```python
from tenuo import Pattern, SigningKey, Warrant
from tenuo.crewai import GuardBuilder, Subpath

# Agent holds warrant and signing key
agent_key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("read_file", {"path": Subpath("/data")})
    .capability("search")
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Build guard with warrant
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("search", query=Pattern("*"))
    .with_warrant(warrant, agent_key)
    .build())

# Register — each tool call is now cryptographically authorized
guard.register()
```

### Human Approval

Add human-in-the-loop approval with `.approval_policy()` and `.on_approval()`. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo.approval import cli_prompt
from tenuo.crewai import GuardBuilder

guard = (GuardBuilder()
    ...
    .approval_policy(policy)
    .on_approval(cli_prompt(approver_key=key))
    .build())

guard.register()
```

---

## Warrant Lifecycle

Warrants (Tier 2) are time-bound credentials. They expire automatically to limit the window of opportunity for attackers.

### Time-To-Live (TTL)

Set a TTL (in seconds) when minting or delegating:

```python
# 1 hour TTL
warrant = Warrant.mint_builder().ttl(3600)... 

# Delegation with reduced TTL (e.g., 5 minutes)
child = delegator.delegate(..., ttl=300)
```

Also supports string format in `guarded_step`: `ttl="15m"`.

### Expiry Handling

When a warrant expires, all tool calls raise `WarrantExpired`.

**Best Practice:**
1. **Short-lived warrants** for active tasks (e.g., 5-15 mins).
2. **Refresh flow**: If `WarrantExpired` is caught, the agent should request a new warrant from the control plane (if architected to do so) or fail the task for manual intervention.

### Debugging WarrantExpired

If you see `WarrantExpired` prematurely:
- Check server/client clock synchronization.
- Verify `ttl` is in seconds (integers) or correct format strings.
- Ensure delegation chain parents have not expired (child cannot outlive parent).

---

## Agent Namespacing

CrewAI crews often have multiple agents with tools of the same name but different security requirements.

**Solution:** Use namespaced constraints with `register()`:

```python
from tenuo import Pattern
from tenuo.crewai import GuardBuilder

guard = (GuardBuilder()
    # Global constraint (fallback)
    .allow("search", query=Pattern("*"))
    
    # Agent-specific constraints (take precedence)
    .allow("researcher::search", query=Pattern("arxiv:*"))
    .allow("writer::search", query=Pattern("internal:*"))
    .build())

# Register as global hook — agent role is resolved automatically
# from the CrewAI hook context (context.agent.role)
guard.register()

# researcher can only search arxiv:*
# writer can only search internal:*
```

**Resolution order:**
1. `agent_role::tool_name` (exact match)
2. `tool_name` (global fallback)
3. Reject if neither exists

---

## Constraints

Tenuo provides semantic constraints that block specific attack vectors:

| Type | Example | Protects Against |
|------|---------|------------------|
| `Subpath(root)` | `Subpath("/data")` | Path traversal (`../etc/passwd`) |
| `Pattern(glob)` | `Pattern("*.pdf")` | Arbitrary file access |
| `OneOf([values])` | `OneOf(["dev", "prod"])` | Injection attacks |
| `Range(min, max)` | `Range(0, 100)` | Parameter tampering |
| `UrlSafe()` | `UrlSafe()` | SSRF attacks |
| `Regex(pattern)` | `Regex(r"^[a-z]+$")` | Format violations |
| `Wildcard()` | `Wildcard()` | Allow any value |

### Zero Trust for Arguments

> [!IMPORTANT]
> Once you add **any** constraint to a tool, Tenuo enforces "closed-world" for that tool.
> **Any unlisted argument is REJECTED**.

```python
# Blocks call with 'timeout' arg because it's unknown
guard = GuardBuilder().allow("api_call", url=UrlSafe()).build()
# agent calls api_call(url="...", timeout=30) -- UnlistedArgument!

# Explicitly allow unknown args
guard = GuardBuilder().allow("api_call", url=UrlSafe(), timeout=Wildcard()).build()
```

---

## Delegation (Hierarchical Crews)

CrewAI's hierarchical process mode allows a manager to delegate tasks to workers. Tenuo's `WarrantDelegator` ensures delegation follows **attenuation-only** rules: child warrants can only narrow scope, never expand.

> [!TIP]
> Use `chain_scope` on the parent warrant to limit maximum delegation depth and prevent unbounded chains in complex multi-agent crews.

```python
from tenuo import Pattern
from tenuo.crewai import WarrantDelegator

delegator = WarrantDelegator()

# Manager delegates to researcher with narrowed scope
researcher_warrant = delegator.delegate(
    parent_warrant=manager_warrant,
    parent_key=manager_key,
    child_holder=researcher.public_key,
    attenuations={
        "search": {"query": Pattern("arxiv:*")},  # Only arxiv
        "fetch": {"url": Pattern("https://arxiv.org/*")},
    },
    ttl=300,  # 5 minute delegation
)

# Researcher can ONLY search arxiv (even if manager has broader access)
```

### Escalation Prevention

Delegation is blocked if:
- Child requests a tool the parent doesn't have
- Child constraint would widen access

```python
# Manager has: search(query=Pattern("arxiv:*"))

# Fails: widening constraint
delegator.delegate(
    ...,
    attenuations={"search": {"query": Pattern("*")}},  # EscalationAttempt!
)

# Fails: new tool
delegator.delegate(
    ...,
    attenuations={"delete_all": {"target": Wildcard()}},  # EscalationAttempt!
)
```

---

## Flow Integration (@guarded_step)

For CrewAI Flows, use the `@guarded_step` decorator to scope authorization to individual steps:

```python
from crewai import Flow, step
from tenuo.crewai import guarded_step, Pattern, Wildcard

class ResearchFlow(Flow):
    
    @guarded_step(
        allow={"web_search": {"query": Wildcard()}},
        ttl="10m",
        strict=True  # Fail if unguarded tools detected
    )
    def research_step(self, state):
        return self.research_crew.kickoff(state)
    
    @guarded_step(
        allow={"send_email": {"recipients": Pattern("*@company.com")}},
        ttl="5m"
    )
    def notify_step(self, state):
        return self.email_agent.execute(state)
```

### Decorator Parameters

| Parameter | Description |
|-----------|-------------|
| `allow` | Dict of tool_name -> constraints (Tier 1) |
| `warrant` | Warrant for Tier 2 |
| `signing_key` | Key for PoP signature |
| `ttl` | Step TTL like "10m", "1h", "1d" |
| `strict` | Fail if unguarded calls detected |
| `audit` | Audit callback |

### Strict Mode

When `strict=True`, the decorator tracks all tool calls during step execution. If any unguarded tool is called, `UnguardedToolError` is raised after the step completes.

```python
from tenuo.crewai import get_active_guard, is_strict_mode

# Check if currently in a guarded context
guard = get_active_guard()  # Returns CrewAIGuard or None
strict = is_strict_mode()   # True if strict mode active
```

---

## Crew-Level Guard (GuardedCrew)

For crew-wide protection with policy-based per-agent authorization:

```python
from tenuo.crewai import GuardedCrew, Pattern, Subpath

crew = (GuardedCrew(
    agents=[researcher, writer, reviewer],
    tasks=[research_task, write_task, review_task],
    process=Process.sequential)
    .policy({
        "researcher": ["web_search", "read_file"],
        "writer": ["write_file"],
        "reviewer": ["read_file", "send_email"],
    })
    .constraints({
        "researcher": {
            "web_search": {"query": Pattern("arxiv:*")},
            "read_file": {"path": Subpath("/data")},
        },
    })
    .on_denial("raise")
    .strict()  # Enable strict mode
    .build())

result = crew.kickoff(inputs={"topic": "AI safety"})
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `.policy({})` | Map agent role to allowed tools |
| `.constraints({})` | Map agent role to tool to constraints |
| `.with_issuer(warrant, key)` | Set warrant issuer for Tier 2 |
| `.on_denial(mode)` | Denial handling mode |
| `.audit(callback)` | Audit callback for all agents |
| `.strict()` | Enable strict mode |
| `.ttl(ttl)` | Set TTL for generated warrants |
| `.build()` | Build the GuardedCrew |

---

## Denial Modes

Configure how denials are handled based on your environment:

```python
from tenuo import Pattern
from tenuo.crewai import GuardBuilder

guard = (GuardBuilder()
    .allow("search", query=Pattern("*"))
    .on_denial("raise")  # "raise", "log", or "skip"
    .build())

guard.register()
```

### Use Case Analysis

| Mode | Behavior | Use Case | Trade-off |
|------|----------|----------|-----------|
| `"raise"` | Exception | **Production** | Guaranteed safety, but requires try/catch block. |
| `"log"` | Return `DenialResult` | **Development** | Visible errors without crashing agent, but dangerous if result ignored. |
| `"skip"` | Return `DenialResult` | **Legacy/Transition** | Simulates "tool unavailable", might confuse agent. |

### Production Recommendations

> [!IMPORTANT]
> **Always use `"raise"` in production.**
> Fail-closed behavior is critical for security. Using `"log"` or `"skip"` can lead to silent failures where an attacker bypasses controls without detection.

### Handling DenialResult (Non-Raising Modes)

When utilizing `"log"` or `"skip"`, checks must be explicit:

```python
result = protected_tool.func(path="/etc/passwd")

if isinstance(result, DenialResult):
    # Logged but didn't raise
    print(f"Blocked: {result.reason}")
else:
    # Success
    pass
```

---

## Audit Logging

Track all authorization decisions:

```python
from tenuo import Pattern
from tenuo.crewai import GuardBuilder, AuditEvent

def audit_callback(event: AuditEvent):
    print(f"{event.decision}: {event.tool}")
    if event.decision == "DENY":
        print(f"  Reason: {event.reason}")

guard = (GuardBuilder()
    .allow("search", query=Pattern("*"))
    .audit(audit_callback)
    .build())

guard.register()
```

### AuditEvent Fields

| Field | Description |
|-------|-------------|
| `tool` | Tool being called |
| `arguments` | Tool arguments |
| `decision` | `"ALLOW"` or `"DENY"` |
| `reason` | Why decision was made |
| `error_code` | Machine-readable error code (if denied) |
| `agent_role` | Agent role (if set) |
| `timestamp` | ISO 8601 timestamp |

---

## Introspection

### Explain Decisions

```python
explanation = guard.explain("read_file", {"path": "/data/report.txt"})

print(explanation.status)  # "ALLOWED" or "DENIED"
print(explanation.reason)  # Why
```

### Tier Detection

```python
print(guard.tier)        # 1 or 2
print(guard.has_warrant) # True if Tier 2

if guard.tier == 2:
    info = guard.warrant_info()
    print(f"Warrant expires in {info['ttl_remaining']}s")
    print(f"Tools: {info['tools']}")
```

### Validation

Check configuration before production:

```python
warnings = guard.validate()
for warning in warnings:
    print(f"WARNING: {warning}")
```

---

## Error Handling Patterns

Robust agents should handle authorization failures gracefully.

### Try/Catch Patterns

```python
from tenuo.crewai import (
    ToolDenied, CrewAIConstraintViolation, UnlistedArgument,
    WarrantExpired, InvalidPoP, EscalationAttempt
)

try:
    result = protected_tool.func(arg="value")
except ToolDenied:
    # Retrying won't help unless we use a different tool
    agent.memory.add("Tool access denied. Trying alternative...")
    return execute_alternative()

except CrewAIConstraintViolation as e:
    # Argument validation failed. Agent can correct the argument.
    agent.memory.add(f"Argument invalid: {e}. Retrying with valid constraints.")
    return retry_with_correction()

except WarrantExpired:
    # Credential dead. Hard stop or request refresh.
    system.alert("Warrant expired during active task")
    raise

except (InvalidPoP, EscalationAttempt):
    # Potential security breach or misconfiguration
    system.security_alert("Integrity check failed!")
    raise
```

### DenialResult Usage

When using `.on_denial("log")` or `.on_denial("skip")`, exceptions are suppressed.
Check the result explicitly:

```python
result = protected_tool.func(...)

if isinstance(result, DenialResult):
    print(f"Action Blocked: {result.reason}")
    # Recovery: skip this step or try another parameter
else:
    process(result)
```

### Error Reference Table

| Error | Tier | Recovery Strategy |
|-------|------|-------------------|
| `ToolDenied` | 1+ | Use different tool |
| `CrewAIConstraintViolation` | 1+ | Retry with compliant arguments |
| `UnlistedArgument` | 1+ | Remove extra arguments |
| `EscalationAttempt` | 1+ | Do not escalate privileges |
| `UnguardedToolError` | 1+ | (Strict Mode) Fix configuration |
| `WarrantExpired` | 2 | Refresh warrant |
| `InvalidPoP` | 2 | Check signing key configuration |
| `MissingSigningKey` | 2 | Provide signing key |

---

## Full Example: Hierarchical Research Crew

```python
from crewai import Agent, Task, Crew, Tool, Process
from tenuo import SigningKey, Warrant
from tenuo.crewai import (
    GuardBuilder,
    WarrantDelegator,
    Pattern,
    Subpath,
    Range,
)

# =============================================================================
# 1. Define Tools
# =============================================================================

search_tool = Tool(
    name="search",
    description="Search academic papers",
    func=lambda query, max_results=10: f"Found {max_results} results for: {query}"
)

read_tool = Tool(
    name="read_file",
    description="Read a file",
    func=lambda path: f"Contents of: {path}"
)

summarize_tool = Tool(
    name="summarize",
    description="Summarize text",
    func=lambda text, style="brief": f"Summary ({style}): {text[:100]}..."
)

# =============================================================================
# 2. Create Warrants (Tier 2)
# =============================================================================

control_plane_key = SigningKey.generate()
manager_key = SigningKey.generate()
researcher_key = SigningKey.generate()
writer_key = SigningKey.generate()

# Manager warrant: broad access
manager_warrant = (Warrant.mint_builder()
    .capability("search", {"query": Pattern("*"), "max_results": Range(1, 50)})
    .capability("read_file", {"path": Subpath("/research")})
    .capability("summarize")
    .holder(manager_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# =============================================================================
# 3. Delegate to Workers
# =============================================================================

delegator = WarrantDelegator()

# Researcher: only arxiv searches
researcher_warrant = delegator.delegate(
    parent_warrant=manager_warrant,
    parent_key=manager_key,
    child_holder=researcher_key.public_key,
    attenuations={
        "search": {"query": Pattern("arxiv:*"), "max_results": Range(1, 20)},
        "read_file": {"path": Subpath("/research/papers")},
    },
    ttl=1800,
)

# Writer: only summarization
writer_warrant = delegator.delegate(
    parent_warrant=manager_warrant,
    parent_key=manager_key,
    child_holder=writer_key.public_key,
    attenuations={
        "summarize": {"text": Pattern("*"), "style": Pattern("*")},
        "read_file": {"path": Subpath("/research/drafts")},
    },
    ttl=1800,
)

# =============================================================================
# 4. Build Guards and Register as Hooks
# =============================================================================

researcher_guard = (GuardBuilder()
    .allow("search", query=Pattern("arxiv:*"), max_results=Range(1, 20))
    .allow("read_file", path=Subpath("/research/papers"))
    .with_warrant(researcher_warrant, researcher_key)
    .build())

writer_guard = (GuardBuilder()
    .allow("summarize", text=Pattern("*"), style=Pattern("*"))
    .allow("read_file", path=Subpath("/research/drafts"))
    .with_warrant(writer_warrant, writer_key)
    .build())

# Register guards — agent role is resolved from hook context automatically
researcher_guard.register(agent_role="Researcher")
writer_guard.register(agent_role="Writer")

# =============================================================================
# 5. Create Agents and Run Crew (tools are unmodified)
# =============================================================================

researcher = Agent(
    role="Researcher",
    goal="Find relevant papers on arxiv",
    tools=[search_tool, read_tool],
)

writer = Agent(
    role="Writer",
    goal="Summarize research findings",
    tools=[summarize_tool, read_tool],
)

research_task = Task(
    description="Find papers on 'language model safety'",
    agent=researcher,
)

writing_task = Task(
    description="Summarize the findings",
    agent=writer,
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    process=Process.sequential,
)

# result = crew.kickoff()
# researcher_guard.unregister()
# writer_guard.unregister()
```

---

## Migration Strategy

Moving from unprotected CrewAI to Tenuo GuardedCrew:

1. **Audit Phase**: Configure `GuardedCrew` with `.on_denial("log")`. Run your existing agents and capture the audit logs.
2. **Policy Generation**: Map the audit logs to agent roles. Identify which tools are actually used by each agent.
3. **Constraint Hardening**: Replace `Wildcard()` with `Pattern` or `Subpath` based on observed data (e.g., if agent only reads `/tmp`, restrict to `/tmp`).
4. **Enforcement**: Switch to `.on_denial("raise")` and enable `.strict()` to prevent future drift.

## Performance Considerations

- **Tier 1 (Guardrails):** Pure regex/string matching — not the bottleneck on any realistic agent workload.
- **Tier 2 (Warrants):** Verification is local and offline — no runtime network call, no shared database. See [Performance Benchmarks](./api-reference#performance-benchmarks) for measured timings.
- **Audit Logging:** The `audit_callback` is synchronous. For high-throughput production, use a non-blocking logger (e.g., `logging` with a queue handler) to avoid stalling the agent thread.

---

## Production Deployment Checklist

Before deploying CrewAI agents with Tenuo protection:

### Security Review
- [ ] **Tier 2 Enabled:** Application uses Warrants + Signing Keys for all production crews.
- [ ] **Hooks Registered:** All guards use `guard.register()` or crew-scoped `as_hook()` for framework-level enforcement.
- [ ] **Least Privilege:** Each agent has specific allowed tools (no `*` patterns unless necessary).
- [ ] **Delegation Depth:** Max delegation depth configured (via `chain_scope`) to prevent infinite chains.

### Decision Matrix

| Feature | Dev / Prototype | Production |
|---------|----------------|------------|
| Tier | Tier 1 (Guardrails) | Tier 2 (Warrants) |
| Denial Mode | "log" or "raise" | "raise" (Fail Closed) |
| Constraints | Loose (Wildcards) | Strict (Specific Patterns) |
| Hook Scope | Global (`register()`) | Crew-scoped (`as_hook()`) or Global |

### Monitoring & Operations
- [ ] **Audit Logging:** `audit_callback` configured and shipping logs to SIEM/storage.
- [ ] **Alerting:** Alerts set for `EscalationAttempt`, `InvalidPoP`, and `WarrantExpired`.
- [ ] **Key Rotation:** Plan for rotating Signing Keys.

---

## Troubleshooting

### Common Issues

**Q: Agent keeps retrying the same denied tool call.**
A: Pass a clear failure message back to the agent. "raise" mode throws an exception which CrewAI catches and feeds back to the LLM. If using "log", ensure you return `DenialResult` content to the agent.

**Q: `UnlistedArgument` error even for valid arguments.**
A: Tenuo enforces "closed-world". You must list **all** expected arguments in `GuardBuilder.allow()`, or use `arg=Wildcard()` to exempt specific ones.

**Q: PoP verification fails (`InvalidPoP`).**
A: Ensure the `SigningKey` used to sign the warrant matches the `holder` public key in the warrant.

**Q: `AttributeError: ... has no attribute 'func'`**
A: Ensure you are wrapping a standard CrewAI `Tool`. If using custom classes, they should inherit from `crewai.tools.BaseTool` or expose a `.func` / `._run` method.

### Debugging Guide

1. **Enable Strict Mode:** `GuardedCrew(...).strict()` will surface lurking unguarded calls.
2. **Audit Logs:** Use `.audit(print)` to see exactly what Tenuo sees.
3. **Introspection:** Print `guard.explain("tool_name", {"arg": "val"})` to dry-run authorization logic.

---

## See Also

- [GuardedCrew Example](../examples/crewai/guarded_crew.py) - Policy-based protection
- [Flow Example](../examples/crewai/guarded_flow.py) - Guarded steps in CrewAI Flows
- [OpenAI Integration](./openai) - Tool protection for OpenAI
- [LangGraph Integration](./langgraph) - Multi-agent graph security
- [Constraints Reference](./constraints) - All constraint types
- [Security Model](./security) - Threat model, best practices
