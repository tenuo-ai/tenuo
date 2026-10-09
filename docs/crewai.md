---
title: CrewAI Integration
description: Tool protection for CrewAI multi-agent workflows
---

# Tenuo CrewAI Integration

## Overview

Tenuo integrates with [CrewAI](https://crewai.com) using a **two-tier** protection model designed for multi-agent workflows:

| Tier | Setup | Best For |
|------|-------|----------|
| **Tier 1: Guardrails** | Inline constraints | Policy in trusted code, including production |
| **Tier 2: Warrants** | Warrant + signing key | Hierarchical delegation, verifiable authority, distributed execution |

**Tier 1** rejects out-of-policy tool and argument calls in trusted application code. A manipulated prompt cannot authorize a call the policy rejects.

**Tier 2** keeps those checks and adds signed, holder-bound authority and delegation that can only narrow. Your own issuer or a control plane issues warrants; the holder supplies Proof-of-Possession (PoP) for each call. A crew or downstream tool can verify that authority on its own.

> [!IMPORTANT]
> **Production Recommendation**: Register `guard.register()` or the callable from `as_hook()` so CrewAI's hook intercepts tool calls at the framework, with no per-tool wrapper. Use **Tier 1** when the crew's trusted code owns the policy. Use **Tier 2** when a crew or downstream tool must verify signed, holder-bound authority. Both hooks are process-wide. When the agent can skip them, enforce in the component that performs the effect, outside the agent's control.

---

## Installation

```bash
uv pip install "tenuo[crewai]"
```

---

## Quick Start

### Tier 1: Guardrails (5 minutes)

Use the **builder pattern** for semantic constraints, then register as a hook:

```python
from crewai import Agent
from crewai.tools import tool
from tenuo.crewai import GuardBuilder, Pattern, Subpath

@tool("search")
def search_tool(query: str) -> str:
    """Search the web."""
    return f"Results for: {query}"

@tool("read_file")
def read_tool(path: str) -> str:
    """Read a file."""
    return f"Contents of: {path}"

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

### Class-Based Hook (Global Scope)

To organize authorization in a `@CrewBase` class, call `guard.authorize_hook(context)` from a method decorated with CrewAI's `@before_tool_call`:

> **These hooks are global, not crew-scoped.** Constructing the class registers its method in CrewAI's process-wide hook registry. Its policy also applies to other crews in that process. Do not use separate class instances to isolate different crews' authorization policies; use separately protected tools or separate processes instead.

```python
from crewai.project import CrewBase
from crewai.hooks import before_tool_call
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

    @before_tool_call
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

Define gates and approvers on the warrant, then pass `.on_approval()`. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo.approval import cli_prompt
from tenuo.crewai import GuardBuilder

guard = (GuardBuilder()
    .allow("transfer_funds", amount=Range(0, 100_000))
    .with_warrant(warrant, agent_key)
    .on_approval(cli_prompt(approver_key=approver_key))
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

`register()` is process-wide. `register(agent_role="Researcher")` does not limit the hook to that agent. It forces every call in the process to look up the `Researcher::` namespace. To run a different guard for one agent, use CrewAI's agent filter:

```python
from crewai.hooks import before_tool_call

@before_tool_call(agents=["Researcher"])
def authorize_researcher(context):
    return researcher_guard.authorize_hook(context)
```

---

## Constraints

Tenuo provides semantic constraints that block specific attack vectors:

| Type | Example | Protects Against |
|------|---------|------------------|
| `Subpath(root)` | `Subpath("/data")` | Path traversal (`../etc/passwd`) |
| `path_glob(root, glob)` | `path_glob("/data", "*.pdf")` | Arbitrary file access |
| `Pattern(glob)` | `Pattern("*.pdf")` | Unexpected value shapes — **not** file access: `*` crosses `/`, so this alone admits `/etc/passwd.pdf` |
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
> A worker guard that trusts only the issuer must also be given the parent warrants. Pass them as `warrant_chain` (root first, excluding the leaf). Without them, the leaf's issuer is the delegator, and the call is denied with `Root warrant issuer is not trusted`.

```python
from tenuo import Pattern, SigningKey, Warrant
from tenuo.crewai import GuardBuilder, WarrantDelegator

control_plane_key = SigningKey.generate()
manager_key = SigningKey.generate()
researcher_key = SigningKey.generate()

manager_warrant = (Warrant.mint_builder()
    .capability("search", query=Pattern("*"))
    .holder(manager_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

researcher_warrant = WarrantDelegator().delegate(
    parent_warrant=manager_warrant,
    parent_key=manager_key,
    child_holder=researcher_key.public_key,
    attenuations={"search": {"query": Pattern("arxiv:*")}},
    ttl=300,
)

# The worker presents the parent and trusts the issuer, not the delegator.
researcher_guard = (GuardBuilder()
    .allow("search", query=Pattern("arxiv:*"))
    .with_warrant(
        researcher_warrant,
        researcher_key,
        warrant_chain=[manager_warrant],
    )
    .with_trusted_roots([control_plane_key.public_key])
    .build())

researcher_guard.authorize("search", {"query": "arxiv:safety"})  # allowed
```

`chain_scope([manager_warrant])` still supplies those parents when `warrant_chain` is omitted. Put the chain on the guard that verifies the call.

### Escalation Prevention

Delegation is blocked if:
- The child requests a tool the parent does not have (`EscalationAttempt`)
- A `Pattern` would be wider than the parent's (`PatternExpanded`)
- A `Subpath` would leave the parent's root (`ConstraintViolation`)

```python
from tenuo import Pattern, SigningKey, Subpath, Warrant
from tenuo.exceptions import ConstraintViolation, PatternExpanded
from tenuo.crewai import EscalationAttempt, WarrantDelegator, Wildcard

issuer = SigningKey.generate()
parent_key = SigningKey.generate()
child_key = SigningKey.generate()
parent = (Warrant.mint_builder()
    .capability("search", query=Pattern("arxiv:*"))
    .capability("read_file", path=Subpath("/data"))
    .holder(parent_key.public_key)
    .ttl(3600)
    .mint(issuer))
delegator = WarrantDelegator()

try:
    delegator.delegate(
        parent, parent_key, child_key.public_key,
        {"search": {"query": Pattern("*")}}, ttl=60,
    )
except PatternExpanded:
    pass  # "*" is wider than "arxiv:*"

try:
    delegator.delegate(
        parent, parent_key, child_key.public_key,
        {"read_file": {"path": Subpath("/")}}, ttl=60,
    )
except ConstraintViolation:
    pass  # "/" is not inside "/data"

try:
    delegator.delegate(
        parent, parent_key, child_key.public_key,
        {"delete_all": {"target": Wildcard()}}, ttl=60,
    )
except EscalationAttempt:
    pass  # the parent has no delete_all tool
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
| `"raise"` | Exception from `authorize()` | **Production** | Fail-closed on denial; callers must handle the exception. |
| `"log"` | `DenialResult` from `authorize()`, after a warning | **Direct calls** | Does not let a hooked tool call through. |
| `"skip"` | `DenialResult` from `authorize()`, quietly | **Direct calls** | Same hook behavior as `"log"`. |

A registered hook blocks the tool in every mode. `register()` and `@before_tool_call` return `False` on a denial, so `"log"` and `"skip"` do not turn the hook into a dry run. Those modes apply when you call `guard.authorize()` yourself. To inspect a call without running it, use `guard.explain(tool_name, arguments)`. The audit callback still runs when a hook denies a call.

### Production Recommendations

> [!IMPORTANT]
> **Use `"raise"` when you call `authorize()` yourself.**
> A registered hook already blocks the tool in every mode. `"log"` and `"skip"` only change `authorize()`. Ignoring the `DenialResult` it returns lets that direct call continue.

### Handling DenialResult (Non-Raising Modes)

When utilizing `"log"` or `"skip"`, checks must be explicit:

```python
from tenuo.crewai import DenialResult, GuardBuilder, Subpath

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .on_denial("log")
    .build())

result = guard.authorize("read_file", {"path": "/etc/passwd"})
if isinstance(result, DenialResult):
    print(f"Blocked: {result.reason}")
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
    WarrantExpired, InvalidPoP,
)

try:
    result = guard.authorize("read_file", {"path": "/data/report.txt"})
except ToolDenied:
    # The tool is not in the guard. Pick a different tool.
    ...
except CrewAIConstraintViolation as e:
    # The arguments failed a constraint. Retry with values inside it.
    ...
except (UnlistedArgument, WarrantExpired, InvalidPoP):
    # Closed-world rejection, an expired warrant, or a failed holder proof.
    raise
```

### DenialResult Usage

When using `.on_denial("log")` or `.on_denial("skip")`, exceptions are suppressed.
Check the result explicitly:

`authorize()` returns `DenialResult` instead of raising. See the check under Denial Modes. Delegation widening is separate: `PatternExpanded`, `ConstraintViolation`, and `EscalationAttempt` come from `WarrantDelegator.delegate()`, not from `authorize()`.

### Error Reference Table

| Error | Tier | Recovery Strategy |
|-------|------|-------------------|
| `ToolDenied` | 1+ | Use different tool |
| `CrewAIConstraintViolation` | 1+ | Retry with compliant arguments |
| `UnlistedArgument` | 1+ | Remove extra arguments |
| `EscalationAttempt` | Delegation | The child asked for a tool the parent does not have |
| `PatternExpanded` | Delegation | The child `Pattern` is wider than the parent's |
| `ConstraintViolation` | Delegation | The child `Subpath` is not inside the parent's root |
| `UnguardedToolError` | 1+ | (Strict Mode) Fix configuration |
| `WarrantExpired` | 2 | Refresh warrant |
| `InvalidPoP` | 2 | Check signing key configuration |
| `MissingSigningKey` | 2 | Provide signing key |

---

## Full Example: Hierarchical Research Crew

```python
from crewai import Agent, Task, Crew, Process
from crewai.hooks import before_tool_call
from crewai.tools import tool
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

@tool("search")
def search_tool(query: str, max_results: int = 10) -> str:
    """Search academic papers."""
    return f"Found {max_results} results for: {query}"

@tool("read_file")
def read_tool(path: str) -> str:
    """Read a file."""
    return f"Contents of: {path}"

@tool("summarize")
def summarize_tool(text: str, style: str = "brief") -> str:
    """Summarize text."""
    return f"Summary ({style}): {text[:100]}..."

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
    .with_warrant(researcher_warrant, researcher_key, warrant_chain=[manager_warrant])
    .with_trusted_roots([control_plane_key.public_key])
    .build())

writer_guard = (GuardBuilder()
    .allow("summarize", text=Pattern("*"), style=Pattern("*"))
    .allow("read_file", path=Subpath("/research/drafts"))
    .with_warrant(writer_warrant, writer_key, warrant_chain=[manager_warrant])
    .with_trusted_roots([control_plane_key.public_key])
    .build())

# CrewAI's agent filter keeps each guard on that agent's calls.
# register(agent_role=...) does not: the hook is process-wide.
@before_tool_call(agents=["Researcher"])
def authorize_researcher(context):
    return researcher_guard.authorize_hook(context)

@before_tool_call(agents=["Writer"])
def authorize_writer(context):
    return writer_guard.authorize_hook(context)

# =============================================================================
# 5. Create Agents and Run Crew (tools are unmodified)
# =============================================================================

researcher = Agent(
    role="Researcher",
    goal="Find relevant papers on arxiv",
    backstory="You search arxiv and read papers under /research/papers.",
    tools=[search_tool, read_tool],
)

writer = Agent(
    role="Writer",
    goal="Summarize research findings",
    backstory="You summarize papers and read drafts under /research/drafts.",
    tools=[summarize_tool, read_tool],
)

research_task = Task(
    description="Find papers on language model safety",
    expected_output="A short list of papers",
    agent=researcher,
)

writing_task = Task(
    description="Summarize the findings",
    expected_output="A short summary",
    agent=writer,
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    process=Process.sequential,
)

# result = crew.kickoff()
```

---

## Migration Strategy

Moving from unprotected CrewAI to Tenuo GuardedCrew:

1. **Audit Phase**: Add `.audit(callback)` and keep `.on_denial("raise")`. A CrewAI hook blocks denied calls in every denial mode. Use `guard.explain(tool, args)` to check one call without running the crew.
2. **Policy Generation**: Map the audit logs to agent roles. Identify which tools are actually used by each agent.
3. **Constraint Hardening**: Replace `Wildcard()` with `Pattern` or `Subpath` based on observed data (e.g., if agent only reads `/tmp`, restrict to `/tmp`).
4. **Enforcement**: Switch to `.on_denial("raise")` and enable `.strict()` to prevent future drift.

## Performance Considerations

- **Tier 1 (Guardrails):** Local, in-process constraint evaluation with no warrant signature check and no network round trip. Benchmark workloads with heavy constraints.
- **Tier 2 (Warrants):** Verification is local and offline — no runtime network call, no shared database. See [Performance Benchmarks](./api-reference#performance-benchmarks) for measured timings.
- **Audit Logging:** The `audit_callback` is synchronous. For high-throughput production, use a non-blocking logger (e.g., `logging` with a queue handler) to avoid stalling the agent thread.

---

## Production Deployment Checklist

Before deploying CrewAI agents with Tenuo protection:

### Security Review
- [ ] **Authority Model:** Use warrants and holder proof when crews need verifiable delegated authority. Local-policy-only deployments explicitly use Tier 1 and keep policy enforcement in trusted code.
- [ ] **Hooks Registered:** Guards use `guard.register()` or explicitly register the callable returned by `as_hook()` for framework-level enforcement. Both use global hooks; `as_hook()` does not provide crew isolation.
- [ ] **Least Privilege:** Each agent has specific allowed tools (no `*` patterns unless necessary).
- [ ] **Delegated warrants:** Worker guards pass `warrant_chain=` (parents, root first, excluding the leaf) and `.with_trusted_roots()` set to the issuer. Trusting the delegator's key instead of the issuer accepts a self-issued leaf.

### Decision Matrix

| Feature | Dev / Prototype | Production |
|---------|----------------|------------|
| Tier | Either, according to the authority model | Tier 2 for verifiable delegation; Tier 1 for trusted local policy |
| Denial Mode | "log" or "raise" | "raise" (Fail Closed) |
| Constraints | Loose (Wildcards) | Strict (Specific Patterns) |
| Hook Scope | `register()` or `as_hook()`, both process-wide | Same. Confirm the hook covers the tool types you use |

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

- [GuardedCrew Example](../tenuo-python/examples/crewai/guarded_crew.py) - Policy-based protection
- [Flow Example](../tenuo-python/examples/crewai/guarded_flow.py) - Guarded steps in CrewAI Flows
- [OpenAI Integration](./openai) - Tool protection for OpenAI
- [LangGraph Integration](./langgraph) - Multi-agent graph security
- [Constraints Reference](./constraints) - All constraint types
- [Security Model](./security) - Threat model, best practices
