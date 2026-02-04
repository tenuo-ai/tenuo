# Tenuo CrewAI Integration Spec

**For**: Tenuo SDK contributors  
**Reference**: [Integration Guide](../../docs/integration-guide.md), [OpenAI](../../docs/openai.md)

---

## Overview

This spec defines the CrewAI integration for the Tenuo Python SDK, providing constraint-based authorization for multi-agent workflows.

---

## Key Design Decisions

### Tool Identity: Namespacing

CrewAI tool names are not globally unique. Multiple agents may have tools named `search` or `fetch` with different implementations and different security requirements.

**Solution:** Internally namespace tools as `agent_role::tool_name`.

```python
# DX: Simple names in builder
guard = (GuardBuilder()
    .allow("search", query=Wildcard())  # Applies to all agents
    .allow("researcher::search", query=Pattern("arxiv:*"))  # Agent-specific
    .allow("writer::search", query=Pattern("internal:*"))  # Different constraints
    .build())

# Internal storage: Namespaced keys
self._allowed = {
    "researcher::search": {"query": Pattern("arxiv:*")},
    "writer::search": {"query": Pattern("internal:*")},
    "search": {"query": Wildcard()},  # Fallback for unqualified
}
```

**Resolution order:**
1. Check `agent_role::tool_name` (exact match)
2. Fall back to `tool_name` (global default)
3. Reject if neither exists

This prevents cross-agent confusion in larger crews while keeping DX simple for basic cases.

### Warrant Lifecycle

Warrants are ephemeral, step-scoped, and must be explicitly managed.

| Aspect | Behavior |
|--------|----------|
| **Scope** | Warrants are step-scoped by default. A warrant issued in `@guarded_step` is valid only for that step's execution. |
| **Storage** | Warrants are held in memory, not persisted. They are NOT stored in CrewAI memory or state. |
| **Expiry** | TTL is enforced at each tool call. Expired warrants are rejected, even mid-step. |
| **Retries** | On retry, a new warrant must be issued. Expired or revoked warrants are not automatically renewed. |
| **Flow restarts** | Warrants do not survive flow restarts. Restarting a flow requires re-issuance from the policy engine. |

```python
# Example: Warrant expires mid-step
warrant = issuer.issue(ttl="30s")
agent.execute(task1)  # OK, within TTL
time.sleep(35)
agent.execute(task2)  # WarrantExpired: must re-issue
```

This prevents subtle bugs from stale or reused warrants.

---

## Development Roadmap

```
1. STUDY
   └─ Read tenuo/openai.py (primary template)
   └─ Read tenuo/langgraph.py (state management patterns)
   └─ Understand CrewAI's Tool, Agent, Crew, Flow architecture

2. WRITE TESTS FIRST
   └─ Copy tests from Critical Test Scenarios
   └─ Copy the 6 Invariant Tests
   └─ Add CrewAI-specific: delegation, hierarchical process

3. SCAFFOLD
   └─ Create tenuo/crewai.py
   └─ Implement GuardBuilder with .allow() and .build()
   └─ Implement protect_tool() zero-config entry point

4. IMPLEMENT
   └─ Tier 1: Constraint checking via satisfies()
   └─ Tier 2: Warrant + PoP for distributed crews
   └─ Handle delegation chain attenuation

5. POLISH
   └─ Rich error messages with quick fixes
   └─ .validate() for startup checks
   └─ on_denial modes (raise/log/skip)

6. VERIFY & DOCUMENT
   └─ Integration Checklist
   └─ docs/crewai.md
   └─ examples/crewai/
```

---

## API Patterns

### Pattern 1: Builder (Primary)

```python
from tenuo.crewai import GuardBuilder
from tenuo import Subpath, UrlSafe, Pattern, Wildcard

# Tier 1: Constraints only (single-process crews)
guard = (GuardBuilder()
    .allow("send_email", 
           recipients=Pattern("*@company.com"),
           subject=Wildcard(),
           body=Wildcard())
    .allow("read_file", path=Subpath("/data"))
    .allow("web_search", query=Wildcard(), max_results=Range(1, 100))
    .on_denial("raise")  # "raise" | "log" | "skip"
    .build())

# Apply to CrewAI tool
from crewai import Tool

protected_tool = guard.protect(gmail_tool)

# Or apply to agent's tools
agent = Agent(
    role="Email Assistant",
    tools=guard.protect_all([gmail_tool, calendar_tool])
)

# Tier 2: Warrant with PoP (distributed crews)
guard = (GuardBuilder()
    .with_warrant(warrant, signing_key)
    .build())
```

### Pattern 2: Zero-Config Entry Point

```python
from tenuo.crewai import protect_tool, protect_agent
from tenuo import Subpath, UrlSafe, Pattern

# Protect a single tool
protected = protect_tool(
    gmail_tool,
    recipients=Pattern("*@company.com"),
    subject=Wildcard(),
)

# Protect all tools on an agent
agent = protect_agent(
    Agent(role="Researcher", tools=[search, fetch]),
    search={"query": Wildcard(), "max_results": Range(1, 50)},
    fetch={"url": UrlSafe(allow_domains=["*.gov", "*.edu"])},
)
```

### Pattern 3: Crew-Level Guard

```python
from tenuo.crewai import GuardedCrew

# Crew that issues warrants to agents (Tier 2)
crew = (GuardedCrew(
    agents=[researcher, writer, reviewer],
    tasks=[research_task, write_task, review_task],
    process=Process.sequential)
    .with_issuer(warrant_issuer)
    .policy({
        "researcher": ["web_search", "read_file"],
        "writer": ["write_file"],
        "reviewer": ["read_file", "send_email"],
    })
    .build())
```

### Pattern 4: Flow Integration

```python
from tenuo.crewai import guarded_step
from crewai import Flow, step

class MyFlow(Flow):
    
    @guarded_step(
        allow={"web_search": {"query": Wildcard()}},
        ttl="10m"
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

**Important:** A guarded step should not call unguarded tools downstream. If `research_step` internally calls tools not covered by its warrant, those calls will fail (or bypass authorization if unprotected).

Best practice:
- Ensure all tools called within a guarded step are protected
- Use `strict=True` to enforce this at runtime (fails if unguarded tools are detected)

```python
@guarded_step(
    allow={...},
    strict=True  # Fails if step calls any unguarded tools
)
def secure_step(self, state):
    ...
```

---

## Policy Explanation API

The `explain()` method provides introspection into authorization decisions. This is critical for debugging, CI testing, and compliance.

### Basic Usage

```python
# Why can't my agent do this?
result = guard.explain("send_email", {"recipients": "external@gmail.com"})

print(result)
# ExplanationResult(
#     tool="send_email",
#     status="DENIED",
#     reason="Constraint violation on 'recipients'",
#     details={
#         "argument": "recipients",
#         "value": "external@gmail.com",
#         "constraint": "Pattern('*@company.com')",
#         "expected": "Recipients must match *@company.com",
#     },
#     quick_fix=".allow('send_email', recipients=Pattern('*@gmail.com'))"
# )
```

### Use Cases

**CI Policy Tests:**
```python
def test_support_bot_cannot_access_payments():
    guard = load_guard("support_bot")
    result = guard.explain("write_payment", {"amount": 100})
    assert result.status == "DENIED"
```

**Pre-flight Compliance Checks:**
```python
def validate_agent_before_deploy(agent, expected_capabilities):
    guard = agent.guard
    for tool, args in expected_capabilities:
        result = guard.explain(tool, args)
        if result.status == "DENIED":
            raise ComplianceError(f"Agent cannot perform required action: {result}")
```

**Interactive Debugging:**
```python
# "Why did my agent fail?"
guard.explain_all(agent.last_session.tool_calls)
# Returns explanation for each call, highlighting failures
```

### Implementation

```python
@dataclass
class ExplanationResult:
    tool: str
    status: str  # "ALLOWED" | "DENIED"
    reason: str
    details: dict | None = None
    quick_fix: str | None = None


class CrewAIGuard:
    
    def explain(self, tool_name: str, args: dict) -> ExplanationResult:
        """Explain why a tool call would be allowed or denied."""
        
        # Check tool allowlist
        if tool_name not in self._allowed:
            return ExplanationResult(
                tool=tool_name,
                status="DENIED",
                reason=f"Tool '{tool_name}' not in allowed list",
                details={"allowed_tools": list(self._allowed.keys())},
                quick_fix=f".allow('{tool_name}', ...)",
            )
        
        constraints = self._allowed[tool_name]
        
        # Check for unlisted arguments
        for arg_name in args:
            if arg_name not in constraints:
                return ExplanationResult(
                    tool=tool_name,
                    status="DENIED",
                    reason=f"Argument '{arg_name}' not in constraints",
                    details={
                        "argument": arg_name,
                        "allowed_args": list(constraints.keys()),
                    },
                    quick_fix=f".allow('{tool_name}', {arg_name}=Wildcard())",
                )
        
        # Check each constraint
        for arg_name, arg_value in args.items():
            constraint = constraints[arg_name]
            if not constraint.satisfies(arg_value):
                return ExplanationResult(
                    tool=tool_name,
                    status="DENIED",
                    reason=f"Constraint violation on '{arg_name}'",
                    details={
                        "argument": arg_name,
                        "value": arg_value,
                        "constraint": str(constraint),
                        "expected": constraint.description(),
                    },
                    quick_fix=None,  # Can't auto-fix constraint violations
                )
        
        # All checks passed
        return ExplanationResult(
            tool=tool_name,
            status="ALLOWED",
            reason="All constraints satisfied",
        )
    
    def allows(self, tool_name: str, args: dict) -> bool:
        """Convenience method for CI tests."""
        return self.explain(tool_name, args).status == "ALLOWED"
```
```

---

## Security Model

### Tier Selection

```
Which tier should I use?
│
├─ Is the tool caller in the same process as the guard?
│   └─ Yes: Tier 1 (CrewAI agents in single process)
│   └─ No:  Tier 2 (distributed crews, crew-to-crew)
│
├─ Is the crew delegating to sub-crews or external agents?
│   └─ Yes: Tier 2 with delegation chain
│   └─ No:  Tier 1 for simplicity
│
└─ Do I need audit trail with cryptographic proof?
    └─ Yes: Tier 2 always
    └─ No:  Tier 1 for simplicity
```

### CrewAI-Specific Threats

| Threat | Mitigation |
|--------|------------|
| Prompt injection expands tool access | Constraints on every parameter |
| Manager delegates too broadly | Attenuation-only delegation |
| Agent calls tools it shouldn't have | Tool allowlisting per agent |
| Hallucinated tool arguments | Closed-world argument checking |
| Cross-crew privilege escalation | Warrant chain validation |

---

## Core Implementation

### Tool Protection

```python
# tenuo/crewai.py

from crewai import Tool
from tenuo import Constraint, ConstraintViolation, ToolDenied

class GuardBuilder:
    """Builder for CrewAI tool authorization."""
    
    def __init__(self):
        self._allowed: dict[str, dict[str, Constraint]] = {}
        self._warrant: Warrant | None = None
        self._signing_key: SigningKey | None = None
        self._on_denial: str = "raise"
    
    def allow(self, tool_name: str, **constraints: Constraint) -> "GuardBuilder":
        """Allow a tool with parameter constraints."""
        self._allowed[tool_name] = constraints
        return self
    
    def with_warrant(self, warrant: Warrant, signing_key: SigningKey) -> "GuardBuilder":
        """Enable Tier 2 with warrant and signing key."""
        if not signing_key:
            raise MissingSigningKey(
                "Tier 2 requires signing_key for Proof-of-Possession. "
                "See: https://docs.tenuo.ai/tier2"
            )
        self._warrant = warrant
        self._signing_key = signing_key
        return self
    
    def on_denial(self, mode: str) -> "GuardBuilder":
        """Set denial mode: 'raise' | 'log' | 'skip'"""
        if mode not in ("raise", "log", "skip"):
            raise ConfigurationError(f"Invalid on_denial mode: {mode}")
        self._on_denial = mode
        return self
    
    def build(self) -> "CrewAIGuard":
        return CrewAIGuard(
            allowed=self._allowed,
            warrant=self._warrant,
            signing_key=self._signing_key,
            on_denial=self._on_denial,
        )


class CrewAIGuard:
    """Runtime guard for CrewAI tools."""
    
    def __init__(self, allowed, warrant, signing_key, on_denial):
        self._allowed = allowed
        self._warrant = warrant
        self._signing_key = signing_key
        self._on_denial = on_denial
    
    def protect(self, tool: Tool) -> Tool:
        """Wrap a CrewAI tool with authorization checks."""
        original_func = tool.func
        
        def guarded_func(**kwargs):
            self._authorize(tool.name, kwargs)
            return original_func(**kwargs)
        
        return Tool(
            name=tool.name,
            description=tool.description,
            func=guarded_func,
        )
    
    def protect_all(self, tools: list[Tool]) -> list[Tool]:
        """Wrap multiple tools."""
        return [self.protect(t) for t in tools]
    
    def _authorize(self, tool_name: str, args: dict):
        """Check authorization for a tool call."""
        
        # Step 1: Check tool is allowed
        if tool_name not in self._allowed:
            self._handle_denial(ToolDenied(
                tool=tool_name,
                reason=f"Tool '{tool_name}' not in allowed list",
                quick_fix=f".allow('{tool_name}', ...)",
            ))
            return
        
        constraints = self._allowed[tool_name]
        
        # Step 2: Check all arguments have constraints (closed-world)
        for arg_name in args:
            if arg_name not in constraints:
                self._handle_denial(ConstraintViolation(
                    tool=tool_name,
                    argument=arg_name,
                    reason=f"Argument '{arg_name}' not in constraints",
                    quick_fix=f".allow('{tool_name}', {arg_name}=Wildcard())",
                ))
                return
        
        # Step 3: Check each argument satisfies its constraint
        for arg_name, arg_value in args.items():
            constraint = constraints[arg_name]
            if not constraint.satisfies(arg_value):
                self._handle_denial(ConstraintViolation(
                    tool=tool_name,
                    argument=arg_name,
                    value=arg_value,
                    constraint=constraint,
                    reason=f"Value '{arg_value}' violates {constraint}",
                ))
                return
        
        # Step 4: Tier 2 - Warrant authorization with PoP
        if self._warrant:
            pop = self._warrant.sign(self._signing_key, tool_name, args)
            self._warrant.authorize(tool_name, args, signature=pop)
    
    def _handle_denial(self, error: TenuoError):
        """Handle authorization denial based on mode."""
        # Always emit audit event, regardless of mode
        self._emit_audit_event(error)
        
        if self._on_denial == "raise":
            raise error
        elif self._on_denial == "log":
            logger.warning(f"Authorization denied: {error}", extra={
                "error_code": error.error_code,
                "tool": error.tool,
            })
            return DenialResult(tool=error.tool, reason=str(error))
        elif self._on_denial == "skip":
            # Return sentinel, not None — allows CrewAI to react deterministically
            logger.info(f"Authorization skipped: {error.tool}", extra={
                "error_code": "DENIAL_SKIPPED",
                "tool": error.tool,
            })
            return DenialResult(tool=error.tool, reason=str(error))
    
    def _emit_audit_event(self, error: TenuoError):
        """Emit structured audit event for all denials."""
        # Hook for Tenuo Cloud or custom audit systems
        if self._audit_callback:
            self._audit_callback({
                "event": "authorization.denied",
                "error_code": error.error_code,
                "tool": getattr(error, "tool", None),
                "argument": getattr(error, "argument", None),
                "timestamp": datetime.utcnow().isoformat(),
            })


@dataclass
class DenialResult:
    """Sentinel returned when on_denial is 'log' or 'skip'.
    
    Allows CrewAI agents to detect and react to denials deterministically,
    rather than receiving ambiguous None values.
    """
    tool: str
    reason: str
    
    def __bool__(self):
        return False  # Falsy, so `if result:` checks work naturally
```

### Zero-Config Entry Points

```python
def protect_tool(tool: Tool, **constraints: Constraint) -> Tool:
    """One-liner tool protection."""
    guard = GuardBuilder().allow(tool.name, **constraints).build()
    return guard.protect(tool)


def protect_agent(agent: Agent, **tool_constraints: dict) -> Agent:
    """Protect all tools on an agent."""
    builder = GuardBuilder()
    for tool_name, constraints in tool_constraints.items():
        builder.allow(tool_name, **constraints)
    guard = builder.build()
    
    agent.tools = guard.protect_all(agent.tools)
    return agent
```

---

## Delegation Support

### Warrant Attenuation for Hierarchical Crews

```python
class WarrantDelegator:
    """Handles warrant delegation in hierarchical processes."""
    
    def delegate(
        self,
        parent_warrant: Warrant,
        parent_key: SigningKey,
        child_holder: PublicKey,
        attenuations: dict[str, Constraint],
    ) -> Warrant:
        """
        Create attenuated child warrant.
        
        Child warrant can ONLY narrow scope, never expand.
        """
        builder = parent_warrant.grant_builder()
        
        for tool_name, constraints in attenuations.items():
            # Verify attenuation is valid (narrowing only)
            if not parent_warrant.allows(tool_name):
                raise EscalationAttempt(
                    f"Cannot grant '{tool_name}': parent doesn't have it"
                )
            
            for arg_name, constraint in constraints.items():
                parent_constraint = parent_warrant.constraint_for(tool_name, arg_name)
                if not constraint.is_subset_of(parent_constraint):
                    raise EscalationAttempt(
                        f"Cannot widen constraint on {tool_name}.{arg_name}"
                    )
            
            builder.capability(tool_name, **constraints)
        
        return builder.holder(child_holder).grant(parent_key)
```

### Usage in Hierarchical Process

```python
from crewai import Process

class WarrantHierarchicalCrew:
    """Crew where manager delegates attenuated warrants to workers."""
    
    def __init__(self, manager_warrant, manager_key, agents, tasks):
        self.manager_warrant = manager_warrant
        self.manager_key = manager_key
        self.delegator = WarrantDelegator()
        self.agents = agents
        self.tasks = tasks
    
    def kickoff(self, inputs):
        for agent, task in zip(self.agents, self.tasks):
            # Manager creates attenuated warrant for this task
            child_warrant = self.delegator.delegate(
                parent_warrant=self.manager_warrant,
                parent_key=self.manager_key,
                child_holder=agent.public_key,
                attenuations=self._attenuations_for_task(task),
            )
            
            # Agent receives narrowed authority
            agent.warrant = child_warrant
            agent.signing_key = agent.private_key
        
        return self._execute()
    
    def _attenuations_for_task(self, task) -> dict:
        """Map task to required tool constraints."""
        # This could come from task metadata or policy
        return TASK_PERMISSIONS.get(task.name, {})
```

---

## Error Types

```python
class ToolDenied(TenuoError):
    """Tool not in allowed list."""
    error_code = "TOOL_DENIED"
    
    def __init__(self, tool: str, reason: str, quick_fix: str):
        self.tool = tool
        self.reason = reason
        self.quick_fix = quick_fix
        super().__init__(
            f"Tool '{tool}' denied: {reason}\n"
            f"Quick fix: {quick_fix}"
        )


class ConstraintViolation(TenuoError):
    """Argument violates constraint."""
    error_code = "CONSTRAINT_VIOLATION"
    
    def __init__(self, tool: str, argument: str, value: Any, 
                 constraint: Constraint, reason: str):
        self.tool = tool
        self.argument = argument
        self.value = value
        self.constraint = constraint
        super().__init__(
            f"Constraint violation on {tool}.{argument}: {reason}\n"
            f"Value: {value!r}\n"
            f"Constraint: {constraint}\n"
            f"See: https://docs.tenuo.ai/constraints"
        )


class EscalationAttempt(TenuoError):
    """Attempted to widen authority during delegation."""
    error_code = "ESCALATION_ATTEMPT"


class MissingSigningKey(TenuoError):
    """Warrant provided without signing key."""
    error_code = "MISSING_SIGNING_KEY"
```

---

## Test Scenarios

### Critical Tests

```python
# 1. Tool allowlisting
def test_disallowed_tool_rejected():
    guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
    tool = Tool(name="delete_file", func=lambda: None)
    
    with pytest.raises(ToolDenied):
        guard.protect(tool)._func(path="/data/file.txt")


# 2. Closed-world arguments
def test_unlisted_argument_rejected():
    guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
    
    with pytest.raises(ConstraintViolation) as exc:
        guard._authorize("read_file", {"path": "/data/f.txt", "mode": "r"})
    
    assert "mode" in str(exc.value)


# 3. Constraint enforcement
def test_constraint_violation_rejected():
    guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
    
    with pytest.raises(ConstraintViolation):
        guard._authorize("read_file", {"path": "/etc/passwd"})


# 4. Path traversal blocked
def test_path_traversal_blocked():
    guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
    
    with pytest.raises(ConstraintViolation):
        guard._authorize("read_file", {"path": "/data/../etc/passwd"})


# 5. Tier 2 requires signing key
def test_warrant_requires_signing_key():
    warrant = Warrant.mint_builder().capability("read").mint(root_key)
    
    with pytest.raises(MissingSigningKey):
        GuardBuilder().with_warrant(warrant, None).build()


# 6. Delegation cannot escalate
def test_delegation_cannot_escalate():
    parent = Warrant.mint_builder().capability("read", path=Subpath("/data")).mint(key)
    
    with pytest.raises(EscalationAttempt):
        WarrantDelegator().delegate(
            parent_warrant=parent,
            parent_key=key,
            child_holder=child_key.public_key,
            attenuations={"read": {"path": Subpath("/")}},  # Wider than /data
        )
```

### Invariant Tests

```python
# All 6 invariants from integration guide
def test_invariant_fail_closed():
    """No tools specified = nothing works."""
    guard = GuardBuilder().build()
    with pytest.raises(ToolDenied):
        guard._authorize("any_tool", {})


def test_invariant_closed_world_args():
    """Unlisted arguments are rejected."""
    guard = GuardBuilder().allow("tool", arg1=Wildcard()).build()
    with pytest.raises(ConstraintViolation):
        guard._authorize("tool", {"arg1": "x", "arg2": "y"})


def test_invariant_constraint_blocks():
    """Constraint violations block execution."""
    guard = GuardBuilder().allow("tool", x=Range(1, 10)).build()
    with pytest.raises(ConstraintViolation):
        guard._authorize("tool", {"x": 100})


def test_invariant_wildcard_required():
    """Wildcard must be explicit."""
    guard = GuardBuilder().allow("tool", x=Wildcard()).build()
    guard._authorize("tool", {"x": "anything"})  # OK


def test_invariant_tier2_needs_key():
    """Tier 2 requires signing key."""
    with pytest.raises(MissingSigningKey):
        GuardBuilder().with_warrant(warrant, None).build()


def test_invariant_attenuation_only():
    """Delegation can only narrow."""
    # Tested in test_delegation_cannot_escalate
```

---

## Integration Checklist

### API Design

- [ ] Builder pattern with fluent API (`GuardBuilder`)
- [ ] Zero-config entry points (`protect_tool`, `protect_agent`)
- [ ] Supports both Tier 1 and Tier 2
- [ ] `on_denial` modes: raise, log, skip
- [ ] `.validate()` method for pre-flight checks
- [ ] Uses `constraint.satisfies()` for checking
- [ ] `explain()` method for policy introspection
- [ ] `allows()` convenience method for CI tests

### Security

- [ ] Fail-closed (deny by default)
- [ ] Closed-world arguments (unlisted params rejected)
- [ ] `Wildcard()` required for explicit any-value
- [ ] Constraint violations block execution
- [ ] Tier 2 requires both warrant AND signing_key
- [ ] Verifies signing_key matches warrant holder
- [ ] Checks warrant expiry before tool calls
- [ ] Generates PoP signature per tool call (Tier 2)
- [ ] Delegation can only attenuate, never escalate
- [ ] Tool namespacing prevents cross-agent confusion

### CrewAI-Specific

- [ ] `protect()` works with CrewAI `Tool`
- [ ] `protect_agent()` works with CrewAI `Agent`
- [ ] Hierarchical process delegation support
- [ ] Flow step decorator (`@guarded_step`)
- [ ] `strict` mode for guarded steps
- [ ] Works with sequential and hierarchical processes
- [ ] Tool identity namespacing (`agent_role::tool_name`)
- [ ] Warrant lifecycle documented and enforced

### Developer Experience

- [ ] Rich error messages with quick fixes
- [ ] `explain()` for debugging and compliance
- [ ] `ExplanationResult` with actionable details
- [ ] Validation at build time (fail fast)
- [ ] Clear docs links in errors

### Observability

- [ ] Audit log hook for authorization decisions
- [ ] Structured logging (tool, args, reason, constraint)
- [ ] CrewAI metadata (crew_id, task_id, agent_role)
- [ ] `DenialResult` sentinel for skip/log modes (not silent `None`)
- [ ] Audit events emitted even for skipped denials

### Tests

- [ ] All critical test scenarios
- [ ] All 6 invariant tests
- [ ] Constraint types: Subpath, UrlSafe, Pattern, Range, Wildcard
- [ ] Delegation attenuation validation
- [ ] Tool namespacing resolution
- [ ] Warrant expiry mid-step
- [ ] `explain()` output correctness
- [ ] `strict` mode catches unguarded downstream calls
- [ ] Async support (if CrewAI adds it)

---

## Implementation Phases

### Phase 1: Tool Protection (MVP) ✅

**Scope:**
- `GuardBuilder` with `.allow()` and `.build()`
- `protect_tool()` zero-config
- Tier 1 constraint checking
- Error types with quick fixes
- Tool namespacing (`agent_role::tool_name`)
- `DenialResult` sentinel for skip/log modes

**Status:** Implemented

**Test:** Single tool protection works with constraints, namespacing resolves correctly

### Phase 2: Agent Protection + Explain API ✅

**Scope:**
- `protect_agent()` 
- `protect_all()` for multiple tools
- Agent-level policy application
- `explain()` and `allows()` methods
- `ExplanationResult` dataclass

**Status:** Implemented

**Test:** Agent with multiple protected tools, CI policy tests pass

### Phase 3: Tier 2 Support ✅

**Scope:**
- `.with_warrant()` builder method
- PoP signature generation
- Warrant expiry checking
- Warrant lifecycle documentation

**Status:** Implemented

**Test:** Warrant-protected tool calls with PoP, expiry enforced mid-step

### Phase 4: Delegation ✅

**Scope:**
- `WarrantDelegator` for hierarchical crews
- Attenuation validation
- Chain preservation

**Status:** Implemented

**Test:** Manager → Worker delegation with narrowing

### Phase 5: Crew/Flow Integration ✅

**Scope:**
- `GuardedCrew` wrapper
- `@guarded_step` decorator with `strict` mode
- Policy-based warrant issuance
- Audit event emission
- Strict mode context vars (`_guarded_zone`, `get_active_guard`, `is_strict_mode`)
- `UnguardedToolError` for strict mode violations
- TTL parsing for guarded steps

**Status:** Implemented

**Test:** Full crew with per-agent warrants, strict mode catches unguarded downstream calls

---

## Open Questions (Resolved)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Warrant storage | Separate from CrewAI memory | Security primitives ≠ conversation context |
| Failure mode | Fail-closed, `on_denial` configurable | Matches integration guide philosophy |
| Policy format | Python first | Familiar to CrewAI users, avoid IAM complexity |
| Cloud integration | SDK-only for now | Build for open source, partnership later |
| Backward compat | Incremental adoption levels | `protect_tool` → `protect_agent` → `GuardedCrew` |
| Tool identity | `agent_role::tool_name` namespacing | Prevents cross-agent confusion in larger crews |
| Skip mode | Return `DenialResult` sentinel, always audit | Silent skip is a footgun |
| Guarded step downstream | Document now, `strict` mode later | Prevent secure-outer-insecure-inner patterns |
| Warrant lifecycle | Ephemeral, step-scoped, no auto-renewal | Prevents subtle bugs from stale warrants |
| Policy explanation | `explain()` API in Phase 2 | Critical for debugging, CI, compliance |

---

## Implementation Status

All phases (1-5) are **complete**:

- ✅ Phase 1: Tool Protection (MVP)
- ✅ Phase 2: Agent Protection + Explain API
- ✅ Phase 3: Tier 2 Support
- ✅ Phase 4: Delegation
- ✅ Phase 5: Crew/Flow Integration

**Deliverables:**
- `tenuo/crewai.py` - Full implementation
- `tests/test_crewai.py` - Unit tests
- `tests/test_crewai_adversarial.py` - Security tests
- `docs/crewai.md` - User documentation
- `examples/crewai/` - Working examples

## Next Steps

1. Reach out to CrewAI team with working demo
2. Gather user feedback on API ergonomics
3. Consider async support if CrewAI adds it
