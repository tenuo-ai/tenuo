# Tenuo Google ADK Integration

**Status:** Draft v2  
**Target:** `tenuo.google_adk`

---

## 1. Problem

Google ADK agents execute tool calls based on LLM output. The `before_tool_callback` can intercept calls, but there's no built-in concept of:

- Cryptographic authorization (who granted this agent these capabilities?)
- Constraint-based validation (is this argument within allowed bounds?)
- Delegation chains (did the parent agent have authority to delegate?)
- Audit trail with warrant context
- Audit trail with warrant context

Current ADK guardrails are ad-hoc:

```python
# Today: Manual checks in callbacks
def my_guardrail(tool: BaseTool, args: dict, tool_context: ToolContext) -> Optional[dict]:
    if args.get("path", "").startswith("/etc"):
        return {"error": "Path not allowed"}  # No proof of policy
    return None  # Allow

agent = Agent(
    name="assistant",
    tools=[read_file, shell],
    before_tool_callback=my_guardrail,
)
```

Problems:
- No cryptographic proof of authorization
- Guardrails are per-agent, not composable
- No delegation/attenuation model
- Audit trail lacks authorization context
- Callbacks can only intercept, not wrap execution (no Layer 2)

---

## 2. Solution

Tenuo integrates via two authorization tiers:

### Tier 1 (Guardrails): Runtime constraint checking
```python
from google.adk.agents import Agent
from tenuo.google_adk import TenuoGuard

# Tier 1: Logic-only checks (suitable for single-process)
guard = TenuoGuard(
    warrant=my_warrant,
    require_pop=False,  # Disable PoP for Tier 1
    skill_map={"read_file": "file_read"},
)

agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, search, shell]),
    before_tool_callback=guard.before_tool,
)
```

### Tier 2 (PoP): Cryptographic Proof-of-Possession (Recommended)
```python
from google.adk.agents import Agent
from tenuo.google_adk import TenuoGuard
from tenuo import SigningKey

# Tier 2: Full cryptographic authorization
guard = TenuoGuard(
    warrant=my_warrant,
    signing_key=agent_key,  # Required for PoP
    skill_map={"read_file": "file_read"},
)

agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, search, shell]),
    before_tool_callback=guard.before_tool,
)
```

**Why Tier 2 (PoP)?**
- Proves the caller holds the private key (not just the warrant)
- Prevents token theft attacks
- Required for distributed/multi-agent scenarios

---

## 3. Design Principles

1. **Use ADK's native patterns.** Callbacks for interception using `before_tool_callback`.

2. **Filter unauthorized tools.** Don't waste tokens showing tools the LLM can't use.

3. **Warrant lives in session state or guard instance.** ADK's `ToolContext` provides state access.

4. **Fail closed.** Unknown tools rejected. Constraint check failures rejected.

5. **Transparent to LLM.** Tool descriptions unchanged. Authorization invisible to model.

6. **Prevent state leaks.** Validate/clear warrants at turn boundaries in multi-tenant scenarios.



---

## 4. API Design

### 4.1 TenuoGuard - Core Class

```python
from tenuo.google_adk import TenuoGuard
from tenuo import Warrant
from tenuo.constraints import Subpath, UrlSafe

guard = TenuoGuard(
    warrant=my_warrant,
    skill_map={
        "read_file": "file_read",        # ADK tool name → warrant skill name
        "duckduckgo_search": "web_search",
    },
    arg_map={
        "file_read": {"file_path": "path"},  # Tool arg → constraint key
    },
    on_deny="return",   # "return" (return error dict) or "raise"
    audit_log=sys.stderr,
)
```

### 4.2 filter_tools() - Token Efficiency

Don't show tools the LLM can't use:

```python
all_tools = [read_file, search, shell, sql_query]

# Filter to only granted tools
available_tools = guard.filter_tools(all_tools)
# Returns: [read_file, search] if shell and sql_query not granted

agent = Agent(
    tools=available_tools,  # LLM only sees authorized tools
    before_tool_callback=guard.before_tool,
)
```

**Why filter?**

Tool descriptions are verbose. Each tool adds 100-500 tokens to the system prompt:

```
# Typical tool description in ADK
def read_file(file_path: str) -> str:
    """Read contents of a file from disk.
    
    Args:
        file_path: Absolute or relative path to the file to read.
                   Must be a valid filesystem path.
    
    Returns:
        The complete contents of the file as a string.
        
    Raises:
        FileNotFoundError: If file doesn't exist.
        PermissionError: If file isn't readable.
    """
```

**Token savings in practice:**

| Tools Available | Tools Granted | Tokens Saved |
|-----------------|---------------|--------------|
| 10 tools | 3 granted | ~1,500-3,000 tokens |
| 20 tools | 5 granted | ~3,000-7,500 tokens |

For tool-heavy agents, filtering reduces prompt size by 20-50% and prevents hallucinated plans the agent can't execute.

**⚠️ Limitation: Static vs Dynamic Warrants**

`filter_tools()` only works with static warrants (set at guard creation):

```python
# ✓ Works: Static warrant
guard = TenuoGuard(warrant=my_warrant)
available_tools = guard.filter_tools(all_tools)

# ✗ Broken: Dynamic warrant from session state
guard = TenuoGuard(warrant_key="tenuo_warrant")
available_tools = guard.filter_tools(all_tools)  # No warrant yet!
```

For dynamic warrants (per-request, multi-tenant), you have two options:

```python
# Option A: Pass warrant explicitly
available_tools = guard.filter_tools(all_tools, warrant=request_warrant)

# Option B: Don't filter, rely on before_tool to reject
# All tools shown to LLM, but unauthorized calls blocked
agent = Agent(
    tools=all_tools,  # No filtering
    before_tool_callback=guard.before_tool,  # Rejects unauthorized
)
```

**Tradeoff:** Option B costs more tokens but supports dynamic authorization. For multi-tenant web servers where different users have different warrants, Option B is typically required.



### 4.4 Using Session State for Per-Request Warrants

For multi-tenant scenarios, warrant can come from session state:

```python
guard = TenuoGuard(
    warrant_key="tenuo_warrant",  # Read from tool_context.state["tenuo_warrant"]
)

# At request time, inject warrant into session
session.state["tenuo_warrant"] = user_specific_warrant
```

### 4.5 Plugin-Based Integration

ADK also supports Plugins for cross-cutting concerns. TenuoGuard can be used as a Plugin:

```python
from google.adk.plugins import BasePlugin
from tenuo.google_adk import TenuoPlugin

plugin = TenuoPlugin(
    warrant=my_warrant,
    skill_map={...},
)

runner = InMemoryRunner(
    agent=my_agent,
    plugins=[plugin],  # Applies to all agents in hierarchy
)
```

---

## 5. Implementation

### 5.1 TenuoGuard Class

```python
from typing import Optional, Dict, Any, List, Callable, Union
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.base_tool import BaseTool
from contextlib import ExitStack


class TenuoGuard:
    """
    Tenuo integration for Google ADK.

    Supports two authorization tiers:
        - Tier 1 (Guardrails): Logic-only checks without cryptography
        - Tier 2 (PoP): Full cryptographic Proof-of-Possession verification
    
    Security: By default, requires signing_key for PoP. Set require_pop=False
    to use Tier 1 guardrails only (suitable for single-process scenarios).
    """

    def __init__(
        self,
        warrant: Optional["Warrant"] = None,
        signing_key: Optional["SigningKey"] = None,  # Required for Tier 2 PoP
        warrant_key: Optional[str] = None,
        skill_map: Optional[Dict[str, str]] = None,
        arg_map: Optional[Dict[str, Dict[str, str]]] = None,
        denial_detail: str = "full",  # DenialDetail.FULL
        denial_template: Optional[str] = None,
        expiry_policy: str = "before",  # ExpiryPolicy.CHECK_BEFORE
        audit_log: Union[None, str, Any] = None,
        on_deny: str = "return",  # "return" or "raise"
        require_pop: bool = True,  # Default to secure mode
    ):
        self._warrant = warrant
        self._signing_key = signing_key
        self._warrant_key = warrant_key
        self._skill_map = skill_map or {}
        self._arg_map = arg_map or {}
        self._denial_detail = denial_detail
        self._denial_template = denial_template
        self._expiry_policy = expiry_policy
        self._on_deny = on_deny
        self._require_pop = require_pop
        
        # Handle audit log: string path or file-like object
        self._exit_stack = ExitStack()
        self._owns_audit_log = False
        if isinstance(audit_log, str):
            self._audit_log = self._exit_stack.enter_context(open(audit_log, "a"))
            self._owns_audit_log = True
        else:
            self._audit_log = audit_log


    # -------------------------------------------------------------------------
    # Tool Filtering
    # -------------------------------------------------------------------------

    def filter_tools(
        self,
        tools: List[Callable],
        warrant: Optional["Warrant"] = None,
    ) -> List[Callable]:
        """
        Filter tools to only those granted in the warrant.
        
        Args:
            tools: List of tool functions to filter
            warrant: Optional warrant to use (defaults to self._warrant)
                     Pass explicitly for dynamic/per-request warrants.
        
        Returns:
            List of tools that are granted in the warrant
        
        Note:
            For dynamic warrants (warrant_key), you must pass warrant explicitly
            since the request-time warrant isn't available at agent creation.
        """
        effective_warrant = warrant or self._warrant
        if effective_warrant is None:
            return []  # No warrant = no tools
        
        granted = self._get_granted_skills(effective_warrant)
        
        result = []
        for tool in tools:
            tool_name = getattr(tool, "__name__", str(tool))
            skill_name = self._skill_map.get(tool_name, tool_name)
            if skill_name in granted:
                result.append(tool)
        
        return result

    def _get_granted_skills(self, warrant: Any) -> set:
        """Extract set of granted skill names from warrant."""
        skills = set()
        
        grants = getattr(warrant, "grants", [])
        for grant in grants:
            if isinstance(grant, dict):
                skill = grant.get("skill")
                if skill:
                    skills.add(skill)
            elif isinstance(grant, str):
                skills.add(grant)
        
        # Fallback to tools attribute
        tools = getattr(warrant, "tools", [])
        skills.update(tools)
        
        return skills

    # -------------------------------------------------------------------------
    # Callbacks (Layer 1.5 + Layer 2)
    # -------------------------------------------------------------------------

    def before_tool(
        self,
        tool: BaseTool,
        args: Dict[str, Any],
        tool_context: ToolContext,
    ) -> Optional[Dict[str, Any]]:
        """
        ADK before_tool_callback implementation.
        
        Returns:
            None: Allow tool execution
            Dict: Skip tool, use this as result (denial message)
        """
        # Get warrant
        warrant = self._get_warrant(tool_context)
        if warrant is None:
            return self._deny("No warrant available", tool.name, args)
        
        # Check expiry
        if self._check_expiry(warrant):
            return self._deny("Warrant expired", tool.name, args)
        
        # Map tool name to skill
        skill_name = self._skill_map.get(tool.name, tool.name)
        
        # Remap arguments based on arg_map
        validation_args = self._remap_args(skill_name, args)

        # =======================================================================
        # Tier 2: Warrant + PoP Authorization (Cryptographic)
        # =======================================================================
        if self._require_pop:
            if self._signing_key is None:
                raise MissingSigningKeyError()

            # Generate Proof-of-Possession signature
            pop_signature = warrant.sign(self._signing_key, skill_name, validation_args)

            # Authorize with PoP - this is the REAL authorization check
            authorized = warrant.authorize(
                skill_name, validation_args, signature=bytes(pop_signature)
            )

            if not authorized:
                reason = self._get_denial_reason(warrant, skill_name, validation_args)
                return self._deny(f"Authorization failed: {reason}", tool.name, args)

            self._audit("tool_allowed", tool.name, args, warrant)
            return None

        # =======================================================================
        # Tier 1: Guardrails-Only Authorization (Logic Checks)
        # =======================================================================
        # Check skill granted
        if not self._skill_granted(warrant, skill_name):
            return self._deny(f"Tool '{tool.name}' not authorized", tool.name, args)
        
        # Get constraints for this skill
        constraints = self._get_skill_constraints(warrant, skill_name)
        
        # ZERO TRUST: Check ALL arguments against constraints
        if constraints:
            has_wildcard = any(type(c).__name__ == "Wildcard" for c in constraints.values())
            allows_unknown = constraints.get("_allow_unknown", False)

            for arg_name, value in validation_args.items():
                if arg_name.startswith("_"):
                    continue

                if arg_name in constraints:
                    constraint = constraints[arg_name]
                    if not self._check_constraint(constraint, value):
                        return self._deny(
                            f"Argument '{arg_name}' violates constraint",
                            tool.name,
                        args,
                    )
        
        # All checks passed
        self._audit("tool_allowed", tool.name, args, warrant)
        return None  # Proceed with tool execution

    def after_tool(
        self,
        tool: BaseTool,
        args: Dict[str, Any],
        tool_context: ToolContext,
        result: Any,
    ) -> Optional[Any]:
        """
        ADK after_tool_callback for audit logging.
        
        Returns:
            None: Use original result
            Any: Replace result
        """
        warrant = self._get_warrant(tool_context)
        self._audit("tool_completed", tool.name, args, warrant, result=result)
        return None

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _get_warrant(self, tool_context: Optional[ToolContext]) -> Optional["Warrant"]:
        """Get warrant from instance or session state."""
        if self._warrant is not None:
            return self._warrant
        if self._warrant_key and tool_context and hasattr(tool_context, "state"):
            return tool_context.state.get(self._warrant_key)
        return None

    def _skill_granted(self, warrant: Any, skill_name: str) -> bool:
        """Check if skill is granted in warrant."""
        return skill_name in self._get_granted_skills(warrant)

    def _get_constraints(self, warrant: Any, skill_name: str) -> Dict[str, Any]:
        """Get constraints for a skill from warrant."""
        grants = getattr(warrant, "grants", [])
        for grant in grants:
            if isinstance(grant, dict) and grant.get("skill") == skill_name:
                return grant.get("constraints", {})
        return {}

    def _check_constraint(self, constraint: Any, value: Any) -> bool:
        """Check if value satisfies constraint. Fail closed on unknown types."""
        if hasattr(constraint, "contains"):  # Subpath
            return constraint.contains(str(value))
        if hasattr(constraint, "is_safe"):  # UrlSafe
            return constraint.is_safe(str(value))
        if hasattr(constraint, "matches"):  # Shlex, Pattern
            return constraint.matches(str(value))
        # Unknown constraint - fail closed
        return False

    def _deny(
        self,
        reason: str,
        tool_name: str,
        args: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Handle denial based on on_deny setting."""
        self._audit("tool_denied", tool_name, args, reason=reason)
        
        if self._on_deny == "raise":
            raise ToolAuthorizationError(reason)
        
        return {
            "error": "authorization_denied",
            "message": reason,
        }

    def _audit(
        self,
        event: str,
        tool_name: str,
        args: Dict[str, Any],
        warrant: Optional[Any] = None,
        **extra,
    ) -> None:
        """Write audit event."""
        if self._audit_log is None:
            return
        
        import json
        from datetime import datetime, timezone
        
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "event": event,
            "tool": tool_name,
            "args": {k: str(v)[:100] for k, v in args.items()},
            **extra,
        }
        
        if warrant:
            record["warrant"] = {
                "jti": getattr(warrant, "jti", None) or getattr(warrant, "id", None),
                "iss": getattr(warrant, "iss", None) or getattr(warrant, "issuer", None),
            }
        
        if hasattr(self._audit_log, "write"):
            self._audit_log.write(json.dumps(record) + "\n")
            self._audit_log.flush()
    
    def close(self):
        """Clean up resources (e.g., audit log file handle)."""
        if self._owns_audit_log and hasattr(self._audit_log, "close"):
            self._audit_log.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


class ToolAuthorizationError(Exception):
    """Raised when tool authorization fails and on_deny='raise'."""
    pass


class DenialDetail:
    """Denial message detail levels."""
    FULL = "full"        # Full details to LLM (development)
    MINIMAL = "minimal"  # Generic message to LLM (production)
    SILENT = "silent"    # No message to LLM
    RAISE = "raise"      # Raise exception


class ExpiryPolicy:
    """Warrant expiry handling during tool execution."""
    CHECK_BEFORE = "before"     # Check once at start
    CHECK_TIMEOUT = "timeout"   # Set tool timeout to warrant TTL
    CHECK_PERIODIC = "periodic" # Check every N seconds (async only)
```

### 5.2 Shared Helpers

These helpers are shared between ADK integration and A2A adapter:

```python
# tenuo/common/warrant_helpers.py

def get_granted_skills(warrant) -> set:
    """
    Extract granted skills from warrant.
    
    Used by:
    - A2A server (server.py)
    - ADK guard (TenuoGuard)
    
    Args:
        warrant: Warrant object with grants or tools attribute
    
    Returns:
        Set of skill names
    """
    skills = set()
    
    grants = getattr(warrant, "grants", [])
    for grant in grants:
        if isinstance(grant, dict):
            skill = grant.get("skill")
            if skill:
                skills.add(skill)
        elif isinstance(grant, str):
            skills.add(grant)
    
    # Fallback to tools attribute (legacy format)
    tools = getattr(warrant, "tools", [])
    skills.update(tools)
    
    return skills


def get_constraints_for_skill(warrant, skill_name: str) -> dict:
    """
    Get constraints dict for a specific skill.
    
    Args:
        warrant: Warrant object
        skill_name: Name of skill to get constraints for
    
    Returns:
        Dict of {constraint_key: constraint_object}
    """
    grants = getattr(warrant, "grants", [])
    for grant in grants:
        if isinstance(grant, dict) and grant.get("skill") == skill_name:
            return grant.get("constraints", {})
    return {}
```

### 5.3 Chaining with Other Callbacks

ADK allows only one callback per hook. To chain TenuoGuard with other callbacks:

```python
from tenuo.google_adk import chain_callbacks

def my_other_guardrail(tool, args, ctx):
    # Custom logic
    return None

agent = Agent(
    name="assistant",
    tools=[...],
    before_tool_callback=chain_callbacks(
        guard.before_tool,
        my_other_guardrail,
    ),
)
```

Implementation:

```python
def chain_callbacks(*callbacks):
    """Chain multiple before_tool_callbacks. First non-None return wins."""
    def chained(tool, args, tool_context):
        for cb in callbacks:
            result = cb(tool, args, tool_context)
            if result is not None:
                return result  # Short-circuit
        return None
    return chained
```

---

## 6. Plugin Implementation

For cross-agent enforcement, use ADK's Plugin system:

```python
from google.adk.plugins import BasePlugin
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.base_tool import BaseTool
from google.adk.agents.callback_context import CallbackContext
from typing import Optional, Dict, Any

class TenuoPlugin(BasePlugin):
    """
    ADK Plugin for warrant-based tool authorization.
    
    Applies to all agents managed by the Runner.
    Includes proactive state scoping to prevent leaks.
    """
    
    def __init__(
        self,
        warrant: Optional["Warrant"] = None,
        warrant_key: str = "tenuo_warrant",
        skill_map: Optional[Dict[str, str]] = None,
        arg_map: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        self._guard = TenuoGuard(
            warrant=warrant,
            warrant_key=warrant_key,
            skill_map=skill_map,
            arg_map=arg_map,
        )
        self._warrant_key = warrant_key
    
    def before_agent_callback(
        self,
        callback_context: CallbackContext,
    ) -> Optional[Any]:
        """
        Validate warrant scope at turn boundary.
        
        SECURITY: Proactive state scoping - warrant is bound to specific agent
        at injection time, not cleared reactively after potential leak.
        """
        state = callback_context.state
        scoped_warrant = state.get(self._warrant_key)
        
        if scoped_warrant is None:
            return None  # No warrant, let before_tool handle it
        
        # Check if warrant is scoped (ScopedWarrant wrapper)
        if hasattr(scoped_warrant, "valid_for_agent"):
            if not scoped_warrant.valid_for_agent(callback_context.agent_name):
                # Warrant was scoped to different agent - reject
                # This catches the leak BEFORE it can be exploited
                del state[self._warrant_key]
                return None  # Will fail in before_tool with "no warrant"
        
        # Check expiry
        warrant = getattr(scoped_warrant, "warrant", scoped_warrant)
        if getattr(warrant, "is_expired", False):
            del state[self._warrant_key]
        
        return None  # Continue with agent execution
    
    def before_tool_callback(
        self,
        tool: BaseTool,
        args: Dict[str, Any],
        tool_context: ToolContext,
    ) -> Optional[Dict[str, Any]]:
        """Plugin hook - called for all tool invocations."""
        return self._guard.before_tool(tool, args, tool_context)
    
    def after_tool_callback(
        self,
        tool: BaseTool,
        args: Dict[str, Any],
        tool_context: ToolContext,
        result: Any,
    ) -> Optional[Any]:
        """Plugin hook - called after all tool invocations."""
        return self._guard.after_tool(tool, args, tool_context, result)


class ScopedWarrant:
    """
    Wrapper that binds a warrant to a specific agent.
    
    Prevents warrant leaks in multi-agent systems by ensuring
    a warrant injected for agent A cannot be used by agent B.
    """
    
    def __init__(self, warrant: "Warrant", agent_name: str):
        self.warrant = warrant
        self.agent_name = agent_name
    
    def valid_for_agent(self, agent_name: str) -> bool:
        return self.agent_name == agent_name
    
    # Delegate warrant attributes
    def __getattr__(self, name):
        return getattr(self.warrant, name)
```

**Usage with scoped warrants:**

```python
from tenuo.google_adk import TenuoPlugin, ScopedWarrant

plugin = TenuoPlugin(warrant_key="tenuo_warrant")

# Inject warrant scoped to specific agent
def inject_warrant_for_agent(ctx, agent_name, warrant):
    ctx.state["tenuo_warrant"] = ScopedWarrant(warrant, agent_name)

# In multi-agent setup
def before_agent_callback(ctx):
    if ctx.agent_name == "researcher":
        inject_warrant_for_agent(ctx, "researcher", researcher_warrant)
    elif ctx.agent_name == "writer":
        inject_warrant_for_agent(ctx, "writer", writer_warrant)
    # If researcher's warrant leaks to writer's state, it will be rejected
    # because ScopedWarrant.valid_for_agent("writer") returns False
```

**Usage:**

```python
from google.adk.runners import InMemoryRunner
from tenuo.google_adk import TenuoPlugin

plugin = TenuoPlugin(warrant=org_warrant, skill_map={...})

runner = InMemoryRunner(
    agent=coordinator_agent,  # Has sub_agents
    plugins=[plugin],         # Applies to all agents
)

# All tool calls across all agents are now warrant-protected
# Warrants are scoped to prevent cross-agent leaks
```

### Security Warning: State Leaks

> **⚠️ Multi-Tenant Warning:** If using `warrant_key` with persistent sessions 
> (e.g., database-backed sessions in a web server), warrants from one user 
> could leak to another user's session if not properly managed.
>
> Mitigations:
> 1. Use `ScopedWarrant` to bind warrants to specific agents (proactive)
> 2. Use short-lived warrants (TTL < session timeout)
> 3. Clear warrant from state at the end of each request
> 4. Use per-request warrant injection rather than session storage

---

## 7. Error Handling

### 7.1 Denial Flow

When authorization fails, TenuoGuard returns an error dict that the LLM sees as the tool result:

```python
# Tool denied → LLM receives this as "tool output"
{
    "error": "authorization_denied",
    "message": "Tool 'shell' not authorized"
}

# LLM can then:
# 1. Explain to user why it can't help
# 2. Try a different approach with authorized tools
# 3. Ask user for elevated permissions
```

### 7.2 Denial Detail Levels

**⚠️ Security consideration:** Detailed denial messages can leak information to attackers via prompt injection.

```python
# Full details (development/debugging)
{"error": "authorization_denied", "message": "Tool 'shell' not authorized"}
# Risk: Attacker learns what's blocked, can probe for other tools

# Minimal details (production)
{"error": "denied", "message": "Request not permitted"}
# Safe: No information about what's blocked or why
```

**Configuration:**

```python
from tenuo.integrations.google_adk import TenuoGuard, DenialDetail

guard = TenuoGuard(
    warrant=warrant,
    denial_detail=DenialDetail.MINIMAL,  # Recommended for production
)
```

| Level | Message to LLM | Audit Log | Use Case |
|-------|----------------|-----------|----------|
| `FULL` | Tool name, reason, constraint details | Full details | Development |
| `MINIMAL` | "Request not permitted" | Full details | Production |
| `SILENT` | `None` (tool appears to fail) | Full details | Stealth |
| `RAISE` | Exception (no message to LLM) | Full details | Fail-fast |

### 7.3 Custom Denial Messages

For `FULL` detail level, configure message templates:

```python
guard = TenuoGuard(
    warrant=warrant,
    denial_detail=DenialDetail.FULL,
    denial_template=(
        "I cannot use {tool} because: {reason}. "
        "I can help you with: {granted_tools}."
    ),
)

# Produces:
# "I cannot use shell because: Tool not authorized. 
#  I can help you with: read_file, search."
```

Available template variables:
- `{tool}` - Tool name that was denied
- `{reason}` - Specific denial reason
- `{granted_tools}` - Comma-separated list of authorized tools
- `{constraint}` - Which constraint failed (for constraint violations)

### 7.4 Warrant Expiry During Execution

What happens if warrant expires mid-tool-execution?

```python
# Problem: Warrant has 60s TTL, tool takes 5 minutes
# Tool starts authorized, finishes unauthorized
```

**Expiry policies:**

```python
from tenuo.integrations.google_adk import ExpiryPolicy

guard = TenuoGuard(
    warrant=warrant,
    expiry_policy=ExpiryPolicy.CHECK_TIMEOUT,  # Recommended
)
```

| Policy | Behavior | Tradeoff |
|--------|----------|----------|
| `CHECK_BEFORE` | Check once at start | Fast, but tool can outlive warrant |
| `CHECK_TIMEOUT` | Tool timeout = min(tool_timeout, warrant_ttl) | Safe, may interrupt long tools |
| `CHECK_PERIODIC` | Check every N seconds (async only) | Overhead, but catches expiry mid-execution |

**Implementation for `CHECK_TIMEOUT`:**

```python
def secure_tool(self, func, skill):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        warrant = self._get_warrant()
        remaining_ttl = warrant.exp - time.time()
        
        if remaining_ttl <= 0:
            return self._deny("Warrant expired", func.__name__, kwargs)
        
        if self._expiry_policy == ExpiryPolicy.CHECK_TIMEOUT:
            with timeout(remaining_ttl):
                return func(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    
    return wrapper
```

### 7.5 Logging Denied Attempts

All denials are logged to `audit_log` with full warrant context (regardless of `denial_detail` level):

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": "tool_denied",
  "tool": "shell",
  "args": {"command": "rm -rf /"},
  "warrant": {
    "jti": "abc123",
    "iss": "did:key:z6Mk..."
  },
  "reason": "Tool 'shell' not authorized",
  "detail_sent_to_llm": "minimal"
}
```

For security monitoring, forward audit logs to your SIEM:

```python
guard = TenuoGuard(
    warrant=warrant,
    audit_log=siem_handler,  # Custom handler that sends to security tooling
)
```

### 7.6 Warrant Refresh

For long-running agents, warrants may expire mid-session. Handle with refresh callback:

```python
async def refresh_warrant(ctx: ToolContext) -> Warrant:
    """Fetch fresh warrant from control plane."""
    return await control_plane.request_warrant(
        agent=ctx.agent_name,
        scope=["read_file", "search"],
    )

guard = TenuoGuard(
    warrant_key="tenuo_warrant",
    warrant_refresh=refresh_warrant,  # Called when warrant expires
)
```

Refresh is triggered when:
1. `before_tool` detects expired warrant
2. Plugin's `before_agent_callback` clears stale warrant

**Recommended pattern for multi-tenant web servers:**

```python
# On each request, inject fresh warrant
@app.middleware
async def inject_warrant(request, call_next):
    user = get_current_user(request)
    warrant = await mint_warrant_for_user(user)
    
    # Inject into session state
    request.state.tenuo_warrant = warrant
    
    response = await call_next(request)
    
    # Clear on response (prevent leaks)
    del request.state.tenuo_warrant
    
    return response
```

---

## 8. Multi-Agent Hierarchies

ADK supports multi-agent systems with `sub_agents`. Tenuo integrates naturally:

### 7.1 Single Warrant for All Agents

```python
# Coordinator delegates to specialists, all use same warrant
plugin = TenuoPlugin(warrant=org_warrant)

coordinator = Agent(
    name="coordinator",
    sub_agents=[researcher, writer, reviewer],
)

runner = InMemoryRunner(agent=coordinator, plugins=[plugin])
```

### 7.2 Per-Agent Warrants via State

```python
# Different warrants for different agents
plugin = TenuoPlugin(warrant_key="agent_warrant")

def before_agent_callback(ctx):
    # Inject agent-specific warrant
    if ctx.agent_name == "researcher":
        ctx.state["agent_warrant"] = researcher_warrant
    elif ctx.agent_name == "writer":
        ctx.state["agent_warrant"] = writer_warrant
    return None

coordinator = Agent(
    name="coordinator",
    sub_agents=[researcher, writer],
    before_agent_callback=before_agent_callback,
)
```

### 7.3 Dynamic Delegation - Tenuo's "Wow" Moment

This is what makes Tenuo different from hardcoded guardrails. When Agent A delegates to Agent B, it can cryptographically attenuate its authority:

```python
from tenuo import Grant
from tenuo.constraints import UrlSafe, Subpath

def delegate_to_researcher(query: str, ctx: ToolContext) -> dict:
    """
    Coordinator tool that delegates search to researcher sub-agent.
    
    Instead of giving researcher full access, coordinator mints
    a narrow, ephemeral credential scoped to this specific task.
    """
    # Get coordinator's warrant
    coordinator_warrant = ctx.state["tenuo_warrant"]
    
    # Attenuate for researcher using grant_builder():
    # - Only search skill (not file access, not shell)
    # - Only arxiv.org (not all URLs coordinator can access)
    # - Only 60 seconds (just for this task)
    researcher_warrant = (coordinator_warrant.grant_builder()
        .capability("search", sources=UrlSafe(allow_domains=["arxiv.org"]))
        .holder(researcher_key.public_key)
        .ttl(60)  # Ephemeral: 1 minute
        .grant(coordinator_key)
    )
    
    # Inject attenuated warrant for sub-agent
    ctx.state["researcher_warrant"] = researcher_warrant
    
    # ADK handles the actual delegation
    return {"delegate_to": "researcher", "input": query}
```

**Why this matters:**

1. **Cryptographic proof:** Researcher's warrant is signed. Verifiable that coordinator authorized it.

2. **Least privilege:** Researcher can't exceed coordinator's authority. If coordinator can't access `shell`, neither can researcher.

3. **Ephemeral:** 60-second TTL means credential is useless after task completes.

4. **Auditable:** Chain of delegation is traceable: `orchestrator → coordinator → researcher`.

5. **No central authority:** Attenuation happens offline. No policy server to query.

Compare to the alternative:

```python
# Without Tenuo: Hardcoded API keys, implicit trust
def delegate_to_researcher(query, ctx):
    # Researcher has same hardcoded API key as coordinator
    # No proof of authorization
    # No constraints
    # No expiry
    return {"delegate_to": "researcher", "input": query}
```

---

## 9. Integration with A2A

ADK has built-in A2A support. When using Tenuo with remote A2A agents:

```python
from google.adk.tools import A2ATool
from tenuo.integrations.google_adk import TenuoGuard

# A2ATool calls remote agent via A2A protocol
remote_search = A2ATool(
    agent_url="https://search-agent.example.com",
    # A2ATool handles warrant header automatically if configured
)

guard = TenuoGuard(
    warrant=my_warrant,
    skill_map={"remote_search": "search"},  # Map A2ATool to warrant skill
)

agent = Agent(
    name="orchestrator",
    tools=[remote_search, local_tool],
    before_tool_callback=guard.before_tool,
)
```

For full A2A integration (warrant in header), use the A2A adapter directly or configure A2ATool:

```python
# Option: A2ATool with warrant injection
remote_search = A2ATool(
    agent_url="https://search-agent.example.com",
    warrant_provider=lambda ctx: ctx.state.get("tenuo_warrant"),
)
```

---

## 10. Comparison to Native ADK Guardrails

| Feature | ADK Native Callback | Tenuo Integration |
|---------|---------------------|-------------------|
| **Authorization model** | Ad-hoc if statements | Cryptographic warrants |
| **Constraint validation** | Manual string checks | Type-safe constraints (Subpath, UrlSafe, etc.) |
| **Delegation** | Implicit trust | Cryptographic attenuation with monotonicity |
| **Audit trail** | Manual logging | Structured events with warrant context |
| **Multi-agent** | Per-agent callbacks | Plugin applies to all agents |
| **Proof of policy** | None | Warrant is verifiable proof |
| **Expiry** | Manual timestamp checks | Built-in TTL with automatic enforcement |
| **Replay protection** | None | JTI tracking (via A2A adapter) |
| **Layer 2 containment** | Not possible | Tool wrappers with jail support |

**When to use native ADK callbacks:**
- Simple, single-agent prototypes
- Static policies that don't change
- No need for audit trail

**When to use Tenuo:**
- Multi-agent systems with delegation
- Dynamic policies (different users get different permissions)
- Compliance/audit requirements
- Defense in depth (Layer 1.5 + Layer 2)

---

## 11. Comparison to LangChain Integration

| Aspect | LangChain | Google ADK |
|--------|-----------|------------|
| Hook mechanism | Tool wrapper class | Native callbacks |
| Multi-agent | Chain-specific | Built-in sub_agents |
| Plugin system | No | Yes (BasePlugin) |
| State access | Via chain | ToolContext.state |
| A2A integration | Manual | Built-in A2ATool |
| Streaming | Partial | Native |

ADK integration is cleaner because:
1. Native callback system (no wrapper classes)
2. Plugin system for cross-agent concerns
3. State management built into ToolContext
4. Built-in A2A support

---

## 12. Example: Secure Research Agent (Full Runnable)

```python
#!/usr/bin/env python3
"""
Secure Research Agent with Tenuo Authorization

This example demonstrates:
1. Warrant creation with constrained grants
2. Tool filtering (shell not shown to LLM)
3. Constraint enforcement (path must be under /data/papers)
4. Audit logging with warrant context
5. Denial handling (LLM sees error, can recover)

Prerequisites:
    pip install google-adk tenuo

Run:
    python secure_research_agent.py
"""

import os
import sys
from datetime import datetime, timezone

# =============================================================================
# Setup: Keys and Environment
# =============================================================================

# In production, load from secure storage (Vault, KMS, etc.)
# For demo, we generate ephemeral keys
from tenuo import SigningKey, VerifyingKey

# Orchestrator's key (the authority that issues warrants)
orchestrator_key = SigningKey.generate()
orchestrator_public = orchestrator_key.verifying_key()

# Agent's key (optional, for PoP if needed)
agent_key = SigningKey.generate()

# Set Gemini API key
os.environ.setdefault("GOOGLE_API_KEY", "your-api-key-here")

# =============================================================================
# Tool Definitions
# =============================================================================

def read_file(file_path: str) -> str:
    """
    Read contents of a file from disk.
    
    Args:
        file_path: Path to the file to read. Must be under /data/papers.
    
    Returns:
        The file contents as a string.
    """
    with open(file_path) as f:
        return f.read()


def run_shell(command: str) -> str:
    """
    Execute a shell command and return output.
    
    Args:
        command: The shell command to execute.
    
    Returns:
        Command output as a string.
    """
    import subprocess
    return subprocess.check_output(command, shell=True).decode()


def search_papers(query: str, source: str = "arxiv") -> list:
    """
    Search for academic papers.
    
    Args:
        query: Search query string.
        source: Source to search (arxiv, scholar).
    
    Returns:
        List of paper results.
    """
    # Mock implementation
    return [
        {"title": f"Paper about {query}", "url": f"https://{source}.org/paper/123"},
        {"title": f"Another paper on {query}", "url": f"https://{source}.org/paper/456"},
    ]


# =============================================================================
# Warrant Creation
# =============================================================================

from tenuo import Warrant, Grant
from tenuo.constraints import Subpath, UrlSafe

# Create warrant with specific grants
# This is what an orchestrator would issue to authorize this agent
warrant = Warrant.create(
    issuer=orchestrator_key,
    subject="research-agent-01",  # Who this warrant is for
    audience="local",              # Where it can be used
    grants=[
        Grant(
            skill="read_file",
            constraints={
                "file_path": Subpath("/data/papers"),  # Only this directory
            },
        ),
        Grant(
            skill="search_papers",
            constraints={
                "source": UrlSafe(allow_domains=["arxiv.org", "scholar.google.com"]),
            },
        ),
        # NOTE: run_shell is intentionally NOT granted
    ],
    ttl=3600,  # 1 hour
)

print(f"Created warrant: {warrant.jti}")
print(f"  Issuer: {warrant.iss[:20]}...")
print(f"  Expires: {datetime.fromtimestamp(warrant.exp, tz=timezone.utc)}")
print(f"  Grants: {[g['skill'] for g in warrant.grants]}")
print()

# =============================================================================
# Guard Setup
# =============================================================================

from tenuo.integrations.google_adk import TenuoGuard, DenialDetail

# Use context manager for proper cleanup
# Guard will close audit log when done
guard = TenuoGuard(
    warrant=warrant,
    audit_log="research_agent_audit.jsonl",  # Path or file object
    denial_detail=DenialDetail.FULL,  # Full details for demo (use MINIMAL in prod)
    denial_template=(
        "Cannot use {tool}: {reason}. "
        "Available tools: {granted_tools}."
    ),
)

# =============================================================================
# Agent Creation
# =============================================================================

from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner

# All tools defined, but guard will filter to only granted ones
all_tools = [read_file, run_shell, search_papers]

# Filter tools - run_shell will be excluded
available_tools = guard.filter_tools(all_tools)
print(f"Tools shown to LLM: {[t.__name__ for t in available_tools]}")
print(f"Tools filtered out: {[t.__name__ for t in all_tools if t not in available_tools]}")
print()

# Create agent
agent = Agent(
    name="research_assistant",
    model="gemini-2.0-flash",
    instruction="""You are a research assistant that helps find and read academic papers.

You can:
- Search for papers on arxiv.org and scholar.google.com
- Read papers stored in /data/papers

Always cite your sources and provide paper URLs when available.""",
    description="A research assistant with access to academic papers.",
    tools=available_tools,
    before_tool_callback=guard.before_tool,
    after_tool_callback=guard.after_tool,
)

# =============================================================================
# Run Examples
# =============================================================================

runner = InMemoryRunner(agent=agent)

# Example 1: Allowed - search papers
print("=" * 60)
print("Example 1: Search papers (ALLOWED)")
print("=" * 60)
result = runner.run("Find recent papers about prompt injection attacks")
print(f"Result: {result}")
print()

# Example 2: Allowed - read file in allowed path
print("=" * 60)
print("Example 2: Read allowed file (ALLOWED)")
print("=" * 60)
# Create test file
os.makedirs("/data/papers", exist_ok=True)
with open("/data/papers/test.txt", "w") as f:
    f.write("This is a test paper about AI safety.")
result = runner.run("Read the file /data/papers/test.txt")
print(f"Result: {result}")
print()

# Example 3: Denied - read file outside allowed path
print("=" * 60)
print("Example 3: Read /etc/passwd (DENIED - constraint violation)")
print("=" * 60)
result = runner.run("Read the file /etc/passwd")
print(f"Result: {result}")
# LLM receives: {"error": "authorization_denied", "message": "Argument 'file_path' violates constraint"}
print()

# Example 4: Denied - shell not granted (but LLM doesn't even see it)
print("=" * 60)
print("Example 4: Shell command (DENIED - tool filtered)")
print("=" * 60)
result = runner.run("Run 'ls -la /data' to list files")
print(f"Result: {result}")
# LLM will say it doesn't have a shell tool (because it was filtered)
print()

# =============================================================================
# Review Audit Log
# =============================================================================

print("=" * 60)
print("Audit Log:")
print("=" * 60)
guard.close()  # Close audit log properly
with open("research_agent_audit.jsonl") as f:
    for line in f:
        print(line.strip())
```

**Expected output:**

```
Created warrant: w_abc123...
  Issuer: did:key:z6MkhaXg...
  Expires: 2024-01-15 15:30:00+00:00
  Grants: ['read_file', 'search_papers']

Tools shown to LLM: ['read_file', 'search_papers']
Tools filtered out: ['run_shell']

============================================================
Example 1: Search papers (ALLOWED)
============================================================
Result: I found several papers about prompt injection...

============================================================
Example 2: Read allowed file (ALLOWED)
============================================================
Result: The file contains: "This is a test paper about AI safety."

============================================================
Example 3: Read /etc/passwd (DENIED - constraint violation)
============================================================
Result: I cannot read that file because it's outside my authorized directory.

============================================================
Example 4: Shell command (DENIED - tool filtered)
============================================================
Result: I don't have access to shell commands. I can only search papers and read files from /data/papers.

============================================================
Audit Log:
============================================================
{"timestamp":"2024-01-15T14:30:01Z","event":"tool_allowed","tool":"search_papers",...}
{"timestamp":"2024-01-15T14:30:02Z","event":"tool_allowed","tool":"read_file",...}
{"timestamp":"2024-01-15T14:30:03Z","event":"tool_denied","tool":"read_file","reason":"constraint_violation",...}
```

---

## 13. Implementation Plan

### Phase 1: Core Guard (MVP)
- [ ] `TenuoGuard` class
- [ ] `before_tool` / `after_tool` callbacks
- [ ] `filter_tools()` for token efficiency
- [ ] Skill and argument mapping
- [ ] Basic constraint checking (Subpath, UrlSafe, Shlex)
- [ ] Audit logging to file

### Phase 2: ADK Integration
- [ ] `TenuoPlugin` for cross-agent enforcement
- [ ] `before_agent_callback` for state leak prevention
- [ ] `chain_callbacks` utility
- [ ] Session state warrant support

### Phase 3: Tool Wrappers
- [ ] `secure_tool()` wrapper function
- [ ] Optional jail integration (when available)
- [ ] Preserve tool metadata for ADK

### Phase 4: Multi-Agent
- [ ] Per-agent warrant injection patterns
- [ ] Dynamic delegation examples
- [ ] A2ATool integration

### Phase 5: Production
- [ ] Warrant refresh callback
- [ ] Metrics/observability hooks
- [ ] Denial message templates
- [ ] Integration tests with ADK
- [ ] Documentation and examples

### Integration Test Matrix

| Test Case | Input | Expected Result |
|-----------|-------|-----------------|
| Valid tool call | `read_file("/data/papers/x.txt")` with valid warrant | Tool executes, audit logged |
| Tool not granted | `run_shell("ls")` with warrant missing shell | Denied, `{"error": "authorization_denied"}` |
| Constraint violation | `read_file("/etc/passwd")` with Subpath("/data") | Denied, constraint error |
| Expired warrant | Any tool call with expired warrant | Denied, `warrant_expired` |
| Missing warrant | Tool call with `warrant=None` | Denied, `no_warrant` |
| Filter tools (static) | `filter_tools([a, b, c])` with warrant granting [a] | Returns `[a]` only |
| Filter tools (dynamic) | `filter_tools([a, b, c], warrant=w)` | Filters using passed warrant |
| State leak (scoped) | `ScopedWarrant` for agent A, accessed by agent B | Denied, warrant not valid for agent |
| Multi-agent delegation | Parent attenuates, child uses | Child constrained to subset |
| A2A with invalid warrant | Remote call with tampered warrant | Remote rejects, `invalid_signature` |
| A2A with valid warrant | Remote call with properly attenuated warrant | Remote executes |
| Jail integration | `secure_tool(f, jail=True)` with Subpath | Execution wrapped in `PathJail` |
| Jail unavailable | `secure_tool(f, jail=True)` on Windows | Warning logged, Layer 1.5 only |
| Denial detail MINIMAL | Tool denied with `denial_detail=MINIMAL` | LLM sees "Request not permitted" only |
| Denial detail FULL | Tool denied with `denial_detail=FULL` | LLM sees tool name and reason |
| Expiry CHECK_TIMEOUT | Tool takes 5min, warrant has 1min TTL | Tool times out at 1min |
| Arg mapping | Tool arg `file_path`, constraint key `path` | Maps correctly via `arg_map` |
| Multi-agent delegation | Parent attenuates, child uses | Child constrained to subset |
| A2A with invalid warrant | Remote call with tampered warrant | Remote rejects, `invalid_signature` |
| A2A with valid warrant | Remote call with properly attenuated warrant | Remote executes |
| Jail integration | `secure_tool(f, jail=True)` with Subpath | Execution wrapped in `path_jail` |
| Jail unavailable | `secure_tool(f, jail=True)` on Windows | Warning logged, Layer 1.5 only |

---

## 14. Resolved Questions

### Q1: Should TenuoGuard filter tools?

**Yes.** `filter_tools()` removes unauthorized tools before the LLM sees them. This:
- Saves tokens (tool descriptions are verbose)
- Prevents hallucinated plans that can't execute
- Results in cleaner agent behavior

### Q2: How to handle state leaks?

**Plugin with `before_agent_callback`.** Clear or validate warrants at turn boundaries. Document the risk for multi-tenant scenarios with persistent sessions.

### Q3: Callbacks vs Tool Wrappers?

**Both, for different purposes:**
- Callbacks: Validation, audit logging (Layer 1.5)
- Wrappers: Execution containment (Layer 2 ready)

Use callbacks for most cases. Use wrappers when you need jail support.

---

## 15. Open Questions

### Q1: A2ATool warrant forwarding

**Question:** Should TenuoGuard automatically inject warrant header when it detects an A2ATool call?

| Option | Pros | Cons |
|--------|------|------|
| **Auto-inject** | Simplifies developer experience; one-liner integration | Risk of over-delegation (warrant sent to unintended targets); hard to attenuate per-target |
| **Manual** | Full control; can attenuate differently per target | More boilerplate; easy to forget |
| **Hybrid (recommended)** | Detect A2ATool, warn if no warrant configured | Guides correct usage without magic |

**Recommendation:** Hybrid. Log a warning if A2ATool detected without explicit warrant config. Don't auto-inject.

### Q2: Plugin vs Callback default recommendation

**Question:** When should users prefer Plugin (global) vs Callback (per-agent)?

| Scenario | Recommendation |
|----------|----------------|
| Single agent | Callback - simpler, less overhead |
| Multi-agent with same warrant | Plugin - one registration covers all |
| Multi-agent with different warrants | Callback per agent, or Plugin with state lookup |
| Web server (multi-tenant) | Plugin with `before_agent_callback` for state cleanup |
| Development/debugging | Callback - easier to trace |

**Recommendation:** Document both patterns with clear guidance. Default examples should use Plugin for multi-agent, Callback for single-agent.

### Q3: Jail availability detection

**Question:** How to handle when Layer 2 jails aren't available (Windows, missing deps)?

| Option | Behavior | Use Case |
|--------|----------|----------|
| `jail="require"` | Fail if jail unavailable | High-security deployments |
| `jail="prefer"` | Use if available, warn if not | Default - defense in depth |
| `jail="off"` | Never use jails (Layer 1.5 only) | When jails cause issues |

**Recommendation:** Default to `jail="prefer"`. Log clear warning when jails unavailable:

```
WARNING: Layer 2 jails not available (platform: Windows). 
Running with Layer 1.5 validation only. Set jail="off" to silence.
```

Configuration:

```python
guard = TenuoGuard(
    warrant=warrant,
    jail_policy="prefer",  # "require" | "prefer" | "off"
)
```
