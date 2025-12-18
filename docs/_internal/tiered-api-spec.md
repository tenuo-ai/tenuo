# Task 5: Tiered API & Integration - Mini Spec (v2)

## Goal

Make Tenuo usable in **3 lines of code** for common cases, while exposing full control for advanced users.

---

## Design Principles

1. **Progressive disclosure**: Simple things simple, complex things possible
2. **Fail-safe defaults**: Unconfigured = secure (no silent pass-through, no magic roots)
3. **Framework-native**: Feel like LangChain/LangGraph, not a bolt-on
4. **Zero magic**: Explicit > implicit, but concise > verbose
5. **Debuggable**: "Why did this fail?" should be trivially answerable

---

## Tier 1: The 3-Line API

**Target user**: Developer who wants delegation without reading the spec.

```python
from tenuo import root_task, scoped_task, protect_tools

tools = [read_file, send_email, query_db]
protect_tools(tools)  # Mutates in place by default

# Explicitly create root authority, then scope it
async with root_task(tools=["read_file", "query_db"], path="/data/*"):
    # Narrow scope for specific subtask
    async with scoped_task(tools=["read_file"], path="/data/reports/*"):
        result = await agent.run(tools, "Summarize Q3 reports")
```

Or get a new list (immutable pattern):

```python
from tenuo import root_task, scoped_task, protect_tools

original_tools = [read_file, send_email, query_db]
tools = protect_tools(original_tools, inplace=False)  # Returns new list

async with root_task(tools=["read_file"], path="/data/*"):
    async with scoped_task(tools=["read_file"], path="/data/reports/*"):
        result = await agent.run(tools, "Summarize Q3 reports")
```

**What happens under the hood**:
1. `protect_tools()` wraps each tool to check authorization before execution
2. `root_task()` creates a root warrant (explicit authority minting)
3. `scoped_task()` attenuates the parent warrant (must have parent, else error)
4. Tool execution checks warrant allowlist -> allows or denies

---

## Tier 2: Explicit Delegation

**Target user**: Developer who needs control over delegation chains.

```python
from tenuo import Warrant, SigningKey

# Create root warrant
root = Warrant.builder() \
    .tools(["read_file", "write_file"]) \
    .constraint("path", "/data/*") \
    .ttl(seconds=300) \
    .holder(agent_keypair.public_key) \
    .build(issuer_keypair)

# Delegate to worker with narrower scope
child = root.attenuate_builder() \
    .tools(["read_file"]) \
    .constraint("path", "/data/reports/*") \
    .ttl(seconds=60) \
    .holder(worker_keypair.public_key) \
    .build(worker_keypair, issuer_keypair)

# Authorize action
child.authorize("read_file", {"path": "/data/reports/q3.csv"}, pop_signature)
```

---

## API Components

### 1. Context Management

```python
# context.py

from contextvars import ContextVar
from typing import Optional

# Async-safe context variables
_warrant_context: ContextVar[Optional[Warrant]] = ContextVar('warrant', default=None)
_keypair_context: ContextVar[Optional[SigningKey]] = ContextVar('keypair', default=None)

def get_warrant() -> Optional[Warrant]:
    """Get the current warrant from async context."""
    return _warrant_context.get()

def set_warrant(warrant: Optional[Warrant]) -> None:
    """Set the current warrant in async context."""
    _warrant_context.set(warrant)

def get_keypair() -> Optional[SigningKey]:
    """Get the current keypair from async context."""
    return _keypair_context.get()

def set_keypair(keypair: Optional[SigningKey]) -> None:
    """Set the current keypair in async context."""
    _keypair_context.set(keypair)
```

---

### 2. root_task Context Manager

```python
# scoped.py

@asynccontextmanager
async def root_task(
    *,
    tools: List[str],
    ttl: Optional[int] = None,  # seconds, defaults to config.default_ttl
    holder_key: Optional[SigningKey] = None,  # Explicit holder (advanced)
    **constraints
) -> AsyncIterator[Warrant]:
    """
    Create a root warrant (explicit authority minting).
    
    This is the ONLY way to mint new authority in Tier 1.
    Use scoped_task() to attenuate within a root_task block.
    
    Issuer vs Holder (Tier 1 default)
    ---------------------------------
    In Tier 1, issuer == holder by default. This means:
    - The configured issuer key signs the warrant
    - The same key is used for Proof-of-Possession
    
    This is correct for single-process agents where one runtime
    creates and uses warrants. For multi-process or cross-service
    delegation, provide holder_key explicitly or use Tier 2 APIs.
    
    Args:
        tools: Allowlist of tools this warrant authorizes
        ttl: Time-to-live in seconds (default from configure())
        holder_key: Explicit holder keypair (default: issuer key)
        **constraints: Constraint kwargs applied to all tools
    
    Raises:
        TenuoConfigError: If no issuer key configured
    
    Example:
        # Single-process (Tier 1 default): issuer == holder
        async with root_task(tools=["read_file"], path="/data/*"):
            ...
        
        # Multi-process: explicit holder
        async with root_task(tools=["read_file"], holder_key=worker_key):
            ...
    """
    config = _get_config()
    if config.issuer_keypair is None:
        raise TenuoConfigError(
            "Cannot create root warrant: no issuer key configured. "
            "Call configure(issuer_key=...) first."
        )
    
    issuer = config.issuer_keypair
    holder = holder_key or issuer  # Tier 1 default: issuer == holder
    
    warrant = _create_root_warrant(
        tools=tools,
        constraints=constraints,
        ttl=ttl or config.default_ttl,
        issuer=issuer,
        holder=holder,
    )
    
    # Set in context
    # Note: We set the HOLDER's keypair, not issuer's, because
    # the holder key is what signs PoP for tool invocations
    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)
    try:
        yield warrant
    finally:
        _warrant_context.reset(warrant_token)
        _keypair_context.reset(keypair_token)


def _create_root_warrant(
    tools: List[str],
    constraints: Dict[str, Any],
    ttl: int,
    issuer: SigningKey,
    holder: SigningKey,
) -> Warrant:
    """Create a root warrant with the given parameters."""
    builder = Warrant.builder() \
        .tools(tools) \
        .ttl(seconds=ttl) \
        .holder(holder.public_key)
    
    # Apply constraints with auto-inferred types
    for key, value in constraints.items():
        constraint = infer_constraint_type(key, value)
        builder = builder.constraint(key, constraint)
    
    return builder.build(issuer)
```

---

### 3. scoped_task Context Manager

```python
# scoped.py

@asynccontextmanager
async def scoped_task(
    *,
    tools: Optional[List[str]] = None,  # None = inherit parent's tools
    ttl: Optional[int] = None,
    **constraints
) -> AsyncIterator[Warrant]:
    """
    Attenuate the current warrant for a subtask.
    
    MUST be called within a root_task() or another scoped_task().
    Cannot mint new authority - only narrow existing authority.
    
    Usage:
        async with root_task(tools=["read_file", "write_file"], path="/data/*"):
            async with scoped_task(tools=["read_file"], path="/data/reports/*"):
                await agent.run(...)
    
    Args:
        tools: Subset of parent's tools (None = inherit all)
        ttl: Shorter TTL in seconds (None = inherit parent's remaining TTL)
        **constraints: Additional constraints (must be contained within parent's)
    
    Raises:
        TenuoAuthError: If no parent warrant in context
        TenuoConstraintError: If constraints aren't contained within parent's
    
    Note:
        Tier 1 supports simple glob patterns (e.g., /data/* -> /data/reports/*).
        For regex or complex patterns, use Tier 2 (Warrant.attenuate() directly).
    """
    parent = get_warrant()
    keypair = get_keypair()
    
    if parent is None:
        raise TenuoAuthError(
            "scoped_task() requires a parent warrant. "
            "Use root_task() to create initial authority, then scoped_task() to narrow it."
        )
    
    if keypair is None:
        raise TenuoConfigError("No keypair in context.")
    
    # Attenuate with containment semantics (Tier 1)
    child = _attenuate_with_containment(parent, tools, constraints, ttl, keypair)
    
    # Set child in context
    token = _warrant_context.set(child)
    try:
        yield child
    finally:
        _warrant_context.reset(token)


def _attenuate_with_containment(
    parent: Warrant,
    tools: Optional[List[str]],
    constraints: Dict[str, Any],
    ttl: Optional[int],
    keypair: SigningKey,
) -> Warrant:
    """
    Attenuate with containment semantics (Tier 1 simplicity).
    
    Tier 1 constraints:
    - Exact values: child must equal parent
    - Patterns (glob): child must be more specific (longer prefix)
    
    For complex narrowing logic (regex, ranges), use Tier 2.
    
    - Tools: child tools must be subset of parent tools
    - Constraints: child must be contained within parent
    - TTL: min(requested, parent_remaining)
    """
    # Validate tools are subset
    parent_tools = set(parent.tools or [])
    child_tools = set(tools) if tools else parent_tools
    
    if not child_tools.issubset(parent_tools):
        invalid = child_tools - parent_tools
        raise TenuoConstraintError(
            field="tools",
            reason=f"Tools {invalid} not in parent's allowlist {parent_tools}"
        )
    
    # Build attenuation
    builder = parent.attenuate().tools(list(child_tools))
    
    # Apply constraints with containment check
    for key, child_value in constraints.items():
        parent_constraint = parent.get_constraint(key)
        
        if parent_constraint is None:
            # New constraint - always valid (narrows from "anything")
            builder = builder.constraint(key, child_value)
        elif not _is_contained(child_value, parent_constraint):
            raise TenuoConstraintError(
                field=key,
                reason=f"'{child_value}' is not contained within parent's '{parent_constraint}'",
                requested=child_value,
                allowed=parent_constraint,
            )
        else:
            builder = builder.constraint(key, child_value)
    
    if ttl:
        builder = builder.ttl(ttl)
    
    return builder.build(keypair, keypair)


def _is_contained(child: str, parent: str) -> bool:
    """
    Check if child constraint is contained within parent.
    
    Tier 1 rules (simple, predictable):
    - Exact match: "foo" contained in "foo" Yes
    - Glob prefix: "/data/users/*" contained in "/data/*" Yes
    - Glob prefix: "/data/*" contained in "/data/users/*" No (child is broader)
- Glob prefix: "/etc/*" contained in "/data/*" No (different prefix)
    
    For regex or complex patterns, use Tier 2.
    """
    # Exact match
    if child == parent:
        return True
    
    # Glob pattern containment (simple prefix logic)
    if parent.endswith("*"):
        parent_prefix = parent[:-1]  # "/data/*" -> "/data/"
        
        if child.endswith("*"):
            child_prefix = child[:-1]  # "/data/users/*" -> "/data/users/"
            # Child prefix must start with parent prefix AND be longer or equal
            return child_prefix.startswith(parent_prefix) and len(child_prefix) >= len(parent_prefix)
        else:
            # Exact child must match parent prefix
            return child.startswith(parent_prefix)
    
    # No glob - must be exact match (already checked above)
    return False
```

**Requirements**:
- [ ] `root_task()` is the only way to mint authority in Tier 1
- [ ] `scoped_task()` errors if no parent (no silent root minting)
- [ ] `tools` is an allowlist (plural), not a single tool
- [ ] Containment semantics for constraint narrowing (not intersection)
- [ ] Simple glob patterns supported: `/data/*` -> `/data/reports/*`
- [ ] Non-contained constraint = error with clear message
- [ ] Restores parent warrant on exit (even on exception)
- [ ] Works with both sync and async code

---

### 3a. Tier 1 Constraint Algebra

Tier 1 uses a **closed set** of constraint types with deterministic containment rules. This prevents "looks like it narrowed but actually widened" bugs.

#### Supported Constraint Types

```python
# constraints.py

from enum import Enum
from typing import Union, List, Tuple
from dataclasses import dataclass

class Tier1ConstraintType(Enum):
    PREFIX_GLOB = "prefix_glob"   # Path patterns: /data/* -> /data/reports/*
    SUFFIX_MATCH = "suffix_match" # Domain patterns: *.example.com -> api.example.com
    EXACT = "exact"               # Exact string match
    ONEOF = "oneof"               # Set membership: ["a","b","c"] -> ["a","b"]
    RANGE = "range"               # Numeric range: (0,100) -> (10,50)


@dataclass
class PrefixGlob:
    """Path-style glob with * suffix. Used for: path, url_prefix"""
    pattern: str  # e.g., "/data/*" or "/data/reports/*"


@dataclass  
class SuffixMatch:
    """Domain-style suffix match. Used for: domain, email_domain"""
    pattern: str  # e.g., "*.example.com" or "example.com"


@dataclass
class Exact:
    """Exact string match. Used for: method, action, etc."""
    value: str


@dataclass
class OneOf:
    """Set membership. Used for: allowed_values, types"""
    values: List[str]


@dataclass
class Range:
    """Numeric range (inclusive). Used for: size, count, amount"""
    min_val: Union[int, float]
    max_val: Union[int, float]
```

#### Containment Rules

| Type | Parent | Child | Contained? | Rule |
|------|--------|-------|------------|------|
| PrefixGlob | `/data/*` | `/data/reports/*` | [OK] | Child prefix starts with parent prefix |
| PrefixGlob | `/data/*` | `/data/q3.csv` | [OK] | Exact path starts with parent prefix |
| PrefixGlob | `/data/reports/*` | `/data/*` | [NO] | Child is broader |
| SuffixMatch | `*.example.com` | `api.example.com` | [OK] | Child ends with parent suffix |
| SuffixMatch | `*.example.com` | `*.api.example.com` | [OK] | Child suffix is longer |
| SuffixMatch | `example.com` | `other.com` | [NO] | Different domain |
| Exact | `"GET"` | `"GET"` | [OK] | Equal |
| Exact | `"GET"` | `"POST"` | [NO] | Not equal |
| OneOf | `["a","b","c"]` | `["a","b"]` | [OK] | Child is subset |
| OneOf | `["a","b"]` | `["a","b","c"]` | [NO] | Child is superset |
| Range | `(0, 100)` | `(10, 50)` | [OK] | Child within parent |
| Range | `(10, 50)` | `(0, 100)` | [NO] | Child exceeds parent |

#### Containment Implementation

```python
def is_contained(child: Tier1Constraint, parent: Tier1Constraint) -> bool:
    """Check if child constraint is contained within parent."""
    
    # Must be same type
    if type(child) != type(parent):
        raise TenuoConstraintError(
            field="type",
            reason=f"Cannot compare {type(child).__name__} with {type(parent).__name__}"
        )
    
    if isinstance(parent, PrefixGlob):
        return _prefix_glob_contains(child.pattern, parent.pattern)
    
    elif isinstance(parent, SuffixMatch):
        return _suffix_match_contains(child.pattern, parent.pattern)
    
    elif isinstance(parent, Exact):
        return child.value == parent.value
    
    elif isinstance(parent, OneOf):
        return set(child.values).issubset(set(parent.values))
    
    elif isinstance(parent, Range):
        return child.min_val >= parent.min_val and child.max_val <= parent.max_val
    
    raise TenuoConstraintError(field="type", reason=f"Unknown constraint type: {type(parent)}")


def _prefix_glob_contains(child: str, parent: str) -> bool:
    """Check PrefixGlob containment."""
    if not parent.endswith("*"):
        return child == parent  # Exact match required
    
    parent_prefix = parent[:-1]  # "/data/*" -> "/data/"
    
    if child.endswith("*"):
        child_prefix = child[:-1]
        return child_prefix.startswith(parent_prefix) and len(child_prefix) >= len(parent_prefix)
    else:
        return child.startswith(parent_prefix)


def _suffix_match_contains(child: str, parent: str) -> bool:
    """Check SuffixMatch containment."""
    # Normalize: remove leading *. if present
    parent_suffix = parent.lstrip("*.")
    child_suffix = child.lstrip("*.")
    
    # Child must end with parent suffix
    if not child_suffix.endswith(parent_suffix):
        return False
    
    # If equal, contained
    if child_suffix == parent_suffix:
        return True
    
    # Child must be longer (more specific)
    # e.g., "api.example.com" ends with "example.com" and is longer
    return len(child_suffix) > len(parent_suffix)
```

#### Default Constraint Types by Key

```python
# Auto-infer constraint type from key name
CONSTRAINT_KEY_TYPES = {
    "path": PrefixGlob,
    "url_prefix": PrefixGlob,
    "domain": SuffixMatch,
    "email_domain": SuffixMatch,
    "method": Exact,
    "action": Exact,
    "allowed_types": OneOf,
    "allowed_values": OneOf,
    "size": Range,
    "count": Range,
    "amount": Range,
}

def infer_constraint_type(key: str, value: Any) -> Tier1Constraint:
    """Infer constraint type from key name and value."""
    if key in CONSTRAINT_KEY_TYPES:
        constraint_cls = CONSTRAINT_KEY_TYPES[key]
        return constraint_cls(value)
    
    # Fallback: infer from value shape
    if isinstance(value, str) and value.endswith("*"):
        return PrefixGlob(value)
    elif isinstance(value, str) and value.startswith("*."):
        return SuffixMatch(value)
    elif isinstance(value, list):
        return OneOf(value)
    elif isinstance(value, tuple) and len(value) == 2:
        return Range(value[0], value[1])
    else:
        return Exact(str(value))
```

**For complex patterns not covered by Tier 1, use Tier 2:**

```python
# Tier 2: Full control over constraint types
child = parent.attenuate() \
    .constraint("path", Regex(r"/data/\d{4}/.*")) \
    .constraint("query", SqlPattern("SELECT * FROM users WHERE id = ?")) \
    .build(keypair, parent_keypair)
```

---

### 4. Preview Mode

```python
# scoped.py

class ScopedTaskBuilder:
    """Builder that supports preview before entering context."""
    
    def __init__(self, tools: Optional[List[str]], constraints: Dict, ttl: Optional[int]):
        self.tools = tools
        self.constraints = constraints
        self.ttl = ttl
    
    def preview(self) -> ScopePreview:
        """
        Preview the derived scope without executing.
        
        Usage:
            scope = scoped_task(tools=["read_file"], path="/data/reports/*")
            scope.preview()
            # Output:
            # Derived scope:
            #   Tools: [read_file]
            #   Constraints:
            #     path: /data/reports/* (narrowed from /data/*)
            #   TTL: 60s (reduced from 300s)
            #   Depth: 2
        
        Returns:
            ScopePreview object with derived scope details
        """
        parent = get_warrant()
        if parent is None:
            return ScopePreview(
                error="No parent warrant. Use root_task() first.",
                tools=self.tools,
                constraints=self.constraints,
            )
        
        try:
            # Compute what the derived scope would be
            derived_tools = self._compute_tools(parent)
            derived_constraints = self._compute_constraints(parent)
            derived_ttl = self._compute_ttl(parent)
            
            return ScopePreview(
                tools=derived_tools,
                parent_tools=parent.tools,
                constraints=derived_constraints,
                parent_constraints=parent.constraints,
                ttl=derived_ttl,
                parent_ttl=parent.remaining_ttl(),
                depth=parent.depth + 1,
            )
        except TenuoConstraintError as e:
            return ScopePreview(error=str(e))
    
    async def __aenter__(self):
        # Same as scoped_task implementation
        ...
    
    async def __aexit__(self, *args):
        ...


@dataclass
class ScopePreview:
    """Preview of derived scope."""
    tools: Optional[List[str]] = None
    parent_tools: Optional[List[str]] = None
    constraints: Optional[Dict] = None
    parent_constraints: Optional[Dict] = None
    ttl: Optional[int] = None
    parent_ttl: Optional[int] = None
    depth: Optional[int] = None
    error: Optional[str] = None
    
    def print(self):
        """Pretty-print the preview."""
        if self.error:
            print(f"[X] Cannot create scope: {self.error}")
            return
        
        print("Derived scope:")
        print(f"  Tools: {self.tools}")
        if self.parent_tools and self.tools != self.parent_tools:
            print(f"    (narrowed from {self.parent_tools})")
        
        print("  Constraints:")
        for key, value in (self.constraints or {}).items():
            parent_val = (self.parent_constraints or {}).get(key)
            if parent_val and parent_val != value:
                print(f"    {key}: {value} (narrowed from {parent_val})")
            else:
                print(f"    {key}: {value}")
        
        print(f"  TTL: {self.ttl}s", end="")
        if self.parent_ttl and self.ttl != self.parent_ttl:
            print(f" (reduced from {self.parent_ttl}s)")
        else:
            print()
        
        print(f"  Depth: {self.depth}")


# Factory function returns builder
def scoped_task(
    *,
    tools: Optional[List[str]] = None,
    ttl: Optional[int] = None,
    **constraints
) -> ScopedTaskBuilder:
    """Create a scoped task builder (supports preview)."""
    return ScopedTaskBuilder(tools, constraints, ttl)
```

**Requirements**:
- [ ] `scoped_task(...).preview()` shows derived scope before execution
- [ ] Preview shows what changed vs parent (narrowed from X)
- [ ] Preview catches errors without executing
- [ ] Pretty-print output for developer debugging

---

### 5. protect_tools Wrapper

```python
# protect.py

def protect_tools(
    tools: List[Tool],
    *,
    inplace: bool = True,  # Default: mutates input list
    strict: bool = False,
    schemas: Optional[Dict[str, ToolSchema]] = None
) -> List[Tool]:
    """
    Wrap tools to enforce warrant authorization.
    
    NOTE: Mutates the input list by default (inplace=True).
    Set inplace=False to get a new list instead.
    
    Args:
        tools: List of LangChain/callable tools
        inplace: If True (default), mutate the original list
        strict: If True, fail on high-risk unconstrained tools
        schemas: Optional tool schemas for constraint hints
    
    Returns:
        Wrapped tools (same list if inplace=True, new list if inplace=False)
    
    Raises:
        TypeError: If inplace=True but tools is not a mutable list
    """
    wrapped = [_wrap_tool(t, strict, schemas) for t in tools]
    
    if inplace:
        if not isinstance(tools, list):
            raise TypeError(
                f"inplace=True requires a mutable list, got {type(tools).__name__}. "
                "Use protect_tools(tools, inplace=False) instead."
            )
        tools.clear()
        tools.extend(wrapped)
        return tools
    
    return wrapped


def _wrap_tool(tool: Tool, strict: bool, schemas: Optional[Dict]) -> Tool:
    """Wrap a single tool with authorization check."""
    
    original_fn = tool.func if hasattr(tool, 'func') else tool
    tool_name = getattr(tool, 'name', original_fn.__name__)
    schema = (schemas or TOOL_SCHEMAS).get(tool_name)
    
    @wraps(original_fn)
    async def protected(*args, **kwargs):
        warrant = get_warrant()
        keypair = get_keypair()
        
        if warrant is None:
            if _allow_passthrough():
                _audit_passthrough(tool_name, kwargs)
                return await _maybe_await(original_fn(*args, **kwargs))
            raise TenuoAuthError(f"No warrant in context for tool: {tool_name}")
        
        # Check tool is in warrant's allowlist
        if warrant.tools and tool_name not in warrant.tools:
            raise TenuoToolError(
                tool=tool_name,
                authorized=warrant.tools,
            )
        
        # Critical tools ALWAYS require at least one constraint
        # This is not controlled by strict flag - it's mandatory
        if schema and schema.risk_level == "critical":
            if not warrant.has_constraints_for(tool_name):
                raise TenuoConfigError(
                    f"Critical tool '{tool_name}' requires at least one constraint. "
                    f"Recommended: {schema.recommended_constraints}. "
                    f"Add constraints in root_task() or scoped_task()."
                )
        
        # High-risk tools: warn if unconstrained (even without strict)
        if schema and schema.risk_level == "high":
            if not warrant.has_constraints_for(tool_name):
                logger.warning(
                    f"[WARNING] High-risk tool '{tool_name}' invoked without constraints. "
                    f"Recommended: {schema.recommended_constraints}"
                )
        
        # Strict mode: require constraints for any tool with require_at_least_one
        if strict and schema and schema.require_at_least_one:
            if not warrant.has_constraints_for(tool_name):
                raise TenuoConfigError(
                    f"Strict mode: tool '{tool_name}' requires at least one constraint. "
                    f"Recommended: {schema.recommended_constraints}"
                )
        
        # Create PoP signature with nonce
        nonce = generate_nonce(str(warrant.id))
        pop, nonce = warrant.create_pop(keypair, tool_name, kwargs, nonce)
        
        # Authorize (checks constraints)
        warrant.authorize(tool_name, kwargs, pop, nonce)
        
        # Audit success
        audit_authorization(warrant, tool_name, kwargs, "allowed")
        
        # Execute
        return await _maybe_await(original_fn(*args, **kwargs))
    
    return _rebuild_tool(tool, protected)


def recommended_constraints(tools: List[Tool]) -> None:
    """
    Print recommended constraints for tools based on risk level.
    
    Usage:
        tools = [read_file, send_email, http_request]
        recommended_constraints(tools)
        
        # Output:
        # http_request: [REQUIRED] (critical) - domain, url, method
        # send_email: recommended (high) - to, domain
        # read_file: recommended (medium) - path
    """
    print("Recommended constraints:\n")
    
    # Sort by risk level (critical first)
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    items = []
    for tool in tools:
        name = getattr(tool, 'name', getattr(tool, '__name__', str(tool)))
        schema = TOOL_SCHEMAS.get(name)
        if schema and schema.recommended_constraints:
            items.append((name, schema))
    
    items.sort(key=lambda x: risk_order.get(x[1].risk_level, 99))
    
    for name, schema in items:
        if schema.risk_level == "critical":
            level_str = "[REQUIRED] (critical)"
        elif schema.risk_level == "high":
            level_str = "[WARNING] recommended (high)"
        else:
            level_str = f"recommended ({schema.risk_level})"
        
        constraints_str = ", ".join(schema.recommended_constraints)
        print(f"  {name}: {level_str} - {constraints_str}")
    
    if not items:
        print("  (no schemas registered for these tools)")


def check_constraints(tools: List[Tool], warrant: Warrant) -> List[str]:
    """
    Check which tools are missing recommended constraints.
    
    Returns list of warning messages for tools missing constraints.
    """
    warnings = []
    
    for tool in tools:
        name = getattr(tool, 'name', getattr(tool, '__name__', str(tool)))
        schema = TOOL_SCHEMAS.get(name)
        
        if schema and schema.recommended_constraints:
            if not warrant.has_constraints_for(name):
                if schema.risk_level == "critical":
                    warnings.append(
                        f"CRITICAL: '{name}' has no constraints. "
                        f"Required: {schema.recommended_constraints}"
                    )
                elif schema.risk_level == "high":
                    warnings.append(
                        f"WARNING: '{name}' has no constraints. "
                        f"Recommended: {schema.recommended_constraints}"
                    )
    
    return warnings
```

**Requirements**:
- [ ] Wraps LangChain `Tool` objects
- [ ] Wraps plain callables
- [ ] Checks tool is in warrant's `tools` allowlist
- [ ] Checks constraints are satisfied
- [ ] Creates and verifies PoP automatically (with nonce)
- [ ] **Critical tools ALWAYS require ≥1 constraint** (not controlled by strict)
- [ ] High-risk tools warn if unconstrained (even without strict)
- [ ] `strict=True` fails on any `require_at_least_one` tool without constraints
- [ ] Pass-through controlled by env var + always audited
- [ ] `inplace=True` by default (mutates input list)
- [ ] Type check rejects non-list inputs when inplace=True

**Helper functions**:
- [ ] `recommended_constraints(tools)` - prints what constraints to add
- [ ] `check_constraints(tools, warrant)` - returns list of warnings

#### Alternative: Decorator API

For users defining their own tools, a decorator avoids the return-value pitfall entirely:

```python
# protect.py

def protected_tool(fn: Callable = None, *, strict: bool = False):
    """
    Decorator to protect a single tool function.
    
    Usage:
        @protected_tool
        def read_file(path: str) -> str:
            ...
        
        @protected_tool(strict=True)
        def send_email(to: str, body: str) -> None:
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapped(*args, **kwargs):
            warrant = get_warrant()
            keypair = get_keypair()
            tool_name = func.__name__
            
            if warrant is None:
                if _allow_passthrough():
                    _audit_passthrough(tool_name, kwargs)
                    return await _maybe_await(func(*args, **kwargs))
                raise TenuoAuthError(f"No warrant in context for tool: {tool_name}")
            
            # Check tool is in allowlist
            if warrant.tools and tool_name not in warrant.tools:
                raise TenuoToolError(tool=tool_name, authorized=warrant.tools)
            
            # Create PoP signature
            pop = warrant.create_pop(keypair, tool_name, kwargs)
            
            # Authorize
            warrant.authorize(tool_name, kwargs, pop)
            
            # Execute
            return await _maybe_await(func(*args, **kwargs))
        
        return wrapped
    
    if fn is not None:
        return decorator(fn)
    return decorator
```

Usage:
```python
# No return value to forget
@protected_tool
def read_file(path: str) -> str:
    return open(path).read()

@protected_tool(strict=True)
def send_email(to: str, body: str) -> None:
    ...
```

---

### 6. Tool Schemas

```python
# schemas.py

@dataclass
class ToolSchema:
    recommended_constraints: List[str]
    require_at_least_one: bool = False
    risk_level: str = "medium"  # low, medium, high, critical


TOOL_SCHEMAS: Dict[str, ToolSchema] = {
    "read_file": ToolSchema(
        recommended_constraints=["path"],
        require_at_least_one=True,
        risk_level="medium",
    ),
    "write_file": ToolSchema(
        recommended_constraints=["path"],
        require_at_least_one=True,
        risk_level="high",
    ),
    "send_email": ToolSchema(
        recommended_constraints=["to", "domain"],
        require_at_least_one=True,
        risk_level="high",
    ),
    "query_db": ToolSchema(
        recommended_constraints=["table", "query_type"],
        require_at_least_one=True,
        risk_level="high",
    ),
    "http_request": ToolSchema(
        recommended_constraints=["url", "domain", "method"],
        require_at_least_one=True,
        risk_level="critical",
    ),
}


def register_schema(tool_name: str, schema: ToolSchema) -> None:
    """Register a custom tool schema."""
    TOOL_SCHEMAS[tool_name] = schema
```

**Requirements**:
- [ ] Built-in schemas for common tools
- [ ] `recommended_constraints`: what to constrain
- [ ] `require_at_least_one`: must have at least one constraint
- [ ] `risk_level`: low/medium/high/critical
- [ ] `register_schema()` for custom tools

---

### 7. Configuration

```python
# config.py

@dataclass
class TenuoConfig:
    issuer_keypair: Optional[SigningKey] = None
    default_ttl: int = 300
    allow_passthrough: bool = False
    passthrough_hook: Optional[Callable] = None
    trusted_roots: List[PublicKey] = field(default_factory=list)
    dev_mode: bool = False
    allow_self_signed_for_testing: bool = False  # Shameful name intentional


_config: Optional[TenuoConfig] = None


def configure(
    *,
    issuer_key: Optional[str] = None,  # PEM or path
    issuer_key_env: str = "TENUO_ISSUER_KEY",
    default_ttl: int = 300,
    allow_passthrough: bool = False,
    passthrough_hook: Optional[Callable[[Dict], None]] = None,
    trusted_roots: Optional[List[str]] = None,  # PEM strings
    dev_mode: bool = False,
    allow_self_signed_for_testing: bool = False,
) -> None:
    """
    Configure Tenuo globally.
    
    Must be called before using root_task().
    
    Args:
        issuer_key: PEM string or file path for issuer keypair
        issuer_key_env: Env var name for issuer key (default: TENUO_ISSUER_KEY)
        default_ttl: Default TTL for root warrants in seconds
        allow_passthrough: Allow tool execution without warrant (dev only!)
        passthrough_hook: Callback for passthrough events (receives audit dict)
        trusted_roots: List of trusted root public keys (PEM strings)
        dev_mode: Enable dev mode (relaxed validation)
        allow_self_signed_for_testing: Skip trusted_roots check (requires dev_mode!)
    
    Raises:
        TenuoConfigError: If configuration is invalid
    
    Production requirements:
        - trusted_roots MUST be provided (unless dev_mode=True)
        - allow_passthrough requires dev_mode=True
        - allow_self_signed_for_testing requires dev_mode=True
    """
    global _config
    
    # =========================================================================
    # Validate production requirements
    # =========================================================================
    
    # Require trusted_roots in production
    if not trusted_roots and not dev_mode:
        raise TenuoConfigError(
            "trusted_roots required in production. "
            "Provide trusted_roots=[...] or set dev_mode=True for local development."
        )
    
    # allow_passthrough requires dev_mode
    if allow_passthrough and not dev_mode:
        raise TenuoConfigError(
            "allow_passthrough=True requires dev_mode=True. "
            "Passthrough is only permitted in development."
        )
    
    # allow_self_signed_for_testing requires dev_mode
    if allow_self_signed_for_testing and not dev_mode:
        raise TenuoConfigError(
            "allow_self_signed_for_testing=True requires dev_mode=True. "
            "This flag exists for testing only and must not be used in production."
        )
    
    # =========================================================================
    # Load keys
    # =========================================================================
    
    # Load issuer key
    key = issuer_key or os.environ.get(issuer_key_env)
    issuer_keypair = None
    if key:
        issuer_keypair = _load_keypair(key)
    elif not dev_mode:
        logger.warning(
            f"No issuer key configured. Set {issuer_key_env} or pass issuer_key. "
            "root_task() will fail without an issuer key."
        )
    
    # Load trusted roots
    roots = []
    if trusted_roots:
        roots = [_load_public_key(r) for r in trusted_roots]
    
    # =========================================================================
    # Dev mode warnings
    # =========================================================================
    
    if dev_mode:
        logger.warning(
        "[WARNING] TENUO DEV MODE ENABLED - Not for production use. "
        "Strict PoP verification disabled for debug tools."
    )
    
    if allow_self_signed_for_testing:
        logger.warning(
        "[WARNING] allow_self_signed_for_testing=True - Chain verification disabled. "
            "This is a testing-only configuration."
        )
    
    _config = TenuoConfig(
        issuer_keypair=issuer_keypair,
        default_ttl=default_ttl,
        allow_passthrough=allow_passthrough,
        passthrough_hook=passthrough_hook,
        trusted_roots=roots,
        dev_mode=dev_mode,
        allow_self_signed_for_testing=allow_self_signed_for_testing,
    )


def _get_config() -> TenuoConfig:
    """Get config or raise if not configured."""
    if _config is None:
        raise TenuoConfigError("Tenuo not configured. Call configure() first.")
    return _config
```

**Requirements**:
- [ ] Global configuration singleton
- [ ] Issuer key from PEM string, file path, or env var
- [ ] Default TTL for root warrants
- [ ] **`trusted_roots` REQUIRED unless `dev_mode=True`** (error, not warning)
- [ ] **`allow_passthrough` requires `dev_mode=True`** (error, not warning)
- [ ] **`allow_self_signed_for_testing` requires `dev_mode=True`** (shameful name)
- [ ] Clear warnings when dev_mode is enabled
- [ ] Production mode is the secure default

---

### 8. Pass-Through Controls (Hardened)

```python
# passthrough.py

def _allow_passthrough() -> bool:
    """
    Check if pass-through is allowed.
    
    Pass-through is ONLY allowed when:
    1. Not explicitly disabled via TENUO_DISABLE_PASSTHROUGH=true
    2. Config has allow_passthrough=True
    3. Either dev_mode=True OR environment looks like development
    
    This prevents "just set the env var" culture in production.
    """
    # Hard kill switch - overrides everything
    if os.environ.get("TENUO_DISABLE_PASSTHROUGH", "").lower() == "true":
        return False
    
    config = _get_config()
    if not config.allow_passthrough:
        return False
    
    # Only allow in dev mode or dev-like environments
    if config.dev_mode:
        return True
    
    # Auto-detect production and disable
    if _is_production_environment():
        logger.error(
            "Passthrough blocked: production environment detected. "
            "Set dev_mode=True explicitly to allow passthrough in non-production."
        )
        return False
    
    return True


def _is_production_environment() -> bool:
    """Detect if we're in a production environment."""
    env = os.environ.get("ENV", "").lower()
    if env in ("prod", "production"):
        return True
    
    # Python optimization flags suggest production
    if sys.flags.optimize > 0:
        return True
    
    # Common production indicators
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True
    
    return False


def _audit_passthrough(tool: str, args: Dict, reason: Optional[str] = None) -> None:
    """
    Always audit pass-through usage.
    
    Args:
        tool: Tool name being invoked
        args: Tool arguments (will be sanitized)
        reason: Why passthrough is being used (required in strict mode)
    """
    config = _get_config()
    
    event = {
        "type": "passthrough",
        "tool": tool,
        "args": _sanitize_args(args),
        "reason": reason or "NOT_PROVIDED",
        "timestamp": datetime.utcnow().isoformat(),
        "warning": "NO_WARRANT_ENFORCEMENT",
        "dev_mode": config.dev_mode,
    }
    
    # Always log with WARNING level
    logger.warning(f"TENUO_PASSTHROUGH: {json.dumps(event)}")
    
    # Call hook if configured
    if config.passthrough_hook:
        config.passthrough_hook(event)


def require_passthrough_reason(tool: str, args: Dict, reason: str) -> None:
    """
    Explicitly request passthrough with a reason.
    
    Use this when you need to bypass warrant enforcement temporarily
    and want to document why.
    
    Usage:
        if special_case:
            require_passthrough_reason("read_file", args, "Bootstrap config load")
            return read_file(**args)
    """
    if not _allow_passthrough():
        raise TenuoAuthError(
            f"Passthrough not allowed for tool: {tool}. "
            "Enable dev_mode or check TENUO_DISABLE_PASSTHROUGH."
        )
    _audit_passthrough(tool, args, reason)
```

**Requirements**:
- [ ] `TENUO_DISABLE_PASSTHROUGH=true` env var (hard kill switch, overrides everything)
- [ ] `TENUO_ALLOW_PASSTHROUGH` only works with `dev_mode=True`
- [ ] Auto-detect production (ENV=prod, PYTHONOPTIMIZE, K8s) and block
- [ ] Pass-through always audited (never silent)
- [ ] Reason string included in audit event
- [ ] `require_passthrough_reason()` for explicit bypass with documentation

---

### 9. PoP Payload Contract

```python
# pop.py

"""
Proof-of-Possession (PoP) Payload Contract
==========================================

PoP signatures prove the caller holds the private key for the warrant's
authorized_holder. This prevents stolen warrants from being used.

Payload Structure
-----------------
The PoP signature is computed over a CBOR-encoded tuple:

    (warrant_id, tool_name, sorted_args, timestamp_window, nonce)

Where:
- warrant_id: str - The warrant's unique ID
- tool_name: str - Name of the tool being invoked
- sorted_args: List[(str, Any)] - Args sorted by key name
- timestamp_window: int - Unix timestamp rounded to POP_WINDOW_SECS
- nonce: str - Unique per-call nonce (prevents replay within window)

Nonce Generation
----------------
The nonce is generated automatically by the wrapper, combining:
- Warrant ID (scopes the counter)
- Monotonic counter (prevents replay within same process)
- Random bytes (prevents replay across processes)

    nonce = f"{warrant_id}:{counter}:{random_hex}"

This makes replay impractical without requiring:
- Central server coordination
- Developer action
- External state

Timestamp Windows
-----------------
To prevent replay attacks while tolerating clock skew:

- POP_WINDOW_SECS = 30 (configurable)
- Timestamps are rounded: ts // POP_WINDOW_SECS * POP_WINDOW_SECS
- Verifier accepts current window ± 2 windows (~2 min tolerance)

Combined with the nonce, this provides defense in depth:
- Nonce prevents replay within the acceptance window
- Window prevents replay after expiration

Example
-------
    # Automatic (Tier 1) - handled by protect_tools
    @protected_tool
    def read_file(path: str): ...
    
    # Manual (Tier 2)
    nonce = generate_nonce(warrant.id)
    pop = warrant.create_pop(keypair, "read_file", {"path": "/data/x.csv"}, nonce)
    warrant.authorize("read_file", {"path": "/data/x.csv"}, pop, nonce)
"""

import os
from threading import Lock
from typing import Dict

POP_WINDOW_SECS = 30  # Default window size
POP_MAX_WINDOWS = 4   # Accept current ± 2 windows

# Thread-safe nonce generation
_nonce_lock = Lock()
_call_counters: Dict[str, int] = {}


def generate_nonce(warrant_id: str) -> str:
    """
    Generate a unique nonce for PoP signature.
    
    Combines:
    - Warrant ID (scope)
    - Monotonic counter (in-process uniqueness)
    - Random bytes (cross-process uniqueness)
    
    This makes replay impractical without central coordination.
    """
    with _nonce_lock:
        _call_counters[warrant_id] = _call_counters.get(warrant_id, 0) + 1
        counter = _call_counters[warrant_id]
    
    random_hex = os.urandom(8).hex()
    return f"{warrant_id}:{counter}:{random_hex}"


def create_pop(
    warrant: Warrant,
    keypair: SigningKey,
    tool: str,
    args: Dict[str, Any],
    nonce: Optional[str] = None,
    window_secs: int = POP_WINDOW_SECS,
) -> Tuple[Signature, str]:
    """
    Create a Proof-of-Possession signature.
    
    Args:
        warrant: The warrant being used
        keypair: SigningKey matching warrant's authorized_holder
        tool: Tool name being invoked
        args: Tool arguments
        nonce: Optional nonce (generated if not provided)
        window_secs: Timestamp window size (default: 30s)
    
    Returns:
        Tuple of (signature, nonce) - both needed for verification
    """
    # Generate nonce if not provided
    if nonce is None:
        nonce = generate_nonce(warrant.id)
    
    # Sort args for deterministic serialization
    sorted_args = sorted(args.items(), key=lambda x: x[0])
    
    # Compute timestamp window
    now = int(datetime.utcnow().timestamp())
    window_ts = (now // window_secs) * window_secs
    
    # Build payload (now includes nonce)
    payload = (str(warrant.id), tool, sorted_args, window_ts, nonce)
    payload_bytes = cbor2.dumps(payload)
    
    return keypair.sign(payload_bytes), nonce


def verify_pop(
    warrant: Warrant,
    tool: str,
    args: Dict[str, Any],
    signature: Signature,
    nonce: str,
    window_secs: int = POP_WINDOW_SECS,
    max_windows: int = POP_MAX_WINDOWS,
) -> bool:
    """
    Verify a Proof-of-Possession signature.
    
    Checks multiple time windows to handle clock skew.
    
    Args:
        warrant: The warrant being used
        tool: Tool name being invoked
        args: Tool arguments
        signature: PoP signature to verify
        nonce: The nonce used when creating the signature
        window_secs: Timestamp window size
        max_windows: Number of windows to check
    
    Returns:
        True if signature is valid for any recent window
    
    Raises:
        TenuoAuthError: If signature is invalid
    """
    sorted_args = sorted(args.items(), key=lambda x: x[0])
    now = int(datetime.utcnow().timestamp())
    
    for i in range(max_windows):
        window_ts = ((now // window_secs) - i) * window_secs
        payload = (str(warrant.id), tool, sorted_args, window_ts, nonce)
        payload_bytes = cbor2.dumps(payload)
        
        if warrant.authorized_holder.verify(payload_bytes, signature):
            return True
    
    raise TenuoAuthError("Proof-of-Possession failed: invalid or expired signature")
```

**Requirements**:
- [ ] PoP payload: `(warrant_id, tool, sorted_args, timestamp_window, nonce)`
- [ ] Nonce generated per-call by wrapper (monotonic counter + random)
- [ ] 30-second windows, 4 windows accepted (~2 min tolerance)
- [ ] Deterministic serialization (sorted args, CBOR)
- [ ] `create_pop()` returns `(signature, nonce)` tuple
- [ ] `verify_pop()` requires nonce parameter
- [ ] Thread-safe nonce generation
- [ ] Automatic in Tier 1 via `protect_tools`

---

### 10. Error Handling & explain()

```python
# exceptions.py

class TenuoError(Exception):
    """Base Tenuo exception."""
    pass


class TenuoConfigError(TenuoError):
    """Configuration error (missing key, invalid config)."""
    pass


class TenuoAuthError(TenuoError):
    """Authorization failed."""
    
    def __init__(self, message: str, context: Optional[Dict] = None):
        super().__init__(message)
        self.context = context or {}


class TenuoConstraintError(TenuoAuthError):
    """Constraint not satisfied."""
    
    def __init__(self, field: str, reason: str, requested: Any = None, allowed: Any = None):
        self.field = field
        self.reason = reason
        self.requested = requested
        self.allowed = allowed
        super().__init__(
            f"Constraint violation on '{field}': {reason}",
            context={"field": field, "requested": requested, "allowed": allowed}
        )


class TenuoExpiredError(TenuoAuthError):
    """Warrant expired."""
    
    def __init__(self, expired_at: datetime):
        self.expired_at = expired_at
        super().__init__(
            f"Warrant expired at {expired_at}",
            context={"expired_at": expired_at.isoformat()}
        )


class TenuoToolError(TenuoAuthError):
    """Tool not authorized."""
    
    def __init__(self, tool: str, authorized: List[str]):
        self.tool = tool
        self.authorized = authorized
        super().__init__(
            f"Tool '{tool}' not in allowlist. Authorized: {authorized}",
            context={"tool": tool, "authorized": authorized}
        )


# explain.py

def explain(error: TenuoError) -> None:
    """
    Print a detailed, actionable explanation of an authorization error.
    
    Usage:
        try:
            await read_file(path="/etc/passwd")
        except TenuoError as e:
            explain(e)
    
    Output:
        [X] Authorization failed
        
        Tool: read_file
        
        Constraint violated: path
          Requested: /etc/passwd
          Allowed:   /data/*
        
        How to fix:
          • Use a path matching: /data/*
          • Or request broader scope from root_task()
    """
    print("[X] Authorization failed\n")
    
    if isinstance(error, TenuoToolError):
        print(f"Tool: {error.tool}")
        print(f"\nTool not in allowlist.")
        print(f"  Authorized tools: {error.authorized}")
        print(f"\nHow to fix:")
        print(f"  • Add '{error.tool}' to root_task(tools=[...])")
        print(f"  • Or use one of: {', '.join(error.authorized)}")
    
    elif isinstance(error, TenuoConstraintError):
        print(f"Tool: (see context)")
        print(f"\nConstraint violated: {error.field}")
        if error.requested:
            print(f"  Requested: {error.requested}")
        if error.allowed:
            print(f"  Allowed:   {error.allowed}")
        print(f"\nHow to fix:")
        if error.allowed:
            print(f"  • Use a value matching: {error.allowed}")
        print(f"  • Or request broader scope from root_task()")
    
    elif isinstance(error, TenuoExpiredError):
        print(f"Warrant expired at: {error.expired_at}")
        print(f"\nHow to fix:")
        print(f"  • Create a new root_task() with fresh TTL")
        print(f"  • Or increase TTL in original root_task()")
    
    else:
        print(f"Error: {error}")
        if hasattr(error, 'context') and error.context:
            print(f"\nContext: {json.dumps(error.context, indent=2)}")
```

**Requirements**:
- [ ] All exceptions carry structured context
- [ ] `explain(e)` prints human-readable diagnosis
- [ ] Shows what was requested vs what was allowed
- [ ] Provides actionable fix suggestions
- [ ] Works for all error types

---

### 11. Audit Logging

```python
# audit.py

def audit_authorization(
    warrant: Warrant,
    tool: str,
    args: Dict,
    result: str,  # "allowed" | "denied"
    reason: Optional[str] = None,
) -> None:
    """Log authorization decision for audit trail."""
    event = {
        "type": "authorization",
        "warrant_id": str(warrant.id),
        "tool": tool,
        "args": _sanitize_args(args),
        "result": result,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
        "depth": warrant.depth,
        "tools_allowed": warrant.tools,
        "expires_at": warrant.expires_at.isoformat(),
    }
    
    if result == "allowed":
        logger.info(f"TENUO_AUDIT: {json.dumps(event)}")
    else:
        logger.warning(f"TENUO_AUDIT: {json.dumps(event)}")


def _sanitize_args(args: Dict) -> Dict:
    """Remove sensitive values from args for logging."""
    sensitive_keys = {"password", "secret", "token", "key", "credential", "auth"}
    return {
        k: "[REDACTED]" if any(s in k.lower() for s in sensitive_keys) else v
        for k, v in args.items()
    }
```

---

## Framework Integrations

### LangChain Integration

```python
# integrations/langchain.py

def protect_langchain_tools(tools: List[BaseTool], **kwargs) -> List[BaseTool]:
    """Wrap LangChain tools with Tenuo authorization."""
    return [TenuoTool(t, **kwargs) for t in tools]


class TenuoTool(BaseTool):
    """LangChain tool wrapper that enforces warrant authorization."""
    
    def __init__(self, wrapped: BaseTool, strict: bool = False):
        super().__init__(
            name=wrapped.name,
            description=wrapped.description,
        )
        self.wrapped = wrapped
        self.strict = strict
    
    def _run(self, *args, **kwargs):
        _check_authorization(self.name, kwargs)
        return self.wrapped._run(*args, **kwargs)
    
    async def _arun(self, *args, **kwargs):
        _check_authorization(self.name, kwargs)
        return await self.wrapped._arun(*args, **kwargs)
```

### LangGraph Integration

```python
# integrations/langgraph.py

def tenuo_node(
    tools: List[str],
    **constraints
) -> Callable:
    """
    Decorator for LangGraph nodes that scopes authority.
    
    Usage:
        @tenuo_node(tools=["read_file"], path="/data/*")
        async def researcher(state):
            ...
    """
    def decorator(fn):
        @wraps(fn)
        async def wrapped(state):
            async with scoped_task(tools=tools, **constraints):
                return await fn(state)
        return wrapped
    return decorator
```

---

## File Structure

```
tenuo/
├── __init__.py          # Public API exports
├── config.py            # Global configuration
├── context.py           # Context variables
├── constraints.py       # Tier 1 constraint types & algebra
├── scoped.py            # root_task, scoped_task, preview
├── protect.py           # protect_tools, protected_tool, recommended_constraints
├── schemas.py           # Tool schemas
├── passthrough.py       # Pass-through controls
├── pop.py               # PoP payload contract & nonce
├── audit.py             # Audit logging
├── exceptions.py        # Error types
├── explain.py           # explain() helper
└── integrations/
    ├── __init__.py
    ├── langchain.py     # LangChain integration
    └── langgraph.py     # LangGraph integration
```

---

## Public API (`__init__.py`)

```python
# Tier 1 (simple)
from .scoped import root_task, scoped_task
from .protect import protect_tools, protected_tool, recommended_constraints, check_constraints
from .config import configure

# Tier 2 (explicit)
from .warrant import Warrant
from .crypto import SigningKey
from .context import get_warrant, set_warrant, get_keypair, set_keypair
from .pop import create_pop, verify_pop, generate_nonce
from .constraints import PrefixGlob, SuffixMatch, Exact, OneOf, Range

# Integrations
from .integrations.langchain import protect_langchain_tools
from .integrations.langgraph import tenuo_node

# Exceptions & debugging
from .exceptions import (
    TenuoError,
    TenuoConfigError,
    TenuoAuthError,
    TenuoConstraintError,
    TenuoExpiredError,
    TenuoToolError,
)
from .explain import explain

__all__ = [
    # Tier 1
    "root_task",
    "scoped_task",
    "protect_tools",
    "protected_tool",
    "recommended_constraints",
    "check_constraints",
    "configure",
    # Tier 2
    "Warrant",
    "SigningKey",
    "get_warrant",
    "set_warrant",
    "get_keypair",
    "set_keypair",
    "create_pop",
    "verify_pop",
    "generate_nonce",
    # Tier 1 constraint types
    "PrefixGlob",
    "SuffixMatch",
    "Exact",
    "OneOf",
    "Range",
    # Integrations
    "protect_langchain_tools",
    "tenuo_node",
    # Exceptions & debugging
    "TenuoError",
    "TenuoConfigError",
    "TenuoAuthError",
    "TenuoConstraintError",
    "TenuoExpiredError",
    "TenuoToolError",
    "explain",
]
```

---

## Test Cases

```python
# tests/test_root_task.py

async def test_root_task_creates_warrant():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT], dev_mode=False)
    async with root_task(tools=["read_file"], path="/data/*") as warrant:
        assert "read_file" in warrant.tools
        assert get_warrant() == warrant

async def test_root_task_requires_issuer_key():
    configure(trusted_roots=[TEST_ROOT], dev_mode=False)  # No issuer key
    with pytest.raises(TenuoConfigError, match="no issuer key"):
        async with root_task(tools=["read_file"]):
            pass

async def test_root_task_issuer_equals_holder_by_default():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT], dev_mode=False)
    async with root_task(tools=["read_file"], path="/data/*") as warrant:
        # In Tier 1, issuer == holder
        keypair = get_keypair()
        assert warrant.holder == keypair.public_key

async def test_root_task_explicit_holder():
    configure(issuer_key=ISSUER_KEY, trusted_roots=[TEST_ROOT], dev_mode=False)
    async with root_task(tools=["read_file"], holder_key=WORKER_KEY) as warrant:
        # Holder is different from issuer
        assert warrant.holder == WORKER_KEY.public_key
        assert get_keypair() == WORKER_KEY  # Context has holder key


# tests/test_configure.py

def test_configure_requires_trusted_roots_in_production():
    with pytest.raises(TenuoConfigError, match="trusted_roots required"):
        configure(issuer_key=TEST_KEY, dev_mode=False)  # No trusted_roots

def test_configure_allows_no_trusted_roots_in_dev_mode():
    # Should not raise
    configure(issuer_key=TEST_KEY, dev_mode=True)

def test_configure_passthrough_requires_dev_mode():
    with pytest.raises(TenuoConfigError, match="requires dev_mode"):
        configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT], allow_passthrough=True)

def test_configure_self_signed_requires_dev_mode():
    with pytest.raises(TenuoConfigError, match="requires dev_mode"):
        configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT], 
                  allow_self_signed_for_testing=True)


# tests/test_scoped_task.py

async def test_scoped_task_requires_parent():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    with pytest.raises(TenuoAuthError, match="requires a parent"):
        async with scoped_task(tools=["read_file"]):
            pass

async def test_scoped_task_attenuates_parent():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    async with root_task(tools=["read_file", "write_file"], path="/data/*") as parent:
        async with scoped_task(tools=["read_file"], path="/data/reports/*") as child:
            assert child.depth == parent.depth + 1
            assert child.tools == ["read_file"]
            assert "write_file" not in child.tools

async def test_scoped_task_rejects_tool_not_in_parent():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    async with root_task(tools=["read_file"], path="/data/*"):
        with pytest.raises(TenuoConstraintError, match="not in parent's allowlist"):
            async with scoped_task(tools=["send_email"]):
                pass

async def test_scoped_task_allows_contained_glob():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    async with root_task(tools=["read_file"], path="/data/*") as parent:
        async with scoped_task(tools=["read_file"], path="/data/reports/*") as child:
            # /data/reports/* is contained in /data/*
            assert child.get_constraint("path") == "/data/reports/*"

async def test_scoped_task_rejects_broader_glob():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    async with root_task(tools=["read_file"], path="/data/reports/*"):
        with pytest.raises(TenuoConstraintError, match="not contained"):
            # /data/* is broader than /data/reports/*
            async with scoped_task(tools=["read_file"], path="/data/*"):
                pass

async def test_scoped_task_rejects_different_prefix():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    async with root_task(tools=["read_file"], path="/data/*"):
        with pytest.raises(TenuoConstraintError, match="not contained"):
            # /etc/* has different prefix than /data/*
            async with scoped_task(tools=["read_file"], path="/etc/*"):
                pass

async def test_scoped_task_restores_context():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    async with root_task(tools=["read_file"], path="/data/*") as parent:
        async with scoped_task(tools=["read_file"], path="/data/reports/*"):
            pass
        assert get_warrant() == parent
    assert get_warrant() is None


# tests/test_constraint_algebra.py

def test_prefix_glob_containment():
    assert _is_contained("/data/reports/*", "/data/*") == True
    assert _is_contained("/data/q3.csv", "/data/*") == True
    assert _is_contained("/data/*", "/data/reports/*") == False
    assert _is_contained("/etc/*", "/data/*") == False

def test_suffix_match_containment():
    assert _suffix_match_contains("api.example.com", "*.example.com") == True
    assert _suffix_match_contains("*.api.example.com", "*.example.com") == True
    assert _suffix_match_contains("example.com", "example.com") == True
    assert _suffix_match_contains("other.com", "example.com") == False

def test_oneof_containment():
    parent = OneOf(["a", "b", "c"])
    assert is_contained(OneOf(["a", "b"]), parent) == True
    assert is_contained(OneOf(["a"]), parent) == True
    assert is_contained(OneOf(["a", "b", "c", "d"]), parent) == False

def test_range_containment():
    parent = Range(0, 100)
    assert is_contained(Range(10, 50), parent) == True
    assert is_contained(Range(0, 100), parent) == True
    assert is_contained(Range(-10, 50), parent) == False
    assert is_contained(Range(10, 150), parent) == False


# tests/test_protect_tools.py

async def test_protect_tools_mutates_by_default():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    tools = [read_file, send_email]
    original_id = id(tools)
    result = protect_tools(tools)  # inplace=True by default
    assert id(result) == original_id
    assert id(tools) == original_id

async def test_protect_tools_inplace_false_returns_new_list():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    tools = [read_file, send_email]
    original_id = id(tools)
    result = protect_tools(tools, inplace=False)
    assert id(result) != original_id

async def test_protect_tools_rejects_tuple():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    tools = (read_file, send_email)  # Tuple, not list
    with pytest.raises(TypeError, match="requires a mutable list"):
        protect_tools(tools)  # inplace=True by default

async def test_protect_tools_allows_authorized():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    tools = [read_file]
    protect_tools(tools)
    async with root_task(tools=["read_file"], path="/data/*"):
        result = await tools[0](path="/data/test.txt")
        assert result is not None

async def test_critical_tool_requires_constraint():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    tools = [http_request]  # critical risk level
    protect_tools(tools)
    async with root_task(tools=["http_request"]):  # No constraints!
        with pytest.raises(TenuoConfigError, match="requires at least one constraint"):
            await tools[0](url="http://evil.com")

async def test_critical_tool_passes_with_constraint():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT])
    tools = [http_request]
    protect_tools(tools)
    async with root_task(tools=["http_request"], domain="*.example.com"):
        result = await tools[0](url="http://api.example.com/data")
        assert result is not None


# tests/test_recommended_constraints.py

def test_recommended_constraints_prints_output(capsys):
    tools = [read_file, send_email, http_request]
    recommended_constraints(tools)
    captured = capsys.readouterr()
    assert "http_request" in captured.out
    assert "REQUIRED" in captured.out
    assert "domain" in captured.out


# tests/test_passthrough.py

async def test_passthrough_blocked_in_production():
    configure(issuer_key=TEST_KEY, trusted_roots=[TEST_ROOT], dev_mode=False)
    tools = [read_file]
    protect_tools(tools)
    # No root_task - no warrant in context
    with pytest.raises(TenuoAuthError):
        await tools[0](path="/data/test.txt")

async def test_passthrough_allowed_in_dev_mode():
    configure(issuer_key=TEST_KEY, allow_passthrough=True, dev_mode=True)
    tools = [read_file]
    protect_tools(tools)
    # No root_task - but passthrough is allowed
    result = await tools[0](path="/data/test.txt")  # Should not raise

async def test_passthrough_kill_switch():
    configure(issuer_key=TEST_KEY, allow_passthrough=True, dev_mode=True)
    tools = [read_file]
    protect_tools(tools)
    
    with mock.patch.dict(os.environ, {"TENUO_DISABLE_PASSTHROUGH": "true"}):
        with pytest.raises(TenuoAuthError):
            await tools[0](path="/data/test.txt")


# tests/test_explain.py

def test_explain_constraint_error(capsys):
    error = TenuoConstraintError(
        field="path",
        reason="not within allowed pattern",
        requested="/etc/passwd",
        allowed="/data/*",
    )
    explain(error)
    captured = capsys.readouterr()
    assert "Constraint violated: path" in captured.out
    assert "Requested: /etc/passwd" in captured.out
    assert "Allowed:   /data/*" in captured.out
    assert "How to fix" in captured.out
```

---

## Checkpoint

**"I can use root_task() and scoped_task() in 5 lines"**

```python
from tenuo import configure, root_task, scoped_task, protect_tools

configure(issuer_key_env="TENUO_KEY", trusted_roots=["path/to/root.pem"])
tools = [read_file, send_email]
protect_tools(tools)  # Mutates in place by default

async with root_task(tools=["read_file"], path="/data/*"):
    async with scoped_task(tools=["read_file"], path="/data/reports/*"):
        result = await agent.run(tools, "Summarize the Q3 report")
```

Or with decorator (for custom tools):

```python
from tenuo import configure, root_task, scoped_task, protected_tool

configure(issuer_key_env="TENUO_KEY", trusted_roots=["path/to/root.pem"])

@protected_tool
def read_file(path: str) -> str:
    return open(path).read()

async with root_task(tools=["read_file"], path="/data/*"):
    async with scoped_task(tools=["read_file"], path="/data/reports/*"):
        content = await read_file(path="/data/reports/q3.csv")
```

With preview:
```python
async with root_task(tools=["read_file", "write_file"], path="/data/*"):
    scope = scoped_task(tools=["read_file"], path="/data/reports/*")
    scope.preview().print()
    # Output:
    # Derived scope:
    #   Tools: ['read_file']
    #     (narrowed from ['read_file', 'write_file'])
    #   Constraints:
    #     path: /data/reports/* (narrowed from /data/*)
    #   TTL: 300s
    #   Depth: 1
    
    async with scope:
        ...
```

Check constraints before running:
```python
from tenuo import recommended_constraints

tools = [read_file, send_email, http_request]
recommended_constraints(tools)
# Output:
#   http_request: ⚠️  REQUIRED (critical) - domain, url, method
#   send_email: ⚠️  recommended (high) - to, domain
#   read_file: recommended (medium) - path
```

---

## Implementation Order

| # | Component | Estimate |
|---|-----------|----------|
| 1 | `context.py` — Context variables | 30 min |
| 2 | `exceptions.py` — Error types with context | 45 min |
| 3 | `constraints.py` — Tier 1 constraint algebra | 2 hours |
| 4 | `config.py` — Configuration with strict validation | 1.5 hours |
| 5 | `passthrough.py` — Hardened passthrough | 1 hour |
| 6 | `pop.py` — PoP payload contract with nonce | 1.5 hours |
| 7 | `scoped.py` — root_task, scoped_task, preview | 3 hours |
| 8 | `protect.py` — protect_tools + decorator + helpers | 2.5 hours |
| 9 | `schemas.py` — Tool schemas | 45 min |
| 10 | `audit.py` — Audit logging | 45 min |
| 11 | `explain.py` — explain() helper | 1 hour |
| 12 | `integrations/langchain.py` — LangChain | 1.5 hours |
| 13 | `integrations/langgraph.py` — LangGraph | 1 hour |
| 14 | Tests | 3.5 hours |

**Total: ~21 hours**

---

## Summary of Changes from v1

| Change | Rationale |
|--------|-----------|
| `tool: str` → `tools: List[str]` | Allowlist semantics, not single-tool label |
| Split `root_task()` / `scoped_task()` | No silent root minting |
| `scoped_task()` errors without parent | Explicit authority flow |
| Containment-based narrowing (Tier 1) | Simpler mental model than intersection |
| **Tier 1 constraint algebra** | Closed set: PrefixGlob, SuffixMatch, Exact, OneOf, Range |
| Simple glob patterns only (Tier 1) | Predictable; complex patterns use Tier 2 |
| `preview()` method | Debug before execution |
| `explain(e)` helper | "Why did this fail?" |
| Hardened passthrough | dev-only, reason string, kill switch |
| **`trusted_roots` required** (not warning) | Error unless dev_mode=True |
| **`allow_passthrough` requires dev_mode** | Error, not warning |
| **`allow_self_signed_for_testing`** | Shameful name for testing-only flag |
| **Issuer == holder documented** | Clear that Tier 1 is single-process mode |
| **`holder_key` parameter on root_task** | Explicit holder for multi-process |
| **PoP includes nonce** | Prevents replay within time window |
| **`inplace=True` by default** | Removes "forgot return value" footgun |
| **Critical tools require constraint** | Not controlled by strict flag |
| **`recommended_constraints()` helper** | Shows what constraints to add |
| PoP payload contract documented | Clear security properties |
| Exceptions carry structured context | Better debugging |
| `inplace=True` type check | Prevents runtime errors with tuples/immutable containers |
