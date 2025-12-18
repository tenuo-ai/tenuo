"""
Scoped task context managers for Tenuo Tier 1 API.

Provides root_task() and scoped_task() for easy warrant management.

Usage:
    from tenuo import configure, root_task, scoped_task, protect_tools
    
    # Configure once at startup
    configure(issuer_key=my_keypair, trusted_roots=[root_key])
    
    # Protect your tools
    tools = [read_file, send_email]
    protect_tools(tools)
    
    # Use scoped authority
    async with root_task(tools=["read_file"], path="/data/*"):
        async with scoped_task(path="/data/reports/*"):
            result = await agent.run(tools, "Summarize reports")
"""

from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, AsyncIterator, Iterator, Union
from contextvars import Token

from tenuo_core import (  # type: ignore[import-untyped]
    Warrant,
    SigningKey,
    Pattern,
    Exact,
    OneOf,
    Range,
    Regex,
    Wildcard,
    NotOneOf,
)

from .config import get_config, ConfigurationError
from .decorators import (
    _warrant_context,
    _keypair_context,
    _allowed_tools_context,
    get_warrant_context,
    get_signing_key_context,
)
from .exceptions import (
    ScopeViolation,
    ConstraintViolation,
    MonotonicityError,
)


# Type alias for constraints
Constraint = Union[Pattern, Exact, OneOf, Range, Regex, Wildcard, NotOneOf, str, int, float, List[str]]


def _ensure_constraint(key: str, value: Any) -> Any:
    """
    Ensure value is a constraint object, wrapping in Exact if not.
    
    NO TYPE INFERENCE is performed.
    - "foo*" is Exact("foo*"), NOT Pattern("foo*")
    - [1, 2] is Exact([1, 2]), NOT OneOf([1, 2])
    
    To use broader constraints, you must explicitly construct them:
    - Pattern("foo*")
    - OneOf([1, 2])
    """
    # Already a constraint object
    if hasattr(value, '__class__') and value.__class__.__name__ in (
        'Pattern', 'Exact', 'OneOf', 'Range', 'NotOneOf', 'Contains', 'Subset', 'Regex', 'Wildcard', 'All', 'AnyOf', 'Not', 'CEL'
    ):
        return value
    
    # Default: Exact match
    # We wrap everything else in Exact to be safe and explicit
    return Exact(str(value)) if not isinstance(value, (int, float, bool)) else Exact(value)


def _extract_pattern_value(value: Any) -> str:
    """Extract the actual pattern string from a constraint value."""
    s = str(value)
    # Handle Pattern('...') wrapper
    if s.startswith("Pattern('") and s.endswith("')"):
        return s[9:-2]
    # Handle Exact('...') wrapper
    if s.startswith("Exact('") and s.endswith("')"):
        return s[7:-2]
    return s


def _is_constraint_contained(child_value: Any, parent_value: Any) -> bool:
    """
    Check if child constraint is contained within parent.
    
    Tier 1 API Containment Rules (Python-side validation for scoped_task):
    
    Universal Containment:
    - Wildcard -> Any: Wildcard parent contains everything (universal superset)
    - Any -> Wildcard: NEVER allowed (would widen permissions)
    
    Same-Type Containment:
    - Pattern -> Pattern: child pattern must be more restrictive (more literal chars)
    - Regex -> Regex: patterns must be IDENTICAL (subset is undecidable)
    - Exact -> Exact: values must be equal
    - OneOf -> OneOf: child must be a subset of parent
    - Range -> Range: child bounds must be within parent bounds
    - string -> string: values must be equal (fallback)
    
    Cross-Type Containment:
    - Pattern -> Exact: exact value must match parent pattern (glob)
    - Pattern -> string: string value must match parent pattern (glob)
    - Regex -> Exact: exact value must match parent regex
    - Regex -> string: string value must match parent regex
    - OneOf -> Exact: exact value must be in parent's set
    - OneOf -> string: string value must be in parent's set
    
    Not Supported in Tier 1 (use Tier 2 API for full validation):
    - NotOneOf, Contains, Subset, All, CEL
    
    Returns:
        True if child is contained within parent, False otherwise.
    """
    import fnmatch
    import re
    
    # Get constraint type names
    child_type = type(child_value).__name__
    parent_type = type(parent_value).__name__
    
    # =========================================================================
    # Wildcard - Universal superset (must check FIRST)
    # =========================================================================
    # Wildcard parent contains ANYTHING
    if parent_type == 'Wildcard':
        return True
    
    # NOTHING can attenuate TO Wildcard (would expand permissions)
    if child_type == 'Wildcard':
        return False
    
    # Extract actual values from wrappers
    child_str = _extract_pattern_value(child_value)
    parent_str = _extract_pattern_value(parent_value)
    
    # =========================================================================
    # Regex - Must be identical pattern or Exact that matches
    # =========================================================================
    if parent_type == 'Regex':
        parent_pattern = getattr(parent_value, 'pattern', None)
        if parent_pattern is None:
            return False
        
        if child_type == 'Regex':
            # Regex -> Regex: must be IDENTICAL (subset is undecidable)
            child_pattern = getattr(child_value, 'pattern', None)
            return parent_pattern == child_pattern
        else:
            # Regex -> Exact/string: value must match regex
            try:
                return bool(re.match(parent_pattern, child_str))
            except re.error:
                return False
    
    # =========================================================================
    # Pattern/glob containment - use fnmatch for proper glob matching
    # =========================================================================
    if parent_type == 'Pattern' or '*' in parent_str:
        if child_type == 'Pattern' or '*' in child_str:
            # Both are patterns - child must be more restrictive
            # A pattern is more restrictive if it has more literal characters
            # or matches a subset of what the parent matches
            child_literal = child_str.replace('*', '')
            parent_literal = parent_str.replace('*', '')
            
            # Child's literal parts must contain parent's literal parts
            # e.g., "*@company.com" contains "@company.com"
            # and "/data/reports/*" is more restrictive than "/data/*"
            if parent_literal in child_literal or child_literal.startswith(parent_literal):
                return True
            
            # Also check if child pattern would only match things parent matches
            # by checking if the non-wildcard parts align
            return len(child_literal) >= len(parent_literal) and parent_literal in child_literal
        else:
            # Child is exact value - must match parent pattern using glob
            return fnmatch.fnmatch(child_str, parent_str)
    
    # OneOf containment - check BEFORE Exact since Exact can be inside OneOf
    if parent_type == 'OneOf':
        parent_values = set(getattr(parent_value, 'values', []))
        if child_type == 'OneOf':
            # Child OneOf must be subset of parent OneOf
            child_values = set(getattr(child_value, 'values', []))
            return child_values.issubset(parent_values)
        elif child_type == 'Exact':
            # Exact value must be in the parent's OneOf set
            return child_str in parent_values
        else:
            # Plain string value must be in the parent's OneOf set
            return child_str in parent_values
    
    # Exact containment - must be equal (both Exact or one is Exact)
    if parent_type == 'Exact' or child_type == 'Exact':
        return child_str == parent_str
    
    # Range containment
    if parent_type == 'Range' and child_type == 'Range':
        p_min = getattr(parent_value, 'min', None)
        p_max = getattr(parent_value, 'max', None)
        c_min = getattr(child_value, 'min', None)
        c_max = getattr(child_value, 'max', None)
        
        min_ok = p_min is None or (c_min is not None and c_min >= p_min)
        max_ok = p_max is None or (c_max is not None and c_max <= p_max)
        return min_ok and max_ok
    
    # Fallback: string equality
    return child_str == parent_str


@dataclass
class ScopePreview:
    """Preview of derived scope before execution."""
    tools: Optional[List[str]] = None
    parent_tools: Optional[List[str]] = None
    constraints: Optional[Dict[str, Any]] = None
    parent_constraints: Optional[Dict[str, Any]] = None
    ttl: Optional[int] = None
    parent_ttl: Optional[int] = None
    depth: Optional[int] = None
    error: Optional[str] = None
    
    def print(self) -> None:
        """Pretty-print the preview."""
        if self.error:
            print(f"❌ Cannot create scope: {self.error}")
            return
        
        print("Derived scope:")
        print(f"  Tools: {self.tools}")
        if self.parent_tools and self.tools != self.parent_tools:
            dropped = set(self.parent_tools) - set(self.tools or [])
            if dropped:
                print(f"    (dropped: {dropped})")
        
        print("  Constraints:")
        for key, value in (self.constraints or {}).items():
            parent_val = (self.parent_constraints or {}).get(key)
            if parent_val and str(parent_val) != str(value):
                print(f"    {key}: {value} (narrowed from {parent_val})")
            else:
                print(f"    {key}: {value}")
        
        if self.ttl:
            print(f"  TTL: {self.ttl}s", end="")
            if self.parent_ttl and self.ttl != self.parent_ttl:
                print(f" (reduced from {self.parent_ttl}s)")
            else:
                print()
        
        if self.depth is not None:
            print(f"  Depth: {self.depth}")


class ScopedTaskBuilder:
    """Builder for scoped_task with preview support."""
    
    def __init__(
        self,
        tools: Optional[List[str]],
        constraints: Dict[str, Any],
        ttl: Optional[int],
    ):
        self.tools = tools
        self.constraints = constraints
        self.ttl = ttl
    
    def preview(self) -> ScopePreview:
        """Preview the derived scope without executing."""
        parent = get_warrant_context()
        
        if parent is None:
            return ScopePreview(
                error="No parent warrant. Use root_task() first.",
                tools=self.tools,
                constraints=self.constraints,
            )
        
        try:
            # Validate tools
            parent_tools = parent.tools if parent.tools else []
            child_tools = self.tools if self.tools else parent_tools
            
            invalid_tools = set(child_tools) - set(parent_tools)
            if invalid_tools and parent_tools:
                return ScopePreview(
                    error=f"Tools {invalid_tools} not in parent's allowlist {parent_tools}"
                )
            
            # Get parent constraints
            parent_constraints = {}
            constraints_dict = parent.constraints_dict() if hasattr(parent, 'constraints_dict') else {}
            for k, v in constraints_dict.items():
                parent_constraints[k] = v
            
            # Compute derived constraints
            derived_constraints = dict(parent_constraints)
            for key, child_value in self.constraints.items():
                parent_value = parent_constraints.get(key)
                if parent_value is not None:
                    if not _is_constraint_contained(child_value, parent_value):
                        return ScopePreview(
                            error=f"Constraint '{key}': {child_value} not contained in {parent_value}"
                        )
                derived_constraints[key] = child_value
            
            # Compute TTL
            parent_ttl = None
            if hasattr(parent, 'ttl_remaining'):
                parent_ttl = parent.ttl_remaining()
            
            child_ttl = self.ttl
            if child_ttl and parent_ttl:
                child_ttl = min(child_ttl, parent_ttl)
            elif parent_ttl:
                child_ttl = parent_ttl
            
            return ScopePreview(
                tools=child_tools,
                parent_tools=parent_tools,
                constraints=derived_constraints,
                parent_constraints=parent_constraints,
                ttl=child_ttl,
                parent_ttl=parent_ttl,
                depth=parent.depth + 1,
            )
        except Exception as e:
            return ScopePreview(error=str(e))
    
    async def __aenter__(self) -> Warrant:
        """Enter the scoped context (async)."""
        return await _enter_scoped_task(self.tools, self.constraints, self.ttl)
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the scoped context (async)."""
        _exit_scoped_task()
    
    def __enter__(self) -> Warrant:
        """Enter the scoped context (sync)."""
        import asyncio
        try:
            asyncio.get_running_loop()
            raise RuntimeError(
                "Cannot use sync 'with scoped_task()' in async context. "
                "Use 'async with scoped_task()' instead."
            )
        except RuntimeError:
            pass
        return _enter_scoped_task_sync(self.tools, self.constraints, self.ttl)
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the scoped context (sync)."""
        _exit_scoped_task()


class _ScopedTaskContext:
    """Holds context tokens for proper restoration on exit."""
    
    def __init__(self, warrant_token: Token, allowed_tools_token: Optional[Token] = None):
        self.warrant_token = warrant_token
        self.allowed_tools_token = allowed_tools_token


# Stack of scoped task contexts for proper nesting
_scoped_task_stack: List[_ScopedTaskContext] = []


async def _enter_scoped_task(
    tools: Optional[List[str]],
    constraints: Dict[str, Any],
    ttl: Optional[int],
) -> Warrant:
    """Enter scoped task context (async version)."""
    return _enter_scoped_task_sync(tools, constraints, ttl)


def _enter_scoped_task_sync(
    tools: Optional[List[str]],
    constraints: Dict[str, Any],
    ttl: Optional[int],
) -> Warrant:
    """Enter scoped task context (sync version)."""
    parent = get_warrant_context()
    keypair = get_signing_key_context()
    
    if parent is None:
        raise ScopeViolation(
            "scoped_task() requires a parent warrant. "
            "Use root_task() to create initial authority, then scoped_task() to narrow it."
        )
    
    if keypair is None:
        raise ConfigurationError("No keypair in context.")
    
    # Build attenuated warrant
    builder = parent.attenuate_builder()
    
    # Apply tool restriction
    if tools:
        # Get allowed tools from context (set by outer scoped_task) or warrant
        current_allowed = _allowed_tools_context.get()
        if current_allowed is not None:
            # Check against the context's allowed tools (nested scoped_task)
            parent_tools = current_allowed
        elif parent.tools:
            # Fall back to warrant's tool field
            parent_tools = parent.tools
        else:
            parent_tools = []
        
        # Check that all requested tools are in parent's allowlist
        if parent_tools:
            for tool in tools:
                if tool not in parent_tools:
                    raise ConstraintViolation(
                        field="tools",
                        reason=f"Tool '{tool}' not in parent's allowlist {parent_tools}",
                        value=str(tools),
                    )
    
    # Apply constraints with containment validation
    parent_constraints = {}
    if hasattr(parent, 'constraints_dict'):
        pc = parent.constraints_dict()
        if pc is not None:
            parent_constraints = dict(pc)
    
    for key, child_value in constraints.items():
        inferred = _ensure_constraint(key, child_value)
        parent_value = parent_constraints.get(key)
        
        if parent_value is not None:
            if not _is_constraint_contained(inferred, parent_value):
                raise MonotonicityError(
                    f"Constraint '{key}': '{child_value}' is not contained within "
                    f"parent's '{parent_value}'"
                )
        
        builder.with_constraint(key, inferred)
    
    # Apply TTL
    if ttl:
        builder.with_ttl(ttl)
    
    # Build child warrant
    try:
        child = builder.delegate_to(keypair, keypair)
    except Exception as e:
        raise MonotonicityError(f"Failed to attenuate warrant: {e}") from e
    
    # Set in context and save token for restoration
    warrant_token = _warrant_context.set(child)
    
    # Set allowed tools if specified (for narrowing beyond warrant.tools)
    allowed_tools_token = None
    if tools:
        allowed_tools_token = _allowed_tools_context.set(tools)
    
    _scoped_task_stack.append(_ScopedTaskContext(warrant_token, allowed_tools_token))
    
    return child


def _exit_scoped_task() -> None:
    """Exit scoped task context."""
    if _scoped_task_stack:
        ctx = _scoped_task_stack.pop()
        _warrant_context.reset(ctx.warrant_token)
        if ctx.allowed_tools_token is not None:
            _allowed_tools_context.reset(ctx.allowed_tools_token)


def scoped_task(
    *,
    tools: Optional[List[str]] = None,
    ttl: Optional[int] = None,
    **constraints: Any,
) -> ScopedTaskBuilder:
    """
    Create a scoped task that attenuates the current warrant.
    
    MUST be called within a root_task() or another scoped_task().
    Cannot mint new authority - only narrow existing authority.
    
    Args:
        tools: Subset of parent's tools (None = inherit)
        ttl: Shorter TTL in seconds (None = inherit remaining)
        **constraints: Additional constraints (must be contained within parent's)
    
    Returns:
        ScopedTaskBuilder that can be used as context manager or previewed
    
    Raises:
        ScopeViolation: If no parent warrant in context
        MonotonicityError: If constraints aren't contained within parent's
    
    Example:
        async with root_task(tools=["read_file"], path="/data/*"):
            async with scoped_task(path="/data/reports/*"):
                # Narrower scope here
                result = await agent.run(...)
            
            # Preview before entering
            scope = scoped_task(path="/data/reports/*")
            scope.preview().print()
            async with scope:
                ...
    """
    return ScopedTaskBuilder(tools, constraints, ttl)


@asynccontextmanager
async def root_task(
    *,
    tools: List[str],
    ttl: Optional[int] = None,
    holder_key: Optional[SigningKey] = None,
    **constraints: Any,
) -> AsyncIterator[Warrant]:
    """
    Create a root warrant (explicit authority minting).
    
    This is the ONLY way to mint new authority in Tier 1.
    Use scoped_task() to attenuate within a root_task block.
    
    Args:
        tools: Allowlist of tools this warrant authorizes (one tool per warrant)
        ttl: Time-to-live in seconds (default from configure())
        holder_key: Explicit holder keypair (default: issuer key)
        **constraints: Constraint kwargs applied to the tool
    
    Raises:
        ConfigurationError: If no issuer key configured
    
    Example:
        async with root_task(tools=["read_file"], path="/data/*") as warrant:
            # warrant is now in context
            result = await protected_read_file(path="/data/report.csv")
    
    Note:
        In Tier 1, issuer == holder by default. For multi-process delegation,
        provide holder_key explicitly or use Tier 2 APIs (Warrant.builder()).
    """
    config = get_config()
    
    if config.issuer_keypair is None:
        raise ConfigurationError(
            "Cannot create root warrant: no issuer key configured. "
            "Call configure(issuer_key=...) first."
        )
    
    issuer = config.issuer_keypair
    holder = holder_key or issuer
    effective_ttl = ttl or config.default_ttl
    
    if not tools:
        raise ConfigurationError("root_task requires at least one tool")
    
    
    # Build constraints dict
    constraint_dict = {}
    for key, value in constraints.items():
        constraint_dict[key] = _ensure_constraint(key, value)
    
    # Issue the warrant
    # Issue the warrant
    warrant = Warrant.issue(
        tools=tools,
        keypair=issuer,
        constraints=constraint_dict if constraint_dict else None,
        ttl_seconds=effective_ttl,
        holder=holder.public_key if holder != issuer else None,
    )
    
    # Set in context
    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)
    
    try:
        yield warrant
    finally:
        _warrant_context.reset(warrant_token)
        _keypair_context.reset(keypair_token)


@contextmanager
def root_task_sync(
    *,
    tools: List[str],
    ttl: Optional[int] = None,
    holder_key: Optional[SigningKey] = None,
    **constraints: Any,
) -> Iterator[Warrant]:
    """
    Synchronous version of root_task().
    
    Use this when not in an async context.
    
    Example:
        with root_task_sync(tools=["read_file"], path="/data/*") as warrant:
            result = protected_read_file(path="/data/report.csv")
    """
    config = get_config()
    
    if config.issuer_keypair is None:
        raise ConfigurationError(
            "Cannot create root warrant: no issuer key configured. "
            "Call configure(issuer_key=...) first."
        )
    
    issuer = config.issuer_keypair
    holder = holder_key or issuer
    effective_ttl = ttl or config.default_ttl
    
    if not tools:
        raise ConfigurationError("root_task requires at least one tool")
    
    constraint_dict = {}
    for key, value in constraints.items():
        constraint_dict[key] = _ensure_constraint(key, value)
    
    warrant = Warrant.issue(
        tools=tools,
        keypair=issuer,
        constraints=constraint_dict if constraint_dict else None,
        ttl_seconds=effective_ttl,
        holder=holder.public_key if holder != issuer else None,
    )
    
    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)
    
    try:
        yield warrant
    finally:
        _warrant_context.reset(warrant_token)
        _keypair_context.reset(keypair_token)


__all__ = [
    "root_task",
    "root_task_sync",
    "scoped_task",
    "ScopedTaskBuilder",
    "ScopePreview",
]
