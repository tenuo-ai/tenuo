"""
Tool protection for Tenuo Tier 1 API.

Provides protect_tools() to wrap tools with authorization checks,
and protected_tool decorator for custom tools.

Usage:
    from tenuo import configure, root_task, protect_tools
    
    # Configure
    configure(issuer_key=my_key, dev_mode=True)
    
    # Protect existing tools
    tools = [read_file, send_email]
    protect_tools(tools)  # Mutates in place by default
    
    # Use with scoped authority
    async with root_task(tools=["read_file"], path="/data/*"):
        result = await tools[0](path="/data/report.csv")
"""

import asyncio
import logging
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar

from .config import allow_passthrough
from .decorators import get_warrant_context, get_keypair_context
from .schemas import ToolSchema, TOOL_SCHEMAS, _get_tool_name
from .exceptions import (
    TenuoError,
    ToolNotAuthorized,
    ConstraintViolation,
    ConfigurationError,
)
from .audit import log_authorization_success, log_authorization_failure

logger = logging.getLogger("tenuo.protect")

# Type variable for tool functions
T = TypeVar('T', bound=Callable)


def _get_constraints_dict(warrant: Any) -> Dict[str, Any]:
    """Safely get constraints dict from warrant, handling None."""
    if hasattr(warrant, 'constraints_dict'):
        result = warrant.constraints_dict()
        if result is not None:
            return dict(result)
    return {}


def protect_tools(
    tools: List[Any],
    *,
    inplace: bool = True,
    strict: bool = False,
    schemas: Optional[Dict[str, ToolSchema]] = None,
) -> List[Any]:
    """
    Wrap tools to enforce warrant authorization.
    
    NOTE: Mutates the input list by default (inplace=True).
    Set inplace=False to get a new list instead.
    
    Args:
        tools: List of LangChain/callable tools
        inplace: If True (default), mutate the original list
        strict: If True, fail on tools with require_at_least_one but no constraints
        schemas: Optional custom tool schemas (merged with built-in)
    
    Returns:
        Wrapped tools (same list if inplace=True, new list if inplace=False)
    
    Raises:
        TypeError: If inplace=True but tools is not a mutable list
    
    Example:
        # Mutate in place (default)
        tools = [read_file, send_email]
        protect_tools(tools)
        
        # Get new list
        original = [read_file, send_email]
        protected = protect_tools(original, inplace=False)
    """
    merged_schemas = {**TOOL_SCHEMAS, **(schemas or {})}
    wrapped = [_wrap_tool(t, strict, merged_schemas) for t in tools]
    
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


def protected_tool(
    fn: Optional[Callable] = None,
    *,
    strict: bool = False,
    schema: Optional[ToolSchema] = None,
) -> Callable:
    """
    Decorator to protect a single tool function.
    
    Usage:
        @protected_tool
        def read_file(path: str) -> str:
            return open(path).read()
        
        @protected_tool(strict=True)
        def send_email(to: str, body: str) -> None:
            ...
        
        @protected_tool(schema=ToolSchema(
            recommended_constraints=["resource_id"],
            risk_level="high",
        ))
        def my_api_call(resource_id: str) -> dict:
            ...
    """
    def decorator(func: Callable) -> Callable:
        # If schema provided, register it
        if schema:
            TOOL_SCHEMAS[func.__name__] = schema
        
        return _create_protected_wrapper(func, strict, TOOL_SCHEMAS)
    
    if fn is not None:
        return decorator(fn)
    return decorator


def _wrap_tool(
    tool: Any,
    strict: bool,
    schemas: Dict[str, ToolSchema],
) -> Any:
    """Wrap a single tool with authorization check."""
    # Get the original function
    if hasattr(tool, 'func'):
        # LangChain Tool
        original_fn = tool.func
    elif hasattr(tool, 'coroutine'):
        # LangChain async Tool
        original_fn = tool.coroutine
    elif callable(tool):
        original_fn = tool
    else:
        raise TypeError(f"Cannot wrap non-callable: {type(tool)}")
    
    tool_name = _get_tool_name(tool)
    protected_fn = _create_protected_wrapper(original_fn, strict, schemas, tool_name)
    
    return _rebuild_tool(tool, protected_fn, tool_name)


def _create_protected_wrapper(
    original_fn: Callable,
    strict: bool,
    schemas: Dict[str, ToolSchema],
    tool_name: Optional[str] = None,
) -> Callable:
    """Create the protected wrapper function."""
    name: str = tool_name if tool_name else str(getattr(original_fn, '__name__', 'unknown'))
    
    @wraps(original_fn)
    async def protected_async(*args: Any, **kwargs: Any) -> Any:
        return await _execute_protected(
            original_fn, name, strict, schemas, args, kwargs, is_async=True
        )
    
    @wraps(original_fn)
    def protected_sync(*args: Any, **kwargs: Any) -> Any:
        # Check if we're in an async context
        try:
            asyncio.get_running_loop()
            # We're in async context, need to handle differently
            # Return a coroutine that will be awaited
            return _execute_protected(
                original_fn, name, strict, schemas, args, kwargs, is_async=True
            )
        except RuntimeError:
            # No event loop - sync context
            pass
        
        # Execute synchronously
        return asyncio.get_event_loop().run_until_complete(
            _execute_protected(
                original_fn, name, strict, schemas, args, kwargs, is_async=False
            )
        )
    
    # If original is async, return async wrapper
    if asyncio.iscoroutinefunction(original_fn):
        return protected_async
    
    return protected_sync


async def _execute_protected(
    original_fn: Callable,
    tool_name: str,
    strict: bool,
    schemas: Dict[str, ToolSchema],
    args: tuple,
    kwargs: dict,
    is_async: bool,
) -> Any:
    """Execute the protected tool with authorization checks."""
    warrant = get_warrant_context()
    _ = get_keypair_context()  # Reserved for PoP signature creation
    schema = schemas.get(tool_name)
    
    # No warrant in context
    if warrant is None:
        if allow_passthrough():
            _audit_passthrough(tool_name, kwargs)
            return await _maybe_await(original_fn(*args, **kwargs))
        raise ToolNotAuthorized(tool=tool_name)
    
    # Check tool is in warrant's allowlist
    if warrant.tool and warrant.tool != tool_name:
        if tool_name not in (warrant.tool or "").split(","):
            raise ToolNotAuthorized(
                tool=tool_name,
                authorized_tools=[warrant.tool] if warrant.tool else None,
            )
    
    # Critical tools ALWAYS require at least one constraint
    if schema and schema.risk_level == "critical":
        constraints = _get_constraints_dict(warrant)
        has_relevant = any(c in constraints for c in schema.recommended_constraints)
        if not has_relevant and not constraints:
            raise ConfigurationError(
                f"Critical tool '{tool_name}' requires at least one constraint. "
                f"Recommended: {schema.recommended_constraints}. "
                "Add constraints in root_task() or scoped_task()."
            )
    
    # High-risk tools: warn if unconstrained
    if schema and schema.risk_level == "high":
        constraints = _get_constraints_dict(warrant)
        has_relevant = any(c in constraints for c in schema.recommended_constraints)
        if not has_relevant and not constraints:
            logger.warning(
                f"⚠️  High-risk tool '{tool_name}' invoked without constraints. "
                f"Recommended: {schema.recommended_constraints}"
            )
    
    # Strict mode: require constraints for any tool with require_at_least_one
    if strict and schema and schema.require_at_least_one:
        constraints = _get_constraints_dict(warrant)
        if not constraints:
            raise ConfigurationError(
                f"Strict mode: tool '{tool_name}' requires at least one constraint. "
                f"Recommended: {schema.recommended_constraints}"
            )
    
    # Authorize (checks constraints)
    try:
        # Get constraint values from kwargs
        constraint_args = {k: v for k, v in kwargs.items()}
        
        # Simple authorization - check tool name matches
        # Full constraint checking happens via warrant.authorize() if PoP is needed
        if warrant.tool and tool_name not in warrant.tool.split(","):
            raise ToolNotAuthorized(
                tool=tool_name,
                authorized_tools=warrant.tool.split(","),
            )
        
        # Check constraints match if we have any
        warrant_constraints = _get_constraints_dict(warrant)
        for key, constraint in warrant_constraints.items():
            if key in constraint_args:
                value = constraint_args[key]
                try:
                    _check_constraint(constraint, value)
                except Exception as e:
                    raise ConstraintViolation(
                        field=key,
                        reason=str(e),
                        value=value,
                    ) from e
        
        # Audit success
        log_authorization_success(warrant, tool_name, constraint_args)
        
    except TenuoError:
        raise
    except Exception as e:
        log_authorization_failure(
            warrant_id=warrant.id if warrant else None,
            tool=tool_name,
            constraints=constraint_args,
            reason=str(e),
        )
        raise
    
    # Execute the original function
    return await _maybe_await(original_fn(*args, **kwargs))


def _check_constraint(constraint: Any, value: Any) -> None:
    """Check if value satisfies constraint."""
    # Use check method if available
    if hasattr(constraint, 'check'):
        constraint.check(value)
        return

    # Manual checks for Rust types
    type_name = type(constraint).__name__
    
    if type_name == 'Pattern':
        pattern = getattr(constraint, 'pattern', '')
        import fnmatch
        if not fnmatch.fnmatch(str(value), pattern):
             raise ValueError(f"Value '{value}' does not match pattern '{pattern}'")
        return

    if type_name == 'Exact':
        expected = getattr(constraint, 'value', None)
        if str(value) != str(expected):
             raise ValueError(f"Value '{value}' does not match expected '{expected}'")
        return
        
    if type_name == 'OneOf':
        allowed = getattr(constraint, 'values', [])
        if str(value) not in allowed:
            raise ValueError(f"Value '{value}' not in allowed values: {allowed}")
        return
        
    if type_name == 'Range':
        min_val = getattr(constraint, 'min', None)
        max_val = getattr(constraint, 'max', None)
        
        try:
            val_num = float(value)
        except (ValueError, TypeError):
            raise ValueError(f"Value '{value}' is not a number")
            
        if min_val is not None and val_num < min_val:
            raise ValueError(f"Value {val_num} is less than minimum {min_val}")
        if max_val is not None and val_num > max_val:
            raise ValueError(f"Value {val_num} is greater than maximum {max_val}")
        return
    
    # Fallback: if it's a raw value (str/int), check equality
    if isinstance(constraint, (str, int, float, bool)):
        if constraint != value:
            raise ValueError(f"Value '{value}' does not match expected '{constraint}'")
        return
        
    # Unknown constraint type
    # We should probably fail safe if we can't verify
    # But for now, let's assume if it has no check() and not a known type, it might be a custom object
    # If we can't check it, we can't enforce it.
    # However, to be secure, we should probably warn or fail.
    # Given the context, failing safe is better.
    raise ValueError(f"Cannot verify constraint of type {type_name}")


async def _maybe_await(result: Any) -> Any:
    """Await the result if it's a coroutine."""
    if asyncio.iscoroutine(result):
        return await result
    return result


def _audit_passthrough(tool_name: str, kwargs: dict) -> None:
    """Audit a passthrough execution (no warrant)."""
    logger.warning(
        f"PASSTHROUGH: Tool '{tool_name}' executed without warrant. "
        f"Args: {list(kwargs.keys())}"
    )


def _rebuild_tool(original_tool: Any, protected_fn: Callable, tool_name: str) -> Any:
    """Rebuild a tool with the protected function."""
    # Try to rebuild as same type
    
    # LangChain StructuredTool
    if hasattr(original_tool, 'func') and hasattr(original_tool, 'name'):
        try:
            # Try to create a new tool with the protected function
            tool_class = type(original_tool)
            if hasattr(tool_class, 'from_function'):
                # StructuredTool.from_function pattern
                return tool_class.from_function(
                    func=protected_fn,
                    name=original_tool.name,
                    description=getattr(original_tool, 'description', ''),
                )
        except Exception:
            pass
        
        # Fallback: shallow copy and replace func
        try:
            import copy
            new_tool = copy.copy(original_tool)
            new_tool.func = protected_fn  # type: ignore[attr-defined]
            return new_tool
        except Exception:
            pass
    
    # If it's just a callable, return the protected function
    if callable(original_tool) and not hasattr(original_tool, 'func'):
        protected_fn.__name__ = tool_name
        protected_fn.__doc__ = getattr(original_tool, '__doc__', None)
        return protected_fn
    
    # Last resort: return protected function with original attributes
    for attr in ['name', 'description', '__doc__']:
        if hasattr(original_tool, attr):
            try:
                setattr(protected_fn, attr, getattr(original_tool, attr))
            except AttributeError:
                pass
    
    return protected_fn


__all__ = [
    "protect_tools",
    "protected_tool",
]
