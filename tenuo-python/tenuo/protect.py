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
from .decorators import get_warrant_context, get_signing_key_context
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
    """Create the protected wrapper function.
    
    Strict about sync/async:
    - If original_fn is async → return async wrapper
    - If original_fn is sync → return sync wrapper
    No magic loop detection.
    """
    name: str = tool_name if tool_name else str(getattr(original_fn, '__name__', 'unknown'))
    
    if asyncio.iscoroutinefunction(original_fn):
        # Async function → async wrapper (strict)
        @wraps(original_fn)
        async def protected_async(*args: Any, **kwargs: Any) -> Any:
            return await _execute_protected_async(
                original_fn, name, strict, schemas, args, kwargs
            )
        return protected_async
    else:
        # Sync function → sync wrapper (strict)
        @wraps(original_fn)
        def protected_sync(*args: Any, **kwargs: Any) -> Any:
            return _execute_protected_sync(
                original_fn, name, strict, schemas, args, kwargs
            )
        return protected_sync


def _check_authorization(
    tool_name: str,
    strict: bool,
    schemas: Dict[str, ToolSchema],
    kwargs: dict,
) -> None:
    """Check authorization - shared by sync and async paths."""
    warrant = get_warrant_context()
    _ = get_signing_key_context()  # Reserved for PoP signature creation
    schema = schemas.get(tool_name)
    
    # No warrant in context
    if warrant is None:
        if allow_passthrough():
            _audit_passthrough(tool_name, kwargs)
            return  # Allow passthrough
        raise ToolNotAuthorized(tool=tool_name)
    
    # Check tool is in warrant's allowlist
    if warrant.tools and tool_name not in warrant.tools:
        raise ToolNotAuthorized(
            tool=tool_name,
            authorized_tools=warrant.tools if warrant.tools else None,
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
    constraint_args = {k: v for k, v in kwargs.items()}
    try:
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


def _execute_protected_sync(
    original_fn: Callable,
    tool_name: str,
    strict: bool,
    schemas: Dict[str, ToolSchema],
    args: tuple,
    kwargs: dict,
) -> Any:
    """Execute protected tool synchronously (strict sync path)."""
    warrant = get_warrant_context()
    
    # Check authorization (may raise or allow passthrough)
    _check_authorization(tool_name, strict, schemas, kwargs)
    
    # If passthrough was allowed (no warrant, dev_mode), just execute
    if warrant is None:
        return original_fn(*args, **kwargs)
    
    # Execute the original function
    return original_fn(*args, **kwargs)


async def _execute_protected_async(
    original_fn: Callable,
    tool_name: str,
    strict: bool,
    schemas: Dict[str, ToolSchema],
    args: tuple,
    kwargs: dict,
) -> Any:
    """Execute protected tool asynchronously (strict async path)."""
    warrant = get_warrant_context()
    
    # Check authorization (may raise or allow passthrough)
    _check_authorization(tool_name, strict, schemas, kwargs)
    
    # If passthrough was allowed (no warrant, dev_mode), just execute
    if warrant is None:
        result = original_fn(*args, **kwargs)
        if asyncio.iscoroutine(result):
            return await result
        return result
    
    # Execute the original function
    result = original_fn(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return await result
    return result


def _check_constraint(constraint: Any, value: Any) -> None:
    """Check if value satisfies constraint.
    
    Uses duck typing with hasattr() for robustness against type renames or subclasses.
    """
    # Use check method if available (preferred path)
    if hasattr(constraint, 'check'):
        constraint.check(value)
        return

    # Duck typing: check for Pattern-like (has 'pattern' attribute)
    if hasattr(constraint, 'pattern'):
        pattern = constraint.pattern
        import fnmatch
        if not fnmatch.fnmatch(str(value), pattern):
            raise ValueError(f"Value '{value}' does not match pattern '{pattern}'")
        return

    # Duck typing: check for Exact-like (has 'value' attribute, not 'values')
    if hasattr(constraint, 'value') and not hasattr(constraint, 'values'):
        expected = constraint.value
        if str(value) != str(expected):
            raise ValueError(f"Value '{value}' does not match expected '{expected}'")
        return
        
    # Duck typing: check for OneOf-like (has 'values' attribute as collection)
    if hasattr(constraint, 'values'):
        allowed = constraint.values
        if str(value) not in allowed:
            raise ValueError(f"Value '{value}' not in allowed values: {allowed}")
        return
        
    # Duck typing: check for Range-like (has 'min' or 'max' attribute)
    if hasattr(constraint, 'min') or hasattr(constraint, 'max'):
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
        
    # Unknown constraint type - fail safe
    raise ValueError(f"Cannot verify constraint of type {type(constraint).__name__}")


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
