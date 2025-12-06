"""
Decorators for Tenuo authorization.

Supports both explicit warrant passing and ContextVar-based context (for LangChain/FastAPI).

Example with explicit warrant:
    @lockdown(warrant, tool="manage_infrastructure")
    def upgrade_cluster(cluster: str, budget: float):
        # This function can only be called if the warrant authorizes it
        ...

Example with ContextVar (LangChain/FastAPI pattern):
    from tenuo import set_warrant_context
    
    # Set warrant in context (e.g., in FastAPI middleware or LangChain callback)
    with set_warrant_context(warrant):
        upgrade_cluster(cluster="staging-web", budget=5000.0)
    
    @lockdown(tool="manage_infrastructure")
    def upgrade_cluster(cluster: str, budget: float):
        # Warrant is automatically retrieved from context
        ...
"""

from functools import wraps
from typing import Callable, Any, Optional, Union
from contextvars import ContextVar
from . import Warrant, AuthorizationError

# Context variable for thread-local warrant storage
# This allows warrants to be passed through async call stacks without explicit threading
_warrant_context: ContextVar[Optional[Warrant]] = ContextVar('_warrant_context', default=None)


def get_warrant_context() -> Optional[Warrant]:
    """
    Get the current warrant from context.
    
    Returns:
        The warrant in the current context, or None if not set.
    """
    return _warrant_context.get()


def set_warrant_context(warrant: Warrant) -> 'WarrantContext':
    """
    Create a context manager to set a warrant in the current context.
    
    This is useful for LangChain/FastAPI where you want to set the warrant
    at the request/message level and have it available throughout the call stack.
    
    Args:
        warrant: The warrant to set in context
    
    Returns:
        A context manager that sets the warrant
    
    Example:
        with set_warrant_context(warrant):
            # All functions decorated with @lockdown will use this warrant
            process_request()
    """
    return WarrantContext(warrant)


class WarrantContext:
    """Context manager for setting warrant in ContextVar."""
    
    def __init__(self, warrant: Warrant):
        self.warrant = warrant
        self.token = None
    
    def __enter__(self):
        self.token = _warrant_context.set(self.warrant)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token is not None:
            _warrant_context.reset(self.token)
        return False


def lockdown(
    warrant_or_tool: Optional[Union[Warrant, str]] = None,
    tool: Optional[str] = None,
    extract_args: Optional[Callable[[Any], dict]] = None
):
    """
    Decorator that enforces warrant authorization before function execution.
    
    Supports two usage patterns:
    
    1. Explicit warrant (simple case):
        @lockdown(warrant, tool="manage_infrastructure")
        def upgrade_cluster(cluster: str, budget: float):
            ...
    
    2. ContextVar-based (LangChain/FastAPI pattern):
        @lockdown(tool="manage_infrastructure")
        def upgrade_cluster(cluster: str, budget: float):
            ...
        
        # Warrant is set in context elsewhere (e.g., FastAPI middleware)
        with set_warrant_context(warrant):
            upgrade_cluster(cluster="staging-web", budget=5000.0)
    
    Args:
        warrant_or_tool: If Warrant instance, use it explicitly. If str, treat as tool name.
                        If None, tool must be provided as keyword arg.
        tool: The tool name to authorize (required if warrant_or_tool is not a string)
        extract_args: Optional function to extract args from function arguments.
                     If None, uses the function's kwargs as args.
    
    Raises:
        AuthorizationError: If no warrant is available or authorization fails.
        ValueError: If tool is not provided.
    """
    # Determine warrant and tool
    active_warrant: Optional[Warrant] = None
    tool_name: Optional[str] = None
    
    if isinstance(warrant_or_tool, Warrant):
        # Pattern 1: @lockdown(warrant, tool="...")
        active_warrant = warrant_or_tool
        tool_name = tool
    elif isinstance(warrant_or_tool, str):
        # Pattern 2: @lockdown(tool="...") - tool passed as first positional arg
        tool_name = warrant_or_tool
    else:
        # Pattern 2: @lockdown(tool="...") - tool passed as keyword arg
        tool_name = tool
    
    if tool_name is None:
        raise ValueError(
            "tool parameter is required. Use @lockdown(warrant, tool='...') "
            "or @lockdown(tool='...')"
        )
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get warrant: explicit or from context
            warrant_to_use = active_warrant
            if warrant_to_use is None:
                warrant_to_use = get_warrant_context()
            
            if warrant_to_use is None:
                raise AuthorizationError(
                    f"No warrant available for {tool_name}. "
                    "Either pass warrant explicitly or set it in context using set_warrant_context()."
                )
            
            # Extract arguments for authorization
            if extract_args:
                auth_args = extract_args(*args, **kwargs)
            else:
                # Use kwargs as args (simple case)
                auth_args = kwargs
            
            # Check authorization
            if not warrant_to_use.authorize(tool_name, auth_args):
                raise AuthorizationError(
                    f"Warrant does not authorize {tool_name} with args {auth_args}"
                )
            
            # Execute the function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

