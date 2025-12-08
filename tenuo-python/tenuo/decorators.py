"""
Decorators for Tenuo authorization.

Supports both explicit warrant passing and ContextVar-based context (for LangChain/FastAPI).

Example with explicit warrant:
    @lockdown(warrant, tool="manage_infrastructure")
    def upgrade_cluster(cluster: str, budget: float):
        # This function can only be called if the warrant authorizes it
        ...

Example with ContextVar (LangChain/FastAPI pattern):
    from tenuo import set_warrant_context, set_keypair_context
    
    # Set warrant and keypair in context (e.g., in FastAPI middleware)
    with set_warrant_context(warrant), set_keypair_context(keypair):
        upgrade_cluster(cluster="staging-web", budget=5000.0)
    
    @lockdown(tool="manage_infrastructure")
    def upgrade_cluster(cluster: str, budget: float):
        # Warrant and keypair are automatically retrieved from context
        # PoP signature is created automatically if warrant.requires_pop
        ...

Audit Logging:
    All authorization decisions are logged as structured JSON events.
    Configure via: tenuo.audit.audit_logger.configure(service_name="my-service")
"""

from functools import wraps
from typing import Callable, Any, Optional, Union
from contextvars import ContextVar
from . import Warrant, Keypair, AuthorizationError
from .audit import audit_logger, AuditEvent, AuditEventType

# Context variable for thread-local warrant storage
# This allows warrants to be passed through async call stacks without explicit threading
_warrant_context: ContextVar[Optional[Warrant]] = ContextVar('_warrant_context', default=None)

# Context variable for thread-local keypair storage (for PoP signatures)
_keypair_context: ContextVar[Optional[Keypair]] = ContextVar('_keypair_context', default=None)


def get_warrant_context() -> Optional[Warrant]:
    """
    Get the current warrant from context.
    
    Returns:
        The warrant in the current context, or None if not set.
    """
    return _warrant_context.get()


def get_keypair_context() -> Optional[Keypair]:
    """
    Get the current keypair from context.
    
    Returns:
        The keypair in the current context, or None if not set.
    """
    return _keypair_context.get()


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


def set_keypair_context(keypair: Keypair) -> 'KeypairContext':
    """
    Create a context manager to set a keypair in the current context.
    
    This is needed for PoP (Proof-of-Possession) when the warrant has
    an authorized_holder set. The keypair will be used to automatically
    create PoP signatures in @lockdown decorated functions.
    
    Args:
        keypair: The keypair to set in context (must match warrant's authorized_holder)
    
    Returns:
        A context manager that sets the keypair
    
    Example:
        with set_warrant_context(warrant), set_keypair_context(keypair):
            # @lockdown will automatically create PoP signatures
            process_request()
    """
    return KeypairContext(keypair)


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


class KeypairContext:
    """Context manager for setting keypair in ContextVar (for PoP)."""
    
    def __init__(self, keypair: Keypair):
        self.keypair = keypair
        self.token = None
    
    def __enter__(self):
        self.token = _keypair_context.set(self.keypair)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token is not None:
            _keypair_context.reset(self.token)
        return False


def lockdown(
    warrant_or_tool: Optional[Union[Warrant, str]] = None,
    tool: Optional[str] = None,
    keypair: Optional[Keypair] = None,
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
    
    For PoP-bound warrants (warrant.requires_pop == True):
        # Set keypair in context for automatic PoP signature creation
        with set_warrant_context(warrant), set_keypair_context(keypair):
            upgrade_cluster(cluster="staging-web", budget=5000.0)
    
    Args:
        warrant_or_tool: If Warrant instance, use it explicitly. If str, treat as tool name.
                        If None, tool must be provided as keyword arg.
        tool: The tool name to authorize (required if warrant_or_tool is not a string)
        keypair: Optional keypair for PoP signature (or use set_keypair_context)
        extract_args: Optional function to extract args from function arguments.
                     If None, uses the function's kwargs as args.
    
    Raises:
        AuthorizationError: If no warrant is available, PoP keypair is missing, 
                           or authorization fails.
        ValueError: If tool is not provided.
    """
    # Determine warrant and tool
    active_warrant: Optional[Warrant] = None
    active_keypair: Optional[Keypair] = keypair
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
                # Log authorization failure - no warrant
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.AUTHORIZATION_FAILURE,
                    tool=tool_name,
                    action="denied",
                    error_code="no_warrant",
                    details=f"No warrant available for {tool_name}",
                ))
                raise AuthorizationError(
                    f"No warrant available for {tool_name}. "
                    "Either pass warrant explicitly or set it in context using set_warrant_context()."
                )
            
            # Get keypair: explicit or from context (needed for PoP)
            keypair_to_use = active_keypair
            if keypair_to_use is None:
                keypair_to_use = get_keypair_context()
            
            # Extract arguments for authorization
            if extract_args:
                auth_args = extract_args(*args, **kwargs)
            else:
                # Try to infer from function signature
                import inspect
                sig = inspect.signature(func)
                params = list(sig.parameters.keys())
                auth_args = {}
                
                # Add kwargs first (they override positional)
                auth_args.update(kwargs)
                
                # Map positional args to parameter names
                for i, arg_val in enumerate(args):
                    if i < len(params):
                        param_name = params[i]
                        # Only add if not already in kwargs
                        if param_name not in auth_args:
                            auth_args[param_name] = arg_val
                
                # SECURITY FIX: Include default values for parameters not provided
                # This prevents bypassing constraints by relying on dangerous defaults
                for param_name, param in sig.parameters.items():
                    if param_name not in auth_args and param.default is not inspect.Parameter.empty:
                        auth_args[param_name] = param.default
            
            # Create PoP signature if warrant requires it
            pop_signature = None
            if warrant_to_use.requires_pop:
                if keypair_to_use is None:
                    # Log PoP failure - no keypair
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.POP_FAILED,
                        warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                        tool=tool_name,
                        action="denied",
                        error_code="no_keypair_for_pop",
                        details=f"Warrant requires PoP but no keypair available for {tool_name}",
                    ))
                    raise AuthorizationError(
                        f"Warrant requires Proof-of-Possession for {tool_name}, "
                        "but no keypair is available. "
                        "Either pass keypair explicitly or set it in context using set_keypair_context()."
                    )
                # Create PoP signature automatically
                pop_signature = warrant_to_use.create_pop_signature(
                    keypair_to_use, tool_name, auth_args
                )
            
            # Check authorization (with PoP signature if required)
            if not warrant_to_use.authorize(tool_name, auth_args, signature=pop_signature):
                # Log authorization failure
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.AUTHORIZATION_FAILURE,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                    tool=tool_name,
                    action="denied",
                    constraints=auth_args,
                    trace_id=warrant_to_use.session_id if hasattr(warrant_to_use, 'session_id') else None,
                    error_code="constraint_violation",
                    details=f"Warrant does not authorize {tool_name} with provided args",
                ))
                raise AuthorizationError(
                    f"Warrant does not authorize {tool_name} with args {auth_args}"
                )
            
            # Log authorization success
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.AUTHORIZATION_SUCCESS,
                warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                tool=tool_name,
                action="authorized",
                constraints=auth_args,
                trace_id=warrant_to_use.session_id if hasattr(warrant_to_use, 'session_id') else None,
                details=f"Authorization successful for {tool_name}",
            ))
            
            # Execute the function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

