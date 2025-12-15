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
from typing import Callable, List, Optional, Union
from contextvars import ContextVar
from .exceptions import (
    ScopeViolation,
    ConstraintViolation,
    ExpiredError,
    MissingKeypair,
)
from .audit import audit_logger, AuditEvent, AuditEventType

# Runtime imports
from tenuo_core import Warrant, Keypair  # type: ignore[import-untyped]

# Context variable for warrant storage (works with both threads and asyncio)
# This allows warrants to be passed through async call stacks without explicit threading
_warrant_context: ContextVar[Optional[Warrant]] = ContextVar('_warrant_context', default=None)

# Context variable for keypair storage (for PoP signatures)
_keypair_context: ContextVar[Optional[Keypair]] = ContextVar('_keypair_context', default=None)

# Context variable for allowed tools (narrower than warrant.tools)
# Used by scoped_task to restrict tools beyond what the warrant allows
_allowed_tools_context: ContextVar[Optional[List[str]]] = ContextVar('_allowed_tools_context', default=None)


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


def get_allowed_tools_context() -> Optional[List[str]]:
    """
    Get the current allowed tools from context.
    
    This returns the tools restricted by scoped_task, which may be
    narrower than what the warrant.tools field allows.
    
    Returns:
        List of allowed tool names, or None if not restricted.
    """
    return _allowed_tools_context.get()


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
    extract_args: Optional[Callable[..., dict]] = None,
    mapping: Optional[dict[str, str]] = None
):
    """
    Decorator that enforces warrant authorization before function execution.
    
    IMPORTANT: PoP is MANDATORY
    ---------------------------
    Keypair must always be available (either provided or in context) because
    Proof-of-Possession is mandatory. This ensures leaked warrants are useless
    without the corresponding private key.
    
    Supports two usage patterns:
    
    1. Explicit warrant (simple case):
        @lockdown(warrant, tool="manage_infrastructure", keypair=keypair)
        def upgrade_cluster(cluster: str, budget: float):
            ...
    
    2. ContextVar-based (LangChain/FastAPI pattern):
        @lockdown(tool="manage_infrastructure")
        def upgrade_cluster(cluster: str, budget: float):
            ...
        
        # Warrant AND keypair are set in context (BOTH required)
        with set_warrant_context(warrant), set_keypair_context(keypair):
            upgrade_cluster(cluster="staging-web", budget=5000.0)
    
    Args:
        warrant_or_tool: If Warrant instance, use it explicitly. If str, treat as tool name.
                        If None, tool must be provided as keyword arg.
        tool: The tool name to authorize (required if warrant_or_tool is not a string)
        keypair: Keypair for PoP signature (required - or use set_keypair_context)
        extract_args: Optional function to extract args from function arguments.
                     If None, uses the function's kwargs as args.
        mapping: Optional dictionary mapping function argument names to constraint names.
                 e.g., {"target_env": "cluster"} maps arg 'target_env' to constraint 'cluster'.
    
    Raises:
        AuthorizationError: If no warrant/keypair is available, or authorization fails.
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
                raise ScopeViolation(
                    f"No warrant available for {tool_name}. "
                    "Either pass warrant explicitly or set it in context using set_warrant_context()."
                )
            
            # Check warrant expiry BEFORE any further processing
            if warrant_to_use.is_expired():
                expires_at = warrant_to_use.expires_at() if hasattr(warrant_to_use, 'expires_at') else "unknown"
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.WARRANT_EXPIRED,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                    tool=tool_name,
                    action="denied",
                    error_code="warrant_expired",
                    details=f"Warrant expired at {expires_at}",
                ))
                raise ExpiredError(
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else "unknown",
                    expired_at=expires_at
                )
            
            # Get keypair: explicit or from context (REQUIRED - PoP is mandatory)
            keypair_to_use = active_keypair
            if keypair_to_use is None:
                keypair_to_use = get_keypair_context()
            
            # PoP is MANDATORY - keypair must always be available
            if keypair_to_use is None:
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.POP_FAILED,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                    tool=tool_name,
                    action="denied",
                    error_code="no_keypair_for_pop",
                    details=f"Proof-of-Possession is mandatory but no keypair available for {tool_name}",
                ))
                raise MissingKeypair(tool=tool_name)
            
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

                # Apply mapping if provided
                if mapping:
                    mapped_args = {}
                    for arg_name, value in auth_args.items():
                        # If arg_name is in mapping, use the mapped name
                        constraint_name = mapping.get(arg_name, arg_name)
                        mapped_args[constraint_name] = value
                    auth_args = mapped_args
            
            # Create PoP signature (ALWAYS - PoP is mandatory)
            # Keypair is guaranteed to be present (validated above)
            pop_signature = warrant_to_use.create_pop_signature(
                keypair_to_use, tool_name, auth_args
            )
            
            # Check authorization (with PoP signature if required)
            # Note: pop_signature is list[int], must convert to bytes
            if not warrant_to_use.authorize(tool_name, auth_args, signature=bytes(pop_signature)):
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
                raise ConstraintViolation(
                    field="authorization",
                    reason=f"Warrant does not authorize {tool_name} with provided args",
                    value=auth_args
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

