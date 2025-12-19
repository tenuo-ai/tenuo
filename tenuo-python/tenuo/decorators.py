"""
Decorators for Tenuo authorization.

Supports both explicit warrant passing and ContextVar-based context (for LangChain/FastAPI).

Example with explicit warrant:
    @lockdown(warrant, tool="manage_infrastructure")
    def scale_cluster(cluster: str, replicas: int):
        # This function can only be called if the warrant authorizes it
        ...

Example with ContextVar (LangChain/FastAPI pattern):
    from tenuo import set_warrant_context, set_signing_key_context
    
    # Set warrant and keypair in context (e.g., in FastAPI middleware)
    with set_warrant_context(warrant), set_signing_key_context(keypair):
        scale_cluster(cluster="staging-web", replicas=5)
    
    @lockdown(tool="manage_infrastructure")
    def scale_cluster(cluster: str, replicas: int):
        # Warrant and keypair are automatically retrieved from context
        # PoP signature is created automatically if warrant.requires_pop
        ...

Audit Logging:
    All authorization decisions are logged as structured JSON events.
    Configure via: tenuo.audit.audit_logger.configure(service_name="my-service")

IMPORTANT: Async Context Sharp Edges
====================================
Python contextvars work correctly with:
- `async def` functions and `await`
- `asyncio.gather()` / `asyncio.wait()`

But NOT automatically with:
- `asyncio.create_task()` called BEFORE context is set
- `concurrent.futures.ThreadPoolExecutor` / `ProcessPoolExecutor`
- Callbacks scheduled with `loop.call_soon()` / `loop.call_later()`

For thread pools, use `contextvars.copy_context().run(fn)` or
the helper `tenuo.spawn()` when available.
"""

from functools import wraps
from typing import Callable, List, Optional, Union
from contextvars import ContextVar
import traceback
import warnings
from .exceptions import (
    ScopeViolation,
    ConstraintViolation,
    ExpiredError,
    MissingSigningKey,
)
from .audit import audit_logger, AuditEvent, AuditEventType


# =============================================================================
# Error Codes for Structured Logging
# =============================================================================

class AuthErrorCode:
    """Standard error codes for authorization failures."""
    MISSING_CONTEXT = "MISSING_CONTEXT"  # No warrant in context
    INVALID_WARRANT = "INVALID_WARRANT"  # Warrant malformed or wrong type
    EXPIRED = "EXPIRED"                   # Warrant has expired
    SCOPE_VIOLATION = "SCOPE_VIOLATION"  # Tool not in warrant.tools
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"  # Args don't satisfy constraints
    POP_MISSING = "POP_MISSING"          # SigningKey not available for PoP
    POP_INVALID = "POP_INVALID"          # PoP signature invalid
    HOLDER_MISMATCH = "HOLDER_MISMATCH"  # Wrong keypair for warrant holder


# Custom warning category for integration issues
class SecurityWarning(UserWarning):
    """Warning for potential security/integration issues."""
    pass


def _get_callsite() -> str:
    """
    Get the callsite (filename:line) of the tool invocation.
    
    Walks up the stack to find the first frame outside tenuo internals.
    """
    for frame_info in traceback.extract_stack():
        # Skip tenuo internals
        if '/tenuo/' in frame_info.filename or frame_info.filename.endswith('decorators.py'):
            continue
        return f"{frame_info.filename}:{frame_info.lineno}"
    return "unknown"


def _make_actionable_error(
    error_code: str,
    tool_name: str,
    func_name: str,
    callsite: str,
    details: str,
) -> str:
    """Create an actionable error message that helps developers fix the issue."""
    base = f"[{error_code}] {details}\n"
    base += f"\n  Tool: {tool_name}"
    base += f"\n  Function: {func_name}"
    base += f"\n  Location: {callsite}"
    
    # Add specific fix suggestions based on error code
    if error_code == AuthErrorCode.MISSING_CONTEXT:
        base += "\n\nTo fix:"
        base += "\n  1. Wrap the call with: async with root_task(Capability(\"<tool>\", ...)):"
        base += "\n  2. Or use: with set_warrant_context(warrant), set_signing_key_context(keypair):"
        base += f"\n  3. Or pass warrant explicitly: @lockdown(warrant, tool='{tool_name}')"
    elif error_code == AuthErrorCode.POP_MISSING:
        base += "\n\nTo fix:"
        base += "\n  1. Add keypair to context: with set_signing_key_context(keypair):"
        base += "\n  2. Or use root_task() which handles this automatically"
    elif error_code == AuthErrorCode.EXPIRED:
        base += "\n\nTo fix:"
        base += "\n  1. Issue a new warrant with root_task()"
        base += "\n  2. Or check TTL configuration"
    elif error_code == AuthErrorCode.SCOPE_VIOLATION:
        base += "\n\nTo fix:"
        base += f'\n  1. Add a capability for this tool: root_task(Capability("{tool_name}", ...))'
        base += "\n  2. Or use scoped_task to narrow from parent warrant"
    elif error_code == AuthErrorCode.CONSTRAINT_VIOLATION:
        base += "\n\nTo fix:"
        base += "\n  1. Check if the function arguments satisfy the warrant constraints"
        base += "\n  2. Or issue a warrant with appropriate constraints"
    
    return base

# Runtime imports (after class definitions above)
from tenuo_core import Warrant, SigningKey  # type: ignore[import-untyped]  # noqa: E402

# Context variable for warrant storage (works with both threads and asyncio)
# This allows warrants to be passed through async call stacks without explicit threading
_warrant_context: ContextVar[Optional[Warrant]] = ContextVar('_warrant_context', default=None)

# Context variable for keypair storage (for PoP signatures)
_keypair_context: ContextVar[Optional[SigningKey]] = ContextVar('_keypair_context', default=None)

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


def get_signing_key_context() -> Optional[SigningKey]:
    """
    Get the current signing key from context.
    
    Returns:
        The signing key in the current context, or None if not set.
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


def set_signing_key_context(keypair: SigningKey) -> 'SigningKeyContext':
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
        with set_warrant_context(warrant), set_signing_key_context(keypair):
            # @lockdown will automatically create PoP signatures
            process_request()
    """
    return SigningKeyContext(keypair)


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


class SigningKeyContext:
    """Context manager for setting keypair in ContextVar (for PoP)."""
    
    def __init__(self, keypair: SigningKey):
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
    keypair: Optional[SigningKey] = None,
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
        def scale_cluster(cluster: str, replicas: int):
            ...
    
    2. ContextVar-based (LangChain/FastAPI pattern):
        @lockdown(tool="manage_infrastructure")
        def scale_cluster(cluster: str, replicas: int):
            ...
        
        # Warrant AND keypair are set in context (BOTH required)
        with set_warrant_context(warrant), set_signing_key_context(keypair):
            scale_cluster(cluster="staging-web", replicas=5)
    
    Args:
        warrant_or_tool: If Warrant instance, use it explicitly. If str, treat as tool name.
                        If None, tool must be provided as keyword arg.
        tool: The tool name to authorize (required if warrant_or_tool is not a string)
        keypair: SigningKey for PoP signature (required - or use set_signing_key_context)
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
    active_keypair: Optional[SigningKey] = keypair
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
            from .config import get_config
            
            config = get_config()
            callsite = _get_callsite()
            func_name = f"{func.__module__}.{func.__qualname__}"
            
            warrant_to_use = active_warrant or get_warrant_context()
            
            if warrant_to_use is None:
                error_code = AuthErrorCode.MISSING_CONTEXT
                
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.AUTHORIZATION_FAILURE,
                    tool=tool_name,
                    action="denied",
                    error_code=error_code,
                    details=f"No warrant context for {tool_name}",
                    metadata={
                        "callsite": callsite,
                        "function": func_name,
                    },
                ))
                
                should_fail = config.strict_mode
                
                # Tripwire: auto-flip to strict after threshold is reached
                if config.max_missing_warrant_warnings > 0:
                    config._missing_warrant_count += 1
                    if config._missing_warrant_count >= config.max_missing_warrant_warnings:
                        should_fail = True
                        warnings.warn(
                            f"Tripwire triggered: {config._missing_warrant_count} missing warrant warnings "
                            f"reached threshold ({config.max_missing_warrant_warnings}). "
                            "Switching to strict mode (hard fail).",
                            SecurityWarning,
                            stacklevel=2,
                        )
                
                if should_fail:
                    error_msg = _make_actionable_error(
                        error_code=error_code,
                        tool_name=tool_name,
                        func_name=func_name,
                        callsite=callsite,
                        details=f"No warrant context available for tool '{tool_name}'.",
                    )
                    raise RuntimeError(error_msg)
                
                elif config.warn_on_missing_warrant:
                    warning_msg = (
                        f"[{error_code}] Tool '{tool_name}' called without warrant context.\n"
                        f"  Function: {func_name}\n"
                        f"  Location: {callsite}\n"
                        "  This would fail in strict_mode. Add root_task() or set_warrant_context()."
                    )
                    warnings.warn(warning_msg, SecurityWarning, stacklevel=2)
                    # Passthrough allowed - continue without authorization
                    return func(*args, **kwargs)
                
                elif config.allow_passthrough:
                    # Dev mode passthrough - just execute
                    return func(*args, **kwargs)
                
                else:
                    error_msg = _make_actionable_error(
                        error_code=error_code,
                        tool_name=tool_name,
                        func_name=func_name,
                        callsite=callsite,
                        details=f"No warrant context available for tool '{tool_name}'.",
                    )
                    raise ScopeViolation(error_msg)
            
            # Check warrant expiry BEFORE any further processing
            if warrant_to_use.is_expired():
                expires_at = warrant_to_use.expires_at() if hasattr(warrant_to_use, 'expires_at') else "unknown"
                error_code = AuthErrorCode.EXPIRED
                
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.WARRANT_EXPIRED,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                    tool=tool_name,
                    action="denied",
                    error_code=error_code,
                    details=f"Warrant expired at {expires_at}",
                    metadata={
                        "callsite": callsite,
                        "function": func_name,
                        "expires_at": str(expires_at),
                    },
                ))
                
                error_msg = _make_actionable_error(
                    error_code=error_code,
                    tool_name=tool_name,
                    func_name=func_name,
                    callsite=callsite,
                    details=f"Warrant expired at {expires_at}.",
                )
                raise ExpiredError(
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else "unknown",
                    expired_at=expires_at
                )
            
            keypair_to_use = active_keypair or get_signing_key_context()
            
            # PoP is MANDATORY - keypair must always be available
            if keypair_to_use is None:
                error_code = AuthErrorCode.POP_MISSING
                
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.POP_FAILED,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                    tool=tool_name,
                    action="denied",
                    error_code=error_code,
                    details=f"Proof-of-Possession is mandatory but no keypair available for {tool_name}",
                    metadata={
                        "callsite": callsite,
                        "function": func_name,
                    },
                ))
                
                error_msg = _make_actionable_error(
                    error_code=error_code,
                    tool_name=tool_name,
                    func_name=func_name,
                    callsite=callsite,
                    details="Proof-of-Possession is mandatory but no keypair available.",
                )
                raise MissingSigningKey(tool=tool_name)
            
            if extract_args:
                auth_args = extract_args(*args, **kwargs)
            else:
                import inspect
                sig = inspect.signature(func)
                
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    auth_args = dict(bound.arguments)
                except TypeError as e:
                    # If binding fails (e.g. wrong number of args), we can't authorize
                    # Let the function call proceed to fail naturally, or raise
                    # But for security, if we can't inspect args, we shouldn't authorize.
                    # However, the function call itself would fail right after.
                    # Let's log and re-raise to be safe/clear.
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.AUTHORIZATION_FAILURE,
                        tool=tool_name,
                        action="denied",
                        error_code="argument_binding_error",
                        details=f"Failed to bind arguments for {tool_name}: {e}",
                    ))
                    raise

                if mapping:
                    mapped_args = {}
                    for arg_name, value in auth_args.items():
                        constraint_name = mapping.get(arg_name, arg_name)
                        mapped_args[constraint_name] = value
                    auth_args = mapped_args
            
            pop_signature = warrant_to_use.create_pop_signature(
                keypair_to_use, tool_name, auth_args
            )
            
            # pop_signature is list[int], convert to bytes
            if not warrant_to_use.authorize(tool_name, auth_args, signature=bytes(pop_signature)):
                warrant_tools = warrant_to_use.tools if hasattr(warrant_to_use, 'tools') else []
                if tool_name not in (warrant_tools or []):
                    error_code = AuthErrorCode.SCOPE_VIOLATION
                    details = f"Tool '{tool_name}' not in warrant.tools: {warrant_tools}"
                else:
                    error_code = AuthErrorCode.CONSTRAINT_VIOLATION
                    details = f"Arguments do not satisfy warrant constraints for '{tool_name}'"
                
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.AUTHORIZATION_FAILURE,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                    tool=tool_name,
                    action="denied",
                    constraints=auth_args,
                    trace_id=warrant_to_use.session_id if hasattr(warrant_to_use, 'session_id') else None,
                    error_code=error_code,
                    details=details,
                    metadata={
                        "callsite": callsite,
                        "function": func_name,
                        "warrant_tools": warrant_tools,
                        "provided_args": {k: str(v)[:100] for k, v in auth_args.items()},  # Truncate for safety
                    },
                ))
                
                error_msg = _make_actionable_error(
                    error_code=error_code,
                    tool_name=tool_name,
                    func_name=func_name,
                    callsite=callsite,
                    details=details,
                )
                raise ConstraintViolation(
                    field="authorization",
                    reason=error_msg,
                    value=auth_args
                )
            
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.AUTHORIZATION_SUCCESS,
                warrant_id=warrant_to_use.id if hasattr(warrant_to_use, 'id') else None,
                tool=tool_name,
                action="authorized",
                constraints=auth_args,
                trace_id=warrant_to_use.session_id if hasattr(warrant_to_use, 'session_id') else None,
                details=f"Authorization successful for {tool_name}",
                metadata={
                    "callsite": callsite,
                    "function": func_name,
                },
            ))
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

