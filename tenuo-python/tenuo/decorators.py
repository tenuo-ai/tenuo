"""
Decorators for Tenuo authorization.

Supports both explicit warrant passing and ContextVar-based context (for LangChain/FastAPI).

Example with explicit warrant:
    @guard(warrant, tool="manage_infrastructure")
    def scale_cluster(cluster: str, replicas: int):
        # This function can only be called if the warrant authorizes it
        ...

Example with ContextVar (LangChain/FastAPI pattern):
    from tenuo import warrant_scope, key_scope

    # Set warrant and keypair in context (e.g., in FastAPI middleware)
    with warrant_scope(warrant), key_scope(keypair):
        scale_cluster(cluster="staging-web", replicas=5)

    @guard(tool="manage_infrastructure")
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
from typing import Callable, List, Optional, Union, overload, get_type_hints, get_origin, get_args, Any
from typing_extensions import Annotated
from contextvars import ContextVar
import traceback
import warnings
from .exceptions import (
    ScopeViolation,
    ExpiredError,
    MissingSigningKey,
    AuthorizationDenied,
    ConstraintResult,
    ToolNotAuthorized,
)
from .audit import audit_logger, AuditEvent, AuditEventType
import logging

logger = logging.getLogger("tenuo.decorators")


# =============================================================================
# Error Codes for Structured Logging
# =============================================================================


class AuthErrorCode:
    """Standard error codes for authorization failures."""

    MISSING_CONTEXT = "MISSING_CONTEXT"  # No warrant in context
    INVALID_WARRANT = "INVALID_WARRANT"  # Warrant malformed or wrong type
    EXPIRED = "EXPIRED"  # Warrant has expired
    SCOPE_VIOLATION = "SCOPE_VIOLATION"  # Tool not in warrant.tools
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"  # Args don't satisfy constraints
    POP_MISSING = "POP_MISSING"  # SigningKey not available for PoP
    POP_INVALID = "POP_INVALID"  # PoP signature invalid
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
        if "/tenuo/" in frame_info.filename or frame_info.filename.endswith("decorators.py"):
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
        base += '\n  1. Wrap the call with: async with root_task(Capability("<tool>", ...)):'
        base += "\n  2. Or use: with warrant_scope(warrant), key_scope(keypair):"
        base += f"\n  3. Or pass warrant explicitly: @guard(warrant, tool='{tool_name}')"
    elif error_code == AuthErrorCode.POP_MISSING:
        base += "\n\nTo fix:"
        base += "\n  1. Add keypair to context: with key_scope(keypair):"
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


# =============================================================================
# Annotated Type Hint Extraction
# =============================================================================


def _is_tenuo_constraint(obj: Any) -> bool:
    """Check if an object is a Tenuo constraint (Pattern, Exact, Range, etc.)."""
    # Check by class name since we can't import all constraint types here
    constraint_types = {
        "Pattern",
        "Exact",
        "Range",
        "OneOf",
        "NotOneOf",
        "Contains",
        "Subset",
        "Regex",
        "Cidr",
        "UrlPattern",
        "CEL",
        "All",
        "AnyOf",
        "Not",
        "Subpath",
        "UrlSafe",
        "Shlex",
        "Wildcard",
    }
    return type(obj).__name__ in constraint_types


def _check_annotated_constraint(constraint: Any, value: Any) -> bool:
    """
    Check if a value satisfies an annotated constraint using Rust core bindings.

    SECURITY: Type-aware dispatch to ensure correct Rust method is called.
    Fails closed (returns False) for unknown constraint types.

    All constraint runtime checks use Rust core bindings:
      - Subpath.contains()     -> Rust core
      - UrlSafe.is_safe()      -> Rust core
      - Cidr.contains_ip()     -> Rust core
      - Pattern.matches()      -> Rust core
      - Shlex.matches()        -> Rust core
      - Range.contains()       -> Rust core
      - Exact.matches()        -> Rust core
      - OneOf.contains()       -> Rust core
      - NotOneOf.allows()      -> Rust core
      - Wildcard.matches()     -> Rust core
    """
    constraint_type = type(constraint).__name__

    try:
        # Subpath - filesystem path containment (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "Subpath":
            return constraint.contains(str(value))

        # UrlSafe - SSRF protection (Rust core)
        if hasattr(constraint, "is_safe"):
            return constraint.is_safe(str(value))

        # Cidr - IP address range (Rust core)
        if hasattr(constraint, "contains_ip"):
            return constraint.contains_ip(str(value))

        # Pattern - glob matching (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Pattern":
            return constraint.matches(value)

        # Shlex - shell command validation (Rust core via Python shlex)
        if hasattr(constraint, "matches") and constraint_type == "Shlex":
            return constraint.matches(str(value))

        # UrlPattern - URL pattern matching (Rust core)
        if hasattr(constraint, "matches_url"):
            return constraint.matches_url(str(value))

        # Range - numeric bounds (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "Range":
            try:
                return constraint.contains(float(value))
            except (ValueError, TypeError):
                return False

        # Exact - exact value match (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Exact":
            return constraint.matches(str(value))

        # OneOf - set membership (Rust core)
        if hasattr(constraint, "contains") and constraint_type == "OneOf":
            return constraint.contains(str(value))

        # NotOneOf - exclusion list (Rust core)
        if hasattr(constraint, "allows") and constraint_type == "NotOneOf":
            return constraint.allows(str(value))

        # Wildcard - matches anything (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Wildcard":
            return constraint.matches(str(value))

        # Regex - regex matching (Rust core)
        if hasattr(constraint, "matches") and constraint_type == "Regex":
            return constraint.matches(value)

        # Fallback: generic matches() for other constraints
        if hasattr(constraint, "matches"):
            return constraint.matches(value)

        # Fallback: check() method (some libraries use this)
        if hasattr(constraint, "check"):
            return constraint.check(value)

        # Fallback: equality for Exact values without methods
        if hasattr(constraint, "value"):
            return constraint.value == value

        # Unknown constraint type - FAIL CLOSED
        logger.warning(f"Unknown constraint type '{constraint_type}' in type annotation - failing closed")
        return False

    except Exception as e:
        logger.warning(f"Constraint check failed with exception: {e} - failing closed")
        return False


def _extract_annotated_constraints(func: Callable) -> dict[str, Any]:
    """
    Extract Tenuo constraints from Annotated type hints.

    Example:
        def read_file(path: Annotated[str, Pattern("/data/*")]) -> str: ...

    Returns:
        {"path": Pattern("/data/*")}
    """
    constraints: dict[str, Any] = {}

    try:
        hints = get_type_hints(func, include_extras=True)
    except Exception:
        return constraints

    for param_name, hint in hints.items():
        if param_name == "return":
            continue

        # Check if it's Annotated[T, ...]
        if get_origin(hint) is Annotated:
            args = get_args(hint)
            # args[0] is the base type, args[1:] are the annotations
            for annotation in args[1:]:
                if _is_tenuo_constraint(annotation):
                    constraints[param_name] = annotation
                    break

    return constraints


# Context variable for warrant storage (works with both threads and asyncio)
# This allows warrants to be passed through async call stacks without explicit threading
_warrant_context: ContextVar[Optional[Warrant]] = ContextVar("_warrant_context", default=None)

# Context variable for keypair storage (for PoP signatures)
_keypair_context: ContextVar[Optional[SigningKey]] = ContextVar("_keypair_context", default=None)

# Context variable for allowed tools (narrower than warrant.tools)
# Used by scoped_task to restrict tools beyond what the warrant allows
_allowed_tools_context: ContextVar[Optional[List[str]]] = ContextVar("_allowed_tools_context", default=None)

# Context variable for test bypass mode (set by allow_all())
# When True, @guard skips authorization entirely
# SECURITY: Only works when TENUO_ENV=test to prevent accidental production bypass
_bypass_context: ContextVar[bool] = ContextVar("_bypass_context", default=False)

# Track bypass call count for audit purposes
_bypass_call_count: int = 0


def is_bypass_enabled() -> bool:
    """
    Check if authorization bypass is enabled (for testing).

    SECURITY: Bypass only works when TENUO_ENV environment variable is set to 'test'.
    This prevents accidental enablement in production.

    Returns:
        True if bypass is enabled AND we're in test mode, False otherwise.
    """
    import os

    if not _bypass_context.get():
        return False

    # SECURITY GUARD: Only allow bypass in test environment
    env = os.environ.get("TENUO_ENV", "").lower()
    if env != "test":
        # Log warning but don't bypass - someone tried to enable bypass in non-test env
        import warnings

        warnings.warn(
            "[SECURITY] Bypass mode requested but TENUO_ENV != 'test'. "
            "Bypass is disabled. Set TENUO_ENV=test to enable bypass for testing.",
            SecurityWarning,
            stacklevel=2,
        )
        return False

    # Audit log bypass usage
    global _bypass_call_count
    _bypass_call_count += 1

    return True


def get_bypass_call_count() -> int:
    """Get the number of times bypass was used (for auditing)."""
    return _bypass_call_count


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


@overload
def warrant_scope() -> Optional[Warrant]: ...
@overload
def warrant_scope(warrant: Warrant) -> "WarrantContext": ...


def warrant_scope(warrant: Optional[Warrant] = None) -> Union[Optional[Warrant], "WarrantContext"]:
    """
    Get or set the warrant context.

    Usage as getter (no args):
        warrant = warrant_scope()

    Usage as setter (context manager):
        with warrant_scope(warrant):
            process_request()  # @guard uses this warrant
    """
    if warrant is None:
        return _warrant_context.get()
    return WarrantContext(warrant)


@overload
def key_scope() -> Optional[SigningKey]: ...
@overload
def key_scope(keypair: SigningKey) -> "SigningKeyContext": ...


def key_scope(keypair: Optional[SigningKey] = None) -> Union[Optional[SigningKey], "SigningKeyContext"]:
    """
    Get or set the signing key context.

    Usage as getter (no args):
        key = key_scope()

    Usage as setter (context manager):
        with key_scope(keypair):
            process_request()  # @guard uses this key for PoP
    """
    if keypair is None:
        return _keypair_context.get()
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


def guard(
    warrant_or_tool: Optional[Union[Warrant, str]] = None,
    tool: Optional[str] = None,
    keypair: Optional[SigningKey] = None,
    extract_args: Optional[Callable[..., dict]] = None,
    mapping: Optional[dict[str, str]] = None,
):
    """
    Decorator that enforces warrant authorization before function execution.

    IMPORTANT: PoP is MANDATORY
    ---------------------------
    Keypair must always be available (either provided or in context) because
    Proof-of-Possession is mandatory. This ensures leaked warrants are useless
    without the corresponding private key.

    Supports multiple usage patterns:

    1. Minimal (tool name inferred from function name):
        @guard
        def search(query: str): ...  # tool="search"

    2. With Annotated constraints (auto-extracted):
        @guard
        def read_file(path: Annotated[str, Pattern("/data/*")]) -> str: ...

    3. Explicit tool name:
        @guard(tool="manage_infrastructure")
        def scale_cluster(cluster: str, replicas: int): ...

    4. Explicit warrant (for non-context usage):
        @guard(warrant, tool="manage_infrastructure", keypair=keypair)
        def scale_cluster(cluster: str, replicas: int): ...

    Args:
        warrant_or_tool: If Warrant instance, use it explicitly. If str, treat as tool name.
                        If None, tool is inferred from function name.
        tool: The tool name to authorize (optional - inferred from function name if not provided)
        keypair: SigningKey for PoP signature (required - or use key_scope)
        extract_args: Optional function to extract args from function arguments.
                     If None, uses the function's kwargs as args.
        mapping: Optional dictionary mapping function argument names to constraint names.
                 e.g., {"target_env": "cluster"} maps arg 'target_env' to constraint 'cluster'.

    Raises:
        AuthorizationError: If no warrant/keypair is available, or authorization fails.
    """
    # Determine warrant and tool
    active_warrant: Optional[Warrant] = None
    active_keypair: Optional[SigningKey] = keypair
    tool_name: Optional[str] = None

    if isinstance(warrant_or_tool, Warrant):
        # Pattern: @guard(warrant, tool="...")
        active_warrant = warrant_or_tool
        tool_name = tool
    elif isinstance(warrant_or_tool, str):
        # Pattern: @guard("tool_name") or @guard(tool="tool_name")
        tool_name = warrant_or_tool
    elif callable(warrant_or_tool):
        # Pattern: @guard (no parentheses) - warrant_or_tool is actually the function
        # Infer tool name from function name
        func = warrant_or_tool
        inferred_tool = func.__name__
        # Apply decorator and return immediately
        inner_decorator = guard(tool=inferred_tool, keypair=keypair, extract_args=extract_args, mapping=mapping)
        return inner_decorator(func)
    else:
        # Pattern: @guard(tool="...") - tool passed as keyword arg
        tool_name = tool

    def decorator(func: Callable) -> Callable:
        # Infer tool name from function name if not provided
        nonlocal tool_name
        if tool_name is None:
            tool_name = func.__name__

        # Extract annotated constraints for defense-in-depth enforcement
        # This allows the code to define strict boundaries that even a broad warrant cannot violate
        annotated_constraints = _extract_annotated_constraints(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check for test bypass mode (set by allow_all())
            if is_bypass_enabled():
                return func(*args, **kwargs)

            from .config import get_config

            config = get_config()
            callsite = _get_callsite()
            func_name = f"{func.__module__}.{func.__qualname__}"

            warrant_to_use = active_warrant or get_warrant_context()

            if warrant_to_use is None:
                error_code = AuthErrorCode.MISSING_CONTEXT

                audit_logger.log(
                    AuditEvent(
                        event_type=AuditEventType.AUTHORIZATION_FAILURE,
                        tool=tool_name,
                        action="denied",
                        error_code=error_code,
                        details=f"No warrant context for {tool_name}",
                        metadata={
                            "callsite": callsite,
                            "function": func_name,
                        },
                    )
                )

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
                        "  This would fail in strict_mode. Add root_task() or warrant_scope()."
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
                expires_at = warrant_to_use.expires_at() if hasattr(warrant_to_use, "expires_at") else "unknown"
                error_code = AuthErrorCode.EXPIRED

                audit_logger.log(
                    AuditEvent(
                        event_type=AuditEventType.WARRANT_EXPIRED,
                        warrant_id=warrant_to_use.id if hasattr(warrant_to_use, "id") else None,
                        tool=tool_name,
                        action="denied",
                        error_code=error_code,
                        details=f"Warrant expired at {expires_at}",
                        metadata={
                            "callsite": callsite,
                            "function": func_name,
                            "expires_at": str(expires_at),
                        },
                    )
                )

                error_msg = _make_actionable_error(
                    error_code=error_code,
                    tool_name=tool_name,
                    func_name=func_name,
                    callsite=callsite,
                    details=f"Warrant expired at {expires_at}.",
                )
                raise ExpiredError(
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, "id") else "unknown", expired_at=expires_at
                )

            keypair_to_use = active_keypair or get_signing_key_context()

            # PoP is MANDATORY - keypair must always be available
            if keypair_to_use is None:
                error_code = AuthErrorCode.POP_MISSING

                audit_logger.log(
                    AuditEvent(
                        event_type=AuditEventType.POP_FAILED,
                        warrant_id=warrant_to_use.id if hasattr(warrant_to_use, "id") else None,
                        tool=tool_name,
                        action="denied",
                        error_code=error_code,
                        details=f"Proof-of-Possession is mandatory but no keypair available for {tool_name}",
                        metadata={
                            "callsite": callsite,
                            "function": func_name,
                        },
                    )
                )

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
                    audit_logger.log(
                        AuditEvent(
                            event_type=AuditEventType.AUTHORIZATION_FAILURE,
                            tool=tool_name,
                            action="denied",
                            error_code="argument_binding_error",
                            details=f"Failed to bind arguments for {tool_name}: {e}",
                        )
                    )
                    raise

                if mapping:
                    mapped_args = {}
                    for arg_name, value in auth_args.items():
                        constraint_name = mapping.get(arg_name, arg_name)
                        mapped_args[constraint_name] = value
                    auth_args = mapped_args

            # Defense in Depth: Enforce code-level constraints from Annotated hints
            # These are checked BEFORE the warrant, preventing unsafe values even if authorized
            if annotated_constraints:
                for param, constraint in annotated_constraints.items():
                    if param in auth_args:
                        val = auth_args[param]
                        # Check constraint using Rust core bindings (type-aware)
                        is_valid = _check_annotated_constraint(constraint, val)

                        if not is_valid:
                            # Use AuthorizatonDenied for rich error
                            details = f"Value '{val}' violates code-defined constraint for '{param}'"
                            hint = f"Function signature requires: {constraint}"

                            # Log the enforcement block
                            audit_logger.log(
                                AuditEvent(
                                    event_type=AuditEventType.AUTHORIZATION_FAILURE,
                                    tool=tool_name,
                                    action="denied",
                                    error_code="CODE_CONSTRAINT_VIOLATION",
                                    details=details,
                                    metadata={"param": param, "value": str(val), "constraint": str(constraint)},
                                )
                            )

                            raise AuthorizationDenied(
                                tool=tool_name,
                                reason=details,
                                hint=hint,
                                constraint_results=[
                                    ConstraintResult(
                                        name=param,
                                        passed=False,
                                        constraint_repr=str(constraint),
                                        value=val,
                                        explanation="Violated type hint constraint",
                                    )
                                ],
                            )

            pop_signature = warrant_to_use.sign(keypair_to_use, tool_name, auth_args)

            # pop_signature is list[int], convert to bytes
            if not warrant_to_use.authorize(tool_name, auth_args, signature=bytes(pop_signature)):
                warrant_tools = warrant_to_use.tools if hasattr(warrant_to_use, "tools") else []

                # Tool not in warrant
                if tool_name not in (warrant_tools or []):
                    error_code = AuthErrorCode.SCOPE_VIOLATION

                    audit_logger.log(
                        AuditEvent(
                            event_type=AuditEventType.AUTHORIZATION_FAILURE,
                            warrant_id=warrant_to_use.id if hasattr(warrant_to_use, "id") else None,
                            tool=tool_name,
                            action="denied",
                            error_code=error_code,
                            details=f"Tool '{tool_name}' not in warrant.tools",
                            metadata={
                                "callsite": callsite,
                                "function": func_name,
                                "warrant_tools": warrant_tools,
                            },
                        )
                    )

                    raise ToolNotAuthorized(
                        tool=tool_name,
                        authorized_tools=warrant_tools,
                        hint=f"Add Capability('{tool_name}', ...) to your mint() call",
                    )

                # Tool is in warrant but constraint violation
                error_code = AuthErrorCode.CONSTRAINT_VIOLATION

                # Get structured denial reason
                why = warrant_to_use.why_denied(tool_name, auth_args)

                # Build constraint results for rich error
                constraint_results = []
                if hasattr(why, "constraint_failures") and why.constraint_failures:
                    for field, info in why.constraint_failures.items():
                        constraint_results.append(
                            ConstraintResult(
                                name=field,
                                passed=False,
                                constraint_repr=str(info.get("expected", "?")),
                                value=auth_args.get(field, "<not provided>"),
                                explanation=info.get("reason", "Constraint not satisfied"),
                            )
                        )
                else:
                    # Fallback: build from args
                    for arg_name, arg_value in auth_args.items():
                        constraint_results.append(
                            ConstraintResult(
                                name=arg_name,
                                passed=False,
                                constraint_repr="<see warrant>",
                                value=arg_value,
                                explanation="Value does not satisfy constraint",
                            )
                        )

                audit_logger.log(
                    AuditEvent(
                        event_type=AuditEventType.AUTHORIZATION_FAILURE,
                        warrant_id=warrant_to_use.id if hasattr(warrant_to_use, "id") else None,
                        tool=tool_name,
                        action="denied",
                        constraints=auth_args,
                        trace_id=warrant_to_use.session_id if hasattr(warrant_to_use, "session_id") else None,
                        error_code=error_code,
                        details=f"Constraint violation for '{tool_name}'",
                        metadata={
                            "callsite": callsite,
                            "function": func_name,
                            "warrant_tools": warrant_tools,
                            "provided_args": {k: str(v)[:100] for k, v in auth_args.items()},
                            "suggestion": why.suggestion if hasattr(why, "suggestion") else None,
                        },
                    )
                )

                # Build explorer URL for debugging
                warrant_b64 = warrant_to_use.to_base64() if hasattr(warrant_to_use, "to_base64") else ""
                explorer_url = f"https://tenuo.ai/explorer/#warrant={warrant_b64[:50]}..." if warrant_b64 else None

                hint = why.suggestion if hasattr(why, "suggestion") else None
                if explorer_url:
                    hint = f"{hint}\n\n🔗 Debug: {explorer_url}" if hint else f"🔗 Debug: {explorer_url}"

                raise AuthorizationDenied(
                    tool=tool_name,
                    constraint_results=constraint_results,
                    reason="Arguments do not satisfy warrant constraints",
                    hint=hint,
                )

            audit_logger.log(
                AuditEvent(
                    event_type=AuditEventType.AUTHORIZATION_SUCCESS,
                    warrant_id=warrant_to_use.id if hasattr(warrant_to_use, "id") else None,
                    tool=tool_name,
                    action="authorized",
                    constraints=auth_args,
                    trace_id=warrant_to_use.session_id if hasattr(warrant_to_use, "session_id") else None,
                    details=f"Authorization successful for {tool_name}",
                    metadata={
                        "callsite": callsite,
                        "function": func_name,
                    },
                )
            )

            return func(*args, **kwargs)

        return wrapper

    return decorator
