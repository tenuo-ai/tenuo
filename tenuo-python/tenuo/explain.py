"""
Human-readable error explanations for Tenuo.

Provides the explain() function to print actionable error diagnoses.

Usage:
    from tenuo import explain
    
    try:
        await read_file(path="/etc/passwd")
    except TenuoError as e:
        explain(e)
        # Output:
        # ❌ Authorization failed
        # 
        # Constraint violated: path
        #   Requested: /etc/passwd
        #   Allowed:   /data/*
        # 
        # How to fix:
        #   • Use a path matching: /data/*
        #   • Or request broader scope from root_task()
"""

import json
from typing import Optional, TextIO
import sys

from .exceptions import (
    TenuoError,
    ScopeViolation,
    ToolNotAuthorized,
    ConstraintViolation,
    ExpiredError,
    MonotonicityError,
    ConfigurationError,
    CryptoError,
    PopError,
    ChainError,
    RevokedError,
)


def explain(
    error: TenuoError,
    *,
    file: Optional[TextIO] = None,
    show_context: bool = True,
) -> None:
    """
    Print a detailed, actionable explanation of a Tenuo error.
    
    Args:
        error: The TenuoError to explain
        file: Output file (defaults to sys.stderr)
        show_context: Whether to show error context dict
    
    Example:
        try:
            await protected_tool(path="/etc/passwd")
        except TenuoError as e:
            explain(e)
    """
    out = file or sys.stderr
    
    print("\n❌ Authorization failed\n", file=out)
    
    # Tool not authorized
    if isinstance(error, ToolNotAuthorized):
        _explain_tool_not_authorized(error, out)
    
    # Constraint violation
    elif isinstance(error, ConstraintViolation):
        _explain_constraint_violation(error, out)
    
    # Warrant expired
    elif isinstance(error, ExpiredError):
        _explain_expired(error, out)
    
    # Monotonicity errors (attenuation failures)
    elif isinstance(error, MonotonicityError):
        _explain_monotonicity(error, out)
    
    # Configuration errors
    elif isinstance(error, ConfigurationError):
        _explain_configuration(error, out)
    
    # Crypto/signature errors
    elif isinstance(error, CryptoError):
        _explain_crypto(error, out)
    
    # PoP errors
    elif isinstance(error, PopError):
        _explain_pop(error, out)
    
    # Chain errors
    elif isinstance(error, ChainError):
        _explain_chain(error, out)
    
    # Revoked warrant
    elif isinstance(error, RevokedError):
        _explain_revoked(error, out)
    
    # Generic scope violation
    elif isinstance(error, ScopeViolation):
        _explain_scope_violation(error, out)
    
    # Generic error
    else:
        _explain_generic(error, out)
    
    # Show context if available and requested
    if show_context and hasattr(error, 'details') and error.details:
        print("\nContext:", file=out)
        print(f"  {json.dumps(error.details, indent=2, default=str)}", file=out)
    
    print("", file=out)  # Final newline


def _explain_tool_not_authorized(error: ToolNotAuthorized, out: TextIO) -> None:
    """Explain a ToolNotAuthorized error."""
    tool = error.details.get("tool", "unknown")
    authorized = error.details.get("authorized_tools", [])
    
    print(f"Tool not authorized: {tool}", file=out)
    if authorized:
        print("\nAuthorized tools:", file=out)
        for t in authorized:
            print(f"  • {t}", file=out)
    
    print("\nHow to fix:", file=out)
    print(f"  • Add capability for '{tool}': root_task(Capability(\"{tool}\", ...))", file=out)
    if authorized:
        print("  • Or use one of the authorized tools", file=out)


def _explain_constraint_violation(error: ConstraintViolation, out: TextIO) -> None:
    """Explain a ConstraintViolation error."""
    field = error.details.get("field", "unknown")
    reason = error.details.get("reason", "")
    value = error.details.get("value", None)
    
    print(f"Constraint violated: {field}", file=out)
    if value is not None:
        print(f"  Requested: {value}", file=out)
    if reason:
        print(f"  Reason: {reason}", file=out)
    
    print("\nHow to fix:", file=out)
    print(f"  • Use a value that satisfies the '{field}' constraint", file=out)
    print("  • Or request broader scope from root_task()", file=out)


def _explain_expired(error: ExpiredError, out: TextIO) -> None:
    """Explain an ExpiredError."""
    warrant_id = error.details.get("warrant_id", "unknown")
    expired_at = error.details.get("expired_at", "unknown")
    
    print(f"Warrant expired: {warrant_id}", file=out)
    if expired_at != "unknown":
        print(f"  Expired at: {expired_at}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Create a new root_task() with fresh TTL", file=out)
    print("  • Or increase TTL in original root_task(ttl=seconds)", file=out)


def _explain_monotonicity(error: MonotonicityError, out: TextIO) -> None:
    """Explain a MonotonicityError."""
    print(f"Attenuation violation: {error.message}", file=out)
    
    print("\nMonotonicity rule:", file=out)
    print("  Child warrants can only NARROW scope, never widen it.", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Use a more restrictive constraint in scoped_task()", file=out)
    print("  • Or request broader scope from the parent warrant", file=out)


def _explain_configuration(error: ConfigurationError, out: TextIO) -> None:
    """Explain a ConfigurationError."""
    print(f"Configuration error: {error.message}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Check your configure() call", file=out)
    print("  • Ensure issuer_key is set before using root_task()", file=out)
    print("  • In production, provide trusted_roots=[]", file=out)


def _explain_crypto(error: CryptoError, out: TextIO) -> None:
    """Explain a CryptoError."""
    print(f"Cryptographic error: {error.message}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Ensure you're using the correct keypair", file=out)
    print("  • Check that the warrant was created with the expected key", file=out)


def _explain_pop(error: PopError, out: TextIO) -> None:
    """Explain a PopError."""
    print(f"Proof-of-Possession error: {error.message}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Ensure keypair is set in context", file=out)
    print("  • Use root_task() which sets keypair automatically", file=out)
    print("  • Check PoP hasn't expired (short window)", file=out)


def _explain_chain(error: ChainError, out: TextIO) -> None:
    """Explain a ChainError."""
    print(f"Delegation chain error: {error.message}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Ensure scoped_task() is inside a root_task()", file=out)
    print("  • Check the warrant chain is valid", file=out)
    print("  • Verify trusted_roots contains the root issuer", file=out)


def _explain_revoked(error: RevokedError, out: TextIO) -> None:
    """Explain a RevokedError."""
    print(f"Warrant revoked: {error.message}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Create a new root_task() with a fresh warrant", file=out)
    print("  • The revoked warrant cannot be used", file=out)


def _explain_scope_violation(error: ScopeViolation, out: TextIO) -> None:
    """Explain a generic ScopeViolation."""
    print(f"Scope violation: {error.message}", file=out)
    
    print("\nHow to fix:", file=out)
    print("  • Check you're operating within the warrant's scope", file=out)
    print("  • Request broader scope from root_task() if needed", file=out)


def _explain_generic(error: TenuoError, out: TextIO) -> None:
    """Explain a generic TenuoError."""
    print(f"Error: {error.message}", file=out)
    print(f"Type: {type(error).__name__}", file=out)
    
    if hasattr(error, 'error_code'):
        print(f"Code: {error.error_code}", file=out)


def explain_str(error: TenuoError, show_context: bool = True) -> str:
    """
    Return explanation as a string instead of printing.
    
    Args:
        error: The TenuoError to explain
        show_context: Whether to include error context
    
    Returns:
        Human-readable explanation string
    """
    import io
    buffer = io.StringIO()
    explain(error, file=buffer, show_context=show_context)
    return buffer.getvalue()


__all__ = [
    "explain",
    "explain_str",
]
