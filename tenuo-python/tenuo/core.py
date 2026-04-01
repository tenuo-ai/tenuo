"""
Core Tenuo utilities for framework integrations.

This module provides framework-agnostic functions used by multiple
Tenuo integrations (OpenAI, CrewAI, LangChain, etc.).

By centralizing this logic here, we avoid coupling between framework
adapters (e.g., CrewAI importing from OpenAI).
"""

import logging
from typing import Any

logger = logging.getLogger("tenuo.core")

# Type alias for any constraint type
Constraint = Any


def check_constraint(constraint: Constraint, value: Any) -> bool:
    """Check if a value satisfies a constraint using the Rust core.

    All tenuo_core constraint objects expose a unified `.satisfies(value)`
    method.  Python-only constraints (e.g. Shlex) also implement `.satisfies()`
    so this function never needs to fall back to a reimplementation.

    SECURITY: Fails closed — unknown or unrecognised constraint types return
    False, never True.  Exceptions from `.satisfies()` propagate so callers
    see the real error rather than a silent allow/deny from a stale Python copy.

    Args:
        constraint: A Tenuo constraint object (tenuo_core or Python).
        value: The value to check.

    Returns:
        True if value satisfies the constraint, False otherwise.
    """
    constraint_type = type(constraint).__name__

    # Range: the Rust binding expects a numeric type; coerce strings so that
    # callers passing "50" still get a meaningful check instead of an error.
    if constraint_type == "Range" and hasattr(constraint, "satisfies"):
        try:
            return constraint.satisfies(float(value))
        except (ValueError, TypeError):
            return False  # Non-numeric — fail closed

    # Unified interface: every current tenuo_core constraint and Shlex support
    # .satisfies().  This is the only code path that should ever execute.
    if hasattr(constraint, "satisfies"):
        try:
            return constraint.satisfies(value)
        except (TypeError, ValueError):
            # e.g. None passed to a string-only constraint, or a non-numeric
            # value passed to Range.  Fail closed — don't call the removed
            # Python reimplementation.
            return False
        except Exception:
            # Rust raised an unexpected error (bad IP, invalid URL, CEL syntax
            # error …).  Fail closed and surface the problem in logs so it can
            # be diagnosed without crashing the caller.
            logger.warning(
                "Constraint '%s'.satisfies() raised for value %r — failing closed.",
                constraint_type,
                value,
            )
            return False

    # SECURITY: Unknown constraint type — fail closed.
    # If you hit this, the constraint is missing a .satisfies() method.
    # Add one rather than adding another branch here.
    logger.error(
        "Unknown constraint type '%s' has no .satisfies() method. "
        "Failing closed per Tenuo security policy.",
        constraint_type,
    )
    return False


__all__ = [
    "check_constraint",
]
