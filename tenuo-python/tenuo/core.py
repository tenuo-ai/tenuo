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
    """Check if a value satisfies a constraint.

    Uses the Tenuo core constraint matching logic via the Rust bindings.
    Falls back to Python implementation only when Rust bindings are not available.

    SECURITY: Fails closed (returns False) for unknown constraint types.
    This follows Tenuo's "fail closed" philosophy - when in doubt, deny.

    UNIFIED INTERFACE: All Rust core constraints now support satisfies(value):
      - constraint.satisfies(value) -> Rust core (handles type conversion)

    The satisfies() method is the preferred interface.

    Args:
        constraint: A Tenuo constraint object
        value: The value to check against the constraint

    Returns:
        True if value satisfies the constraint, False otherwise
    """
    try:
        constraint_type = type(constraint).__name__

        # =================================================================
        # SPECIAL CASES - Type coercion required before satisfies()
        # =================================================================
        # Range requires explicit string-to-number coercion
        if constraint_type == "Range" and hasattr(constraint, "satisfies"):
            try:
                return constraint.satisfies(float(value))
            except (ValueError, TypeError):
                return False  # Non-numeric value fails Range check

        # =================================================================
        # UNIFIED INTERFACE - All Rust core constraints support satisfies()
        # =================================================================
        if hasattr(constraint, "satisfies"):
            return constraint.satisfies(value)

        # =================================================================
        # LEGACY FALLBACKS - For older constraint versions without satisfies()
        # =================================================================

        # Subpath - filesystem path containment
        if hasattr(constraint, "contains") and constraint_type == "Subpath":
            return constraint.contains(str(value))

        # UrlSafe - SSRF protection
        if hasattr(constraint, "is_safe"):
            return constraint.is_safe(str(value))

        # Cidr - IP address range
        if hasattr(constraint, "contains_ip"):
            return constraint.contains_ip(str(value))

        # Pattern/Shlex - pattern matching
        if hasattr(constraint, "matches"):
            return constraint.matches(str(value))

        # UrlPattern - URL pattern matching
        if hasattr(constraint, "matches_url"):
            return constraint.matches_url(str(value))

        # Range - numeric bounds
        if hasattr(constraint, "contains") and constraint_type == "Range":
            try:
                return constraint.contains(float(value))
            except (ValueError, TypeError):
                return False

        # OneOf - set membership
        if hasattr(constraint, "contains") and constraint_type == "OneOf":
            return constraint.contains(str(value))

        # NotOneOf - exclusion list
        if hasattr(constraint, "allows"):
            return constraint.allows(str(value))

        # =================================================================
        # FALLBACK - Python checks for constraints without Rust bindings
        # =================================================================
        return _python_constraint_check(constraint, value)

    except Exception as e:
        # If Rust binding fails, try Python fallback
        logger.debug(f"Rust constraint check failed, using Python fallback: {e}")
        return _python_constraint_check(constraint, value)


def _python_constraint_check(constraint: Constraint, value: Any) -> bool:
    """Python fallback for constraint checking.

    SECURITY: This function follows Tenuo's "fail closed" philosophy.
    Unknown constraint types return False, not True.
    """
    import fnmatch
    import ipaddress
    import re as regex_module

    constraint_type = type(constraint).__name__

    if constraint_type == "Pattern":
        # Glob pattern matching
        pattern = _get_attr_safe(constraint, "pattern")
        if pattern is None:
            logger.warning("Pattern constraint has no pattern attribute, failing closed")
            return False
        return fnmatch.fnmatch(str(value), pattern)

    elif constraint_type == "Exact":
        # Exact match
        expected = _get_attr_safe(constraint, "value")
        return value == expected

    elif constraint_type == "OneOf":
        # Set membership
        allowed = _get_attr_safe(constraint, "values")
        if allowed is None:
            return False
        return value in allowed

    elif constraint_type == "Range":
        # Numeric range - type-strict like Rust core
        # NOTE: ConstraintValue::as_number() returns None for strings,
        # so "15" as a string would NOT match Range(0,100).
        # Only actual int/float types pass. This matches Tenuo's rigorous semantics.
        min_val = _get_attr_safe(constraint, "min")
        max_val = _get_attr_safe(constraint, "max")

        # Type-strict: only int/float pass, strings fail (matches Rust behavior)
        if not isinstance(value, (int, float)):
            return False

        try:
            num_value = float(value)
            if min_val is not None and num_value < min_val:
                return False
            if max_val is not None and num_value > max_val:
                return False
            return True
        except (ValueError, TypeError):
            return False

    elif constraint_type == "Regex":
        # Regex matching - uses fullmatch for complete string match (Tenuo spec semantics)
        pattern = _get_attr_safe(constraint, "pattern")
        if pattern is None:
            logger.warning("Regex constraint has no pattern attribute, failing closed")
            return False
        # fullmatch ensures the ENTIRE value matches, not just a prefix
        return bool(regex_module.fullmatch(pattern, str(value)))

    elif constraint_type == "Wildcard":
        # Wildcard matches anything
        return True

    elif constraint_type == "NotOneOf":
        # Exclusion set
        excluded = _get_attr_safe(constraint, "excluded")
        if excluded is None:
            excluded = []
        return value not in excluded

    elif constraint_type == "Contains":
        # List must contain required values
        required = _get_attr_safe(constraint, "required")
        if required is None:
            required = []
        if not isinstance(value, (list, set, tuple)):
            return False
        return all(r in value for r in required)

    elif constraint_type == "Subset":
        # Value must be subset of allowed
        allowed = _get_attr_safe(constraint, "allowed")
        if allowed is None:
            return False
        if not isinstance(value, (list, set, tuple)):
            return value in allowed
        return all(v in allowed for v in value)

    elif constraint_type == "Cidr":
        # IP address must be within CIDR range
        # Note: Tenuo uses .network attribute, not .cidr
        network_str = _get_attr_safe(constraint, "network")
        if network_str is None:
            logger.warning("Cidr constraint has no network attribute, failing closed")
            return False
        try:
            network = ipaddress.ip_network(str(network_str), strict=False)
            ip = ipaddress.ip_address(str(value))
            return ip in network
        except (ValueError, TypeError):
            return False

    elif constraint_type == "UrlPattern":
        # URL must match pattern (scheme, host, path)
        return _check_url_pattern(constraint, value)

    elif constraint_type == "CEL":
        # CEL expressions require Rust - cannot safely evaluate in Python
        # SECURITY: Fail closed. CEL is complex and must use the Rust evaluator.
        logger.warning(
            "CEL constraint cannot be evaluated in Python fallback. "
            "Ensure tenuo-core Rust bindings are available. Failing closed."
        )
        return False

    # Composite constraints - recursive checking
    elif constraint_type == "AnyOf":
        # OR: at least one constraint must match
        options = _get_attr_safe(constraint, "constraints")
        if not options:
            return False
        return any(check_constraint(c, value) for c in options)

    elif constraint_type == "All":
        # AND: all constraints must match
        constraints_list = _get_attr_safe(constraint, "constraints")
        if not constraints_list:
            return True  # Empty AND is vacuously true
        return all(check_constraint(c, value) for c in constraints_list)

    elif constraint_type == "Not":
        # NOT: inner constraint must NOT match
        inner = _get_attr_safe(constraint, "constraint")
        if inner is None:
            return False
        return not check_constraint(inner, value)

    # SECURITY: Unknown constraint type - fail closed
    # This is intentional. Tenuo's philosophy is "when in doubt, deny."
    logger.error(f"Unknown constraint type '{constraint_type}'. Failing closed per Tenuo security policy.")
    return False


def _get_attr_safe(obj: Any, attr: str) -> Any:
    """Safely get an attribute, handling both properties and methods."""
    val = getattr(obj, attr, None)
    if callable(val):
        try:
            return val()
        except Exception:
            return None
    return val


def _check_url_pattern(constraint: Any, value: Any) -> bool:
    """Check URL against UrlPattern constraint."""
    import fnmatch
    from urllib.parse import urlparse

    try:
        parsed = urlparse(str(value))

        # Check scheme if specified
        scheme = _get_attr_safe(constraint, "scheme")
        if scheme and parsed.scheme != scheme:
            return False

        # Check host if specified
        host = _get_attr_safe(constraint, "host")
        if host and not fnmatch.fnmatch(parsed.netloc, host):
            return False

        # Check path if specified
        path = _get_attr_safe(constraint, "path")
        if path and not fnmatch.fnmatch(parsed.path, path):
            return False

        return True
    except Exception:
        return False


__all__ = [
    "check_constraint",
]
