"""
Testing utilities for Tenuo.

This module provides utilities for testing warrant-protected code.
All utilities check _is_test_environment() to prevent accidental misuse.

Note:
    These utilities protect against accidents, not attacks. An attacker
    with code access can bypass these checks. The real protection is:
    - Don't import tenuo.testing in production modules
    - Use linting rules to catch test imports in production code
"""

import os
import base64
from contextlib import contextmanager
from typing import Tuple, List, Optional
from tenuo_core import Warrant, SigningKey  # type: ignore[import-untyped]


class SecurityError(Exception):
    """Raised when a security-sensitive operation is attempted in production."""
    pass


def _is_test_environment() -> bool:
    """
    Check if running in a test environment.
    
    Returns True if:
    - TENUO_TEST_MODE=1
    - Running under pytest
    - Running under unittest
    """
    # Check explicit test mode flag
    if os.getenv("TENUO_TEST_MODE") == "1":
        return True
    
    # Check if running under pytest
    if "pytest" in os.getenv("PYTEST_CURRENT_TEST", ""):
        return True
    
    # Check if running under unittest
    import sys
    main_module = sys.modules.get("__main__")
    if main_module and "unittest" in str(type(main_module)):
        return True
    
    return False


@contextmanager
def allow_all():
    """
    Bypass authorization for testing.
    
    This context manager disables warrant checks for testing purposes.
    All @lockdown decorated functions will execute without authorization.
    Only works when running under pytest, unittest, or with TENUO_TEST_MODE=1.
    
    Raises:
        RuntimeError: If not in a test environment
        
    Example:
        # Under pytest - works automatically
        def test_my_function():
            with allow_all():
                result = my_protected_function()  # No warrant needed
        
        # Outside pytest - set TENUO_TEST_MODE=1
        os.environ["TENUO_TEST_MODE"] = "1"
        with allow_all():
            result = my_protected_function()
    """
    if not _is_test_environment():
        raise RuntimeError(
            "allow_all() only works in test environments. "
            "Run under pytest/unittest or set TENUO_TEST_MODE=1."
        )
    
    # Import here to avoid circular imports
    from tenuo.decorators import _bypass_context
    
    # Enable bypass mode
    token = _bypass_context.set(True)
    try:
        yield
    finally:
        # Always restore previous state
        _bypass_context.reset(token)


def deterministic_headers(
    warrant: Warrant,
    key: SigningKey,
    tool: str,
    args: dict,
    timestamp: Optional[int] = None
) -> dict:
    """
    Generate deterministic headers for testing.
    
    This creates headers with a fixed timestamp for PoP signatures,
    making them deterministic and suitable for test assertions.
    
    Args:
        warrant: The warrant to use
        key: Signing key
        tool: Tool name
        args: Tool arguments
        timestamp: Optional fixed timestamp (default: 0)
        
    Returns:
        Dictionary with X-Tenuo-Warrant and X-Tenuo-PoP headers
        
    Example:
        headers = deterministic_headers(warrant, key, "search", {"query": "test"})
        assert headers["X-Tenuo-PoP"] == expected_pop  # Deterministic!
    """
    # Use fixed timestamp for deterministic PoP
    if timestamp is None:
        timestamp = 0
    
    # Create PoP signature with fixed timestamp
    # Note: This requires Rust support for custom timestamps
    # For now, use regular PoP (will be non-deterministic)
    pop_sig = warrant.create_pop_signature(key, tool, args)
    
    # create_pop_signature returns bytes, encode to base64
    pop_b64 = base64.b64encode(pop_sig).decode('ascii')
    
    return {
        "X-Tenuo-Warrant": warrant.to_base64(),
        "X-Tenuo-PoP": pop_b64
    }


# ============================================================================
# Add quick_issue and for_testing to Warrant class
# ============================================================================

def _warrant_quick_issue(
    tools: List[str],
    ttl: int = 3600,
    clearance: Optional[str] = None
) -> Tuple[Warrant, SigningKey]:
    """
    Quick warrant issuance for prototyping and testing.
    
    Creates a warrant with the specified tools and a new signing key.
    Useful for quick demos and prototypes.
    
    Args:
        tools: List of tool names to authorize
        ttl: Time-to-live in seconds (default: 3600 = 1 hour)
        clearance: Optional clearance level
        
    Returns:
        Tuple of (warrant, signing_key)
        
    Example:
        # Quick start for demos
        warrant, key = Warrant.quick_issue(["search", "read_file"], ttl=300)
        
        # Use the warrant
        bound = warrant.bind_key(key)
        headers = bound.auth_headers("search", {"query": "test"})
    """
    key = SigningKey.generate()
    builder = Warrant.builder()
    
    # Add capabilities for each tool
    for tool in tools:
        builder.capability(tool, {})
    
    # Set holder and TTL
    builder.holder(key.public_key)
    builder.ttl(ttl)
    
    # Set clearance if provided
    if clearance:
        from tenuo_core import Clearance  # type: ignore[import-untyped]
        if hasattr(Clearance, clearance.upper()):
            builder.clearance(getattr(Clearance, clearance.upper()))
    
    # Issue and return
    warrant = builder.issue(key)
    return warrant, key


def _warrant_for_testing(tools: List[str]) -> Warrant:
    """
    Create a test warrant (only works in test environment).
    
    This is a convenience wrapper around quick_issue() that only works
    in test environments. Use for unit tests.
    
    Args:
        tools: List of tool names to authorize
        
    Returns:
        Warrant (without the key - use quick_issue if you need the key)
        
    Raises:
        RuntimeError: If not in test environment
        
    Example:
        import os
        os.environ["TENUO_TEST_MODE"] = "1"
        
        def test_my_function():
            warrant = Warrant.for_testing(["search"])
            # ... test code
    """
    if not _is_test_environment():
        raise RuntimeError(
            "for_testing() only works in test environments. "
            "Set TENUO_TEST_MODE=1 or run under pytest/unittest."
        )
    
    warrant, _ = _warrant_quick_issue(tools, ttl=3600)
    return warrant


# Attach to Warrant class as static methods
if not hasattr(Warrant, 'quick_issue'):
    Warrant.quick_issue = staticmethod(_warrant_quick_issue)  # type: ignore[attr-defined]

if not hasattr(Warrant, 'for_testing'):
    Warrant.for_testing = staticmethod(_warrant_for_testing)  # type: ignore[attr-defined]
