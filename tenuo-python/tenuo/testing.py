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

import base64
import os
from contextlib import contextmanager
from typing import List, Optional, Tuple

from tenuo_core import SigningKey, Warrant  # type: ignore[import-untyped]

from .exceptions import AuthorizationDenied


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
    All @guard decorated functions will execute without authorization.
    Only works when running under pytest, unittest, or with TENUO_TEST_MODE=1.

    Raises:
        RuntimeError: If not in a test environment

    Example:
        # Under pytest - works automatically
        # Create a dummy function decorated with @guard
        from tenuo.decorators import guard
        @guard(tool="test_tool")
        def protected_function(arg1, arg2):
            return f"{arg1}-{arg2}"

        with allow_all():
            result = protected_function("hello", "world") # No warrant needed
            assert result == "hello-world"

        # Outside pytest - set TENUO_TEST_MODE=1
        os.environ["TENUO_TEST_MODE"] = "1"
        with allow_all():
            result = protected_function("foo", "bar")
            assert result == "foo-bar"
    """
    if not _is_test_environment():
        raise RuntimeError(
            "allow_all() only works in test environments. Run under pytest/unittest or set TENUO_TEST_MODE=1."
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
    warrant: Warrant, key: SigningKey, tool: str, args: dict, timestamp: Optional[int] = None
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
        timestamp = 1234567890

    # Create PoP signature with fixed timestamp
    pop_sig = warrant.sign(key, tool, args, timestamp)
    # sign returns bytes, encode to base64
    pop_b64 = base64.b64encode(pop_sig).decode("ascii")

    return {"X-Tenuo-Warrant": warrant.to_base64(), "X-Tenuo-PoP": pop_b64}


# ============================================================================
# Add quick_issue and for_testing to Warrant class
# ============================================================================


def _warrant_quick_mint(
    tools: List[str], ttl: int = 3600, clearance: Optional[str] = None
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
        warrant, key = Warrant.quick_mint(["search", "read_file"], ttl=300)

        # Use the warrant
        bound = warrant.bind(key)
        headers = bound.headers("search", {"query": "test"})
    """
    key = SigningKey.generate()
    builder = Warrant.mint_builder()

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
    warrant = builder.mint(key)
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
            "for_testing() only works in test environments. Set TENUO_TEST_MODE=1 or run under pytest/unittest."
        )

    warrant, _ = _warrant_quick_mint(tools, ttl=3600)
    return warrant


# Attach to Warrant class as static methods
if not hasattr(Warrant, "quick_issue"):
    Warrant.quick_mint = staticmethod(_warrant_quick_mint)  # type: ignore[attr-defined]

if not hasattr(Warrant, "for_testing"):
    Warrant.for_testing = staticmethod(_warrant_for_testing)  # type: ignore[attr-defined]


# ============================================================================
# Test Assertions - assert_authorized / assert_denied
# ============================================================================


class AuthorizationAssertionError(AssertionError):
    """Raised when an authorization assertion fails."""

    pass


@contextmanager
def assert_authorized(
    warrant: Optional[Warrant] = None,
    key: Optional[SigningKey] = None,
    tool: Optional[str] = None,
    args: Optional[dict] = None,
    *,
    message: Optional[str] = None,
):
    """
    Assert that code is authorized or that a warrant matches.

    Can be used as a context manager or a function.

    Context Manager Usage:
        with assert_authorized():
            protected_function()

    Function Usage:
        assert_authorized(warrant, key, "tool", args)
    """
    # Legacy Function Mode
    if warrant is not None:
        if not _is_test_environment():
            raise RuntimeError("assert_authorized() only works in test environments.")

        if key is None or tool is None:
            raise ValueError("If warrant is provided, key and tool are required.")

        args = args or {}
        try:
            bound = warrant.bind(key)
            result = bound.validate(tool, args)
            if not result:
                raise AuthorizationAssertionError(
                    message or f"Expected authorization to succeed for tool '{tool}', but it was denied: {result.reason}"
                )
        except Exception as e:
            if isinstance(e, AuthorizationAssertionError):
                raise
            raise AuthorizationAssertionError(f"Authorization failed with error: {e}") from e
        yield
        return

    # Context Manager Mode
    try:
        yield
    except AuthorizationDenied as e:
        raise AssertionError(
            message or f"Expected code to be authorized, but it raised AuthorizationDenied: {e}"
        ) from e
    except Exception:
        # Rethrow other exceptions (e.g. ValueError) as they are not auth failures
        raise


@contextmanager
def assert_denied(
    warrant: Optional[Warrant] = None,
    key: Optional[SigningKey] = None,
    tool: Optional[str] = None,
    args: Optional[dict] = None,
    *,
    expected_reason: Optional[str] = None,
    code: Optional[str] = None,
    message: Optional[str] = None,
):
    """
    Assert that code raises AuthorizationDenied or a warrant denies access.

    Context Manager Usage:
        with assert_denied(code="ScopeViolation"):
            protected_function()

    Function Usage:
        assert_denied(warrant, key, "tool", expected_reason="...")
    """
    # Legacy Function Mode
    if warrant is not None:
        if not _is_test_environment():
            raise RuntimeError("assert_denied() only works in test environments.")

        if key is None or tool is None:
            raise ValueError("If warrant is provided, key and tool are required.")

        args = args or {}
        try:
            bound = warrant.bind(key)
            result = bound.validate(tool, args)
            if result:
                raise AuthorizationAssertionError(
                    message or f"Expected authorization to FAIL for tool '{tool}', but it was ALLOWED."
                )
        except AuthorizationAssertionError:
            raise
        except Exception as e:
            # Grant failed as expected, check reason
            error_str = str(e)
            if expected_reason and expected_reason not in error_str:
                raise AuthorizationAssertionError(
                    message or f"Authorization denied as expected, but reason mismatch. Got: {error_str}"
                ) from e
        yield
        return

    # Context Manager Mode
    try:
        yield
    except AuthorizationDenied as exc:
        # Check code/reason
        if code:
            if not hasattr(exc, "error_code") or exc.error_code != code:
                current_code = getattr(exc, "error_code", "None")
                raise AssertionError(
                    f"Caught AuthorizationDenied as expected, but code mismatch. "
                    f"Expected '{code}', got '{current_code}'."
                )
        if expected_reason and expected_reason not in str(exc):
            raise AssertionError(
                f"Caught AuthorizationDenied as expected, but reason mismatch. Expected '{expected_reason}' in '{exc}'."
            )
        # Success - caught expected exception
        return
    except Exception:
        # Rethrow unexpected exceptions
        raise

    # If we got here, no exception was raised
    raise AssertionError(message or "Expected AuthorizationDenied but code succeeded")


def assert_can_grant(
    parent: Warrant,
    parent_key: SigningKey,
    child_tools: List[str],
    child_constraints: Optional[dict] = None,
    *,
    message: Optional[str] = None,
) -> Tuple[Warrant, SigningKey]:
    """
    Assert that a grant (delegation) from parent to child is valid.

    This verifies monotonic attenuation - that the child warrant
    has properly narrowed capabilities from the parent.

    Args:
        parent: Parent warrant to grant from
        parent_key: Signing key for parent
        child_tools: List of tools for child warrant
        child_constraints: Additional constraints for child (optional)
        message: Custom assertion message (optional)

    Returns:
        Tuple of (child_warrant, child_key) on success

    Raises:
        AuthorizationAssertionError: If grant fails

    Example:
        def test_delegation_chain():
            root, root_key = Warrant.quick_mint(["search", "read_file"], ttl=3600)

            # Grant subset of tools
            child, child_key = assert_can_grant(
                root, root_key,
                child_tools=["read_file"],
            )

            # Child can read_file but not search
            assert_authorized(child, child_key, "read_file", {"path": "/data/x"})
            assert_denied(child, child_key, "search", {"query": "test"})
    """
    if not _is_test_environment():
        raise RuntimeError(
            "assert_can_grant() only works in test environments. Set TENUO_TEST_MODE=1 or run under pytest/unittest."
        )

    try:
        child_key = SigningKey.generate()

        # Build the grant using grant_builder
        builder = parent.grant_builder()

        # Set tools
        for tool in child_tools:
            if child_constraints:
                builder.capability(tool, child_constraints)
            else:
                builder.capability(tool, {})

        # Set holder and TTL
        builder.holder(child_key.public_key)
        builder.ttl(parent.ttl)  # Inherit TTL

        # Grant
        child = builder.grant(parent_key)

        return child, child_key

    except Exception as e:
        raise AuthorizationAssertionError(message or f"Expected grant to succeed, but it failed: {e}") from e


def assert_cannot_grant(
    parent: Warrant,
    parent_key: SigningKey,
    child_tools: List[str],
    child_constraints: Optional[dict] = None,
    *,
    expected_reason: Optional[str] = None,
    message: Optional[str] = None,
) -> None:
    """
    Assert that a grant (delegation) would fail due to monotonicity violation.

    This verifies that attempts to expand capabilities beyond the parent
    are properly rejected.

    Args:
        parent: Parent warrant to attempt grant from
        parent_key: Signing key for parent
        child_tools: List of tools for attempted child warrant
        child_constraints: Constraints for child (optional)
        expected_reason: Expected error substring (optional)
        message: Custom assertion message (optional)

    Raises:
        AuthorizationAssertionError: If grant unexpectedly succeeds

    Example:
        def test_monotonicity_enforcement():
            root, root_key = Warrant.quick_mint(["read_file"], ttl=3600)

            # Cannot grant a tool not in parent
            assert_cannot_grant(
                root, root_key,
                child_tools=["delete_file"],  # Not in parent!
                expected_reason="ToolNotAuthorized",
            )
    """
    if not _is_test_environment():
        raise RuntimeError(
            "assert_cannot_grant() only works in test environments. Set TENUO_TEST_MODE=1 or run under pytest/unittest."
        )

    try:
        child, _ = assert_can_grant(parent, parent_key, child_tools, child_constraints)

        # If we get here, grant unexpectedly succeeded
        raise AuthorizationAssertionError(
            message
            or f"Expected grant to FAIL for tools {child_tools}, but it succeeded and created warrant {child.id}."
        )

    except AuthorizationAssertionError as e:
        if "Expected grant to FAIL" in str(e):
            raise
        # Grant failed as expected
        error_str = str(e)
        if expected_reason and expected_reason not in error_str:
            raise AuthorizationAssertionError(
                message
                or f"Grant failed as expected, but the reason '{error_str}' "
                f"does not contain expected substring '{expected_reason}'."
            ) from e


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    # Test environment controls
    "SecurityError",
    "allow_all",
    "deterministic_headers",
    "_is_test_environment",
    # Assertion helpers
    "AuthorizationAssertionError",
    "assert_authorized",
    "assert_denied",
    "assert_can_grant",
    "assert_cannot_grant",
]
