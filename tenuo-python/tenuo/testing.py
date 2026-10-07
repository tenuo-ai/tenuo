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

try:
    from tenuo_core import WARRANT_HEADER as _WARRANT_HEADER  # type: ignore[attr-defined]
except ImportError:
    _WARRANT_HEADER = "X-Tenuo-Warrant"

from .exceptions import (
    AuthorizationDenied,
    ClearanceViolation,
    ConfigurationError,
    LimitError,
    MonotonicityError,
)


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

    # pytest sets PYTEST_CURRENT_TEST (a test id) while a test runs
    if os.getenv("PYTEST_CURRENT_TEST"):
        return True

    # Check if running under unittest (python -m unittest)
    import sys

    main_module = sys.modules.get("__main__")
    main_spec = getattr(main_module, "__spec__", None)
    if main_spec is not None and (main_spec.name or "").startswith("unittest"):
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

    return {_WARRANT_HEADER: warrant.to_base64(), "X-Tenuo-PoP": pop_b64}


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


def _assertion_trusted_roots(warrant: Warrant, explicit: Optional[List] = None) -> List:
    """Resolve the trust anchor for the warrant-and-key assertion helpers.

    These helpers answer "what does this warrant permit", not "who issued it",
    and they refuse to run outside a test environment, so they default to the
    warrant's own issuer. Deliberately not `tenuo.configure()`: reading global
    state here would make an assertion about one warrant depend on unrelated
    configuration, and on test ordering. Pass ``trusted_roots`` to assert
    issuer trust as well.
    """
    if explicit is not None:
        return list(explicit)
    return [warrant.issuer]


@contextmanager
def assert_authorized(
    warrant: Optional[Warrant] = None,
    key: Optional[SigningKey] = None,
    tool: Optional[str] = None,
    args: Optional[dict] = None,
    *,
    message: Optional[str] = None,
    trusted_roots: Optional[List] = None,
):
    """
    Assert that code is authorized or that a warrant matches.

    Context Manager Usage:
        with assert_authorized():
            protected_function()

    Warrant Usage:
        with assert_authorized(warrant, key, "tool", args):
            pass

    Both forms must be entered with ``with``. Calling it without ``with``
    returns an unentered context manager and checks nothing.

    Pass ``trusted_roots`` to assert issuer trust too; the default anchors on
    the configured roots, then the warrant's own issuer, so a self-minted test
    warrant is checked for what it permits.
    """
    # Legacy Function Mode
    if warrant is not None:
        if not _is_test_environment():
            raise RuntimeError("assert_authorized() only works in test environments.")

        if key is None or tool is None:
            raise ValueError("If warrant is provided, key and tool are required.")

        args = args or {}
        roots = _assertion_trusted_roots(warrant, trusted_roots)
        try:
            bound = warrant.bind(key, trusted_roots=roots)
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
    trusted_roots: Optional[List] = None,
):
    """
    Assert that code raises AuthorizationDenied or a warrant denies access.

    Context Manager Usage:
        with assert_denied(code="authorization_denied"):
            protected_function()

    Warrant Usage:
        with assert_denied(warrant, key, "tool", args):
            pass

    Both forms must be entered with ``with``. Calling it without ``with``
    returns an unentered context manager and checks nothing. ``code`` is
    matched against the ``error_code`` of the ``AuthorizationDenied`` raised
    (``"authorization_denied"`` for a ``@guard`` constraint failure).

    Pass ``trusted_roots`` to assert issuer trust too; the default anchors on
    the configured roots, then the warrant's own issuer, so a self-minted test
    warrant is checked for what it permits.
    """
    # Legacy Function Mode
    if warrant is not None:
        if not _is_test_environment():
            raise RuntimeError("assert_denied() only works in test environments.")

        if key is None or tool is None:
            raise ValueError("If warrant is provided, key and tool are required.")

        args = args or {}
        roots = _assertion_trusted_roots(warrant, trusted_roots)
        try:
            bound = warrant.bind(key, trusted_roots=roots)
            result = bound.validate(tool, args)
            if result:
                raise AuthorizationAssertionError(
                    message or f"Expected authorization to FAIL for tool '{tool}', but it was ALLOWED."
                )
        except AuthorizationAssertionError:
            raise
        except ConfigurationError:
            # A misconfigured harness is not a denial. Swallowing it here would
            # make this assertion pass for any warrant at all.
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


# Grant refusals that mean "the parent cannot delegate this". Anything else
# (wrong parent key, malformed constraint) is a broken test, not a refusal.
_ATTENUATION_ERRORS = (MonotonicityError, ClearanceViolation, LimitError)


def _attempt_grant(
    parent: Warrant,
    parent_key: SigningKey,
    child_tools: List[str],
    child_constraints: Optional[dict],
) -> Tuple[Warrant, SigningKey]:
    child_key = SigningKey.generate()
    builder = parent.grant_builder()
    for tool in child_tools:
        builder.capability(tool, child_constraints or {})
    # No TTL: the child inherits the parent's expiry.
    builder.holder(child_key.public_key)
    return builder.grant(parent_key), child_key


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
    has properly narrowed capabilities from the parent. The child
    expires with the parent.

    Args:
        parent: Parent warrant to grant from
        parent_key: Signing key of the parent's holder
        child_tools: List of tools for child warrant
        child_constraints: Constraints applied to every child tool (optional)
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
            with assert_authorized(child, child_key, "read_file", {"path": "/data/x"}):
                pass
            with assert_denied(child, child_key, "search", {"query": "test"}):
                pass
    """
    if not _is_test_environment():
        raise RuntimeError(
            "assert_can_grant() only works in test environments. Set TENUO_TEST_MODE=1 or run under pytest/unittest."
        )

    try:
        return _attempt_grant(parent, parent_key, child_tools, child_constraints)
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
    Assert that a grant (delegation) is refused because it would widen authority.

    Passes only when the grant is rejected for an attenuation reason
    (``MonotonicityError``, ``ClearanceViolation`` or ``LimitError``). Any
    other failure, such as signing with a key that does not hold the parent,
    is reported as an assertion error so a broken test cannot pass.

    Args:
        parent: Parent warrant to attempt grant from
        parent_key: Signing key of the parent's holder
        child_tools: List of tools for attempted child warrant
        child_constraints: Constraints applied to every child tool (optional)
        expected_reason: Substring expected in "<ExceptionType>: <message>" (optional)
        message: Custom assertion message (optional)

    Raises:
        AuthorizationAssertionError: If the grant succeeds, fails for a
            non-attenuation reason, or ``expected_reason`` is set and is not
            a substring of ``"<ExceptionType>: <message>"``. Omitting
            ``expected_reason`` is valid.

    Example:
        def test_monotonicity_enforcement():
            root, root_key = Warrant.quick_mint(["read_file"], ttl=3600)

            # Cannot grant a tool not in parent
            assert_cannot_grant(
                root, root_key,
                child_tools=["delete_file"],  # Not in parent!
                expected_reason="MonotonicityError",
            )
    """
    if not _is_test_environment():
        raise RuntimeError(
            "assert_cannot_grant() only works in test environments. Set TENUO_TEST_MODE=1 or run under pytest/unittest."
        )

    try:
        child, _ = _attempt_grant(parent, parent_key, child_tools, child_constraints)
    except _ATTENUATION_ERRORS as e:
        reason = f"{type(e).__name__}: {e}"
        if expected_reason and expected_reason not in reason:
            raise AuthorizationAssertionError(
                message
                or f"Grant failed as expected, but the reason '{reason}' "
                f"does not contain expected substring '{expected_reason}'."
            ) from e
        return
    except Exception as e:
        raise AuthorizationAssertionError(
            message
            or f"Expected grant to be refused for an attenuation reason, but it failed with "
            f"{type(e).__name__}: {e}. Check that parent_key holds the parent warrant."
        ) from e

    raise AuthorizationAssertionError(
        message or f"Expected grant to FAIL for tools {child_tools}, but it succeeded and created warrant {child.id}."
    )


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    # Test environment controls
    "allow_all",
    "deterministic_headers",
    # Assertion helpers
    "AuthorizationAssertionError",
    "assert_authorized",
    "assert_denied",
    "assert_can_grant",
    "assert_cannot_grant",
]
