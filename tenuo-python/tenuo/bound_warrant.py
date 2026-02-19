"""
BoundWarrant - Warrant bound to a signing key.

This module provides the BoundWarrant class, which wraps a Warrant with a SigningKey
for convenience in repeated operations. BoundWarrant is intentionally NOT a subclass
of Warrant to prevent accidental serialization of private keys.

Security:
    - BoundWarrant cannot be serialized (raises TypeError)
    - BoundWarrant should never be stored in state/cache
    - Use for short-lived operations only (e.g., loops, API calls)

Context Manager:
    BoundWarrant can be used as a context manager to set both warrant and key scope:

        with bound:
            @guard(tool="search")
            def my_func(): ...
"""

from typing import TYPE_CHECKING, Optional, Union, List, Dict
from tenuo_core import Warrant, SigningKey, PublicKey  # type: ignore[import-untyped]
from datetime import timedelta
from .validation import ValidationResult

if TYPE_CHECKING:
    pass


class BoundWarrant:
    """
    Warrant bound to a signing key.

    This is NOT a Warrant subclass to prevent accidental serialization.
    Use for convenience in repeated operations, but never store in state.

    Security:
        - Uses __slots__ to prevent __dict__ access (key not exposed via vars())
        - __getstate__/__reduce__ raise TypeError (blocks pickle)
        - Not JSON serializable

    Example:
        # Bind once, use multiple times
        bound = warrant.bind(key)
        for item in items:
            headers = bound.headers("process", {"item": item})
            # ... make API call

        # As context manager (sets both warrant and key scope)
        with bound:
            @guard(tool="search")
            def my_func(): ...

        # DON'T do this:
        state.warrant = warrant.bind(key)  # Type error! (good)
    """

    # Use __slots__ to prevent __dict__ access (security: key not exposed via vars())
    __slots__ = ("_warrant", "_key", "_warrant_token", "_key_token")

    def __init__(self, warrant: Warrant, key: SigningKey):
        """
        Create a BoundWarrant.

        Args:
            warrant: The warrant to bind
            key: The signing key to bind to
        """
        self._warrant = warrant
        self._key = key
        self._warrant_token = None
        self._key_token = None

    @staticmethod
    def bind_warrant(warrant: Warrant, key: SigningKey) -> "BoundWarrant":
        """
        Bind a warrant to a signing key.

        Usage:
            bound = warrant.bind(key)
        """
        return BoundWarrant(warrant, key)

    # ========================================================================
    # Context Manager (sets both warrant and key scope)
    # ========================================================================

    def __enter__(self):
        """
        Enter context: set both warrant and key scope.

        Allows using BoundWarrant as a context manager:
            with bound:
                @guard(tool="search")
                def my_func(): ...
        """
        from .decorators import _warrant_context, _keypair_context

        self._warrant_token = _warrant_context.set(self._warrant)
        self._key_token = _keypair_context.set(self._key)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context: reset warrant and key scope."""
        from .decorators import _warrant_context, _keypair_context

        if self._warrant_token is not None:
            _warrant_context.reset(self._warrant_token)
        if self._key_token is not None:
            _keypair_context.reset(self._key_token)
        return False

    # ========================================================================
    # Forward ReadableWarrant properties
    # ========================================================================

    @property
    def id(self) -> str:
        """Warrant ID."""
        return self._warrant.id

    @property
    def tools(self) -> list:
        """List of authorized tools."""
        return self._warrant.tools

    @property
    def ttl_remaining(self) -> timedelta:
        """Time remaining until expiration."""
        return self._warrant.ttl_remaining

    @property
    def ttl(self) -> timedelta:
        """Alias for ttl_remaining."""
        return self._warrant.ttl_remaining

    @property
    def expires_at(self) -> str:
        """Absolute expiration time (RFC3339 string)."""
        return self._warrant.expires_at()

    @property
    def is_terminal(self) -> bool:
        """Cannot delegate further."""
        return self._warrant.is_terminal()

    @property
    def is_expired(self) -> bool:
        """TTL has elapsed."""
        return self._warrant.is_expired()

    @property
    def clearance(self):
        """Clearance level."""
        return self._warrant.clearance

    @property
    def depth(self) -> int:
        """Current delegation depth."""
        return self._warrant.depth

    @property
    def max_depth(self) -> int:
        """Maximum delegation depth."""
        # Handle both max_depth and max_issue_depth for compatibility
        max_d = getattr(self._warrant, "max_depth", None)
        if max_d is None:
            max_d = getattr(self._warrant, "max_issue_depth", None)
        return max_d if max_d is not None else 0

    @property
    def warrant_type(self):
        """Warrant type (Execution or Issuer)."""
        return self._warrant.warrant_type

    # ========================================================================
    # Access to inner warrant
    # ========================================================================

    @property
    def warrant(self) -> Warrant:
        """Get the inner warrant (read-only access)."""
        return self._warrant

    def unbind(self) -> Warrant:
        """Return the inner warrant without the key."""
        return self._warrant

    def bind(self, key: SigningKey) -> "BoundWarrant":
        """Return a new BoundWarrant with a different key."""
        return BoundWarrant(self._warrant, key)

    # ========================================================================
    # Convenience methods (use bound key)
    # ========================================================================

    def grant(
        self,
        *,
        to: PublicKey,
        allow: "Union[str, List[str]]",
        ttl: int,
        **constraints,
    ) -> Warrant:
        """Grant using the bound key.

        Args:
            to: Public key of new holder
            allow: Tool(s) to grant
            ttl: Time-to-live in seconds
            **constraints: Additional constraints

        Returns:
            New child warrant (plain Warrant, not BoundWarrant)
        """
        return self._warrant.grant(to=to, allow=allow, ttl=ttl, key=self._key, **constraints)

    def headers(self, tool: str, args: dict) -> Dict[str, str]:
        """
        Generate HTTP authorization headers using the bound key.

        Args:
            tool: Tool name
            args: Tool arguments

        Returns:
            Dictionary with X-Tenuo-Warrant and X-Tenuo-PoP headers
        """
        import base64
        import time

        # Validate before signing for better error messages
        validation = self.validate(tool, args)
        if not validation:
            raise RuntimeError(f"Authorization failed: {validation.reason}")

        pop_sig = self._warrant.sign(self._key, tool, args, int(time.time()))
        # sign returns bytes, encode to base64
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")
        return {
            "X-Tenuo-Warrant": self._warrant.to_base64(),
            "X-Tenuo-PoP": pop_b64,
        }

    def validate(self, tool: str, args: dict) -> ValidationResult:
        """
        Pre-check if this action would be authorized.

        Use before making the actual API call to verify locally that
        the warrant allows the action and the PoP signature is valid.

        Args:
            tool: Tool name
            args: Tool arguments (constraints)

        Returns:
            ValidationResult (True if authorized and PoP is valid, with feedback on failure)

        Example:
            result = bound.validate("search", {"query": "test"})
            if result:
                headers = bound.headers("search", {"query": "test"})
                # ...
            else:
                print(f"Validation failed: {result.reason}")
        """
        import time

        # 1. Sign
        pop_signature = self._warrant.sign(self._key, tool, args, int(time.time()))

        # 2. Verify (calls Rust authorize)
        success = self._warrant.authorize(tool=tool, args=args, signature=bytes(pop_signature))

        if success:
            return ValidationResult.ok()

        # 3. If failed, get rich feedback via why_denied
        why = self.why_denied(tool, args)
        return ValidationResult.fail(
            reason=why.suggestion or f"Authorization failed ({why.deny_code})",
            suggestions=[why.suggestion] if why.suggestion else [],
        )

    # ========================================================================
    # Forward preview/debugging methods
    # ========================================================================

    def allows(self, tool: str, args: Optional[dict] = None) -> bool:
        """
        Check if the warrant allows the given tool and arguments.

        This is a pure logic check (math only) and does not perform
        cryptographic verification or Proof-of-Possession.

        Args:
            tool: The tool name to check.
            args: Optional arguments to check against constraints.
                  If None, only checks if tool is in the allowlist.

        Returns:
            True if allowed, False otherwise.
        """
        # Use the newly injected allowed method on warrant
        return self._warrant.allows(tool, args)

    def why_denied(self, tool: str, args: Optional[dict] = None):
        """Get structured explanation for why a request would be denied."""
        return self._warrant.why_denied(tool, args)

    def explain(self, include_chain: bool = False) -> str:
        """Human-readable warrant explanation."""
        return self._warrant.explain(include_chain=include_chain)

    def inspect(self) -> str:
        """Alias for explain() with chain information."""
        return self._warrant.inspect()

    @property
    def capabilities(self) -> dict:
        """Human-readable constraints for each tool."""
        return self._warrant.capabilities

    def constraints_dict(self) -> dict:
        """Get flattened constraints dict for authorization checks.

        This is used by guard() to verify critical tools have constraints.
        Extracts constraints from capabilities and flattens into a single dict.
        """
        caps = self._warrant.capabilities
        if caps:
            all_constraints = {}
            for tool_name, constraints in caps.items():
                if constraints:
                    all_constraints.update(constraints)
            return all_constraints
        return {}

    @property
    def expired(self) -> bool:
        """Whether the warrant has expired."""
        return self._warrant.expired

    @property
    def terminal(self) -> bool:
        """Whether the warrant is terminal (cannot delegate)."""
        return self._warrant.terminal

    # ========================================================================
    # Serialization guards (SECURITY-CRITICAL)
    # ========================================================================

    def __getstate__(self):
        """Prevent pickle serialization."""
        raise TypeError(
            "BoundWarrant cannot be serialized (contains private key). "
            "Store the Warrant separately and rebind at runtime."
        )

    def __reduce__(self):
        """Prevent pickle serialization."""
        raise TypeError("BoundWarrant cannot be pickled")

    def __repr__(self):
        """String representation (hides key)."""
        return f"<BoundWarrant id={self._warrant.id[:12]}... KEY_BOUND=True>"


# ============================================================================
# Add bind method to Warrant class
# ============================================================================


def _warrant_bind(self: Warrant, key: SigningKey) -> BoundWarrant:
    """
    Bind this warrant to a signing key for convenience.

    Returns a BoundWarrant which wraps the warrant and key together.
    Use for repeated operations, but never store in state/cache.

    Args:
        key: The signing key to bind

    Returns:
        BoundWarrant instance

    Example:
        # Bind once, use multiple times
        bound = warrant.bind(key)

        # Make multiple API calls
        headers1 = bound.headers("search", {"query": "test"})
        headers2 = bound.headers("read", {"path": "/data/file.txt"})

        worker1 = bound.grant(to=w1_key, allow="search", ttl=300)
        worker2 = bound.grant(to=w2_key, allow="read", ttl=300)

    Security Note:
        This method performs **lazy validation**. It does not check if the key matches
        the warrant's authorized holder immediately. Validation happens strictly at
        usage time (when `authorize()` is called), which verifies the Proof-of-Possession
        signature. If the wrong key is bound, `authorize()` will fail securely.
    """
    return BoundWarrant(self, key)


# Attach to Warrant class
if not hasattr(Warrant, "bind"):
    Warrant.bind = _warrant_bind  # type: ignore[attr-defined]
