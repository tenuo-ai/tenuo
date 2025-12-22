"""
BoundWarrant - Warrant bound to a signing key.

This module provides the BoundWarrant class, which wraps a Warrant with a SigningKey
for convenience in repeated operations. BoundWarrant is intentionally NOT a subclass
of Warrant to prevent accidental serialization of private keys.

Security:
    - BoundWarrant cannot be serialized (raises TypeError)
    - BoundWarrant should never be stored in state/cache
    - Use for short-lived operations only (e.g., loops, API calls)
"""

from typing import TYPE_CHECKING, Optional
from tenuo_core import Warrant, SigningKey, PublicKey  # type: ignore[import-untyped]
from datetime import timedelta

if TYPE_CHECKING:
    from typing import Union, List


class BoundWarrant:
    """
    Warrant bound to a signing key.
    
    This is NOT a Warrant subclass to prevent accidental serialization.
    Use for convenience in repeated operations, but never store in state.
    
    Example:
        # Bind once, use multiple times
        bound = warrant.bind_key(key)
        for item in items:
            headers = bound.auth_headers("process", {"item": item})
            # ... make API call
        
        # DON'T do this:
        state.warrant = warrant.bind_key(key)  # Type error! (good)
    """
    
    def __init__(self, warrant: Warrant, key: SigningKey):
        """
        Create a BoundWarrant.
        
        Args:
            warrant: The warrant to bind
            key: The signing key to bind to
        """
        self._warrant = warrant
        self._key = key
    
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
        max_d = getattr(self._warrant, 'max_depth', None)
        if max_d is None:
            max_d = getattr(self._warrant, 'max_issue_depth', None)
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
    
    def bind_key(self, key: SigningKey) -> "BoundWarrant":
        """Return a new BoundWarrant with a different key."""
        return BoundWarrant(self._warrant, key)
    
    # ========================================================================
    # Convenience methods (use bound key)
    # ========================================================================
    
    def delegate(
        self,
        *,
        to: PublicKey,
        allow: "Union[str, List[str]]",
        ttl: int,
        **constraints
    ) -> Warrant:
        """
        Delegate using the bound key.
        
        Args:
            to: Public key of new holder
            allow: Tool(s) to delegate
            ttl: Time-to-live in seconds
            **constraints: Additional constraints
            
        Returns:
            New child warrant (plain Warrant, not BoundWarrant)
        """
        return self._warrant.delegate(
            to=to,
            allow=allow,
            ttl=ttl,
            key=self._key,
            **constraints
        )
    
    async def auth_headers_async(
        self,
        tool: str,
        args: Optional[dict] = None
    ) -> dict:
        """
        Generate HTTP authorization headers using the bound key.
        
        Args:
            tool: Tool name
            args: Tool arguments
            
        Returns:
            Dictionary with X-Tenuo-Warrant and X-Tenuo-PoP headers
        """
        import base64
        pop_sig = await self._warrant.create_pop_signature_async(self._key, tool, args)
        # create_pop_signature returns bytes, encode to base64
        pop_b64 = base64.b64encode(pop_sig).decode('ascii')
        return {
            "X-Tenuo-Warrant": self._warrant.to_base64(),
            "X-Tenuo-PoP": pop_b64
        }
    
    def auth_headers(self, tool: str, args: dict) -> dict:
        """
        Generate HTTP authorization headers using the bound key.
        
        Args:
            tool: Tool name
            args: Tool arguments
            
        Returns:
            Dictionary with X-Tenuo-Warrant and X-Tenuo-PoP headers
        """
        import base64
        pop_sig = self._warrant.create_pop_signature(self._key, tool, args)
        # create_pop_signature returns bytes, encode to base64
        pop_b64 = base64.b64encode(pop_sig).decode('ascii')
        return {
            "X-Tenuo-Warrant": self._warrant.to_base64(),
            "X-Tenuo-PoP": pop_b64
        }
    
    # ========================================================================
    # Forward preview/debugging methods
    # ========================================================================
    
    def preview_can(self, tool: str):
        """Check if tool is in warrant (UX only)."""
        return self._warrant.preview_can(tool)
    
    def preview_would_allow(self, tool: str, args: dict):
        """Check if args would satisfy constraints (UX only)."""
        return self._warrant.preview_would_allow(tool, args)
    
    def why_denied(self, tool: str, args: dict = None):
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
# Add bind_key method to Warrant class
# ============================================================================

def _warrant_bind_key(self: Warrant, key: SigningKey) -> BoundWarrant:
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
        bound = warrant.bind_key(key)
        
        # Make multiple API calls
        headers1 = bound.auth_headers("search", {"query": "test"})
        headers2 = bound.auth_headers("read", {"path": "/data/file.txt"})
        
        # Delegate to workers
        worker1 = bound.delegate(to=w1_key, allow="search", ttl=300)
        worker2 = bound.delegate(to=w2_key, allow="read", ttl=300)
    """
    return BoundWarrant(self, key)


# Attach to Warrant class
if not hasattr(Warrant, 'bind_key'):
    Warrant.bind_key = _warrant_bind_key  # type: ignore[attr-defined]
