"""
High-level Tenuo Client.

This module provides an ergonomic client for managing warrants and signing keys.
It simplifies the process of:
1. Managing a signing key
2. Binding a warrant to that key
3. Making authorized calls (auto-generating PoP signatures)

Usage:
    client = tenuo.Client(signing_key)
    client.use_warrant(my_warrant)
    
    # Auto-generates headers with PoP signature
    headers = client.auth_headers("search", {"query": "test"})
    
    # Or for inspecting current state
    print(client.inspect())
"""

from typing import Optional, Dict, Any, Union
from tenuo_core import (  # type: ignore[import-untyped]
    Warrant,
    SigningKey,
    PublicKey,
)
from .bound_warrant import BoundWarrant
from .warrant_ext import AnyWarrant
from .exceptions import ConfigurationError


class Client:
    """
    High-level client for Tenuo authorization.
    
    Acts as a stateful wrapper around a SigningKey and an optional Warrant.
    Simplifies authorization by automating Proof-of-Possession (PoP) signatures.
    """
    
    def __init__(self, key: Optional[SigningKey] = None):
        """
        Initialize the client.
        
        Args:
            key: SigningKey for Proof-of-Possession. If None, one can be generated
                 or set later, but is required for authorization.
        """
        self._key = key
        self._warrant: Optional[AnyWarrant] = None
    
    @classmethod
    def generate(cls) -> "Client":
        """Generate a new client with a fresh signing key."""
        return cls(SigningKey.generate())
    
    @property
    def key(self) -> SigningKey:
        """Get the signing key (raises if not set)."""
        if self._key is None:
            raise ConfigurationError("Client has no signing key. Set one with client.set_key().")
        return self._key
        
    @property
    def public_key(self) -> PublicKey:
        """Get the public key (raises if not set)."""
        return self.key.public_key
    
    def set_key(self, key: SigningKey) -> None:
        """Set or limit the signing key."""
        self._key = key
        # If we have a bound warrant, we might need to re-bind or warn?
        # Actually BoundWarrant holds its own key ref, so changing self._key
        # implies we want to use a NEW key, potentially invalidating the old bound warrant
        # if the warrant was issued to the old key.
        if self._warrant and isinstance(self._warrant, BoundWarrant):
            # We can't easily rebind a BoundWarrant to a new key if the underlying
            # warrant expects the old key (holder binding).
            # For safety, simple unbind.
            self._warrant = self._warrant.unbind()
            
    def use_warrant(self, warrant: Union[Warrant, str]) -> None:
        """
        Set the active warrant.
        
        Args:
            warrant: A Warrant object or a base64-encoded warrant string.
        """
        if isinstance(warrant, str):
            # Parse from base64
            warrant_obj = Warrant.from_base64(warrant)
        else:
            warrant_obj = warrant
            
        # If we have a key, automatically bind for convenience
        if self._key:
            self._warrant = warrant_obj.bind_key(self._key)
        else:
            self._warrant = warrant_obj
            
    def clear_warrant(self) -> None:
        """Remove the active warrant."""
        self._warrant = None
        
    def auth_headers(self, tool: str, args: Optional[dict] = None) -> Dict[str, str]:
        """
        Generate authorization headers for a tool call.
        
        Automatically creates a PoP signature using the active warrant and key.
        
        Args:
            tool: Name of the tool being called
            args: Arguments for the tool call (used for PoP binding)
            
        Returns:
            Dict containing X-Tenuo-Warrant and X-Tenuo-PoP headers
            
        Raises:
            ConfigurationError: If key or warrant is missing
        """
        if not self._warrant:
            raise ConfigurationError("No warrant active. Call client.use_warrant() first.")
            
        # Ensure we have a BoundWarrant (or bind it now)
        if isinstance(self._warrant, BoundWarrant):
            bound = self._warrant
        else:
            # Try to bind on the fly
            bound = self._warrant.bind_key(self.key)
            self._warrant = bound # Cache it
            
        return bound.auth_headers(tool, args or {})
        
    async def auth_headers_async(self, tool: str, args: Optional[dict] = None) -> Dict[str, str]:
        """
        Async version of auth_headers.
        """
        if not self._warrant:
             raise ConfigurationError("No warrant active. Call client.use_warrant() first.")
             
        if isinstance(self._warrant, BoundWarrant):
            bound = self._warrant
        else:
            bound = self._warrant.bind_key(self.key)
            self._warrant = bound
            
        return await bound.auth_headers_async(tool, args or {})

    def inspect(self) -> Dict[str, Any]:
        """Inspect the current client state."""
        warrant_info = None
        if self._warrant:
            warrant_info = self._warrant.inspect()
            
        return {
            "has_key": self._key is not None,
            "public_key": str(self._key.public_key) if self._key else None,
            "warrant": warrant_info
        }
    
    def explain(self) -> str:
        """Explain the current authorization state in English."""
        lines = ["Tenuo Client State:"]
        
        if self._key:
            lines.append(f"  Key: Set (Public: {self._key.public_key})")
        else:
            lines.append("  Key: [MISSING] - No signing key set")
            
        if self._warrant:
            lines.append("\n  Active Warrant:")
            # Indent the warrant explanation
            w_expl = self._warrant.explain().replace("\n", "\n    ")
            lines.append(f"    {w_expl}")
        else:
            lines.append("\n  Active Warrant: [NONE]")
            
        return "\n".join(lines)
