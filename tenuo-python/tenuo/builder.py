"""
Attenuation builder with diff support.

Wraps the Rust AttenuationBuilder. The Rust builder handles:
- Core state management
- Warrant building  
- Diff computation

This Python wrapper adds:
- Receipt storage (keyed by warrant ID)
- Backward compatibility with existing Python API
"""

from typing import Dict, Optional, Any, List

from tenuo_core import (  # type: ignore[import-untyped]
    Warrant,
    Keypair,
    PublicKey,
    TrustLevel,
    AttenuationBuilder as RustAttenuationBuilder,
    DelegationDiff as RustDelegationDiff,
)


class AttenuationBuilder:
    """Builder for attenuating warrants with diff support.
    
    This wraps the Rust AttenuationBuilder and provides:
    - diff() - Human-readable diff preview (from Rust)
    - diff_structured() - Structured diff for programmatic use (from Rust)
    - delegate_to() - Creates child warrant with attached receipt
    """
    
    def __init__(
        self,
        parent: Warrant,
        _rust_builder: Optional[RustAttenuationBuilder] = None,
    ):
        """Initialize builder with parent warrant.
        
        Args:
            parent: The parent warrant to attenuate
            _rust_builder: Internal - Rust builder if already created
        """
        self._parent = parent
        # Use provided Rust builder or create new one
        if _rust_builder is not None:
            self._rust_builder = _rust_builder
        else:
            # Get Rust builder directly from warrant (bypass Python wrapper)
            from .warrant_ext import _original_attenuate_builder
            self._rust_builder = _original_attenuate_builder(parent)
    
    @property
    def parent(self) -> Warrant:
        """Get the parent warrant."""
        return self._parent
    
    @property
    def ttl_seconds(self) -> Optional[int]:
        """Get the configured TTL in seconds."""
        return self._rust_builder.ttl_seconds
    
    @property
    def holder(self) -> Optional[PublicKey]:
        """Get the configured holder."""
        return self._rust_builder.holder
    
    @property
    def trust_level(self) -> Optional[TrustLevel]:
        """Get the configured trust level."""
        return self._rust_builder.trust_level
    
    @property
    def intent(self) -> Optional[str]:
        """Get the configured intent."""
        return self._rust_builder.intent
    
    @property
    def constraints(self) -> Dict[str, Any]:
        """Get the configured constraints as a dict."""
        return dict(self._rust_builder.constraints_dict())
    
    def with_constraint(self, field: str, constraint: Any) -> 'AttenuationBuilder':
        """Add or override a constraint."""
        self._rust_builder.with_constraint(field, constraint)
        return self
    
    def with_ttl(self, seconds: int) -> 'AttenuationBuilder':
        """Set TTL in seconds."""
        self._rust_builder.with_ttl(seconds)
        return self
    
    def with_holder(self, public_key: PublicKey) -> 'AttenuationBuilder':
        """Set the authorized holder."""
        self._rust_builder.with_holder(public_key)
        return self
    
    def with_trust_level(self, level: TrustLevel) -> 'AttenuationBuilder':
        """Set trust level."""
        self._rust_builder.with_trust_level(level)
        return self
    
    def with_intent(self, intent: str) -> 'AttenuationBuilder':
        """Set human-readable intent for this delegation."""
        self._rust_builder.with_intent(intent)
        return self

    def with_tool(self, tool: str) -> 'AttenuationBuilder':
        """Narrow to a single tool (for execution warrants).
        
        The specified tool must be in the parent warrant's tools.
        This enables "always shrinking authority" for non-terminal warrants.
        
        For ISSUER warrants (narrowing issuable_tools), this also works.
        
        Args:
            tool: The tool name to keep
            
        Returns:
            Self for method chaining
            
        Example:
            # Parent has ["read_file", "send_email", "query_db"]
            child = parent.attenuate_builder()
                .with_tool("read_file")  # Narrow to just read_file
                .with_holder(worker_key)
                .delegate_to(kp, kp)
        """
        self._rust_builder.with_tool(tool)
        return self

    def with_tools(self, tools: List[str]) -> 'AttenuationBuilder':
        """Narrow to a subset of tools (for execution warrants).
        
        The specified tools must all be in the parent warrant's tools.
        This enables "always shrinking authority" for non-terminal warrants.
        
        For ISSUER warrants (narrowing issuable_tools), this also works.
        
        Args:
            tools: List of tool names to keep
            
        Returns:
            Self for method chaining
        """
        self._rust_builder.with_tools(tools)
        return self

    def with_issuable_tool(self, tool: str) -> 'AttenuationBuilder':
        """Set a single issuable tool (for ISSUER warrants only).
        
        For EXECUTION warrants, use with_tool() instead.
        """
        self._rust_builder.with_issuable_tool(tool)
        return self

    def with_issuable_tools(self, tools: List[str]) -> 'AttenuationBuilder':
        """Set issuable tools (for ISSUER warrants only).
        
        For EXECUTION warrants, use with_tools() instead.
        """
        self._rust_builder.with_issuable_tools(tools)
        return self

    def drop_tools(self, tools: List[str]) -> 'AttenuationBuilder':
        """Drop tools from issuable_tools (for issuer warrants only)."""
        self._rust_builder.drop_tools(tools)
        return self

    def terminal(self) -> 'AttenuationBuilder':
        """Make this warrant terminal (cannot be delegated further)."""
        self._rust_builder.terminal()
        return self
    
    def diff(self) -> str:
        """Get human-readable diff preview.
        
        This calls the Rust diff computation.
        """
        return self._rust_builder.diff()
    
    def diff_structured(self) -> RustDelegationDiff:
        """Get structured diff for programmatic use.
        
        Returns the Rust DelegationDiff type with full functionality:
        - to_json() - JSON serialization
        - to_human() - Human-readable output
        - to_siem_json() - SIEM-compatible JSON
        """
        return self._rust_builder.diff_structured()
    
    def delegate_to(
        self,
        keypair: Keypair,
        parent_keypair: Keypair,
    ) -> Warrant:
        """Create the attenuated child warrant.
        
        Args:
            keypair: The keypair of the delegator
            parent_keypair: The keypair that signed the parent warrant
            
        Returns:
            The newly created child warrant with attached receipt
        """
        # Use Rust's build_with_receipt for atomic creation
        child, receipt = self._rust_builder.delegate_to_with_receipt(keypair, parent_keypair)
        
        # Store receipt in module-level dict (Rust objects don't allow Python attributes)
        from .warrant_ext import _delegation_receipts
        _delegation_receipts[child.id] = receipt
        
        return child
    
    def delegate_to_with_receipt(
        self,
        keypair: Keypair,
        parent_keypair: Keypair,
    ) -> tuple:
        """Create the attenuated child warrant and return both warrant and receipt.
        
        Args:
            keypair: The keypair of the delegator
            parent_keypair: The keypair that signed the parent warrant
            
        Returns:
            Tuple of (child_warrant, delegation_receipt)
        """
        child, receipt = self._rust_builder.delegate_to_with_receipt(keypair, parent_keypair)
        
        # Also store receipt for later access via child.delegation_receipt
        from .warrant_ext import _delegation_receipts
        _delegation_receipts[child.id] = receipt
        
        return child, receipt


def wrap_rust_builder(rust_builder: RustAttenuationBuilder) -> AttenuationBuilder:
    """Wrap a Rust AttenuationBuilder in Python AttenuationBuilder.
    
    This is used when getting a builder from Warrant.attenuate_builder().
    """
    parent = rust_builder.parent
    return AttenuationBuilder(parent, _rust_builder=rust_builder)
