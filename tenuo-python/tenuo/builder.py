"""
Warrant builders with fluent API support.

Provides two builders:
- WarrantBuilder: Create new root warrants (execution or issuer)
- AttenuationBuilder: Attenuate existing warrants with diff support

The Rust core handles all validation and cryptographic operations.
These Python wrappers add:
- Fluent API for better DX
- Receipt storage (keyed by warrant ID)
- Type hints and documentation
"""

from typing import Dict, Optional, Any, List, Union

from tenuo_core import (  # type: ignore[import-untyped]
    Warrant,
    SigningKey,
    PublicKey,
    TrustLevel,
    AttenuationBuilder as RustAttenuationBuilder,
    DelegationDiff as RustDelegationDiff,
)


class WarrantBuilder:
    """Fluent builder for creating new root warrants.
    
    Provides a Pythonic alternative to Warrant.issue() with method chaining.
    
    Example - Execution Warrant:
        warrant = (Warrant.builder()
            .tools(["read_file", "write_file"])
            .constraint("path", Pattern("/data/*"))
            .constraint("max_size", Range(0, 1000000))
            .trust_level(TrustLevel.Trusted)
            .ttl(3600)
            .issue(keypair))
    
    Example - Issuer Warrant:
        issuer = (Warrant.builder()
            .issuer()  # Switch to issuer mode
            .issuable_tools(["read_file", "write_file"])
            .trust_ceiling(TrustLevel.Privileged)
            .constraint_bound("path", Pattern("/data/*"))
            .max_issue_depth(3)
            .issue(keypair))
    
    Note:
        This builder is for creating NEW root warrants.
        To attenuate an existing warrant, use warrant.attenuate_builder().
    """
    
    def __init__(self):
        """Initialize a new warrant builder."""
        """Initialize a new warrant builder."""
        self._capabilities: Dict[str, Dict[str, Any]] = {}
        # Legacy support/Implicit mode fields
        self._tools: Optional[Union[str, List[str]]] = None
        self._constraints: Dict[str, Any] = {}
        
        self._ttl_seconds: int = 3600  # Default 1 hour
        self._holder: Optional[PublicKey] = None
        self._session_id: Optional[str] = None
        self._trust_level: Optional[TrustLevel] = None
        
        # Issuer-specific fields
        self._is_issuer: bool = False
        self._issuable_tools: Optional[List[str]] = None
        self._trust_ceiling: Optional[TrustLevel] = None
        self._constraint_bounds: Dict[str, Any] = {}
        self._max_issue_depth: Optional[int] = None
    
    def issuer(self) -> 'WarrantBuilder':
        """Switch to issuer warrant mode.
        
        Issuer warrants can delegate to other warrants but cannot
        execute tools directly.
        """
        self._is_issuer = True
        return self
    
    def tools(self, tools: Union[str, List[str]]) -> 'WarrantBuilder':
        """Set the tools this warrant authorizes (execution warrants).
        
        Args:
            tools: Single tool name or list of tool names
        """
        self._tools = tools
        return self
    
    def tool(self, tool: str) -> 'WarrantBuilder':
        """Set a single tool (convenience method).
        
        Args:
            tool: Tool name
        """
        self._tools = tool
        return self
    
    def constraint(self, field: str, value: Any) -> 'WarrantBuilder':
        """Add a constraint (execution warrants).
        
        Args:
            field: Constraint field name (e.g., "path", "amount")
            value: Constraint value (Pattern, Range, Exact, etc.)
        """
        self._constraints[field] = value
        return self
    
    def constraints(self, constraints: Dict[str, Any]) -> 'WarrantBuilder':
        """Set all constraints at once (execution warrants).
        
        Args:
            constraints: Dict mapping field names to constraint values
        """
        self._constraints = constraints
        return self

    def capability(self, tool: str, constraints: Dict[str, Any]) -> 'WarrantBuilder':
        """Add a capability (tool + constraints).
        
        Args:
            tool: Tool name
            constraints: Dict of constraints
        """
        self._capabilities[tool] = constraints
        return self
    
    def ttl(self, seconds: int) -> 'WarrantBuilder':
        """Set time-to-live in seconds.
        
        Args:
            seconds: TTL in seconds (default: 3600)
        """
        self._ttl_seconds = seconds
        return self
    
    def holder(self, public_key: PublicKey) -> 'WarrantBuilder':
        """Set the authorized holder's public key.
        
        If not set, defaults to the issuer (self-signed).
        
        Args:
            public_key: The holder's public key
        """
        self._holder = public_key
        return self
    
    def session_id(self, session_id: str) -> 'WarrantBuilder':
        """Set an optional session identifier.
        
        Args:
            session_id: Session ID for tracking
        """
        self._session_id = session_id
        return self
    
    def trust_level(self, level: TrustLevel) -> 'WarrantBuilder':
        """Set the trust level.
        
        Args:
            level: TrustLevel enum value
        """
        self._trust_level = level
        return self
    
    # =========================================================================
    # Issuer-specific methods
    # =========================================================================
    
    def issuable_tools(self, tools: List[str]) -> 'WarrantBuilder':
        """Set tools this issuer can delegate (issuer warrants only).
        
        Args:
            tools: List of tool names that can be issued
        """
        self._is_issuer = True
        self._issuable_tools = tools
        return self
    
    def trust_ceiling(self, level: TrustLevel) -> 'WarrantBuilder':
        """Set max trust level for issued warrants (issuer warrants only).
        
        Args:
            level: Maximum TrustLevel for child warrants
        """
        self._is_issuer = True
        self._trust_ceiling = level
        return self
    
    def constraint_bound(self, field: str, value: Any) -> 'WarrantBuilder':
        """Add a constraint bound (issuer warrants only).
        
        Constraint bounds limit what constraints child warrants can have.
        
        Args:
            field: Constraint field name
            value: Maximum bound for this constraint
        """
        self._constraint_bounds[field] = value
        return self
    
    def constraint_bounds(self, bounds: Dict[str, Any]) -> 'WarrantBuilder':
        """Set all constraint bounds at once (issuer warrants only).
        
        Args:
            bounds: Dict mapping field names to constraint bounds
        """
        self._constraint_bounds = bounds
        return self
    
    def max_issue_depth(self, depth: int) -> 'WarrantBuilder':
        """Set maximum delegation depth (issuer warrants only).
        
        Args:
            depth: Maximum depth of delegation chain
        """
        self._max_issue_depth = depth
        return self
    
    # =========================================================================
    # Build methods
    # =========================================================================
    
    def issue(self, keypair: SigningKey) -> Warrant:
        """Build and sign the warrant.
        
        Args:
            keypair: The signing key to sign the warrant
            
        Returns:
            The newly created Warrant
            
        Raises:
            ValidationError: If required fields are missing
            TenuoError: If warrant creation fails
        """
        if self._is_issuer:
            return self._issue_issuer(keypair)
        else:
            return self._issue_execution(keypair)
    
    def _issue_execution(self, keypair: SigningKey) -> Warrant:
        """Issue an execution warrant."""
        # Convert legacy tools/constraints to capabilities
        capabilities = self._capabilities.copy()
        
        if self._tools:
            tools_list = [self._tools] if isinstance(self._tools, str) else self._tools
            for t in tools_list:
                # If tool not already in capabilities (or merge?), overwrite/set default constraints
                if t not in capabilities:
                    capabilities[t] = self._constraints.copy()
        
        if not capabilities:
            from .exceptions import ValidationError
            raise ValidationError("capabilities (or tools) are required for execution warrants")
        
        return Warrant.issue(
            keypair=keypair,
            capabilities=capabilities,
            ttl_seconds=self._ttl_seconds,
            holder=self._holder,
            session_id=self._session_id,
            trust_level=self._trust_level,
        )
    
    def _issue_issuer(self, keypair: SigningKey) -> Warrant:
        """Issue an issuer warrant."""
        if self._issuable_tools is None:
            from .exceptions import ValidationError
            raise ValidationError("issuable_tools are required for issuer warrants")
        if self._trust_ceiling is None:
            from .exceptions import ValidationError
            raise ValidationError("trust_ceiling is required for issuer warrants")
        
        return Warrant.issue_issuer(
            issuable_tools=self._issuable_tools,
            trust_ceiling=self._trust_ceiling,
            keypair=keypair,
            constraint_bounds=self._constraint_bounds if self._constraint_bounds else None,
            max_issue_depth=self._max_issue_depth,
            ttl_seconds=self._ttl_seconds,
            holder=self._holder,
            session_id=self._session_id,
            trust_level=self._trust_level,
        )
    
    def preview(self) -> Dict[str, Any]:
        """Preview the warrant configuration before building.
        
        Returns:
            Dict with all configured values
        """
        if self._is_issuer:
            return {
                "type": "issuer",
                "issuable_tools": self._issuable_tools,
                "trust_ceiling": self._trust_ceiling,
                "constraint_bounds": self._constraint_bounds,
                "max_issue_depth": self._max_issue_depth,
                "ttl_seconds": self._ttl_seconds,
                "holder": self._holder,
                "session_id": self._session_id,
                "trust_level": self._trust_level,
            }
        else:
            return {
                "type": "execution",
                "tools": self._tools,
                "constraints": self._constraints,
                "ttl_seconds": self._ttl_seconds,
                "holder": self._holder,
                "session_id": self._session_id,
                "trust_level": self._trust_level,
            }


# Add builder() class method to Warrant
def _add_builder_to_warrant():
    """Add the builder() class method to Warrant."""
    @classmethod
    def builder(cls) -> WarrantBuilder:
        """Create a fluent builder for new warrants.
        
        Example:
            warrant = (Warrant.builder()
                .tools(["read_file"])
                .constraint("path", Pattern("/data/*"))
                .ttl(3600)
                .issue(keypair))
        
        Returns:
            WarrantBuilder instance
        """
        return WarrantBuilder()
    
    # Only add if not already present
    if not hasattr(Warrant, 'builder'):
        Warrant.builder = builder

# Initialize on module load
_add_builder_to_warrant()


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
    def capabilities(self) -> Dict[str, Dict[str, Any]]:
        """Get the configured capabilities as a dict."""
        return self._rust_builder.capabilities
    
    def with_capability(self, tool: str, constraints: Dict[str, Any]) -> 'AttenuationBuilder':
        """Add or override a capability."""
        self._rust_builder.with_capability(tool, constraints)
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
        keypair: SigningKey,
        parent_keypair: SigningKey,
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
        keypair: SigningKey,
        parent_keypair: SigningKey,
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
