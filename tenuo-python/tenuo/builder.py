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
    Clearance,
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
            .clearance(Clearance.System)
            .ttl(3600)
            .issue(keypair))
    
    Example - Issuer Warrant:
        issuer = (Warrant.builder()
            .issuer()  # Switch to issuer mode
            .issuable_tools(["read_file", "write_file"])
            .clearance(Clearance.Privileged)
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
        self._clearance: Optional[Clearance] = None
        
        # Issuer-specific fields
        self._is_issuer: bool = False
        self._issuable_tools: Optional[List[str]] = None
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
        """Add a single tool (accumulates).
        
        Args:
            tool: Tool name
        """
        if self._tools is None:
            self._tools = [tool]
        elif isinstance(self._tools, str):
            self._tools = [self._tools, tool]
        else:
            self._tools.append(tool)
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
    
    def clearance(self, level: Clearance) -> 'WarrantBuilder':
        """Set the clearance level.
        
        Args:
            level: Clearance enum value
        """
        self._clearance = level
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
            clearance=self._clearance,
        )
    
    def _issue_issuer(self, keypair: SigningKey) -> Warrant:
        """Issue an issuer warrant."""
        if self._issuable_tools is None:
            from .exceptions import ValidationError
            raise ValidationError("issuable_tools are required for issuer warrants")
        
        return Warrant.issue_issuer(
            issuable_tools=self._issuable_tools,
            keypair=keypair,
            constraint_bounds=self._constraint_bounds if self._constraint_bounds else None,
            max_issue_depth=self._max_issue_depth,
            ttl_seconds=self._ttl_seconds,
            holder=self._holder,
            session_id=self._session_id,
            clearance=self._clearance,
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
                "clearance": self._clearance,
                "constraint_bounds": self._constraint_bounds,
                "max_issue_depth": self._max_issue_depth,
                "ttl_seconds": self._ttl_seconds,
                "holder": self._holder,
                "session_id": self._session_id,
            }
        else:
            return {
                "type": "execution",
                "tools": self._tools,
                "constraints": self._constraints,
                "ttl_seconds": self._ttl_seconds,
                "holder": self._holder,
                "session_id": self._session_id,
                "clearance": self._clearance,
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
    - delegate() - Creates child warrant with attached receipt
    
    All setter methods use a dual-purpose pattern:
    - Called with argument: sets value, returns self for chaining
    - Called without argument: returns current value (getter)
    
    Example:
        child = (parent.attenuate()
            .capability("read", {"path": Pattern("/data/*")})
            .holder(worker_kp.public_key)
            .ttl(300)
            .delegate(keypair))
        
        # Reading configured values
        print(builder.holder())   # Returns configured holder or None
        print(builder.ttl())      # Returns configured TTL or None
    """
    
    # Sentinel for detecting "no argument passed"
    _NOT_SET = object()
    
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
    
    def parent(self) -> Warrant:
        """Get the parent warrant."""
        return self._parent
    
    def ttl(self, seconds: Any = _NOT_SET) -> Union['AttenuationBuilder', Optional[int]]:
        """Get or set TTL in seconds.
        
        Args:
            seconds: TTL in seconds (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current TTL (if getting)
        """
        if seconds is self._NOT_SET:
            return self._rust_builder.ttl_seconds
        self._rust_builder.with_ttl(seconds)
        return self
    
    def holder(self, public_key: Any = _NOT_SET) -> Union['AttenuationBuilder', Optional[PublicKey]]:
        """Get or set the authorized holder.
        
        Args:
            public_key: The holder's public key (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current holder (if getting)
        """
        if public_key is self._NOT_SET:
            return self._rust_builder.holder
        self._rust_builder.with_holder(public_key)
        return self
    
    def clearance(self, level: Any = _NOT_SET) -> Union['AttenuationBuilder', Optional[Clearance]]:
        """Get or set clearance level.
        
        Args:
            level: Clearance value (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current clearance level (if getting)
        """
        if level is self._NOT_SET:
            return self._rust_builder.clearance
        self._rust_builder.with_clearance(level)
        return self
    
    def intent(self, text: Any = _NOT_SET) -> Union['AttenuationBuilder', Optional[str]]:
        """Get or set human-readable intent for this delegation.
        
        Args:
            text: Intent description (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current intent (if getting)
        """
        if text is self._NOT_SET:
            return self._rust_builder.intent
        self._rust_builder.with_intent(text)
        return self
    
    @property
    def capabilities(self) -> Dict[str, Dict[str, Any]]:
        """Get the configured capabilities as a dict (read-only)."""
        return self._rust_builder.capabilities
    
    def capability(self, tool: str, constraints: Dict[str, Any]) -> 'AttenuationBuilder':
        """Add a capability (tool + constraints).
        
        **POLA**: You must explicitly add each capability you want. Only tools
        specified via this method will be in the child warrant.
        
        Args:
            tool: Tool name
            constraints: Dict of field -> constraint mappings
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_capability(tool, constraints)
        return self

    def inherit_all(self) -> 'AttenuationBuilder':
        """Inherit all capabilities from the parent warrant.
        
        This is an **explicit opt-in** to full inheritance. Use this when you
        want to start with all parent capabilities and then narrow specific ones.
        
        Without this, the builder follows POLA (Principle of Least Authority)
        and starts with NO capabilities.
        
        Example:
            # Keep all parent capabilities but reduce TTL
            child = (parent.attenuate()
                .inherit_all()
                .ttl(300)
                .delegate(kp))
        """
        self._rust_builder.inherit_all()
        return self

    def tool(self, name: str) -> 'AttenuationBuilder':
        """Narrow to a single tool (for execution warrants).
        
        The specified tool must be in the parent warrant's tools.
        This enables "always shrinking authority" for non-terminal warrants.
        
        For ISSUER warrants (narrowing issuable_tools), this also works.
        
        Args:
            name: The tool name to keep
            
        Returns:
            Self for method chaining
            
        Example:
            # Parent has ["read_file", "send_email", "query_db"]
            child = (parent.attenuate()
                .tool("read_file")  # Narrow to just read_file
                .holder(worker_key)
                .delegate(kp))
        """
        self._rust_builder.with_tool(name)
        return self

    def tools(self, names: List[str]) -> 'AttenuationBuilder':
        """Narrow to a subset of tools (for execution warrants).
        
        The specified tools must all be in the parent warrant's tools.
        This enables "always shrinking authority" for non-terminal warrants.
        
        For ISSUER warrants (narrowing issuable_tools), this also works.
        
        Args:
            names: List of tool names to keep
            
        Returns:
            Self for method chaining
        """
        self._rust_builder.with_tools(names)
        return self

    def issuable_tool(self, name: str) -> 'AttenuationBuilder':
        """Set a single issuable tool (for ISSUER warrants only).
        
        For EXECUTION warrants, use tool() instead.
        """
        self._rust_builder.with_issuable_tool(name)
        return self

    def issuable_tools(self, names: List[str]) -> 'AttenuationBuilder':
        """Set issuable tools (for ISSUER warrants only).
        
        For EXECUTION warrants, use tools() instead.
        """
        self._rust_builder.with_issuable_tools(names)
        return self

    def drop_tools(self, names: List[str]) -> 'AttenuationBuilder':
        """Drop tools from issuable_tools (for issuer warrants only)."""
        self._rust_builder.drop_tools(names)
        return self

    def terminal(self) -> 'AttenuationBuilder':
        """Make this warrant terminal (cannot be delegated further)."""
        self._rust_builder.terminal()
        return self
    
    # =========================================================================
    # Aliases for backward compatibility (deprecated, will be removed)
    # =========================================================================
    
    def with_capability(self, tool: str, constraints: Dict[str, Any]) -> 'AttenuationBuilder':
        """Alias for capability() - deprecated, use capability() instead."""
        return self.capability(tool, constraints)
    
    def with_ttl(self, seconds: int) -> 'AttenuationBuilder':
        """Alias for ttl() - deprecated, use ttl() instead."""
        return self.ttl(seconds)  # type: ignore[return-value]
    
    def with_holder(self, public_key: PublicKey) -> 'AttenuationBuilder':
        """Alias for holder() - deprecated, use holder() instead."""
        return self.holder(public_key)  # type: ignore[return-value]
    
    def with_clearance(self, level: Clearance) -> 'AttenuationBuilder':
        """Alias for clearance() - deprecated, use clearance() instead."""
        return self.clearance(level)  # type: ignore[return-value]
    
    def with_intent(self, text: str) -> 'AttenuationBuilder':
        """Alias for intent() - deprecated, use intent() instead."""
        return self.intent(text)  # type: ignore[return-value]
    
    def with_tool(self, name: str) -> 'AttenuationBuilder':
        """Alias for tool() - deprecated, use tool() instead."""
        return self.tool(name)
    
    def with_tools(self, names: List[str]) -> 'AttenuationBuilder':
        """Alias for tools() - deprecated, use tools() instead."""
        return self.tools(names)
    
    def with_issuable_tool(self, name: str) -> 'AttenuationBuilder':
        """Alias for issuable_tool() - deprecated."""
        return self.issuable_tool(name)
    
    def with_issuable_tools(self, names: List[str]) -> 'AttenuationBuilder':
        """Alias for issuable_tools() - deprecated."""
        return self.issuable_tools(names)
    
    # =========================================================================
    # Diff and build methods
    # =========================================================================
    
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
    
    def delegate(self, signing_key: SigningKey) -> Warrant:
        """Create the attenuated child warrant.
        
        The signing key must belong to the holder of the parent warrant (the delegator).
        This enforces the delegation authority rule: you can only delegate what you hold.
        
        Args:
            signing_key: The keypair of the parent warrant's holder
            
        Returns:
            The newly created child warrant with attached receipt
            
        Raises:
            DelegationAuthorityError: If signing_key doesn't match parent's holder
        """
        # Use Rust's delegate_with_receipt for atomic creation
        child, receipt = self._rust_builder.delegate_with_receipt(signing_key)
        
        # Store receipt in module-level dict (Rust objects don't allow Python attributes)
        from .warrant_ext import _delegation_receipts
        _delegation_receipts[child.id] = receipt
        
        return child
    
    def delegate_with_receipt(self, signing_key: SigningKey) -> tuple:
        """Create the attenuated child warrant and return both warrant and receipt.
        
        The signing key must belong to the holder of the parent warrant.
        
        Args:
            signing_key: The keypair of the parent warrant's holder
            
        Returns:
            Tuple of (child_warrant, delegation_receipt)
            
        Raises:
            DelegationAuthorityError: If signing_key doesn't match parent's holder
        """
        child, receipt = self._rust_builder.delegate_with_receipt(signing_key)
        
        # Also store receipt for later access via child.delegation_receipt
        from .warrant_ext import _delegation_receipts
        _delegation_receipts[child.id] = receipt
        
        return child, receipt
    
    # =========================================================================
    # Legacy property aliases (for backward compatibility with tests)
    # =========================================================================
    
    @property
    def ttl_seconds(self) -> Optional[int]:
        """Deprecated: Use ttl() instead."""
        return self.ttl()  # type: ignore[return-value]


def wrap_rust_builder(rust_builder: RustAttenuationBuilder) -> AttenuationBuilder:
    """Wrap a Rust AttenuationBuilder in Python AttenuationBuilder.
    
    This is used when getting a builder from Warrant.attenuate_builder().
    """
    parent = rust_builder.parent
    return AttenuationBuilder(parent, _rust_builder=rust_builder)


class IssuanceBuilder:
    """Builder for issuing execution warrants from issuer warrants.
    
    This wraps the Rust IssuanceBuilder and provides dual-purpose methods:
    - Called with argument: sets value, returns self for chaining
    - Called without argument: returns current value (getter)
    
    Example:
        exec_warrant = (issuer_warrant.issue_execution()
            .tool("read_file")
            .capability("read_file", {"path": Pattern("/data/*")})
            .holder(worker_kp.public_key)
            .ttl(300)
            .build(issuer_kp))
        
        # Reading configured values
        print(builder.holder())   # Returns configured holder or None
        print(builder.ttl())      # Returns configured TTL or None
    """
    
    # Sentinel for detecting "no argument passed"
    _NOT_SET = object()
    
    def __init__(self, rust_builder):
        """Initialize builder with Rust IssuanceBuilder.
        
        Args:
            rust_builder: The Rust IssuanceBuilder from issue_execution()
        """
        self._rust_builder = rust_builder
    
    @property
    def issuer(self) -> Warrant:
        """Get the issuer warrant."""
        return self._rust_builder.issuer
    
    def ttl(self, seconds: Any = _NOT_SET) -> Union['IssuanceBuilder', Optional[int]]:
        """Get or set TTL in seconds.
        
        Args:
            seconds: TTL in seconds (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current TTL (if getting)
        """
        if seconds is self._NOT_SET:
            return self._rust_builder.ttl_seconds
        self._rust_builder.with_ttl(seconds)
        return self
    
    def holder(self, public_key: Any = _NOT_SET) -> Union['IssuanceBuilder', Optional[PublicKey]]:
        """Get or set the authorized holder.
        
        Args:
            public_key: The holder's public key (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current holder (if getting)
        """
        if public_key is self._NOT_SET:
            return self._rust_builder.holder
        self._rust_builder.with_holder(public_key)
        return self
    
    def clearance(self, level: Any = _NOT_SET) -> Union['IssuanceBuilder', Optional[Clearance]]:
        """Get or set clearance level.
        
        Args:
            level: Clearance level (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current clearance level (if getting)
        """
        if level is self._NOT_SET:
            return self._rust_builder.clearance
        self._rust_builder.with_clearance(level)
        return self
    
    def intent(self, value: Any = _NOT_SET) -> Union['IssuanceBuilder', Optional[str]]:
        """Get or set intent/purpose.
        
        Args:
            value: Intent string (omit to get current value)
            
        Returns:
            Self for chaining (if setting), or current intent (if getting)
        """
        if value is self._NOT_SET:
            return self._rust_builder.intent
        self._rust_builder.with_intent(value)
        return self
    
    def tool(self, name: str) -> 'IssuanceBuilder':
        """Add a single tool with empty constraints.
        
        Args:
            name: Tool name to add
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_tool(name)
        return self
    
    def tools(self, names: List[str]) -> 'IssuanceBuilder':
        """Get configured tools or set multiple tools.
        
        When called without arguments, returns list of configured tools.
        When called with names, adds all specified tools.
        
        Args:
            names: List of tool names to add
            
        Returns:
            Self for chaining (if setting), or list of tools (if getting)
        """
        for name in names:
            self._rust_builder.with_tool(name)
        return self
    
    @property 
    def configured_tools(self) -> Optional[List[str]]:
        """Get configured tools list."""
        return self._rust_builder.tools
    
    def capability(self, tool: str, constraints: Dict[str, Any]) -> 'IssuanceBuilder':
        """Add a capability (tool + constraints).
        
        Args:
            tool: Tool name
            constraints: Dict of field->constraint mappings
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_capability(tool, constraints)
        return self
    
    def max_depth(self, depth: int) -> 'IssuanceBuilder':
        """Set maximum delegation depth.
        
        Args:
            depth: Maximum delegation depth
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_max_depth(depth)
        return self
    
    def session_id(self, value: str) -> 'IssuanceBuilder':
        """Set session ID.
        
        Args:
            value: Session ID string
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_session_id(value)
        return self
    
    def agent_id(self, value: str) -> 'IssuanceBuilder':
        """Set agent ID.
        
        Args:
            value: Agent ID string
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_agent_id(value)
        return self
    
    def required_approvers(self, approvers: List[PublicKey]) -> 'IssuanceBuilder':
        """Set required approvers.
        
        Args:
            approvers: List of approver public keys
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_required_approvers(approvers)
        return self
    
    def min_approvals(self, count: int) -> 'IssuanceBuilder':
        """Set minimum approvals required.
        
        Args:
            count: Minimum number of approvals
            
        Returns:
            Self for chaining
        """
        self._rust_builder.with_min_approvals(count)
        return self
    
    def terminal(self) -> 'IssuanceBuilder':
        """Make warrant terminal (cannot delegate further).
        
        Returns:
            Self for chaining
        """
        self._rust_builder.terminal()
        return self
    
    def build(self, signing_key: SigningKey) -> Warrant:
        """Build and sign the execution warrant.
        
        The signing key must belong to the holder of the issuer warrant.
        
        Args:
            signing_key: The keypair of the issuer warrant's holder
            
        Returns:
            The newly created execution warrant
        """
        return self._rust_builder.build(signing_key)
    
    def issue(self, signing_key: SigningKey) -> Warrant:
        """Issue the execution warrant (alias for build).
        
        Semantically preferred name when issuing execution warrants from an issuer warrant.
        
        Args:
            signing_key: The keypair of the issuer warrant's holder
            
        Returns:
            The newly created execution warrant
        """
        return self.build(signing_key)
    
    # =========================================================================
    # Legacy aliases (for backward compatibility)
    # =========================================================================
    
    def with_tool(self, name: str) -> 'IssuanceBuilder':
        """Alias for tool()."""
        return self.tool(name)
    
    def with_capability(self, tool: str, constraints: Dict[str, Any]) -> 'IssuanceBuilder':
        """Alias for capability()."""
        return self.capability(tool, constraints)
    
    def with_ttl(self, seconds: int) -> 'IssuanceBuilder':
        """Alias for ttl()."""
        return self.ttl(seconds)  # type: ignore[return-value]
    
    def with_holder(self, public_key: PublicKey) -> 'IssuanceBuilder':
        """Alias for holder()."""
        return self.holder(public_key)  # type: ignore[return-value]
    
    def with_clearance(self, level: Clearance) -> 'IssuanceBuilder':
        """Alias for clearance()."""
        return self.clearance(level)  # type: ignore[return-value]
    
    def with_intent(self, value: str) -> 'IssuanceBuilder':
        """Alias for intent()."""
        return self.intent(value)  # type: ignore[return-value]
    
    def with_max_depth(self, depth: int) -> 'IssuanceBuilder':
        """Alias for max_depth()."""
        return self.max_depth(depth)


def wrap_rust_issuance_builder(rust_builder) -> IssuanceBuilder:
    """Wrap a Rust IssuanceBuilder in Python IssuanceBuilder.
    
    This is used when getting a builder from Warrant.issue_execution().
    """
    return IssuanceBuilder(rust_builder)
