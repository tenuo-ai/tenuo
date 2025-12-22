"""
Extensions for Warrant class - convenience methods and DX improvements.

This module provides:
- Core convenience properties (ttl_remaining, expires_at, is_terminal, is_expired)
- Preview methods for UX (preview_can, preview_would_allow)
- Debugging methods (explain, inspect, why_denied)
- Improved delegation with auto-wrapping
- Delegation receipts and chain reconstruction
- Diff computation between warrants (delegates to Rust)

Note on memory management:
    Delegation receipts are stored in a module-level cache keyed by warrant ID.
    For long-running processes that create many warrants, call clear_receipts()
    periodically or clear_receipt(warrant) when individual warrants are no longer needed.
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING, Union, Protocol, runtime_checkable
from datetime import timedelta, datetime, timezone
from dataclasses import dataclass
import base64
from tenuo_core import Warrant, PublicKey, SigningKey  # type: ignore[import-untyped]
from tenuo_core import (  # type: ignore[import-untyped]
    DelegationDiff,
    DelegationReceipt,
    compute_diff as rust_compute_diff,
)

from .decorators import get_signing_key_context

if TYPE_CHECKING:
    from .builder import AttenuationBuilder


# ============================================================================
# Type Protocols (P1)
# ============================================================================

@runtime_checkable
class ReadableWarrant(Protocol):
    """Protocol for warrant-like objects (read-only operations)."""
    
    @property
    def id(self) -> str: ...
    
    @property
    def tools(self) -> List[str]: ...
    
    @property
    def clearance(self) -> Any: ...
    
    @property
    def depth(self) -> int: ...
    
    @property
    def max_depth(self) -> int: ...
    
    def is_expired(self) -> bool: ...
    
    def is_terminal(self) -> bool: ...
    
    def explain(self, include_chain: bool = False) -> str: ...


@runtime_checkable
class SignableWarrant(Protocol):
    """Protocol for warrant-like objects that can sign requests."""
    
    def auth_headers(self, tool: str, args: dict) -> Dict[str, str]: ...
    
    def delegate(self, *, to: PublicKey, allow: Union[str, List[str]], ttl: int) -> "Warrant": ...


if TYPE_CHECKING:
    from .bound_warrant import BoundWarrant

# Union type for convenience
AnyWarrant = Union[Warrant, "BoundWarrant"]


# ============================================================================
# Deny Codes (for why_denied)
# ============================================================================

class DenyCode:
    """Stable deny codes for programmatic handling."""
    ALLOWED = "ALLOWED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    WARRANT_EXPIRED = "WARRANT_EXPIRED"
    CONSTRAINT_MISMATCH = "CONSTRAINT_MISMATCH"
    CONSTRAINT_RANGE = "CONSTRAINT_RANGE"
    CONSTRAINT_MISSING = "CONSTRAINT_MISSING"
    CLEARANCE_INSUFFICIENT = "CLEARANCE_INSUFFICIENT"
    TERMINAL = "TERMINAL"


@dataclass
class WhyDenied:
    """
    Structured explanation for why a request would be denied.
    
    Use warrant.why_denied(tool, args) to get this.
    """
    denied: bool
    deny_code: str
    deny_path: Optional[str] = None
    tool: str = ""
    field: Optional[str] = None
    constraint: Any = None
    value: Any = None
    suggestion: str = ""
    
    def __repr__(self) -> str:
        if not self.denied:
            return f"<WhyDenied ALLOWED tool={self.tool!r}>"
        return f"<WhyDenied {self.deny_code} tool={self.tool!r} field={self.field!r}>"

# Store receipts in a dict keyed by warrant ID (string)
# Rust-exposed objects can't store arbitrary Python attributes.
# Use clear_receipt() or clear_receipts() to prevent memory leaks in long-running processes.
_delegation_receipts: Dict[str, DelegationReceipt] = {}

# Maximum receipts to keep (LRU-style eviction)
_MAX_RECEIPTS = 10000


# ============================================================================
# 1. Core Convenience Properties
# ============================================================================

def _warrant_ttl_remaining(self: Warrant) -> timedelta:
    """Time remaining until expiration."""
    # Prefer ttl_seconds() from Rust (accurate, no parsing needed)
    if hasattr(self, 'ttl_seconds') and callable(getattr(self, 'ttl_seconds', None)):
        return timedelta(seconds=self.ttl_seconds())

    # Fallback: calculate from is_expired() and expires_at()
    # This is less precise but works with older Rust builds
    if self.is_expired():
        return timedelta(0)
    
    try:
        # expires_at() returns RFC3339 format like "2025-12-22T12:00:00Z"
        expires_str = self.expires_at()
        # Python 3.11+ handles 'Z' directly, older versions need conversion
        if expires_str.endswith('Z'):
            expires_str = expires_str[:-1] + '+00:00'
        expires = datetime.fromisoformat(expires_str)
        now = datetime.now(timezone.utc)
        remaining = expires - now
        return remaining if remaining.total_seconds() > 0 else timedelta(0)
    except (ValueError, AttributeError) as e:
        # If parsing fails, warn and return zero (expired)
        import warnings
        warnings.warn(
            f"Could not parse expires_at: {e}. "
            "Consider rebuilding tenuo_core for ttl_seconds() support.",
            UserWarning
        )
        return timedelta(0)


def _warrant_is_terminal_prop(self: Warrant) -> bool:
    """Property wrapper for is_terminal() method."""
    return self.is_terminal()


def _warrant_is_expired_prop(self: Warrant) -> bool:
    """Property wrapper for is_expired() method."""
    return self.is_expired()


# Add ttl_remaining as a property (wraps ttl_seconds())
if not hasattr(Warrant, 'ttl_remaining'):
    Warrant.ttl_remaining = property(_warrant_ttl_remaining)  # type: ignore[attr-defined]

# Short alias: ttl → ttl_remaining
if not hasattr(Warrant, 'ttl'):
    Warrant.ttl = property(_warrant_ttl_remaining)  # type: ignore[attr-defined]

# Note: is_expired() and is_terminal() are methods from Rust
# We expose them also as properties for convenience (spec compliance)
# The methods still work, but properties are more Pythonic
if not hasattr(Warrant, 'expired'):
    Warrant.expired = property(_warrant_is_expired_prop)  # type: ignore[attr-defined]

if not hasattr(Warrant, 'terminal'):
    Warrant.terminal = property(_warrant_is_terminal_prop)  # type: ignore[attr-defined]


# ============================================================================
# 1.5 Capabilities Property (P1)
# ============================================================================

def _warrant_capabilities(self: Warrant) -> Dict[str, Dict[str, str]]:
    """
    Human-readable constraints for each tool.
    
    Returns:
        Dict mapping tool names to constraint dicts with string representations.
        
    Example:
        warrant.capabilities
        # {
        #     "read_file": {"path": "Pattern('/data/*')"},
        #     "search": {"query": "Pattern('*')", "max_results": "Range(max=100)"}
        # }
    """
    result: Dict[str, Dict[str, str]] = {}
    
    # Get constraints for each tool
    for tool in self.tools:
        try:
            # Try to get constraints from Rust if available
            if hasattr(self, 'get_constraints'):
                constraints = self.get_constraints(tool)
                if constraints:
                    result[tool] = {k: repr(v) for k, v in constraints.items()}
                else:
                    result[tool] = {}
            else:
                # Fallback: no constraint info available
                result[tool] = {}
        except Exception:
            result[tool] = {}
    
    return result


if not hasattr(Warrant, 'capabilities'):
    Warrant.capabilities = property(_warrant_capabilities)  # type: ignore[attr-defined]


# ============================================================================
# 1.5.1 Warrant __repr__ Redaction (Security)
# ============================================================================

def _warrant_repr(self: Warrant) -> str:
    """
    Safe string representation that doesn't leak sensitive data.
    
    Shows: id (truncated), tools, TTL remaining
    Hides: signatures, full warrant bytes, session_id
    """
    try:
        ttl = self.ttl_remaining
        ttl_str = str(ttl).split('.')[0]  # Remove microseconds
    except Exception:
        ttl_str = "?"
    
    tools_str = ", ".join(self.tools[:3])
    if len(self.tools) > 3:
        tools_str += f", +{len(self.tools) - 3} more"
    
    return f"<Warrant id={self.id[:16]}... tools=[{tools_str}] ttl={ttl_str}>"


# Override Rust's __repr__ with our safe version
Warrant.__repr__ = _warrant_repr  # type: ignore[method-assign]


# ============================================================================
# 1.6 auth_headers on Warrant (P0)
# ============================================================================

def _warrant_auth_headers(
    self: Warrant,
    key: SigningKey,
    tool: str,
    args: dict,
) -> Dict[str, str]:
    """
    Generate HTTP authorization headers.
    
    This creates the X-Tenuo-Warrant and X-Tenuo-PoP headers needed
    for authenticated API calls.
    
    Args:
        key: Signing key (must match warrant's authorized_holder)
        tool: Tool name being called
        args: Tool arguments
        
    Returns:
        Dictionary with X-Tenuo-Warrant and X-Tenuo-PoP headers
        
    Example:
        headers = warrant.auth_headers(key, "search", {"query": "test"})
        response = requests.post(url, headers=headers, json=args)
    """
    pop_sig = self.create_pop_signature(key, tool, args)
    pop_b64 = base64.b64encode(pop_sig).decode('ascii')
    
    return {
        "X-Tenuo-Warrant": self.to_base64(),
        "X-Tenuo-PoP": pop_b64
    }


if not hasattr(Warrant, 'auth_headers'):
    Warrant.auth_headers = _warrant_auth_headers  # type: ignore[attr-defined]


# ============================================================================
# 2. Preview Methods (UX Only - NOT Authorization)
# ============================================================================

@dataclass
class PreviewResult:
    """Result of a preview check. NOT AUTHORIZATION - for UX only."""
    
    allowed: bool
    reason: Optional[str] = None
    
    def __bool__(self) -> bool:
        return self.allowed
    
    def __repr__(self) -> str:
        status = "OK" if self.allowed else "DENIED"
        return f"<PreviewResult {status} (UX ONLY - not authorization)>"


def _warrant_preview_can(self: Warrant, tool: str) -> PreviewResult:
    """Check if tool is in warrant (UX only, not authorization)."""
    if tool in self.tools:
        return PreviewResult(True)
    available = ", ".join(self.tools) if self.tools else "none"
    return PreviewResult(False, f"Tool '{tool}' not in warrant. Available: {available}")


def _warrant_preview_would_allow(self: Warrant, tool: str, args: dict) -> PreviewResult:
    """
    Check if args would satisfy constraints (UX only, not authorization).
    
    ⚠️  SECURITY WARNING: THIS IS NOT A SECURITY CHECK  ⚠️
    
    This method checks constraints WITHOUT verifying Proof-of-Possession.
    It is intended for UI hints ("should I show this button?"), NOT for
    authorization decisions that gate sensitive operations.
    
    For actual authorization, use:
        bound_warrant.authorize(tool, args)  # Verifies PoP signature
    
    NEVER do this:
        if warrant.preview_would_allow("tool", args).allowed:
            execute_dangerous_operation()  # ❌ NO PoP CHECK!
    
    This delegates to Rust for constraint checking to avoid logic divergence.
    """
    # First check if tool is in warrant
    if tool not in self.tools:
        return PreviewResult(False, f"Tool '{tool}' not in warrant")
    
    # TODO: Need Rust method to check constraints without PoP
    # For now, just check tool presence
    return PreviewResult(True, "Tool present (constraint check not yet implemented)")


# Attach preview methods
if not hasattr(Warrant, 'preview_can'):
    Warrant.preview_can = _warrant_preview_can  # type: ignore[attr-defined]

if not hasattr(Warrant, 'preview_would_allow'):
    Warrant.preview_would_allow = _warrant_preview_would_allow  # type: ignore[attr-defined]


# ============================================================================
# 2.5 why_denied Method (P0)
# ============================================================================

def _warrant_why_denied(self: Warrant, tool: str, args: Optional[dict] = None) -> WhyDenied:
    """
    Get structured explanation for why a request would be denied.
    
    Use this for debugging authorization failures.
    
    Args:
        tool: Tool name to check
        args: Tool arguments (optional)
        
    Returns:
        WhyDenied with deny_code, field, suggestion, etc.
        
    Example:
        result = warrant.why_denied("delete_file", {"path": "/etc/passwd"})
        if result.denied:
            print(f"Denied: {result.deny_code}")
            print(f"Field: {result.field}")
            print(f"Suggestion: {result.suggestion}")
    """
    args = args or {}
    
    # Check if warrant is expired
    if self.is_expired():
        return WhyDenied(
            denied=True,
            deny_code=DenyCode.WARRANT_EXPIRED,
            deny_path="warrant.expired",
            tool=tool,
            suggestion=f"Warrant expired at {self.expires_at()}. Request a fresh warrant.",
        )
    
    # Check if tool is in warrant
    if tool not in self.tools:
        available = ", ".join(self.tools) if self.tools else "none"
        return WhyDenied(
            denied=True,
            deny_code=DenyCode.TOOL_NOT_FOUND,
            deny_path="tool.not_found",
            tool=tool,
            suggestion=f"Tool '{tool}' not in warrant. Available: {available}",
        )
    
    # Check if warrant is terminal (can't delegate)
    # This isn't really a "denial" for execution, but useful info
    
    # Try to check constraints via Rust authorize (without PoP)
    # Note: This will return False for MissingSignature, not constraint failure
    # For now, we can't distinguish constraint failures without PoP
    # This is a known limitation - full implementation needs Rust support
    
    # Check constraints if we have a method for it
    if hasattr(self, 'check_constraints'):
        try:
            result = self.check_constraints(tool, args)
            if not result.get('allowed', True):
                return WhyDenied(
                    denied=True,
                    deny_code=DenyCode.CONSTRAINT_MISMATCH,
                    deny_path=f"constraints.{result.get('field', 'unknown')}",
                    tool=tool,
                    field=result.get('field'),
                    constraint=result.get('constraint'),
                    value=result.get('value'),
                    suggestion=result.get('reason', 'Constraint not satisfied'),
                )
        except Exception:
            pass  # Fall through to allowed
    
    # If we got here, authorization would likely succeed
    # (assuming valid PoP signature)
    return WhyDenied(
        denied=False,
        deny_code=DenyCode.ALLOWED,
        tool=tool,
        suggestion="Request would be allowed (assuming valid PoP signature)",
    )


if not hasattr(Warrant, 'why_denied'):
    Warrant.why_denied = _warrant_why_denied  # type: ignore[attr-defined]


# ============================================================================
# 3. Debugging Methods
# ============================================================================

def _warrant_explain(self: Warrant, include_chain: bool = False) -> str:
    """Human-readable warrant explanation."""
    lines = [
        f"Warrant {self.id[:12]}...",
        f"  Type: {self.warrant_type}",
        f"  Tools: {', '.join(self.tools) if self.tools else 'none'}",
        f"  TTL: {self.ttl_remaining}",
        f"  Expires: {self.expires_at()}",  # Rust method returns RFC3339 string
    ]
    
    if self.clearance is not None:
        lines.append(f"  Clearance: {self.clearance}")
    
    # max_depth might be None in older Rust builds or for some warrant types
    max_d = getattr(self, 'max_depth', None)
    if max_d is None and hasattr(self, 'max_issue_depth'):
        max_d = self.max_issue_depth
    lines.append(f"  Depth: {self.depth}/{max_d if max_d is not None else '?'}")
    
    if self.is_terminal():  # Method, not property
        lines.append("  [WARNING] Terminal - cannot delegate further")
    
    if self.is_expired():  # Method, not property
        lines.append("  [WARNING] Expired")
    
    if include_chain and self.parent_hash:
        lines.append(f"  Parent: {self.parent_hash[:12]}...")
    
    return "\n".join(lines)


def _warrant_inspect(self: Warrant) -> str:
    """Alias for explain() with chain information."""
    return self.explain(include_chain=True)


# Attach debugging methods
if not hasattr(Warrant, 'explain'):
    Warrant.explain = _warrant_explain  # type: ignore[attr-defined]

if not hasattr(Warrant, 'inspect'):
    Warrant.inspect = _warrant_inspect  # type: ignore[attr-defined]


# ============================================================================
# 4. Delegation Receipts (Existing Code)
# ============================================================================

def get_delegation_receipt(warrant: Warrant) -> Optional[DelegationReceipt]:
    """Get the delegation receipt if this warrant was created via delegation."""
    return _delegation_receipts.get(warrant.id)


def set_delegation_receipt(warrant: Warrant, receipt: DelegationReceipt) -> None:
    """Set the delegation receipt for a warrant."""
    # Simple size limit to prevent unbounded growth
    if len(_delegation_receipts) >= _MAX_RECEIPTS:
        # Remove oldest entry (first key in dict - Python 3.7+ maintains insertion order)
        oldest_key = next(iter(_delegation_receipts))
        del _delegation_receipts[oldest_key]
    _delegation_receipts[warrant.id] = receipt


def clear_receipt(warrant: Warrant) -> None:
    """Clear the delegation receipt for a warrant (memory cleanup)."""
    _delegation_receipts.pop(warrant.id, None)


def clear_receipts() -> None:
    """Clear all stored delegation receipts (memory cleanup)."""
    _delegation_receipts.clear()


# Add delegation_receipt property to Warrant class
def _warrant_get_delegation_receipt(self: Warrant) -> Optional[DelegationReceipt]:
    """Get the delegation receipt if this warrant was created via delegation."""
    return _delegation_receipts.get(self.id)


def _warrant_set_delegation_receipt(self: Warrant, receipt: DelegationReceipt) -> None:
    """Set the delegation receipt (internal use)."""
    set_delegation_receipt(self, receipt)


# Add delegation_receipt property to Warrant
if not hasattr(Warrant, 'delegation_receipt'):
    Warrant.delegation_receipt = property(  # type: ignore[attr-defined]
        _warrant_get_delegation_receipt,
        _warrant_set_delegation_receipt
    )


# ============================================================================
# 5. Attenuation Builder Wrappers (Existing Code)
# ============================================================================

# Store original Rust attenuate_builder method
_original_attenuate_builder = Warrant.attenuate_builder


def _wrapped_attenuate_builder(self: Warrant) -> 'AttenuationBuilder':
    """Wrap attenuate_builder to return Python AttenuationBuilder with diff support."""
    from .builder import AttenuationBuilder
    rust_builder = _original_attenuate_builder(self)
    return AttenuationBuilder(self, _rust_builder=rust_builder)


# Replace with wrapped version
Warrant.attenuate_builder = _wrapped_attenuate_builder  # type: ignore[method-assign]


# Store original Rust attenuate method
_original_attenuate = Warrant.attenuate


def _wrapped_attenuate(self: Warrant, *args, **kwargs) -> Union[Warrant, 'AttenuationBuilder']:
    """
    Attenuate the warrant.
    
    If arguments are provided, it performs immediate attenuation (backward compatibility).
    If no arguments are provided, it returns an AttenuationBuilder (fluent API).
    """
    if args or kwargs:
        return _original_attenuate(self, *args, **kwargs)
    
    return self.attenuate_builder()


# Replace with wrapped version
Warrant.attenuate = _wrapped_attenuate  # type: ignore[method-assign]


# ============================================================================
# 6. Improved Delegate Method
# ============================================================================

def _warrant_delegate(
    self: Warrant,
    *,
    to: PublicKey,
    allow: Union[str, List[str]],
    ttl: int,
    key: Optional[SigningKey] = None,
    **constraints
) -> Warrant:
    """
    Convenience method to delegate a warrant to a new holder.
    
    This creates a new child warrant with narrowed capabilities.
    
    Args:
        to: The public key of the new holder
        allow: Tool(s) to delegate - string for single tool or list for multiple
        ttl: Time-to-live in seconds for the child warrant
        key: Signing key (optional if using context)
        **constraints: Additional constraints to apply
        
    Returns:
        The new child warrant
        
    Raises:
        RuntimeError: If no key provided and no keypair in context
        
    Example:
        # With explicit key
        child = parent.delegate(
            to=worker_key.public_key,
            allow="search",
            ttl=300,
            key=parent_key
        )
        
        # With context key
        with set_signing_key_context(parent_key):
            child = parent.delegate(
                to=worker_key.public_key,
                allow=["search", "read_file"],
                ttl=300
            )
    """
    # Get signing key from argument or context
    signing_key = key or get_signing_key_context()
    if not signing_key:
        raise RuntimeError(
            "No signing key provided. Either pass key= argument or use "
            "inside a task context / set_signing_key_context()."
        )
    
    # Auto-wrap single string to list
    tools = [allow] if isinstance(allow, str) else list(allow)
    
    # Build child warrant using attenuation builder
    builder = self.attenuate_builder()
    
    # POLA: Start by inheriting all parent capabilities, then narrow
    builder.inherit_all()
    
    # Narrow to specified tools
    builder.tools(tools)
    
    # Apply additional constraints if provided
    if constraints:
        from tenuo.constraints import ensure_constraint
        
        # Apply constraints to each tool
        for tool in tools:
            tool_constraints = {}
            for field, value in constraints.items():
                tool_constraints[field] = ensure_constraint(value)
            builder.capability(tool, tool_constraints)
    
    # Set new holder and TTL
    builder.holder(to)
    builder.ttl(ttl)
    
    # Sign and return
    return builder.delegate(signing_key)


# Replace existing delegate method
Warrant.delegate = _warrant_delegate  # type: ignore[method-assign]


# ============================================================================
# 7. Issue Execution Wrapper (Existing Code)
# ============================================================================

# Store the original issue_execution method
_original_issue_execution = Warrant.issue_execution if hasattr(Warrant, 'issue_execution') else None


def _wrapped_issue_execution(self):
    """Wrap issue_execution() to return Python IssuanceBuilder.
    
    Returns:
        IssuanceBuilder (Python wrapper) with dual-purpose methods
    """
    from .builder import wrap_rust_issuance_builder
    rust_builder = _original_issue_execution(self)
    return wrap_rust_issuance_builder(rust_builder)


# Replace with wrapped version
if _original_issue_execution is not None:
    Warrant.issue_execution = _wrapped_issue_execution


# ============================================================================
# 8. Chain Reconstruction (Existing Code)
# ============================================================================

def get_chain_with_diffs(
    warrant: Warrant,
    warrant_store: Optional[Any] = None,
) -> List[Union[DelegationDiff, Dict[str, Any]]]:
    """
    Reconstruct full delegation chain with diffs.
    
    NOTE: This is for AUDIT purposes only. Runtime verification
    uses embedded ChainLink data and requires no external fetches.
    
    Args:
        warrant: The leaf warrant to trace back from
        warrant_store: Optional storage for fetching parent warrants
            Must have a .get(warrant_id) method
        
    Returns:
        List of DelegationDiff objects (or fallback dicts) from root to leaf
    """
    chain: List[Union[DelegationDiff, Dict[str, Any]]] = []
    current = warrant
    
    # Without a store, we can only return minimal info
    if warrant_store is None:
        return [_create_minimal_diff(current)]
    
    # Trace back using parent_hash
    while current.parent_hash is not None:
        parent_hash = current.parent_hash
        
        # Try to fetch parent from store
        parent: Optional[Warrant] = None
        try:
            if hasattr(warrant_store, "get_by_hash"):
                parent = warrant_store.get_by_hash(parent_hash)
            else:
                # Fallback: assume store might support hash lookup via get
                parent = warrant_store.get(parent_hash)
        except (AttributeError, KeyError, TypeError):
            break
        
        if parent:
            diff = compute_diff(parent, current)
            chain.append(diff)
            current = parent
        else:
            break
    
    # Reverse to get root-first order
    return list(reversed(chain))


def _create_minimal_diff(child: Warrant) -> Dict[str, Any]:
    """Create minimal diff dict when parent not available (fallback)."""
    return {
        "parent_warrant_hash": child.parent_hash or "unknown",
        "child_warrant_id": child.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "depth": {"parent": child.depth - 1, "child": child.depth},
        "note": "Minimal diff - parent warrant not available",
    }


def compute_diff(parent: Warrant, child: Warrant) -> DelegationDiff:
    """Compute diff between two warrants (parent and child).
    
    Delegates to the Rust implementation for performance and consistency.
    """
    return rust_compute_diff(parent, child)
