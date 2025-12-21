"""
Extensions for Warrant class - delegation receipts and chain reconstruction.

This module provides:
- Receipt storage for delegated warrants  
- Chain reconstruction utilities for audit
- Diff computation between warrants (delegates to Rust)
- Wrapper for attenuate_builder() to return Python builder with diff support

Note on memory management:
    Delegation receipts are stored in a module-level cache keyed by warrant ID.
    For long-running processes that create many warrants, call clear_receipts()
    periodically or clear_receipt(warrant) when individual warrants are no longer needed.
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING, Union
from tenuo_core import Warrant, PublicKey  # type: ignore[import-untyped]
from .decorators import get_signing_key_context

if TYPE_CHECKING:
    from .builder import AttenuationBuilder

from tenuo_core import (  # type: ignore[import-untyped]
    DelegationDiff,
    DelegationReceipt,
    compute_diff as rust_compute_diff,
)

# Store receipts in a dict keyed by warrant ID (string)
# Rust-exposed objects can't store arbitrary Python attributes.
# Use clear_receipt() or clear_receipts() to prevent memory leaks in long-running processes.
_delegation_receipts: Dict[str, DelegationReceipt] = {}

# Maximum receipts to keep (LRU-style eviction)
_MAX_RECEIPTS = 10000


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


def _warrant_delegate(
    self: Warrant,
    holder: PublicKey,
    tools: Optional[list] = None,
    **constraints
) -> Warrant:
    """
    Convenience method to delegate a warrant to a new holder.
    
    This attenuates the warrant by narrowing tools, adding/tightening constraints,
    and assigning a new holder.
    
    Args:
        holder: The public key of the new holder
        tools: Optional list of tools to narrow to (must be subset of parent's)
        **constraints: Constraints to apply (must be tighter than parent's)
        
    Returns:
        The new child warrant
        
    Raises:
        RuntimeError: If no keypair in context
        MonotonicityViolation: If tools aren't a subset of parent's
        
    Example:
        with set_keypair_context(my_keypair):
            # Narrow tools AND constraints
            child = parent.delegate(
                holder=worker.public_key,
                tools=["read_file"],  # Narrow from parent's tools
                path=Exact("/data/q3.pdf"),
            )
    """
    # Get context keypair (delegator)
    keypair = get_signing_key_context()
    if not keypair:
        raise RuntimeError("No active keypair context. Use inside a task context or set_keypair_context().")
    
    builder = self.attenuate_builder()
    
    # POLA: Start by inheriting all parent capabilities, then narrow
    builder.inherit_all()

    # Narrow tools if specified
    if tools is not None:
        builder.tools(tools)

    # Apply constraints (merge logic)
    # We must fetch current capabilities, apply new constraints to target tools, and set them back.
    from tenuo.constraints import ensure_constraint
    
    # Target tools: if specified, use them. Otherwise, apply to ALL tools in current builder capabilities.
    current_caps = builder.capabilities # dict[tool, dict[field, constraint]]
    target_tools_set = set(tools) if tools else set(current_caps.keys())
    
    for tool in target_tools_set:
        tool_constraints = current_caps.get(tool, {}).copy()
        
        # Merge new constraints
        for k, v in constraints.items():
            tool_constraints[k] = ensure_constraint(v)
        
        # Note: If tool wasn't in current_caps (and not explicit tools list), we skipped it.
        # If explicit tool list has new tool, current_caps.get returns empty dict, so we add it. 
        # But wait, attenuation cannot ADD tools. The Rust builder will fail validation if we try to add a tool not in parent?
        # Actually OwnedAttenuationBuilder allows adding capabilities, but `build()` checks against parent?
        # OwnedAttenuationBuilder initializes with parent caps.
        # If we use `builder.capability`, we update self.capabilities.
        # If we add a tool that wasn't there, it's effectively "keeping" it? 
        # But if it wasn't in parent, we can't have it.
        # If it WAS in parent but removed by earlier `tools`?
        builder.capability(tool, tool_constraints)
        
    builder.holder(holder)
    
    # We are the holder of the parent warrant, so we sign both
    return builder.delegate(keypair)


# Add delegate method to Warrant
if not hasattr(Warrant, 'delegate'):
    Warrant.delegate = _warrant_delegate


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
    from datetime import datetime, timezone
    
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
