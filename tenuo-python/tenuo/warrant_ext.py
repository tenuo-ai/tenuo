"""
Extensions for Warrant class - delegation receipts and chain reconstruction.

This module provides:
- Receipt storage for delegated warrants  
- Chain reconstruction utilities for audit
- Diff computation between warrants (delegates to Rust)
- Wrapper for attenuate_builder() to return Python builder with diff support
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING, Union
from tenuo_core import Warrant  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from .builder import AttenuationBuilder

from tenuo_core import (  # type: ignore[import-untyped]
    DelegationDiff,
    DelegationReceipt,
    compute_diff as rust_compute_diff,
)

# Store receipts in a dict keyed by warrant ID (string)
# Rust-exposed objects can't store arbitrary attributes
_delegation_receipts: Dict[str, DelegationReceipt] = {}


def get_delegation_receipt(warrant: Warrant) -> Optional[DelegationReceipt]:
    """Get the delegation receipt if this warrant was created via delegation."""
    return _delegation_receipts.get(warrant.id)


def set_delegation_receipt(warrant: Warrant, receipt: DelegationReceipt) -> None:
    """Set the delegation receipt for a warrant."""
    _delegation_receipts[warrant.id] = receipt


# Add delegation_receipt property to Warrant class
def _warrant_get_delegation_receipt(self: Warrant) -> Optional[DelegationReceipt]:
    """Get the delegation receipt if this warrant was created via delegation."""
    return _delegation_receipts.get(self.id)


def _warrant_set_delegation_receipt(self: Warrant, receipt: DelegationReceipt) -> None:
    """Set the delegation receipt (internal use)."""
    _delegation_receipts[self.id] = receipt


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
    
    # Trace back using parent_id
    while current.parent_id is not None:
        parent_id = current.parent_id
        
        # Try to fetch parent from store
        parent: Optional[Warrant] = None
        try:
            parent = warrant_store.get(parent_id)
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
        "parent_warrant_id": child.parent_id or "unknown",
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
