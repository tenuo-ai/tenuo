"""
Extensions for Warrant class - delegation receipts and chain reconstruction.

This module provides:
- Receipt storage for delegated warrants  
- Chain reconstruction utilities for audit
- Diff computation between warrants
- Wrapper for attenuate_builder() to return Python builder with diff support
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING
from tenuo_core import Warrant  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from .builder import AttenuationBuilder

from tenuo_core import (  # type: ignore[import-untyped]
    DelegationDiff,
    DelegationReceipt,
    compute_diff as rust_compute_diff,
)
from .diff import (
    DelegationDiff as PyDelegationDiff,
    ToolsDiff as PyToolsDiff,
    TtlDiff as PyTtlDiff,
    TrustDiff as PyTrustDiff,
    DepthDiff as PyDepthDiff,
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
) -> List[DelegationDiff]:
    """
    Reconstruct full delegation chain with diffs.
    
    NOTE: This is for AUDIT purposes only. Runtime verification
    uses embedded ChainLink data and requires no external fetches.
    
    Args:
        warrant: The leaf warrant to trace back from
        warrant_store: Optional storage for fetching parent warrants
            Must have a .get(warrant_id) method
        
    Returns:
        List of DelegationDiff objects from root to leaf
    """
    chain: List[DelegationDiff] = []
    current = warrant
    
    # Without a store, we can only return minimal info
    if warrant_store is None:
        return [compute_diff_from_link_minimal(current)]
    
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


def compute_diff_from_link_minimal(child: Warrant) -> PyDelegationDiff:
    """Create minimal diff when parent not available (fallback).
    
    Returns a Python DelegationDiff since we don't have full warrant data.
    """
    from datetime import datetime, timezone
    
    return PyDelegationDiff(
        parent_warrant_id=child.parent_id or "unknown",
        child_warrant_id=child.id,
        timestamp=datetime.now(timezone.utc),
        tools=PyToolsDiff(parent_tools=[], child_tools=[]),
        constraints={},
        ttl=PyTtlDiff(parent_ttl_seconds=None, child_ttl_seconds=None),
        trust=PyTrustDiff(parent_trust=None, child_trust=child.trust_level),
        depth=PyDepthDiff(parent_depth=child.depth - 1, child_depth=child.depth),
        intent=None,
    )


def compute_diff(parent: Warrant, child: Warrant) -> DelegationDiff:
    """Compute diff between two warrants (parent and child).
    
    Delegates to the Rust implementation for performance and consistency.
    """
    return rust_compute_diff(parent, child)


def compute_diff_from_link(link: Any, child: Warrant) -> PyDelegationDiff:
    """Compute diff from embedded chain link data.
    
    This is a fallback when the parent warrant is not available
    in the warrant store. Returns a Python DelegationDiff.
    """
    from datetime import datetime, timezone
    
    return PyDelegationDiff(
        parent_warrant_id=getattr(link, 'issuer_id', 'unknown'),
        child_warrant_id=child.id,
        timestamp=datetime.now(timezone.utc),
        tools=PyToolsDiff(parent_tools=[], child_tools=[]),
        constraints={},
        ttl=PyTtlDiff(parent_ttl_seconds=None, child_ttl_seconds=None),
        trust=PyTrustDiff(parent_trust=None, child_trust=child.trust_level),
        depth=PyDepthDiff(parent_depth=child.depth - 1, child_depth=child.depth),
        intent=None,
    )
