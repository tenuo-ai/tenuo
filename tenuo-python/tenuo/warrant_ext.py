"""
Extensions for Warrant class - delegation receipts and chain reconstruction.

This module provides:
- Receipt storage for delegated warrants  
- Chain reconstruction utilities for audit
- Diff computation between warrants (delegates to Rust)
- Wrapper for attenuate_builder() to return Python builder with diff support
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING, Union
from tenuo_core import Warrant, PublicKey  # type: ignore[import-untyped]
from .decorators import get_keypair_context

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
    tool: Optional[str] = None,
    **constraints
) -> Warrant:
    """
    Convenience method to delegate a warrant to a new holder.
    
    Args:
        holder: The public key of the new holder
        tool: Optional tool name (if narrowing from issuer warrant or same as parent)
        **constraints: Constraints to apply
        
    Returns:
        The new child warrant
    """
    # Get context keypair (delegator)
    keypair = get_keypair_context()
    if not keypair:
        raise RuntimeError("No active keypair context. Use inside a task context or set_keypair_context().")
        
    # We need the parent keypair (which signed THIS warrant)
    # But wait, to sign the child, we need OUR keypair (delegator).
    # The `delegate_to` method takes (keypair, parent_keypair).
    # - keypair: The one signing the child (us)
    # - parent_keypair: The one that signed US (parent). Wait, no.
    #
    # Let's re-read Rust:
    # fn build(self, keypair: &Keypair, parent_keypair: &Keypair)
    # - keypair: The delegator (us). We sign the child payload.
    # - parent_keypair: The issuer of the parent warrant. We need this to sign the ChainLink.
    #
    # BUT, we don't have the parent's private key!
    # The ChainLink signature is `parent_keypair.sign(&payload_bytes)`.
    # This implies the parent MUST be online to sign the delegation?
    #
    # NO. The ChainLink contains the parent's signature over the child.
    # If I am delegating, I am the parent of the new child.
    # So `keypair` (me) signs the child warrant.
    # And `keypair` (me) signs the ChainLink?
    #
    # Let's look at Rust `build` again:
    # let signature = keypair.sign(&payload_bytes); // Child warrant signature
    # let parent_link = ChainLink { ... signature: parent_keypair.sign(&payload_bytes) }
    #
    # Wait, `parent_keypair` in `build` refers to the keypair of the warrant being attenuated (the parent).
    # If I hold warrant A, and I want to issue warrant B (child of A).
    # I am the holder of A. I am the issuer of B.
    # So `keypair` should be ME.
    # And `parent_keypair` should be ME.
    #
    # Why does `build` take two keypairs?
    # `keypair` -> signs the Warrant (payload).
    # `parent_keypair` -> signs the ChainLink.
    #
    # If I am delegating A -> B.
    # I am the holder of A.
    # I am the issuer of B.
    # So I sign B. (`keypair` = me)
    # And I sign the link from A to B. (`parent_keypair` = me)
    #
    # So why two args?
    # Maybe for root warrants? No, root warrants don't have parents.
    #
    # Ah, `parent` in `AttenuationBuilder` is the warrant being attenuated.
    # So `parent_keypair` is the keypair that matches `parent.authorized_holder`.
    # And `keypair` is the keypair that matches `child.issuer`.
    # Since `child.issuer` MUST be `parent.authorized_holder` (chain of custody),
    # these two keypairs MUST be the same.
    #
    # Unless... we are doing something weird with multi-sig or distinct signing keys?
    # But standard Tenuo flow: Holder of A issues B.
    # So `keypair` == `parent_keypair`.
    #
    # Let's verify this assumption.
    # Rust `build`:
    # `issuer: keypair.public_key` (Child issuer)
    # `parent_link.signature: parent_keypair.sign(...)`
    #
    # Yes, they are the same identity.
    # So `delegate` only needs one keypair (ours).
    
    builder = self.attenuate_builder()
    
    if tool:
        # If tool is provided, we might be narrowing or issuing from issuer warrant
        # But `attenuate_builder` doesn't support changing tool for execution warrants.
        # It DOES support setting tool if parent is Issuer warrant.
        # But `AttenuationBuilder` wrapper in Python doesn't expose `tool()`.
        # Rust `AttenuationBuilder` doesn't have `tool()` method?
        #
        # Let's check Rust `AttenuationBuilder`.
        # It has `issuable_tools` etc.
        # It does NOT have `tool()`.
        #
        # Wait, if I have an Issuer Warrant, how do I create an Execution Warrant?
        # Rust: `warrant.issue_execution_warrant()` -> `IssuanceBuilder`.
        # NOT `attenuate()`.
        #
        # So `attenuate()` is ONLY for Warrant -> Warrant (same type, narrower scope).
        # Execution -> Execution (narrower constraints).
        # Issuer -> Issuer (narrower issuable_tools).
        #
        # If the user wants to issue an execution warrant from an issuer warrant,
        # they should use a different method, e.g., `issue_execution()`.
        #
        # `delegate()` implies passing authority.
        # If I have Execution warrant, I delegate (attenuate) it.
        # If I have Issuer warrant, do I delegate (attenuate) it to another Issuer?
        # Or do I issue an Execution warrant?
        #
        # The spec example: `child = parent.delegate(worker, tool="read_file", path=file_path)`
        # This looks like Execution -> Execution (if parent had "read_file").
        #
        # So `delegate` should handle adding constraints.
        pass

    # Apply constraints
    from tenuo.scoped import _ensure_constraint
    for k, v in constraints.items():
        builder.with_constraint(k, _ensure_constraint(k, v))
        
    builder.with_holder(holder)
    
    # We assume we are the holder of the parent warrant
    return builder.delegate_to(keypair, keypair)


# Add delegate method to Warrant
if not hasattr(Warrant, 'delegate'):
    Warrant.delegate = _warrant_delegate


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
