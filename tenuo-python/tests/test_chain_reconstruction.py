"""
Tests for chain reconstruction with diffs.
"""

from tenuo import (
    SigningKey, Warrant, Pattern, Exact, Range, Constraints,
    DelegationDiff, DelegationReceipt,
)
from tenuo.warrant_ext import get_chain_with_diffs, compute_diff


def test_compute_diff_basic():
    """Test computing diff between two warrants."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    # Create parent
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    # Create child via builder
    builder = parent.attenuate_builder()
    builder.with_capability("read_file", {"path": Exact("/data/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    
    child = builder.delegate_to(control_kp, control_kp)
    
    # Compute diff
    diff = compute_diff(parent, child)
    
    assert isinstance(diff, DelegationDiff)
    assert diff.parent_warrant_id == parent.id
    assert diff.child_warrant_id == child.id
    assert "read_file" in diff.capabilities
    assert diff.ttl.change.value == "reduced"
    assert diff.depth.parent_depth == 0
    assert diff.depth.child_depth == 1


def test_chain_reconstruction_simple():
    """Test reconstructing a simple 2-level chain."""
    control_kp = SigningKey.generate()
    orchestrator_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    # Root warrant
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=orchestrator_kp.public_key,
        ttl_seconds=3600
    )
    
    # First delegation
    builder1 = root.attenuate_builder()
    builder1.with_capability("read_file", {"path": Pattern("/data/reports/*")})
    builder1.with_ttl(300)
    builder1.with_holder(worker_kp.public_key)
    
    child1 = builder1.delegate_to(orchestrator_kp, control_kp)
    
    # Second delegation
    builder2 = child1.attenuate_builder()
    builder2.with_capability("read_file", {"path": Exact("/data/reports/q3.pdf")})
    builder2.with_ttl(60)
    
    child2 = builder2.delegate_to(worker_kp, orchestrator_kp)
    
    # Reconstruct chain - need a store with all warrants
    # Create a simple store
    class SimpleStore:
        def __init__(self):
            self.warrants = {}
        def get(self, key: str):
            return self.warrants.get(key)
        def put(self, warrant: Warrant):
            self.warrants[warrant.id] = warrant
            # Also index by payload hash for chain reconstruction
            import hashlib
            h = hashlib.sha256(warrant.payload_bytes).hexdigest()
            self.warrants[h] = warrant
    
    store = SimpleStore()
    store.put(root)
    store.put(child1)
    store.put(child2)
    
    chain = get_chain_with_diffs(child2, warrant_store=store)
    
    # Should have 2 diffs (root->child1, child1->child2)
    assert len(chain) == 2
    
    # Check first diff
    diff1 = chain[0]
    assert diff1.parent_warrant_id == root.id
    assert diff1.child_warrant_id == child1.id
    
    # Check second diff
    diff2 = chain[1]
    assert diff2.parent_warrant_id == child1.id
    assert diff2.child_warrant_id == child2.id


def test_chain_reconstruction_with_store():
    """Test chain reconstruction with warrant store."""
    control_kp = SigningKey.generate()
    orchestrator_kp = SigningKey.generate()
    
    # Root warrant
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=orchestrator_kp.public_key,
        ttl_seconds=3600
    )
    
    # First delegation
    builder1 = root.attenuate_builder()
    builder1.with_capability("read_file", {"path": Pattern("/data/reports/*")})
    builder1.with_ttl(300)
    
    child1 = builder1.delegate_to(orchestrator_kp, control_kp)
    
    # Mock warrant store
    class MockWarrantStore:
        def __init__(self):
            self.warrants = {}
        
        def get(self, key: str):
            return self.warrants.get(key)
        
        def put(self, warrant: Warrant):
            self.warrants[warrant.id] = warrant
            import hashlib
            h = hashlib.sha256(warrant.payload_bytes).hexdigest()
            self.warrants[h] = warrant
    
    store = MockWarrantStore()
    store.put(root)
    store.put(child1)
    
    # Reconstruct chain
    chain = get_chain_with_diffs(child1, warrant_store=store)
    
    # Should have 1 diff (root->child1)
    assert len(chain) == 1
    diff = chain[0]
    assert diff.parent_warrant_id == root.id
    assert diff.child_warrant_id == child1.id


def test_multiple_constraint_changes():
    """Test diff with multiple constraint changes."""
    control_kp = SigningKey.generate()
    
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_ops", {
            "path": Pattern("/data/*"),
            "max_size": Range.max_value(1000000),
        }),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = parent.attenuate_builder()
    builder.with_capability("file_ops", {
        "path": Exact("/data/q3.pdf"),
        "max_size": Range.max_value(500000),
    })
    builder.with_ttl(60)
    
    diff = builder.diff_structured()
    
    # Should have capability changes
    assert "file_ops" in diff.capabilities
    # The constraints within the capability should show changes


def test_trust_level_change():
    """Test diff with trust level change."""
    control_kp = SigningKey.generate()
    
    from tenuo import TrustLevel
    
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = parent.attenuate_builder()
    builder.with_trust_level(TrustLevel("external"))  # Demote trust - TrustLevel is created with string
    builder.with_ttl(60)
    
    diff = builder.diff_structured()
    
    # Trust should be demoted (if parent had higher trust)
    # Note: Parent might not have explicit trust level set
    assert diff.trust is not None
    # The change type depends on parent's trust level


def test_tool_dropping():
    """Test diff when tools are dropped."""
    control_kp = SigningKey.generate()
    
    # Parent with multiple tools (comma-separated)
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    # Note: Tool narrowing in execution warrants is done via capabilities
    # For issuer warrants, we'd use issuable_tools
    # This test verifies the diff shows tool inheritance
    builder = parent.attenuate_builder()
    builder.with_capability("read_file", {"path": Exact("/data/q3.pdf")})
    
    diff = builder.diff_structured()
    
    # Tools should be inherited (not dropped in execution warrants)
    assert len(diff.tools.kept) > 0
    # Dropped tools would be shown if we had issuer warrant with issuable_tools


def test_receipt_serialization_roundtrip():
    """Test that receipt can be serialized and contains all fields."""
    import json
    from tenuo.builder import AttenuationBuilder
    
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}), 
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = AttenuationBuilder(parent)
    builder.with_capability("file_operations", {"path": Exact("/data/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    builder.with_intent("Test delegation")
    
    child = builder.delegate_to(control_kp, control_kp)
    receipt = child.delegation_receipt
    
    # Serialize to JSON
    json_str = receipt.to_json()
    data = json.loads(json_str)
    
    # Verify all fields present
    assert "parent_warrant_id" in data
    assert "child_warrant_id" in data
    assert "delegator_fingerprint" in data
    assert "delegatee_fingerprint" in data
    assert "intent" in data
    assert "used_pass_through" in data
    assert "tools" in data
    assert "ttl" in data
    assert "trust" in data
    assert "depth" in data
    
    # Verify values
    assert data["parent_warrant_id"] == parent.id
    assert data["child_warrant_id"] == child.id
    assert data["intent"] == "Test delegation"
    assert data["used_pass_through"] is False


def test_diff_with_no_changes():
    """Test diff when no changes are made (self-attenuation)."""
    control_kp = SigningKey.generate()
    
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    # Create builder but don't make any changes
    builder = parent.attenuate_builder()
    # Just change holder (self-attenuation)
    builder.with_holder(control_kp.public_key)
    
    diff = builder.diff_structured()
    
    # Should show no constraint changes (inherited)
    # TTL should be unchanged (inherited)
    assert diff.depth.child_depth == diff.depth.parent_depth + 1


def test_receipt_after_delegation():
    """Test that receipt is properly attached after delegation."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    parent = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = parent.attenuate_builder()
    builder.with_capability("read_file", {"path": Exact("/data/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    builder.with_intent("Read Q3 report")
    
    child = builder.delegate_to(control_kp, control_kp)
    
    # Check receipt exists (stored in module dict, accessed via property)
    receipt = child.delegation_receipt
    assert receipt is not None
    assert isinstance(receipt, DelegationReceipt)
    
    # Verify receipt data
    assert receipt.parent_warrant_id == parent.id
    assert receipt.child_warrant_id == child.id
    assert receipt.intent == "Read Q3 report"
    assert receipt.delegator_fingerprint is not None
    assert receipt.delegatee_fingerprint is not None