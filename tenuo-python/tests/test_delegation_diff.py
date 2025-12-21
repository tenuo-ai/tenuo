"""
Tests for delegation diff and builder functionality.
"""

from tenuo import (
    SigningKey, Warrant, Pattern, Exact,
    DelegationDiff, DelegationReceipt, ChangeType, Constraints,
)
from tenuo.builder import AttenuationBuilder


def test_builder_basic():
    """Test basic builder functionality."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    # Create root warrant
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    # Use builder
    builder = AttenuationBuilder(root)
    builder.with_capability("file_operations", {"path": Exact("/data/reports/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    builder.with_intent("Q3 report access for worker")
    
    # Check builder state
    assert "file_operations" in builder.capabilities
    assert builder.ttl_seconds == 60
    assert builder.holder is not None
    assert builder.holder.to_bytes() == worker_kp.public_key.to_bytes()  # Compare bytes
    assert builder.intent == "Q3 report access for worker"


def test_builder_diff_computation():
    """Test diff computation before delegation."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = AttenuationBuilder(root)
    builder.with_capability("file_operations", {"path": Exact("/data/reports/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    
    # Get structured diff
    diff = builder.diff_structured()
    
    assert isinstance(diff, DelegationDiff)
    assert diff.parent_warrant_id == root.id
    assert diff.child_warrant_id is None  # Not yet delegated
    assert "file_operations" in diff.capabilities
    assert diff.ttl.child_ttl_seconds == 60
    assert diff.ttl.change == ChangeType.REDUCED


def test_builder_human_readable_diff():
    """Test human-readable diff output."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = AttenuationBuilder(root)
    builder.with_capability("file_operations", {"path": Exact("/data/reports/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    builder.with_intent("Q3 report access")
    
    # Get human-readable diff
    diff_str = builder.diff()
    
    assert isinstance(diff_str, str)
    assert "DELEGATION DIFF" in diff_str
    assert "TOOLS" in diff_str or "CAPABILITIES" in diff_str
    assert "TTL" in diff_str


def test_builder_delegation():
    """Test actual delegation via builder."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = AttenuationBuilder(root)
    builder.with_capability("file_operations", {"path": Exact("/data/reports/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    builder.with_intent("Q3 report access")
    
    # Delegate
    child = builder.delegate(control_kp)
    
    assert child.tools == ["file_operations"]
    assert child.depth == 1
    assert child.authorized_holder.to_bytes() == worker_kp.public_key.to_bytes()  # Compare bytes
    
    # Check receipt was attached
    receipt = child.delegation_receipt
    assert isinstance(receipt, DelegationReceipt)
    assert receipt.child_warrant_id == child.id
    assert receipt.parent_warrant_id == root.id
    assert receipt.intent == "Q3 report access"


def test_warrant_attenuate_builder_method():
    """Test attenuate_builder method on Warrant."""
    control_kp = SigningKey.generate()
    
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    # Use attenuate_builder method
    builder = root.attenuate_builder()
    
    assert isinstance(builder, AttenuationBuilder)
    assert builder.parent == root


def test_delegation_receipt_to_dict():
    """Test receipt serialization using actual delegation."""
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = AttenuationBuilder(root)
    builder.with_capability("file_operations", {"path": Exact("/data/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    builder.with_intent("Test delegation")
    
    child = builder.delegate(control_kp)
    receipt = child.delegation_receipt
    
    # Check receipt exists and has expected structure
    assert receipt is not None
    assert receipt.parent_warrant_id == root.id
    assert receipt.child_warrant_id == child.id
    assert receipt.intent == "Test delegation"
    assert receipt.used_pass_through is False
    # Fingerprints should be non-empty strings
    assert len(receipt.delegator_fingerprint) > 0
    assert len(receipt.delegatee_fingerprint) > 0


def test_delegation_receipt_siem_json():
    """Test SIEM JSON format using actual delegation."""
    import json
    control_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    root = Warrant.issue(
        keypair=control_kp,
        capabilities=Constraints.for_tool("file_operations", {"path": Pattern("/data/*")}),
        holder=control_kp.public_key,
        ttl_seconds=3600
    )
    
    builder = AttenuationBuilder(root)
    builder.with_capability("file_operations", {"path": Exact("/data/q3.pdf")})
    builder.with_ttl(60)
    builder.with_holder(worker_kp.public_key)
    
    child = builder.delegate(control_kp)
    receipt = child.delegation_receipt
    
    # Convert to SIEM JSON
    siem_str = receipt.to_siem_json()
    siem = json.loads(siem_str)
    
    assert siem["event_type"] == "tenuo.delegation.complete"
    assert siem["parent_warrant_id"] == root.id
    assert siem["child_warrant_id"] == child.id
    assert "deltas" in siem
    assert "summary" in siem
    assert siem["summary"]["ttl_reduced"] is True
    # trust_demoted is False when both trusts are None (unchanged)
    assert siem["summary"]["trust_demoted"] is False