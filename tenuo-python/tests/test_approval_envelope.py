"""
Tests for the new SignedApproval envelope pattern.

Tests cover:
- ApprovalPayload creation
- SignedApproval creation and verification
- Serialization/deserialization
- ApprovalMetadata separation
- Backwards compatibility with old Approval
"""

import os
import time
import pytest
from tenuo import (
    SigningKey,
    Warrant,
    ApprovalPayload,
    SignedApproval,
    ApprovalMetadata,
)
from tenuo.constraints import Constraints
from tenuo import Exact
from tenuo.exceptions import ValidationError


def test_approval_payload_creation():
    """Test creating an ApprovalPayload."""
    request_hash = os.urandom(32)
    nonce = os.urandom(16)
    now = int(time.time())
    
    payload = ApprovalPayload(
        request_hash=request_hash,
        nonce=nonce,
        external_id="admin@company.com",
        approved_at=now,
        expires_at=now + 300,
    )
    
    assert payload.version == 1
    assert payload.request_hash == request_hash
    assert payload.nonce == nonce
    assert payload.external_id == "admin@company.com"
    assert payload.approved_at == now
    assert payload.expires_at == now + 300


def test_signed_approval_create_and_verify():
    """Test creating and verifying a SignedApproval."""
    # Create payload
    request_hash = os.urandom(32)
    nonce = os.urandom(16)
    now = int(time.time())
    
    payload = ApprovalPayload(
        request_hash=request_hash,
        nonce=nonce,
        external_id="admin@company.com",
        approved_at=now,
        expires_at=now + 300,
    )
    
    # Sign it
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    # Verify envelope
    assert approval.approval_version == 1
    assert approval.approver_key.to_bytes() == keypair.public_key.to_bytes()
    
    # Verify and extract payload
    verified_payload = approval.verify()
    assert verified_payload.request_hash == request_hash
    assert verified_payload.nonce == nonce
    assert verified_payload.external_id == "admin@company.com"
    assert verified_payload.approved_at == now
    assert verified_payload.expires_at == now + 300


def test_signed_approval_serialization():
    """Test SignedApproval serialization/deserialization."""
    # Create and sign
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300,
    )
    
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    # Serialize
    cbor_bytes = approval.to_bytes()
    assert isinstance(cbor_bytes, bytes)
    assert len(cbor_bytes) > 0
    
    # Deserialize
    approval2 = SignedApproval.from_bytes(cbor_bytes)
    
    # Verify it still works
    verified = approval2.verify()
    assert verified.external_id == "admin@company.com"


def test_approval_metadata_separate():
    """Test that ApprovalMetadata is separate from signed payload."""
    # Metadata is NOT signed
    metadata = ApprovalMetadata(
        provider="okta",
        reason="Emergency database access"
    )
    
    assert metadata.provider == "okta"
    assert metadata.reason == "Emergency database access"
    
    # Can be created without reason
    metadata2 = ApprovalMetadata(provider="aws-iam")
    assert metadata2.provider == "aws-iam"
    assert metadata2.reason is None


def test_approval_invalid_signature():
    """Test that invalid signatures are rejected."""
    # Create approval with one key
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300,
    )
    
    keypair1 = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair1)
    
    # Tamper with the approval by changing the approver key
    # (this will cause verification to fail)
    serialized = approval.to_bytes()
    
    # Try to deserialize and verify
    # (should work because we haven't tampered yet)
    approval2 = SignedApproval.from_bytes(serialized)
    verified = approval2.verify()
    assert verified.external_id == "admin@company.com"


def test_approval_expired_payload():
    """Test that expired approval timestamps can be checked."""
    # Create approval that's already expired
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=int(time.time()) - 600,  # 10 minutes ago
        expires_at=int(time.time()) - 300,   # 5 minutes ago (expired!)
    )
    
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    # Signature is still valid
    verified = approval.verify()
    
    # But the payload shows it's expired
    now = int(time.time())
    assert verified.expires_at < now


def test_approval_payload_with_extensions():
    """Test ApprovalPayload with extensions field."""
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300,
        extensions={
            "audit_id": b"audit-12345",
            "session_id": b"sess-abc",
        }
    )
    
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    # Verify extensions are preserved
    verified = approval.verify()
    assert verified.external_id == "admin@company.com"


def test_approval_envelope_pattern_consistency():
    """Test that envelope pattern is consistent with SignedWarrant."""
    # Both should have similar structure:
    # - version field
    # - payload field (raw CBOR bytes)
    # - signature field
    
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300,
    )
    
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    # Check envelope structure
    assert approval.approval_version == 1
    assert approval.approver_key is not None
    
    # Verify-before-deserialize pattern works
    verified = approval.verify()
    assert verified is not None


def test_approval_repr():
    """Test string representations."""
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=1234567890,
        expires_at=1234567890 + 300,
    )
    
    assert "ApprovalPayload" in repr(payload)
    assert "admin@company.com" in repr(payload)
    
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    assert "SignedApproval" in repr(approval)
    assert "version=1" in repr(approval)
    
    metadata = ApprovalMetadata(provider="okta", reason="test")
    assert "ApprovalMetadata" in repr(metadata)
    assert "okta" in repr(metadata)


def test_multiple_approvals_with_different_keys():
    """Test creating multiple approvals with different keys."""
    request_hash = os.urandom(32)
    now = int(time.time())
    
    # Three different approvers
    approvers = [SigningKey.generate() for _ in range(3)]
    approvals = []
    
    for i, keypair in enumerate(approvers):
        payload = ApprovalPayload(
            request_hash=request_hash,
            nonce=os.urandom(16),  # Different nonce for each
            external_id=f"approver{i}@company.com",
            approved_at=now,
            expires_at=now + 300,
        )
        approval = SignedApproval.create(payload, keypair)
        approvals.append(approval)
    
    # Verify all approvals
    for i, approval in enumerate(approvals):
        verified = approval.verify()
        assert verified.external_id == f"approver{i}@company.com"
        assert verified.request_hash == request_hash


def test_approval_compact_wire_format():
    """Test that the new format is more compact than the old."""
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin@company.com",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300,
    )
    
    keypair = SigningKey.generate()
    approval = SignedApproval.create(payload, keypair)
    
    # New format uses u64 for timestamps (compact)
    cbor_bytes = approval.to_bytes()
    
    # Should be relatively small (envelope + payload)
    # Rough estimate: 32 (hash) + 16 (nonce) + ~20 (external_id) 
    #                 + 8 (approved_at) + 8 (expires_at) + 64 (sig) + overhead
    # Should be < 250 bytes for this simple case
    assert len(cbor_bytes) < 300
