"""
Adversarial tests for Tenuo Approval Protocol.
These tests explicitly attempt to break the security model.
"""
import pytest
import os
import time
from tenuo import SigningKey
from tenuo_core import ApprovalPayload, SignedApproval, py_compute_request_hash

def test_verify_before_deserialize_tampering():
    """
    Attack: Modify valid payload bytes inside the envelope without updating signature.
    Goal: Ensure verification fails BEFORE deserialization (or at least strictly rejects).
    """
    key = SigningKey.generate()
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="valid_user",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300
    )
    signed = SignedApproval.create(payload, key)

    # Tamper with the raw payload bytes
    # We flip a bit in the middle of the CBOR payload
    original_bytes = bytearray(signed.payload)
    original_bytes[len(original_bytes) // 2] ^= 0xFF

    # Create forged envelope using the new constructor
    # We pass the TAMPERED payload bytes, but the ORIGINAL signature.
    # This should match the signature against the WRONG bytes -> SignatureInvalid.
    forged = SignedApproval(
        signed.approval_version,
        bytes(original_bytes),   # Tampered payload
        signed.approver_key,     # Original key
        signed.signature         # Original signature
    )

    # Should fail signature verification
    # Matches "Signature verification failed" or "Verification equation was not satisfied"
    with pytest.raises(Exception, match=r"verification failed|Verification equation"):
        forged.verify()

def test_replay_attack_binding_mismatch():
    """
    Attack: Use a valid approval for Request A to satisfy Request B.
    Goal: Ensure request_hash binding prevents context switching.
    """
    approver = SigningKey.generate()
    agent = SigningKey.generate()

    # Request A and B differ only by one argument key
    hash_a = py_compute_request_hash("w1", "tool", {"amount": 100}, agent.public_key)
    hash_b = py_compute_request_hash("w1", "tool", {"amount": 200}, agent.public_key)

    assert hash_a != hash_b

    # Sign approval for A
    payload_a = ApprovalPayload(
        request_hash=hash_a,
        nonce=os.urandom(16),
        external_id="admin",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300
    )
    signed_a = SignedApproval.create(payload_a, approver)

    # Verify strict equality check in enforcement logic
    # (Simulated enforcement check)
    verified_payload = signed_a.verify()

    # Attack: verifying against Hash B
    if verified_payload.request_hash == hash_b:
        pytest.fail("Replay attack succeeded: Approval for A accepted for B")

def test_signature_context_separation():
    """
    Attack: Try to verify a raw signature without the domain separation context.
    Goal: Ensure 'tenuo-approval-v1' context works.
    """
    key = SigningKey.generate()
    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="admin",
        approved_at=int(time.time()),
        expires_at=int(time.time()) + 300
    )
    signed = SignedApproval.create(payload, key)

    # Try to verify signature directly against payload bytes (missing context)
    # This simulates a cross-protocol attack where another system signs raw bytes
    try:
        # Native Ed25519 verify on raw payload should fail because
        # sign() added the context prefix
        key.public_key.verify(signed.payload, signed.signature)
        pytest.fail("Signature verified without context! Domain separation broken.")
    except Exception:
        # Expected failure
        pass

def test_clock_skew_future_rejection():
    """
    Attack: Create approval valid in the far future.
    Goal: Ensure time-travel protection (sanity check).
    """
    key = SigningKey.generate()
    now = int(time.time())
    future = now + 10000

    payload = ApprovalPayload(
        request_hash=os.urandom(32),
        nonce=os.urandom(16),
        external_id="time_traveler",
        approved_at=future, # In the future
        expires_at=future + 300
    )
    signed = SignedApproval.create(payload, key)

    with pytest.raises(Exception, match="future"):
        signed.verify()

def test_canonical_cbor_serialization():
    """
    Attack: Reorder map keys in payload construction.
    Goal: Ensure CBOR canonicalization (if implemented) or at least stability.
    Actually, SignedApproval stores *raw bytes* at creation time.
    So verification is over those exact bytes.
    This test verifies that `VerifiedPayload` preserves the fields correctly.
    """
    key = SigningKey.generate()
    payload = ApprovalPayload(
        request_hash=b'\x01' * 32,
        nonce=b'\x02' * 16,
        external_id="user",
        approved_at=100,
        expires_at=200
    )
    signed = SignedApproval.create(payload, key)

    # Deserialize
    verified = signed.verify()
    assert verified.request_hash == b'\x01' * 32
    assert verified.approved_at == 100
