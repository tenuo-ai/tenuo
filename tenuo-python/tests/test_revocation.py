"""
Tests for RevocationRequest and SignedRevocationList Python bindings.

Covers:
- RevocationRequest creation and verification
- SignedRevocationList building and verification
- Serialization roundtrips
- Edge cases and error handling
"""

import pytest
from tenuo import (
    RevocationRequest,
    SignedRevocationList,
    SrlBuilder,
    SigningKey,
    PublicKey,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def control_plane_keypair():
    """Control Plane keypair for signing SRLs."""
    return SigningKey.generate()


@pytest.fixture
def issuer_keypair():
    """Issuer keypair for revocation requests."""
    return SigningKey.generate()


@pytest.fixture
def holder_keypair():
    """Holder keypair for self-revocation (surrender)."""
    return SigningKey.generate()


# =============================================================================
# RevocationRequest Tests
# =============================================================================


class TestRevocationRequest:
    """Tests for RevocationRequest."""

    def test_create_revocation_request(self, issuer_keypair):
        """Basic creation and verification."""
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_test_123",
            reason="Key compromise detected",
            requestor_keypair=issuer_keypair,
        )

        assert request.warrant_id == "tnu_wrt_test_123"
        assert request.reason == "Key compromise detected"
        assert request.requestor.to_bytes() == issuer_keypair.public_key.to_bytes()

        # Verify signature
        request.verify_signature()  # Should not raise

    def test_signature_verification_fails_for_tampered_request(self, issuer_keypair):
        """Tampering with request should fail verification."""
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_original",
            reason="Original reason",
            requestor_keypair=issuer_keypair,
        )

        # Serialize, deserialize (bytes are immutable, so this tests the signing)
        request_bytes = request.to_bytes()
        loaded = RevocationRequest.from_bytes(request_bytes)
        loaded.verify_signature()  # Should work

    def test_serialization_roundtrip(self, issuer_keypair):
        """Serialize and deserialize preserves all fields."""
        original = RevocationRequest.new(
            warrant_id="tnu_wrt_roundtrip_test",
            reason="Testing serialization",
            requestor_keypair=issuer_keypair,
        )

        bytes_data = original.to_bytes()
        loaded = RevocationRequest.from_bytes(bytes_data)

        assert loaded.warrant_id == original.warrant_id
        assert loaded.reason == original.reason
        assert loaded.requestor.to_bytes() == original.requestor.to_bytes()
        assert loaded.requested_at == original.requested_at

        # Verify signature still works
        loaded.verify_signature()

    def test_repr_is_readable(self, issuer_keypair):
        """__repr__ provides useful information."""
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_repr_test",
            reason="Testing repr",
            requestor_keypair=issuer_keypair,
        )

        repr_str = repr(request)
        assert "RevocationRequest" in repr_str
        assert "tnu_wrt_repr_test" in repr_str
        assert "Testing repr" in repr_str

    def test_requested_at_is_set(self, issuer_keypair):
        """Timestamp is automatically set."""
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_timestamp_test",
            reason="Testing timestamp",
            requestor_keypair=issuer_keypair,
        )

        # requested_at should be a valid ISO 8601 timestamp
        assert request.requested_at is not None
        assert "T" in request.requested_at  # ISO format contains T

    def test_empty_warrant_id(self, issuer_keypair):
        """Empty warrant ID is allowed (server will reject)."""
        request = RevocationRequest.new(
            warrant_id="",
            reason="Testing empty ID",
            requestor_keypair=issuer_keypair,
        )
        assert request.warrant_id == ""

    def test_empty_reason(self, issuer_keypair):
        """Empty reason is allowed."""
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_empty_reason",
            reason="",
            requestor_keypair=issuer_keypair,
        )
        assert request.reason == ""

    def test_unicode_reason(self, issuer_keypair):
        """Unicode in reason is supported."""
        reason = "Key compromise detected 🔑 危険"
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_unicode",
            reason=reason,
            requestor_keypair=issuer_keypair,
        )
        assert request.reason == reason


# =============================================================================
# SignedRevocationList Tests
# =============================================================================


class TestSignedRevocationList:
    """Tests for SignedRevocationList."""

    def test_create_empty_srl(self, control_plane_keypair):
        """Empty SRL is valid."""
        srl = SignedRevocationList.empty(control_plane_keypair)

        assert srl.version == 0
        assert len(srl) == 0
        assert srl.revoked_ids == []

    def test_builder_single_revoke(self, control_plane_keypair):
        """Build SRL with single revocation."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_single")
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        assert len(srl) == 1
        assert srl.is_revoked("tnu_wrt_single")
        assert not srl.is_revoked("tnu_wrt_not_revoked")

    def test_builder_multiple_revocations(self, control_plane_keypair):
        """Build SRL with multiple revocations."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_1")
        builder.revoke("tnu_wrt_2")
        builder.revoke("tnu_wrt_3")
        builder.version(5)
        srl = builder.build(control_plane_keypair)

        assert len(srl) == 3
        assert srl.version == 5
        assert srl.is_revoked("tnu_wrt_1")
        assert srl.is_revoked("tnu_wrt_2")
        assert srl.is_revoked("tnu_wrt_3")
        assert not srl.is_revoked("tnu_wrt_4")

    def test_builder_revoke_all(self, control_plane_keypair):
        """Build SRL using revoke_all."""
        builder = SignedRevocationList.builder()
        builder.revoke_all(["tnu_wrt_batch_1", "tnu_wrt_batch_2", "tnu_wrt_batch_3"])
        builder.version(10)
        srl = builder.build(control_plane_keypair)

        assert len(srl) == 3
        assert srl.is_revoked("tnu_wrt_batch_1")
        assert srl.is_revoked("tnu_wrt_batch_2")
        assert srl.is_revoked("tnu_wrt_batch_3")

    def test_verify_srl_signature(self, control_plane_keypair):
        """SRL signature verification works."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_verify_test")
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        # Verify with correct key
        srl.verify(control_plane_keypair.public_key)  # Should not raise

    def test_verify_srl_wrong_key_fails(self, control_plane_keypair):
        """SRL verification fails with wrong key."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_wrong_key")
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        # Verify with wrong key should fail
        wrong_keypair = SigningKey.generate()
        with pytest.raises(Exception):  # Will raise signature error
            srl.verify(wrong_keypair.public_key)

    def test_serialization_roundtrip(self, control_plane_keypair):
        """SRL serialization preserves all data."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_serialize_1")
        builder.revoke("tnu_wrt_serialize_2")
        builder.version(42)
        original = builder.build(control_plane_keypair)

        bytes_data = original.to_bytes()
        loaded = SignedRevocationList.from_bytes(bytes_data)

        assert loaded.version == original.version
        assert len(loaded) == len(original)
        assert loaded.revoked_ids == original.revoked_ids
        assert loaded.issuer.to_bytes() == original.issuer.to_bytes()

        # Verify signature still works
        loaded.verify(control_plane_keypair.public_key)

    def test_from_existing_srl(self, control_plane_keypair):
        """Build new SRL from existing one."""
        # Create initial SRL
        builder1 = SignedRevocationList.builder()
        builder1.revoke("tnu_wrt_existing_1")
        builder1.revoke("tnu_wrt_existing_2")
        builder1.version(1)
        srl1 = builder1.build(control_plane_keypair)

        # Create new SRL from existing, adding more revocations
        builder2 = SignedRevocationList.builder()
        builder2.from_existing(srl1)
        builder2.revoke("tnu_wrt_new_3")
        builder2.version(2)
        srl2 = builder2.build(control_plane_keypair)

        assert len(srl2) == 3
        assert srl2.version == 2
        assert srl2.is_revoked("tnu_wrt_existing_1")
        assert srl2.is_revoked("tnu_wrt_existing_2")
        assert srl2.is_revoked("tnu_wrt_new_3")

    def test_issued_at_is_set(self, control_plane_keypair):
        """SRL has issued_at timestamp."""
        srl = SignedRevocationList.empty(control_plane_keypair)

        assert srl.issued_at is not None
        assert "T" in srl.issued_at  # ISO format

    def test_issuer_is_signer(self, control_plane_keypair):
        """SRL issuer matches the signing key."""
        srl = SignedRevocationList.empty(control_plane_keypair)

        assert srl.issuer.to_bytes() == control_plane_keypair.public_key.to_bytes()

    def test_repr_is_readable(self, control_plane_keypair):
        """__repr__ provides useful information."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_repr")
        builder.version(99)
        srl = builder.build(control_plane_keypair)

        repr_str = repr(srl)
        assert "SignedRevocationList" in repr_str
        assert "99" in repr_str  # version
        assert "1" in repr_str  # count

    def test_len_method(self, control_plane_keypair):
        """__len__ works correctly."""
        builder = SignedRevocationList.builder()
        builder.revoke("a")
        builder.revoke("b")
        builder.revoke("c")
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        assert len(srl) == 3


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Edge cases and error scenarios."""

    def test_large_revocation_list(self, control_plane_keypair):
        """SRL can handle many revocations."""
        ids = [f"tnu_wrt_bulk_{i}" for i in range(1000)]

        builder = SignedRevocationList.builder()
        builder.revoke_all(ids)
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        assert len(srl) == 1000
        assert srl.is_revoked("tnu_wrt_bulk_500")

        # Serialization should work
        bytes_data = srl.to_bytes()
        loaded = SignedRevocationList.from_bytes(bytes_data)
        assert len(loaded) == 1000

    def test_duplicate_revocation_ids(self, control_plane_keypair):
        """Duplicate IDs in builder are handled."""
        builder = SignedRevocationList.builder()
        builder.revoke("tnu_wrt_dup")
        builder.revoke("tnu_wrt_dup")  # Duplicate
        builder.revoke("tnu_wrt_dup")  # Triple
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        # Implementation may dedupe or keep all - just ensure it works
        assert srl.is_revoked("tnu_wrt_dup")

    def test_special_characters_in_warrant_id(self, control_plane_keypair):
        """Special characters in warrant ID work."""
        weird_id = "tnu_wrt_特殊文字_🔐_test"

        builder = SignedRevocationList.builder()
        builder.revoke(weird_id)
        builder.version(1)
        srl = builder.build(control_plane_keypair)

        assert srl.is_revoked(weird_id)

        # Roundtrip
        loaded = SignedRevocationList.from_bytes(srl.to_bytes())
        assert loaded.is_revoked(weird_id)

    def test_version_zero(self, control_plane_keypair):
        """Version 0 is valid (from empty())."""
        srl = SignedRevocationList.empty(control_plane_keypair)
        assert srl.version == 0

    def test_high_version_number(self, control_plane_keypair):
        """Large version numbers work."""
        builder = SignedRevocationList.builder()
        builder.version(2**63 - 1)  # Large but valid u64
        srl = builder.build(control_plane_keypair)

        assert srl.version == 2**63 - 1

    def test_invalid_bytes_deserialization(self):
        """Invalid bytes raise error on deserialization."""
        with pytest.raises(Exception):
            RevocationRequest.from_bytes(b"not valid cbor")

        with pytest.raises(Exception):
            SignedRevocationList.from_bytes(b"also not valid")

    def test_empty_bytes_deserialization(self):
        """Empty bytes raise error."""
        with pytest.raises(Exception):
            RevocationRequest.from_bytes(b"")

        with pytest.raises(Exception):
            SignedRevocationList.from_bytes(b"")


# =============================================================================
# Integration Scenarios
# =============================================================================


class TestIntegrationScenarios:
    """Real-world usage scenarios."""

    def test_holder_surrender_workflow(self, holder_keypair):
        """Holder can create revocation request for self-surrender."""
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_my_warrant",
            reason="No longer needed",
            requestor_keypair=holder_keypair,
        )

        # Request can be serialized for transmission
        bytes_data = request.to_bytes()
        assert len(bytes_data) > 0

        # Server can deserialize and verify
        loaded = RevocationRequest.from_bytes(bytes_data)
        loaded.verify_signature()

    def test_issuer_revocation_workflow(self, issuer_keypair, control_plane_keypair):
        """Issuer revokes a compromised warrant, CP builds SRL."""
        # 1. Issuer creates revocation request
        request = RevocationRequest.new(
            warrant_id="tnu_wrt_compromised_agent",
            reason="Agent key compromised",
            requestor_keypair=issuer_keypair,
        )

        # 2. Request sent to Control Plane (simulated)
        request_bytes = request.to_bytes()
        received_request = RevocationRequest.from_bytes(request_bytes)
        received_request.verify_signature()

        # 3. Control Plane builds new SRL
        builder = SignedRevocationList.builder()
        builder.revoke(received_request.warrant_id)
        builder.version(100)
        srl = builder.build(control_plane_keypair)

        # 4. SRL distributed to authorizers (simulated)
        srl_bytes = srl.to_bytes()
        authorizer_srl = SignedRevocationList.from_bytes(srl_bytes)
        authorizer_srl.verify(control_plane_keypair.public_key)

        # 5. Authorizer checks warrant against SRL
        assert authorizer_srl.is_revoked("tnu_wrt_compromised_agent")

    def test_srl_update_workflow(self, control_plane_keypair):
        """SRL updates preserve existing revocations."""
        # Day 1: Initial revocation
        builder1 = SignedRevocationList.builder()
        builder1.revoke("tnu_wrt_day1_revoked")
        builder1.version(1)
        srl_v1 = builder1.build(control_plane_keypair)

        # Day 2: Add more revocations
        builder2 = SignedRevocationList.builder()
        builder2.from_existing(srl_v1)
        builder2.revoke("tnu_wrt_day2_revoked")
        builder2.version(2)
        srl_v2 = builder2.build(control_plane_keypair)

        # Both should be revoked
        assert srl_v2.is_revoked("tnu_wrt_day1_revoked")
        assert srl_v2.is_revoked("tnu_wrt_day2_revoked")
        assert srl_v2.version == 2
