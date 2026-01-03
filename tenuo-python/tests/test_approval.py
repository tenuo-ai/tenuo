"""
Tests for the Approval class (multi-sig support).

The Approval class enables multi-signature authorization workflows where
multiple parties must cryptographically approve an action before it proceeds.
"""

import pytest
import time
from tenuo import (
    SigningKey,
    Warrant,
    Approval,
    Authorizer,
    Exact,
    Pattern,
    compute_approval_hash,
)


class TestApprovalCreation:
    """Test Approval.create() functionality."""

    @pytest.fixture
    def keys(self):
        """Generate test keys."""
        return {
            "issuer": SigningKey.generate(),
            "agent": SigningKey.generate(),
            "approver": SigningKey.generate(),
        }

    @pytest.fixture
    def warrant(self, keys):
        """Create a test warrant."""
        return (
            Warrant.mint_builder()
            .holder(keys["agent"].public_key)
            .ttl(300)
            .capability("delete_database", database=Exact("production"))
            .capability("read_file", path=Pattern("/data/*"))
            .mint(keys["issuer"])
        )

    def test_create_approval(self, warrant, keys):
        """Test basic approval creation."""
        approval = Approval.create(
            warrant=warrant,
            tool="delete_database",
            args={"database": "production"},
            keypair=keys["approver"],
            external_id="admin@company.com",
            provider="okta",
            ttl_secs=300,
        )

        assert approval is not None
        assert approval.external_id == "admin@company.com"
        assert approval.provider == "okta"
        assert approval.approver_key is not None

    def test_create_approval_with_reason(self, warrant, keys):
        """Test approval creation with reason."""
        approval = Approval.create(
            warrant=warrant,
            tool="delete_database",
            args={"database": "production"},
            keypair=keys["approver"],
            external_id="admin@company.com",
            provider="okta",
            ttl_secs=300,
            reason="Emergency maintenance window",
        )

        assert approval.reason == "Emergency maintenance window"

    def test_approval_timestamps(self, warrant, keys):
        """Test that approval has valid timestamps."""
        approval = Approval.create(
            warrant=warrant,
            tool="delete_database",
            args={"database": "production"},
            keypair=keys["approver"],
            external_id="admin@company.com",
            provider="okta",
            ttl_secs=300,
        )

        # Should have ISO format timestamps
        assert "T" in approval.approved_at
        assert "T" in approval.expires_at
        assert not approval.is_expired()


class TestApprovalVerification:
    """Test approval signature verification."""

    @pytest.fixture
    def keys(self):
        return {
            "issuer": SigningKey.generate(),
            "agent": SigningKey.generate(),
            "approver": SigningKey.generate(),
        }

    @pytest.fixture
    def warrant(self, keys):
        return (
            Warrant.mint_builder()
            .holder(keys["agent"].public_key)
            .ttl(300)
            .capability("search", query=Pattern("*"))
            .mint(keys["issuer"])
        )

    def test_verify_valid_approval(self, warrant, keys):
        """Test that a valid approval verifies successfully."""
        approval = Approval.create(
            warrant=warrant,
            tool="search",
            args={"query": "test"},
            keypair=keys["approver"],
            external_id="user@example.com",
            provider="internal",
            ttl_secs=300,
        )

        # Should not raise
        approval.verify()

    def test_approval_request_hash(self, warrant, keys):
        """Test that request hash is consistent."""
        approval = Approval.create(
            warrant=warrant,
            tool="search",
            args={"query": "test"},
            keypair=keys["approver"],
            external_id="user@example.com",
            provider="internal",
            ttl_secs=300,
        )

        # Request hash should be 32 bytes
        assert len(approval.request_hash) == 32
        assert len(approval.request_hash_hex) == 64

        # Same inputs should produce same hash
        computed_hash = compute_approval_hash(
            warrant=warrant,
            tool="search",
            args={"query": "test"},
        )
        assert approval.request_hash == computed_hash


class TestApprovalSerialization:
    """Test approval serialization/deserialization."""

    @pytest.fixture
    def approval(self):
        """Create a test approval."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        approver = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        return Approval.create(
            warrant=warrant,
            tool="action",
            args={"param": "value"},
            keypair=approver,
            external_id="test@example.com",
            provider="test-provider",
            ttl_secs=300,
            reason="Test approval",
        )

    def test_bytes_roundtrip(self, approval):
        """Test CBOR serialization roundtrip."""
        # Serialize
        data = approval.to_bytes()
        assert isinstance(data, bytes)
        assert len(data) > 0

        # Deserialize
        restored = Approval.from_bytes(data)

        # Verify fields match
        assert restored.external_id == approval.external_id
        assert restored.provider == approval.provider
        assert restored.reason == approval.reason
        assert restored.request_hash == approval.request_hash
        assert restored.request_hash_hex == approval.request_hash_hex

    def test_json_roundtrip(self, approval):
        """Test JSON serialization roundtrip."""
        # Serialize
        json_str = approval.to_json()
        assert isinstance(json_str, str)
        assert "request_hash" in json_str
        assert "external_id" in json_str

        # Deserialize
        restored = Approval.from_json(json_str)

        # Verify fields match
        assert restored.external_id == approval.external_id
        assert restored.provider == approval.provider
        assert restored.request_hash_hex == approval.request_hash_hex

    def test_json_pretty(self, approval):
        """Test pretty JSON output."""
        pretty = approval.to_json_pretty()
        assert "\n" in pretty  # Should have newlines
        assert "  " in pretty  # Should have indentation

    def test_invalid_bytes_raises(self):
        """Test that invalid bytes raise an error."""
        with pytest.raises(ValueError, match="Deserialization failed"):
            Approval.from_bytes(b"invalid data")

    def test_invalid_json_raises(self):
        """Test that invalid JSON raises an error."""
        with pytest.raises(ValueError, match="JSON deserialization failed"):
            Approval.from_json("not valid json")


class TestApprovalWithAuthorizer:
    """Test using approvals with Authorizer."""

    @pytest.fixture
    def keys(self):
        return {
            "issuer": SigningKey.generate(),
            "agent": SigningKey.generate(),
            "approver1": SigningKey.generate(),
            "approver2": SigningKey.generate(),
        }

    @pytest.fixture
    def warrant(self, keys):
        return (
            Warrant.mint_builder()
            .holder(keys["agent"].public_key)
            .ttl(300)
            .capability("sensitive_action", level=Exact("high"))
            .mint(keys["issuer"])
        )

    def test_authorize_with_approvals(self, warrant, keys):
        """Test that authorization works with approvals."""
        # Create approvals from two approvers
        approval1 = Approval.create(
            warrant=warrant,
            tool="sensitive_action",
            args={"level": "high"},
            keypair=keys["approver1"],
            external_id="admin1@company.com",
            provider="okta",
            ttl_secs=300,
        )

        approval2 = Approval.create(
            warrant=warrant,
            tool="sensitive_action",
            args={"level": "high"},
            keypair=keys["approver2"],
            external_id="admin2@company.com",
            provider="okta",
            ttl_secs=300,
        )

        # Create authorizer
        authorizer = Authorizer(trusted_roots=[keys["issuer"].public_key])

        # Create PoP signature
        pop_sig = warrant.sign(
            keys["agent"], "sensitive_action", {"level": "high"}
        )

        # Authorize with approvals
        authorizer.authorize(
            warrant,
            "sensitive_action",
            {"level": "high"},
            signature=bytes(pop_sig),
            approvals=[approval1, approval2],
        )

    def test_authorize_without_approvals_still_works(self, warrant, keys):
        """Test that authorization works without approvals (for non-multisig warrants)."""
        authorizer = Authorizer(trusted_roots=[keys["issuer"].public_key])

        pop_sig = warrant.sign(
            keys["agent"], "sensitive_action", {"level": "high"}
        )

        # Should work without approvals for non-multisig warrants
        authorizer.authorize(
            warrant,
            "sensitive_action",
            {"level": "high"},
            signature=bytes(pop_sig),
        )


class TestApprovalExpiry:
    """Test approval expiration behavior."""

    def test_short_ttl_expires(self):
        """Test that approvals with short TTL expire."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        approver = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        # Create approval with 1 second TTL
        approval = Approval.create(
            warrant=warrant,
            tool="action",
            args={"param": "value"},
            keypair=approver,
            external_id="test@example.com",
            provider="test",
            ttl_secs=1,
        )

        assert not approval.is_expired()

        # Wait for expiry
        time.sleep(1.5)

        assert approval.is_expired()

    def test_long_ttl_does_not_expire_immediately(self):
        """Test that approvals with long TTL don't expire immediately."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        approver = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        approval = Approval.create(
            warrant=warrant,
            tool="action",
            args={"param": "value"},
            keypair=approver,
            external_id="test@example.com",
            provider="test",
            ttl_secs=3600,  # 1 hour
        )

        assert not approval.is_expired()


class TestComputeApprovalHash:
    """Test the compute_approval_hash helper function."""

    def test_same_inputs_same_hash(self):
        """Test that same inputs produce same hash."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        hash1 = compute_approval_hash(warrant, "action", {"param": "value"})
        hash2 = compute_approval_hash(warrant, "action", {"param": "value"})

        assert hash1 == hash2

    def test_different_tools_different_hash(self):
        """Test that different tools produce different hashes."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action1", param=Exact("value"))
            .capability("action2", param=Exact("value"))
            .mint(issuer)
        )

        hash1 = compute_approval_hash(warrant, "action1", {"param": "value"})
        hash2 = compute_approval_hash(warrant, "action2", {"param": "value"})

        assert hash1 != hash2

    def test_different_args_different_hash(self):
        """Test that different args produce different hashes."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Pattern("*"))
            .mint(issuer)
        )

        hash1 = compute_approval_hash(warrant, "action", {"param": "value1"})
        hash2 = compute_approval_hash(warrant, "action", {"param": "value2"})

        assert hash1 != hash2


class TestApprovalNonce:
    """Test approval nonce for replay protection."""

    def test_nonce_is_present(self):
        """Test that approvals have a nonce field."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        approver = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        approval = Approval.create(
            warrant=warrant,
            tool="action",
            args={"param": "value"},
            keypair=approver,
            external_id="test@example.com",
            provider="test-provider",
            ttl_secs=300,
        )

        # Nonce should be 16 bytes (128 bits)
        assert len(approval.nonce) == 16
        assert isinstance(approval.nonce, (bytes, list))

    def test_nonce_is_unique(self):
        """Test that each approval has a unique nonce (replay protection)."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        approver = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        # Create multiple approvals for the SAME request
        approvals = [
            Approval.create(
                warrant=warrant,
                tool="action",
                args={"param": "value"},
                keypair=approver,
                external_id="test@example.com",
                provider="test-provider",
                ttl_secs=300,
            )
            for _ in range(5)
        ]

        # All nonces should be different
        nonces = [bytes(a.nonce) for a in approvals]
        assert len(set(nonces)) == 5, "Each approval should have a unique nonce"


class TestApprovalRepr:
    """Test approval string representation."""

    def test_repr_format(self):
        """Test that repr has expected format."""
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        approver = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .holder(agent.public_key)
            .ttl(300)
            .capability("action", param=Exact("value"))
            .mint(issuer)
        )

        approval = Approval.create(
            warrant=warrant,
            tool="action",
            args={"param": "value"},
            keypair=approver,
            external_id="test@example.com",
            provider="test-provider",
            ttl_secs=300,
        )

        repr_str = repr(approval)
        assert "Approval(" in repr_str
        assert "approver=" in repr_str
        assert "provider=test-provider" in repr_str
        assert "external_id=test@example.com" in repr_str

