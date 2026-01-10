"""
Signature & Trust Verification Attacks

Tests verifying:
- Signatures must be verified against trusted roots
- Self-signed warrants rejected without explicit trust
- Expired warrants rejected
- Session IDs are metadata only, not authorization
"""

import pytest
import time
from dataclasses import dataclass
from typing import Callable, Optional

from tenuo import (
    Warrant,
)
from tenuo.constraints import Constraints
from tenuo.exceptions import ExpiredError, SignatureInvalid


@dataclass
class NodeState:
    """Simulated state object passed between nodes."""

    messages: list
    warrant: Optional[str] = None


class MockNode:
    """A simulated LangGraph node."""

    def __init__(self, name: str, behavior: Callable[[NodeState], NodeState]):
        self.name = name
        self.behavior = behavior

    def run(self, state: NodeState) -> NodeState:
        print(f"[{self.name}] Running...")
        return self.behavior(state)


@pytest.mark.security
@pytest.mark.signature
class TestSignatureTrust:
    """Signature and trust verification attacks."""

    def test_attack_1_state_tampering(self, keypair, attacker_keypair):
        """
        Attack: Swap warrant in state with attacker-signed warrant.

        Defense: Signature verification against TRUSTED root fails.
        """
        print("\n--- Attack 1: State Tampering ---")

        # Setup: Valid initial state with a weak warrant
        weak_warrant = Warrant.mint(
            keypair=keypair, capabilities=Constraints.for_tool("read_public", {}), ttl_seconds=60
        )
        state = NodeState(messages=[], warrant=weak_warrant.to_base64())

        # Attack: Malicious node swaps in a stronger warrant (self-signed by attacker)
        fake_root = Warrant.mint(
            keypair=attacker_keypair, capabilities=Constraints.for_tool("admin_access", {}), ttl_seconds=3600
        )

        def malicious_behavior(s: NodeState):
            print("  [Attacker] Swapping warrant in state...")
            s.warrant = fake_root.to_base64()
            return s

        state = MockNode("malicious", malicious_behavior).run(state)

        # Victim verifies against trusted root
        def victim_behavior(s: NodeState):
            print("  [Victim] Verifying warrant...")
            w = Warrant.from_base64(s.warrant)

            # Secure check: verify against trusted root
            is_valid = w.verify(keypair.public_key.to_bytes())

            if is_valid:
                print("  [Victim] Warrant verified successfully (VULNERABLE!)")
                return "Success"
            else:
                print("  [Victim] Warrant verification failed (SECURE)")
                raise SignatureInvalid("Verification failed")

        # Expectation: Should reject - signed by attacker, not trusted root
        with pytest.raises(SignatureInvalid):
            MockNode("victim", victim_behavior).run(state)

        print("  [Result] Attack 1 blocked (Signature verification enforced)")

    def test_attack_1b_replay_old_warrant(self, keypair):
        """
        Attack: Replay a previously seen stronger warrant after expiry.

        Defense: TTL enforcement blocks expired warrants.
        """
        print("\n--- Attack 1b: Replay Old Warrant ---")

        # Attacker has an expired admin warrant
        old_admin_warrant = Warrant.mint(
            keypair=keypair, capabilities=Constraints.for_tool("admin_access", {}), ttl_seconds=1
        )
        time.sleep(1.1)  # Wait for expiry

        # Current state has a weak warrant
        current_warrant = Warrant.mint(
            keypair=keypair, capabilities=Constraints.for_tool("read_only", {}), ttl_seconds=60
        )
        state = NodeState(messages=[], warrant=current_warrant.to_base64())

        # Attack: Swap in the old admin warrant
        def malicious_behavior(s: NodeState):
            print("  [Attacker] Swapping in old admin warrant...")
            s.warrant = old_admin_warrant.to_base64()
            return s

        state = MockNode("malicious", malicious_behavior).run(state)

        # Victim verifies
        def victim_behavior(s: NodeState):
            w = Warrant.from_base64(s.warrant)
            if not w.verify(keypair.public_key.to_bytes()):
                raise SignatureInvalid("Sig failed")
            # authorize() checks expiry
            w.authorize("admin_access", {})

        # Expectation: Should fail due to expiry
        with pytest.raises(ExpiredError):
            MockNode("victim", victim_behavior).run(state)

        print("  [Result] Attack 1b blocked (Expired warrant rejected)")

    def test_attack_4_verifier_confusion(self, keypair, attacker_keypair):
        """
        Attack: Present valid chain rooted in attacker's key.

        Defense: Verify against TRUSTED root, not self-verification.
        """
        print("\n--- Attack 4: Verifier Confusion ---")

        # Attacker creates a valid-looking chain with their own key
        attacker_root = Warrant.mint(
            keypair=attacker_keypair, capabilities=Constraints.for_tool("admin_access", {}), ttl_seconds=3600
        )

        builder = attacker_root.grant_builder()
        builder.inherit_all()  # POLA: explicit inheritance
        attacker_child = builder.grant(attacker_keypair)

        # Verify against TRUSTED root (should fail)
        print("  [Attack 4A] Verifying against TRUSTED root...")
        is_valid = attacker_child.verify(keypair.public_key.to_bytes())
        assert is_valid is False
        print("  [Result] Attack 4A blocked (Wrong root rejected)")

        # Self-verification (always passes - this is why apps must check roots)
        print("  [Attack 4B] Self-verification (expected to pass)...")
        is_valid_self = attacker_child.verify(attacker_keypair.public_key.to_bytes())
        assert is_valid_self is True
        print("  [Info] Self-verification passed. App MUST enforce root trust.")

    def test_attack_33_self_signed_root_trust(self, keypair, attacker_keypair):
        """
        Attack: Self-signed warrant accepted without checking trusted roots.

        Defense: Authorizer with trusted_roots rejects untrusted signers.
        """
        print("\n--- Attack 33: Self-Signed Root Trust ---")

        attacker_warrant = Warrant.mint(
            keypair=attacker_keypair, capabilities=Constraints.for_tool("admin", {}), ttl_seconds=3600
        )

        print("  [Attack 33A] Self-verification (signature valid)...")
        assert attacker_warrant.verify(attacker_keypair.public_key.to_bytes())
        print("  [Info] Self-verification passed (expected)")

        print("  [Attack 33B] Verifying against Authorizer with trusted roots...")
        from tenuo import Authorizer

        auth = Authorizer(trusted_roots=[keypair.public_key])

        try:
            auth.verify_chain([attacker_warrant])
            print("  [CRITICAL] Attack 33B SUCCEEDED: Untrusted root accepted!")
            assert False, "Should have rejected untrusted root"
        except Exception as e:
            print(f"  [Result] Attack 33B blocked (Root trust enforced: {type(e).__name__})")

    def test_attack_36_session_id_reuse(self, keypair):
        """
        Attack: Reuse session_id from privileged warrant in low-privilege warrant.

        Defense: Session ID is metadata only, not authorization.
        """
        print("\n--- Attack 36: Session ID Reuse ---")

        # Privileged warrant with session
        _admin_warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("admin", {}),
            ttl_seconds=3600,
            session_id="admin_session_123",
        )

        # Low-privilege warrant with SAME session_id
        low_warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("read", {}),
            ttl_seconds=3600,
            session_id="admin_session_123",
        )

        print("  [Info] Created two warrants with same session_id")
        print(f"  [Check] Low warrant tools: {low_warrant.tools}")

        # Try to use low warrant for admin action
        if low_warrant.authorize("admin", {}):
            print("  [CRITICAL] Attack 36 SUCCEEDED: Session ID gave unauthorized access!")
            assert False, "Session ID should not grant authorization"
        else:
            print("  [Result] Attack 36 blocked (Session ID is metadata, not authorization)")
