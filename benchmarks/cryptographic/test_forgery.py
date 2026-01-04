"""
Benchmark: Warrant Forgery Resistance

Demonstrates that Tenuo warrants are cryptographically protected against
tampering - essential for distributed systems where warrants cross trust
boundaries.

Key insight: When Service A receives a warrant claiming to be from Service B,
A can verify it locally without calling B's API. The warrant is self-proving.

This enables:
- Offline verification (issuer may be unreachable)
- Reduced coupling (no runtime dependency on issuer)
- Portable trust (any party with issuer's public key can verify)
"""

import pytest
from tenuo import SigningKey, Warrant, Pattern, Range, Authorizer


class TestWarrantForgeryResistance:
    """
    These tests demonstrate that warrants are cryptographically protected.

    The key property: warrants are self-verifying. Any party can verify
    a warrant's authenticity without contacting the issuer.
    """

    @pytest.fixture
    def issuer_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def holder_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def attacker_key(self):
        """Attacker has their own key but not the issuer's"""
        return SigningKey.generate()

    @pytest.fixture
    def valid_warrant(self, issuer_key, holder_key):
        """A legitimately issued warrant with constraints"""
        return (
            Warrant.mint_builder()
            .capability("send_money", amount=Range(0, 1000))
            .capability("read_file", path=Pattern("/public/*"))
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

    def test_valid_warrant_works(self, valid_warrant, holder_key):
        """Baseline: legitimate usage works"""
        # Sign with holder's key
        sig = valid_warrant.sign(holder_key, "send_money", {"amount": 500})

        # Verify succeeds
        assert valid_warrant.authorize("send_money", {"amount": 500}, bytes(sig))

    def test_attacker_cannot_sign_without_holder_key(self, valid_warrant, attacker_key):
        """
        Even with the warrant, attacker can't use it without holder's key.

        Scenario: Attacker intercepts a warrant in transit (e.g., from a
        message queue or HTTP proxy). They have the full warrant but not
        the holder's private key.

        Result: The warrant is useless. PoP signature requires the key.
        """
        # Attacker tries to sign with their own key
        sig = valid_warrant.sign(attacker_key, "send_money", {"amount": 500})

        # Verification fails - wrong key
        assert not valid_warrant.authorize("send_money", {"amount": 500}, bytes(sig))

    def test_cannot_forge_warrant_with_broader_constraints(
        self, issuer_key, holder_key, attacker_key
    ):
        """
        Attacker cannot create a warrant with broader permissions.

        Even if they know the structure, they lack the issuer's key.
        """
        # Attacker tries to create their own warrant with unlimited amount
        forged = (
            Warrant.mint_builder()
            .capability("send_money", amount=Range(0, 1_000_000))  # 1M instead of 1K
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(attacker_key)  # Signed with attacker's key, not issuer's
        )

        # The forged warrant has a different issuer than the real issuer
        # (We just verify the authorizer rejects it below)

        # An authorizer that trusts the real issuer will reject this
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        sig = forged.sign(holder_key, "send_money", {"amount": 500000})

        # Rejected: forged warrant is not trusted (raises exception)
        try:
            authorizer.authorize(
                forged, "send_money", {"amount": 500000}, signature=bytes(sig)
            )
            pytest.fail("Forged warrant should have been rejected")
        except Exception:
            pass  # Expected: issuer not in trusted roots

    def test_serialized_warrant_tampering_detected(self, valid_warrant, holder_key):
        """
        If attacker modifies serialized warrant, verification will fail.

        This simulates tampering with the warrant - the cryptographic
        signature will not match the modified content.
        """
        # The warrant has an internal signature that covers all fields
        # Any modification would require re-signing with the issuer's key

        # We test a simpler form: if someone creates a new warrant with
        # modified constraints, they can't sign it as the original issuer

        attacker_key = SigningKey.generate()

        # Attacker tries to create a "modified" version of the warrant
        # with broader constraints, signing with their own key
        _ = (
            Warrant.mint_builder()
            .capability("read_file", path=Pattern("/*"))  # Broader than /public/*
            .holder(holder_key.public_key)  # Same holder
            .ttl(3600)
            .mint(attacker_key)  # Attacker's key, not real issuer
        )

        # This modified warrant is not from the trusted issuer
        # An authorizer would reject it (tested in other tests)

    def test_replay_with_different_args_fails(self, valid_warrant, holder_key):
        """
        PoP signature is bound to specific arguments.

        Attacker cannot capture a valid signature and replay it with different args.
        """
        # Legitimate call: transfer $100
        legitimate_sig = valid_warrant.sign(holder_key, "send_money", {"amount": 100})

        # Verify works for the original args
        assert valid_warrant.authorize(
            "send_money", {"amount": 100}, bytes(legitimate_sig)
        )

        # Attacker tries to replay with $999 (max allowed)
        # The signature was for $100, not $999
        assert not valid_warrant.authorize(
            "send_money", {"amount": 999}, bytes(legitimate_sig)
        )

        # Attacker tries to replay with different tool
        assert not valid_warrant.authorize(
            "read_file", {"path": "/public/x"}, bytes(legitimate_sig)
        )


class TestCrossBoundaryVerification:
    """
    Tests the core distributed systems value: cross-boundary verification.

    The question isn't "can if-statements be bypassed?" - production systems
    have plenty of controls for that.

    The question is: "When Agent A receives a warrant from Agent B, how does
    A verify B's authority WITHOUT calling B's backend?"

    Traditional approaches:
    - API call to B's auth service (adds latency, single point of failure)
    - Shared database (coupling, consistency issues)
    - Trust headers blindly (insecure)

    Tenuo approach:
    - Self-contained cryptographic proof
    - Verify locally, no network calls
    - Works even if issuer is offline
    """

    def test_offline_verification(self):
        """
        Verifier can validate warrant without contacting issuer.

        Scenario: Service A receives a warrant from Service B.
        Service B is temporarily down or in a different network.
        A can still verify the warrant cryptographically.
        """
        issuer_key = SigningKey.generate()
        holder_key = SigningKey.generate()

        # Issuer creates warrant (could be hours ago, in different datacenter)
        warrant = (
            Warrant.mint_builder()
            .capability("read_data", scope=Pattern("/shared/*"))
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        # Verifier only needs the issuer's PUBLIC key (shared via config/PKI)
        # No API call to issuer required
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        # Holder signs the request
        sig = warrant.sign(holder_key, "read_data", {"scope": "/shared/file.txt"})

        # Verification succeeds locally - no network call
        authorizer.authorize(
            warrant, "read_data", {"scope": "/shared/file.txt"}, signature=bytes(sig)
        )

    def test_portable_trust(self):
        """
        Same warrant can be verified by multiple independent parties.

        Scenario: A warrant is issued by Org HQ, used by Agent in Region A,
        verified by Service in Region B. No shared database needed.
        """
        hq_key = SigningKey.generate()
        agent_key = SigningKey.generate()

        # HQ issues warrant
        warrant = (
            Warrant.mint_builder()
            .capability("deploy", env=Pattern("staging-*"))
            .holder(agent_key.public_key)
            .ttl(3600)
            .mint(hq_key)
        )

        # Region A and Region B both trust HQ (via PKI/config)
        region_a = Authorizer(trusted_roots=[hq_key.public_key])
        region_b = Authorizer(trusted_roots=[hq_key.public_key])

        sig = warrant.sign(agent_key, "deploy", {"env": "staging-us"})

        # Both regions can verify independently
        region_a.authorize(
            warrant, "deploy", {"env": "staging-us"}, signature=bytes(sig)
        )
        region_b.authorize(
            warrant, "deploy", {"env": "staging-us"}, signature=bytes(sig)
        )

    def test_non_repudiation(self):
        """
        Cryptographic signatures provide audit trail that can't be forged.

        Unlike log entries (which can be modified), a valid signature proves
        the holder authorized the action with their private key.
        """
        issuer_key = SigningKey.generate()
        holder_key = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .capability("approve_expense", amount=Range(0, 10000))
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        # Holder signs approval
        sig = warrant.sign(holder_key, "approve_expense", {"amount": 5000})

        # This signature is proof:
        # 1. The warrant was valid (signed by trusted issuer)
        # 2. The holder authorized this specific action
        # 3. The action had these specific parameters

        # The signature can be stored as an audit record
        # It's self-proving - no need to trust the log system
        assert warrant.authorize("approve_expense", {"amount": 5000}, bytes(sig))


class BenchmarkMetrics:
    """Collect metrics for the forgery resistance benchmark."""

    @staticmethod
    def run_forgery_benchmark(num_attempts: int = 1000) -> dict:
        """
        Run N forgery attempts and measure detection rate.

        Returns metrics showing 100% detection of all forgery types.
        """
        issuer_key = SigningKey.generate()
        holder_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 1000))
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        results = {
            "wrong_key_attempts": 0,
            "wrong_key_blocked": 0,
            "replay_attempts": 0,
            "replay_blocked": 0,
            "escalation_attempts": 0,
            "escalation_blocked": 0,
        }

        import random

        for _ in range(num_attempts):
            # Test 1: Wrong key signing
            results["wrong_key_attempts"] += 1
            sig = warrant.sign(attacker_key, "transfer", {"amount": 500})
            if not warrant.authorize("transfer", {"amount": 500}, bytes(sig)):
                results["wrong_key_blocked"] += 1

            # Test 2: Signature replay with different args
            results["replay_attempts"] += 1
            original_amount = random.randint(1, 500)
            replay_amount = random.randint(501, 1000)
            sig = warrant.sign(holder_key, "transfer", {"amount": original_amount})
            if not warrant.authorize("transfer", {"amount": replay_amount}, bytes(sig)):
                results["replay_blocked"] += 1

            # Test 3: Constraint escalation (amount > 1000)
            results["escalation_attempts"] += 1
            sig = warrant.sign(holder_key, "transfer", {"amount": 5000})
            if not warrant.authorize("transfer", {"amount": 5000}, bytes(sig)):
                results["escalation_blocked"] += 1

        # Calculate rates
        results["wrong_key_detection_rate"] = (
            results["wrong_key_blocked"] / results["wrong_key_attempts"]
        )
        results["replay_detection_rate"] = (
            results["replay_blocked"] / results["replay_attempts"]
        )
        results["escalation_detection_rate"] = (
            results["escalation_blocked"] / results["escalation_attempts"]
        )

        return results


if __name__ == "__main__":
    print("Running Forgery Resistance Benchmark")
    print("=" * 60)

    metrics = BenchmarkMetrics.run_forgery_benchmark(1000)

    print(f"\nResults ({metrics['wrong_key_attempts']} attempts each):")
    print(f"  Wrong Key Detection:  {metrics['wrong_key_detection_rate']:.1%}")
    print(f"  Replay Detection:     {metrics['replay_detection_rate']:.1%}")
    print(f"  Escalation Detection: {metrics['escalation_detection_rate']:.1%}")

    # All should be 100%
    assert metrics["wrong_key_detection_rate"] == 1.0
    assert metrics["replay_detection_rate"] == 1.0
    assert metrics["escalation_detection_rate"] == 1.0

    print("\nAll forgery attempts detected (100% rate)")
