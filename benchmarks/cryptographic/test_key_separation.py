"""
Benchmark: Key Separation

Demonstrates that Tenuo enforces strict separation between:
- Issuer key (can create warrants)
- Holder key (can use warrants with PoP)
- Verifier (can validate without any secrets)

Key insight: Even if a warrant is intercepted, it's useless without
the holder's private key.
"""

import pytest
from tenuo import SigningKey, Warrant, Range, Authorizer


class TestKeySeparation:
    """
    Tests that prove the cryptographic separation between principals.

    This is fundamentally different from session tokens or API keys where
    possession of the token = authorization.
    """

    @pytest.fixture
    def issuer_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def holder_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def attacker_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def warrant(self, issuer_key, holder_key):
        return (
            Warrant.mint_builder()
            .capability("secret_action", level=Range(1, 10))
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

    def test_warrant_alone_is_useless(self, warrant, attacker_key):
        """
        Having the warrant bytes doesn't grant access.

        Unlike bearer tokens, a warrant requires PoP.
        """
        # Attacker has the warrant (maybe intercepted it)
        warrant_base64 = warrant.to_base64()
        recovered_warrant = Warrant.from_base64(warrant_base64)

        # But attacker can't use it without holder's key
        sig = recovered_warrant.sign(attacker_key, "secret_action", {"level": 5})
        assert not recovered_warrant.authorize(
            "secret_action", {"level": 5}, bytes(sig)
        )

    def test_holder_key_alone_is_useless(self, holder_key):
        """
        Having the holder's key doesn't grant access without a warrant.

        The key lets you sign, but there's nothing valid to sign for.
        """
        # Holder has their key, but no warrant
        # They can't just create tool calls - they need a warrant from an issuer

        # There's no way to use a key without a warrant
        # (This is more of a conceptual test - the API doesn't allow it)
        pass

    def test_issuer_cannot_use_warrant_as_holder(self, warrant, issuer_key):
        """
        Even the issuer can't use a warrant issued to someone else.

        The warrant is bound to a specific holder.
        """
        # Issuer tries to use warrant they created for someone else
        sig = warrant.sign(issuer_key, "secret_action", {"level": 5})
        assert not warrant.authorize("secret_action", {"level": 5}, bytes(sig))

    def test_verifier_needs_no_secrets(self, warrant, holder_key, issuer_key):
        """
        Verification requires only public keys.

        The verifier (e.g., tool executor) never sees private keys.
        """
        # Create authorizer with only public keys
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        # Holder creates valid signature
        sig = warrant.sign(holder_key, "secret_action", {"level": 5})

        # Verifier can validate without any private keys
        # Authorizer.authorize() returns None on success, raises on failure
        try:
            authorizer.authorize(
                warrant, "secret_action", {"level": 5}, signature=bytes(sig)
            )
            # Success!
        except Exception as e:
            pytest.fail(f"Authorization should have succeeded: {e}")

    def test_different_holder_keys_are_not_interchangeable(self, issuer_key):
        """
        Warrants are bound to specific holders.

        Alice's warrant can't be used with Bob's key, even if both
        are valid holders from the same issuer.
        """
        alice_key = SigningKey.generate()
        bob_key = SigningKey.generate()

        # Issue warrant to Alice
        alice_warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(alice_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        # Bob tries to use Alice's warrant
        sig = alice_warrant.sign(bob_key, "action", {"value": 50})
        assert not alice_warrant.authorize("action", {"value": 50}, bytes(sig))

        # Only Alice can use her warrant
        sig = alice_warrant.sign(alice_key, "action", {"value": 50})
        assert alice_warrant.authorize("action", {"value": 50}, bytes(sig))


class TestStolenCredentialScenarios:
    """
    Tests that model real-world credential theft scenarios.
    """

    def test_stolen_warrant_without_key(self):
        """
        Scenario: Attacker steals warrant from network traffic.

        Result: Warrant is useless without holder's private key.
        """
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        attacker = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 10000))
            .holder(holder.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        # Attacker "steals" the warrant
        stolen_base64 = warrant.to_base64()
        stolen_warrant = Warrant.from_base64(stolen_base64)

        # Attacker tries various attacks:

        # 1. Sign with their own key
        sig = stolen_warrant.sign(attacker, "transfer", {"amount": 9999})
        assert not stolen_warrant.authorize("transfer", {"amount": 9999}, bytes(sig))

        # 2. Try random bytes as signature (must be exactly 64 bytes)
        import os

        random_sig = os.urandom(64)
        assert not stolen_warrant.authorize("transfer", {"amount": 9999}, random_sig)

    def test_stolen_key_but_no_warrant(self):
        """
        Scenario: Attacker steals holder's private key.

        Result: Key alone is useless - they need both key AND warrant.

        Note: This test demonstrates that having a key isn't enough.
        The attacker can create their own warrant, but:
        1. It won't be trusted by systems that verify the issuer
        2. The warrant.authorize() method doesn't check issuer trust
           (that's what Authorizer is for in production)
        """
        # Attacker has a key
        holder = SigningKey.generate()

        # Attacker creates their own warrant (self-issued)
        attacker_warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 1000000))
            .holder(holder.public_key)
            .ttl(3600)
            .mint(holder)  # Self-signed
        )

        # The warrant works for the attacker (they are both issuer and holder)
        sig = attacker_warrant.sign(holder, "transfer", {"amount": 500000})

        # But in a real system, the tool executor would verify the issuer
        # is in a trusted set. The attacker's self-issued warrant would
        # not be in that set.

        # For now, we just verify the mechanics work correctly
        assert attacker_warrant.authorize("transfer", {"amount": 500000}, bytes(sig))

    def test_compromised_worker_cannot_escalate(self):
        """
        Scenario: Worker agent is fully compromised (attacker has its key).

        Result: Attacker is still limited to worker's delegated permissions.
        """
        issuer = SigningKey.generate()
        orchestrator = SigningKey.generate()
        worker = SigningKey.generate()  # Attacker compromises this

        # Orchestrator gets broad permissions
        orchestrator_warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 100000))
            .holder(orchestrator.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        # Worker gets limited delegation
        ab = orchestrator_warrant.attenuate_builder()
        ab.with_capability("transfer", {"amount": Range(0, 100)})  # Only $100
        ab.with_holder(worker.public_key)
        ab.with_ttl(1800)
        worker_warrant = ab.delegate(orchestrator)

        # Attacker has worker's key but can only do what worker was allowed
        sig = worker_warrant.sign(worker, "transfer", {"amount": 99})
        assert worker_warrant.authorize("transfer", {"amount": 99}, bytes(sig))

        # Can't exceed worker's limits even with the key
        sig = worker_warrant.sign(worker, "transfer", {"amount": 5000})
        assert not worker_warrant.authorize("transfer", {"amount": 5000}, bytes(sig))

        # Can't use orchestrator's warrant
        sig = orchestrator_warrant.sign(worker, "transfer", {"amount": 5000})
        assert not orchestrator_warrant.authorize(
            "transfer", {"amount": 5000}, bytes(sig)
        )


class BenchmarkMetrics:
    """Collect metrics for key separation benchmark."""

    @staticmethod
    def run_key_separation_benchmark(num_attempts: int = 1000) -> dict:
        """Test that key separation is always enforced."""
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        attacker = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        results = {
            "wrong_key_attempts": 0,
            "wrong_key_blocked": 0,
            "stolen_warrant_attempts": 0,
            "stolen_warrant_blocked": 0,
        }

        for _ in range(num_attempts):
            # Test: Wrong key signing
            results["wrong_key_attempts"] += 1
            sig = warrant.sign(attacker, "action", {"value": 50})
            if not warrant.authorize("action", {"value": 50}, bytes(sig)):
                results["wrong_key_blocked"] += 1

            # Test: Stolen warrant (simulated by re-serializing)
            results["stolen_warrant_attempts"] += 1
            stolen = Warrant.from_base64(warrant.to_base64())
            sig = stolen.sign(attacker, "action", {"value": 50})
            if not stolen.authorize("action", {"value": 50}, bytes(sig)):
                results["stolen_warrant_blocked"] += 1

        results["wrong_key_block_rate"] = (
            results["wrong_key_blocked"] / results["wrong_key_attempts"]
        )
        results["stolen_warrant_block_rate"] = (
            results["stolen_warrant_blocked"] / results["stolen_warrant_attempts"]
        )

        return results


if __name__ == "__main__":
    print("Running Key Separation Benchmark")
    print("=" * 60)

    metrics = BenchmarkMetrics.run_key_separation_benchmark(1000)

    print(f"\nResults ({metrics['wrong_key_attempts']} attempts each):")
    print(f"  Wrong Key Block Rate:     {metrics['wrong_key_block_rate']:.1%}")
    print(f"  Stolen Warrant Block Rate: {metrics['stolen_warrant_block_rate']:.1%}")

    assert metrics["wrong_key_block_rate"] == 1.0
    assert metrics["stolen_warrant_block_rate"] == 1.0

    print("\nAll unauthorized access blocked (100% key separation)")
