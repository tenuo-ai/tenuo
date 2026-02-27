"""
Benchmark: Key Separation

Demonstrates that Tenuo enforces strict separation between:
- Issuer key (can create warrants)
- Holder key (can use warrants with PoP)
- Verifier (can validate without any secrets)

Key insight: Even if a warrant is intercepted, it's useless without
the holder's private key.
"""

import time

import pytest
from tenuo import SigningKey, Warrant, Range, Authorizer



# ---------------------------------------------------------------------------
# Authorization helpers — require an explicit issuer_key so each test
# configures trust roots the same way production code does. No self-trust.
# ---------------------------------------------------------------------------

def _is_authorized(warrant, tool, args, sig, *, issuer_key):
    """Return True if authorized, False if denied. Uses explicit root-of-trust."""
    try:
        Authorizer(trusted_roots=[issuer_key]).authorize_one(
            warrant, tool, args,
            signature=sig if isinstance(sig, bytes) else bytes(sig)
        )
        return True
    except Exception:
        return False

def _assert_authorized(warrant, tool, args, sig, *, issuer_key):
    """Assert that authorization succeeds against an explicit trust root."""
    Authorizer(trusted_roots=[issuer_key]).authorize_one(
        warrant, tool, args,
        signature=sig if isinstance(sig, bytes) else bytes(sig)
    )

def _assert_denied(warrant, tool, args, sig, *, issuer_key):
    """Assert that authorization fails against an explicit trust root."""
    with pytest.raises(Exception):
        Authorizer(trusted_roots=[issuer_key]).authorize_one(
            warrant, tool, args,
            signature=sig if isinstance(sig, bytes) else bytes(sig)
        )


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

    def test_warrant_alone_is_useless(self, warrant, attacker_key, issuer_key):
        """
        Having the warrant bytes doesn't grant access.

        Unlike bearer tokens, a warrant requires PoP.
        """
        # Attacker has the warrant (maybe intercepted it)
        warrant_base64 = warrant.to_base64()
        recovered_warrant = Warrant.from_base64(warrant_base64)

        # But attacker can't use it without holder's key
        sig = recovered_warrant.sign(attacker_key, "secret_action", {"level": 5}, int(time.time()))
        _assert_denied(recovered_warrant,
            "secret_action", {"level": 5}, bytes(sig),
            issuer_key=issuer_key.public_key
        )

    def test_holder_key_alone_is_useless(self, issuer_key, holder_key):
        """
        A holder key without a trusted warrant cannot authorize anything.

        The holder can self-sign a warrant, but an Authorizer that trusts
        only the real issuer will reject it.
        """
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        self_issued = (
            Warrant.mint_builder()
            .capability("secret_action", level=Range(1, 10))
            .holder(holder_key.public_key)
            .ttl(3600)
            .mint(holder_key)  # Self-signed — not the trusted issuer
        )

        sig = self_issued.sign(holder_key, "secret_action", {"level": 5}, int(time.time()))

        with pytest.raises(Exception):
            authorizer.authorize(
                self_issued, "secret_action", {"level": 5}, signature=bytes(sig)
            )

    def test_issuer_cannot_use_warrant_as_holder(self, warrant, issuer_key):
        """Even the issuer can't use a warrant issued to someone else."""
        sig = warrant.sign(issuer_key, "secret_action", {"level": 5}, int(time.time()))
        _assert_denied(warrant, "secret_action", {"level": 5}, bytes(sig), issuer_key=issuer_key.public_key)

    def test_verifier_needs_no_secrets(self, warrant, holder_key, issuer_key):
        """
        Verification requires only public keys.

        The verifier (e.g., tool executor) never sees private keys.
        """
        # Create authorizer with only public keys
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        # Holder creates valid signature
        sig = warrant.sign(holder_key, "secret_action", {"level": 5}, int(time.time()))
        # Authorizer is configured with only public keys — no secrets needed
        Authorizer(trusted_roots=[issuer_key.public_key]).authorize_one(
            warrant, "secret_action", {"level": 5}, signature=bytes(sig)
        )

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
        sig = alice_warrant.sign(bob_key, "action", {"value": 50}, int(time.time()))
        _assert_denied(alice_warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer_key.public_key)

        sig = alice_warrant.sign(alice_key, "action", {"value": 50}, int(time.time()))
        _assert_authorized(alice_warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer_key.public_key)


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
        sig = stolen_warrant.sign(attacker, "transfer", {"amount": 9999}, int(time.time()))
        _assert_denied(stolen_warrant, "transfer", {"amount": 9999}, bytes(sig), issuer_key=issuer.public_key)

        import os
        random_sig = os.urandom(64)
        _assert_denied(stolen_warrant, "transfer", {"amount": 9999}, random_sig, issuer_key=issuer.public_key)

    def test_stolen_key_but_no_warrant(self):
        """
        Scenario: Attacker steals holder's private key but has no
        warrant from a trusted issuer.

        The attacker can self-issue a warrant, but an Authorizer that
        only trusts the real issuer rejects it.
        """
        real_issuer = SigningKey.generate()
        stolen_key = SigningKey.generate()

        authorizer = Authorizer(trusted_roots=[real_issuer.public_key])

        # Attacker self-issues a warrant with the stolen key
        attacker_warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 1000000))
            .holder(stolen_key.public_key)
            .ttl(3600)
            .mint(stolen_key)  # Self-signed — not the trusted issuer
        )

        sig = attacker_warrant.sign(stolen_key, "transfer", {"amount": 500000}, int(time.time()))

        # Self-signed warrant: the Authorizer below trusts ONLY the real issuer,
        # so a SELF-issued warrant (signed by stolen_key, not real_issuer) is rejected.
        # This is the meaningful distinction: even with a valid key, no trusted warrant = no access.
        with pytest.raises(Exception):
            Authorizer(trusted_roots=[real_issuer.public_key]).authorize_one(
                attacker_warrant, "transfer", {"amount": 500000}, signature=bytes(sig)
            )

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

        sig = worker_warrant.sign(worker, "transfer", {"amount": 99}, int(time.time()))
        # Delegated warrant: the issuer of worker_warrant is the orchestrator, not the org.
        # Use the org issuer as the root — Authorizer.check_chain would be ideal for full
        # chain validation, but authorize_one on the leaf warrant still proves enforcement.
        _assert_authorized(worker_warrant, "transfer", {"amount": 99}, bytes(sig),
            issuer_key=orchestrator.public_key
        )

        sig = worker_warrant.sign(worker, "transfer", {"amount": 5000}, int(time.time()))
        _assert_denied(worker_warrant, "transfer", {"amount": 5000}, bytes(sig),
            issuer_key=orchestrator.public_key
        )

        sig = orchestrator_warrant.sign(worker, "transfer", {"amount": 5000}, int(time.time()))
        _assert_denied(orchestrator_warrant, "transfer", {"amount": 5000}, bytes(sig),
            issuer_key=issuer.public_key
        )


class BenchmarkMetrics:
    """Collect metrics for key separation benchmark."""

    @staticmethod
    def run_key_separation_benchmark(num_attempts: int = 1000) -> dict:
        """Test that key separation is always enforced."""
        import random
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
            call_value = random.randint(1, 100)  # vary per iteration

            # Test 1: Wrong key — attacker signs with their own key, not the holder's.
            results["wrong_key_attempts"] += 1
            sig = warrant.sign(attacker, "action", {"value": call_value}, int(time.time()))
            if not _is_authorized(warrant, "action", {"value": call_value}, bytes(sig), issuer_key=issuer.public_key):
                results["wrong_key_blocked"] += 1

            # Test 2: Stolen warrant — simulates attacker intercepting the warrant bytes
            # over the wire (serialise → deserialise), then trying to use it with their
            # own key. Distinct from Test 1 because `stolen` is a separate deserialized
            # object; confirms the check doesn't depend on Python object identity.
            results["stolen_warrant_attempts"] += 1
            stolen = Warrant.from_base64(warrant.to_base64())
            stolen_value = random.randint(1, 100)
            sig = stolen.sign(attacker, "action", {"value": stolen_value}, int(time.time()))
            if not _is_authorized(stolen, "action", {"value": stolen_value}, bytes(sig), issuer_key=issuer.public_key):
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
