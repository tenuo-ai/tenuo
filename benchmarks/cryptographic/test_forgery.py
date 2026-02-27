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

import time

import pytest
from tenuo import SigningKey, Warrant, Pattern, Range, Authorizer



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

    def test_valid_warrant_works(self, valid_warrant, holder_key, issuer_key):
        """Baseline: legitimate usage works"""
        sig = valid_warrant.sign(holder_key, "send_money", {"amount": 500}, int(time.time()))
        _assert_authorized(valid_warrant, "send_money", {"amount": 500}, bytes(sig), issuer_key=issuer_key.public_key)

    def test_attacker_cannot_sign_without_holder_key(self, valid_warrant, attacker_key, issuer_key):
        """
        Even with the warrant, attacker can't use it without holder's key.

        Scenario: Attacker intercepts a warrant in transit (e.g., from a
        message queue or HTTP proxy). They have the full warrant but not
        the holder's private key.

        Result: The warrant is useless. PoP signature requires the key.
        """
        sig = valid_warrant.sign(attacker_key, "send_money", {"amount": 500}, int(time.time()))
        _assert_denied(valid_warrant, "send_money", {"amount": 500}, bytes(sig), issuer_key=issuer_key.public_key)

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

        sig = forged.sign(holder_key, "send_money", {"amount": 500000}, int(time.time()))

        # Rejected: forged warrant is not trusted (raises exception)
        try:
            authorizer.authorize(
                forged, "send_money", {"amount": 500000}, signature=bytes(sig)
            )
            pytest.fail("Forged warrant should have been rejected")
        except Exception:
            pass  # Expected: issuer not in trusted roots

    def test_serialized_warrant_tampering_detected(self, valid_warrant, holder_key, issuer_key):
        """
        Flipping a byte in the serialized warrant invalidates it.

        Serialize, corrupt a byte in the middle, then show that
        deserialization or verification fails.
        """
        wire = valid_warrant.to_base64()

        mid = len(wire) // 2
        flip_char = 'A' if wire[mid] != 'A' else 'B'
        tampered = wire[:mid] + flip_char + wire[mid + 1:]

        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        try:
            recovered = Warrant.from_base64(tampered)
            sig = recovered.sign(holder_key, "read_file", {"path": "/public/x"}, int(time.time()))
            authorizer.authorize(
                recovered, "read_file", {"path": "/public/x"}, signature=bytes(sig)
            )
            pytest.fail("Tampered warrant should not pass verification")
        except Exception:
            pass  # Deserialization or signature failure — both acceptable

    def test_replay_with_different_args_fails(self, valid_warrant, holder_key, issuer_key):
        """
        PoP signature is bound to specific arguments.

        Attacker cannot capture a valid signature and replay it with different args.
        """
        legitimate_sig = valid_warrant.sign(holder_key, "send_money", {"amount": 100}, int(time.time()))

        _assert_authorized(valid_warrant,
            "send_money", {"amount": 100}, bytes(legitimate_sig),
            issuer_key=issuer_key.public_key
        )
        _assert_denied(valid_warrant,
            "send_money", {"amount": 999}, bytes(legitimate_sig),
            issuer_key=issuer_key.public_key
        )
        _assert_denied(valid_warrant,
            "read_file", {"path": "/public/x"}, bytes(legitimate_sig),
            issuer_key=issuer_key.public_key
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
        sig = warrant.sign(holder_key, "read_data", {"scope": "/shared/file.txt"}, int(time.time()))

        # Verification succeeds locally - no network call
        authorizer.authorize_one(
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

        sig = warrant.sign(agent_key, "deploy", {"env": "staging-us"}, int(time.time()))

        # Both regions can verify independently
        region_a.authorize_one(
            warrant, "deploy", {"env": "staging-us"}, signature=bytes(sig)
        )
        region_b.authorize_one(
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
        sig = warrant.sign(holder_key, "approve_expense", {"amount": 5000}, int(time.time()))

        # This signature is proof:
        # 1. The warrant was valid (signed by trusted issuer)
        # 2. The holder authorized this specific action
        # 3. The action had these specific parameters

        # The signature can be stored as an audit record
        # It's self-proving - no need to trust the log system
        _assert_authorized(warrant, "approve_expense", {"amount": 5000}, bytes(sig),
            issuer_key=issuer_key.public_key
        )


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
            call_amount = random.randint(1, 1000)  # vary per iteration

            # Test 1: Wrong key — vary amount so PoP covers different args each time
            results["wrong_key_attempts"] += 1
            sig = warrant.sign(attacker_key, "transfer", {"amount": call_amount}, int(time.time()))
            if not _is_authorized(warrant, "transfer", {"amount": call_amount}, bytes(sig), issuer_key=issuer_key.public_key):
                results["wrong_key_blocked"] += 1

            # Test 2: Signature replay with different args (always different amounts)
            results["replay_attempts"] += 1
            original_amount = random.randint(1, 500)
            replay_amount = random.randint(501, 1000)
            sig = warrant.sign(holder_key, "transfer", {"amount": original_amount}, int(time.time()))
            if not _is_authorized(warrant, "transfer", {"amount": replay_amount}, bytes(sig), issuer_key=issuer_key.public_key):
                results["replay_blocked"] += 1

            # Test 3: Constraint escalation — vary amount above limit so boundary is probed
            escalation_amount = random.randint(1001, 10000)
            results["escalation_attempts"] += 1
            sig = warrant.sign(holder_key, "transfer", {"amount": escalation_amount}, int(time.time()))
            if not _is_authorized(warrant, "transfer", {"amount": escalation_amount}, bytes(sig), issuer_key=issuer_key.public_key):
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
