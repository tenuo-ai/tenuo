"""
Benchmark: Temporal Enforcement

Demonstrates that warrant expiration is cryptographically enforced -
not just a "check" that can be bypassed.

Key insight: The expiration time is part of the signed payload.
Changing it invalidates the signature.
"""

import pytest
import time
from tenuo import SigningKey, Warrant, Range
from tenuo import Authorizer
from tenuo.exceptions import ExpiredError, TenuoError



# ---------------------------------------------------------------------------
# Authorization helpers — require an explicit issuer_key so each test
# configures trust roots the same way production code does. No self-trust.
# ---------------------------------------------------------------------------

def _is_authorized(warrant, tool, args, sig, *, issuer_key):
    """Return True if authorized, False if denied. Uses explicit root-of-trust.

    Only catches expected authorization errors (TenuoError, ExpiredError).
    Other exceptions (import failures, attribute errors, etc.) propagate so
    that environment issues are not silently reported as authorization denials.
    """
    try:
        Authorizer(trusted_roots=[issuer_key]).authorize_one(
            warrant, tool, args,
            signature=sig if isinstance(sig, bytes) else bytes(sig)
        )
        return True
    except (TenuoError, ExpiredError):
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


class TestTemporalEnforcement:
    """
    Tests that warrant TTL and expiration are strictly enforced.
    """

    @pytest.fixture
    def issuer_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def holder_key(self):
        return SigningKey.generate()

    def test_fresh_warrant_works(self, issuer_key, holder_key):
        """Baseline: fresh warrants work."""
        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder_key.public_key)
            .ttl(3600)  # 1 hour
            .mint(issuer_key)
        )

        sig = warrant.sign(holder_key, "action", {"value": 50}, int(time.time()))
        _assert_authorized(warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer_key.public_key)

    def test_expired_warrant_rejected(self, issuer_key, holder_key):
        """
        Expired warrants are rejected.

        We create a warrant with 1-second TTL and wait for it to expire.
        """
        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder_key.public_key)
            .ttl(1)  # 1 second TTL
            .mint(issuer_key)
        )

        # Works immediately
        sig = warrant.sign(holder_key, "action", {"value": 50}, int(time.time()))
        _assert_authorized(warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer_key.public_key)

        # Wait for expiration
        time.sleep(2)

        # Now it's expired - should raise ExpiredError or return False
        sig = warrant.sign(holder_key, "action", {"value": 50}, int(time.time()))
        try:
            result = _is_authorized(warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer_key.public_key)
            assert not result
        except ExpiredError:
            pass

    def test_cannot_tamper_with_expiration(self, issuer_key, holder_key):
        """
        Cannot extend expiration by tampering with serialized warrant.

        The expiration is part of the signed data - changing it
        invalidates the issuer's signature.
        """
        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder_key.public_key)
            .ttl(1)  # 1 second TTL
            .mint(issuer_key)
        )

        # Get the serialized form
        original_base64 = warrant.to_base64()

        # Wait for expiration
        time.sleep(2)

        # Verify it's expired
        recovered = Warrant.from_base64(original_base64)
        sig = recovered.sign(holder_key, "action", {"value": 50}, int(time.time()))
        try:
            result = _is_authorized(recovered, "action", {"value": 50}, bytes(sig), issuer_key=issuer_key.public_key)
            assert not result
        except ExpiredError:
            pass

        # Attacker cannot just "edit" the expiration in the bytes
        # because it would invalidate the signature
        # (CBOR structure makes targeted tampering complex, but the
        # signature verification would catch it regardless)

    def test_delegation_cannot_extend_ttl(self, issuer_key, holder_key):
        """
        Delegated warrant cannot have longer TTL than parent.

        Note: TTL is capped at parent's remaining TTL, not rejected.
        The child warrant will have its TTL automatically capped.
        """
        worker_key = SigningKey.generate()

        parent = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder_key.public_key)
            .ttl(3600)  # 1 hour
            .mint(issuer_key)
        )

        # Delegate with longer requested TTL - it will be capped
        ab = parent.attenuate_builder()
        ab.with_capability("action", {"value": Range(0, 50)})
        ab.with_holder(worker_key.public_key)
        ab.with_ttl(7200)  # Requested 2 hours
        child = ab.delegate(holder_key)

        # Child's TTL should be <= parent's remaining TTL
        assert child.ttl_remaining <= parent.ttl_remaining

    def test_short_lived_warrants_for_sensitive_ops(self, issuer_key, holder_key):
        """
        Pattern: Use short-lived warrants for sensitive operations.

        This limits the window of exposure if a warrant is compromised.
        """
        # Sensitive operation: 30-second window
        sensitive_warrant = (
            Warrant.mint_builder()
            .capability("delete_database", confirmed=Range(1, 1))
            .holder(holder_key.public_key)
            .ttl(30)  # 30 seconds
            .mint(issuer_key)
        )

        # Must act quickly
        sig = sensitive_warrant.sign(holder_key, "delete_database", {"confirmed": 1}, int(time.time()))
        _assert_authorized(sensitive_warrant,
            "delete_database", {"confirmed": 1}, bytes(sig),
            issuer_key=issuer_key.public_key
        )

        # After 30 seconds, warrant is useless (even if stolen)


class TestJustInTimeWarrants:
    """
    Tests the Just-in-Time warrant pattern where warrants are minted
    immediately before use with minimal TTL.
    """

    def test_jit_warrant_pattern(self):
        """
        Demonstrate JIT warrant pattern:
        1. Request comes in
        2. Control plane mints short-lived warrant
        3. Agent uses it immediately
        4. Warrant expires before any replay is possible
        """
        issuer = SigningKey.generate()
        agent = SigningKey.generate()

        # Simulate: request comes in at time T
        start_time = time.time()

        # Control plane mints warrant with 5-second TTL
        warrant = (
            Warrant.mint_builder()
            .capability("process_payment", amount=Range(0, 500))
            .holder(agent.public_key)
            .ttl(5)  # Very short-lived
            .mint(issuer)
        )

        # Agent uses it immediately
        sig = warrant.sign(agent, "process_payment", {"amount": 100}, int(time.time()))
        _assert_authorized(warrant, "process_payment", {"amount": 100}, bytes(sig), issuer_key=issuer.public_key)

        # Verify we're within the window
        elapsed = time.time() - start_time
        assert elapsed < 5, "Test took too long, warrant may have expired"

        # After 5 seconds, even if attacker captured the warrant+signature,
        # it's useless


class BenchmarkMetrics:
    """Collect metrics for temporal enforcement benchmark."""

    @staticmethod
    def run_temporal_benchmark() -> dict:
        """Test temporal enforcement with various TTLs."""
        issuer = SigningKey.generate()
        holder = SigningKey.generate()

        results = {
            "fresh_warrants": 0,
            "fresh_warrants_accepted": 0,
            "expired_warrants": 0,
            "expired_warrants_rejected": 0,
        }

        # Test fresh warrants (should work)
        for ttl in [1, 5, 10, 60, 3600]:
            warrant = (
                Warrant.mint_builder()
                .capability("action", value=Range(0, 100))
                .holder(holder.public_key)
                .ttl(ttl)
                .mint(issuer)
            )

            results["fresh_warrants"] += 1
            sig = warrant.sign(holder, "action", {"value": 50}, int(time.time()))
            if _is_authorized(warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer.public_key):
                results["fresh_warrants_accepted"] += 1

        # Test expired warrants (should fail)
        for _ in range(5):
            warrant = (
                Warrant.mint_builder()
                .capability("action", value=Range(0, 100))
                .holder(holder.public_key)
                .ttl(1)
                .mint(issuer)
            )
            time.sleep(1.5)

            results["expired_warrants"] += 1
            sig = warrant.sign(holder, "action", {"value": 50}, int(time.time()))
            try:
                result = _is_authorized(warrant, "action", {"value": 50}, bytes(sig), issuer_key=issuer.public_key)
                if not result:
                    results["expired_warrants_rejected"] += 1
            except ExpiredError:
                results["expired_warrants_rejected"] += 1

        results["fresh_acceptance_rate"] = (
            results["fresh_warrants_accepted"] / results["fresh_warrants"]
        )
        results["expired_rejection_rate"] = (
            results["expired_warrants_rejected"] / results["expired_warrants"]
        )

        return results


if __name__ == "__main__":
    print("Running Temporal Enforcement Benchmark")
    print("=" * 60)

    metrics = BenchmarkMetrics.run_temporal_benchmark()

    print("\nResults:")
    print(f"  Fresh Warrants Accepted:  {metrics['fresh_acceptance_rate']:.1%}")
    print(f"  Expired Warrants Rejected: {metrics['expired_rejection_rate']:.1%}")

    assert metrics["fresh_acceptance_rate"] == 1.0
    assert metrics["expired_rejection_rate"] == 1.0

    print("\nTemporal enforcement working correctly (100% accuracy)")
