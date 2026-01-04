"""
Benchmark: Multi-Signature Requirements

Demonstrates that M-of-N approval requirements are cryptographically enforced.
Each approval is independently signed and verified.

Key insight: You can't fake approvals - each requires the approver's private key.
"""

import pytest
from tenuo import (
    SigningKey,
    Warrant,
    Range,
    Authorizer,
    Approval,
)


class TestMultiSigEnforcement:
    """
    Tests that multi-signature requirements are strictly enforced.

    NOTE: These tests are currently skipped because the MintBuilder
    doesn't properly pass required_approvers/min_approvals to Warrant.issue().
    This is a known builder bug tracked separately.
    """

    @pytest.fixture
    def issuer_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def holder_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def approvers(self):
        """Three potential approvers"""
        return [SigningKey.generate() for _ in range(3)]

    def test_single_approval_when_required(self, issuer_key, holder_key, approvers):
        """
        When 1 approval is required, 1 valid approval suffices.
        """
        warrant = (
            Warrant.mint_builder()
            .capability("sensitive_action", level=Range(1, 10))
            .holder(holder_key.public_key)
            .required_approvers([a.public_key for a in approvers])
            .min_approvals(1)
            .ttl(3600)
            .mint(issuer_key)
        )

        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        # Create PoP signature
        sig = warrant.sign(holder_key, "sensitive_action", {"level": 5})

        # Create one approval (correct API: warrant, tool, args, keypair, ...)
        approval = Approval.create(
            warrant=warrant,
            tool="sensitive_action",
            args={"level": 5},
            keypair=approvers[0],
            external_id="user:alice@example.com",
            provider="auth0",
            ttl_secs=300,
        )

        # Should succeed with 1 approval
        # Authorizer.authorize() returns None on success, raises on failure
        try:
            authorizer.authorize(
                warrant,
                "sensitive_action",
                {"level": 5},
                signature=bytes(sig),
                approvals=[approval],
            )
            # Success!
        except Exception as e:
            pytest.fail(f"Should have succeeded with 1 approval: {e}")

    def test_two_of_three_requirement(self, issuer_key, holder_key, approvers):
        """
        When 2-of-3 approvals are required:
        - 1 approval fails
        - 2 approvals succeed
        """
        warrant = (
            Warrant.mint_builder()
            .capability("critical_action", amount=Range(0, 1000000))
            .holder(holder_key.public_key)
            .required_approvers([a.public_key for a in approvers])
            .min_approvals(2)  # 2-of-3
            .ttl(3600)
            .mint(issuer_key)
        )

        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        sig = warrant.sign(holder_key, "critical_action", {"amount": 500000})

        # Only 1 approval - should fail
        approval1 = Approval.create(
            warrant=warrant,
            tool="critical_action",
            args={"amount": 500000},
            keypair=approvers[0],
            external_id="user:alice@example.com",
            provider="auth0",
            ttl_secs=300,
        )

        # Only 1 approval - should fail
        try:
            authorizer.authorize(
                warrant,
                "critical_action",
                {"amount": 500000},
                signature=bytes(sig),
                approvals=[approval1],
            )
            pytest.fail("Should fail with only 1 of required 2 approvals")
        except Exception:
            pass  # Expected

        # 2 approvals - should succeed
        approval2 = Approval.create(
            warrant=warrant,
            tool="critical_action",
            args={"amount": 500000},
            keypair=approvers[1],
            external_id="user:bob@example.com",
            provider="auth0",
            ttl_secs=300,
        )

        try:
            authorizer.authorize(
                warrant,
                "critical_action",
                {"amount": 500000},
                signature=bytes(sig),
                approvals=[approval1, approval2],
            )
            # Success!
        except Exception as e:
            pytest.fail(f"Should succeed with 2 of required 2 approvals: {e}")

    def test_cannot_forge_approval(self, issuer_key, holder_key, approvers):
        """
        Cannot create valid approval without approver's private key.
        """
        attacker = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder_key.public_key)
            .required_approvers([approvers[0].public_key])
            .min_approvals(1)
            .ttl(3600)
            .mint(issuer_key)
        )

        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        sig = warrant.sign(holder_key, "action", {"value": 50})

        # Attacker tries to forge approval
        forged_approval = Approval.create(
            warrant=warrant,
            tool="action",
            args={"value": 50},
            keypair=attacker,  # Wrong key!
            external_id="user:fake@example.com",
            provider="fake_provider",
            ttl_secs=300,
        )

        # Should fail - forged approval not from valid approver
        try:
            authorizer.authorize(
                warrant,
                "action",
                {"value": 50},
                signature=bytes(sig),
                approvals=[forged_approval],
            )
            pytest.fail("Forged approval should have been rejected")
        except Exception:
            pass  # Expected

    def test_approval_bound_to_specific_action(self, issuer_key, holder_key, approvers):
        """
        Approval for one action cannot be used for another.

        The approval hash includes the tool and args.
        """
        warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 10000))
            .holder(holder_key.public_key)
            .required_approvers([approvers[0].public_key])
            .min_approvals(1)
            .ttl(3600)
            .mint(issuer_key)
        )

        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        # Approval for $100 transfer
        approval_for_100 = Approval.create(
            warrant=warrant,
            tool="transfer",
            args={"amount": 100},
            keypair=approvers[0],
            external_id="user:approver@example.com",
            provider="auth0",
            ttl_secs=300,
        )

        # Try to use approval for $100 to authorize $9999
        sig = warrant.sign(holder_key, "transfer", {"amount": 9999})

        try:
            authorizer.authorize(
                warrant,
                "transfer",
                {"amount": 9999},  # Different amount!
                signature=bytes(sig),
                approvals=[approval_for_100],  # Approval was for $100
            )
            pytest.fail("Approval for $100 should not work for $9999")
        except Exception:
            pass  # Expected

    def test_expired_approval_rejected(self, issuer_key, holder_key, approvers):
        """
        Expired approvals are rejected.
        """
        import time

        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder_key.public_key)
            .required_approvers([approvers[0].public_key])
            .min_approvals(1)
            .ttl(3600)
            .mint(issuer_key)
        )

        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        sig = warrant.sign(holder_key, "action", {"value": 50})

        # Create approval with 1-second TTL
        short_lived_approval = Approval.create(
            warrant=warrant,
            tool="action",
            args={"value": 50},
            keypair=approvers[0],
            external_id="user:approver@example.com",
            provider="auth0",
            ttl_secs=1,  # Very short!
        )

        # Works immediately
        try:
            authorizer.authorize(
                warrant,
                "action",
                {"value": 50},
                signature=bytes(sig),
                approvals=[short_lived_approval],
            )
            # Success!
        except Exception as e:
            pytest.fail(f"Fresh approval should work: {e}")

        # Wait for expiration
        time.sleep(2)

        # Now fails
        try:
            authorizer.authorize(
                warrant,
                "action",
                {"value": 50},
                signature=bytes(sig),
                approvals=[short_lived_approval],
            )
            pytest.fail("Expired approval should be rejected")
        except Exception:
            pass  # Expected


class TestMultiSigPatterns:
    """
    Real-world patterns for multi-sig usage.
    """

    def test_dual_control_pattern(self):
        """
        Dual Control: Two different humans must approve.

        Common for: Large financial transfers, production deployments
        """
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        human1 = SigningKey.generate()  # CFO
        human2 = SigningKey.generate()  # CEO

        warrant = (
            Warrant.mint_builder()
            .capability("transfer", amount=Range(0, 1000000))
            .holder(agent.public_key)
            .required_approvers([human1.public_key, human2.public_key])
            .min_approvals(2)  # Both must approve
            .ttl(300)  # 5-minute window
            .mint(issuer)
        )

        authorizer = Authorizer(trusted_roots=[issuer.public_key])

        # Both approve
        sig = warrant.sign(agent, "transfer", {"amount": 500000})

        cfo_approval = Approval.create(
            warrant=warrant,
            tool="transfer",
            args={"amount": 500000},
            keypair=human1,
            external_id="user:cfo@company.com",
            provider="okta",
            ttl_secs=300,
            reason="Budget approved in Q4 planning",
        )

        ceo_approval = Approval.create(
            warrant=warrant,
            tool="transfer",
            args={"amount": 500000},
            keypair=human2,
            external_id="user:ceo@company.com",
            provider="okta",
            ttl_secs=300,
            reason="Strategic investment approved",
        )

        try:
            authorizer.authorize(
                warrant,
                "transfer",
                {"amount": 500000},
                signature=bytes(sig),
                approvals=[cfo_approval, ceo_approval],
            )
            # Success!
        except Exception as e:
            pytest.fail(f"Dual control should have succeeded: {e}")

    def test_break_glass_pattern(self):
        """
        Break Glass: High threshold normally, lower in emergencies.

        Normal: 3-of-5 approval
        Emergency: 1-of-5 (but creates audit trail)
        """
        issuer = SigningKey.generate()
        agent = SigningKey.generate()
        admins = [SigningKey.generate() for _ in range(5)]

        # Normal operation: 3-of-5 (shown for contrast)
        # normal_warrant would require 3 approvals - not tested here
        # We focus on the emergency pattern below

        # Emergency "break glass" warrant: 1-of-5 but short-lived
        emergency_warrant = (
            Warrant.mint_builder()
            .capability("modify_production", action=Range(0, 10))
            .holder(agent.public_key)
            .required_approvers([a.public_key for a in admins])
            .min_approvals(1)  # Lower threshold
            .ttl(300)  # Only 5 minutes
            .mint(issuer)
        )

        authorizer = Authorizer(trusted_roots=[issuer.public_key])

        # Emergency: 1 approval works
        sig = emergency_warrant.sign(agent, "modify_production", {"action": 5})

        emergency_approval = Approval.create(
            warrant=emergency_warrant,
            tool="modify_production",
            args={"action": 5},
            keypair=admins[0],
            external_id="user:oncall@company.com",
            provider="pagerduty",
            ttl_secs=300,
            reason="INCIDENT-1234: Production down, emergency fix",
        )

        try:
            authorizer.authorize(
                emergency_warrant,
                "modify_production",
                {"action": 5},
                signature=bytes(sig),
                approvals=[emergency_approval],
            )
            # Success!
        except Exception as e:
            pytest.fail(f"Break glass should have succeeded: {e}")


class BenchmarkMetrics:
    """Collect metrics for multi-sig enforcement benchmark."""

    @staticmethod
    def run_multisig_benchmark(num_attempts: int = 100) -> dict:
        """Test that multi-sig thresholds are enforced."""
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approvers = [SigningKey.generate() for _ in range(3)]

        # 2-of-3 requirement
        warrant = (
            Warrant.mint_builder()
            .capability("action", value=Range(0, 100))
            .holder(holder.public_key)
            .required_approvers([a.public_key for a in approvers])
            .min_approvals(2)
            .ttl(3600)
            .mint(issuer)
        )

        authorizer = Authorizer(trusted_roots=[issuer.public_key])

        results = {
            "insufficient_approval_attempts": 0,
            "insufficient_approval_blocked": 0,
            "sufficient_approval_attempts": 0,
            "sufficient_approval_accepted": 0,
            "forged_approval_attempts": 0,
            "forged_approval_blocked": 0,
        }

        for i in range(num_attempts):
            sig = warrant.sign(holder, "action", {"value": i % 100})

            # Test: Only 1 approval (should fail)
            results["insufficient_approval_attempts"] += 1
            approval1 = Approval.create(
                warrant=warrant,
                tool="action",
                args={"value": i % 100},
                keypair=approvers[0],
                external_id=f"user:approver0-{i}@example.com",
                provider="test",
                ttl_secs=300,
            )
            try:
                authorizer.authorize(
                    warrant,
                    "action",
                    {"value": i % 100},
                    signature=bytes(sig),
                    approvals=[approval1],
                )
                # If we get here, authorization succeeded (unexpected)
            except Exception:
                # Expected: authorization should fail with insufficient approvals
                results["insufficient_approval_blocked"] += 1

            # Test: 2 approvals (should succeed)
            results["sufficient_approval_attempts"] += 1
            approval2 = Approval.create(
                warrant=warrant,
                tool="action",
                args={"value": i % 100},
                keypair=approvers[1],
                external_id=f"user:approver1-{i}@example.com",
                provider="test",
                ttl_secs=300,
            )
            try:
                authorizer.authorize(
                    warrant,
                    "action",
                    {"value": i % 100},
                    signature=bytes(sig),
                    approvals=[approval1, approval2],
                )
                # Success - authorization passed
                results["sufficient_approval_accepted"] += 1
            except Exception:
                # Authorization failed unexpectedly
                pass

            # Test: Forged approval (should fail)
            results["forged_approval_attempts"] += 1
            attacker = SigningKey.generate()
            forged = Approval.create(
                warrant=warrant,
                tool="action",
                args={"value": i % 100},
                keypair=attacker,
                external_id="user:fake@example.com",
                provider="fake",
                ttl_secs=300,
            )
            try:
                authorizer.authorize(
                    warrant,
                    "action",
                    {"value": i % 100},
                    signature=bytes(sig),
                    approvals=[approval1, forged],  # 1 valid + 1 forged
                )
                # If we get here, forged approval was accepted (bad!)
            except Exception:
                # Expected: forged approval should be rejected
                results["forged_approval_blocked"] += 1

        results["insufficient_block_rate"] = (
            results["insufficient_approval_blocked"]
            / results["insufficient_approval_attempts"]
        )
        results["sufficient_accept_rate"] = (
            results["sufficient_approval_accepted"]
            / results["sufficient_approval_attempts"]
        )
        results["forged_block_rate"] = (
            results["forged_approval_blocked"] / results["forged_approval_attempts"]
        )

        return results


if __name__ == "__main__":
    print("Running Multi-Sig Enforcement Benchmark")
    print("=" * 60)

    metrics = BenchmarkMetrics.run_multisig_benchmark(100)

    print(f"\nResults ({metrics['insufficient_approval_attempts']} attempts each):")
    print(f"  Insufficient Approvals Blocked: {metrics['insufficient_block_rate']:.1%}")
    print(f"  Sufficient Approvals Accepted:  {metrics['sufficient_accept_rate']:.1%}")
    print(f"  Forged Approvals Blocked:       {metrics['forged_block_rate']:.1%}")

    assert metrics["insufficient_block_rate"] == 1.0
    assert metrics["sufficient_accept_rate"] == 1.0
    assert metrics["forged_block_rate"] == 1.0

    print("\n✅ Multi-sig enforcement working correctly (100% accuracy)")
