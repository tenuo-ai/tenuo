#!/usr/bin/env python3
"""
Generate a comprehensive security report for Tenuo's cryptographic properties.

This report demonstrates that Tenuo provides security guarantees that
simple input validation cannot match.

Usage:
    python -m benchmarks.cryptographic.report
"""

import time
from dataclasses import dataclass


@dataclass
class SecurityMetrics:
    """Aggregated security metrics from all benchmarks."""

    # Forgery resistance
    wrong_key_detection: float
    replay_detection: float
    escalation_detection: float

    # Delegation monotonicity
    delegation_enforcement: float

    # Key separation
    key_separation: float
    stolen_warrant_protection: float

    # Temporal
    fresh_acceptance: float
    expired_rejection: float

    # Multi-sig
    insufficient_approval_rejection: float
    sufficient_approval_acceptance: float
    forged_approval_rejection: float


def run_all_benchmarks() -> SecurityMetrics:
    """Run all cryptographic benchmarks and collect metrics."""
    from .test_forgery import BenchmarkMetrics as ForgeryMetrics
    from .test_delegation import BenchmarkMetrics as DelegationMetrics
    from .test_key_separation import BenchmarkMetrics as KeyMetrics
    from .test_temporal import BenchmarkMetrics as TemporalMetrics
    from .test_multisig import BenchmarkMetrics as MultisigMetrics

    print("Running cryptographic security benchmarks...")
    print()

    # Forgery resistance
    print("  [1/5] Forgery resistance...")
    forgery = ForgeryMetrics.run_forgery_benchmark(100)

    # Delegation
    print("  [2/5] Delegation monotonicity...")
    delegation = DelegationMetrics.run_delegation_benchmark(50)

    # Key separation
    print("  [3/5] Key separation...")
    keys = KeyMetrics.run_key_separation_benchmark(100)

    # Temporal
    print("  [4/5] Temporal enforcement...")
    temporal = TemporalMetrics.run_temporal_benchmark()

    # Multi-sig
    print("  [5/5] Multi-signature enforcement...")
    multisig = MultisigMetrics.run_multisig_benchmark(50)

    print()

    return SecurityMetrics(
        wrong_key_detection=forgery["wrong_key_detection_rate"],
        replay_detection=forgery["replay_detection_rate"],
        escalation_detection=forgery["escalation_detection_rate"],
        delegation_enforcement=delegation["escalation_block_rate"],
        key_separation=keys["wrong_key_block_rate"],
        stolen_warrant_protection=keys["stolen_warrant_block_rate"],
        fresh_acceptance=temporal["fresh_acceptance_rate"],
        expired_rejection=temporal["expired_rejection_rate"],
        insufficient_approval_rejection=multisig["insufficient_block_rate"],
        sufficient_approval_acceptance=multisig["sufficient_accept_rate"],
        forged_approval_rejection=multisig["forged_block_rate"],
    )


def generate_report(metrics: SecurityMetrics) -> str:
    """Generate markdown report from metrics."""
    all_100 = all(
        [
            metrics.wrong_key_detection == 1.0,
            metrics.replay_detection == 1.0,
            metrics.escalation_detection == 1.0,
            metrics.delegation_enforcement == 1.0,
            metrics.key_separation == 1.0,
            metrics.stolen_warrant_protection == 1.0,
            metrics.fresh_acceptance == 1.0,
            metrics.expired_rejection == 1.0,
            metrics.insufficient_approval_rejection == 1.0,
            metrics.sufficient_approval_acceptance == 1.0,
            metrics.forged_approval_rejection == 1.0,
        ]
    )

    status = "PASS" if all_100 else "FAIL"
    status_emoji = "✅" if all_100 else "❌"

    return f"""# Tenuo Cryptographic Security Report

**Status**: {status_emoji} {status}
**Generated**: {time.strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

This report validates that Tenuo's cryptographic enforcement provides security
guarantees that simple input validation cannot match. All tests measure the
detection/enforcement rate of security properties.

**Target**: 100% enforcement for all properties

## Results

### 1. Forgery Resistance

These properties ensure that warrants cannot be tampered with or misused.

| Property | Rate | Status |
|----------|------|--------|
| Wrong Key Detection | {metrics.wrong_key_detection:.1%} | {"✅" if metrics.wrong_key_detection == 1.0 else "❌"} |
| Replay Detection | {metrics.replay_detection:.1%} | {"✅" if metrics.replay_detection == 1.0 else "❌"} |
| Escalation Detection | {metrics.escalation_detection:.1%} | {"✅" if metrics.escalation_detection == 1.0 else "❌"} |

**Why if-statements can't do this**: Signature verification is mathematically
bound to the original data. Tampering is always detected.

### 2. Delegation Monotonicity

These properties ensure delegated warrants never exceed their parent's authority.

| Property | Rate | Status |
|----------|------|--------|
| Escalation Prevention | {metrics.delegation_enforcement:.1%} | {"✅" if metrics.delegation_enforcement == 1.0 else "❌"} |

**Why if-statements can't do this**: Parent constraints are cryptographically
embedded in the child's signature chain. Escalation is mathematically impossible.

### 3. Key Separation

These properties ensure the separation between issuers, holders, and verifiers.

| Property | Rate | Status |
|----------|------|--------|
| Wrong Key Rejection | {metrics.key_separation:.1%} | {"✅" if metrics.key_separation == 1.0 else "❌"} |
| Stolen Warrant Protection | {metrics.stolen_warrant_protection:.1%} | {"✅" if metrics.stolen_warrant_protection == 1.0 else "❌"} |

**Why if-statements can't do this**: Warrants are useless without the holder's
private key. Intercepted warrants cannot be used.

### 4. Temporal Enforcement

These properties ensure time-based access control.

| Property | Rate | Status |
|----------|------|--------|
| Fresh Warrant Acceptance | {metrics.fresh_acceptance:.1%} | {"✅" if metrics.fresh_acceptance == 1.0 else "❌"} |
| Expired Warrant Rejection | {metrics.expired_rejection:.1%} | {"✅" if metrics.expired_rejection == 1.0 else "❌"} |

**Why if-statements can't do this**: Expiration time is part of the signed
payload. Tampering with it invalidates the signature.

### 5. Multi-Signature Enforcement

These properties ensure M-of-N approval requirements are met.

| Property | Rate | Status |
|----------|------|--------|
| Insufficient Approval Rejection | {metrics.insufficient_approval_rejection:.1%} | {"✅" if metrics.insufficient_approval_rejection == 1.0 else "❌"} |
| Sufficient Approval Acceptance | {metrics.sufficient_approval_acceptance:.1%} | {"✅" if metrics.sufficient_approval_acceptance == 1.0 else "❌"} |
| Forged Approval Rejection | {metrics.forged_approval_rejection:.1%} | {"✅" if metrics.forged_approval_rejection == 1.0 else "❌"} |

**Why if-statements can't do this**: Each approval is cryptographically signed.
Forging an approval requires the approver's private key.

## Comparison: If-Statements vs Tenuo

| Property | If-Statements | Tenuo |
|----------|---------------|-------|
| Tamper-proof constraints | ❌ Code can be modified | ✅ Cryptographic |
| Verifiable without secrets | ❌ Often needs DB/service | ✅ Self-contained |
| Delegation safety | ❌ Manual enforcement | ✅ Mathematically bound |
| Key compromise impact | ❌ Full access | ✅ Limited by warrant |
| Replay protection | ❌ Needs state | ✅ Signature-bound |
| Approval verification | ❌ Trust the sender | ✅ Cryptographic proof |

## Conclusion

{"All cryptographic security properties are enforced at 100%. Tenuo provides strong security guarantees that input validation alone cannot achieve." if all_100 else "Some security properties did not reach 100% enforcement. Investigation required."}
"""


def main():
    """Run benchmarks and generate report."""
    print("=" * 70)
    print("TENUO CRYPTOGRAPHIC SECURITY BENCHMARK")
    print("=" * 70)
    print()

    metrics = run_all_benchmarks()
    report = generate_report(metrics)

    # Print to console
    print(report)

    # Save to file
    with open("security_report.md", "w") as f:
        f.write(report)
    print("\nReport saved to: security_report.md")


if __name__ == "__main__":
    main()
