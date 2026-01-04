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

    def status_mark(val: float) -> str:
        return "PASS" if val == 1.0 else "FAIL"

    return f"""# Tenuo Cryptographic Security Report

**Status**: {status}
**Generated**: {time.strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

This report validates Tenuo's cryptographic enforcement properties.
All tests measure detection/enforcement rate of security properties.

**Target**: 100% enforcement for all properties

## Results

### 1. Forgery Resistance

Warrants cannot be tampered with or misused.

| Property | Rate | Status |
|----------|------|--------|
| Wrong Key Detection | {metrics.wrong_key_detection:.1%} | {status_mark(metrics.wrong_key_detection)} |
| Replay Detection | {metrics.replay_detection:.1%} | {status_mark(metrics.replay_detection)} |
| Escalation Detection | {metrics.escalation_detection:.1%} | {status_mark(metrics.escalation_detection)} |

Any party can verify warrant authenticity without calling the issuer's API.

### 2. Delegation Monotonicity

Delegated warrants never exceed their parent's authority.

| Property | Rate | Status |
|----------|------|--------|
| Escalation Prevention | {metrics.delegation_enforcement:.1%} | {status_mark(metrics.delegation_enforcement)} |

Parent constraints are cryptographically embedded. Child warrants
mathematically cannot exceed parent's authority.

### 3. Key Separation

Separation between issuers, holders, and verifiers is enforced.

| Property | Rate | Status |
|----------|------|--------|
| Wrong Key Rejection | {metrics.key_separation:.1%} | {status_mark(metrics.key_separation)} |
| Stolen Warrant Protection | {metrics.stolen_warrant_protection:.1%} | {status_mark(metrics.stolen_warrant_protection)} |

Warrants intercepted in transit are useless without the holder's private key.

### 4. Temporal Enforcement

Time-based access control is enforced.

| Property | Rate | Status |
|----------|------|--------|
| Fresh Warrant Acceptance | {metrics.fresh_acceptance:.1%} | {status_mark(metrics.fresh_acceptance)} |
| Expired Warrant Rejection | {metrics.expired_rejection:.1%} | {status_mark(metrics.expired_rejection)} |

Expiration is cryptographically enforced. Verifier checks signature locally.

### 5. Multi-Signature Enforcement

M-of-N approval requirements are met.

| Property | Rate | Status |
|----------|------|--------|
| Insufficient Approval Rejection | {metrics.insufficient_approval_rejection:.1%} | {status_mark(metrics.insufficient_approval_rejection)} |
| Sufficient Approval Acceptance | {metrics.sufficient_approval_acceptance:.1%} | {status_mark(metrics.sufficient_approval_acceptance)} |
| Forged Approval Rejection | {metrics.forged_approval_rejection:.1%} | {status_mark(metrics.forged_approval_rejection)} |

Approvals are cryptographically signed. Separation of duties without shared
database or consensus protocol.

## When Tenuo Adds Value

| Scenario | Tenuo Value |
|----------|-------------|
| Cross-service calls (same org) | Audit trail, reduced coupling |
| Cross-organization trust | Essential - no shared database |
| Offline/disconnected agents | Required - cannot call issuer |
| Compliance (non-repudiation) | Cryptographic proof of authorization |
| Single service, single trust domain | Input validation may suffice |

## Conclusion

{"All cryptographic security properties enforced at 100%." if all_100 else "Some security properties did not reach 100% enforcement. Investigation required."}
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
