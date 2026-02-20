"""
Approval Policy Demo - Human-in-the-loop authorization with cryptographic proofs.

Warrants define *what* an agent can do.
Approval policies define *when* a human must confirm before execution proceeds.

    warrant: "You can transfer up to $100K"
    policy:  "Amounts over $10K need human approval"

Every approval is cryptographically signed - there is no unsigned "approved=True"
path. The request hash binds the approval to the exact (warrant, tool, args, holder)
tuple, preventing replay and tampering.

This demo shows:
1. Single-approver policy with conditional rules
2. M-of-N multi-sig (2-of-3 approvers)
3. Policy-level TTL configuration for async workflows
4. Built-in handlers: auto_approve, auto_deny, cli_prompt
5. Caller-provided approvals (spec §6 path)
6. Error diagnostics for rejected approvals

Usage:
    python examples/approval_policy_demo.py
    python examples/approval_policy_demo.py --interactive   # uses cli_prompt
"""

from __future__ import annotations

import argparse

from tenuo import Range, SigningKey, Warrant
from tenuo.approval import (
    ApprovalDenied,
    ApprovalPolicy,
    ApprovalRequired,
    ApprovalVerificationError,
    auto_approve,
    auto_deny,
    cli_prompt,
    require_approval,
    sign_approval,
)
from tenuo.autogen import GuardBuilder
from tenuo import compute_request_hash


def demo_single_approver(agent_key, warrant, interactive=False):
    """Basic single-approver policy with conditional rules."""
    print("\n" + "=" * 60)
    print("  PART 1: Single Approver")
    print("=" * 60)

    approver_key = SigningKey.generate()

    policy = ApprovalPolicy(
        require_approval(
            "transfer_funds",
            when=lambda a: a.get("amount", 0) > 10_000,
            description="Transfers over $10K require human approval",
        ),
        require_approval("delete_user", description="All user deletions require approval"),
        trusted_approvers=[approver_key.public_key],
    )

    if interactive:
        handler = cli_prompt(approver_key=approver_key)
    else:
        handler = auto_approve(approver_key=approver_key)

    guard = (
        GuardBuilder()
        .allow("search")
        .allow("transfer_funds")
        .allow("delete_user")
        .with_warrant(warrant, agent_key)
        .approval_policy(policy)
        .on_approval(handler)
        .build()
    )

    # No approval needed
    print("\n--- search (no rule) ---")
    guard._authorize("search", {})
    print("  -> Authorized")

    # Below conditional threshold
    print("\n--- transfer $5K (below threshold) ---")
    guard._authorize("transfer_funds", {"amount": 5_000})
    print("  -> Authorized (no approval needed)")

    # Above threshold - approval triggered
    print("\n--- transfer $50K (above threshold) ---")
    guard._authorize("transfer_funds", {"amount": 50_000})
    print("  -> Authorized (approval granted)")

    # Unconditional rule
    print("\n--- delete_user (always requires approval) ---")
    guard._authorize("delete_user", {})
    print("  -> Authorized (approval granted)")

    # auto_deny for dry-run
    print("\n--- dry-run with auto_deny ---")
    deny_guard = (
        GuardBuilder()
        .allow("delete_user")
        .with_warrant(warrant, agent_key)
        .approval_policy(policy)
        .on_approval(auto_deny(reason="dry-run: would require human approval"))
        .build()
    )
    try:
        deny_guard._authorize("delete_user", {})
    except ApprovalDenied as e:
        print(f"  -> Denied: {e.reason}")

    # No handler configured
    print("\n--- no handler configured ---")
    no_handler_guard = (
        GuardBuilder()
        .allow("delete_user")
        .with_warrant(warrant, agent_key)
        .approval_policy(policy)
        .build()
    )
    try:
        no_handler_guard._authorize("delete_user", {})
    except ApprovalRequired:
        print("  -> ApprovalRequired raised (expected)")


def demo_multisig(agent_key, warrant):
    """2-of-3 multi-sig approval with policy-level TTL."""
    print("\n" + "=" * 60)
    print("  PART 2: M-of-N Multi-sig (2-of-3)")
    print("=" * 60)

    alice = SigningKey.generate()
    bob = SigningKey.generate()
    carol = SigningKey.generate()

    # 2-of-3 policy with 1-hour approval window
    policy = ApprovalPolicy(
        require_approval("deploy_prod", description="Production deploys need 2-of-3 leads"),
        trusted_approvers=[alice.public_key, bob.public_key, carol.public_key],
        threshold=2,
        default_ttl=3600,  # 1 hour -- for async approval workflows
    )

    bound = warrant.bind(agent_key)
    warrant_id = bound.id or ""

    # Pre-compute request hash (same hash the enforcement layer computes)
    rh = compute_request_hash(warrant_id, "deploy_prod", {}, agent_key.public_key)

    from tenuo.approval import ApprovalRequest
    request = ApprovalRequest(
        tool="deploy_prod", arguments={}, warrant_id=warrant_id,
        request_hash=rh, suggested_ttl=policy.default_ttl,
    )

    # Alice and Bob approve (2-of-3)
    alice_approval = sign_approval(request, alice, external_id="alice@company.com")
    bob_approval = sign_approval(request, bob, external_id="bob@company.com")

    print(f"\n  Policy TTL: {policy.default_ttl}s (flows to sign_approval automatically)")
    print(f"  Alice signed: expires_at = approved_at + {policy.default_ttl}s")
    print(f"  Bob signed:   expires_at = approved_at + {policy.default_ttl}s")

    # Pass pre-signed approvals via GuardBuilder (spec §6 path)
    print("\n--- deploy_prod with 2-of-3 caller-provided approvals ---")
    guard_2of3 = (
        GuardBuilder()
        .allow("deploy_prod")
        .with_warrant(warrant, agent_key)
        .approval_policy(policy)
        .with_approvals([alice_approval, bob_approval])
        .build()
    )
    guard_2of3._authorize("deploy_prod", {})
    print("  -> Authorized (2-of-3 threshold met)")

    # Try with only 1 approval (insufficient)
    print("\n--- deploy_prod with only 1-of-3 (insufficient) ---")
    try:
        guard_1of3 = (
            GuardBuilder()
            .allow("deploy_prod")
            .with_warrant(warrant, agent_key)
            .approval_policy(policy)
            .with_approvals([alice_approval])
            .build()
        )
        guard_1of3._authorize("deploy_prod", {})
    except ApprovalVerificationError as e:
        print(f"  -> Rejected: {e.reason}")

    # Try with an outsider's approval (untrusted)
    outsider = SigningKey.generate()
    outsider_approval = sign_approval(request, outsider, external_id="rogue@attacker.com")
    print("\n--- deploy_prod with outsider approval (untrusted) ---")
    try:
        guard_outsider = (
            GuardBuilder()
            .allow("deploy_prod")
            .with_warrant(warrant, agent_key)
            .approval_policy(policy)
            .with_approvals([alice_approval, outsider_approval])
            .build()
        )
        guard_outsider._authorize("deploy_prod", {})
    except ApprovalVerificationError as e:
        print(f"  -> Rejected: {e.reason}")


def main():
    parser = argparse.ArgumentParser(description="Approval Policy Demo")
    parser.add_argument(
        "--interactive", action="store_true", help="Use cli_prompt (asks in terminal)"
    )
    args = parser.parse_args()

    issuer_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("search")
        .capability("transfer_funds", amount=Range(0, 100_000))
        .capability("delete_user")
        .capability("deploy_prod")
        .ttl(3600)
        .mint(issuer_key)
    )

    demo_single_approver(agent_key, warrant, interactive=args.interactive)
    demo_multisig(agent_key, warrant)

    print("\nDone.\n")


if __name__ == "__main__":
    main()
