#!/usr/bin/env python3
"""
Tenuo Human-in-the-loop Example

This example demonstrates a "Human-in-the-loop" workflow where an AI Agent
is authorized to perform actions, but sensitive actions require explicit
approval from a human administrator (Multi-Sig).

Scenario:
1.  **Orchestrator** issues a warrant to **Junior Agent**.
2.  **Policy**: "Delete Database" requires 1 approval from **Admin**.
3.  **Attempt 1**: Agent tries to delete DB without approval -> **DENIED**.
4.  **Approval**: Admin reviews request and signs an `Approval`.
5.  **Attempt 2**: Agent attaches approval -> **AUTHORIZED**.

Requirements:
    pip install tenuo

Run:
    python examples/human_in_the_loop.py
"""

import time
from tenuo import Keypair, Warrant, Exact, Authorizer, Approval

def main():
    print("=" * 70)
    print("Tenuo Human-in-the-loop (Multi-Sig) Example")
    print("=" * 70)
    print()

    # =========================================================================
    # 1. SETUP: Identities
    # =========================================================================
    print("1. [SETUP] Establishing Identities...")
    
    # The System (Trust Anchor)
    orchestrator_key = Keypair.generate()
    
    # The AI Agent (Requestor)
    agent_key = Keypair.generate()
    
    # The Human Admins (Approvers) - We have a board of 3 admins
    admin_alice = Keypair.generate()
    admin_bob = Keypair.generate()
    admin_charlie = Keypair.generate()
    
    print(f"   ✓ Orchestrator:  {bytes(orchestrator_key.public_key().to_bytes()).hex()[:16]}...")
    print(f"   ✓ AI Agent:      {bytes(agent_key.public_key().to_bytes()).hex()[:16]}...")
    print(f"   ✓ Admin Alice:   {bytes(admin_alice.public_key().to_bytes()).hex()[:16]}...")
    print(f"   ✓ Admin Bob:     {bytes(admin_bob.public_key().to_bytes()).hex()[:16]}...")
    print(f"   ✓ Admin Charlie: {bytes(admin_charlie.public_key().to_bytes()).hex()[:16]}...")
    print()

    # =========================================================================
    # 2. ISSUANCE: Warrant with M-of-N Requirement
    # =========================================================================
    print("2. [ISSUANCE] Creating Warrant with M-of-N Requirement...")
    print("   Policy: 'delete_database' requires approval from 2 of 3 Admins.")

    warrant = Warrant.create(
        tool="delete_database",
        constraints={
            "db_name": Exact("production-db")
        },
        ttl_seconds=3600,
        keypair=orchestrator_key,
        authorized_holder=agent_key.public_key(),
        # MULTI-SIG CONFIGURATION: 2-of-3
        required_approvers=[
            admin_alice.public_key(),
            admin_bob.public_key(),
            admin_charlie.public_key()
        ],
        min_approvals=2
    )
    
    print(f"   ✓ Warrant ID: {warrant.id}")
    print(f"   ✓ Approvers:  [Alice, Bob, Charlie]")
    print(f"   ✓ Threshold:  2 approvals required")
    print()

    # Initialize Authorizer (trusted by the resource)
    authorizer = Authorizer.new(orchestrator_key.public_key())

    # =========================================================================
    # 3. ATTEMPT 1: Execution WITHOUT Approval
    # =========================================================================
    print("3. [EXECUTION] Attempt 1: Agent tries without approval...")
    
    args = {"db_name": "production-db"}
    
    # Agent signs the request (PoP)
    pop_sig = warrant.create_pop_signature(agent_key, "delete_database", args)
    
    try:
        authorizer.authorize(
            warrant,
            "delete_database",
            args,
            signature=pop_sig,
            approvals=[] # No approvals attached
        )
        print("   ❌ ERROR: Should have been denied!")
    except Exception as e:
        print(f"   ✅ DENIED: {e}")
        print("      (Correctly blocked: 0/2 approvals)")
    print()

    # =========================================================================
    # 4. ATTEMPT 2: Execution with PARTIAL Approval (1 of 2)
    # =========================================================================
    print("4. [EXECUTION] Attempt 2: Agent gets approval from Alice only...")
    
    approval_alice = Approval.create(
        warrant_id=warrant.id,
        tool="delete_database",
        args=args,
        approver_key=admin_alice,
        external_id="alice@corp.com",
        provider="okta",
        ttl_seconds=300,
        reason="LGTM - Alice",
        authorized_holder=agent_key.public_key()
    )
    print(f"   ✓ Alice signed approval.")

    try:
        authorizer.authorize(
            warrant,
            "delete_database",
            args,
            signature=pop_sig,
            approvals=[approval_alice] # Only 1 approval
        )
        print("   ❌ ERROR: Should have been denied!")
    except Exception as e:
        print(f"   ✅ DENIED: {e}")
        print("      (Correctly blocked: 1/2 approvals)")
    print()

    # =========================================================================
    # 5. ATTEMPT 3: Execution with SUFFICIENT Approval (2 of 2)
    # =========================================================================
    print("5. [EXECUTION] Attempt 3: Agent gets approval from Bob too...")
    
    approval_bob = Approval.create(
        warrant_id=warrant.id,
        tool="delete_database",
        args=args,
        approver_key=admin_bob,
        external_id="bob@corp.com",
        provider="okta",
        ttl_seconds=300,
        reason="Approved - Bob",
        authorized_holder=agent_key.public_key()
    )
    print(f"   ✓ Bob signed approval.")
    
    try:
        authorizer.authorize(
            warrant,
            "delete_database",
            args,
            signature=pop_sig,
            approvals=[approval_alice, approval_bob] # 2 approvals attached
        )
        print("   ✅ AUTHORIZED: Database deleted successfully.")
        print("      (Success: 2/2 approvals provided)")
    except Exception as e:
        print(f"   ❌ DENIED: {e}")
    print()
    
    print("=" * 70)
    print("Key Takeaway:")
    print("Tenuo supports M-of-N multi-sig policies (e.g., '2 of 3 admins').")
    print("This prevents any single compromised admin key from authorizing sensitive actions.")
    print("=" * 70)

if __name__ == "__main__":
    main()
