#!/usr/bin/env python3
"""
Delegation Receipts Example

Demonstrates Tenuo's delegation diff and receipt functionality for first-class auditability.

Key Features:
1. Preview changes before delegation (diff)
2. Human-readable diff output
3. Structured diff for programmatic use
4. Delegation receipts attached to child warrants
5. SIEM-compatible JSON output for audit logs
6. Chain reconstruction with full diffs
"""

from tenuo import (
    SigningKey, Warrant, Pattern, Exact,
    Authorizer
)


def main():
    print("=" * 70)
    print("Delegation Receipts Example")
    print("=" * 70)
    
    # Setup: Control Plane, Orchestrator, Worker identities
    control_kp = SigningKey.generate()
    orchestrator_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    print(f"\nControl Plane: {control_kp.public_key.to_bytes()[:8].hex()}...")
    print(f"Orchestrator:  {orchestrator_kp.public_key.to_bytes()[:8].hex()}...")
    print(f"Worker:        {worker_kp.public_key.to_bytes()[:8].hex()}...")
    
    # ============================================================================
    # Step 1: Control Plane issues root warrant
    # ============================================================================
    print("\n" + "=" * 70)
    print("Step 1: Control Plane issues root warrant")
    print("=" * 70)
    
    root_warrant = Warrant.issue(
        tools=["read_file", "send_email", "search"],  # Multiple tools as list
        keypair=control_kp,
        holder=orchestrator_kp.public_key,
        constraints={
            "path": Pattern("/data/*"),  # Any path under /data
            "recipient": Pattern("*@company.com"),  # Company emails only
        },
        ttl_seconds=3600,  # 1 hour
    )
    
    print(f"Root warrant ID: {root_warrant.id}")
    print(f"Tools: {root_warrant.tools}")
    print("TTL: 3600s")
    print("Constraints: path=/data/*, recipient=*@company.com")
    
    # ============================================================================
    # Step 2: Orchestrator previews delegation with diff
    # ============================================================================
    print("\n" + "=" * 70)
    print("Step 2: Orchestrator previews delegation (diff)")
    print("=" * 70)
    
    # Create builder
    builder = root_warrant.attenuate_builder()
    
    # Configure child warrant
    builder.with_constraint("path", Exact("/data/q3.pdf"))  # Narrow to specific file
    builder.with_ttl(60)  # Reduce TTL to 60 seconds
    builder.with_holder(worker_kp.public_key)  # Bind to worker
    builder.with_intent("Read Q3 report for analysis")  # Human-readable intent
    
    # Preview human-readable diff
    print("\nHuman-Readable Diff:")
    print(builder.diff())
    
    # Get structured diff for programmatic use
    diff = builder.diff_structured()
    print("\nStructured Diff:")
    print(f"  Parent: {diff.parent_warrant_id}")
    print(f"  Child: {diff.child_warrant_id} (pending)")
    print(f"  Tools kept: {diff.tools.kept}")
    print(f"  Tools dropped: {diff.tools.dropped}")
    print(f"  TTL change: {diff.ttl.change.value}")
    print(f"  Intent: {diff.intent}")
    
    # ============================================================================
    # Step 3: Delegate and get receipt
    # ============================================================================
    print("\n" + "=" * 70)
    print("Step 3: Delegate and get receipt")
    print("=" * 70)
    
    # Delegate (builds warrant and attaches receipt)
    child_warrant = builder.delegate_to(
        keypair=orchestrator_kp,
        parent_keypair=control_kp,
    )
    
    print(f"\nChild warrant created: {child_warrant.id}")
    print(f"Depth: {child_warrant.depth}")
    
    # Access receipt
    receipt = child_warrant.delegation_receipt
    if receipt:
        print("\nDelegation Receipt:")
        print(f"  Parent: {receipt.parent_warrant_id}")
        print(f"  Child: {receipt.child_warrant_id}")
        print(f"  Delegator: {receipt.delegator_fingerprint}")
        print(f"  Delegatee: {receipt.delegatee_fingerprint}")
        print(f"  Intent: {receipt.intent}")
        print(f"  Timestamp: {receipt.timestamp}")
    
    # ============================================================================
    # Step 4: SIEM-compatible JSON output
    # ============================================================================
    print("\n" + "=" * 70)
    print("Step 4: SIEM-compatible JSON output")
    print("=" * 70)
    
    if receipt:
        siem_json_str = receipt.to_siem_json()
        import json
        siem_json = json.loads(siem_json_str)
        
        print("\nSIEM Event (for audit logging):")
        print(f"  Event Type: {siem_json['event_type']}")
        print(f"  Deltas: {len(siem_json['deltas'])} changes")
        for delta in siem_json['deltas']:
            print(f"    - {delta['field']}: {delta['change']}")
        print("  Summary:")
        print(f"    - Tools dropped: {siem_json['summary']['tools_dropped']}")
        print(f"    - TTL reduced: {siem_json['summary']['ttl_reduced']}")
        print(f"    - Is terminal: {siem_json['summary']['is_terminal']}")
        
        # Full JSON (for sending to SIEM)
        print("\nFull SIEM JSON:")
        print(siem_json_str)
    
    # ============================================================================
    # Step 5: Chain verification with receipts
    # ============================================================================
    print("\n" + "=" * 70)
    print("Step 5: Chain verification")
    print("=" * 70)
    
    # Verify the chain
    authorizer = Authorizer(trusted_roots=[control_kp.public_key])
    chain_result = authorizer.verify_chain([root_warrant, child_warrant])
    
    print("\nChain Verification:")
    print("  Valid: True")
    print(f"  Steps: {len(chain_result.verified_steps)}")
    
    # Show receipt for each step
    for i, step in enumerate(chain_result.verified_steps):
        print(f"\n  Step {i+1}:")
        print(f"    Warrant ID: {step.warrant_id}")
        print("    Valid: True")
        if i > 0:  # Child warrants have receipts
            # Note: In a real scenario, you'd access the receipt from the warrant
            print("    (Receipt available via warrant.delegation_receipt)")
    
    # ============================================================================
    # Step 6: Multiple delegations (chain with receipts)
    # ============================================================================
    print("\n" + "=" * 70)
    print("Step 6: Multiple delegations (chain)")
    print("=" * 70)
    
    # Create another delegation from child
    builder2 = child_warrant.attenuate_builder()
    builder2.with_ttl(30)  # Further reduce TTL
    builder2.with_intent("Final read before expiration")
    
    print("\nSecond delegation diff:")
    print(builder2.diff())
    
    grandchild = builder2.delegate_to(
        keypair=worker_kp,
        parent_keypair=orchestrator_kp,
    )
    
    receipt2 = grandchild.delegation_receipt
    if receipt2:
        print("\nSecond receipt:")
        print(f"  Parent: {receipt2.parent_warrant_id}")
        print(f"  Child: {receipt2.child_warrant_id}")
        print(f"  Intent: {receipt2.intent}")
    
    print("\n" + "=" * 70)
    print("Example Complete")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("1. Preview changes before delegation with builder.diff()")
    print("2. Receipts are automatically attached after delegation")
    print("3. SIEM JSON format ready for audit logging")
    print("4. Full audit trail with intent and fingerprints")
    print("5. Chain reconstruction possible with get_chain_with_diffs()")


if __name__ == "__main__":
    main()
