#!/usr/bin/env python3
"""
End-to-End Proof-of-Possession (PoP) Example

This example demonstrates the full end-to-end PoP pattern where:
1. Parent creates a PoP-bound warrant for child
2. Parent sends request + warrant to child (via gateway or directly)
3. Child uses warrant with PoP signature to authorize actions

This pattern ensures:
- Stolen warrants are useless (attacker needs child's private key)
- Child proves identity cryptographically
- Gateway validates but cannot use the warrant

Requirements:
    pip install tenuo

Run:
    python examples/end_to_end_pop.py
"""

from tenuo import (
    Keypair,
    Warrant,
    Pattern,
    Exact,
    Range,
    Authorizer,
    lockdown,
    set_warrant_context,
    set_keypair_context,
    AuthorizationError,
)


def main():
    print("=" * 70)
    print("End-to-End Proof-of-Possession (PoP) Example")
    print("=" * 70)
    print()

    # =========================================================================
    # Setup: Create keypairs for all parties
    # =========================================================================
    
    # Control plane (trust anchor)
    control_plane_keypair = Keypair.generate()
    control_plane_public_key = control_plane_keypair.public_key()
    print("✓ Control plane keypair generated")
    
    # Parent agent (receives root warrant from control plane)
    parent_keypair = Keypair.generate()
    parent_public_key = parent_keypair.public_key()
    print("✓ Parent agent keypair generated")
    
    # Child agent (will receive PoP-bound warrant from parent)
    child_keypair = Keypair.generate()
    child_public_key = child_keypair.public_key()
    print("✓ Child agent keypair generated")
    print()

    # =========================================================================
    # Step 1: Control Plane issues root warrant to Parent
    # =========================================================================
    
    print("Step 1: Control Plane → Parent (Root Warrant)")
    print("-" * 50)
    
    # Control plane creates root warrant for parent
    # Note: This could also be PoP-bound to parent
    root_warrant = Warrant.create(
        tool="agent_tools",
        constraints={
            "file_path": Pattern("/data/*"),
            "budget": Range.max_value(10000.0),
        },
        ttl_seconds=3600,
        keypair=control_plane_keypair,
        # Optionally bind to parent: authorized_holder=parent_public_key
    )
    print(f"  Root warrant ID: {root_warrant.id[:16]}...")
    print(f"  Tool: {root_warrant.tool}")
    print(f"  Requires PoP: {root_warrant.requires_pop}")
    print()

    # =========================================================================
    # Step 2: Parent creates PoP-bound child warrant
    # =========================================================================
    
    print("Step 2: Parent → Child (PoP-Bound Warrant)")
    print("-" * 50)
    
    # Parent attenuates warrant for child, binding it to child's public key
    child_warrant = root_warrant.attenuate(
        constraints={
            "file_path": Exact("/data/task-123.txt"),  # More restrictive
            "budget": Range.max_value(1000.0),         # Lower budget
        },
        keypair=parent_keypair,
        ttl_seconds=300,  # Short TTL for request
        authorized_holder=child_public_key,  # PoP binding!
    )
    print(f"  Child warrant ID: {child_warrant.id[:16]}...")
    print(f"  Requires PoP: {child_warrant.requires_pop}")  # Should be True!
    print(f"  Authorized holder matches child: {child_warrant.authorized_holder == child_public_key}")
    print()

    # =========================================================================
    # Step 3: Child receives warrant and uses it with PoP
    # =========================================================================
    
    print("Step 3: Child uses warrant with PoP")
    print("-" * 50)
    
    # Simulate child receiving warrant (e.g., from HTTP request)
    # In real scenario: warrant_base64 = request.json["warrant_base64"]
    warrant_base64 = child_warrant.to_base64()
    received_warrant = Warrant.from_base64(warrant_base64)
    
    # Child verifies warrant is bound to them
    if received_warrant.authorized_holder != child_public_key:
        raise ValueError("Warrant not bound to this child!")
    print("  ✓ Verified warrant is bound to child's public key")
    
    # Define a protected function
    @lockdown(tool="agent_tools")
    def process_file(file_path: str, budget: float):
        """Process a file with budget limit."""
        print(f"  ✓ Processing file: {file_path} (budget: ${budget})")
        return f"Processed {file_path}"
    
    # Use PoP with context managers (automatic PoP signature creation)
    print("\n  Using @lockdown with automatic PoP:")
    with set_warrant_context(received_warrant), set_keypair_context(child_keypair):
        result = process_file(file_path="/data/task-123.txt", budget=500.0)
        print(f"  ✓ Result: {result}")
    
    print()

    # =========================================================================
    # Step 4: Demonstrate PoP failure scenarios
    # =========================================================================
    
    print("Step 4: PoP Failure Scenarios")
    print("-" * 50)
    
    # Scenario A: Attacker steals warrant but doesn't have keypair
    print("\n  Scenario A: Attacker with stolen warrant (no keypair)")
    attacker_keypair = Keypair.generate()  # Attacker has different keypair
    
    try:
        with set_warrant_context(received_warrant), set_keypair_context(attacker_keypair):
            process_file(file_path="/data/task-123.txt", budget=500.0)
        print("  ✗ Should have failed!")
    except AuthorizationError as e:
        print(f"  ✓ Correctly rejected: PoP signature invalid")
    
    # Scenario B: Missing keypair context
    print("\n  Scenario B: Missing keypair context")
    
    try:
        with set_warrant_context(received_warrant):  # No keypair context!
            process_file(file_path="/data/task-123.txt", budget=500.0)
        print("  ✗ Should have failed!")
    except AuthorizationError as e:
        print(f"  ✓ Correctly rejected: {e}")
    
    # Scenario C: Manual PoP signature creation
    print("\n  Scenario C: Manual PoP signature creation")
    
    tool = "agent_tools"
    args = {"file_path": "/data/task-123.txt", "budget": 500.0}
    
    # Create PoP signature manually
    pop_signature = received_warrant.create_pop_signature(child_keypair, tool, args)
    print(f"  Created PoP signature: {bytes(pop_signature.to_bytes()).hex()[:32]}...")
    
    # Authorize with signature
    authorized = received_warrant.authorize(tool, args, signature=pop_signature)
    print(f"  Authorization result: {authorized}")
    
    print()

    # =========================================================================
    # Step 5: Gateway validation (gateway validates but cannot use warrant)
    # =========================================================================
    
    print("Step 5: Gateway Pattern (Validates but Cannot Use)")
    print("-" * 50)
    
    # Gateway creates authorizer with control plane's public key
    gateway_authorizer = Authorizer.new(control_plane_public_key)
    
    # Gateway verifies warrant chain (signature, expiry)
    try:
        gateway_authorizer.verify(received_warrant)
        print("  ✓ Gateway verified warrant chain")
    except Exception as e:
        print(f"  ✗ Gateway verification failed: {e}")
    
    # Gateway cannot authorize (no keypair for PoP)
    print("  Note: Gateway can verify but cannot create PoP signature")
    print("  → Warrant must be forwarded to child for PoP")
    
    print()
    print("=" * 70)
    print("End-to-End PoP Pattern Complete!")
    print("=" * 70)
    print()
    print("Key Takeaways:")
    print("  1. authorized_holder binds warrant to child's public key")
    print("  2. requires_pop == True means PoP signature is required")
    print("  3. @lockdown automatically creates PoP when keypair is in context")
    print("  4. Stolen warrants are useless without the private key")
    print("  5. Gateway validates but cannot use PoP-bound warrants")


if __name__ == "__main__":
    main()

