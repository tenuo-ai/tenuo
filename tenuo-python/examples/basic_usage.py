#!/usr/bin/env python3
"""
Basic Tenuo Python SDK Usage Example

Demonstrates:
- Keypair generation
- Warrant creation with constraints
- Warrant attenuation (delegation)
- Authorization checks
"""

from tenuo import Keypair, Warrant, Pattern, Exact, Range

def main():
    print("=== Tenuo Python SDK - Basic Usage ===\n")
    
    # 1. Generate keypairs
    print("1. Generating keypairs...")
    control_keypair = Keypair.generate()
    worker_keypair = Keypair.generate()
    print(f"   Control plane public key: {bytes(control_keypair.public_key_bytes())[:16].hex()}...")
    print(f"   Worker public key: {bytes(worker_keypair.public_key_bytes())[:16].hex()}...")
    print()
    
    # 2. Create a root warrant with constraints
    print("2. Creating root warrant...")
    root_warrant = Warrant.issue(
        tool="manage_infrastructure",
        constraints={
            "cluster": Pattern("staging-*"),
            "budget": Range.max_value(10000.0)
        },
        ttl_seconds=3600,
        keypair=control_keypair,
        holder=control_keypair.public_key() # Bind to control plane initially
    )
    print(f"   Tool: {root_warrant.tool}")
    print(f"   Depth: {root_warrant.depth}")
    print()
    
    # 3. Attenuate (delegate) the warrant to a worker
    print("3. Attenuating warrant for worker...")
    worker_warrant = root_warrant.attenuate(
        constraints={
            "cluster": Exact("staging-web"),
            "budget": Range.max_value(1000.0)
        },
        keypair=control_keypair, # Signed by parent (Control Plane)
        holder=worker_keypair.public_key() # Bound to worker
    )
    print(f"   Worker tool: {worker_warrant.tool}")
    print(f"   Worker depth: {worker_warrant.depth} (attenuated)")
    print()
    
    # 4. Test authorization
    print("4. Testing authorization...")
    
    # Helper to authorize with PoP
    def check_auth(warrant, tool, args, keypair):
        # Create Proof-of-Possession signature
        signature = warrant.create_pop_signature(keypair, tool, args)
        # Note: signature is returned as list[int], must convert to bytes
        return warrant.authorize(tool, args, bytes(signature))

    # Allowed: matches constraints
    args1 = {"cluster": "staging-web", "budget": 500.0}
    if check_auth(worker_warrant, "manage_infrastructure", args1, worker_keypair):
        print("   ✓ Allowed: cluster=staging-web, budget=500.0 -> True")
    else:
        print("   ✗ Allowed: cluster=staging-web, budget=500.0 -> False (Unexpected)")
    
    # Denied: budget too high
    args2 = {"cluster": "staging-web", "budget": 2000.0}
    if not check_auth(worker_warrant, "manage_infrastructure", args2, worker_keypair):
        print("   ✓ Denied: cluster=staging-web, budget=2000.0 -> False")
    else:
        print("   ✗ Denied: cluster=staging-web, budget=2000.0 -> True (Unexpected)")
    
    # Denied: wrong cluster
    args3 = {"cluster": "production-web", "budget": 500.0}
    if not check_auth(worker_warrant, "manage_infrastructure", args3, worker_keypair):
        print("   ✓ Denied: cluster=production-web, budget=500.0 -> False")
    else:
        print("   ✗ Denied: cluster=production-web, budget=500.0 -> True (Unexpected)")
    print()
    
    # 5. Serialize warrant
    print("5. Serializing warrant...")
    warrant_base64 = worker_warrant.to_base64()
    print(f"   Warrant (base64, first 80 chars): {warrant_base64[:80]}...")
    
    # Deserialize
    deserialized = Warrant.from_base64(warrant_base64)
    print("   ✓ Deserialized successfully")
    print(f"   Deserialized tool: {deserialized.tool}")
    print()
    
    print("=== Example completed successfully! ===")

if __name__ == "__main__":
    main()

