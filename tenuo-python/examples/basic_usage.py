#!/usr/bin/env python3
"""
Basic Tenuo Python SDK Usage Example

Demonstrates:
- Keypair generation
- Warrant creation with constraints
- Warrant attenuation (delegation)
- Authorization checks
"""

from tenuo import SigningKey, Warrant, Pattern, Exact, Range

def main():
    print("=== Tenuo Python SDK - Basic Usage ===\n")
    
    # 1. Generate keypairs
    print("1. Generating keypairs...")
    control_keypair = SigningKey.generate()
    worker_keypair = SigningKey.generate()
    print(f"   Control plane public key: {bytes(control_keypair.public_key_bytes())[:16].hex()}...")
    print(f"   Worker public key: {bytes(worker_keypair.public_key_bytes())[:16].hex()}...")
    print()
    
    # 2. Create a root warrant with constraints
    print("2. Creating root warrant...")
    root_warrant = Warrant.issue(
        tools="manage_infrastructure",  # Can also be a list: ["tool1", "tool2"]
        constraints={
            "cluster": Pattern("staging-*"),
            "replicas": Range.max_value(15)
        },
        ttl_seconds=3600,
        keypair=control_keypair,
        holder=control_keypair.public_key # Bind to control plane initially
    )
    print(f"   Tools: {root_warrant.tools}")
    print(f"   Depth: {root_warrant.depth}")
    print()
    
    # 3. Attenuate (delegate) the warrant to a worker
    print("3. Attenuating warrant for worker...")
    worker_warrant = root_warrant.attenuate(
        constraints={
            "cluster": Exact("staging-web"),
            "replicas": Range.max_value(10)
        },
        keypair=worker_keypair,       # Subject keypair (for binding)
        parent_keypair=control_keypair, # Issuer keypair (for signing)
        holder=worker_keypair.public_key # Explicit holder (optional if keypair matches)
    )
    print(f"   Worker tools: {worker_warrant.tools}")
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
    args1 = {"cluster": "staging-web", "replicas": 5}
    if check_auth(worker_warrant, "manage_infrastructure", args1, worker_keypair):
        print("   ✓ Allowed: cluster=staging-web, replicas=5 -> True")
    else:
        print("   ✗ Allowed: cluster=staging-web, replicas=5 -> False (Unexpected)")
    
    # Denied: replicas too high
    args2 = {"cluster": "staging-web", "replicas": 20}
    if not check_auth(worker_warrant, "manage_infrastructure", args2, worker_keypair):
        print("   ✓ Denied: cluster=staging-web, replicas=20 -> False")
    else:
        print("   ✗ Denied: cluster=staging-web, replicas=20 -> True (Unexpected)")
    
    # Denied: wrong cluster
    args3 = {"cluster": "production-web", "replicas": 5}
    if not check_auth(worker_warrant, "manage_infrastructure", args3, worker_keypair):
        print("   ✓ Denied: cluster=production-web, replicas=5 -> False")
    else:
        print("   ✗ Denied: cluster=production-web, replicas=5 -> True (Unexpected)")
    print()
    
    # 5. Serialize warrant
    print("5. Serializing warrant...")
    warrant_base64 = worker_warrant.to_base64()
    print(f"   Warrant (base64, first 80 chars): {warrant_base64[:80]}...")
    
    # Deserialize
    deserialized = Warrant.from_base64(warrant_base64)
    print("   ✓ Deserialized successfully")
    print(f"   Deserialized tools: {deserialized.tools}")
    print()
    
    print("=== Example completed successfully! ===")

if __name__ == "__main__":
    main()

