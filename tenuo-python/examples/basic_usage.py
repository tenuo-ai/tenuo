#!/usr/bin/env python3
"""
Basic Tenuo Python SDK Usage Example

Demonstrates:
- SigningKey generation
- Warrant creation with constraints
- Warrant attenuation (delegation) using builder pattern
- Authorization checks with Proof-of-Possession
"""

from tenuo import SigningKey, Warrant, Pattern, Exact, Range

def main():
    print("=== Tenuo Python SDK - Basic Usage ===\n")
    
    # 1. Generate signing keys
    print("1. Generating signing keys...")
    control_key = SigningKey.generate()
    worker_key = SigningKey.generate()
    print(f"   Control plane public key: {bytes(control_key.public_key_bytes())[:16].hex()}...")
    print(f"   Worker public key: {bytes(worker_key.public_key_bytes())[:16].hex()}...")
    print()
    
    # 2. Create a root warrant with constraints
    print("2. Creating root warrant...")
    root_warrant = (Warrant.mint_builder()
        .capability("manage_infrastructure",
            cluster=Pattern("staging-*"),
            replicas=Range.max_value(15))
        .holder(control_key.public_key)
        .ttl(3600)
        .mint(control_key))
    print(f"   Tools: {root_warrant.tools}")
    print(f"   Depth: {root_warrant.depth}")
    print()
    
    # 3. Attenuate (delegate) the warrant to a worker using builder pattern
    # POLA (Principle of Least Authority): Explicit capabilities only
    print("3. Attenuating warrant for worker (POLA - explicit capabilities)...")
    worker_warrant = (
        root_warrant.grant_builder()
        # ✓ POLA: Explicitly grant only what's needed
        .capability("manage_infrastructure",
            cluster=Exact("staging-web"),     # Narrowed from staging-*
            replicas=Range.max_value(10))     # Reduced from 15
        .holder(worker_key.public_key)
        .grant(control_key)
    )
    print(f"   Worker tools: {worker_warrant.tools}")
    print(f"   Worker depth: {worker_warrant.depth} (attenuated)")
    print("   ℹ️  POLA: Worker only gets explicitly granted capabilities")
    print("   ℹ️  No inherit_all() - must specify each capability")
    print()
    
    # 4. Test authorization
    print("4. Testing authorization...")
    
    # Helper to authorize with PoP
    def check_auth(warrant, tool, args, signing_key):
        # Create Proof-of-Possession signature
        signature = warrant.sign(signing_key, tool, args)
        # Authorize returns True/False based on constraint check
        return warrant.authorize(tool, args, bytes(signature))

    # Allowed: matches constraints
    args1 = {"cluster": "staging-web", "replicas": 5}
    if check_auth(worker_warrant, "manage_infrastructure", args1, worker_key):
        print("   ✓ Allowed: cluster=staging-web, replicas=5")
    else:
        print("   ✗ Unexpected: cluster=staging-web, replicas=5 should be allowed")
    
    # Denied: replicas too high
    args2 = {"cluster": "staging-web", "replicas": 20}
    if not check_auth(worker_warrant, "manage_infrastructure", args2, worker_key):
        print("   ✓ Denied: cluster=staging-web, replicas=20 (exceeds max)")
    else:
        print("   ✗ Unexpected: replicas=20 should be denied")
    
    # Denied: wrong cluster
    args3 = {"cluster": "production-web", "replicas": 5}
    if not check_auth(worker_warrant, "manage_infrastructure", args3, worker_key):
        print("   ✓ Denied: cluster=production-web (not in scope)")
    else:
        print("   ✗ Unexpected: production cluster should be denied")
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
