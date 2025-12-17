#!/usr/bin/env python3
"""
Example demonstrating the @lockdown decorator with explicit warrant.

For LangChain/FastAPI integration using ContextVar, see examples/context_pattern.py
"""

from tenuo import Keypair, Warrant, Pattern, Range, lockdown, AuthorizationError

def main():
    print("=== Tenuo @lockdown Decorator Example ===\n")
    
    # Create a warrant
    keypair = Keypair.generate()
    warrant = Warrant.issue(
        tools="scale_cluster",
        constraints={
            "cluster": Pattern("staging-*"),
            "replicas": Range.max_value(15)
        },
        ttl_seconds=3600,
        keypair=keypair,
        holder=keypair.public_key # Bind to self
    )
    
    # Define a function protected by the warrant
    # Note: We must pass keypair for Proof-of-Possession signing
    @lockdown(warrant, tool="scale_cluster", keypair=keypair)
    def scale_cluster(cluster: str, replicas: int):
        """This function can only be called if the warrant authorizes it."""
        print(f"[OK] Scaling cluster {cluster} to {replicas} replicas")
        # ... actual scaling logic here
    
    # Test authorized call
    print("1. Testing authorized call...")
    try:
        scale_cluster(cluster="staging-web", replicas=5)
        print("   ✓ Function executed successfully\n")
    except AuthorizationError as e:
        print(f"   ✗ Authorization failed: {e}\n")
    
    # Test unauthorized call (replicas too high)
    print("2. Testing unauthorized call (replicas exceeds limit)...")
    try:
        scale_cluster(cluster="staging-web", replicas=20)
        print("   [ERR] Function should not have executed!\n")
    except AuthorizationError as e:
        print(f"   [OK] Authorization correctly blocked: {e}\n")
    
    # Test unauthorized call (wrong cluster)
    print("3. Testing unauthorized call (wrong cluster)...")
    try:
        scale_cluster(cluster="production-web", replicas=5)
        print("   [ERR] Function should not have executed!\n")
    except AuthorizationError as e:
        print(f"   [OK] Authorization correctly blocked: {e}\n")
    
    print("=== Example completed! ===")

if __name__ == "__main__":
    main()

