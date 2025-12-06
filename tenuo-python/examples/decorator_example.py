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
    warrant = Warrant.create(
        tool="upgrade_cluster",
        constraints={
            "cluster": Pattern("staging-*"),
            "budget": Range.max_value(10000.0)
        },
        ttl_seconds=3600,
        keypair=keypair
    )
    
    # Define a function protected by the warrant
    @lockdown(warrant, tool="upgrade_cluster")
    def upgrade_cluster(cluster: str, budget: float):
        """This function can only be called if the warrant authorizes it."""
        print(f"✓ Upgrading cluster {cluster} with budget ${budget}")
        # ... actual upgrade logic here
    
    # Test authorized call
    print("1. Testing authorized call...")
    try:
        upgrade_cluster(cluster="staging-web", budget=5000.0)
        print("   ✓ Function executed successfully\n")
    except AuthorizationError as e:
        print(f"   ✗ Authorization failed: {e}\n")
    
    # Test unauthorized call (budget too high)
    print("2. Testing unauthorized call (budget exceeds limit)...")
    try:
        upgrade_cluster(cluster="staging-web", budget=15000.0)
        print("   ✗ Function should not have executed!\n")
    except AuthorizationError as e:
        print(f"   ✓ Authorization correctly blocked: {e}\n")
    
    # Test unauthorized call (wrong cluster)
    print("3. Testing unauthorized call (wrong cluster)...")
    try:
        upgrade_cluster(cluster="production-web", budget=5000.0)
        print("   ✗ Function should not have executed!\n")
    except AuthorizationError as e:
        print(f"   ✓ Authorization correctly blocked: {e}\n")
    
    print("=== Example completed! ===")

if __name__ == "__main__":
    main()

