#!/usr/bin/env python3
"""
Example demonstrating the @guard decorator with explicit warrant.

For LangChain/FastAPI integration using ContextVar, see examples/context_pattern.py
"""

from tenuo import SigningKey, Warrant, Pattern, Range, guard
from tenuo.exceptions import AuthorizationError

def main():
    print("=== Tenuo @guard Decorator Example ===\n")
    
    # Create a warrant
    key = SigningKey.generate()
    warrant = (Warrant.mint_builder()
        .capability("scale_cluster",
            cluster=Pattern("staging-*"),
            replicas=Range.max_value(15))
        .holder(key.public_key)
        .ttl(3600)
        .mint(key))
    
    # Define a function with @guard decorator
    print("=== Tenuo @guard Decorator Example ===\n")

    @guard(tool="scale_cluster")
    def scale_cluster(cluster_id: str, replicas: int):
        print(f"  [OK] Scaling cluster {cluster_id} to {replicas} replicas")
        
    print("  Decorated 'scale_cluster' function created with @guard")

    # This call should succeed (if warrant allows)
    print("  Calling protected function...")
    try:
        scale_cluster(cluster_id="staging-cluster", replicas=3)
        print("  Function executed successfully.")
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

