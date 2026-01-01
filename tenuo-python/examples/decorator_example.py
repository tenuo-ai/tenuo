#!/usr/bin/env python3
"""
Example demonstrating the @guard decorator with explicit warrant.

For LangChain/FastAPI integration using ContextVar, see examples/context_pattern.py
"""

from tenuo import SigningKey, Pattern, Range, guard, configure, mint_sync, Capability

def main():
    print("=== Tenuo @guard Decorator Example ===\n")

    # Configure Tenuo
    key = SigningKey.generate()
    configure(issuer_key=key, dev_mode=True, audit_log=False)

    # Define a function with @guard decorator
    @guard(tool="scale_cluster")
    def scale_cluster(cluster: str, replicas: int):
        print(f"  [OK] Scaling cluster {cluster} to {replicas} replicas")

    print("  Decorated 'scale_cluster' function created with @guard\n")

    # Test 1: Authorized call (within constraints)
    print("1. Testing authorized call...")
    with mint_sync(Capability("scale_cluster",
                              cluster=Pattern("staging-*"),
                              replicas=Range.max_value(15))):
        try:
            scale_cluster(cluster="staging-web", replicas=3)
            print("  Function executed successfully.\n")
        except Exception as e:
            print(f"   ✗ Unexpected error: {e}\n")

    # Test 2: Unauthorized call (replicas too high)
    print("2. Testing unauthorized call (replicas exceeds limit)...")
    with mint_sync(Capability("scale_cluster",
                              cluster=Pattern("staging-*"),
                              replicas=Range.max_value(15))):
        try:
            scale_cluster(cluster="staging-web", replicas=20)
            print("   [ERR] Function should not have executed!\n")
        except Exception as e:
            print(f"   [OK] Authorization correctly blocked: {type(e).__name__}\n")

    # Test 3: Unauthorized call (wrong cluster pattern)
    print("3. Testing unauthorized call (wrong cluster)...")
    with mint_sync(Capability("scale_cluster",
                              cluster=Pattern("staging-*"),
                              replicas=Range.max_value(15))):
        try:
            scale_cluster(cluster="production-web", replicas=5)
            print("   [ERR] Function should not have executed!\n")
        except Exception as e:
            print(f"   [OK] Authorization correctly blocked: {type(e).__name__}\n")

    print("=== Example completed! ===")

if __name__ == "__main__":
    main()

