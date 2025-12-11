#!/usr/bin/env python3
"""
Tenuo @lockdown Decorator Example

This example demonstrates how to protect Python functions using the @lockdown decorator.
It covers:
1.  **Explicit Binding**: Passing the warrant directly to the decorator.
2.  **Argument Mapping**: Mapping function arguments to different constraint names.
3.  **Context Pattern**: Implicitly using a warrant from the execution context (e.g., for web frameworks).

SECURITY BEST PRACTICES demonstrated:
- PoP (Proof-of-Possession) binding: Warrants are bound to specific identities
- Keypair context: Agent's keypair is set to enable automatic PoP signatures
- Stolen warrants are useless without the matching private key
"""

from tenuo import (
    Keypair, Warrant, Pattern, Range, lockdown, AuthorizationError,
    set_warrant_context, set_keypair_context, get_warrant_context
)

def main():
    print("=" * 70)
    print("Tenuo @lockdown Decorator Example")
    print("=" * 70)
    print()
    
    # Setup: Create keypairs for issuer and agent
    # SECURITY: In production, these come from K8s Secrets or HSM
    issuer_keypair = Keypair.generate()  # Control plane / orchestrator
    agent_keypair = Keypair.generate()   # The agent using the warrant
    
    # SECURITY BEST PRACTICE: Always PoP-bind warrants to the agent's identity
    # This prevents stolen warrants from being used by attackers
    warrant = Warrant.create(
        tool="manage_resources",
        constraints={
            "cluster": Pattern("staging-*"),
            "budget": Range.max_value(1000.0)
        },
        ttl_seconds=3600,
        keypair=issuer_keypair,
        authorized_holder=agent_keypair.public_key()  # PoP binding!
    )
    print(f"Issued Warrant ID: {warrant.id}")
    print(f"Constraints: cluster='staging-*', budget<=1000.0")
    print(f"PoP-bound: {warrant.requires_pop} (stolen warrants are useless)")
    print()

    # =========================================================================
    # 1. Explicit Binding (with keypair for PoP)
    # =========================================================================
    print("1. [Explicit Binding] Passing warrant directly...")
    print("   SECURITY: Keypair context enables automatic PoP signatures")
    
    @lockdown(warrant, tool="manage_resources", keypair=agent_keypair)
    def deploy_app(cluster: str, budget: float):
        print(f"   ✓ DEPLOYED to {cluster} with budget ${budget}")

    try:
        deploy_app(cluster="staging-web", budget=500.0)
    except AuthorizationError as e:
        print(f"   ✗ Failed: {e}")
    print()

    # =========================================================================
    # 2. Argument Mapping (with keypair for PoP)
    # =========================================================================
    print("2. [Argument Mapping] Mapping function args to constraints...")
    print("   (Mapping 'target_env' arg -> 'cluster' constraint)")
    
    # Map 'target_env' argument to 'cluster' constraint
    @lockdown(warrant, tool="manage_resources", keypair=agent_keypair, mapping={"target_env": "cluster"})
    def scale_service(target_env: str, budget: float):
        print(f"   ✓ SCALED service in {target_env}")

    try:
        scale_service(target_env="staging-db", budget=800.0)
    except AuthorizationError as e:
        print(f"   ✗ Failed: {e}")
        
    # Test failure case
    try:
        print("   Testing blocked call (production-db)...")
        scale_service(target_env="production-db", budget=800.0)
    except AuthorizationError as e:
        print(f"   ✓ Correctly Blocked: {e}")
    print()

    # =========================================================================
    # 3. Context Pattern (Implicit Binding with PoP)
    # =========================================================================
    print("3. [Context Pattern] Using implicit warrant from context...")
    print("   (Ideal for Flask/FastAPI/LangChain integration)")
    print("   SECURITY: Both warrant AND keypair must be in context for PoP")
    
    # No warrant passed to decorator! It looks for it in the context.
    @lockdown(tool="manage_resources")
    def restart_pod(cluster: str, budget: float):
        print(f"   ✓ RESTARTED pod in {cluster}")

    # SECURITY BEST PRACTICE: Set BOTH warrant and keypair context
    # This enables automatic PoP signature creation
    print("   Context set (warrant + keypair). Calling decorated function...")
    with set_warrant_context(warrant), set_keypair_context(agent_keypair):
        restart_pod(cluster="staging-cache", budget=100.0)
    print("   Context cleared.")
    
    # Verify it fails without context
    try:
        print("   Calling without context (should fail)...")
        restart_pod(cluster="staging-cache", budget=100.0)
    except AuthorizationError as e:
        print(f"   ✓ Correctly Failed: {e}")

    print()
    print("=" * 70)
    print("Key Takeaways:")
    print("1. @lockdown separates POLICY (Warrant) from CODE (Function).")
    print("2. ALWAYS PoP-bind warrants to the agent's identity (authorized_holder).")
    print("3. ALWAYS set keypair context to enable automatic PoP signatures.")
    print("4. Stolen warrants are useless without the matching private key.")
    print("=" * 70)

if __name__ == "__main__":
    main()

