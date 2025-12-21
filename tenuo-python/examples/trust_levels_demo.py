#!/usr/bin/env python3
"""
Trust Levels and Tool Requirements Demo

Demonstrates alpha.5 trust level features with realistic scenarios.

REAL-WORLD USE CASES:

1. Multi-Tenant SaaS Platform
   - External: Customer-facing AI agents (read public data)
   - Internal: Support agents (read customer data, create tickets)
   - Privileged: Engineering team (deploy to staging, delete test data)
   - System: Platform admins (production deploys, delete customer data)

2. Enterprise AI Orchestration
   - External: Third-party API integrations (limited read access)
   - Internal: Department agents (read/write department data)
   - Privileged: Cross-department workflows (access multiple departments)
   - System: Compliance/audit agents (read all data, generate reports)

3. Healthcare AI System (HIPAA)
   - External: Public health info chatbot (read public health articles)
   - Internal: Appointment scheduler (read/write appointments)
   - Privileged: Clinical decision support (read patient records)
   - System: Audit/compliance agents (read all PHI, generate audit logs)

4. Financial Services (SOC2/PCI-DSS)
   - External: Customer service chatbot (read account balances)
   - Internal: Fraud detection (read transactions, flag suspicious)
   - Privileged: Risk management (read all accounts, generate reports)
   - System: Compliance agents (read all data, modify risk rules)

5. DevOps/Infrastructure Automation
   - External: Monitoring agents (read metrics, no writes)
   - Internal: Auto-scaling agents (read metrics, scale services)
   - Privileged: Deployment agents (deploy to staging, rollback)
   - System: Production control plane (deploy to prod, delete databases)

This demo shows how to enforce these boundaries at the gateway level.
"""

from tenuo import (
    SigningKey, Warrant, Authorizer, TrustLevel, Pattern, Unauthorized
)

def main():
    print("="*70)
    print("Trust Levels and Tool Requirements Demo")
    print("="*70)
    
    # ========================================================================
    # Setup: Create warrants with different trust levels
    # ========================================================================
    
    print("\n1. Creating warrants with different trust levels:")
    print("-" * 70)
    
    # System-level warrant (highest trust)
    system_kp = SigningKey.generate()
    system_warrant = (Warrant.builder()
        .capability("admin_reset", {"cluster": Pattern("*")})
        .capability("delete_database", {"name": Pattern("*")})
        .capability("read_file", {"path": Pattern("/*")})
        .trust_level(TrustLevel.System)
        .holder(system_kp.public_key)
        .ttl(3600)
        .issue(system_kp))
    
    print("   ✓ System warrant (TrustLevel.System)")
    print(f"     Tools: {system_warrant.tools}")
    
    # Privileged warrant (mid-level trust)
    privileged_kp = SigningKey.generate()
    privileged_warrant = (Warrant.builder()
        .capability("delete_database", {"name": Pattern("test_*")})
        .capability("read_file", {"path": Pattern("/data/*")})
        .trust_level(TrustLevel.Privileged)
        .holder(privileged_kp.public_key)
        .ttl(3600)
        .issue(privileged_kp))
    
    print("   ✓ Privileged warrant (TrustLevel.Privileged)")
    print(f"     Tools: {privileged_warrant.tools}")
    
    # External warrant (low trust)
    external_kp = SigningKey.generate()
    external_warrant = (Warrant.builder()
        .capability("read_file", {"path": Pattern("/public/*")})
        .trust_level(TrustLevel.External)
        .holder(external_kp.public_key)
        .ttl(3600)
        .issue(external_kp))

    
    print("   ✓ External warrant (TrustLevel.External)")
    print(f"     Tools: {external_warrant.tools}")
    
    # ========================================================================
    # Configure Authorizer with trust requirements (gateway policy)
    # ========================================================================
    
    print("\n2. Configuring gateway trust requirements:")
    print("-" * 70)
    
    # Create authorizer with trusted roots
    authorizer = Authorizer(trusted_roots=[
        system_kp.public_key, 
        privileged_kp.public_key, 
        external_kp.public_key
    ])
    
    # Configure trust requirements (gateway policy)
    authorizer.require_trust("admin_*", TrustLevel.System)       # Admin tools need System
    authorizer.require_trust("delete_*", TrustLevel.Privileged)  # Delete tools need Privileged
    authorizer.require_trust("read_*", TrustLevel.External)      # Read tools need External

    
    print("   ✓ Configured trust requirements:")
    print("     admin_*  → TrustLevel.System")
    print("     delete_* → TrustLevel.Privileged")
    print("     read_*   → TrustLevel.External")
    
    # ========================================================================
    # Test 1: System warrant can access admin tools
    # ========================================================================
    
    print("\n3. Test 1: System warrant → admin_reset")
    print("-" * 70)
    
    args = {"cluster": "production"}
    pop_sig = system_warrant.create_pop_signature(system_kp, "admin_reset", args)
    
    try:
        authorizer.authorize(system_warrant, "admin_reset", args, bytes(pop_sig))
        print("   ✅ ALLOWED: System trust level can access admin tools")
    except Unauthorized as e:
        print(f"   ❌ BLOCKED: {e}")
    
    # ========================================================================
    # Test 2: Privileged warrant CANNOT access admin tools
    # ========================================================================
    
    print("\n4. Test 2: Privileged warrant → admin_reset")
    print("-" * 70)
    
    args = {"cluster": "staging"}
    
    try:
        # No PoP signature needed - trust check happens first
        authorizer.authorize(privileged_warrant, "admin_reset", args, None)
        print("   ❌ SECURITY FAILURE: Privileged should not access admin tools!")
    except Unauthorized as e:
        print(f"   ✅ BLOCKED (expected): {e}")
        print("      Privileged < System (trust hierarchy enforced)")
    
    # ========================================================================
    # Test 3: Privileged warrant CAN access delete tools
    # ========================================================================
    
    print("\n5. Test 3: Privileged warrant → delete_database")
    print("-" * 70)
    
    args = {"name": "test_db"}
    pop_sig = privileged_warrant.create_pop_signature(privileged_kp, "delete_database", args)
    
    try:
        authorizer.authorize(privileged_warrant, "delete_database", args, bytes(pop_sig))
        print("   ✅ ALLOWED: Privileged trust level can access delete tools")
    except Unauthorized as e:
        print(f"   ❌ BLOCKED: {e}")
    
    # ========================================================================
    # Test 4: Trust hierarchy (higher can access lower)
    # ========================================================================
    
    print("\n6. Test 4: System warrant → read_file (trust hierarchy)")
    print("-" * 70)
    
    args = {"path": "/public/readme.txt"}
    pop_sig = system_warrant.create_pop_signature(system_kp, "read_file", args)
    
    try:
        authorizer.authorize(system_warrant, "read_file", args, bytes(pop_sig))
        print("   ✅ ALLOWED: System > External (trust hierarchy)")
        print("      Higher trust levels can access lower-trust tools")
    except Unauthorized as e:
        print(f"   ❌ BLOCKED: {e}")
    
    # ========================================================================
    # Test 5: External warrant can access read tools
    # ========================================================================
    
    print("\n7. Test 5: External warrant → read_file")
    print("-" * 70)
    
    args = {"path": "/public/data.json"}
    pop_sig = external_warrant.create_pop_signature(external_kp, "read_file", args)
    
    try:
        authorizer.authorize(external_warrant, "read_file", args, bytes(pop_sig))
        print("   ✅ ALLOWED: External trust level can access read tools")
    except Unauthorized as e:
        print(f"   ❌ BLOCKED: {e}")
    
    # ========================================================================
    # Test 6: External warrant CANNOT access delete tools
    # ========================================================================
    
    print("\n8. Test 6: External warrant → delete_database")
    print("-" * 70)
    
    args = {"name": "test_db"}
    
    try:
        authorizer.authorize(external_warrant, "delete_database", args, None)
        print("   ❌ SECURITY FAILURE: External should not access delete tools!")
    except Unauthorized as e:
        print(f"   ✅ BLOCKED (expected): {e}")
        print("      External < Privileged (trust hierarchy enforced)")
    
    # ========================================================================
    # Summary
    # ========================================================================
    
    print("\n" + "="*70)
    print("Key Takeaways:")
    print("="*70)
    print("1. Trust levels are assigned to warrants at creation time")
    print("2. Trust requirements are gateway policy (not in warrant)")
    print("3. Trust hierarchy: System > Privileged > Internal > External > Untrusted")
    print("4. Higher trust can access lower-trust tools")
    print("5. Lower trust CANNOT access higher-trust tools")
    print("6. Trust check happens BEFORE PoP verification (fail fast)")
    print("7. Use glob patterns for tool families (admin_*, delete_*, etc.)")
    print("\n" + "="*70)
    print("Real-World Scenarios:")
    print("="*70)
    print("• SaaS Platform: External (customer agents) vs System (admin agents)")
    print("• Healthcare: External (public chatbot) vs Privileged (clinical AI)")
    print("• Finance: Internal (fraud detection) vs System (compliance agents)")
    print("• DevOps: Internal (auto-scaling) vs System (production deploys)")
    print("\nTrust levels provide defense in depth for sensitive operations!")

if __name__ == "__main__":
    main()
