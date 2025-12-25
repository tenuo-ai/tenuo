"""
Delegation Patterns: Issuer → Issuer vs Issuer → Executor

This example demonstrates the key delegation patterns in Tenuo using the new API.
"""

from tenuo import SigningKey, Warrant, Pattern, Exact

def main():
    print("=" * 70)
    print("Pattern 1: Issuer → Issuer (Delegation of Issuance Rights)")
    print("=" * 70)
    print("Use case: Root admin delegates admin rights to team lead\n")

    # Root admin creates an issuer warrant
    root_admin_key = SigningKey.generate()

    root_issuer = (
        Warrant.mint_builder()
        .issuer()
        .holder(root_admin_key.public_key)
        .issuable_tools(["deploy", "delete", "create_user"])
        .ttl(86400)
        .mint(root_admin_key)
    )

    print("✅ Root issuer warrant created")
    print(f"   Type: {root_issuer.warrant_type}")
    print(f"   Issuable tools: {root_issuer.issuable_tools}")

    # Root admin delegates issuer rights to team lead
    team_lead_key = SigningKey.generate()

    team_lead_issuer = (
        root_issuer.grant_builder()
        .holder(team_lead_key.public_key)
        .issuable_tools(["deploy", "create_user"])  # Narrowed from parent
        .ttl(43200)
        .grant(root_admin_key)
    )

    print("\n✅ Team lead issuer warrant created (via grant_builder)")
    print(f"   Type: {team_lead_issuer.warrant_type}")
    print(f"   Issuable tools: {team_lead_issuer.issuable_tools}")
    print("   → Team lead can now mint warrants for 'deploy' and 'create_user'")

    print("\n" + "=" * 70)
    print("Pattern 2: Issuer → Executor (Creating Execution Warrants)")
    print("=" * 70)
    print("Use case: Team lead creates execution warrant for deployment bot\n")

    # Team lead creates execution warrant for deployment bot
    deploy_bot_key = SigningKey.generate()

    deploy_warrant = (
        Warrant.mint_builder()
        .tools(["deploy"])
        .holder(deploy_bot_key.public_key)
        .capability("deploy", {"environment": Pattern("staging-*")})
        .ttl(3600)
        .mint(team_lead_key)
    )

    print("✅ Deployment execution warrant created")
    print(f"   Type: {deploy_warrant.warrant_type}")
    print(f"   Tools: {deploy_warrant.tools}")
    print("   → Bot can deploy to staging-* environments only")

    print("\n" + "=" * 70)
    print("Pattern 3: Executor → Executor (Narrowing Execution)")
    print("=" * 70)
    print("Use case: Bot narrows its own warrant for specific task\n")

    # Bot narrows its own warrant - must use same or narrower constraint
    narrow_bot_key = SigningKey.generate()

    narrow_deploy = (
        deploy_warrant.grant_builder()
        .holder(narrow_bot_key.public_key)
        .capability("deploy", {"environment": Exact("staging-1")})  # More specific
        .ttl(1800)
        .grant(deploy_bot_key)
    )

    print("✅ Narrowed deployment warrant created")
    print(f"   Type: {narrow_deploy.warrant_type}")
    print(f"   Tools: {narrow_deploy.tools}")
    print("   → Can only deploy to staging-1 (more restricted)")

    print("\n" + "=" * 70)
    print("Summary: Key Differences")
    print("=" * 70)
    print("""
1. Issuer → Issuer (Delegation of Issuance Rights):
   • Delegates the RIGHT to create warrants
   • Code: parent_issuer.grant_builder().holder(...).grant(key)
   • Uses GRANT (narrowing existing issuer warrant)
   • Result: Child can mint new warrants (within narrowed scope)
   • Example: Root admin → Team lead
  
2. Issuer → Executor (Creating Execution Warrants):
   • Grants SPECIFIC execution capabilities  
   • Code: Warrant.mint_builder().tools([...]).mint(issuer_key)
   • Uses MINT (creating new execution warrant from scratch)
   • Result: Can execute tools but cannot delegate issuance rights
   • Example: Team lead → Deployment bot
  
3. Executor → Executor (Narrowing Execution):
   • Narrows existing execution capabilities
   • Code: parent_executor.grant_builder().grant(key)
   • Uses GRANT (narrowing existing execution warrant)
   • Result: More restricted execution warrant (POLA)
   • Example: Deployment bot → Task-specific bot

Key Insight:
  • mint() = Create NEW warrant (root authority)
  • grant() = Narrow EXISTING warrant (delegation)
    """)

if __name__ == "__main__":
    main()
