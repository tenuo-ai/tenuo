#!/usr/bin/env python3
"""
Tenuo × AgentQL Integration Demo
Run: python demo.py
"""

import asyncio
from tenuo import Warrant, SigningKey, AuthorizationDenied, OneOf, Wildcard, UrlPattern
from wrapper import TenuoAgentQLAgent

# Mock visualize for demo purposes since it's in the spec but maybe not in main lib yet
def visualize_warrant(w):
    print(f"Warrant ID: {w.id[:8]}...")
    print(f"Issuer:   {str(w.issuer)[:12]}...")
    print(f"Subject:  {str(w.authorized_holder)[:12]}...")
    print("Capabilities:")
    for tool, constraints in w.capabilities.items():
        print(f"  - {tool}: {constraints}")

    exp = w.expires_at()
    print(f"Expires:  {exp}")

# === SETUP ===
print("=" * 60)
print("  TENUO × AGENTQL INTEGRATION DEMO")
print("=" * 60)

# Generate demo keys
user_keypair = SigningKey.generate()
orchestrator_keypair = SigningKey.generate()
worker_keypair = SigningKey.generate()

# === ACT 1: WARRANT VISUALIZATION ===
print("\n[ACT 1] Authorization Contract\n")

agent_warrant = (Warrant.mint_builder()
    .capability("navigate", url=UrlPattern("https://*.example.com/*"))
    .capability("fill", element=OneOf(["search_box", "email_field"]))
    .capability("click", element=OneOf(["submit_button", "search_button"]))
    .holder(orchestrator_keypair.public_key)
    .ttl(3600)
    .mint(user_keypair)
)

print("🔐 Agent's Authorization Contract:\n")
visualize_warrant(agent_warrant)

# input("\nPress Enter to continue to ACT 2...")

# === ACT 2: HAPPY PATH ===
print("\n[ACT 2] Authorized Actions\n")

async def happy_path():
    agent = TenuoAgentQLAgent(warrant=agent_warrant)

    async with agent.start_session() as session:
        print("▶ Navigating to https://example.com...")
        # Note: In our mock, goto returns MockPage which happens to be awaitable or direct
        # Let's adjust wrapper to match mock behavior if needed.
        # The wrapper awaits backend.goto(), mock.goto is async. Correct.
        page = await session.goto("https://example.com")
        print("  ✅ Authorized\n")

        print("▶ Filling 'search_box'...")
        await page.locator("search_box").fill("test query")
        print("  ✅ Authorized\n")

        print("▶ Clicking 'search_button'...")
        await page.click("search_button")
        print("  ✅ Authorized\n")

    print("📋 Audit Trail:")
    for entry in agent.audit_log:
        print(f"  {entry.timestamp} | {entry.action:10} | {entry.target:20} | {entry.result}")

asyncio.run(happy_path())

# input("\nPress Enter to continue to ACT 3...")

# === ACT 3: BLOCKED ACTIONS ===
print("\n[ACT 3] Unauthorized Actions (Blocked)\n")

async def blocked_actions():
    agent = TenuoAgentQLAgent(warrant=agent_warrant)

    async with agent.start_session() as session:
        page = await session.goto("https://example.com")

        print("▶ Attempting: navigate to https://malicious.com (Expect: BLOCKED)...")
        try:
            await session.goto("https://malicious.com/steal-cookies")
        except AuthorizationDenied as e:
            print(f"  🚫 BLOCKED: {e}\n")

        print("▶ Attempting: click 'delete_account_button' (Expect: BLOCKED)...")
        try:
            await page.click("delete_account_button")
        except AuthorizationDenied as e:
            # Truncate verbose debug URL
            msg = str(e).split("Debug at")[0].strip()
            print(f"  🚫 BLOCKED: {msg}\n")
        else:
            print("  ⚠️ UNEXPECTED SUCCESS: Button click was allowed!\n")

asyncio.run(blocked_actions())

# input("\nPress Enter to continue to ACT 4...")

# === ACT 4: MULTI-AGENT DELEGATION ===
print("\n[ACT 4] Multi-Agent Delegation with Attenuation\n")

# Orchestrator warrant (broad permissions)
# Note: 'delegate' capability logic is implicit in Warrant.grant(),
# but for the demo ensuring the Orchestrator works is key.
orchestrator_warrant = (Warrant.mint_builder()
    .capability("navigate", url=UrlPattern("https://*.example.com/*"))
    # Wildcards for fill/click
    .capability("fill", element=Wildcard())
    .capability("click", element=Wildcard())
    .holder(orchestrator_keypair.public_key)
    .ttl(3600)
    .mint(user_keypair)
)

print("🎭 Orchestrator Warrant:")
visualize_warrant(orchestrator_warrant)

# Orchestrator delegates to Worker (Attenuated)
# Using .grant() instead of delegate() as per SDK
worker_warrant = (orchestrator_warrant.grant_builder()
    .holder(worker_keypair.public_key)
    .ttl(1800)
    .capability("navigate", url=UrlPattern("https://search.example.com/*"))
    .capability("fill", element=OneOf(["search_box"]))
    .grant(orchestrator_keypair)
)

print("\n👷 Worker Warrant (attenuated):")
visualize_warrant(worker_warrant)

async def multi_agent_demo():
    worker = TenuoAgentQLAgent(warrant=worker_warrant)

    async with worker.start_session() as session:
        print("\n▶ Worker: navigate to search.example.com...")
        page = await session.goto("https://search.example.com")
        print("  ✅ Authorized\n")

        print("▶ Worker: fill 'search_box'...")
        await page.locator("search_box").fill("research query")
        print("  ✅ Authorized\n")

        print("▶ Worker: attempting click 'search_button' (Expect: BLOCKED)...")
        try:
            await page.click("search_button")
        except AuthorizationDenied as e:
            msg = str(e).split("Debug at")[0].strip()
            print(f"  🚫 BLOCKED: {msg}\n")
        else:
            print("  ⚠️ UNEXPECTED SUCCESS: Button click was allowed!\n")

        print("▶ Worker: attempting navigate to admin.example.com (Expect: BLOCKED)...")
        try:
            await session.goto("https://admin.example.com")
        except AuthorizationDenied as e:
            msg = str(e).split("Debug at")[0].strip()
            print(f"  🚫 BLOCKED: {msg}\n")
        else:
            print("  ⚠️ UNEXPECTED SUCCESS: Navigation was allowed!\n")

asyncio.run(multi_agent_demo())

# === ACT 5: THE ASK ===
print("\n" + "=" * 60)
print("  THE INTEGRATION OPPORTUNITY")
print("=" * 60)
print("""
Current state:
  - Tenuo authorizes against CSS selectors
  - Policies like 'allow(fill, "div > span:nth-child(3)")' are useless

The ask:
  - Expose semantic_label on AgentQL locators
  - locator.semantic_label → "search_box"

The result:
  - Policies become: 'allow(fill, "search_box")'
  - AgentQL's semantic engine becomes a security boundary
  - Differentiator: policy-controllable agents by INTENT
""")

print("\n✨ Demo complete.")
