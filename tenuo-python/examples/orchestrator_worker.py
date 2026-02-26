#!/usr/bin/env python3
"""
Orchestrator-Worker Delegation Example

Demonstrates Tenuo's core value: authority that shrinks as it flows.

Pattern:
1. Control Plane issues root warrant to Orchestrator
2. Orchestrator attenuates warrant for Worker (scope shrinks)
3. Worker cannot exceed delegated authority
4. Full chain is cryptographically verifiable

This is the "temporal mismatch" solution: same agent identity,
different authority per task phase.
"""

import time

from tenuo import Warrant, SigningKey, guard, Pattern, Range, Authorizer, warrant_scope, key_scope, Wildcard
from tenuo_core import ChainVerificationResult

# ============================================================================
# Protected Tools
# ============================================================================


@guard(tool="search")
async def search_tool(query: str, max_results: int = 10) -> list:
    """Search tool - simulated."""
    return [f"Result {i} for '{query}'" for i in range(max_results)]


@guard(tool="fetch")
async def fetch_tool(url: str) -> str:
    """Fetch tool - simulated."""
    return f"Content from {url}"


@guard(tool="write")
async def write_tool(path: str, content: str) -> None:
    """Write tool - simulated."""
    print(f"  [write] {path}: {content[:50]}...")


# Aliases for example code readability
def search(query: str, max_results: int = 10):
    """Sync wrapper for examples."""
    pass  # Placeholder - actual execution would use search_tool


def fetch(url: str):
    """Sync wrapper for examples."""
    pass  # Placeholder - actual execution would use fetch_tool


def write(path: str, content: str):
    """Sync wrapper for examples."""
    pass  # Placeholder - actual execution would use write_tool


# ============================================================================
# Agents (Simulated)
# ============================================================================


def orchestrator_task(warrant: Warrant, keypair: SigningKey, worker_keypair: SigningKey):
    """
    Orchestrator: Receives broad authority, delegates narrow slices to workers.

    This is the key pattern:
    - Orchestrator holds authority for the full task
    - Each phase gets only what it needs
    - Authority is reissued (attenuated) as intent changes

    Returns:
        Tuple of (research_warrant, write_warrant) for chain verification
    """
    print("\n[Orchestrator] Starting task: 'Research Q3 competitors'")
    print(f"[Orchestrator] My warrant allows: {warrant.tools}")

    # Phase 1: Research (delegate search + fetch only)
    # Note: Attenuation inherits tools from parent. We use constraints to restrict usage.
    # The warrant still has all tools, but constraints make search/fetch the only usable ones.
    print("\n[Orchestrator] Phase 1: Delegating research to Worker")

    # Use builder pattern with diff preview
    research_builder = warrant.grant_builder()
    research_builder.capability("search", query=Pattern("*competitor*"), max_results=Range.max_value(5))
    research_builder.capability("fetch", url=Pattern("https://public.*"))
    research_builder.ttl(60)  # Short-lived
    research_builder.holder(worker_keypair.public_key)
    research_builder.intent("Research Q3 competitors")

    # Optional: Preview diff before delegation
    # print("\nDelegation Diff Preview:")
    # print(research_builder.diff())

    research_warrant = research_builder.grant(keypair)
    print(f"  Attenuated: tools={research_warrant.tools} (inherited)")
    print("  Constraints: query=*competitor*, max_results<=5, url=https://public.*, ttl=60s")

    # Access receipt if needed for audit
    if hasattr(research_warrant, "delegation_receipt") and research_warrant.delegation_receipt:
        receipt = research_warrant.delegation_receipt
        print(f"  Receipt: {receipt.child_warrant_id} (intent: {receipt.intent})")

    # Worker executes research phase
    worker_research(research_warrant, worker_keypair)

    # Phase 2: Write (delegate write only, no search/fetch)
    # For write-only phase, we issue a new warrant with only write tool
    # This is the cleanest pattern when you want to completely change the tool set
    print("\n[Orchestrator] Phase 2: Delegating write to Worker")
    write_warrant = (
        Warrant.mint_builder()
        .capability("write", path=Pattern("/output/reports/*"), _allow_unknown=True)  # Restricted path
        .holder(worker_keypair.public_key)
        .ttl(30)
        .mint(keypair)
    )
    print("  New warrant: tools=write, path=/output/reports/*, ttl=30s")
    print("  Note: This is a new warrant (not attenuated) to change tool set")

    # Worker executes write phase
    worker_write(write_warrant, worker_keypair)

    print("\n[Orchestrator] Task complete")

    return research_warrant, write_warrant


def worker_research(warrant: Warrant, issuer_key: SigningKey, keypair: SigningKey):
    """Worker: Executes research with attenuated authority."""
    print("\n  [Worker/Research] Received research warrant")
    print(f"  [Worker/Research] Warrant allows: {warrant.tools}")

    # Build Authorizer for full single-warrant verification
    # (issuer trust + PoP + constraints in one call)
    auth = Authorizer(trusted_roots=[issuer_key.public_key])

    with warrant_scope(warrant), key_scope(keypair):
        print("\n  [Worker/Research] Demonstrating authorize_one calls (issuer trust + PoP + constraints):")

        # 1. Search (Allowed)
        try:
            print("  > Attempting: search(query='competitor analysis', max_results=3)")
            args = {"query": "competitor analysis", "max_results": 3}
            sig = warrant.sign(keypair, "search", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "search", args, signature=bytes(sig))
                print("    [Allowed] Search executed")
                search(query="competitor analysis", max_results=3)
            except Exception:
                print("    [Blocked] Search denied (unexpected)")
        except Exception as e:
            print(f"    [Error] {e}")

        # 2. Search (Blocked - wrong query)
        try:
            print("  > Attempting: search(query='internal salary data', max_results=3)")
            args = {"query": "internal salary data", "max_results": 3}
            sig = warrant.sign(keypair, "search", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "search", args, signature=bytes(sig))
                print("    [Allowed] Search executed (unexpected)")
            except Exception:
                print("    [Blocked] Search denied (constraint violation)")
        except Exception as e:
            print(f"    [Error] {e}")

        # 3. Fetch (Allowed)
        try:
            print("  > Attempting: fetch(url='https://public.example.com/report')")
            args = {"url": "https://public.example.com/report"}
            sig = warrant.sign(keypair, "fetch", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "fetch", args, signature=bytes(sig))
                print("    [Allowed] Fetch executed")
                fetch(url="https://public.example.com/report")
            except Exception:
                print("    [Blocked] Fetch denied (unexpected)")
        except Exception as e:
            print(f"    [Error] {e}")

        # 4. Fetch (Blocked - wrong URL)
        try:
            print("  > Attempting: fetch(url='https://internal.example.com/secret')")
            args = {"url": "https://internal.example.com/secret"}
            sig = warrant.sign(keypair, "fetch", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "fetch", args, signature=bytes(sig))
                print("    [Allowed] Fetch executed (unexpected)")
            except Exception:
                print("    [Blocked] Fetch denied (constraint violation)")
        except Exception as e:
            print(f"    [Error] {e}")

        # 5. Write (Blocked - tool not authorized in this warrant)
        try:
            print("  > Attempting: write(path='/output/reports/research.txt', content='data')")
            args = {"path": "/output/reports/research.txt", "content": "data"}
            sig = warrant.sign(keypair, "write", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "write", args, signature=bytes(sig))
                print("    [Allowed] Write executed (unexpected)")
            except Exception:
                print("    [Blocked] Write denied (no matching constraint)")
        except Exception as e:
            print(f"    [Error] {e}")


def worker_write(warrant: Warrant, issuer_key: SigningKey, keypair: SigningKey):
    """Worker: Executes write with attenuated authority."""
    print("\n  [Worker/Write] Received write warrant")
    print(f"  [Worker/Write] Warrant allows: {warrant.tools}")

    auth = Authorizer(trusted_roots=[issuer_key.public_key])

    with warrant_scope(warrant), key_scope(keypair):
        print("\n  [Worker/Write] Demonstrating authorize_one calls:")

        # 1. Write (Allowed)
        try:
            print("  > Attempting: write(path='/output/reports/q3-analysis.txt', content='Q3 competitor analysis...')")
            args = {"path": "/output/reports/q3-analysis.txt", "content": "Q3 competitor analysis..."}
            sig = warrant.sign(keypair, "write", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "write", args, signature=bytes(sig))
                print("    [Allowed] Write executed")
                write(path="/output/reports/q3-analysis.txt", content="Q3 competitor analysis...")
            except Exception:
                print("    [Blocked] Write denied (unexpected)")
        except Exception as e:
            print(f"    [Error] {e}")

        # 2. Write (Blocked - wrong path)
        try:
            print("  > Attempting: write(path='/etc/passwd', content='malicious')")
            args = {"path": "/etc/passwd", "content": "malicious"}
            sig = warrant.sign(keypair, "write", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "write", args, signature=bytes(sig))
                print("    [Allowed] Write executed (unexpected)")
            except Exception:
                print("    [Blocked] Write denied (constraint violation)")
        except Exception as e:
            print(f"    [Error] {e}")

        # 3. Search (Blocked - tool not authorized in this warrant)
        try:
            print("  > Attempting: search(query='more data', max_results=1)")
            args = {"query": "more data", "max_results": 1}
            sig = warrant.sign(keypair, "search", args, int(time.time()))
            try:
                auth.authorize_one(warrant, "search", args, signature=bytes(sig))
                print("    [Allowed] Search executed (unexpected)")
            except Exception:
                print("    [Blocked] Search denied (tool not authorized)")
        except Exception as e:
            print(f"    [Error] {e}")


# ============================================================================
# Main
# ============================================================================


def main():
    print("=" * 60)
    print("Orchestrator-Worker Delegation Example")
    print("=" * 60)

    # Setup: Control Plane, Orchestrator, Worker identities
    control_plane_keypair = SigningKey.generate()
    orchestrator_keypair = SigningKey.generate()
    worker_keypair = SigningKey.generate()

    print(f"\nControl Plane: {control_plane_keypair.public_key.to_bytes()[:8].hex()}...")
    print(f"Orchestrator:  {orchestrator_keypair.public_key.to_bytes()[:8].hex()}...")
    print(f"Worker:        {worker_keypair.public_key.to_bytes()[:8].hex()}...")

    # Control Plane issues root warrant to Orchestrator
    print("\n[Control Plane] Issuing root warrant to Orchestrator")
    root_warrant = (
        Warrant.mint_builder()
        .capability("search", query=Wildcard())
        .capability("fetch", url=Pattern("https://*"))
        .capability("write", path=Pattern("/output/*"), _allow_unknown=True)
        .holder(orchestrator_keypair.public_key)
        .ttl(3600)
        .mint(control_plane_keypair)
    )
    print("  Root warrant: tools=[search, fetch, write], ttl=1h")

    # Create Authorizer to verify delegation chain
    authorizer = Authorizer(trusted_roots=[control_plane_keypair.public_key])
    print(f"\n[Authorizer] Created with trusted root: {control_plane_keypair.public_key.to_bytes()[:8].hex()}...")

    # Orchestrator executes task, delegating to Worker
    research_warrant, write_warrant = orchestrator_task(root_warrant, orchestrator_keypair, worker_keypair)
    worker_research(research_warrant, orchestrator_keypair, worker_keypair)
    worker_write(write_warrant, orchestrator_keypair, worker_keypair)

    # ============================================================================
    # Chain Verification
    # ============================================================================
    print("\n" + "=" * 60)
    print("Chain Verification")
    print("=" * 60)

    # Verify Phase 1 chain: root -> research (attenuated)
    print("\n[Chain Verification] Phase 1: Root -> Research (attenuated)")
    try:
        chain1 = [root_warrant, research_warrant]
        result1: ChainVerificationResult = authorizer.verify_chain(chain1)
        print("[OK] Chain verified successfully!")
        print(f"  Chain length: {result1.chain_length}")
        print(f"  Leaf depth: {result1.leaf_depth}")
        print(f"  Root issuer: {result1.root_issuer[:8].hex()}..." if result1.root_issuer else "  Root issuer: None")
        print("  Verified steps:")
        for i, step in enumerate(result1.verified_steps):
            print(f"    [{i}] ID={step.warrant_id[:16]}..., depth={step.depth}, issuer={step.issuer[:8].hex()}...")
    except Exception as e:
        print(f"[ERR] Chain verification failed: {e}")

    # Verify Phase 2 chain: root -> write (new warrant)
    print("\n[Chain Verification] Phase 2: Root -> Write (new warrant)")
    try:
        chain2 = [root_warrant, write_warrant]
        result2: ChainVerificationResult = authorizer.verify_chain(chain2)
        print("[OK] Chain verified successfully!")
        print(f"  Chain length: {result2.chain_length}")
        print(f"  Leaf depth: {result2.leaf_depth}")
        print(f"  Root issuer: {result2.root_issuer[:8].hex()}..." if result2.root_issuer else "  Root issuer: None")
        print("  Verified steps:")
        for i, step in enumerate(result2.verified_steps):
            print(f"    [{i}] ID={step.warrant_id[:16]}..., depth={step.depth}, issuer={step.issuer[:8].hex()}...")
    except Exception as e:
        print(f"[ERR] Chain verification failed: {e}")

    # Demonstrate check_chain: verify chain AND authorize action
    print("\n[Chain Verification] Using check_chain (verify + authorize)")
    try:
        chain1 = [root_warrant, research_warrant]
        # This verifies the chain AND checks if search is authorized
        result: ChainVerificationResult = authorizer.check_chain(
            chain=chain1,
            tool="search",
            args={"query": "competitor analysis", "max_results": 3},
            signature=None,  # In production, include PoP signature
        )
        print("[OK] Chain verified and action authorized!")
        print(f"  Chain length: {result.chain_length}, leaf depth: {result.leaf_depth}")
    except Exception as e:
        print(f"[ERR] Chain verification or authorization failed: {e}")

    print("\n" + "=" * 60)
    print("Key Takeaways:")
    print("=" * 60)
    print("1. Same Worker identity, different authority per phase")
    print("2. Authority shrinks at each delegation (monotonic attenuation)")
    print("3. Worker cannot exceed what Orchestrator delegated")
    print("4. Short TTLs limit blast radius of compromised warrants")
    print("5. No identity change needed - authority tracks intent")
    print("6. Tool narrowing: Use attenuation for sub-scopes, new warrants for disjoint scopes")
    print("   - Attenuation: 'I give you a slice of my power' (inherits tools, adds constraints)")
    print("   - New Warrant: 'I give you a different power' (requires issuer authority)")
    print("=" * 60)


if __name__ == "__main__":
    main()
