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

from tenuo import (
    Keypair, Warrant, Pattern, Range, Authorizer,
    lockdown, set_warrant_context, set_keypair_context,
    AuthorizationError
)

# ============================================================================
# Protected Tools
# ============================================================================

@lockdown(tool="search")
def search(query: str, max_results: int = 10) -> list:
    """Search tool - simulated."""
    return [f"Result {i} for '{query}'" for i in range(max_results)]


@lockdown(tool="fetch")
def fetch(url: str) -> str:
    """Fetch tool - simulated."""
    return f"Content from {url}"


@lockdown(tool="write")
def write(path: str, content: str) -> None:
    """Write tool - simulated."""
    print(f"  [write] {path}: {content[:50]}...")


# ============================================================================
# Agents (Simulated)
# ============================================================================

def orchestrator_task(warrant: Warrant, keypair: Keypair, worker_keypair: Keypair):
    """
    Orchestrator: Receives broad authority, delegates narrow slices to workers.
    
    This is the key pattern:
    - Orchestrator holds authority for the full task
    - Each phase gets only what it needs
    - Authority is reissued (attenuated) as intent changes
    """
    print("\n[Orchestrator] Starting task: 'Research Q3 competitors'")
    print(f"[Orchestrator] My warrant allows: {warrant.tool}")
    
    # Phase 1: Research (delegate search + fetch only)
    # Note: Attenuation inherits tools from parent. We use constraints to restrict usage.
    # The warrant still has all tools, but constraints make search/fetch the only usable ones.
    print("\n[Orchestrator] Phase 1: Delegating research to Worker")
    research_warrant = warrant.attenuate(
        constraints={
            "query": Pattern("*competitor*"),  # Only competitor queries
            "max_results": Range.max_value(5),  # Limit results
            "url": Pattern("https://public.*"),  # Only public URLs
            # Note: path constraint restricts write, but write tool is still in warrant
            # Authorization will fail if write is called (no matching constraint)
        },
        keypair=keypair,
        holder=worker_keypair.public_key(),
        ttl_seconds=60  # Short-lived
    )
    print(f"  Attenuated: tools={research_warrant.tool} (inherited)")
    print(f"  Constraints: query=*competitor*, max_results<=5, url=https://public.*, ttl=60s")
    
    # Worker executes research phase
    worker_research(research_warrant, worker_keypair)
    
    # Phase 2: Write (delegate write only, no search/fetch)
    # For write-only phase, we issue a new warrant with only write tool
    # This is the cleanest pattern when you want to completely change the tool set
    print("\n[Orchestrator] Phase 2: Delegating write to Worker")
    write_warrant = Warrant.issue(
        tool="write",  # Only write tool (new warrant, not attenuated)
        keypair=keypair,
        holder=worker_keypair.public_key(),
        constraints={
            "path": Pattern("/output/reports/*"),  # Restricted path
        },
        ttl_seconds=30
    )
    print(f"  New warrant: tool=write, path=/output/reports/*, ttl=30s")
    print(f"  Note: This is a new warrant (not attenuated) to change tool set")
    
    # Worker executes write phase
    worker_write(write_warrant, worker_keypair)
    
    print("\n[Orchestrator] Task complete")


def worker_research(warrant: Warrant, keypair: Keypair):
    """Worker: Executes research with attenuated authority."""
    print("\n  [Worker/Research] Received research warrant")
    print(f"  [Worker/Research] Warrant allows: {warrant.tool}")
    
    with set_warrant_context(warrant), set_keypair_context(keypair):
        # Allowed: search for competitors (matches constraint)
        results = search(query="competitor analysis", max_results=3)
        print(f"  [Worker/Research] Search succeeded: {len(results)} results")
        
        # Allowed: fetch public URL (matches constraint)
        content = fetch(url="https://public.example.com/report")
        print(f"  [Worker/Research] Fetch succeeded: {len(content)} chars")
        
        # NOT allowed: write (warrant has write tool, but no path constraint matches)
        # The warrant inherited all tools, but constraints don't allow any write paths
        try:
            write(path="/output/reports/research.txt", content="data")
            print("  [Worker/Research] ERROR: Write should have failed!")
        except AuthorizationError as e:
            print(f"  [Worker/Research] Write correctly blocked: no matching constraint")
        
        # NOT allowed: search outside constraint
        try:
            search(query="internal salary data", max_results=3)
            print("  [Worker/Research] ERROR: Query should have failed!")
        except AuthorizationError as e:
            print(f"  [Worker/Research] Query correctly blocked: constraint violation")
        
        # NOT allowed: fetch outside constraint
        try:
            fetch(url="https://internal.example.com/secret")
            print("  [Worker/Research] ERROR: Fetch should have failed!")
        except AuthorizationError as e:
            print(f"  [Worker/Research] Fetch correctly blocked: URL constraint violation")


def worker_write(warrant: Warrant, keypair: Keypair):
    """Worker: Executes write with attenuated authority."""
    print("\n  [Worker/Write] Received write warrant")
    print(f"  [Worker/Write] Warrant allows: {warrant.tool}")
    
    with set_warrant_context(warrant), set_keypair_context(keypair):
        # Allowed: write to authorized path
        write(path="/output/reports/q3-analysis.txt", content="Q3 competitor analysis...")
        print(f"  [Worker/Write] Write succeeded")
        
        # NOT allowed: search (not in this warrant's tools)
        try:
            search(query="more data", max_results=1)
            print("  [Worker/Write] ERROR: Search should have failed!")
        except AuthorizationError as e:
            print(f"  [Worker/Write] Search correctly blocked: tool not authorized")
        
        # NOT allowed: write outside constraint
        try:
            write(path="/etc/passwd", content="malicious")
            print("  [Worker/Write] ERROR: Write should have failed!")
        except AuthorizationError as e:
            print(f"  [Worker/Write] Write correctly blocked: path constraint violation")


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 60)
    print("Orchestrator-Worker Delegation Example")
    print("=" * 60)
    
    # Setup: Control Plane, Orchestrator, Worker identities
    control_plane_keypair = Keypair.generate()
    orchestrator_keypair = Keypair.generate()
    worker_keypair = Keypair.generate()
    
    print(f"\nControl Plane: {control_plane_keypair.public_key().to_bytes()[:8].hex()}...")
    print(f"Orchestrator:  {orchestrator_keypair.public_key().to_bytes()[:8].hex()}...")
    print(f"Worker:        {worker_keypair.public_key().to_bytes()[:8].hex()}...")
    
    # Control Plane issues root warrant to Orchestrator
    print("\n[Control Plane] Issuing root warrant to Orchestrator")
    root_warrant = Warrant.issue(
        tool="search,fetch,write",  # All tools allowed (comma-separated)
        keypair=control_plane_keypair,
        holder=orchestrator_keypair.public_key(),
        constraints={
            "query": Pattern("*"),  # Any query allowed
            "url": Pattern("https://*"),  # Any HTTPS URL
            "path": Pattern("/output/*"),  # Any path under /output
        },
        ttl_seconds=3600
    )
    print(f"  Root warrant: tools=[search, fetch, write], ttl=1h")
    
    # Create Authorizer to verify delegation chain
    authorizer = Authorizer.new(control_plane_keypair.public_key())
    print(f"\n[Authorizer] Created with trusted root: {control_plane_keypair.public_key().to_bytes()[:8].hex()}...")
    
    # Orchestrator executes task, delegating to Worker
    orchestrator_task(root_warrant, orchestrator_keypair, worker_keypair)
    
    # Verify the delegation chain
    print("\n" + "=" * 60)
    print("Delegation Chain Verification")
    print("=" * 60)
    
    # Verify root warrant
    try:
        authorizer.verify(root_warrant)
        print("✓ Root warrant verified (signed by control plane)")
    except Exception as e:
        print(f"✗ Root warrant verification failed: {e}")
    
    # Note: For the write phase, we issued a new warrant rather than attenuating
    # This is a valid pattern when you want to completely change the tool set
    # In a real system, you might attenuate and rely on authorization-time tool checking
    
    print("\n" + "=" * 60)
    print("Key Takeaways:")
    print("=" * 60)
    print("1. Same Worker identity, different authority per phase")
    print("2. Authority shrinks at each delegation (monotonic attenuation)")
    print("3. Worker cannot exceed what Orchestrator delegated")
    print("4. Short TTLs limit blast radius of compromised warrants")
    print("5. No identity change needed - authority tracks intent")
    print("6. Tool narrowing: Use separate warrants or rely on constraints")
    print("=" * 60)


if __name__ == "__main__":
    main()
