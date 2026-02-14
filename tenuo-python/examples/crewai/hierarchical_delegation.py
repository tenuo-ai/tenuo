#!/usr/bin/env python3
"""
Tenuo CrewAI Integration - Hierarchical Delegation Example

This example demonstrates Tier 2 delegation for hierarchical CrewAI crews.
A manager delegates narrowed authority to workers using WarrantDelegator.

Run with: python hierarchical_delegation.py

Requires: pip install tenuo crewai
"""

from dataclasses import dataclass
from unittest.mock import MagicMock

# Mock CrewAI Tool
@dataclass
class Tool:
    name: str
    description: str
    func: callable


# Import Tenuo CrewAI integration
from tenuo.crewai import (  # noqa: E402
    GuardBuilder,
    WarrantDelegator,
    Pattern,
    Subpath,
    Range,
    Wildcard,
    EscalationAttempt,
)


def create_mock_warrant(tools: list, constraints: dict = None):
    """Create a mock warrant for demonstration."""
    mock = MagicMock()
    mock.tools.return_value = tools
    mock.constraint_for.return_value = None  # No constraint checking in demo
    mock.grant_builder.return_value = MagicMock(
        capability=lambda *a, **kw: mock.grant_builder.return_value,
        holder=lambda *a: mock.grant_builder.return_value,
        ttl=lambda *a: mock.grant_builder.return_value,
        grant=lambda *a: MagicMock(),  # Returns child warrant
    )
    return mock


def main():
    print("=" * 60)
    print("Tenuo CrewAI - Hierarchical Delegation Demo")
    print("=" * 60)

    # ==========================================================================
    # 1. Setup: Manager Warrant
    # ==========================================================================

    print("\n📋 Manager's Warrant (broad access):")
    print("-" * 40)

    # Manager has access to: search, read_file, write_file, summarize
    manager_tools = ["search", "read_file", "write_file", "summarize"]
    manager_warrant = create_mock_warrant(manager_tools)
    manager_key = MagicMock()

    print(f"  Tools: {manager_tools}")
    print("  Constraints: Search any query, read/write /research/*, summarize any")

    # ==========================================================================
    # 2. Delegate to Researcher (narrowed)
    # ==========================================================================

    print("\n👨‍🔬 Delegating to Researcher:")
    print("-" * 40)

    delegator = WarrantDelegator()
    researcher_pubkey = MagicMock()

    # Researcher gets: search (arxiv only), read_file (/research/papers only)
    researcher_attenuations = {
        "search": {
            "query": Pattern("arxiv:*"),      # Only arxiv queries
            "max_results": Range(1, 20),      # Limited results
        },
        "read_file": {
            "path": Subpath("/research/papers"),  # Narrowed path
        },
    }

    researcher_warrant = delegator.delegate(
        parent_warrant=manager_warrant,
        parent_key=manager_key,
        child_holder=researcher_pubkey,
        attenuations=researcher_attenuations,
        ttl=1800,  # 30 minutes
    )

    print("  ✓ Researcher warrant created")
    print(f"    Tools: {list(researcher_attenuations.keys())}")
    print("    search.query: arxiv:* only")
    print("    read_file.path: /research/papers only")
    print("    TTL: 30 minutes")

    # ==========================================================================
    # 3. Delegate to Writer (different narrowing)
    # ==========================================================================

    print("\n✍️ Delegating to Writer:")
    print("-" * 40)

    writer_pubkey = MagicMock()

    # Writer gets: read_file (/research/drafts), write_file (/research/output), summarize
    writer_attenuations = {
        "read_file": {
            "path": Subpath("/research/drafts"),
        },
        "write_file": {
            "path": Subpath("/research/output"),
        },
        "summarize": {
            "text": Wildcard(),
            "style": Pattern("*"),
        },
    }

    delegator.delegate(
        parent_warrant=manager_warrant,
        parent_key=manager_key,
        child_holder=writer_pubkey,
        attenuations=writer_attenuations,
        ttl=1800,
    )

    print("  ✓ Writer warrant created")
    print(f"    Tools: {list(writer_attenuations.keys())}")
    print("    read_file.path: /research/drafts only")
    print("    write_file.path: /research/output only")

    # ==========================================================================
    # 4. Test Escalation Prevention
    # ==========================================================================

    print("\n🚫 Escalation Prevention Tests:")
    print("-" * 40)

    # Test 1: Try to delegate a tool manager doesn't have
    print("\n  Test 1: Delegating unknown tool")
    try:
        delegator.delegate(
            parent_warrant=manager_warrant,
            parent_key=manager_key,
            child_holder=MagicMock(),
            attenuations={"delete_all": {"target": Wildcard()}},  # Manager doesn't have this!
        )
        print("  ✗ Should have been rejected")
    except EscalationAttempt:
        print("  ✓ Correctly rejected: EscalationAttempt")
        print("    Reason: Cannot grant tool manager doesn't have")

    # Test 2: Show that proper narrowing works
    print("\n  Test 2: Valid narrowing succeeds")
    result = delegator.delegate(
        parent_warrant=manager_warrant,
        parent_key=manager_key,
        child_holder=MagicMock(),
        attenuations={"search": {"query": Pattern("arxiv:*")}},  # Valid narrowing
    )
    print("  ✓ Delegation succeeded (proper attenuation)")

    # ==========================================================================
    # 5. Using Delegated Warrants in Guards
    # ==========================================================================

    print("\n🛡️ Building Guards with Delegated Warrants:")
    print("-" * 40)

    # In real usage, agents would have their own signing keys
    researcher_signing_key = MagicMock()

    researcher_guard = (GuardBuilder()
        .allow("search", query=Pattern("arxiv:*"), max_results=Range(1, 20))
        .allow("read_file", path=Subpath("/research/papers"))
        .with_warrant(researcher_warrant, researcher_signing_key)
        .build())

    print("  Researcher Guard:")
    print(f"    Tier: {researcher_guard.tier}")
    print(f"    Has warrant: {researcher_guard.has_warrant}")

    # Test researcher's constraints
    print("\n  Testing researcher's access:")

    # Allowed: arxiv search
    result = researcher_guard._authorize("search", {"query": "arxiv:2301.00001"})
    print(f"    search('arxiv:2301.00001'): {'ALLOWED' if result is None else 'DENIED'}")

    # Denied: non-arxiv search
    from tenuo.crewai import ConstraintViolation
    try:
        researcher_guard._authorize("search", {"query": "pubmed:12345"})
        print("    search('pubmed:12345'): Should be denied!")
    except ConstraintViolation:
        print("    search('pubmed:12345'): DENIED ✓")

    # Denied: write_file (not delegated)
    from tenuo.crewai import ToolDenied
    try:
        researcher_guard._authorize("write_file", {"path": "/any"})
        print("    write_file('/any'): Should be denied!")
    except ToolDenied:
        print("    write_file('/any'): DENIED ✓ (not in researcher's scope)")

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)
    print("""
Key Takeaways:
1. WarrantDelegator ensures attenuation-only delegation
2. Child warrants can ONLY narrow scope, never widen
3. Escalation attempts are immediately rejected
4. Hooks API enforces authorization at the framework level
5. Each agent operates within their cryptographically-enforced scope
""")


if __name__ == "__main__":
    main()
