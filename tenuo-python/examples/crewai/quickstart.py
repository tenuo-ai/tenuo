#!/usr/bin/env python3
"""
Tenuo CrewAI Integration - Basic Protection Example

This example demonstrates Tier 1 (constraint-based) protection for CrewAI tools
using CrewAI's native hooks system. Run with: python quickstart.py

Requires: pip install tenuo crewai>=0.80.0
"""

# Import Tenuo CrewAI integration
from tenuo.crewai import (
    GuardBuilder,
    Pattern,
    Subpath,
    Range,
    Wildcard,
    ToolDenied,
    ConstraintViolation,
    UnlistedArgument,
    HOOKS_AVAILABLE,
)


def main():
    print("=" * 60)
    print("Tenuo CrewAI Integration - Hooks API Demo")
    print("=" * 60)

    # ==========================================================================
    # 1. Create Guard with Constraints
    # ==========================================================================

    guard = (GuardBuilder()
        .allow("search",
               query=Pattern("*"),        # Any search query
               max_results=Range(1, 20))  # But limit results
        .allow("read_file",
               path=Subpath("/data"))     # Only /data directory
        .allow("send_email",
               to=Pattern("*@company.com"),  # Only company emails
               subject=Wildcard(),
               body=Wildcard())
        .on_denial("raise")               # Raise exception on denial
        .build())

    # ==========================================================================
    # 2. Hooks API Usage
    # ==========================================================================

    print("\n🔌 Hooks API:")
    print("-" * 40)

    if HOOKS_AVAILABLE:
        print("  CrewAI hooks API is available (v0.80.0+)")
        print("  Usage: guard.register() to install global hook")
        print("  Usage: guard.as_hook() for crew-scoped hooks")
    else:
        print("  CrewAI hooks API not available (requires v0.80.0+)")
        print("  Install with: pip install 'crewai>=0.80.0'")

    # Example of how registration works (commented out to avoid side effects)
    # guard.register()  # All tool calls now go through authorization
    # crew.kickoff()
    # guard.unregister()

    # ==========================================================================
    # 3. Test Allowed Calls
    # ==========================================================================

    print("\n✅ Testing ALLOWED calls:")
    print("-" * 40)

    tests_allowed = [
        ("search", {"query": "machine learning"}),
        ("read_file", {"path": "/data/report.txt"}),
        ("send_email", {"to": "alice@company.com", "subject": "Hello", "body": "Hi!"}),
    ]

    for tool_name, args in tests_allowed:
        result = guard._authorize(tool_name, args)
        if result is None:
            print(f"  ✓ {tool_name}({args}) → ALLOWED")
        else:
            print(f"  ✗ {tool_name}({args}) → DENIED: {result.reason}")

    # ==========================================================================
    # 4. Test Denied Calls
    # ==========================================================================

    print("\n❌ Testing DENIED calls:")
    print("-" * 40)

    tests_denied = [
        ("delete_all", {}, ToolDenied, "unknown tool"),
        ("read_file", {"path": "/etc/passwd"}, ConstraintViolation, "path traversal"),
        ("send_email", {"to": "hacker@evil.com", "subject": "Hi", "body": "..."},
         ConstraintViolation, "external email"),
        ("search", {"query": "test", "admin_flag": True}, UnlistedArgument, "extra arg"),
    ]

    for tool_name, args, expected_error, description in tests_denied:
        try:
            guard._authorize(tool_name, args)
            print(f"  ✗ {tool_name}({args}) → Should have been denied ({description})")
        except expected_error:
            print(f"  ✓ {tool_name}({args}) → Denied ({description})")

    # ==========================================================================
    # 5. Introspection
    # ==========================================================================

    print("\n🔍 Guard Introspection:")
    print("-" * 40)

    print(f"  Tier: {guard.tier}")
    print(f"  Has warrant: {guard.has_warrant}")

    # Explain a decision
    explanation = guard.explain("read_file", {"path": "/data/file.txt"})
    print(f"  Explain read_file('/data/file.txt'): {explanation.status}")

    explanation = guard.explain("read_file", {"path": "/etc/passwd"})
    print(f"  Explain read_file('/etc/passwd'): {explanation.status} - {explanation.reason}")

    # Check for configuration warnings
    warnings = guard.validate()
    if warnings:
        print(f"  Warnings: {len(warnings)}")
        for w in warnings:
            print(f"    ⚠️ {w}")
    else:
        print("  No configuration warnings")

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
