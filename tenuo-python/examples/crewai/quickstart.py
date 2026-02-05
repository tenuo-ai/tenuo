#!/usr/bin/env python3
"""
Tenuo CrewAI Integration - Basic Protection Example

This example demonstrates Tier 1 (constraint-based) protection for CrewAI tools.
Run with: python quickstart.py

Requires: pip install tenuo crewai
"""

from dataclasses import dataclass

# Mock CrewAI Tool for demonstration (avoids crewai dependency for simple test)
@dataclass
class Tool:
    name: str
    description: str
    func: callable


# Import Tenuo CrewAI integration
from tenuo.crewai import (  # noqa: E402
    GuardBuilder,
    protect_tool,
    Pattern,
    Subpath,
    Range,
    Wildcard,
    ToolDenied,
    ConstraintViolation,
    UnlistedArgument,
)


def main():
    print("=" * 60)
    print("Tenuo CrewAI Integration - Basic Protection Demo")
    print("=" * 60)

    # ==========================================================================
    # 1. Define Tools
    # ==========================================================================

    def search_web(query: str, max_results: int = 10) -> str:
        return f"Found {max_results} results for: {query}"

    def read_file(path: str) -> str:
        return f"Contents of: {path}"

    def send_email(to: str, subject: str, body: str) -> str:
        return f"Email sent to: {to}"

    Tool(name="search", description="Search the web", func=search_web)
    read_tool = Tool(name="read_file", description="Read a file", func=read_file)
    Tool(name="send_email", description="Send email", func=send_email)

    # ==========================================================================
    # 2. Create Guard with Constraints
    # ==========================================================================

    guard = (GuardBuilder()
        .allow("search",
               query=Pattern("*"),      # Any search query
               max_results=Range(1, 20))  # But limit results
        .allow("read_file",
               path=Subpath("/data"))    # Only /data directory
        .allow("send_email",
               to=Pattern("*@company.com"),   # Only company emails
               subject=Wildcard(),
               body=Wildcard())
        .on_denial("raise")              # Raise exception on denial
        .build())

    # ==========================================================================
    # 3. Test Allowed Calls
    # ==========================================================================

    print("\n✅ Testing ALLOWED calls:")
    print("-" * 40)

    # These should work
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
    # 5. Zero-Config Protection
    # ==========================================================================

    print("\n🔧 Zero-Config Protection:")
    print("-" * 40)

    # Protect a single tool
    # Note: This requires the actual crewai package to be installed
    try:
        protected_read = protect_tool(read_tool, path=Subpath("/safe"))
        print(f"  Created protected tool: {protected_read.name}")
    except ImportError:
        print("  (Skipped - requires 'pip install crewai')")
        print("  In production, protect_tool() wraps the tool with authorization checks")

    # The protected tool wraps the original
    # (In real usage, this would be passed to a CrewAI Agent)

    # ==========================================================================
    # 6. Introspection
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
