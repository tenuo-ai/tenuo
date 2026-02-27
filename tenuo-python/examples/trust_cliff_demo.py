#!/usr/bin/env python3
"""
Trust Cliff Demo - Closed-World Constraint Semantics

Demonstrates Tenuo's "Trust Cliff" behavior:
- No constraints → OPEN (any arguments allowed)
- ≥1 constraint → CLOSED (unknown arguments rejected)
- _allow_unknown: True → Explicit opt-out
- Wildcard() → Allow any value for specific field
- Non-inheritance during attenuation

Run:
    python trust_cliff_demo.py
"""

import time

from tenuo import (
    Pattern,
    Range,
    SigningKey,
    Warrant,
    Wildcard,
)


def main():
    print("=" * 70)
    print("🧗 Trust Cliff Demo - Closed-World Constraint Semantics")
    print("=" * 70)

    key = SigningKey.generate()

    # =========================================================================
    # 1. No Constraints = OPEN (any arguments allowed)
    # =========================================================================
    print("\n1. NO CONSTRAINTS → OPEN")
    print("-" * 70)

    open_warrant = (
        Warrant.mint_builder()
        .tool("api_call")  # No constraints - fully open
        .holder(key.public_key)
        .ttl(3600)
        .mint(key)
    )

    # Create PoP and authorize
    args = {"url": "https://any.com", "timeout": 999, "retries": 100}
    pop = open_warrant.sign(key, "api_call", args, int(time.time()))
    result = open_warrant.authorize("api_call", args, bytes(pop))
    if result:
        print("   ✅ ALLOWED: url=https://any.com, timeout=999, retries=100")
        print("   ℹ️  No constraints = all arguments pass through")
    else:
        print("   ❌ Unexpected: should have been allowed")

    # =========================================================================
    # 2. One Constraint = CLOSED (unknown fields rejected)
    # =========================================================================
    print("\n2. ONE CONSTRAINT → CLOSED (Trust Cliff)")
    print("-" * 70)

    closed_warrant = (
        Warrant.mint_builder()
        .capability("api_call", url=Pattern("https://api.example.com/*"))
        .holder(key.public_key)
        .ttl(3600)
        .mint(key)
    )

    # Try with unknown field 'timeout' - should be BLOCKED
    args = {"url": "https://api.example.com/v1", "timeout": 30}
    pop = closed_warrant.sign(key, "api_call", args, int(time.time()))
    result = closed_warrant.authorize("api_call", args, bytes(pop))
    if not result:
        # Get detailed reason
        reason = closed_warrant.check_constraints("api_call", args)
        print(f"   ❌ BLOCKED: {reason}")
        print("   ℹ️  'timeout' is unknown → rejected (closed-world mode)")
    else:
        print("   ⚠️  Unexpected: should have been blocked")

    # =========================================================================
    # 3. _allow_unknown: True (explicit opt-out)
    # =========================================================================
    print("\n3. _allow_unknown: True → OPT OUT")
    print("-" * 70)

    # Use dict syntax for _allow_unknown
    permissive_warrant = (
        Warrant.mint_builder()
        .capability(
            "api_call",
            {
                "url": Pattern("https://api.example.com/*"),
                "_allow_unknown": True,
            },
        )
        .holder(key.public_key)
        .ttl(3600)
        .mint(key)
    )

    args = {"url": "https://api.example.com/v1", "timeout": 30, "retries": 5}
    pop = permissive_warrant.sign(key, "api_call", args, int(time.time()))
    result = permissive_warrant.authorize("api_call", args, bytes(pop))
    if result:
        print("   ✅ ALLOWED: url, timeout=30, retries=5")
        print("   ℹ️  _allow_unknown: True → unknown fields pass through")
    else:
        print("   ❌ Unexpected: should have been allowed")

    # =========================================================================
    # 4. Wildcard() for specific fields (stay closed for others)
    # =========================================================================
    print("\n4. Wildcard() → ALLOW SPECIFIC FIELD (stay closed)")
    print("-" * 70)

    selective_warrant = (
        Warrant.mint_builder()
        .capability(
            "api_call",
            url=Pattern("https://api.example.com/*"),
            timeout=Wildcard(),  # Any value allowed
            retries=Range.max_value(3),
        )
        .holder(key.public_key)
        .ttl(3600)
        .mint(key)
    )

    # All fields constrained (even if Wildcard) → allowed
    args = {"url": "https://api.example.com/v1", "timeout": 9999, "retries": 2}
    pop = selective_warrant.sign(key, "api_call", args, int(time.time()))
    result = selective_warrant.authorize("api_call", args, bytes(pop))
    if result:
        print("   ✅ ALLOWED: timeout=9999, retries=2")
        print("   ℹ️  timeout=Wildcard() allows any value")
        print("   ℹ️  retries=2 satisfies Range.max_value(3)")
    else:
        print("   ❌ Unexpected: should have been allowed")

    # Try with retries too high
    args_bad = {"url": "https://api.example.com/v1", "timeout": 30, "retries": 10}
    pop_bad = selective_warrant.sign(key, "api_call", args_bad, int(time.time()))
    result_bad = selective_warrant.authorize("api_call", args_bad, bytes(pop_bad))
    if not result_bad:
        print("   ❌ BLOCKED: retries=10 exceeds Range.max_value(3)")
        print("   ℹ️  Wildcard on 'timeout' doesn't affect 'retries' constraint")
    else:
        print("   ⚠️  Unexpected: retries=10 should have been blocked")

    # Try with unknown field - should be blocked even though others have Wildcard
    args_unknown = {"url": "https://api.example.com/v1", "timeout": 30, "retries": 2, "unknown_field": True}
    pop_unknown = selective_warrant.sign(key, "api_call", args_unknown, int(time.time()))
    result_unknown = selective_warrant.authorize("api_call", args_unknown, bytes(pop_unknown))
    if not result_unknown:
        print("   ❌ BLOCKED: 'unknown_field' not in constraint set")
        print("   ℹ️  Wildcard() for specific fields doesn't open everything")
    else:
        print("   ⚠️  Unexpected: unknown_field should have been blocked")

    # =========================================================================
    # 5. _allow_unknown is NOT inherited
    # =========================================================================
    print("\n5. _allow_unknown is NOT INHERITED")
    print("-" * 70)

    parent = (
        Warrant.mint_builder()
        .capability(
            "api_call",
            {
                "url": Pattern("https://*"),
                "_allow_unknown": True,
            },
        )
        .holder(key.public_key)
        .ttl(3600)
        .mint(key)
    )

    # Child doesn't set _allow_unknown → defaults to False (closed)
    child = (
        parent.grant_builder()
        .capability("api_call", url=Pattern("https://api.example.com/*"))
        # Note: no _allow_unknown here → defaults to closed
        .holder(key.public_key)
        .ttl(300)
        .grant(key)
    )

    print("   Parent: _allow_unknown=True (permissive)")
    print("   Child:  _allow_unknown not set → defaults to False (closed)")

    # Child will block unknown fields even though parent allowed them
    args = {"url": "https://api.example.com/v1", "timeout": 30}
    pop = child.sign(key, "api_call", args, int(time.time()))
    result = child.authorize("api_call", args, bytes(pop))
    if not result:
        reason = child.check_constraints("api_call", args)
        print(f"   ❌ BLOCKED: {reason}")
        print("   ℹ️  Child did NOT inherit parent's _allow_unknown=True")
        print("   ℹ️  This prevents privilege escalation through delegation")
    else:
        print("   ⚠️  Unexpected: should have been blocked")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 70)
    print("📋 SUMMARY: Trust Cliff Behavior")
    print("=" * 70)
    print("""
┌─────────────────────────────────────────────────────────────────────┐
│ STATE                        │ BEHAVIOR                             │
├─────────────────────────────────────────────────────────────────────┤
│ No constraints               │ OPEN: Any arguments allowed          │
│ ≥1 constraint                │ CLOSED: Unknown arguments rejected   │
│ _allow_unknown: True         │ Explicit opt-out from closed-world   │
│ field=Wildcard()             │ Any value OK for that field          │
│ Attenuation                  │ _allow_unknown NOT inherited         │
└─────────────────────────────────────────────────────────────────────┘

Use Cases:
  • Wildcard():       "I know this field exists, allow any value"
  • _allow_unknown:   "I don't want to enumerate all fields"
  • Neither:          "Strict security - reject everything unknown"
""")
    print("=" * 70)
    print("✅ Demo completed!")


if __name__ == "__main__":
    main()
