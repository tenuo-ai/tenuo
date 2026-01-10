#!/usr/bin/env python3
"""
OpenAI + Tenuo Tier 2 Warrant Example

Demonstrates cryptographic authorization with Proof-of-Possession (PoP).
This is the full security model - every tool call is signed by the agent.

Key Differences from Tier 1 (Guardrails):
- Tier 1: Runtime checks only, no cryptography
- Tier 2: Cryptographic warrant + PoP signature per call

When to use Tier 2:
- Distributed/multi-agent systems
- When you can't trust the executor to honestly report tool calls
- Audit trails with non-repudiation
- Cross-service authorization

Requirements:
    pip install openai tenuo
"""

import os

from tenuo import SigningKey, Warrant, Pattern, Range
from tenuo.openai import (
    guard,
    WarrantDenied,
    MissingSigningKey,
    ConfigurationError,
    ToolDenied,
)

# Try to import OpenAI
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Install OpenAI: pip install openai\n")


# ============================================================================
# Mock Client (for demo without API key)
# ============================================================================

class MockOpenAIClient:
    """Mock OpenAI client for demonstration purposes."""

    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                """Simulate response - returns tool call for demo."""
                from dataclasses import dataclass

                @dataclass
                class Function:
                    name: str
                    arguments: str

                @dataclass
                class ToolCall:
                    id: str
                    function: Function

                @dataclass
                class Message:
                    role: str
                    content: str
                    tool_calls: list

                @dataclass
                class Choice:
                    message: Message

                @dataclass
                class Response:
                    choices: list

                # Simulate tool calls based on user input
                messages = kwargs.get("messages", [])
                user_msg = messages[-1]["content"] if messages else ""

                if "/etc/passwd" in user_msg:
                    tool_name, args = "read_file", '{"path": "/etc/passwd"}'
                elif "delete" in user_msg.lower():
                    tool_name, args = "delete_file", '{"path": "/important.txt"}'
                elif "results=500" in user_msg:
                    tool_name, args = "search", '{"query": "test", "max_results": 500}'
                else:
                    tool_name, args = "read_file", '{"path": "/data/report.txt"}'

                return Response(choices=[Choice(message=Message(
                    role="assistant",
                    content=None,
                    tool_calls=[ToolCall(
                        id="call_1",
                        function=Function(name=tool_name, arguments=args)
                    )]
                ))])


# ============================================================================
# Demo Functions
# ============================================================================

def _key_id(public_key) -> str:
    """Get short identifier for a public key."""
    return bytes(public_key.to_bytes()).hex()[:16]


def demo_setup():
    """Create warrant and keypairs for demos."""
    print("=" * 60)
    print("Setup: Creating Warrant with PoP")
    print("=" * 60)

    # In production: Control plane has its own key
    # Agent has a different key and receives warrant from control plane
    # For demo: We use separate keys to show the pattern

    control_plane_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    print("  Control Plane Key:", _key_id(control_plane_key.public_key) + "...")
    print("  Agent Key:        ", _key_id(agent_key.public_key) + "...")

    # Control plane mints warrant for agent
    warrant = (Warrant.mint_builder()
        .capability("read_file", {"path": Pattern("/data/*")})
        .capability("search", {"max_results": Range(1, 100)})
        .holder(agent_key.public_key)  # Agent is the authorized holder
        .ttl(3600)
        .mint(control_plane_key))      # Control plane signs

    print("  Warrant ID:       ", warrant.id[:16] + "...")
    print("  Holder bound to:   Agent's public key")
    print("  Capabilities:      read_file, search")
    print()

    return control_plane_key, agent_key, warrant


def demo_missing_signing_key(warrant):
    """Demonstrate error when signing key is missing."""
    print("=" * 60)
    print("Demo 1: Missing Signing Key")
    print("=" * 60)

    # Common mistake: providing warrant without signing_key
    client = guard(
        MockOpenAIClient(),
        warrant=warrant,
        # signing_key is missing!
    )

    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
        print("  X Should have raised MissingSigningKey!")
    except MissingSigningKey as e:
        print(f"  OK Correctly caught: {e.code}")
        print(f"     {e}")

    print()


def demo_wrong_signing_key(warrant):
    """Demonstrate failure with wrong signing key."""
    print("=" * 60)
    print("Demo 2: Wrong Signing Key (Not the Holder)")
    print("=" * 60)

    # Wrong key - not the warrant holder
    wrong_key = SigningKey.generate()
    print(f"  Warrant holder:  {_key_id(warrant.authorized_holder)}...")
    print(f"  Signing key:     {_key_id(wrong_key.public_key)}... (wrong!)")

    client = guard(
        MockOpenAIClient(),
        warrant=warrant,
        signing_key=wrong_key,  # Wrong key!
    )

    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
        print("  X Should have raised WarrantDenied!")
    except WarrantDenied as e:
        print("  OK PoP verification failed (wrong key)")
        print(f"     Tool: {e.tool_name}")

    print()


def demo_valid_call(agent_key, warrant):
    """Demonstrate a valid call with correct warrant and key."""
    print("=" * 60)
    print("Demo 3: Valid Call (Correct Warrant + PoP)")
    print("=" * 60)

    client = guard(
        MockOpenAIClient(),
        warrant=warrant,
        signing_key=agent_key,  # Correct key - agent is the holder
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
        tool_call = response.choices[0].message.tool_calls[0]
        print(f"  OK Tool call authorized: {tool_call.function.name}")
        print(f"     Arguments: {tool_call.function.arguments}")
        print("     (PoP signature verified)")
    except (WarrantDenied, MissingSigningKey) as e:
        print(f"  X Unexpected error: {e}")

    print()


def demo_constraint_violation(agent_key, warrant):
    """Demonstrate blocking a constraint violation."""
    print("=" * 60)
    print("Demo 4: Constraint Violation (Path Not Allowed)")
    print("=" * 60)

    client = guard(
        MockOpenAIClient(),
        warrant=warrant,
        signing_key=agent_key,
    )

    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read /etc/passwd"}],
        )
        print("  X Should have raised WarrantDenied!")
    except WarrantDenied as e:
        print("  OK Constraint violation blocked")
        print(f"     Tool: {e.tool_name}")
        print(f"     Reason: {e.reason}")

    print()


def demo_unauthorized_tool(agent_key, warrant):
    """Demonstrate blocking a tool not in warrant."""
    print("=" * 60)
    print("Demo 5: Unauthorized Tool (Not in Warrant)")
    print("=" * 60)

    client = guard(
        MockOpenAIClient(),
        warrant=warrant,
        signing_key=agent_key,
    )

    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "delete the file"}],
        )
        print("  X Should have raised WarrantDenied!")
    except WarrantDenied as e:
        print("  OK Tool not authorized by warrant")
        print(f"     Tool: {e.tool_name}")

    print()


def demo_defense_in_depth(agent_key, warrant):
    """Demonstrate Tier 1 + Tier 2 defense in depth."""
    print("=" * 60)
    print("Demo 6: Defense in Depth (Tier 1 + Tier 2)")
    print("=" * 60)

    # Warrant allows read_file, but Tier 1 denies it
    client = guard(
        MockOpenAIClient(),
        warrant=warrant,
        signing_key=agent_key,
        deny_tools=["read_file"],  # Tier 1: explicit deny
    )

    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
        print("  X Should have been blocked!")
    except ToolDenied:
        print("  OK Tier 1 denylist blocked the call")
        print("     (Warrant would allow, but Tier 1 denies)")
    except WarrantDenied:
        # Tier 2 is checked first now, so this path shouldn't happen
        # for a valid warrant call
        print("  OK Blocked (unexpectedly by Tier 2)")

    print()


def demo_validate(agent_key, warrant):
    """Demonstrate pre-flight validation."""
    print("=" * 60)
    print("Demo 7: Pre-flight Validation")
    print("=" * 60)

    # Good config - should pass
    client = guard(MockOpenAIClient(), warrant=warrant, signing_key=agent_key)
    try:
        client.validate()
        print("  OK Validation passed for correct config")
    except ConfigurationError as e:
        print(f"  X Unexpected error: {e}")

    # Bad config - wrong key
    wrong_key = SigningKey.generate()
    client2 = guard(MockOpenAIClient(), warrant=warrant, signing_key=wrong_key)
    try:
        client2.validate()
        print("  X Should have caught key mismatch!")
    except ConfigurationError as e:
        print(f"  OK validate() caught config error: {e.code}")
        print(f"     {str(e)[:60]}...")

    print()


def demo_real_openai(agent_key, warrant):
    """Demonstrate with real OpenAI client."""
    print("=" * 60)
    print("Demo 8: Real OpenAI Integration")
    print("=" * 60)

    if not OPENAI_AVAILABLE:
        print("  OpenAI not installed. Install with: pip install openai\n")
        return

    if not os.getenv("OPENAI_API_KEY"):
        print("  OPENAI_API_KEY not set.\n")
        print("  Example:")
        print("    export OPENAI_API_KEY='your-key-here'\n")
        return

    # Real OpenAI with full Tier 2 protection
    guard(
        openai.OpenAI(),
        warrant=warrant,
        signing_key=agent_key,
        on_denial="raise",
    )

    print("  Real OpenAI client created with Tier 2 protection.")
    print("  Every tool call is cryptographically signed.\n")
    print("  Use: real_client.chat.completions.create(...)")
    print()


def main():
    print("\n=== OpenAI + Tenuo Tier 2 (Warrant + PoP) ===\n")
    print("This example shows Tier 2 cryptographic protection:")
    print("  - Warrant defines allowed capabilities")
    print("  - Agent's signing key proves warrant holder")
    print("  - Every tool call has Proof-of-Possession signature")
    print()

    # Enable debug logging to see authorization decisions
    # Uncomment the next line to see detailed logs:
    # enable_debug()

    # Setup
    control_plane_key, agent_key, warrant = demo_setup()

    # Demos
    demo_missing_signing_key(warrant)
    demo_wrong_signing_key(warrant)
    demo_valid_call(agent_key, warrant)
    demo_constraint_violation(agent_key, warrant)
    demo_unauthorized_tool(agent_key, warrant)
    demo_defense_in_depth(agent_key, warrant)
    demo_validate(agent_key, warrant)
    demo_real_openai(agent_key, warrant)

    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print("""
Tier 2 provides cryptographic authorization:

  1. Control plane mints warrant with capabilities
  2. Warrant is bound to agent's public key (holder)
  3. Agent signs PoP for each tool call
  4. Verification proves:
     - Warrant is valid (signature chain)
     - Tool is in capabilities
     - Arguments satisfy constraints
     - Caller holds the warrant's private key

This is essential for distributed systems where you can't
trust the executor to honestly report what tools it called.

For simpler single-process scenarios, use Tier 1 guardrails:
  - See: tenuo-python/examples/openai_guardrails.py
""")


if __name__ == "__main__":
    main()

