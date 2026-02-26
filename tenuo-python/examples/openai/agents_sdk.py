#!/usr/bin/env python3
"""
Tenuo + OpenAI Agents SDK Integration Example

This example demonstrates how to use Tenuo guardrails with the OpenAI Agents SDK
to protect multi-agent workflows from prompt injection and unauthorized tool use.

Requirements:
    uv pip install openai-agents tenuo

Two tiers of protection:
    - Tier 1: Runtime constraint checking (no cryptography)
    - Tier 2: Warrant-based authorization with Proof-of-Possession
"""

import asyncio
import os

# Check if openai-agents is installed
try:
    from agents import Agent, Runner  # noqa: F401

    AGENTS_SDK_AVAILABLE = True
except ImportError:
    AGENTS_SDK_AVAILABLE = False
    print("Note: openai-agents not installed. Running in demo mode.")
    print("Install with: uv pip install openai-agents")
    print()

from tenuo import SigningKey, Warrant
from tenuo.openai import (
    GuardrailResult,
    Pattern,
    Range,
    Subpath,  # Secure path containment
    create_tier1_guardrail,
    create_tier2_guardrail,
)

# =============================================================================
# Demo 1: Tier 1 Guardrails (Runtime Constraints)
# =============================================================================


def demo_tier1_guardrails():
    """
    Tier 1: Simple constraint checking without cryptography.

    Good for single-process scenarios where you want to validate
    tool calls against constraints before execution.
    """
    print("=" * 60)
    print("Demo 1: Tier 1 Guardrails")
    print("=" * 60)

    # Create a guardrail with constraints
    guardrail = create_tier1_guardrail(
        # Only allow these tools
        allow_tools=["send_email", "read_file", "search"],
        # Deny these tools (takes precedence over allow)
        deny_tools=["delete_file", "execute_code"],
        # Per-tool argument constraints
        constraints={
            "send_email": {
                "to": Pattern("*@company.com"),  # Only internal emails
            },
            "read_file": {
                # Subpath instead of Pattern for traversal protection
                # Pattern("/data/*") would allow /data/../etc/passwd
                "path": Subpath("/data"),
            },
            "search": {
                "limit": Range(1, 100),  # Max 100 results
            },
        },
        # tripwire=True means halt agent on violation
        tripwire=True,
    )

    print(f"Guardrail name: {guardrail.name}")
    print(f"Allowed tools: {guardrail.allow_tools}")
    print(f"Constraints defined for: {list(guardrail.constraints.keys())}")
    print()

    # Test the guardrail
    async def test_guardrail():
        # Valid tool call
        valid_input = [
            {"function": {"name": "send_email", "arguments": '{"to": "alice@company.com", "body": "Hello"}'}}
        ]
        result = await guardrail(None, None, valid_input)
        print(f"Valid call result: {result.output_info}")
        print(f"  Tripwire triggered: {result.tripwire_triggered}")

        # Invalid tool call (constraint violation)
        invalid_input = [
            {"function": {"name": "send_email", "arguments": '{"to": "attacker@evil.com", "body": "Secrets"}'}}
        ]
        result = await guardrail(None, None, invalid_input)
        print(f"\nInvalid call result: {result.output_info}")
        print(f"  Tripwire triggered: {result.tripwire_triggered}")

        # Denied tool
        denied_input = [{"function": {"name": "delete_file", "arguments": '{"path": "/etc/passwd"}'}}]
        result = await guardrail(None, None, denied_input)
        print(f"\nDenied tool result: {result.output_info}")
        print(f"  Tripwire triggered: {result.tripwire_triggered}")

    asyncio.run(test_guardrail())
    print()


# =============================================================================
# Demo 2: Tier 2 Warrant-Based Authorization
# =============================================================================


def demo_tier2_warrant():
    """
    Tier 2: Cryptographic authorization with warrants.

    Required for distributed/multi-agent scenarios where:
    - Control plane issues warrants to agents
    - Agents must prove they hold the warrant (PoP)
    - Authorization is cryptographically verifiable
    """
    print("=" * 60)
    print("Demo 2: Tier 2 Warrant-Based Authorization")
    print("=" * 60)

    # Control plane (issuer) key
    control_key = SigningKey.generate()
    print(f"Control plane key: {control_key.public_key.to_bytes().hex()[:16]}...")

    # Agent's key (holder)
    agent_key = SigningKey.generate()
    print(f"Agent key: {agent_key.public_key.to_bytes().hex()[:16]}...")

    # Control plane issues warrant to agent
    warrant = (
        Warrant.mint_builder()
        .capability(
            "send_email",
            {
                "to": Pattern("*@company.com"),
            },
        )
        .capability(
            "read_file",
            {
                "path": Pattern("/data/*"),
            },
        )
        .holder(agent_key.public_key)  # Bind to agent
        .ttl(3600)  # Valid for 1 hour
        .mint(control_key)
    )

    print(f"Warrant ID: {warrant.id}")
    print("Capabilities: send_email, read_file")
    print()

    # Create Tier 2 guardrail
    guardrail = create_tier2_guardrail(
        warrant=warrant,
        signing_key=agent_key,  # Agent proves possession
        tripwire=True,
    )

    # Test the guardrail
    async def test_warrant_guardrail():
        # Valid: tool in warrant, constraints satisfied
        valid_input = [{"function": {"name": "send_email", "arguments": '{"to": "bob@company.com"}'}}]
        result = await guardrail(None, None, valid_input)
        print(f"Valid call (in warrant): {result.output_info}")
        print(f"  Tripwire triggered: {result.tripwire_triggered}")

        # Invalid: tool NOT in warrant
        invalid_input = [
            {
                "function": {
                    "name": "delete_file",  # Not in warrant!
                    "arguments": '{"path": "/important/data"}',
                }
            }
        ]
        result = await guardrail(None, None, invalid_input)
        print(f"\nUnauthorized tool: {result.output_info[:80]}...")
        print(f"  Tripwire triggered: {result.tripwire_triggered}")

        # Invalid: constraint violation
        constraint_input = [
            {
                "function": {
                    "name": "send_email",
                    "arguments": '{"to": "attacker@external.com"}',  # Violates constraint
                }
            }
        ]
        result = await guardrail(None, None, constraint_input)
        print(f"\nConstraint violation: {result.output_info[:80]}...")
        print(f"  Tripwire triggered: {result.tripwire_triggered}")

    asyncio.run(test_warrant_guardrail())
    print()


# =============================================================================
# Demo 3: Integration with OpenAI Agents SDK
# =============================================================================


def demo_agents_sdk_integration():
    """
    Full integration with OpenAI Agents SDK.

    Shows how to attach Tenuo guardrails to agents using the
    input_guardrails parameter.
    """
    print("=" * 60)
    print("Demo 3: OpenAI Agents SDK Integration")
    print("=" * 60)

    if not AGENTS_SDK_AVAILABLE:
        print("Skipping: openai-agents not installed")
        print()
        print("To run this demo:")
        print("  1. uv pip install openai-agents")
        print("  2. export OPENAI_API_KEY=your-key")
        print("  3. python openai_agents_sdk.py")
        print()
        return

    from agents import Agent, Runner

    # Create guardrail
    guardrail = create_tier1_guardrail(
        constraints={
            "send_email": {"to": Pattern("*@company.com")},
        }
    )

    # Create agent with guardrail
    agent = Agent(
        name="SecureAssistant",
        instructions="You help users with email tasks. Only send to company addresses.",
        input_guardrails=[guardrail],
    )

    print(f"Created agent: {agent.name}")
    print(f"Guardrails: {len(agent.input_guardrails)}")
    print()

    # Run the agent (requires OPENAI_API_KEY)
    if os.environ.get("OPENAI_API_KEY"):

        async def run_agent():
            result = await Runner.run(agent, "Send an email to alice@company.com saying hello")
            print(f"Agent output: {result.final_output}")

        asyncio.run(run_agent())
    else:
        print("Set OPENAI_API_KEY to run the agent")
    print()


# =============================================================================
# Demo 4: GuardrailResult API
# =============================================================================


def demo_guardrail_result():
    """
    Understanding GuardrailResult for custom integrations.
    """
    print("=" * 60)
    print("Demo 4: GuardrailResult API")
    print("=" * 60)

    # Create results manually
    allowed = GuardrailResult(
        output_info="Tool call authorized",
        tripwire_triggered=False,
    )
    print("Allowed result:")
    print(f"  output_info: {allowed.output_info}")
    print(f"  tripwire_triggered: {allowed.tripwire_triggered}")

    blocked = GuardrailResult(
        output_info="Blocked: email to external domain",
        tripwire_triggered=True,
    )
    print("\nBlocked result:")
    print(f"  output_info: {blocked.output_info}")
    print(f"  tripwire_triggered: {blocked.tripwire_triggered}")

    # Convert to Agents SDK format (if installed)
    print("\nto_agents_sdk():")
    sdk_result = allowed.to_agents_sdk()
    print(f"  Type: {type(sdk_result).__name__}")
    print()


# =============================================================================
# Main
# =============================================================================


def main():
    print()
    print("Tenuo + OpenAI Agents SDK Integration")
    print("=====================================")
    print()

    demo_tier1_guardrails()
    demo_tier2_warrant()
    demo_agents_sdk_integration()
    demo_guardrail_result()

    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print("""
Tenuo provides two tiers of protection for OpenAI Agents:

Tier 1 (Guardrails):
  - Runtime constraint checking
  - No cryptography needed
  - Good for single-process scenarios
  - Use: create_tier1_guardrail()

Tier 2 (Warrants):
  - Cryptographic authorization
  - Proof-of-Possession verification
  - Required for distributed systems
  - Use: create_tier2_guardrail()

Both integrate via the input_guardrails parameter:

    agent = Agent(
        name="MyAgent",
        input_guardrails=[guardrail],
    )

For more information:
  - Documentation: https://tenuo.ai/docs
  - Explorer: https://tenuo.ai/explorer
""")


if __name__ == "__main__":
    main()
