#!/usr/bin/env python3
"""
OpenAI + Tenuo Tier 1 Guardrails Example

A minimal example showing how to protect OpenAI tool calls with Tenuo guardrails.
This uses Tier 1 (no cryptography) - runtime constraint checking only.

Key Pattern:
1. Wrap OpenAI client with guard()
2. Define allow_tools, deny_tools, and constraints
3. All tool calls are automatically verified before execution

Requirements:
    pip install openai tenuo
"""

import os

from tenuo.openai import (
    guard,
    Pattern,
    Range,
    OneOf,
    ToolDenied,
    ConstraintViolation,
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
                
                # Simulate what a malicious/confused model might return
                messages = kwargs.get("messages", [])
                user_msg = messages[-1]["content"] if messages else ""
                
                # Simulate tool calls based on user input
                if "/etc/passwd" in user_msg:
                    tool_name, args = "read_file", '{"path": "/etc/passwd"}'
                elif "delete" in user_msg.lower():
                    tool_name, args = "delete_file", '{"path": "/important.txt"}'
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

def demo_constraint_violation():
    """Demonstrate blocking a constraint violation."""
    print("=" * 60)
    print("Demo 1: Constraint Violation (Path Protection)")
    print("=" * 60)
    
    # Create protected client
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),  # Only /data/* paths allowed
            },
        },
        on_denial="raise",
    )
    
    # Try to make a call that violates constraints
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read /etc/passwd"}],
        )
        print("✗ Should have been blocked!")
    except ConstraintViolation as e:
        print(f"✓ Blocked: {e}")
        print(f"  Tool: {e.tool_name}")
        print(f"  Param: {e.param}")
        print(f"  Value: {e.value}")
        print(f"  Type mismatch: {e.type_mismatch}")
    
    print()


def demo_tool_denied():
    """Demonstrate blocking a tool not in the allowlist."""
    print("=" * 60)
    print("Demo 2: Tool Denied (Hallucinated Tool)")
    print("=" * 60)
    
    # Create protected client
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],  # delete_file NOT in list
        deny_tools=["delete_file"],  # Explicitly blocked for defense-in-depth
        on_denial="raise",
    )
    
    # Try a tool that's not allowed
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "delete the important file"}],
        )
        print("✗ Should have been blocked!")
    except ToolDenied as e:
        print(f"✓ Blocked: {e}")
    
    print()


def demo_valid_call():
    """Demonstrate a valid call that passes all checks."""
    print("=" * 60)
    print("Demo 3: Valid Call (Passes Guardrails)")
    print("=" * 60)
    
    # Create protected client
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),
            },
        },
        on_denial="raise",
    )
    
    # This should pass - path matches pattern
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
        tool_call = response.choices[0].message.tool_calls[0]
        print(f"✓ Allowed: {tool_call.function.name}")
        print(f"  Arguments: {tool_call.function.arguments}")
    except (ToolDenied, ConstraintViolation) as e:
        print(f"✗ Unexpected block: {e}")
    
    print()


def demo_real_openai():
    """Demonstrate with real OpenAI client (if available)."""
    print("=" * 60)
    print("Demo 4: Real OpenAI Integration")
    print("=" * 60)
    
    if not OPENAI_AVAILABLE:
        print("OpenAI not installed. Install with: pip install openai\n")
        return
    
    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. Set it to use real OpenAI API.\n")
        print("Example:")
        print("  export OPENAI_API_KEY='your-key-here'\n")
        return
    
    # Real OpenAI integration
    real_client = guard(
        openai.OpenAI(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),
            },
            "search": {
                "max_results": Range(1, 50),
            },
        },
        on_denial="raise",
    )
    
    print("Real OpenAI client created with guardrails.")
    print("Use: real_client.chat.completions.create(...)")
    print()


def demo_skip_mode():
    """Demonstrate skip mode (silent filtering)."""
    print("=" * 60)
    print("Demo 5: Skip Mode (Silent Filtering)")
    print("=" * 60)
    
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),
            },
        },
        on_denial="skip",  # Don't raise, just filter out
    )
    
    # This won't raise - the denied tool call is silently removed
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Read /etc/passwd"}],
    )
    
    tool_calls = response.choices[0].message.tool_calls
    if tool_calls is None:
        print("✓ Tool call was silently filtered out (skip mode)")
    else:
        print(f"Tool calls remaining: {len(tool_calls)}")
    
    print("\n⚠ Warning: Using skip mode can cause the LLM to hang")
    print("  if it expects a tool response that never comes.")
    print("  Prefer on_denial='raise' and handle the exception.\n")


def main():
    print("\n=== OpenAI + Tenuo Tier 1 Guardrails ===\n")
    print("This example shows Tier 1 (no cryptography) protection:")
    print("  - Allowlist/denylist for tools")
    print("  - Argument constraints (Pattern, Range, OneOf, etc.)")
    print("  - Type-strict validation\n")
    
    demo_constraint_violation()
    demo_tool_denied()
    demo_valid_call()
    demo_skip_mode()
    demo_real_openai()
    
    print("=" * 60)
    print("For Tier 2 (cryptographic warrants), see:")
    print("  - tenuo-python/examples/langchain_simple.py")
    print("  - tenuo-python/tenuo/openai-adapter-spec-v2.2.md")
    print("=" * 60)


if __name__ == "__main__":
    main()
