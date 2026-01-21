#!/usr/bin/env python3
"""
Tenuo OpenAI Integration - Async Examples

Demonstrates async client wrapping, async streaming with TOCTOU protection,
and async patterns for production use.

Requirements:
    uv pip install tenuo openai

Usage:
    # Demo mode (no API key needed)
    python openai_async.py

    # With real OpenAI API
    export OPENAI_API_KEY="sk-..."
    python openai_async.py
"""

import asyncio

from tenuo.openai import (
    guard,
    Subpath,
    Pattern,
    Range,
)
from tenuo import SigningKey, Warrant

# Check if OpenAI is available
try:
    import openai

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Note: openai not installed. Running in demo mode.")
    print("Install with: uv pip install openai")
    print()


# =============================================================================
# Demo 1: Async Client Wrapping
# =============================================================================


async def demo_async_client():
    """
    Wrap an async OpenAI client with Tenuo guardrails.

    The guard() function works with both sync and async clients.
    """
    print("=" * 60)
    print("Demo 1: Async Client Wrapping")
    print("=" * 60)

    if not OPENAI_AVAILABLE:
        print("Skipping: openai not installed")
        print()
        return

    # Create async client with guardrails
    client = guard(
        openai.AsyncOpenAI(),
        allow_tools=["search", "read_file"],
        constraints={
            "read_file": {"path": Subpath("/data")},
            "search": {"max_results": Range(1, 20)},
        },
        on_denial="log",  # Log violations during development
    )

    print("Created async guarded client")
    print(f"  Allowed tools: {client._guard_config.allow_tools}")
    print(f"  Constraints: {list(client._guard_config.constraints.keys())}")
    print()

    # Validate configuration before making calls
    try:
        client.validate()
        print("Configuration validated successfully")
    except Exception as e:
        print(f"Configuration error: {e}")
    print()


# =============================================================================
# Demo 2: Async Streaming with TOCTOU Protection
# =============================================================================


async def demo_async_streaming():
    """
    Async streaming with buffer-verify-emit TOCTOU protection.

    Tenuo buffers tool call chunks, verifies the complete JSON,
    then emits. This prevents timing attacks where malicious content
    is injected mid-stream.
    """
    print("=" * 60)
    print("Demo 2: Async Streaming with TOCTOU Protection")
    print("=" * 60)

    if not OPENAI_AVAILABLE:
        print("Skipping: openai not installed")
        print()
        return

    # Create async client (prefixed _ to indicate demo-only)
    _client = guard(
        openai.AsyncOpenAI(),
        allow_tools=["analyze_document"],
        constraints={
            "analyze_document": {
                "path": Subpath("/documents"),
                "max_pages": Range(1, 100),
            },
        },
    )

    print("Streaming protection flow:")
    print("  1. BUFFER: Accumulate tool_call chunks silently")
    print("  2. VERIFY: On completion, check tool + constraints")
    print("  3. EMIT: Yield verified call OR raise denial")
    print()

    # Example: How streaming would work (without actual API call)
    print("Example code for async streaming:")
    print("""
    async for chunk in client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Analyze /documents/report.pdf"}],
        tools=[ANALYZE_DOCUMENT_TOOL],
        stream=True,
    ):
        # Tool calls only emitted after verification
        if chunk.choices[0].delta.tool_calls:
            print(f"Verified tool call: {chunk.choices[0].delta.tool_calls}")
        else:
            print(chunk.choices[0].delta.content or "", end="")
    """)
    print()


# =============================================================================
# Demo 3: Async with Warrants (Tier 2)
# =============================================================================


async def demo_async_warrant():
    """
    Async client with Tier 2 warrant-based authorization.

    Shows cryptographic Proof-of-Possession with async client.
    """
    print("=" * 60)
    print("Demo 3: Async with Warrants (Tier 2)")
    print("=" * 60)

    if not OPENAI_AVAILABLE:
        print("Skipping: openai not installed")
        print()
        return

    # Setup keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    print(f"Control plane key: {control_key.public_key.to_bytes().hex()[:16]}...")
    print(f"Agent key: {agent_key.public_key.to_bytes().hex()[:16]}...")

    # Issue warrant
    warrant = (
        Warrant.mint_builder()
        .capability("send_notification", {"channel": Pattern("#alerts-*")})
        .capability("query_metrics", {"time_range": Range(1, 3600)})
        .holder(agent_key.public_key)
        .ttl(3600)
        .mint(control_key)
    )

    print(f"Warrant ID: {warrant.id}")
    print()

    # Create async client with warrant (prefixed _ to indicate demo-only)
    _client = guard(
        openai.AsyncOpenAI(),
        warrant=warrant,
        signing_key=agent_key,
    )

    print("Created async Tier 2 client")
    print("  Each tool call will include Proof-of-Possession signature")
    print()


# =============================================================================
# Demo 4: Concurrent Tool Calls
# =============================================================================


async def demo_concurrent_calls():
    """
    Handle concurrent tool calls safely.

    Tenuo's guardrails are async-safe and can handle multiple
    concurrent calls without race conditions.
    """
    print("=" * 60)
    print("Demo 4: Concurrent Tool Calls")
    print("=" * 60)

    if not OPENAI_AVAILABLE:
        print("Skipping: openai not installed")
        print()
        return

    _client = guard(
        openai.AsyncOpenAI(),
        allow_tools=["fetch_data", "process_data", "store_result"],
        constraints={
            "fetch_data": {"source": Pattern("https://*.internal.com/*")},
            "store_result": {"destination": Subpath("/results")},
        },
    )

    print("Concurrent call pattern:")
    print("""
    async def process_batch(items: list[str]) -> list[dict]:
        # Create multiple concurrent tasks
        tasks = [
            client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": f"Process: {item}"}],
                tools=[FETCH_TOOL, PROCESS_TOOL, STORE_TOOL],
            )
            for item in items
        ]

        # Execute concurrently - each call is independently guarded
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle results
        for i, result in enumerate(results):
            if isinstance(result, ToolDenied):
                print(f"Item {i} denied: {result.tool_name}")
            elif isinstance(result, Exception):
                print(f"Item {i} error: {result}")
            else:
                print(f"Item {i} success")

        return [r for r in results if not isinstance(r, Exception)]
    """)
    print()


# =============================================================================
# Demo 5: Async Context Manager Pattern
# =============================================================================


async def demo_context_manager():
    """
    Using async context managers for scoped authorization.

    Useful when you need different authorization scopes
    within the same async flow.
    """
    print("=" * 60)
    print("Demo 5: Async Context Manager Pattern")
    print("=" * 60)

    print("Pattern for scoped authorization:")
    print("""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def authorized_scope(warrant: Warrant, key: SigningKey):
        \"\"\"Create a temporarily authorized client.\"\"\"
        client = guard(
            openai.AsyncOpenAI(),
            warrant=warrant,
            signing_key=key,
        )
        try:
            yield client
        finally:
            # Cleanup if needed
            pass

    # Usage
    async def handle_request(user_warrant: Warrant, user_key: SigningKey):
        async with authorized_scope(user_warrant, user_key) as client:
            # All calls within this scope use user's warrant
            response = await client.chat.completions.create(...)
            return response
    """)
    print()


# =============================================================================
# Demo 6: Error Handling in Async
# =============================================================================


async def demo_async_error_handling():
    """
    Proper async error handling with Tenuo guardrails.
    """
    print("=" * 60)
    print("Demo 6: Async Error Handling")
    print("=" * 60)

    print("Error handling pattern:")
    print("""
    from tenuo.openai import (
        guard,
        ToolDenied,
        ConstraintViolation,
        WarrantDenied,
        MalformedToolCall,
    )

    async def safe_tool_call(client, messages, tools):
        try:
            response = await client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=tools,
            )
            return {"success": True, "response": response}

        except ToolDenied as e:
            # Tool not in allowlist
            return {"success": False, "error": f"Tool '{e.tool_name}' not allowed"}

        except ConstraintViolation as e:
            # Argument failed constraint
            return {"success": False, "error": f"Constraint violation: {e}"}

        except WarrantDenied as e:
            # Warrant doesn't allow this operation
            return {"success": False, "error": f"Warrant denied: {e}"}

        except MalformedToolCall as e:
            # Invalid JSON in tool arguments
            return {"success": False, "error": f"Malformed tool call: {e}"}

        except openai.APIError as e:
            # OpenAI API error (network, rate limit, etc.)
            return {"success": False, "error": f"API error: {e}"}
    """)
    print()


# =============================================================================
# Main
# =============================================================================


async def main():
    print()
    print("Tenuo OpenAI Integration - Async Examples")
    print("=========================================")
    print()

    await demo_async_client()
    await demo_async_streaming()
    await demo_async_warrant()
    await demo_concurrent_calls()
    await demo_context_manager()
    await demo_async_error_handling()

    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(
        """
Key async patterns:

1. **Async Client**: guard(openai.AsyncOpenAI(), ...)
   - Same API as sync, works with await

2. **Streaming**: Buffer-verify-emit pattern
   - Tool calls only emitted after full verification
   - Prevents TOCTOU attacks in streaming responses

3. **Concurrent Calls**: asyncio.gather() friendly
   - Each call independently guarded
   - No race conditions

4. **Tier 2**: Warrant + PoP works identically
   - Signatures generated per-call
   - Async-safe signature generation

5. **Error Handling**: Same exceptions
   - ToolDenied, ConstraintViolation, WarrantDenied
   - Use try/except as normal

For more information:
  - Documentation: https://tenuo.dev/docs/openai
  - Examples: https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples
"""
    )


if __name__ == "__main__":
    asyncio.run(main())

