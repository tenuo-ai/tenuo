#!/usr/bin/env python3
"""
Tenuo + MCP Full Integration Example.

Demonstrates connecting to a real MCP server with Tenuo authorization.

Prerequisites:
    pip install "tenuo[mcp]"

Usage:
    # Terminal 1: Start MCP server
    python mcp_server_demo.py

    # Terminal 2: Run client
    python mcp_client_demo.py
"""

import asyncio
from pathlib import Path

from tenuo import (
    SigningKey,
    configure,
    mint,
    Pattern,
    Range,
    Capability,
)
from tenuo.mcp import SecureMCPClient, MCP_AVAILABLE


async def main():
    if not MCP_AVAILABLE:
        print("❌ MCP SDK not installed")
        print('   Install with: pip install "tenuo[mcp]"')
        return

    print("=== Tenuo + MCP Full Integration Demo ===\n")

    # Setup Tenuo
    print("1. Configuring Tenuo...")
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    print("   ✓ Tenuo configured")

    # Find MCP server script
    server_script = Path(__file__).parent / "mcp_server_demo.py"
    if not server_script.exists():
        print(f"\n❌ MCP server script not found: {server_script}")
        print("   Make sure mcp_server_demo.py is in the same directory")
        return

    print(f"2. Connecting to MCP server: {server_script.name}")

    try:
        # register_config=True enables global configuration for @guard decorators
        # This allows Tenuo to verify arguments without explicit extraction logic in code
        async with SecureMCPClient(
            command="python",
            args=[str(server_script)],
            register_config=True,
        ) as client:
            print("   ✓ Connected to MCP server")

            # Discover tools
            print("\n3. Discovering tools...")
            tools = await client.get_tools()
            print(f"   ✓ Found {len(tools)} tools:")
            for tool in tools:
                print(f"     - {tool.name}: {tool.description}")

            # Get protected wrappers
            print("\n4. Creating protected tool wrappers...")
            protected_tools = client.tools
            print(f"   ✓ {len(protected_tools)} tools protected")

            # Use with task scoping
            print("\n5. Executing with warrant authorization...")

            # Create test file
            test_file = Path("/tmp/tenuo_mcp_test.txt")
            test_file.write_text("Hello from Tenuo + MCP!")
            print(f"   ✓ Created test file: {test_file}")

            async with mint(
                Capability("read_file", path=Pattern("/tmp/*"), max_size=Range.max_value(10000))
            ):
                # Pattern A: Call through protected wrapper (local authorization)
                print("\n   Pattern A: Local authorization (default)")
                read_file = protected_tools["read_file"]
                result = await read_file(path=str(test_file), max_size=1000)

                print("   ✓ Tool call authorized locally")
                print(f"   Result: {result[0].text if result else 'No content'}")

                # Pattern B: Inject warrant for remote authorization
                print("\n   Pattern B: Remote authorization (warrant injection)")
                _ = await client.call_tool(
                    "read_file",
                    {"path": str(test_file), "max_size": 1000},
                    warrant_context=True,
                    inject_warrant=True  # ← Injects _tenuo field
                )
                print("   ✓ Warrant injected into arguments._tenuo")
                print("   ✓ Warrant injected into arguments._tenuo")
                print("   (MCP server can extract and verify if configured)")
                print("   ⚠️  Note: If the server uses strict JSON schema validation (additionalProperties: false),")
                print("       this call might fail. Ensure your server allows the '_tenuo' field.")

                # Try unauthorized call (should fail)
                print("\n6. Testing constraint enforcement...")
                try:
                    await read_file(path="/etc/passwd", max_size=1000)
                    print("   ❌ Should have been blocked!")
                except Exception as e:
                    print(f"   ✓ Blocked: {type(e).__name__}")

            print("\n=== Demo Complete ===")
            print("\n✓ MCP server integrated with Tenuo authorization")
            print("✓ Tool calls cryptographically authorized")
            print("✓ Constraints enforced at runtime")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
