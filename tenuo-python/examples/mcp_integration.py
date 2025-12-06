#!/usr/bin/env python3
"""
MCP (Model Context Protocol) Integration Example

Demonstrates:
- Loading MCP configuration
- Extracting constraints from MCP tool calls
- Authorizing MCP operations
"""

from tenuo import McpConfig, CompiledMcpConfig, Authorizer, PublicKey, Keypair, Warrant

def main():
    print("=== Tenuo Python SDK - MCP Integration ===\n")
    
    # 1. Load MCP configuration
    print("1. Loading MCP configuration...")
    try:
        config = McpConfig.from_file("../../examples/mcp-config.yaml")
        compiled = CompiledMcpConfig.compile(config)
        print("   ✓ Configuration loaded and compiled")
    except FileNotFoundError:
        print("   ⚠ mcp-config.yaml not found, using example config...")
        # For demo purposes, we'll show the concept
        print("   (In production, load from actual mcp-config.yaml)")
        return
    
    # 2. Initialize authorizer
    print("\n2. Initializing authorizer...")
    control_keypair = Keypair.generate()
    authorizer = Authorizer.new(control_keypair.public_key())
    print(f"   Control plane public key: {bytes(control_keypair.public_key().to_bytes())[:16].hex()}...")
    
    # 3. Create a warrant for filesystem operations
    print("\n3. Creating warrant for filesystem operations...")
    warrant = Warrant.create(
        tool="filesystem_read",
        constraints={
            "path": Pattern("/var/log/*"),
            "maxSize": Range.max_value(1024 * 1024)  # 1MB max
        },
        ttl_seconds=3600,
        keypair=control_keypair
    )
    print(f"   Tool: {warrant.tool()}")
    print(f"   Constraints: path=/var/log/*, maxSize<=1MB")
    
    # 4. Simulate MCP tool call
    print("\n4. Simulating MCP tool call...")
    mcp_arguments = {
        "path": "/var/log/app.log",
        "maxSize": 512 * 1024  # 512KB
    }
    print(f"   MCP arguments: {mcp_arguments}")
    
    # 5. Extract constraints from MCP call
    print("\n5. Extracting constraints from MCP call...")
    result = compiled.extract_constraints("filesystem_read", mcp_arguments)
    print(f"   Extracted constraints: {result.constraints}")
    print(f"   All fields extracted: {result.all_extracted()}")
    
    # 6. Authorize the operation
    print("\n6. Authorizing operation...")
    # Note: In real usage, you'd need a PoP signature
    # For demo, we'll just show the extracted constraints
    print(f"   ✓ Constraints extracted successfully")
    print(f"   Path: {result.constraints.get('path', 'N/A')}")
    print(f"   MaxSize: {result.constraints.get('maxSize', 'N/A')}")
    
    # Check if warrant authorizes these constraints
    authorized = warrant.authorize(
        tool="filesystem_read",
        args=result.constraints
    )
    print(f"   Authorization result: {authorized}")
    print()
    
    print("=== MCP Integration example completed! ===")
    print("\nNote: In production, you would:")
    print("  1. Receive MCP tool call from AI agent")
    print("  2. Extract constraints using CompiledMcpConfig")
    print("  3. Verify warrant chain with Authorizer.check()")
    print("  4. Allow or deny the operation based on authorization")

if __name__ == "__main__":
    main()

