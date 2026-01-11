#!/usr/bin/env python3
"""
LangChain + Tenuo + MCP Integration Example

Demonstrates:
- Using Tenuo to authorize MCP tool calls
- LangChain agent with MCP tools
- Warrant-based constraint enforcement
- End-to-end authorization flow

This example shows how to combine:
1. LangChain - Agent framework
2. Tenuo - Authorization layer
3. MCP - Tool protocol

Pattern: LangChain connects → Tenuo authorizes → MCP executes
"""

from tenuo import (
    Authorizer,
    SigningKey,
    Warrant,
    Pattern,
    Range,
    guard,
    warrant_scope,
    key_scope,
)
from tenuo_core import CompiledMcpConfig, McpConfig


def main():
    print("=== LangChain + Tenuo + MCP Integration ===\n")

    # =========================================================================
    # 1. Setup: Load MCP Configuration
    # =========================================================================
    print("1. Loading MCP configuration...")

    # Try multiple paths for demo
    config_paths = [
        "../../examples/mcp-config.yaml",
        "../examples/mcp-config.yaml",
        "examples/mcp-config.yaml",
    ]

    config = None
    for path in config_paths:
        try:
            config = McpConfig.from_file(path)
            print(f"   ✓ Loaded config from: {path}")
            break
        except Exception:
            continue

    if config is None:
        print("   ⚠ mcp-config.yaml not found")
        print("   Continuing with simulated MCP tools...\n")
        demo_without_config()
        return

    # Compile configuration for fast extraction
    compiled = CompiledMcpConfig.compile(config)

    # Validate (warns about incompatible extraction sources)
    warnings = compiled.validate()
    if warnings:
        print("   ⚠ Configuration warnings:")
        for warning in warnings:
            print(f"     - {warning}")
    else:
        print("   ✓ Configuration validated")

    # =========================================================================
    # 2. Setup: Create Keypairs and Authorizer
    # =========================================================================
    print("\n2. Setting up authorization...")

    # Control plane keypair (issues root warrants)
    control_keypair = SigningKey.generate()

    # Worker keypair (executes MCP tools)
    worker_keypair = SigningKey.generate()

    # Create authorizer with trusted root
    authorizer = Authorizer(trusted_roots=[control_keypair.public_key])
    print("   ✓ Authorizer initialized")
    print(f"   Control plane key: {bytes(control_keypair.public_key.to_bytes())[:8].hex()}...")
    print(f"   Worker key: {bytes(worker_keypair.public_key.to_bytes())[:8].hex()}...")

    # =========================================================================
    # 3. Define MCP Tools (Simulated)
    # =========================================================================
    print("\n3. Defining MCP tools...")

    # In production, these would call actual MCP servers
    # For demo, we simulate the MCP tool behavior

    @guard(tool="filesystem_read")
    def filesystem_read(path: str, max_size: int = 1048576) -> str:
        """
        Read file from filesystem (MCP tool).

        In production, this would:
        1. Connect to MCP filesystem server
        2. Send read request with path and max_size
        3. Return file contents

        For demo, we simulate the response.
        """
        print(f"      [MCP] Reading file: {path} (max {max_size} bytes)")
        return f"[Simulated content of {path}]"

    @guard(tool="database_query")
    def database_query(table: str, operation: str, limit: int = 100) -> str:
        """
        Execute database query (MCP tool).

        In production, this would:
        1. Connect to MCP database server
        2. Execute query with constraints
        3. Return results

        For demo, we simulate the response.
        """
        print(f"      [MCP] Querying table: {table}, operation: {operation}, limit: {limit}")
        return f"[Simulated query results from {table}]"

    print("   ✓ MCP tools defined:")
    print("     - filesystem_read")
    print("     - database_query")

    # =========================================================================
    # 4. Mint Root Warrant (Control Plane)
    # =========================================================================
    print("\n4. Minting root warrant...")

    # Mint warrant for filesystem_read only (simpler demo)
    root_warrant = (
        Warrant.mint_builder()
        .capability(
            "filesystem_read", path=Pattern("/var/log/*"), max_size=Range.max_value(1024 * 1024)
        )  # Match MCP extraction name
        .holder(worker_keypair.public_key)  # Bind to worker
        .ttl(3600)
        .mint(control_keypair)
    )

    print("   ✓ Root warrant issued")
    print(f"   Tools: {root_warrant.tools}")
    print("   Constraints: path=/var/log/*, max_size≤1MB")

    # =========================================================================
    # 5. Execute MCP Tools with Authorization
    # =========================================================================
    print("\n5. Executing MCP tools with authorization...\n")

    # Set warrant context for authorization
    with warrant_scope(root_warrant), key_scope(worker_keypair):
        # =====================================================================
        # Test 1: Authorized filesystem read
        # =====================================================================
        print("   Test 1: Authorized filesystem read")
        try:
            result = filesystem_read("/var/log/app.log", max_size=512 * 1024)
            print(f"      ✓ Success: {result}")
        except Exception as e:
            print(f"      ✗ Failed: {e}")

        # =====================================================================
        # Test 2: Unauthorized filesystem read (path violation)
        # =====================================================================
        print("\n   Test 2: Unauthorized filesystem read (path violation)")
        try:
            result = filesystem_read("/etc/passwd", max_size=512 * 1024)
            print("      ✗ Should have been blocked!")
        except Exception as e:
            print(f"      ✓ Blocked as expected: {type(e).__name__}")

        # =====================================================================
        # Test 3: Size limit violation
        # =====================================================================
        print("\n   Test 3: Size limit violation")
        try:
            result = filesystem_read("/var/log/app.log", max_size=2 * 1024 * 1024)  # 2MB > 1MB limit
            print("      ✗ Should have been blocked!")
        except Exception as e:
            print(f"      ✓ Blocked as expected: {type(e).__name__}")

    # =========================================================================
    # 6. Demonstrate MCP Constraint Extraction
    # =========================================================================
    print("\n6. Demonstrating MCP constraint extraction...\n")

    # Simulate MCP tool call from LangChain agent
    mcp_arguments = {
        "path": "/var/log/app.log",
        "maxSize": 512 * 1024,
    }

    print(f"   MCP arguments: {mcp_arguments}")

    # Extract constraints using compiled config
    result = compiled.extract_constraints("filesystem_read", mcp_arguments)
    print(f"   Extracted tool: {result.tool}")
    print(f"   Extracted constraints: {dict(result.constraints)}")

    # Authorize with extracted constraints
    pop_sig = root_warrant.sign(worker_keypair, "filesystem_read", dict(result.constraints))

    try:
        authorizer.check(
            root_warrant,
            "filesystem_read",
            dict(result.constraints),
            bytes(pop_sig),
        )
        print("   ✓ Authorization successful")
    except Exception as e:
        print(f"   ✗ Authorization failed: {e}")

    # =========================================================================
    # 7. Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print("Summary: LangChain + Tenuo + MCP Integration")
    print("=" * 60)
    print("\n✓ MCP configuration loaded and compiled")
    print("✓ Warrants issued with constraints")
    print("✓ MCP tools protected with @guard")
    print("✓ Authorization enforced on every call")
    print("✓ Constraint extraction from MCP arguments")
    print("\nPattern:")
    print("  LangChain Agent → MCP Tool Call → Tenuo Authorization → MCP Server")
    print("\nKey Benefits:")
    print("  • Cryptographic proof of authorization")
    print("  • Automatic constraint extraction")
    print("  • Fail-closed security (deny by default)")
    print("  • Audit trail via warrant chains")
    print()


def demo_without_config():
    """
    Demo the integration pattern without MCP config file.
    Shows the authorization flow with simulated MCP tools.
    """
    print("=== Simulated MCP Integration (no config file) ===\n")

    # Setup
    control_keypair = SigningKey.generate()
    worker_keypair = SigningKey.generate()

    # Define simulated MCP tool
    @guard(tool="filesystem_read")
    def filesystem_read(path: str, max_size: int = 1048576) -> str:
        print(f"   [MCP] Reading: {path}")
        return f"[Content of {path}]"

    # Mint warrant
    warrant = (
        Warrant.mint_builder()
        .capability(
            "filesystem_read", path=Pattern("/var/log/*"), max_size=Range.max_value(1024 * 1024)
        )  # Match extraction name
        .holder(worker_keypair.public_key)
        .ttl(3600)
        .mint(control_keypair)
    )

    print("✓ Warrant issued: filesystem_read, path=/var/log/*, max_size≤1MB\n")

    # Execute with authorization
    with warrant_scope(warrant), key_scope(worker_keypair):
        print("Test 1: Authorized read")
        try:
            result = filesystem_read("/var/log/app.log", max_size=512 * 1024)
            print(f"   ✓ Success: {result}\n")
        except Exception as e:
            print(f"   ✗ Failed: {e}\n")

        print("Test 2: Unauthorized read (path violation)")
        try:
            result = filesystem_read("/etc/passwd")
            print("   ✗ Should have been blocked!\n")
        except Exception as e:
            print(f"   ✓ Blocked: {type(e).__name__}\n")

    print("=" * 60)
    print("Pattern: LangChain → Tenuo → MCP")
    print("=" * 60)


if __name__ == "__main__":
    main()
