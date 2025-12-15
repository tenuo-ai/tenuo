#!/usr/bin/env python3
"""
MCP (Model Context Protocol) Integration Example

Demonstrates:
- Loading MCP configuration
- Extracting constraints from MCP tool calls
- Authorizing MCP operations
"""

from tenuo import McpConfig, CompiledMcpConfig, Authorizer, Keypair, Warrant, Pattern, Range

def main():
    print("=== Tenuo Python SDK - MCP Integration ===\n")
    
    # 1. Load MCP configuration
    print("1. Loading MCP configuration...")
    # HARDCODED PATH: Try multiple locations for demo
    # In production: Use env var or config to specify path
    config_paths = [
        "../../examples/mcp-config.yaml",  # From tenuo-python/examples/
        "../examples/mcp-config.yaml",    # Alternative path
        "examples/mcp-config.yaml",        # From repo root
    ]
    
    config = None
    for path in config_paths:
        try:
            config = McpConfig.from_file(path)
            print(f"   [OK] Configuration loaded from: {path}")
            break
        except Exception as e:
            # print(f"   [DEBUG] Failed to load from {path}: {e}")
            continue
    
    if config is None:
        print("   ⚠ mcp-config.yaml not found in any standard location")
        print("   [SIMULATION] Continuing with demo using mock extraction...")
        print("   (In production, ensure mcp-config.yaml exists)")
        # Continue with demo - we'll show the pattern even without config file
        # Note: control_keypair needs to be defined first
        control_keypair = Keypair.generate()
        demo_without_config(control_keypair)
        return
    
    try:
        compiled = CompiledMcpConfig.compile(config)
        print("   [OK] Configuration compiled successfully")
    except Exception as e:
        print(f"   [ERR] Error compiling configuration: {e}")
        return
    
    # 2. Initialize authorizer
    print("\n2. Initializing authorizer...")
    try:
        # SIMULATION: Generate keypair for demo
        # In production: Control plane keypair is loaded from secure storage
        control_keypair = Keypair.generate()
        
        # Get public key object (method call, not property)
        public_key = control_keypair.public_key
        
        # Create authorizer with public key
        # HARDCODED: Using generated keypair for demo
        # In production: Load public key from K8s Secret or config
        authorizer = Authorizer(trusted_roots=[public_key])
        
        # Display public key (first 8 bytes for brevity)
        # Note: to_bytes() returns a list/vector, convert to bytes for hex()
        pub_key_bytes = public_key.to_bytes()
        pub_key_bytes_obj = bytes(pub_key_bytes)  # Convert list to bytes
        print("   [OK] Authorizer initialized")
        print(f"   Control plane public key: {pub_key_bytes_obj[:8].hex()}...")
    except Exception as e:
        print(f"   [ERR] Error initializing authorizer: {e}")
        return
    
    # 3. Create a warrant for filesystem operations
    print("\n3. Creating warrant for filesystem operations...")
    try:
        # SIMULATION: Create warrant with hardcoded constraints
        # In production: Constraints come from policy engine or configuration
        # HARDCODED: Pattern("/var/log/*"), Range.max_value(1MB)
        # Note: Constraint names must match what MCP config extracts
        # MCP config extracts "max_size" (snake_case), but we'll use "maxSize" (camelCase)
        # In production, ensure warrant constraint names match MCP extraction names
        warrant = Warrant.issue(
            tools="filesystem_read",
            constraints={
                "path": Pattern("/var/log/*"),  # HARDCODED: Only /var/log/ files for demo
                "max_size": Range.max_value(1024 * 1024)  # HARDCODED: Match MCP extraction name "max_size"
            },
            ttl_seconds=3600,  # HARDCODED: 1 hour TTL. In production, use env var or config.
            keypair=control_keypair,
            holder=control_keypair.public_key # Bind to self for demo
        )
        # Note: warrant.tools is a property (getter) returning a list
        print("   [OK] Warrant created")
        print(f"   Tools: {warrant.tools}")
        print("   Constraints: path=/var/log/*, max_size<=1MB")
    except Exception as e:
        print(f"   [ERR] Error creating warrant: {e}")
        return
    
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
    print(f"   Extracted tool: {result.tool}")
    print(f"   Extracted constraints: {dict(result.constraints)}")
    
    # 6. Authorize the operation
    print("\n6. Authorizing operation...")
    # Convert result.constraints (PyObject) to dict for warrant.authorize
    constraints_dict = dict(result.constraints)
    print(f"   Extracted constraints: {constraints_dict}")
    
    # Note: MCP config extracts constraints with names matching the config (e.g., "max_size")
    # The warrant must use the same constraint names for authorization to work
    # In production, ensure MCP config constraint names match warrant constraint names
    
    # Check if warrant authorizes these constraints
    # Note: constraints_dict already has the correct names from MCP extraction
    try:
        # Create PoP signature
        pop_signature = warrant.create_pop_signature(control_keypair, "filesystem_read", constraints_dict)
        
        authorized = warrant.authorize(
            tool="filesystem_read",
            args=constraints_dict,  # Use extracted constraints directly (names match warrant)
            signature=bytes(pop_signature)
        )
        if authorized:
            print("   [OK] Warrant authorization: Allowed")
        else:
            print("   [ERR] Warrant authorization: Denied (constraints not satisfied)")
    except Exception as e:
        print(f"   [ERR] Warrant authorization error: {e}")
    
    # 7. Full authorization with Authorizer (verifies signature + constraints)
    print("\n7. Full authorization with Authorizer.check()...")
    try:
        # Authorizer.check() verifies:
        # 1. Warrant signature (signed by trusted issuer)
        # 2. Warrant expiration (not expired)
        # 3. Warrant revocation (not in revocation list)
        # 4. Constraint satisfaction (all constraints match)
        # Note: check() expects args as a dict - PyO3 automatically converts Python dict to PyDict
        # Note: signature parameter expects bytes (64 bytes) or None for PoP signature
        authorizer.check(warrant, "filesystem_read", constraints_dict, bytes(pop_signature))
        print("   ✓ Full authorization successful (signature + constraints verified)")
    except Exception as e:
        print(f"   ✗ Authorization failed: {e}")
        print("   (Check: constraint names match, warrant is signed by trusted issuer)")
    print()
    
    print("=== MCP Integration example completed! ===")
    print("\nNote: In production, you would:")
    print("  1. Receive MCP tool call from AI agent")
    print("  2. Extract constraints using CompiledMcpConfig")
    print("  3. Verify warrant chain with Authorizer.check()")
    print("  4. Allow or deny the operation based on authorization")


def demo_without_config(control_keypair):
    """
    [SIMULATION] Demo the MCP integration pattern without config file.
    Shows how extraction and authorization would work.
    """
    print("\n=== MCP Integration Pattern (without config file) ===\n")
    
    # Create warrant
    try:
        warrant = Warrant.issue(
            tools="filesystem_read",
            constraints={
                "path": Pattern("/var/log/*"),
                "maxSize": Range.max_value(1024 * 1024)
            },
            ttl_seconds=3600,
            keypair=control_keypair,
            holder=control_keypair.public_key
        )
        print(f"✓ Warrant created: {warrant.tools}")
    except Exception as e:
        print(f"✗ Error: {e}")
        return
    
    # Simulate MCP tool call
    mcp_arguments = {
        "path": "/var/log/app.log",
        "maxSize": 512 * 1024
    }
    print(f"\nSimulated MCP arguments: {mcp_arguments}")
    
    # In real usage, CompiledMcpConfig would extract these
    # For demo, we'll manually create the constraint dict
    extracted_constraints = {
        "path": "/var/log/app.log",
        "maxSize": 512 * 1024
    }
    print(f"Extracted constraints: {extracted_constraints}")
    
    # Authorize
    try:
        pop_sig = warrant.create_pop_signature(control_keypair, "filesystem_read", extracted_constraints)
        authorized = warrant.authorize("filesystem_read", extracted_constraints, bytes(pop_sig))
        print(f"\n✓ Warrant authorization: {authorized}")
        
        # Full authorization with Authorizer
        public_key = control_keypair.public_key
        authorizer = Authorizer(trusted_roots=[public_key])
        try:
            authorizer.check(warrant, "filesystem_read", extracted_constraints, bytes(pop_sig))
            print("✓ Full authorization (Authorizer.check): Success")
        except Exception as e:
            print(f"✗ Authorizer.check failed: {e}")
    except Exception as e:
        print(f"\n✗ Authorization failed: {e}")
if __name__ == "__main__":
    main()

