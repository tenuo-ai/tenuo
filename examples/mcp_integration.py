#!/usr/bin/env python3
"""
Tenuo MCP Integration Example: "The Junior Debugger"

This example demonstrates Tenuo's core value: CAPABILITY ATTENUATION.

SCENARIO:
1.  **Orchestrator** (System) has a Root Warrant allowing access to ALL logs (`/var/log/*`).
2.  **Junior Agent** (AI) is tasked with debugging a specific app crash.
3.  **Delegation**: The Orchestrator issues a *narrow* Task Warrant to the Agent,
    allowing access ONLY to `/var/log/app.log` and nothing else.
4.  **Binding**: The System defines a Binding Contract (MCP Config) that maps
    MCP tool arguments (JSON) to Tenuo Constraints.
5.  **Proof-of-Possession (PoP)**: The Agent signs the request to prove it owns the warrant.
6.  **Enforcement**: The Agent tries to access a sensitive file (`/var/log/auth.log`)
    and is cryptographically blocked.

This proves that you can safely delegate tasks to AI agents without giving them
your full keys to the kingdom.
"""

import sys
import os
import time
from tenuo import (
    McpConfig, CompiledMcpConfig, Authorizer, Keypair, Warrant, 
    Pattern, Exact, Range, PublicKey
)

# =========================================================================
# DEMO CONFIGURATION (The "Binding Contract")
# =========================================================================
MCP_CONFIG_CONTENT = """
version: "1"
settings:
  trusted_issuers: []
tools:
  filesystem_read:
    description: "Read files from the filesystem"
    constraints:
      path:
        from: body       # Extract from the tool arguments object
        path: "path"     # Map argument "path" -> constraint "path"
        required: true
      max_size:
        from: body
        path: "maxSize"  # Map argument "maxSize" -> constraint "max_size"
        type: integer
"""

CONFIG_FILENAME = "mcp-config-demo.yaml"

def main():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║             Tenuo MCP Integration: Capability Delegation         ║")
    print("╚══════════════════════════════════════════════════════════════════╝\n")

    # Write config file
    with open(CONFIG_FILENAME, "w") as f:
        f.write(MCP_CONFIG_CONTENT)
    print(f"1. [SETUP] Wrote binding contract to {CONFIG_FILENAME}")

    try:
        run_demo()
    finally:
        if os.path.exists(CONFIG_FILENAME):
            os.remove(CONFIG_FILENAME)
            print(f"\n[CLEANUP] Removed {CONFIG_FILENAME}")

def run_demo():
    # =========================================================================
    # STEP 1: LOAD BINDING CONFIGURATION
    # =========================================================================
    print("2. [BINDING] Loading MCP Configuration...")
    try:
        raw_config = McpConfig.from_file(CONFIG_FILENAME)
        mcp_config = CompiledMcpConfig.compile(raw_config)
        print("   ✓ Configuration loaded and compiled.")
    except Exception as e:
        print(f"   ❌ Failed to load config: {e}")
        return

    # =========================================================================
    # STEP 2: IDENTITY SETUP
    # =========================================================================
    print("\n3. [IDENTITY] Establishing Identities...")
    
    control_plane_key = Keypair.generate()
    orchestrator_key  = Keypair.generate()
    junior_agent_key  = Keypair.generate()

    print(f"   ✓ Control Plane (Trust Anchor): {bytes(control_plane_key.public_key().to_bytes()).hex()[:16]}...")
    print(f"   ✓ Orchestrator  (System Admin): {bytes(orchestrator_key.public_key().to_bytes()).hex()[:16]}...")
    print(f"   ✓ Junior Agent  (AI Debugger):  {bytes(junior_agent_key.public_key().to_bytes()).hex()[:16]}...")


    # =========================================================================
    # STEP 3: ROOT WARRANT ISSUANCE
    # =========================================================================
    print("\n4. [ISSUANCE] Control Plane issues Root Warrant to Orchestrator...")
    
    root_warrant = Warrant.create(
        tool="filesystem_read",
        constraints={
            "path": Pattern("/var/log/*"),
            "max_size": Range.max_value(10 * 1024 * 1024)
        },
        ttl_seconds=86400,
        keypair=control_plane_key,
        authorized_holder=orchestrator_key.public_key(),  # PoP is mandatory
    )
    
    print(f"   ✓ Root Warrant ID: {root_warrant.id}")
    print(f"   ✓ Scope:  path=/var/log/* (BROAD)")


    # =========================================================================
    # STEP 4: ATTENUATION (DELEGATION)
    # =========================================================================
    print("\n5. [ATTENUATION] Orchestrator delegates task to Junior Agent...")
    print("   Task: 'Debug the application crash in app.log'")
    
    # The Orchestrator creates a CHILD warrant bound to the Junior Agent's Public Key.
    task_warrant = root_warrant.attenuate(
        constraints={
            "path": Exact("/var/log/app.log"),
            "max_size": Range.max_value(1 * 1024 * 1024)
        },
        keypair=orchestrator_key,
        authorized_holder=junior_agent_key.public_key()
    )
    
    print(f"   ✓ Task Warrant ID: {task_warrant.id}")
    print(f"   ✓ Holder:          Junior Agent (Bound to Key)")
    print(f"   ✓ Scope:           path=/var/log/app.log (NARROW)")


    # =========================================================================
    # STEP 5: MCP TOOL EXECUTION (The "Runtime")
    # =========================================================================
    print("\n6. [RUNTIME] Agent attempts MCP tool calls...")

    # Initialize the Authorizer
    authorizer = Authorizer.new(control_plane_key.public_key())

    # --- SCENARIO A: Agent does its job (Reads app.log) ---
    print("\n   [Case A] Agent tries to read '/var/log/app.log'...")
    
    mcp_tool_name = "filesystem_read"
    mcp_args_a = {"path": "/var/log/app.log", "maxSize": 1024}
    print(f"   Incoming Call: {mcp_tool_name}({mcp_args_a})")

    # 1. PoP: Agent signs the request to prove ownership
    # SECURITY: We use create_pop_signature() which signs:
    # (warrant_id, tool, canonical_args, timestamp)
    # This prevents REPLAY ATTACKS where a signature for one action
    # is reused for another.
    try:
        # 2. BINDING
        extraction = mcp_config.extract_constraints(mcp_tool_name, mcp_args_a)
        
        # Generate secure PoP signature over the EXTRACTED constraints
        pop_signature = task_warrant.create_pop_signature(
            junior_agent_key,
            extraction.tool,
            extraction.constraints
        )
        print("   ✓ PoP Signature generated (Secure: binds to args + timestamp)")
        
        # 3. VERIFICATION
        authorizer.check(
            task_warrant, 
            extraction.tool, 
            extraction.constraints, 
            pop_signature
        )
        print("   ✅ AUTHORIZED: Agent allowed to read app.log")
    except Exception as e:
        print(f"   ❌ DENIED: {e}")


    # --- SCENARIO B: Agent goes rogue (Reads auth.log) ---
    print("\n   [Case B] Agent tries to read '/var/log/auth.log' (Sensitive!)...")
    
    mcp_args_b = {"path": "/var/log/auth.log", "maxSize": 1024}
    print(f"   Incoming Call: {mcp_tool_name}({mcp_args_b})")
    
    try:
        # 2. BINDING
        extraction = mcp_config.extract_constraints(mcp_tool_name, mcp_args_b)
        print(f"   Bound Constraints: {extraction.constraints}")

        # Generate secure PoP signature
        pop_signature_b = task_warrant.create_pop_signature(
            junior_agent_key,
            extraction.tool,
            extraction.constraints
        )

        # 3. VERIFICATION
        authorizer.check(
            task_warrant, 
            extraction.tool, 
            extraction.constraints, 
            pop_signature_b
        )
        print("   ✅ AUTHORIZED: (This should not happen!)")
    except Exception as e:
        print(f"   🛡️  BLOCKED: {e}")
        print("      (Tenuo correctly prevented access outside the delegated scope)")


    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║                       DEMO COMPLETE                              ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║ Key Takeaway:                                                    ║")
    print("║ 1. Binding Contract mapped arguments to constraints.             ║")
    print("║ 2. Proof-of-Possession (PoP) proved the Agent held the warrant.  ║")
    print("║ 3. Attenuation restricted the Agent to a safe subset.            ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

if __name__ == "__main__":
    main()
