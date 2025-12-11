#!/usr/bin/env python3
"""
LangChain Integration Example with Tenuo

This example demonstrates the recommended pattern for integrating Tenuo with
LangChain agents and tools, following the principle:

    "ZERO TENUO IMPORTS IN USER CODE - tools and nodes are pure business logic"

The pattern:
1. Define tools as plain Python functions (NO Tenuo imports)
2. Wrap tools at setup time using protect_tools() from tenuo.langchain
3. Configure per-tool constraints via config file or dict

SECURITY BEST PRACTICES demonstrated:
- PoP (Proof-of-Possession) binding: Warrants are bound to the agent's identity
- Config-based constraints: Per-tool permissions defined in config
- Stolen warrants are useless without the matching private key

Requirements:
    pip install langchain langchain-openai tenuo

Note: This example uses OpenAI, but the pattern works with any LLM provider.
"""

import os
from typing import Optional

# ============================================================================
# STEP 1: Define Tools - PURE BUSINESS LOGIC (NO TENUO IMPORTS!)
# ============================================================================

# These are plain Python functions. They know nothing about Tenuo.
# Authorization is handled externally by the protect_tools() wrapper.

def read_file(file_path: str) -> str:
    """
    Read a file from the filesystem.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        File contents as string, or error message
    """
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: File {file_path} not found"
    except PermissionError:
        return f"Error: Permission denied reading {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"


def write_file(file_path: str, content: str) -> str:
    """
    Write content to a file.
    
    Args:
        file_path: Path to the file to write
        content: Content to write
        
    Returns:
        Success message or error
    """
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {file_path}"
    except PermissionError:
        return f"Error: Permission denied writing to {file_path}"
    except OSError as e:
        return f"Error: {str(e)}"


def execute_command(command: str) -> str:
    """
    Execute a shell command.
    
    WARNING: This is a demo function. In production, use a whitelist
    of allowed commands and proper sanitization.
    
    Args:
        command: Shell command to execute
        
    Returns:
        Command output or error message
    """
    import subprocess
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout or "(no output)"
        else:
            return f"Error (exit code {result.returncode}): {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 10 seconds"
    except Exception as e:
        return f"Error: {str(e)}"


# ============================================================================
# STEP 2: Configuration Notes
# ============================================================================

# Per-tool constraints can be defined in two ways:
# 1. Via config dict/file passed to protect_tools() - see file_config below
# 2. Via constraints in the warrant itself - see cmd_warrant below
#
# Example tenuo.yaml file:
#   version: "1"
#   tools:
#     read_file:
#       constraints:
#         file_path:
#           pattern: "/tmp/*"
#     write_file:
#       constraints:
#         file_path:
#           pattern: "/tmp/output/*"


# ============================================================================
# STEP 3: Main Integration
# ============================================================================

def main():
    """
    Main function demonstrating LangChain + Tenuo integration.
    """
    print("=== Tenuo + LangChain Integration Example ===\n")
    print("Pattern: 'Zero Tenuo imports in user code'\n")
    
    # ========================================================================
    # Import Tenuo ONLY in the setup/wiring code
    # ========================================================================
    from tenuo import Keypair, Warrant, Pattern, AuthorizationError
    from tenuo.langchain import protect_tools
    
    # ========================================================================
    # Create Keypairs
    # In production: Control plane keypair loaded from secure storage
    # ========================================================================
    print("1. Creating keypairs...")
    control_keypair = Keypair.generate()  # Control plane (issuer)
    agent_keypair = Keypair.generate()    # Agent's identity
    print("   ✓ Control plane and agent keypairs created\n")
    
    # ========================================================================
    # Create Root Warrants (one per tool type for cleaner constraint handling)
    # In production: These come from your control plane
    # ========================================================================
    print("2. Creating warrants...")
    
    # For file operations - constrain to /tmp/
    file_warrant = Warrant.create(
        tool="*",  # Will be attenuated to read_file/write_file
        constraints={"file_path": Pattern("/tmp/**")},
        ttl_seconds=3600,
        keypair=control_keypair,
        authorized_holder=agent_keypair.public_key()
    )
    
    # For command execution - no path constraint needed
    from tenuo import OneOf
    cmd_warrant = Warrant.create(
        tool="execute_command",
        constraints={"command": OneOf(["ls", "pwd", "date", "whoami"])},
        ttl_seconds=3600,
        keypair=control_keypair,
        authorized_holder=agent_keypair.public_key()
    )
    
    print(f"   ✓ File warrant created: {file_warrant.id}")
    print(f"   ✓ Command warrant created: {cmd_warrant.id}")
    print(f"   ✓ PoP-bound: True\n")
    
    # ========================================================================
    # Wrap Tools with Tenuo Protection
    # This is where the magic happens - tools get their specific warrants
    # ========================================================================
    print("3. Wrapping tools with protect_tools()...")
    
    # File tools share the file_warrant (attenuated per-tool via config)
    file_config = {
        "version": "1",
        "tools": {
            "read_file": {"constraints": {"file_path": {"pattern": "/tmp/*"}}},
            "write_file": {"constraints": {"file_path": {"pattern": "/tmp/output/*"}}},
        }
    }
    secure_file_tools = protect_tools(
        tools=[read_file, write_file],
        warrant=file_warrant,
        keypair=agent_keypair,
        config=file_config,
    )
    
    # Command tool uses cmd_warrant directly (already has the right constraints)
    from tenuo.langchain import protect_tool
    secure_exec = protect_tool(
        execute_command,
        warrant=cmd_warrant,
        keypair=agent_keypair,
    )
    
    secure_tools = secure_file_tools + [secure_exec]
    print(f"   ✓ {len(secure_tools)} tools wrapped with authorization\n")
    
    # ========================================================================
    # Demonstrate Protection (without LLM for simplicity)
    # ========================================================================
    print("4. Testing authorization...")
    
    # Extract wrapped functions by name
    secure_read = secure_tools[0]
    secure_write = secure_tools[1]
    secure_exec = secure_tools[2]
    
    # Test 1: Allowed read
    print("\n   Test 1: read_file('/tmp/test.txt') - should be ALLOWED")
    try:
        # Create test file first
        with open("/tmp/test.txt", 'w') as f:
            f.write("Hello from Tenuo!")
        result = secure_read("/tmp/test.txt")
        print(f"   ✓ Result: {result}")
    except AuthorizationError as e:
        print(f"   ✗ Blocked (unexpected): {e}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 2: Blocked read (outside allowed path)
    print("\n   Test 2: read_file('/etc/passwd') - should be BLOCKED")
    try:
        result = secure_read("/etc/passwd")
        print(f"   ✗ Allowed (unexpected): {result}")
    except AuthorizationError as e:
        print(f"   ✓ Correctly blocked: {str(e)[:60]}...")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 3: Allowed write
    print("\n   Test 3: write_file('/tmp/output/log.txt', ...) - should be ALLOWED")
    try:
        os.makedirs("/tmp/output", exist_ok=True)
        result = secure_write("/tmp/output/log.txt", "Log entry")
        print(f"   ✓ Result: {result}")
    except AuthorizationError as e:
        print(f"   ✗ Blocked (unexpected): {e}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 4: Blocked write (outside allowed path)
    print("\n   Test 4: write_file('/etc/malicious.txt', ...) - should be BLOCKED")
    try:
        result = secure_write("/etc/malicious.txt", "bad stuff")
        print(f"   ✗ Allowed (unexpected): {result}")
    except AuthorizationError as e:
        print(f"   ✓ Correctly blocked: {str(e)[:60]}...")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 5: Allowed command
    print("\n   Test 5: execute_command('pwd') - should be ALLOWED")
    try:
        result = secure_exec("pwd")
        print(f"   ✓ Result: {result.strip()}")
    except AuthorizationError as e:
        print(f"   ✗ Blocked (unexpected): {e}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # Test 6: Blocked command
    print("\n   Test 6: execute_command('rm -rf /') - should be BLOCKED")
    try:
        result = secure_exec("rm -rf /")
        print(f"   ✗ Allowed (unexpected): {result}")
    except AuthorizationError as e:
        print(f"   ✓ Correctly blocked: {str(e)[:60]}...")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    # ========================================================================
    # LangChain Integration (if OpenAI key available)
    # ========================================================================
    print("\n" + "="*60)
    openai_api_key = os.getenv("OPENAI_API_KEY")
    
    if not openai_api_key:
        print("OPENAI_API_KEY not set. Skipping LangChain agent demo.")
        print("Set it to see the full agent integration:")
        print("   export OPENAI_API_KEY='your-key-here'")
    else:
        print("5. Running LangChain agent with protected tools...\n")
        
        try:
            from langchain.tools import StructuredTool
            from langchain.agents import AgentExecutor, create_openai_tools_agent
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
            
            # Create LangChain Tool objects from our protected functions
            langchain_tools = [
                StructuredTool.from_function(
                    func=secure_read,
                    name="read_file",
                    description="Read a file from /tmp/ directory"
                ),
                StructuredTool.from_function(
                    func=secure_write,
                    name="write_file",
                    description="Write content to a file in /tmp/output/"
                ),
                StructuredTool.from_function(
                    func=secure_exec,
                    name="execute_command",
                    description="Execute a safe command (ls, pwd, date, whoami)"
                ),
            ]
            
            # Create agent
            llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a helpful assistant. Use the tools provided to help the user."),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ])
            agent = create_openai_tools_agent(llm, langchain_tools, prompt)
            agent_executor = AgentExecutor(agent=agent, tools=langchain_tools, verbose=True)
            
            # Run agent
            response = agent_executor.invoke({
                "input": "What's in /tmp/test.txt? Then tell me the current directory."
            })
            print(f"\n   Agent response: {response['output']}")
            
        except ImportError as e:
            print(f"   Missing dependency: {e}")
            print("   Install with: pip install langchain langchain-openai")
        except Exception as e:
            print(f"   Error: {e}")
    
    # ========================================================================
    # Summary
    # ========================================================================
    print("\n" + "="*60)
    print("=== Summary ===")
    print("""
Key Points:
  1. Tool functions are PURE BUSINESS LOGIC - no Tenuo imports
  2. protect_tools() wraps them with authorization at setup time
  3. Config defines per-tool constraints (what each tool can access)
  4. PoP binding prevents stolen warrant replay attacks
  5. All authorization happens transparently - tools don't know about it

Security Properties Achieved:
  ✓ Scoped: Each tool has specific constraints
  ✓ Temporal: Warrants expire (TTL)
  ✓ Delegatable: Root warrant attenuated to tool-specific warrants
  ✓ Bound: PoP prevents credential theft
  ✓ Dynamic: Config can reference runtime state (see SecureGraph)
""")


if __name__ == "__main__":
    main()
