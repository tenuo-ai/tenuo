#!/usr/bin/env python3
"""
Simple LangChain + Tenuo Integration Example

A minimal example showing how to protect LangChain tools with Tenuo warrants.

Key Pattern:
1. Decorate tool functions with @lockdown(tool="...")
2. Set warrant in context before agent execution
3. All tool calls are automatically authorized

Requirements:
    pip install langchain langchain-openai tenuo
"""

from tenuo import (
    SigningKey, Warrant, Pattern, Constraints,
    lockdown, set_warrant_context, set_signing_key_context, AuthorizationError
)

# Try to import LangChain
try:
    from langchain_core.tools import Tool
    from langchain.agents.agent import AgentExecutor
    from langchain.agents.openai_tools.base import create_openai_tools_agent
    from langchain_openai import ChatOpenAI
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Install LangChain: pip install langchain langchain-openai\n")


# ============================================================================
# Protected Tool Functions
# ============================================================================

@lockdown(tool="read_file", extract_args=lambda file_path, **kwargs: {"file_path": file_path})
def read_file(file_path: str) -> str:
    """Read a file. Protected by Tenuo - only authorized paths allowed."""
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: File not found: {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"


@lockdown(tool="write_file", extract_args=lambda file_path, content, **kwargs: {"file_path": file_path, "content": content})
def write_file(file_path: str, content: str) -> str:
    """Write to a file. Protected by Tenuo - only authorized paths allowed."""
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"


# ============================================================================
# LangChain Integration
# ============================================================================

def main():
    print("=== Simple LangChain + Tenuo Integration ===\n")
    
    # ========================================================================
    # STEP 1: Create Warrant (SIMULATION - In production, from control plane)
    # ========================================================================
    print("1. Creating warrant...")
    try:
        # SIMULATION: Generate keypair for demo
        # In production: Control plane keypair is loaded from secure storage
        keypair = SigningKey.generate()
        
        # SIMULATION: Create warrant with hardcoded constraints
        # HARDCODED: Pattern("/tmp/*"), ttl_seconds=3600
        # In production: Constraints come from policy engine or configuration
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {
                "file_path": Pattern("/tmp/*")  # HARDCODED: Only /tmp/ for demo safety
            }),
            ttl_seconds=3600,  # HARDCODED: 1 hour TTL. In production, use env var or config.
            holder=keypair.public_key  # Bind to self for demo
        )
        print("   [OK] Warrant created: only /tmp/* files allowed\n")
    except Exception as e:
        print(f"   [ERR] Error creating warrant: {e}")
        return
    
    # ========================================================================
    # STEP 2: Handle Missing LangChain (SIMULATION MODE)
    # ========================================================================
    if not LANGCHAIN_AVAILABLE:
        print("2. [SIMULATION] Demonstrating protection (LangChain not installed)...")
        print("   Install with: pip install langchain langchain-openai\n")
        
        # Show it works without LangChain
        try:
            with set_warrant_context(warrant), set_signing_key_context(keypair):
                # Test authorized access
                # HARDCODED PATH: /tmp/test.txt for demo
                try:
                    read_file("/tmp/test.txt")
                    print("   ✓ read_file('/tmp/test.txt'): Allowed")
                except AuthorizationError as e:
                    print(f"   ✗ Unexpected authorization error: {e}")
                except Exception as e:
                    print(f"   ✗ Unexpected error: {e}")
                
                # Test blocked access
                # HARDCODED PATH: /etc/passwd (protected system file for demo)
                try:
                    read_file("/etc/passwd")
                    print("   ✗ Should have been blocked!")
                except AuthorizationError as e:
                    print(f"   ✓ read_file('/etc/passwd'): Blocked ({str(e)[:50]}...)\n")
                except Exception as e:
                    print(f"   ✗ Unexpected error (not AuthorizationError): {e}\n")
        except Exception as e:
            print(f"   ✗ Error in protection test: {e}\n")
        
        print("With LangChain installed:")
        print("  1. Create tools: Tool(name='read_file', func=read_file, ...)")
        print("  2. Create agent: create_openai_tools_agent(llm, tools)")
        print("  3. Set warrant: with set_warrant_context(warrant):")
        print("  4. Run agent: agent_executor.invoke(...)")
        print("\nAll tool calls are automatically protected!")
        return
    
    # ========================================================================
    # STEP 2.5: Check for OpenAI API Key
    # ========================================================================
    import os
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠ OPENAI_API_KEY not set. Running in simulation mode (no LLM)...\n")
        
        # Show it works without LangChain/LLM
        try:
            with set_warrant_context(warrant), set_signing_key_context(keypair):
                # Test authorized access
                try:
                    read_file("/tmp/test.txt")
                    print("   ✓ read_file('/tmp/test.txt'): Allowed")
                except AuthorizationError as e:
                    print(f"   ✗ Unexpected authorization error: {e}")
                except Exception as e:
                    print(f"   ✗ Unexpected error: {e}")
                
                # Test blocked access
                try:
                    read_file("/etc/passwd")
                    print("   ✗ Should have been blocked!")
                except AuthorizationError as e:
                    print(f"   ✓ read_file('/etc/passwd'): Blocked ({str(e)[:50]}...)\n")
                except Exception as e:
                    print(f"   ✗ Unexpected error (not AuthorizationError): {e}\n")
        except Exception as e:
            print(f"   ✗ Error in protection test: {e}\n")
            
        print("To run full LangChain agent example:")
        print("  export OPENAI_API_KEY='your-key-here'")
        return

    # ========================================================================
    # STEP 3: Create LangChain Tools (REAL CODE - Production-ready)
    # ========================================================================
    print("2. Creating LangChain tools...")
    try:
        tools = [
            Tool(name="read_file", func=read_file, description="Read a file. Input: file path"),
            Tool(name="write_file", func=write_file, description="Write to a file. Input: file_path='path', content='text'"),
        ]
        print(f"   ✓ Created {len(tools)} tools\n")
    except Exception as e:
        print(f"   ✗ Error creating tools: {e}")
        return
    
    # ========================================================================
    # STEP 4: Create LangChain Agent (REAL CODE - Production-ready)
    # ========================================================================
    print("3. Creating LangChain agent...")
    try:
        # ENV VARIABLE: OPENAI_API_KEY is used here (must be set)
        # HARDCODED: model="gpt-3.5-turbo" - in production, use env var or config
        llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
        agent = create_openai_tools_agent(llm, tools)
        executor = AgentExecutor(agent=agent, tools=tools, verbose=False)
        print("   ✓ Agent created\n")
    except Exception as e:
        print(f"   ✗ Error creating agent: {e}")
        print("   (Check OPENAI_API_KEY and network connectivity)")
        return
    
    # ========================================================================
    # STEP 5: Run Agent with Protection (REAL CODE - Production-ready)
    # ========================================================================
    print("4. Running agent with Tenuo protection...")
    print("   Warrant restricts access to /tmp/* files only\n")
    
    # HARDCODED PATH: /tmp/langchain_demo.txt for demo
    # In production: Use tempfile or env-specified test directory
    test_file = "/tmp/langchain_demo.txt"
    try:
        with open(test_file, 'w') as f:
            f.write("Hello from LangChain + Tenuo!")
    except (IOError, OSError) as e:
        print(f"   ⚠ Warning: Could not create test file: {e}")
        print("   Continuing with agent execution...\n")
    
    # Set warrant in context and run agent
    try:
        with set_warrant_context(warrant), set_signing_key_context(keypair):
            # This should work - file is in /tmp/
            try:
                response = executor.invoke({
                    "input": f"Read the file {test_file} and tell me what it contains",
                    "chat_history": []
                })
                print(f"   Agent: {response['output']}\n")
            except AuthorizationError as e:
                print(f"   ✗ Authorization error: {e}\n")
            except Exception as e:
                print(f"   ✗ Error running agent: {e}\n")
            
            # Try to make agent read protected file
            print("5. Testing protection - trying to read /etc/passwd...")
            # HARDCODED PATH: /etc/passwd (protected system file for demo)
            try:
                response = executor.invoke({
                    "input": "Read the file /etc/passwd",
                    "chat_history": []
                })
                print("   ✗ Should have been blocked!")
            except AuthorizationError as e:
                print(f"   ✓ Correctly blocked: {str(e)[:60]}...\n")
            except Exception as e:
                print(f"   ✗ Unexpected error (not AuthorizationError): {e}\n")
    except Exception as e:
        print(f"   ✗ Error in agent execution: {e}\n")
    
    print("=== Integration complete! ===")
    print("\nKey takeaway:")
    print("  Set warrant in context once, all @lockdown functions are protected automatically.")


if __name__ == "__main__":
    main()

