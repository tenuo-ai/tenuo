#!/usr/bin/env python3
"""
LangChain Integration Example with Tenuo

This example shows how to integrate Tenuo with LangChain agents and tools.
The warrant is set in context using LangChain callbacks, and all tool
functions are protected with @lockdown decorators.

SECURITY BEST PRACTICES demonstrated:
- PoP (Proof-of-Possession) binding: Warrants are bound to the agent's identity
- Keypair context: Agent's keypair enables automatic PoP signatures
- Stolen warrants are useless without the matching private key

Requirements:
    pip install langchain langchain-openai tenuo

Note: This example uses OpenAI, but the pattern works with any LLM provider.
"""

from tenuo import (
    Keypair, Warrant, Pattern, Range, Exact,
    lockdown, set_warrant_context, set_keypair_context, AuthorizationError
)
from typing import Optional, Dict, Any
import os

# LangChain imports (required for this example)
from langchain.tools import Tool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.callbacks.base import BaseCallbackHandler
from langchain.schema import AgentAction, AgentFinish, LLMResult


# ============================================================================
# Protected Tool Functions (using ContextVar pattern)
# ============================================================================

@lockdown(tool="read_file", extract_args=lambda file_path, **kwargs: {"file_path": file_path})
def read_file_tool(file_path: str) -> str:
    """
    Read a file from the filesystem.
    Protected by Tenuo: only files matching the warrant's path constraint can be read.
    
    Note: Authorization happens automatically via @lockdown decorator.
    This function will raise AuthorizationError if the warrant doesn't allow access.
    """
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        # File doesn't exist - return error message (not an exception)
        return f"Error: File {file_path} not found"
    except PermissionError:
        # File exists but no permission - return error message
        return f"Error: Permission denied reading {file_path}"
    except Exception as e:
        # Catch-all for other I/O errors
        return f"Error: {str(e)}"


@lockdown(tool="write_file", extract_args=lambda file_path, content, **kwargs: {"file_path": file_path, "content": content})
def write_file_tool(file_path: str, content: str) -> str:
    """
    Write content to a file.
    Protected by Tenuo: only files matching the warrant's path constraint can be written.
    
    Note: Authorization happens automatically via @lockdown decorator.
    This function will raise AuthorizationError if the warrant doesn't allow access.
    """
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {file_path}"
    except PermissionError:
        # File exists but no write permission
        return f"Error: Permission denied writing to {file_path}"
    except OSError as e:
        # Disk full, invalid path, etc.
        return f"Error: {str(e)}"
    except Exception as e:
        # Catch-all for other errors
        return f"Error: {str(e)}"


@lockdown(tool="execute_command", extract_args=lambda command, **kwargs: {"command": command})
def execute_command_tool(command: str) -> str:
    """
    Execute a shell command.
    Protected by Tenuo: only commands matching the warrant's constraints can be executed.
    
    WARNING: This is a demo function. In production, use more secure command execution
    (e.g., whitelist of allowed commands, no shell=True, proper sanitization).
    
    Note: Authorization happens automatically via @lockdown decorator.
    This function will raise AuthorizationError if the warrant doesn't allow the command.
    """
    import subprocess
    try:
        # HARDCODED: timeout=10 seconds. In production, use config or env var.
        result = subprocess.run(
            command,
            shell=True,  # WARNING: shell=True is insecure. Use shell=False with explicit args in production.
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error (exit code {result.returncode}): {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 10 seconds"
    except Exception as e:
        return f"Error: {str(e)}"


# ============================================================================
# LangChain Callback to Set Warrant Context
# ============================================================================

class TenuoWarrantCallback(BaseCallbackHandler):
    """
    LangChain callback that sets the warrant AND keypair in context before tool execution.
    
    SECURITY: Both warrant and keypair must be set for PoP-bound warrants.
    The keypair enables automatic PoP signature creation, which proves the agent
    holds the private key matching the warrant's authorized_holder.
    
    This ensures all @lockdown-decorated functions have access to the warrant
    via ContextVar, even when called from within LangChain's execution flow.
    
    Usage:
        warrant = Warrant.create(..., authorized_holder=agent_keypair.public_key())
        callback = TenuoWarrantCallback(warrant, agent_keypair)
        agent_executor.invoke(inputs, {"callbacks": [callback]})
    """
    
    def __init__(self, warrant: Warrant, keypair: Optional[Keypair] = None):
        super().__init__()
        self.warrant = warrant
        self.keypair = keypair  # SECURITY: Required for PoP-bound warrants
        self.warrant_token = None
        self.keypair_token = None
    
    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs) -> None:
        """Called when a tool starts executing. Set warrant and keypair in context."""
        from tenuo.decorators import _warrant_context, _keypair_context
        self.warrant_token = _warrant_context.set(self.warrant)
        if self.keypair:
            self.keypair_token = _keypair_context.set(self.keypair)
    
    def on_tool_end(self, output: str, **kwargs) -> None:
        """Called when a tool finishes. Clean up context."""
        from tenuo.decorators import _warrant_context, _keypair_context
        if self.warrant_token:
            _warrant_context.reset(self.warrant_token)
            self.warrant_token = None
        if self.keypair_token:
            _keypair_context.reset(self.keypair_token)
            self.keypair_token = None
    
    def on_tool_error(self, error: Exception, **kwargs) -> None:
        """Called when a tool errors. Clean up context."""
        from tenuo.decorators import _warrant_context, _keypair_context
        if self.warrant_token:
            _warrant_context.reset(self.warrant_token)
            self.warrant_token = None
        if self.keypair_token:
            _keypair_context.reset(self.keypair_token)
            self.keypair_token = None


# ============================================================================
# LangChain Tools Setup
# ============================================================================

def create_langchain_tools():
    """
    Create LangChain Tool objects from our protected functions.
    
    Note: The actual authorization happens inside the functions via @lockdown.
    LangChain just calls the functions - Tenuo enforces authorization automatically.
    """
    tools = [
        Tool(
            name="read_file",
            func=read_file_tool,
            description="Read a file from the filesystem. Input should be the file path as a string."
        ),
        Tool(
            name="write_file",
            func=lambda x: write_file_tool(**eval(f"dict({x})")),  # Simple parser for demo
            description="Write content to a file. Input format: file_path='path', content='text'"
        ),
        Tool(
            name="execute_command",
            func=execute_command_tool,
            description="Execute a shell command. Use with caution. Input should be the command to run as a string."
        ),
    ]
    return tools


# ============================================================================
# Main Integration Example
# ============================================================================

def main():
    print("=== Tenuo + LangChain Integration Example ===\n")
    
    # ========================================================================
    # STEP 1: Create Warrant (SIMULATION - In production, warrant comes from control plane)
    # ========================================================================
    print("1. Creating warrant for agent...")
    try:
        # SIMULATION: Generate keypairs for demo
        # In production: Control plane keypair is loaded from secure storage (K8s Secret, HSM, etc.)
        control_keypair = Keypair.generate()  # Issuer (control plane)
        agent_keypair = Keypair.generate()    # Agent's identity
        
        # SIMULATION: Create warrant with hardcoded constraints
        # In production: Constraints come from policy engine, user request, or configuration
        # HARDCODED PATH: /tmp/* is used for demo safety. In production, use env vars or config.
        #
        # SECURITY BEST PRACTICE: Always PoP-bind warrants to the agent's identity
        # This prevents stolen warrants from being used by attackers
        agent_warrant = Warrant.create(
            tool="read_file",  # Base tool - can be used for multiple tools
            constraints={
                "file_path": Pattern("/tmp/*"),  # HARDCODED: Only files in /tmp/ for demo safety
            },
            ttl_seconds=3600,  # HARDCODED: 1 hour TTL. In production, use env var or config.
            keypair=control_keypair,
            authorized_holder=agent_keypair.public_key()  # PoP binding! Stolen warrants are useless
        )
        
        print(f"   ✓ Warrant created with constraints:")
        print(f"     - file_path: Pattern('/tmp/*')")
        print(f"     - TTL: 3600 seconds")
        print(f"     - PoP-bound: {agent_warrant.requires_pop} (stolen warrants are useless)\n")
    except Exception as e:
        print(f"   ✗ Error creating warrant: {e}")
        return
    
    # 2. Check for OpenAI API key
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        print("⚠️  OPENAI_API_KEY not set. Set it to run the full example.")
        print("   export OPENAI_API_KEY='your-key-here'")
        print("\n   For now, demonstrating protection without LLM...\n")
        
        # Show protection works
        # SECURITY: Set BOTH warrant and keypair context for PoP-bound warrants
        print("2. Demonstrating protection...")
        test_file = "/tmp/test.txt"  # HARDCODED: Demo test file
        try:
            with set_warrant_context(agent_warrant), set_keypair_context(agent_keypair):
                result = read_file_tool(test_file)
                print(f"   ✓ read_file('{test_file}') authorized")
        except AuthorizationError as e:
            print(f"   ✗ Authorization error: {e}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        
        try:
            with set_warrant_context(agent_warrant), set_keypair_context(agent_keypair):
                read_file_tool("/etc/passwd")  # HARDCODED: Protected file for demo
        except AuthorizationError as e:
            print(f"   ✓ read_file('/etc/passwd') correctly blocked: {str(e)[:60]}...")
        except Exception as e:
            print(f"   ✗ Unexpected error: {e}")
        
        return
    
    # ========================================================================
    # STEP 4: Create LangChain Tools (REAL CODE - Production-ready)
    # ========================================================================
    print("2. Creating LangChain tools...")
    try:
        tools = create_langchain_tools()
        print(f"   ✓ Created {len(tools)} tools\n")
    except Exception as e:
        print(f"   ✗ Error creating tools: {e}")
        return
    
    # ========================================================================
    # STEP 5: Create LangChain Agent (REAL CODE - Production-ready)
    # ========================================================================
    print("3. Creating LangChain agent...")
    try:
        # ENV VARIABLE: OPENAI_API_KEY is used here (already checked above)
        # HARDCODED: model="gpt-3.5-turbo" - in production, use env var or config
        llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
        agent = create_openai_tools_agent(llm, tools)
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
        print("   ✓ Agent created\n")
    except Exception as e:
        print(f"   ✗ Error creating agent: {e}")
        print("   (Check OPENAI_API_KEY and network connectivity)")
        return
    
    # ========================================================================
    # STEP 6: Set Up Warrant Callback (REAL CODE - Production-ready)
    # ========================================================================
    print("4. Setting up Tenuo warrant callback...")
    try:
        # SECURITY: Pass BOTH warrant and keypair for PoP-bound warrants
        warrant_callback = TenuoWarrantCallback(agent_warrant, agent_keypair)
        print("   ✓ Callback created - warrant + keypair will be set in context for all tool calls")
        print("   ✓ PoP signatures will be created automatically\n")
    except Exception as e:
        print(f"   ✗ Error creating callback: {e}")
        return
    
    # ========================================================================
    # STEP 7: Run Agent with Protection (REAL CODE - Production-ready)
    # ========================================================================
    print("5. Running agent with Tenuo protection...")
    print("   The agent can only access files in /tmp/ due to warrant constraints.\n")
    
    # HARDCODED PATH: /tmp/langchain_test.txt for demo
    # In production: Use tempfile or env-specified test directory
    test_file = "/tmp/langchain_test.txt"
    
    try:
        # Create a test file first
        try:
            with open(test_file, 'w') as f:
                f.write("Hello from LangChain + Tenuo!")
        except (IOError, OSError) as e:
            print(f"   ⚠ Warning: Could not create test file: {e}")
            print("   Continuing with agent execution...\n")
        
        # Run agent - it should be able to read the test file
        try:
            response = agent_executor.invoke(
                {
                    "input": f"Read the file {test_file} and tell me what it says",
                    "chat_history": []
                },
                {"callbacks": [warrant_callback]}
            )
            print(f"\n   Agent response: {response['output']}\n")
        except AuthorizationError as e:
            print(f"   ✗ Authorization error: {e}\n")
        except Exception as e:
            print(f"   ✗ Error running agent: {e}\n")
            print("   (This might be due to OpenAI API issues or network problems)")
        
        # Try to make agent read a protected file
        print("6. Testing protection - trying to read /etc/passwd...")
        try:
            response = agent_executor.invoke(
                {
                    "input": "Read the file /etc/passwd",  # HARDCODED: Protected file for demo
                    "chat_history": []
                },
                {"callbacks": [warrant_callback]}
            )
            print("   ✗ Should have been blocked!")
        except AuthorizationError as e:
            print(f"   ✓ Correctly blocked: {str(e)[:60]}...\n")
        except Exception as e:
            print(f"   ✗ Unexpected error (not AuthorizationError): {e}\n")
        
    except Exception as e:
        print(f"   ✗ Unexpected error: {e}\n")
        print("   (This might be due to missing OpenAI API key or other setup issues)")
    
    print("=== Integration example completed! ===")
    print("\nKey Security Points:")
    print("  - Warrant is PoP-bound to the agent's identity (authorized_holder)")
    print("  - Keypair context enables automatic PoP signatures")
    print("  - Stolen warrants are useless without the matching private key")
    print("  - All tool functions are protected with @lockdown decorators")
    print("  - Authorization happens automatically - no manual checks needed")


if __name__ == "__main__":
    main()

