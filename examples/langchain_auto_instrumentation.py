#!/usr/bin/env python3
"""
Tenuo + LangChain: Auto-Instrumentation Example

This example demonstrates a more ROBUST and DEVELOPER-FRIENDLY integration pattern.
Instead of decorating every tool function with @lockdown, we use a `protect_tools`
helper to automatically wrap a list of LangChain tools with Tenuo security.

ADVANTAGES:
1.  **Decoupling**: Tool logic is pure Python. No Tenuo dependencies in your tool code.
2.  **Centralization**: Security is applied in one place (agent setup), not scattered across functions.
3.  **Fail-Safe**: The wrapper enforces that a warrant MUST be present, or it blocks execution.

"""

import os
from typing import List, Any, Optional, Dict
from tenuo import Keypair, Warrant, Pattern, AuthorizationError

# LangChain imports
from langchain.tools import StructuredTool, BaseTool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.callbacks.base import BaseCallbackHandler

# ============================================================================
# 1. The "Middleware": Reusable Security Components
# ============================================================================

class TenuoToolWrapper:
    """
    Wraps a LangChain tool to enforce Tenuo authorization.
    This acts as a security proxy around the original tool.
    """
    def __init__(self, tool: BaseTool):
        self.original_tool = tool
        self.name = tool.name
        self.description = tool.description
        self.args_schema = tool.args_schema
        
        # Copy other attributes to look like the original tool
        # (This is a simplified wrapper for demonstration)
        
    def _check_auth(self, tool_input: dict) -> None:
        """Performs the security check before execution."""
        warrant = get_warrant_context()
        if not warrant:
            raise AuthorizationError(f"Security Blocked: No warrant provided for tool '{self.name}'")
            
        keypair = get_keypair_context()
        
        # 1. PoP Check
        pop_signature = None
        if warrant.requires_pop:
            if not keypair:
                raise AuthorizationError(f"Security Blocked: Warrant requires PoP but no keypair found for '{self.name}'")
            # Auto-sign
            pop_signature = warrant.create_pop_signature(keypair, self.name, tool_input)
            
        # 2. Authorization Check
        if not warrant.authorize(self.name, tool_input, signature=pop_signature):
            raise AuthorizationError(
                f"Access Denied: Warrant does not authorize '{self.name}' with args {tool_input}"
            )

    def run(self, tool_input: Any, **kwargs) -> Any:
        """Synchronous execution wrapper."""
        # Normalize input to dict if needed (LangChain tools can take str or dict)
        if isinstance(tool_input, str):
            # This is a simplification; real wrapper would parse based on args_schema
            # For this demo, we assume tools take named args if they are structured
            pass 
            
        # For StructuredTools, input is usually a dict
        auth_input = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
        
        self._check_auth(auth_input)
        return self.original_tool.run(tool_input, **kwargs)

    async def arun(self, tool_input: Any, **kwargs) -> Any:
        """Async execution wrapper."""
        auth_input = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
        self._check_auth(auth_input)
        return await self.original_tool.arun(tool_input, **kwargs)

def protect_tools(
    tools: List[BaseTool],
    warrant: Warrant,
    keypair: Optional[Keypair] = None,
) -> List[BaseTool]:
    """
    Wrap tools with Tenuo authorization.
    
    For single-agent use. For multi-agent delegation, use SecureGraph.
    """
    protected = []
    for tool in tools:
        # We create a copy to avoid mutating the original
        import copy
        secure_tool = copy.copy(tool)
        
        original_run = secure_tool._run
        tool_name = secure_tool.name
        
        # Closure captures warrant and keypair directly
        def secure_run(*args, config=None, _tool_name=tool_name, _original_run=original_run, **kwargs):
            # Reconstruct args dictionary for checking
            check_args = kwargs.copy()
            
            # PoP
            sig = None
            if warrant.requires_pop:
                if not keypair:
                    raise AuthorizationError(f"PoP required but no keypair for {_tool_name}")
                sig = warrant.create_pop_signature(keypair, _tool_name, check_args)
            
            # Authorize
            if not warrant.authorize(_tool_name, check_args, signature=sig):
                raise AuthorizationError(f"Unauthorized access to {_tool_name} with {check_args}")
            
            # Always pass config
            kwargs['config'] = config
            
            return _original_run(*args, **kwargs)
            
        secure_tool._run = secure_run
        protected.append(secure_tool)
        
    return protected

# ============================================================================
# 2. Pure Business Logic (No Security Code!)
# ============================================================================

def read_file(file_path: str) -> str:
    """Reads a file."""
    # Look ma, no decorators! Just pure logic.
    if not os.path.exists(file_path):
        return "File not found"
    return "Contents of " + file_path

def write_file(file_path: str, content: str) -> str:
    """Writes a file."""
    return f"Wrote to {file_path}"

# ============================================================================
# 3. The Setup (Where Security Happens)
# ============================================================================

def main():
    print("=== Tenuo Auto-Instrumentation Demo ===\n")
    
    # 1. Define Tools (Pure LangChain)
    raw_tools = [
        StructuredTool.from_function(read_file),
        StructuredTool.from_function(write_file)
    ]
    
    # 2. Create Identity & Warrant
    kp = Keypair.generate()
    warrant = Warrant.create(
        tool="read_file",
        constraints={"file_path": Pattern("/tmp/*")},
        ttl_seconds=300,
        keypair=kp,
        authorized_holder=kp.public_key()
    )
    
    # 3. Apply Protection (The "Magic" Step)
    # This is the ONLY place the developer needs to think about Tenuo
    print("1. Auto-instrumenting tools...")
    secure_tools = protect_tools(raw_tools, warrant=warrant, keypair=kp)
    print("   ✓ Tools wrapped with security layer")
    
    # 4. Run Agent
    # No callback needed! The tools carry their own security.
    
    print("\n2. Testing Protected Execution...")
    
    # Simulate a tool call (what the Agent would do)
    tool = secure_tools[0] # read_file
    
    try:
        print("   Attempting: read_file('/tmp/safe.txt')")
        result = tool.run({"file_path": "/tmp/safe.txt"})
        print(f"   ✓ Success: {result}")
        
        print("   Attempting: read_file('/etc/passwd')")
        tool.run({"file_path": "/etc/passwd"})
        
    except AuthorizationError as e:
        print(f"   ✓ Blocked: {e}")

if __name__ == "__main__":
    from typing import Dict # Fix missing import
    main()
