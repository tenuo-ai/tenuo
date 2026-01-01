"""
Tool protection wrapper for the Local LLM Demo.

Uses Proof-of-Possession (PoP) cryptographic authorization:
    1. Each tool call is SIGNED with the agent's private key
    2. The signature is VERIFIED against the warrant
    
This proves the caller possesses the private key matching
the warrant's authorized_holder, preventing replay attacks.
"""

import functools
from tenuo import Warrant, SigningKey
import display


class ProtectedToolWrapper:
    """
    Wraps standard functions with cryptographic Tenuo authorization.
    
    Uses warrant.validate() which:
    1. Signs the tool call with the agent's private key (PoP)
    2. Verifies the signature against the warrant
    3. Checks all constraints are satisfied
    """
    def __init__(self, warrant: Warrant, signing_key: SigningKey):
        self.warrant = warrant
        self.signing_key = signing_key
        self.blocked_count = 0
        self.allowed_count = 0
        self._shown_tool_insight = False
        self._shown_constraint_insight = False

    def guard(self, tools: list) -> list:
        """Wrap a list of tools."""
        return [self._wrap(t) for t in tools]

    def _wrap(self, tool):
        @functools.wraps(tool)
        def wrapper(**kwargs):
            tool_name = tool.__name__
            
            # Show what the LLM is trying to do
            display.print_llm_intent(tool_name, kwargs)

            # CRYPTOGRAPHIC AUTHORIZATION using Proof-of-Possession
            # warrant.validate() internally:
            # 1. Signs: pop_sig = warrant.sign(key, tool, args)
            # 2. Verifies: warrant.authorize(tool, args, pop_sig)
            result = self.warrant.validate(self.signing_key, tool_name, kwargs)
            
            if not result:
                self.blocked_count += 1
                
                # Determine if it's a tool issue or constraint issue
                if tool_name not in self.warrant.tools:
                    display.print_verdict(False, f"Tool '{tool_name}' not in warrant",
                        "This tool was never granted to this agent.")
                    if not self._shown_tool_insight:
                        display.print_learning("Principle of Least Authority",
                            "Agents only have access to explicitly granted capabilities.\n"
                            "Even if tricked by prompt injection, they cannot use unauthorized tools.")
                        self._shown_tool_insight = True
                else:
                    display.print_verdict(False, "Authorization Failed", 
                        result.reason or "Constraint violation")
                    if not self._shown_constraint_insight:
                        display.print_learning("Constraint Enforcement",
                            "Even for allowed tools, arguments must satisfy constraints.\n"
                            "The agent tried to access something outside its permitted scope.")
                        self._shown_constraint_insight = True
                
                return f"AUTHORIZATION ERROR: {result.reason or 'Not authorized'}"
            
            # Authorized - PoP signature verified
            self.allowed_count += 1
            display.print_verdict(True, "Authorized (PoP Verified)",
                "Cryptographic proof: agent holds the key and arguments satisfy constraints.")

            # Execute
            return tool(**kwargs)
        
        return wrapper
    
    def get_stats(self) -> tuple:
        """Return (blocked_count, allowed_count)"""
        return (self.blocked_count, self.allowed_count)
