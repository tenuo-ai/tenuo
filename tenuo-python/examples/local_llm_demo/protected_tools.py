"""
Tool protection wrapper for the Local LLM Demo.

DEMO MODE vs PRODUCTION:
    This demo uses check_constraints() which is a DIAGNOSTIC method.
    It checks constraints without requiring a Proof-of-Possession signature.
    
    In PRODUCTION, you should use authorize() with a real PoP signature:
    
        # Production pattern
        pop_signature = warrant.sign(signing_key, tool_name, kwargs)
        if warrant.authorize(tool_name, kwargs, pop_signature):
            # Execute tool
        else:
            # Denied
    
    The PoP signature proves the caller possesses the private key matching
    the warrant's authorized_holder, preventing replay attacks.
"""

import functools
from tenuo import Warrant
import display

class ProtectedToolWrapper:
    """
    Wraps standard functions with Tenuo authorization.
    
    Uses check_constraints() for diagnostic authorization checking.
    See module docstring for production usage notes.
    """
    def __init__(self, warrant: Warrant):
        self.warrant = warrant
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

            # 1. Check if tool exists in warrant
            if tool_name not in self.warrant.tools:
                self.blocked_count += 1
                display.print_verdict(False, f"Tool '{tool_name}' not in warrant",
                    "This tool was never granted to this agent.")
                # Only show the learning insight once
                if not self._shown_tool_insight:
                    display.print_learning("Principle of Least Authority",
                        "Agents only have access to explicitly granted capabilities.\n"
                        "Even if tricked by prompt injection, they cannot use unauthorized tools.")
                    self._shown_tool_insight = True
                return f"AUTHORIZATION ERROR: Tool '{tool_name}' is not authorized. You do not have this capability."

            # 2. Check constraints (diagnostic mode - no PoP required)
            failure = self.warrant.check_constraints(tool_name, kwargs)
            if failure:
                self.blocked_count += 1
                display.print_verdict(False, "Constraint Violation", failure)
                # Only show the learning insight once
                if not self._shown_constraint_insight:
                    display.print_learning("Constraint Enforcement",
                        "Even for allowed tools, arguments must satisfy constraints.\n"
                        "The agent tried to access something outside its permitted scope.")
                    self._shown_constraint_insight = True
                return f"AUTHORIZATION ERROR: {failure}"
            
            # Authorized
            self.allowed_count += 1
            display.print_verdict(True, "Access Granted",
                "Tool and arguments match the warrant's capabilities.")

            # 3. Execute
            return tool(**kwargs)
        
        return wrapper
    
    def get_stats(self) -> tuple:
        """Return (blocked_count, allowed_count)"""
        return (self.blocked_count, self.allowed_count)
