"""
Tool protection for Tenuo.

This module re-exports the @guard decorator for protecting tool functions.
For wrapping lists of tools, use guard_tools() from tenuo.langchain.
For wrapping entire agents, use guard_agent() from tenuo.langchain.

Usage:
    from tenuo import guard, mint, Capability, Pattern
    
    @guard(tool="read_file")
    def read_file(path: str) -> str:
        return open(path).read()
    
    # Use with scoped authority
    async with mint(Capability("read_file", path=Pattern("/data/*"))):
        result = await read_file(path="/data/report.csv")
"""

# Re-export @guard as the primary API
from .decorators import guard

__all__ = ["guard"]
