"""
Tenuo Python SDK - Capability tokens for AI agents

A pure Python wrapper around the Rust tenuo_core extension.
"""

# Import all public API from the Rust extension
from tenuo_core import (
    # Core types
    Keypair,
    Warrant,
    
    # Constraints
    Pattern,
    Exact,
    OneOf,
    Range,
    CEL,
    
    # MCP integration
    McpConfig,
    CompiledMcpConfig,
    
    # Constants
    MAX_DELEGATION_DEPTH,
    WIRE_VERSION,
    WARRANT_HEADER,
)

# Import Pythonic additions
from .exceptions import (
    TenuoError,
    WarrantError,
    AuthorizationError,
    ConstraintError,
    ConfigurationError,
)
from .decorators import (
    lockdown,
    get_warrant_context,
    set_warrant_context,
    WarrantContext,
)

# Re-export everything for clean imports
__all__ = [
    # Core types
    "Keypair",
    "Warrant",
    
    # Constraints
    "Pattern",
    "Exact",
    "OneOf",
    "Range",
    "CEL",
    
    # MCP integration
    "McpConfig",
    "CompiledMcpConfig",
    
    # Constants
    "MAX_DELEGATION_DEPTH",
    "WIRE_VERSION",
    "WARRANT_HEADER",
    
    # Pythonic additions
    "TenuoError",
    "WarrantError",
    "AuthorizationError",
    "ConstraintError",
    "ConfigurationError",
    "lockdown",
    "get_warrant_context",
    "set_warrant_context",
    "WarrantContext",
]

__version__ = "0.1.0"
