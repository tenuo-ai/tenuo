"""
Tenuo Python SDK - Capability tokens for AI agents

80% API - The essentials for most users:

    from tenuo import (
        # Authority (the core primitives)
        mint, grant, Capability, Warrant,
        # Protection
        guard, guard_tools,
        # Constraints
        Pattern, Range, OneOf, Exact,
        # Setup (usually once at startup)
        configure, auto_configure, SigningKey, PublicKey,
    )

For advanced usage, import from submodules:

    from tenuo.exceptions import AuthorizationDenied, MonotonicityError, ...
    from tenuo.audit import AuditEvent, AuditLogger, ...
    from tenuo.templates import FileReader, WebSearcher, ...
"""

# =============================================================================
# Core Types (from Rust)
# =============================================================================
from tenuo_core import (  # type: ignore
    SigningKey,
    PublicKey,
    Warrant,
    Authorizer,
    # Common constraints
    Pattern,
    Exact,
    OneOf,
    Range,
    Contains,
)

# =============================================================================
# 80% API - What most users need
# =============================================================================

# Setup
from .config import (
    configure,
    auto_configure,
    reset_config,
    is_configured,
)

# Authority context managers
from .scoped import (
    mint,
    mint_sync,
    grant,
)

# Constraints
from .constraints import Capability

# Protection decorator
from .decorators import (
    guard,
    warrant_scope,
    key_scope,
)

# LangChain integration
from .langchain import (
    guard_tools,
    guard_agent,
    auto_protect,
    LANGCHAIN_AVAILABLE,
)

# Essential errors only
from .exceptions import (
    TenuoError,
    ConstraintViolation,
    MonotonicityError,
    ConfigurationError,
    AuthorizationDenied,  # Rich error with diff support
)

# Error explanation
from .explain import explain, explain_str

# BoundWarrant (common result of warrant.bind())
from .bound_warrant import BoundWarrant

# Validation result
from .validation import ValidationResult

# =============================================================================
# Initialize extensions (must run)
# =============================================================================
import tenuo.warrant_ext  # noqa: F401
import tenuo.builder  # noqa: F401 - Adds Warrant.mint_builder()
import tenuo.keys  # noqa: F401 - Adds SigningKey.from_env(), PublicKey.from_env()
Warrant.bind = BoundWarrant.bind_warrant

# =============================================================================
# 80% API Exports
# =============================================================================
__all__ = [
    # Authority (the core primitives)
    "mint",
    "mint_sync",
    "grant",
    "Capability",
    "Warrant",
    
    # Core types
    "BoundWarrant",
    "Authorizer",
    
    # Setup
    "configure",
    "auto_configure", 
    "reset_config",
    "is_configured",
    "SigningKey",
    "PublicKey",
    
    # Protection
    "guard",
    "guard_tools",
    "guard_agent",
    "auto_protect",
    "LANGCHAIN_AVAILABLE",
    
    # Context
    "warrant_scope",
    "key_scope",
    
    # Common constraints
    "Pattern",
    "Exact",
    "OneOf",
    "Range",
    "Contains",
    
    # Errors (essential only)
    "TenuoError",
    "ConstraintViolation",
    "MonotonicityError",
    "ConfigurationError",
    "AuthorizationDenied",  # Rich error with diff support
    
    # Error explanation
    "explain",
    "explain_str",
    
    # Result types
    "ValidationResult",
]

__version__ = "0.1.0a9"
