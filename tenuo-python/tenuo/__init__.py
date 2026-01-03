"""
Tenuo Python SDK - Capability tokens for AI agents

80% API - The essentials for most users:

    from tenuo import (
        # Authority (the core primitives)
        mint, grant, Capability, Warrant,
        # Protection
        guard, guard_tools,
        # Constraints
        Pattern, Range, OneOf, Exact, Any,  # Any = Wildcard for zero-trust
        # Composites
        AnyOf, All, Not,  # AnyOf = OR, All = AND
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
    # Multi-sig
    Approval,
    compute_approval_hash,
    # Common constraints
    Pattern,
    Exact,
    OneOf,
    Range,
    Contains,
    Wildcard,
    # Advanced constraints
    AnyOf,
    All,
    Not,
    NotOneOf,
    Subset,
    Cidr,
    UrlPattern,
    Regex,
    CEL,
)

# Semantic alias: Any() = Wildcard() for zero-trust constraint sets
# Use Any() to explicitly allow any value for a field while in closed-world mode
Any = Wildcard

# =============================================================================
# 80% API - What most users need
# =============================================================================

# Setup
from .config import (
    configure,
    auto_configure,
    reset_config,
    is_configured,
    is_audit_mode,
    is_enforce_mode,
    should_block_violation,
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

# Diagnostics
from .diagnostics import diagnose, info

# BoundWarrant (common result of warrant.bind())
from .bound_warrant import BoundWarrant

# Validation result
from .validation import ValidationResult

# Key management
from .keys import KeyRegistry, Keyring

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

    # Multi-sig
    "Approval",
    "compute_approval_hash",

    # Setup
    "configure",
    "auto_configure",
    "reset_config",
    "is_configured",
    "is_audit_mode",
    "is_enforce_mode",
    "should_block_violation",
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
    "Wildcard",
    "Any",  # Alias for Wildcard - use in zero-trust constraint sets
    # Advanced constraints
    "AnyOf",  # OR composite (at least one must match)
    "All",  # AND composite (all must match)
    "Not",  # Negation
    "NotOneOf",  # Exclude values
    "Subset",  # List must be subset
    "Cidr",  # IP network range
    "UrlPattern",  # URL matching
    "Regex",  # Regular expression
    "CEL",  # Common Expression Language

    # Errors (essential only)
    "TenuoError",
    "ConstraintViolation",
    "MonotonicityError",
    "ConfigurationError",
    "AuthorizationDenied",  # Rich error with diff support

    # Error explanation
    "explain",
    "explain_str",

    # Diagnostics
    "diagnose",
    "info",

    # Result types
    "ValidationResult",

    # Key management
    "KeyRegistry",
    "Keyring",
]

__version__ = "0.1.0b3"
