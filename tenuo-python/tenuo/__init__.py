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
        # Security (from Rust core - can be embedded in Warrants)
        Subpath, UrlSafe, Shlex,  # Path traversal, SSRF, shell injection protection
        # Setup (usually once at startup)
        configure, auto_configure, SigningKey, PublicKey,
    )

For advanced usage, import from submodules:

    from tenuo.exceptions import AuthorizationDenied, MonotonicityError, ...
    from tenuo.audit import AuditEvent, AuditLogger, ...
    from tenuo.templates import FileReader, WebSearcher, ...
"""

# =============================================================================
# Helpers
# =============================================================================

def now() -> int:
    """Return current Unix timestamp for PoP signatures.

    This is a convenience helper for non-Temporal use cases.

    Usage:
        from tenuo import now
        pop = warrant.sign(key, "tool", args, timestamp=now())

    For Temporal workflows, use workflow.now().timestamp() instead.
    """
    import time
    return int(time.time())


# =============================================================================
# Core Types (from Rust)
# =============================================================================
from tenuo_core import (  # type: ignore
    CEL,
    DEFAULT_WARRANT_TTL_SECS,
    # Protocol constants
    MAX_DELEGATION_DEPTH,
    MAX_WARRANT_SIZE,
    MAX_WARRANT_TTL_SECS,
    All,
    # Advanced constraints
    AnyOf,
    ApprovalMetadata,
    # Approval cryptography
    ApprovalPayload,
    Authorizer,
    Cidr,
    Contains,
    Exact,
    Not,
    NotOneOf,
    OneOf,
    # Common constraints
    Pattern,
    PublicKey,
    Range,
    Regex,
    # Revocation
    RevocationRequest,
    SignedApproval,
    SignedRevocationList,
    SigningKey,
    SrlBuilder,
    Subset,
    UrlPattern,
    Warrant,
    Wildcard,
)
from tenuo_core import (
    py_compute_request_hash as compute_request_hash,
)

# Semantic alias: Any() = Wildcard() for zero-trust constraint sets
# Use Any() to explicitly allow any value for a field while in closed-world mode
Any = Wildcard

# =============================================================================
# 80% API - What most users need
# =============================================================================

# Setup
from .config import (
    auto_configure,
    configure,
    is_audit_mode,
    is_configured,
    is_enforce_mode,
    reset_config,
    should_block_violation,
)

# Constraints
from .constraints import Capability, Shlex, Subpath, UrlSafe

# Authority context managers
from .scoped import (
    grant,
    mint,
    mint_sync,
)

# Constraint aliases (shorter names for common use)
# Path = Subpath, Url = UrlSafe, Cmd = Shlex
Path = Subpath
Url = UrlSafe
Cmd = Shlex

# One-line guard (auto-inference)
import tenuo.builder  # noqa: F401 - Adds Warrant.mint_builder()
import tenuo.keys  # noqa: F401 - Adds SigningKey.from_env(), PublicKey.from_env()

# =============================================================================
# Initialize extensions (must run)
# =============================================================================
import tenuo.warrant_ext  # noqa: F401

# BoundWarrant (common result of warrant.bind())
from .bound_warrant import BoundWarrant

# Protection decorator
from .decorators import (
    guard as _guard_decorator,  # Import with temp name to avoid module shadowing
    key_scope,
    warrant_scope,
)

# Diagnostics
from .diagnostics import diagnose, info

# Essential errors only
from .exceptions import (
    AuthorizationDenied,  # Rich error with diff support
    ConfigurationError,
    ConstraintViolation,
    MonotonicityError,
    ScopeViolation,  # Authorization scope exceeded
    TenuoError,
)

# Error explanation
from .explain import explain, explain_str

# Auto-guard (import with alias to avoid shadowing decorator.guard)
from .guard import guard as auto_guard

# Key management
from .keys import KeyRegistry, Keyring

# LangChain integration
from .langchain import (
    LANGCHAIN_AVAILABLE,
    auto_protect,
    guard_agent,
    guard_tools,
)

# Validation result
from .validation import ValidationResult

Warrant.bind = BoundWarrant.bind_warrant

# Ensure guard refers to the decorator function, not the guard module
# The guard module is available as auto_guard
guard = _guard_decorator
del _guard_decorator  # Clean up temporary name

from tenuo.approval import (  # noqa: E402
    ApprovalDenied,
    ApprovalPolicy,
    ApprovalRequest,
    ApprovalRequired,
    ApprovalRule,
    ApprovalTimeout,
    ApprovalVerificationError,
    auto_approve,
    auto_deny,
    cli_prompt,
    require_approval,
    sign_approval,
)

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
    # Approval cryptography
    "ApprovalPayload",
    "SignedApproval",
    "ApprovalMetadata",
    "compute_request_hash",
    # Revocation
    "RevocationRequest",
    "SignedRevocationList",
    "SrlBuilder",
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
    # Protocol constants
    "MAX_DELEGATION_DEPTH",
    "MAX_WARRANT_TTL_SECS",
    "DEFAULT_WARRANT_TTL_SECS",
    "MAX_WARRANT_SIZE",
    # Python-only security constraints
    "Subpath",  # Secure path containment (path traversal protection)
    "UrlSafe",  # SSRF protection (IP/domain blocking)
    "Shlex",  # Shell injection protection (command validation)
    # Constraint aliases (shorter names)
    "Path",  # Alias for Subpath
    "Url",  # Alias for UrlSafe
    "Cmd",  # Alias for Shlex
    # One-line guard
    "auto_guard",  # guard() with auto-inference
    # Errors (essential only)
    "TenuoError",
    "ConstraintViolation",
    "MonotonicityError",
    "ConfigurationError",
    "AuthorizationDenied",  # Rich error with diff support
    "ScopeViolation",  # Authorization scope exceeded
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
    # Approval policy (cryptographically verified human-in-the-loop)
    "ApprovalPolicy",
    "ApprovalRule",
    "ApprovalRequest",
    "ApprovalRequired",
    "ApprovalDenied",
    "ApprovalTimeout",
    "ApprovalVerificationError",
    "require_approval",
    "sign_approval",
    "compute_request_hash",
    "cli_prompt",
    "auto_approve",
    "auto_deny",
]

__version__ = "0.1.0b10"
