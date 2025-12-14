"""
Tenuo Python SDK - Capability tokens for AI agents

A pure Python wrapper around the Rust tenuo_core extension.
"""

# Import all public API from the Rust extension
# Note: Commented-out features (TODO) are planned for v0.2+ and not included in v0.1 scope.
from tenuo_core import (  # type: ignore
    # Core types
    Keypair,
    Warrant,
    WarrantType,
    TrustLevel,
    PublicKey,
    Signature,
    Authorizer,
    # Approval,  # TODO: Implement in python.rs
    
    # Constraints - Basic
    # Wildcard,  # TODO
    Pattern,
    # Regex,  # TODO
    Exact,
    OneOf,
    NotOneOf,
    Range,
    
    # Constraints - List operations
    Contains,
    Subset,
    
    # Constraints - Composite
    All,
    AnyOf,
    Not,
    CEL,
    
    # Revocation
    # SignedRevocationList,  # TODO
    # SrlBuilder,  # TODO
    
    # Chain Verification
    ChainStep,
    ChainVerificationResult,
    
    # Gateway Config
    # GatewayConfig,  # TODO
    # CompiledGatewayConfig,  # TODO
    
    # Revocation Manager
    # RevocationManager,  # TODO
    
    # MCP integration
    McpConfig,
    CompiledMcpConfig,
    ExtractionResult,
    
    # Constants
    MAX_DELEGATION_DEPTH,
    # MAX_CONSTRAINT_DEPTH,  # TODO
    WIRE_VERSION,
    WARRANT_HEADER,
)

# Note: Signature is now exported from tenuo_core (added in python.rs)

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
    get_keypair_context,
    set_keypair_context,
    WarrantContext,
    KeypairContext,
)
from .audit import (
    audit_logger,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    AuditLogger,
    log_authorization_success,
    log_authorization_failure,
)
from .builder import AttenuationBuilder

# Import Rust diff types
from tenuo_core import (  # type: ignore
    DelegationDiff,
    DelegationReceipt,
    ToolsDiff,
    ConstraintDiff,
    TtlDiff,
    TrustDiff,
    DepthDiff,
    ChangeType,
)

from .warrant_ext import (
    get_chain_with_diffs,
    compute_diff,
    compute_diff_from_link,
)

# Initialize warrant extensions
# This adds the delegation_receipt property to Warrant
import tenuo.warrant_ext  # noqa: F401

# Re-export everything for clean imports
__all__ = [
    # Core types
    "Keypair",
    "Warrant",
    "WarrantType",
    "TrustLevel",
    "PublicKey",
    "Signature",
    "Authorizer",
    # "Approval",
    
    # Constraints - Basic
    # "Wildcard",
    "Pattern",
    # "Regex",
    "Exact",
    "OneOf",
    "NotOneOf",
    "Range",
    
    # Constraints - List operations
    "Contains",
    "Subset",
    
    # Constraints - Composite
    "All",
    "AnyOf",
    "Not",
    "CEL",
    
    # Revocation
    # "SignedRevocationList",
    # "SrlBuilder",
    
    # Chain Verification
    "ChainStep",
    "ChainVerificationResult",
    
    # Gateway Config
    # "GatewayConfig",
    # "CompiledGatewayConfig",
    
    # Revocation Manager
    # "RevocationManager",
    
    # MCP integration
    "McpConfig",
    "CompiledMcpConfig",
    "ExtractionResult",
    
    # Constants
    "MAX_DELEGATION_DEPTH",
    # "MAX_CONSTRAINT_DEPTH",
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
    "get_keypair_context",
    "set_keypair_context",
    "WarrantContext",
    "KeypairContext",
    
    # Audit logging (SIEM compatible)
    "audit_logger",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "AuditLogger",
    "log_authorization_success",
    "log_authorization_failure",
    
    # Delegation diffs and receipts
    "AttenuationBuilder",
    "DelegationDiff",
    "DelegationReceipt",
    "ToolsDiff",
    "ConstraintDiff",
    "TtlDiff",
    "TrustDiff",
    "DepthDiff",
    "ChangeType",
    "get_chain_with_diffs",
    "compute_diff",
    "compute_diff_from_link",
]

__version__ = "0.1.0"
