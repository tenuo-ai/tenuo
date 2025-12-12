"""
Tenuo Python SDK - Capability tokens for AI agents

A pure Python wrapper around the Rust tenuo_core extension.
"""

# Import all public API from the Rust extension
from tenuo_core import (
    # Core types
    Keypair,
    Warrant,
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
    # ChainStep,  # TODO
    # ChainVerificationResult,  # TODO
    
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

# Re-export everything for clean imports
__all__ = [
    # Core types
    "Keypair",
    "Warrant",
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
    # "ChainStep",
    # "ChainVerificationResult",
    
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
]

__version__ = "0.1.0"
