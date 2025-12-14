"""
Tenuo Python SDK - Capability tokens for AI agents

A pure Python wrapper around the Rust tenuo_core extension.
"""

from tenuo_core import (  # type: ignore
    # Core types
    Keypair,
    Warrant,
    WarrantType,
    TrustLevel,
    PublicKey,
    Signature,
    Authorizer,
    # Constraints
    Pattern,
    Exact,
    OneOf,
    NotOneOf,
    Range,
    Contains,
    Subset,
    All,
    AnyOf,
    Not,
    CEL,
    # Chain Verification
    ChainStep,
    ChainVerificationResult,
    # MCP integration
    McpConfig,
    CompiledMcpConfig,
    ExtractionResult,
    # Constants
    MAX_DELEGATION_DEPTH,
    WIRE_VERSION,
    WARRANT_HEADER,
)

# Import Pythonic additions - exceptions map 1:1 to Rust Error variants
from .exceptions import (
    # Base
    TenuoError,
    RUST_ERROR_MAP,
    RUST_ERROR_VARIANTS,
    # Crypto errors
    CryptoError,
    SignatureInvalid,
    MissingSignature,
    InvalidSignature,  # alias for SignatureInvalid
    # Scope violations
    ScopeViolation,
    ToolNotAuthorized,
    ToolMismatch,
    ConstraintViolation,
    ExpiredError,
    Unauthorized,
    # Monotonicity errors
    MonotonicityError,
    IncompatibleConstraintTypes,
    WildcardExpansion,
    EmptyResultSet,
    ExclusionRemoved,
    ValueNotInParentSet,
    RangeExpanded,
    PatternExpanded,
    RequiredValueRemoved,
    ExactValueMismatch,
    # Trust violations
    TrustViolation,
    TrustLevelExceeded,
    # PoP errors
    PopError,
    MissingKeypair,
    SignatureMismatch,
    PopExpired,
    # Chain errors
    ChainError,
    BrokenChain,
    CycleDetected,
    UntrustedRoot,
    ParentRequired,
    # Limit errors
    LimitError,
    DepthExceeded,
    ConstraintDepthExceeded,
    PayloadTooLarge,
    TtlExceeded,
    # Revocation
    RevokedError,
    # Validation errors
    ValidationError,
    MissingField,
    InvalidWarrantId,
    InvalidTtl,
    # Constraint syntax errors
    ConstraintSyntaxError,
    InvalidPattern,
    InvalidRange,
    InvalidRegex,
    CelError,
    # Serialization errors
    SerializationError,
    DeserializationError,
    UnsupportedVersion,
    # Approval errors
    ApprovalError,
    ApprovalExpired,
    InsufficientApprovals,
    InvalidApproval,
    UnknownProvider,
    # Config
    ConfigurationError,
    # Legacy aliases
    WarrantError,
    AuthorizationError,
    # Helper
    categorize_rust_error,
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
    # Constraints
    "Pattern",
    "Exact",
    "OneOf",
    "NotOneOf",
    "Range",
    "Contains",
    "Subset",
    "All",
    "AnyOf",
    "Not",
    "CEL",
    # Chain Verification
    "ChainStep",
    "ChainVerificationResult",
    # MCP integration
    "McpConfig",
    "CompiledMcpConfig",
    "ExtractionResult",
    # Constants
    "MAX_DELEGATION_DEPTH",
    "WIRE_VERSION",
    "WARRANT_HEADER",
    # Exceptions - Base & Mapping
    "TenuoError",
    "RUST_ERROR_MAP",
    "RUST_ERROR_VARIANTS",
    # Exceptions - Crypto
    "CryptoError",
    "SignatureInvalid",
    "MissingSignature",
    "InvalidSignature",
    # Exceptions - Scope violations
    "ScopeViolation",
    "ToolNotAuthorized",
    "ToolMismatch",
    "ConstraintViolation",
    "ExpiredError",
    "Unauthorized",
    # Exceptions - Monotonicity
    "MonotonicityError",
    "IncompatibleConstraintTypes",
    "WildcardExpansion",
    "EmptyResultSet",
    "ExclusionRemoved",
    "ValueNotInParentSet",
    "RangeExpanded",
    "PatternExpanded",
    "RequiredValueRemoved",
    "ExactValueMismatch",
    # Exceptions - Trust violations
    "TrustViolation",
    "TrustLevelExceeded",
    # Exceptions - PoP errors
    "PopError",
    "MissingKeypair",
    "SignatureMismatch",
    "PopExpired",
    # Exceptions - Chain errors
    "ChainError",
    "BrokenChain",
    "CycleDetected",
    "UntrustedRoot",
    "ParentRequired",
    # Exceptions - Limit errors
    "LimitError",
    "DepthExceeded",
    "ConstraintDepthExceeded",
    "PayloadTooLarge",
    "TtlExceeded",
    # Exceptions - Revocation
    "RevokedError",
    # Exceptions - Validation
    "ValidationError",
    "MissingField",
    "InvalidWarrantId",
    "InvalidTtl",
    # Exceptions - Constraint syntax
    "ConstraintSyntaxError",
    "InvalidPattern",
    "InvalidRange",
    "InvalidRegex",
    "CelError",
    # Exceptions - Serialization
    "SerializationError",
    "DeserializationError",
    "UnsupportedVersion",
    # Exceptions - Approval
    "ApprovalError",
    "ApprovalExpired",
    "InsufficientApprovals",
    "InvalidApproval",
    "UnknownProvider",
    # Exceptions - Config
    "ConfigurationError",
    # Exceptions - Legacy aliases
    "WarrantError",
    "AuthorizationError",
    # Exceptions - Helper
    "categorize_rust_error",
    # Decorators
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
]

__version__ = "0.1.0"
