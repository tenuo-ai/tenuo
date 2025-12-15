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

# Tier 1 API - Simple scoped authority
from .config import (
    configure,
    get_config,
    reset_config,
    is_configured,
    is_dev_mode,
    TenuoConfig,
)
from .scoped import (
    root_task,
    root_task_sync,
    scoped_task,
    ScopedTaskBuilder,
    ScopePreview,
)

# Tier 1 API - Tool protection
from .protect import (
    protect_tools,
    protected_tool,
)
from .schemas import (
    ToolSchema,
    TOOL_SCHEMAS,
    register_schema,
    get_schema,
    recommended_constraints,
    check_constraints,
)

# Tier 1 API - LangChain integration
from .langchain import (
    protect_langchain_tools,
    TenuoTool,
    LANGCHAIN_AVAILABLE,
)

# Tier 1 API - LangGraph integration
from .langgraph import (
    tenuo_node,
    require_warrant,
)

# Tier 1 API - Error explanation
from .explain import (
    explain,
    explain_str,
)

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
    # =========================================================================
    # Tier 1 API (Simple - 3 lines of code)
    # =========================================================================
    "configure",
    "root_task",
    "root_task_sync",
    "scoped_task",
    # Tier 1 helpers
    "get_config",
    "reset_config",
    "is_configured",
    "is_dev_mode",
    "TenuoConfig",
    "ScopedTaskBuilder",
    "ScopePreview",
    # Tool protection
    "protect_tools",
    "protected_tool",
    # Tool schemas
    "ToolSchema",
    "TOOL_SCHEMAS",
    "register_schema",
    "get_schema",
    "recommended_constraints",
    "check_constraints",
    
    # =========================================================================
    # Framework Integrations
    # =========================================================================
    # LangChain
    "protect_langchain_tools",
    "TenuoTool",
    "LANGCHAIN_AVAILABLE",
    # LangGraph
    "tenuo_node",
    "require_warrant",
    # Error explanation
    "explain",
    "explain_str",
    
    # =========================================================================
    # Tier 2 API (Explicit control)
    # =========================================================================
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
