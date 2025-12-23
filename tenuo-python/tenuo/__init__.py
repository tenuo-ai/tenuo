"""
Tenuo Python SDK - Capability tokens for AI agents

A pure Python wrapper around the Rust tenuo_core extension.
"""

from tenuo_core import (  # type: ignore
    # Core types
    SigningKey,
    Warrant,
    WarrantType,
    Clearance,
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
    Regex,
    Wildcard,
    # Chain Verification
    ChainStep,
    ChainVerificationResult,
    # MCP integration
    McpConfig,
    CompiledMcpConfig,
    ExtractionResult,
    # Constants
    MAX_DELEGATION_DEPTH,
    MAX_WARRANT_SIZE,
    MAX_WARRANT_TTL_SECS,
    DEFAULT_WARRANT_TTL_SECS,
    WIRE_VERSION,
    WARRANT_HEADER,
)

# Optional: Some constraints may be absent on lean builds of tenuo_core
try:
    from tenuo_core import Cidr  # type: ignore
except Exception:  # pragma: no cover - defensive import
    Cidr = None  # type: ignore

try:
    from tenuo_core import UrlPattern  # type: ignore
except Exception:  # pragma: no cover - defensive import
    UrlPattern = None  # type: ignore

from .constraints import Constraints, Capability

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
    # Scope violations
    ScopeViolation,
    AuthorizationError,
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
    ClearanceViolation,
    ClearanceLevelExceeded,
    # Issuance errors
    IssuanceError,
    UnauthorizedToolIssuance,
    SelfIssuanceProhibited,
    IssueDepthExceeded,
    InvalidWarrantType,
    IssuerChainTooLong,
    # PoP errors
    PopError,
    MissingSigningKey,
    SignatureMismatch,
    PopExpired,
    # Chain errors
    ChainError,
    BrokenChain,
    CycleDetected,
    UntrustedRoot,
    ParentRequired,
    DelegationAuthorityError,
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
    # DX (diff-style errors)
    AuthorizationDenied,
    ConstraintResult,
    # Helper
    categorize_rust_error,
)
from .decorators import (
    lockdown,
    get_warrant_context,
    set_warrant_context,
    get_signing_key_context,
    set_signing_key_context,
    is_bypass_enabled,
    WarrantContext,
    SigningKeyContext,
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
from .builder import AttenuationBuilder, WarrantBuilder, IssuanceBuilder

# Tier 1 API - Simple scoped authority
from .config import (
    configure,
    get_config,
    reset_config,
    is_configured,
    is_dev_mode,
    TenuoConfig,
)
from .keys import (
    load_signing_key_from_env,
    load_signing_key_from_file,
    Keyring,
    KeyRegistry,
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
    secure_agent,  # DX: One-liner entry point
    LANGCHAIN_AVAILABLE,
)

# Tier 1 API - LangGraph integration
from .langgraph import (
    tenuo_node,
    require_warrant,
    TenuoToolNode,  # DX: Drop-in ToolNode replacement
    LANGGRAPH_AVAILABLE,
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
    DepthDiff,
    ChangeType,
)

from .warrant_ext import (
    get_chain_with_diffs,
    compute_diff,
    # Type protocols
    ReadableWarrant,
    SignableWarrant,
    AnyWarrant,
    # Debugging
    WhyDenied,
    DenyCode,
    PreviewResult,
)

# Initialize warrant extensions
# This adds the delegation_receipt property to Warrant
import tenuo.warrant_ext  # noqa: F401

# Import BoundWarrant class
from .bound_warrant import BoundWarrant

# Import testing utilities
from .testing import (
    allow_all,
    deterministic_headers,
)

# Import diagnostics
from .diagnostics import (
    diagnose,
    info,
)

# Import Client


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
    # Key management
    "load_signing_key_from_env",
    "load_signing_key_from_file",
    "Keyring",
    "KeyRegistry",
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
    "secure_agent",  # DX: One-liner entry point
    "LANGCHAIN_AVAILABLE",
    # LangGraph
    "tenuo_node",
    "require_warrant",
    "TenuoToolNode",  # DX: Drop-in ToolNode replacement
    "LANGGRAPH_AVAILABLE",
    # Error explanation
    "explain",
    "explain_str",
    
    # =========================================================================
    # Tier 2 API (Explicit control)
    # =========================================================================

    # Core types
    "SigningKey",
    "Warrant",
    "BoundWarrant",  # DX: Warrant bound to key
    "WarrantType",
    "Clearance",
    "PublicKey",
    "Signature",
    "Authorizer",
    # DX: Testing utilities
    "allow_all",
    "is_bypass_enabled",
    "deterministic_headers",
    # DX: Diagnostics
    "diagnose",
    "info",
    # Constraints
    "Constraints",
    "Capability",
    "Pattern",
    "Exact",
    "OneOf",
    "NotOneOf",
    "Range",
    "Cidr",
    "UrlPattern",
    "Contains",
    "Subset",
    "All",
    "AnyOf",
    "Not",
    "CEL",
    "Regex",
    "Wildcard",
    # Chain Verification
    "ChainStep",
    "ChainVerificationResult",
    # MCP integration
    "McpConfig",
    "CompiledMcpConfig",
    "ExtractionResult",
    # Constants
    "MAX_DELEGATION_DEPTH",
    "MAX_WARRANT_SIZE",
    "MAX_WARRANT_TTL_SECS",
    "DEFAULT_WARRANT_TTL_SECS",
    "WIRE_VERSION",
    "WARRANT_HEADER",
    
    # =========================================================================
    # Exceptions
    # =========================================================================
    # Base
    "TenuoError",
    "RUST_ERROR_MAP",
    "RUST_ERROR_VARIANTS",
    # Exceptions - Crypto
    "CryptoError",
    "SignatureInvalid",
    "MissingSignature",
    # Exceptions - Scope violations
    "ScopeViolation",
    "AuthorizationError",
    "ToolNotAuthorized",
    "ToolMismatch",
    "ConstraintViolation",
    # Exceptions - Lifecycle
    "RevokedError",
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
    # Exceptions - Clearance violations
    "ClearanceViolation",
    "ClearanceLevelExceeded",
    # Exceptions - Issuance errors
    "IssuanceError",
    "UnauthorizedToolIssuance",
    "SelfIssuanceProhibited",
    "IssueDepthExceeded",
    "InvalidWarrantType",
    "IssuerChainTooLong",
    # Exceptions - PoP errors
    "PopError",
    "MissingSigningKey",
    "SignatureMismatch",
    "PopExpired",
    # Exceptions - Chain errors
    "ChainError",
    "BrokenChain",
    "CycleDetected",
    "UntrustedRoot",
    "ParentRequired",
    "DelegationAuthorityError",
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
    # Exceptions - DX (diff-style errors)
    "AuthorizationDenied",
    "ConstraintResult",
    # Exceptions - Helper
    "categorize_rust_error",
    # Decorators
    "lockdown",
    "get_warrant_context",
    "set_warrant_context",
    "get_signing_key_context",
    "set_signing_key_context",
    "WarrantContext",
    "SigningKeyContext",
    
    # Audit logging (SIEM compatible)
    "audit_logger",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "AuditLogger",
    "log_authorization_success",
    "log_authorization_failure",
    
    # Delegation diffs and receipts
    "WarrantBuilder",
    "AttenuationBuilder",
    "IssuanceBuilder",
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
    # Type protocols
    "ReadableWarrant",
    "SignableWarrant",
    "AnyWarrant",
    # Debugging types
    "WhyDenied",
    "DenyCode",
    "PreviewResult",
]

__version__ = "0.1.0a9"
