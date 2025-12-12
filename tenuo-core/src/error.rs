//! Error types for Tenuo.
//!
//! Errors are designed to be specific and actionable, especially for
//! constraint violations during attenuation. This helps developers
//! understand exactly what went wrong and how to fix it.

use thiserror::Error;

/// Result type alias for Tenuo operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in Tenuo operations.
#[derive(Error, Debug)]
pub enum Error {
    // =========================================================================
    // Signature & Cryptographic Errors
    // =========================================================================
    
    /// Warrant signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Missing signature for Proof-of-Possession.
    #[error("missing signature: {0}")]
    MissingSignature(String),

    /// Cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    // =========================================================================
    // Warrant Lifecycle Errors
    // =========================================================================
    
    /// Warrant has been revoked.
    #[error("warrant revoked: {0}")]
    WarrantRevoked(String),

    /// Warrant has expired.
    #[error("warrant expired at {0}")]
    WarrantExpired(chrono::DateTime<chrono::Utc>),

    /// Warrant depth exceeds maximum allowed.
    #[error("delegation depth {0} exceeds maximum {1}")]
    DepthExceeded(u32, u32),

    /// Invalid warrant ID format.
    #[error("invalid warrant ID: {0}")]
    InvalidWarrantId(String),

    /// Invalid TTL value.
    #[error("invalid TTL: {0}")]
    InvalidTtl(String),

    /// Constraint nesting depth exceeds maximum allowed.
    #[error("constraint depth {depth} exceeds maximum {max}")]
    ConstraintDepthExceeded { depth: u32, max: u32 },

    /// Payload size exceeds maximum allowed.
    #[error("payload size {size} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },

    /// Parent warrant not provided for attenuation.
    #[error("parent warrant required for attenuation")]
    ParentRequired,

    /// Tool name mismatch during attenuation.
    #[error("tool name mismatch: parent has '{parent}', child has '{child}'")]
    ToolMismatch { parent: String, child: String },

    // =========================================================================
    // Monotonicity Violation Errors (Attenuation)
    // =========================================================================
    
    /// Generic attenuation would expand capabilities.
    /// Use more specific errors when possible.
    #[error("attenuation would expand capabilities: {0}")]
    MonotonicityViolation(String),

    /// Incompatible constraint types for attenuation.
    /// E.g., Range cannot attenuate to Pattern.
    #[error("incompatible constraint types: cannot attenuate {parent_type} to {child_type}")]
    IncompatibleConstraintTypes {
        parent_type: String,
        child_type: String,
    },

    /// Cannot attenuate to Wildcard (would allow everything).
    #[error("cannot attenuate to Wildcard: this would expand permissions from {parent_type}")]
    WildcardExpansion { parent_type: String },

    /// NotOneOf would result in an empty set (paradox).
    /// Child excludes everything the parent allows.
    #[error("empty result set: NotOneOf excludes all {count} values from parent {parent_type}")]
    EmptyResultSet { parent_type: String, count: usize },

    /// NotOneOf child doesn't exclude all values that parent excludes.
    #[error("exclusion removed: child must still exclude '{value}'")]
    ExclusionRemoved { value: String },

    /// OneOf/Subset child contains value not in parent set.
    #[error("value not allowed: '{value}' is not in parent's allowed set")]
    ValueNotInParentSet { value: String },

    /// Range child expands beyond parent bounds.
    #[error("range expanded: child {bound} ({child_value}) exceeds parent {bound} ({parent_value})")]
    RangeExpanded {
        bound: String, // "min" or "max"
        parent_value: f64,
        child_value: f64,
    },

    /// Pattern child is broader than parent.
    #[error("pattern expanded: child pattern '{child}' is broader than parent '{parent}'")]
    PatternExpanded { parent: String, child: String },

    /// Contains child doesn't require all values that parent requires.
    #[error("required value removed: child must still require '{value}'")]
    RequiredValueRemoved { value: String },

    /// Exact value mismatch.
    #[error("exact value mismatch: parent requires '{parent}', child has '{child}'")]
    ExactValueMismatch { parent: String, child: String },

    // =========================================================================
    // Constraint Matching Errors (Authorization)
    // =========================================================================
    
    /// Constraint does not match the action.
    #[error("constraint not satisfied: {field} - {reason}")]
    ConstraintNotSatisfied { field: String, reason: String },

    // =========================================================================
    // Constraint Syntax Errors
    // =========================================================================
    
    /// Invalid pattern syntax.
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),

    /// Invalid range specification.
    #[error("invalid range: {0}")]
    InvalidRange(String),

    /// Invalid regex pattern.
    #[error("invalid regex: {0}")]
    InvalidRegex(String),

    /// CEL expression error.
    #[error("CEL expression error: {0}")]
    CelError(String),

    // =========================================================================
    // Serialization Errors
    // =========================================================================
    
    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Wire format version mismatch.
    #[error("unsupported wire format version: {0}")]
    UnsupportedVersion(u8),

    // =========================================================================
    // General Errors
    // =========================================================================
    
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Chain verification failed.
    #[error("chain verification failed: {0}")]
    ChainVerificationFailed(String),

    // =========================================================================
    // Approval Errors
    // =========================================================================

    /// Approval has expired.
    #[error("approval expired: approved at {approved_at}, expired at {expired_at}")]
    ApprovalExpired {
        approved_at: chrono::DateTime<chrono::Utc>,
        expired_at: chrono::DateTime<chrono::Utc>,
    },

    /// Insufficient approvals for multi-sig.
    #[error("insufficient approvals: required {required}, received {received}")]
    InsufficientApprovals { required: u32, received: u32 },

    /// Invalid approval (bad format, DoS attempt, etc.).
    #[error("invalid approval: {0}")]
    InvalidApproval(String),

    /// Unknown approval provider.
    #[error("unknown approval provider: {0}")]
    UnknownProvider(String),

    /// Operation unauthorized.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::SerializationError(e.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for Error {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Error::DeserializationError(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Error::CryptoError(e.to_string())
    }
}

