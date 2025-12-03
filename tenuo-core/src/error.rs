//! Error types for Tenuo.

use thiserror::Error;

/// Result type alias for Tenuo operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in Tenuo operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Warrant signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Missing signature for Proof-of-Possession.
    #[error("missing signature: {0}")]
    MissingSignature(String),

    /// Warrant has been revoked.
    #[error("warrant revoked: {0}")]
    WarrantRevoked(String),

    /// Warrant has expired.
    #[error("warrant expired at {0}")]
    WarrantExpired(chrono::DateTime<chrono::Utc>),

    /// Warrant depth exceeds maximum allowed.
    #[error("delegation depth {0} exceeds maximum {1}")]
    DepthExceeded(u32, u32),

    /// Attenuation would expand capabilities (violates monotonicity).
    #[error("attenuation would expand capabilities: {0}")]
    MonotonicityViolation(String),

    /// Constraint does not match the action.
    #[error("constraint not satisfied: {field} - {reason}")]
    ConstraintNotSatisfied { field: String, reason: String },

    /// Invalid pattern syntax.
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),

    /// Invalid range specification.
    #[error("invalid range: {0}")]
    InvalidRange(String),

    /// CEL expression error.
    #[error("CEL expression error: {0}")]
    CelError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Invalid warrant ID format.
    #[error("invalid warrant ID: {0}")]
    InvalidWarrantId(String),

    /// Parent warrant not provided for attenuation.
    #[error("parent warrant required for attenuation")]
    ParentRequired,

    /// Tool name mismatch during attenuation.
    #[error("tool name mismatch: parent has '{parent}', child has '{child}'")]
    ToolMismatch { parent: String, child: String },

    /// Cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    /// Wire format version mismatch.
    #[error("unsupported wire format version: {0}")]
    UnsupportedVersion(u8),

    /// Chain verification failed.
    #[error("chain verification failed: {0}")]
    ChainVerificationFailed(String),

    /// Invalid regex pattern.
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
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

