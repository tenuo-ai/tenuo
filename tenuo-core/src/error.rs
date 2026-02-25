//! Error types for Tenuo.
//!
//! Errors are designed to be specific and actionable, especially for
//! constraint violations during attenuation. This helps developers
//! understand exactly what went wrong and how to fix it.

use thiserror::Error;

/// Result type alias for Tenuo operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Canonical error codes from wire format spec (§Appendix A).
///
/// All Tenuo errors map to these codes. Protocol-specific representations
/// (strings for HTTP, negative codes for JSON-RPC) are derived from these.
///
/// Code ranges:
/// - 1000-1099: Envelope errors
/// - 1100-1199: Signature errors
/// - 1200-1299: Payload structure errors
/// - 1300-1399: Temporal validation errors
/// - 1400-1499: Chain validation errors
/// - 1500-1599: Capability errors
/// - 1600-1699: PoP errors
/// - 1700-1799: Multi-sig errors
/// - 1800-1899: Revocation errors
/// - 1900-1999: Size limit errors
/// - 2000-2099: Extension errors
/// - 2100-2199: Reserved namespace errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    // Envelope errors (1000-1099)
    UnsupportedEnvelopeVersion = 1000,
    InvalidEnvelopeStructure = 1001,

    // Signature errors (1100-1199)
    SignatureInvalid = 1100,
    SignatureAlgorithmMismatch = 1101,
    UnsupportedAlgorithm = 1102,
    InvalidKeyLength = 1103,
    InvalidSignatureLength = 1104,

    // Payload structure errors (1200-1299)
    UnsupportedPayloadVersion = 1200,
    InvalidPayloadStructure = 1201,
    MalformedCBOR = 1202,
    UnknownPayloadField = 1203,
    MissingRequiredField = 1204,

    // Temporal validation errors (1300-1399)
    WarrantExpired = 1300,
    WarrantNotYetValid = 1301,
    IssuedInFuture = 1302,
    TTLExceeded = 1303,

    // Chain validation errors (1400-1499)
    InvalidIssuer = 1400,
    ParentHashMismatch = 1401,
    DepthExceeded = 1402,
    DepthViolation = 1403,
    ChainTooLong = 1404,
    ChainBroken = 1405,
    UntrustedRoot = 1406,

    // Capability errors (1500-1599)
    ToolNotAuthorized = 1500,
    ConstraintViolation = 1501,
    InvalidAttenuation = 1502,
    CapabilityExpansion = 1503,
    UnknownConstraintType = 1504,

    // PoP errors (1600-1699)
    PopSignatureInvalid = 1600,
    PopExpired = 1601,
    PopChallengeInvalid = 1602,

    // Multi-sig errors (1700-1799)
    InsufficientApprovals = 1700,
    ApprovalInvalid = 1701,
    ApproverNotAuthorized = 1702,
    ApprovalExpired = 1703,
    UnsupportedApprovalVersion = 1704,
    ApprovalPayloadInvalid = 1705,
    ApprovalRequestHashMismatch = 1706,

    // Revocation errors (1800-1899)
    WarrantRevoked = 1800,
    SRLInvalid = 1801,
    SRLVersionRollback = 1802,

    // Size limit errors (1900-1999)
    WarrantTooLarge = 1900,
    ChainTooLarge = 1901,
    TooManyTools = 1902,
    TooManyConstraints = 1903,
    ExtensionTooLarge = 1904,
    ValueTooLarge = 1905,

    // Extension errors (2000-2099)
    ReservedExtensionKey = 2000,
    InvalidExtensionValue = 2001,

    // Reserved namespace errors (2100-2199)
    ReservedToolName = 2100,
}

impl ErrorCode {
    /// Get the numeric code value.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Get machine-readable name (kebab-case).
    ///
    /// This is the canonical string representation used in HTTP APIs.
    pub fn name(self) -> &'static str {
        match self {
            // Envelope errors
            Self::UnsupportedEnvelopeVersion => "unsupported-envelope-version",
            Self::InvalidEnvelopeStructure => "invalid-envelope-structure",

            // Signature errors
            Self::SignatureInvalid => "signature-invalid",
            Self::SignatureAlgorithmMismatch => "signature-algorithm-mismatch",
            Self::UnsupportedAlgorithm => "unsupported-algorithm",
            Self::InvalidKeyLength => "invalid-key-length",
            Self::InvalidSignatureLength => "invalid-signature-length",

            // Payload structure errors
            Self::UnsupportedPayloadVersion => "unsupported-payload-version",
            Self::InvalidPayloadStructure => "invalid-payload-structure",
            Self::MalformedCBOR => "malformed-cbor",
            Self::UnknownPayloadField => "unknown-payload-field",
            Self::MissingRequiredField => "missing-required-field",

            // Temporal validation errors
            Self::WarrantExpired => "warrant-expired",
            Self::WarrantNotYetValid => "warrant-not-yet-valid",
            Self::IssuedInFuture => "issued-in-future",
            Self::TTLExceeded => "ttl-exceeded",

            // Chain validation errors
            Self::InvalidIssuer => "invalid-issuer",
            Self::ParentHashMismatch => "parent-hash-mismatch",
            Self::DepthExceeded => "depth-exceeded",
            Self::DepthViolation => "depth-violation",
            Self::ChainTooLong => "chain-too-long",
            Self::ChainBroken => "chain-broken",
            Self::UntrustedRoot => "untrusted-root",

            // Capability errors
            Self::ToolNotAuthorized => "tool-not-authorized",
            Self::ConstraintViolation => "constraint-violation",
            Self::InvalidAttenuation => "invalid-attenuation",
            Self::CapabilityExpansion => "capability-expansion",
            Self::UnknownConstraintType => "unknown-constraint-type",

            // PoP errors
            Self::PopSignatureInvalid => "pop-signature-invalid",
            Self::PopExpired => "pop-expired",
            Self::PopChallengeInvalid => "pop-challenge-invalid",

            // Multi-sig errors
            Self::InsufficientApprovals => "insufficient-approvals",
            Self::ApprovalInvalid => "approval-invalid",
            Self::ApproverNotAuthorized => "approver-not-authorized",
            Self::ApprovalExpired => "approval-expired",
            Self::UnsupportedApprovalVersion => "unsupported-approval-version",
            Self::ApprovalPayloadInvalid => "approval-payload-invalid",
            Self::ApprovalRequestHashMismatch => "approval-request-hash-mismatch",

            // Revocation errors
            Self::WarrantRevoked => "warrant-revoked",
            Self::SRLInvalid => "srl-invalid",
            Self::SRLVersionRollback => "srl-version-rollback",

            // Size limit errors
            Self::WarrantTooLarge => "warrant-too-large",
            Self::ChainTooLarge => "chain-too-large",
            Self::TooManyTools => "too-many-tools",
            Self::TooManyConstraints => "too-many-constraints",
            Self::ExtensionTooLarge => "extension-too-large",
            Self::ValueTooLarge => "value-too-large",

            // Extension errors
            Self::ReservedExtensionKey => "reserved-extension-key",
            Self::InvalidExtensionValue => "invalid-extension-value",

            // Reserved namespace errors
            Self::ReservedToolName => "reserved-tool-name",
        }
    }

    /// Get HTTP status code based on error category.
    pub fn http_status(self) -> u16 {
        match self.code() / 100 {
            10 => 400, // Envelope errors -> Bad Request
            11 => 401, // Signature errors -> Unauthorized
            12 => 400, // Payload errors -> Bad Request
            13 => 401, // Temporal errors -> Unauthorized
            14 => 403, // Chain errors -> Forbidden
            15 => 403, // Capability errors -> Forbidden
            16 => 401, // PoP errors -> Unauthorized
            17 => 403, // Approval errors -> Forbidden
            18 => 401, // Revocation -> Unauthorized
            19 => 413, // Size limits -> Payload Too Large
            20 => 400, // Extensions -> Bad Request
            21 => 400, // Reserved namespace -> Bad Request
            _ => 500,  // Unknown -> Internal Error
        }
    }

    /// Get human-readable description.
    pub fn description(self) -> &'static str {
        match self {
            // Envelope errors
            Self::UnsupportedEnvelopeVersion => "Envelope version not supported",
            Self::InvalidEnvelopeStructure => "Envelope structure is invalid",

            // Signature errors
            Self::SignatureInvalid => "Signature verification failed",
            Self::SignatureAlgorithmMismatch => "Signature algorithm does not match key type",
            Self::UnsupportedAlgorithm => "Cryptographic algorithm not supported",
            Self::InvalidKeyLength => "Cryptographic key length is invalid",
            Self::InvalidSignatureLength => "Signature length is invalid",

            // Payload structure errors
            Self::UnsupportedPayloadVersion => "Payload version not supported",
            Self::InvalidPayloadStructure => "Payload structure is invalid",
            Self::MalformedCBOR => "CBOR serialization is malformed",
            Self::UnknownPayloadField => "Unknown field in payload",
            Self::MissingRequiredField => "Required field is missing",

            // Temporal validation errors
            Self::WarrantExpired => "Warrant has expired",
            Self::WarrantNotYetValid => "Warrant is not yet valid",
            Self::IssuedInFuture => "Warrant issued_at is in the future",
            Self::TTLExceeded => "Warrant TTL exceeded",

            // Chain validation errors
            Self::InvalidIssuer => "Issuer is invalid",
            Self::ParentHashMismatch => "Parent hash does not match",
            Self::DepthExceeded => "Delegation depth exceeded",
            Self::DepthViolation => "Delegation depth constraint violated",
            Self::ChainTooLong => "Warrant chain too long",
            Self::ChainBroken => "Warrant chain verification failed",
            Self::UntrustedRoot => "Root issuer not trusted",

            // Capability errors
            Self::ToolNotAuthorized => "Tool not authorized by warrant",
            Self::ConstraintViolation => "Constraint not satisfied",
            Self::InvalidAttenuation => "Attenuation is invalid",
            Self::CapabilityExpansion => "Attenuation would expand capabilities",
            Self::UnknownConstraintType => "Constraint type not recognized",

            // PoP errors
            Self::PopSignatureInvalid => "Proof-of-Possession signature invalid",
            Self::PopExpired => "Proof-of-Possession expired",
            Self::PopChallengeInvalid => "Proof-of-Possession challenge invalid",

            // Multi-sig errors
            Self::InsufficientApprovals => "Insufficient approvals for multi-sig",
            Self::ApprovalInvalid => "Approval is invalid",
            Self::ApproverNotAuthorized => "Approver not authorized",
            Self::ApprovalExpired => "Approval has expired",
            Self::UnsupportedApprovalVersion => "Approval version not supported",
            Self::ApprovalPayloadInvalid => "Approval payload is invalid",
            Self::ApprovalRequestHashMismatch => "Approval request hash mismatch",

            // Revocation errors
            Self::WarrantRevoked => "Warrant has been revoked",
            Self::SRLInvalid => "Signature Revocation List is invalid",
            Self::SRLVersionRollback => "SRL version rollback detected",

            // Size limit errors
            Self::WarrantTooLarge => "Warrant size exceeds limit",
            Self::ChainTooLarge => "Warrant chain size exceeds limit",
            Self::TooManyTools => "Too many tools in warrant",
            Self::TooManyConstraints => "Too many constraints",
            Self::ExtensionTooLarge => "Extension size exceeds limit",
            Self::ValueTooLarge => "Value size exceeds limit",

            // Extension errors
            Self::ReservedExtensionKey => "Extension key is reserved",
            Self::InvalidExtensionValue => "Extension value is invalid",

            // Reserved namespace errors
            Self::ReservedToolName => "Tool name is reserved",
        }
    }
}

/// Errors that can occur in Tenuo operations.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
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

    /// Warrant issued in the future (Clock Skew violation).
    #[error("warrant issued in the future (check system clock)")]
    IssuedInFuture,

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
    #[error(
        "range expanded: child {bound} ({child_value}) exceeds parent {bound} ({parent_value})"
    )]
    RangeExpanded {
        bound: String, // "min" or "max"
        parent_value: f64,
        child_value: f64,
    },

    /// Range inclusivity was expanded (exclusive -> inclusive at same bound).
    #[error(
        "range inclusivity expanded: child made {bound} ({value}) inclusive when parent was exclusive"
    )]
    RangeInclusivityExpanded {
        bound: String, // "min" or "max"
        value: f64,
        parent_inclusive: bool,
        child_inclusive: bool,
    },

    /// Value is not within the specified range.
    #[error("value {value} not in range [{min:?}, {max:?}]")]
    ValueNotInRange {
        value: f64,
        min: Option<f64>,
        max: Option<f64>,
    },

    /// Pattern attenuation cannot be verified (complex patterns with multiple wildcards).
    #[error("pattern attenuation cannot be verified: parent pattern '{parent}' has multiple wildcards (child: '{child}'). Use UrlPattern for URL constraints, or use exact equality")]
    PatternExpanded { parent: String, child: String },

    /// Invalid CIDR notation.
    #[error("invalid CIDR: '{cidr}' - {reason}")]
    InvalidCidr { cidr: String, reason: String },

    /// Invalid IP address.
    #[error("invalid IP address: '{ip}' - {reason}")]
    InvalidIpAddress { ip: String, reason: String },

    /// IP address not in CIDR range.
    #[error("IP address '{ip}' not in CIDR range '{cidr}'")]
    IpNotInCidr { ip: String, cidr: String },

    /// Child CIDR is not a subnet of parent.
    #[error("CIDR not subnet: '{child}' is not a subnet of '{parent}'")]
    CidrNotSubnet { parent: String, child: String },

    /// Invalid URL.
    #[error("invalid URL: '{url}' - {reason}")]
    InvalidUrl { url: String, reason: String },

    /// URL scheme mismatch or expansion.
    #[error("URL scheme expanded: child scheme '{child}' not allowed by parent scheme '{parent}'")]
    UrlSchemeExpanded { parent: String, child: String },

    /// URL host mismatch or expansion.
    #[error("URL host expanded: child host '{child}' not allowed by parent host '{parent}'")]
    UrlHostExpanded { parent: String, child: String },

    /// URL port expansion.
    #[error("URL port expanded: child port '{child:?}' not allowed by parent port '{parent:?}'")]
    UrlPortExpanded {
        parent: Option<u16>,
        child: Option<u16>,
    },

    /// URL path expansion.
    #[error("URL path expanded: child path '{child}' not allowed by parent path '{parent}'")]
    UrlPathExpanded { parent: String, child: String },

    /// URL does not match constraint.
    #[error("URL does not match: {reason}")]
    UrlMismatch { reason: String },

    /// Path not contained within root directory.
    #[error("path '{path}' is not contained within root '{root}'")]
    PathNotContained { path: String, root: String },

    /// Invalid path format.
    #[error("invalid path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },

    /// URL not safe (SSRF protection).
    #[error("URL '{url}' blocked: {reason}")]
    UrlNotSafe { url: String, reason: String },

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

    /// Clearance insufficient for the requested tool.
    #[error("insufficient clearance: tool '{tool}' requires {required}, warrant has {actual}")]
    InsufficientClearance {
        tool: String,
        required: String,
        actual: String,
    },

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
    // Issuance Errors (Issuer Warrant Operations)
    // =========================================================================
    /// Clearance level exceeds the issuer's clearance.
    #[error("clearance level exceeded: requested {requested:?} exceeds limit {limit:?}")]
    ClearanceLevelExceeded { requested: String, limit: String },

    /// Tool not authorized for issuance by the issuer warrant.
    #[error("unauthorized tool issuance: '{tool}' not in issuable_tools {allowed:?}")]
    UnauthorizedToolIssuance { tool: String, allowed: Vec<String> },

    /// Self-issuance is prohibited (issuer cannot grant execution to themselves).
    #[error("self-issuance prohibited: {reason}")]
    SelfIssuanceProhibited { reason: String },

    /// Delegation authority error: signer is not the holder of the parent warrant.
    #[error("delegation authority error: expected signer {expected}, got {actual}")]
    DelegationAuthorityError { expected: String, actual: String },

    /// Issued warrant depth exceeds issuer's max_issue_depth.
    #[error("issue depth exceeded: depth {depth} exceeds max_issue_depth {max}")]
    IssueDepthExceeded { depth: u32, max: u32 },

    /// Invalid warrant type for the operation.
    #[error("invalid warrant type: {message}")]
    InvalidWarrantType { message: String },

    /// Issuer chain length would exceed protocol maximum.
    #[error("issuer chain too long: length {length} would exceed maximum {max}")]
    IssuerChainTooLong { length: usize, max: usize },

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

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigurationError(String),

    /// Authorizer has no trusted roots configured.
    ///
    /// This error is returned when an Authorizer with no trusted root keys
    /// attempts to verify or authorize a warrant. Configure trusted roots
    /// via `with_trusted_root()`, or use `trust_any()` for dev/testing only.
    #[error("no trusted roots configured: add trusted roots via with_trusted_root() or use trust_any() for dev/testing")]
    NoTrustedRootsConfigured,

    // =========================================================================
    // Feature Flag Errors
    // =========================================================================
    /// Feature not enabled.
    /// Returned when a constraint type requires an optional feature that isn't compiled in.
    #[error("{feature} requires the '{feature}' feature. Enable with: tenuo = {{ features = [\"{feature}\"] }}")]
    FeatureNotEnabled { feature: &'static str },
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

impl Error {
    /// Map this error to a canonical error code.
    ///
    /// All errors map to codes defined in the wire format spec (§Appendix A).
    /// Protocol-specific representations are derived from these codes.
    pub fn code(&self) -> ErrorCode {
        match self {
            // Signature & Cryptographic Errors
            Self::SignatureInvalid(_) => ErrorCode::SignatureInvalid,
            Self::MissingSignature(_) => ErrorCode::SignatureInvalid,
            Self::CryptoError(_) => ErrorCode::SignatureInvalid,

            // Warrant Lifecycle Errors
            Self::WarrantRevoked(_) => ErrorCode::WarrantRevoked,
            Self::WarrantExpired(_) => ErrorCode::WarrantExpired,
            Self::IssuedInFuture => ErrorCode::IssuedInFuture,
            Self::DepthExceeded(_, _) => ErrorCode::DepthExceeded,
            Self::InvalidWarrantId(_) => ErrorCode::InvalidPayloadStructure,
            Self::InvalidTtl(_) => ErrorCode::TTLExceeded,
            Self::ConstraintDepthExceeded { .. } => ErrorCode::TooManyConstraints,
            Self::PayloadTooLarge { .. } => ErrorCode::WarrantTooLarge,
            Self::ParentRequired => ErrorCode::MissingRequiredField,
            Self::ToolMismatch { .. } => ErrorCode::InvalidAttenuation,

            // Monotonicity Violation Errors (Attenuation)
            Self::MonotonicityViolation(_) => ErrorCode::InvalidAttenuation,
            Self::IncompatibleConstraintTypes { .. } => ErrorCode::InvalidAttenuation,
            Self::WildcardExpansion { .. } => ErrorCode::CapabilityExpansion,
            Self::EmptyResultSet { .. } => ErrorCode::InvalidAttenuation,
            Self::ExclusionRemoved { .. } => ErrorCode::CapabilityExpansion,
            Self::ValueNotInParentSet { .. } => ErrorCode::CapabilityExpansion,
            Self::RangeExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::RangeInclusivityExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::ValueNotInRange { .. } => ErrorCode::ConstraintViolation,
            Self::PatternExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::InvalidCidr { .. } => ErrorCode::ConstraintViolation,
            Self::InvalidIpAddress { .. } => ErrorCode::ConstraintViolation,
            Self::IpNotInCidr { .. } => ErrorCode::ConstraintViolation,
            Self::CidrNotSubnet { .. } => ErrorCode::CapabilityExpansion,
            Self::InvalidUrl { .. } => ErrorCode::ConstraintViolation,
            Self::UrlSchemeExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::UrlHostExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::UrlPortExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::UrlPathExpanded { .. } => ErrorCode::CapabilityExpansion,
            Self::UrlMismatch { .. } => ErrorCode::ConstraintViolation,
            Self::PathNotContained { .. } => ErrorCode::ConstraintViolation,
            Self::InvalidPath { .. } => ErrorCode::ConstraintViolation,
            Self::UrlNotSafe { .. } => ErrorCode::ConstraintViolation,
            Self::RequiredValueRemoved { .. } => ErrorCode::CapabilityExpansion,
            Self::ExactValueMismatch { .. } => ErrorCode::InvalidAttenuation,

            // Constraint Matching Errors (Authorization)
            Self::ConstraintNotSatisfied { .. } => ErrorCode::ConstraintViolation,
            Self::InsufficientClearance { .. } => ErrorCode::ToolNotAuthorized,

            // Constraint Syntax Errors
            Self::InvalidPattern(_) => ErrorCode::ConstraintViolation,
            Self::InvalidRange(_) => ErrorCode::ConstraintViolation,
            Self::InvalidRegex(_) => ErrorCode::ConstraintViolation,
            Self::CelError(_) => ErrorCode::ConstraintViolation,

            // Serialization Errors
            Self::SerializationError(_) => ErrorCode::MalformedCBOR,
            Self::DeserializationError(_) => ErrorCode::MalformedCBOR,
            Self::UnsupportedVersion(_) => ErrorCode::UnsupportedPayloadVersion,

            // General Errors
            Self::MissingField(_) => ErrorCode::MissingRequiredField,
            Self::ChainVerificationFailed(_) => ErrorCode::ChainBroken,

            // Issuance Errors
            Self::ClearanceLevelExceeded { .. } => ErrorCode::ToolNotAuthorized,
            Self::UnauthorizedToolIssuance { .. } => ErrorCode::ToolNotAuthorized,
            Self::SelfIssuanceProhibited { .. } => ErrorCode::InvalidIssuer,
            Self::DelegationAuthorityError { .. } => ErrorCode::InvalidIssuer,
            Self::IssueDepthExceeded { .. } => ErrorCode::DepthExceeded,
            Self::InvalidWarrantType { .. } => ErrorCode::InvalidPayloadStructure,
            Self::IssuerChainTooLong { .. } => ErrorCode::ChainTooLong,

            // Approval Errors
            Self::ApprovalExpired { .. } => ErrorCode::ApprovalExpired,
            Self::InsufficientApprovals { .. } => ErrorCode::InsufficientApprovals,
            Self::InvalidApproval(_) => ErrorCode::ApprovalInvalid,
            Self::UnknownProvider(_) => ErrorCode::ApprovalInvalid,

            // Other Errors
            Self::Unauthorized(_) => ErrorCode::ToolNotAuthorized,
            Self::Validation(_) => ErrorCode::InvalidPayloadStructure,
            Self::ConfigurationError(_) => ErrorCode::InvalidPayloadStructure,
            Self::NoTrustedRootsConfigured => ErrorCode::UntrustedRoot,

            // Feature Flag Errors
            Self::FeatureNotEnabled { .. } => ErrorCode::UnknownConstraintType,
        }
    }

    /// Get the machine-readable error name (kebab-case).
    ///
    /// This is the canonical string representation for HTTP APIs.
    pub fn name(&self) -> &'static str {
        self.code().name()
    }

    /// Get HTTP status code for this error.
    pub fn http_status(&self) -> u16 {
        self.code().http_status()
    }

    /// Get human-readable description.
    pub fn description(&self) -> &'static str {
        self.code().description()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_values() {
        // Envelope errors
        assert_eq!(ErrorCode::UnsupportedEnvelopeVersion.code(), 1000);
        assert_eq!(ErrorCode::InvalidEnvelopeStructure.code(), 1001);

        // Signature errors
        assert_eq!(ErrorCode::SignatureInvalid.code(), 1100);
        assert_eq!(ErrorCode::SignatureAlgorithmMismatch.code(), 1101);

        // Payload errors
        assert_eq!(ErrorCode::UnsupportedPayloadVersion.code(), 1200);
        assert_eq!(ErrorCode::MalformedCBOR.code(), 1202);

        // Temporal errors
        assert_eq!(ErrorCode::WarrantExpired.code(), 1300);
        assert_eq!(ErrorCode::WarrantNotYetValid.code(), 1301);

        // Chain errors
        assert_eq!(ErrorCode::InvalidIssuer.code(), 1400);
        assert_eq!(ErrorCode::DepthExceeded.code(), 1402);
        assert_eq!(ErrorCode::ChainBroken.code(), 1405);
        assert_eq!(ErrorCode::UntrustedRoot.code(), 1406);

        // Capability errors
        assert_eq!(ErrorCode::ToolNotAuthorized.code(), 1500);
        assert_eq!(ErrorCode::ConstraintViolation.code(), 1501);
        assert_eq!(ErrorCode::InvalidAttenuation.code(), 1502);
        assert_eq!(ErrorCode::CapabilityExpansion.code(), 1503);

        // PoP errors
        assert_eq!(ErrorCode::PopSignatureInvalid.code(), 1600);
        assert_eq!(ErrorCode::PopExpired.code(), 1601);

        // Approval errors
        assert_eq!(ErrorCode::InsufficientApprovals.code(), 1700);
        assert_eq!(ErrorCode::ApprovalInvalid.code(), 1701);
        assert_eq!(ErrorCode::ApprovalExpired.code(), 1703);

        // Revocation errors
        assert_eq!(ErrorCode::WarrantRevoked.code(), 1800);
        assert_eq!(ErrorCode::SRLVersionRollback.code(), 1802);

        // Size limit errors
        assert_eq!(ErrorCode::WarrantTooLarge.code(), 1900);
        assert_eq!(ErrorCode::TooManyConstraints.code(), 1903);
        assert_eq!(ErrorCode::ExtensionTooLarge.code(), 1904);

        // Reserved namespace errors
        assert_eq!(ErrorCode::ReservedToolName.code(), 2100);
    }

    #[test]
    fn test_error_code_names() {
        assert_eq!(ErrorCode::SignatureInvalid.name(), "signature-invalid");
        assert_eq!(ErrorCode::WarrantExpired.name(), "warrant-expired");
        assert_eq!(
            ErrorCode::ConstraintViolation.name(),
            "constraint-violation"
        );
        assert_eq!(ErrorCode::WarrantRevoked.name(), "warrant-revoked");
        assert_eq!(ErrorCode::ChainBroken.name(), "chain-broken");
        assert_eq!(ErrorCode::DepthExceeded.name(), "depth-exceeded");
        assert_eq!(ErrorCode::ToolNotAuthorized.name(), "tool-not-authorized");
    }

    #[test]
    fn test_error_code_descriptions() {
        assert_eq!(
            ErrorCode::SignatureInvalid.description(),
            "Signature verification failed"
        );
        assert_eq!(
            ErrorCode::WarrantExpired.description(),
            "Warrant has expired"
        );
        assert_eq!(
            ErrorCode::ConstraintViolation.description(),
            "Constraint not satisfied"
        );
    }

    #[test]
    fn test_error_code_http_status() {
        // Signature errors -> 401
        assert_eq!(ErrorCode::SignatureInvalid.http_status(), 401);

        // Temporal errors -> 401
        assert_eq!(ErrorCode::WarrantExpired.http_status(), 401);

        // Chain errors -> 403
        assert_eq!(ErrorCode::ChainBroken.http_status(), 403);

        // Capability errors -> 403
        assert_eq!(ErrorCode::ConstraintViolation.http_status(), 403);
        assert_eq!(ErrorCode::ToolNotAuthorized.http_status(), 403);

        // PoP errors -> 401
        assert_eq!(ErrorCode::PopSignatureInvalid.http_status(), 401);

        // Revocation errors -> 401
        assert_eq!(ErrorCode::WarrantRevoked.http_status(), 401);

        // Size errors -> 413
        assert_eq!(ErrorCode::WarrantTooLarge.http_status(), 413);
    }

    #[test]
    fn test_error_to_code_mapping() {
        // Signature errors
        let err = Error::SignatureInvalid("test".into());
        assert_eq!(err.code(), ErrorCode::SignatureInvalid);
        assert_eq!(err.name(), "signature-invalid");
        assert_eq!(err.http_status(), 401);

        // Temporal errors
        let err = Error::WarrantExpired(chrono::Utc::now());
        assert_eq!(err.code(), ErrorCode::WarrantExpired);
        assert_eq!(err.name(), "warrant-expired");

        // Chain errors
        let err = Error::DepthExceeded(10, 5);
        assert_eq!(err.code(), ErrorCode::DepthExceeded);
        assert_eq!(err.name(), "depth-exceeded");

        // Capability errors
        let err = Error::ConstraintNotSatisfied {
            field: "amount".into(),
            reason: "too large".into(),
        };
        assert_eq!(err.code(), ErrorCode::ConstraintViolation);
        assert_eq!(err.name(), "constraint-violation");

        // Monotonicity violations
        let err = Error::RangeExpanded {
            bound: "max".into(),
            parent_value: 100.0,
            child_value: 200.0,
        };
        assert_eq!(err.code(), ErrorCode::CapabilityExpansion);

        // Revocation
        let err = Error::WarrantRevoked("test".into());
        assert_eq!(err.code(), ErrorCode::WarrantRevoked);
        assert_eq!(err.name(), "warrant-revoked");
    }

    #[test]
    fn test_all_error_variants_map() {
        // Ensure all Error variants have a mapping to ErrorCode
        // This test will fail to compile if we add a new Error variant
        // without adding it to the code() match statement

        let test_errors = vec![
            Error::SignatureInvalid("test".into()),
            Error::MissingSignature("test".into()),
            Error::CryptoError("test".into()),
            Error::WarrantRevoked("test".into()),
            Error::WarrantExpired(chrono::Utc::now()),
            Error::DepthExceeded(1, 0),
            Error::InvalidWarrantId("test".into()),
            Error::InvalidTtl("test".into()),
            Error::ConstraintDepthExceeded { depth: 10, max: 5 },
            Error::PayloadTooLarge { size: 100, max: 50 },
            Error::ParentRequired,
            Error::ToolMismatch {
                parent: "a".into(),
                child: "b".into(),
            },
            Error::MonotonicityViolation("test".into()),
            Error::IncompatibleConstraintTypes {
                parent_type: "a".into(),
                child_type: "b".into(),
            },
            Error::WildcardExpansion {
                parent_type: "a".into(),
            },
            Error::EmptyResultSet {
                parent_type: "a".into(),
                count: 1,
            },
            Error::ConstraintNotSatisfied {
                field: "a".into(),
                reason: "b".into(),
            },
            Error::InvalidPattern("test".into()),
            Error::InvalidRange("test".into()),
            Error::InvalidRegex("test".into()),
            Error::CelError("test".into()),
            Error::SerializationError("test".into()),
            Error::DeserializationError("test".into()),
            Error::UnsupportedVersion(1),
            Error::MissingField("test".into()),
            Error::ChainVerificationFailed("test".into()),
            Error::ApprovalExpired {
                approved_at: chrono::Utc::now(),
                expired_at: chrono::Utc::now(),
            },
            Error::InsufficientApprovals {
                required: 2,
                received: 1,
            },
            Error::InvalidApproval("test".into()),
            Error::Unauthorized("test".into()),
            Error::Validation("test".into()),
            Error::ConfigurationError("test".into()),
        ];

        // All errors should map to some error code
        for error in test_errors {
            let code = error.code();
            assert!(code.code() >= 1000 && code.code() < 2200);
        }
    }

    #[test]
    fn test_error_name_format() {
        // All error names should be kebab-case (lowercase with hyphens)
        let codes = vec![
            ErrorCode::SignatureInvalid,
            ErrorCode::WarrantExpired,
            ErrorCode::ConstraintViolation,
            ErrorCode::ToolNotAuthorized,
            ErrorCode::PopSignatureInvalid,
            ErrorCode::UnsupportedPayloadVersion,
        ];

        for code in codes {
            let name = code.name();
            // Check kebab-case: lowercase letters, numbers, and hyphens only
            assert!(
                name.chars()
                    .all(|c| c.is_lowercase() || c.is_numeric() || c == '-'),
                "Error name '{}' is not kebab-case",
                name
            );
            // Should not start or end with hyphen
            assert!(!name.starts_with('-') && !name.ends_with('-'));
        }
    }
}
