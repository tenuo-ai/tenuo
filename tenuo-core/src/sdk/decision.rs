use crate::approval::ApprovalRequest;
use crate::error::{Error, ErrorCode};
use crate::receipt::Receipt;
use chrono::{DateTime, Utc};
use std::fmt;

/// Result of an authorization check that did not invoke an operation.
pub struct Decision {
    /// Non-secret record of the decision that permitted this call.
    pub metadata: DecisionMetadata,
    /// Signed authorization receipt, when the `receipts` feature and an evidence policy are configured.
    pub receipt: Option<Receipt>,
}

/// Evidence derived from the core decision. Not a capability.
#[derive(Clone, Debug)]
pub struct DecisionMetadata {
    /// Identifies this decision. Correlates a denial or allow across logs and receipts.
    pub decision_id: String,
    /// Fresh per attempt. Two retries of one logical operation have different values.
    pub invocation_id: String,
    /// Protocol deduplication key over the signed argument view. Stable across retries of
    /// the same logical operation, so a downstream store can coalesce or reject repeats.
    pub dedup_key: String,
    /// Capability name the decision authorized.
    pub capability: String,
    /// Number of warrants from root to leaf.
    pub chain_depth: usize,
    /// The attempt's captured verification instant, not the time this struct was read.
    pub timestamp: DateTime<Utc>,
}

/// How a denial is reported. Changes log level only, never execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DenialReporting {
    #[default]
    /// Log denials at error level.
    Error,
    /// Log denials at warn level.
    Warn,
    /// Log denials at debug level. Still denies; only the log level changes.
    Debug,
}

/// Classified denial. At least one of `protocol_code` or `sdk_kind` is present.
#[derive(Debug)]
pub struct Denial {
    protocol_code: Option<ErrorCode>,
    sdk_kind: Option<SdkDenialKind>,
    retryability: Retryability,
    message: String,
    approval_request: Option<Box<ApprovalRequest>>,
    constraint_field: Option<String>,
}

impl Denial {
    /// Wire error code when the core decision produced this denial.
    ///
    /// `None` means the condition has no protocol representation; see [`Self::sdk_kind`].
    pub fn protocol_code(&self) -> Option<ErrorCode> {
        self.protocol_code
    }

    /// SDK-stage classification for conditions the protocol does not model.
    ///
    /// `None` means the core decided; see [`Self::protocol_code`]. At least one is always set.
    pub fn sdk_kind(&self) -> Option<SdkDenialKind> {
        self.sdk_kind
    }

    /// What the caller may usefully do next. Never an authorization to proceed.
    pub fn retryability(&self) -> Retryability {
        self.retryability
    }

    /// Sanitized, caller-safe text. Never names which constraint nearly matched;
    /// use [`crate::sdk::Diagnostics`] for operator-side detail.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Core-produced approval descriptor, present when the denial is `approval-required`.
    ///
    /// Hand this to an [`crate::sdk::ApprovalProvider`], then retry with
    /// [`crate::sdk::AuthorizationAttempt::with_approvals`].
    pub fn approval_request(&self) -> Option<&ApprovalRequest> {
        self.approval_request.as_deref()
    }

    /// Canonical kebab-case name: protocol `ErrorCode` or SDK kind.
    pub fn code(&self) -> &'static str {
        if let Some(code) = self.protocol_code {
            return code.name();
        }
        match self.sdk_kind {
            Some(SdkDenialKind::ArgumentsRejected) => "arguments-rejected",
            Some(SdkDenialKind::AuthorityMissing) => "authority-missing",
            Some(SdkDenialKind::AuthorityMalformed) => "authority-malformed",
            Some(SdkDenialKind::SignerUnavailable) => "signer-unavailable",
            Some(SdkDenialKind::ApprovalProviderUnavailable) => "approval-provider-unavailable",
            Some(SdkDenialKind::RevocationStateUnavailable) => "revocation-state-unavailable",
            Some(SdkDenialKind::DeadlineExceeded) => "deadline-exceeded",
            Some(SdkDenialKind::Cancelled) => "cancelled",
            Some(SdkDenialKind::EvidenceUnavailable) => "evidence-unavailable",
            None => "denied",
        }
    }

    /// True when policy denied: the chain, constraints, expiry, or revocation said no.
    /// Retrying the identical call will deny again.
    pub fn is_policy(&self) -> bool {
        self.protocol_code.is_some() && !self.is_infrastructure()
    }

    /// True when the call is permitted once a valid approval exists.
    pub fn needs_approval(&self) -> bool {
        self.protocol_code == Some(ErrorCode::ApprovalRequired)
    }

    pub(crate) fn constraint_field(&self) -> Option<&str> {
        self.constraint_field.as_deref()
    }

    /// True when a dependency failed rather than policy denying — a signer, approval
    /// provider, or revocation state was unavailable. Still a denial; retry after backoff.
    pub fn is_infrastructure(&self) -> bool {
        matches!(
            self.sdk_kind,
            Some(
                SdkDenialKind::SignerUnavailable
                    | SdkDenialKind::ApprovalProviderUnavailable
                    | SdkDenialKind::RevocationStateUnavailable
                    | SdkDenialKind::DeadlineExceeded
                    | SdkDenialKind::Cancelled
                    | SdkDenialKind::EvidenceUnavailable
            )
        )
    }

    pub(crate) fn from_core(err: Error) -> Self {
        let constraint_field = match &err {
            Error::ConstraintNotSatisfied { field, .. } => Some(field.clone()),
            _ => None,
        };
        if let Error::ApprovalRequired { request, .. } = err {
            return Self {
                protocol_code: Some(ErrorCode::ApprovalRequired),
                sdk_kind: None,
                retryability: Retryability::AfterApproval,
                message: ErrorCode::ApprovalRequired.description().to_string(),
                approval_request: Some(request),
                constraint_field: None,
            };
        }
        let code = err.code();
        Self {
            protocol_code: Some(code),
            sdk_kind: None,
            retryability: Retryability::No,
            message: code.description().to_string(),
            approval_request: None,
            constraint_field,
        }
    }

    pub(crate) fn sdk(kind: SdkDenialKind, retryability: Retryability, message: &str) -> Self {
        Self {
            protocol_code: None,
            sdk_kind: Some(kind),
            retryability,
            message: message.to_string(),
            approval_request: None,
            constraint_field: None,
        }
    }
}

impl From<super::approvals::ApprovalError> for Denial {
    fn from(err: super::approvals::ApprovalError) -> Self {
        Self::sdk(
            SdkDenialKind::ApprovalProviderUnavailable,
            Retryability::AfterBackoff,
            &err.to_string(),
        )
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.retryability {
            Retryability::AfterApproval => {
                write!(f, "{}: collect an approval and retry", self.message)
            }
            Retryability::AfterBackoff => write!(f, "{}: retry after backoff", self.message),
            Retryability::No => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for Denial {}

/// Conditions the protocol does not name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdkDenialKind {
    /// Arguments failed bounds, shape, or conversion before any decision ran.
    ArgumentsRejected,
    /// No authority was presented.
    AuthorityMissing,
    /// Authority failed structural validation.
    AuthorityMalformed,
    /// The holder signer errored, timed out, or no longer matches the leaf.
    SignerUnavailable,
    /// The approval provider errored or exceeded its deadline. Distinct from
    /// `approval-required`, which means approval is genuinely needed.
    ApprovalProviderUnavailable,
    /// Required revocation state was missing, stale, untrusted, or rolled back.
    RevocationStateUnavailable,
    /// The attempt's deadline passed.
    DeadlineExceeded,
    /// The attempt was cancelled before the decision completed.
    Cancelled,
    /// A synchronous evidence gate was configured and the receipt could not be persisted.
    EvidenceUnavailable,
}

/// What the caller may usefully do next. Never authorizes execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retryability {
    /// The identical call will be denied again.
    No,
    /// Retry once a valid approval exists.
    AfterApproval,
    /// A dependency failed; the identical call may succeed later.
    AfterBackoff,
}

/// `guard` / `guard_attempt` failure.
#[derive(Debug)]
pub enum GuardError<E> {
    /// Tenuo denied. The operation did not run.
    Denied(Denial),
    /// Tenuo allowed and the operation itself returned an error.
    Operation(E),
}

impl<E: fmt::Display> fmt::Display for GuardError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(denial) => write!(f, "{denial}"),
            Self::Operation(err) => write!(f, "operation failed: {err}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for GuardError<E> {}
