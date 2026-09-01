use crate::approval::ApprovalRequest;
use crate::error::{Error, ErrorCode};
use crate::receipt::Receipt;
use chrono::{DateTime, Utc};
use std::fmt;

/// Result of an authorization check that did not invoke an operation.
pub struct Decision {
    pub metadata: DecisionMetadata,
    pub receipt: Option<Receipt>,
}

/// Evidence derived from the core decision. Not a capability.
#[derive(Clone, Debug)]
pub struct DecisionMetadata {
    pub decision_id: String,
    pub invocation_id: String,
    pub dedup_key: String,
    pub capability: String,
    pub chain_depth: usize,
    pub timestamp: DateTime<Utc>,
}

/// How a denial is reported. Changes log level only, never execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DenialReporting {
    #[default]
    Error,
    Warn,
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
}

impl Denial {
    pub fn protocol_code(&self) -> Option<ErrorCode> {
        self.protocol_code
    }

    pub fn sdk_kind(&self) -> Option<SdkDenialKind> {
        self.sdk_kind
    }

    pub fn retryability(&self) -> Retryability {
        self.retryability
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn approval_request(&self) -> Option<&ApprovalRequest> {
        self.approval_request.as_deref()
    }

    pub fn needs_approval(&self) -> bool {
        self.protocol_code == Some(ErrorCode::ApprovalRequired)
    }

    pub fn is_infrastructure(&self) -> bool {
        matches!(
            self.sdk_kind,
            Some(
                SdkDenialKind::SignerUnavailable
                    | SdkDenialKind::ApprovalProviderUnavailable
                    | SdkDenialKind::RevocationStateUnavailable
                    | SdkDenialKind::DeadlineExceeded
                    | SdkDenialKind::Cancelled
            )
        )
    }

    pub(crate) fn from_core(err: Error) -> Self {
        if let Error::ApprovalRequired { request, .. } = err {
            return Self {
                protocol_code: Some(ErrorCode::ApprovalRequired),
                sdk_kind: None,
                retryability: Retryability::AfterApproval,
                message: ErrorCode::ApprovalRequired.description().to_string(),
                approval_request: Some(request),
            };
        }
        let code = err.code();
        Self {
            protocol_code: Some(code),
            sdk_kind: None,
            retryability: Retryability::No,
            message: code.description().to_string(),
            approval_request: None,
        }
    }

    pub(crate) fn sdk(kind: SdkDenialKind, retryability: Retryability, message: &str) -> Self {
        Self {
            protocol_code: None,
            sdk_kind: Some(kind),
            retryability,
            message: message.to_string(),
            approval_request: None,
        }
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
    ArgumentsRejected,
    AuthorityMissing,
    AuthorityMalformed,
    SignerUnavailable,
    ApprovalProviderUnavailable,
    RevocationStateUnavailable,
    DeadlineExceeded,
    Cancelled,
}

/// What the caller may usefully do next. Never authorizes execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retryability {
    No,
    AfterApproval,
    AfterBackoff,
}

/// `guard` / `guard_attempt` failure.
#[derive(Debug)]
pub enum GuardError<E> {
    Denied(Denial),
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
