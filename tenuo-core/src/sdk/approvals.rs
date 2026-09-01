//! Approval provider: invoked between attempts with a core-produced request.

use crate::approval::{ApprovalPayload, ApprovalRequest, SignedApproval};
use crate::crypto::SigningKey;
use chrono::{DateTime, Utc};
use std::fmt;

/// Local, non-blocking lookup. Remote or human review belongs on the async surface.
pub trait ApprovalProvider: Send + Sync {
    /// Fetch approvals for a core-produced request descriptor.
    ///
    /// Called only between attempts, never inside one, so blocking on human review is
    /// safe here.
    fn approvals_for(
        &self,
        request: &ApprovalRequest,
    ) -> Result<Vec<SignedApproval>, ApprovalError>;
}

/// Signs the core-produced request hash. Development and tests; not a human review.
pub struct LocalApprovalSigner {
    key: SigningKey,
    external_id: String,
}

impl LocalApprovalSigner {
    /// An in-process approver. For tests and single-node deployments.
    pub fn new(key: SigningKey, external_id: impl Into<String>) -> Self {
        Self {
            key,
            external_id: external_id.into(),
        }
    }
}

impl ApprovalProvider for LocalApprovalSigner {
    fn approvals_for(
        &self,
        request: &ApprovalRequest,
    ) -> Result<Vec<SignedApproval>, ApprovalError> {
        if !request
            .required_approvers
            .iter()
            .any(|key| key == &self.key.public_key())
        {
            return Err(ApprovalError::Unauthorized);
        }
        let expires_at = DateTime::<Utc>::from_timestamp(request.warrant_expires_at as i64, 0)
            .ok_or(ApprovalError::Unavailable)?;
        let nonce = *uuid::Uuid::new_v4().as_bytes();
        let payload = ApprovalPayload::new(
            request.request_hash,
            nonce,
            self.external_id.clone(),
            Utc::now(),
            expires_at,
        );
        Ok(vec![SignedApproval::create(payload, &self.key)])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Why approvals could not be obtained.
pub enum ApprovalError {
    /// No provider is configured on the guard.
    NoProvider,
    /// The provider could not be reached or timed out. An outage, not a policy outcome.
    Unavailable,
    /// The provider declined to approve this request.
    Unauthorized,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProvider => write!(f, "no approval provider is configured"),
            Self::Unavailable => write!(f, "approval provider is unavailable"),
            Self::Unauthorized => write!(f, "approver is not authorized for this request"),
        }
    }
}

impl std::error::Error for ApprovalError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use std::collections::HashMap;

    #[test]
    fn signs_a_core_request_and_rejects_the_wrong_key() {
        let approver = SigningKey::generate();
        let other = SigningKey::generate();
        let request = ApprovalRequest::new(
            "wrt_test",
            "sensitive",
            &HashMap::new(),
            [7u8; 32],
            vec![approver.public_key()],
            1,
            (Utc::now().timestamp() as u64) + 300,
        );
        let signed = LocalApprovalSigner::new(approver, "approver@local")
            .approvals_for(&request)
            .unwrap();
        assert_eq!(signed.len(), 1);
        assert!(signed[0].verify().is_ok());
        assert_eq!(
            LocalApprovalSigner::new(other, "intruder")
                .approvals_for(&request)
                .err()
                .unwrap(),
            ApprovalError::Unauthorized
        );
    }
}
