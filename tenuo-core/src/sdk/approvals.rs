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

/// Sign an approval for `request` after an approver has reviewed it.
///
/// For approval services and CLIs that present a request outside the process
/// that produced it. Refuses a key the request does not list as an approver
/// and a request whose hash does not match its own warrant, tool, arguments,
/// and `holder` (the leaf's authorized holder). The nonce is random; expiry is
/// `ttl` from now, capped at the warrant's expiry.
pub fn approve_request(
    request: &ApprovalRequest,
    holder: Option<&crate::crypto::PublicKey>,
    approver: &SigningKey,
    external_id: impl Into<String>,
    ttl: std::time::Duration,
) -> Result<SignedApproval, ApprovalError> {
    if !request.required_approvers.is_empty()
        && !request
            .required_approvers
            .iter()
            .any(|key| key == &approver.public_key())
    {
        return Err(ApprovalError::Unauthorized);
    }
    if !request.matches(holder) {
        return Err(ApprovalError::RequestMismatch);
    }
    let now = Utc::now();
    let requested = now
        + chrono::Duration::from_std(ttl).map_err(|_| ApprovalError::Unavailable)?;
    let warrant_expiry = DateTime::<Utc>::from_timestamp(request.warrant_expires_at as i64, 0)
        .ok_or(ApprovalError::Unavailable)?;
    let expires_at = requested.min(warrant_expiry);
    if expires_at <= now {
        return Err(ApprovalError::Unavailable);
    }
    let payload = ApprovalPayload::new(
        request.request_hash,
        *uuid::Uuid::new_v4().as_bytes(),
        external_id.into(),
        now,
        expires_at,
    );
    Ok(SignedApproval::create(payload, approver))
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Why approvals could not be obtained.
#[non_exhaustive]
pub enum ApprovalError {
    /// No provider is configured on the guard.
    NoProvider,
    /// The provider could not be reached or timed out. An outage, not a policy outcome.
    Unavailable,
    /// The provider declined to approve this request.
    Unauthorized,
    /// The request's hash does not match its warrant, tool, arguments, and holder.
    RequestMismatch,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProvider => write!(f, "no approval provider is configured"),
            Self::Unavailable => write!(f, "approval provider is unavailable"),
            Self::Unauthorized => write!(f, "approver is not authorized for this request"),
            Self::RequestMismatch => write!(f, "approval request hash does not match its contents"),
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

    #[test]
    fn approve_request_signs_only_what_matches_the_request() {
        use crate::constraints::ConstraintValue;
        let approver = SigningKey::generate();
        let holder = SigningKey::generate().public_key();
        let mut args = HashMap::new();
        args.insert("replicas".to_string(), ConstraintValue::Integer(3));
        let hash = crate::approval::compute_request_hash("wrt_1", "restart", &args, Some(&holder));
        let expires = (Utc::now().timestamp() as u64) + 60;
        let request = ApprovalRequest::new(
            "wrt_1",
            "restart",
            &args,
            hash,
            vec![approver.public_key()],
            1,
            expires,
        );
        assert!(request.matches(Some(&holder)));

        let signed = approve_request(
            &request,
            Some(&holder),
            &approver,
            "ops@example",
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        let payload = signed.verify().unwrap();
        assert_eq!(payload.request_hash, hash);
        assert!(payload.expires_at <= expires, "expiry is capped at the warrant's");

        let stranger = SigningKey::generate();
        assert_eq!(
            approve_request(&request, Some(&holder), &stranger, "x", std::time::Duration::from_secs(60))
                .err(),
            Some(ApprovalError::Unauthorized)
        );
        let other_holder = SigningKey::generate().public_key();
        assert_eq!(
            approve_request(&request, Some(&other_holder), &approver, "x", std::time::Duration::from_secs(60))
                .err(),
            Some(ApprovalError::RequestMismatch)
        );
        let mut tampered = request.clone();
        tampered.args.insert("replicas".to_string(), ConstraintValue::Integer(30));
        assert!(!tampered.matches(Some(&holder)));

        let json = serde_json::to_string(&request).unwrap();
        let round_trip: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert!(round_trip.matches(Some(&holder)));
    }
}
