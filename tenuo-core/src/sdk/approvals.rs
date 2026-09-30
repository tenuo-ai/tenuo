//! Approval provider: invoked between attempts with a core-produced request.

use crate::approval::{ApprovalPayload, ApprovalRequest, SignedApproval};
use crate::crypto::SigningKey;
use crate::warrant::Warrant;
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
/// that produced it. The reviewer must verify `warrant`'s chain to a trusted
/// root, then call [`ApprovalRequest::matches_warrant`] before displaying the
/// request's message, approvers, threshold, or expiry. Show the tool and arguments
/// as well, and pass that same reviewed request here after consent.
///
/// Rechecks the request hash and review metadata against `warrant`, and refuses
/// an empty approver list or a signing key the warrant does not authorize.
/// The nonce is random; expiry is `ttl` from now, capped at the trusted warrant's
/// expiry. `request_id` and `created_at` are untrusted correlation metadata.
pub fn approve_request(
    request: &ApprovalRequest,
    warrant: &Warrant,
    approver: &SigningKey,
    external_id: impl Into<String>,
    ttl: std::time::Duration,
) -> Result<SignedApproval, ApprovalError> {
    let approvers = warrant
        .required_approvers()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if approvers.is_empty() || !approvers.iter().any(|key| key == &approver.public_key()) {
        return Err(ApprovalError::Unauthorized);
    }
    if !request
        .matches_warrant(warrant)
        .map_err(|_| ApprovalError::RequestMismatch)?
    {
        return Err(ApprovalError::RequestMismatch);
    }
    let now = Utc::now();
    let requested =
        now + chrono::Duration::from_std(ttl).map_err(|_| ApprovalError::Unavailable)?;
    let warrant_expiry = DateTime::<Utc>::from_timestamp(warrant.payload.expires_at as i64, 0)
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
    /// The request's hash or review metadata does not match the trusted warrant.
    RequestMismatch,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProvider => write!(f, "no approval provider is configured"),
            Self::Unavailable => write!(f, "approval provider is unavailable"),
            Self::Unauthorized => write!(f, "approver is not authorized for this request"),
            Self::RequestMismatch => {
                write!(f, "approval request does not match its contents or warrant")
            }
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
        use crate::approval_gate::{encode_approval_gate_map, ApprovalGateMap, ToolApprovalGate};
        use crate::constraints::ConstraintValue;
        let issuer = SigningKey::generate();
        let approver = SigningKey::generate();
        let holder = SigningKey::generate().public_key();
        let mut gates = ApprovalGateMap::new();
        gates.insert(
            "restart".into(),
            ToolApprovalGate::whole_tool().with_message("Restart production replicas"),
        );
        let warrant = Warrant::builder()
            .capability("restart", crate::ConstraintSet::new())
            .holder(holder.clone())
            .required_approvers(vec![approver.public_key()])
            .extension(
                "tenuo.approval_gates",
                encode_approval_gate_map(&gates).unwrap(),
            )
            .ttl(std::time::Duration::from_secs(60))
            .build(&issuer)
            .unwrap();
        let mut args = HashMap::new();
        args.insert("replicas".to_string(), ConstraintValue::Integer(3));
        let warrant_id = warrant.id().to_string();
        let hash =
            crate::approval::compute_request_hash(&warrant_id, "restart", &args, Some(&holder));
        let expires = warrant.payload.expires_at;
        let request = ApprovalRequest::new(
            &warrant_id,
            "restart",
            &args,
            hash,
            vec![approver.public_key()],
            1,
            expires,
        )
        .with_resolved_message(Some("Restart production replicas"));
        assert!(request.matches(Some(&holder)));
        assert!(request.matches_warrant(&warrant).unwrap());

        let signed = approve_request(
            &request,
            &warrant,
            &approver,
            "ops@example",
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        let payload = signed.verify().unwrap();
        assert_eq!(payload.request_hash, hash);
        assert!(
            payload.expires_at <= expires,
            "expiry is capped at the warrant's"
        );

        let stranger = SigningKey::generate();
        assert_eq!(
            approve_request(
                &request,
                &warrant,
                &stranger,
                "x",
                std::time::Duration::from_secs(60)
            )
            .err(),
            Some(ApprovalError::Unauthorized)
        );
        let other_holder = SigningKey::generate().public_key();
        assert!(!request.matches(Some(&other_holder)));

        // Every review field must be checked separately: none is in request_hash.
        for field in ["message", "approvers", "threshold", "expiry"] {
            let mut tampered = request.clone();
            match field {
                "message" => tampered.message = "Read a harmless status page".into(),
                "approvers" => tampered.required_approvers.clear(),
                "threshold" => tampered.min_approvals = 0,
                "expiry" => tampered.warrant_expires_at += 3600,
                _ => unreachable!(),
            }
            assert!(
                tampered.matches(Some(&holder)),
                "hash does not cover {field}"
            );
            assert!(!tampered.matches_warrant(&warrant).unwrap(), "{field}");
            assert_eq!(
                approve_request(
                    &tampered,
                    &warrant,
                    &approver,
                    "ops@example",
                    std::time::Duration::from_secs(60),
                )
                .err(),
                Some(ApprovalError::RequestMismatch),
                "{field}",
            );
        }
        let mut tampered = request.clone();
        tampered
            .args
            .insert("replicas".to_string(), ConstraintValue::Integer(30));
        assert!(!tampered.matches(Some(&holder)));
        assert_eq!(
            approve_request(
                &tampered,
                &warrant,
                &approver,
                "ops@example",
                std::time::Duration::from_secs(60),
            )
            .err(),
            Some(ApprovalError::RequestMismatch),
        );

        // Even a self-consistent hash must refer to this exact trusted warrant.
        tampered = request.clone();
        tampered.warrant_id = "another-warrant".into();
        tampered.request_hash = crate::approval::compute_request_hash(
            &tampered.warrant_id,
            "restart",
            &args,
            Some(&holder),
        );
        assert!(tampered.matches(Some(&holder)));
        assert!(!tampered.matches_warrant(&warrant).unwrap());

        // Gate messages fall back to the standard text when no custom text exists.
        gates.insert("restart".into(), ToolApprovalGate::whole_tool());
        let mut default_warrant = Warrant::builder()
            .capability("restart", crate::ConstraintSet::new())
            .holder(holder.clone())
            .required_approvers(vec![approver.public_key()])
            .extension(
                "tenuo.approval_gates",
                encode_approval_gate_map(&gates).unwrap(),
            )
            .build(&issuer)
            .unwrap();
        let mut default_request = request.clone().with_resolved_message(None);
        default_request.warrant_id = default_warrant.id().to_string();
        default_request.warrant_expires_at = default_warrant.payload.expires_at;
        default_request.request_hash = crate::approval::compute_request_hash(
            &default_request.warrant_id,
            "restart",
            &args,
            Some(&holder),
        );
        assert!(default_request.matches_warrant(&default_warrant).unwrap());

        // Invalid gate bytes must never silently fall back to a default message.
        default_warrant
            .payload
            .extensions
            .insert("tenuo.approval_gates".into(), vec![0xff]);
        assert!(default_request.matches_warrant(&default_warrant).is_err());
        assert_eq!(
            approve_request(
                &default_request,
                &default_warrant,
                &approver,
                "ops@example",
                std::time::Duration::from_secs(60),
            )
            .err(),
            Some(ApprovalError::RequestMismatch),
        );

        let no_approvers = Warrant::builder()
            .capability("restart", crate::ConstraintSet::new())
            .holder(holder.clone())
            .build(&issuer)
            .unwrap();
        assert_eq!(
            approve_request(
                &request,
                &no_approvers,
                &approver,
                "ops@example",
                std::time::Duration::from_secs(60),
            )
            .err(),
            Some(ApprovalError::Unauthorized),
        );

        let json = serde_json::to_string(&request).unwrap();
        let round_trip: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert!(round_trip.matches(Some(&holder)));
        assert!(round_trip.matches_warrant(&warrant).unwrap());
        assert!(approve_request(
            &round_trip,
            &warrant,
            &approver,
            "ops@example",
            std::time::Duration::from_secs(60),
        )
        .is_ok());
    }
}
