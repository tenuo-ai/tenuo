//! Security tests for Tenuo.
//!
//! These tests verify that security vulnerabilities are properly mitigated:
//! - Duplicate approval attacks
//! - Pattern attenuation bypass

use chrono::Utc;
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    approval::{compute_request_hash, Approval},
    constraints::{ConstraintSet, Pattern},
    crypto::SigningKey,
    planes::Authorizer,
    warrant::Warrant,
};

// ============================================================================
// Multi-sig Security
// ============================================================================

/// Verify that duplicate approvals cannot bypass M-of-N requirements.
///
/// Attack: Submit the same approval twice to satisfy a 2-of-2 requirement.
/// Expected: Rejected (duplicates don't count).
#[test]
fn test_duplicate_approvals_rejected() {
    let root_key = SigningKey::generate();
    let approver_1 = SigningKey::generate();
    let approver_2 = SigningKey::generate();

    // Require 2-of-2 approvals
    let warrant = Warrant::builder()
        .capability("critical_op", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![approver_1.public_key(), approver_2.public_key()])
        .min_approvals(2)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    // Create ONE approval
    let args = HashMap::new();
    let request_hash = compute_request_hash(&warrant.id().to_string(), "critical_op", &args, None);

    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let mut signable_bytes = Vec::new();
    signable_bytes.extend_from_slice(&request_hash);
    signable_bytes.extend_from_slice("approver_1".as_bytes());
    signable_bytes.extend_from_slice(&now.timestamp().to_le_bytes());
    signable_bytes.extend_from_slice(&expires.timestamp().to_le_bytes());

    let signature = approver_1.sign(&signable_bytes);

    let approval = Approval {
        request_hash,
        approver_key: approver_1.public_key(),
        external_id: "approver_1".to_string(),
        provider: "test".to_string(),
        approved_at: now,
        expires_at: expires,
        reason: None,
        signature,
    };

    // Submit SAME approval twice
    let approvals = vec![approval.clone(), approval.clone()];

    let sig = warrant.sign(&root_key, "critical_op", &args).unwrap();
    let result = authorizer.authorize(&warrant, "critical_op", &args, Some(&sig), &approvals);

    assert!(result.is_err(), "Duplicate approvals should be rejected");
}

/// Verify that insufficient approvals are rejected.
///
/// Attack: Provide 1 approval when 2 are required.
/// Expected: Rejected.
#[test]
fn test_insufficient_approvals_rejected() {
    let root_key = SigningKey::generate();
    let approver_1 = SigningKey::generate();
    let approver_2 = SigningKey::generate();

    // Require 2-of-2
    let warrant = Warrant::builder()
        .capability("critical_op", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![approver_1.public_key(), approver_2.public_key()])
        .min_approvals(2)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    // Create ONE valid approval from approver_1
    let args = HashMap::new();
    let request_hash = compute_request_hash(&warrant.id().to_string(), "critical_op", &args, None);

    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let mut signable_bytes = Vec::new();
    signable_bytes.extend_from_slice(&request_hash);
    signable_bytes.extend_from_slice("approver_1".as_bytes());
    signable_bytes.extend_from_slice(&now.timestamp().to_le_bytes());
    signable_bytes.extend_from_slice(&expires.timestamp().to_le_bytes());

    let signature = approver_1.sign(&signable_bytes);

    let approval = Approval {
        request_hash,
        approver_key: approver_1.public_key(),
        external_id: "approver_1".to_string(),
        provider: "test".to_string(),
        approved_at: now,
        expires_at: expires,
        reason: None,
        signature,
    };

    // Submit only 1 approval
    let sig = warrant.sign(&root_key, "critical_op", &args).unwrap();
    let result = authorizer.authorize(&warrant, "critical_op", &args, Some(&sig), &[approval]);

    assert!(result.is_err(), "Insufficient approvals should be rejected");
}

/// Verify that approvals from unauthorized keys are rejected.
///
/// Attack: Provide valid approval signed by an unauthorized key.
/// Expected: Rejected (ignored, count remains 0).
#[test]
fn test_unauthorized_approver_rejected() {
    let root_key = SigningKey::generate();
    let authorized_approver = SigningKey::generate();
    let random_attacker = SigningKey::generate();

    // Require 1 specific approver
    let warrant = Warrant::builder()
        .capability("critical_op", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![authorized_approver.public_key()])
        .min_approvals(1)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    // Create approval signed by RANDOM ATTACKER
    let args = HashMap::new();
    let request_hash = compute_request_hash(&warrant.id().to_string(), "critical_op", &args, None);
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let mut signable_bytes = Vec::new();
    signable_bytes.extend_from_slice(&request_hash);
    signable_bytes.extend_from_slice("attacker".as_bytes()); // external_id
    signable_bytes.extend_from_slice(&now.timestamp().to_le_bytes());
    signable_bytes.extend_from_slice(&expires.timestamp().to_le_bytes());

    let signature = random_attacker.sign(&signable_bytes);

    let approval = Approval {
        request_hash,
        approver_key: random_attacker.public_key(), // <-- Unauthorized key
        external_id: "attacker".to_string(),
        provider: "test".to_string(),
        approved_at: now,
        expires_at: expires,
        reason: None,
        signature,
    };

    let sig = warrant.sign(&root_key, "critical_op", &args).unwrap();
    let result = authorizer.authorize(&warrant, "critical_op", &args, Some(&sig), &[approval]);

    assert!(result.is_err(), "Unauthorized approver should be rejected");
}

/// Verify that approvals for a different request are rejected.
///
/// Attack: Replay approval from a different tool invocation (hash mismatch).
/// Expected: Rejected.
#[test]
fn test_mismatched_request_hash_rejected() {
    let root_key = SigningKey::generate();
    let approver = SigningKey::generate();

    let warrant = Warrant::builder()
        .capability("critical_op", ConstraintSet::new())
        .capability("other_op", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![approver.public_key()])
        .min_approvals(1)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    let args = HashMap::new();

    // Approval is for "other_op"
    let other_hash = compute_request_hash(&warrant.id().to_string(), "other_op", &args, None);
    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    let mut signable = Vec::new();
    signable.extend_from_slice(&other_hash);
    signable.extend_from_slice("approver".as_bytes());
    signable.extend_from_slice(&now.timestamp().to_le_bytes());
    signable.extend_from_slice(&expires.timestamp().to_le_bytes());
    let signature = approver.sign(&signable);

    let approval = Approval {
        request_hash: other_hash, // Mismatched hash vs current request
        approver_key: approver.public_key(),
        external_id: "approver".to_string(),
        provider: "test".to_string(),
        approved_at: now,
        expires_at: expires,
        reason: None,
        signature,
    };

    // Request is for "critical_op"
    let sig = warrant.sign(&root_key, "critical_op", &args).unwrap();
    let result = authorizer.authorize(&warrant, "critical_op", &args, Some(&sig), &[approval]);

    assert!(
        result.is_err(),
        "Mismatched request hash should be rejected"
    );
}

/// Verify that expired approvals are rejected.
///
/// Attack: Use an old approval that has expired.
/// Expected: Rejected.
#[test]
fn test_expired_approval_rejected() {
    let root_key = SigningKey::generate();
    let approver = SigningKey::generate();

    let warrant = Warrant::builder()
        .capability("critical_op", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![approver.public_key()])
        .min_approvals(1)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    let args = HashMap::new();
    let request_hash = compute_request_hash(&warrant.id().to_string(), "critical_op", &args, None);

    // Expired 1 hour ago
    let now = Utc::now();
    let expired_time = now - chrono::Duration::hours(1);
    let approved_at = now - chrono::Duration::hours(2);

    let mut signable = Vec::new();
    signable.extend_from_slice(&request_hash);
    signable.extend_from_slice("approver".as_bytes());
    signable.extend_from_slice(&approved_at.timestamp().to_le_bytes());
    signable.extend_from_slice(&expired_time.timestamp().to_le_bytes());
    let signature = approver.sign(&signable);

    let approval = Approval {
        request_hash,
        approver_key: approver.public_key(),
        external_id: "approver".to_string(),
        provider: "test".to_string(),
        approved_at,
        expires_at: expired_time, // EXPIRED
        reason: None,
        signature,
    };

    let sig = warrant.sign(&root_key, "critical_op", &args).unwrap();
    let result = authorizer.authorize(&warrant, "critical_op", &args, Some(&sig), &[approval]);

    assert!(result.is_err(), "Expired approval should be rejected");
}

// ============================================================================
// Pattern Attenuation Security
// ============================================================================

/// Verify that suffix patterns cannot be widened.
///
/// Attack: Parent requires "*-safe", child tries to allow "*".
/// Expected: Rejected (child is wider).
#[test]
fn test_suffix_pattern_cannot_widen() {
    let parent = Pattern::new("*-safe").unwrap();
    let child = Pattern::new("*").unwrap();

    let result = parent.validate_attenuation(&child);

    assert!(
        result.is_err(),
        "Suffix pattern should not allow wildcard-only child"
    );
}

/// Verify that infix patterns (wildcard in middle) require exact match.
///
/// Attack: Parent requires "img-*.png", child tries "img-*".
/// Expected: Rejected (child removes suffix constraint).
#[test]
fn test_infix_pattern_requires_exact() {
    let parent = Pattern::new("img-*.png").unwrap();
    let child = Pattern::new("img-*").unwrap();

    let result = parent.validate_attenuation(&child);

    assert!(
        result.is_err(),
        "Infix pattern should not allow suffix removal"
    );
}

/// Verify that prefix patterns work correctly.
#[test]
fn test_prefix_pattern_valid_attenuation() {
    let parent = Pattern::new("staging-*").unwrap();

    // Valid: extend prefix
    let child1 = Pattern::new("staging-web-*").unwrap();
    assert!(parent.validate_attenuation(&child1).is_ok());

    // Valid: exact match
    let child2 = Pattern::new("staging-web").unwrap();
    assert!(parent.validate_attenuation(&child2).is_ok());

    // Invalid: different prefix
    let child3 = Pattern::new("prod-*").unwrap();
    assert!(parent.validate_attenuation(&child3).is_err());
}

/// Verify that suffix patterns work correctly.
#[test]
fn test_suffix_pattern_valid_attenuation() {
    let parent = Pattern::new("*-safe").unwrap();

    // Valid: extend suffix
    let child1 = Pattern::new("*-extra-safe").unwrap();
    assert!(parent.validate_attenuation(&child1).is_ok());

    // Valid: exact match
    let child2 = Pattern::new("image-safe").unwrap();
    assert!(parent.validate_attenuation(&child2).is_ok());

    // Invalid: different suffix
    let child3 = Pattern::new("*-unsafe").unwrap();
    assert!(parent.validate_attenuation(&child3).is_err());
}
