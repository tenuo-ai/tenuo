//! Security tests for Tenuo.
//!
//! These tests verify that security vulnerabilities are properly mitigated:
//! - Duplicate approval attacks
//! - Pattern attenuation bypass

use chrono::Utc;
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    approval::{compute_request_hash, ApprovalPayload, SignedApproval},
    constraints::{ConstraintSet, Pattern},
    crypto::SigningKey,
    planes::Authorizer,
    warrant::Warrant,
};

// ============================================================================
// Multi-sig Security - Positive Cases
// ============================================================================

/// Verify that a single valid approval succeeds when 1 is required.
#[test]
fn test_single_approval_succeeds() {
    let root_key = SigningKey::generate();
    let approver = SigningKey::generate();

    // Require 1 approval
    let warrant = Warrant::builder()
        .capability("action", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![approver.public_key()])
        .min_approvals(1)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    let args = HashMap::new();
    // Include authorized_holder in request hash (matches what verify_approvals does)
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        "action",
        &args,
        Some(&root_key.public_key()),
    );

    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    // Generate nonce for replay protection
    let nonce: [u8; 16] = rand::random();

    // Create approval using envelope pattern
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce,
        external_id: "approver@example.com".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };

    let approval = SignedApproval::create(payload, &approver);

    let sig = warrant.sign(&root_key, "action", &args).unwrap();
    let result = authorizer.authorize(&warrant, "action", &args, Some(&sig), &[approval]);

    assert!(
        result.is_ok(),
        "Single valid approval should succeed: {:?}",
        result.err()
    );
}

/// Verify that 2-of-3 multi-sig succeeds with 2 valid approvals.
#[test]
fn test_two_of_three_approvals_succeeds() {
    let root_key = SigningKey::generate();
    let approver_1 = SigningKey::generate();
    let approver_2 = SigningKey::generate();
    let approver_3 = SigningKey::generate();

    // Require 2-of-3 approvals
    let warrant = Warrant::builder()
        .capability("critical_action", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![
            approver_1.public_key(),
            approver_2.public_key(),
            approver_3.public_key(),
        ])
        .min_approvals(2)
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    let args = HashMap::new();
    // Include authorized_holder in request hash
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        "critical_action",
        &args,
        Some(&root_key.public_key()),
    );

    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);

    // Create approval from approver 1
    let nonce_1: [u8; 16] = rand::random();
    let payload_1 = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: nonce_1,
        external_id: "approver1@example.com".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };
    let approval_1 = SignedApproval::create(payload_1, &approver_1);

    // Create approval from approver 2
    let nonce_2: [u8; 16] = rand::random();
    let payload_2 = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: nonce_2,
        external_id: "approver2@example.com".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };
    let approval_2 = SignedApproval::create(payload_2, &approver_2);

    let sig = warrant.sign(&root_key, "critical_action", &args).unwrap();
    let result = authorizer.authorize(
        &warrant,
        "critical_action",
        &args,
        Some(&sig),
        &[approval_1, approval_2],
    );

    assert!(
        result.is_ok(),
        "2-of-3 with 2 valid approvals should succeed: {:?}",
        result.err()
    );
}

/// Verify that warrants without multi-sig requirements work without approvals.
#[test]
fn test_no_multisig_requirement_succeeds_without_approvals() {
    let root_key = SigningKey::generate();

    // No multi-sig requirement
    let warrant = Warrant::builder()
        .capability("simple_action", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    let args = HashMap::new();
    let sig = warrant.sign(&root_key, "simple_action", &args).unwrap();

    // Should succeed without any approvals
    let result = authorizer.authorize(&warrant, "simple_action", &args, Some(&sig), &[]);

    assert!(
        result.is_ok(),
        "Non-multisig warrant should succeed without approvals"
    );
}

// ============================================================================
// Multi-sig Security - Rejection Cases
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

    // Generate nonce for replay protection
    let nonce: [u8; 16] = rand::random();

    // Create approval using envelope pattern
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce,
        external_id: "approver_1".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };

    let approval = SignedApproval::create(payload, &approver_1);

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

    // Generate nonce for replay protection
    let nonce: [u8; 16] = rand::random();

    // Create approval using envelope pattern
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce,
        external_id: "approver_1".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };

    let approval = SignedApproval::create(payload, &approver_1);

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

    // Generate nonce for replay protection
    let nonce: [u8; 16] = rand::random();

    // Create approval using envelope pattern (with unauthorized key)
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce,
        external_id: "attacker".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };

    let approval = SignedApproval::create(payload, &random_attacker); // <-- Unauthorized key

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

    // Generate nonce for replay protection
    let nonce: [u8; 16] = rand::random();

    // Create approval using envelope pattern (with mismatched hash)
    let payload = ApprovalPayload {
        version: 1,
        request_hash: other_hash, // Mismatched hash vs current request
        nonce,
        external_id: "approver".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: expires.timestamp() as u64,
        extensions: None,
    };

    let approval = SignedApproval::create(payload, &approver);

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

    // Generate nonce for replay protection
    let nonce: [u8; 16] = rand::random();

    // Create approval using envelope pattern (with expired timestamp)
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce,
        external_id: "approver".to_string(),
        approved_at: approved_at.timestamp() as u64,
        expires_at: expired_time.timestamp() as u64, // EXPIRED
        extensions: None,
    };

    let approval = SignedApproval::create(payload, &approver);

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
