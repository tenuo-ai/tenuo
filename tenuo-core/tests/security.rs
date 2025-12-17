//! Security tests for Tenuo.
//!
//! These tests verify that security vulnerabilities are properly mitigated:
//! - Duplicate approval attacks
//! - Pattern attenuation bypass

use chrono::Utc;
use std::collections::HashMap;
use std::time::Duration;
use tenuo_core::{
    approval::{compute_request_hash, Approval},
    constraints::Pattern,
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
        .tool("critical_op")
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![approver_1.public_key(), approver_2.public_key()])
        .min_approvals(2)
        .authorized_holder(root_key.public_key())
        .build(&root_key)
        .unwrap();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    // Create ONE approval
    let args = HashMap::new();
    let request_hash = compute_request_hash(warrant.id().as_str(), "critical_op", &args, None);

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

    let sig = warrant
        .create_pop_signature(&root_key, "critical_op", &args)
        .unwrap();
    let result = authorizer.authorize(&warrant, "critical_op", &args, Some(&sig), &approvals);

    assert!(result.is_err(), "Duplicate approvals should be rejected");
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
