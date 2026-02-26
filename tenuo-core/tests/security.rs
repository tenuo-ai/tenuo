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
    let result = authorizer.authorize_one(&warrant, "action", &args, Some(&sig), &[approval]);

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
    let result = authorizer.authorize_one(
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
    let result = authorizer.authorize_one(&warrant, "simple_action", &args, Some(&sig), &[]);

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
    let result = authorizer.authorize_one(&warrant, "critical_op", &args, Some(&sig), &approvals);

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
    let result = authorizer.authorize_one(&warrant, "critical_op", &args, Some(&sig), &[approval]);

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
    let result = authorizer.authorize_one(&warrant, "critical_op", &args, Some(&sig), &[approval]);

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
    let result = authorizer.authorize_one(&warrant, "critical_op", &args, Some(&sig), &[approval]);

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
    let result = authorizer.authorize_one(&warrant, "critical_op", &args, Some(&sig), &[approval]);

    assert!(result.is_err(), "Expired approval should be rejected");
}

// ============================================================================
// M-of-N Multi-sig - Comprehensive Tests
// ============================================================================

/// Helper: create a warrant with m-of-n approval requirements.
fn make_multisig_warrant(
    root_key: &SigningKey,
    tool: &str,
    approver_keys: &[&SigningKey],
    min_approvals: u32,
) -> Warrant {
    let approver_pks: Vec<_> = approver_keys.iter().map(|k| k.public_key()).collect();
    Warrant::builder()
        .capability(tool, ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .required_approvers(approver_pks)
        .min_approvals(min_approvals)
        .holder(root_key.public_key())
        .build(root_key)
        .unwrap()
}

/// Helper: create a valid SignedApproval for a given warrant + tool.
fn make_approval(
    root_key: &SigningKey,
    approver: &SigningKey,
    warrant: &Warrant,
    tool: &str,
    external_id: &str,
) -> SignedApproval {
    let args = HashMap::new();
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        tool,
        &args,
        Some(&root_key.public_key()),
    );
    let now = Utc::now();
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: rand::random(),
        external_id: external_id.to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: (now + chrono::Duration::hours(1)).timestamp() as u64,
        extensions: None,
    };
    SignedApproval::create(payload, approver)
}

/// 3-of-5: exactly 3 valid approvals from 5 possible → succeeds.
#[test]
fn test_three_of_five_exact_threshold() {
    let root = SigningKey::generate();
    let approvers: Vec<_> = (0..5).map(|_| SigningKey::generate()).collect();
    let approver_refs: Vec<&SigningKey> = approvers.iter().collect();

    let warrant = make_multisig_warrant(&root, "deploy", &approver_refs, 3);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let a0 = make_approval(&root, &approvers[0], &warrant, "deploy", "alice");
    let a1 = make_approval(&root, &approvers[1], &warrant, "deploy", "bob");
    let a2 = make_approval(&root, &approvers[2], &warrant, "deploy", "carol");

    let args = HashMap::new();
    let sig = warrant.sign(&root, "deploy", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "deploy", &args, Some(&sig), &[a0, a1, a2]);

    assert!(
        result.is_ok(),
        "3-of-5 with 3 valid should succeed: {:?}",
        result.err()
    );
}

/// 3-of-5: all 5 approve → succeeds (early exit after 3).
#[test]
fn test_three_of_five_all_approve() {
    let root = SigningKey::generate();
    let approvers: Vec<_> = (0..5).map(|_| SigningKey::generate()).collect();
    let approver_refs: Vec<&SigningKey> = approvers.iter().collect();

    let warrant = make_multisig_warrant(&root, "deploy", &approver_refs, 3);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let all: Vec<_> = approvers
        .iter()
        .enumerate()
        .map(|(i, k)| make_approval(&root, k, &warrant, "deploy", &format!("approver-{i}")))
        .collect();

    let args = HashMap::new();
    let sig = warrant.sign(&root, "deploy", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "deploy", &args, Some(&sig), &all);

    assert!(
        result.is_ok(),
        "3-of-5 with all 5 should succeed: {:?}",
        result.err()
    );
}

/// 3-of-5: only 2 valid → fails with InsufficientApprovals.
#[test]
fn test_three_of_five_insufficient() {
    let root = SigningKey::generate();
    let approvers: Vec<_> = (0..5).map(|_| SigningKey::generate()).collect();
    let approver_refs: Vec<&SigningKey> = approvers.iter().collect();

    let warrant = make_multisig_warrant(&root, "deploy", &approver_refs, 3);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let a0 = make_approval(&root, &approvers[0], &warrant, "deploy", "alice");
    let a1 = make_approval(&root, &approvers[1], &warrant, "deploy", "bob");

    let args = HashMap::new();
    let sig = warrant.sign(&root, "deploy", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "deploy", &args, Some(&sig), &[a0, a1]);

    assert!(result.is_err(), "3-of-5 with only 2 valid should fail");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("insufficient approvals"),
        "Error should say 'insufficient approvals', got: {err_msg}"
    );
    assert!(
        err_msg.contains("required 3") && err_msg.contains("received 2"),
        "Error should include counts, got: {err_msg}"
    );
}

/// 2-of-3: mix of valid + expired + untrusted → still succeeds if 2 valid.
#[test]
fn test_two_of_three_with_mixed_invalid() {
    let root = SigningKey::generate();
    let a1 = SigningKey::generate();
    let a2 = SigningKey::generate();
    let a3 = SigningKey::generate();
    let outsider = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&a1, &a2, &a3], 2);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let args = HashMap::new();
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        "op",
        &args,
        Some(&root.public_key()),
    );
    let now = Utc::now();

    // Valid approval from a1
    let valid = make_approval(&root, &a1, &warrant, "op", "alice");

    // Expired approval from a2
    let expired_payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: rand::random(),
        external_id: "bob-expired".to_string(),
        approved_at: (now - chrono::Duration::hours(3)).timestamp() as u64,
        expires_at: (now - chrono::Duration::hours(1)).timestamp() as u64,
        extensions: None,
    };
    let expired = SignedApproval::create(expired_payload, &a2);

    // Untrusted approval from outsider
    let untrusted = make_approval(&root, &outsider, &warrant, "op", "outsider");

    // Valid approval from a3
    let valid2 = make_approval(&root, &a3, &warrant, "op", "carol");

    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(
        &warrant,
        "op",
        &args,
        Some(&sig),
        &[valid, expired, untrusted, valid2],
    );

    assert!(
        result.is_ok(),
        "Should succeed with 2 valid despite invalid ones: {:?}",
        result.err()
    );
}

/// 2-of-3: all invalid → fails with rejection summary.
#[test]
fn test_two_of_three_all_invalid_shows_summary() {
    let root = SigningKey::generate();
    let a1 = SigningKey::generate();
    let a2 = SigningKey::generate();
    let a3 = SigningKey::generate();
    let outsider = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&a1, &a2, &a3], 2);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let args = HashMap::new();
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        "op",
        &args,
        Some(&root.public_key()),
    );
    let now = Utc::now();

    // Expired approval from a1
    let expired_payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: rand::random(),
        external_id: "alice-expired".to_string(),
        approved_at: (now - chrono::Duration::hours(3)).timestamp() as u64,
        expires_at: (now - chrono::Duration::hours(1)).timestamp() as u64,
        extensions: None,
    };
    let expired = SignedApproval::create(expired_payload, &a1);

    // Untrusted approval
    let untrusted = make_approval(&root, &outsider, &warrant, "op", "rogue");

    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[expired, untrusted]);

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("insufficient approvals"),
        "m-of-n error should say 'insufficient approvals', got: {err_msg}"
    );
    assert!(
        err_msg.contains("rejected"),
        "m-of-n error should include rejection details, got: {err_msg}"
    );
}

/// 1-of-1 diagnostic: untrusted key → specific error message.
#[test]
fn test_one_of_one_untrusted_key_specific_error() {
    let root = SigningKey::generate();
    let authorized = SigningKey::generate();
    let rogue = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&authorized], 1);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let rogue_approval = make_approval(&root, &rogue, &warrant, "op", "rogue");

    let args = HashMap::new();
    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[rogue_approval]);

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("approver not in trusted set"),
        "1-of-1 untrusted should give specific reason, got: {err_msg}"
    );
}

/// 1-of-1 diagnostic: expired → specific error message.
#[test]
fn test_one_of_one_expired_specific_error() {
    let root = SigningKey::generate();
    let approver = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&approver], 1);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let args = HashMap::new();
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        "op",
        &args,
        Some(&root.public_key()),
    );
    let now = Utc::now();

    let expired_payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: rand::random(),
        external_id: "slow".to_string(),
        approved_at: (now - chrono::Duration::hours(3)).timestamp() as u64,
        expires_at: (now - chrono::Duration::hours(1)).timestamp() as u64,
        extensions: None,
    };
    let expired = SignedApproval::create(expired_payload, &approver);

    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[expired]);

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("expired"),
        "1-of-1 expired should give specific reason, got: {err_msg}"
    );
}

/// 1-of-1 diagnostic: request hash mismatch → specific error message.
#[test]
fn test_one_of_one_hash_mismatch_specific_error() {
    let root = SigningKey::generate();
    let approver = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&approver], 1);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    // Approval signed for a DIFFERENT tool
    let args = HashMap::new();
    let wrong_hash = compute_request_hash(
        &warrant.id().to_string(),
        "different_op",
        &args,
        Some(&root.public_key()),
    );
    let now = Utc::now();
    let wrong_payload = ApprovalPayload {
        version: 1,
        request_hash: wrong_hash,
        nonce: rand::random(),
        external_id: "approver".to_string(),
        approved_at: now.timestamp() as u64,
        expires_at: (now + chrono::Duration::hours(1)).timestamp() as u64,
        extensions: None,
    };
    let wrong_approval = SignedApproval::create(wrong_payload, &approver);

    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[wrong_approval]);

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("request hash mismatch"),
        "1-of-1 hash mismatch should give specific reason, got: {err_msg}"
    );
}

/// Duplicate attack on m-of-n: same approver signs twice, counted only once.
#[test]
fn test_m_of_n_duplicate_counted_once() {
    let root = SigningKey::generate();
    let a1 = SigningKey::generate();
    let a2 = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&a1, &a2], 2);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    // a1 signs twice with different nonces
    let approval_1a = make_approval(&root, &a1, &warrant, "op", "alice-attempt-1");
    let approval_1b = make_approval(&root, &a1, &warrant, "op", "alice-attempt-2");

    let args = HashMap::new();
    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(
        &warrant,
        "op",
        &args,
        Some(&sig),
        &[approval_1a, approval_1b],
    );

    assert!(
        result.is_err(),
        "Duplicate approver should not count twice for 2-of-2"
    );
}

/// Zero approvals provided for m-of-n → fails.
#[test]
fn test_m_of_n_no_approvals_provided() {
    let root = SigningKey::generate();
    let a1 = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&a1], 1);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let args = HashMap::new();
    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[]);

    assert!(result.is_err(), "No approvals should fail m-of-n");
}

/// DoS protection: too many approvals (>2× approver count) → rejected.
#[test]
fn test_dos_protection_too_many_approvals() {
    let root = SigningKey::generate();
    let a1 = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&a1], 1);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    // Create 3 approvals for 1 trusted approver (limit is 2× = 2)
    let a = make_approval(&root, &a1, &warrant, "op", "alice-1");
    let b = make_approval(&root, &a1, &warrant, "op", "alice-2");
    let c = make_approval(&root, &a1, &warrant, "op", "alice-3");

    let args = HashMap::new();
    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[a, b, c]);

    assert!(result.is_err(), "Too many approvals should be rejected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too many approvals"),
        "Should mention DoS protection, got: {err_msg}"
    );
}

/// Clock tolerance: approval that expired 20s ago (within 30s tolerance) → succeeds.
#[test]
fn test_clock_tolerance_allows_near_expiry() {
    let root = SigningKey::generate();
    let approver = SigningKey::generate();

    let warrant = make_multisig_warrant(&root, "op", &[&approver], 1);
    let authorizer = Authorizer::new().with_trusted_root(root.public_key());

    let args = HashMap::new();
    let request_hash = compute_request_hash(
        &warrant.id().to_string(),
        "op",
        &args,
        Some(&root.public_key()),
    );
    let now = Utc::now();

    // Expired 20 seconds ago — within default 30s tolerance
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: rand::random(),
        external_id: "approver".to_string(),
        approved_at: (now - chrono::Duration::minutes(5)).timestamp() as u64,
        expires_at: (now - chrono::Duration::seconds(20)).timestamp() as u64,
        extensions: None,
    };
    let approval = SignedApproval::create(payload, &approver);

    let sig = warrant.sign(&root, "op", &args).unwrap();
    let result = authorizer.authorize_one(&warrant, "op", &args, Some(&sig), &[approval]);

    assert!(
        result.is_ok(),
        "Approval within clock tolerance should succeed: {:?}",
        result.err()
    );
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

// ============================================================================
// Chain Expiry - Expired parent must invalidate entire chain
// ============================================================================

/// When a parent warrant in a chain expires, check_chain must reject the
/// entire chain. Monotonicity ensures child.expires_at <= parent.expires_at,
/// so an expired parent implies an expired child.
#[test]
fn test_expired_parent_invalidates_chain() {
    let root_key = SigningKey::generate();
    let delegator = SigningKey::generate();
    let worker = SigningKey::generate();

    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

    let root = Warrant::builder()
        .capability("read", ConstraintSet::new())
        .holder(delegator.public_key())
        .ttl(Duration::from_secs(1))
        .build(&root_key)
        .unwrap();

    let child = root
        .attenuate()
        .capability("read", ConstraintSet::new())
        .holder(worker.public_key())
        .ttl(Duration::from_secs(1))
        .build(&delegator)
        .unwrap();

    // Immediately should pass
    let args = HashMap::new();
    let pop = child.sign(&worker, "read", &args).unwrap();
    assert!(authorizer
        .check_chain(
            &[root.clone(), child.clone()],
            "read",
            &args,
            Some(&pop),
            &[]
        )
        .is_ok());

    // Wait for expiry
    std::thread::sleep(Duration::from_millis(1500));

    let pop2 = child.sign(&worker, "read", &args).unwrap();
    let result = authorizer.check_chain(&[root, child], "read", &args, Some(&pop2), &[]);
    assert!(result.is_err(), "expired chain must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expired") || err.contains("Expired"),
        "error should mention expiration: {}",
        err
    );
}
