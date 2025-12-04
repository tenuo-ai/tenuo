use tenuo_core::{
    approval::{Approval, compute_request_hash},
    constraints::ConstraintValue,
    crypto::{Keypair, PublicKey},
    planes::{Authorizer, DataPlane},
    warrant::Warrant,
};
use std::collections::HashMap;
use std::time::Duration;
use chrono::Utc;

#[test]
fn test_multisig_duplicate_approval_vulnerability() {
    // 1. Setup keys
    let root_key = Keypair::generate();
    let approver_1 = Keypair::generate();
    let approver_2 = Keypair::generate();
    
    // 2. Create a warrant requiring 2-of-2 approvals
    let warrant = Warrant::builder()
        .tool("critical_op")
        .ttl(Duration::from_secs(3600))
        .required_approvers(vec![
            approver_1.public_key(),
            approver_2.public_key(),
        ])
        .min_approvals(2) // Require BOTH to sign
        .build(&root_key)
        .unwrap();

    // 3. Setup Authorizer
    let authorizer = Authorizer::new(root_key.public_key());

    // 4. Create ONE valid approval from Approver 1
    let args = HashMap::new();
    let request_hash = compute_request_hash(
        warrant.id().as_str(),
        "critical_op",
        &args,
        None
    );

    let now = Utc::now();
    let expires = now + chrono::Duration::hours(1);
    
    // Construct the approval payload manually (simulating what the provider does)
    let mut signable_bytes = Vec::new();
    signable_bytes.extend_from_slice(&request_hash);
    signable_bytes.extend_from_slice("approver_1".as_bytes());
    signable_bytes.extend_from_slice(&now.timestamp().to_le_bytes());
    signable_bytes.extend_from_slice(&expires.timestamp().to_le_bytes());
    
    let signature = approver_1.sign(&signable_bytes);
    
    let approval_1 = Approval {
        request_hash,
        approver_key: approver_1.public_key(),
        external_id: "approver_1".to_string(),
        provider: "test".to_string(),
        approved_at: now,
        expires_at: expires,
        reason: None,
        signature,
    };

    // 5. Submit the SAME approval twice
    // We expect this to FAIL if the system is robust, but PASS if vulnerable.
    let approvals = vec![approval_1.clone(), approval_1.clone()];

    let result = authorizer.authorize(
        &warrant,
        "critical_op",
        &args,
        None,
        &approvals
    );

    // If result is Err, the vulnerability is FIXED.
    if result.is_err() {
        println!("FIX CONFIRMED: Duplicate approvals were rejected as expected.");
    } else {
        println!("VULNERABILITY STILL PRESENT: Duplicate approvals bypassed 2-of-2 requirement!");
    }
    
    assert!(result.is_err(), "Expected duplicate approvals to be rejected");
}
