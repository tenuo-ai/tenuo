//! Integration tests demonstrating full Tenuo workflows.
//!
//! These tests show how Tenuo would be used in real agent systems.

use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::{ConstraintSet, ConstraintValue, Exact, OneOf, Pattern, Range},
    crypto::SigningKey,
    warrant::Warrant,
    wire,
};

/// Demo 1: Safe Kubernetes Upgrades
///
/// Control plane issues broad warrant, orchestrator narrows to staging,
/// worker narrows to specific cluster.
#[test]
fn demo_kubernetes_upgrade_delegation_chain() {
    // Control plane has root authority
    let control_plane_kp = SigningKey::generate();

    // Orchestrator agent
    let orchestrator_kp = SigningKey::generate();

    // Worker agent
    let worker_kp = SigningKey::generate();

    // Step 1: Control plane issues broad warrant
    let mut root_constraints = ConstraintSet::new();
    root_constraints.insert("cluster", Pattern::new("*").unwrap()); // Any cluster
    root_constraints.insert("version", Pattern::new("1.28.*").unwrap());
    let root_warrant = Warrant::builder()
        .capability("upgrade_cluster", root_constraints)
        .ttl(Duration::from_secs(3600))
        .authorized_holder(orchestrator_kp.public_key())
        .build(&control_plane_kp)
        .unwrap();

    assert_eq!(root_warrant.depth(), 0);
    assert!(root_warrant.verify(&control_plane_kp.public_key()).is_ok());

    // Step 2: Orchestrator attenuates to staging only
    let mut orch_constraints = ConstraintSet::new();
    orch_constraints.insert("cluster", Pattern::new("staging-*").unwrap());
    orch_constraints.insert("version", Pattern::new("1.28.*").unwrap());
    let orchestrator_warrant = root_warrant
        .attenuate()
        .capability("upgrade_cluster", orch_constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(worker_kp.public_key())
        .build(&orchestrator_kp)
        .unwrap();

    assert_eq!(orchestrator_warrant.depth(), 1);
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(root_warrant.payload_bytes());
        let root_hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(orchestrator_warrant.parent_hash(), Some(&root_hash));
    }

    // Step 3: Worker attenuates to specific cluster
    // Note: In this demo, worker binds to itself or a sub-worker.
    // Let's assume worker binds to itself for the final execution warrant.
    let mut worker_constraints = ConstraintSet::new();
    worker_constraints.insert("cluster", Exact::new("staging-web"));
    worker_constraints.insert("version", Pattern::new("1.28.*").unwrap());
    let worker_warrant = orchestrator_warrant
        .attenuate()
        .capability("upgrade_cluster", worker_constraints)
        .authorized_holder(worker_kp.public_key())
        .build(&worker_kp)
        .unwrap();

    assert_eq!(worker_warrant.depth(), 2);
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(orchestrator_warrant.payload_bytes());
        let orchestrator_hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(worker_warrant.parent_hash(), Some(&orchestrator_hash));
    }

    // Verify worker can upgrade staging-web
    let mut args = HashMap::new();
    args.insert(
        "cluster".to_string(),
        ConstraintValue::String("staging-web".to_string()),
    );
    args.insert(
        "version".to_string(),
        ConstraintValue::String("1.28.5".to_string()),
    );

    let sig = worker_warrant
        .sign(&worker_kp, "upgrade_cluster", &args)
        .unwrap();
    assert!(worker_warrant
        .authorize("upgrade_cluster", &args, Some(&sig))
        .is_ok());

    // Worker cannot upgrade other staging clusters
    args.insert(
        "cluster".to_string(),
        ConstraintValue::String("staging-api".to_string()),
    );
    let sig = worker_warrant
        .sign(&worker_kp, "upgrade_cluster", &args)
        .unwrap();
    assert!(worker_warrant
        .authorize("upgrade_cluster", &args, Some(&sig))
        .is_err());

    // Worker cannot upgrade production
    args.insert(
        "cluster".to_string(),
        ConstraintValue::String("prod-web".to_string()),
    );
    let sig = worker_warrant
        .sign(&worker_kp, "upgrade_cluster", &args)
        .unwrap();
    assert!(worker_warrant
        .authorize("upgrade_cluster", &args, Some(&sig))
        .is_err());
}

/// Demo 2: Delegated Budget Authority
///
/// Finance agent handles transfers under $10k autonomously,
/// with constraints propagating through delegation.
#[test]
fn demo_finance_delegation_with_budget() {
    let cfo_kp = SigningKey::generate();
    let finance_agent_kp = SigningKey::generate();
    let payment_worker_kp = SigningKey::generate();

    // CFO authorizes finance agent for transfers up to $100k
    let mut cfo_constraints = ConstraintSet::new();
    cfo_constraints.insert("amount", Range::max(100_000.0).unwrap());
    cfo_constraints.insert("currency", Exact::new("USD"));
    let cfo_warrant = Warrant::builder()
        .capability("transfer_funds", cfo_constraints)
        .ttl(Duration::from_secs(86400)) // 24 hours
        .authorized_holder(finance_agent_kp.public_key())
        .build(&cfo_kp)
        .unwrap();

    // Finance agent self-restricts to $10k for autonomous operations
    let mut finance_constraints = ConstraintSet::new();
    finance_constraints.insert("amount", Range::max(10_000.0).unwrap());
    finance_constraints.insert("currency", Exact::new("USD"));
    let finance_warrant = cfo_warrant
        .attenuate()
        .capability("transfer_funds", finance_constraints)
        .authorized_holder(payment_worker_kp.public_key())
        .build(&finance_agent_kp)
        .unwrap();

    // Payment worker gets even narrower: $1k max
    let mut worker_constraints = ConstraintSet::new();
    worker_constraints.insert("amount", Range::max(1_000.0).unwrap());
    worker_constraints.insert("currency", Exact::new("USD"));
    let worker_warrant = finance_warrant
        .attenuate()
        .capability("transfer_funds", worker_constraints)
        .authorized_holder(payment_worker_kp.public_key())
        .build(&payment_worker_kp)
        .unwrap();

    // Worker can process small payments
    let mut args = HashMap::new();
    args.insert("amount".to_string(), ConstraintValue::Float(500.0));
    args.insert(
        "currency".to_string(),
        ConstraintValue::String("USD".to_string()),
    );
    let sig = worker_warrant
        .sign(&payment_worker_kp, "transfer_funds", &args)
        .unwrap();
    assert!(worker_warrant
        .authorize("transfer_funds", &args, Some(&sig))
        .is_ok());

    // Worker cannot exceed $1k
    args.insert("amount".to_string(), ConstraintValue::Float(5_000.0));
    let sig = worker_warrant
        .sign(&payment_worker_kp, "transfer_funds", &args)
        .unwrap();
    assert!(worker_warrant
        .authorize("transfer_funds", &args, Some(&sig))
        .is_err());

    // Finance agent can do $5k (but not worker)
    // Note: finance_warrant holder is payment_worker_kp, so payment_worker_kp signs
    let sig = finance_warrant
        .sign(&payment_worker_kp, "transfer_funds", &args)
        .unwrap();
    assert!(finance_warrant
        .authorize("transfer_funds", &args, Some(&sig))
        .is_ok());

    // Finance agent cannot exceed $10k
    args.insert("amount".to_string(), ConstraintValue::Float(50_000.0));
    let sig = finance_warrant
        .sign(&payment_worker_kp, "transfer_funds", &args)
        .unwrap();
    assert!(finance_warrant
        .authorize("transfer_funds", &args, Some(&sig))
        .is_err());

    // CFO warrant can do $50k
    // Note: cfo_warrant holder is finance_agent_kp
    let sig = cfo_warrant
        .sign(&finance_agent_kp, "transfer_funds", &args)
        .unwrap();
    assert!(cfo_warrant
        .authorize("transfer_funds", &args, Some(&sig))
        .is_ok());
}

/// Demo 3: Wire Format for HTTP Transport
///
/// Shows warrants being serialized for HTTP headers and deserialized
/// on the receiving service.
#[test]
fn demo_http_transport() {
    let issuer_kp = SigningKey::generate();

    // Create a warrant
    let mut db_constraints = ConstraintSet::new();
    db_constraints.insert("database", OneOf::new(["analytics", "logs"]));
    db_constraints.insert("table", Pattern::new("public_*").unwrap());
    let warrant = Warrant::builder()
        .capability("query_database", db_constraints)
        .ttl(Duration::from_secs(300))
        .session_id("session_abc123")
        .authorized_holder(issuer_kp.public_key()) // Bind to self for demo
        .build(&issuer_kp)
        .unwrap();

    // Encode for HTTP header
    let header_value = wire::encode_base64(&warrant).unwrap();

    // Header should be reasonably sized
    assert!(
        header_value.len() < 1500,
        "Warrant too large for headers: {} bytes",
        header_value.len()
    );

    // Simulate receiving on another service
    let received = wire::decode_base64(&header_value).unwrap();

    // Verify the warrant
    let verify_result = received.verify(&issuer_kp.public_key());
    assert!(
        verify_result.is_ok(),
        "Verification failed: {:?}",
        verify_result.err()
    );
    assert_eq!(received.tools(), vec!["query_database".to_string()]);
    assert_eq!(received.session_id(), Some("session_abc123"));

    // Authorize a query
    let mut args = HashMap::new();
    args.insert(
        "database".to_string(),
        ConstraintValue::String("analytics".to_string()),
    );
    args.insert(
        "table".to_string(),
        ConstraintValue::String("public_users".to_string()),
    );

    let sig = received.sign(&issuer_kp, "query_database", &args).unwrap();
    assert!(received
        .authorize("query_database", &args, Some(&sig))
        .is_ok());

    // Cannot access private tables
    args.insert(
        "table".to_string(),
        ConstraintValue::String("private_billing".to_string()),
    );
    let sig = received.sign(&issuer_kp, "query_database", &args).unwrap();
    assert!(received
        .authorize("query_database", &args, Some(&sig))
        .is_err());
}

/// Demo 4: Session Binding
///
/// Warrants are bound to specific agent sessions, preventing
/// replay across sessions.
#[test]
fn demo_session_binding() {
    let kp = SigningKey::generate();

    let session_1_warrant = Warrant::builder()
        .capability("execute_task", ConstraintSet::new())
        .ttl(Duration::from_secs(600))
        .session_id("session_001")
        .authorized_holder(kp.public_key())
        .build(&kp)
        .unwrap();

    let session_2_warrant = Warrant::builder()
        .capability("execute_task", ConstraintSet::new())
        .ttl(Duration::from_secs(600))
        .session_id("session_002")
        .authorized_holder(kp.public_key())
        .build(&kp)
        .unwrap();

    // Different warrants for different sessions
    assert_ne!(
        session_1_warrant.id().to_string(),
        session_2_warrant.id().to_string()
    );
    assert_eq!(session_1_warrant.session_id(), Some("session_001"));
    assert_eq!(session_2_warrant.session_id(), Some("session_002"));

    // Session is preserved through attenuation (POLA: inherit_all)
    let attenuated = session_1_warrant
        .attenuate()
        .inherit_all()
        .authorized_holder(kp.public_key())
        .build(&kp)
        .unwrap();
    assert_eq!(attenuated.session_id(), Some("session_001"));
}

/// Demo 5: Audit Trail via Parent Chain
///
/// Every warrant maintains a link to its parent, enabling
/// full chain-of-custody reconstruction.
#[test]
fn demo_audit_chain_reconstruction() {
    let root_kp = SigningKey::generate();
    let level1_kp = SigningKey::generate();
    let level2_kp = SigningKey::generate();
    let level3_kp = SigningKey::generate();

    // Build a 4-level delegation chain
    let mut root_constraints = ConstraintSet::new();
    root_constraints.insert("scope", Pattern::new("*").unwrap());
    let root = Warrant::builder()
        .capability("sensitive_operation", root_constraints)
        .ttl(Duration::from_secs(3600))
        .authorized_holder(level1_kp.public_key())
        .build(&root_kp)
        .unwrap();

    let mut l1_constraints = ConstraintSet::new();
    l1_constraints.insert("scope", Pattern::new("dept-*").unwrap());
    let level1 = root
        .attenuate()
        .capability("sensitive_operation", l1_constraints)
        .authorized_holder(level2_kp.public_key())
        .build(&level1_kp)
        .unwrap();

    let mut l2_constraints = ConstraintSet::new();
    l2_constraints.insert("scope", Pattern::new("dept-engineering-*").unwrap());
    let level2 = level1
        .attenuate()
        .capability("sensitive_operation", l2_constraints)
        .authorized_holder(level3_kp.public_key())
        .build(&level2_kp)
        .unwrap();

    let mut l3_constraints = ConstraintSet::new();
    l3_constraints.insert("scope", Exact::new("dept-engineering-frontend"));
    let level3 = level2
        .attenuate()
        .capability("sensitive_operation", l3_constraints)
        .authorized_holder(level3_kp.public_key())
        .build(&level3_kp)
        .unwrap();

    // Reconstruct the chain from the leaf
    // Verify chain linkage via hashes
    let chain_warrants = [&level3, &level2, &level1, &root];
    for (i, w) in chain_warrants.iter().enumerate() {
        if i + 1 < chain_warrants.len() {
            let parent = chain_warrants[i + 1];
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(parent.payload_bytes());
            let parent_hash: [u8; 32] = hasher.finalize().into();
            assert_eq!(w.parent_hash(), Some(&parent_hash));
        } else {
            assert!(w.is_root());
        }
    }

    // Verify depth increases along the chain
    assert_eq!(root.depth(), 0);
    assert_eq!(level1.depth(), 1);
    assert_eq!(level2.depth(), 2);
    assert_eq!(level3.depth(), 3);
}

/// Demo 6: Constraint Narrowing Combinations
///
/// Shows how different constraint types can be combined and narrowed.
#[test]
fn demo_mixed_constraint_narrowing() {
    let parent_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    // Parent has multiple constraint types
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("region", OneOf::new(["us-east", "us-west", "eu-west"]));
    parent_constraints.insert("format", Pattern::new("*").unwrap());
    parent_constraints.insert("max_rows", Range::max(1_000_000.0).unwrap());
    let parent = Warrant::builder()
        .capability("data_export", parent_constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(child_kp.public_key())
        .build(&parent_kp)
        .unwrap();

    // Child narrows each constraint
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("region", OneOf::new(["us-east", "us-west"])); // Removed eu-west
    child_constraints.insert("format", Pattern::new("csv*").unwrap()); // Only CSV formats
    child_constraints.insert("max_rows", Range::max(10_000.0).unwrap()); // Much smaller limit
    let child = parent
        .attenuate()
        .capability("data_export", child_constraints)
        .authorized_holder(child_kp.public_key())
        .build(&child_kp)
        .unwrap();

    // Valid request within child constraints
    let mut args = HashMap::new();
    args.insert(
        "region".to_string(),
        ConstraintValue::String("us-east".to_string()),
    );
    args.insert(
        "format".to_string(),
        ConstraintValue::String("csv".to_string()),
    );
    args.insert("max_rows".to_string(), ConstraintValue::Float(5_000.0));

    let sig = child.sign(&child_kp, "data_export", &args).unwrap();
    assert!(child.authorize("data_export", &args, Some(&sig)).is_ok());

    // Region outside child's scope
    args.insert(
        "region".to_string(),
        ConstraintValue::String("eu-west".to_string()),
    );
    let sig = child.sign(&child_kp, "data_export", &args).unwrap();
    assert!(child.authorize("data_export", &args, Some(&sig)).is_err());

    // But parent can still do eu-west
    // Note: parent holder is child_kp
    let sig = parent.sign(&child_kp, "data_export", &args).unwrap();
    assert!(parent.authorize("data_export", &args, Some(&sig)).is_ok());
}

/// Test that monotonicity violations are rejected at attenuation time.
#[test]
fn test_monotonicity_violation_rejected() {
    let parent_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("amount", Range::max(1000.0).unwrap());
    let parent = Warrant::builder()
        .capability("test", parent_constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(child_kp.public_key())
        .build(&parent_kp)
        .unwrap();

    // Attempt to increase range max (violation)
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("amount", Range::max(5000.0).unwrap());
    let result = parent
        .attenuate()
        .capability("test", child_constraints)
        .authorized_holder(child_kp.public_key())
        .build(&child_kp);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("monotonicity")
            || err.to_string().contains("exceeds")
            || err.to_string().contains("expanded"),
        "Expected monotonicity error, got: {}",
        err
    );
}
