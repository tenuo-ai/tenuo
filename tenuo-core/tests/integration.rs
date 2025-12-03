//! Integration tests demonstrating full Tenuo workflows.
//!
//! These tests show how Tenuo would be used in real agent systems.

use std::collections::HashMap;
use std::time::Duration;
use tenuo_core::{
    constraints::{ConstraintValue, Exact, OneOf, Pattern, Range},
    crypto::Keypair,
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
    let control_plane_kp = Keypair::generate();
    
    // Orchestrator agent
    let orchestrator_kp = Keypair::generate();
    
    // Worker agent
    let worker_kp = Keypair::generate();

    // Step 1: Control plane issues broad warrant
    let root_warrant = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("*").unwrap()) // Any cluster
        .constraint("version", Pattern::new("1.28.*").unwrap())
        .ttl(Duration::from_secs(3600))
        .build(&control_plane_kp)
        .unwrap();

    assert_eq!(root_warrant.depth(), 0);
    assert!(root_warrant.verify(&control_plane_kp.public_key()).is_ok());

    // Step 2: Orchestrator attenuates to staging only
    let orchestrator_warrant = root_warrant
        .attenuate()
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .ttl(Duration::from_secs(600))
        .build(&orchestrator_kp)
        .unwrap();

    assert_eq!(orchestrator_warrant.depth(), 1);
    assert_eq!(orchestrator_warrant.parent_id(), Some(root_warrant.id()));

    // Step 3: Worker attenuates to specific cluster
    let worker_warrant = orchestrator_warrant
        .attenuate()
        .constraint("cluster", Exact::new("staging-web"))
        .build(&worker_kp)
        .unwrap();

    assert_eq!(worker_warrant.depth(), 2);
    assert_eq!(worker_warrant.parent_id(), Some(orchestrator_warrant.id()));

    // Verify worker can upgrade staging-web
    let mut args = HashMap::new();
    args.insert("cluster".to_string(), ConstraintValue::String("staging-web".to_string()));
    args.insert("version".to_string(), ConstraintValue::String("1.28.5".to_string()));
    
    assert!(worker_warrant.authorize("upgrade_cluster", &args).is_ok());

    // Worker cannot upgrade other staging clusters
    args.insert("cluster".to_string(), ConstraintValue::String("staging-api".to_string()));
    assert!(worker_warrant.authorize("upgrade_cluster", &args).is_err());

    // Worker cannot upgrade production
    args.insert("cluster".to_string(), ConstraintValue::String("prod-web".to_string()));
    assert!(worker_warrant.authorize("upgrade_cluster", &args).is_err());
}

/// Demo 2: Delegated Budget Authority
///
/// Finance agent handles transfers under $10k autonomously,
/// with constraints propagating through delegation.
#[test]
fn demo_finance_delegation_with_budget() {
    let cfo_kp = Keypair::generate();
    let finance_agent_kp = Keypair::generate();
    let payment_worker_kp = Keypair::generate();

    // CFO authorizes finance agent for transfers up to $100k
    let cfo_warrant = Warrant::builder()
        .tool("transfer_funds")
        .constraint("amount", Range::max(100_000.0))
        .constraint("currency", Exact::new("USD"))
        .ttl(Duration::from_secs(86400)) // 24 hours
        .build(&cfo_kp)
        .unwrap();

    // Finance agent self-restricts to $10k for autonomous operations
    let finance_warrant = cfo_warrant
        .attenuate()
        .constraint("amount", Range::max(10_000.0))
        .build(&finance_agent_kp)
        .unwrap();

    // Payment worker gets even narrower: $1k max
    let worker_warrant = finance_warrant
        .attenuate()
        .constraint("amount", Range::max(1_000.0))
        .build(&payment_worker_kp)
        .unwrap();

    // Worker can process small payments
    let mut args = HashMap::new();
    args.insert("amount".to_string(), ConstraintValue::Float(500.0));
    args.insert("currency".to_string(), ConstraintValue::String("USD".to_string()));
    assert!(worker_warrant.authorize("transfer_funds", &args).is_ok());

    // Worker cannot exceed $1k
    args.insert("amount".to_string(), ConstraintValue::Float(5_000.0));
    assert!(worker_warrant.authorize("transfer_funds", &args).is_err());

    // Finance agent can do $5k (but not worker)
    assert!(finance_warrant.authorize("transfer_funds", &args).is_ok());

    // Finance agent cannot exceed $10k
    args.insert("amount".to_string(), ConstraintValue::Float(50_000.0));
    assert!(finance_warrant.authorize("transfer_funds", &args).is_err());

    // CFO warrant can do $50k
    assert!(cfo_warrant.authorize("transfer_funds", &args).is_ok());
}

/// Demo 3: Wire Format for HTTP Transport
///
/// Shows warrants being serialized for HTTP headers and deserialized
/// on the receiving service.
#[test]
fn demo_http_transport() {
    let issuer_kp = Keypair::generate();

    // Create a warrant
    let warrant = Warrant::builder()
        .tool("query_database")
        .constraint("database", OneOf::new(["analytics", "logs"]))
        .constraint("table", Pattern::new("public_*").unwrap())
        .ttl(Duration::from_secs(300))
        .session_id("session_abc123")
        .build(&issuer_kp)
        .unwrap();

    // Encode for HTTP header
    let header_value = wire::encode_base64(&warrant).unwrap();
    
    // Header should be reasonably sized
    assert!(header_value.len() < 1000, "Warrant too large for headers: {} bytes", header_value.len());
    
    // Simulate receiving on another service
    let received = wire::decode_base64(&header_value).unwrap();

    // Verify the warrant
    let verify_result = received.verify(&issuer_kp.public_key());
    assert!(verify_result.is_ok(), "Verification failed: {:?}", verify_result.err());
    assert_eq!(received.tool(), "query_database");
    assert_eq!(received.session_id(), Some("session_abc123"));

    // Authorize a query
    let mut args = HashMap::new();
    args.insert("database".to_string(), ConstraintValue::String("analytics".to_string()));
    args.insert("table".to_string(), ConstraintValue::String("public_users".to_string()));
    assert!(received.authorize("query_database", &args).is_ok());

    // Cannot access private tables
    args.insert("table".to_string(), ConstraintValue::String("private_billing".to_string()));
    assert!(received.authorize("query_database", &args).is_err());
}

/// Demo 4: Session Binding
///
/// Warrants are bound to specific agent sessions, preventing
/// replay across sessions.
#[test]
fn demo_session_binding() {
    let kp = Keypair::generate();

    let session_1_warrant = Warrant::builder()
        .tool("execute_task")
        .ttl(Duration::from_secs(600))
        .session_id("session_001")
        .build(&kp)
        .unwrap();

    let session_2_warrant = Warrant::builder()
        .tool("execute_task")
        .ttl(Duration::from_secs(600))
        .session_id("session_002")
        .build(&kp)
        .unwrap();

    // Different warrants for different sessions
    assert_ne!(session_1_warrant.id().as_str(), session_2_warrant.id().as_str());
    assert_eq!(session_1_warrant.session_id(), Some("session_001"));
    assert_eq!(session_2_warrant.session_id(), Some("session_002"));

    // Session is preserved through attenuation
    let attenuated = session_1_warrant.attenuate().build(&kp).unwrap();
    assert_eq!(attenuated.session_id(), Some("session_001"));
}

/// Demo 5: Audit Trail via Parent Chain
///
/// Every warrant maintains a link to its parent, enabling
/// full chain-of-custody reconstruction.
#[test]
fn demo_audit_chain_reconstruction() {
    let root_kp = Keypair::generate();
    let level1_kp = Keypair::generate();
    let level2_kp = Keypair::generate();
    let level3_kp = Keypair::generate();

    // Build a 4-level delegation chain
    let root = Warrant::builder()
        .tool("sensitive_operation")
        .constraint("scope", Pattern::new("*").unwrap())
        .ttl(Duration::from_secs(3600))
        .build(&root_kp)
        .unwrap();

    let level1 = root
        .attenuate()
        .constraint("scope", Pattern::new("dept-*").unwrap())
        .build(&level1_kp)
        .unwrap();

    let level2 = level1
        .attenuate()
        .constraint("scope", Pattern::new("dept-engineering-*").unwrap())
        .build(&level2_kp)
        .unwrap();

    let level3 = level2
        .attenuate()
        .constraint("scope", Exact::new("dept-engineering-frontend"))
        .build(&level3_kp)
        .unwrap();

    // Reconstruct the chain from the leaf
    let mut chain = vec![level3.id().to_string()];
    let mut current_parent = level3.parent_id();

    // Walk back through the chain (in real system, would fetch warrants by ID)
    let warrant_map: HashMap<String, &Warrant> = [
        (root.id().to_string(), &root),
        (level1.id().to_string(), &level1),
        (level2.id().to_string(), &level2),
    ].into_iter().collect();

    while let Some(parent_id) = current_parent {
        chain.push(parent_id.to_string());
        current_parent = warrant_map
            .get(parent_id.as_str())
            .and_then(|w| w.parent_id());
    }

    // Chain should have 4 warrants
    assert_eq!(chain.len(), 4);
    
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
    let parent_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    // Parent has multiple constraint types
    let parent = Warrant::builder()
        .tool("data_export")
        .constraint("region", OneOf::new(["us-east", "us-west", "eu-west"]))
        .constraint("format", Pattern::new("*").unwrap())
        .constraint("max_rows", Range::max(1_000_000.0))
        .ttl(Duration::from_secs(600))
        .build(&parent_kp)
        .unwrap();

    // Child narrows each constraint
    let child = parent
        .attenuate()
        .constraint("region", OneOf::new(["us-east", "us-west"])) // Removed eu-west
        .constraint("format", Pattern::new("csv*").unwrap()) // Only CSV formats
        .constraint("max_rows", Range::max(10_000.0)) // Much smaller limit
        .build(&child_kp)
        .unwrap();

    // Valid request within child constraints
    let mut args = HashMap::new();
    args.insert("region".to_string(), ConstraintValue::String("us-east".to_string()));
    args.insert("format".to_string(), ConstraintValue::String("csv".to_string()));
    args.insert("max_rows".to_string(), ConstraintValue::Float(5_000.0));
    assert!(child.authorize("data_export", &args).is_ok());

    // Region outside child's scope
    args.insert("region".to_string(), ConstraintValue::String("eu-west".to_string()));
    assert!(child.authorize("data_export", &args).is_err());

    // But parent can still do eu-west
    assert!(parent.authorize("data_export", &args).is_ok());
}

/// Test that monotonicity violations are rejected at attenuation time.
#[test]
fn test_monotonicity_violation_rejected() {
    let parent_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    let parent = Warrant::builder()
        .tool("test")
        .constraint("amount", Range::max(1000.0))
        .ttl(Duration::from_secs(600))
        .build(&parent_kp)
        .unwrap();

    // Attempt to increase range max (violation)
    let result = parent
        .attenuate()
        .constraint("amount", Range::max(5000.0))
        .build(&child_kp);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("monotonicity") || err.to_string().contains("greater"));
}

