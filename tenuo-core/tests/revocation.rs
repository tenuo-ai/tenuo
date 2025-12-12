//! Revocation tests for Tenuo.
//!
//! Tests cover:
//! - Single warrant revocation
//! - Chain/cascading revocation
//! - RevocationRequest and RevocationManager flow

use std::time::Duration;
use chrono::Utc;
use tenuo_core::{
    crypto::Keypair,
    warrant::Warrant,
    planes::{ControlPlane, DataPlane},
    revocation::{RevocationRequest, SignedRevocationList},
    revocation_manager::RevocationManager,
    Error,
};

// ============================================================================
// Basic Revocation
// ============================================================================

#[test]
fn test_single_warrant_revocation() {
    let kp = Keypair::generate();
    let warrant = Warrant::builder()
        .tool("test")
        .ttl(Duration::from_secs(600))
        .authorized_holder(kp.public_key())
        .build(&kp)
        .unwrap();

    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", kp.public_key());
    
    // Initially valid
    assert!(data_plane.verify(&warrant).is_ok());

    // Revoke the warrant
    let srl = SignedRevocationList::builder()
        .revoke(warrant.id().to_string())
        .version(1)
        .build(&kp)
        .unwrap();
    data_plane.set_revocation_list(srl, &kp.public_key()).unwrap();

    // Now invalid
    match data_plane.verify(&warrant) {
        Err(Error::WarrantRevoked(id)) => assert_eq!(id, warrant.id().to_string()),
        res => panic!("Expected WarrantRevoked, got {:?}", res),
    }
}

// ============================================================================
// Chain/Cascading Revocation
// ============================================================================

#[test]
fn test_chain_revocation_child() {
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    let root = Warrant::builder()
        .tool("test")
        .ttl(Duration::from_secs(600))
        .authorized_holder(child_kp.public_key())
        .build(&root_kp)
        .unwrap();

    let child = root.attenuate().authorized_holder(child_kp.public_key()).build(&child_kp).unwrap();

    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_kp.public_key());

    // Initially valid
    assert!(data_plane.verify_chain(&[root.clone(), child.clone()]).is_ok());

    // Revoke the child
    let srl = SignedRevocationList::builder()
        .revoke(child.id().to_string())
        .version(1)
        .build(&root_kp)
        .unwrap();
    data_plane.set_revocation_list(srl, &root_kp.public_key()).unwrap();

    // Chain invalid
    match data_plane.verify_chain(&[root.clone(), child.clone()]) {
        Err(Error::WarrantRevoked(id)) => assert_eq!(id, child.id().to_string()),
        res => panic!("Expected WarrantRevoked, got {:?}", res),
    }
}

#[test]
fn test_chain_revocation_parent_cascades() {
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    let root = Warrant::builder()
        .tool("test")
        .ttl(Duration::from_secs(600))
        .authorized_holder(child_kp.public_key())
        .build(&root_kp)
        .unwrap();

    let child = root.attenuate().authorized_holder(child_kp.public_key()).build(&child_kp).unwrap();

    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_kp.public_key());

    // Revoke the parent (root) - child becomes invalid too
    let srl = SignedRevocationList::builder()
        .revoke(root.id().to_string())
        .version(1)
        .build(&root_kp)
        .unwrap();
    data_plane.set_revocation_list(srl, &root_kp.public_key()).unwrap();

    match data_plane.verify_chain(&[root.clone(), child.clone()]) {
        Err(Error::WarrantRevoked(id)) => assert_eq!(id, root.id().to_string()),
        res => panic!("Expected WarrantRevoked, got {:?}", res),
    }
}

#[test]
fn test_cascading_revocation_multiple_warrants() {
    let cp_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();

    let control_plane = ControlPlane::new(cp_keypair.clone());
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("control-plane", control_plane.public_key());
    data_plane.trust_issuer("issuer", issuer_keypair.public_key());

    // Issue multiple warrants
    let warrant1 = Warrant::builder()
        .tool("test_tool_1")
        .ttl(Duration::from_secs(3600))
        .authorized_holder(issuer_keypair.public_key())
        .build(&issuer_keypair)
        .unwrap();

    let warrant2 = Warrant::builder()
        .tool("test_tool_2")
        .ttl(Duration::from_secs(3600))
        .authorized_holder(issuer_keypair.public_key())
        .build(&issuer_keypair)
        .unwrap();

    assert!(data_plane.verify(&warrant1).is_ok());
    assert!(data_plane.verify(&warrant2).is_ok());

    // Revoke both via cascade (simulating key revocation)
    let affected_ids = vec![warrant1.id().to_string(), warrant2.id().to_string()];
    let manager = RevocationManager::new();
    let srl = manager.generate_srl_with_cascade(&cp_keypair, 1, &affected_ids).unwrap();

    data_plane.set_revocation_list(srl, &control_plane.public_key()).unwrap();

    assert!(matches!(data_plane.verify(&warrant1), Err(Error::WarrantRevoked(_))));
    assert!(matches!(data_plane.verify(&warrant2), Err(Error::WarrantRevoked(_))));
}

// ============================================================================
// RevocationRequest Flow
// ============================================================================

#[test]
fn test_revocation_request_flow() {
    let cp_keypair = Keypair::generate();
    let issuer_keypair = Keypair::generate();
    
    let mut manager = RevocationManager::new();

    // Issuer requests revocation of their warrant
    let request = RevocationRequest::new(
        "warrant_to_revoke",
        "key compromised",
        &issuer_keypair,
    ).unwrap();

    // Submit to manager
    manager.submit_request(
        request,
        "warrant_to_revoke",
        &issuer_keypair.public_key(),
        None,
        Utc::now() + chrono::Duration::hours(1),
        &cp_keypair.public_key(),
    ).unwrap();

    // Generate SRL
    let srl = manager.generate_srl(&cp_keypair, 1).unwrap();

    assert!(srl.is_revoked("warrant_to_revoke"));
    assert!(!srl.is_revoked("other_warrant"));
}
