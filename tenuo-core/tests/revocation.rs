use std::time::Duration;
use tenuo_core::{
    crypto::Keypair,
    warrant::Warrant,
    planes::DataPlane,
    revocation::RevocationList,
    Error,
};

#[test]
fn test_single_warrant_revocation() {
    let kp = Keypair::generate();
    let warrant = Warrant::builder()
        .tool("test")
        .ttl(Duration::from_secs(600))
        .build(&kp)
        .unwrap();

    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", kp.public_key());
    
    // Initially valid
    assert!(data_plane.verify(&warrant).is_ok());

    // Revoke the warrant
    let mut revocation_list = RevocationList::new();
    revocation_list.revoke(warrant.id().to_string());
    data_plane.set_revocation_list(revocation_list);

    // Now invalid
    match data_plane.verify(&warrant) {
        Err(Error::WarrantRevoked(id)) => assert_eq!(id, warrant.id().to_string()),
        res => panic!("Expected WarrantRevoked, got {:?}", res),
    }
}

#[test]
fn test_chain_revocation_child() {
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    let root = Warrant::builder()
        .tool("test")
        .ttl(Duration::from_secs(600))
        .build(&root_kp)
        .unwrap();

    let child = root.attenuate().build(&child_kp).unwrap();

    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_kp.public_key());

    // Initially valid
    assert!(data_plane.verify_chain(&[root.clone(), child.clone()]).is_ok());

    // Revoke the child
    let mut revocation_list = RevocationList::new();
    revocation_list.revoke(child.id().to_string());
    data_plane.set_revocation_list(revocation_list);

    // Chain invalid
    match data_plane.verify_chain(&[root.clone(), child.clone()]) {
        Err(Error::WarrantRevoked(id)) => assert_eq!(id, child.id().to_string()),
        res => panic!("Expected WarrantRevoked, got {:?}. Child ID: {}", res, child.id()),
    }
}

#[test]
fn test_chain_revocation_parent() {
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    let root = Warrant::builder()
        .tool("test")
        .ttl(Duration::from_secs(600))
        .build(&root_kp)
        .unwrap();

    let child = root.attenuate().build(&child_kp).unwrap();

    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_kp.public_key());

    // Revoke the parent (root)
    let mut revocation_list = RevocationList::new();
    revocation_list.revoke(root.id().to_string());
    data_plane.set_revocation_list(revocation_list);

    // Chain invalid because root is revoked
    match data_plane.verify_chain(&[root.clone(), child.clone()]) {
        Err(Error::WarrantRevoked(id)) => assert_eq!(id, root.id().to_string()),
        res => panic!("Expected WarrantRevoked, got {:?}", res),
    }
}
