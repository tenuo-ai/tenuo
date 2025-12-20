use std::time::Duration;
use tenuo::constraints::ConstraintSet;
use tenuo::crypto::SigningKey;
use tenuo::planes::DataPlane;
use tenuo::revocation::RevocationRequest;
use tenuo::warrant::Warrant;

#[test]
fn test_parental_revocation() {
    // 1. Setup
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let data_plane = DataPlane::new_with_issuers(vec![issuer.public_key()]);

    // 2. Issue Warrant
    let warrant = Warrant::builder()
        .capability("test_tool", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(holder.public_key())
        .build(&issuer)
        .unwrap();

    // 3. Verify Initial State (Valid)
    assert!(data_plane.verify(&warrant).is_ok());
    assert!(!data_plane.is_revoked(&warrant));

    // 4. Submit Revocation (Parent)
    let request =
        RevocationRequest::new(warrant.id().to_string(), "Emergency Stop", &issuer).unwrap();

    data_plane
        .submit_revocation(&request, &warrant)
        .expect("Revocation submission failed");

    // 5. Verify Revoked State
    assert!(data_plane.is_revoked(&warrant));

    // Verify verify() fails
    let result = data_plane.verify(&warrant);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("revoked"));
}

#[test]
fn test_self_revocation() {
    // Holder surrenders warrant
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let data_plane = DataPlane::new_with_issuers(vec![issuer.public_key()]);

    let warrant = Warrant::builder()
        .capability("test_tool", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(holder.public_key())
        .build(&issuer)
        .unwrap();

    let request = RevocationRequest::new(warrant.id().to_string(), "I quit", &holder).unwrap();

    data_plane
        .submit_revocation(&request, &warrant)
        .expect("Self-revocation failed");
    assert!(data_plane.is_revoked(&warrant));
}

#[test]
fn test_unauthorized_revocation() {
    let issuer = SigningKey::generate();
    let attacker = SigningKey::generate();
    let data_plane = DataPlane::new_with_issuers(vec![issuer.public_key()]);

    let warrant = Warrant::builder()
        .capability("test_tool", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(issuer.public_key())
        .build(&issuer)
        .unwrap();

    let request =
        RevocationRequest::new(warrant.id().to_string(), "Malicious revocation", &attacker)
            .unwrap();

    let result = data_plane.submit_revocation(&request, &warrant);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not authorized"));
    assert!(!data_plane.is_revoked(&warrant));
}
