use std::time::Duration;
use tenuo::crypto::SigningKey;
use tenuo::warrant::{Clearance, Warrant, WarrantType};

fn create_test_keypair() -> SigningKey {
    // Deterministic seed for testing signatures
    let seed = [0u8; 32];
    SigningKey::from_bytes(&seed)
}

#[test]
fn test_issuable_tools_canonicalization() {
    let kp = create_test_keypair();

    // Create warrant with tools ["a", "b"]
    let w1 = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["a".to_string(), "b".to_string()])
        .clearance(Clearance::INTERNAL)
        .max_issue_depth(1)
        .ttl(Duration::from_secs(3600))
        .build(&kp)
        .unwrap();

    // Create warrant with tools ["b", "a"]
    // We must ensure all other fields (ID, dates) are identical to verify full payload match.
    // However, WarrantBuilder sets random ID and current timestamp.
    // We can't easily force those in the builder without exposing internal fields or mocking time.

    // Instead, let's inspect the payload specifically or use a method that allows explicit setting if available.
    // The builder DOES allow setting ID. But dates are set to Now().
    //
    // HACK: For this test, valid strategy is to override the fields *after* build if possible,
    // OR just verify that `tools` in the generated payload IS sorted.

    let tools1 = w1.issuable_tools().unwrap();
    assert_eq!(tools1, &vec!["a".to_string(), "b".to_string()]);

    let w2 = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["b".to_string(), "a".to_string()])
        .clearance(Clearance::INTERNAL)
        .max_issue_depth(1)
        .ttl(Duration::from_secs(3600))
        .build(&kp)
        .unwrap();

    let tools2 = w2.issuable_tools().unwrap();
    assert_eq!(
        tools2,
        &vec!["a".to_string(), "b".to_string()],
        "Tools should be sorted alpha"
    );
    assert_eq!(tools1, tools2);
}

#[test]
fn test_required_approvers_canonicalization() {
    let kp = create_test_keypair();

    // Create two public keys
    let pk_a = SigningKey::from_bytes(&[1u8; 32]).public_key();
    let pk_b = SigningKey::from_bytes(&[2u8; 32]).public_key();

    // Determine which is smaller to test sorting
    let (pk1, pk2) = if pk_a.to_bytes() < pk_b.to_bytes() {
        (pk_a, pk_b)
    } else {
        (pk_b, pk_a)
    };

    // Ensure byte order for test
    assert!(pk1.to_bytes() < pk2.to_bytes());

    // Order 1: [pk1, pk2] (already sorted)
    let w1 = Warrant::builder()
        .r#type(WarrantType::Execution)
        .tool("test", tenuo::constraints::ConstraintSet::new())
        .required_approvers(vec![pk1.clone(), pk2.clone()])
        .build(&kp) // build consumes builder, keys moved into warrant
        .unwrap();

    // Order 2: [pk2, pk1] (unsorted)
    let w2 = Warrant::builder()
        .r#type(WarrantType::Execution)
        .tool("test", tenuo::constraints::ConstraintSet::new())
        .required_approvers(vec![pk2.clone(), pk1.clone()])
        .build(&kp)
        .unwrap();

    let approvers1 = w1.required_approvers().unwrap();
    let approvers2 = w2.required_approvers().unwrap();

    assert_eq!(approvers1[0], pk1);
    assert_eq!(approvers1[1], pk2);

    assert_eq!(approvers2[0], pk1); // Should be sorted to pk1
    assert_eq!(approvers2[1], pk2);

    assert_eq!(approvers1, approvers2);
}
