use std::time::Duration;
use tenuo::{constraints::ConstraintSet, crypto::SigningKey, warrant::Warrant, Error};

/// Test: Verify delegation semantics - issuer should be parent's holder
///
/// This test ensures that when a warrant is attenuated (delegated), the child
/// warrant's issuer is the parent warrant's holder. This is the standard
/// delegation model used in X.509, Macaroons, SPIFFE, and other capability systems.
///
/// Delegation authority rule: "You can only delegate what you hold"
#[test]
fn test_delegation_semantics_issuer_equals_parent_holder() {
    let parent_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    // Create parent warrant
    let parent = Warrant::builder()
        .capability("read", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(parent_kp.public_key())
        .build(&parent_kp)
        .unwrap();

    // Attenuate to child
    let child = parent
        .attenuate()
        .inherit_all()
        .authorized_holder(child_kp.public_key())
        .build(&parent_kp) // Parent signs (is the delegator)
        .unwrap();

    // CRITICAL ASSERTION: Child's issuer should be parent's holder
    assert_eq!(
        child.issuer(),
        parent.authorized_holder(),
        "Child's issuer must equal parent's holder (delegation authority)"
    );

    // Verify holder is different (not self-delegation)
    assert_ne!(
        child.issuer(),
        child.authorized_holder(),
        "Child's issuer should not equal child's holder (except for root warrants)"
    );

    println!("✅ Delegation semantics correct:");
    println!(
        "   Parent holder: {}",
        parent.authorized_holder().fingerprint()
    );
    println!("   Child issuer:  {}", child.issuer().fingerprint());
    println!(
        "   Child holder:  {}",
        child.authorized_holder().fingerprint()
    );
    println!(
        "   Audit trail: '{}' delegated to '{}'",
        parent.authorized_holder().fingerprint(),
        child.authorized_holder().fingerprint()
    );
}

/// Test: Verify delegation authority is enforced
///
/// Only the parent's holder can sign the child warrant. Attempting to sign
/// with a different key should fail.
#[test]
fn test_delegation_authority_enforcement() {
    let parent_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();
    let wrong_kp = SigningKey::generate();

    let parent = Warrant::builder()
        .capability("read", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(parent_kp.public_key())
        .build(&parent_kp)
        .unwrap();

    // Attempt to delegate with wrong key (not parent's holder)
    let result = parent
        .attenuate()
        .inherit_all()
        .authorized_holder(child_kp.public_key())
        .build(&wrong_kp); // Wrong signer!

    match result {
        Err(Error::DelegationAuthorityError { expected, actual }) => {
            println!("✅ Delegation authority enforced:");
            println!("   Expected signer: {}", expected);
            println!("   Actual signer:   {}", actual);
            assert_eq!(expected, parent.authorized_holder().fingerprint());
            assert_eq!(actual, wrong_kp.public_key().fingerprint());
        }
        Ok(_) => panic!("Should have rejected delegation from non-holder"),
        Err(e) => panic!("Wrong error type: {:?}", e),
    }
}

/// Test: Verify multi-level delegation chain semantics
///
/// In a chain Root → Middle → Leaf:
/// - Middle.issuer == Root.holder
/// - Leaf.issuer == Middle.holder
#[test]
fn test_multi_level_delegation_chain_semantics() {
    let root_kp = SigningKey::generate();
    let middle_kp = SigningKey::generate();
    let leaf_kp = SigningKey::generate();

    // Root warrant
    let root = Warrant::builder()
        .capability("read", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_kp.public_key())
        .build(&root_kp)
        .unwrap();

    // Middle warrant (delegated from root)
    let middle = root
        .attenuate()
        .inherit_all()
        .authorized_holder(middle_kp.public_key())
        .build(&root_kp) // Root holder signs
        .unwrap();

    // Leaf warrant (delegated from middle)
    let leaf = middle
        .attenuate()
        .inherit_all()
        .authorized_holder(leaf_kp.public_key())
        .build(&middle_kp) // Middle holder signs
        .unwrap();

    // Verify delegation chain semantics
    assert_eq!(
        middle.issuer(),
        root.authorized_holder(),
        "Middle's issuer should be root's holder"
    );

    assert_eq!(
        leaf.issuer(),
        middle.authorized_holder(),
        "Leaf's issuer should be middle's holder"
    );

    println!("✅ Multi-level delegation chain correct:");
    println!(
        "   Root:   holder={}",
        root.authorized_holder().fingerprint()
    );
    println!(
        "   Middle: issuer={}, holder={}",
        middle.issuer().fingerprint(),
        middle.authorized_holder().fingerprint()
    );
    println!(
        "   Leaf:   issuer={}, holder={}",
        leaf.issuer().fingerprint(),
        leaf.authorized_holder().fingerprint()
    );
    println!("   Chain: Root → Middle → Leaf");
}
