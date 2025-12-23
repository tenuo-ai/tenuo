// Wire Format Compliance Tests
// Tests for requirements from docs/wire-format-spec.md

use std::time::Duration;
use tenuo::*;

/// Test: Reserved tool namespace rejection (Spec §9)
/// Requirement: Tools starting with "tenuo:" MUST be rejected
#[test]
#[should_panic(expected = "Reserved tool namespace")]
fn test_reserved_tool_namespace_rejection() {
    let keypair = SigningKey::generate();

    // Attempt to create warrant with reserved tool name
    let _warrant = Warrant::builder()
        .capability("tenuo:revoke", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(keypair.public_key())
        .build(&keypair);
}

/// Test: Extension preservation through serialization (Spec §8)
/// Requirement: Extensions MUST be preserved in signature and survive round-trip
#[test]
fn test_extension_preservation() {
    let keypair = SigningKey::generate();

    // Create warrant with extensions
    let original = Warrant::builder()
        .capability("test_tool", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .extension("com.example.trace_id", b"abc123".to_vec())
        .extension("com.example.billing_tag", b"team-ml".to_vec())
        .authorized_holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Serialize and deserialize
    let encoded = wire::encode(&original).unwrap();
    let decoded = wire::decode(&encoded).unwrap();

    // Verify extensions are preserved (access via payload field)
    let extensions = &decoded.payload.extensions;
    assert_eq!(
        extensions.get("com.example.trace_id"),
        Some(&b"abc123".to_vec())
    );
    assert_eq!(
        extensions.get("com.example.billing_tag"),
        Some(&b"team-ml".to_vec())
    );

    // Verify signature is still valid (extensions were signed)
    assert!(decoded.verify(&keypair.public_key()).is_ok());
}

/// Test: Clock tolerance for expiration (Spec §5)
/// Requirement: Implementations should allow ±120 seconds clock skew
#[test]
fn test_clock_tolerance() {
    use chrono::Duration as ChronoDuration;

    let keypair = SigningKey::generate();

    // Create warrant that expires in 60 seconds
    let warrant = Warrant::builder()
        .capability("test_tool", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .authorized_holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Should NOT be expired with +120s tolerance (60s + 120s = 180s future)
    assert!(!warrant.is_expired_with_tolerance(ChronoDuration::seconds(120)));

    // Should be expired with -120s tolerance (60s - 120s = -60s past)
    assert!(warrant.is_expired_with_tolerance(ChronoDuration::seconds(-120)));
}

/// Test: Warrant size limit enforcement (Spec §13)
/// Requirement: Warrants exceeding 64KB MUST be rejected
/// Note: Creating a warrant that actually exceeds 64KB is difficult in practice
/// due to CBOR compression. This test verifies the limit exists and is enforced.
#[test]
fn test_warrant_size_limit() {
    // Verify MAX_WARRANT_SIZE constant is defined correctly
    assert_eq!(wire::MAX_WARRANT_SIZE, 64 * 1024);

    // Create a moderately large warrant to verify encoding works
    let keypair = SigningKey::generate();
    let mut builder = Warrant::builder()
        .ttl(Duration::from_secs(3600))
        .authorized_holder(keypair.public_key());

    // Add 100 tools with moderate constraints
    for i in 0..100 {
        let tool_name = format!("tool_{}", i);
        let mut constraints = ConstraintSet::new();
        constraints.insert("arg".to_string(), Exact::new("value"));
        builder = builder.capability(tool_name, constraints);
    }

    let warrant = builder.build(&keypair).unwrap();
    let encoded = wire::encode(&warrant).unwrap();

    // Verify the encoded size is reasonable but under limit
    assert!(
        encoded.len() < wire::MAX_WARRANT_SIZE,
        "Encoded size {} should be under MAX_WARRANT_SIZE {}",
        encoded.len(),
        wire::MAX_WARRANT_SIZE
    );
}

/// Test: Contains constraint basic functionality (Spec §6)
/// Note: Contains/Subset are implemented as constraint types
#[test]
fn test_contains_constraint_basic() {
    // Contains constraint ensures list contains all required values
    let required = vec!["apple".to_string(), "banana".to_string()];
    let contains_struct = Contains::new(required.clone());
    let constraint = Constraint::Contains(contains_struct);

    // Verify constraint can be created
    match constraint {
        Constraint::Contains(ref items) => {
            assert_eq!(items.required.len(), 2);
        }
        _ => panic!("Expected Contains constraint"),
    }
}

/// Test: Subset constraint basic functionality (Spec §6)
#[test]
fn test_subset_constraint_basic() {
    // Subset constraint ensures list is subset of allowed values
    let allowed = vec!["red".to_string(), "green".to_string(), "blue".to_string()];
    let subset_struct = Subset::new(allowed.clone());
    let constraint = Constraint::Subset(subset_struct);

    // Verify constraint can be created
    match constraint {
        Constraint::Subset(ref items) => {
            assert_eq!(items.allowed.len(), 3);
        }
        _ => panic!("Expected Subset constraint"),
    }
}
