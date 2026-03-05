use std::time::Duration;
use tenuo::*;

// Import constants for verification
// Note: We access these via the public API if exposed, or defining them here if we rely on behavior
// wire::* constants are public.

#[test]
fn test_max_tools_limit() {
    let keypair = SigningKey::generate();
    let mut builder = Warrant::builder()
        .ttl(Duration::from_secs(60))
        .holder(keypair.public_key());

    // Add 257 tools (Limit is 256)
    for i in 0..=wire::MAX_TOOLS_PER_WARRANT {
        // 0 to 256 = 257 items
        builder = builder.capability(format!("tool_{}", i), ConstraintSet::new());
    }

    let result = builder.build(&keypair);
    assert!(result.is_err(), "Should reach validation error");

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("tools count"),
        "Error should be about tools count: {}",
        err
    );
}

#[test]
fn test_max_constraints_limit() {
    let keypair = SigningKey::generate();

    // Create constraint set with 65 items (Limit is 64)
    let mut constraints = ConstraintSet::new();
    for i in 0..=wire::MAX_CONSTRAINTS_PER_TOOL {
        // 0 to 64 = 65 items
        constraints.insert(
            format!("arg_{}", i),
            tenuo::constraints::Pattern::new("val").unwrap(),
        );
    }

    let builder = Warrant::builder()
        .capability("tool", constraints)
        .ttl(Duration::from_secs(60))
        .holder(keypair.public_key());

    let result = builder.build(&keypair);
    assert!(result.is_err(), "Should reach validation error");

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("constraints count"),
        "Error should be about constraints count: {}",
        err
    );
}

#[test]
fn test_max_extensions_limit() {
    let keypair = SigningKey::generate();
    let mut builder = Warrant::builder()
        .capability("tool", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .holder(keypair.public_key());

    // Add 65 extensions (Limit is 64)
    for i in 0..=wire::MAX_EXTENSION_KEYS {
        // 0 to 64 = 65 items
        builder = builder.extension(format!("ext_{}", i), vec![0u8]);
    }

    let result = builder.build(&keypair);

    // build() validates extensions eagerly; it should fail before signing.
    assert!(result.is_err(), "build() should reject too many extensions");
    assert!(
        result.unwrap_err().to_string().contains("extensions count"),
        "expected extensions count error"
    );
}

#[test]
fn test_max_extension_value_limit() {
    let keypair = SigningKey::generate();

    // Create 9KB value (Limit 8KB)
    let large_val = vec![0u8; wire::MAX_EXTENSION_VALUE_SIZE + 100];

    let builder = Warrant::builder()
        .capability("tool", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .holder(keypair.public_key())
        .extension("big_ext", large_val);

    let result = builder.build(&keypair);

    // build() validates extensions eagerly; it should fail before signing.
    assert!(
        result.is_err(),
        "build() should reject oversized extension value"
    );
    assert!(
        result.unwrap_err().to_string().contains("exceeds limit"),
        "expected exceeds limit error"
    );
}

#[test]
fn test_max_extension_key_length() {
    let keypair = SigningKey::generate();

    // Create a key that exceeds MAX_EXTENSION_KEY_SIZE (255 bytes)
    let long_key = "x".repeat(wire::MAX_EXTENSION_KEY_SIZE + 1);

    let result = Warrant::builder()
        .capability("tool", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .holder(keypair.public_key())
        .extension(long_key, vec![0u8])
        .build(&keypair);

    assert!(
        result.is_err(),
        "build() should reject oversized extension key"
    );
    assert!(
        result.unwrap_err().to_string().contains("exceeds limit"),
        "expected exceeds limit error for key length"
    );
}
