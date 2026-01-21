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

    // Note: build() might not validate extensions if I didn't add the check to build() explicitly.
    // I added check to `validate()`, but `build()` calls `validate()`?
    // Let's check logic. If build() doesn't call validate(), this test might pass (false positive)
    // until we decode it. But `build()` constructs a Warrant.
    // If build() succeeds, we should try `wire::encode` and `wire::decode` and assert decode failure.
    // Ideally `build()` should fail too.

    let result = builder.build(&keypair);

    // If build() incorporates validation, it should fail.
    // My change to `warrant.rs` did NOT add extension check to `build()` explicitly
    // (I added it to `validate()` and `validate_constraint_depth`).
    // `build()` calls `validate_constraint_depth()`.
    // But extension check was added to `validate()`.
    // So `build()` will likely SUCCEED.
    // We must verify via `wire::decode` (simulating verifier).

    if let Ok(warrant) = result {
        let encoded = wire::encode(&warrant).unwrap();
        let decode_result = wire::decode(&encoded);
        assert!(decode_result.is_err(), "Decode should fail validation");
        let err = decode_result.unwrap_err();
        assert!(
            err.to_string().contains("extensions count"),
            "Error: {}",
            err
        );
    } else {
        // If build() was updated to call validate(), then this is also good.
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("extensions count"),
            "Error: {}",
            err
        );
    }
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

    // Same logic as above: Verifier must reject.
    if let Ok(warrant) = result {
        let encoded = wire::encode(&warrant).unwrap();
        let decode_result = wire::decode(&encoded);
        assert!(decode_result.is_err(), "Decode should fail validation");
        let err = decode_result.unwrap_err();
        assert!(err.to_string().contains("exceeds limit"), "Error: {}", err);
    } else {
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds limit"), "Error: {}", err);
    }
}
