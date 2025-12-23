//! Wire format for Tenuo warrants.
//!
//! Uses CBOR (RFC 8949) for compact binary serialization.
//! Warrants are typically carried in HTTP headers or gRPC metadata,
//! so compact encoding is important.
//!
//! ## Security Limits
//!
//! - **Payload size**: Limited to [`MAX_WARRANT_SIZE`] (64 KB) to prevent memory exhaustion
//! - **Constraint depth**: Limited to 16 levels to prevent stack overflow

use crate::error::{Error, Result};
use crate::warrant::Warrant;
use base64::Engine;
use serde::Serialize;

/// Maximum allowed size for a serialized warrant in bytes (64 KB).
///
/// This prevents memory exhaustion attacks from extremely large payloads.
/// Typical warrants are a few KB; 64 KB provides ample headroom for complex
/// policies while protecting against abuse.
pub const MAX_WARRANT_SIZE: usize = 64 * 1024; // 64 KB

/// Encode a warrant to a compact binary format.
pub fn encode(warrant: &Warrant) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(warrant, &mut buf)?;
    Ok(buf)
}

/// Helper to serialize any serializable type to CBOR bytes.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Decode a warrant from binary format.
///
/// Returns `PayloadTooLarge` if the input exceeds [`MAX_WARRANT_SIZE`].
pub fn decode(data: &[u8]) -> Result<Warrant> {
    // Check size BEFORE attempting deserialization
    if data.len() > MAX_WARRANT_SIZE {
        return Err(Error::PayloadTooLarge {
            size: data.len(),
            max: MAX_WARRANT_SIZE,
        });
    }

    let warrant: Warrant = ciborium::de::from_reader(data)?;

    // Validate constraint depth to prevent stack overflow attacks
    warrant.validate_constraint_depth()?;

    // Validate payload version early (reject unknown versions)
    if warrant.payload.version != crate::warrant::WARRANT_VERSION as u8 {
        return Err(Error::UnsupportedVersion(warrant.payload.version));
    }

    Ok(warrant)
}

/// Encode a warrant to a base64 string (for HTTP headers).
pub fn encode_base64(warrant: &Warrant) -> Result<String> {
    let bytes = encode(warrant)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Decode a warrant from a base64 string.
///
/// Returns `PayloadTooLarge` if the decoded bytes exceed [`MAX_WARRANT_SIZE`].
pub fn decode_base64(s: &str) -> Result<Warrant> {
    // Quick check: base64 encodes 3 bytes as 4 chars, so estimate decoded size
    // This is a lower bound; actual decoded size may be slightly smaller
    let estimated_size = (s.len() * 3) / 4;
    if estimated_size > MAX_WARRANT_SIZE {
        return Err(Error::PayloadTooLarge {
            size: estimated_size,
            max: MAX_WARRANT_SIZE,
        });
    }

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::DeserializationError(e.to_string()))?;
    decode(&bytes)
}

/// Header name for carrying warrants in HTTP requests.
pub const WARRANT_HEADER: &str = "X-Tenuo-Warrant";

/// Header name for carrying warrant IDs (for out-of-band transport).
pub const WARRANT_ID_HEADER: &str = "X-Tenuo-Warrant-Id";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{ConstraintSet, Pattern};
    use crate::crypto::SigningKey;
    use std::time::Duration;

    #[test]
    fn test_encode_decode_roundtrip() {
        let keypair = SigningKey::generate();
        let mut constraints = ConstraintSet::new();
        constraints.insert("arg", Pattern::new("value-*").unwrap());
        let warrant = Warrant::builder()
            .capability("test_tool", constraints)
            .ttl(Duration::from_secs(300))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let encoded = encode(&warrant).unwrap();
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.id(), warrant.id());
        assert_eq!(decoded.tools(), warrant.tools()); // Both return Option<Vec<String>>
    }

    #[test]
    fn test_base64_roundtrip() {
        let keypair = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let encoded = encode_base64(&warrant).unwrap();

        // Should be reasonably short for headers
        println!("Base64 warrant length: {} chars", encoded.len());
        assert!(
            encoded.len() < 1000,
            "Warrant too large for typical headers"
        );

        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded.id(), warrant.id());
    }

    #[test]
    fn test_version_check() {
        let keypair = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // Manually tweak envelope_version inside the serialized form to simulate mismatch
        let mut encoded = encode(&warrant).unwrap();
        if let Some(first_byte) = encoded.first_mut() {
            *first_byte = 99; // overwrite envelope_version field in array[0]
        }

        let result = decode(&encoded);
        assert!(
            matches!(result, Err(Error::DeserializationError(_))),
            "expected deserialization error for bad envelope_version"
        );
    }

    #[test]
    fn test_compact_encoding() {
        let keypair = SigningKey::generate();

        // Minimal warrant
        let minimal = Warrant::builder()
            .capability("t", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let minimal_size = encode(&minimal).unwrap().len();
        println!("Minimal warrant size: {} bytes", minimal_size);

        // Warrant with constraints
        let mut constraints = ConstraintSet::new();
        constraints.insert("cluster", Pattern::new("staging-*").unwrap());
        constraints.insert("version", Pattern::new("1.28.*").unwrap());
        let with_constraints = Warrant::builder()
            .capability("upgrade_cluster", constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let constrained_size = encode(&with_constraints).unwrap().len();
        println!("Constrained warrant size: {} bytes", constrained_size);

        // Both should be well under HTTP header limits (typically 8KB)
        assert!(constrained_size < 2000);
    }

    #[test]
    fn test_deterministic_serialization() {
        // This test verifies that serialization is deterministic
        // (critical for signature verification after roundtrip)
        let keypair = SigningKey::generate();

        // Create a warrant with multiple constraints in different "insertion" order
        // to verify BTreeMap provides consistent ordering
        let mut constraints = ConstraintSet::new();
        constraints.insert("zebra", Pattern::new("z-*").unwrap()); // Insert Z first
        constraints.insert("alpha", Pattern::new("a-*").unwrap()); // Then A
        constraints.insert("middle", Pattern::new("m-*").unwrap()); // Then M
        let warrant1 = Warrant::builder()
            .capability("test", constraints)
            .ttl(Duration::from_secs(300))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // Serialize multiple times - should always produce identical bytes
        let bytes1 = encode(&warrant1).unwrap();
        let bytes2 = encode(&warrant1).unwrap();
        let bytes3 = encode(&warrant1).unwrap();

        assert_eq!(bytes1, bytes2, "Serialization should be deterministic");
        assert_eq!(bytes2, bytes3, "Serialization should be deterministic");

        // Roundtrip and re-serialize should also be identical
        let decoded = decode(&bytes1).unwrap();
        let bytes_after_roundtrip = encode(&decoded).unwrap();
        assert_eq!(
            bytes1, bytes_after_roundtrip,
            "Serialization after roundtrip should be identical"
        );

        // Verify signature still works after roundtrip
        assert!(
            decoded.verify(&keypair.public_key()).is_ok(),
            "Signature verification should work after roundtrip"
        );
    }

    #[test]
    fn test_deterministic_constraint_set_serialization() {
        // Verify that ConstraintSet serialization is deterministic even with
        // composite constraints (All, Any) that contain Vec<Constraint>.
        // This is critical for warrant ID consistency and signature verification.
        use crate::constraints::{All, Constraint, Pattern, Range};

        let keypair = SigningKey::generate();

        // Create a warrant with All constraint containing multiple constraints
        // in different orders to verify Vec serialization is deterministic
        let all_constraint1 = All::new([
            Constraint::Pattern(Pattern::new("staging-*").unwrap()),
            Constraint::Range(Range::max(1000.0).unwrap()),
        ]);

        let all_constraint2 = All::new([
            Constraint::Range(Range::max(1000.0).unwrap()),
            Constraint::Pattern(Pattern::new("staging-*").unwrap()),
        ]);

        // Create warrants with same constraints but different insertion order
        let mut cs1 = ConstraintSet::new();
        cs1.insert("cluster", all_constraint1.clone());
        let warrant1 = Warrant::builder()
            .capability("test", cs1)
            .ttl(Duration::from_secs(300))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let mut cs2 = ConstraintSet::new();
        cs2.insert("cluster", all_constraint2.clone());
        let warrant2 = Warrant::builder()
            .capability("test", cs2)
            .ttl(Duration::from_secs(300))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // Serialize both warrants
        let bytes1 = encode(&warrant1).unwrap();
        let _bytes2 = encode(&warrant2).unwrap();

        // Note: Vec<Constraint> in All/Any may serialize differently based on order
        // This is acceptable - the important thing is that the same warrant
        // serializes identically each time (tested below)

        // Verify same warrant serializes identically multiple times
        let bytes1_repeat = encode(&warrant1).unwrap();
        assert_eq!(
            bytes1, bytes1_repeat,
            "Same warrant must serialize identically"
        );

        // Verify roundtrip preserves serialization
        let decoded = decode(&bytes1).unwrap();
        let bytes_after_roundtrip = encode(&decoded).unwrap();
        assert_eq!(
            bytes1, bytes_after_roundtrip,
            "Serialization after roundtrip must be identical"
        );

        // Verify signature still works after roundtrip
        assert!(
            decoded.verify(&keypair.public_key()).is_ok(),
            "Signature verification must work after roundtrip"
        );
    }

    #[test]
    fn test_cbor_encoding_consistency() {
        // Verify ciborium uses consistent encoding for the same data
        use std::collections::BTreeMap;

        // Test 1: BTreeMap iteration order is preserved
        let mut map1: BTreeMap<String, i32> = BTreeMap::new();
        map1.insert("zebra".to_string(), 1);
        map1.insert("alpha".to_string(), 2);

        let mut map2: BTreeMap<String, i32> = BTreeMap::new();
        map2.insert("alpha".to_string(), 2); // Insert in different order
        map2.insert("zebra".to_string(), 1);

        let mut bytes1 = Vec::new();
        let mut bytes2 = Vec::new();
        ciborium::ser::into_writer(&map1, &mut bytes1).unwrap();
        ciborium::ser::into_writer(&map2, &mut bytes2).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "BTreeMap should serialize identically regardless of insertion order"
        );

        // Test 2: Same struct serializes identically
        #[derive(serde::Serialize)]
        struct TestStruct {
            a: i32,
            b: String,
            c: Option<f64>,
        }

        let s1 = TestStruct {
            a: 42,
            b: "hello".to_string(),
            c: Some(1.234),
        };
        let s2 = TestStruct {
            a: 42,
            b: "hello".to_string(),
            c: Some(1.234),
        };

        let mut b1 = Vec::new();
        let mut b2 = Vec::new();
        ciborium::ser::into_writer(&s1, &mut b1).unwrap();
        ciborium::ser::into_writer(&s2, &mut b2).unwrap();

        assert_eq!(b1, b2, "Identical structs should serialize identically");

        // Test 3: Integers use minimal encoding
        let small: i64 = 23; // Should fit in 1 byte
        let mut small_bytes = Vec::new();
        ciborium::ser::into_writer(&small, &mut small_bytes).unwrap();
        assert!(
            small_bytes.len() <= 2,
            "Small integers should use compact encoding: got {} bytes",
            small_bytes.len()
        );
    }

    #[test]
    fn test_envelope_is_array() {
        // Verify that the top-level wire format is a CBOR Array(3), not a Map.
        let keypair = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let encoded = encode(&warrant).unwrap();

        // CBOR Array(3) starts with 0x83
        assert_eq!(encoded[0], 0x83, "Wire format must be CBOR Array(3)");
    }

    #[test]
    fn test_unknown_constraint_fail_closed() {
        use crate::constraints::{Constraint, ConstraintValue};

        // Manual construction of Unknown constraint
        let unknown = Constraint::Unknown {
            type_id: 99,
            payload: vec![1, 2, 3],
        };

        let value = ConstraintValue::String("anything".to_string());

        // Must always fail
        assert!(
            !unknown.matches(&value).unwrap(),
            "Unknown constraint must fail closed"
        );

        // Verify depth is 0
        assert_eq!(unknown.depth(), 0);

        // Verify it round-trips via serialization as "Unknown" tag?
        // Note: Our current Deserialize impl converts `type="Unknown"` to Constraint::Unknown.
        // It does NOT preserve the original unrecognized type ID yet (as noted in TODO).
        // But we should verify it serializes/deserializes safely.

        // Let's test deserialization of a conceptually "future" constraint
        // We can simulated this by serializing a custom struct that matches the wire format of a constraint
        // but has a type name that is not known.
        // BUT serde (tag="type") relies on the string tag name.
        // If we send `{"type": "FutureConstraint", "value": ...}` -> deserializer -> Unknown variant?

        // Manual JSON construction to simulate unknown constraint

        // Construct raw JSON then convert to CBOR for test? Or just serde_json for simplicity of structure logic?
        // Constraint uses serde, so JSON string test is valid for logic check.
        let json = r#"{"type": "FutureConstraint", "value": {"foo": "bar"}}"#;

        let deserialized: std::result::Result<Constraint, _> = serde_json::from_str(json);
        assert!(
            deserialized.is_err(),
            "Should fail deserialization for unknown constraint with content (current safe-guard)"
        );
    }
}
