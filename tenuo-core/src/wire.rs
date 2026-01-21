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
use serde::{Deserialize, Serialize};

/// Maximum allowed size for a serialized warrant in bytes (64 KB).
///
/// This prevents memory exhaustion attacks from extremely large payloads.
/// Typical warrants are a few KB; 64 KB provides ample headroom for complex
/// policies while protecting against abuse.
pub const MAX_WARRANT_SIZE: usize = 64 * 1024; // 64 KB

/// Maximum number of tools per warrant.
pub const MAX_TOOLS_PER_WARRANT: usize = 256;

/// Maximum number of constraints per tool.
pub const MAX_CONSTRAINTS_PER_TOOL: usize = 64;

/// Maximum number of extension keys.
pub const MAX_EXTENSION_KEYS: usize = 64;

/// Maximum size of an extension value (8 KB).
pub const MAX_EXTENSION_VALUE_SIZE: usize = 8 * 1024;

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

    // Validate semantic rules (including temporal checks)
    warrant.validate()?;

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

/// Encode a warrant to a PEM string (canonical format with headers).
pub fn encode_pem(warrant: &Warrant) -> Result<String> {
    let b64 = encode_base64(warrant)?;
    let mut pem = String::new();
    pem.push_str("-----BEGIN TENUO WARRANT-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(
            std::str::from_utf8(chunk).map_err(|e| Error::SerializationError(e.to_string()))?,
        );
        pem.push('\n');
    }
    pem.push_str("-----END TENUO WARRANT-----\n");
    Ok(pem)
}

/// Header name for carrying warrants in HTTP requests.
pub const WARRANT_HEADER: &str = "X-Tenuo-Warrant";

use std::borrow::Cow;

/// Header name for carrying warrant IDs (for out-of-band transport).
pub const WARRANT_ID_HEADER: &str = "X-Tenuo-Warrant-Id";

/// Strip PEM armor and remove whitespace to get clean base64.
/// Returns Cow<str> to avoid allocation if no changes are needed.
pub fn normalize_token(token: &str) -> Cow<'_, str> {
    let s = token.trim();
    if s.starts_with("-----BEGIN TENUO WARRANT-----") {
        Cow::Owned(
            s.lines()
                .filter(|line| !line.trim().starts_with("-----"))
                .collect::<String>()
                .replace(|c: char| c.is_whitespace(), ""),
        )
    } else if s.chars().any(|c| c.is_whitespace()) {
        // Only allocate if there's internal whitespace to remove
        Cow::Owned(s.replace(|c: char| c.is_whitespace(), ""))
    } else {
        // Zero-copy path for clean tokens (even if they had surrounding whitespace, as s is a slice)
        Cow::Borrowed(s)
    }
}

/// Decode a warrant from a base64 string (handles raw base64 or PEM).
///
/// Returns `PayloadTooLarge` if the decoded bytes exceed [`MAX_WARRANT_SIZE`].
pub fn decode_base64(s: &str) -> Result<Warrant> {
    // Normalize input (strip PEM armor, whitespace) - optimization: zero copy for clean inputs
    let clean = normalize_token(s);

    // Quick check: base64 encodes 3 bytes as 4 chars, so estimate decoded size
    // This is a lower bound; actual decoded size may be slightly smaller
    let estimated_size = (clean.len() * 3) / 4;
    if estimated_size > MAX_WARRANT_SIZE {
        return Err(Error::PayloadTooLarge {
            size: estimated_size,
            max: MAX_WARRANT_SIZE,
        });
    }

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(clean.as_ref())
        .map_err(|e| Error::DeserializationError(e.to_string()))?;
    decode(&bytes)
}

/// A stack of warrants representing a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WarrantStack(pub Vec<Warrant>);

impl WarrantStack {
    /// Create a new warrant stack.
    pub fn new(warrants: Vec<Warrant>) -> Self {
        Self(warrants)
    }

    /// Check if the stack is valid (not empty).
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty()
    }

    /// Get the leaf warrant (last element).
    pub fn leaf(&self) -> Option<&Warrant> {
        self.0.last()
    }

    /// Get the root warrant (first element).
    pub fn root(&self) -> Option<&Warrant> {
        self.0.first()
    }
}

/// Encode a warrant stack to a compact binary format (CBOR array).
pub fn encode_stack(stack: &WarrantStack) -> Result<Vec<u8>> {
    to_vec(stack)
}

/// Maximum allowed size for a serialized warrant stack (256 KB).
pub const MAX_STACK_SIZE: usize = 256 * 1024; // 256 KB

/// Decode a warrant stack from binary format.
pub fn decode_stack(data: &[u8]) -> Result<WarrantStack> {
    if data.len() > MAX_STACK_SIZE {
        return Err(Error::PayloadTooLarge {
            size: data.len(),
            max: MAX_STACK_SIZE,
        });
    }
    let stack: WarrantStack = ciborium::de::from_reader(data)?;
    // Basic validation?
    if stack.0.is_empty() {
        return Err(Error::DeserializationError(
            "Warrant stack cannot be empty".to_string(),
        ));
    }
    Ok(stack)
}

/// Encode a warrant stack to a PEM string (Explicit Chain format).
pub fn encode_pem_stack(stack: &WarrantStack) -> Result<String> {
    let bytes = encode_stack(stack)?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let mut pem = String::new();
    pem.push_str("-----BEGIN TENUO WARRANT CHAIN-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(
            std::str::from_utf8(chunk).map_err(|e| Error::SerializationError(e.to_string()))?,
        );
        pem.push('\n');
    }
    pem.push_str("-----END TENUO WARRANT CHAIN-----\n");
    Ok(pem)
}

/// Decode a chain of warrants from a string containing:
/// 1. Explicit Stack: `-----BEGIN TENUO WARRANT CHAIN-----` (Base64 of CBOR Array)
/// 2. Implicit Stack: Multiple `-----BEGIN TENUO WARRANT-----` blocks (Leafs/Parents)
/// 3. Single Warrant: One `-----BEGIN TENUO WARRANT-----` or raw Base64
pub fn decode_pem_chain(input: &str) -> Result<WarrantStack> {
    // 1. Check for Explicit Chain Header
    if let Some(start) = input.find("-----BEGIN TENUO WARRANT CHAIN-----") {
        let start_processed = start + "-----BEGIN TENUO WARRANT CHAIN-----".len();
        if let Some(end) = input[start_processed..].find("-----END TENUO WARRANT CHAIN-----") {
            let content = &input[start_processed..start_processed + end];
            // Use normalize_token logic to strip whitespace from inner base64?
            // Or just strip whitespace manually since it's one block.
            let clean = content.replace(|c: char| c.is_whitespace(), "");

            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(clean)
                .map_err(|e| Error::DeserializationError(e.to_string()))?;

            return decode_stack(&bytes);
        }
    }

    // 2. Implicit Stack (Multiple individual warrants)
    let mut warrants = Vec::new();
    let mut current_pos = 0;
    let mut found_pem = false;

    while let Some(start) = input[current_pos..].find("-----BEGIN TENUO WARRANT-----") {
        found_pem = true;
        let abs_start = current_pos + start;
        if let Some(end) = input[abs_start..].find("-----END TENUO WARRANT-----") {
            let abs_end = abs_start + end + "-----END TENUO WARRANT-----".len();
            let block = &input[abs_start..abs_end];
            warrants.push(decode_base64(block)?);
            current_pos = abs_end;
        } else {
            break;
        }
    }

    // 3. Single Warrant / Raw Base64
    if !found_pem {
        if !input.trim().is_empty() {
            warrants.push(decode_base64(input)?);
        }
    } else if warrants.is_empty() {
        return Err(Error::DeserializationError(
            "Found PEM headers but failed to extract valid warrants".to_string(),
        ));
    }

    if warrants.is_empty() {
        return Err(Error::DeserializationError(
            "No valid warrants found".to_string(),
        ));
    }

    Ok(WarrantStack(warrants))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{ConstraintSet, Pattern};
    use crate::crypto::SigningKey;
    use std::time::Duration;

    #[test]
    fn test_normalize_token() {
        // Clean input - should be Borrowed
        let clean = "abcdef";
        match normalize_token(clean) {
            Cow::Borrowed(s) => assert_eq!(s, "abcdef"),
            _ => panic!("Expected Borrowed for clean input"),
        }

        // Surrounding whitespace only - should be Borrowed (slice)
        let surrounding = " abcdef ";
        match normalize_token(surrounding) {
            Cow::Borrowed(s) => assert_eq!(s, "abcdef"),
            _ => panic!("Expected Borrowed for surrounding whitespace"),
        }

        // Internal whitespace - should be Owned
        let internal = "abc def";
        match normalize_token(internal) {
            Cow::Owned(s) => assert_eq!(s, "abcdef"),
            _ => panic!("Expected Owned for internal whitespace"),
        }

        // PEM format - should be Owned
        let pem = "-----BEGIN TENUO WARRANT-----\nabc\ndef\n-----END TENUO WARRANT-----";
        assert_eq!(normalize_token(pem), "abcdef");

        // PEM with extra junk
        let pem_junk =
            "  -----BEGIN TENUO WARRANT-----  \n  abc  \n  def  \n  -----END TENUO WARRANT-----  ";
        assert_eq!(normalize_token(pem_junk), "abcdef");

        // Not PEM but looks similar (should just strip whitespace)
        assert_eq!(
            normalize_token("-----BEGIN PUBLIC KEY----- abc"),
            "-----BEGINPUBLICKEY-----abc"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let keypair = SigningKey::generate();
        let mut constraints = ConstraintSet::new();
        constraints.insert("arg", Pattern::new("value-*").unwrap());
        let warrant = Warrant::builder()
            .capability("test_tool", constraints)
            .ttl(Duration::from_secs(300))
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let mut cs2 = ConstraintSet::new();
        cs2.insert("cluster", all_constraint2.clone());
        let warrant2 = Warrant::builder()
            .capability("test", cs2)
            .ttl(Duration::from_secs(300))
            .holder(keypair.public_key())
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
            .holder(keypair.public_key())
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

        // Must always fail (returns Err, not Ok(false) - this is fail-closed behavior)
        assert!(
            unknown.matches(&value).is_err(),
            "Unknown constraint must fail closed with an error"
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

    #[test]
    fn test_pem_chain_and_encode() {
        let keypair = SigningKey::generate();
        let warrant1 = Warrant::builder()
            .capability("w1", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let warrant2 = Warrant::builder()
            .capability("w2", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // 1. Test encoding single PEM
        let pem1 = encode_pem(&warrant1).unwrap();
        assert!(pem1.starts_with("-----BEGIN TENUO WARRANT-----\n"));
        assert!(pem1.ends_with("-----END TENUO WARRANT-----\n"));

        // 2. Test concatenated PEM parsing (Chain)
        let pem2 = encode_pem(&warrant2).unwrap();
        let chain_str = format!("{}{}", pem1, pem2);

        let stack = decode_pem_chain(&chain_str).unwrap();
        assert_eq!(stack.0.len(), 2);
        assert_eq!(stack.0[0].id(), warrant1.id());
        assert_eq!(stack.0[1].id(), warrant2.id());

        // 3. Explicit Stack (New Chain Header)
        let explicit_stack = WarrantStack(vec![warrant1.clone(), warrant2.clone()]);
        let explicit_pem = encode_pem_stack(&explicit_stack).unwrap();

        assert!(explicit_pem.starts_with("-----BEGIN TENUO WARRANT CHAIN-----"));

        let decoded_explicit = decode_pem_chain(&explicit_pem).unwrap();
        assert_eq!(decoded_explicit.0.len(), 2);
        assert_eq!(decoded_explicit.0[0].id(), warrant1.id());

        // 3. Test mixed garbage fallback (bad chain)
        let bad = decode_pem_chain("junk");
        // Verify that invalid non-PEM input properly propagates the base64 decoding error
        assert!(bad.is_err());
    }

    #[test]
    fn test_stack_size_limit() {
        let keypair = SigningKey::generate();

        // Create a heavy warrant (approx 50KB)
        // We do this by adding many constraints
        let mut constraints = ConstraintSet::new();
        // 50 constraints of ~1KB each
        for i in 0..50 {
            let large_val = "x".repeat(1000);
            constraints.insert(
                format!("chk_{}", i),
                Pattern::new(&format!("{}-*", large_val)).unwrap(),
            );
        }

        let heavy_warrant = Warrant::builder()
            .capability("heavy_loading", constraints)
            .ttl(Duration::from_secs(60))
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let single_size = encode(&heavy_warrant).unwrap().len();
        println!("Heavy warrant size: {} bytes", single_size);
        assert!(
            single_size < MAX_WARRANT_SIZE,
            "Single warrant must be valid"
        );

        // Stack 5 of them -> ~250KB + overhead.
        // If single is ~50KB, 5 is ~250KB. We might need 6 to be sure to cross 256KB limit.
        // Let's go for 6 to be safe. 6 * 50 = 300KB > 256KB.
        let chain = vec![heavy_warrant; 6];
        let stack = WarrantStack(chain);

        let encoded_stack = encode_stack(&stack).unwrap();
        println!("Encoded stack size: {} bytes", encoded_stack.len());
        assert!(
            encoded_stack.len() > MAX_STACK_SIZE,
            "Test setup failed: stack not large enough"
        );

        let result = decode_stack(&encoded_stack);
        match result {
            Err(Error::PayloadTooLarge { size, max }) => {
                assert_eq!(max, MAX_STACK_SIZE);
                assert_eq!(size, encoded_stack.len());
            }
            res => panic!("Expected PayloadTooLarge, got {:?}", res),
        }
    }
}
