//! Wire format for Tenuo warrants.
//!
//! Uses CBOR (RFC 8949) for compact binary serialization.
//! Warrants are typically carried in HTTP headers or gRPC metadata,
//! so compact encoding is important.

use crate::error::{Error, Result};
use crate::warrant::Warrant;
use crate::WIRE_VERSION;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// A versioned wire envelope for warrants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// Wire format version.
    pub version: u8,
    /// The warrant payload (CBOR-encoded, then included here).
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

impl WireEnvelope {
    /// Create a new envelope for a warrant.
    pub fn new(warrant: &Warrant) -> Result<Self> {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(warrant, &mut payload)?;
        Ok(Self {
            version: WIRE_VERSION,
            payload,
        })
    }

    /// Extract the warrant from the envelope.
    pub fn extract(&self) -> Result<Warrant> {
        if self.version != WIRE_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        ciborium::de::from_reader(&self.payload[..]).map_err(Into::into)
    }
}

/// Encode a warrant to a compact binary format.
pub fn encode(warrant: &Warrant) -> Result<Vec<u8>> {
    let envelope = WireEnvelope::new(warrant)?;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut buf)?;
    Ok(buf)
}

/// Decode a warrant from binary format.
pub fn decode(data: &[u8]) -> Result<Warrant> {
    let envelope: WireEnvelope = ciborium::de::from_reader(data)?;
    envelope.extract()
}

/// Encode a warrant to a base64 string (for HTTP headers).
pub fn encode_base64(warrant: &Warrant) -> Result<String> {
    let bytes = encode(warrant)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Decode a warrant from a base64 string.
pub fn decode_base64(s: &str) -> Result<Warrant> {
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
    use crate::constraints::Pattern;
    use crate::crypto::Keypair;
    use std::time::Duration;

    #[test]
    fn test_encode_decode_roundtrip() {
        let keypair = Keypair::generate();
        let warrant = Warrant::builder()
            .tool("test_tool")
            .constraint("arg", Pattern::new("value-*").unwrap())
            .ttl(Duration::from_secs(300))
            .build(&keypair)
            .unwrap();

        let encoded = encode(&warrant).unwrap();
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.id(), warrant.id());
        assert_eq!(decoded.tool(), warrant.tool());
    }

    #[test]
    fn test_base64_roundtrip() {
        let keypair = Keypair::generate();
        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .build(&keypair)
            .unwrap();

        let encoded = encode_base64(&warrant).unwrap();
        
        // Should be reasonably short for headers
        println!("Base64 warrant length: {} chars", encoded.len());
        assert!(encoded.len() < 1000, "Warrant too large for typical headers");

        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded.id(), warrant.id());
    }

    #[test]
    fn test_version_check() {
        let keypair = Keypair::generate();
        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .build(&keypair)
            .unwrap();

        let mut envelope = WireEnvelope::new(&warrant).unwrap();
        envelope.version = 99; // Invalid version

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&envelope, &mut buf).unwrap();

        let result = decode(&buf);
        assert!(matches!(result, Err(Error::UnsupportedVersion(99))));
    }

    #[test]
    fn test_compact_encoding() {
        let keypair = Keypair::generate();
        
        // Minimal warrant
        let minimal = Warrant::builder()
            .tool("t")
            .ttl(Duration::from_secs(60))
            .build(&keypair)
            .unwrap();

        let minimal_size = encode(&minimal).unwrap().len();
        println!("Minimal warrant size: {} bytes", minimal_size);

        // Warrant with constraints
        let with_constraints = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .constraint("version", Pattern::new("1.28.*").unwrap())
            .ttl(Duration::from_secs(600))
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
        let keypair = Keypair::generate();
        
        // Create a warrant with multiple constraints in different "insertion" order
        // to verify BTreeMap provides consistent ordering
        let warrant1 = Warrant::builder()
            .tool("test")
            .constraint("zebra", Pattern::new("z-*").unwrap())  // Insert Z first
            .constraint("alpha", Pattern::new("a-*").unwrap())  // Then A
            .constraint("middle", Pattern::new("m-*").unwrap()) // Then M
            .ttl(Duration::from_secs(300))
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
        assert_eq!(bytes1, bytes_after_roundtrip, 
            "Serialization after roundtrip should be identical");
        
        // Verify signature still works after roundtrip
        assert!(decoded.verify(&keypair.public_key()).is_ok(),
            "Signature verification should work after roundtrip");
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
        map2.insert("alpha".to_string(), 2);  // Insert in different order
        map2.insert("zebra".to_string(), 1);
        
        let mut bytes1 = Vec::new();
        let mut bytes2 = Vec::new();
        ciborium::ser::into_writer(&map1, &mut bytes1).unwrap();
        ciborium::ser::into_writer(&map2, &mut bytes2).unwrap();
        
        assert_eq!(bytes1, bytes2, 
            "BTreeMap should serialize identically regardless of insertion order");
        
        // Test 2: Same struct serializes identically
        #[derive(serde::Serialize)]
        struct TestStruct {
            a: i32,
            b: String,
            c: Option<f64>,
        }
        
        let s1 = TestStruct { a: 42, b: "hello".to_string(), c: Some(3.14) };
        let s2 = TestStruct { a: 42, b: "hello".to_string(), c: Some(3.14) };
        
        let mut b1 = Vec::new();
        let mut b2 = Vec::new();
        ciborium::ser::into_writer(&s1, &mut b1).unwrap();
        ciborium::ser::into_writer(&s2, &mut b2).unwrap();
        
        assert_eq!(b1, b2, "Identical structs should serialize identically");
        
        // Test 3: Integers use minimal encoding
        let small: i64 = 23;  // Should fit in 1 byte
        let mut small_bytes = Vec::new();
        ciborium::ser::into_writer(&small, &mut small_bytes).unwrap();
        assert!(small_bytes.len() <= 2, 
            "Small integers should use compact encoding: got {} bytes", small_bytes.len());
    }
}

