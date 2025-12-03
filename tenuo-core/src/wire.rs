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
}

