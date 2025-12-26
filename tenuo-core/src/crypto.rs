//! Cryptographic primitives for Tenuo.
//!
//! Uses Ed25519 with context strings to prevent cross-protocol attacks.
//!
//! ## Security Properties
//!
//! 1. **Domain Separation**: All signatures include a context prefix (`tenuo-warrant-v1`)
//!    to prevent cross-protocol attacks.
//!
//! 2. **Batch Verification**: For deep delegation chains, use `verify_batch` to verify
//!    multiple signatures in a single pass (~3x faster than sequential).

use crate::error::{Error, Result};
use crate::SIGNATURE_CONTEXT;
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as Ed25519SigningKey, Verifier, VerifyingKey,
};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use secrecy::{CloneableSecret, ExposeSecret, Secret, Zeroize};
use serde::{Deserialize, Serialize};

/// A signing key for creating and signing warrants.
///
/// Contains an Ed25519 private key wrapped in `Secret` for:
/// 1. Guaranteed zeroization on drop
/// 2. Prevention of accidental logging (Debug is redacted)
/// 3. Safe cloning (zeroizes the old memory)
#[derive(Clone)]
pub struct SigningKey {
    signing_key: Secret<Ed25519SigningKeyWrapper>,
}

// Wrapper to implement Zeroize and Clone for Ed25519SigningKey
// ed25519-dalek 2.x SigningKey implements ZeroizeOnDrop.
// We implement Zeroize as a no-op because the inner type handles it on Drop.
struct Ed25519SigningKeyWrapper(Ed25519SigningKey);

impl Clone for Ed25519SigningKeyWrapper {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Zeroize for Ed25519SigningKeyWrapper {
    fn zeroize(&mut self) {
        // No-op: ed25519-dalek handles zeroization on Drop.
    }
}

/// Marker trait for Secrecy to allow cloning Secret<T>
impl CloneableSecret for Ed25519SigningKeyWrapper {}

// Custom Debug to match secrecy's behavior (redacted)
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("signing_key", &"***SECRET***")
            .finish()
    }
}

impl SigningKey {
    /// Generate a new random signing key.
    pub fn generate() -> Self {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        Self {
            signing_key: Secret::new(Ed25519SigningKeyWrapper(signing_key)),
        }
    }

    /// Create a signing key from secret key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = Ed25519SigningKey::from_bytes(bytes);
        Self {
            signing_key: Secret::new(Ed25519SigningKeyWrapper(signing_key)),
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.expose_secret().0.verifying_key(),
        }
    }

    /// Sign a message with context prefix.
    ///
    /// The actual signed data is: `SIGNATURE_CONTEXT || message`
    pub fn sign(&self, message: &[u8]) -> Signature {
        let prefixed = Self::prefix_message(message);
        let sig = self.signing_key.expose_secret().0.sign(&prefixed);
        Signature { inner: sig }
    }

    /// Get the secret key bytes.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.expose_secret().0.to_bytes()
    }

    /// Prefix a message with the context string for domain separation.
    fn prefix_message(message: &[u8]) -> Vec<u8> {
        let mut prefixed = Vec::with_capacity(SIGNATURE_CONTEXT.len() + message.len());
        prefixed.extend_from_slice(SIGNATURE_CONTEXT);
        prefixed.extend_from_slice(message);
        prefixed
    }

    /// Create a signing key from a PEM string.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let signing_key = Ed25519SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::CryptoError(format!("Invalid PEM: {}", e)))?;
        Ok(Self {
            signing_key: Secret::new(Ed25519SigningKeyWrapper(signing_key)),
        })
    }

    /// Convert the signing key to a PEM string.
    pub fn to_pem(&self) -> String {
        self.signing_key
            .expose_secret()
            .0
            .to_pkcs8_pem(LineEnding::LF)
            .map(|s| s.to_string())
            .unwrap_or_else(|e| format!("error generating pem: {}", e))
    }
}

/// A public key for verifying warrant signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

impl PublicKey {
    /// Create a public key from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|e| Error::CryptoError(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Get the public key as bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get a short fingerprint of the public key (first 16 hex chars).
    ///
    /// Useful for audit logs and receipts where full key isn't needed.
    pub fn fingerprint(&self) -> String {
        let bytes = self.to_bytes();
        hex::encode(&bytes[..8])
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let prefixed = SigningKey::prefix_message(message);
        self.verifying_key
            .verify(&prefixed, &signature.inner)
            .map_err(|e| Error::SignatureInvalid(e.to_string()))
    }

    /// Create a public key from a PEM string.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let verifying_key = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| Error::CryptoError(format!("Invalid PEM: {}", e)))?;
        Ok(Self { verifying_key })
    }

    /// Convert the public key to a PEM string.
    pub fn to_pem(&self) -> String {
        self.verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map(|s| s.to_string())
            .unwrap_or_else(|e| format!("error generating pem: {}", e))
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

/// Batch verify multiple signatures in a single pass.
///
/// This is significantly faster than verifying each signature individually
/// when you have many signatures to check (e.g., deep delegation chains).
///
/// Uses random linear combinations internally for security.
///
/// # Example
///
/// ```rust,ignore
/// let items: Vec<(&PublicKey, &[u8], &Signature)> = chain
///     .iter()
///     .map(|w| (w.issuer(), w.payload_bytes(), w.signature()))
///     .collect();
/// verify_batch(&items)?;
/// ```
pub fn verify_batch(items: &[(&PublicKey, &[u8], &Signature)]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }

    // Prepare prefixed messages
    let prefixed_messages: Vec<Vec<u8>> = items
        .iter()
        .map(|(_, msg, _)| SigningKey::prefix_message(msg))
        .collect();

    // Extract components for batch verification
    let messages: Vec<&[u8]> = prefixed_messages.iter().map(|v| v.as_slice()).collect();
    let signatures: Vec<DalekSignature> = items.iter().map(|(_, _, s)| s.inner).collect();
    let verifying_keys: Vec<VerifyingKey> =
        items.iter().map(|(pk, _, _)| pk.verifying_key).collect();

    // Use ed25519_dalek's batch verification
    ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys)
        .map_err(|e| Error::SignatureInvalid(format!("batch verification failed: {}", e)))
}

const ED25519_ALG_ID: u8 = 1; //Djb's gift to the world.

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                bytes,
            ))
        } else {
            // Wire format: [algorithm, bytes]
            use serde::ser::SerializeTuple;
            let mut tup = serializer.serialize_tuple(2)?;
            tup.serialize_element(&ED25519_ALG_ID)?;
            tup.serialize_element(&serde_bytes::Bytes::new(&bytes))?;
            tup.end()
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &s)
                    .map_err(serde::de::Error::custom)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid public key length"))?;
            PublicKey::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            struct PublicKeyVisitor;

            impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a public key array [algo, bytes]")
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let alg: u8 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                    if alg != ED25519_ALG_ID {
                        return Err(serde::de::Error::custom(format!(
                            "unsupported algorithm id: {}",
                            alg
                        )));
                    }

                    let bytes: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| serde::de::Error::custom("invalid public key length"))?;

                    PublicKey::from_bytes(&arr).map_err(serde::de::Error::custom)
                }
            }

            deserializer.deserialize_tuple(2, PublicKeyVisitor)
        }
    }
}

/// An Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    inner: DalekSignature,
}

impl Signature {
    /// Create a signature from bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let inner = DalekSignature::from_bytes(bytes);
        Ok(Self { inner })
    }

    /// Get the signature as bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                bytes,
            ))
        } else {
            // Wire format: [algorithm, bytes]
            use serde::ser::SerializeTuple;
            let mut tup = serializer.serialize_tuple(2)?;
            tup.serialize_element(&ED25519_ALG_ID)?;
            tup.serialize_element(&serde_bytes::Bytes::new(&bytes))?;
            tup.end()
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &s)
                    .map_err(serde::de::Error::custom)?;
            let arr: [u8; 64] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid signature length"))?;
            Signature::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            struct SignatureVisitor;

            impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
                type Value = Signature;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a signature array [algo, bytes]")
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let alg: u8 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                    if alg != ED25519_ALG_ID {
                        return Err(serde::de::Error::custom(format!(
                            "unsupported algorithm id: {}",
                            alg
                        )));
                    }

                    let bytes: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                    let arr: [u8; 64] = bytes
                        .try_into()
                        .map_err(|_| serde::de::Error::custom("invalid signature length"))?;

                    Signature::from_bytes(&arr).map_err(serde::de::Error::custom)
                }
            }

            deserializer.deserialize_tuple(2, SignatureVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = SigningKey::generate();
        let public_key = keypair.public_key();
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SigningKey::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let keypair = SigningKey::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        let wrong_message = b"wrong message";
        assert!(keypair
            .public_key()
            .verify(wrong_message, &signature)
            .is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let keypair1 = SigningKey::generate();
        let keypair2 = SigningKey::generate();
        let message = b"test message";
        let signature = keypair1.sign(message);

        assert!(keypair2.public_key().verify(message, &signature).is_err());
    }

    #[test]
    fn test_keypair_from_bytes() {
        let keypair = SigningKey::generate();
        let bytes = keypair.secret_key_bytes();
        let restored = SigningKey::from_bytes(&bytes);

        assert_eq!(
            keypair.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
    }

    #[test]
    fn test_context_prefix_prevents_cross_protocol() {
        let keypair = SigningKey::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        // Manually create a signature without context prefix
        // This should fail verification
        // Manually create a signature without context prefix
        // This should fail verification
        let raw_sig = keypair.signing_key.expose_secret().0.sign(message);
        let wrong_signature = Signature { inner: raw_sig };

        assert!(keypair
            .public_key()
            .verify(message, &wrong_signature)
            .is_err());
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_batch_verification() {
        let kp1 = SigningKey::generate();
        let kp2 = SigningKey::generate();
        let kp3 = SigningKey::generate();

        let msg1 = b"message 1";
        let msg2 = b"message 2";
        let msg3 = b"message 3";

        let sig1 = kp1.sign(msg1);
        let sig2 = kp2.sign(msg2);
        let sig3 = kp3.sign(msg3);

        let pk1 = kp1.public_key();
        let pk2 = kp2.public_key();
        let pk3 = kp3.public_key();

        // All valid - should pass
        let items = vec![
            (&pk1, msg1.as_slice(), &sig1),
            (&pk2, msg2.as_slice(), &sig2),
            (&pk3, msg3.as_slice(), &sig3),
        ];
        assert!(verify_batch(&items).is_ok());

        // One invalid - should fail
        let bad_items = vec![
            (&pk1, msg1.as_slice(), &sig1),
            (&pk2, msg1.as_slice(), &sig2), // Wrong message
            (&pk3, msg3.as_slice(), &sig3),
        ];
        assert!(verify_batch(&bad_items).is_err());
    }
}
