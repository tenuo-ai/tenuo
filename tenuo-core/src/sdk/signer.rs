use crate::crypto::{PublicKey, Signature, SigningKey};
use crate::SIGNATURE_CONTEXT;
use std::fmt;

/// Signs holder-side proofs and (later) delegation payloads.
pub trait HolderSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;

    fn sign_pop(&self, request: &PopSigningRequest<'_>) -> Result<Signature, SignerError>;

    fn sign_delegation(
        &self,
        request: &DelegationSigningRequest<'_>,
    ) -> Result<Signature, SignerError>;
}

/// Exact bytes an Ed25519 signer must sign for a PoP.
///
/// `final_signing_bytes()` is `SIGNATURE_CONTEXT || pop_preimage`.
/// [`LocalSigner`] calls [`SigningKey::sign_raw`] on those bytes.
pub struct PopSigningRequest<'a> {
    preimage: Vec<u8>,
    capability: &'a str,
    warrant_id: String,
}

impl<'a> PopSigningRequest<'a> {
    pub(crate) fn new(preimage: Vec<u8>, capability: &'a str, warrant_id: String) -> Self {
        Self {
            preimage,
            capability,
            warrant_id,
        }
    }

    pub fn capability(&self) -> &str {
        self.capability
    }

    pub fn warrant_id(&self) -> &str {
        &self.warrant_id
    }

    pub fn purpose(&self) -> &'static str {
        "pop"
    }

    pub fn final_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_CONTEXT.len() + self.preimage.len());
        out.extend_from_slice(SIGNATURE_CONTEXT);
        out.extend_from_slice(&self.preimage);
        out
    }
}

/// Exact bytes an Ed25519 signer must sign for a child warrant.
pub struct DelegationSigningRequest<'a> {
    final_bytes: &'a [u8],
}

impl<'a> DelegationSigningRequest<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(final_bytes: &'a [u8]) -> Self {
        Self { final_bytes }
    }

    pub fn purpose(&self) -> &'static str {
        "delegation"
    }

    pub fn final_signing_bytes(&self) -> &[u8] {
        self.final_bytes
    }
}

/// Local in-process holder key.
pub struct LocalSigner {
    key: SigningKey,
}

impl LocalSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }
}

impl HolderSigner for LocalSigner {
    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    fn sign_pop(&self, request: &PopSigningRequest<'_>) -> Result<Signature, SignerError> {
        Ok(self.key.sign_raw(&request.final_signing_bytes()))
    }

    fn sign_delegation(
        &self,
        request: &DelegationSigningRequest<'_>,
    ) -> Result<Signature, SignerError> {
        Ok(self.key.sign_raw(request.final_signing_bytes()))
    }
}

impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigner")
            .field("public_key", &self.key.public_key().fingerprint())
            .finish()
    }
}

impl fmt::Display for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalSigner({})", self.key.public_key().fingerprint())
    }
}

/// Signer failure. Never includes key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    Unavailable,
    Failed,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "holder signer unavailable"),
            Self::Failed => write!(f, "holder signer failed"),
        }
    }
}

impl std::error::Error for SignerError {}
