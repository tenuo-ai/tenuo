use super::signer::HolderSigner;
use crate::approval::SignedApproval;
use crate::crypto::{PublicKey, Signature};
use crate::warrant::Warrant;
use chrono::{DateTime, Utc};
use std::fmt;
use std::sync::Arc;

/// What a caller presents: an immutable chain plus a holder signer.
///
/// Construction checks empty-chain and signer-to-leaf binding only.
/// Trust, expiry, and cryptography are the guard's decision.
#[derive(Clone)]
pub struct PresentedAuthority {
    chain: Arc<[Warrant]>,
    signer: Arc<dyn HolderSigner>,
}

impl PresentedAuthority {
    pub fn new(chain: Vec<Warrant>, signer: Arc<dyn HolderSigner>) -> Result<Self, AuthorityError> {
        if chain.is_empty() {
            return Err(AuthorityError::EmptyChain);
        }
        let leaf = chain.last().expect("non-empty chain");
        if signer.public_key() != *leaf.authorized_holder() {
            return Err(AuthorityError::SignerMismatch);
        }
        Ok(Self {
            chain: chain.into(),
            signer,
        })
    }

    pub fn leaf(&self) -> &Warrant {
        self.chain.last().expect("non-empty chain")
    }

    pub fn chain(&self) -> &[Warrant] {
        &self.chain
    }

    pub fn holder(&self) -> &PublicKey {
        self.leaf().authorized_holder()
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.leaf().expires_at()
    }

    pub fn capabilities(&self) -> CapabilityView {
        let names = self
            .leaf()
            .capabilities()
            .map(|caps| caps.keys().cloned().collect())
            .unwrap_or_default();
        CapabilityView { names }
    }

    pub(crate) fn signer(&self) -> &dyn HolderSigner {
        self.signer.as_ref()
    }

    #[cfg(feature = "async")]
    pub(crate) fn signer_arc(&self) -> Arc<dyn HolderSigner> {
        self.signer.clone()
    }

    #[cfg(feature = "async")]
    pub(crate) fn chain_arc(&self) -> Arc<[Warrant]> {
        self.chain.clone()
    }

    pub(crate) fn signer_matches_leaf(&self) -> bool {
        self.signer.public_key() == *self.leaf().authorized_holder()
    }
}

impl fmt::Debug for PresentedAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentedAuthority")
            .field("leaf_id", &self.leaf().id().to_string())
            .field("chain_depth", &self.chain.len())
            .field("expires_at", &self.expires_at())
            .field("holder", &self.holder().fingerprint())
            .finish()
    }
}

/// Policy-sensitive capability names claimed by the leaf. Not a verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityView {
    names: Vec<String>,
}

impl CapabilityView {
    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn contains(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }
}

/// Chain + caller PoP + approvals from one received message.
///
/// Construction rejects an empty chain. It does not verify linkage, trust,
/// or the signature — that is the decision.
pub struct ReceivedAuthorization<'a> {
    chain: &'a [Warrant],
    signature: &'a Signature,
    approvals: &'a [SignedApproval],
}

impl<'a> ReceivedAuthorization<'a> {
    pub fn new(
        chain: &'a [Warrant],
        signature: &'a Signature,
        approvals: &'a [SignedApproval],
    ) -> Result<Self, AuthorityError> {
        if chain.is_empty() {
            return Err(AuthorityError::EmptyChain);
        }
        Ok(Self {
            chain,
            signature,
            approvals,
        })
    }

    pub fn chain(&self) -> &'a [Warrant] {
        self.chain
    }

    pub fn signature(&self) -> &'a Signature {
        self.signature
    }

    pub fn approvals(&self) -> &'a [SignedApproval] {
        self.approvals
    }

    pub fn leaf(&self) -> &Warrant {
        self.chain.last().expect("non-empty chain")
    }
}

impl fmt::Debug for ReceivedAuthorization<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedAuthorization")
            .field("leaf_id", &self.leaf().id().to_string())
            .field("chain_depth", &self.chain.len())
            .field("approvals", &self.approvals.len())
            .finish()
    }
}

/// Transport-owned received artifacts. Does not borrow the wire buffer.
#[derive(Clone)]
pub struct OwnedReceivedAuthorization {
    chain: Vec<Warrant>,
    signature: Signature,
    approvals: Vec<SignedApproval>,
}

impl OwnedReceivedAuthorization {
    #[cfg(any(feature = "mcp-transport", feature = "http-transport"))]
    pub(crate) fn new(
        chain: Vec<Warrant>,
        signature: Signature,
        approvals: Vec<SignedApproval>,
    ) -> Result<Self, AuthorityError> {
        if chain.is_empty() {
            return Err(AuthorityError::EmptyChain);
        }
        Ok(Self {
            chain,
            signature,
            approvals,
        })
    }

    pub fn chain(&self) -> &[Warrant] {
        &self.chain
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn approvals(&self) -> &[SignedApproval] {
        &self.approvals
    }

    pub fn as_received(&self) -> Result<ReceivedAuthorization<'_>, AuthorityError> {
        ReceivedAuthorization::new(&self.chain, &self.signature, &self.approvals)
    }
}

/// Structural failure constructing presented or received authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    EmptyChain,
    SignerMismatch,
    MissingSignature,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "authority chain is empty"),
            Self::SignerMismatch => write!(f, "signer does not match leaf holder"),
            Self::MissingSignature => write!(f, "received authorization is missing a signature"),
        }
    }
}

impl std::error::Error for AuthorityError {}
