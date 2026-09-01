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
    /// Bind a chain to the signer that holds its leaf.
    ///
    /// Validates only that the chain is non-empty and that the signer's public key is the
    /// leaf holder. Trust, linkage, expiry, and revocation are the guard's, evaluated on
    /// every invocation.
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

    /// Last warrant in the chain — the one that authorizes calls.
    pub fn leaf(&self) -> &Warrant {
        self.chain.last().expect("non-empty chain")
    }

    /// Full chain, root first.
    pub fn chain(&self) -> &[Warrant] {
        &self.chain
    }

    /// Public key of the leaf holder.
    pub fn holder(&self) -> &PublicKey {
        self.leaf().authorized_holder()
    }

    /// When the leaf expires.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.leaf().expires_at()
    }

    /// Capability names this chain claims.
    ///
    /// Policy-sensitive: it reflects what the chain asserts, not what any enforcement
    /// point will allow, and the set a principal holds is itself disclosive. Use it for
    /// local UX filtering, not as an answer to an untrusted caller.
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
    /// Capability names, sorted.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Whether a capability name is present.
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
    /// Bind artifacts received from a peer.
    ///
    /// Validates only that the chain is non-empty. Verification is the decision.
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

    /// Received chain, root first.
    pub fn chain(&self) -> &'a [Warrant] {
        self.chain
    }

    /// Caller's proof of possession.
    pub fn signature(&self) -> &'a Signature {
        self.signature
    }

    /// Approvals the caller supplied.
    pub fn approvals(&self) -> &'a [SignedApproval] {
        self.approvals
    }

    /// Last warrant in the received chain.
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

    /// Received chain, root first.
    pub fn chain(&self) -> &[Warrant] {
        &self.chain
    }

    /// Caller's proof of possession.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Approvals the caller supplied.
    pub fn approvals(&self) -> &[SignedApproval] {
        &self.approvals
    }

    /// Borrow these owned artifacts as a [`ReceivedAuthorization`].
    pub fn as_received(&self) -> Result<ReceivedAuthorization<'_>, AuthorityError> {
        ReceivedAuthorization::new(&self.chain, &self.signature, &self.approvals)
    }
}

/// Structural failure constructing presented or received authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// The chain was empty.
    EmptyChain,
    /// The signer's public key is not the leaf holder.
    SignerMismatch,
    /// A proof of possession was expected and absent.
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
