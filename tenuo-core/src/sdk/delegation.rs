use super::authority::{AuthorityError, PresentedAuthority};
use super::signer::{DelegationSigningRequest, LocalSigner, SignerError};
use crate::constraints::ConstraintSet;
use crate::crypto::{PublicKey, SigningKey};
use crate::warrant::{PreparedDelegation, Warrant};
use crate::Error;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Capabilities for one delegation. Starts empty; no inherit-all.
#[derive(Clone, Debug, Default)]
pub struct DelegationProfile {
    tools: BTreeMap<String, ConstraintSet>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    terminal: bool,
}

impl DelegationProfile {
    /// An empty profile. Capabilities must be added explicitly; a child starts with none.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant one capability to the child, under `constraints`.
    pub fn capability(mut self, tool: impl Into<String>, constraints: ConstraintSet) -> Self {
        self.tools.insert(tool.into(), constraints);
        self
    }

    /// Child lifetime. Capped by the parent's remaining lifetime regardless.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Maximum depth the child may delegate to. Never wider than the parent's.
    pub fn max_depth(mut self, depth: u32) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Child cannot delegate further.
    pub fn terminal(mut self) -> Self {
        self.terminal = true;
        self
    }
}

impl PresentedAuthority {
    /// Local child: mint a fresh ephemeral key and return a usable authority.
    ///
    /// This does not consult trust, revocation, or clearance. A revoked parent
    /// can still mint here. Prefer [`crate::sdk::Guard::delegate`] when a
    /// [`crate::sdk::Guard`] is in scope — that path checks the parent under
    /// current policy before signing. The child is only as good as the
    /// receiving enforcement point's fresh revocation state.
    pub fn delegate_local(
        &self,
        profile: &DelegationProfile,
    ) -> Result<PresentedAuthority, DelegationError> {
        let child_key = SigningKey::generate();
        let chain = self.delegate_to(&child_key.public_key(), profile)?;
        PresentedAuthority::new(chain, Arc::new(LocalSigner::new(child_key))).map_err(Into::into)
    }

    /// Remote child: this process has no signer for the child.
    ///
    /// Unguarded, same as [`Self::delegate_local`]. Use [`crate::sdk::Guard::delegate_to`]
    /// to refuse minting from a parent that is not live under current policy.
    pub fn delegate_to(
        &self,
        child_holder: &PublicKey,
        profile: &DelegationProfile,
    ) -> Result<Vec<Warrant>, DelegationError> {
        if profile.tools.is_empty() {
            return Err(DelegationError::EmptyProfile);
        }
        if child_holder == self.holder() {
            return Err(DelegationError::ChildMustBeDistinct);
        }

        let mut builder = self.leaf().attenuate().holder(child_holder.clone());
        for (tool, constraints) in &profile.tools {
            builder = builder.tool(tool.clone(), constraints.clone());
        }
        if let Some(ttl) = profile.ttl {
            builder = builder.ttl(ttl);
        }
        if profile.terminal {
            builder = builder.max_depth(self.leaf().depth() + 1);
        } else if let Some(depth) = profile.max_depth {
            builder = builder.max_depth(depth);
        }

        let prepared: PreparedDelegation = builder.prepare()?;
        let bytes = prepared.final_signing_bytes().to_vec();
        let request = DelegationSigningRequest::new(&bytes);
        let signature = self.signer().sign_delegation(&request)?;
        let child = prepared.finalize(signature)?;

        let mut chain = self.chain().to_vec();
        chain.push(child);
        Ok(chain)
    }
}

#[derive(Debug)]
/// Why a child could not be minted.
pub enum DelegationError {
    /// The profile granted nothing. A child with no capabilities is a mistake, not a
    /// restriction.
    EmptyProfile,
    /// The child holder is the parent holder. Delegation must produce a distinct identity.
    ChildMustBeDistinct,
    /// A guard refused to delegate from this parent under current policy.
    Denied(super::decision::Denial),
    /// The parent's signer could not sign the child payload.
    Signer(SignerError),
    /// The resulting child authority was not constructible.
    Authority(AuthorityError),
    /// Core rejected the attenuation — the child was not narrower than the parent.
    Core(Error),
}

impl From<Error> for DelegationError {
    fn from(value: Error) -> Self {
        Self::Core(value)
    }
}

impl From<SignerError> for DelegationError {
    fn from(value: SignerError) -> Self {
        Self::Signer(value)
    }
}

impl From<AuthorityError> for DelegationError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<super::decision::Denial> for DelegationError {
    fn from(value: super::decision::Denial) -> Self {
        Self::Denied(value)
    }
}

impl fmt::Display for DelegationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProfile => write!(f, "delegation profile has no capabilities"),
            Self::ChildMustBeDistinct => write!(f, "child holder must differ from the parent"),
            Self::Denied(err) => write!(f, "{err}"),
            Self::Signer(err) => write!(f, "{err}"),
            Self::Authority(err) => write!(f, "{err}"),
            Self::Core(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DelegationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::planes::Authorizer;
    use crate::sdk::signer::{HolderSigner, LocalSigner};
    use crate::sdk::{Call, Guard, RevocationMode};
    use crate::SigningKey;
    use std::collections::HashMap;
    use std::time::Duration;

    fn mint_root(issuer: &SigningKey, holder: &SigningKey, tool: &str) -> Warrant {
        Warrant::builder()
            .capability(tool, ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .max_depth(8)
            .build(issuer)
            .unwrap()
    }

    fn authority(issuer: &SigningKey, holder: SigningKey, tool: &str) -> PresentedAuthority {
        let warrant = mint_root(issuer, &holder, tool);
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap()
    }

    #[test]
    fn three_hop_local_delegation() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        let child = root.delegate_local(&profile).unwrap();
        let grandchild = child.delegate_local(&profile).unwrap();

        assert_eq!(root.chain().len(), 1);
        assert_eq!(child.chain().len(), 2);
        assert_eq!(grandchild.chain().len(), 3);
        assert_ne!(root.holder(), child.holder());
        assert_ne!(child.holder(), grandchild.holder());
        assert_eq!(grandchild.leaf().depth(), 2);

        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        guard.check(&grandchild, &call).expect("three-hop allow");
    }

    #[test]
    fn delegate_to_returns_chain_not_authority() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let remote = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        let chain = root.delegate_to(&remote.public_key(), &profile).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].authorized_holder(), &remote.public_key());
        let child = PresentedAuthority::new(chain, Arc::new(LocalSigner::new(remote))).unwrap();
        assert_ne!(child.holder(), root.holder());
    }

    #[test]
    fn empty_profile_and_same_holder_rejected() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        assert!(matches!(
            root.delegate_to(
                &SigningKey::generate().public_key(),
                &DelegationProfile::new()
            )
            .err()
            .unwrap(),
            DelegationError::EmptyProfile
        ));
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        assert!(matches!(
            root.delegate_to(root.holder(), &profile).err().unwrap(),
            DelegationError::ChildMustBeDistinct
        ));
    }

    #[test]
    fn guard_delegate_refuses_revoked_parent() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        let srl = crate::revocation::SignedRevocationList::builder()
            .revoke(root.leaf().id().to_string())
            .version(1)
            .build(&issuer)
            .unwrap();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        authorizer
            .set_revocation_list(srl, &issuer.public_key())
            .unwrap();
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::SignedSrl)
            .build()
            .unwrap();
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        assert!(matches!(
            guard.delegate(&root, &profile).err().unwrap(),
            DelegationError::Denied(_)
        ));
        assert!(root.delegate_local(&profile).is_ok());
    }

    #[test]
    fn guard_delegate_allows_live_parent() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        let child = guard.delegate(&root, &profile).unwrap();
        assert_eq!(child.chain().len(), 2);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        guard.check(&child, &call).expect("child live");
    }

    #[test]
    fn cannot_widen_capability() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        let profile = DelegationProfile::new().capability("write", ConstraintSet::new());
        assert!(root
            .delegate_to(&SigningKey::generate().public_key(), &profile)
            .is_err());
    }

    #[test]
    fn parallel_children_are_distinct() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let root = authority(&issuer, holder, "read");
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        let a = root.delegate_local(&profile).unwrap();
        let b = root.delegate_local(&profile).unwrap();
        assert_ne!(a.holder(), b.holder());
        assert_ne!(a.leaf().id(), b.leaf().id());
    }

    #[test]
    fn raw_parent_signer_delegates() {
        struct Raw(SigningKey);
        impl HolderSigner for Raw {
            fn public_key(&self) -> PublicKey {
                self.0.public_key()
            }
            fn sign_pop(
                &self,
                request: &crate::sdk::PopSigningRequest<'_>,
            ) -> Result<crate::crypto::Signature, SignerError> {
                Ok(self.0.sign_raw(&request.final_signing_bytes()))
            }
            fn sign_delegation(
                &self,
                request: &DelegationSigningRequest<'_>,
            ) -> Result<crate::crypto::Signature, SignerError> {
                Ok(self.0.sign_raw(request.final_signing_bytes()))
            }
        }

        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_root(&issuer, &holder, "read");
        let parent = PresentedAuthority::new(vec![warrant], Arc::new(Raw(holder))).unwrap();
        let remote = SigningKey::generate();
        let profile = DelegationProfile::new().capability("read", ConstraintSet::new());
        let chain = parent.delegate_to(&remote.public_key(), &profile).unwrap();
        assert_eq!(chain.len(), 2);
    }
}
