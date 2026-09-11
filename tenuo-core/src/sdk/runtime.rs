//! Long-lived holder runtime: identity, trust, revocation, and sessions.
//!
//! [`Tenuo::local`] still builds one guard bound to one chain. A [`Runtime`]
//! holds the pieces that stay the same across warrants — holder key, trusted
//! roots, receipt policy, TTL fallback — and binds each new warrant into a
//! [`Session`]. Callers that obtain warrants and SRLs from the network
//! should not assemble `Authorizer`, `LocalReceiptSigner`, and
//! `MemoryReceiptSink`.

use super::authority::{AuthorityError, PresentedAuthority};
use super::call::Call;
use super::decision::{Denial, DenialReporting, GuardError};
use super::delegation::{DelegationError, DelegationProfile};
use super::diagnostics::Diagnostics;
use super::guard::{AuthorizedCall, Guard, GuardBuildError, Guarded, RevocationMode};
use super::identity::{IdentityError, PersistentIdentity};
use super::signer::LocalSigner;
use crate::crypto::{PublicKey, SigningKey};
use crate::planes::Authorizer;
use crate::revocation::SignedRevocationList;
use crate::revocation_tracker::{
    FileFloorStore, InMemoryFloorStore, RevocationError, RevocationFloorStore, RevocationTracker,
    RevocationUpdate,
};
use crate::warrant::Warrant;
use crate::Error;
use chrono::{DateTime, Utc};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "receipts")]
use super::evidence::{EvidencePolicy, LocalReceiptSigner, MemoryReceiptSink};
#[cfg(feature = "receipts")]
use crate::receipt::Receipt;

const DEFAULT_SRL_MAX_AGE: Duration = Duration::from_secs(300);
const DEFAULT_SRL_CLOCK_TOLERANCE: Duration = Duration::from_secs(30);

/// Configured holder runtime. Clone shares identity, trust, and revocation.
#[derive(Clone)]
pub struct Runtime {
    identity: PersistentIdentity,
    roots: Vec<PublicKey>,
    ttl_fallback: Duration,
    revocation: Option<RevocationMode>,
    tracker: Arc<RevocationTracker>,
    denial_reporting: DenialReporting,
    #[cfg(feature = "receipts")]
    evidence: EvidencePolicy,
    #[cfg(feature = "receipts")]
    receipt_capacity: usize,
    #[cfg(feature = "receipts")]
    receipt_link: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
}

/// One warrant bound to this runtime's holder key.
pub struct Session {
    enforcer: Guard,
    authority: PresentedAuthority,
    #[cfg(feature = "receipts")]
    receipts: Option<Arc<MemoryReceiptSink>>,
}

/// Builds a [`Runtime`]. Identity, at least one trusted root, and either
/// [`Self::ttl_fallback`] (selects [`RevocationMode::TtlUntilSrl`]) or
/// [`Self::revocation`] are required.
pub struct RuntimeBuilder {
    identity: Option<PersistentIdentity>,
    roots: Vec<PublicKey>,
    ttl_fallback: Option<Duration>,
    revocation: Option<RevocationMode>,
    srl_max_age: Duration,
    srl_clock_tolerance: Duration,
    floor_path: Option<PathBuf>,
    denial_reporting: DenialReporting,
    #[cfg(feature = "receipts")]
    evidence: EvidencePolicy,
    #[cfg(feature = "receipts")]
    receipt_capacity: usize,
}

impl Runtime {
    /// Start a runtime builder.
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder {
            identity: None,
            roots: Vec::new(),
            ttl_fallback: None,
            revocation: None,
            srl_max_age: DEFAULT_SRL_MAX_AGE,
            srl_clock_tolerance: DEFAULT_SRL_CLOCK_TOLERANCE,
            floor_path: None,
            denial_reporting: DenialReporting::Error,
            #[cfg(feature = "receipts")]
            evidence: EvidencePolicy::Disabled,
            #[cfg(feature = "receipts")]
            receipt_capacity: 10_000,
        }
    }

    /// Holder identity this runtime signs with.
    pub fn identity(&self) -> &PersistentIdentity {
        &self.identity
    }

    /// Trusted roots used for warrants and signed revocation lists.
    pub fn trusted_roots(&self) -> &[PublicKey] {
        &self.roots
    }

    /// Install a decoded SRL using the current time as `fetched_at`.
    pub fn apply_signed_revocation_list_now(
        &self,
        srl: SignedRevocationList,
    ) -> Result<u64, RuntimeError> {
        self.apply_signed_revocation_list(srl, Utc::now())
    }

    /// Install or refresh a decoded signed revocation list.
    ///
    /// Existing sessions see the new list on the next check. Until the first
    /// successful call they keep the TTL fallback. How the list is fetched is
    /// the caller's concern.
    pub fn apply_signed_revocation_list(
        &self,
        srl: SignedRevocationList,
        fetched_at: DateTime<Utc>,
    ) -> Result<u64, RuntimeError> {
        if matches!(self.revocation, Some(RevocationMode::TtlOnly { .. })) {
            return Err(RuntimeError::TtlOnlyIgnoresSrl);
        }
        let version = srl.version();
        self.tracker
            .accept(RevocationUpdate { srl, fetched_at }, Utc::now())?;
        Ok(version)
    }

    /// Decode a standard-base64 SRL and install it.
    pub fn apply_encoded_revocation_list(
        &self,
        encoded: &str,
        fetched_at: DateTime<Utc>,
    ) -> Result<u64, RuntimeError> {
        let srl = SignedRevocationList::from_base64(encoded).map_err(RuntimeError::Warrant)?;
        self.apply_signed_revocation_list(srl, fetched_at)
    }

    /// Bind an encoded or decoded warrant to the holder key and return a session.
    pub fn session_from_warrant(
        &self,
        warrant: impl SessionWarrant,
    ) -> Result<Session, RuntimeError> {
        let warrant = warrant.into_warrant()?;
        let mut authorizer = Authorizer::new();
        for root in &self.roots {
            authorizer.add_trusted_root(root.clone());
        }

        let mut builder = Guard::builder()
            .authorizer(authorizer)
            .denial_reporting(self.denial_reporting);
        builder = match &self.revocation {
            None | Some(RevocationMode::TtlUntilSrl { .. }) => {
                builder.ttl_until_signed_srl(self.ttl_fallback, self.tracker.clone())
            }
            Some(RevocationMode::TtlOnly { max_lifetime }) => {
                builder.revocation(RevocationMode::TtlOnly {
                    max_lifetime: *max_lifetime,
                })
            }
            Some(RevocationMode::SignedSrl) => builder
                .revocation(RevocationMode::SignedSrl)
                .revocation_tracker(self.tracker.clone()),
        };

        #[cfg(feature = "receipts")]
        let receipts = {
            let receipts = match self.evidence {
                EvidencePolicy::Disabled => None,
                EvidencePolicy::BestEffort | EvidencePolicy::RequiredBeforeExecution => Some(
                    Arc::new(MemoryReceiptSink::with_capacity(self.receipt_capacity)),
                ),
            };
            if let Some(sink) = receipts.as_ref() {
                builder = builder
                    .evidence_policy(self.evidence)
                    .receipt_signer(Arc::new(LocalReceiptSigner::new(
                        self.identity.signing_key().clone(),
                    )))
                    .receipt_sink(sink.clone())
                    .receipt_link(self.receipt_link.clone());
            }
            receipts
        };

        let enforcer = builder.build()?;
        let authority = PresentedAuthority::new(
            vec![warrant],
            Arc::new(LocalSigner::new(self.identity.signing_key().clone())),
        )?;

        Ok(Session {
            enforcer,
            authority,
            #[cfg(feature = "receipts")]
            receipts,
        })
    }
}

impl Session {
    /// The guard this session will use.
    pub fn enforcer(&self) -> &Guard {
        &self.enforcer
    }

    /// Warrant chain bound to the runtime holder key.
    pub fn authority(&self) -> &PresentedAuthority {
        &self.authority
    }

    /// Authorize `call` with this session's warrant, then run `op`.
    pub fn guard<T, E>(
        &self,
        call: &Call<'_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        self.enforcer.guard(&self.authority, call, op)
    }

    /// Decide without running anything.
    pub fn check(&self, call: &Call<'_>) -> Result<crate::sdk::Decision, Denial> {
        self.enforcer.check(&self.authority, call)
    }

    /// Snapshot of pending receipts. They are removed only by
    /// [`acknowledge_receipts`].
    #[cfg(feature = "receipts")]
    pub fn drain_receipts(&self) -> Vec<Receipt> {
        self.peek_receipts()
    }

    /// Snapshot of pending receipts. Same as [`drain_receipts`].
    #[cfg(feature = "receipts")]
    pub fn peek_receipts(&self) -> Vec<Receipt> {
        let Some(sink) = self.receipts.as_ref() else {
            return Vec::new();
        };
        sink.pending()
    }

    /// Remove the first `count` pending receipts from the sink.
    #[cfg(feature = "receipts")]
    pub fn acknowledge_receipts(&self, count: usize) -> usize {
        let Some(sink) = self.receipts.as_ref() else {
            return 0;
        };
        sink.drop_prefix(count)
    }

    /// Receipts dropped because this session's outbox was full.
    #[cfg(feature = "receipts")]
    pub fn receipt_overflows(&self) -> usize {
        self.receipts
            .as_ref()
            .map(|sink| sink.overflowed())
            .unwrap_or(0)
    }

    /// Operator-side explanation for this session's warrant.
    pub fn diagnostics(&self) -> Diagnostics<'_> {
        self.enforcer.diagnostics(&self.authority)
    }

    /// Mint a local child after confirming this session's parent is live.
    pub fn delegate(
        &self,
        profile: &DelegationProfile,
    ) -> Result<PresentedAuthority, DelegationError> {
        self.enforcer.delegate(&self.authority, profile)
    }

    /// Mint a remote child after confirming this session's parent is live.
    pub fn delegate_to(
        &self,
        child_holder: &PublicKey,
        profile: &DelegationProfile,
    ) -> Result<Vec<Warrant>, DelegationError> {
        self.enforcer
            .delegate_to(&self.authority, child_holder, profile)
    }
}

impl RuntimeBuilder {
    /// Persistent or ephemeral holder identity.
    pub fn identity(mut self, identity: PersistentIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// In-process holder key. Equivalent to [`PersistentIdentity::ephemeral`].
    pub fn holder(self, key: SigningKey) -> Self {
        self.identity(PersistentIdentity::ephemeral(key))
    }

    /// Replace the trusted-root set.
    pub fn trusted_roots(mut self, roots: impl Into<Vec<PublicKey>>) -> Self {
        self.roots = roots.into();
        self
    }

    /// Add one trusted root.
    pub fn trusted_root(mut self, root: PublicKey) -> Self {
        self.roots.push(root);
        self
    }

    /// Selects [`RevocationMode::TtlUntilSrl`]: TTL ceiling until an SRL arrives.
    pub fn ttl_fallback(mut self, max_lifetime: Duration) -> Self {
        self.ttl_fallback = Some(max_lifetime);
        if self.revocation.is_none() {
            self.revocation = Some(RevocationMode::TtlUntilSrl { max_lifetime });
        }
        self
    }

    /// Explicit revocation policy. Required unless [`Self::ttl_fallback`] already
    /// selected [`RevocationMode::TtlUntilSrl`].
    pub fn revocation(mut self, mode: RevocationMode) -> Self {
        match &mode {
            RevocationMode::TtlOnly { max_lifetime }
            | RevocationMode::TtlUntilSrl { max_lifetime } => {
                self.ttl_fallback = Some(*max_lifetime);
            }
            RevocationMode::SignedSrl => {}
        }
        self.revocation = Some(mode);
        self
    }

    /// How long an accepted SRL stays fresh. Defaults to 300 seconds.
    pub fn srl_max_age(mut self, max_age: Duration) -> Self {
        self.srl_max_age = max_age;
        self
    }

    /// Allowed clock skew when accepting an SRL. Defaults to 30 seconds.
    pub fn srl_clock_tolerance(mut self, tolerance: Duration) -> Self {
        self.srl_clock_tolerance = tolerance;
        self
    }

    /// Persist revocation floors at `path` instead of beside the identity
    /// key. Use this when the key lives on a read-only or root-owned mount.
    pub fn revocation_floor_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.floor_path = Some(path.into());
        self
    }

    /// Log level for denials. Never changes whether the operation runs.
    pub fn denial_reporting(mut self, reporting: DenialReporting) -> Self {
        self.denial_reporting = reporting;
        self
    }

    #[cfg(feature = "receipts")]
    /// Whether sessions emit receipts. Disabled unless set.
    pub fn evidence_policy(mut self, policy: EvidencePolicy) -> Self {
        self.evidence = policy;
        self
    }

    /// Bound on the session receipt outbox. A full sink drops the new
    /// receipt, counts it, and returns Unavailable. Best-effort still
    /// proceeds; RequiredBeforeExecution denies.
    #[cfg(feature = "receipts")]
    pub fn receipt_capacity(mut self, max: usize) -> Self {
        self.receipt_capacity = max.max(1);
        self
    }

    /// Build the runtime.
    pub fn build(self) -> Result<Runtime, RuntimeError> {
        let identity = self.identity.ok_or(RuntimeError::MissingIdentity)?;
        if self.roots.is_empty() {
            return Err(RuntimeError::MissingRoots);
        }
        let ttl_fallback = match (&self.revocation, self.ttl_fallback) {
            (
                Some(RevocationMode::TtlOnly { max_lifetime })
                | Some(RevocationMode::TtlUntilSrl { max_lifetime }),
                _,
            ) => *max_lifetime,
            (_, Some(ttl)) => ttl,
            (Some(RevocationMode::SignedSrl), None) => Duration::from_secs(60),
            (None, None) => return Err(RuntimeError::MissingTtlFallback),
        };
        if ttl_fallback.is_zero() {
            return Err(RuntimeError::InvalidTtlFallback);
        }
        if self.srl_max_age.is_zero() {
            return Err(RuntimeError::InvalidSrlMaxAge);
        }
        let tracker = Arc::new(build_tracker(
            &identity,
            self.roots.clone(),
            self.srl_max_age,
            self.srl_clock_tolerance,
            self.floor_path,
        )?);
        Ok(Runtime {
            identity,
            roots: self.roots,
            ttl_fallback,
            revocation: self.revocation,
            tracker,
            denial_reporting: self.denial_reporting,
            #[cfg(feature = "receipts")]
            evidence: self.evidence,
            #[cfg(feature = "receipts")]
            receipt_capacity: self.receipt_capacity,
            #[cfg(feature = "receipts")]
            receipt_link: Arc::new(std::sync::Mutex::new(None)),
        })
    }
}

fn build_tracker(
    identity: &PersistentIdentity,
    roots: Vec<PublicKey>,
    max_age: Duration,
    clock_tolerance: Duration,
    floor_path: Option<PathBuf>,
) -> Result<RevocationTracker, RuntimeError> {
    let floors: Arc<dyn RevocationFloorStore> = if let Some(path) = floor_path {
        Arc::new(FileFloorStore::open(path)?)
    } else if identity.path().as_os_str().is_empty() {
        Arc::new(InMemoryFloorStore::for_development())
    } else {
        let default_path = identity.path().with_extension("srl-floors");
        Arc::new(FileFloorStore::open(default_path)?)
    };
    Ok(RevocationTracker::new(
        roots,
        max_age,
        clock_tolerance,
        floors,
    )?)
}

/// Value that [`Runtime::session_from_warrant`] can bind.
pub trait SessionWarrant {
    /// Produce a decoded warrant.
    fn into_warrant(self) -> Result<Warrant, RuntimeError>;
}

impl SessionWarrant for Warrant {
    fn into_warrant(self) -> Result<Warrant, RuntimeError> {
        Ok(self)
    }
}

impl SessionWarrant for &Warrant {
    fn into_warrant(self) -> Result<Warrant, RuntimeError> {
        Ok(self.clone())
    }
}

impl SessionWarrant for &str {
    fn into_warrant(self) -> Result<Warrant, RuntimeError> {
        crate::wire::decode_base64(self).map_err(RuntimeError::Warrant)
    }
}

impl SessionWarrant for String {
    fn into_warrant(self) -> Result<Warrant, RuntimeError> {
        crate::wire::decode_base64(&self).map_err(RuntimeError::Warrant)
    }
}

/// Failure constructing a runtime or session, or applying an SRL.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeError {
    /// No holder identity was supplied.
    MissingIdentity,
    /// No trusted roots were supplied.
    MissingRoots,
    /// No TTL fallback was supplied.
    MissingTtlFallback,
    /// TTL fallback must be greater than zero.
    InvalidTtlFallback,
    /// SRL freshness window must be greater than zero.
    InvalidSrlMaxAge,
    /// Guard construction failed.
    Guard(GuardBuildError),
    /// The warrant could not be bound to the holder key.
    Authority(AuthorityError),
    /// Warrant or SRL bytes could not be decoded.
    Warrant(Error),
    /// Signed revocation was rejected.
    Revocation(RevocationError),
    /// Holder identity could not be loaded.
    Identity(IdentityError),
    /// [`RevocationMode::TtlOnly`] does not consume signed revocation lists.
    TtlOnlyIgnoresSrl,
}

impl From<GuardBuildError> for RuntimeError {
    fn from(value: GuardBuildError) -> Self {
        Self::Guard(value)
    }
}

impl From<AuthorityError> for RuntimeError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<RevocationError> for RuntimeError {
    fn from(value: RevocationError) -> Self {
        Self::Revocation(value)
    }
}

impl From<IdentityError> for RuntimeError {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingIdentity => write!(f, "runtime requires a holder identity"),
            Self::MissingRoots => write!(f, "runtime requires at least one trusted root"),
            Self::MissingTtlFallback => {
                write!(
                    f,
                    "runtime requires a TTL fallback before a signed SRL arrives"
                )
            }
            Self::InvalidTtlFallback => write!(f, "TTL fallback must be greater than zero"),
            Self::InvalidSrlMaxAge => write!(f, "SRL max age must be greater than zero"),
            Self::Guard(err) => write!(f, "{err}"),
            Self::Authority(err) => write!(f, "{err}"),
            Self::Warrant(err) => write!(f, "{err}"),
            Self::Revocation(err) => write!(f, "{err}"),
            Self::Identity(err) => write!(f, "{err}"),
            Self::TtlOnlyIgnoresSrl => {
                write!(f, "TtlOnly runtime does not apply signed revocation lists")
            }
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(err) => Some(err),
            Self::Authority(err) => Some(err),
            Self::Warrant(err) => Some(err),
            Self::Revocation(err) => Some(err),
            Self::Identity(err) => Some(err),
            Self::MissingIdentity
            | Self::MissingRoots
            | Self::MissingTtlFallback
            | Self::InvalidTtlFallback
            | Self::InvalidSrlMaxAge
            | Self::TtlOnlyIgnoresSrl => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::sdk::Call;
    use crate::wire;
    use std::collections::HashMap;

    fn mint_pair() -> (SigningKey, SigningKey, Warrant) {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        (issuer, holder, warrant)
    }

    fn runtime(issuer: &SigningKey, holder: SigningKey) -> Runtime {
        Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .build()
            .unwrap()
    }

    #[test]
    fn session_from_decoded_and_encoded_warrant() {
        let (issuer, holder, warrant) = mint_pair();
        let encoded = wire::encode_base64(&warrant).unwrap();
        let runtime = runtime(&issuer, holder);
        let from_decoded = runtime.session_from_warrant(warrant.clone()).unwrap();
        let from_encoded = runtime.session_from_warrant(encoded.as_str()).unwrap();
        assert_eq!(
            from_decoded.authority().leaf().id(),
            from_encoded.authority().leaf().id()
        );
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        assert!(from_decoded.check(&call).is_ok());
        let out = from_decoded
            .guard(&call, |_| Ok::<_, &str>("ok"))
            .unwrap()
            .into_inner();
        assert_eq!(out, "ok");
    }

    #[test]
    fn wrong_holder_is_rejected() {
        let (issuer, _holder, warrant) = mint_pair();
        let runtime = runtime(&issuer, SigningKey::generate());
        let err = runtime.session_from_warrant(warrant).err().unwrap();
        assert!(matches!(err, RuntimeError::Authority(_)));
    }

    #[test]
    fn ttl_fallback_without_srl_still_authorizes() {
        let (issuer, holder, warrant) = mint_pair();
        let runtime = runtime(&issuer, holder);
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        assert!(session.check(&Call::borrowed("read", &args)).is_ok());
    }

    #[test]
    fn first_srl_enables_signed_enforcement_and_later_updates() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let runtime = runtime(&issuer, holder);
        let now = Utc::now();

        let empty = SignedRevocationList::builder()
            .version(1)
            .build(&issuer)
            .unwrap();
        assert_eq!(runtime.apply_signed_revocation_list(empty, now).unwrap(), 1);

        let session = runtime.session_from_warrant(warrant.clone()).unwrap();
        let args = HashMap::new();
        assert!(session.check(&Call::borrowed("read", &args)).is_ok());

        let revoked = SignedRevocationList::builder()
            .version(2)
            .revoke(warrant.id().to_string())
            .build(&issuer)
            .unwrap();
        assert_eq!(
            runtime.apply_signed_revocation_list(revoked, now).unwrap(),
            2
        );
        let session = runtime.session_from_warrant(warrant).unwrap();
        let denial = session.check(&Call::borrowed("read", &args)).err().unwrap();
        assert_eq!(denial.code(), crate::ErrorCode::WarrantRevoked.name());
    }

    #[test]
    fn early_session_sees_srl_applied_later() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let runtime = runtime(&issuer, holder);
        let session = runtime.session_from_warrant(warrant.clone()).unwrap();
        let args = HashMap::new();
        assert!(session.check(&Call::borrowed("read", &args)).is_ok());

        let revoked = SignedRevocationList::builder()
            .version(1)
            .revoke(warrant.id().to_string())
            .build(&issuer)
            .unwrap();
        runtime
            .apply_signed_revocation_list(revoked, Utc::now())
            .unwrap();
        let denial = session.check(&Call::borrowed("read", &args)).err().unwrap();
        assert_eq!(denial.code(), crate::ErrorCode::WarrantRevoked.name());
    }

    #[test]
    fn encoded_srl_round_trips() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let runtime = runtime(&issuer, holder);
        let srl = SignedRevocationList::builder()
            .version(3)
            .build(&issuer)
            .unwrap();
        let encoded = srl.to_base64().unwrap();
        assert_eq!(
            runtime
                .apply_encoded_revocation_list(&encoded, Utc::now())
                .unwrap(),
            3
        );
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn drain_receipts_does_not_repeat() {
        let (issuer, holder, warrant) = mint_pair();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::BestEffort)
            .build()
            .unwrap();
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        session.check(&call).unwrap();
        session.check(&call).unwrap();
        let first = session.drain_receipts();
        assert_eq!(first.len(), 2);
        assert_eq!(session.drain_receipts().len(), 2);
        assert_eq!(session.acknowledge_receipts(2), 2);
        assert!(session.drain_receipts().is_empty());
        session.check(&call).unwrap();
        assert_eq!(session.drain_receipts().len(), 1);
        assert_eq!(session.acknowledge_receipts(1), 1);
        assert!(session.drain_receipts().is_empty());
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn overflow_does_not_deny_and_is_counted() {
        let (issuer, holder, warrant) = mint_pair();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::BestEffort)
            .receipt_capacity(1)
            .build()
            .unwrap();
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        assert!(session.check(&call).is_ok());
        assert!(session.check(&call).is_ok());
        assert_eq!(session.drain_receipts().len(), 1);
        assert_eq!(session.receipt_overflows(), 1);
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn overflow_denies_when_evidence_is_required() {
        let (issuer, holder, warrant) = mint_pair();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::RequiredBeforeExecution)
            .receipt_capacity(1)
            .build()
            .unwrap();
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        assert!(session.check(&call).is_ok());
        assert!(session.check(&call).is_err());
        assert_eq!(session.drain_receipts().len(), 1);
        assert_eq!(session.receipt_overflows(), 1);
    }

    #[test]
    fn revocation_floor_path_does_not_write_beside_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("holder.key");
        let floor = dir.path().join("custom.srl-floors");
        let identity = PersistentIdentity::load_or_generate(&key_path).unwrap();
        Runtime::builder()
            .identity(identity)
            .trusted_root(SigningKey::generate().public_key())
            .ttl_fallback(Duration::from_secs(600))
            .revocation_floor_path(&floor)
            .build()
            .unwrap();
        assert!(floor.exists());
        assert!(!key_path.with_extension("srl-floors").exists());
    }

    #[test]
    fn builder_requires_the_three_pieces() {
        assert!(matches!(
            Runtime::builder().build().err().unwrap(),
            RuntimeError::MissingIdentity
        ));
        let holder = SigningKey::generate();
        assert!(matches!(
            Runtime::builder()
                .holder(holder.clone())
                .build()
                .err()
                .unwrap(),
            RuntimeError::MissingRoots
        ));
        assert!(matches!(
            Runtime::builder()
                .holder(holder)
                .trusted_root(SigningKey::generate().public_key())
                .build()
                .err()
                .unwrap(),
            RuntimeError::MissingTtlFallback
        ));
    }

    #[test]
    fn ttl_only_rejects_srl_and_still_allows_revoked_leaf() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(600),
            })
            .build()
            .unwrap();
        let revoked = SignedRevocationList::builder()
            .version(1)
            .revoke(warrant.id().to_string())
            .build(&issuer)
            .unwrap();
        assert!(matches!(
            runtime.apply_signed_revocation_list_now(revoked),
            Err(RuntimeError::TtlOnlyIgnoresSrl)
        ));
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        assert!(session.check(&Call::borrowed("read", &args)).is_ok());
    }

    #[test]
    fn ttl_until_srl_is_selected_by_ttl_fallback() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .build()
            .unwrap();
        assert!(matches!(
            runtime.revocation,
            Some(RevocationMode::TtlUntilSrl { .. })
        ));
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn guard_deny_emits_receipt_with_roots_and_chain() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let empty = SignedRevocationList::builder()
            .version(4)
            .build(&issuer)
            .unwrap();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::BestEffort)
            .build()
            .unwrap();
        runtime.apply_signed_revocation_list_now(empty).unwrap();
        let first = runtime.session_from_warrant(warrant.clone()).unwrap();
        let second = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        let denied = first
            .guard(&Call::borrowed("write", &args), |_| Ok::<_, &str>("no"))
            .err()
            .unwrap();
        assert!(matches!(denied, crate::sdk::GuardError::Denied(_)));
        let receipts = first.peek_receipts();
        assert_eq!(receipts.len(), 1);
        let payload = receipts[0].verify_signature().unwrap();
        assert_eq!(payload.outcome, crate::receipt::Outcome::Deny);
        assert!(payload.trusted_roots_hash.is_some());
        assert_eq!(payload.srl_version, Some(4));
        assert!(payload.srl_hash.is_some());
        assert!(payload.prev_receipt_hash.is_none());
        let before = receipts.len();
        assert!(first
            .diagnostics()
            .why_denied(&Call::borrowed("write", &args))
            .is_some());
        assert_eq!(first.peek_receipts().len(), before);

        assert!(second.check(&Call::borrowed("read", &args)).is_ok());
        let chained = second.peek_receipts();
        assert_eq!(chained.len(), 1);
        let next = chained[0].verify_signature().unwrap();
        assert_eq!(next.prev_receipt_hash, Some(receipts[0].digest().unwrap()));
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn deny_flood_does_not_starve_required_allow() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::RequiredBeforeExecution)
            .receipt_capacity(1)
            .build()
            .unwrap();
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        assert!(session.check(&Call::borrowed("write", &args)).is_err());
        assert!(session.check(&Call::borrowed("write", &args)).is_err());
        assert!(session.check(&Call::borrowed("read", &args)).is_ok());
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn persist_failure_does_not_advance_receipt_chain() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::BestEffort)
            .receipt_capacity(1)
            .build()
            .unwrap();
        let session = runtime.session_from_warrant(warrant).unwrap();
        let args = HashMap::new();
        let first = session.check(&Call::borrowed("read", &args)).unwrap();
        let a = first.receipt.clone().expect("first receipt");
        let second = session.check(&Call::borrowed("read", &args)).unwrap();
        assert!(second.receipt.is_some());
        assert_eq!(session.peek_receipts().len(), 1);
        session.acknowledge_receipts(1);
        let third = session.check(&Call::borrowed("read", &args)).unwrap();
        let c = third.receipt.expect("third receipt");
        assert_eq!(
            c.verify_signature().unwrap().prev_receipt_hash,
            Some(a.digest().unwrap())
        );
    }

    #[cfg(feature = "receipts")]
    #[test]
    fn concurrent_receipts_share_one_predecessor_chain() {
        use std::collections::HashSet;
        use std::thread;

        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let runtime = Runtime::builder()
            .holder(holder)
            .trusted_root(issuer.public_key())
            .ttl_fallback(Duration::from_secs(600))
            .evidence_policy(EvidencePolicy::BestEffort)
            .receipt_capacity(128)
            .build()
            .unwrap();
        let session = Arc::new(runtime.session_from_warrant(warrant).unwrap());
        let threads = 8;
        let per_thread = 10;
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let session = session.clone();
                thread::spawn(move || {
                    let args = HashMap::new();
                    for _ in 0..per_thread {
                        session.check(&Call::borrowed("read", &args)).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("worker");
        }
        let receipts = session.peek_receipts();
        assert_eq!(receipts.len(), threads * per_thread);
        let digests: HashSet<_> = receipts.iter().map(|r| r.digest().unwrap()).collect();
        assert_eq!(digests.len(), receipts.len());
        let mut predecessors = HashSet::new();
        let mut roots = 0usize;
        for receipt in &receipts {
            match receipt.verify_signature().unwrap().prev_receipt_hash {
                None => roots += 1,
                Some(prev) => assert!(predecessors.insert(prev), "duplicate predecessor"),
            }
        }
        assert_eq!(roots, 1);
        assert_eq!(predecessors.len(), receipts.len() - 1);
        for prev in &predecessors {
            assert!(digests.contains(prev), "link to unpublished receipt");
        }
    }
}
