//! Async counterparts. Trait definitions only; the caller brings the runtime.

use super::authority::{AuthorityError, PresentedAuthority, ReceivedAuthorization};
use super::call::Call;
use super::decision::{Denial, GuardError, Retryability, SdkDenialKind};
use super::guard::{AuthorizedCall, Guard, Guarded};
use super::signer::{HolderSigner, LocalSigner, PopSigningRequest, SignerError};
use crate::crypto::{PublicKey, Signature};
use crate::revocation_tracker::{RevocationError, RevocationUpdate};
use crate::warrant::Warrant;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Deadline and cancellation for one authorization attempt.
///
/// The host runtime may also drop the future. `control` is passed into the
/// operations this surface exists to wait on: remote PoP signing and remote
/// revocation fetch.
#[derive(Clone, Debug)]
pub struct AttemptControl {
    deadline: Option<DateTime<Utc>>,
    cancelled: Arc<AtomicBool>,
}

impl AttemptControl {
    pub fn new() -> Self {
        Self {
            deadline: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_deadline(deadline: DateTime<Utc>) -> Self {
        Self {
            deadline: Some(deadline),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn deadline(&self) -> Option<DateTime<Utc>> {
        self.deadline
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl Default for AttemptControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Async holder signer. Implementations may be remote; they must honor `control`.
///
/// Accepted by [`PresentedAsyncAuthority`] and therefore by
/// [`Guard::check_async`] / [`Guard::guard_async`]. The sync [`HolderSigner`]
/// path cannot be interrupted and is the wrong place to `block_on` a remote
/// call.
#[async_trait]
pub trait AsyncHolderSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    async fn sign_pop(
        &self,
        request: &PopSigningRequest<'_>,
        control: &AttemptControl,
    ) -> Result<Signature, SignerError>;
}

/// Remote SRL fetch for one async attempt. Called only when the tracker has
/// no fresh snapshot.
#[async_trait]
pub trait AsyncRevocationProvider: Send + Sync {
    async fn fetch(&self, control: &AttemptControl) -> Result<RevocationUpdate, RevocationError>;
}

/// Chain plus an async holder signer. The async Guard methods accept this type.
#[derive(Clone)]
pub struct PresentedAsyncAuthority {
    chain: Arc<[Warrant]>,
    signer: Arc<dyn AsyncHolderSigner>,
}

impl PresentedAsyncAuthority {
    pub fn new(
        chain: Vec<Warrant>,
        signer: Arc<dyn AsyncHolderSigner>,
    ) -> Result<Self, AuthorityError> {
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

    /// Wrap a sync authority. The adapter signs in-task; `control` can refuse
    /// before or after `sign_pop`, but cannot interrupt a blocking signer.
    pub fn from_sync(authority: &PresentedAuthority) -> Self {
        Self {
            chain: authority.chain_arc(),
            signer: Arc::new(SyncSignerAdapter(authority.signer_arc())),
        }
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

    pub(crate) fn signer(&self) -> &dyn AsyncHolderSigner {
        self.signer.as_ref()
    }

    pub(crate) fn signer_matches_leaf(&self) -> bool {
        self.signer.public_key() == *self.leaf().authorized_holder()
    }
}

impl fmt::Debug for PresentedAsyncAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentedAsyncAuthority")
            .field("leaf_id", &self.leaf().id().to_string())
            .field("chain_depth", &self.chain.len())
            .field("holder", &self.holder().fingerprint())
            .finish()
    }
}

impl PresentedAuthority {
    /// View this authority as the type [`Guard::check_async`] accepts.
    pub fn as_async(&self) -> PresentedAsyncAuthority {
        PresentedAsyncAuthority::from_sync(self)
    }
}

struct SyncSignerAdapter(Arc<dyn HolderSigner>);

#[async_trait]
impl AsyncHolderSigner for SyncSignerAdapter {
    fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    async fn sign_pop(
        &self,
        request: &PopSigningRequest<'_>,
        control: &AttemptControl,
    ) -> Result<Signature, SignerError> {
        if control.is_cancelled() {
            return Err(SignerError::Unavailable);
        }
        self.0.sign_pop(request)
    }
}

#[async_trait]
impl AsyncHolderSigner for LocalSigner {
    fn public_key(&self) -> PublicKey {
        HolderSigner::public_key(self)
    }

    async fn sign_pop(
        &self,
        request: &PopSigningRequest<'_>,
        control: &AttemptControl,
    ) -> Result<Signature, SignerError> {
        if control.is_cancelled() {
            return Err(SignerError::Unavailable);
        }
        HolderSigner::sign_pop(self, request)
    }
}

impl Guard {
    pub async fn check_async(
        &self,
        authority: &PresentedAsyncAuthority,
        call: &Call<'_>,
        control: &AttemptControl,
    ) -> Result<super::decision::Decision, Denial> {
        self.preflight_async(control)?;
        match self
            .authorize_holder_async(
                authority,
                &super::guard::AuthorizationAttempt::new(call),
                control,
            )
            .await
        {
            Ok(authorized) => {
                self.reject_if_cancelled(control)?;
                self.complete_allow(&authorized)
            }
            Err(denial) => {
                self.record_deny(&denial);
                Err(denial)
            }
        }
    }

    pub async fn check_received_async(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
        control: &AttemptControl,
    ) -> Result<super::decision::Decision, Denial> {
        self.preflight_async(control)?;
        match self.authorize_received(received, call) {
            Ok(authorized) => {
                self.reject_if_cancelled(control)?;
                self.complete_allow(&authorized)
            }
            Err(denial) => {
                self.record_deny(&denial);
                Err(denial)
            }
        }
    }

    pub async fn guard_async<T, E>(
        &self,
        authority: &PresentedAsyncAuthority,
        call: &Call<'_>,
        control: &AttemptControl,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        self.preflight_async(control).map_err(GuardError::Denied)?;
        let authorized = self
            .authorize_holder_async(
                authority,
                &super::guard::AuthorizationAttempt::new(call),
                control,
            )
            .await
            .map_err(|denial| {
                self.record_deny(&denial);
                GuardError::Denied(denial)
            })?;
        self.reject_if_cancelled(control)
            .map_err(GuardError::Denied)?;
        let decision = self
            .complete_allow(&authorized)
            .map_err(GuardError::Denied)?;
        let value = op(&authorized).map_err(GuardError::Operation)?;
        Ok(Guarded { value, decision })
    }

    pub async fn guard_received_async<T, E>(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
        control: &AttemptControl,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        self.preflight_async(control).map_err(GuardError::Denied)?;
        let authorized = self.authorize_received(received, call).map_err(|denial| {
            self.record_deny(&denial);
            GuardError::Denied(denial)
        })?;
        self.reject_if_cancelled(control)
            .map_err(GuardError::Denied)?;
        let decision = self
            .complete_allow(&authorized)
            .map_err(GuardError::Denied)?;
        let value = op(&authorized).map_err(GuardError::Operation)?;
        Ok(Guarded { value, decision })
    }

    pub(crate) fn preflight_async(&self, control: &AttemptControl) -> Result<(), Denial> {
        if control.is_cancelled() {
            return Err(Denial::sdk(
                SdkDenialKind::Cancelled,
                Retryability::AfterBackoff,
                "authorization cancelled",
            ));
        }
        let Some(deadline) = control.deadline() else {
            return Ok(());
        };
        let now = self.now();
        if now >= deadline {
            return Err(Denial::sdk(
                SdkDenialKind::DeadlineExceeded,
                Retryability::AfterBackoff,
                "authorization deadline exceeded",
            ));
        }
        let (window_secs, max_windows) = self.pop_window_config();
        let max_budget = chrono::Duration::seconds(window_secs.saturating_mul(max_windows as i64));
        if deadline - now > max_budget {
            return Err(Denial::sdk(
                SdkDenialKind::DeadlineExceeded,
                Retryability::No,
                "deadline exceeds PoP acceptance range",
            ));
        }
        Ok(())
    }

    fn reject_if_cancelled(&self, control: &AttemptControl) -> Result<(), Denial> {
        if control.is_cancelled() {
            return Err(Denial::sdk(
                SdkDenialKind::Cancelled,
                Retryability::AfterBackoff,
                "authorization cancelled",
            ));
        }
        if control
            .deadline()
            .is_some_and(|deadline| self.now() >= deadline)
        {
            return Err(Denial::sdk(
                SdkDenialKind::DeadlineExceeded,
                Retryability::AfterBackoff,
                "authorization deadline exceeded",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::crypto::SigningKey;
    use crate::planes::Authorizer;
    use crate::revocation::SignedRevocationList;
    use crate::revocation_tracker::RevocationTracker;
    use crate::sdk::RevocationMode;
    use crate::warrant::Warrant;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn mint(issuer: &SigningKey, holder: &SigningKey) -> Warrant {
        Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(issuer)
            .unwrap()
    }

    fn guard_for(issuer: &SigningKey) -> Guard {
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap()
    }

    struct Remote {
        key: SigningKey,
        signed: AtomicUsize,
    }

    #[async_trait]
    impl AsyncHolderSigner for Remote {
        fn public_key(&self) -> PublicKey {
            self.key.public_key()
        }

        async fn sign_pop(
            &self,
            request: &PopSigningRequest<'_>,
            control: &AttemptControl,
        ) -> Result<Signature, SignerError> {
            if control.is_cancelled() {
                return Err(SignerError::Unavailable);
            }
            self.signed.fetch_add(1, Ordering::SeqCst);
            Ok(self.key.sign_raw(&request.final_signing_bytes()))
        }
    }

    #[tokio::test]
    async fn cancelled_before_decision_does_not_run() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = PresentedAsyncAuthority::new(
            vec![mint(&issuer, &holder)],
            Arc::new(LocalSigner::new(holder)),
        )
        .unwrap();
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let control = AttemptControl::new();
        control.cancel();
        let runs = AtomicUsize::new(0);
        let err = guard
            .guard_async(&presented, &call, &control, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .await
            .err()
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert_eq!(denial.sdk_kind(), Some(SdkDenialKind::Cancelled));
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    #[tokio::test]
    async fn oversized_deadline_is_rejected() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = PresentedAsyncAuthority::new(
            vec![mint(&issuer, &holder)],
            Arc::new(LocalSigner::new(holder)),
        )
        .unwrap();
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let control = AttemptControl::with_deadline(Utc::now() + chrono::Duration::hours(2));
        let err = guard
            .check_async(&presented, &call, &control)
            .await
            .err()
            .unwrap();
        assert_eq!(err.sdk_kind(), Some(SdkDenialKind::DeadlineExceeded));
        assert!(err.message().contains("PoP"));
    }

    #[tokio::test]
    async fn allow_async_runs_once() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = PresentedAsyncAuthority::new(
            vec![mint(&issuer, &holder)],
            Arc::new(LocalSigner::new(holder)),
        )
        .unwrap();
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let control = AttemptControl::new();
        let runs = AtomicUsize::new(0);
        let guarded = guard
            .guard_async(&presented, &call, &control, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(3)
            })
            .await
            .unwrap();
        assert_eq!(guarded.value, 3);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn async_signer_is_the_one_that_signs() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let remote = Arc::new(Remote {
            key: holder.clone(),
            signed: AtomicUsize::new(0),
        });
        let presented =
            PresentedAsyncAuthority::new(vec![mint(&issuer, &holder)], remote.clone()).unwrap();
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        guard
            .check_async(&presented, &call, &AttemptControl::new())
            .await
            .unwrap();
        assert_eq!(remote.signed.load(Ordering::SeqCst), 1);
    }

    struct FetchOnce {
        update: RevocationUpdate,
        fetches: AtomicUsize,
    }

    #[async_trait]
    impl AsyncRevocationProvider for FetchOnce {
        async fn fetch(&self, _: &AttemptControl) -> Result<RevocationUpdate, RevocationError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            Ok(self.update.clone())
        }
    }

    #[tokio::test]
    async fn stale_tracker_refreshes_through_async_provider() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder);
        let srl = SignedRevocationList::builder()
            .version(1)
            .build(&issuer)
            .unwrap();
        let tracker = Arc::new(
            RevocationTracker::with_in_memory_floors(
                vec![issuer.public_key()],
                Duration::from_secs(60),
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let provider = Arc::new(FetchOnce {
            update: RevocationUpdate {
                srl,
                fetched_at: Utc::now(),
            },
            fetches: AtomicUsize::new(0),
        });
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::SignedSrl)
            .revocation_tracker(tracker)
            .async_revocation_provider(provider.clone())
            .build()
            .unwrap();
        let presented =
            PresentedAsyncAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder)))
                .unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        guard
            .check_async(&presented, &call, &AttemptControl::new())
            .await
            .expect("refresh then allow");
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 1);
    }
}
