//! Async counterparts. Trait definitions only; the caller brings the runtime.

use super::authority::{PresentedAuthority, ReceivedAuthorization};
use super::call::Call;
use super::decision::{Denial, GuardError, Retryability, SdkDenialKind};
use super::guard::{AuthorizedCall, Guard, Guarded};
use super::signer::{PopSigningRequest, SignerError};
use crate::crypto::{PublicKey, Signature};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Deadline and cancellation for one authorization attempt.
///
/// Enforceable only when the host runtime drops or times out the future.
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

/// Async holder signer. Implementations may be remote; the host enforces `control`.
#[async_trait]
pub trait AsyncHolderSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    async fn sign_pop(
        &self,
        request: &PopSigningRequest<'_>,
        control: &AttemptControl,
    ) -> Result<Signature, SignerError>;
}

impl Guard {
    pub async fn check_async(
        &self,
        authority: &PresentedAuthority,
        call: &Call<'_>,
        control: &AttemptControl,
    ) -> Result<super::decision::Decision, Denial> {
        self.preflight_async(control)?;
        self.check(authority, call)
    }

    pub async fn check_received_async(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
        control: &AttemptControl,
    ) -> Result<super::decision::Decision, Denial> {
        self.preflight_async(control)?;
        self.check_received(received, call)
    }

    pub async fn guard_async<T, E>(
        &self,
        authority: &PresentedAuthority,
        call: &Call<'_>,
        control: &AttemptControl,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        self.preflight_async(control).map_err(GuardError::Denied)?;
        let authorized = self
            .authorize_holder(authority, &super::guard::AuthorizationAttempt::new(call))
            .map_err(GuardError::Denied)?;
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
        let authorized = self
            .authorize_received(received, call)
            .map_err(GuardError::Denied)?;
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
        let now = Utc::now();
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
            .is_some_and(|deadline| Utc::now() >= deadline)
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
    use crate::sdk::signer::LocalSigner;
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

    #[tokio::test]
    async fn cancelled_before_decision_does_not_run() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = PresentedAuthority::new(
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
        let presented = PresentedAuthority::new(
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
        let presented = PresentedAuthority::new(
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
}
