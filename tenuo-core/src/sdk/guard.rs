use super::approvals::{ApprovalError, ApprovalProvider};
use super::authority::{PresentedAuthority, ReceivedAuthorization};
use super::call::Call;
use super::clock::{Clock, SystemClock};
use super::decision::{
    Decision, DecisionMetadata, Denial, DenialReporting, GuardError, Retryability, SdkDenialKind,
};
use super::delegation::{DelegationError, DelegationProfile};
use super::diagnostics::Diagnostics;
use super::signer::PopSigningRequest;
use crate::approval::{ApprovalRequest, SignedApproval};
use crate::constraints::ConstraintValue;
use crate::crypto::{PublicKey, Signature};
use crate::planes::Authorizer;
use crate::revocation_tracker::RevocationTracker;
use crate::verification::{
    RevocationSnapshot, RevocationState, VerificationContext, VerificationInstant,
};
use crate::warrant::Warrant;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "receipts")]
use super::evidence::{sign_payload, EvidencePolicy, ReceiptSigner, ReceiptSink, ReceiptSinkError};
#[cfg(feature = "receipts")]
use crate::approval::compute_request_hash;
#[cfg(feature = "receipts")]
use crate::receipt::ReceiptPayload;
#[cfg(feature = "receipts")]
use crate::wire::{encode_stack, WarrantStack};

/// Explicit revocation policy. No implicit fallback from SignedSrl to TtlOnly.
///
/// There is no default: the builder requires this choice, because the two
/// modes accept different risk and neither is safe to pick silently.
#[derive(Clone, Debug)]
pub enum RevocationMode {
    /// No revocation list. A warrant stays valid until it expires, so the
    /// only bound on a leaked or misissued warrant is its lifetime.
    ///
    /// Choose this when no signed revocation list is distributed to this
    /// enforcement point, and keep `max_lifetime` short — minutes, not hours.
    /// Every warrant in the chain must satisfy the ceiling or the decision
    /// denies, so the ceiling is enforced rather than advisory.
    ///
    /// The residual risk is explicit: a warrant revoked centrally keeps
    /// working here until it expires.
    TtlOnly {
        /// Maximum `expires_at - issued_at` any warrant in the chain may have.
        max_lifetime: Duration,
    },
    /// A current, trusted signed revocation list decides.
    ///
    /// Choose this for production. Revocation takes effect as soon as this
    /// enforcement point holds a fresh list. Missing, stale, untrusted, or
    /// rolled-back state denies — it never degrades to `TtlOnly`.
    ///
    /// Supply the list through [`GuardBuilder::revocation_tracker`] (which
    /// enforces freshness and a persistent rollback floor) or install one on
    /// the `Authorizer` before building.
    SignedSrl,
}

/// Enforcement surface. Holds configuration, nothing per-call.
#[derive(Clone)]
pub struct Guard {
    authorizer: Authorizer,
    revocation: ResolvedRevocation,
    denial_reporting: DenialReporting,
    clock: Arc<dyn Clock>,
    approval_provider: Option<Arc<dyn ApprovalProvider>>,
    #[cfg(feature = "async")]
    async_revocation: Option<Arc<dyn super::async_api::AsyncRevocationProvider>>,
    #[cfg(feature = "receipts")]
    evidence: EvidenceConfig,
}

#[derive(Clone)]
enum ResolvedRevocation {
    TtlOnly { max_lifetime: Duration },
    Snapshot(Arc<RevocationSnapshot>),
    Tracker(std::sync::Arc<RevocationTracker>),
}

impl Guard {
    /// Start configuring a guard. Every required field must be supplied; there are no defaults for trust or revocation.
    pub fn builder() -> GuardBuilder {
        GuardBuilder::default()
    }

    /// Decide without running anything.
    ///
    /// Returns the allow decision, or a [`Denial`] explaining why not. Use this when the
    /// operation is performed elsewhere, or to test policy.
    pub fn check(
        &self,
        authority: &PresentedAuthority,
        call: &Call<'_>,
    ) -> Result<Decision, Denial> {
        self.check_attempt(authority, AuthorizationAttempt::new(call))
    }

    /// Decide for an attempt that may carry approvals.
    ///
    /// See [`AuthorizationAttempt::with_approvals`] for the approval retry flow.
    pub fn check_attempt(
        &self,
        authority: &PresentedAuthority,
        attempt: AuthorizationAttempt<'_, '_>,
    ) -> Result<Decision, Denial> {
        match self.authorize_holder(authority, &attempt) {
            Ok(authorized) => self.complete_allow(&authorized),
            Err(denial) => {
                self.record_deny(&denial);
                Err(denial)
            }
        }
    }

    /// Authorize, then run `op` exactly once — and only after an allow.
    ///
    /// The closure receives the [`AuthorizedCall`] for this invocation, so it can tag an
    /// outbound request or write an idempotency key. On denial the closure never runs.
    ///
    /// ```
    /// use std::time::Duration;
    /// use tenuo::sdk::prelude::*;
    /// use tenuo::{args, constraints};
    ///
    /// let root = SigningKey::generate();
    /// let holder = SigningKey::generate();
    /// let warrant = Warrant::builder()
    ///     .capability("read_file", constraints! { "path" => Pattern::new("/data/*")? })
    ///     .holder(holder.public_key())
    ///     .ttl(Duration::from_secs(300))
    ///     .build(&root)?;
    ///
    /// let (guard, authority) = Tenuo::local()
    ///     .trusted_root(root.public_key())
    ///     .chain(vec![warrant])
    ///     .signer(holder)
    ///     .revocation(RevocationMode::TtlOnly { max_lifetime: Duration::from_secs(600) })
    ///     .build()?;
    ///
    /// let call = Call::owned("read_file", args! { "path" => "/data/x" })?;
    /// let out = guard.guard(&authority, &call, |authorized| {
    ///     // Tag the downstream write with the decision that permitted it.
    ///     let _idempotency_key = authorized.dedup_key();
    ///     Ok::<_, std::io::Error>("ran")
    /// })?;
    /// assert_eq!(out.into_inner(), "ran");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn guard<T, E>(
        &self,
        authority: &PresentedAuthority,
        call: &Call<'_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        self.guard_attempt(authority, AuthorizationAttempt::new(call), op)
    }

    /// Authorize an attempt that may carry approvals, then run `op` once.
    pub fn guard_attempt<T, E>(
        &self,
        authority: &PresentedAuthority,
        attempt: AuthorizationAttempt<'_, '_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        let authorized = self
            .authorize_holder(authority, &attempt)
            .map_err(|denial| {
                self.record_deny(&denial);
                GuardError::Denied(denial)
            })?;
        let decision = self
            .complete_allow(&authorized)
            .map_err(GuardError::Denied)?;
        let value = op(&authorized).map_err(GuardError::Operation)?;
        Ok(Guarded { value, decision })
    }

    /// Decide over authorization received from a peer.
    ///
    /// This is the enforcement-point path: the chain, PoP, and approvals arrived on the
    /// wire. Nothing is signed here.
    pub fn check_received(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
    ) -> Result<Decision, Denial> {
        match self.authorize_received(received, call) {
            Ok(authorized) => self.complete_allow(&authorized),
            Err(denial) => {
                self.record_deny(&denial);
                Err(denial)
            }
        }
    }

    /// Verify received authorization, then run `op` exactly once.
    pub fn guard_received<T, E>(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        let authorized = self.authorize_received(received, call).map_err(|denial| {
            self.record_deny(&denial);
            GuardError::Denied(denial)
        })?;
        let decision = self
            .complete_allow(&authorized)
            .map_err(GuardError::Denied)?;
        let value = op(&authorized).map_err(GuardError::Operation)?;
        Ok(Guarded { value, decision })
    }

    /// Operator-side explanation. Never for caller-visible text.
    pub fn diagnostics<'a>(&'a self, authority: &'a PresentedAuthority) -> Diagnostics<'a> {
        Diagnostics::holder(self, authority)
    }

    /// Operator-side explanation for received authorization. Never for caller-visible text.
    pub fn diagnostics_received<'a>(
        &'a self,
        received: &'a ReceivedAuthorization<'a>,
    ) -> Diagnostics<'a> {
        Diagnostics::received(self, received)
    }

    /// Mint a local child after confirming the parent is live under this guard.
    ///
    /// Trust, expiry, TTL ceiling, and revocation are evaluated at `now()`.
    /// [`PresentedAuthority::delegate_local`] skips that check.
    pub fn delegate(
        &self,
        parent: &PresentedAuthority,
        profile: &DelegationProfile,
    ) -> Result<PresentedAuthority, DelegationError> {
        self.confirm_parent_live(parent)?;
        parent.delegate_local(profile)
    }

    /// Mint a remote child after confirming the parent is live under this guard.
    pub fn delegate_to(
        &self,
        parent: &PresentedAuthority,
        child_holder: &PublicKey,
        profile: &DelegationProfile,
    ) -> Result<Vec<Warrant>, DelegationError> {
        self.confirm_parent_live(parent)?;
        parent.delegate_to(child_holder, profile)
    }

    fn confirm_parent_live(&self, parent: &PresentedAuthority) -> Result<(), DelegationError> {
        let instant = VerificationInstant::new(self.now());
        let loaded = self
            .load_revocation(instant.as_datetime())
            .map_err(|denial| {
                self.record_deny(&denial);
                DelegationError::Denied(denial)
            })?;
        let context = VerificationContext::new(instant.as_datetime(), loaded.as_state());
        self.authorizer
            .verify_chain_with_context(parent.chain(), &context)
            .map_err(|err| {
                let denial = Denial::from_core(err);
                self.record_deny(&denial);
                DelegationError::Denied(denial)
            })?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn denial_reporting(&self) -> DenialReporting {
        self.denial_reporting
    }

    #[cfg(feature = "async")]
    pub(crate) fn pop_window_config(&self) -> (i64, u32) {
        self.authorizer.pop_window_config()
    }

    pub(crate) fn snapshot_for_observe(&self) -> Self {
        let cloned = self.clone();
        #[cfg(feature = "receipts")]
        {
            let mut cloned = cloned;
            cloned.evidence = EvidenceConfig::disabled();
            cloned
        }
        #[cfg(not(feature = "receipts"))]
        cloned
    }

    pub(crate) fn complete_allow(
        &self,
        authorized: &AuthorizedCall<'_>,
    ) -> Result<Decision, Denial> {
        #[cfg(feature = "otel")]
        super::telemetry::record_authorize("allow", "allowed", false);
        #[cfg(feature = "receipts")]
        {
            let mut decision = authorized.as_decision();
            decision.receipt = self.attach_receipt(authorized)?;
            Ok(decision)
        }
        #[cfg(not(feature = "receipts"))]
        Ok(authorized.as_decision())
    }

    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    /// Local non-blocking lookup. Never invoked from `guard` / `check`.
    pub fn resolve_approvals(
        &self,
        request: &ApprovalRequest,
    ) -> Result<Vec<SignedApproval>, ApprovalError> {
        let provider = self
            .approval_provider
            .as_ref()
            .ok_or(ApprovalError::NoProvider)?;
        provider.approvals_for(request)
    }

    #[cfg(feature = "async")]
    /// Fetch approvals for a denial that requires them, using the configured provider.
    ///
    /// Call this after [`Denial::needs_approval`], then retry with
    /// [`AuthorizationAttempt::with_approvals`].
    pub async fn resolve_approvals_async(
        &self,
        request: &ApprovalRequest,
        control: &super::async_api::AttemptControl,
    ) -> Result<Vec<SignedApproval>, ApprovalError> {
        if control.is_cancelled() {
            return Err(ApprovalError::Unavailable);
        }
        self.resolve_approvals(request)
    }

    pub(crate) fn record_deny(&self, denial: &Denial) {
        match self.denial_reporting {
            DenialReporting::Error => {
                eprintln!("tenuo deny [{}]: {}", denial.code(), denial);
            }
            DenialReporting::Warn => {
                eprintln!("tenuo deny [{}] (warn): {}", denial.code(), denial);
            }
            DenialReporting::Debug => {}
        }
        #[cfg(feature = "otel")]
        super::telemetry::record_authorize("deny", denial.code(), false);
    }

    #[cfg(feature = "receipts")]
    fn attach_receipt(
        &self,
        authorized: &AuthorizedCall<'_>,
    ) -> Result<Option<crate::receipt::Receipt>, Denial> {
        if self.evidence.policy == EvidencePolicy::Disabled {
            return Ok(None);
        }
        let signer = self.evidence.signer.as_ref().ok_or_else(|| {
            Denial::sdk(
                SdkDenialKind::EvidenceUnavailable,
                Retryability::AfterBackoff,
                "receipt signer unavailable",
            )
        })?;
        let stack = encode_stack(&WarrantStack(authorized.chain().to_vec())).map_err(|_| {
            Denial::sdk(
                SdkDenialKind::EvidenceUnavailable,
                Retryability::AfterBackoff,
                "receipt chain encoding failed",
            )
        })?;
        let leaf = authorized.chain().last().ok_or_else(|| {
            Denial::sdk(
                SdkDenialKind::AuthorityMalformed,
                Retryability::No,
                "authority chain is empty",
            )
        })?;
        let mut payload = ReceiptPayload::allow(
            stack,
            format!("tool:{}", authorized.capability()),
            authorized.instant().as_datetime().timestamp(),
            authorized.invocation_id(),
            authorized.pop_signature().to_bytes(),
        );
        payload.request_hash = Some(compute_request_hash(
            &leaf.id().to_string(),
            authorized.capability(),
            authorized.pop_args(),
            Some(leaf.authorized_holder()),
        ));
        let bytes = payload.to_cbor().map_err(|_| {
            Denial::sdk(
                SdkDenialKind::EvidenceUnavailable,
                Retryability::AfterBackoff,
                "receipt payload encoding failed",
            )
        })?;
        let receipt = sign_payload(&bytes, signer.as_ref()).map_err(|_| {
            Denial::sdk(
                SdkDenialKind::EvidenceUnavailable,
                Retryability::AfterBackoff,
                "receipt signer unavailable",
            )
        })?;
        if let Some(sink) = &self.evidence.sink {
            match sink.persist(&receipt) {
                Ok(_) => Ok(Some(receipt)),
                Err(ReceiptSinkError::Unavailable)
                    if self.evidence.policy == EvidencePolicy::BestEffort =>
                {
                    Ok(Some(receipt))
                }
                Err(_) => Err(Denial::sdk(
                    SdkDenialKind::EvidenceUnavailable,
                    Retryability::AfterBackoff,
                    "receipt persistence failed",
                )),
            }
        } else {
            Ok(Some(receipt))
        }
    }

    pub(crate) fn authorize_holder<'a>(
        &'a self,
        authority: &'a PresentedAuthority,
        attempt: &AuthorizationAttempt<'a, 'a>,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let as_of = self.now();
        let instant = VerificationInstant::new(as_of);

        if !authority.signer_matches_leaf() {
            return Err(Denial::sdk(
                SdkDenialKind::SignerUnavailable,
                Retryability::AfterBackoff,
                "holder signer does not match leaf",
            ));
        }

        let call = attempt.call;
        let leaf = authority.leaf();
        let (window_secs, _) = self.authorizer.pop_window_config();
        let preimage = leaf
            .pop_preimage(
                call.capability(),
                call.pop_args(),
                as_of.timestamp(),
                window_secs,
            )
            .map_err(Denial::from_core)?;
        let request = PopSigningRequest::new(preimage, call.capability(), leaf.id().to_string());
        let pop_signature = authority.signer().sign_pop(&request).map_err(|_| {
            Denial::sdk(
                SdkDenialKind::SignerUnavailable,
                Retryability::AfterBackoff,
                "holder signer unavailable",
            )
        })?;

        self.decide(
            authority.chain(),
            pop_signature,
            attempt.approvals,
            call,
            instant,
        )
    }

    #[cfg(feature = "async")]
    pub(crate) async fn authorize_holder_async<'a>(
        &'a self,
        authority: &'a super::async_api::PresentedAsyncAuthority,
        attempt: &AuthorizationAttempt<'a, 'a>,
        control: &super::async_api::AttemptControl,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let as_of = self.now();
        let instant = VerificationInstant::new(as_of);

        if !authority.signer_matches_leaf() {
            return Err(Denial::sdk(
                SdkDenialKind::SignerUnavailable,
                Retryability::AfterBackoff,
                "holder signer does not match leaf",
            ));
        }

        let call = attempt.call;
        let leaf = authority.leaf();
        let (window_secs, _) = self.authorizer.pop_window_config();
        let preimage = leaf
            .pop_preimage(
                call.capability(),
                call.pop_args(),
                as_of.timestamp(),
                window_secs,
            )
            .map_err(Denial::from_core)?;
        let request = PopSigningRequest::new(preimage, call.capability(), leaf.id().to_string());
        let pop_signature = authority
            .signer()
            .sign_pop(&request, control)
            .await
            .map_err(|_| {
                Denial::sdk(
                    SdkDenialKind::SignerUnavailable,
                    Retryability::AfterBackoff,
                    "holder signer unavailable",
                )
            })?;

        self.decide_async(
            authority.chain(),
            pop_signature,
            attempt.approvals,
            call,
            instant,
            control,
        )
        .await
    }

    pub(crate) fn authorize_received<'a>(
        &'a self,
        received: &'a ReceivedAuthorization<'a>,
        call: &'a Call<'a>,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let instant = VerificationInstant::new(self.now());
        self.decide(
            received.chain(),
            received.signature().clone(),
            received.approvals(),
            call,
            instant,
        )
    }

    fn decide<'a>(
        &'a self,
        chain: &'a [Warrant],
        pop_signature: Signature,
        approvals: &'a [SignedApproval],
        call: &'a Call<'a>,
        instant: VerificationInstant,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let loaded = self.load_revocation(instant.as_datetime())?;
        self.finish_decide(chain, pop_signature, approvals, call, instant, &loaded)
    }

    #[cfg(feature = "async")]
    async fn decide_async<'a>(
        &'a self,
        chain: &'a [Warrant],
        pop_signature: Signature,
        approvals: &'a [SignedApproval],
        call: &'a Call<'a>,
        instant: VerificationInstant,
        control: &super::async_api::AttemptControl,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let loaded = self
            .load_revocation_async(instant.as_datetime(), control)
            .await?;
        self.finish_decide(chain, pop_signature, approvals, call, instant, &loaded)
    }

    fn finish_decide<'a>(
        &'a self,
        chain: &'a [Warrant],
        pop_signature: Signature,
        approvals: &'a [SignedApproval],
        call: &'a Call<'a>,
        instant: VerificationInstant,
        loaded: &LoadedRevocation,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let _ = self.denial_reporting;
        let context = VerificationContext::new(instant.as_datetime(), loaded.as_state());

        self.authorizer
            .check_chain_with_context(
                chain,
                call.capability(),
                call.pop_args(),
                call.constraint_args(),
                Some(&pop_signature),
                approvals,
                &context,
            )
            .map_err(Denial::from_core)?;

        let invocation_id = uuid::Uuid::new_v4().to_string();
        let decision_id = uuid::Uuid::new_v4().to_string();
        let leaf = chain.last().ok_or_else(|| {
            Denial::sdk(
                SdkDenialKind::AuthorityMalformed,
                Retryability::No,
                "authority chain is empty",
            )
        })?;
        let dedup_key = leaf.dedup_key(call.capability(), call.pop_args());

        Ok(AuthorizedCall {
            invocation_id,
            dedup_key,
            decision_id,
            capability: call.capability(),
            instant,
            execution_args: call.constraint_args(),
            pop_args: call.pop_args(),
            pop_signature,
            chain,
            approvals,
        })
    }

    fn load_revocation(&self, at: DateTime<Utc>) -> Result<LoadedRevocation, Denial> {
        match &self.revocation {
            ResolvedRevocation::TtlOnly { max_lifetime } => Ok(LoadedRevocation::TtlOnly {
                max_lifetime: *max_lifetime,
            }),
            ResolvedRevocation::Snapshot(snapshot) => {
                if !snapshot.is_fresh_at(at) {
                    return Err(Denial::sdk(
                        SdkDenialKind::RevocationStateUnavailable,
                        Retryability::AfterBackoff,
                        "revocation snapshot is stale",
                    ));
                }
                Ok(LoadedRevocation::Snapshot(snapshot.clone()))
            }
            ResolvedRevocation::Tracker(tracker) => {
                let snapshot = tracker.latest(at).map_err(|_| {
                    Denial::sdk(
                        SdkDenialKind::RevocationStateUnavailable,
                        Retryability::AfterBackoff,
                        "revocation state unavailable",
                    )
                })?;
                if !snapshot.is_fresh_at(at) {
                    return Err(Denial::sdk(
                        SdkDenialKind::RevocationStateUnavailable,
                        Retryability::AfterBackoff,
                        "revocation snapshot is stale",
                    ));
                }
                Ok(LoadedRevocation::Snapshot(snapshot))
            }
        }
    }

    #[cfg(feature = "async")]
    async fn load_revocation_async(
        &self,
        at: DateTime<Utc>,
        control: &super::async_api::AttemptControl,
    ) -> Result<LoadedRevocation, Denial> {
        match self.load_revocation(at) {
            Ok(loaded) => Ok(loaded),
            Err(denial)
                if matches!(
                    denial.sdk_kind(),
                    Some(SdkDenialKind::RevocationStateUnavailable)
                ) =>
            {
                let Some(provider) = &self.async_revocation else {
                    return Err(denial);
                };
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
                let ResolvedRevocation::Tracker(tracker) = &self.revocation else {
                    return Err(denial);
                };
                let update = provider.fetch(control).await.map_err(|_| {
                    Denial::sdk(
                        SdkDenialKind::RevocationStateUnavailable,
                        Retryability::AfterBackoff,
                        "revocation state unavailable",
                    )
                })?;
                let snapshot = tracker.accept(update, at).map_err(|_| {
                    Denial::sdk(
                        SdkDenialKind::RevocationStateUnavailable,
                        Retryability::AfterBackoff,
                        "revocation state unavailable",
                    )
                })?;
                if !snapshot.is_fresh_at(at) {
                    return Err(Denial::sdk(
                        SdkDenialKind::RevocationStateUnavailable,
                        Retryability::AfterBackoff,
                        "revocation snapshot is stale",
                    ));
                }
                Ok(LoadedRevocation::Snapshot(snapshot))
            }
            Err(denial) => Err(denial),
        }
    }
}

enum LoadedRevocation {
    TtlOnly { max_lifetime: Duration },
    Snapshot(Arc<RevocationSnapshot>),
}

impl LoadedRevocation {
    fn as_state(&self) -> RevocationState<'_> {
        match self {
            Self::TtlOnly { max_lifetime } => RevocationState::TtlOnly {
                max_lifetime: *max_lifetime,
            },
            Self::Snapshot(snapshot) => RevocationState::Snapshot(snapshot.as_ref()),
        }
    }
}

#[cfg(feature = "receipts")]
#[derive(Clone)]
struct EvidenceConfig {
    policy: EvidencePolicy,
    signer: Option<std::sync::Arc<dyn ReceiptSigner>>,
    sink: Option<std::sync::Arc<dyn ReceiptSink>>,
}

#[cfg(feature = "receipts")]
impl EvidenceConfig {
    fn disabled() -> Self {
        Self {
            policy: EvidencePolicy::Disabled,
            signer: None,
            sink: None,
        }
    }
}

/// One holder-sign attempt, including approvals carried into a retry.
///
/// [`Guard::check`] / [`Guard::guard`] construct this with no approvals.
/// After an `approval-required` denial, resolve signatures and retry through
/// [`Guard::check_attempt`] / [`Guard::guard_attempt`] with
/// [`AuthorizationAttempt::with_approvals`]. That is the §7.4 state machine;
/// it is not a second way to do the common path.
pub struct AuthorizationAttempt<'attempt, 'args> {
    call: &'attempt Call<'args>,
    approvals: &'attempt [SignedApproval],
}

impl<'attempt, 'args> AuthorizationAttempt<'attempt, 'args> {
    /// First attempt: the call, no approvals yet.
    pub fn new(call: &'attempt Call<'args>) -> Self {
        Self {
            call,
            approvals: &[],
        }
    }

    /// Retry after [`Denial::needs_approval`]: the same call plus resolved approvals.
    pub fn with_approvals(
        call: &'attempt Call<'args>,
        approvals: &'attempt [SignedApproval],
    ) -> Self {
        Self { call, approvals }
    }
}

/// Borrow scoped to one allowed invocation. Not a capability.
pub struct AuthorizedCall<'a> {
    invocation_id: String,
    dedup_key: String,
    decision_id: String,
    capability: &'a str,
    instant: VerificationInstant,
    execution_args: &'a HashMap<String, ConstraintValue>,
    pop_args: &'a HashMap<String, ConstraintValue>,
    pop_signature: Signature,
    chain: &'a [Warrant],
    approvals: &'a [SignedApproval],
}

impl<'a> AuthorizedCall<'a> {
    /// Identifies this attempt. Fresh on every retry.
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    /// Protocol deduplication key over the signed argument view. Stable across retries
    /// of the same logical operation.
    pub fn dedup_key(&self) -> &str {
        &self.dedup_key
    }

    /// Identifies the decision that permitted this invocation.
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    /// Capability that was authorized.
    pub fn capability(&self) -> &str {
        self.capability
    }

    /// The single instant this attempt committed to.
    pub fn instant(&self) -> VerificationInstant {
        self.instant
    }

    /// Arguments matched against the warrant's constraints.
    pub fn execution_args(&self) -> &HashMap<String, ConstraintValue> {
        self.execution_args
    }

    /// Arguments the proof of possession was computed over.
    pub fn pop_args(&self) -> &HashMap<String, ConstraintValue> {
        self.pop_args
    }

    /// The proof of possession for this invocation.
    pub fn pop_signature(&self) -> &Signature {
        &self.pop_signature
    }

    /// Warrant chain that authorized this invocation, root to leaf.
    pub fn chain(&self) -> &[Warrant] {
        self.chain
    }

    /// Approvals that satisfied the gate, if one fired.
    pub fn approvals(&self) -> &[SignedApproval] {
        self.approvals
    }

    fn as_decision(&self) -> Decision {
        Decision {
            metadata: DecisionMetadata {
                decision_id: self.decision_id.clone(),
                invocation_id: self.invocation_id.clone(),
                dedup_key: self.dedup_key.clone(),
                capability: self.capability.to_string(),
                chain_depth: self.chain.len(),
                timestamp: self.instant.as_datetime(),
            },
            receipt: None,
        }
    }
}

/// Result of an allowed guarded operation.
#[must_use]
pub struct Guarded<T> {
    /// What the operation returned.
    pub value: T,
    /// Evidence that the call was authorized.
    pub decision: Decision,
}

impl<T> Guarded<T> {
    /// Discard the evidence and take the operation's value.
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Build a [`Guard`]. Rejects an empty trust store and a missing revocation mode.
#[derive(Default)]
pub struct GuardBuilder {
    authorizer: Option<Authorizer>,
    revocation: Option<RevocationMode>,
    tracker: Option<std::sync::Arc<RevocationTracker>>,
    denial_reporting: DenialReporting,
    clock: Option<Arc<dyn Clock>>,
    approval_provider: Option<Arc<dyn ApprovalProvider>>,
    #[cfg(feature = "async")]
    async_revocation: Option<Arc<dyn super::async_api::AsyncRevocationProvider>>,
    #[cfg(feature = "receipts")]
    evidence: EvidencePolicy,
    #[cfg(feature = "receipts")]
    receipt_signer: Option<std::sync::Arc<dyn ReceiptSigner>>,
    #[cfg(feature = "receipts")]
    receipt_sink: Option<std::sync::Arc<dyn ReceiptSink>>,
    #[cfg(feature = "async")]
    declared_sync_deadline: bool,
}

impl GuardBuilder {
    /// The authorizer supplying trusted roots and clearance policy. Required.
    pub fn authorizer(mut self, authorizer: Authorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Revocation policy. Required — there is no default; see [`RevocationMode`].
    pub fn revocation(mut self, mode: RevocationMode) -> Self {
        self.revocation = Some(mode);
        self
    }

    /// Production SignedSrl path: snapshots come from the tracker, not a fallback.
    pub fn revocation_tracker(mut self, tracker: std::sync::Arc<RevocationTracker>) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// Log level for denials. Never changes whether the operation runs.
    pub fn denial_reporting(mut self, reporting: DenialReporting) -> Self {
        self.denial_reporting = reporting;
        self
    }

    /// Provider consulted only after a denial requires approval.
    pub fn approval_provider(mut self, provider: Arc<dyn ApprovalProvider>) -> Self {
        self.approval_provider = Some(provider);
        self
    }

    /// Remote SRL fetch used by the async decision path when the tracker has no
    /// fresh snapshot. The sync path never calls this.
    #[cfg(feature = "async")]
    pub fn async_revocation_provider(
        mut self,
        provider: Arc<dyn super::async_api::AsyncRevocationProvider>,
    ) -> Self {
        self.async_revocation = Some(provider);
        self
    }

    /// Test and forensic clocks only. Production uses [`SystemClock`].
    #[cfg(feature = "test-utils")]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    #[cfg(feature = "receipts")]
    /// Whether a receipt is best-effort evidence or a gate that denies on persistence failure.
    pub fn evidence_policy(mut self, policy: EvidencePolicy) -> Self {
        self.evidence = policy;
        self
    }

    #[cfg(feature = "receipts")]
    /// Signer for authorization receipts.
    pub fn receipt_signer(mut self, signer: std::sync::Arc<dyn ReceiptSigner>) -> Self {
        self.receipt_signer = Some(signer);
        self
    }

    #[cfg(feature = "receipts")]
    /// Sink receipts are written to.
    pub fn receipt_sink(mut self, sink: std::sync::Arc<dyn ReceiptSink>) -> Self {
        self.receipt_sink = Some(sink);
        self
    }

    /// Sync surface cannot enforce a deadline. Calling this makes `build` fail.
    #[cfg(feature = "async")]
    pub fn deadline(mut self, _deadline: Duration) -> Self {
        self.declared_sync_deadline = true;
        self
    }

    /// Build the guard, or fail if a required field is missing or unusable.
    pub fn build(self) -> Result<Guard, GuardBuildError> {
        let authorizer = self.authorizer.ok_or(GuardBuildError::MissingAuthorizer)?;
        if !authorizer.has_trusted_roots() {
            return Err(GuardBuildError::EmptyTrustStore);
        }
        let mode = self
            .revocation
            .ok_or(GuardBuildError::MissingRevocationMode)?;
        #[cfg(feature = "async")]
        if self.declared_sync_deadline {
            return Err(GuardBuildError::DeadlineNotEnforceable);
        }
        #[cfg(feature = "receipts")]
        let evidence = {
            match self.evidence {
                EvidencePolicy::Disabled => EvidenceConfig::disabled(),
                EvidencePolicy::BestEffort => {
                    if self.receipt_signer.is_none() {
                        return Err(GuardBuildError::MissingReceiptSigner);
                    }
                    EvidenceConfig {
                        policy: EvidencePolicy::BestEffort,
                        signer: self.receipt_signer,
                        sink: self.receipt_sink,
                    }
                }
                EvidencePolicy::RequiredBeforeExecution => {
                    if self.receipt_signer.is_none() {
                        return Err(GuardBuildError::MissingReceiptSigner);
                    }
                    if self.receipt_sink.is_none() {
                        return Err(GuardBuildError::MissingReceiptSink);
                    }
                    EvidenceConfig {
                        policy: EvidencePolicy::RequiredBeforeExecution,
                        signer: self.receipt_signer,
                        sink: self.receipt_sink,
                    }
                }
            }
        };
        let revocation = match mode {
            RevocationMode::TtlOnly { max_lifetime } => {
                ResolvedRevocation::TtlOnly { max_lifetime }
            }
            RevocationMode::SignedSrl => {
                if let Some(tracker) = self.tracker {
                    ResolvedRevocation::Tracker(tracker)
                } else {
                    let list = authorizer
                        .installed_revocation_list()
                        .cloned()
                        .ok_or(GuardBuildError::SignedSrlUnavailable)?;
                    ResolvedRevocation::Snapshot(Arc::new(RevocationSnapshot::from_accepted_list(
                        list,
                    )))
                }
            }
        };
        Ok(Guard {
            authorizer,
            revocation,
            denial_reporting: self.denial_reporting,
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            approval_provider: self.approval_provider,
            #[cfg(feature = "async")]
            async_revocation: self.async_revocation,
            #[cfg(feature = "receipts")]
            evidence,
        })
    }
}

/// Failure constructing a [`Guard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardBuildError {
    /// No authorizer was supplied.
    MissingAuthorizer,
    /// The authorizer trusts no roots, so nothing could ever verify.
    EmptyTrustStore,
    /// No revocation mode was chosen.
    MissingRevocationMode,
    /// `SignedSrl` was chosen but no signed list or tracker is available.
    SignedSrlUnavailable,
    #[cfg(feature = "receipts")]
    /// An evidence policy requires receipts but no signer was supplied.
    MissingReceiptSigner,
    #[cfg(feature = "receipts")]
    /// An evidence policy requires receipts but no sink was supplied.
    MissingReceiptSink,
    #[cfg(feature = "async")]
    /// A deadline was configured on the synchronous surface, where it cannot be enforced.
    /// Use the async surface for enforceable deadlines.
    DeadlineNotEnforceable,
}

impl fmt::Display for GuardBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAuthorizer => write!(f, "guard requires an authorizer"),
            Self::EmptyTrustStore => write!(f, "guard authorizer has an empty trust store"),
            Self::MissingRevocationMode => write!(f, "guard requires an explicit revocation mode"),
            Self::SignedSrlUnavailable => {
                write!(f, "SignedSrl requires a revocation list on the authorizer")
            }
            #[cfg(feature = "receipts")]
            Self::MissingReceiptSigner => {
                write!(f, "receipts require an explicit ReceiptSigner")
            }
            #[cfg(feature = "receipts")]
            Self::MissingReceiptSink => {
                write!(f, "RequiredBeforeExecution requires a local ReceiptSink")
            }
            #[cfg(feature = "async")]
            Self::DeadlineNotEnforceable => {
                write!(f, "the synchronous guard cannot enforce a deadline")
            }
        }
    }
}

impl std::error::Error for GuardBuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::crypto::SigningKey;
    use crate::error::ErrorCode;
    use crate::sdk::signer::{HolderSigner, LocalSigner, SignerError};
    use crate::sdk::{Call, PresentedAuthority, ReceivedAuthorization, VerifiedProjection};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn mint(issuer: &SigningKey, holder: &SigningKey, tool: &str) -> Warrant {
        Warrant::builder()
            .capability(tool, ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(issuer)
            .expect("mint")
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
            .expect("guard")
    }

    fn authority(chain: Vec<Warrant>, holder: SigningKey) -> PresentedAuthority {
        PresentedAuthority::new(chain, Arc::new(LocalSigner::new(holder))).expect("authority")
    }

    #[test]
    fn allow_runs_operation_once() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);

        let guarded = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(7)
            })
            .expect("allow");

        assert_eq!(guarded.value, 7);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(guarded.decision.metadata.capability, "read");
        assert_eq!(guarded.decision.metadata.chain_depth, 1);
        let expected = authority.leaf().dedup_key("read", &args);
        assert_eq!(guarded.decision.metadata.dedup_key, expected);
        let again = guard.check(&authority, &call).expect("second allow");
        assert_eq!(again.metadata.dedup_key, expected);
        assert_ne!(
            again.metadata.invocation_id,
            guarded.decision.metadata.invocation_id
        );
    }

    #[test]
    fn deny_does_not_run_operation() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);
        let runs = AtomicUsize::new(0);

        let err = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("deny");

        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert_eq!(denial.protocol_code(), Some(ErrorCode::ToolNotAuthorized));
                assert!(!denial.is_infrastructure());
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    #[test]
    fn empty_chain_rejected() {
        let holder = SigningKey::generate();
        let err = PresentedAuthority::new(vec![], Arc::new(LocalSigner::new(holder)))
            .expect_err("empty chain must be rejected");
        assert_eq!(err, crate::sdk::AuthorityError::EmptyChain);
    }

    #[test]
    fn signer_mismatch_rejected_at_construction() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let other = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let err = PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(other)))
            .expect_err("signer mismatch must be rejected");
        assert_eq!(err, crate::sdk::AuthorityError::SignerMismatch);
    }

    #[test]
    fn empty_trust_store_rejected() {
        let err = Guard::builder()
            .authorizer(Authorizer::new())
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(60),
            })
            .build()
            .err()
            .expect("empty trust");
        assert_eq!(err, GuardBuildError::EmptyTrustStore);
    }

    #[test]
    fn missing_revocation_mode_rejected() {
        let issuer = SigningKey::generate();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let err = Guard::builder()
            .authorizer(authorizer)
            .build()
            .err()
            .expect("missing mode");
        assert_eq!(err, GuardBuildError::MissingRevocationMode);
    }

    #[test]
    fn signed_srl_without_list_rejected() {
        let issuer = SigningKey::generate();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let err = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::SignedSrl)
            .build()
            .err()
            .expect("no srl");
        assert_eq!(err, GuardBuildError::SignedSrlUnavailable);
    }

    #[test]
    fn same_authority_denied_by_other_trust_store() {
        let issuer = SigningKey::generate();
        let other_root = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);

        assert!(guard_for(&issuer).check(&authority, &call).is_ok());

        let mut stranger = Authorizer::new();
        stranger.add_trusted_root(other_root.public_key());
        let other_guard = Guard::builder()
            .authorizer(stranger)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let denial = other_guard
            .check(&authority, &call)
            .err()
            .expect("untrusted");
        assert!(
            matches!(
                denial.protocol_code(),
                Some(ErrorCode::UntrustedRoot | ErrorCode::SignatureInvalid)
            ),
            "expected a protocol denial, got {:?}",
            denial.protocol_code()
        );
    }

    struct FlipSigner {
        matching: SigningKey,
        other: SigningKey,
        flip: AtomicBool,
    }

    impl HolderSigner for FlipSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            if self.flip.load(Ordering::SeqCst) {
                self.other.public_key()
            } else {
                self.matching.public_key()
            }
        }

        fn sign_pop(
            &self,
            request: &crate::sdk::PopSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Ok(self.matching.sign_raw(&request.final_signing_bytes()))
        }

        fn sign_delegation(
            &self,
            request: &crate::sdk::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Ok(self.matching.sign_raw(request.final_signing_bytes()))
        }
    }

    #[test]
    fn signer_mismatch_at_call_time_denies_without_running() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let other = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let signer = Arc::new(FlipSigner {
            matching: holder,
            other,
            flip: AtomicBool::new(false),
        });
        let authority = PresentedAuthority::new(vec![warrant], signer.clone()).expect("construct");
        signer.flip.store(true, Ordering::SeqCst);

        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);
        let err = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("deny");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert_eq!(denial.sdk_kind(), Some(SdkDenialKind::SignerUnavailable));
                assert_eq!(denial.retryability(), Retryability::AfterBackoff);
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    struct CountingSigner {
        inner: LocalSigner,
        pops: AtomicUsize,
    }

    impl HolderSigner for CountingSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            self.inner.public_key()
        }

        fn sign_pop(
            &self,
            request: &crate::sdk::PopSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            self.pops.fetch_add(1, Ordering::SeqCst);
            self.inner.sign_pop(request)
        }

        fn sign_delegation(
            &self,
            request: &crate::sdk::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            self.inner.sign_delegation(request)
        }
    }

    #[test]
    fn holder_path_always_signs_locally() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let signer = Arc::new(CountingSigner {
            inner: LocalSigner::new(holder),
            pops: AtomicUsize::new(0),
        });
        let authority = PresentedAuthority::new(vec![warrant], signer.clone()).unwrap();
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        guard.check(&authority, &call).expect("allow");
        assert_eq!(signer.pops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denial_reporting_does_not_change_execution() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);

        for reporting in [
            DenialReporting::Error,
            DenialReporting::Warn,
            DenialReporting::Debug,
        ] {
            let mut authorizer = Authorizer::new();
            authorizer.add_trusted_root(issuer.public_key());
            let guard = Guard::builder()
                .authorizer(authorizer)
                .revocation(RevocationMode::TtlOnly {
                    max_lifetime: Duration::from_secs(3600),
                })
                .denial_reporting(reporting)
                .build()
                .unwrap();
            let runs = AtomicUsize::new(0);
            let err = guard
                .guard(&authority, &call, |_| {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &str>(())
                })
                .err()
                .unwrap();
            assert_eq!(runs.load(Ordering::SeqCst), 0);
            match err {
                GuardError::Denied(denial) => {
                    assert_eq!(denial.protocol_code(), Some(ErrorCode::ToolNotAuthorized));
                }
                GuardError::Operation(_) => panic!("operation must not run"),
            }
        }
    }

    #[test]
    fn diagnostics_explain_denied_call() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);
        let why = guard
            .diagnostics(&authority)
            .why_denied(&call)
            .expect("denied");
        assert!(why.contains("tool-not-authorized"));
        assert!(guard
            .diagnostics(&authority)
            .explain_authority()
            .contains("read"));
    }

    #[test]
    fn owned_call_rejects_empty_capability() {
        let err = Call::owned("", HashMap::new()).err().expect("empty");
        assert_eq!(err, crate::sdk::ArgumentError::EmptyCapability);
    }

    #[test]
    fn received_empty_chain_rejected() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let pop = guard
            .guard(&authority, &call, |authorized| {
                Ok::<_, &str>(authorized.pop_signature().clone())
            })
            .unwrap()
            .into_inner();
        let err =
            ReceivedAuthorization::new(&[], &pop, &[]).expect_err("empty chain must be rejected");
        assert_eq!(err, crate::sdk::AuthorityError::EmptyChain);
    }

    #[test]
    fn received_allows_without_signing() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let client = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let pop = client
            .guard(&authority, &call, |authorized| {
                Ok::<_, &str>(authorized.pop_signature().clone())
            })
            .unwrap()
            .into_inner();

        let received = ReceivedAuthorization::new(authority.chain(), &pop, &[]).unwrap();
        let projection = VerifiedProjection::identical(HashMap::new());
        let inbound = Call::from_transport("read", &projection);
        let server = guard_for(&issuer);
        let runs = AtomicUsize::new(0);
        let _ = server
            .guard_received(&received, &inbound, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .expect("allow");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn received_wrong_signature_denies_without_running() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let other = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let client = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        client.check(&authority, &call).expect("holder allow");
        let junk = other.sign_raw(b"not-the-pop");

        let received = ReceivedAuthorization::new(authority.chain(), &junk, &[]).unwrap();
        let projection = VerifiedProjection::identical(HashMap::new());
        let inbound = Call::from_transport("read", &projection);
        let server = guard_for(&issuer);
        let runs = AtomicUsize::new(0);
        let err = server
            .guard_received(&received, &inbound, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("deny");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert!(
                    matches!(
                        denial.protocol_code(),
                        Some(ErrorCode::PopSignatureInvalid | ErrorCode::SignatureInvalid)
                    ),
                    "expected a PoP/signature denial, got {:?}",
                    denial.protocol_code()
                );
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    #[test]
    fn tracker_signed_srl_without_accept_denies() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let tracker = std::sync::Arc::new(
            crate::RevocationTracker::with_in_memory_floors(
                vec![issuer.public_key()],
                Duration::from_secs(60),
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::SignedSrl)
            .revocation_tracker(tracker)
            .build()
            .unwrap();
        let authority = authority(vec![warrant], holder);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);
        let err = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert_eq!(
                    denial.sdk_kind(),
                    Some(SdkDenialKind::RevocationStateUnavailable)
                );
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }
}
